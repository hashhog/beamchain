-module(beamchain_mempool).
-behaviour(gen_server).

%% Transaction memory pool — holds unconfirmed transactions with
%% fee-rate ordering, ancestor/descendant tracking, and RBF support.

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% API
-export([start_link/0]).

%% Transaction submission
-export([add_transaction/1]).

%% Queries
-export([has_tx/1, get_tx/1, get_entry/1]).
-export([get_all_txids/0, get_info/0]).
-export([get_sorted_by_fee/0]).

%% Block interaction
-export([remove_for_block/1]).

%% Maintenance
-export([trim_to_size/1, expire_old/0]).

%% UTXO lookups (called externally from validation)
-export([get_mempool_utxo/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2]).

-define(SERVER, ?MODULE).

%%% -------------------------------------------------------------------
%%% Policy constants
%%% -------------------------------------------------------------------

-define(DEFAULT_MAX_MEMPOOL_SIZE, 300 * 1024 * 1024).  % 300 MB
-define(MIN_RELAY_TX_FEE, 1000).           % 1000 sat/kvB = 1 sat/vB
-define(DUST_RELAY_TX_FEE, 3000).          % 3000 sat/kvB for dust calc
-define(MAX_ORPHAN_TXS, 100).
-define(ORPHAN_TX_EXPIRE_TIME, 1200).      % 20 minutes
-define(MAX_RBF_EVICTIONS, 100).

%%% -------------------------------------------------------------------
%%% ETS table names
%%% -------------------------------------------------------------------

-define(MEMPOOL_TXS, mempool_txs).           %% txid -> mempool_entry
-define(MEMPOOL_BY_FEE, mempool_by_fee).     %% ordered {fee_rate, txid}
-define(MEMPOOL_OUTPOINTS, mempool_outpoints). %% {txid, vout} -> spending_txid
-define(MEMPOOL_ORPHANS, mempool_orphans).   %% txid -> {tx, expiry}

%%% -------------------------------------------------------------------
%%% Mempool entry record
%%% -------------------------------------------------------------------

-record(mempool_entry, {
    txid              :: binary(),
    wtxid             :: binary(),
    tx                :: #transaction{},
    fee               :: non_neg_integer(),
    size              :: non_neg_integer(),
    vsize             :: non_neg_integer(),
    weight            :: non_neg_integer(),
    fee_rate          :: float(),              %% sat/vB
    time_added        :: integer(),
    height_added      :: integer(),
    ancestor_count    :: non_neg_integer(),
    ancestor_size     :: non_neg_integer(),
    ancestor_fee      :: non_neg_integer(),
    descendant_count  :: non_neg_integer(),
    descendant_size   :: non_neg_integer(),
    descendant_fee    :: non_neg_integer(),
    spends_coinbase   :: boolean(),
    rbf_signaling     :: boolean()
}).

%%% -------------------------------------------------------------------
%%% gen_server state
%%% -------------------------------------------------------------------

-record(state, {
    max_size       :: non_neg_integer(),   %% max mempool bytes
    total_bytes    :: non_neg_integer(),   %% current total vbytes
    total_count    :: non_neg_integer()    %% number of transactions
}).

%%% ===================================================================
%%% API
%%% ===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc Submit a transaction to the mempool.
-spec add_transaction(#transaction{}) -> {ok, binary()} | {error, term()}.
add_transaction(Tx) ->
    gen_server:call(?SERVER, {add_tx, Tx}, 30000).

%% @doc Check if a transaction is in the mempool.
-spec has_tx(binary()) -> boolean().
has_tx(Txid) ->
    ets:member(?MEMPOOL_TXS, Txid).

%% @doc Get a transaction by txid.
-spec get_tx(binary()) -> {ok, #transaction{}} | not_found.
get_tx(Txid) ->
    case ets:lookup(?MEMPOOL_TXS, Txid) of
        [{Txid, Entry}] -> {ok, Entry#mempool_entry.tx};
        [] -> not_found
    end.

%% @doc Get the full mempool entry for a txid.
-spec get_entry(binary()) -> {ok, #mempool_entry{}} | not_found.
get_entry(Txid) ->
    case ets:lookup(?MEMPOOL_TXS, Txid) of
        [{Txid, Entry}] -> {ok, Entry};
        [] -> not_found
    end.

%% @doc Get all txids currently in the mempool.
-spec get_all_txids() -> [binary()].
get_all_txids() ->
    [Txid || {Txid, _} <- ets:tab2list(?MEMPOOL_TXS)].

%% @doc Get mempool summary info.
-spec get_info() -> map().
get_info() ->
    gen_server:call(?SERVER, get_info).

%% @doc Get mempool entries sorted by descending fee rate.
-spec get_sorted_by_fee() -> [#mempool_entry{}].
get_sorted_by_fee() ->
    %% ordered_set stores ascending, so we fold from the end
    Pairs = ets:tab2list(?MEMPOOL_BY_FEE),
    SortedDesc = lists:reverse(lists:sort(Pairs)),
    lists:filtermap(fun({_FeeRate, Txid}) ->
        case ets:lookup(?MEMPOOL_TXS, Txid) of
            [{Txid, Entry}] -> {true, Entry};
            [] -> false
        end
    end, SortedDesc).

%% @doc Remove confirmed transactions from the mempool.
-spec remove_for_block([binary()]) -> ok.
remove_for_block(Txids) ->
    gen_server:call(?SERVER, {remove_for_block, Txids}, 30000).

%% @doc Trim mempool to fit within MaxBytes.
-spec trim_to_size(non_neg_integer()) -> ok.
trim_to_size(MaxBytes) ->
    gen_server:call(?SERVER, {trim_to_size, MaxBytes}, 30000).

%% @doc Expire transactions older than 14 days.
-spec expire_old() -> non_neg_integer().
expire_old() ->
    gen_server:call(?SERVER, expire_old, 30000).

%% @doc Look up a mempool UTXO (output created by a mempool tx).
-spec get_mempool_utxo(binary(), non_neg_integer()) ->
    {ok, #utxo{}} | not_found.
get_mempool_utxo(Txid, Vout) ->
    case ets:lookup(?MEMPOOL_TXS, Txid) of
        [{Txid, Entry}] ->
            Outputs = (Entry#mempool_entry.tx)#transaction.outputs,
            case Vout < length(Outputs) of
                true ->
                    Out = lists:nth(Vout + 1, Outputs),
                    {ok, #utxo{
                        value = Out#tx_out.value,
                        script_pubkey = Out#tx_out.script_pubkey,
                        is_coinbase = false,
                        height = 0   %% unconfirmed
                    }};
                false ->
                    not_found
            end;
        [] ->
            not_found
    end.

%%% ===================================================================
%%% gen_server callbacks
%%% ===================================================================

init([]) ->
    %% Create ETS tables
    ets:new(?MEMPOOL_TXS, [set, public, named_table,
                            {read_concurrency, true}]),
    ets:new(?MEMPOOL_BY_FEE, [ordered_set, public, named_table]),
    ets:new(?MEMPOOL_OUTPOINTS, [set, public, named_table]),
    ets:new(?MEMPOOL_ORPHANS, [set, public, named_table]),

    %% Schedule periodic orphan expiry
    erlang:send_after(60000, self(), expire_orphans),

    logger:info("mempool: initialized"),
    {ok, #state{
        max_size = ?DEFAULT_MAX_MEMPOOL_SIZE,
        total_bytes = 0,
        total_count = 0
    }}.

handle_call({add_tx, Tx}, _From, State) ->
    case do_add_transaction(Tx, State) of
        {ok, Txid, State2} ->
            {reply, {ok, Txid}, State2};
        {error, Reason} ->
            {reply, {error, Reason}, State}
    end;

handle_call(get_info, _From, State) ->
    Info = #{
        size => State#state.total_count,
        bytes => State#state.total_bytes,
        max_size => State#state.max_size,
        min_fee => calc_min_fee(State)
    },
    {reply, Info, State};

handle_call({remove_for_block, Txids}, _From, State) ->
    State2 = do_remove_for_block(Txids, State),
    {reply, ok, State2};

handle_call({trim_to_size, MaxBytes}, _From, State) ->
    State2 = do_trim_to_size(MaxBytes, State),
    {reply, ok, State2};

handle_call(expire_old, _From, State) ->
    {Count, State2} = do_expire_old(State),
    {reply, Count, State2};

handle_call(_Request, _From, State) ->
    {reply, {error, not_implemented}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(expire_orphans, State) ->
    do_expire_orphans(),
    erlang:send_after(60000, self(), expire_orphans),
    {noreply, State};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    logger:info("mempool: shutting down (~B transactions)",
                [ets:info(?MEMPOOL_TXS, size)]),
    ok.

%%% ===================================================================
%%% Internal: add transaction (stub — filled in next commits)
%%% ===================================================================

do_add_transaction(Tx, State) ->
    Txid = beamchain_serialize:tx_hash(Tx),
    _Wtxid = beamchain_serialize:wtx_hash(Tx),

    try
        %% 1. basic structure check
        case beamchain_validation:check_transaction(Tx) of
            ok -> ok;
            {error, E} -> throw({validation, E})
        end,

        %% 2. not already in mempool
        ets:member(?MEMPOOL_TXS, Txid) andalso throw(already_in_mempool),

        %% TODO: full validation pipeline
        {error, not_implemented}
    catch
        throw:{validation, Reason} ->
            {error, Reason};
        throw:Reason ->
            {error, Reason}
    end.

%%% ===================================================================
%%% Internal: entry management (stubs)
%%% ===================================================================

insert_entry(#mempool_entry{txid = Txid, fee_rate = FeeRate, tx = Tx} = Entry) ->
    ets:insert(?MEMPOOL_TXS, {Txid, Entry}),
    ets:insert(?MEMPOOL_BY_FEE, {{FeeRate, Txid}}),
    lists:foreach(fun(#tx_in{prev_out = #outpoint{hash = H, index = I}}) ->
        ets:insert(?MEMPOOL_OUTPOINTS, {{H, I}, Txid})
    end, Tx#transaction.inputs).

remove_entry(Txid) ->
    case ets:lookup(?MEMPOOL_TXS, Txid) of
        [{Txid, Entry}] ->
            Tx = Entry#mempool_entry.tx,
            FeeRate = Entry#mempool_entry.fee_rate,
            ets:delete(?MEMPOOL_BY_FEE, {FeeRate, Txid}),
            lists:foreach(fun(#tx_in{prev_out = #outpoint{hash = H, index = I}}) ->
                ets:delete(?MEMPOOL_OUTPOINTS, {H, I})
            end, Tx#transaction.inputs),
            ets:delete(?MEMPOOL_TXS, Txid),
            Entry;
        [] ->
            not_found
    end.

%%% ===================================================================
%%% Internal: block removal (stub)
%%% ===================================================================

do_remove_for_block(Txids, State) ->
    {RemovedBytes, RemovedCount} = lists:foldl(
        fun(Txid, {Bytes, Count}) ->
            case remove_entry(Txid) of
                #mempool_entry{vsize = VSize} ->
                    {Bytes + VSize, Count + 1};
                not_found ->
                    {Bytes, Count}
            end
        end,
        {0, 0},
        Txids),
    case RemovedCount > 0 of
        true ->
            logger:debug("mempool: removed ~B txs for block (~B vB)",
                         [RemovedCount, RemovedBytes]);
        false -> ok
    end,
    State#state{
        total_bytes = max(0, State#state.total_bytes - RemovedBytes),
        total_count = max(0, State#state.total_count - RemovedCount)
    }.

%%% ===================================================================
%%% Internal: trimming / eviction (stub)
%%% ===================================================================

do_trim_to_size(_MaxBytes, State) ->
    State.

do_expire_old(State) ->
    {0, State}.

do_expire_orphans() ->
    ok.

%%% ===================================================================
%%% Internal: helpers
%%% ===================================================================

calc_min_fee(#state{total_bytes = TotalBytes, max_size = MaxSize}) ->
    case TotalBytes > (MaxSize div 2) of
        true ->
            Ratio = TotalBytes / MaxSize,
            1.0 * (1.0 + Ratio * 10.0);
        false ->
            1.0
    end.

short_hex(<<H:4/binary, _/binary>>) ->
    beamchain_serialize:hex_encode(H);
short_hex(Other) ->
    beamchain_serialize:hex_encode(Other).
