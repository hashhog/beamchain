-module(beamchain_mempool).
-behaviour(gen_server).

%% Transaction memory pool — holds unconfirmed transactions with
%% fee-rate ordering, ancestor/descendant tracking, and RBF support.

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% API
-export([start_link/0]).

%% Transaction submission
-export([add_transaction/1, accept_package/1]).

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

%% @doc Submit a package of related transactions to the mempool.
%% Transactions must be topologically sorted (parents before children).
%% A child can pay fees for its low-fee parent (CPFP).
-spec accept_package([#transaction{}]) ->
    {ok, [binary()]} | {error, term()}.
accept_package(Package) ->
    gen_server:call(?SERVER, {accept_package, Package}, 60000).

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
    %% ordered_set is ascending by key, so collect and reverse
    collect_by_fee_desc(ets:last(?MEMPOOL_BY_FEE), []).

collect_by_fee_desc('$end_of_table', Acc) ->
    lists:reverse(Acc);
collect_by_fee_desc({_FeeRate, Txid} = Key, Acc) ->
    Acc2 = case ets:lookup(?MEMPOOL_TXS, Txid) of
        [{Txid, E}] -> [E | Acc];
        [] -> Acc
    end,
    collect_by_fee_desc(ets:prev(?MEMPOOL_BY_FEE, Key), Acc2).

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
                            {read_concurrency, true},
                            {write_concurrency, true}]),
    ets:new(?MEMPOOL_BY_FEE, [ordered_set, public, named_table]),
    ets:new(?MEMPOOL_OUTPOINTS, [set, public, named_table,
                                  {write_concurrency, true}]),
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

handle_call({accept_package, Package}, _From, State) ->
    case do_accept_package(Package, State) of
        {ok, Txids, State2} ->
            {reply, {ok, Txids}, State2};
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
%%% Internal: add transaction
%%% ===================================================================

do_add_transaction(Tx, State) ->
    Txid = beamchain_serialize:tx_hash(Tx),
    Wtxid = beamchain_serialize:wtx_hash(Tx),

    try
        %% 1. basic structure check
        case beamchain_validation:check_transaction(Tx) of
            ok -> ok;
            {error, E} -> throw({validation, E})
        end,

        %% 2. not already in mempool
        ets:member(?MEMPOOL_TXS, Txid) andalso throw(already_in_mempool),

        %% 3. check standardness (weight, version)
        check_standard(Tx),

        %% 4. look up all inputs (UTXO set + mempool)
        {InputCoins, SpendsCoinbase} = lookup_inputs(Tx),

        %% 5. check for double-spends in mempool (+ RBF)
        check_mempool_conflicts(Tx, InputCoins),

        %% 6. compute fee
        TotalIn = lists:foldl(fun(C, A) -> A + C#utxo.value end,
                              0, InputCoins),
        TotalOut = lists:foldl(fun(#tx_out{value = V}, A) -> A + V end,
                               0, Tx#transaction.outputs),
        TotalIn >= TotalOut orelse throw(insufficient_fee),
        Fee = TotalIn - TotalOut,

        %% 7. compute size metrics
        Weight = beamchain_serialize:tx_weight(Tx),
        VSize = beamchain_serialize:tx_vsize(Tx),
        Size = byte_size(beamchain_serialize:encode_transaction(Tx)),
        FeeRate = Fee / max(1, VSize),

        %% 8. check minimum relay fee (1 sat/vB)
        FeeRate >= 1.0 orelse throw(mempool_min_fee_not_met),

        %% 9. check dust outputs
        check_dust(Tx),

        %% 10. verify scripts
        verify_scripts(Tx, InputCoins),

        %% 11. ancestor/descendant limits
        {AncCount, AncSize, AncFee} = compute_ancestors(Tx, Fee, VSize),
        AncCount =< ?MAX_ANCESTOR_COUNT orelse throw(too_long_mempool_chain),
        AncSize =< ?MAX_ANCESTOR_SIZE orelse throw(too_long_mempool_chain),
        check_descendant_limits(Tx, VSize),

        %% 12. check coinbase maturity for mempool spending
        {ok, {TipHash, TipHeight}} = beamchain_chainstate:get_tip(),
        check_mempool_coinbase_maturity(InputCoins, TipHeight + 1),

        %% 12b. BIP 68 sequence lock check
        %% For mempool, check if tx would satisfy locks in the next block
        check_mempool_sequence_locks(Tx, InputCoins, TipHash, TipHeight + 1),

        %% 13. build entry
        Now = erlang:system_time(second),
        RbfSignaling = lists:any(fun(#tx_in{sequence = Seq}) ->
            Seq < 16#fffffffe
        end, Tx#transaction.inputs),

        Entry = #mempool_entry{
            txid = Txid,
            wtxid = Wtxid,
            tx = Tx,
            fee = Fee,
            size = Size,
            vsize = VSize,
            weight = Weight,
            fee_rate = FeeRate,
            time_added = Now,
            height_added = TipHeight,
            ancestor_count = AncCount,
            ancestor_size = AncSize,
            ancestor_fee = AncFee,
            descendant_count = 1,
            descendant_size = VSize,
            descendant_fee = Fee,
            spends_coinbase = SpendsCoinbase,
            rbf_signaling = RbfSignaling
        },

        %% 14. insert into all tables
        insert_entry(Entry),

        %% 15. update ancestor descendant stats
        update_ancestors_for_new_tx(Tx, VSize, Fee),

        %% 16. update state
        State2 = State#state{
            total_bytes = State#state.total_bytes + VSize,
            total_count = State#state.total_count + 1
        },

        %% 17. check if any orphans now have parents
        reprocess_orphans(Txid),

        logger:debug("mempool: accepted ~s (fee_rate=~.1f sat/vB, ~B vB)",
                     [short_hex(Txid), FeeRate, VSize]),
        {ok, Txid, State2}
    catch
        throw:{validation, Reason} ->
            {error, Reason};
        throw:orphan ->
            add_orphan(Tx, Txid),
            {error, orphan};
        throw:Reason ->
            {error, Reason}
    end.

%%% ===================================================================
%%% Internal: package acceptance
%%% ===================================================================

%% @doc Accept a package of transactions with CPFP support.
%% Implements Bitcoin Core's AcceptPackage logic.
do_accept_package([], _State) ->
    {error, empty_package};
do_accept_package(Package, State) ->
    try
        %% 1. Context-free package validation
        validate_package_structure(Package),

        %% 2. Compute txids for deduplication
        TxidTxPairs = [{beamchain_serialize:tx_hash(Tx), Tx} || Tx <- Package],

        %% 3. Try each transaction individually, track results
        {AcceptedTxids, DeferredTxs, State2} =
            try_individual_accept(TxidTxPairs, State),

        %% 4. If no deferred transactions, we're done
        case DeferredTxs of
            [] ->
                {ok, AcceptedTxids, State2};
            _ ->
                %% 5. Evaluate deferred transactions as a package (CPFP)
                evaluate_package_cpfp(DeferredTxs, AcceptedTxids, State2)
        end
    catch
        throw:Reason ->
            {error, Reason}
    end.

%% Validate package structure (context-free checks).
validate_package_structure(Package) when length(Package) > ?MAX_PACKAGE_COUNT ->
    throw(package_too_many_transactions);
validate_package_structure(Package) ->
    %% Check total weight (only for multi-tx packages)
    case length(Package) > 1 of
        true ->
            TotalWeight = lists:foldl(fun(Tx, Acc) ->
                Acc + beamchain_serialize:tx_weight(Tx)
            end, 0, Package),
            TotalWeight =< ?MAX_PACKAGE_WEIGHT orelse throw(package_too_large);
        false ->
            ok
    end,

    %% Check for duplicate transactions
    Txids = [beamchain_serialize:tx_hash(Tx) || Tx <- Package],
    length(lists:usort(Txids)) =:= length(Txids)
        orelse throw(package_contains_duplicates),

    %% Check topological ordering (parents before children)
    is_topo_sorted(Package) orelse throw(package_not_sorted),

    %% Check no conflicting inputs within package
    is_consistent_package(Package) orelse throw(conflict_in_package),

    %% For multi-tx packages, verify child-with-parents structure
    case length(Package) > 1 of
        true ->
            is_child_with_parents(Package) orelse throw(package_not_child_with_parents);
        false ->
            ok
    end,

    ok.

%% Check if package is topologically sorted (parents before children).
%% A package is topo-sorted if no transaction spends an output that appears later.
is_topo_sorted(Package) ->
    Txids = [beamchain_serialize:tx_hash(Tx) || Tx <- Package],
    TxidSet = sets:from_list(Txids),
    is_topo_sorted_loop(Package, TxidSet).

is_topo_sorted_loop([], _LaterTxids) ->
    true;
is_topo_sorted_loop([Tx | Rest], LaterTxids) ->
    Txid = beamchain_serialize:tx_hash(Tx),
    %% Check if any input spends a tx that comes later
    SpendsFuture = lists:any(fun(#tx_in{prev_out = #outpoint{hash = H}}) ->
        H =/= Txid andalso sets:is_element(H, LaterTxids)
    end, Tx#transaction.inputs),
    case SpendsFuture of
        true -> false;
        false ->
            %% Remove this txid from the "later" set
            LaterTxids2 = sets:del_element(Txid, LaterTxids),
            is_topo_sorted_loop(Rest, LaterTxids2)
    end.

%% Check that no two transactions in the package spend the same input.
is_consistent_package(Package) ->
    AllInputs = lists:flatmap(fun(#transaction{inputs = Inputs}) ->
        [{In#tx_in.prev_out#outpoint.hash, In#tx_in.prev_out#outpoint.index}
         || In <- Inputs]
    end, Package),
    length(lists:usort(AllInputs)) =:= length(AllInputs).

%% Check if package is child-with-parents (last tx is child, all others are parents).
%% All parent txids must be inputs to the child.
is_child_with_parents([_]) ->
    true;  %% Single tx is trivially valid
is_child_with_parents(Package) when length(Package) < 2 ->
    false;
is_child_with_parents(Package) ->
    %% Last tx is the child
    Child = lists:last(Package),
    Parents = lists:droplast(Package),
    %% Child must spend at least one output from each parent
    ChildInputTxids = sets:from_list([
        In#tx_in.prev_out#outpoint.hash
        || In <- Child#transaction.inputs
    ]),
    %% Every parent's txid must be in the child's input set
    lists:all(fun(P) ->
        Txid = beamchain_serialize:tx_hash(P),
        sets:is_element(Txid, ChildInputTxids)
    end, Parents).

%% Try to accept each transaction individually.
%% Returns {AcceptedTxids, DeferredTxs, UpdatedState}
%% DeferredTxs contains {Txid, Tx} pairs that failed due to fee issues.
try_individual_accept(TxidTxPairs, State) ->
    try_individual_accept(TxidTxPairs, State, [], []).

try_individual_accept([], State, AcceptedAcc, DeferredAcc) ->
    {lists:reverse(AcceptedAcc), lists:reverse(DeferredAcc), State};
try_individual_accept([{Txid, Tx} | Rest], State, AcceptedAcc, DeferredAcc) ->
    %% Check if already in mempool
    case ets:member(?MEMPOOL_TXS, Txid) of
        true ->
            %% Already in mempool, treat as accepted
            try_individual_accept(Rest, State, [Txid | AcceptedAcc], DeferredAcc);
        false ->
            case do_add_transaction(Tx, State) of
                {ok, Txid, State2} ->
                    try_individual_accept(Rest, State2, [Txid | AcceptedAcc], DeferredAcc);
                {error, mempool_min_fee_not_met} ->
                    %% Defer for package evaluation (CPFP)
                    try_individual_accept(Rest, State, AcceptedAcc,
                                          [{Txid, Tx} | DeferredAcc]);
                {error, orphan} ->
                    %% Missing inputs - defer for package (parent may be earlier in pkg)
                    try_individual_accept(Rest, State, AcceptedAcc,
                                          [{Txid, Tx} | DeferredAcc]);
                {error, Reason} ->
                    %% Non-recoverable failure - abort entire package
                    throw({tx_failed, Txid, Reason})
            end
    end.

%% Evaluate deferred transactions as a package with CPFP.
%% Calculates aggregate package fee rate and accepts if sufficient.
evaluate_package_cpfp(DeferredTxs, AlreadyAccepted, State) ->
    %% Build a map of package outputs for input lookup
    PackageTxMap = maps:from_list(DeferredTxs),

    %% Calculate total fees and vsize for the package
    {TotalFee, TotalVSize, TxEntries} =
        compute_package_metrics(DeferredTxs, PackageTxMap, State),

    %% Calculate package fee rate
    PackageFeeRate = TotalFee / max(1, TotalVSize),

    %% Check against minimum relay fee (1 sat/vB)
    PackageFeeRate >= 1.0 orelse throw(package_fee_too_low),

    %% Check for package RBF
    AllConflicts = find_all_package_conflicts(DeferredTxs),
    case AllConflicts of
        [] ->
            ok;
        _ ->
            do_package_rbf(DeferredTxs, TotalFee, TotalVSize, AllConflicts)
    end,

    %% Accept all deferred transactions
    State2 = accept_package_txs(TxEntries, State),

    AcceptedTxids = AlreadyAccepted ++ [Txid || {Txid, _} <- DeferredTxs],
    logger:debug("mempool: accepted package of ~B txs (pkg_fee_rate=~.1f sat/vB)",
                 [length(DeferredTxs), PackageFeeRate]),
    {ok, AcceptedTxids, State2}.

%% Compute package metrics: total fee, total vsize, and entry data.
compute_package_metrics(TxPairs, PackageTxMap, _State) ->
    {ok, {_TipHash, TipHeight}} = beamchain_chainstate:get_tip(),
    Now = erlang:system_time(second),

    lists:foldl(fun({Txid, Tx}, {FeeAcc, VSizeAcc, EntriesAcc}) ->
        %% Look up inputs (UTXO set + mempool + package)
        {InputCoins, SpendsCoinbase} = lookup_inputs_with_package(Tx, PackageTxMap),

        %% Compute fee
        TotalIn = lists:foldl(fun(C, A) -> A + C#utxo.value end, 0, InputCoins),
        TotalOut = lists:foldl(fun(#tx_out{value = V}, A) -> A + V end,
                               0, Tx#transaction.outputs),
        TotalIn >= TotalOut orelse throw(insufficient_fee),
        Fee = TotalIn - TotalOut,

        %% Compute size metrics
        Weight = beamchain_serialize:tx_weight(Tx),
        VSize = beamchain_serialize:tx_vsize(Tx),
        Size = byte_size(beamchain_serialize:encode_transaction(Tx)),
        FeeRate = Fee / max(1, VSize),

        Wtxid = beamchain_serialize:wtx_hash(Tx),
        RbfSignaling = lists:any(fun(#tx_in{sequence = Seq}) ->
            Seq < 16#fffffffe
        end, Tx#transaction.inputs),

        Entry = #mempool_entry{
            txid = Txid,
            wtxid = Wtxid,
            tx = Tx,
            fee = Fee,
            size = Size,
            vsize = VSize,
            weight = Weight,
            fee_rate = FeeRate,
            time_added = Now,
            height_added = TipHeight,
            ancestor_count = 1,
            ancestor_size = VSize,
            ancestor_fee = Fee,
            descendant_count = 1,
            descendant_size = VSize,
            descendant_fee = Fee,
            spends_coinbase = SpendsCoinbase,
            rbf_signaling = RbfSignaling
        },

        {FeeAcc + Fee, VSizeAcc + VSize, [{Txid, Tx, Entry, InputCoins} | EntriesAcc]}
    end, {0, 0, []}, TxPairs).

%% Look up inputs for a package transaction.
%% Checks UTXO set, mempool, then package outputs.
lookup_inputs_with_package(#transaction{inputs = Inputs}, PackageTxMap) ->
    {Coins, AnyMissing, AnyCoinbase} = lists:foldl(
        fun(#tx_in{prev_out = #outpoint{hash = H, index = I}},
            {Acc, Missing, Cb}) ->
            case beamchain_chainstate:get_utxo(H, I) of
                {ok, Coin} ->
                    {[Coin | Acc], Missing, Cb orelse Coin#utxo.is_coinbase};
                not_found ->
                    case get_mempool_utxo(H, I) of
                        {ok, Coin} ->
                            {[Coin | Acc], Missing, Cb};
                        not_found ->
                            %% Check package outputs
                            case get_package_utxo(H, I, PackageTxMap) of
                                {ok, Coin} ->
                                    {[Coin | Acc], Missing, Cb};
                                not_found ->
                                    {Acc, true, Cb}
                            end
                    end
            end
        end,
        {[], false, false},
        Inputs),
    case AnyMissing of
        true -> throw(missing_inputs);
        false -> {lists:reverse(Coins), AnyCoinbase}
    end.

%% Get output from a package transaction.
get_package_utxo(Txid, Vout, PackageTxMap) ->
    case maps:get(Txid, PackageTxMap, undefined) of
        undefined ->
            not_found;
        Tx ->
            Outputs = Tx#transaction.outputs,
            case Vout < length(Outputs) of
                true ->
                    Out = lists:nth(Vout + 1, Outputs),
                    {ok, #utxo{
                        value = Out#tx_out.value,
                        script_pubkey = Out#tx_out.script_pubkey,
                        is_coinbase = false,
                        height = 0
                    }};
                false ->
                    not_found
            end
    end.

%% Find all mempool conflicts for the package.
find_all_package_conflicts(TxPairs) ->
    lists:usort(lists:flatmap(fun({_Txid, Tx}) ->
        find_mempool_conflicts(Tx)
    end, TxPairs)).

%% Handle package RBF.
do_package_rbf(_TxPairs, TotalFee, TotalVSize, ConflictTxids) ->
    %% Gather all conflicting entries
    ConflictEntries = lists:filtermap(fun(Cid) ->
        case ets:lookup(?MEMPOOL_TXS, Cid) of
            [{_, E}] -> {true, E};
            [] -> false
        end
    end, ConflictTxids),

    %% Check RBF signaling (unless full RBF is enabled)
    FullRbfEnabled = beamchain_config:mempool_full_rbf(),
    case FullRbfEnabled of
        true -> ok;
        false ->
            lists:foreach(fun(E) ->
                E#mempool_entry.rbf_signaling orelse throw(rbf_not_signaled)
            end, ConflictEntries)
    end,

    %% Collect all descendants of conflicting txs
    AllEvictTxids = lists:usort(lists:flatmap(fun(Cid) ->
        [Cid | get_all_descendants(Cid)]
    end, ConflictTxids)),
    length(AllEvictTxids) =< ?MAX_RBF_EVICTIONS
        orelse throw(rbf_too_many_evictions),

    AllEvictEntries = lists:filtermap(fun(Eid) ->
        case ets:lookup(?MEMPOOL_TXS, Eid) of
            [{_, E}] -> {true, E};
            [] -> false
        end
    end, AllEvictTxids),

    %% Package fee must be >= sum of all evicted fees
    EvictedFeeTotal = lists:foldl(fun(E, Acc) ->
        Acc + E#mempool_entry.fee
    end, 0, AllEvictEntries),
    TotalFee >= EvictedFeeTotal orelse throw(rbf_insufficient_fee),

    %% Additional fee must cover incremental relay fee
    MinAdditionalFee = TotalVSize,  %% 1 sat/vB * vsize
    (TotalFee - EvictedFeeTotal) >= MinAdditionalFee
        orelse throw(rbf_insufficient_additional_fee),

    %% Package fee rate must exceed all conflict fee rates
    PackageFeeRate = TotalFee / max(1, TotalVSize),
    lists:foreach(fun(E) ->
        PackageFeeRate > E#mempool_entry.fee_rate
            orelse throw(rbf_insufficient_fee_rate)
    end, ConflictEntries),

    %% Evict all conflicting txs + descendants
    lists:foreach(fun(EvictTxid) ->
        remove_entry(EvictTxid)
    end, AllEvictTxids),

    logger:debug("mempool: package rbf evicted ~B txs", [length(AllEvictTxids)]),
    ok.

%% Accept all package transactions (after CPFP validation passed).
accept_package_txs(TxEntries, State) ->
    lists:foldl(fun({Txid, Tx, Entry, InputCoins}, St) ->
        %% Verify scripts
        verify_scripts(Tx, InputCoins),

        %% Check ancestor/descendant limits
        VSize = Entry#mempool_entry.vsize,
        Fee = Entry#mempool_entry.fee,
        {AncCount, AncSize, AncFee} = compute_ancestors(Tx, Fee, VSize),
        AncCount =< ?MAX_ANCESTOR_COUNT orelse throw(too_long_mempool_chain),
        AncSize =< ?MAX_ANCESTOR_SIZE orelse throw(too_long_mempool_chain),
        check_descendant_limits(Tx, VSize),

        %% Update entry with computed ancestors
        Entry2 = Entry#mempool_entry{
            ancestor_count = AncCount,
            ancestor_size = AncSize,
            ancestor_fee = AncFee
        },

        %% Insert into tables
        insert_entry(Entry2),

        %% Update ancestors
        update_ancestors_for_new_tx(Tx, VSize, Fee),

        %% Reprocess orphans
        reprocess_orphans(Txid),

        St#state{
            total_bytes = St#state.total_bytes + VSize,
            total_count = St#state.total_count + 1
        }
    end, State, lists:reverse(TxEntries)).

%%% ===================================================================
%%% Internal: input lookup
%%% ===================================================================

%% Look up all inputs. For each input, first check the UTXO set
%% (confirmed outputs), then fall back to mempool outputs.
lookup_inputs(#transaction{inputs = Inputs}) ->
    {Coins, AnyMissing, AnyCoinbase} = lists:foldl(
        fun(#tx_in{prev_out = #outpoint{hash = H, index = I}},
            {Acc, Missing, Cb}) ->
            case beamchain_chainstate:get_utxo(H, I) of
                {ok, Coin} ->
                    {[Coin | Acc], Missing,
                     Cb orelse Coin#utxo.is_coinbase};
                not_found ->
                    %% check mempool
                    case get_mempool_utxo(H, I) of
                        {ok, Coin} ->
                            {[Coin | Acc], Missing, Cb};
                        not_found ->
                            {Acc, true, Cb}
                    end
            end
        end,
        {[], false, false},
        Inputs),
    case AnyMissing of
        true -> throw(orphan);
        false -> {lists:reverse(Coins), AnyCoinbase}
    end.

%%% ===================================================================
%%% Internal: standardness checks
%%% ===================================================================

check_standard(#transaction{version = V} = Tx) ->
    %% version must be 1 or 2
    (V =:= 1 orelse V =:= 2) orelse throw(version),
    %% weight limit
    Weight = beamchain_serialize:tx_weight(Tx),
    Weight =< ?MAX_STANDARD_TX_WEIGHT orelse throw(tx_size),
    ok.

%%% ===================================================================
%%% Internal: mempool conflict detection + RBF
%%% ===================================================================

check_mempool_conflicts(Tx, _InputCoins) ->
    case find_mempool_conflicts(Tx) of
        [] ->
            ok;
        ConflictTxids ->
            %% attempt RBF (BIP 125)
            do_rbf(Tx, ConflictTxids)
    end.

find_mempool_conflicts(#transaction{inputs = Inputs}) ->
    lists:usort(lists:filtermap(
        fun(#tx_in{prev_out = #outpoint{hash = H, index = I}}) ->
            Key = {H, I},
            case ets:lookup(?MEMPOOL_OUTPOINTS, Key) of
                [{Key, SpendingTxid}] -> {true, SpendingTxid};
                [] -> false
            end
        end,
        Inputs)).

%% @doc Replace-by-fee (BIP 125 + Full RBF).
%% Full RBF (Bitcoin Core 28.0+): allows replacement of any unconfirmed tx
%% regardless of BIP125 opt-in signaling, when mempoolfullrbf=1.
do_rbf(NewTx, ConflictTxids) ->
    %% gather all conflicting entries
    ConflictEntries = lists:filtermap(fun(Cid) ->
        case ets:lookup(?MEMPOOL_TXS, Cid) of
            [{_, E}] -> {true, E};
            [] -> false
        end
    end, ConflictTxids),

    %% 1. Check RBF signaling (unless full RBF is enabled)
    FullRbfEnabled = beamchain_config:mempool_full_rbf(),
    case FullRbfEnabled of
        true ->
            ok;  %% Full RBF: no signaling required
        false ->
            %% BIP 125: all conflicting txs must signal RBF
            lists:foreach(fun(E) ->
                E#mempool_entry.rbf_signaling orelse throw(rbf_not_signaled)
            end, ConflictEntries)
    end,

    %% 2. new tx must not add new unconfirmed parents (Rule 2)
    %% The replacement transaction may only include an unconfirmed input
    %% if that input was included in one of the original transactions.
    NewParents = get_parent_txids(NewTx),
    OldParents = lists:usort(lists:flatmap(fun(E) ->
        get_parent_txids(E#mempool_entry.tx)
    end, ConflictEntries)),
    NewUnconfirmed = NewParents -- OldParents -- ConflictTxids,
    NewUnconfirmed =:= [] orelse throw(rbf_new_unconfirmed_inputs),

    %% 3. collect all descendants of conflicting txs (Rule 5)
    %% Max 100 transactions can be evicted (conflicting txs + descendants)
    AllEvictTxids = lists:usort(lists:flatmap(fun(Cid) ->
        [Cid | get_all_descendants(Cid)]
    end, ConflictTxids)),
    length(AllEvictTxids) =< ?MAX_RBF_EVICTIONS
        orelse throw(rbf_too_many_evictions),

    AllEvictEntries = lists:filtermap(fun(Eid) ->
        case ets:lookup(?MEMPOOL_TXS, Eid) of
            [{_, E}] -> {true, E};
            [] -> false
        end
    end, AllEvictTxids),

    %% 4. new tx fee must be >= sum of all evicted fees (Rule 3)
    EvictedFeeTotal = lists:foldl(fun(E, Acc) ->
        Acc + E#mempool_entry.fee
    end, 0, AllEvictEntries),

    %% compute new tx fee from its inputs
    NewTotalIn = compute_tx_input_value(NewTx),
    NewTotalOut = lists:foldl(fun(#tx_out{value = V}, A) -> A + V end,
                               0, NewTx#transaction.outputs),
    NewFee = NewTotalIn - NewTotalOut,
    NewFee >= EvictedFeeTotal orelse throw(rbf_insufficient_fee),

    %% 5. additional fee must cover incremental relay fee for new tx (Rule 4)
    %% additional_fees >= relay_fee * new_tx_vsize
    %% incremental relay fee = 1 sat/vB
    NewVSize = beamchain_serialize:tx_vsize(NewTx),
    MinAdditionalFee = NewVSize,  %% 1 sat/vB * vsize
    (NewFee - EvictedFeeTotal) >= MinAdditionalFee
        orelse throw(rbf_insufficient_additional_fee),

    %% 6. new tx fee rate must be higher than all directly conflicting txs
    %% (additional check for fee rate, not just absolute fee)
    NewFeeRate = NewFee / max(1, NewVSize),
    lists:foreach(fun(E) ->
        NewFeeRate > E#mempool_entry.fee_rate
            orelse throw(rbf_insufficient_fee_rate)
    end, ConflictEntries),

    %% evict all conflicting txs + descendants
    lists:foreach(fun(EvictTxid) ->
        remove_entry(EvictTxid)
    end, AllEvictTxids),

    logger:debug("mempool: rbf evicted ~B txs (fullrbf=~p)",
                 [length(AllEvictTxids), FullRbfEnabled]),
    ok.

%% Sum the input values for a transaction (UTXO set + mempool).
compute_tx_input_value(#transaction{inputs = Inputs}) ->
    lists:foldl(
        fun(#tx_in{prev_out = #outpoint{hash = H, index = I}}, Acc) ->
            case beamchain_chainstate:get_utxo(H, I) of
                {ok, Coin} -> Acc + Coin#utxo.value;
                not_found ->
                    case get_mempool_utxo(H, I) of
                        {ok, Coin} -> Acc + Coin#utxo.value;
                        not_found -> Acc
                    end
            end
        end, 0, Inputs).

%% Get all descendant txids for a given mempool tx.
get_all_descendants(Txid) ->
    get_all_descendants([Txid], [], []).

get_all_descendants([], _Visited, Acc) ->
    Acc;
get_all_descendants([Txid | Rest], Visited, Acc) ->
    case lists:member(Txid, Visited) of
        true ->
            get_all_descendants(Rest, Visited, Acc);
        false ->
            Children = find_children(Txid),
            get_all_descendants(Children ++ Rest,
                                [Txid | Visited],
                                Children ++ Acc)
    end.

%% Find mempool txs that spend outputs of a given txid.
find_children(ParentTxid) ->
    case ets:lookup(?MEMPOOL_TXS, ParentTxid) of
        [{_, Entry}] ->
            NumOutputs = length((Entry#mempool_entry.tx)#transaction.outputs),
            lists:filtermap(fun(Vout) ->
                case ets:lookup(?MEMPOOL_OUTPOINTS, {ParentTxid, Vout}) of
                    [{_, ChildTxid}] -> {true, ChildTxid};
                    [] -> false
                end
            end, lists:seq(0, NumOutputs - 1));
        [] ->
            []
    end.

%%% ===================================================================
%%% Internal: dust check
%%% ===================================================================

check_dust(#transaction{outputs = Outputs}) ->
    lists:foreach(fun(#tx_out{value = Value, script_pubkey = SPK}) ->
        %% OP_RETURN outputs are allowed to be zero value
        case SPK of
            <<16#6a, _/binary>> -> ok;
            _ ->
                Threshold = dust_threshold(SPK),
                Value >= Threshold orelse throw(dust)
        end
    end, Outputs).

%% dust = (output_size + spend_input_size) * dust_relay_fee / 1000
dust_threshold(SPK) ->
    OutputSize = 8 + 1 + byte_size(SPK),
    SpendSize = spend_input_size(SPK),
    (OutputSize + SpendSize) * ?DUST_RELAY_TX_FEE div 1000.

spend_input_size(SPK) ->
    case classify_output(SPK) of
        p2pkh     -> 148;
        p2sh      -> 148;
        p2wpkh    -> 68;
        p2wsh     -> 68;
        p2tr      -> 58;
        _unknown  -> 148
    end.

classify_output(<<16#76, 16#a9, 16#14, _:20/binary, 16#88, 16#ac>>) ->
    p2pkh;
classify_output(<<16#a9, 16#14, _:20/binary, 16#87>>) ->
    p2sh;
classify_output(<<16#00, 16#14, _:20/binary>>) ->
    p2wpkh;
classify_output(<<16#00, 16#20, _:32/binary>>) ->
    p2wsh;
classify_output(<<16#51, 16#20, _:32/binary>>) ->
    p2tr;
classify_output(_) ->
    unknown.

%%% ===================================================================
%%% Internal: script verification
%%% ===================================================================

verify_scripts(Tx, InputCoins) ->
    Flags = all_standard_flags(),
    Inputs = Tx#transaction.inputs,
    AllPrevOuts = [{C#utxo.value, C#utxo.script_pubkey} || C <- InputCoins],
    lists:foldl(fun({Input, Coin}, Idx) ->
        ScriptSig = Input#tx_in.script_sig,
        ScriptPubKey = Coin#utxo.script_pubkey,
        Witness = Input#tx_in.witness,
        Amount = Coin#utxo.value,
        SigChecker = {Tx, Idx, Amount, AllPrevOuts},
        case beamchain_script:verify_script(
                ScriptSig, ScriptPubKey, Witness, Flags, SigChecker) of
            true -> ok;
            false -> throw({script_verify_failed, Idx})
        end,
        Idx + 1
    end, 0, lists:zip(Inputs, InputCoins)),
    ok.

all_standard_flags() ->
    ?SCRIPT_VERIFY_P2SH bor
    ?SCRIPT_VERIFY_STRICTENC bor
    ?SCRIPT_VERIFY_DERSIG bor
    ?SCRIPT_VERIFY_LOW_S bor
    ?SCRIPT_VERIFY_NULLDUMMY bor
    ?SCRIPT_VERIFY_MINIMALDATA bor
    ?SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS bor
    ?SCRIPT_VERIFY_CLEANSTACK bor
    ?SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY bor
    ?SCRIPT_VERIFY_CHECKSEQUENCEVERIFY bor
    ?SCRIPT_VERIFY_WITNESS bor
    ?SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM bor
    ?SCRIPT_VERIFY_MINIMALIF bor
    ?SCRIPT_VERIFY_NULLFAIL bor
    ?SCRIPT_VERIFY_WITNESS_PUBKEYTYPE bor
    ?SCRIPT_VERIFY_CONST_SCRIPTCODE bor
    ?SCRIPT_VERIFY_TAPROOT.

%%% ===================================================================
%%% Internal: coinbase maturity check
%%% ===================================================================

check_mempool_coinbase_maturity(InputCoins, NextHeight) ->
    lists:foreach(fun(Coin) ->
        case Coin#utxo.is_coinbase of
            true ->
                Confs = NextHeight - Coin#utxo.height,
                Confs >= ?COINBASE_MATURITY
                    orelse throw(premature_spend_of_coinbase);
            false -> ok
        end
    end, InputCoins).

%%% ===================================================================
%%% Internal: BIP 68 sequence lock check for mempool
%%% ===================================================================

%% @doc Check BIP 68 sequence locks for mempool acceptance.
%% For mempool, we check if the tx would satisfy sequence locks in the next block.
check_mempool_sequence_locks(#transaction{version = Version}, _InputCoins,
                             _TipHash, _NextHeight) when Version < 2 ->
    %% BIP 68 only applies to tx version >= 2
    ok;
check_mempool_sequence_locks(Tx, InputCoins, TipHash, NextHeight) ->
    %% Get the tip block index to compute MTP
    TipIndex = case beamchain_db:get_block_index_by_hash(TipHash) of
        {ok, TI} -> TI;
        not_found -> throw(missing_tip_index)
    end,
    %% Calculate sequence lock pair for the next block
    {MinHeight, MinTime} = beamchain_validation:calculate_sequence_lock_pair(
        Tx, InputCoins, TipIndex),
    %% Get the MTP of the current tip (which is pprev for the next block)
    MTP = beamchain_validation:median_time_past(TipIndex),
    %% Check if locks are satisfied for the next block
    case MinHeight >= NextHeight of
        true -> throw(sequence_lock_not_met);
        false -> ok
    end,
    case MinTime >= MTP of
        true -> throw(sequence_lock_not_met);
        false -> ok
    end.

%%% ===================================================================
%%% Internal: ancestor / descendant tracking
%%% ===================================================================

%% Compute ancestor stats for a new transaction.
compute_ancestors(#transaction{inputs = Inputs}, Fee, VSize) ->
    ParentTxids = get_parent_txids_from_inputs(Inputs),
    lists:foldl(
        fun(ParentTxid, {AC, AS, AF}) ->
            case ets:lookup(?MEMPOOL_TXS, ParentTxid) of
                [{_, Parent}] ->
                    {AC + Parent#mempool_entry.ancestor_count,
                     AS + Parent#mempool_entry.ancestor_size,
                     AF + Parent#mempool_entry.ancestor_fee};
                [] ->
                    {AC, AS, AF}
            end
        end,
        {1, VSize, Fee},
        ParentTxids).

%% Update each ancestor's descendant stats when a new tx is added.
update_ancestors_for_new_tx(#transaction{inputs = Inputs}, VSize, Fee) ->
    ParentTxids = get_parent_txids_from_inputs(Inputs),
    update_ancestor_descendants(ParentTxids, VSize, Fee, add, []).

%% Update each ancestor's descendant stats when a tx is removed.
update_ancestors_for_removed_tx(#transaction{inputs = Inputs}, VSize, Fee) ->
    ParentTxids = get_parent_txids_from_inputs(Inputs),
    update_ancestor_descendants(ParentTxids, VSize, Fee, remove, []).

update_ancestor_descendants([], _VSize, _Fee, _Op, _Visited) ->
    ok;
update_ancestor_descendants([Txid | Rest], VSize, Fee, Op, Visited) ->
    case lists:member(Txid, Visited) of
        true ->
            update_ancestor_descendants(Rest, VSize, Fee, Op, Visited);
        false ->
            case ets:lookup(?MEMPOOL_TXS, Txid) of
                [{Txid, Entry}] ->
                    Updated = case Op of
                        add ->
                            Entry#mempool_entry{
                                descendant_count = Entry#mempool_entry.descendant_count + 1,
                                descendant_size = Entry#mempool_entry.descendant_size + VSize,
                                descendant_fee = Entry#mempool_entry.descendant_fee + Fee
                            };
                        remove ->
                            Entry#mempool_entry{
                                descendant_count = max(1, Entry#mempool_entry.descendant_count - 1),
                                descendant_size = max(Entry#mempool_entry.vsize,
                                                      Entry#mempool_entry.descendant_size - VSize),
                                descendant_fee = max(Entry#mempool_entry.fee,
                                                     Entry#mempool_entry.descendant_fee - Fee)
                            }
                    end,
                    ets:insert(?MEMPOOL_TXS, {Txid, Updated}),
                    Parents = get_parent_txids(Entry#mempool_entry.tx),
                    update_ancestor_descendants(Parents ++ Rest, VSize, Fee, Op,
                                                [Txid | Visited]);
                [] ->
                    update_ancestor_descendants(Rest, VSize, Fee, Op, Visited)
            end
    end.

%% Check that adding a new tx won't bust any ancestor's descendant limits.
%% VSize is the vsize of the new transaction being added.
check_descendant_limits(#transaction{inputs = Inputs}, VSize) ->
    ParentTxids = get_parent_txids_from_inputs(Inputs),
    check_desc_limits_walk(ParentTxids, VSize, []).

check_desc_limits_walk([], _VSize, _Visited) ->
    ok;
check_desc_limits_walk([Txid | Rest], VSize, Visited) ->
    case lists:member(Txid, Visited) of
        true ->
            check_desc_limits_walk(Rest, VSize, Visited);
        false ->
            case ets:lookup(?MEMPOOL_TXS, Txid) of
                [{_, Entry}] ->
                    %% Check if adding this tx would exceed descendant count limit
                    (Entry#mempool_entry.descendant_count + 1) =<
                        ?MAX_DESCENDANT_COUNT
                        orelse throw(too_long_mempool_chain),
                    %% Check if adding this tx would exceed descendant size limit
                    %% Must include the new tx's vsize in the check
                    (Entry#mempool_entry.descendant_size + VSize) =<
                        ?MAX_DESCENDANT_SIZE
                        orelse throw(too_long_mempool_chain),
                    Parents = get_parent_txids(Entry#mempool_entry.tx),
                    check_desc_limits_walk(Parents ++ Rest, VSize, [Txid | Visited]);
                [] ->
                    check_desc_limits_walk(Rest, VSize, Visited)
            end
    end.

%% Get unique list of mempool parent txids from input list.
get_parent_txids_from_inputs(Inputs) ->
    lists:usort(lists:filtermap(
        fun(#tx_in{prev_out = #outpoint{hash = H}}) ->
            case ets:member(?MEMPOOL_TXS, H) of
                true -> {true, H};
                false -> false
            end
        end, Inputs)).

get_parent_txids(#transaction{inputs = Inputs}) ->
    get_parent_txids_from_inputs(Inputs).

%%% ===================================================================
%%% Internal: orphan pool
%%% ===================================================================

add_orphan(Tx, Txid) ->
    OrphanCount = ets:info(?MEMPOOL_ORPHANS, size),
    case OrphanCount < ?MAX_ORPHAN_TXS of
        true ->
            Expiry = erlang:system_time(second) + ?ORPHAN_TX_EXPIRE_TIME,
            ets:insert(?MEMPOOL_ORPHANS, {Txid, Tx, Expiry}),
            logger:debug("mempool: added orphan ~s (~B total)",
                         [short_hex(Txid), OrphanCount + 1]);
        false ->
            %% evict a random orphan to make room
            case ets:first(?MEMPOOL_ORPHANS) of
                '$end_of_table' -> ok;
                OldTxid ->
                    ets:delete(?MEMPOOL_ORPHANS, OldTxid)
            end,
            Expiry = erlang:system_time(second) + ?ORPHAN_TX_EXPIRE_TIME,
            ets:insert(?MEMPOOL_ORPHANS, {Txid, Tx, Expiry})
    end.

%% Attempt to re-process orphans whose missing parent might now exist.
reprocess_orphans(NewTxid) ->
    Orphans = ets:tab2list(?MEMPOOL_ORPHANS),
    lists:foreach(fun({OrphanTxid, OrphanTx, _Expiry}) ->
        HasParent = lists:any(
            fun(#tx_in{prev_out = #outpoint{hash = H}}) ->
                H =:= NewTxid
            end,
            OrphanTx#transaction.inputs),
        case HasParent of
            true ->
                ets:delete(?MEMPOOL_ORPHANS, OrphanTxid),
                case add_transaction(OrphanTx) of
                    {ok, _} ->
                        logger:debug("mempool: promoted orphan ~s",
                                     [short_hex(OrphanTxid)]);
                    {error, _} ->
                        ok
                end;
            false ->
                ok
        end
    end, Orphans).

%%% ===================================================================
%%% Internal: entry management
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
            VSize = Entry#mempool_entry.vsize,
            Fee = Entry#mempool_entry.fee,
            FeeRate = Entry#mempool_entry.fee_rate,
            %% Update ancestor descendant stats before removing
            update_ancestors_for_removed_tx(Tx, VSize, Fee),
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
    %% 1. remove confirmed transactions
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

    %% 2. remove any mempool txs that conflict with the block
    %%    (their inputs were spent by block transactions)
    {ConflictBytes, ConflictCount} = remove_block_conflicts(Txids),

    TotalBytes = RemovedBytes + ConflictBytes,
    TotalCount = RemovedCount + ConflictCount,
    case TotalCount > 0 of
        true ->
            logger:debug("mempool: removed ~B txs for block (~B confirmed, "
                         "~B conflicts)", [TotalCount, RemovedCount, ConflictCount]);
        false -> ok
    end,
    State#state{
        total_bytes = max(0, State#state.total_bytes - TotalBytes),
        total_count = max(0, State#state.total_count - TotalCount)
    }.

%% After confirming block transactions, check if any remaining mempool
%% transactions now double-spend a confirmed output. Remove them.
remove_block_conflicts(ConfirmedTxids) ->
    %% Build set of outpoints spent by confirmed txs
    %% For each confirmed txid, its outputs are now in the UTXO set,
    %% and any mempool tx spending the same inputs as a confirmed tx
    %% is now invalid.
    ConfSet = sets:from_list(ConfirmedTxids),
    AllEntries = ets:tab2list(?MEMPOOL_TXS),
    lists:foldl(fun({Txid, Entry}, {Bytes, Count}) ->
        %% skip if we already removed it
        case sets:is_element(Txid, ConfSet) of
            true -> {Bytes, Count};
            false ->
                %% check if any input's previous output was just confirmed
                HasConflict = lists:any(
                    fun(#tx_in{prev_out = #outpoint{hash = H}}) ->
                        sets:is_element(H, ConfSet)
                    end,
                    (Entry#mempool_entry.tx)#transaction.inputs),
                case HasConflict of
                    true ->
                        %% remove this tx and its descendants
                        Desc = get_all_descendants(Txid),
                        AllRemove = [Txid | Desc],
                        lists:foldl(fun(RTxid, {B, C}) ->
                            case remove_entry(RTxid) of
                                #mempool_entry{vsize = VS} -> {B + VS, C + 1};
                                not_found -> {B, C}
                            end
                        end, {Bytes, Count}, AllRemove);
                    false ->
                        {Bytes, Count}
                end
        end
    end, {0, 0}, AllEntries).

%%% ===================================================================
%%% Internal: trimming / eviction (stub)
%%% ===================================================================

%% Remove lowest fee-rate transactions until total size fits.
do_trim_to_size(MaxBytes, State) ->
    case State#state.total_bytes =< MaxBytes of
        true ->
            State;
        false ->
            case ets:first(?MEMPOOL_BY_FEE) of
                '$end_of_table' ->
                    State;
                {_FeeRate, Txid} ->
                    %% remove this tx and all its descendants
                    Desc = get_all_descendants(Txid),
                    AllRemove = [Txid | Desc],
                    {RemovedBytes, RemovedCount} = lists:foldl(
                        fun(RTxid, {Bytes, Count}) ->
                            case remove_entry(RTxid) of
                                #mempool_entry{vsize = VSize} ->
                                    {Bytes + VSize, Count + 1};
                                not_found ->
                                    {Bytes, Count}
                            end
                        end, {0, 0}, AllRemove),
                    State2 = State#state{
                        total_bytes = max(0, State#state.total_bytes - RemovedBytes),
                        total_count = max(0, State#state.total_count - RemovedCount)
                    },
                    do_trim_to_size(MaxBytes, State2)
            end
    end.

%% Expire transactions older than 14 days (336 hours).
do_expire_old(State) ->
    CutoffTime = erlang:system_time(second) - (?MEMPOOL_EXPIRY_HOURS * 3600),
    AllEntries = ets:tab2list(?MEMPOOL_TXS),
    {ExpiredCount, ExpiredBytes} = lists:foldl(
        fun({Txid, Entry}, {Count, Bytes}) ->
            case Entry#mempool_entry.time_added < CutoffTime of
                true ->
                    remove_entry(Txid),
                    {Count + 1, Bytes + Entry#mempool_entry.vsize};
                false ->
                    {Count, Bytes}
            end
        end,
        {0, 0},
        AllEntries),
    case ExpiredCount > 0 of
        true ->
            logger:debug("mempool: expired ~B old txs (~B vB)",
                         [ExpiredCount, ExpiredBytes]);
        false -> ok
    end,
    State2 = State#state{
        total_bytes = max(0, State#state.total_bytes - ExpiredBytes),
        total_count = max(0, State#state.total_count - ExpiredCount)
    },
    {ExpiredCount, State2}.

do_expire_orphans() ->
    Now = erlang:system_time(second),
    Orphans = ets:tab2list(?MEMPOOL_ORPHANS),
    Expired = lists:foldl(fun({Txid, _Tx, Expiry}, Count) ->
        case Now >= Expiry of
            true ->
                ets:delete(?MEMPOOL_ORPHANS, Txid),
                Count + 1;
            false ->
                Count
        end
    end, 0, Orphans),
    case Expired > 0 of
        true ->
            logger:debug("mempool: expired ~B orphans", [Expired]);
        false -> ok
    end.

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
