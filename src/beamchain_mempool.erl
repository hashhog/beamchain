-module(beamchain_mempool).
-behaviour(gen_server).

%% Transaction memory pool — holds unconfirmed transactions with
%% fee-rate ordering, ancestor/descendant tracking, and RBF support.

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% Dialyzer suppressions for false positives:
%% interpolate_diagram/2: empty-list base case is defensive; dialyzer infers
%% the argument is always non-empty from call sites.
-dialyzer({nowarn_function, interpolate_diagram/2}).

%% API
-export([start_link/0]).

%% Transaction submission
-export([accept_to_memory_pool/1, add_transaction/1, accept_package/1]).

%% Queries
-export([has_tx/1, get_tx/1, get_entry/1]).
-export([get_all_txids/0, get_all_entries/0, get_all_id_pairs/0, get_info/0]).
-export([get_sorted_by_fee/0]).
-export([get_tx_fee_rate/1]).
-export([get_ancestors/1, get_descendants/1]).

%% Block interaction
-export([remove_for_block/1]).

%% Maintenance
-export([trim_to_size/1, expire_old/0]).

%% Persistence (Bitcoin Core mempool.dat compatible)
-export([dump_mempool/0, load_mempool/0, get_persistable_entries/0]).

%% UTXO lookups (called externally from validation)
-export([get_mempool_utxo/2]).

%% Cluster mempool API
-export([get_cluster/1, get_cluster_txids/1, get_cluster_linearization/1]).
-export([get_mining_order/0, get_all_clusters/0]).
-export([linearize_cluster/1]).  %% Exported for testing
-export([uf_union/3, uf_get_cluster_members/2]).  %% Union-find utilities for debugging

%% TRUC (v3 transaction) policy checks - exported for testing
-export([check_truc_rules/3]).

%% Ephemeral anchor policy - exported for testing
-export([check_dust/2, find_ephemeral_anchor/2]).

%% Output standardness classifier and check_standard - exported for testing
-export([classify_output_standard/1, check_standard/1]).

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
-define(MAX_CLUSTER_SIZE, 100).            % Max transactions per cluster

%%% -------------------------------------------------------------------
%%% ETS table names
%%% -------------------------------------------------------------------

-define(MEMPOOL_TXS, mempool_txs).           %% txid -> mempool_entry
-define(MEMPOOL_BY_FEE, mempool_by_fee).     %% ordered {fee_rate, txid}
-define(MEMPOOL_OUTPOINTS, mempool_outpoints). %% {txid, vout} -> spending_txid
-define(MEMPOOL_ORPHANS, mempool_orphans).   %% txid -> {tx, expiry}
-define(MEMPOOL_CLUSTERS, mempool_clusters). %% cluster_id -> cluster_data
-define(MEMPOOL_EPHEMERAL, mempool_ephemeral). %% {parent_txid, anchor_index} -> child_txid

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
%%% Cluster mempool data structures
%%% -------------------------------------------------------------------

%% Cluster data stored in ETS: cluster_id -> cluster_data record
-record(cluster_data, {
    id            :: binary(),             %% cluster identifier (txid of first tx)
    txids         :: [binary()],           %% list of txids in this cluster
    total_fee     :: non_neg_integer(),    %% sum of all fees
    total_vsize   :: non_neg_integer(),    %% sum of all vsizes
    linearization :: [binary()],           %% ordered txids (highest feerate prefix first)
    fee_rate      :: float()               %% aggregate fee rate (total_fee / total_vsize)
}).

%%% -------------------------------------------------------------------
%%% gen_server state
%%% -------------------------------------------------------------------

-record(state, {
    max_size       :: non_neg_integer(),   %% max mempool bytes
    total_bytes    :: non_neg_integer(),   %% current total vbytes
    total_count    :: non_neg_integer(),   %% number of transactions
    %% Union-find: txid -> cluster_id (root txid of cluster)
    union_find     :: map(),               %% txid -> parent_txid (for find)
    cluster_count  :: non_neg_integer(),   %% number of clusters
    zmq_seq        :: non_neg_integer()    %% ZMQ sequence number for mempool events
}).

%%% ===================================================================
%%% API
%%% ===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc AcceptToMemoryPool — canonical entry point matching Bitcoin Core naming.
%% Validates and adds a transaction to the mempool with all policy checks
%% including BIP125 RBF, fee-rate validation, script verification, and
%% cluster mempool limits.
-spec accept_to_memory_pool(#transaction{}) -> {ok, binary()} | {error, term()}.
accept_to_memory_pool(Tx) ->
    add_transaction(Tx).

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

%% @doc Get the fee rate for a transaction in sat/kvB (for BIP133 feefilter).
-spec get_tx_fee_rate(binary()) -> {ok, non_neg_integer()} | not_found.
get_tx_fee_rate(Txid) ->
    case ets:lookup(?MEMPOOL_TXS, Txid) of
        [{Txid, Entry}] ->
            %% fee_rate is in sat/vB, convert to sat/kvB (* 1000)
            FeeRateKvB = round(Entry#mempool_entry.fee_rate * 1000),
            {ok, FeeRateKvB};
        [] ->
            not_found
    end.

%% @doc Get all txids currently in the mempool.
-spec get_all_txids() -> [binary()].
get_all_txids() ->
    [Txid || {Txid, _} <- ets:tab2list(?MEMPOOL_TXS)].

%% @doc Get all entries currently in the mempool.
-spec get_all_entries() -> [#mempool_entry{}].
get_all_entries() ->
    [Entry || {_Txid, Entry} <- ets:tab2list(?MEMPOOL_TXS)].

%% @doc Get all (txid, wtxid) pairs currently in the mempool.
%% Used by the BIP35 mempool-message handler in beamchain_peer_manager
%% to build an inv response without leaking the full #mempool_entry{}
%% record across module boundaries.
-spec get_all_id_pairs() -> [{binary(), binary()}].
get_all_id_pairs() ->
    [{E#mempool_entry.txid, E#mempool_entry.wtxid}
     || {_Txid, E} <- ets:tab2list(?MEMPOOL_TXS)].

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

%% @doc Dump the current mempool to <datadir>/mempool.dat (Bitcoin
%% Core-compatible binary format). Synchronous; safe to call from RPC
%% or shutdown.
-spec dump_mempool() -> {ok, non_neg_integer()} | {error, term()}.
dump_mempool() ->
    beamchain_mempool_persist:dump().

%% @doc Load <datadir>/mempool.dat and re-submit its transactions to the
%% running mempool. Returns a stats map: #{accepted, expired, failed,
%% already, total}.
-spec load_mempool() -> {ok, map()} | {error, term()}.
load_mempool() ->
    beamchain_mempool_persist:load().

%% @doc Snapshot the current mempool as `[{#transaction{}, Time}]` for
%% the persist module. Hides the private #mempool_entry{} record from
%% callers so they don't need an `-include` of beamchain_mempool's
%% internals.
-spec get_persistable_entries() -> [{#transaction{}, integer()}].
get_persistable_entries() ->
    [{E#mempool_entry.tx, E#mempool_entry.time_added}
     || {_Txid, E} <- ets:tab2list(?MEMPOOL_TXS)].

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
    ets:new(?MEMPOOL_CLUSTERS, [set, public, named_table,
                                 {read_concurrency, true}]),
    ets:new(?MEMPOOL_EPHEMERAL, [set, public, named_table]),

    %% Schedule periodic orphan expiry
    erlang:send_after(60000, self(), expire_orphans),

    %% Defer mempool.dat load until after the supervision tree has
    %% finished booting (chainstate, sig cache, etc.). 5s is generous
    %% but well below any user-visible RPC latency, and keeps the
    %% startup path identical for fresh datadirs (no file = no-op).
    erlang:send_after(5000, self(), load_persisted),

    logger:info("mempool: initialized"),
    {ok, #state{
        max_size = ?DEFAULT_MAX_MEMPOOL_SIZE,
        total_bytes = 0,
        total_count = 0,
        union_find = #{},
        cluster_count = 0,
        zmq_seq = 0
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

handle_call({get_cluster, Txid}, _From, #state{union_find = UF} = State) ->
    case maps:is_key(Txid, UF) of
        true ->
            {Root, UF2} = uf_find(Txid, UF),
            {reply, {ok, Root}, State#state{union_find = UF2}};
        false ->
            {reply, not_found, State}
    end;

handle_call(_Request, _From, State) ->
    {reply, {error, not_implemented}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(expire_orphans, State) ->
    do_expire_orphans(),
    erlang:send_after(60000, self(), expire_orphans),
    {noreply, State};

handle_info(load_persisted, State) ->
    %% Best-effort: missing file is normal on a fresh datadir.
    case beamchain_mempool_persist:load() of
        {ok, Stats} ->
            logger:info("mempool: loaded mempool.dat ~p", [Stats]);
        {error, no_file} ->
            ok;
        {error, Reason} ->
            logger:warning("mempool: load failed: ~p", [Reason])
    end,
    {noreply, State};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    Size = ets:info(?MEMPOOL_TXS, size),
    %% Persist mempool.dat on graceful shutdown so we can warm-restart
    %% with the same set of unconfirmed txs (matches Bitcoin Core).
    case Size > 0 of
        true ->
            try beamchain_mempool_persist:dump() of
                {ok, N} ->
                    logger:info("mempool: dumped ~B txs to mempool.dat", [N]);
                {error, R} ->
                    logger:warning("mempool: dump failed: ~p", [R])
            catch
                Class:Err ->
                    logger:warning("mempool: dump crashed: ~p:~p",
                                   [Class, Err])
            end;
        false ->
            ok
    end,
    logger:info("mempool: shutting down (~B transactions)", [Size]),
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

        %% 3b. IsFinalTx (BIP-113): reject non-final transactions at mempool admit.
        %% Mempool holds txs for the *next* block, so we check against height+1 and
        %% the current chain MTP (MEDIAN_TIME_PAST of the last 11 blocks) per BIP-113.
        %% Mirrors Bitcoin Core MemPoolAccept::PreChecks → CheckFinalTxAtTip.
        {ok, {TipHash, TipHeight}} = beamchain_chainstate:get_tip(),
        Mtp = beamchain_chainstate:get_mtp(),
        beamchain_validation:is_final_tx(Tx, TipHeight + 1, Mtp)
            orelse throw(non_final),

        %% 4. look up all inputs (UTXO set + mempool)
        {InputCoins, SpendsCoinbase} = lookup_inputs(Tx),

        %% 5. check for double-spends in mempool (+ RBF)
        %% Returns {ok, EvictedTxids, EvictedVBytes} - store for cluster cleanup later
        {ok, RbfEvictedTxids, RbfEvictedVBytes} = check_mempool_conflicts(Tx, InputCoins),

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

        %% 8. check dust outputs (with ephemeral anchor support)
        %% This returns {has_ephemeral, Index} if tx is an ephemeral anchor parent
        EphemeralInfo = check_dust(Tx, Fee),

        %% 9. check minimum relay fee (1 sat/vB)
        %% Ephemeral anchor parents are allowed to have 0 fee, but need package
        case EphemeralInfo of
            {has_ephemeral, _} ->
                %% Zero-fee tx with ephemeral anchor - must be spent in package
                throw(ephemeral_anchor_needs_spending);
            none ->
                FeeRate >= 1.0 orelse throw(mempool_min_fee_not_met)
        end,

        %% 10. verify scripts
        verify_scripts(Tx, InputCoins),

        %% 10b. TRUC (v3 transaction) policy checks
        MempoolParentTxids = get_parent_txids(Tx),
        {TrucEvictedTxids, TrucEvictedVBytes} = case check_truc_rules(Tx, VSize, MempoolParentTxids) of
            ok ->
                {[], 0};
            {sibling_eviction, SiblingTxid} ->
                %% v3 sibling eviction - new child replaces existing child
                case do_truc_sibling_eviction(SiblingTxid, Tx, Fee) of
                    {ok, Evicted, EvictedVB} -> {Evicted, EvictedVB};
                    {error, TrucErr} -> throw(TrucErr)
                end;
            {error, TrucErr} ->
                throw(TrucErr)
        end,

        %% 11. ancestor/descendant limits
        {AncCount, AncSize, AncFee} = compute_ancestors(Tx, Fee, VSize),
        AncCount =< ?MAX_ANCESTOR_COUNT orelse throw(too_long_mempool_chain),
        AncSize =< ?MAX_ANCESTOR_SIZE orelse throw(too_long_mempool_chain),
        check_descendant_limits(Tx, VSize),

        %% 12. check coinbase maturity for mempool spending
        %% TipHash and TipHeight were already fetched at step 3b above.
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

        %% 16. clean up clusters for evicted transactions (RBF + TRUC sibling)
        AllEvictedTxids = RbfEvictedTxids ++ TrucEvictedTxids,
        AllEvictedVBytes = RbfEvictedVBytes + TrucEvictedVBytes,
        State2 = lists:foldl(fun(EvictedTxid, St) ->
            cluster_remove_tx(EvictedTxid, St)
        end, State, AllEvictedTxids),

        %% 17. update cluster membership for new tx
        State3 = cluster_add_tx(Txid, Tx, Fee, VSize, State2),

        %% 18. update state totals (subtract evicted vbytes, add new tx)
        State4 = State3#state{
            total_bytes = State3#state.total_bytes + VSize - AllEvictedVBytes,
            total_count = State3#state.total_count + 1 - length(AllEvictedTxids)
        },

        %% 19. check if any orphans now have parents
        reprocess_orphans(Txid),

        %% 20. ZMQ notification for mempool acceptance
        ZmqSeq = State4#state.zmq_seq,
        beamchain_zmq:notify_transaction(Tx, mempool_add, ZmqSeq),
        State5 = State4#state{zmq_seq = ZmqSeq + 1},

        logger:debug("mempool: accepted ~s (fee_rate=~.1f sat/vB, ~B vB)",
                     [short_hex(Txid), FeeRate, VSize]),
        {ok, Txid, State5}
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
                {error, ephemeral_anchor_needs_spending} ->
                    %% Ephemeral anchor parent - must be spent by child in package
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

    %% Check ephemeral anchor spends - all dust must be spent by children
    EphemeralDeps = check_ephemeral_spends(TxEntries, PackageTxMap),

    %% Check for package RBF
    AllConflicts = find_all_package_conflicts(DeferredTxs),
    case AllConflicts of
        [] ->
            ok;
        _ ->
            do_package_rbf(DeferredTxs, TotalFee, TotalVSize, AllConflicts)
    end,

    %% Accept all deferred transactions
    State2 = accept_package_txs(TxEntries, EphemeralDeps, State),

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

%% @doc Check that all ephemeral anchor dust is spent by children in the package.
%% Returns a list of {ParentTxid, AnchorIndex, ChildTxid} tuples for tracking.
check_ephemeral_spends(TxEntries, PackageTxMap) ->
    %% Build a map of txid -> Entry for fee lookup
    EntryMap = maps:from_list([{Txid, Entry} || {Txid, _Tx, Entry, _Coins} <- TxEntries]),

    %% For each tx in package, check if its parents have dust that needs spending
    lists:foldl(fun({Txid, Tx, _Entry, _Coins}, DepsAcc) ->
        %% Get all inputs (outpoints this tx spends)
        InputOutpoints = [{In#tx_in.prev_out#outpoint.hash,
                           In#tx_in.prev_out#outpoint.index}
                          || In <- Tx#transaction.inputs],

        %% For each parent in package, check for unspent dust
        ParentTxids = lists:usort([H || {H, _I} <- InputOutpoints,
                                        maps:is_key(H, PackageTxMap)]),

        lists:foldl(fun(ParentTxid, InnerAcc) ->
            ParentTx = maps:get(ParentTxid, PackageTxMap),
            ParentFee = case maps:get(ParentTxid, EntryMap, undefined) of
                undefined -> undefined;
                E -> E#mempool_entry.fee
            end,
            %% Find ephemeral anchors in parent
            case find_ephemeral_anchor(ParentTx, ParentFee) of
                {has_ephemeral, AnchorIdx} ->
                    %% Check if this child spends the anchor
                    case lists:member({ParentTxid, AnchorIdx}, InputOutpoints) of
                        true ->
                            [{ParentTxid, AnchorIdx, Txid} | InnerAcc];
                        false ->
                            throw({ephemeral_anchor_not_spent, ParentTxid, AnchorIdx, Txid})
                    end;
                none ->
                    InnerAcc
            end
        end, DepsAcc, ParentTxids)
    end, [], TxEntries).

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
    DescendantsAndSelf = lists:usort(lists:flatmap(fun(Cid) ->
        [Cid | get_all_descendants(Cid)]
    end, ConflictTxids)),

    %% Also include ephemeral anchor parents whose dust is no longer spent
    EphemeralParents = lists:usort(lists:flatmap(fun(EvictTxid) ->
        find_orphaned_ephemeral_parents(EvictTxid)
    end, DescendantsAndSelf)),

    AllEvictTxids = lists:usort(DescendantsAndSelf ++ EphemeralParents),
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
accept_package_txs(TxEntries, EphemeralDeps, State) ->
    %% Build package map for TRUC checks
    PackageTxMap = [{Txid, Tx} || {Txid, Tx, _Entry, _Coins} <- TxEntries],

    %% Register ephemeral anchor dependencies
    %% EphemeralDeps = [{ParentTxid, AnchorIndex, ChildTxid}, ...]
    lists:foreach(fun({ParentTxid, AnchorIdx, ChildTxid}) ->
        ets:insert(?MEMPOOL_EPHEMERAL, {{ParentTxid, AnchorIdx}, ChildTxid})
    end, EphemeralDeps),

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

        %% TRUC checks for package transactions
        MempoolParentTxids = get_parent_txids(Tx),
        case check_truc_package_rules(Tx, VSize, PackageTxMap, MempoolParentTxids) of
            ok -> ok;
            {error, TrucErr} -> throw(TrucErr)
        end,

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

        %% Update cluster membership
        St2 = cluster_add_tx(Txid, Tx, Fee, VSize, St),

        %% Reprocess orphans
        reprocess_orphans(Txid),

        St2#state{
            total_bytes = St2#state.total_bytes + VSize,
            total_count = St2#state.total_count + 1
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

check_standard(#transaction{version = V, inputs = Inputs, outputs = Outputs} = Tx) ->
    %% version must be 1, 2, or 3 (v3 = TRUC)
    %% mirrors Bitcoin Core TX_MIN_STANDARD_VERSION / TX_MAX_STANDARD_VERSION
    (V =:= 1 orelse V =:= 2 orelse V =:= 3) orelse throw(version),
    %% weight limit — mirrors Bitcoin Core MAX_STANDARD_TX_WEIGHT
    Weight = beamchain_serialize:tx_weight(Tx),
    Weight =< ?MAX_STANDARD_TX_WEIGHT orelse throw(tx_size),
    %% input scriptSig checks — mirrors Bitcoin Core IsStandardTx input loop:
    %%   (1) scriptSig size <= MAX_STANDARD_SCRIPTSIG_SIZE (1650 bytes)
    %%   (2) scriptSig must be push-only
    lists:foreach(fun(#tx_in{script_sig = SS}) ->
        byte_size(SS) =< ?MAX_STANDARD_SCRIPTSIG_SIZE orelse throw(scriptsig_size),
        beamchain_script:is_push_only(SS) orelse throw(scriptsig_not_pushonly)
    end, Inputs),
    %% output standardness + datacarrier budget — mirrors Bitcoin Core IsStandardTx output loop:
    %%   (1) each output scriptPubKey must be standard (nonstandard → reject)
    %%   (2) OP_RETURN (nulldata) outputs consume from MAX_OP_RETURN_RELAY budget
    %%   The W56-fixed OP_RETURN classifier: remainder after 0x6a must be push-only;
    %%   if not, it is nonstandard (matching Core's Solver / IsPushOnly gate).
    DatacarrierLeft = lists:foldl(fun(#tx_out{script_pubkey = SPK}, Budget) ->
        case classify_output_standard(SPK) of
            op_return ->
                Size = byte_size(SPK),
                Size =< Budget orelse throw(datacarrier),
                Budget - Size;
            nonstandard ->
                throw(scriptpubkey);
            _Known ->
                Budget
        end
    end, ?MAX_OP_RETURN_RELAY, Outputs),
    _ = DatacarrierLeft,
    ok.

%% @doc Classify a scriptPubKey for mempool standardness, applying the
%% W56 push-only gate for OP_RETURN outputs (mirrors Bitcoin Core Solver).
%%   <<16#6a, Rest/binary>> is NULL_DATA only if Rest is entirely push opcodes.
%%   A truncated or non-push remainder makes it NONSTANDARD.
classify_output_standard(<<16#6a, Rest/binary>>) ->
    case beamchain_script:is_push_only(Rest) of
        true  -> op_return;
        false -> nonstandard
    end;
classify_output_standard(<<16#76, 16#a9, 16#14, _:20/binary, 16#88, 16#ac>>) -> p2pkh;
classify_output_standard(<<16#a9, 16#14, _:20/binary, 16#87>>)               -> p2sh;
classify_output_standard(<<16#00, 16#14, _:20/binary>>)                       -> p2wpkh;
classify_output_standard(<<16#00, 16#20, _:32/binary>>)                       -> p2wsh;
classify_output_standard(<<16#51, 16#20, _:32/binary>>)                       -> p2tr;
classify_output_standard(<<16#51, 16#02, 16#4e, 16#73>>)                      -> p2a;
%% Future witness versions (v2..v16, programs 2..40 bytes) are standard per Core
classify_output_standard(<<WitVer:8, Len:8, _:Len/binary>>)
  when (WitVer >= 16#51 andalso WitVer =< 16#60), (Len >= 2 andalso Len =< 40) ->
    {witness, WitVer - 16#50};
classify_output_standard(_) -> nonstandard.

%%% ===================================================================
%%% Internal: mempool conflict detection + RBF
%%% ===================================================================

check_mempool_conflicts(Tx, _InputCoins) ->
    case find_mempool_conflicts(Tx) of
        [] ->
            {ok, [], 0};
        ConflictTxids ->
            %% attempt RBF (BIP 125)
            %% Returns {ok, EvictedTxids, EvictedVBytes} or throws error
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
    DescendantsAndSelf = lists:usort(lists:flatmap(fun(Cid) ->
        [Cid | get_all_descendants(Cid)]
    end, ConflictTxids)),

    %% Also include ephemeral anchor parents whose dust is no longer spent
    EphemeralParents = lists:usort(lists:flatmap(fun(EvictTxid) ->
        find_orphaned_ephemeral_parents(EvictTxid)
    end, DescendantsAndSelf)),

    AllEvictTxids = lists:usort(DescendantsAndSelf ++ EphemeralParents),
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

    %% 7. cluster-based RBF check: new tx's diagram must dominate old cluster's diagram
    %% This ensures the replacement improves the mempool's fee-rate quality
    check_cluster_rbf_diagram(NewFee, NewVSize, AllEvictTxids),

    %% evict all conflicting txs + descendants
    %% Collect vbytes before removal for state update
    EvictedVBytes = lists:foldl(fun(EvictTxid, Acc) ->
        case remove_entry(EvictTxid) of
            #mempool_entry{vsize = VS} -> Acc + VS;
            not_found -> Acc
        end
    end, 0, AllEvictTxids),

    logger:debug("mempool: rbf evicted ~B txs (fullrbf=~p)",
                 [length(AllEvictTxids), FullRbfEnabled]),
    {ok, AllEvictTxids, EvictedVBytes}.

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

%% @doc Check that the new tx's fee-rate diagram dominates the old cluster's diagram.
%% A diagram dominates if at every cumulative vsize point, it has >= cumulative fee.
%% This ensures the replacement improves mempool quality.
check_cluster_rbf_diagram(NewFee, NewVSize, OldTxids) ->
    %% Build the old fee-rate diagram (cumulative vsize -> cumulative fee)
    OldDiagram = build_feerate_diagram(OldTxids),
    %% Build the new diagram (just the single replacement tx for now)
    NewDiagram = [{NewVSize, NewFee}],
    %% Check dominance: at each point in the old diagram, the new diagram
    %% must have >= cumulative fee at that cumulative vsize
    case diagram_dominates(NewDiagram, OldDiagram) of
        true ->
            ok;
        false ->
            throw(rbf_cluster_diagram_not_dominated)
    end.

%% @doc Build a fee-rate diagram from a list of txids.
%% Returns a list of {cumulative_vsize, cumulative_fee} points, sorted by fee rate.
build_feerate_diagram(Txids) ->
    %% Get fee and vsize for each txid, compute fee rate, sort by descending fee rate
    Entries = lists:filtermap(fun(Txid) ->
        case ets:lookup(?MEMPOOL_TXS, Txid) of
            [{_, E}] -> {true, {E#mempool_entry.fee, E#mempool_entry.vsize,
                                E#mempool_entry.fee_rate}};
            [] -> false
        end
    end, Txids),
    %% Sort by descending fee rate (best first)
    Sorted = lists:sort(fun({_, _, R1}, {_, _, R2}) -> R1 >= R2 end, Entries),
    %% Build cumulative diagram
    {Diagram, _, _} = lists:foldl(
        fun({Fee, VSize, _Rate}, {Acc, CumFee, CumVSize}) ->
            NewCumFee = CumFee + Fee,
            NewCumVSize = CumVSize + VSize,
            {[{NewCumVSize, NewCumFee} | Acc], NewCumFee, NewCumVSize}
        end,
        {[], 0, 0},
        Sorted),
    lists:reverse(Diagram).

%% @doc Check if diagram A dominates diagram B (A >= B at all points).
%% Both diagrams are lists of {cumulative_vsize, cumulative_fee}.
diagram_dominates(NewDiagram, OldDiagram) ->
    %% For each point in OldDiagram, find the cumulative fee at that vsize in NewDiagram
    %% The new diagram dominates if NewFee >= OldFee at each point
    lists:all(
        fun({OldVSize, OldFee}) ->
            NewFee = interpolate_diagram(NewDiagram, OldVSize),
            NewFee >= OldFee
        end,
        OldDiagram).

%% @doc Interpolate the cumulative fee at a given vsize in a diagram.
%% Uses linear interpolation between diagram points.
interpolate_diagram([], _VSize) ->
    0;
interpolate_diagram([{V, F}], VSize) when VSize >= V ->
    F;
interpolate_diagram([{V, F} | _], VSize) when VSize =< V ->
    %% Linear interpolation from origin to first point
    (F * VSize) div max(1, V);
interpolate_diagram([{V1, F1}, {V2, F2} | Rest], VSize) when VSize > V1 ->
    case VSize =< V2 of
        true ->
            %% Linear interpolation between V1 and V2
            F1 + ((F2 - F1) * (VSize - V1)) div max(1, (V2 - V1));
        false ->
            interpolate_diagram([{V2, F2} | Rest], VSize)
    end;
interpolate_diagram([{_V, F} | _], _VSize) ->
    %% VSize is before this point - interpolate from origin
    F.

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

%% @doc Check dust policy for a transaction.
%% Ephemeral anchors: zero-value P2A outputs are allowed if fee == 0.
%% The ephemeral anchor MUST be spent by a child in the same package.
%% Fee can be 'undefined' to skip ephemeral anchor checks.
check_dust(#transaction{outputs = Outputs} = Tx, Fee) ->
    %% First, check for P2A policy violations
    check_p2a_policy(Outputs),
    %% Check for ephemeral anchor (zero-value P2A with zero fee)
    EphemeralInfo = find_ephemeral_anchor(Tx, Fee),
    %% Then check regular dust rules
    lists:foreach(fun(#tx_out{value = Value, script_pubkey = SPK}) ->
        %% OP_RETURN outputs are allowed to be zero value
        case SPK of
            <<16#6a, _/binary>> -> ok;
            _ ->
                %% Skip dust check for ephemeral anchor P2A output
                case is_ephemeral_anchor_output(SPK, Value, EphemeralInfo) of
                    true -> ok;
                    false ->
                        Threshold = dust_threshold(SPK),
                        Value >= Threshold orelse throw(dust)
                end
        end
    end, Outputs),
    EphemeralInfo.

%% @doc Check if this output is an allowed ephemeral anchor.
is_ephemeral_anchor_output(SPK, Value, {has_ephemeral, _}) ->
    %% In ephemeral anchor mode, only the zero-value P2A is exempt
    Value =:= 0 andalso beamchain_script:is_pay_to_anchor(SPK);
is_ephemeral_anchor_output(_, _, none) ->
    false.

%% @doc Find ephemeral anchor in transaction.
%% Returns {has_ephemeral, Index} if tx has zero fee and exactly one zero-value P2A,
%% or 'none' otherwise.
find_ephemeral_anchor(#transaction{outputs = Outputs}, Fee) when Fee =:= 0 ->
    %% Find all zero-value P2A outputs
    ZeroP2A = [{Idx, O} || {Idx, #tx_out{value = 0, script_pubkey = SPK} = O}
                          <- lists:zip(lists:seq(0, length(Outputs) - 1), Outputs),
                          beamchain_script:is_pay_to_anchor(SPK)],
    case ZeroP2A of
        [{AnchorIdx, _}] -> {has_ephemeral, AnchorIdx};
        [] -> none;
        _ -> throw(multiple_ephemeral_anchors)  %% only 1 allowed
    end;
find_ephemeral_anchor(#transaction{outputs = Outputs}, Fee) when Fee =/= undefined ->
    %% Non-zero fee: reject any zero-value P2A outputs (they must be dust)
    HasZeroP2A = lists:any(fun(#tx_out{value = 0, script_pubkey = SPK}) ->
        beamchain_script:is_pay_to_anchor(SPK);
    (_) -> false
    end, Outputs),
    case HasZeroP2A of
        true -> throw(ephemeral_dust_requires_zero_fee);
        false -> none
    end;
find_ephemeral_anchor(_, undefined) ->
    %% Fee not yet computed, skip ephemeral check
    none.

%% @doc Check Pay-to-Anchor (P2A) policy rules.
%% - Max 1 P2A output per transaction
check_p2a_policy(Outputs) ->
    P2aCount = length([O || #tx_out{script_pubkey = SPK} = O <- Outputs,
                            beamchain_script:is_pay_to_anchor(SPK)]),
    P2aCount =< 1 orelse throw(multiple_p2a_outputs),
    ok.

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
        p2a       -> 67;   %% P2A uses standard witness input size (67 bytes)
                           %% Dust = (13 + 67) * 3000 / 1000 = 240 satoshis
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
classify_output(<<16#51, 16#02, 16#4e, 16#73>>) ->
    p2a;  %% Pay-to-Anchor: OP_1 OP_PUSHBYTES_2 0x4e73
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

%% @doc Get all in-mempool ancestors of a transaction (recursive).
%% Returns a list of ancestor txids (not including the queried tx itself).
get_ancestors(Txid) ->
    case get_tx(Txid) of
        {ok, Tx} ->
            Parents = get_parent_txids(Tx),
            get_ancestors_loop(Parents, sets:from_list(Parents), []);
        not_found ->
            []
    end.

%% @doc Get all in-mempool descendants of a transaction (recursive).
%% Returns a deduplicated list of descendant txids (not including the
%% queried tx itself). Returns [] if the tx is not in the mempool.
%% Mirrors Bitcoin Core's CTxMemPool::CalculateDescendants minus the
%% query tx (see rpc/mempool.cpp `getmempooldescendants`).
get_descendants(Txid) ->
    case has_tx(Txid) of
        true ->
            lists:usort(get_all_descendants(Txid));
        false ->
            []
    end.

get_ancestors_loop([], _Visited, Acc) ->
    lists:usort(Acc);
get_ancestors_loop([Txid | Rest], Visited, Acc) ->
    case get_tx(Txid) of
        {ok, Tx} ->
            Parents = get_parent_txids(Tx),
            NewParents = [P || P <- Parents, not sets:is_element(P, Visited)],
            NewVisited = lists:foldl(fun(P, S) -> sets:add_element(P, S) end,
                                      Visited, NewParents),
            get_ancestors_loop(Rest ++ NewParents, NewVisited, [Txid | Acc]);
        not_found ->
            get_ancestors_loop(Rest, Visited, Acc)
    end.

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
                ets:delete(?MEMPOOL_OUTPOINTS, {H, I}),
                %% Also remove ephemeral anchor dependency if this tx was spending one
                ets:delete(?MEMPOOL_EPHEMERAL, {H, I})
            end, Tx#transaction.inputs),
            ets:delete(?MEMPOOL_TXS, Txid),
            Entry;
        [] ->
            not_found
    end.

%% @doc Remove an entry and send ZMQ notification.
%% Returns {Entry, NewState} on success or {not_found, State} if not in mempool.
remove_entry_with_zmq(Txid, Reason, #state{zmq_seq = ZmqSeq} = State) ->
    case remove_entry(Txid) of
        #mempool_entry{tx = Tx} = Entry ->
            %% Send ZMQ notification for mempool removal
            beamchain_zmq:notify_transaction(Tx, Reason, ZmqSeq),
            {Entry, State#state{zmq_seq = ZmqSeq + 1}};
        not_found ->
            {not_found, State}
    end.

%% @doc Find parents that have ephemeral anchors no longer spent by this child.
%% Returns list of parent txids that should be removed because their dust is unspent.
find_orphaned_ephemeral_parents(Txid) ->
    case ets:lookup(?MEMPOOL_TXS, Txid) of
        [{Txid, Entry}] ->
            Tx = Entry#mempool_entry.tx,
            %% Find all inputs that were spending ephemeral anchors
            lists:filtermap(fun(#tx_in{prev_out = #outpoint{hash = ParentTxid, index = Idx}}) ->
                %% Check if this was an ephemeral anchor dependency
                case ets:lookup(?MEMPOOL_EPHEMERAL, {ParentTxid, Idx}) of
                    [{_, Txid}] ->
                        %% Yes, this tx was spending the ephemeral anchor
                        {true, ParentTxid};
                    _ ->
                        false
                end
            end, Tx#transaction.inputs);
        [] ->
            []
    end.

%%% ===================================================================
%%% Internal: block removal (stub)
%%% ===================================================================

do_remove_for_block(Txids, State) ->
    %% 1. remove confirmed transactions and update clusters
    {RemovedBytes, RemovedCount, State2} = lists:foldl(
        fun(Txid, {Bytes, Count, St}) ->
            case remove_entry(Txid) of
                #mempool_entry{vsize = VSize} ->
                    St2 = cluster_remove_tx(Txid, St),
                    {Bytes + VSize, Count + 1, St2};
                not_found ->
                    {Bytes, Count, St}
            end
        end,
        {0, 0, State},
        Txids),

    %% 2. remove any mempool txs that conflict with the block
    %%    (their inputs were spent by block transactions)
    {ConflictBytes, ConflictCount, State3} = remove_block_conflicts(Txids, State2),

    TotalBytes = RemovedBytes + ConflictBytes,
    TotalCount = RemovedCount + ConflictCount,
    case TotalCount > 0 of
        true ->
            logger:debug("mempool: removed ~B txs for block (~B confirmed, "
                         "~B conflicts)", [TotalCount, RemovedCount, ConflictCount]);
        false -> ok
    end,
    State3#state{
        total_bytes = max(0, State3#state.total_bytes - TotalBytes),
        total_count = max(0, State3#state.total_count - TotalCount)
    }.

%% After confirming block transactions, check if any remaining mempool
%% transactions now double-spend a confirmed output. Remove them.
remove_block_conflicts(ConfirmedTxids, State) ->
    %% Build set of outpoints spent by confirmed txs
    %% For each confirmed txid, its outputs are now in the UTXO set,
    %% and any mempool tx spending the same inputs as a confirmed tx
    %% is now invalid.
    ConfSet = sets:from_list(ConfirmedTxids),
    AllEntries = ets:tab2list(?MEMPOOL_TXS),
    lists:foldl(fun({Txid, Entry}, {Bytes, Count, St}) ->
        %% skip if we already removed it
        case sets:is_element(Txid, ConfSet) of
            true -> {Bytes, Count, St};
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
                        lists:foldl(fun(RTxid, {B, C, St2}) ->
                            case remove_entry_with_zmq(RTxid, mempool_remove, St2) of
                                {#mempool_entry{vsize = VS}, St3} ->
                                    St4 = cluster_remove_tx(RTxid, St3),
                                    {B + VS, C + 1, St4};
                                {not_found, St3} -> {B, C, St3}
                            end
                        end, {Bytes, Count, St}, AllRemove);
                    false ->
                        {Bytes, Count, St}
                end
        end
    end, {0, 0, State}, AllEntries).

%%% ===================================================================
%%% Internal: trimming / eviction (cluster-based)
%%% ===================================================================

%% Remove transactions from the worst cluster linearization tails until
%% total size fits within MaxBytes.
do_trim_to_size(MaxBytes, State) ->
    case State#state.total_bytes =< MaxBytes of
        true ->
            State;
        false ->
            %% Find the worst cluster (lowest aggregate fee rate)
            case find_worst_cluster() of
                not_found ->
                    State;
                {ClusterId, ClusterData} ->
                    %% Evict from the tail of this cluster's linearization
                    Linearization = ClusterData#cluster_data.linearization,
                    case Linearization of
                        [] ->
                            %% Empty cluster - remove it and try again
                            ets:delete(?MEMPOOL_CLUSTERS, ClusterId),
                            State2 = State#state{
                                cluster_count = max(0, State#state.cluster_count - 1)
                            },
                            do_trim_to_size(MaxBytes, State2);
                        _ ->
                            %% Remove the last transaction in the linearization
                            %% (lowest priority within this cluster)
                            TailTxid = lists:last(Linearization),
                            %% Also remove any descendants
                            Desc = get_all_descendants(TailTxid),
                            DescAndSelf = [TailTxid | Desc],
                            %% Also remove ephemeral parents whose dust is unspent
                            EphParents = lists:usort(lists:flatmap(fun(ETxid) ->
                                find_orphaned_ephemeral_parents(ETxid)
                            end, DescAndSelf)),
                            AllRemove = lists:usort(DescAndSelf ++ EphParents),
                            {RemovedBytes, RemovedCount, State2} = lists:foldl(
                                fun(RTxid, {Bytes, Count, St}) ->
                                    case remove_entry(RTxid) of
                                        #mempool_entry{vsize = VSize} ->
                                            St2 = cluster_remove_tx(RTxid, St),
                                            {Bytes + VSize, Count + 1, St2};
                                        not_found ->
                                            {Bytes, Count, St}
                                    end
                                end, {0, 0, State}, AllRemove),
                            State3 = State2#state{
                                total_bytes = max(0, State2#state.total_bytes - RemovedBytes),
                                total_count = max(0, State2#state.total_count - RemovedCount)
                            },
                            do_trim_to_size(MaxBytes, State3)
                    end
            end
    end.

%% @doc Find the cluster with the lowest aggregate fee rate.
find_worst_cluster() ->
    AllClusters = ets:tab2list(?MEMPOOL_CLUSTERS),
    case AllClusters of
        [] ->
            not_found;
        _ ->
            lists:foldl(
                fun({Id, Data}, Worst) ->
                    case Worst of
                        not_found ->
                            {Id, Data};
                        {_, WorstData} ->
                            case Data#cluster_data.fee_rate < WorstData#cluster_data.fee_rate of
                                true -> {Id, Data};
                                false -> Worst
                            end
                    end
                end,
                not_found,
                AllClusters)
    end.

%% Expire transactions older than 14 days (336 hours).
do_expire_old(State) ->
    CutoffTime = erlang:system_time(second) - (?MEMPOOL_EXPIRY_HOURS * 3600),
    AllEntries = ets:tab2list(?MEMPOOL_TXS),
    {ExpiredCount, ExpiredBytes, State2} = lists:foldl(
        fun({Txid, Entry}, {Count, Bytes, St}) ->
            case Entry#mempool_entry.time_added < CutoffTime of
                true ->
                    remove_entry(Txid),
                    St2 = cluster_remove_tx(Txid, St),
                    {Count + 1, Bytes + Entry#mempool_entry.vsize, St2};
                false ->
                    {Count, Bytes, St}
            end
        end,
        {0, 0, State},
        AllEntries),
    case ExpiredCount > 0 of
        true ->
            logger:debug("mempool: expired ~B old txs (~B vB)",
                         [ExpiredCount, ExpiredBytes]);
        false -> ok
    end,
    State3 = State2#state{
        total_bytes = max(0, State2#state.total_bytes - ExpiredBytes),
        total_count = max(0, State2#state.total_count - ExpiredCount)
    },
    {ExpiredCount, State3}.

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
%%% Internal: TRUC (v3 transaction) policy checks
%%% BIP 431 - Topologically Restricted Until Confirmation
%%% ===================================================================

%% @doc Check TRUC rules for a single transaction.
%% Returns ok or {error, {truc_violation, Reason}} or {sibling_eviction, SiblingTxid}.
-spec check_truc_rules(#transaction{}, non_neg_integer(), [binary()]) ->
    ok | {error, {truc_violation, term()}} | {sibling_eviction, binary()}.
check_truc_rules(Tx, VSize, MempoolParentTxids) ->
    TxVersion = Tx#transaction.version,
    case TxVersion of
        ?TRUC_VERSION ->
            check_truc_v3_rules(Tx, VSize, MempoolParentTxids);
        _ ->
            %% Non-v3 tx cannot spend unconfirmed v3 outputs
            check_non_truc_parents(MempoolParentTxids)
    end.

%% Check that a non-v3 tx doesn't have any v3 parents in mempool.
check_non_truc_parents([]) ->
    ok;
check_non_truc_parents([ParentTxid | Rest]) ->
    case ets:lookup(?MEMPOOL_TXS, ParentTxid) of
        [{_, Entry}] ->
            ParentTx = Entry#mempool_entry.tx,
            case ParentTx#transaction.version of
                ?TRUC_VERSION ->
                    {error, {truc_violation, non_truc_spends_truc}};
                _ ->
                    check_non_truc_parents(Rest)
            end;
        [] ->
            check_non_truc_parents(Rest)
    end.

%% Check TRUC rules for a v3 transaction.
check_truc_v3_rules(Tx, VSize, MempoolParentTxids) ->
    %% Rule 1: v3 tx must be <= TRUC_MAX_VSIZE
    case VSize > ?TRUC_MAX_VSIZE of
        true ->
            {error, {truc_violation, {tx_too_large, VSize, ?TRUC_MAX_VSIZE}}};
        false ->
            check_truc_v3_ancestry(Tx, VSize, MempoolParentTxids)
    end.

check_truc_v3_ancestry(_Tx, _VSize, []) ->
    %% No mempool parents - this is a v3 parent (no unconfirmed ancestors)
    ok;
check_truc_v3_ancestry(Tx, VSize, MempoolParentTxids) ->
    %% Has mempool parents - this is a v3 child

    %% Rule 2: v3 child can have at most 1 unconfirmed parent
    case length(MempoolParentTxids) > 1 of
        true ->
            {error, {truc_violation, too_many_ancestors}};
        false ->
            [ParentTxid] = MempoolParentTxids,
            check_truc_v3_child_rules(Tx, VSize, ParentTxid)
    end.

check_truc_v3_child_rules(_Tx, VSize, ParentTxid) ->
    %% Rule 3: v3 child must be <= TRUC_CHILD_MAX_VSIZE
    case VSize > ?TRUC_CHILD_MAX_VSIZE of
        true ->
            {error, {truc_violation, {child_too_large, VSize, ?TRUC_CHILD_MAX_VSIZE}}};
        false ->
            check_truc_parent_version(ParentTxid, VSize)
    end.

check_truc_parent_version(ParentTxid, VSize) ->
    %% Rule 4: v3 child can only spend from v3 parent
    case ets:lookup(?MEMPOOL_TXS, ParentTxid) of
        [{_, Entry}] ->
            ParentTx = Entry#mempool_entry.tx,
            case ParentTx#transaction.version of
                ?TRUC_VERSION ->
                    check_truc_parent_descendant_limit(Entry, VSize);
                _ ->
                    {error, {truc_violation, truc_spends_non_truc}}
            end;
        [] ->
            %% Parent not in mempool (should not happen if called correctly)
            ok
    end.

check_truc_parent_descendant_limit(ParentEntry, _VSize) ->
    %% Rule 5: v3 parent can have at most 1 unconfirmed child
    %% descendant_count includes the parent itself, so limit is 2
    case ParentEntry#mempool_entry.descendant_count >= ?TRUC_DESCENDANT_LIMIT of
        true ->
            %% Parent already has a child - check for sibling eviction
            ParentTxid = ParentEntry#mempool_entry.txid,
            case find_truc_sibling(ParentTxid) of
                {ok, SiblingTxid} ->
                    %% Sibling eviction is possible
                    {sibling_eviction, SiblingTxid};
                not_found ->
                    %% No sibling found (inconsistent state) or multiple children
                    {error, {truc_violation, too_many_descendants}}
            end;
        false ->
            ok
    end.

%% Find the existing child of a v3 parent for sibling eviction.
find_truc_sibling(ParentTxid) ->
    case ets:lookup(?MEMPOOL_TXS, ParentTxid) of
        [{_, Entry}] ->
            ParentTx = Entry#mempool_entry.tx,
            NumOutputs = length(ParentTx#transaction.outputs),
            find_truc_sibling_in_outputs(ParentTxid, 0, NumOutputs);
        [] ->
            not_found
    end.

find_truc_sibling_in_outputs(_ParentTxid, Idx, NumOutputs) when Idx >= NumOutputs ->
    not_found;
find_truc_sibling_in_outputs(ParentTxid, Idx, NumOutputs) ->
    case ets:lookup(?MEMPOOL_OUTPOINTS, {ParentTxid, Idx}) of
        [{{ParentTxid, Idx}, ChildTxid}] ->
            %% Found a child spending this output
            {ok, ChildTxid};
        [] ->
            find_truc_sibling_in_outputs(ParentTxid, Idx + 1, NumOutputs)
    end.

%% @doc Perform sibling eviction for v3 transactions.
%% Evicts the existing sibling and returns {ok, EvictedTxids, EvictedVBytes} if successful.
-spec do_truc_sibling_eviction(binary(), #transaction{}, non_neg_integer()) ->
    {ok, [binary()], non_neg_integer()} | {error, term()}.
do_truc_sibling_eviction(SiblingTxid, NewTx, NewFee) ->
    case ets:lookup(?MEMPOOL_TXS, SiblingTxid) of
        [{_, SiblingEntry}] ->
            %% For sibling eviction, the new child must pay enough to cover
            %% the sibling's fee plus incremental relay fee
            SiblingFee = SiblingEntry#mempool_entry.fee,
            NewVSize = beamchain_serialize:tx_vsize(NewTx),
            MinFee = SiblingFee + NewVSize,  %% sibling fee + 1 sat/vB * new_vsize
            case NewFee >= MinFee of
                true ->
                    %% Evict sibling and its descendants
                    Descendants = get_all_descendants(SiblingTxid),
                    AllEvict = [SiblingTxid | Descendants],
                    EvictedVBytes = lists:foldl(fun(Txid, Acc) ->
                        case remove_entry(Txid) of
                            #mempool_entry{vsize = VS} -> Acc + VS;
                            not_found -> Acc
                        end
                    end, 0, AllEvict),
                    logger:debug("mempool: truc sibling eviction ~s + ~B descendants",
                                 [short_hex(SiblingTxid), length(Descendants)]),
                    {ok, AllEvict, EvictedVBytes};
                false ->
                    {error, {truc_violation, sibling_eviction_insufficient_fee}}
            end;
        [] ->
            %% Sibling already removed
            {ok, [], 0}
    end.

%% @doc Check TRUC rules for package transactions.
%% Must check that v3 topology is maintained within the package.
-spec check_truc_package_rules(#transaction{}, non_neg_integer(),
                                [{binary(), #transaction{}}], [binary()]) ->
    ok | {error, {truc_violation, term()}}.
check_truc_package_rules(Tx, VSize, PackageTxMap, MempoolParentTxids) ->
    TxVersion = Tx#transaction.version,
    Txid = beamchain_serialize:tx_hash(Tx),

    %% Find in-package parents
    InPackageParents = find_in_package_parents(Tx, PackageTxMap, Txid),

    case TxVersion of
        ?TRUC_VERSION ->
            check_truc_v3_package_rules(VSize, PackageTxMap, Txid,
                                        MempoolParentTxids, InPackageParents);
        _ ->
            %% Non-v3: check for v3 parents in mempool or package
            check_non_truc_package_parents(MempoolParentTxids, InPackageParents, PackageTxMap)
    end.

find_in_package_parents(Tx, PackageTxMap, OwnTxid) ->
    lists:filtermap(fun(#tx_in{prev_out = #outpoint{hash = H}}) ->
        case H =:= OwnTxid of
            true -> false;  %% Skip self-reference
            false ->
                case lists:keyfind(H, 1, PackageTxMap) of
                    {H, _ParentTx} -> {true, H};
                    false -> false
                end
        end
    end, Tx#transaction.inputs).

check_non_truc_package_parents(MempoolParentTxids, InPackageParents, PackageTxMap) ->
    %% Check mempool parents
    case check_non_truc_parents(MempoolParentTxids) of
        ok ->
            %% Check in-package parents
            check_non_truc_in_package_parents(InPackageParents, PackageTxMap);
        Error ->
            Error
    end.

check_non_truc_in_package_parents([], _PackageTxMap) ->
    ok;
check_non_truc_in_package_parents([ParentTxid | Rest], PackageTxMap) ->
    case lists:keyfind(ParentTxid, 1, PackageTxMap) of
        {ParentTxid, ParentTx} ->
            case ParentTx#transaction.version of
                ?TRUC_VERSION ->
                    {error, {truc_violation, non_truc_spends_truc}};
                _ ->
                    check_non_truc_in_package_parents(Rest, PackageTxMap)
            end;
        false ->
            check_non_truc_in_package_parents(Rest, PackageTxMap)
    end.

check_truc_v3_package_rules(VSize, PackageTxMap, Txid, MempoolParentTxids, InPackageParents) ->
    %% Rule 1: v3 tx size limit
    case VSize > ?TRUC_MAX_VSIZE of
        true ->
            {error, {truc_violation, {tx_too_large, VSize, ?TRUC_MAX_VSIZE}}};
        false ->
            AllParents = MempoolParentTxids ++ InPackageParents,
            check_truc_v3_package_ancestry(VSize, PackageTxMap, Txid,
                                           MempoolParentTxids, AllParents)
    end.

check_truc_v3_package_ancestry(_VSize, _PackageTxMap, _Txid,
                               _MempoolParentTxids, []) ->
    %% No parents - this is a v3 parent
    ok;
check_truc_v3_package_ancestry(VSize, PackageTxMap, Txid,
                               MempoolParentTxids, AllParents) ->
    %% Rule 2: max 1 unconfirmed parent total (mempool + package)
    case length(AllParents) > 1 of
        true ->
            {error, {truc_violation, too_many_ancestors}};
        false ->
            %% Rule 3: v3 child size limit
            case VSize > ?TRUC_CHILD_MAX_VSIZE of
                true ->
                    {error, {truc_violation, {child_too_large, VSize, ?TRUC_CHILD_MAX_VSIZE}}};
                false ->
                    [ParentTxid] = AllParents,
                    check_truc_v3_package_parent(ParentTxid, Txid, PackageTxMap,
                                                 MempoolParentTxids)
            end
    end.

check_truc_v3_package_parent(ParentTxid, ChildTxid, PackageTxMap, MempoolParentTxids) ->
    %% Get parent version
    ParentVersion = case lists:keyfind(ParentTxid, 1, PackageTxMap) of
        {ParentTxid, ParentTx} ->
            ParentTx#transaction.version;
        false ->
            case ets:lookup(?MEMPOOL_TXS, ParentTxid) of
                [{_, Entry}] -> (Entry#mempool_entry.tx)#transaction.version;
                [] -> undefined
            end
    end,

    %% Rule 4: v3 child must have v3 parent
    case ParentVersion of
        ?TRUC_VERSION ->
            %% Check for siblings in package or mempool
            check_truc_v3_package_siblings(ParentTxid, ChildTxid, PackageTxMap,
                                           MempoolParentTxids);
        undefined ->
            %% Parent not found - let other validation catch this
            ok;
        _ ->
            {error, {truc_violation, truc_spends_non_truc}}
    end.

check_truc_v3_package_siblings(ParentTxid, ChildTxid, PackageTxMap, MempoolParentTxids) ->
    %% Check if any other tx in the package spends from the same parent
    OtherPackageChildren = lists:filtermap(fun({OtherTxid, OtherTx}) ->
        case OtherTxid =:= ChildTxid of
            true -> false;
            false ->
                SpendsParent = lists:any(fun(#tx_in{prev_out = #outpoint{hash = H}}) ->
                    H =:= ParentTxid
                end, OtherTx#transaction.inputs),
                case SpendsParent of
                    true -> {true, OtherTxid};
                    false -> false
                end
        end
    end, PackageTxMap),

    case OtherPackageChildren of
        [_|_] ->
            {error, {truc_violation, too_many_descendants}};
        [] ->
            %% Check mempool for existing children
            case lists:member(ParentTxid, MempoolParentTxids) of
                true ->
                    %% Parent is in mempool - check its descendant count
                    case ets:lookup(?MEMPOOL_TXS, ParentTxid) of
                        [{_, Entry}] ->
                            case Entry#mempool_entry.descendant_count >= ?TRUC_DESCENDANT_LIMIT of
                                true ->
                                    {error, {truc_violation, too_many_descendants}};
                                false ->
                                    ok
                            end;
                        [] ->
                            ok
                    end;
                false ->
                    ok
            end
    end.

%%% ===================================================================
%%% Cluster mempool public API
%%% ===================================================================

%% @doc Get the cluster ID for a transaction.
-spec get_cluster(binary()) -> {ok, binary()} | not_found.
get_cluster(Txid) ->
    gen_server:call(?SERVER, {get_cluster, Txid}).

%% @doc Get all txids in a cluster.
-spec get_cluster_txids(binary()) -> {ok, [binary()]} | not_found.
get_cluster_txids(ClusterId) ->
    case ets:lookup(?MEMPOOL_CLUSTERS, ClusterId) of
        [{ClusterId, ClusterData}] ->
            {ok, ClusterData#cluster_data.txids};
        [] ->
            not_found
    end.

%% @doc Get the linearization (optimal ordering) for a cluster.
-spec get_cluster_linearization(binary()) -> {ok, [binary()]} | not_found.
get_cluster_linearization(ClusterId) ->
    case ets:lookup(?MEMPOOL_CLUSTERS, ClusterId) of
        [{ClusterId, ClusterData}] ->
            {ok, ClusterData#cluster_data.linearization};
        [] ->
            not_found
    end.

%% @doc Get all transactions in mining order (best fee-rate prefixes first).
%% Returns a list of txids ordered for optimal block construction.
-spec get_mining_order() -> [binary()].
get_mining_order() ->
    %% Collect all clusters with their linearizations and aggregate fee rates
    AllClusters = ets:tab2list(?MEMPOOL_CLUSTERS),
    %% Sort clusters by fee rate (descending)
    SortedClusters = lists:sort(
        fun({_, A}, {_, B}) ->
            A#cluster_data.fee_rate >= B#cluster_data.fee_rate
        end,
        AllClusters),
    %% Flatten linearizations in order
    lists:flatmap(
        fun({_, ClusterData}) ->
            ClusterData#cluster_data.linearization
        end,
        SortedClusters).

%% @doc Get all cluster IDs.
-spec get_all_clusters() -> [binary()].
get_all_clusters() ->
    [Id || {Id, _} <- ets:tab2list(?MEMPOOL_CLUSTERS)].

%%% ===================================================================
%%% Internal: Union-Find for cluster tracking
%%% ===================================================================

%% @doc Find the root (cluster ID) for a txid with path compression.
%% Returns {Root, UpdatedUnionFind} where Root is the cluster ID.
-spec uf_find(binary(), map()) -> {binary(), map()}.
uf_find(Txid, UnionFind) ->
    case maps:get(Txid, UnionFind, Txid) of
        Txid ->
            %% Txid is its own root
            {Txid, UnionFind};
        Parent ->
            %% Recursively find root with path compression
            {Root, UF2} = uf_find(Parent, UnionFind),
            %% Path compression: point directly to root
            {Root, maps:put(Txid, Root, UF2)}
    end.

%% @doc Union two sets (clusters) by their txids.
%% Returns {NewRoot, UpdatedUnionFind}.
-spec uf_union(binary(), binary(), map()) -> {binary(), map()}.
uf_union(Txid1, Txid2, UnionFind) ->
    {Root1, UF1} = uf_find(Txid1, UnionFind),
    {Root2, UF2} = uf_find(Txid2, UF1),
    case Root1 =:= Root2 of
        true ->
            %% Already in the same cluster
            {Root1, UF2};
        false ->
            %% Merge: make Root1 the parent of Root2
            %% (arbitrary choice, could use rank heuristic)
            {Root1, maps:put(Root2, Root1, UF2)}
    end.

%% @doc Get all txids in the same cluster as Txid.
-spec uf_get_cluster_members(binary(), map()) -> [binary()].
uf_get_cluster_members(Txid, UnionFind) ->
    {Root, _} = uf_find(Txid, UnionFind),
    %% Find all txids that have this root
    [T || T <- maps:keys(UnionFind),
          element(1, uf_find(T, UnionFind)) =:= Root].

%%% ===================================================================
%%% Internal: Cluster linearization (chunking algorithm)
%%% ===================================================================

%% @doc Build a dependency graph for transactions in a cluster.
%% Returns a map: txid -> {parents, children, fee, vsize}
-spec build_dep_graph([binary()]) -> map().
build_dep_graph(Txids) ->
    TxidSet = sets:from_list(Txids),
    lists:foldl(
        fun(Txid, Graph) ->
            case ets:lookup(?MEMPOOL_TXS, Txid) of
                [{Txid, Entry}] ->
                    Tx = Entry#mempool_entry.tx,
                    Fee = Entry#mempool_entry.fee,
                    VSize = Entry#mempool_entry.vsize,
                    %% Find parents (inputs that are in this cluster)
                    Parents = lists:filtermap(
                        fun(#tx_in{prev_out = #outpoint{hash = H}}) ->
                            case sets:is_element(H, TxidSet) of
                                true -> {true, H};
                                false -> false
                            end
                        end,
                        Tx#transaction.inputs),
                    maps:put(Txid, #{parents => Parents, children => [],
                                     fee => Fee, vsize => VSize}, Graph);
                [] ->
                    Graph
            end
        end,
        #{},
        Txids),
    %% Second pass: populate children from parents
    Graph = lists:foldl(
        fun(Txid, G) ->
            case maps:get(Txid, G, undefined) of
                undefined -> G;
                TxData ->
                    Parents = maps:get(parents, TxData),
                    lists:foldl(
                        fun(ParentTxid, G2) ->
                            case maps:get(ParentTxid, G2, undefined) of
                                undefined -> G2;
                                ParentData ->
                                    Children = maps:get(children, ParentData),
                                    maps:put(ParentTxid,
                                             ParentData#{children => [Txid | Children]},
                                             G2)
                            end
                        end,
                        G,
                        Parents)
            end
        end,
        build_dep_graph_initial(Txids),
        Txids),
    Graph.

build_dep_graph_initial(Txids) ->
    TxidSet = sets:from_list(Txids),
    lists:foldl(
        fun(Txid, Graph) ->
            case ets:lookup(?MEMPOOL_TXS, Txid) of
                [{Txid, Entry}] ->
                    Tx = Entry#mempool_entry.tx,
                    Fee = Entry#mempool_entry.fee,
                    VSize = Entry#mempool_entry.vsize,
                    Parents = lists:filtermap(
                        fun(#tx_in{prev_out = #outpoint{hash = H}}) ->
                            case sets:is_element(H, TxidSet) of
                                true -> {true, H};
                                false -> false
                            end
                        end,
                        Tx#transaction.inputs),
                    maps:put(Txid, #{parents => Parents, children => [],
                                     fee => Fee, vsize => VSize}, Graph);
                [] ->
                    Graph
            end
        end,
        #{},
        Txids).

%% @doc Linearize a cluster using the greedy chunking algorithm.
%% This implements a simplified version of the SFL algorithm:
%% Repeatedly find the highest fee-rate connected subset and place it first.
-spec linearize_cluster([binary()]) -> {[binary()], non_neg_integer(), non_neg_integer()}.
linearize_cluster([]) ->
    {[], 0, 0};
linearize_cluster([SingleTxid]) ->
    case ets:lookup(?MEMPOOL_TXS, SingleTxid) of
        [{SingleTxid, Entry}] ->
            {[SingleTxid], Entry#mempool_entry.fee, Entry#mempool_entry.vsize};
        [] ->
            {[], 0, 0}
    end;
linearize_cluster(Txids) ->
    DepGraph = build_dep_graph(Txids),
    linearize_with_graph(Txids, DepGraph).

%% @doc Linearize using dependency graph with greedy chunking.
%% The algorithm:
%% 1. Find all transactions with no unplaced parents (ready set)
%% 2. For each ready transaction, calculate its "chunk" - the highest
%%    fee-rate set that can be mined together
%% 3. Place the best chunk first, mark as placed, repeat
-spec linearize_with_graph([binary()], map()) -> {[binary()], non_neg_integer(), non_neg_integer()}.
linearize_with_graph(Txids, DepGraph) ->
    Remaining = sets:from_list(Txids),
    linearize_loop(Remaining, DepGraph, [], 0, 0).

linearize_loop(Remaining, DepGraph, Acc, TotalFee, TotalVSize) ->
    case sets:size(Remaining) of
        0 ->
            {lists:reverse(Acc), TotalFee, TotalVSize};
        _ ->
            %% Find ready transactions (no unplaced parents)
            Ready = find_ready_txids(Remaining, DepGraph),
            case Ready of
                [] ->
                    %% Shouldn't happen with valid DAG, but handle gracefully
                    %% Just take any remaining tx
                    [AnyTxid | _] = sets:to_list(Remaining),
                    TxData = maps:get(AnyTxid, DepGraph, #{fee => 0, vsize => 1}),
                    Fee = maps:get(fee, TxData, 0),
                    VSize = maps:get(vsize, TxData, 1),
                    Remaining2 = sets:del_element(AnyTxid, Remaining),
                    linearize_loop(Remaining2, DepGraph, [AnyTxid | Acc],
                                   TotalFee + Fee, TotalVSize + VSize);
                _ ->
                    %% Find the best chunk among ready transactions
                    BestChunk = find_best_chunk(Ready, Remaining, DepGraph),
                    %% Add chunk to linearization
                    {ChunkTxids, ChunkFee, ChunkVSize} = BestChunk,
                    Remaining2 = lists:foldl(fun sets:del_element/2, Remaining, ChunkTxids),
                    linearize_loop(Remaining2, DepGraph, lists:reverse(ChunkTxids) ++ Acc,
                                   TotalFee + ChunkFee, TotalVSize + ChunkVSize)
            end
    end.

%% @doc Find transactions that are ready to be placed (all parents already placed).
-spec find_ready_txids(sets:set(), map()) -> [binary()].
find_ready_txids(Remaining, DepGraph) ->
    lists:filter(
        fun(Txid) ->
            case maps:get(Txid, DepGraph, undefined) of
                undefined -> false;
                TxData ->
                    Parents = maps:get(parents, TxData, []),
                    %% Ready if no parents are in remaining set
                    not lists:any(fun(P) -> sets:is_element(P, Remaining) end, Parents)
            end
        end,
        sets:to_list(Remaining)).

%% @doc Find the best (highest fee-rate) chunk starting from ready transactions.
%% A chunk is a topologically valid subset that can be mined together.
-spec find_best_chunk([binary()], sets:set(), map()) -> {[binary()], non_neg_integer(), non_neg_integer()}.
find_best_chunk(ReadyTxids, Remaining, DepGraph) ->
    %% For each ready tx, calculate the best chunk starting from it
    Chunks = lists:map(
        fun(StartTxid) ->
            build_chunk(StartTxid, Remaining, DepGraph)
        end,
        ReadyTxids),
    %% Return the chunk with highest fee rate
    lists:foldl(
        fun({_Txids, Fee, VSize} = Chunk, {_, BestFee, BestVSize} = Best) ->
            ChunkRate = Fee / max(1, VSize),
            BestRate = BestFee / max(1, BestVSize),
            case ChunkRate > BestRate of
                true -> Chunk;
                false -> Best
            end
        end,
        {[], 0, 0},
        Chunks).

%% @doc Build a chunk starting from a transaction.
%% Uses greedy absorption: include descendants if they increase the chunk fee rate.
-spec build_chunk(binary(), sets:set(), map()) -> {[binary()], non_neg_integer(), non_neg_integer()}.
build_chunk(StartTxid, Remaining, DepGraph) ->
    TxData = maps:get(StartTxid, DepGraph, #{fee => 0, vsize => 1}),
    StartFee = maps:get(fee, TxData, 0),
    StartVSize = maps:get(vsize, TxData, 1),
    %% Start with just this transaction
    Chunk = [StartTxid],
    %% Try to absorb children greedily
    absorb_children(Chunk, StartFee, StartVSize, Remaining, DepGraph).

%% @doc Try to absorb children into the chunk if it improves fee rate.
absorb_children(Chunk, ChunkFee, ChunkVSize, Remaining, DepGraph) ->
    ChunkSet = sets:from_list(Chunk),
    ChunkRate = ChunkFee / max(1, ChunkVSize),
    %% Find children of chunk members that are in remaining and ready
    Candidates = find_absorbable_children(ChunkSet, Remaining, DepGraph),
    case Candidates of
        [] ->
            %% No more candidates, return current chunk (topo-sorted)
            {topo_sort_chunk(Chunk, DepGraph), ChunkFee, ChunkVSize};
        _ ->
            %% Try each candidate and pick the best absorption
            BestAbsorption = lists:foldl(
                fun(CandTxid, Best) ->
                    TxData = maps:get(CandTxid, DepGraph, #{fee => 0, vsize => 1}),
                    CandFee = maps:get(fee, TxData, 0),
                    CandVSize = maps:get(vsize, TxData, 1),
                    NewFee = ChunkFee + CandFee,
                    NewVSize = ChunkVSize + CandVSize,
                    NewRate = NewFee / max(1, NewVSize),
                    case NewRate >= ChunkRate of
                        true ->
                            %% Absorption improves or maintains rate
                            case Best of
                                none -> {CandTxid, NewFee, NewVSize, NewRate};
                                {_, _, _, BestRate} when NewRate > BestRate ->
                                    {CandTxid, NewFee, NewVSize, NewRate};
                                _ -> Best
                            end;
                        false ->
                            Best
                    end
                end,
                none,
                Candidates),
            case BestAbsorption of
                none ->
                    %% No beneficial absorption found
                    {topo_sort_chunk(Chunk, DepGraph), ChunkFee, ChunkVSize};
                {BestCand, NewFee, NewVSize, _} ->
                    %% Absorb and continue
                    absorb_children([BestCand | Chunk], NewFee, NewVSize, Remaining, DepGraph)
            end
    end.

%% @doc Find children that can be absorbed (all parents in chunk or already placed).
find_absorbable_children(ChunkSet, Remaining, DepGraph) ->
    AllChildren = lists:usort(lists:flatmap(
        fun(Txid) ->
            TxData = maps:get(Txid, DepGraph, #{children => []}),
            maps:get(children, TxData, [])
        end,
        sets:to_list(ChunkSet))),
    %% Filter to those in Remaining and whose parents are all in ChunkSet
    lists:filter(
        fun(ChildTxid) ->
            sets:is_element(ChildTxid, Remaining) andalso
            not sets:is_element(ChildTxid, ChunkSet) andalso
            begin
                TxData = maps:get(ChildTxid, DepGraph, #{parents => []}),
                Parents = maps:get(parents, TxData, []),
                lists:all(fun(P) ->
                    sets:is_element(P, ChunkSet) orelse not sets:is_element(P, Remaining)
                end, Parents)
            end
        end,
        AllChildren).

%% @doc Topologically sort the chunk (parents before children).
topo_sort_chunk(Chunk, DepGraph) ->
    ChunkSet = sets:from_list(Chunk),
    topo_sort_loop(Chunk, ChunkSet, DepGraph, []).

topo_sort_loop([], _, _, Acc) ->
    lists:reverse(Acc);
topo_sort_loop(Remaining, ChunkSet, DepGraph, Acc) ->
    %% Find a tx with no unplaced parents in chunk
    PlacedSet = sets:from_list(Acc),
    Ready = lists:filter(
        fun(Txid) ->
            TxData = maps:get(Txid, DepGraph, #{parents => []}),
            Parents = maps:get(parents, TxData, []),
            InChunkParents = [P || P <- Parents, sets:is_element(P, ChunkSet)],
            lists:all(fun(P) -> sets:is_element(P, PlacedSet) end, InChunkParents)
        end,
        Remaining),
    case Ready of
        [] ->
            %% Should not happen, but handle gracefully
            lists:reverse(Acc) ++ Remaining;
        [First | _] ->
            topo_sort_loop(Remaining -- [First], ChunkSet, DepGraph, [First | Acc])
    end.

%%% ===================================================================
%%% Internal: Cluster management operations
%%% ===================================================================

%% @doc Add a transaction to the cluster system.
%% Creates a new cluster or merges with existing cluster(s).
-spec cluster_add_tx(binary(), #transaction{}, non_neg_integer(), non_neg_integer(), #state{}) -> #state{}.
cluster_add_tx(Txid, Tx, Fee, VSize, State) ->
    %% Find all mempool parents of this transaction
    ParentTxids = get_parent_txids(Tx),

    case ParentTxids of
        [] ->
            %% No mempool parents - create new singleton cluster
            create_singleton_cluster(Txid, Fee, VSize, State);
        _ ->
            %% Has mempool parents - find their clusters and merge
            merge_into_clusters(Txid, Fee, VSize, ParentTxids, State)
    end.

%% @doc Create a new singleton cluster for a transaction.
create_singleton_cluster(Txid, Fee, VSize, #state{union_find = UF, cluster_count = CC} = State) ->
    %% Add to union-find (self-referential)
    UF2 = maps:put(Txid, Txid, UF),

    %% Create cluster data
    ClusterData = #cluster_data{
        id = Txid,
        txids = [Txid],
        total_fee = Fee,
        total_vsize = VSize,
        linearization = [Txid],
        fee_rate = Fee / max(1, VSize)
    },
    ets:insert(?MEMPOOL_CLUSTERS, {Txid, ClusterData}),

    State#state{union_find = UF2, cluster_count = CC + 1}.

%% @doc Merge a new transaction into existing cluster(s).
merge_into_clusters(Txid, Fee, VSize, ParentTxids, #state{union_find = UF} = State) ->
    %% Find all unique cluster roots for parents
    {Roots, UF2} = lists:foldl(
        fun(ParentTxid, {RootsAcc, UFAcc}) ->
            case maps:is_key(ParentTxid, UFAcc) of
                true ->
                    {Root, UFAcc2} = uf_find(ParentTxid, UFAcc),
                    {[Root | RootsAcc], UFAcc2};
                false ->
                    {RootsAcc, UFAcc}
            end
        end,
        {[], UF},
        ParentTxids),

    UniqueRoots = lists:usort(Roots),

    case UniqueRoots of
        [] ->
            %% All parents confirmed - create singleton
            create_singleton_cluster(Txid, Fee, VSize, State#state{union_find = UF2});
        [SingleRoot] ->
            %% Single cluster - add to it
            add_to_cluster(Txid, Fee, VSize, SingleRoot, State#state{union_find = UF2});
        _ ->
            %% Multiple clusters - merge them all
            merge_clusters_and_add(Txid, Fee, VSize, UniqueRoots, State#state{union_find = UF2})
    end.

%% @doc Add a transaction to an existing cluster.
add_to_cluster(Txid, _Fee, _VSize, ClusterId, #state{union_find = UF} = State) ->
    %% Add to union-find
    UF2 = maps:put(Txid, ClusterId, UF),

    %% Update cluster
    recompute_cluster(ClusterId, UF2),

    State#state{union_find = UF2}.

%% @doc Merge multiple clusters and add a new transaction.
merge_clusters_and_add(Txid, _Fee, _VSize, ClusterIds, #state{union_find = UF, cluster_count = CC} = State) ->
    [FirstCluster | RestClusters] = ClusterIds,

    %% Merge all clusters into the first one
    UF2 = lists:foldl(
        fun(OtherCluster, UFAcc) ->
            %% Get all members of OtherCluster
            case ets:lookup(?MEMPOOL_CLUSTERS, OtherCluster) of
                [{_, ClusterData}] ->
                    %% Update union-find to point all members to FirstCluster
                    lists:foldl(
                        fun(MemberTxid, UF3) ->
                            maps:put(MemberTxid, FirstCluster, UF3)
                        end,
                        UFAcc,
                        ClusterData#cluster_data.txids);
                [] ->
                    UFAcc
            end
        end,
        UF,
        RestClusters),

    %% Add new txid to first cluster
    UF3 = maps:put(Txid, FirstCluster, UF2),

    %% Delete merged cluster records
    lists:foreach(fun(CId) ->
        ets:delete(?MEMPOOL_CLUSTERS, CId)
    end, RestClusters),

    %% Recompute the merged cluster
    recompute_cluster(FirstCluster, UF3),

    %% Update cluster count (merged n clusters into 1, added new tx)
    NewCC = CC - length(RestClusters),

    State#state{union_find = UF3, cluster_count = NewCC}.

%% @doc Recompute cluster data after modification.
recompute_cluster(ClusterId, UnionFind) ->
    %% Find all members of this cluster
    AllTxids = [T || T <- maps:keys(UnionFind),
                     element(1, uf_find(T, UnionFind)) =:= ClusterId],

    %% Check cluster size limit
    case length(AllTxids) > ?MAX_CLUSTER_SIZE of
        true ->
            %% Cluster too large - this shouldn't happen with normal mempool limits
            %% but handle gracefully by keeping existing linearization
            logger:warning("mempool: cluster ~s exceeds size limit (~B txs)",
                          [short_hex(ClusterId), length(AllTxids)]),
            ok;
        false ->
            %% Recompute linearization
            {Linearization, TotalFee, TotalVSize} = linearize_cluster(AllTxids),

            ClusterData = #cluster_data{
                id = ClusterId,
                txids = AllTxids,
                total_fee = TotalFee,
                total_vsize = TotalVSize,
                linearization = Linearization,
                fee_rate = TotalFee / max(1, TotalVSize)
            },
            ets:insert(?MEMPOOL_CLUSTERS, {ClusterId, ClusterData})
    end.

%% @doc Remove a transaction from the cluster system.
%% May split a cluster if the removed tx was connecting parts.
-spec cluster_remove_tx(binary(), #state{}) -> #state{}.
cluster_remove_tx(Txid, #state{union_find = UF} = State) ->
    case maps:is_key(Txid, UF) of
        false ->
            State;
        true ->
            {ClusterId, UF2} = uf_find(Txid, UF),

            %% Remove txid from union-find
            UF3 = maps:remove(Txid, UF2),

            %% Get remaining cluster members
            case ets:lookup(?MEMPOOL_CLUSTERS, ClusterId) of
                [{_, ClusterData}] ->
                    RemainingTxids = ClusterData#cluster_data.txids -- [Txid],
                    handle_cluster_after_removal(ClusterId, RemainingTxids, State#state{union_find = UF3});
                [] ->
                    State#state{union_find = UF3}
            end
    end.

%% @doc Handle cluster state after a transaction is removed.
handle_cluster_after_removal(ClusterId, [], #state{cluster_count = CC} = State) ->
    %% Cluster is now empty - delete it
    ets:delete(?MEMPOOL_CLUSTERS, ClusterId),
    State#state{cluster_count = CC - 1};
handle_cluster_after_removal(ClusterId, RemainingTxids, State) ->
    %% Check if cluster needs to be split
    Components = find_connected_components(RemainingTxids),
    case length(Components) of
        1 ->
            %% Still one connected component - just recompute
            recompute_cluster(ClusterId, State#state.union_find),
            State;
        N when N > 1 ->
            %% Split into multiple clusters
            split_cluster(ClusterId, Components, State)
    end.

%% @doc Find connected components among a set of txids.
find_connected_components(Txids) ->
    TxidSet = sets:from_list(Txids),
    find_components_loop(Txids, TxidSet, []).

find_components_loop([], _, Components) ->
    Components;
find_components_loop([Txid | Rest], TxidSet, Components) ->
    case sets:is_element(Txid, TxidSet) of
        false ->
            find_components_loop(Rest, TxidSet, Components);
        true ->
            %% BFS to find all connected txids
            {Component, TxidSet2} = bfs_component([Txid], TxidSet, []),
            find_components_loop(Rest, TxidSet2, [Component | Components])
    end.

bfs_component([], TxidSet, Component) ->
    {Component, TxidSet};
bfs_component([Txid | Queue], TxidSet, Component) ->
    case sets:is_element(Txid, TxidSet) of
        false ->
            bfs_component(Queue, TxidSet, Component);
        true ->
            TxidSet2 = sets:del_element(Txid, TxidSet),
            %% Find neighbors (parents and children in mempool)
            Neighbors = find_mempool_neighbors(Txid, TxidSet2),
            bfs_component(Neighbors ++ Queue, TxidSet2, [Txid | Component])
    end.

%% @doc Find mempool neighbors (parents and children) of a transaction.
find_mempool_neighbors(Txid, TxidSet) ->
    case ets:lookup(?MEMPOOL_TXS, Txid) of
        [{Txid, Entry}] ->
            Tx = Entry#mempool_entry.tx,
            %% Find parents that are in TxidSet
            Parents = lists:filtermap(
                fun(#tx_in{prev_out = #outpoint{hash = H}}) ->
                    case sets:is_element(H, TxidSet) of
                        true -> {true, H};
                        false -> false
                    end
                end,
                Tx#transaction.inputs),
            %% Find children that are in TxidSet
            Children = find_children_in_set(Txid, TxidSet),
            Parents ++ Children;
        [] ->
            []
    end.

%% @doc Find children of a txid that are in the given set.
find_children_in_set(ParentTxid, TxidSet) ->
    case ets:lookup(?MEMPOOL_TXS, ParentTxid) of
        [{_, Entry}] ->
            NumOutputs = length((Entry#mempool_entry.tx)#transaction.outputs),
            lists:filtermap(fun(Vout) ->
                case ets:lookup(?MEMPOOL_OUTPOINTS, {ParentTxid, Vout}) of
                    [{_, ChildTxid}] ->
                        case sets:is_element(ChildTxid, TxidSet) of
                            true -> {true, ChildTxid};
                            false -> false
                        end;
                    [] -> false
                end
            end, lists:seq(0, NumOutputs - 1));
        [] ->
            []
    end.

%% @doc Split a cluster into multiple components.
split_cluster(OldClusterId, Components, #state{union_find = UF, cluster_count = CC} = State) ->
    %% Delete old cluster
    ets:delete(?MEMPOOL_CLUSTERS, OldClusterId),

    %% Create new clusters for each component
    {UF2, NewClusterCount} = lists:foldl(
        fun(Component, {UFAcc, CountAcc}) ->
            %% Use first txid as new cluster ID
            [NewClusterId | _] = Component,
            %% Update union-find for all members
            UFAcc2 = lists:foldl(
                fun(Txid, UF3) ->
                    maps:put(Txid, NewClusterId, UF3)
                end,
                UFAcc,
                Component),
            %% Recompute cluster
            recompute_cluster(NewClusterId, UFAcc2),
            {UFAcc2, CountAcc + 1}
        end,
        {UF, 0},
        Components),

    %% Adjust cluster count (removed 1, added N)
    NewCC = CC - 1 + NewClusterCount,

    State#state{union_find = UF2, cluster_count = NewCC}.

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
