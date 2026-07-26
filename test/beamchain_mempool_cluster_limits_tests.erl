-module(beamchain_mempool_cluster_limits_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%%% W75 — beamchain ancestor/descendant/cluster limits audit
%%%
%%% Tests for the cluster-limit gate added in W75:
%%%   check_cluster_limits/2 — pre-acceptance guard (Core validation.cpp:1341-1344)
%%%
%%% Reference constants (Bitcoin Core policy/policy.h:72-74):
%%%   DEFAULT_CLUSTER_LIMIT          = 64   (tx count)
%%%   DEFAULT_CLUSTER_SIZE_LIMIT_KVB = 101  (=> 101,000 vbytes)

%%% -------------------------------------------------------------------
%%% Re-define internal records needed for test helpers
%%% -------------------------------------------------------------------

-record(mempool_entry, {
    txid, wtxid, tx, fee, size, vsize, weight, fee_rate,
    time_added, height_added,
    ancestor_count, ancestor_size, ancestor_fee,
    descendant_count, descendant_size, descendant_fee,
    spends_coinbase, rbf_signaling,
    adj_weight
}).

-record(cluster_data, {
    id, txids, total_fee, total_vsize, linearization, fee_rate
}).

%%% -------------------------------------------------------------------
%%% ETS lifecycle helpers
%%% -------------------------------------------------------------------

setup() ->
    Tables = [mempool_txs, mempool_by_fee, mempool_outpoints,
              mempool_orphans, mempool_clusters, mempool_ephemeral],
    lists:foreach(fun(T) ->
        case ets:info(T) of
            undefined -> ok;
            _ -> ets:delete(T)
        end
    end, Tables),
    ets:new(mempool_txs,       [set, public, named_table, {read_concurrency, true}]),
    ets:new(mempool_by_fee,    [ordered_set, public, named_table]),
    ets:new(mempool_outpoints, [set, public, named_table]),
    ets:new(mempool_orphans,   [set, public, named_table]),
    ets:new(mempool_clusters,  [set, public, named_table, {read_concurrency, true}]),
    ets:new(mempool_ephemeral, [set, public, named_table]),
    ok.

cleanup(_) ->
    lists:foreach(fun(T) ->
        case ets:info(T) of
            undefined -> ok;
            _ -> ets:delete(T)
        end
    end, [mempool_txs, mempool_by_fee, mempool_outpoints,
          mempool_orphans, mempool_clusters, mempool_ephemeral]).

%%% -------------------------------------------------------------------
%%% Tx / entry construction helpers
%%% -------------------------------------------------------------------

make_tx(Inputs, Outputs) ->
    TxIns = [#tx_in{
        prev_out = #outpoint{hash = H, index = I},
        script_sig = <<>>, sequence = 16#fffffffe, witness = []
    } || {H, I} <- Inputs],
    TxOuts = [#tx_out{value = V, script_pubkey = SPK} ||
              {V, SPK} <- Outputs],
    #transaction{
        version = 2, inputs = TxIns, outputs = TxOuts, locktime = 0
    }.

p2pkh_script() ->
    <<16#76, 16#a9, 16#14, 0:160, 16#88, 16#ac>>.

make_entry(Txid, Tx, VSize) ->
    #mempool_entry{
        txid = Txid, wtxid = Txid, tx = Tx,
        fee = 1000, size = VSize, vsize = VSize, weight = VSize * 4,
        fee_rate = 5.0,
        time_added = erlang:system_time(second),
        height_added = 800000,
        ancestor_count = 1, ancestor_size = VSize, ancestor_fee = 1000,
        descendant_count = 1, descendant_size = VSize, descendant_fee = 1000,
        spends_coinbase = false, rbf_signaling = false,
        adj_weight = VSize * 4
    }.

%% Insert a tx+entry into mempool_txs and mempool_outpoints (for each output).
%% Also inserts a cluster record reflecting the tx as a singleton cluster
%% (or can be grouped later).
insert_tx(Txid, Tx, VSize) ->
    Entry = make_entry(Txid, Tx, VSize),
    ets:insert(mempool_txs, {Txid, Entry}),
    %% Register each output as spendable (outpoints index).
    lists:foreach(fun(I) ->
        ets:insert(mempool_outpoints, {{Txid, I}, Txid})
    end, lists:seq(0, length(Tx#transaction.outputs) - 1)),
    ok.

%% Insert an entry whose UNROUNDED sigop-adjusted weight is exactly AdjWeight.
%% vsize is derived the way the production path derives it (ceil(adj/4)), so a
%% fixture can never accidentally encode a self-inconsistent pair.
insert_tx_w(Txid, Tx, AdjWeight) ->
    VSize = (AdjWeight + ?WITNESS_SCALE_FACTOR - 1) div ?WITNESS_SCALE_FACTOR,
    Entry = (make_entry(Txid, Tx, VSize))#mempool_entry{adj_weight = AdjWeight},
    ets:insert(mempool_txs, {Txid, Entry}),
    lists:foreach(fun(I) ->
        ets:insert(mempool_outpoints, {{Txid, I}, Txid})
    end, lists:seq(0, length(Tx#transaction.outputs) - 1)),
    ok.

%% Build a cluster record over Txids.  check_cluster_limits/2 derives the count
%% and weight from LIVE ?MEMPOOL_TXS membership, so the cached totals here are
%% only for the fee-rate/eviction machinery; they are computed from the same
%% entries to keep the fixture self-consistent.
insert_cluster_of(RootId, Txids) ->
    TotalVSize = lists:sum([entry_field(T, #mempool_entry.vsize) || T <- Txids]),
    CD = #cluster_data{
        id = RootId,
        txids = Txids,
        total_fee = length(Txids) * 1000,
        total_vsize = TotalVSize,
        linearization = Txids,
        fee_rate = 5.0
    },
    ets:insert(mempool_clusters, {RootId, CD}).

entry_field(Txid, Pos) ->
    [{_, E}] = ets:lookup(mempool_txs, Txid),
    element(Pos, E).

%% Legacy helper: N txs of uniform vsize, cluster record over them.
insert_cluster_group(RootId, Txids, _TotalVSize) ->
    insert_cluster_of(RootId, Txids).

%%% ===================================================================
%%% Gate 1: Policy constant values (Core parity)
%%% ===================================================================

%% Core DEFAULT_CLUSTER_LIMIT=64 (policy.h:72)
cluster_count_constant_test() ->
    ?assertEqual(64, beamchain_mempool:cluster_count_limit()).

%% Core DEFAULT_CLUSTER_SIZE_LIMIT_KVB=101 => 101,000 vbytes (policy.h:74)
cluster_vbytes_constant_test() ->
    ?assertEqual(101000, beamchain_mempool:cluster_vbytes_limit()).

%%% ===================================================================
%%% Gate 2: Ancestor count (Core DEFAULT_ANCESTOR_LIMIT=25)
%%% ===================================================================

%% compute_ancestors respects MAX_ANCESTOR_COUNT = 25
ancestor_count_limit_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
             %% Pre-populate a parent at ancestor_count = 25 (at the limit).
             ParentTxid = <<1:256>>,
             ParentTx = make_tx([{<<99:256>>, 0}], [{1000, p2pkh_script()}]),
             Entry = make_entry(ParentTxid, ParentTx, 200),
             %% Manually set ancestor_count to 25 (the parent itself has 25 ancestors).
             OverLimit = Entry#mempool_entry{ancestor_count = 25},
             ets:insert(mempool_txs, {ParentTxid, OverLimit}),

             %% A new tx spending this parent would compute AncCount = 1 + 25 = 26.
             NewTx = make_tx([{ParentTxid, 0}], [{900, p2pkh_script()}]),
             {AncCount, _, _} = beamchain_mempool:compute_ancestors_for_test(
                 NewTx, 1000, 200),
             ?assert(AncCount > ?MAX_ANCESTOR_COUNT,
                     "ancestor count must exceed 25 when parent already has 25")
         end]
     end}.

%%% ===================================================================
%%% Gate 3: Ancestor vbytes (Core DEFAULT_ANCESTOR_LIMIT → 101 kvB)
%%% ===================================================================

ancestor_size_limit_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
             ParentTxid = <<2:256>>,
             ParentTx = make_tx([{<<99:256>>, 0}], [{1000, p2pkh_script()}]),
             Entry = (make_entry(ParentTxid, ParentTx, 500))#mempool_entry{
                 ancestor_size = 100800  %% close to limit (101000)
             },
             ets:insert(mempool_txs, {ParentTxid, Entry}),

             %% New tx vsize = 500: combined = 100800 + 500 = 101300 > 101000
             NewTx = make_tx([{ParentTxid, 0}], [{900, p2pkh_script()}]),
             {_, AncSize, _} = beamchain_mempool:compute_ancestors_for_test(
                 NewTx, 1000, 500),
             ?assert(AncSize > ?MAX_ANCESTOR_SIZE)
         end]
     end}.

%%% ===================================================================
%%% Gate 4: Descendant count (Core DEFAULT_DESCENDANT_LIMIT=25)
%%% ===================================================================

descendant_count_limit_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
             ParentTxid = <<3:256>>,
             ParentTx = make_tx([{<<99:256>>, 0}], [{1000, p2pkh_script()}]),
             %% Parent already has 25 descendants (including itself): at limit.
             Entry = (make_entry(ParentTxid, ParentTx, 200))#mempool_entry{
                 descendant_count = 25,
                 descendant_size  = 5000
             },
             ets:insert(mempool_txs, {ParentTxid, Entry}),
             ets:insert(mempool_outpoints, {{ParentTxid, 0}, ParentTxid}),

             %% New tx spending parent would push parent's descendant_count to 26.
             NewTx = make_tx([{ParentTxid, 0}], [{900, p2pkh_script()}]),
             ?assertThrow(too_long_mempool_chain,
                beamchain_mempool:check_descendant_limits_for_test(NewTx, 200))
         end]
     end}.

%%% ===================================================================
%%% Gate 5: Descendant vbytes (Core DEFAULT_DESCENDANT_LIMIT → 101 kvB)
%%% ===================================================================

descendant_size_limit_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
             ParentTxid = <<4:256>>,
             ParentTx = make_tx([{<<99:256>>, 0}], [{1000, p2pkh_script()}]),
             Entry = (make_entry(ParentTxid, ParentTx, 200))#mempool_entry{
                 descendant_count = 10,
                 descendant_size  = 100900  %% 100 bytes below limit
             },
             ets:insert(mempool_txs, {ParentTxid, Entry}),
             ets:insert(mempool_outpoints, {{ParentTxid, 0}, ParentTxid}),

             %% new tx vsize = 200 => 100900 + 200 = 101100 > 101000
             NewTx = make_tx([{ParentTxid, 0}], [{900, p2pkh_script()}]),
             ?assertThrow(too_long_mempool_chain,
                beamchain_mempool:check_descendant_limits_for_test(NewTx, 200))
         end]
     end}.

%%% ===================================================================
%%% Gate 6: Cluster count limit = 64 (Core DEFAULT_CLUSTER_LIMIT)
%%% ===================================================================

%% check_cluster_limits throws too_large_cluster when adding would
%% create a cluster with 65+ transactions.
cluster_count_limit_gate_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
             %% Build a cluster with exactly 64 txs (at the limit).
             RootId = <<10:256>>,
             TxidsIn = [<<(10 + I):256>> || I <- lists:seq(0, 63)],
             %% Insert all 64 txs into mempool_txs so parent lookup works.
             lists:foreach(fun(Txid) ->
                 Tx = make_tx([{<<99:256>>, 0}], [{1000, p2pkh_script()}]),
                 insert_tx(Txid, Tx, 200)
             end, TxidsIn),
             %% Register them all in one cluster.
             insert_cluster_group(RootId, TxidsIn, 64 * 200),

             %% New tx that spends the last element of the cluster — would push to 65.
             LastTxid = lists:last(TxidsIn),
             NewTx = make_tx([{LastTxid, 0}], [{900, p2pkh_script()}]),

             ?assertThrow(too_large_cluster,
                beamchain_mempool:check_cluster_limits_for_test(NewTx, 800))
         end]
     end}.

%% Cluster exactly AT limit (64 txs) with 1 new tx joining a DIFFERENT cluster
%% must not be rejected.
cluster_count_at_limit_no_merge_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
             %% Cluster A: 64 txs
             RootA = <<20:256>>,
             TxidsA = [<<(20 + I):256>> || I <- lists:seq(0, 63)],
             lists:foreach(fun(Txid) ->
                 Tx = make_tx([{<<99:256>>, 0}], [{1000, p2pkh_script()}]),
                 insert_tx(Txid, Tx, 200)
             end, TxidsA),
             insert_cluster_group(RootA, TxidsA, 64 * 200),

             %% New tx spending a confirmed (non-mempool) output — joins no cluster.
             %% Must use a hash that is NOT in TxidsA (which covers <<20:256>>..<<83:256>>).
             NewTx = make_tx([{<<9999:256>>, 0}], [{900, p2pkh_script()}]),
             ?assertEqual(ok,
                beamchain_mempool:check_cluster_limits_for_test(NewTx, 800))
         end]
     end}.

%%% ===================================================================
%%% Gate 7: Cluster size limit = 404,000 WEIGHT units
%%% (Core txmempool.cpp:181 cluster_size_vbytes * WITNESS_SCALE_FACTOR)
%%% ===================================================================

cluster_weight_limit_gate_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
             %% Cluster with 5 txs totalling 403,600 weight (just under limit).
             RootId = <<30:256>>,
             TxidsIn = [<<(30 + I):256>> || I <- lists:seq(0, 4)],
             lists:foreach(fun(Txid) ->
                 Tx = make_tx([{<<99:256>>, 0}], [{1000, p2pkh_script()}]),
                 insert_tx_w(Txid, Tx, 80720)   %% 5 * 80720 = 403600 wu
             end, TxidsIn),
             insert_cluster_of(RootId, TxidsIn),

             %% New tx weight = 800: 403600 + 800 = 404400 > 404000 → reject.
             LastTxid = lists:last(TxidsIn),
             NewTx = make_tx([{LastTxid, 0}], [{900, p2pkh_script()}]),

             ?assertThrow(too_large_cluster,
                beamchain_mempool:check_cluster_limits_for_test(NewTx, 800))
         end]
     end}.

%% Cluster weight exactly at limit — new tx with adjusted weight 4 still fits.
cluster_weight_exactly_at_limit_fits_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
             RootId = <<40:256>>,
             TxidsIn = [<<(40 + I):256>> || I <- lists:seq(0, 4)],
             %% 4 * 80799 + 80800 = 403996 (4 wu below 404000)
             lists:foreach(fun(Txid) ->
                 Tx = make_tx([{<<99:256>>, 0}], [{1000, p2pkh_script()}]),
                 insert_tx_w(Txid, Tx, 80799)
             end, lists:sublist(TxidsIn, 4)),
             insert_tx_w(lists:last(TxidsIn),
                         make_tx([{<<99:256>>, 0}], [{1000, p2pkh_script()}]), 80800),
             insert_cluster_of(RootId, TxidsIn),
             ?assertEqual(403996,
                 lists:sum([entry_field(T, #mempool_entry.adj_weight) || T <- TxidsIn])),

             LastTxid = lists:last(TxidsIn),
             NewTx = make_tx([{LastTxid, 0}], [{900, p2pkh_script()}]),
             %% adj weight = 4 => 403996 + 4 = 404000 (at limit, not over) — accept.
             ?assertEqual(ok,
                beamchain_mempool:check_cluster_limits_for_test(NewTx, 4))
         end]
     end}.

%%% ===================================================================
%%% Gate 8: Cluster merge — two clusters joining must respect limits
%%% ===================================================================

cluster_merge_count_limit_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
             %% Cluster A: 33 txs; Cluster B: 32 txs.
             %% New tx spends one from each => would merge: 33+32+1 = 66 > 64.
             RootA = <<50:256>>,
             TxidsA = [<<(50 + I):256>> || I <- lists:seq(0, 32)],
             lists:foreach(fun(Txid) ->
                 Tx = make_tx([{<<99:256>>, 0}], [{1000, p2pkh_script()}]),
                 insert_tx(Txid, Tx, 100)
             end, TxidsA),
             insert_cluster_group(RootA, TxidsA, 33 * 100),

             RootB = <<90:256>>,
             TxidsB = [<<(90 + I):256>> || I <- lists:seq(0, 31)],
             lists:foreach(fun(Txid) ->
                 Tx = make_tx([{<<99:256>>, 0}], [{1000, p2pkh_script()}]),
                 insert_tx(Txid, Tx, 100)
             end, TxidsB),
             insert_cluster_group(RootB, TxidsB, 32 * 100),

             LastA = lists:last(TxidsA),
             LastB = lists:last(TxidsB),
             NewTx = make_tx([{LastA, 0}, {LastB, 0}], [{900, p2pkh_script()}]),

             ?assertThrow(too_large_cluster,
                beamchain_mempool:check_cluster_limits_for_test(NewTx, 400))
         end]
     end}.

%% Two clusters merging within limit is allowed.
cluster_merge_within_limit_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
             %% Cluster A: 31 txs; Cluster B: 31 txs; new tx => 63 total — under 64.
             RootA = <<60:256>>,
             TxidsA = [<<(60 + I):256>> || I <- lists:seq(0, 30)],
             lists:foreach(fun(Txid) ->
                 Tx = make_tx([{<<99:256>>, 0}], [{1000, p2pkh_script()}]),
                 insert_tx(Txid, Tx, 100)
             end, TxidsA),
             insert_cluster_group(RootA, TxidsA, 31 * 100),

             RootB = <<95:256>>,
             TxidsB = [<<(95 + I):256>> || I <- lists:seq(0, 30)],
             lists:foreach(fun(Txid) ->
                 Tx = make_tx([{<<99:256>>, 0}], [{1000, p2pkh_script()}]),
                 insert_tx(Txid, Tx, 100)
             end, TxidsB),
             insert_cluster_group(RootB, TxidsB, 31 * 100),

             LastA = lists:last(TxidsA),
             LastB = lists:last(TxidsB),
             NewTx = make_tx([{LastA, 0}, {LastB, 0}], [{900, p2pkh_script()}]),
             %% 31 + 31 + 1 = 63 <= 64 and (31+31)*400 + 400 = 25200 <= 404000 — ok.
             ?assertEqual(ok,
                beamchain_mempool:check_cluster_limits_for_test(NewTx, 400))
         end]
     end}.

%%% ===================================================================
%%% Gate 9: No-parent tx always passes cluster gate (singleton)
%%% ===================================================================

no_parents_always_ok_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
             %% Tx spending only confirmed (non-mempool) outputs => singleton cluster.
             NewTx = make_tx([{<<77:256>>, 0}], [{900, p2pkh_script()}]),
             ?assertEqual(ok,
                beamchain_mempool:check_cluster_limits_for_test(NewTx, 800))
         end]
     end}.

%%% ===================================================================
%%% Gate 10: check_descendant_limits walks all ancestors (not just direct parents)
%%% ===================================================================

descendant_limit_walks_ancestors_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
             %% Chain: A -> B -> C (each already at descendant_count=1).
             %% C's grandparent A should also be checked when adding D below C.

             A = <<101:256>>,
             ATx = make_tx([{<<99:256>>, 0}], [{1000, p2pkh_script()}]),
             AEntry = (make_entry(A, ATx, 200))#mempool_entry{
                 descendant_count = 25,   %% A already at the limit
                 descendant_size  = 5000
             },
             ets:insert(mempool_txs, {A, AEntry}),

             B = <<102:256>>,
             BTx = make_tx([{A, 0}], [{1000, p2pkh_script()}]),
             BEntry = make_entry(B, BTx, 200),
             ets:insert(mempool_txs, {B, BEntry}),
             ets:insert(mempool_outpoints, {{A, 0}, B}),

             %% Adding D spending B should catch A's over-limit via the walk.
             NewTx = make_tx([{B, 0}], [{900, p2pkh_script()}]),
             ?assertThrow(too_long_mempool_chain,
                beamchain_mempool:check_descendant_limits_for_test(NewTx, 200))
         end]
     end}.

%%% ===================================================================
%%% WAVE A — Core v31 cluster mempool limits, exact-form parity
%%%
%%% Reference (read directly from bitcoin-core/):
%%%   policy/policy.h:50   DEFAULT_BYTES_PER_SIGOP        = 20
%%%   policy/policy.h:72   DEFAULT_CLUSTER_LIMIT          = 64
%%%   policy/policy.h:74   DEFAULT_CLUSTER_SIZE_LIMIT_KVB = 101
%%%   kernel/mempool_limits.h:22  cluster_size_vbytes = 101 * 1000
%%%   txmempool.cpp:181    max_cluster_size = cluster_size_vbytes * WITNESS_SCALE_FACTOR
%%%   txmempool.cpp:1017   TxGraph is fed GetSigOpsAdjustedWeight(weight, sigops, 20)
%%%   policy/policy.cpp:390 GetSigOpsAdjustedWeight = max(weight, sigop_cost*20)
%%%   txgraph.cpp:2059     total_count > max_count || total_size > max_size  (strict >)
%%%
%%% In WEIGHT units throughout:
%%%   per-tx  := max(tx_weight, tx_sigops_cost * 20)     [UNROUNDED]
%%%   cluster := sum(per-tx)                              [NO per-tx division]
%%%   reject iff cluster > 404000
%%% ===================================================================

%%% -------------------------------------------------------------------
%%% A1 — the enforcement bound is 404,000 WEIGHT units, and the REPORTED
%%% limit stays 101,000 VBYTES (Core rpc/mempool.cpp:1062 pushes
%%% limits.cluster_size_vbytes, not the weight-scaled TxGraph bound).
%%% -------------------------------------------------------------------
wave_a_constants_test() ->
    ?assertEqual(64,     beamchain_mempool:cluster_count_limit()),
    ?assertEqual(101000, beamchain_mempool:cluster_vbytes_limit()),
    ?assertEqual(404000, beamchain_mempool:cluster_weight_limit()),
    ?assertEqual(beamchain_mempool:cluster_vbytes_limit() * ?WITNESS_SCALE_FACTOR,
                 beamchain_mempool:cluster_weight_limit()).

%%% -------------------------------------------------------------------
%%% A2 — COUNT boundary: 64 accepts, 65 rejects.
%%% -------------------------------------------------------------------
wave_a_count_64_accepts_65_rejects_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
             %% 63-member cluster: adding one more => 64, at the limit, ACCEPT.
             Root63 = <<200:256>>,
             Txids63 = [<<(200 + I):256>> || I <- lists:seq(0, 62)],
             lists:foreach(fun(T) ->
                 insert_tx(T, make_tx([{<<99:256>>, 0}], [{1000, p2pkh_script()}]), 100)
             end, Txids63),
             insert_cluster_of(Root63, Txids63),
             Child63 = make_tx([{lists:last(Txids63), 0}], [{900, p2pkh_script()}]),
             ?assertEqual(ok,
                beamchain_mempool:check_cluster_limits_for_test(Child63, 400)),

             %% 64-member cluster: adding one more => 65, over the limit, REJECT.
             Root64 = <<400:256>>,
             Txids64 = [<<(400 + I):256>> || I <- lists:seq(0, 63)],
             lists:foreach(fun(T) ->
                 insert_tx(T, make_tx([{<<99:256>>, 0}], [{1000, p2pkh_script()}]), 100)
             end, Txids64),
             insert_cluster_of(Root64, Txids64),
             Child64 = make_tx([{lists:last(Txids64), 0}], [{900, p2pkh_script()}]),
             ?assertThrow(too_large_cluster,
                beamchain_mempool:check_cluster_limits_for_test(Child64, 400))
         end]
     end}.

%%% -------------------------------------------------------------------
%%% A3 — SIZE boundary: 404000 accepts, 404001 rejects.
%%% Same cluster, same new tx, one weight unit apart.
%%% -------------------------------------------------------------------
wave_a_weight_404000_accepts_404001_rejects_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
             Root = <<600:256>>,
             Txids = [<<(600 + I):256>> || I <- lists:seq(0, 4)],
             lists:foreach(fun(T) ->
                 insert_tx_w(T, make_tx([{<<99:256>>, 0}], [{1000, p2pkh_script()}]), 80000)
             end, Txids),
             %% Cluster sits at exactly 400,000 weight units (5 * 80000).
             insert_cluster_of(Root, Txids),
             ?assertEqual(400000,
                 lists:sum([entry_field(T, #mempool_entry.adj_weight) || T <- Txids])),
             NewTx = make_tx([{lists:last(Txids), 0}], [{900, p2pkh_script()}]),

             %% 400000 + 4000 = 404000 — exactly at the bound, ACCEPT.
             ?assertEqual(ok,
                beamchain_mempool:check_cluster_limits_for_test(NewTx, 4000)),
             %% 400000 + 4001 = 404001 — one weight unit over, REJECT.
             ?assertThrow(too_large_cluster,
                beamchain_mempool:check_cluster_limits_for_test(NewTx, 4001))
         end]
     end}.

%%% -------------------------------------------------------------------
%%% A4 — UNITS regression.  THIS IS THE TEST THAT CATCHES A CONSTANT SWAP
%%% WITHOUT A UNIT CHANGE (i.e. 101000 -> 404000 while still summing
%%% per-transaction ceil(w/4) vbytes).
%%%
%%% Construct a 64-tx cluster with:
%%%   sum(w_i)         = 404000     -> Core ACCEPTS (404000 !> 404000)
%%%   sum(ceil(w_i/4)) = 101048     -> a per-tx-rounding impl REJECTS
%%%
%%% 63 txs of weight 6313 (= 1 mod 4) + 1 tx of weight 6281 (= 1 mod 4):
%%%   63*6313 + 6281                      = 404000
%%%   63*ceil(6313/4) + ceil(6281/4)
%%%     = 63*1579 + 1571 = 99477 + 1571   = 101048   (> 101000)
%%%
%%% The cluster record deliberately carries BOTH axes so a regression that
%%% reads total_vsize against 101000 fails here while the weight form passes.
%%% -------------------------------------------------------------------
wave_a_units_no_per_tx_rounding_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
             %% Arithmetic pinned in the test itself so the fixture cannot drift.
             ?assertEqual(404000, 63 * 6313 + 6281),
             ?assertEqual(101048, 63 * ((6313 + 3) div 4) + ((6281 + 3) div 4)),
             ?assert(101048 > 101000),

             Root = <<800:256>>,
             Txids = [<<(800 + I):256>> || I <- lists:seq(0, 62)],
             lists:foreach(fun(T) ->
                 insert_tx_w(T, make_tx([{<<99:256>>, 0}], [{1000, p2pkh_script()}]), 6313)
             end, Txids),
             insert_cluster_of(Root, Txids),
             %% 63 members: sum(adj_weight) = 397719, sum(vsize=ceil(w/4)) = 99477.
             ?assertEqual(397719,
                 lists:sum([entry_field(T, #mempool_entry.adj_weight) || T <- Txids])),
             ?assertEqual(99477,
                 lists:sum([entry_field(T, #mempool_entry.vsize) || T <- Txids])),

             NewTx = make_tx([{lists:last(Txids), 0}], [{900, p2pkh_script()}]),
             %% New tx: adjusted weight 6281, ceil -> 1571 vbytes.
             %% Weight form : 397719 + 6281 = 404000 <= 404000  -> ACCEPT (Core).
             %% Rounded form:  99477 + 1571 = 101048 >  101000  -> would REJECT.
             %% Count: 63 + 1 = 64 <= 64, so the count axis cannot mask this.
             ?assertEqual(ok,
                beamchain_mempool:check_cluster_limits_for_test(NewTx, 6281))
         end]
     end}.

%%% -------------------------------------------------------------------
%%% A5 — per-tx quantity is max(weight, sigops*20), UNROUNDED
%%% (Core policy/policy.cpp:390 GetSigOpsAdjustedWeight).
%%% -------------------------------------------------------------------
wave_a_sigop_adjusted_weight_form_test() ->
    Tx = make_tx([{<<99:256>>, 0}], [{1000, p2pkh_script()}]),
    W = beamchain_serialize:tx_weight(Tx),

    %% sigops = 0 -> the weight term wins, returned verbatim (no rounding).
    ?assertEqual(W, beamchain_serialize:tx_sigop_adjusted_weight(Tx, 0)),

    %% A sigop cost just below W/20 still leaves the weight term dominant.
    LowSigops = W div 20,
    ?assertEqual(max(W, LowSigops * 20),
                 beamchain_serialize:tx_sigop_adjusted_weight(Tx, LowSigops)),

    %% A large sigop cost makes the sigop term dominate: exactly sigops*20.
    HighSigops = W,   %% HighSigops*20 = 20*W >> W
    ?assertEqual(HighSigops * 20,
                 beamchain_serialize:tx_sigop_adjusted_weight(Tx, HighSigops)),

    %% tx_sigop_vsize/2 must remain exactly ceil(adjusted_weight / 4) — the
    %% rounding lives ONLY here, never in the cluster accumulator.
    lists:foreach(fun(S) ->
        Adj = beamchain_serialize:tx_sigop_adjusted_weight(Tx, S),
        ?assertEqual((Adj + ?WITNESS_SCALE_FACTOR - 1) div ?WITNESS_SCALE_FACTOR,
                     beamchain_serialize:tx_sigop_vsize(Tx, S))
    end, [0, 1, 5, 17, 100, 3000]).

%%% -------------------------------------------------------------------
%%% A6 — sigop-DOMINATED cluster rejection: the tx's raw weight is far
%%% under the bound, but max(weight, sigops*20) is what trips the limit.
%%% -------------------------------------------------------------------
wave_a_sigop_dominated_trips_limit_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
             Root = <<1000:256>>,
             Txids = [<<(1000 + I):256>> || I <- lists:seq(0, 4)],
             lists:foreach(fun(T) ->
                 insert_tx_w(T, make_tx([{<<99:256>>, 0}], [{1000, p2pkh_script()}]), 80000)
             end, Txids),
             %% Cluster at 400,000 weight units — 4,000 wu of headroom.
             insert_cluster_of(Root, Txids),

             NewTx = make_tx([{lists:last(Txids), 0}], [{900, p2pkh_script()}]),
             RawWeight = beamchain_serialize:tx_weight(NewTx),
             %% Raw weight alone fits comfortably in the 4,000 wu of headroom.
             ?assert(RawWeight < 4000),

             %% 0 sigops -> weight term dominates -> ACCEPT.
             AdjNoSigops = beamchain_serialize:tx_sigop_adjusted_weight(NewTx, 0),
             ?assertEqual(RawWeight, AdjNoSigops),
             ?assertEqual(ok,
                beamchain_mempool:check_cluster_limits_for_test(NewTx, AdjNoSigops)),

             %% 201 sigops -> 201*20 = 4020 wu dominates the raw weight and
             %% pushes the cluster to 404,020 > 404,000 -> REJECT.
             Sigops = 201,
             AdjWithSigops =
                 beamchain_serialize:tx_sigop_adjusted_weight(NewTx, Sigops),
             ?assertEqual(Sigops * ?DEFAULT_BYTES_PER_SIGOP, AdjWithSigops),
             ?assert(AdjWithSigops > RawWeight),
             ?assertEqual(404020, 400000 + AdjWithSigops),
             ?assertThrow(too_large_cluster,
                beamchain_mempool:check_cluster_limits_for_test(NewTx, AdjWithSigops))
         end]
     end}.

%%% -------------------------------------------------------------------
%%% A7 — reject TOKEN is Core's hyphenated "too-large-cluster".
%%% Core validation.cpp:1024/:1116/:1343/:1521 pass an EMPTY debug string,
%%% so the RPC message must be the bare token with no decoration.
%%% Before this wave the atom fell through to the catch-all and surfaced as
%%% the underscored Erlang term "too_large_cluster".
%%% -------------------------------------------------------------------
wave_a_reject_token_is_hyphenated_test() ->
    Txid = <<0:256>>,
    ?assertMatch({error, _, <<"too-large-cluster">>},
                 beamchain_rpc:format_mempool_error(too_large_cluster, Txid)),
    %% testmempoolaccept surfaces the same reject-reason string.
    ?assertEqual(<<"too-large-cluster">>,
                 beamchain_rpc:mempool_reject_reason(too_large_cluster, Txid)),
    %% No underscored form may leak out.
    {error, _, Msg} = beamchain_rpc:format_mempool_error(too_large_cluster, Txid),
    ?assertEqual(nomatch, binary:match(Msg, <<"too_large_cluster">>)).

%%% -------------------------------------------------------------------
%%% A8 — MUST NOT CHANGE: package limits and TRUC limits are separate
%%% policies and keep their own constants.
%%% -------------------------------------------------------------------
wave_a_untouched_neighbouring_limits_test() ->
    %% MAX_PACKAGE_COUNT is a DIFFERENT limit (Core policy/packages.h:19).
    ?assertEqual(25, ?MAX_PACKAGE_COUNT),
    ?assertEqual(404000, ?MAX_PACKAGE_WEIGHT),
    %% TRUC / v3 ancestor+descendant caps are the only surviving anc/desc
    %% enforcement (Core policy/truc_policy.h).
    ?assertEqual(2, ?TRUC_ANCESTOR_LIMIT),
    ?assertEqual(2, ?TRUC_DESCENDANT_LIMIT).
