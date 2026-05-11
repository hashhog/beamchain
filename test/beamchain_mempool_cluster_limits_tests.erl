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
    spends_coinbase, rbf_signaling
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
        spends_coinbase = false, rbf_signaling = false
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

%% Build a cluster record for a group of txids under a given root.
insert_cluster_group(RootId, Txids, TotalVSize) ->
    CD = #cluster_data{
        id = RootId,
        txids = Txids,
        total_fee = length(Txids) * 1000,
        total_vsize = TotalVSize,
        linearization = Txids,
        fee_rate = 5.0
    },
    ets:insert(mempool_clusters, {RootId, CD}).

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
                beamchain_mempool:check_cluster_limits_for_test(NewTx, 200))
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
                beamchain_mempool:check_cluster_limits_for_test(NewTx, 200))
         end]
     end}.

%%% ===================================================================
%%% Gate 7: Cluster vbytes limit = 101,000 (Core 101 kvB)
%%% ===================================================================

cluster_vbytes_limit_gate_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
             %% Cluster with 5 txs totalling 100,900 vbytes (just under limit).
             RootId = <<30:256>>,
             TxidsIn = [<<(30 + I):256>> || I <- lists:seq(0, 4)],
             lists:foreach(fun(Txid) ->
                 Tx = make_tx([{<<99:256>>, 0}], [{1000, p2pkh_script()}]),
                 insert_tx(Txid, Tx, 100)
             end, TxidsIn),
             insert_cluster_group(RootId, TxidsIn, 100900),

             %% New tx vsize = 200: 100900 + 200 = 101100 > 101000 → reject.
             LastTxid = lists:last(TxidsIn),
             NewTx = make_tx([{LastTxid, 0}], [{900, p2pkh_script()}]),

             ?assertThrow(too_large_cluster,
                beamchain_mempool:check_cluster_limits_for_test(NewTx, 200))
         end]
     end}.

%% Cluster vbytes exactly at limit — new tx with vsize=1 still fits.
cluster_vbytes_exactly_at_limit_fits_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
             RootId = <<40:256>>,
             TxidsIn = [<<(40 + I):256>> || I <- lists:seq(0, 4)],
             lists:foreach(fun(Txid) ->
                 Tx = make_tx([{<<99:256>>, 0}], [{1000, p2pkh_script()}]),
                 insert_tx(Txid, Tx, 100)
             end, TxidsIn),
             %% total_vsize = 100999 (1 byte below 101000)
             insert_cluster_group(RootId, TxidsIn, 100999),

             LastTxid = lists:last(TxidsIn),
             NewTx = make_tx([{LastTxid, 0}], [{900, p2pkh_script()}]),
             %% vsize=1 => 100999 + 1 = 101000 (at limit, not over) — accept.
             ?assertEqual(ok,
                beamchain_mempool:check_cluster_limits_for_test(NewTx, 1))
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
                beamchain_mempool:check_cluster_limits_for_test(NewTx, 100))
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
             %% 31 + 31 + 1 = 63 <= 64 and (31+31+1)*100 = 6300 <= 101000 — ok.
             ?assertEqual(ok,
                beamchain_mempool:check_cluster_limits_for_test(NewTx, 100))
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
                beamchain_mempool:check_cluster_limits_for_test(NewTx, 200))
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
