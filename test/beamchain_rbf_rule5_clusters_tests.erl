%%% RBF rule 5 counts distinct mempool CLUSTERS among the direct conflicts
%%% (Core policy/rbf.cpp GetEntriesForConflicts -> GetUniqueClusterCount),
%%% not the number of evicted transactions. Regtest row rbf/clusters/submit
%%% was a node_error: five clusters of 21 txs (105 evictions) were rejected
%%% "too many potential replacements" where Core accepts.
-module(beamchain_rbf_rule5_clusters_tests).
-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-record(mempool_entry, {
    txid, wtxid, tx, fee, size, vsize, weight, fee_rate, time_added,
    height_added, ancestor_count, ancestor_size, ancestor_fee,
    descendant_count, descendant_size, descendant_fee, spends_coinbase,
    rbf_signaling, adj_weight
}).

setup() ->
    cleanup(ok),
    ets:new(mempool_txs, [set, public, named_table]),
    ets:new(mempool_outpoints, [set, public, named_table]),
    ok.
cleanup(_) ->
    [catch ets:delete(T) || T <- [mempool_txs, mempool_outpoints]], ok.

mk(Prev, Index, Outs, Salt) ->
    #transaction{version = 2,
        inputs = [#tx_in{prev_out = #outpoint{hash = Prev, index = Index},
                         script_sig = <<Salt:16>>, sequence = 16#fffffffd,
                         witness = undefined}],
        outputs = [#tx_out{value = 1000, script_pubkey = <<16#51>>}
                   || _ <- lists:seq(1, Outs)],
        locktime = 0}.

add(Tx) ->
    Id = beamchain_serialize:tx_hash(Tx),
    ets:insert(mempool_txs, {Id, #mempool_entry{txid = Id, tx = Tx}}),
    [ets:insert(mempool_outpoints, {{P, I}, Id})
     || #tx_in{prev_out = #outpoint{hash = P, index = I}} <- Tx#transaction.inputs],
    Id.

%% A root with 20 outputs and one child per output: 21 txs, one cluster.
cluster(Seed) ->
    Root = add(mk(<<Seed:256>>, 0, 20, Seed)),
    Kids = [add(mk(Root, V, 1, Seed * 100 + V)) || V <- lists:seq(0, 19)],
    {Root, Kids}.

cluster_count_test_() ->
    {setup, fun setup/0, fun cleanup/1, fun() ->
        Cs = [cluster(S) || S <- lists:seq(1, 5)],
        Roots = [R || {R, _} <- Cs],
        %% 5 conflicts (roots) -> 5 clusters, though 105 txs would evict.
        ?assertEqual(5, beamchain_mempool:count_conflict_clusters(Roots)),
        %% Conflicting with a root and one of its own children: still 1.
        {R1, [K1 | _]} = hd(Cs),
        ?assertEqual(1, beamchain_mempool:count_conflict_clusters([R1, K1])),
        %% 101 singleton clusters exceed the limit; 105 txs in 5 do not.
        Singles = [add(mk(<<(1000 + N):256>>, 0, 1, 7000 + N))
                   || N <- lists:seq(1, 101)],
        ?assertEqual(101, beamchain_mempool:count_conflict_clusters(Singles)),
        ?assert(101 > ?MAX_RBF_EVICTIONS),
        ?assert(5 =< ?MAX_RBF_EVICTIONS)
    end}.
