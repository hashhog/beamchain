-module(beamchain_gbt_order_tests).
%% getblocktemplate transaction order: Core lists transactions in the order
%% the block assembler selected them (parent immediately before its child,
%% best chunk first).  beamchain re-sorted the selection by txid.

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

-record(mempool_entry, {
    txid, wtxid, tx, fee, size, vsize, weight, fee_rate,
    time_added, height_added,
    ancestor_count, ancestor_size, ancestor_fee,
    descendant_count, descendant_size, descendant_fee,
    spends_coinbase, rbf_signaling,
    adj_weight
}).

entry(Txid, SpendsTxid) ->
    Tx = #transaction{version = 2, locktime = 0, outputs = [],
        inputs = [#tx_in{prev_out = #outpoint{hash = SpendsTxid, index = 0},
                         script_sig = <<>>, sequence = 16#ffffffff,
                         witness = []}]},
    #mempool_entry{txid = Txid, tx = Tx}.

ids(Entries) -> [E#mempool_entry.txid || E <- Entries].

%% Selection order [P, C, X] (CPFP package first, then X) must be kept even
%% though X's txid sorts before P's.
topological_sort_keeps_selection_order_test() ->
    P = <<9:256>>, C = <<5:256>>, X = <<1:256>>,
    In = [entry(P, <<100:256>>), entry(C, P), entry(X, <<101:256>>)],
    ?assertEqual([P, C, X], ids(beamchain_miner:topological_sort(In))).

%% Still reorders when a child precedes its parent.
topological_sort_parents_first_test() ->
    P = <<9:256>>, C = <<5:256>>, X = <<1:256>>,
    In = [entry(C, P), entry(X, <<101:256>>), entry(P, <<100:256>>)],
    ?assertEqual([P, C, X], ids(beamchain_miner:topological_sort(In))).

%% Grandparent chain given fully reversed.
topological_sort_chain_test() ->
    A = <<3:256>>, B = <<2:256>>, C = <<1:256>>,
    In = [entry(C, B), entry(B, A), entry(A, <<100:256>>)],
    ?assertEqual([A, B, C], ids(beamchain_miner:topological_sort(In))).
