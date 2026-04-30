-module(beamchain_mempool_descendants_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%%% Tests for beamchain_mempool:get_descendants/1, the helper backing
%%% the getmempooldescendants RPC. Mirrors the existing
%%% beamchain_mempool_tests structure (uses ETS directly, no
%%% gen_server).

%%% -------------------------------------------------------------------
%%% Re-define mempool_entry for test access
%%% -------------------------------------------------------------------

-record(mempool_entry, {
    txid, wtxid, tx, fee, size, vsize, weight, fee_rate,
    time_added, height_added,
    ancestor_count, ancestor_size, ancestor_fee,
    descendant_count, descendant_size, descendant_fee,
    spends_coinbase, rbf_signaling
}).

%%% -------------------------------------------------------------------
%%% ETS lifecycle
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
    ets:new(mempool_txs, [set, public, named_table,
                          {read_concurrency, true}]),
    ets:new(mempool_by_fee, [ordered_set, public, named_table]),
    ets:new(mempool_outpoints, [set, public, named_table]),
    ets:new(mempool_orphans, [set, public, named_table]),
    ets:new(mempool_clusters, [set, public, named_table,
                                {read_concurrency, true}]),
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
%%% Helpers
%%% -------------------------------------------------------------------

%% Insert a parent->child edge in the mempool: the "child" tx spends
%% (Parent, 0) and lives at txid Child.
insert_chain_node(Txid, ParentTxid) ->
    Tx = make_tx([{ParentTxid, 0}], [{1000, p2pkh_script()}]),
    Entry = make_entry(Txid, Tx),
    ets:insert(mempool_txs, {Txid, Entry}),
    %% link ParentTxid:0 -> Txid in the outpoint index
    ets:insert(mempool_outpoints, {{ParentTxid, 0}, Txid}),
    ok.

%% Insert a "root" tx that spends a non-mempool outpoint.
insert_root_node(Txid) ->
    Tx = make_tx([{<<99:256>>, 0}], [{1000, p2pkh_script()}]),
    Entry = make_entry(Txid, Tx),
    ets:insert(mempool_txs, {Txid, Entry}),
    ok.

make_entry(Txid, Tx) ->
    #mempool_entry{
        txid = Txid, wtxid = Txid, tx = Tx,
        fee = 1000, size = 200, vsize = 200, weight = 800,
        fee_rate = 5.0,
        time_added = erlang:system_time(second),
        height_added = 800000,
        ancestor_count = 1, ancestor_size = 200, ancestor_fee = 1000,
        descendant_count = 1, descendant_size = 200,
        descendant_fee = 1000,
        spends_coinbase = false, rbf_signaling = true
    }.

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

%%% -------------------------------------------------------------------
%%% Tests
%%% -------------------------------------------------------------------

%% Tx not in mempool -> [].
descendants_missing_tx_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
             ?assertEqual([],
                          beamchain_mempool:get_descendants(<<42:256>>))
         end]
     end}.

%% Single tx with no children -> [].
descendants_no_children_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
             A = <<1:256>>,
             insert_root_node(A),
             ?assertEqual([], beamchain_mempool:get_descendants(A))
         end]
     end}.

%% Linear chain A -> B -> C: get_descendants(A) = [B, C].
descendants_chain_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
             A = <<1:256>>,
             B = <<2:256>>,
             C = <<3:256>>,
             insert_root_node(A),
             insert_chain_node(B, A),
             insert_chain_node(C, B),
             Descs = lists:sort(beamchain_mempool:get_descendants(A)),
             ?assertEqual(lists:sort([B, C]), Descs),
             %% B's only descendant is C.
             ?assertEqual([C],
                          beamchain_mempool:get_descendants(B)),
             %% C is a leaf.
             ?assertEqual([],
                          beamchain_mempool:get_descendants(C))
         end]
     end}.

%% Diamond: A -> B, A -> C, B -> D, C -> D (different vouts).
%% get_descendants(A) returns {B, C, D} once each.
descendants_dedup_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
             A = <<1:256>>,
             B = <<2:256>>,
             C = <<3:256>>,
             D = <<4:256>>,
             %% A has TWO outputs so B and C can spend distinct vouts.
             TxA = make_tx([{<<99:256>>, 0}],
                            [{1000, p2pkh_script()},
                             {1000, p2pkh_script()}]),
             ets:insert(mempool_txs, {A, make_entry(A, TxA)}),
             %% B spends (A, 0), C spends (A, 1).
             TxB = make_tx([{A, 0}], [{1000, p2pkh_script()}]),
             ets:insert(mempool_txs, {B, make_entry(B, TxB)}),
             ets:insert(mempool_outpoints, {{A, 0}, B}),
             TxC = make_tx([{A, 1}], [{1000, p2pkh_script()}]),
             ets:insert(mempool_txs, {C, make_entry(C, TxC)}),
             ets:insert(mempool_outpoints, {{A, 1}, C}),
             %% D spends (B, 0) AND (C, 0): two parents in mempool.
             TxD = make_tx([{B, 0}, {C, 0}],
                            [{1000, p2pkh_script()}]),
             ets:insert(mempool_txs, {D, make_entry(D, TxD)}),
             ets:insert(mempool_outpoints, {{B, 0}, D}),
             ets:insert(mempool_outpoints, {{C, 0}, D}),
             %% Walking from A must yield B, C, D once each.
             Descs = lists:sort(beamchain_mempool:get_descendants(A)),
             ?assertEqual(lists:sort([B, C, D]), Descs)
         end]
     end}.
