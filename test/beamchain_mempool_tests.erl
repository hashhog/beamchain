-module(beamchain_mempool_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%%% ===================================================================
%%% Re-define the mempool_entry record for test access
%%% (it's internal to beamchain_mempool)
%%% ===================================================================

-record(mempool_entry, {
    txid, wtxid, tx, fee, size, vsize, weight, fee_rate,
    time_added, height_added,
    ancestor_count, ancestor_size, ancestor_fee,
    descendant_count, descendant_size, descendant_fee,
    spends_coinbase, rbf_signaling
}).

%%% ===================================================================
%%% ETS table setup for testing (no gen_server needed)
%%% ===================================================================

setup() ->
    Tables = [mempool_txs, mempool_by_fee, mempool_outpoints, mempool_orphans],
    lists:foreach(fun(T) ->
        case ets:info(T) of
            undefined -> ok;
            _ -> ets:delete(T)
        end
    end, Tables),
    ets:new(mempool_txs, [set, public, named_table, {read_concurrency, true}]),
    ets:new(mempool_by_fee, [ordered_set, public, named_table]),
    ets:new(mempool_outpoints, [set, public, named_table]),
    ets:new(mempool_orphans, [set, public, named_table]),
    ok.

cleanup(_) ->
    lists:foreach(fun(T) ->
        case ets:info(T) of
            undefined -> ok;
            _ -> ets:delete(T)
        end
    end, [mempool_txs, mempool_by_fee, mempool_outpoints, mempool_orphans]).

%%% ===================================================================
%%% has_tx / get_tx / get_all_txids tests
%%% ===================================================================

has_tx_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [
         ?_assertEqual(false, beamchain_mempool:has_tx(<<1:256>>)),
         fun() ->
             Entry = make_entry(<<1:256>>, 10.0),
             ets:insert(mempool_txs, {<<1:256>>, Entry}),
             ?assert(beamchain_mempool:has_tx(<<1:256>>)),
             ?assertNot(beamchain_mempool:has_tx(<<2:256>>))
         end
        ]
     end}.

get_tx_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
             ?assertEqual(not_found, beamchain_mempool:get_tx(<<1:256>>)),
             Tx = make_tx([{<<5:256>>, 0}], [{1000, p2pkh_script()}]),
             Entry = make_entry_with_tx(<<1:256>>, 5.0, Tx),
             ets:insert(mempool_txs, {<<1:256>>, Entry}),
             {ok, GotTx} = beamchain_mempool:get_tx(<<1:256>>),
             ?assertEqual(Tx, GotTx)
         end]
     end}.

get_all_txids_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
             ?assertEqual([], beamchain_mempool:get_all_txids()),
             ets:insert(mempool_txs, {<<1:256>>, make_entry(<<1:256>>, 5.0)}),
             ets:insert(mempool_txs, {<<2:256>>, make_entry(<<2:256>>, 3.0)}),
             Txids = lists:sort(beamchain_mempool:get_all_txids()),
             ?assertEqual([<<1:256>>, <<2:256>>], Txids)
         end]
     end}.

%%% ===================================================================
%%% get_mempool_utxo tests
%%% ===================================================================

get_mempool_utxo_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
             ?assertEqual(not_found, beamchain_mempool:get_mempool_utxo(<<1:256>>, 0)),
             Tx = make_tx([{<<5:256>>, 0}],
                          [{5000, p2pkh_script()}, {3000, p2wpkh_script()}]),
             Entry = make_entry_with_tx(<<1:256>>, 10.0, Tx),
             ets:insert(mempool_txs, {<<1:256>>, Entry}),
             {ok, Utxo0} = beamchain_mempool:get_mempool_utxo(<<1:256>>, 0),
             ?assertEqual(5000, Utxo0#utxo.value),
             ?assertEqual(false, Utxo0#utxo.is_coinbase),
             {ok, Utxo1} = beamchain_mempool:get_mempool_utxo(<<1:256>>, 1),
             ?assertEqual(3000, Utxo1#utxo.value),
             %% out of range
             ?assertEqual(not_found, beamchain_mempool:get_mempool_utxo(<<1:256>>, 5))
         end]
     end}.

%%% ===================================================================
%%% get_sorted_by_fee tests
%%% ===================================================================

sorted_by_fee_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
             %% empty mempool
             ?assertEqual([], beamchain_mempool:get_sorted_by_fee()),

             %% insert entries with different fee rates
             E1 = make_entry(<<1:256>>, 2.5),
             E2 = make_entry(<<2:256>>, 10.0),
             E3 = make_entry(<<3:256>>, 5.0),

             ets:insert(mempool_txs, {<<1:256>>, E1}),
             ets:insert(mempool_txs, {<<2:256>>, E2}),
             ets:insert(mempool_txs, {<<3:256>>, E3}),

             ets:insert(mempool_by_fee, {{2.5, <<1:256>>}}),
             ets:insert(mempool_by_fee, {{10.0, <<2:256>>}}),
             ets:insert(mempool_by_fee, {{5.0, <<3:256>>}}),

             Sorted = beamchain_mempool:get_sorted_by_fee(),
             FeeRates = [E#mempool_entry.fee_rate || E <- Sorted],
             %% should be descending
             ?assertEqual([10.0, 5.0, 2.5], FeeRates)
         end]
     end}.

%%% ===================================================================
%%% Test helpers
%%% ===================================================================

make_entry(Txid, FeeRate) ->
    Tx = make_tx([{<<99:256>>, 0}], [{1000, p2pkh_script()}]),
    make_entry_with_tx(Txid, FeeRate, Tx).

make_entry_with_tx(Txid, FeeRate, Tx) ->
    VSize = 200,
    Fee = round(FeeRate * VSize),
    #mempool_entry{
        txid = Txid,
        wtxid = Txid,
        tx = Tx,
        fee = Fee,
        size = VSize,
        vsize = VSize,
        weight = VSize * 4,
        fee_rate = FeeRate,
        time_added = erlang:system_time(second),
        height_added = 800000,
        ancestor_count = 1,
        ancestor_size = VSize,
        ancestor_fee = Fee,
        descendant_count = 1,
        descendant_size = VSize,
        descendant_fee = Fee,
        spends_coinbase = false,
        rbf_signaling = true
    }.

make_tx(Inputs, Outputs) ->
    TxIns = [#tx_in{
        prev_out = #outpoint{hash = H, index = I},
        script_sig = <<>>,
        sequence = 16#fffffffe,
        witness = []
    } || {H, I} <- Inputs],
    TxOuts = [#tx_out{value = V, script_pubkey = SPK} || {V, SPK} <- Outputs],
    #transaction{
        version = 2,
        inputs = TxIns,
        outputs = TxOuts,
        locktime = 0
    }.

p2pkh_script() ->
    <<16#76, 16#a9, 16#14, 0:160, 16#88, 16#ac>>.

p2wpkh_script() ->
    <<16#00, 16#14, 0:160>>.
