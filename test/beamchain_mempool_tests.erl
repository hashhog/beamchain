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
%%% Outpoint tracking tests
%%% ===================================================================

outpoint_tracking_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
             %% Insert a tx and register its outpoints
             Txid = <<10:256>>,
             Tx = make_tx([{<<50:256>>, 0}], [{2000, p2pkh_script()}]),
             Entry = make_entry_with_tx(Txid, 8.0, Tx),
             ets:insert(mempool_txs, {Txid, Entry}),
             %% Register outpoint: {prev_hash, prev_index} -> spending_txid
             ets:insert(mempool_outpoints, {{<<50:256>>, 0}, Txid}),
             ?assertEqual([{{<<50:256>>, 0}, Txid}],
                          ets:lookup(mempool_outpoints, {<<50:256>>, 0})),
             %% Non-existent outpoint
             ?assertEqual([], ets:lookup(mempool_outpoints, {<<99:256>>, 0}))
         end]
     end}.

%%% ===================================================================
%%% get_entry tests
%%% ===================================================================

get_entry_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
             ?assertEqual(not_found, beamchain_mempool:get_entry(<<1:256>>)),
             Tx = make_tx([{<<5:256>>, 0}], [{1000, p2pkh_script()}]),
             Entry = make_entry_with_tx(<<1:256>>, 5.0, Tx),
             ets:insert(mempool_txs, {<<1:256>>, Entry}),
             {ok, Got} = beamchain_mempool:get_entry(<<1:256>>),
             ?assertEqual(<<1:256>>, Got#mempool_entry.txid),
             ?assertEqual(5.0, Got#mempool_entry.fee_rate)
         end]
     end}.

%%% ===================================================================
%%% Sorted by fee with many entries
%%% ===================================================================

sorted_by_fee_many_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
             %% Insert 10 entries with fee rates 1.0 through 10.0
             lists:foreach(fun(N) ->
                 Txid = <<N:256>>,
                 FeeRate = float(N),
                 E = make_entry(Txid, FeeRate),
                 ets:insert(mempool_txs, {Txid, E}),
                 ets:insert(mempool_by_fee, {{FeeRate, Txid}})
             end, lists:seq(1, 10)),
             Sorted = beamchain_mempool:get_sorted_by_fee(),
             ?assertEqual(10, length(Sorted)),
             %% Verify descending order
             Rates = [E#mempool_entry.fee_rate || E <- Sorted],
             ?assertEqual([10.0, 9.0, 8.0, 7.0, 6.0,
                           5.0, 4.0, 3.0, 2.0, 1.0], Rates)
         end]
     end}.

%%% ===================================================================
%%% Single entry sorted
%%% ===================================================================

sorted_by_fee_single_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
             E = make_entry(<<1:256>>, 42.0),
             ets:insert(mempool_txs, {<<1:256>>, E}),
             ets:insert(mempool_by_fee, {{42.0, <<1:256>>}}),
             Sorted = beamchain_mempool:get_sorted_by_fee(),
             ?assertEqual(1, length(Sorted)),
             ?assertEqual(42.0, (hd(Sorted))#mempool_entry.fee_rate)
         end]
     end}.

%%% ===================================================================
%%% Mempool UTXO with various script types
%%% ===================================================================

mempool_utxo_script_types_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
             %% P2TR output in mempool
             P2trScript = <<16#51, 16#20, 0:256>>,
             Tx = make_tx([{<<5:256>>, 0}],
                          [{10000, P2trScript}]),
             Entry = make_entry_with_tx(<<1:256>>, 15.0, Tx),
             ets:insert(mempool_txs, {<<1:256>>, Entry}),
             {ok, Utxo} = beamchain_mempool:get_mempool_utxo(<<1:256>>, 0),
             ?assertEqual(10000, Utxo#utxo.value),
             ?assertEqual(P2trScript, Utxo#utxo.script_pubkey),
             ?assertEqual(false, Utxo#utxo.is_coinbase),
             ?assertEqual(0, Utxo#utxo.height)  %% unconfirmed
         end]
     end}.

%%% ===================================================================
%%% RBF signaling detection
%%% ===================================================================

rbf_signaling_test() ->
    %% sequence < 0xfffffffe signals RBF
    TxRbf = make_tx([{<<1:256>>, 0}], [{1000, p2pkh_script()}]),
    %% our make_tx helper uses 0xfffffffe, so it's NOT signaling RBF
    %% (sequence must be < 0xfffffffe to signal)
    [Input] = TxRbf#transaction.inputs,
    ?assertEqual(16#fffffffe, Input#tx_in.sequence),
    %% Modify to signal RBF
    RbfInput = Input#tx_in{sequence = 16#fffffffd},
    ?assert(RbfInput#tx_in.sequence < 16#fffffffe),
    %% Final sequence (0xffffffff) does not signal RBF
    FinalInput = Input#tx_in{sequence = 16#ffffffff},
    ?assertNot(FinalInput#tx_in.sequence < 16#fffffffe).

%%% ===================================================================
%%% Multiple outputs mempool UTXO test
%%% ===================================================================

mempool_utxo_multiple_outputs_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
             P2wsh = <<16#00, 16#20, 0:256>>,
             OpReturn = <<16#6a, 4, "test">>,
             Tx = make_tx([{<<5:256>>, 0}],
                          [{8000, p2pkh_script()},
                           {4000, p2wpkh_script()},
                           {2000, P2wsh},
                           {0, OpReturn}]),
             Entry = make_entry_with_tx(<<7:256>>, 20.0, Tx),
             ets:insert(mempool_txs, {<<7:256>>, Entry}),
             %% Check each output
             {ok, U0} = beamchain_mempool:get_mempool_utxo(<<7:256>>, 0),
             ?assertEqual(8000, U0#utxo.value),
             {ok, U1} = beamchain_mempool:get_mempool_utxo(<<7:256>>, 1),
             ?assertEqual(4000, U1#utxo.value),
             {ok, U2} = beamchain_mempool:get_mempool_utxo(<<7:256>>, 2),
             ?assertEqual(2000, U2#utxo.value),
             {ok, U3} = beamchain_mempool:get_mempool_utxo(<<7:256>>, 3),
             ?assertEqual(0, U3#utxo.value),
             ?assertEqual(OpReturn, U3#utxo.script_pubkey),
             %% index 4 out of range
             ?assertEqual(not_found, beamchain_mempool:get_mempool_utxo(<<7:256>>, 4))
         end]
     end}.

%%% ===================================================================
%%% Entry field consistency tests
%%% ===================================================================

entry_fields_test() ->
    Entry = make_entry(<<42:256>>, 7.5),
    ?assertEqual(<<42:256>>, Entry#mempool_entry.txid),
    ?assertEqual(7.5, Entry#mempool_entry.fee_rate),
    %% fee = fee_rate * vsize = 7.5 * 200 = 1500
    ?assertEqual(1500, Entry#mempool_entry.fee),
    ?assertEqual(200, Entry#mempool_entry.vsize),
    ?assertEqual(800, Entry#mempool_entry.weight),  %% vsize * 4
    %% initial ancestor/descendant counts
    ?assertEqual(1, Entry#mempool_entry.ancestor_count),
    ?assertEqual(200, Entry#mempool_entry.ancestor_size),
    ?assertEqual(1500, Entry#mempool_entry.ancestor_fee),
    ?assertEqual(1, Entry#mempool_entry.descendant_count),
    ?assertEqual(200, Entry#mempool_entry.descendant_size),
    ?assertEqual(1500, Entry#mempool_entry.descendant_fee),
    ?assertEqual(false, Entry#mempool_entry.spends_coinbase),
    ?assertEqual(true, Entry#mempool_entry.rbf_signaling).

%%% ===================================================================
%%% Orphan pool ETS tests
%%% ===================================================================

orphan_pool_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
             %% Orphan pool starts empty
             ?assertEqual(0, ets:info(mempool_orphans, size)),
             %% Insert an orphan
             Txid = <<1:256>>,
             Tx = make_tx([{<<99:256>>, 0}], [{1000, p2pkh_script()}]),
             Expiry = erlang:system_time(second) + 1200,
             ets:insert(mempool_orphans, {Txid, Tx, Expiry}),
             ?assertEqual(1, ets:info(mempool_orphans, size)),
             %% Can look it up
             [{Txid, _, _}] = ets:lookup(mempool_orphans, Txid),
             %% Delete it
             ets:delete(mempool_orphans, Txid),
             ?assertEqual(0, ets:info(mempool_orphans, size))
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
