%%% testmempoolaccept argument handling and reject rows vs Core v31.1.
%%%
%%% Core regtest rows (operator group), all `testmempoolaccept/<step>`:
%%%   in-mempool / confirmed  reject-reason "txn-already-in-mempool" /
%%%                           "txn-already-known" (state.GetRejectReason(),
%%%                           not sendrawtransaction's prose) and
%%%                           reject-details = state.ToString()
%%%   trailing                hex with trailing bytes -> -22 (DecodeHexTx)
%%%   maxfeerate-zero         second parameter maxfeerate is accepted
%%%   empty-array             [] -> -8 "Array must contain between 1 and 25
%%%                           transactions."
%%%   not-an-array            string for rawtxs -> -3 "Wrong type passed: ..."
%%% beamchain_mempool is mocked so a call that wrongly passes argument
%%% validation yields a result row instead of an error.
-module(beamchain_testmempoolaccept_args_tests).
-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

tx() ->
    #transaction{version = 2, locktime = 0,
        inputs = [#tx_in{prev_out = #outpoint{hash = <<1:256>>, index = 0},
                         script_sig = <<>>, sequence = 16#fffffffd, witness = []}],
        outputs = [#tx_out{value = 1000, script_pubkey = <<0, 20, 0:160>>}]}.

hex(Tx) ->
    beamchain_serialize:hex_encode(beamchain_serialize:encode_transaction(Tx)).

setup() ->
    meck:new(beamchain_mempool, [passthrough, no_link]),
    Txid = beamchain_serialize:tx_hash(tx()),
    Wtxid = beamchain_serialize:wtx_hash(tx()),
    meck:expect(beamchain_mempool, accept_to_memory_pool_dry_run,
                fun(_) -> {ok, Txid, Wtxid, 1000, 100, 10.0} end).

cleanup(_) -> meck:unload(beamchain_mempool).

%% Through the JSON-RPC dispatcher, the same entry point the harness uses.
call(Params) ->
    case beamchain_rpc:dispatch(#{<<"jsonrpc">> => <<"1.0">>, <<"id">> => <<"t">>,
                                  <<"method">> => <<"testmempoolaccept">>,
                                  <<"params">> => Params}, undefined) of
        #{<<"error">> := null, <<"result">> := R} -> {ok, R};
        #{<<"error">> := #{<<"code">> := C, <<"message">> := M}} -> {error, C, M}
    end.

reject(Reason) ->
    meck:expect(beamchain_mempool, accept_to_memory_pool_dry_run,
                fun(_) -> {error, Reason} end),
    {ok, [Row]} = call([[hex(tx())]]),
    Row.

args_test_() ->
    {foreach, fun setup/0, fun cleanup/1, [
      {"trailing bytes -> -22", fun() ->
          ?assertMatch({error, -22, <<"TX decode failed: ", _/binary>>},
                       call(
                         [[<<(hex(tx()))/binary, "00">>]]))
      end},
      {"empty array -> -8", fun() ->
          ?assertEqual({error, -8,
                        <<"Array must contain between 1 and 25 transactions.">>},
                       call([[]]))
      end},
      {"more than 25 transactions -> -8", fun() ->
          ?assertMatch({error, -8, _},
                       call(
                         [lists:duplicate(26, hex(tx()))]))
      end},
      {"string instead of array -> -3 Wrong type", fun() ->
          ?assertEqual({error, -3,
                        <<"Wrong type passed:\n{\n    \"Position 1 (rawtxs)\": "
                          "\"JSON value of type string is not of expected type "
                          "array\"\n}">>},
                       call([hex(tx())]))
      end},
      {"maxfeerate 0 is accepted and lifts the cap", fun() ->
          ?assertMatch({ok, [#{<<"allowed">> := true}]},
                       call([[hex(tx())], 0]))
      end},
      {"fee above maxfeerate -> allowed=false max-fee-exceeded", fun() ->
          %% base fee 1000 sat, vsize 100; 1000 sat/kvB allows 100 sat.
          {ok, [Row]} = call(
                          [[hex(tx())], <<"0.00001">>]),
          ?assertEqual(false, maps:get(<<"allowed">>, Row)),
          ?assertEqual(<<"max-fee-exceeded">>, maps:get(<<"reject-reason">>, Row)),
          ?assertNot(maps:is_key(<<"fees">>, Row))
      end},
      {"sub-satoshi maxfeerate is Invalid amount, not a disabled cap", fun() ->
          ?assertEqual({error, -3, <<"Invalid amount">>},
                       call([[hex(tx())], 1.0e-9])),
          ?assertEqual({error, -3, <<"Amount out of range">>},
                       call([[hex(tx())], <<"-0.1">>]))
      end},
      {"malformed amount text is Invalid amount (ParseFixedPoint)", fun() ->
          [?assertEqual({error, -3, <<"Invalid amount">>}, call([[hex(tx())], T]))
           || T <- [<<".5">>, <<"1.">>, <<"01">>, <<"">>, <<"-">>, <<"1e">>,
                    <<"10000000000">>, <<"10000000000.1">>, <<"-10000000000.1">>, <<"0e10">>, <<"0e-30">>, <<"0.000000001">>]],
          [?assertMatch({ok, [_]}, call([[hex(tx())], T]))
           || T <- [<<"0.5">>, <<"0e-8">>, <<"0.100000000">>, <<"5e-6">>]]
      end},
      {"maxfeerate cap rounds up like CFeeRate::GetFee", fun() ->
          %% 1 sat/kvB * 100 vB = 0.1 sat -> cap 1 sat; a 1 sat fee is allowed.
          Txid = beamchain_serialize:tx_hash(tx()),
          Wtxid = beamchain_serialize:wtx_hash(tx()),
          meck:expect(beamchain_mempool, accept_to_memory_pool_dry_run,
                      fun(_) -> {ok, Txid, Wtxid, 1, 100, 0.01} end),
          ?assertMatch({ok, [#{<<"allowed">> := true}]},
                       call([[hex(tx())], <<"0.00000001">>]))
      end},
      {"after max-fee-exceeded later rows carry only txid and wtxid", fun() ->
          Tx1 = tx(),
          Tx2 = Tx1#transaction{locktime = 1},
          T1 = beamchain_serialize:tx_hash(Tx1), W1 = beamchain_serialize:wtx_hash(Tx1),
          T2 = beamchain_serialize:tx_hash(Tx2), W2 = beamchain_serialize:wtx_hash(Tx2),
          meck:expect(beamchain_mempool, accept_package_dry_run,
                      fun(_) -> {ok, [{ok, T1, W1, 1000, 100}, {ok, T2, W2, 10, 100}]} end),
          {ok, [R1, R2]} = call([[hex(Tx1), hex(Tx2)], <<"0.00001">>]),
          ?assertEqual(false, maps:get(<<"allowed">>, R1)),
          ?assertEqual(<<"max-fee-exceeded">>, maps:get(<<"reject-reason">>, R1)),
          ?assertEqual([<<"txid">>, <<"wtxid">>], lists:sort(maps:keys(R2)))
      end},
      {"decode_package_tx (shared with submitpackage) needs the whole hex consumed", fun() ->
          Hex = hex(tx()),
          ?assertEqual(tx(), beamchain_rpc:decode_package_tx(Hex)),
          ?assertThrow({decode_failed, _},
                       beamchain_rpc:decode_package_tx(<<Hex/binary, "00">>))
      end},
      {"bad maxfeerate -> -3 / -8", fun() ->
          ?assertEqual({error, -3, <<"Invalid amount">>},
                       call([[hex(tx())], <<"x">>])),
          ?assertMatch({error, -8, _},
                       call([[hex(tx())], 1]))
      end},
      {"already in mempool -> txn-already-in-mempool with details", fun() ->
          Row = reject('txn-already-in-mempool'),
          ?assertEqual(<<"txn-already-in-mempool">>, maps:get(<<"reject-reason">>, Row)),
          ?assertEqual(<<"txn-already-in-mempool">>, maps:get(<<"reject-details">>, Row))
      end},
      {"already known (confirmed) -> txn-already-known with details", fun() ->
          Row = reject('txn-already-known'),
          ?assertEqual(<<"txn-already-known">>, maps:get(<<"reject-reason">>, Row)),
          ?assertEqual(<<"txn-already-known">>, maps:get(<<"reject-details">>, Row))
      end},
      {"CONTROL: missing inputs has no reject-details", fun() ->
          Row = reject(orphan),
          ?assertEqual(<<"missing-inputs">>, maps:get(<<"reject-reason">>, Row)),
          ?assertNot(maps:is_key(<<"reject-details">>, Row))
      end}]}.
