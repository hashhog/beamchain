%%% sendrawtransaction argument and error-message parity with Core v31.1.
%%%
%%% Core regtest rows (operator group):
%%%   sendrawtransaction/trailing        hex with trailing bytes -> -22
%%%                                      "TX decode failed..." (DecodeHexTx
%%%                                      needs the whole string consumed)
%%%   sendrawtransaction/bad-maxfeerate  maxfeerate "x" -> -3 "Invalid amount"
%%%                                      (ParseFeeRate -> AmountFromValue)
%%%   sendrawtransaction/missing-inputs  message = state.ToString() =
%%%                                      "bad-txns-inputs-missingorspent"
%%% The mempool is mocked to say "already present" so that a call which wrongly
%%% gets past argument validation returns {ok, Txid} instead of an error.
-module(beamchain_sendraw_args_tests).
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
    meck:new(beamchain_chainstate, [passthrough, no_link]),
    meck:new(beamchain_peer_manager, [passthrough, no_link]),
    meck:expect(beamchain_peer_manager, announce_tx, fun(_) -> ok end),
    meck:expect(beamchain_mempool, get_wtxid, fun(_) -> {ok, <<9:256>>} end),
    meck:expect(beamchain_chainstate, has_utxo, fun(_, _) -> false end).

cleanup(_) ->
    meck:unload(beamchain_mempool),
    meck:unload(beamchain_chainstate),
    meck:unload(beamchain_peer_manager).

args_test_() ->
    {foreach, fun setup/0, fun cleanup/1, [
      {"trailing bytes after the transaction -> -22", fun() ->
          ?assertMatch({error, -22, <<"TX decode failed", _/binary>>},
                       beamchain_rpc:rpc_sendrawtransaction(
                         [<<(hex(tx()))/binary, "00">>]))
      end},
      {"CONTROL: the same tx without trailing bytes passes validation", fun() ->
          ?assertMatch({ok, _}, beamchain_rpc:rpc_sendrawtransaction([hex(tx())]))
      end},
      {"maxfeerate \"x\" -> -3 Invalid amount", fun() ->
          ?assertEqual({error, -3, <<"Invalid amount">>},
                       beamchain_rpc:rpc_sendrawtransaction([hex(tx()), <<"x">>]))
      end},
      {"maxfeerate of the wrong JSON type -> -3", fun() ->
          ?assertEqual({error, -3, <<"Amount is not a number or string">>},
                       beamchain_rpc:rpc_sendrawtransaction([hex(tx()), true]))
      end},
      {"maxfeerate >= 1 BTC/kvB -> -8", fun() ->
          ?assertEqual({error, -8,
                        <<"Fee rates larger than or equal to 1BTC/kvB are not accepted">>},
                       beamchain_rpc:rpc_sendrawtransaction([hex(tx()), 1]))
      end},
      {"maxfeerate 0 and numeric-string rates are accepted", fun() ->
          ?assertMatch({ok, _}, beamchain_rpc:rpc_sendrawtransaction([hex(tx()), 0])),
          ?assertMatch({ok, _}, beamchain_rpc:rpc_sendrawtransaction([hex(tx()), <<"0.00001">>])),
          ?assertMatch({ok, _}, beamchain_rpc:rpc_sendrawtransaction([hex(tx()), 0.1]))
      end},
      {"sub-satoshi maxfeerate is Invalid amount, not a disabled cap", fun() ->
          ?assertEqual({error, -3, <<"Invalid amount">>},
                       beamchain_rpc:rpc_sendrawtransaction([hex(tx()), 1.0e-9])),
          ?assertEqual({error, -3, <<"Invalid amount">>},
                       beamchain_rpc:rpc_sendrawtransaction([hex(tx()), <<"0.000000001">>]))
      end},
      {"exponent strings and negative amounts follow ParseFixedPoint / MoneyRange", fun() ->
          ?assertMatch({ok, _}, beamchain_rpc:rpc_sendrawtransaction([hex(tx()), <<"1e-5">>])),
          ?assertEqual({error, -3, <<"Amount out of range">>},
                       beamchain_rpc:rpc_sendrawtransaction([hex(tx()), <<"-0.1">>]))
      end},
      {"malformed amount text is Invalid amount (ParseFixedPoint)", fun() ->
          [?assertEqual({error, -3, <<"Invalid amount">>},
                        beamchain_rpc:rpc_sendrawtransaction([hex(tx()), T]))
           || T <- [<<".5">>, <<"1.">>, <<"01">>, <<"">>, <<"-">>, <<"1e">>,
                    <<"10000000000">>, <<"10000000000.1">>, <<"-10000000000.1">>, <<"0e10">>, <<"0e-30">>, <<"0.000000001">>]],
          [?assertMatch({ok, _}, beamchain_rpc:rpc_sendrawtransaction([hex(tx()), T]))
           || T <- [<<"0.5">>, <<"0e-8">>, <<"0.100000000">>, <<"5e-6">>]]
      end},
      {"missing inputs reports Core's reject reason", fun() ->
          ?assertEqual({error, -25, <<"bad-txns-inputs-missingorspent">>},
                       beamchain_rpc:format_mempool_error(orphan, <<0:256>>)),
          meck:expect(beamchain_mempool, get_wtxid, fun(_) -> not_found end),
          meck:expect(beamchain_mempool, accept_to_memory_pool,
                      fun(_) -> {error, orphan} end),
          ?assertEqual({error, -25, <<"bad-txns-inputs-missingorspent">>},
                       beamchain_rpc:rpc_sendrawtransaction([hex(tx()), 0]))
      end}]}.
