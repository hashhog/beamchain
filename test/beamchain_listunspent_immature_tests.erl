-module(beamchain_listunspent_immature_tests).

%%% listunspent leaves out immature coinbase outputs, as Core does.
%%%
%%% Core v31.1:
%%%   wallet/spend.cpp:357   AvailableCoins skips a coin when
%%%                          IsTxImmatureCoinBase(wtx) && !include_immature_coinbase
%%%   wallet/spend.h         CoinFilterParams::include_immature_coinbase = false
%%%   wallet/rpc/coins.cpp   listunspent reads query_options.include_immature_coinbase
%%%                          (RPCTypeCheckObj: VBOOL, else RPC_TYPE_ERROR -3) and
%%%                          reports "spendable": true for every coin it lists
%%%   wallet/wallet.cpp:3333 a coinbase is immature while it has fewer than
%%%                          COINBASE_MATURITY+1 (101) confirmations
%%%
%%% Fixture: a wallet that mined blocks 1..101 (one coinbase each) plus one
%%% ordinary payment confirmed in block 101; tip = 101. Exactly one coinbase
%%% (height 1, 101 confirmations) is mature.
%%%
%%% Calls go through beamchain_rpc:dispatch/2, the JSON-RPC path. The
%%% addresses slot is passed as null (Core: no filter): beamchain currently
%%% treats an empty `[]` as "match nothing", a separate issue kept out of
%%% this file so these tests measure only the immature-coinbase rule.
%%%
%%% CONTROL: `rebar3 eunit --module=beamchain_listunspent_immature_tests`

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

-define(TIP, 101).
-define(MOCKED, [beamchain_wallet, beamchain_wallet_sup,
                 beamchain_chainstate, beamchain_config]).

%%% ===================================================================
%%% fixture
%%% ===================================================================

p2wpkh(N) ->
    <<0, 20, N:160>>.

coinbase_utxo(H) ->
    {<<H:256>>, 0,
     #utxo{value = 5000000000, script_pubkey = p2wpkh(H),
           is_coinbase = true, height = H}}.

payment_utxo() ->
    {<<16#ffff:256>>, 1,
     #utxo{value = 100000000, script_pubkey = p2wpkh(16#ffff),
           is_coinbase = false, height = ?TIP}}.

wallet_utxos() ->
    [coinbase_utxo(H) || H <- lists:seq(1, ?TIP)] ++ [payment_utxo()].

setup() ->
    lists:foreach(fun(M) -> meck:new(M, [passthrough, no_link]) end, ?MOCKED),
    WalletPid = self(),
    meck:expect(beamchain_wallet_sup, list_wallets, fun() -> [<<"w">>] end),
    meck:expect(beamchain_wallet_sup, get_wallet,
                fun(_) -> {ok, WalletPid} end),
    meck:expect(beamchain_wallet, get_wallet_utxos, fun() -> wallet_utxos() end),
    meck:expect(beamchain_wallet, get_address_entry,
                fun(_, _) -> {error, not_found} end),
    meck:expect(beamchain_chainstate, get_tip,
                fun() -> {ok, {<<0:256>>, ?TIP}} end),
    meck:expect(beamchain_config, network, fun() -> regtest end),
    ok.

cleanup(_) ->
    lists:foreach(fun(M) -> catch meck:unload(M) end, ?MOCKED).

dispatch_rpc(Params) ->
    Resp = beamchain_rpc:dispatch(
             #{<<"jsonrpc">> => <<"1.0">>,
               <<"id">> => <<"lu">>,
               <<"method">> => <<"listunspent">>,
               <<"params">> => Params},
             undefined),
    Decoded = case Resp of
        {raw_json, Bin} -> jsx:decode(Bin, [return_maps]);
        Map when is_map(Map) -> Map
    end,
    case Decoded of
        #{<<"error">> := null, <<"result">> := Result} -> {ok, Result};
        #{<<"error">> := #{<<"code">> := Code, <<"message">> := Msg}} ->
            {error, Code, Msg}
    end.

coinbase_confs(Coins) ->
    lists:sort([maps:get(<<"confirmations">>, C) || C <- Coins,
                maps:get(<<"txid">>, C) =/= payment_txid_hex()]).

payment_txid_hex() ->
    {Txid, _, _} = payment_utxo(),
    beamchain_serialize:hex_encode(Txid).

flags(Coins) ->
    lists:usort([{maps:get(<<"spendable">>, C), maps:get(<<"solvable">>, C),
                  maps:get(<<"safe">>, C)} || C <- Coins]).

%%% ===================================================================
%%% tests
%%% ===================================================================

listunspent_immature_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     [{"default listunspent skips the 100 immature coinbases",
       fun default_skips_immature_coinbases/0},
      {"include_immature_coinbase=true lists them, all spendable/solvable/safe",
       fun include_immature_true_lists_them/0},
      {"include_immature_coinbase=false is the default",
       fun include_immature_false_is_default/0},
      {"non-bool include_immature_coinbase is RPC_TYPE_ERROR (-3)",
       fun non_bool_include_immature_is_type_error/0},
      {"explicit null include_immature_coinbase is -3 (Core get_bool)",
       fun null_include_immature_is_type_error/0},
      {"minconf 101 lists exactly the one mature coinbase (control)",
       fun minconf_101_lists_the_mature_coinbase/0}]}.

default_skips_immature_coinbases() ->
    {ok, Coins} = dispatch_rpc([]),
    %% Only the height-1 coinbase (101 confirmations) plus the payment.
    ?assertEqual([101], coinbase_confs(Coins)),
    ?assertEqual(2, length(Coins)),
    ?assertEqual([{true, true, true}], flags(Coins)).

include_immature_true_lists_them() ->
    {ok, Coins} = dispatch_rpc(
                    [0, 9999999, null, true,
                     #{<<"include_immature_coinbase">> => true}]),
    ?assertEqual(lists:seq(1, ?TIP), coinbase_confs(Coins)),
    ?assertEqual(?TIP + 1, length(Coins)),
    %% Core reports spendable:true for every listed coin; a confirmed own
    %% coin is solvable and safe.
    ?assertEqual([{true, true, true}], flags(Coins)).

include_immature_false_is_default() ->
    {ok, Coins} = dispatch_rpc(
                    [0, 9999999, null, true,
                     #{<<"include_immature_coinbase">> => false}]),
    ?assertEqual([101], coinbase_confs(Coins)),
    ?assertEqual(2, length(Coins)).

non_bool_include_immature_is_type_error() ->
    lists:foreach(
      fun(Bad) ->
          ?assertMatch({error, -3, _},
                       dispatch_rpc([0, 9999999, null, true,
                                     #{<<"include_immature_coinbase">> => Bad}]))
      end,
      [1, <<"true">>, [true], #{}]),
    %% Core's RPCTypeCheckObj wording.
    ?assertEqual({error, -3,
                  <<"JSON value of type number for field "
                    "include_immature_coinbase is not of expected type bool">>},
                 dispatch_rpc([0, 9999999, null, true,
                               #{<<"include_immature_coinbase">> => 1}])).

null_include_immature_is_type_error() ->
    %% Core v31.1: the key is present, RPCTypeCheckObj allows null, then
    %% options["include_immature_coinbase"].get_bool() throws
    %% UniValue::type_error, which rpc/server.cpp maps to RPC_TYPE_ERROR.
    ?assertEqual({error, -3,
                  <<"JSON value of type null is not of expected type bool">>},
                 dispatch_rpc([0, 9999999, null, true,
                               #{<<"include_immature_coinbase">> => null}])).

minconf_101_lists_the_mature_coinbase() ->
    {ok, Coins} = dispatch_rpc([101]),
    ?assertEqual([101], coinbase_confs(Coins)),
    ?assertEqual(1, length(Coins)),
    ?assertEqual([{true, true, true}], flags(Coins)).
