-module(beamchain_getwalletinfo_no_balance_tests).

%%% getwalletinfo has no balance fields, as in Core.
%%%
%%% Core v31.1 wallet/rpc/wallet.cpp, RPCHelpMan getwalletinfo, returns
%%% walletname, walletversion, format, txcount, keypoolsize,
%%% keypoolsize_hd_internal, unlocked_until, private_keys_enabled,
%%% avoid_reuse, scanning, descriptors, external_signer, blank, birthtime,
%%% flags and lastprocessedblock. Balances come from getbalances/getbalance.
%%%
%%% Calls go through beamchain_rpc:dispatch/2 (the JSON-RPC path) with the
%%% wallet process mocked, so the reply is the real encoded response.
%%%
%%% CONTROL: `rebar3 eunit --module=beamchain_getwalletinfo_no_balance_tests`

-include_lib("eunit/include/eunit.hrl").

-define(MOCKED, [beamchain_wallet, beamchain_wallet_sup,
                 beamchain_chainstate, beamchain_config]).

setup() ->
    lists:foreach(fun(M) -> meck:new(M, [passthrough, no_link]) end, ?MOCKED),
    WalletPid = self(),
    meck:expect(beamchain_wallet_sup, list_wallets, fun() -> [<<"w">>] end),
    meck:expect(beamchain_wallet_sup, get_wallet,
                fun(_) -> {ok, WalletPid} end),
    meck:expect(beamchain_wallet, get_wallet_info,
                fun(_) -> {ok, #{wallet_name => <<"w">>, addresses => 3,
                                 encrypted => false, locked => false,
                                 private_keys_enabled => true}} end),
    %% A non-zero balance, so a field that still reports it is visible.
    meck:expect(beamchain_wallet, get_balance,
                fun(_) -> {ok, 5000000000} end),
    meck:expect(beamchain_wallet, get_tx_history, fun() -> [] end),
    meck:expect(beamchain_chainstate, get_tip,
                fun() -> {ok, {<<0:256>>, 101}} end),
    meck:expect(beamchain_config, network, fun() -> regtest end),
    ok.

cleanup(_) ->
    lists:foreach(fun(M) -> catch meck:unload(M) end, ?MOCKED).

walletinfo() ->
    Resp = beamchain_rpc:dispatch(
             #{<<"jsonrpc">> => <<"1.0">>,
               <<"id">> => <<"gwi">>,
               <<"method">> => <<"getwalletinfo">>,
               <<"params">> => []},
             undefined),
    Decoded = case Resp of
        {raw_json, Bin} -> jsx:decode(Bin, [return_maps]);
        Map when is_map(Map) -> Map
    end,
    #{<<"error">> := null, <<"result">> := Result} = Decoded,
    Result.

getwalletinfo_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     [{"getwalletinfo has no balance field",
       fun() -> assert_absent(<<"balance">>) end},
      {"getwalletinfo has no unconfirmed_balance field",
       fun() -> assert_absent(<<"unconfirmed_balance">>) end},
      {"getwalletinfo has no immature_balance field",
       fun() -> assert_absent(<<"immature_balance">>) end},
      {"control: the fields Core returns are still there",
       fun keeps_core_fields/0}]}.

assert_absent(Key) ->
    Info = walletinfo(),
    ?assertEqual(false, maps:is_key(Key, Info)).

keeps_core_fields() ->
    Info = walletinfo(),
    ?assertEqual(<<"w">>, maps:get(<<"walletname">>, Info)),
    ?assertEqual(3, maps:get(<<"keypoolsize">>, Info)),
    ?assertEqual(0, maps:get(<<"txcount">>, Info)),
    ?assertEqual(true, maps:get(<<"private_keys_enabled">>, Info)),
    ?assertEqual(true, maps:get(<<"descriptors">>, Info)),
    ?assertEqual(false, maps:get(<<"avoid_reuse">>, Info)),
    ?assertEqual(false, maps:get(<<"scanning">>, Info)),
    ?assertEqual(false, maps:get(<<"external_signer">>, Info)),
    ?assertEqual(false, maps:get(<<"blank">>, Info)),
    ?assertEqual([], maps:get(<<"flags">>, Info)),
    ?assertMatch(#{<<"height">> := 101}, maps:get(<<"lastprocessedblock">>, Info)).
