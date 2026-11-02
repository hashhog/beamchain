-module(beamchain_setmocktime_tests).

%%% setmocktime (Core rpc/node.cpp, hidden command): the Core regtest
%%% ratchet's warden_invalidated_submit/clock rows got -32601 "Method not
%%% found" from beamchain while Core answered null.

-include_lib("eunit/include/eunit.hrl").

rpc(Params) ->
    beamchain_rpc:handle_method(<<"setmocktime">>, Params, undefined).

setup(Network) ->
    case ets:whereis(beamchain_config_ets) of
        undefined -> ets:new(beamchain_config_ets, [named_table, public, set]);
        _ -> ok
    end,
    ets:insert(beamchain_config_ets, {network, Network}),
    persistent_term:erase(beamchain_mocktime).

cleanup() ->
    persistent_term:erase(beamchain_mocktime),
    ets:delete(beamchain_config_ets).

regtest_test_() ->
    {setup, fun() -> setup(regtest) end, fun(_) -> cleanup() end,
     [fun() ->
          ?assertEqual({ok, null}, rpc([1700000000])),
          ?assertEqual(1700000000, persistent_term:get(beamchain_mocktime, undefined)),
          ?assertEqual({ok, null}, rpc([0])),
          ?assertEqual(undefined, persistent_term:get(beamchain_mocktime, undefined))
      end,
      fun() ->
          ?assertMatch({error, -8, <<"Mocktime must be in the range [0, ", _/binary>>},
                       rpc([-1]))
      end]}.

mainnet_refused_test_() ->
    {setup, fun() -> setup(mainnet) end, fun(_) -> cleanup() end,
     fun() ->
         ?assertEqual({error, -1,
                       <<"setmocktime is for regression testing (-regtest mode) only">>},
                      rpc([1700000000])),
         ?assertEqual(undefined, persistent_term:get(beamchain_mocktime, undefined))
     end}.
