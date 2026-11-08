%%% GET /rest/mempool/info.json must answer like getmempoolinfo.
%%%
%%% Core rest.cpp rest_mempool_info serialises MempoolInfoToJSON, the same
%%% serializer as the getmempoolinfo RPC. beamchain's REST handler built its own
%%% map: it lacked permitbaremultisig, maxdatacarriersize, limitclustercount,
%%% limitclustersize and optimal, used 1e-05 BTC/kvB for the fee floors where
%%% Core reports 1e-06, and reported total_fee as 0 (Core regtest ratchet rows
%%% warden_invalidated_submit/rest/*-info:*).
-module(beamchain_rest_mempool_info_tests).
-include_lib("eunit/include/eunit.hrl").

entry(Txid, Fee) ->
    {mempool_entry, Txid, <<7:256>>, undefined, Fee, 110, 110, 437, 9090,
     1700000100, 100, 1, 110, Fee, 1, 110, Fee, false, true, 437}.

setup() ->
    meck:new(beamchain_mempool, [passthrough, no_link]),
    meck:expect(beamchain_mempool, get_info,
                fun() -> #{size => 1, bytes => 110, total_fee => 100000,
                           min_fee_rate => 1} end),
    meck:expect(beamchain_mempool, get_all_entries,
                fun() -> [entry(<<1:256>>, 100000)] end),
    meck:expect(beamchain_mempool, unbroadcast_count, fun() -> 0 end),
    ok.

cleanup(_) -> meck:unload(beamchain_mempool).

info_test_() ->
    {foreach, fun setup/0, fun cleanup/1, [
      fun(_) -> {"REST info has exactly getmempoolinfo's fields and values", fun() ->
          {ok, json, Body} = beamchain_rest:rest_mempool_info(json),
          {ok, Rpc} = beamchain_rpc:rpc_getmempoolinfo(),
          RestMap = jsx:decode(Body, [return_maps]),
          RpcMap = jsx:decode(jsx:encode(Rpc), [return_maps]),
          ?assertEqual(RpcMap, RestMap)
      end} end,
      fun(_) -> {"REST info reports Core's fee floors, cluster limits and total_fee", fun() ->
          {ok, json, Body} = beamchain_rest:rest_mempool_info(json),
          M = jsx:decode(Body, [return_maps]),
          ?assertEqual(1.0e-6, maps:get(<<"minrelaytxfee">>, M)),
          ?assertEqual(1.0e-6, maps:get(<<"incrementalrelayfee">>, M)),
          ?assertEqual(64, maps:get(<<"limitclustercount">>, M)),
          ?assertEqual(101000, maps:get(<<"limitclustersize">>, M)),
          ?assertEqual(100000, maps:get(<<"maxdatacarriersize">>, M)),
          ?assertEqual(true, maps:get(<<"permitbaremultisig">>, M)),
          ?assertEqual(true, maps:get(<<"optimal">>, M)),
          ?assertEqual(0.001, maps:get(<<"total_fee">>, M))
      end} end]}.
