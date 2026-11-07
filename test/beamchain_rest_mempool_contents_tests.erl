%%% GET /rest/mempool/contents.json?verbose=true must answer like getrawmempool true.
%%%
%%% Core rest.cpp rest_mempool calls MempoolToJSON(mempool, verbose), the same
%%% serializer as the getrawmempool RPC. beamchain read the txid with
%%% element(1, Entry), which is the record tag, so hash_to_hex crashed and the
%%% REST handler answered HTTP 500 (Core regtest ratchet row
%%% warden_invalidated_submit/rest/tip100-contents).
-module(beamchain_rest_mempool_contents_tests).
-include_lib("eunit/include/eunit.hrl").

%% Same field order as #mempool_entry{} in beamchain_rpc.erl.
entry(Txid) ->
    {mempool_entry, Txid, <<7:256>>, undefined, 1000000, 110, 110, 437, 9090,
     1700000100, 100, 1, 110, 1000000, 1, 110, 1000000, false, true, 437}.

setup() ->
    meck:new(beamchain_mempool, [passthrough, no_link]),
    Txid = <<1:256>>,
    meck:expect(beamchain_mempool, get_all_txids, fun() -> [Txid] end),
    meck:expect(beamchain_mempool, get_all_entries, fun() -> [entry(Txid)] end),
    meck:expect(beamchain_mempool, get_entry, fun(T) when T =:= Txid -> {ok, entry(Txid)};
                                                 (_) -> not_found end),
    meck:expect(beamchain_mempool, get_fee_delta, fun(_) -> 0 end),
    Txid.

cleanup(_) -> meck:unload(beamchain_mempool).

contents_test_() ->
    {foreach, fun setup/0, fun cleanup/1, [
      fun(Txid) -> {"verbose contents is keyed by display txid with Core's fields", fun() ->
          {ok, json, Body} = beamchain_rest:rest_mempool_contents(json, true),
          Map = jsx:decode(Body, [return_maps]),
          Key = beamchain_serialize:hex_encode(beamchain_serialize:reverse_bytes(Txid)),
          ?assertEqual([Key], maps:keys(Map)),
          E = maps:get(Key, Map),
          ?assertEqual(110, maps:get(<<"vsize">>, E)),
          ?assertEqual(437, maps:get(<<"weight">>, E)),
          ?assertEqual(100, maps:get(<<"height">>, E)),
          ?assertEqual(1, maps:get(<<"descendantcount">>, E)),
          ?assertEqual(1, maps:get(<<"ancestorcount">>, E)),
          ?assert(maps:is_key(<<"wtxid">>, E)),
          ?assert(maps:is_key(<<"depends">>, E)),
          ?assert(maps:is_key(<<"spentby">>, E)),
          ?assert(maps:is_key(<<"bip125-replaceable">>, E)),
          ?assert(maps:is_key(<<"unbroadcast">>, E)),
          Fees = maps:get(<<"fees">>, E),
          ?assertEqual([<<"ancestor">>, <<"base">>, <<"chunk">>, <<"descendant">>,
                        <<"modified">>], lists:sort(maps:keys(Fees)))
      end} end]}.
