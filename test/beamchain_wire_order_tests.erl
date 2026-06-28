-module(beamchain_wire_order_tests).
-include_lib("eunit/include/eunit.hrl").

%% SERIALIZED-ORDER regression tests for the map-returning RPC handlers whose
%% key order had diverged from Bitcoin Core's pushKV() insertion order.
%%
%% Background: beamchain serialises RPC results with jsx:encode. jsx ALPHABETISES
%% the keys of an Erlang map, but PRESERVES the order of a proplist
%% ([{Key, Value}, ...]). The fix converts each divergent handler's result (and
%% its NESTED objects) to ordered proplists in Core pushKV order. A prior sweep
%% missed the nested getblockchaininfo `softforks` value (left it as an
%% alphabetised map); these tests assert that nested order explicitly.
%%
%% These tests drive the PRODUCTION pure result-shape builders exported from
%% beamchain_rpc (mempoolinfo_proplist/4, networkinfo_proplist/4,
%% mininginfo_proplist/7, peerinfo_obj_proplist/1, build_deployment_proplist/3,
%% blockchaininfo_assemble/4) and encode them through the SAME jsx path
%% production uses. They assert the ACTUAL EMITTED BYTE ORDER in the encoded
%% wire bytes (binary:match start positions strictly increasing), NOT an
%% order-insensitive maps:keys/lists:sort set check.
%%
%% NON-TAUTOLOGICAL: if any builder regresses to a plain Erlang map, jsx will
%% alphabetise its keys and the strict-increasing-position assertions fail. The
%% guard test below proves the harness itself can detect a map (an alphabetised
%% encoding is rejected). Several of the builders also splice their parts with
%% `++`, which would crash outright if a map sneaked in — a louder failure still.

%%% ===================================================================
%%% Helpers — reproduce the production wire-encoding path
%%% ===================================================================

%% Production path for {ok, Result}: dispatch/2 wraps Result via result_obj/2
%% (#{<<"result">> => Result, ...}) then reply_json -> jsx:encode. We rebuild
%% the same wrapper so the inner Result's key order is byte-identical to the
%% wire. The outer map keys are jsx-alphabetised, which is fine and does not
%% touch the Result's internal order.
encode_wire(Result) ->
    Body = #{<<"result">> => Result, <<"error">> => null, <<"id">> => 1},
    jsx:encode(Body).

%% Position of a JSON object key (quoted, trailing colon) within encoded bytes.
%% Fails the test if the key is absent.
key_pos(Json, Key) ->
    Needle = <<"\"", Key/binary, "\":">>,
    case binary:match(Json, Needle) of
        {Start, _Len} -> Start;
        nomatch -> erlang:error({key_absent, Key, Json})
    end.

%% Like key_pos/2 but searches from byte offset From onward. Used to anchor a
%% NESTED object's keys so an identically-named outer key cannot satisfy the
%% inner assertion (e.g. getblockchaininfo top-level "time" vs. a softfork's
%% "type"/"height").
key_pos_from(Json, Key, From) ->
    Needle = <<"\"", Key/binary, "\":">>,
    Slice = binary:part(Json, From, byte_size(Json) - From),
    case binary:match(Slice, Needle) of
        {Start, _Len} -> From + Start;
        nomatch -> erlang:error({key_absent_after, Key, From, Json})
    end.

%% Assert listed keys appear in the encoded JSON in exactly this order
%% (strictly increasing byte positions). All listed keys MUST be present.
assert_order(Json, Keys) ->
    Positions = [key_pos(Json, K) || K <- Keys],
    assert_strictly_increasing(Keys, Positions).

%% Assert listed keys appear in order, all AT OR AFTER byte offset From.
assert_order_from(Json, Keys, From) ->
    {_, RPositions} = lists:foldl(
        fun(K, {Cursor, Acc}) ->
            P = key_pos_from(Json, K, Cursor),
            {P, [P | Acc]}
        end, {From, []}, Keys),
    Positions = lists:reverse(RPositions),
    assert_strictly_increasing(Keys, Positions).

assert_strictly_increasing(_Keys, []) -> ok;
assert_strictly_increasing(_Keys, [_]) -> ok;
assert_strictly_increasing([K1, K2 | KT], [P1, P2 | PT]) ->
    ?assert(P1 < P2,
            lists:flatten(io_lib:format(
                "~s (pos ~p) must precede ~s (pos ~p) on the wire",
                [K1, P1, K2, P2]))),
    assert_strictly_increasing([K2 | KT], [P2 | PT]).

%% Stub HeightGetter for build_deployment_proplist/3 — no DB access.
stub_getter() -> fun(_H) -> not_found end.

%%% ===================================================================
%%% getmempoolinfo
%%% ===================================================================

getmempoolinfo_order_test() ->
    PL = beamchain_rpc:mempoolinfo_proplist(7, 4096, 0.0001, true),
    Json = encode_wire(PL),
    assert_order(Json, [
        <<"loaded">>, <<"size">>, <<"bytes">>, <<"usage">>, <<"total_fee">>,
        <<"maxmempool">>, <<"mempoolminfee">>, <<"minrelaytxfee">>,
        <<"incrementalrelayfee">>, <<"unbroadcastcount">>, <<"fullrbf">>,
        %% Core v31.99 additions:
        <<"permitbaremultisig">>, <<"maxdatacarriersize">>,
        <<"limitclustercount">>, <<"limitclustersize">>, <<"optimal">>
    ]).

%%% ===================================================================
%%% getnetworkinfo (incl. nested networks + localaddresses objects)
%%% ===================================================================

getnetworkinfo_order_test() ->
    LocalAddrs = [[
        {<<"address">>, <<"abc.onion">>},
        {<<"port">>, 8333},
        {<<"score">>, 4}
    ]],
    PL = beamchain_rpc:networkinfo_proplist(3, 1, 2, LocalAddrs),
    Json = encode_wire(PL),
    assert_order(Json, [
        <<"version">>, <<"subversion">>, <<"protocolversion">>,
        <<"localservices">>, <<"localservicesnames">>, <<"localrelay">>,
        <<"timeoffset">>, <<"networkactive">>, <<"connections">>,
        <<"connections_in">>, <<"connections_out">>, <<"networks">>,
        <<"relayfee">>, <<"incrementalfee">>, <<"localaddresses">>,
        <<"warnings">>
    ]).

getnetworkinfo_nested_networks_order_test() ->
    PL = beamchain_rpc:networkinfo_proplist(0, 0, 0, []),
    Json = encode_wire(PL),
    NetFrom = key_pos(Json, <<"networks">>),
    %% Nested networks[0] object (GetNetworksInfo) Core order.
    assert_order_from(Json, [
        <<"name">>, <<"limited">>, <<"reachable">>, <<"proxy">>,
        <<"proxy_randomize_credentials">>
    ], NetFrom).

getnetworkinfo_nested_localaddr_order_test() ->
    LocalAddrs = [[
        {<<"address">>, <<"abc.onion">>},
        {<<"port">>, 8333},
        {<<"score">>, 4}
    ]],
    PL = beamchain_rpc:networkinfo_proplist(0, 0, 0, LocalAddrs),
    Json = encode_wire(PL),
    LaFrom = key_pos(Json, <<"localaddresses">>),
    %% Nested localaddresses[0] object Core order: address, port, score.
    assert_order_from(Json, [<<"address">>, <<"port">>, <<"score">>], LaFrom).

%%% ===================================================================
%%% getmininginfo (incl. nested next object)
%%% ===================================================================

getmininginfo_order_test() ->
    %% 3rd arg is now the compact tip bits (integer) — the proplist routes it
    %% through the __DIFF__ sentinel for difficulty. Core v31.99 dropped
    %% currentblocksize.
    PL = beamchain_rpc:mininginfo_proplist(800000, <<"170331db">>, 16#170331db,
                                           <<"00000000000000000000">>, 5,
                                           <<"main">>, 12345),
    Json = encode_wire(PL),
    assert_order(Json, [
        <<"blocks">>, <<"currentblockweight">>,
        <<"currentblocktx">>, <<"bits">>, <<"difficulty">>, <<"target">>,
        <<"networkhashps">>, <<"pooledtx">>, <<"blockmintxfee">>,
        <<"chain">>, <<"next">>, <<"warnings">>
    ]).

getmininginfo_nested_next_order_test() ->
    PL = beamchain_rpc:mininginfo_proplist(800000, <<"170331db">>, 16#170331db,
                                           <<"00000000000000000000">>, 5,
                                           <<"main">>, 12345),
    Json = encode_wire(PL),
    NextFrom = key_pos(Json, <<"next">>),
    %% Nested next object Core order: height, bits, difficulty, target.
    assert_order_from(Json, [
        <<"height">>, <<"bits">>, <<"difficulty">>, <<"target">>
    ], NextFrom).

%%% ===================================================================
%%% getpeerinfo (per-peer object) — mapped_as right after network
%%% ===================================================================

getpeerinfo_order_test() ->
    F = #{
        id => 12345, addr => <<"1.2.3.4:8333">>, mapped_as => 7,
        services => <<"0000000000000409">>, servicesnames => [<<"NETWORK">>],
        relaytxes => true, lastsend => 100, lastrecv => 101,
        bytessent => 200, bytesrecv => 300, conntime => 50, timeoffset => 0,
        pingtime => 0.1, version => 70016, subver => <<"/x/">>,
        startingheight => 0, inbound => false,
        connection_type => <<"outbound-full-relay">>
    },
    PL = beamchain_rpc:peerinfo_obj_proplist(F),
    Json = encode_wire(PL),
    %% Spot-check the Core-critical leading order: mapped_as MUST be right after
    %% network and BEFORE services (the prior bug emitted it dead last). Also
    %% pins Core v31.99: last_inv_sequence + inv_to_send right after relaytxes
    %% and before lastsend; startingheight DROPPED.
    assert_order(Json, [
        <<"id">>, <<"addr">>, <<"addrbind">>, <<"network">>, <<"mapped_as">>,
        <<"services">>, <<"servicesnames">>, <<"relaytxes">>,
        <<"last_inv_sequence">>, <<"inv_to_send">>, <<"lastsend">>,
        <<"lastrecv">>, <<"last_transaction">>, <<"last_block">>,
        <<"bytessent">>, <<"bytesrecv">>, <<"conntime">>, <<"timeoffset">>,
        <<"pingtime">>, <<"minping">>, <<"version">>, <<"subver">>,
        <<"inbound">>, <<"bip152_hb_to">>, <<"bip152_hb_from">>,
        <<"presynced_headers">>, <<"synced_headers">>, <<"synced_blocks">>,
        <<"inflight">>, <<"addr_relay_enabled">>, <<"addr_processed">>,
        <<"addr_rate_limited">>, <<"permissions">>, <<"minfeefilter">>,
        <<"connection_type">>, <<"transport_protocol_type">>, <<"session_id">>
    ]),
    %% Core v31.99 removed startingheight from getpeerinfo — assert it is absent.
    ?assertEqual(nomatch, binary:match(Json, <<"\"startingheight\":">>)).

getpeerinfo_mapped_as_not_last_test() ->
    F = #{
        id => 1, addr => <<"a">>, mapped_as => 9,
        services => <<"00">>, servicesnames => [], relaytxes => true,
        lastsend => 0, lastrecv => 0, bytessent => 0, bytesrecv => 0,
        conntime => 0, timeoffset => 0, pingtime => 0.0, version => 0,
        subver => <<"/u/">>, startingheight => 0, inbound => true,
        connection_type => <<"inbound">>
    },
    Json = encode_wire(beamchain_rpc:peerinfo_obj_proplist(F)),
    MappedPos = key_pos(Json, <<"mapped_as">>),
    SessionPos = key_pos(Json, <<"session_id">>),
    ?assert(MappedPos < SessionPos).

%%% ===================================================================
%%% getblockchaininfo — top-level order AND nested softforks order
%%% ===================================================================

%% Assemble the full getblockchaininfo result from the production splicer with
%% representative parts (no DB), then assert the top-level Core v31.99 key order.
%% Core v31.99 DROPPED softforks; beamchain's compact_filters_enabled is also
%% gone. size_on_disk now sits between chainwork and pruned; warnings is last.
getblockchaininfo_toplevel_order_test() ->
    Base = blockchaininfo_base(),
    Prune = [{<<"pruned">>, false}],
    Result = beamchain_rpc:blockchaininfo_assemble(Base, Prune),
    Json = encode_wire(Result),
    assert_order(Json, [
        <<"chain">>, <<"blocks">>, <<"headers">>, <<"bestblockhash">>,
        <<"bits">>, <<"target">>, <<"difficulty">>, <<"time">>,
        <<"mediantime">>, <<"verificationprogress">>,
        <<"initialblockdownload">>, <<"chainwork">>, <<"size_on_disk">>,
        <<"pruned">>, <<"warnings">>
    ]),
    %% v31.99 no longer carries softforks / compact_filters_enabled.
    ?assertEqual(nomatch, binary:match(Json, <<"softforks">>)),
    ?assertEqual(nomatch, binary:match(Json, <<"compact_filters_enabled">>)).

%% build_deployment_proplist is still the getdeploymentinfo source of truth
%% (no longer spliced into getblockchaininfo). Assert (a) the softfork NAMES are
%% in canonical order and (b) the inner keys of a buried entry and a bip9 entry
%% are in Core pushKV order.
getblockchaininfo_softforks_nested_order_test() ->
    Softforks = beamchain_rpc:build_deployment_proplist(mainnet, 900000,
                                                        stub_getter()),
    Json = encode_wire([{<<"softforks">>, Softforks}]),
    SfFrom = key_pos(Json, <<"softforks">>),
    %% (a) deployment names in order (buried defs first, then bip9-only tail).
    assert_order_from(Json, [
        <<"bip34">>, <<"bip65">>, <<"bip66">>, <<"csv">>, <<"segwit">>,
        <<"taproot">>, <<"testdummy">>
    ], SfFrom),
    %% (b) inner keys of the first buried entry (bip34): type, active, height.
    Bip34From = key_pos_from(Json, <<"bip34">>, SfFrom),
    assert_order_from(Json, [<<"type">>, <<"active">>, <<"height">>], Bip34From),
    %% (c) inner keys of the bip9 entry (testdummy): type, active, height,
    %% min_activation_height, bit, start_time, timeout, status, count, elapsed,
    %% possible.
    TdFrom = key_pos_from(Json, <<"testdummy">>, SfFrom),
    assert_order_from(Json, [
        <<"type">>, <<"active">>, <<"height">>, <<"min_activation_height">>,
        <<"bit">>, <<"start_time">>, <<"timeout">>, <<"status">>,
        <<"count">>, <<"elapsed">>, <<"possible">>
    ], TdFrom).

%% Mirror of the production base proplist (the part of rpc_getblockchaininfo
%% that needs no DB); used to drive blockchaininfo_assemble/4.
blockchaininfo_base() ->
    [
        {<<"chain">>, <<"main">>},
        {<<"blocks">>, 900000},
        {<<"headers">>, 900000},
        {<<"bestblockhash">>, <<"00deadbeef">>},
        {<<"bits">>, <<"170331db">>},
        {<<"target">>, <<"0000target">>},
        {<<"difficulty">>, 1.0e12},
        {<<"time">>, 1700000000},
        {<<"mediantime">>, 1699999000},
        {<<"verificationprogress">>, 1.0},
        {<<"initialblockdownload">>, false},
        {<<"chainwork">>, <<"00work">>},
        {<<"size_on_disk">>, 0}
    ].

%%% ===================================================================
%%% Non-tautology guard — the harness must REJECT an alphabetised map
%%% ===================================================================

%% Prove the assertion machinery can actually fail when a builder is a plain
%% map (jsx alphabetises map keys). We encode a map whose Core order would be
%% [b, a] and confirm the wire emits a BEFORE b — i.e. the strict-order check
%% would have caught a regression to a map.
harness_rejects_map_test() ->
    MapJson = encode_wire(#{<<"zzz">> => 1, <<"aaa">> => 2}),
    PA = key_pos(MapJson, <<"aaa">>),
    PZ = key_pos(MapJson, <<"zzz">>),
    %% jsx alphabetised the map: aaa precedes zzz despite insertion order.
    ?assert(PA < PZ),
    %% And the strict-order assertion for the (Core) order [zzz, aaa] must fail.
    ?assertError(_, assert_order(MapJson, [<<"zzz">>, <<"aaa">>])).
