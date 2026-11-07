%% getpeerinfo per-peer shape vs Core rpc/net.cpp: `addrlocal` is emitted when
%% the peer reported our address, and `mapped_as` is omitted when 0 (no -asmap
%% or an unmapped address).
-module(beamchain_peerinfo_core_shape_tests).
-include_lib("eunit/include/eunit.hrl").

fields(Extra) ->
    maps:merge(#{
        id => 1, addr => <<"1.2.3.4:8333">>, network => <<"ipv4">>,
        mapped_as => 0, services => <<"0000000000000409">>,
        servicesnames => [<<"NETWORK">>], relaytxes => true, lastsend => 0,
        lastrecv => 0, bytessent => 0, bytesrecv => 0, conntime => 0,
        timeoffset => 0, pingtime => 0.0, version => 70016,
        subver => <<"/x/">>, inbound => false,
        connection_type => <<"outbound-full-relay">>
    }, Extra).

keys(PL) -> [K || {K, _} <- PL].

mapped_as_omitted_when_zero_test() ->
    PL = beamchain_rpc:peerinfo_obj_proplist(fields(#{mapped_as => 0})),
    ?assertNot(lists:member(<<"mapped_as">>, keys(PL))).

mapped_as_present_when_nonzero_test() ->
    PL = beamchain_rpc:peerinfo_obj_proplist(fields(#{mapped_as => 64496})),
    ?assertEqual(64496, proplists:get_value(<<"mapped_as">>, PL)).

addrlocal_emitted_after_addrbind_test() ->
    PL = beamchain_rpc:peerinfo_obj_proplist(
           fields(#{addrlocal => <<"203.0.113.9:18444">>})),
    ?assertEqual(<<"203.0.113.9:18444">>,
                 proplists:get_value(<<"addrlocal">>, PL)),
    [_, _, _, K4, K5 | _] = keys(PL),
    ?assertEqual({<<"addrlocal">>, <<"network">>}, {K4, K5}).

addrlocal_omitted_when_unknown_test() ->
    PL = beamchain_rpc:peerinfo_obj_proplist(fields(#{})),
    ?assertNot(lists:member(<<"addrlocal">>, keys(PL))).
