-module(beamchain_localaddr_tests).
-include_lib("eunit/include/eunit.hrl").

%% Self-address advertisement (Core mapLocalHost / GetLocalAddrForPeer /
%% MaybeSendAddr). Covers the routable filter, discovery from VERSION
%% addr_recv, the addr/addrv2 wire contents (incl. the LISTEN port), and the
%% IBD / connection-type send gate.

-define(LP, 18444).
-define(NOW, 1800000000).

%%% ------------------------------------------------------------------
%%% Routable filter
%%% ------------------------------------------------------------------

routable_test_() ->
    [?_assert(beamchain_localaddr:routable_ip({1, 2, 3, 4})),
     ?_assert(beamchain_localaddr:routable_ip({76, 38, 7, 169})),
     ?_assert(beamchain_localaddr:routable_ip({16#2a01, 16#4f8, 0, 0, 0, 0, 0, 1})),
     ?_assertNot(beamchain_localaddr:routable_ip({127, 0, 0, 1})),
     ?_assertNot(beamchain_localaddr:routable_ip({0, 0, 0, 0})),
     ?_assertNot(beamchain_localaddr:routable_ip({10, 1, 2, 3})),
     ?_assertNot(beamchain_localaddr:routable_ip({172, 16, 0, 1})),
     ?_assertNot(beamchain_localaddr:routable_ip({192, 168, 1, 128})),
     ?_assertNot(beamchain_localaddr:routable_ip({100, 64, 0, 1})),
     ?_assertNot(beamchain_localaddr:routable_ip({169, 254, 1, 1})),
     ?_assertNot(beamchain_localaddr:routable_ip({224, 0, 0, 1})),
     ?_assertNot(beamchain_localaddr:routable_ip({255, 255, 255, 255})),
     ?_assertNot(beamchain_localaddr:routable_ip({0, 0, 0, 0, 0, 0, 0, 0})),
     ?_assertNot(beamchain_localaddr:routable_ip({0, 0, 0, 0, 0, 0, 0, 1})),
     ?_assertNot(beamchain_localaddr:routable_ip({16#fe80, 0, 0, 0, 0, 0, 0, 1})),
     ?_assertNot(beamchain_localaddr:routable_ip({16#fd00, 0, 0, 0, 0, 0, 0, 1})),
     ?_assertNot(beamchain_localaddr:routable_ip({16#ff02, 0, 0, 0, 0, 0, 0, 1})),
     ?_assertNot(beamchain_localaddr:routable_ip(undefined)),
     ?_assertNot(beamchain_localaddr:routable_ip({300, 1, 1, 1}))].

%%% ------------------------------------------------------------------
%%% -externalip parsing / -discover soft-set
%%% ------------------------------------------------------------------

parse_externalip_test_() ->
    P = fun beamchain_localaddr:parse_externalip/1,
    [?_assertEqual({ok, {1, 2, 3, 4}, 0}, P("1.2.3.4")),
     ?_assertEqual({ok, {1, 2, 3, 4}, 8336}, P("1.2.3.4:8336")),
     ?_assertEqual({ok, {16#2001, 16#db8, 0, 0, 0, 0, 0, 1}, 0}, P("2001:db8::1")),
     ?_assertEqual({ok, {16#2001, 16#db8, 0, 0, 0, 0, 0, 1}, 8336}, P("[2001:db8::1]:8336")),
     ?_assertEqual({ok, {16#2001, 16#db8, 0, 0, 0, 0, 0, 1}, 0}, P("[2001:db8::1]")),
     ?_assertMatch({error, _}, P("1.2.3.4:99999")),
     ?_assertMatch({error, _}, P("not-an-ip")),
     ?_assertEqual(["1.2.3.4", "5.6.7.8:9"],
                   beamchain_localaddr:parse_externalip_list(["1.2.3.4, 5.6.7.8:9"])),
     ?_assertEqual(["1.2.3.4", "5.6.7.8"],
                   beamchain_localaddr:parse_externalip_list([["1.2.3.4"], ["5.6.7.8"]])),
     ?_assertEqual([], beamchain_localaddr:parse_externalip_list([[], []])),
     ?_assert(beamchain_localaddr:discover_enabled(undefined, [])),
     ?_assertNot(beamchain_localaddr:discover_enabled(undefined, ["1.2.3.4"])),
     ?_assert(beamchain_localaddr:discover_enabled(true, ["1.2.3.4"])),
     ?_assertNot(beamchain_localaddr:discover_enabled(false, []))].

add_manual_test_() ->
    T0 = beamchain_localaddr:new(),
    {ok, T1} = beamchain_localaddr:add_manual(T0, {1, 2, 3, 4}, ?LP),
    [?_assertEqual({error, not_routable},
                   beamchain_localaddr:add_manual(T0, {192, 168, 1, 1}, ?LP)),
     ?_assertEqual([{{1, 2, 3, 4}, ?LP, 4}], beamchain_localaddr:list(T1, ?NOW)),
     %% A manual entry is usable immediately and never expires.
     ?_assertEqual({ok, {{1, 2, 3, 4}, ?LP, 4}},
                   beamchain_localaddr:best(T1, undefined, ?NOW + 10 * 86400))].

%%% ------------------------------------------------------------------
%%% Discovery from VERSION addr_recv
%%% ------------------------------------------------------------------

note(T, PeerIP, Seen, Inbound, Now) ->
    beamchain_localaddr:note_addr_recv(
      T, #{discover => true, listen_port => ?LP, peer_ip => PeerIP,
           peer_group => beamchain_addrman:netgroup(PeerIP),
           inbound => Inbound, addr_recv_ip => Seen, now => Now}).

discovery_test_() ->
    Me = {76, 38, 7, 169},
    T0 = beamchain_localaddr:new(),
    %% One outbound peer: recorded, with OUR listen port, score 1 -> not yet
    %% usable (needs 2 distinct netgroups).
    T1 = note(T0, {8, 8, 8, 8}, Me, false, ?NOW),
    %% Same /16 again: still score 1.
    T1b = note(T1, {8, 8, 4, 4}, Me, false, ?NOW),
    %% A second netgroup: score 2 -> usable.
    T2 = note(T1b, {9, 9, 9, 9}, Me, false, ?NOW),
    [?_assertEqual([{Me, ?LP, 1}], beamchain_localaddr:list(T1, ?NOW)),
     ?_assertEqual(none, beamchain_localaddr:best(T1, undefined, ?NOW)),
     ?_assertEqual([{Me, ?LP, 1}], beamchain_localaddr:list(T1b, ?NOW)),
     ?_assertEqual({ok, {Me, ?LP, 2}}, beamchain_localaddr:best(T2, undefined, ?NOW)),
     %% Unroutable peer or unroutable reported address: ignored.
     ?_assertEqual(#{}, note(T0, {192, 168, 1, 1}, Me, false, ?NOW)),
     ?_assertEqual(#{}, note(T0, {8, 8, 8, 8}, {10, 0, 0, 5}, false, ?NOW)),
     %% Inbound peers only score an EXISTING entry.
     ?_assertEqual(#{}, note(T0, {8, 8, 8, 8}, Me, true, ?NOW)),
     ?_assertEqual([{Me, ?LP, 2}],
                   beamchain_localaddr:list(note(T1, {9, 9, 9, 9}, Me, true, ?NOW), ?NOW)),
     %% -discover off, or not listening: nothing recorded.
     ?_assertEqual(#{}, beamchain_localaddr:note_addr_recv(
                          T0, #{discover => false, listen_port => ?LP,
                                peer_ip => {8, 8, 8, 8}, peer_group => g,
                                inbound => false, addr_recv_ip => Me, now => ?NOW})),
     ?_assertEqual(#{}, beamchain_localaddr:note_addr_recv(
                          T0, #{discover => true, listen_port => 0,
                                peer_ip => {8, 8, 8, 8}, peer_group => g,
                                inbound => false, addr_recv_ip => Me, now => ?NOW})),
     %% Discovered entries expire after 3h unconfirmed.
     ?_assertEqual([], beamchain_localaddr:list(T2, ?NOW + 3 * 3600 + 1)),
     ?_assertEqual([{Me, ?LP, 2}], beamchain_localaddr:list(T2, ?NOW + 3 * 3600))].

discovery_cap_test() ->
    %% At most 8 discovered entries; the weakest/oldest is evicted.
    T = lists:foldl(fun(N, Acc) ->
                            note(Acc, {8, N, 1, 1}, {50, N, 0, 1}, false, ?NOW + N)
                    end, beamchain_localaddr:new(), lists:seq(1, 12)),
    L = beamchain_localaddr:list(T, ?NOW + 20),
    ?assertEqual(8, length(L)),
    ?assertNot(lists:keymember({50, 1, 0, 1}, 1, L)),
    ?assert(lists:keymember({50, 12, 0, 1}, 1, L)).

%%% ------------------------------------------------------------------
%%% Per-peer choice (GetLocalAddrForPeer)
%%% ------------------------------------------------------------------

peer_ctx(Inbound, AddrLocal, Rand) ->
    #{discover => true, listen_port => ?LP, peer_ip => {8, 8, 8, 8},
      inbound => Inbound, addr_local => AddrLocal, now => ?NOW,
      rand => fun(_) -> Rand end}.

local_addr_for_peer_test_() ->
    Empty = beamchain_localaddr:new(),
    {ok, Manual} = beamchain_localaddr:add_manual(Empty, {1, 2, 3, 4}, ?LP),
    F = fun beamchain_localaddr:local_addr_for_peer/2,
    [%% Manual entry, peer view not taken (rand != 0).
     ?_assertEqual({ok, {1, 2, 3, 4}, ?LP}, F(Manual, peer_ctx(false, {{5, 5, 5, 5}, 1234}, 1))),
     %% Peer view taken (rand == 0): OUTBOUND -> peer's IP, OUR port.
     ?_assertEqual({ok, {5, 5, 5, 5}, ?LP}, F(Manual, peer_ctx(false, {{5, 5, 5, 5}, 1234}, 0))),
     %% INBOUND -> peer's IP AND port (it dialed our listen port).
     ?_assertEqual({ok, {5, 5, 5, 5}, 1234}, F(Manual, peer_ctx(true, {{5, 5, 5, 5}, 1234}, 0))),
     %% Nothing known: peer's routable view always used, with listen port.
     ?_assertEqual({ok, {5, 5, 5, 5}, ?LP}, F(Empty, peer_ctx(false, {{5, 5, 5, 5}, 1}, 1))),
     %% Nothing known and peer view unroutable: do not advertise.
     ?_assertEqual(none, F(Empty, peer_ctx(false, {{10, 0, 0, 1}, 1}, 0))),
     ?_assertEqual(none, F(Empty, peer_ctx(false, undefined, 0))),
     %% -discover off: peer view never used.
     ?_assertEqual(none, F(Empty, (peer_ctx(false, {{5, 5, 5, 5}, 1}, 0))#{discover => false}))].

%%% ------------------------------------------------------------------
%%% Send gate (MaybeSendAddr): IBD, listening, conn type, schedule
%%% ------------------------------------------------------------------

gate(Over) ->
    beamchain_localaddr:announce_due(
      maps:merge(#{listening => true, ibd => false, conn_type => full_relay,
                   next_send => undefined, now => ?NOW}, Over),
      fun() -> 3600 end).

gate_test_() ->
    [?_assertEqual({send, ?NOW + 3600}, gate(#{})),
     %% IBD: skip WITHOUT consuming the schedule (next_send stays undefined),
     %% so the first send fires on the first tick after IBD.
     ?_assertEqual(skip, gate(#{ibd => true})),
     ?_assertEqual({send, ?NOW + 3600}, gate(#{ibd => false})),
     ?_assertEqual(skip, gate(#{listening => false})),
     ?_assertEqual(skip, gate(#{conn_type => block_relay})),
     ?_assertEqual(skip, gate(#{conn_type => feeler})),
     ?_assertEqual(skip, gate(#{next_send => ?NOW + 1})),
     ?_assertEqual({send, ?NOW + 3600}, gate(#{next_send => ?NOW}))].

poisson_test_() ->
    [?_assertEqual(0, beamchain_localaddr:next_delay(1.0)),
     ?_assertEqual(86400, beamchain_localaddr:next_delay(math:exp(-1))),
     ?_assert(begin
                  N = 20000,
                  Mean = lists:sum([beamchain_localaddr:next_delay() || _ <- lists:seq(1, N)]) / N,
                  Mean > 0.9 * 86400 andalso Mean < 1.1 * 86400
              end)].

%%% ------------------------------------------------------------------
%%% Wire contents: one entry, our services, time now, LISTEN port
%%% ------------------------------------------------------------------

addr_message_test() ->
    Svc = 16#c09,
    {addr, Payload} = beamchain_localaddr:self_addr_message({1, 2, 3, 4}, 39777, Svc, ?NOW, false),
    Bin = beamchain_p2p_msg:encode_payload(addr, Payload),
    %% count=1, time, services, ::ffff:1.2.3.4, port big-endian.
    ?assertEqual(<<1, ?NOW:32/little, Svc:64/little,
                   0:80, 16#ffff:16, 1, 2, 3, 4, 39777:16/big>>, Bin),
    {ok, #{addrs := [E]}} = beamchain_p2p_msg:decode_payload(addr, Bin),
    ?assertMatch(#{port := 39777, services := Svc, timestamp := ?NOW}, E).

addrv2_message_test() ->
    Svc = 16#c09,
    {addrv2, Payload} = beamchain_localaddr:self_addr_message({1, 2, 3, 4}, 39777, Svc, ?NOW, true),
    Bin = beamchain_p2p_msg:encode_payload(addrv2, Payload),
    %% count=1, time, compactsize services (0xc09 -> fd 09 0c), netid 1 (IPv4),
    %% len 4, addr, port big-endian.
    ?assertEqual(<<1, ?NOW:32/little, 16#fd, 16#09, 16#0c, 1, 4, 1, 2, 3, 4,
                   39777:16/big>>, Bin),
    {ok, #{addrs := [E]}} = beamchain_p2p_msg:decode_payload(addrv2, Bin),
    ?assertMatch(#{port := 39777, services := Svc, timestamp := ?NOW}, E).
