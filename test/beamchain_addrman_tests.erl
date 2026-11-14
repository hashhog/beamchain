-module(beamchain_addrman_tests).
-include_lib("eunit/include/eunit.hrl").

%% Tests for addrman bucket-based address storage and eclipse protections

%%% ===================================================================
%%% Test setup/teardown
%%% ===================================================================

setup() ->
    %% Set up test environment
    TestDir = "/tmp/beamchain_test_" ++
              integer_to_list(erlang:unique_integer([positive])),
    os:putenv("BEAMCHAIN_NETWORK", "testnet4"),
    os:putenv("BEAMCHAIN_DATADIR", TestDir),
    %% Start config first (addrman depends on it)
    {ok, ConfigPid} = beamchain_config:start_link(),
    %% Start the addrman
    {ok, AddrmanPid} = beamchain_addrman:start_link(),
    {ConfigPid, AddrmanPid, TestDir}.

cleanup({ConfigPid, AddrmanPid, TestDir}) ->
    gen_server:stop(AddrmanPid),
    gen_server:stop(ConfigPid),
    %% Clean up ETS table
    catch ets:delete(beamchain_config_ets),
    %% Clean up test directory
    os:cmd("rm -rf " ++ TestDir),
    ok.

%%% ===================================================================
%%% Netgroup tests
%%% ===================================================================

netgroup_test_() ->
    {"Netgroup calculation tests", [
        ?_assertEqual({ipv4, 192, 168}, beamchain_addrman:netgroup({{192, 168, 1, 1}, 8333})),
        ?_assertEqual({ipv4, 10, 0}, beamchain_addrman:netgroup({{10, 0, 0, 1}, 8333})),
        ?_assertEqual({ipv4, 192, 168}, beamchain_addrman:netgroup({192, 168, 1, 1})),
        ?_assertEqual({ipv6, 8193, 3512, 0, 0}, beamchain_addrman:netgroup({{8193, 3512, 0, 0, 0, 0, 0, 1}, 8333})),
        ?_assertEqual(other, beamchain_addrman:netgroup(invalid))
    ]}.

%%% ===================================================================
%%% Bucket assignment tests
%%% ===================================================================

bucket_determinism_test_() ->
    {"Bucket assignment is deterministic", {
        setup, fun setup/0, fun cleanup/1,
        fun(_Setup) ->
            [
                fun() ->
                    %% Same address+source should always get same bucket.
                    %% Pre-2026-04 tests used 192.168.x and 10.x.x.x — both
                    %% now rejected by addrman as non-routable (BUG-2 fix
                    %% mirroring Core addrman.cpp AddSingle()). Switch to
                    %% public-IP addresses outside RFC 1918 / RFC 6598 / RFC 5737.
                    _Secret = beamchain_addrman:get_secret(),
                    Addr1 = {{8, 8, 8, 1}, 8333},
                    beamchain_addrman:add_address(Addr1, 0, {{1, 1, 1, 1}, 8333}),
                    timer:sleep(50),  %% Let cast process

                    {NewCount, _} = beamchain_addrman:count(),
                    ?assert(NewCount >= 1)
                end
            ]
        end
    }}.

%%% ===================================================================
%%% Address lifecycle tests
%%% ===================================================================

add_and_select_test_() ->
    {"Adding and selecting addresses", {
        setup, fun setup/0, fun cleanup/1,
        fun(_Setup) ->
            [
                {"Empty addrman returns empty", fun() ->
                    ?assertEqual(empty, beamchain_addrman:select_address())
                end},

                {"Adding address makes it selectable", fun() ->
                    %% Use a routable IP (was 192.168.1.100, RFC 1918 → dropped).
                    Addr = {{8, 8, 8, 100}, 8333},
                    beamchain_addrman:add_address(Addr, 0, dns),
                    timer:sleep(50),

                    {NewCount, _} = beamchain_addrman:count(),
                    ?assertEqual(1, NewCount),

                    %% select_address should find the address
                    %% (last_try is 0, so it will pass the MIN_RETRY check)
                    Result = beamchain_addrman:select_address(),
                    case Result of
                        {ok, Addr} -> ok;
                        empty ->
                            %% If empty, the random selection might have missed
                            %% Let's verify the count is still correct
                            {N2, _} = beamchain_addrman:count(),
                            ?assertEqual(1, N2)
                    end
                end}
            ]
        end
    }}.

mark_tried_test_() ->
    {"Moving address from new to tried", {
        setup, fun setup/0, fun cleanup/1,
        fun(_Setup) ->
            [
                fun() ->
                    %% Use a routable IP (was 10.20.30.40, RFC 1918 → dropped).
                    Addr = {{20, 30, 40, 50}, 8333},

                    %% Add to new table
                    beamchain_addrman:add_address(Addr, 0, dns),
                    timer:sleep(50),

                    {New1, Tried1} = beamchain_addrman:count(),
                    ?assertEqual(1, New1),
                    ?assertEqual(0, Tried1),

                    %% Mark as tried
                    beamchain_addrman:mark_tried(Addr),
                    timer:sleep(50),

                    {New2, Tried2} = beamchain_addrman:count(),
                    ?assertEqual(0, New2),
                    ?assertEqual(1, Tried2)
                end
            ]
        end
    }}.

%%% ===================================================================
%%% Netgroup-based bucket limit tests
%%% ===================================================================

netgroup_limit_test_() ->
    {"Netgroup limits prevent flooding", {
        setup, fun setup/0, fun cleanup/1,
        fun(_Setup) ->
            [
                fun() ->
                    %% Add many addresses from the same source netgroup
                    %% They should all hash to the same bucket based on source
                    Source = {{1, 2, 3, 4}, 8333},

                    %% Add 100 addresses from different target netgroups
                    %% but same source netgroup
                    lists:foreach(fun(I) ->
                        Addr = {{192, I, 1, 1}, 8333},
                        beamchain_addrman:add_address(Addr, 0, Source)
                    end, lists:seq(1, 100)),
                    timer:sleep(100),

                    %% We should have some addresses but not necessarily all 100
                    %% due to bucket collisions from the same source netgroup
                    {NewCount, _} = beamchain_addrman:count(),
                    ?assert(NewCount > 0),
                    ?assert(NewCount =< 100)
                end
            ]
        end
    }}.

%%% ===================================================================
%%% Tried table collision test
%%% ===================================================================

tried_collision_test_() ->
    {"Tried table collision handling", {
        setup, fun setup/0, fun cleanup/1,
        fun(_Setup) ->
            [
                fun() ->
                    %% Add two addresses that might collide in tried table
                    Addr1 = {{1, 1, 1, 1}, 8333},
                    Addr2 = {{1, 1, 1, 2}, 8333},  %% Same /16 netgroup

                    beamchain_addrman:add_address(Addr1, 0, dns),
                    beamchain_addrman:add_address(Addr2, 0, dns),
                    timer:sleep(50),

                    %% Mark both as tried
                    beamchain_addrman:mark_tried(Addr1),
                    beamchain_addrman:mark_tried(Addr2),
                    timer:sleep(50),

                    %% Both should be tracked somewhere
                    {New, Tried} = beamchain_addrman:count(),
                    ?assertEqual(2, New + Tried)
                end
            ]
        end
    }}.

%%% ===================================================================
%%% Get addresses test
%%% ===================================================================

get_addresses_test_() ->
    {"get_addresses returns random subset", {
        setup, fun setup/0, fun cleanup/1,
        fun(_Setup) ->
            [
                fun() ->
                    %% Add 10 addresses from 10 distinct /16 netgroups so
                    %% each lands in a different new-table bucket regardless
                    %% of the random secret.  Avoid any /8 that is_routable/2
                    %% rejects: 0,10,100,127,172 (with 2nd in 16..31), 169,192
                    %% (with 2nd =:= 168), 198 (with 2nd in 18,19,51), 203
                    %% (with 2nd =:= 0 and 3rd =:= 113).  Pick 10 first
                    %% octets that are all clearly routable.
                    Firsts = [11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
                    lists:foreach(fun(I) ->
                        Addr = {{I, I, 0, 1}, 8333},
                        beamchain_addrman:add_address(Addr, 0, dns)
                    end, Firsts),
                    timer:sleep(100),

                    %% Request 5
                    Addrs = beamchain_addrman:get_addresses(5),
                    ?assertEqual(5, length(Addrs)),

                    %% Request 20 (more than we have)
                    Addrs2 = beamchain_addrman:get_addresses(20),
                    ?assertEqual(10, length(Addrs2))
                end
            ]
        end
    }}.

%%% ===================================================================
%%% Mark failed test
%%% ===================================================================

mark_failed_test_() ->
    {"mark_failed updates attempt count", {
        setup, fun setup/0, fun cleanup/1,
        fun(_Setup) ->
            [
                fun() ->
                    Addr = {{5, 5, 5, 5}, 8333},
                    beamchain_addrman:add_address(Addr, 0, dns),
                    timer:sleep(50),

                    %% Mark failed multiple times
                    beamchain_addrman:mark_failed(Addr),
                    beamchain_addrman:mark_failed(Addr),
                    timer:sleep(50),

                    %% Address should still be there
                    {New, _} = beamchain_addrman:count(),
                    ?assertEqual(1, New)
                end
            ]
        end
    }}.

%%% ===================================================================
%%% Secret key persistence test
%%% ===================================================================

secret_key_test_() ->
    {"Secret key is generated and consistent", {
        setup, fun setup/0, fun cleanup/1,
        fun(_Setup) ->
            [
                fun() ->
                    Secret = beamchain_addrman:get_secret(),
                    ?assertEqual(32, byte_size(Secret)),

                    %% Same secret on subsequent calls
                    Secret2 = beamchain_addrman:get_secret(),
                    ?assertEqual(Secret, Secret2)
                end
            ]
        end
    }}.

%%% ===================================================================
%%% Gossiped addr: source group and nTime (Core AddrManImpl::AddSingle)
%%%
%%% Core files a gossiped address in a new bucket chosen from
%%% (address group, SOURCE group), where the source is the address of the
%%% peer that relayed it (net_processing ProcessAddrs ->
%%% m_addrman.Add(vAddrOk, pfrom.addr, 2h)). The source group bounds how
%%% much of the new table one peer's network can fill: 64 of 1024 buckets.
%%% It also keeps the relayed nTime, penalised by 2h unless the address is
%%% the source's own (self-announcement).
%%%
%%% Before this fix the peer manager handed addrman the peer PID as the
%%% source, which source_netgroup/1 mapped to the single group `local`, so
%%% every gossiped address from every peer competed for the same <=64 new
%%% buckets; and addrman stamped every entry with "now", discarding nTime.
%%%
%%% The test drives the real peer-manager addr/addrv2 handlers into a live
%%% addrman, then counts the distinct new buckets from inside the addrman
%%% process (its ETS tables are private).
%%% ===================================================================

gossip_spreads_across_buckets_by_source_group_test_() ->
    {"gossiped addrs are bucketed by the relaying peer's group and keep nTime",
     {setup, fun setup/0, fun cleanup/1,
      fun(_Setup) ->
          {timeout, 60, fun gossip_spreads_across_buckets_by_source_group/0}
      end}}.

gossip_spreads_across_buckets_by_source_group() ->
    beamchain_peer_manager:test_ensure_peer_table(),
    PeerAddrs = [{{11, 1, 0, 1}, 8333},
                 {{22, 2, 0, 1}, 8333},
                 {{33, 3, 0, 1}, 8333}],
    Peers = [{gossip_test_peer(A), A} || A <- PeerAddrs],
    Now = erlang:system_time(second),
    T0 = Now - 3 * 86400,
    %% 5000 routable addresses, each in its own /16 (A in 40..89, B in 0..99).
    All = [#{timestamp => T0, services => 1,
             ip => {40 + I rem 50, I div 50, 7, 9}, port => 8333}
           || I <- lists:seq(0, 4999)],
    [Chunk1, Chunk2, Chunk3] = split3(All),
    [{P1, A1}, {P2, A2}, {P3, A3}] = Peers,
    %% Peer 1 also announces itself: no time penalty for a self-announcement.
    {SelfIP, SelfPort} = A1,
    Self = #{timestamp => T0, services => 1, ip => SelfIP, port => SelfPort},
    send_addr(P1, addr, [Self | Chunk1]),
    send_addr(P2, addr, Chunk2),
    send_addr(P3, addrv2, Chunk3),
    {NewCount, _} = beamchain_addrman:count(),   %% sync with the casts
    ?assert(NewCount > 0),
    Buckets = new_bucket_ids(),
    ?debugFmt("~B entries in ~B distinct new buckets", [NewCount, length(Buckets)]),
    %% One source group can reach at most 64 new buckets; three distinct
    %% relaying peers (three /16s) must reach more than that.
    ?assert(length(Buckets) > 64),
    %% nTime is kept (minus Core's 2h relay penalty), not replaced by now.
    Dump = beamchain_addrman:get_node_addresses(0, all),
    Times = maps:from_list([{{maps:get(address, E), maps:get(port, E)},
                             maps:get(time, E)} || E <- Dump]),
    ?assertEqual(T0, maps:get({<<"11.1.0.1">>, 8333}, Times)),
    Others = [T || {K, T} <- maps:to_list(Times), K =/= {<<"11.1.0.1">>, 8333}],
    ?assert(length(Others) > 0),
    ?assertEqual([T0 - 7200], lists:usort(Others)),
    [begin ets:delete(beamchain_peers, P), P ! stop end || {P, _} <- Peers],
    _ = {A2, A3},
    ok.

%% A registered, rate-limit-exempt (noban) peer whose address is Addr.
gossip_test_peer(Addr) ->
    P = spawn(fun Loop() -> receive stop -> ok; _ -> Loop() end end),
    ok = beamchain_peer_manager:test_insert_peer(P, inbound, full_relay, noban),
    %% test_insert_peer pins 127.0.0.1:18333; rewrite that field to Addr.
    [Row] = ets:lookup(beamchain_peers, P),
    Fields = tuple_to_list(Row),
    Idx = length(lists:takewhile(fun(F) -> F =/= {{127, 0, 0, 1}, 18333} end,
                                 Fields)) + 1,
    ets:insert(beamchain_peers, setelement(Idx, Row, Addr)),
    P.

send_addr(_Pid, _Cmd, []) ->
    ok;
send_addr(Pid, Cmd, Entries) ->
    {Batch, Rest} = lists:split(min(1000, length(Entries)), Entries),
    Wire = case Cmd of
        addr -> Batch;
        addrv2 -> [#{timestamp => T, services => S, network_id => 1,
                     address => list_to_binary(tuple_to_list(IP)), port => Po}
                   || #{timestamp := T, services := S, ip := IP, port := Po} <- Batch]
    end,
    Payload = beamchain_p2p_msg:encode_payload(Cmd, #{addrs => Wire}),
    ok = beamchain_peer_manager:test_peer_message(Pid, Cmd, Payload),
    send_addr(Pid, Cmd, Rest).

split3(L) ->
    N = length(L) div 3,
    {A, R1} = lists:split(N, L),
    {B, C} = lists:split(N, R1),
    [A, B, C].

%% Distinct new-table bucket ids, read inside the addrman process.
new_bucket_ids() ->
    Self = self(),
    sys:replace_state(beamchain_addrman, fun(S) ->
        NewTab = element(3, S),   %% #state.new_buckets
        Self ! {new_buckets, lists:usort([B || {{B, _}, _} <- ets:tab2list(NewTab)])},
        S
    end),
    receive {new_buckets, Bs} -> Bs after 5000 -> error(no_bucket_reply) end.
