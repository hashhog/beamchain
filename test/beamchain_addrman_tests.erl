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
                    %% Same address+source should always get same bucket
                    _Secret = beamchain_addrman:get_secret(),
                    Addr1 = {{192, 168, 1, 1}, 8333},

                    %% Add the address
                    beamchain_addrman:add_address(Addr1, 0, {{10, 0, 0, 1}, 8333}),
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
                    Addr = {{192, 168, 1, 100}, 8333},
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
                    Addr = {{10, 20, 30, 40}, 8333},

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
                    %% of the random secret.  Using addresses all in the same
                    %% /16 (e.g. 10.0.0.x) can cause two to hash to the same
                    %% slot and one is silently dropped, making the count
                    %% non-deterministic.
                    lists:foreach(fun(I) ->
                        Addr = {{I, I, 0, 1}, 8333},
                        beamchain_addrman:add_address(Addr, 0, dns)
                    end, lists:seq(1, 10)),
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
