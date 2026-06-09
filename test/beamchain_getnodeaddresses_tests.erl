-module(beamchain_getnodeaddresses_tests).
-include_lib("eunit/include/eunit.hrl").

%% Regression tests for the getnodeaddresses RPC, exercised end-to-end through
%% beamchain_rpc:handle_method/3. Validates EXACT Bitcoin Core parity:
%%   * result is a JSON array of objects, each with EXACTLY 5 keys in Core
%%     order: time, services, address, port, network
%%     (bitcoin-core/src/rpc/net.cpp:911-970)
%%   * time/services/port are integers, address/network are strings (binaries),
%%     services is the RAW bitfield (not hex), address has NO port
%%   * count semantics: default 1, 0 => all, <0 => error -8
%%   * network filter: lowercased, only ipv4|ipv6|onion|i2p|cjdns else -8
%%   * empty addrman => [] (NOT an error)

%%% ===================================================================
%%% Test setup/teardown (mirrors beamchain_addrman_tests:setup/0+cleanup/1)
%%% ===================================================================

setup() ->
    TestDir = "/tmp/beamchain_gna_test_" ++
              integer_to_list(erlang:unique_integer([positive])),
    os:putenv("BEAMCHAIN_NETWORK", "testnet4"),
    os:putenv("BEAMCHAIN_DATADIR", TestDir),
    {ok, ConfigPid} = beamchain_config:start_link(),
    {ok, AddrmanPid} = beamchain_addrman:start_link(),
    {ConfigPid, AddrmanPid, TestDir}.

cleanup({ConfigPid, AddrmanPid, TestDir}) ->
    gen_server:stop(AddrmanPid),
    gen_server:stop(ConfigPid),
    catch ets:delete(beamchain_config_ets),
    os:cmd("rm -rf " ++ TestDir),
    ok.

%%% ===================================================================
%%% Helpers
%%% ===================================================================

get_node_addresses(Params) ->
    beamchain_rpc:handle_method(<<"getnodeaddresses">>, Params, undefined).

add_peer(AddrBin, Port) ->
    {ok, #{<<"success">> := true}} =
        beamchain_rpc:handle_method(<<"addpeeraddress">>,
                                    [AddrBin, Port], undefined),
    ok.

%% Three routable peers from DISTINCT /16 source netgroups so they reliably
%% land in different addrman new-table buckets regardless of the per-instance
%% random secret (mirrors beamchain_addrman_tests:get_addresses_test_, which
%% spreads first octets to avoid bucket-slot collisions). 8.0.0.0/8 is public.
add_three_peers() ->
    add_peer(<<"8.8.8.1">>, 8333),
    add_peer(<<"9.9.9.1">>, 8334),
    add_peer(<<"11.11.11.1">>, 8335),
    ok.

%% getnodeaddresses entries are emitted as ORDERED proplists (jsx preserves
%% proplist order; a plain map would be alphabetised). Look up a key by name.
get_field(Key, Entry) ->
    {Key, Val} = lists:keyfind(Key, 1, Entry),
    Val.

entry_keys(Entry) ->
    [K || {K, _V} <- Entry].

%% The 5 keys Core emits, in the exact order it builds them
%% (bitcoin-core/src/rpc/net.cpp:949-963).
expected_keys() ->
    [<<"time">>, <<"services">>, <<"address">>, <<"port">>, <<"network">>].

%%% ===================================================================
%%% Case 1: empty addrman => [] (NOT an error)
%%% ===================================================================

empty_addrman_test_() ->
    {"Empty addrman returns an empty list, not an error", {
        setup, fun setup/0, fun cleanup/1,
        fun(_Setup) ->
            [
                {"count=0 on empty addrman", fun() ->
                    ?assertEqual({ok, []}, get_node_addresses([0]))
                end},
                {"default (no count) on empty addrman", fun() ->
                    ?assertEqual({ok, []}, get_node_addresses([]))
                end}
            ]
        end
    }}.

%%% ===================================================================
%%% Case 2: shape + order + types (3 ipv4 peers, count=0)
%%% ===================================================================

shape_and_types_test_() ->
    {"Result entries have EXACTLY the 5 Core keys in order, correct types", {
        setup, fun setup/0, fun cleanup/1,
        fun(_Setup) ->
            [
                fun() ->
                    %% Routable public IPs from distinct /16s (RFC 1918 / 6598
                    %% / 5737 are dropped by addrman, mirroring Core AddSingle()).
                    add_three_peers(),

                    {ok, Result} = get_node_addresses([0]),
                    ?assertEqual(3, length(Result)),

                    Ports = lists:sort([get_field(<<"port">>, E)
                                        || E <- Result]),
                    ?assertEqual([8333, 8334, 8335], Ports),

                    Addrs = lists:sort([get_field(<<"address">>, E)
                                        || E <- Result]),
                    ?assertEqual([<<"11.11.11.1">>, <<"8.8.8.1">>,
                                  <<"9.9.9.1">>], Addrs),

                    lists:foreach(fun(E) ->
                        %% EXACTLY 5 keys, in Core ORDER (on the wire: the
                        %% handler builds an ordered proplist so jsx preserves
                        %% time/services/address/port/network).
                        ?assertEqual(expected_keys(), entry_keys(E)),
                        ?assertEqual(5, length(E)),

                        %% Types: integers for time/services/port.
                        ?assert(is_integer(get_field(<<"time">>, E))),
                        ?assert(is_integer(get_field(<<"services">>, E))),
                        ?assert(is_integer(get_field(<<"port">>, E))),

                        %% Strings (binaries) for address/network.
                        ?assert(is_binary(get_field(<<"address">>, E))),
                        ?assert(is_binary(get_field(<<"network">>, E))),

                        %% services is the RAW bitfield NODE_NETWORK|NODE_WITNESS
                        %% = 9 (Core), NOT a hex string.
                        ?assertEqual(9, get_field(<<"services">>, E)),

                        %% network for an IPv4 peer is "ipv4".
                        ?assertEqual(<<"ipv4">>, get_field(<<"network">>, E)),

                        %% address must NOT contain a port (no ':').
                        Addr = get_field(<<"address">>, E),
                        ?assertEqual(nomatch, binary:match(Addr, <<":">>))
                    end, Result)
                end
            ]
        end
    }}.

%%% ===================================================================
%%% Case 3: count cap (inject 3, count=1 => length 1)
%%% ===================================================================

count_cap_test_() ->
    {"count caps the number of returned entries", {
        setup, fun setup/0, fun cleanup/1,
        fun(_Setup) ->
            [
                fun() ->
                    add_three_peers(),

                    {ok, R1} = get_node_addresses([1]),
                    ?assertEqual(1, length(R1)),

                    {ok, R2} = get_node_addresses([2]),
                    ?assertEqual(2, length(R2)),

                    {ok, R0} = get_node_addresses([0]),
                    ?assertEqual(3, length(R0))
                end
            ]
        end
    }}.

%%% ===================================================================
%%% Case 4: count < 0 => error -8 "Address count out of range"
%%% ===================================================================

negative_count_test_() ->
    {"count < 0 returns -8 'Address count out of range'", {
        setup, fun setup/0, fun cleanup/1,
        fun(_Setup) ->
            [
                fun() ->
                    ?assertEqual({error, -8, <<"Address count out of range">>},
                                 get_node_addresses([-1]))
                end
            ]
        end
    }}.

%%% ===================================================================
%%% Case 5: unknown network filter => -8 "Network not recognized: <raw>"
%%% ===================================================================

unknown_network_test_() ->
    {"unknown network returns -8 'Network not recognized: <raw>'", {
        setup, fun setup/0, fun cleanup/1,
        fun(_Setup) ->
            [
                fun() ->
                    ?assertEqual(
                        {error, -8, <<"Network not recognized: foonet">>},
                        get_node_addresses([0, <<"foonet">>]))
                end
            ]
        end
    }}.

%%% ===================================================================
%%% Case 6: network filter case-insensitivity + filtering
%%% ===================================================================

network_filter_test_() ->
    {"network filter is lowercased and filters by network", {
        setup, fun setup/0, fun cleanup/1,
        fun(_Setup) ->
            [
                fun() ->
                    add_peer(<<"8.8.8.1">>, 8333),
                    add_peer(<<"9.9.9.1">>, 8334),

                    %% Mixed-case "IPv4" is lowercased and accepted, returns
                    %% the ipv4 entries.
                    {ok, R1} = get_node_addresses([0, <<"IPv4">>]),
                    ?assertEqual(2, length(R1)),
                    lists:foreach(fun(E) ->
                        ?assertEqual(<<"ipv4">>, get_field(<<"network">>, E))
                    end, R1),

                    %% Filtering on "onion" with only ipv4 present => [].
                    {ok, R2} = get_node_addresses([0, <<"onion">>]),
                    ?assertEqual([], R2)
                end
            ]
        end
    }}.

%%% ===================================================================
%%% Case 7: default count (no count arg) returns at most 1
%%% ===================================================================

default_count_test_() ->
    {"default count (no arg) returns at most 1 entry", {
        setup, fun setup/0, fun cleanup/1,
        fun(_Setup) ->
            [
                fun() ->
                    add_three_peers(),

                    {ok, R} = get_node_addresses([]),
                    ?assertEqual(1, length(R))
                end
            ]
        end
    }}.

%%% ===================================================================
%%% Case 8: explicit JSON null count behaves as default 1
%%% (Core rpc/net.cpp:946: request.params[0].isNull() ? 1 : getInt<int>())
%%% jsx decodes JSON null to the atom `null`; it must NOT type-error.
%%% ===================================================================

null_count_test_() ->
    {"explicit null count behaves as default 1 (Core isNull() => 1)", {
        setup, fun setup/0, fun cleanup/1,
        fun(_Setup) ->
            [
                {"null count on empty addrman => []", fun() ->
                    ?assertEqual({ok, []}, get_node_addresses([null]))
                end},
                {"null count caps to 1 (same as default)", fun() ->
                    add_three_peers(),
                    {ok, R} = get_node_addresses([null]),
                    ?assertEqual(1, length(R))
                end},
                {"null count + network filter resolves count first", fun() ->
                    add_peer(<<"8.8.8.1">>, 8333),
                    {ok, R} = get_node_addresses([null, <<"ipv4">>]),
                    ?assertEqual(1, length(R)),
                    ?assertEqual(<<"ipv4">>,
                                 get_field(<<"network">>, hd(R)))
                end}
            ]
        end
    }}.

%%% ===================================================================
%%% Case 9: non-integral / float-literal count is rejected like Core
%%% getInt<int>() (from_chars on "1.0"/"1.5" fails -> runtime_error
%%% "JSON integer out of range" -> RPC_MISC_ERROR (-1)). jsx delivers
%%% every JSON float-literal as an Erlang float, including 1.0.
%%% ===================================================================

non_integral_count_test_() ->
    {"float-literal count rejected with -1 'JSON integer out of range'", {
        setup, fun setup/0, fun cleanup/1,
        fun(_Setup) ->
            [
                {"count=1.5 (fractional) => -1", fun() ->
                    ?assertEqual(
                        {error, -1, <<"JSON integer out of range">>},
                        get_node_addresses([1.5]))
                end},
                {"count=1.0 (integral-valued float) => -1 (Core rejects too)",
                 fun() ->
                    ?assertEqual(
                        {error, -1, <<"JSON integer out of range">>},
                        get_node_addresses([1.0]))
                end},
                {"count=1 (genuine integer) still accepted", fun() ->
                    add_three_peers(),
                    {ok, R} = get_node_addresses([1]),
                    ?assertEqual(1, length(R))
                end}
            ]
        end
    }}.
