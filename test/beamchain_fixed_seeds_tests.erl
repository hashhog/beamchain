%%% -------------------------------------------------------------------
%%% Fixed-seed fallback (Bitcoin Core vFixedSeeds) unit tests.
%%%
%%% Proves:
%%%   (1) The mainnet network params carry exactly 40 fixed-seed entries,
%%%       and they parse to 40 routable IPv4 {Ip,8333} tuples.
%%%   (2) Non-mainnet networks (testnet/testnet4/signet/regtest) carry an
%%%       EMPTY fixed-seed list — the fallback can never fire there (Core
%%%       clears vFixedSeeds for regtest).
%%%   (3) The Core-faithful firing predicate (net.cpp:2604-2643):
%%%         * fires on an EMPTY address book when DNS is disabled
%%%           (net.cpp:2620 `!dnsseed && !use_seednodes` immediate),
%%%         * fires on an EMPTY book once the 60s grace has elapsed
%%%           (net.cpp:2614),
%%%         * does NOT fire while the grace is still pending with DNS on,
%%%         * does NOT fire when the address book is NON-empty,
%%%         * does NOT fire when the fallback is disabled (-fixedseeds=0 /
%%%           -connect),
%%%         * does NOT fire twice (one-shot guard).
%%% -------------------------------------------------------------------
-module(beamchain_fixed_seeds_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

%% The exact 40 IPs from the spec (verbatim).
-define(SEED_IPS, [
    "2.121.116.198:8333", "3.86.179.235:8333", "4.2.51.251:8333",
    "5.2.23.226:8333", "12.11.29.34:8333", "14.49.142.41:8333",
    "18.27.125.103:8333", "23.93.18.82:8333", "24.16.202.74:8333",
    "27.83.109.113:8333", "31.41.23.249:8333", "34.65.45.157:8333",
    "35.78.97.86:8333", "37.15.61.236:8333", "38.52.3.192:8333",
    "40.160.1.232:8333", "44.223.26.178:8333", "45.19.130.200:8333",
    "46.126.216.3:8333", "47.90.137.13:8333", "50.4.123.66:8333",
    "51.154.0.142:8333", "52.182.185.242:8333", "60.241.1.72:8333",
    "62.34.57.141:8333", "63.247.147.166:8333", "64.23.97.128:8333",
    "65.94.134.253:8333", "66.35.84.14:8333", "67.4.139.122:8333",
    "68.61.69.53:8333", "69.4.94.226:8333", "70.44.20.24:8333",
    "71.56.178.136:8333", "72.88.192.74:8333", "73.42.33.255:8333",
    "74.48.195.218:8333", "75.80.3.4:8333", "76.124.35.108:8333",
    "77.38.72.37:8333"
]).

%%% ===================================================================
%%% (1) DATA: mainnet carries 40 verbatim fixed seeds
%%% ===================================================================

mainnet_has_40_fixed_seeds_test() ->
    P = beamchain_config:network_params(mainnet),
    Seeds = P#network_params.fixed_seeds,
    ?assertEqual(40, length(Seeds)),
    %% Verbatim match against the spec list (order preserved).
    ?assertEqual(?SEED_IPS, Seeds).

%%% ===================================================================
%%% (1b) PARSING: 40 routable IPv4:8333 tuples
%%% ===================================================================

fixed_seeds_parse_to_40_routable_ipv4_8333_test() ->
    P = beamchain_config:network_params(mainnet),
    Specs = P#network_params.fixed_seeds,
    Addrs = beamchain_peer_manager:parse_fixed_seeds(Specs, 8333),
    %% Every entry parsed and survived the routability filter.
    ?assertEqual(40, length(Addrs)),
    %% Each is a {ipv4-4-tuple, 8333} with a routable address.
    lists:foreach(fun({IP, Port}) ->
        ?assertEqual(8333, Port),
        ?assertMatch({_, _, _, _}, IP),
        {A, B, _C, _D} = IP,
        %% None of the curated set is loopback / RFC1918 / link-local.
        ?assert(A =/= 127 andalso A =/= 0 andalso A =/= 10),
        ?assertNot(A =:= 172 andalso B >= 16 andalso B =< 31),
        ?assertNot(A =:= 192 andalso B =:= 168),
        ?assertNot(A =:= 169 andalso B =:= 254)
    end, Addrs),
    %% Spot-check the first and last parse exactly.
    ?assert(lists:member({{2, 121, 116, 198}, 8333}, Addrs)),
    ?assert(lists:member({{77, 38, 72, 37}, 8333}, Addrs)).

%% fixed_seed_addrs/0 (the live entrypoint) reads network_params/0 from the
%% beamchain_config ETS table; configure it to mainnet and assert 40 parsed
%% addresses.
fixed_seed_addrs_uses_active_network_test() ->
    with_network_params(mainnet, fun() ->
        Addrs = beamchain_peer_manager:fixed_seed_addrs(),
        ?assertEqual(40, length(Addrs))
    end).

%%% ===================================================================
%%% (2) Non-mainnet networks carry NO fixed seeds
%%% ===================================================================

non_mainnet_fixed_seeds_empty_test() ->
    lists:foreach(fun(Net) ->
        P = beamchain_config:network_params(Net),
        ?assertEqual([], P#network_params.fixed_seeds)
    end, [testnet, testnet4, signet, regtest]).

regtest_fallback_never_fires_test() ->
    %% Even with the firing predicate satisfied, an empty fixed-seed list
    %% means there is nothing to inject — the fallback is a no-op on regtest.
    with_network_params(regtest, fun() ->
        ?assertEqual([], beamchain_peer_manager:fixed_seed_addrs())
    end).

%% Configure the beamchain_config ETS table with the given network's params
%% for the duration of Fun, then restore.
with_network_params(Net, Fun) ->
    Tab = beamchain_config_ets,
    Created = case ets:info(Tab) of
        undefined ->
            ets:new(Tab, [named_table, set, public]),
            true;
        _ ->
            false
    end,
    Prev = ets:lookup(Tab, network_params),
    ets:insert(Tab, {network_params, beamchain_config:network_params(Net)}),
    try
        Fun()
    after
        case Created of
            true ->
                catch ets:delete(Tab);
            false ->
                case Prev of
                    [{network_params, V}] ->
                        ets:insert(Tab, {network_params, V});
                    [] ->
                        ets:delete(Tab, network_params)
                end
        end
    end.

%%% ===================================================================
%%% (3) Core-faithful firing predicate (net.cpp:2604-2643)
%%% ===================================================================

%% should_fire_fixed_seeds(AlreadyAdded, NoFixedSeed, Discovered,
%%                         NoDnsSeed, Start, Now)

predicate_fires_on_dns_disabled_empty_book_test() ->
    %% DNS off, book empty, not yet fired, enabled: fire immediately
    %% (net.cpp:2620 cheap shortcut), regardless of elapsed time.
    Now = 1000,
    ?assert(beamchain_peer_manager:should_fire_fixed_seeds(
              false, false, [], true, Now, Now)).

predicate_fires_after_60s_grace_with_dns_on_test() ->
    %% DNS on, book empty, 60s elapsed: fire (net.cpp:2614).
    Start = 1000,
    ?assert(beamchain_peer_manager:should_fire_fixed_seeds(
              false, false, [], false, Start, Start + 60)),
    %% Strictly more than 60s also fires.
    ?assert(beamchain_peer_manager:should_fire_fixed_seeds(
              false, false, [], false, Start, Start + 120)).

predicate_does_not_fire_within_grace_with_dns_on_test() ->
    %% DNS on, book empty, but only 30s elapsed: still waiting for DNS.
    Start = 1000,
    ?assertNot(beamchain_peer_manager:should_fire_fixed_seeds(
                 false, false, [], false, Start, Start + 30)),
    ?assertNot(beamchain_peer_manager:should_fire_fixed_seeds(
                 false, false, [], false, Start, Start + 59)).

predicate_does_not_fire_when_book_non_empty_test() ->
    %% A populated address book blocks the fallback even past the grace and
    %% even with DNS disabled (Core GetReachableEmptyNetworks() proxy).
    Book = [{{8, 8, 8, 8}, 8333}],
    Start = 1000,
    ?assertNot(beamchain_peer_manager:should_fire_fixed_seeds(
                 false, false, Book, true, Start, Start + 9999)),
    ?assertNot(beamchain_peer_manager:should_fire_fixed_seeds(
                 false, false, Book, false, Start, Start + 9999)).

predicate_does_not_fire_when_disabled_test() ->
    %% -fixedseeds=0 / -connect (NoFixedSeed=true): never fire, even on an
    %% empty book with DNS off.
    Now = 1000,
    ?assertNot(beamchain_peer_manager:should_fire_fixed_seeds(
                 false, true, [], true, Now, Now + 9999)).

predicate_is_one_shot_test() ->
    %% AlreadyAdded=true: never re-fire even if every other condition holds.
    Now = 1000,
    ?assertNot(beamchain_peer_manager:should_fire_fixed_seeds(
                 true, false, [], true, Now, Now + 9999)).
