%%% Service-flags advertisement unit tests (campaign 2026-06-11,
%%% v2-flip 2026-06-12).
%%%
%%% Asserts the bitset beamchain advertises in its `version' message
%%% matches Bitcoin Core's full non-pruned node local-services set with
%%% the v2 (BIP-324) transport enabled:
%%%   NODE_NETWORK | NODE_WITNESS | NODE_NETWORK_LIMITED | NODE_P2P_V2
%%%   = 0xc09 (Core regtest -v2transport value).
%%%
%%% Properties under test:
%%%   1. NODE_NETWORK_LIMITED (0x400) is advertised UNCONDITIONALLY
%%%      (Core init.cpp:863 seeds it for every node, not just pruned).
%%%   2. NODE_P2P_V2 (0x800) IS advertised when the v2 transport is
%%%      enabled (the default), giving 0xc09 — gated on the SAME predicate
%%%      that enables the transport (bip324_v2_outbound_enabled/0) so the
%%%      bit can never claim an off-wire capability.
%%%   3. With v2 explicitly opted out the bit drops, giving 0x409 — proving
%%%      the advertisement is genuinely gated, not hardcoded.
%%%
%%% Exercises the production code path: beamchain_peer:advertised_services/0
%%% is the exact function do_send_version/1 calls to build the wire
%%% `services' field (no logic duplicated in the test — avoids the
%%% dead-code failure mode).
-module(beamchain_service_flags_tests).

-include_lib("eunit/include/eunit.hrl").

%% Service flag bit values (must mirror include/beamchain_protocol.hrl).
-define(NODE_NETWORK,         1).        %% 0x001
-define(NODE_WITNESS,         8).        %% 0x008
-define(NODE_NETWORK_LIMITED, 1024).     %% 0x400
-define(NODE_P2P_V2,          2048).     %% 0x800 (must stay UNSET by default)

%% Core full non-pruned node local-services set with the v2 transport on
%% (the default): NODE_NETWORK | NODE_WITNESS | NODE_NETWORK_LIMITED |
%% NODE_P2P_V2 = 0xc09 (matches Core regtest -v2transport getnetworkinfo).
-define(EXPECTED_FULL_NODE_SERVICES, 16#c09).
%% Same set with the v2 transport explicitly opted out: the P2P_V2 bit
%% drops, leaving NODE_NETWORK | NODE_WITNESS | NODE_NETWORK_LIMITED = 0x409.
-define(EXPECTED_FULL_NODE_SERVICES_V2_OFF, 16#409).

%% --- fixture ------------------------------------------------------------
%% advertised_services/0 reads config via beamchain_config:get/2, which does
%% an ets:lookup on the beamchain_config_ets table (badarg if absent). Create
%% it for the duration of the fixture and clear the keys we care about so the
%% test process behaves as a default-configured full node. Also clear the
%% precedence-taking env vars.
setup() ->
    Created = case ets:info(beamchain_config_ets) of
        undefined ->
            ets:new(beamchain_config_ets,
                    [named_table, set, public, {read_concurrency, true}]),
            created;
        _ ->
            existed
    end,
    [os:unsetenv(V) || V <- ["BEAMCHAIN_PRUNE",
                             "BEAMCHAIN_PEERBLOOMFILTERS",
                             "BEAMCHAIN_BLOCKFILTERINDEX"]],
    %% v2 transport predicate reads env + app-env (NOT the config ets).
    %% Capture the prior env so we can restore it, then clear both so the
    %% default-configured node path runs (env unset + app-env unset → v2 ON).
    PriorV2 = os:getenv("BEAMCHAIN_BIP324_V2_OUTBOUND"),
    PriorAppV2 = application:get_env(beamchain, bip324_v2_outbound),
    os:unsetenv("BEAMCHAIN_BIP324_V2_OUTBOUND"),
    application:unset_env(beamchain, bip324_v2_outbound),
    reset_keys(),
    {Created, PriorV2, PriorAppV2}.

cleanup({Created, PriorV2, PriorAppV2}) ->
    %% Restore the v2 env/app-env exactly as we found it.
    case PriorV2 of
        false -> os:unsetenv("BEAMCHAIN_BIP324_V2_OUTBOUND");
        V     -> os:putenv("BEAMCHAIN_BIP324_V2_OUTBOUND", V)
    end,
    case PriorAppV2 of
        undefined  -> application:unset_env(beamchain, bip324_v2_outbound);
        {ok, AppV} -> application:set_env(beamchain, bip324_v2_outbound, AppV)
    end,
    case Created of
        created -> ets:delete(beamchain_config_ets);
        existed -> reset_keys(), ok
    end.

reset_keys() ->
    catch ets:delete(beamchain_config_ets, prune),
    catch ets:delete(beamchain_config_ets, peerbloomfilters),
    catch ets:delete(beamchain_config_ets, blockfilterindex),
    ok.

service_flags_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [
         {"default full node advertises exactly 0xc09 (v2 on)",
          fun default_full_node_services/0},
         {"NODE_NETWORK_LIMITED set on a non-pruned full node",
          fun network_limited_set_unpruned/0},
         {"NODE_NETWORK and NODE_WITNESS both set",
          fun network_and_witness_set/0},
         {"NODE_P2P_V2 advertised when v2 enabled (the default)",
          fun p2p_v2_set_by_default/0},
         {"NODE_P2P_V2 dropped on explicit v2 opt-out (gated, not hardcoded)",
          fun p2p_v2_gated_off_on_optout/0},
         {"NODE_NETWORK_LIMITED independent of prune (un-gating fix)",
          fun network_limited_independent_of_prune/0},
         {"NODE_NETWORK_LIMITED still set under prune, P2P_V2 still set",
          fun network_limited_set_when_pruned/0}
        ]
     end}.

%% Default full node (no prune, no bloom, no compact filters, v2 on):
%% advertised set must be EXACTLY 0xc09.
default_full_node_services() ->
    reset_keys(),
    Services = beamchain_peer:advertised_services(),
    ?assertEqual(?EXPECTED_FULL_NODE_SERVICES, Services).

%% NODE_NETWORK_LIMITED must be set on a non-pruned full node (the fix:
%% Core advertises it unconditionally — init.cpp:863).
network_limited_set_unpruned() ->
    reset_keys(),
    Services = beamchain_peer:advertised_services(),
    ?assert((Services band ?NODE_NETWORK_LIMITED) =/= 0).

%% NODE_NETWORK and NODE_WITNESS must also be set (full witness node).
network_and_witness_set() ->
    reset_keys(),
    Services = beamchain_peer:advertised_services(),
    ?assert((Services band ?NODE_NETWORK) =/= 0),
    ?assert((Services band ?NODE_WITNESS) =/= 0).

%% NODE_P2P_V2 MUST be set by default: the v2 transport is proven and
%% default-on, and the bit is gated on the same predicate that enables it
%% (bip324_v2_outbound_enabled/0), so the wire claim is genuine.
p2p_v2_set_by_default() ->
    reset_keys(),
    Services = beamchain_peer:advertised_services(),
    ?assert((Services band ?NODE_P2P_V2) =/= 0).

%% Proves the advertisement is GATED, not hardcoded: with the v2 transport
%% explicitly opted out, NODE_P2P_V2 drops and the set falls back to 0x409.
%% The bit can therefore never claim an off-wire capability.
p2p_v2_gated_off_on_optout() ->
    reset_keys(),
    os:putenv("BEAMCHAIN_BIP324_V2_OUTBOUND", "0"),
    ?assertNot(beamchain_peer:bip324_v2_outbound_enabled()),
    Services = beamchain_peer:advertised_services(),
    ?assertEqual(0, Services band ?NODE_P2P_V2),
    ?assertEqual(?EXPECTED_FULL_NODE_SERVICES_V2_OFF, Services),
    os:unsetenv("BEAMCHAIN_BIP324_V2_OUTBOUND").

%% Regression guard for the un-gating fix: NODE_NETWORK_LIMITED stays set
%% even when prune mode is explicitly OFF. (Pre-fix it was advertised ONLY
%% under prune_enabled(); this asserts it no longer depends on prune.)
network_limited_independent_of_prune() ->
    reset_keys(),
    ets:insert(beamchain_config_ets, {prune, "0"}),
    ?assertNot(beamchain_config:prune_enabled()),
    Services = beamchain_peer:advertised_services(),
    ?assertEqual(?EXPECTED_FULL_NODE_SERVICES, Services),
    ?assert((Services band ?NODE_NETWORK_LIMITED) =/= 0).

%% And still set when prune mode IS on (sanity: the bit was always meant
%% to be present under prune; the fix only broadens it). P2P_V2 is
%% orthogonal to prune and stays SET (v2 default-on).
network_limited_set_when_pruned() ->
    reset_keys(),
    ets:insert(beamchain_config_ets, {prune, "550"}),
    ?assert(beamchain_config:prune_enabled()),
    Services = beamchain_peer:advertised_services(),
    ?assert((Services band ?NODE_NETWORK_LIMITED) =/= 0),
    ?assert((Services band ?NODE_P2P_V2) =/= 0),
    reset_keys().
