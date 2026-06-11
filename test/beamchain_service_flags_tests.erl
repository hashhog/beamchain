%%% Service-flags advertisement unit tests (campaign 2026-06-11).
%%%
%%% Asserts the bitset beamchain advertises in its `version' message
%%% matches Bitcoin Core's full non-pruned node local-services set:
%%%   NODE_NETWORK | NODE_WITNESS | NODE_NETWORK_LIMITED = 0x409.
%%%
%%% Two properties under test:
%%%   1. NODE_NETWORK_LIMITED (0x400) is advertised UNCONDITIONALLY
%%%      (Core init.cpp:863 seeds it for every node, not just pruned).
%%%   2. NODE_P2P_V2 (0x800) is NOT advertised — BIP-324 v2 transport is
%%%      default-off here, so claiming the bit would fake an off-wire
%%%      capability.
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

%% Core full non-pruned node local-services set.
-define(EXPECTED_FULL_NODE_SERVICES, 16#409).

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
    reset_keys(),
    Created.

cleanup(created) -> ets:delete(beamchain_config_ets);
cleanup(existed) -> reset_keys(), ok.

reset_keys() ->
    catch ets:delete(beamchain_config_ets, prune),
    catch ets:delete(beamchain_config_ets, peerbloomfilters),
    catch ets:delete(beamchain_config_ets, blockfilterindex),
    ok.

service_flags_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [
         {"default full node advertises exactly 0x409",
          fun default_full_node_services/0},
         {"NODE_NETWORK_LIMITED set on a non-pruned full node",
          fun network_limited_set_unpruned/0},
         {"NODE_NETWORK and NODE_WITNESS both set",
          fun network_and_witness_set/0},
         {"NODE_P2P_V2 NOT advertised (v2 default-off)",
          fun p2p_v2_not_set/0},
         {"NODE_NETWORK_LIMITED independent of prune (un-gating fix)",
          fun network_limited_independent_of_prune/0},
         {"NODE_NETWORK_LIMITED still set under prune, P2P_V2 still unset",
          fun network_limited_set_when_pruned/0}
        ]
     end}.

%% Default full node (no prune, no bloom, no compact filters):
%% advertised set must be EXACTLY 0x409.
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

%% NODE_P2P_V2 must NOT be set: v2 transport is default-off, so the bit
%% would advertise an off-wire capability.
p2p_v2_not_set() ->
    reset_keys(),
    Services = beamchain_peer:advertised_services(),
    ?assertEqual(0, Services band ?NODE_P2P_V2).

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
%% to be present under prune; the fix only broadens it). P2P_V2 stays unset.
network_limited_set_when_pruned() ->
    reset_keys(),
    ets:insert(beamchain_config_ets, {prune, "550"}),
    ?assert(beamchain_config:prune_enabled()),
    Services = beamchain_peer:advertised_services(),
    ?assert((Services band ?NODE_NETWORK_LIMITED) =/= 0),
    ?assertEqual(0, Services band ?NODE_P2P_V2),
    reset_keys().
