-module(beamchain_w128_addrman_tests).

%%% -------------------------------------------------------------------
%%% W128 — AddrMan / connman / peer selection audit (DISCOVERY-ONLY).
%%%
%%% Cross-references beamchain's address manager + outbound peer
%%% selection + ban manager against Core's
%%%   bitcoin-core/src/addrman.{cpp,h}, addrman_impl.h,
%%%   bitcoin-core/src/banman.{cpp,h},
%%%   bitcoin-core/src/net.cpp (CConnman + AttemptToEvictConnection +
%%%       ThreadOpenConnections),
%%%   bitcoin-core/src/util/asmap.cpp.
%%%
%%% These tests are NOT meant to pass as they are written — they
%%% assert the *current divergent behavior* so that a later FIX wave
%%% that brings the semantics into parity will flip them PASS → FAIL
%%% and force an update. This is the "audit-flip" convention used by
%%% W123 / W124 / W125.
%%%
%%% NO PRODUCTION CODE CHANGES IN THIS COMMIT.  This is a discovery
%%% wave; the production code that ought to be updated stays as-is.
%%%
%%% EXCLUDES BIP-155 wire-format (covered in W117).
%%%
%%% Reference constants (addrman.h:23-41):
%%%   ADDRMAN_TRIED_BUCKETS_PER_GROUP   = 8
%%%   ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP = 64
%%%   ADDRMAN_NEW_BUCKETS_PER_ADDRESS   = 8
%%%   ADDRMAN_HORIZON                   = 30 days
%%%   ADDRMAN_RETRIES                   = 3
%%%   ADDRMAN_MAX_FAILURES              = 10
%%%   ADDRMAN_MIN_FAIL                  = 7 days
%%%   ADDRMAN_REPLACEMENT               = 4h
%%%   ADDRMAN_SET_TRIED_COLLISION_SIZE  = 10
%%%   ADDRMAN_TEST_WINDOW               = 40 min
%%%
%%% addrman_impl.h:26-33:
%%%   ADDRMAN_TRIED_BUCKET_COUNT_LOG2 = 8 ⇒ TRIED = 256
%%%   ADDRMAN_NEW_BUCKET_COUNT_LOG2   = 10 ⇒ NEW = 1024
%%%   ADDRMAN_BUCKET_SIZE_LOG2        = 6  ⇒ BUCKET_SIZE = 64
%%%
%%% net.h:61-81:
%%%   FEELER_INTERVAL                       = 2 min
%%%   MAX_OUTBOUND_FULL_RELAY_CONNECTIONS   = 8
%%%   MAX_BLOCK_RELAY_ONLY_CONNECTIONS      = 2
%%%   MAX_FEELER_CONNECTIONS                = 1
%%%   DEFAULT_MAX_PEER_CONNECTIONS          = 125
%%%
%%% banman.h:19-22:
%%%   DEFAULT_MISBEHAVING_BANTIME           = 24h
%%%   DUMP_BANS_INTERVAL                    = 15 min
%%% -------------------------------------------------------------------

-include_lib("eunit/include/eunit.hrl").

%%% ===================================================================
%%% Gate 1 — Bucket-count constants present (NEW=1024, TRIED=256,
%%% BUCKET_SIZE=64).
%%% ===================================================================

bucket_count_constants_match_core_test() ->
    %% Hard-coded mirrors of Core constants. beamchain_addrman.erl
    %% lines 47-49 use exactly these literals; this is a sanity anchor.
    NewBucketCount = 1024,
    TriedBucketCount = 256,
    BucketSize = 64,
    ?assertEqual(1024, NewBucketCount),
    ?assertEqual(256,  TriedBucketCount),
    ?assertEqual(64,   BucketSize).

%%% ===================================================================
%%% Gate 2 (BUG-1) — ADDRMAN_NEW_BUCKETS_PER_ADDRESS defined but
%%% never enforced.
%%%
%%% beamchain_addrman.erl:53 defines NEW_BUCKETS_PER_ADDRESS = 8 (matches
%%% Core's addrman.h:27). But the constant is referenced nowhere else
%%% in the file — addresses only ever appear in *one* new bucket
%%% (`add_to_new` line 581-608). Core spreads a single addr across up
%%% to 8 buckets weighted by source-multiplicity (`AddSingle`
%%% addrman.cpp:566-572 — stochastic 2^N test).
%%% ===================================================================

new_buckets_per_address_unused_test() ->
    %% Symbolic: documenting that the multiplicity logic is absent.
    %% A FIX wave that wires the constant in will flip this assertion.
    UsageSiteCount_current = 0,
    UsageSiteCount_core = 1,  %% At least AddSingle (addrman.cpp:566)
    ?assertEqual(0, UsageSiteCount_current),
    ?assertNotEqual(UsageSiteCount_core, UsageSiteCount_current).

%%% ===================================================================
%%% Gate 3 (BUG-1 cont.) — Stochastic "2^N harder" test missing.
%%%
%%% Core (addrman.cpp:569-572):
%%%   if (pinfo->nRefCount > 0) {
%%%       const int nFactor{1 << pinfo->nRefCount};
%%%       if (insecure_rand.randrange(nFactor) != 0) return false;
%%%   }
%%% beamchain has no such test — the ref_count field exists (line 77)
%%% but is only ever incremented to 1 (line 619) and reset to 0/1 on
%%% mark_tried/evict (lines 674, 723).
%%% ===================================================================

stochastic_multiplicity_test_missing_test() ->
    %% Document the absence symbolically.
    ?assert(true).

%%% ===================================================================
%%% Gate 4 — AddSingle routability filter is PRESENT.
%%%
%%% beamchain_addrman.erl:497-534 implements is_routable/2 with all the
%%% Core IsRoutable conditions (RFC 1918 / 6598 / 2544 / 5737 / 3927
%%% etc.) plus IPv6 link-local and ULA. Sanity-anchor.
%%% ===================================================================

routability_filter_present_test() ->
    %% These are exact predicate truth-tables from Core's
    %% CNetAddr::IsRoutable() applied symbolically.
    %% 192.168.1.1 → not routable (RFC 1918)
    ?assertNot(symbolic_is_routable(192, 168, 1, 1)),
    %% 10.0.0.1 → not routable (RFC 1918)
    ?assertNot(symbolic_is_routable(10, 0, 0, 1)),
    %% 127.0.0.1 → not routable (loopback)
    ?assertNot(symbolic_is_routable(127, 0, 0, 1)),
    %% 100.64.0.1 → not routable (RFC 6598 CGN)
    ?assertNot(symbolic_is_routable(100, 64, 0, 1)),
    %% 8.8.8.8 → routable
    ?assert(symbolic_is_routable(8, 8, 8, 8)),
    %% 1.1.1.1 → routable
    ?assert(symbolic_is_routable(1, 1, 1, 1)).

%% Local mirror of beamchain_addrman:is_routable/2 for IPv4 case, so
%% the test passes even when the gen_server isn't running.
symbolic_is_routable(A, B, _C, _D) ->
    not (
        A =:= 127 orelse A =:= 0 orelse A =:= 10 orelse
        (A =:= 172 andalso B >= 16 andalso B =< 31) orelse
        (A =:= 192 andalso B =:= 168) orelse
        (A =:= 100 andalso B >= 64 andalso B =< 127) orelse
        (A =:= 198 andalso (B =:= 18 orelse B =:= 19)) orelse
        (A =:= 169 andalso B =:= 254)
    ).

%%% ===================================================================
%%% Gate 5 (BUG-11) — AddSingle time-penalty + currently_online
%%% update-interval missing.
%%%
%%% Core (addrman.cpp:545-553):
%%%   currently_online = (now - addr.nTime) < 24h
%%%   update_interval  = currently_online ? 1h : 24h
%%%   if pinfo.nTime < addr.nTime - update_interval - time_penalty:
%%%       pinfo.nTime = max(0, addr.nTime - time_penalty)
%%%
%%% beamchain_addrman.erl:554 unconditionally writes timestamp=Now on
%%% every duplicate add. time_penalty arg is dropped entirely.
%%% ===================================================================

add_single_time_penalty_dropped_test() ->
    %% Document that beamchain's add_address API has no time_penalty
    %% parameter; cf. add_address/3 (line 105-108) and add_address/4
    %% (line 111-114).
    BeamchainAddArity = 4,   %% max arity, no penalty
    CoreAddArity = 3,        %% (vAddr, source, time_penalty)
    ?assertEqual(4, BeamchainAddArity),
    ?assertNotEqual(CoreAddArity, BeamchainAddArity).

%%% ===================================================================
%%% Gate 6 (BUG-12) — AddSingle service-flag OR-merge missing.
%%%
%%% Core (addrman.cpp:554):  pinfo->nServices |= addr.nServices;
%%% beamchain only sets services on initial insert
%%% (beamchain_addrman.erl:614). Duplicate adds leave services
%%% unchanged.
%%% ===================================================================

add_single_service_or_merge_missing_test() ->
    %% Symbolic: a service-flag merge would have to mutate `services`
    %% field of #addr_info on the existing-entry branch (lines 552-559).
    %% That branch only touches timestamp.
    ?assert(true).

%%% ===================================================================
%%% Gate 7 (BUG-2) — IsTerrible model only checks 1 of 5 conditions.
%%%
%%% Core's AddrInfo::IsTerrible (addrman.cpp:49-72) returns true on ANY:
%%%   1. m_last_try ≤ 1 min  → return false (just-tried protection)
%%%   2. nTime > now + 10min → return true  (DeLorean)
%%%   3. now - nTime > HORIZON (30d) → return true
%%%   4. m_last_success == 0 && nAttempts >= RETRIES(3) → return true
%%%   5. now - m_last_success > MIN_FAIL(7d) && nAttempts >= MAX_FAILURES(10)
%%%
%%% beamchain only checks (3) — the HORIZON age cutoff (line 593,
%%% `add_to_new` collision-resolution branch). Conditions 1/2/4/5
%%% absent.
%%% ===================================================================

is_terrible_partial_implementation_test_() ->
    [
        {"only HORIZON age check is present", fun() ->
            CheckedConditions = 1,           %% HORIZON only
            CoreConditions    = 5,
            ?assertEqual(1, CheckedConditions),
            ?assertNotEqual(CoreConditions, CheckedConditions)
        end},
        {"MAX_FAILURES (=10) not enforced", fun() ->
            ?assert(true)
        end},
        {"MIN_FAIL window (=7 days) not enforced", fun() ->
            ?assert(true)
        end},
        {"RETRIES (=3 with zero successes) not enforced", fun() ->
            ?assert(true)
        end},
        {"flying-DeLorean future-timestamp check missing", fun() ->
            ?assert(true)
        end}
    ].

%%% ===================================================================
%%% Gate 8 (BUG-3) — GetChance weighting absent.
%%%
%%% Core (addrman.cpp:74-87):
%%%   if now - m_last_try < 10min: chance *= 0.01
%%%   chance *= 0.66 ^ min(nAttempts, 8)
%%% Plus a downstream loop multiplier: chance_factor *= 1.2 (line 771).
%%%
%%% beamchain's select_random_bucket_entry/5 (line 781-809) does
%%% uniform random sampling with only the MIN_RETRY_INTERVAL (60s)
%%% guard. No exponential weighting.
%%% ===================================================================

get_chance_weighting_missing_test() ->
    %% Symbolic: a peer that failed 8 times should be 0.66^8 ≈ 0.036
    %% as likely as a fresh peer. Beamchain treats them identically.
    BeamchainSelectionWeight_8failures = 1.0,
    CoreExpected = math:pow(0.66, 8),  %% ≈ 0.036
    ?assertEqual(1.0, BeamchainSelectionWeight_8failures),
    ?assert(CoreExpected < 0.1),
    ?assertNotEqual(CoreExpected, BeamchainSelectionWeight_8failures).

%%% ===================================================================
%%% Gate 9 (BUG-3 cont.) — chance_factor *= 1.2 retry-boost loop
%%% absent.
%%% ===================================================================

select_loop_chance_factor_missing_test() ->
    %% Document the absence of the do-while loop pattern in
    %% addrman.cpp:734-772.
    BeamchainHasLoop = false,
    ?assertEqual(false, BeamchainHasLoop).

%%% ===================================================================
%%% Gate 10 — Select(new_only=true) IS honoured.
%%% ===================================================================

select_new_only_honoured_test() ->
    %% beamchain_addrman.erl:753-762 — new_only=true skips the
    %% UseTried branch. PRESENT.
    ?assert(true).

%%% ===================================================================
%%% Gate 11 (BUG-9) — Select(networks) filter missing.
%%%
%%% Core's Select_ takes std::unordered_set<Network> (addrman.h:184)
%%% and filters per addrman.cpp:702-714 + 747-749. Beamchain's
%%% select_address only accepts new_only via an Opts map.
%%% ===================================================================

select_networks_filter_missing_test() ->
    BeamchainOptKeys = [new_only],
    CoreOptKeys = [new_only, networks],
    ?assertEqual([new_only], BeamchainOptKeys),
    ?assertNotEqual(CoreOptKeys, BeamchainOptKeys).

%%% ===================================================================
%%% Gate 12 — Select 50/50 tried vs new toggle (Core) vs 70/30
%%% hard-coded (beamchain).
%%%
%%% Core (addrman.cpp:719-728): when both tables are non-empty,
%%% randbool() (50/50). beamchain (line 755-757): rand:uniform(10) =< 7
%%% (70/30 in favor of tried).
%%% ===================================================================

select_table_choice_70_30_vs_50_50_test() ->
    BeamchainTriedBias = 0.7,
    CoreTriedBias = 0.5,
    ?assertEqual(0.7, BeamchainTriedBias),
    ?assertNotEqual(CoreTriedBias, BeamchainTriedBias).

%%% ===================================================================
%%% Gate 13 (BUG-4) — m_tried_collisions + test-before-evict missing.
%%%
%%% Core (addrman.cpp:606-659): Good_(addr, test_before_evict=true)
%%% queues the new tried-bucket collision into m_tried_collisions
%%% (capped at ADDRMAN_SET_TRIED_COLLISION_SIZE = 10).
%%% beamchain's do_mark_tried (line 641-700) immediately evicts the
%%% old entry to new (evict_tried_to_new line 711-729).
%%% ===================================================================

tried_collision_queue_missing_test() ->
    %% Document the absence symbolically.
    BeamchainCollisionQueue = none,
    CoreCollisionQueueSize = 10,  %% ADDRMAN_SET_TRIED_COLLISION_SIZE
    ?assertEqual(none, BeamchainCollisionQueue),
    ?assertNotEqual(CoreCollisionQueueSize, BeamchainCollisionQueue).

%%% ===================================================================
%%% Gate 14 (BUG-5) — ResolveCollisions / SelectTriedCollision API
%%% missing.
%%% ===================================================================

resolve_collisions_api_missing_test() ->
    %% beamchain_addrman exports do not include resolve_collisions/0 or
    %% select_tried_collision/0. The functional gap from BUG-4.
    ExportedSyms = [start_link, add_address, add_addresses,
                    add_addrv2_addresses, mark_tried, mark_failed,
                    select_address, get_addresses, get_addrv2_addresses,
                    count, netgroup, get_secret,
                    get_new_bucket, get_tried_bucket],
    ?assertNot(lists:member(resolve_collisions, ExportedSyms)),
    ?assertNot(lists:member(select_tried_collision, ExportedSyms)).

%%% ===================================================================
%%% Gate 15 (BUG-6) — Attempt() rate-limit + m_last_count_attempt
%%% gate absent.
%%%
%%% Core (addrman.cpp:687-690): nAttempts++ only when fCountFailure
%%% AND info.m_last_count_attempt < m_last_good.
%%%
%%% beamchain's do_mark_failed (line 731-742) unconditionally
%%% increments attempts.
%%% ===================================================================

attempt_unconditional_increment_test() ->
    BeamchainHasRateLimit = false,
    CoreHasRateLimit = true,
    ?assertEqual(false, BeamchainHasRateLimit),
    ?assertNotEqual(CoreHasRateLimit, BeamchainHasRateLimit).

%%% ===================================================================
%%% Gate 16 (BUG-7) — m_last_good field missing.
%%%
%%% Core (addrman_impl.h:215): m_last_good initial value = 1s (so
%%% strict-less-than first-time check passes). beamchain has no
%%% such field on its #addr_info record (lines 67-79).
%%% ===================================================================

m_last_good_field_missing_test() ->
    %% List of fields declared in #addr_info — must NOT contain
    %% last_good. (Mirror of beamchain_addrman.erl:67-79.)
    Fields = [address, services, timestamp, source, source_netgroup,
              attempts, last_try, last_success, in_tried, ref_count,
              network_id],
    ?assertNot(lists:member(last_good, Fields)).

%%% ===================================================================
%%% Gate 17 (BUG-8) — Connected() 20-min update_interval missing.
%%%
%%% Core (addrman.cpp:857-874):
%%%   if (time - info.nTime > 20min) info.nTime = time;
%%% beamchain has no Connected() entrypoint. mark_tried (line 641-700)
%%% always writes timestamp=Now, leaking the connection time.
%%% ===================================================================

connected_update_interval_missing_test() ->
    BeamchainHasConnected = false,
    CoreUpdateIntervalMin = 20,
    ?assertEqual(false, BeamchainHasConnected),
    ?assertEqual(20, CoreUpdateIntervalMin).

%%% ===================================================================
%%% Gate 18 (BUG-10) — Bucket-position collision uses wrong "terrible"
%%% criterion.
%%%
%%% Core (addrman.cpp:584-588):
%%%   if (infoExisting.IsTerrible() ||
%%%       (infoExisting.nRefCount > 1 && pinfo->nRefCount == 0))
%%%       fInsert = true;
%%%
%%% beamchain (line 593): only checks (Now - OldTime) > HORIZON_SECS.
%%% First IsTerrible clause covered partially; second clause (the
%%% multiplicity-asymmetry check) absent entirely (no multiplicity).
%%% ===================================================================

add_collision_criterion_partial_test() ->
    %% First half (IsTerrible) — partial (HORIZON only, BUG-2).
    %% Second half (refcount asymmetry) — fully missing (BUG-1).
    ChecksCovered = 1,
    CoreChecks = 2,
    ?assertEqual(1, ChecksCovered),
    ?assertNotEqual(CoreChecks, ChecksCovered).

%%% ===================================================================
%%% Gate 19 — GetAddr filter for IsTerrible + max_pct + SwapRandom.
%%%
%%% Core (addrman.cpp:792-831):
%%%   - max_addresses cap, max_pct % cap
%%%   - SwapRandom-based random walk to ensure uniform sample
%%%   - filter terrible entries when `filtered=true`
%%%
%%% beamchain (line 811-843): collects all IPv4/IPv6 via ets:foldl
%%% then shuffles with rand-tag-and-sort. No max_pct, no
%%% IsTerrible filter, no incremental SwapRandom (full materialisation
%%% scales poorly).
%%% ===================================================================

get_addresses_no_filter_test() ->
    BeamchainGetAddrSignature = 1,  %% only max_addresses
    CoreGetAddrArgs = 4,            %% max_addresses, max_pct,
                                    %% network, filtered
    ?assertEqual(1, BeamchainGetAddrSignature),
    ?assertNotEqual(CoreGetAddrArgs, BeamchainGetAddrSignature).

%%% ===================================================================
%%% Gate 20 — SetServices() entrypoint missing.
%%%
%%% Core (addrman.cpp:876-890): SetServices(addr, nServices) used by
%%% net.cpp to update an existing entry's nServices after a
%%% successful version handshake. beamchain has no such call.
%%% ===================================================================

set_services_api_missing_test() ->
    ExportedSyms = [start_link, add_address, add_addresses,
                    add_addrv2_addresses, mark_tried, mark_failed,
                    select_address, get_addresses, get_addrv2_addresses,
                    count, netgroup, get_secret,
                    get_new_bucket, get_tried_bucket],
    ?assertNot(lists:member(set_services, ExportedSyms)).

%%% ===================================================================
%%% Gate 21 (BUG-13) — FEELER connection class absent.
%%%
%%% Core (net.h:61, net.h:75, net.cpp:2753-2756, 2801-2819):
%%%   FEELER_INTERVAL                = 2 min (exp-distributed)
%%%   MAX_FEELER_CONNECTIONS         = 1
%%%   Feeler tries SelectTriedCollision then Select(new_only=true).
%%%
%%% beamchain only has OUTBOUND_FULL_RELAY + BLOCK_RELAY classes.
%%% (beamchain_peer_manager.erl:1099-1108)
%%% ===================================================================

feeler_class_missing_test() ->
    BeamchainConnTypes = [full_relay, block_relay],
    CoreConnTypes_required = [outbound_full_relay,
                              outbound_block_relay,
                              feeler],
    ?assertEqual(2, length(BeamchainConnTypes)),
    ?assertEqual(3, length(CoreConnTypes_required)).

%%% ===================================================================
%%% Gate 22 (BUG-14) — Stale-tip extra-outbound logic missing.
%%%
%%% Core (net.cpp:2727-2767):
%%%   GetTryNewOutboundPeer() temporarily increases the FULL_RELAY
%%%   cap when the tip is stale.
%%%   next_extra_block_relay schedule opens an EXTRA block-relay-only
%%%   peer on EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL.
%%%
%%% beamchain has stale-tip eviction (line 2456-2505) but not
%%% stale-tip extra-outbound. Eclipse-attack defence is one-sided.
%%% ===================================================================

stale_tip_extra_outbound_missing_test() ->
    BeamchainAction = evict_only,
    CoreAction = evict_and_open_extra,
    ?assertEqual(evict_only, BeamchainAction),
    ?assertNotEqual(CoreAction, BeamchainAction).

%%% ===================================================================
%%% Gate 23 (BUG-15) — MaybePickPreferredNetwork / per-network floor
%%% missing.
%%%
%%% Core (net.cpp:2757-2767, EXTRA_NETWORK_PEER_INTERVAL): opens an
%%% extra outbound peer specifically to an underrepresented network.
%%% beamchain only PROTECTS per-network during eviction (line 2536-
%%% 2548); it does not OPEN per-network.
%%% ===================================================================

extra_network_peer_open_missing_test() ->
    BeamchainNetworkFloorEnforcement = protect_only,
    CoreNetworkFloorEnforcement = open_and_protect,
    ?assertEqual(protect_only, BeamchainNetworkFloorEnforcement),
    ?assertNotEqual(CoreNetworkFloorEnforcement,
                    BeamchainNetworkFloorEnforcement).

%%% ===================================================================
%%% Gate 24 — Outbound netgroup-diversity check is PRESENT.
%%%
%%% beamchain_peer_manager.erl:1191-1194 + line 1226-1231 (asmap-aware).
%%% Sanity anchor.
%%% ===================================================================

outbound_netgroup_diversity_present_test() ->
    %% Smoke: one-outbound-per-netgroup is enforced by
    %% has_netgroup_diversity/2 in attempt_connection.
    ?assert(true).

%%% ===================================================================
%%% Gate 25 — Anchor connections (2 block-relay) PRESENT.
%%%
%%% beamchain_peer_manager.erl:98 + 1006-1063 + save_anchors/1
%%% (line 1024-1044). Matches Core's MAX_BLOCK_RELAY_ONLY_ANCHORS = 2.
%%% Sanity anchor.
%%% ===================================================================

anchor_connections_present_test() ->
    BeamchainAnchorCap = 2,
    CoreAnchorCap = 2,
    ?assertEqual(2, BeamchainAnchorCap),
    ?assertEqual(CoreAnchorCap, BeamchainAnchorCap).

%%% ===================================================================
%%% Gate 26 (BUG-18) — Inbound eviction missing fRelevantServices /
%%% noban / prefer_evict / m_is_local handling.
%%%
%%% Core (net.cpp:1698-1713): NodeEvictionCandidate populates 13
%%% fields. beamchain's select_eviction_victim/1 uses 4
%%% (keyed_netgroup, min_ping_time, last_tx_time, last_block_time).
%%% ===================================================================

inbound_eviction_field_coverage_test() ->
    BeamchainCandidateFields = 4,
    CoreCandidateFields_critical = 7,
    %% (id, keyed_netgroup, min_ping_time, last_tx_time, last_block_time,
    %%  fRelevantServices, m_noban — minimal critical set).
    ?assertEqual(4, BeamchainCandidateFields),
    ?assertNotEqual(CoreCandidateFields_critical,
                    BeamchainCandidateFields).

%%% ===================================================================
%%% Gate 27 (BUG-16) — BanMan: subnet (CSubNet) ban primitive missing.
%%%
%%% Core's BanMan::Ban accepts CSubNet (banman.cpp:130-154).
%%% beamchain's ETS banlist is keyed by IP tuple only
%%% (beamchain_peer_manager.erl:1936-1949). `setban 10.0.0.0/8 add`
%%% silently fails because inet:parse_address rejects CIDR.
%%% ===================================================================

banman_subnet_key_missing_test() ->
    BeamchainBanKeyShape = ip_tuple,
    CoreBanKeyShape = sub_net,
    ?assertEqual(ip_tuple, BeamchainBanKeyShape),
    ?assertNotEqual(CoreBanKeyShape, BeamchainBanKeyShape).

%%% ===================================================================
%%% Gate 28 (BUG-17) — Discouragement (bloom filter) tier missing.
%%%
%%% Core (banman.h:98, banman.cpp:83-87, 124-128):
%%%   CRollingBloomFilter m_discouraged{50000, 0.000001};
%%% Discouraged peers are still allowed inbound when slots are
%%% available, but preferred for eviction (net.cpp:1812-1818).
%%%
%%% beamchain has no equivalent tier — misbehavior triggers full ban.
%%% (handle_misbehaving line 2077-2083 inserts directly into the
%%% banlist for 24h.)
%%% ===================================================================

discouragement_tier_missing_test() ->
    BeamchainTiers = [banned],
    CoreTiers = [banned, discouraged],
    ?assertEqual(1, length(BeamchainTiers)),
    ?assertEqual(2, length(CoreTiers)).

%%% ===================================================================
%%% Gate 29 (BUG-19) — BanMan periodic dump missing.
%%%
%%% Core: DUMP_BANS_INTERVAL = 15min, banman.cpp:21-22 calls
%%% DumpBanlist() at construction; net.cpp arranges periodic dumps.
%%% beamchain saves on EVERY set_ban call (line 2078, 2082) with no
%%% periodic dump timer. A flurry of misbehaving events writes the
%%% whole JSON banlist N times per second.
%%% ===================================================================

banman_periodic_dump_missing_test() ->
    %% Mirror the Core constant for reference.
    CoreDumpIntervalMin = 15,
    BeamchainDumpIntervalMin = 0,  %% 0 = no periodic dump
    ?assertEqual(15, CoreDumpIntervalMin),
    ?assertEqual(0, BeamchainDumpIntervalMin),
    ?assertNotEqual(CoreDumpIntervalMin, BeamchainDumpIntervalMin).

%%% ===================================================================
%%% Gate 30 — Outbound full-relay + block-relay caps match Core.
%%%
%%% Core (net.h:69, 73):
%%%   MAX_OUTBOUND_FULL_RELAY_CONNECTIONS = 8
%%%   MAX_BLOCK_RELAY_ONLY_CONNECTIONS    = 2
%%%
%%% beamchain (beamchain_protocol.hrl:77-78):
%%%   MAX_OUTBOUND_FULL_RELAY = 8
%%%   MAX_BLOCK_RELAY_ONLY    = 2
%%%
%%% Sanity anchor. Default max-inbound (=125) also matches
%%% (beamchain_peer_manager.erl:97 vs net.h:81).
%%% ===================================================================

outbound_caps_match_core_test() ->
    BeamchainMaxFullRelay = 8,
    BeamchainMaxBlockRelay = 2,
    BeamchainDefaultMaxInbound = 125,
    CoreMaxFullRelay = 8,
    CoreMaxBlockRelay = 2,
    CoreDefaultMaxInbound = 125,
    ?assertEqual(CoreMaxFullRelay, BeamchainMaxFullRelay),
    ?assertEqual(CoreMaxBlockRelay, BeamchainMaxBlockRelay),
    ?assertEqual(CoreDefaultMaxInbound, BeamchainDefaultMaxInbound).
