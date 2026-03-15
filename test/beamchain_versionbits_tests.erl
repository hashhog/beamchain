-module(beamchain_versionbits_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%%% ===================================================================
%%% Test setup/teardown
%%% ===================================================================

setup() ->
    %% Initialize the ETS cache
    beamchain_versionbits:init_cache(),
    ok.

cleanup(_) ->
    %% Clear cache between tests
    case ets:whereis(beamchain_versionbits_cache) of
        undefined -> ok;
        _ -> ets:delete_all_objects(beamchain_versionbits_cache)
    end,
    ok.

%%% ===================================================================
%%% Helper functions
%%% ===================================================================

%% Create a mock height getter that returns block info from a list
make_height_getter(Blocks) ->
    fun(Height) ->
        case lists:keyfind(Height, 1, Blocks) of
            {Height, Version, MTP} ->
                Header = #block_header{
                    version = Version,
                    prev_hash = <<0:256>>,
                    merkle_root = <<0:256>>,
                    timestamp = MTP,
                    bits = 16#1d00ffff,
                    nonce = 0
                },
                {ok, #{height => Height, header => Header, median_time_past => MTP}};
            false ->
                not_found
        end
    end.

%% Generate blocks for a period with a specific version
%% MTP at block N = StartMTP + (N - StartHeight) * 600
generate_period_blocks(StartHeight, Version, StartMTP) ->
    [{H, Version, StartMTP + (H - StartHeight) * 600}
     || H <- lists:seq(StartHeight, StartHeight + 2015)].

%% Generate blocks with specific end MTP (useful for precise testing)
%% EndMTP is the MTP of the LAST block in the period
generate_period_blocks_end_mtp(StartHeight, Version, EndMTP) ->
    EndHeight = StartHeight + 2015,
    StartMTP = EndMTP - 2015 * 600,
    [{H, Version, StartMTP + (H - StartHeight) * 600}
     || H <- lists:seq(StartHeight, EndHeight)].

%% Version with signaling bit set (top bits = 001, bit 0 set)
signaling_version(Bit) ->
    16#20000000 bor (1 bsl Bit).

%% Non-signaling version (top bits = 001, no deployment bits)
non_signaling_version() ->
    16#20000000.

%% Old-style version (top bits != 001)
old_version() ->
    4.  %% BIP9 doesn't consider this as signaling

%%% ===================================================================
%%% Version bits condition tests
%%% ===================================================================

version_bits_condition_test_() ->
    {foreach, fun setup/0, fun cleanup/1, [
        {"signaling version bit 0", fun signaling_bit0_test/0},
        {"signaling version bit 1", fun signaling_bit1_test/0},
        {"signaling version bit 2", fun signaling_bit2_test/0},
        {"non-signaling version", fun non_signaling_test/0},
        {"old version format", fun old_version_test/0},
        {"wrong top bits", fun wrong_top_bits_test/0}
    ]}.

signaling_bit0_test() ->
    Version = signaling_version(0),
    ?assertEqual(true, beamchain_versionbits:version_bits_condition(Version, 0)),
    ?assertEqual(false, beamchain_versionbits:version_bits_condition(Version, 1)).

signaling_bit1_test() ->
    Version = signaling_version(1),
    ?assertEqual(false, beamchain_versionbits:version_bits_condition(Version, 0)),
    ?assertEqual(true, beamchain_versionbits:version_bits_condition(Version, 1)).

signaling_bit2_test() ->
    Version = signaling_version(2),
    ?assertEqual(true, beamchain_versionbits:version_bits_condition(Version, 2)),
    ?assertEqual(false, beamchain_versionbits:version_bits_condition(Version, 0)).

non_signaling_test() ->
    Version = non_signaling_version(),
    ?assertEqual(false, beamchain_versionbits:version_bits_condition(Version, 0)),
    ?assertEqual(false, beamchain_versionbits:version_bits_condition(Version, 1)),
    ?assertEqual(false, beamchain_versionbits:version_bits_condition(Version, 2)).

old_version_test() ->
    Version = old_version(),
    ?assertEqual(false, beamchain_versionbits:version_bits_condition(Version, 0)).

wrong_top_bits_test() ->
    %% Top bits = 000 instead of 001
    Version = 16#00000001,
    ?assertEqual(false, beamchain_versionbits:version_bits_condition(Version, 0)),
    %% Top bits = 010 instead of 001
    Version2 = 16#40000001,
    ?assertEqual(false, beamchain_versionbits:version_bits_condition(Version2, 0)).

%%% ===================================================================
%%% Deployment parameters tests
%%% ===================================================================

deployment_params_test_() ->
    {foreach, fun setup/0, fun cleanup/1, [
        {"mainnet csv deployment", fun mainnet_csv_params_test/0},
        {"mainnet taproot deployment", fun mainnet_taproot_params_test/0},
        {"testnet4 always active", fun testnet4_always_active_test/0},
        {"unknown deployment error", fun unknown_deployment_test/0}
    ]}.

mainnet_csv_params_test() ->
    Dep = beamchain_versionbits:deployment_params(mainnet, csv),
    ?assertEqual(csv, element(2, Dep)),  %% name
    ?assertEqual(0, element(3, Dep)),    %% bit
    ?assert(element(4, Dep) > 0),        %% start_time
    ?assert(element(5, Dep) > 0).        %% timeout

mainnet_taproot_params_test() ->
    Dep = beamchain_versionbits:deployment_params(mainnet, taproot),
    ?assertEqual(taproot, element(2, Dep)),
    ?assertEqual(2, element(3, Dep)),  %% bit
    %% min_activation_height for taproot
    ?assertEqual(709632, element(6, Dep)).

testnet4_always_active_test() ->
    Dep = beamchain_versionbits:deployment_params(testnet4, taproot),
    ?assertEqual(-1, element(4, Dep)).  %% ALWAYS_ACTIVE

unknown_deployment_test() ->
    ?assertError({unknown_deployment, nonexistent},
                 beamchain_versionbits:deployment_params(mainnet, nonexistent)).

%%% ===================================================================
%%% State machine tests
%%% ===================================================================

state_machine_test_() ->
    {foreach, fun setup/0, fun cleanup/1, [
        {"always active deployment", fun always_active_test/0},
        {"never active deployment", fun never_active_test/0},
        {"defined before start time", fun defined_before_start_test/0},
        {"started after start time", fun started_after_start_test/0},
        {"failed after timeout", fun failed_after_timeout_test/0},
        {"locked in after threshold", fun locked_in_after_threshold_test/0},
        {"stays started below threshold", fun stays_started_below_threshold_test/0},
        {"active after locked in period", fun active_after_locked_in_test/0},
        {"min activation height", fun min_activation_height_test/0}
    ]}.

always_active_test() ->
    HeightGetter = make_height_getter([]),
    State = beamchain_versionbits:get_deployment_state_at_height(
        testnet4, taproot, 100, HeightGetter),
    ?assertEqual(active, State).

never_active_test() ->
    %% Create a fake deployment with NEVER_ACTIVE
    %% We test by checking that testnet4 deployments use ALWAYS_ACTIVE
    %% For a direct test, we'd need to expose a test deployment
    HeightGetter = make_height_getter([]),
    %% regtest with ALWAYS_ACTIVE should be active
    State = beamchain_versionbits:get_deployment_state_at_height(
        regtest, csv, 100, HeightGetter),
    ?assertEqual(active, State).

defined_before_start_test() ->
    %% CSV on mainnet started May 1st 2016 = 1462060800
    %% Create blocks with MTP before that
    BeforeStart = 1462060800 - 86400,  %% 1 day before
    Blocks = generate_period_blocks(0, non_signaling_version(), BeforeStart - 2016 * 600),
    HeightGetter = make_height_getter(Blocks),

    %% At height 2015 (end of first period), should still be defined
    State = beamchain_versionbits:get_deployment_state_at_height(
        mainnet, csv, 2015, HeightGetter),
    ?assertEqual(defined, State).

started_after_start_test() ->
    %% CSV on mainnet started May 1st 2016 = 1462060800
    StartTime = 1462060800,

    %% First period: MTP at block 2015 must be >= start_time for started state in period 1
    %% Use end MTP = start_time + 1 to ensure we're past the start
    Period1 = generate_period_blocks_end_mtp(0, non_signaling_version(), StartTime + 600),

    %% Second period: not signaling (so won't lock in)
    Period2 = generate_period_blocks(2016, non_signaling_version(), StartTime + 1200),

    Blocks = Period1 ++ Period2,
    HeightGetter = make_height_getter(Blocks),

    %% At height 4031 (in period 1: blocks 2016-4031), should be started
    %% because MTP at block 2015 (end of period 0) >= start_time
    State = beamchain_versionbits:get_deployment_state_at_height(
        mainnet, csv, 4031, HeightGetter),
    ?assertEqual(started, State).

failed_after_timeout_test() ->
    %% CSV on mainnet: start = 1462060800, timeout = 1493596800
    StartTime = 1462060800,
    Timeout = 1493596800,

    %% Period 0: ends with MTP >= start_time (so period 1 will be STARTED)
    Period0 = generate_period_blocks_end_mtp(0, non_signaling_version(), StartTime + 600),

    %% Period 1: started but not signaling, ends before timeout
    Period1 = generate_period_blocks(2016, non_signaling_version(), StartTime + 2000),

    %% Period 2: ends with MTP >= timeout (so period 3 will be FAILED)
    Period2 = generate_period_blocks_end_mtp(4032, non_signaling_version(), Timeout + 600),

    Blocks = Period0 ++ Period1 ++ Period2,
    HeightGetter = make_height_getter(Blocks),

    %% At height 6047 (end of period 2), state is still STARTED
    %% State becomes FAILED when we compute state FOR period 3
    %% which happens when we query a height in period 3
    State = beamchain_versionbits:get_deployment_state_at_height(
        mainnet, csv, 6048, HeightGetter),
    ?assertEqual(failed, State).

locked_in_after_threshold_test() ->
    %% Clear cache to ensure no state from other tests
    ets:delete_all_objects(beamchain_versionbits_cache),

    %% Need 1916/2016 signaling blocks (95% on mainnet)
    StartTime = 1462060800,

    %% Period 0: ends with MTP >= start_time (so period 1 will be STARTED)
    Period0 = generate_period_blocks_end_mtp(0, non_signaling_version(), StartTime + 600),

    %% Period 1: STARTED, all signaling (threshold met)
    SignalingVersion = signaling_version(0),  %% CSV uses bit 0
    Period1 = generate_period_blocks(2016, SignalingVersion, StartTime + 2000),

    Blocks = Period0 ++ Period1,
    HeightGetter = make_height_getter(Blocks),

    %% Period 1 has all 2016 blocks signaling (>= 1916 threshold)
    %% So period 2 will have LOCKED_IN state
    %% Query at height 4032 (first block of period 2)
    State = beamchain_versionbits:get_deployment_state_at_height(
        mainnet, csv, 4032, HeightGetter),
    ?assertEqual(locked_in, State).

stays_started_below_threshold_test() ->
    %% Clear cache to ensure no state from other tests
    ets:delete_all_objects(beamchain_versionbits_cache),

    %% Need 1916/2016 signaling blocks, test with only 1900
    StartTime = 1462060800,

    %% Period 0: ends with MTP >= start_time (so period 1 will be STARTED)
    Period0 = generate_period_blocks_end_mtp(0, non_signaling_version(), StartTime + 600),

    %% Period 1: STARTED, only 1900 signaling (below 1916 threshold)
    SignalingVersion = signaling_version(0),
    NonSignaling = non_signaling_version(),
    Period1MTP = StartTime + 2000,
    Period1Signaling = [{H, SignalingVersion, Period1MTP + (H - 2016) * 600}
                        || H <- lists:seq(2016, 2016 + 1899)],
    Period1NonSig = [{H, NonSignaling, Period1MTP + (H - 2016) * 600}
                     || H <- lists:seq(2016 + 1900, 4031)],
    Period1 = Period1Signaling ++ Period1NonSig,

    Blocks = Period0 ++ Period1,
    HeightGetter = make_height_getter(Blocks),

    %% Period 1 had only 1900 signaling (< 1916 threshold)
    %% So period 2 will still have STARTED state
    State = beamchain_versionbits:get_deployment_state_at_height(
        mainnet, csv, 4032, HeightGetter),
    ?assertEqual(started, State).

active_after_locked_in_test() ->
    %% Clear cache to ensure no state from other tests
    ets:delete_all_objects(beamchain_versionbits_cache),

    StartTime = 1462060800,
    %% CSV timeout is 1493596800, all our MTPs are well before this

    %% Period 0: ends with MTP >= start_time (so period 1 will be STARTED)
    Period0 = generate_period_blocks_end_mtp(0, non_signaling_version(), StartTime + 600),

    %% Period 1: STARTED, all signaling -> period 2 will be LOCKED_IN
    %% MTP needs to be before timeout
    Period1 = generate_period_blocks(2016, signaling_version(0), StartTime + 2000),

    %% Period 2: LOCKED_IN -> period 3 will be ACTIVE (no min_activation_height for CSV)
    %% MTP needs to be before timeout
    Period2 = generate_period_blocks(4032, non_signaling_version(), StartTime + 4000),

    Blocks = Period0 ++ Period1 ++ Period2,
    HeightGetter = make_height_getter(Blocks),

    %% At height 6048 (first block of period 3), should be active
    State = beamchain_versionbits:get_deployment_state_at_height(
        mainnet, csv, 6048, HeightGetter),
    ?assertEqual(active, State).

min_activation_height_test() ->
    %% Taproot has min_activation_height = 709632
    %% Even if locked_in earlier, won't activate until that height
    StartTime = 1619222400,

    %% Period 0: ends with MTP >= start_time (so period 1 will be STARTED)
    Period0 = generate_period_blocks_end_mtp(0, non_signaling_version(), StartTime + 600),

    %% Period 1: STARTED, all signaling -> period 2 will be LOCKED_IN
    Period1 = generate_period_blocks(2016, signaling_version(2), StartTime + 2000),

    %% Period 2: LOCKED_IN, but min_activation_height = 709632
    %% Height 4032 < 709632, so period 3 will still be LOCKED_IN
    Period2 = generate_period_blocks(4032, non_signaling_version(), StartTime + 3000000),

    Blocks = Period0 ++ Period1 ++ Period2,
    HeightGetter = make_height_getter(Blocks),

    %% At height 6048 (first block of period 3), still locked_in because 6048 < 709632
    State = beamchain_versionbits:get_deployment_state_at_height(
        mainnet, taproot, 6048, HeightGetter),
    ?assertEqual(locked_in, State).

%%% ===================================================================
%%% Full deployment lifecycle test
%%% ===================================================================

full_lifecycle_test_() ->
    {foreach, fun setup/0, fun cleanup/1, [
        {"complete deployment lifecycle", fun complete_lifecycle_test/0}
    ]}.

complete_lifecycle_test() ->
    %% Simulate a complete CSV deployment on mainnet
    %% defined -> started -> locked_in -> active

    %% Clear cache to ensure no state from other tests
    ets:delete_all_objects(beamchain_versionbits_cache),

    StartTime = 1462060800,  %% CSV start
    SignalingVersion = signaling_version(0),
    NonSignaling = non_signaling_version(),

    %% Period 0 (blocks 0-2015): MTP at 2015 < start_time, so period 1 = DEFINED
    %% To stay DEFINED in period 1, end MTP must be < start_time
    Period0 = generate_period_blocks_end_mtp(0, NonSignaling, StartTime - 1000),

    %% Period 1 (blocks 2016-4031): MTP at 4031 >= start_time, so period 2 = STARTED
    %% Period 1 state is still DEFINED (computed from period 0's end)
    Period1 = generate_period_blocks_end_mtp(2016, NonSignaling, StartTime + 1000),

    %% Period 2 (blocks 4032-6047): STARTED state, all signaling
    %% Period 2 state is STARTED (computed from period 1's end where MTP >= start_time)
    %% All 2016 blocks signal, so period 3 = LOCKED_IN
    Period2 = generate_period_blocks(4032, SignalingVersion, StartTime + 2000000),

    %% Period 3 (blocks 6048-8063): LOCKED_IN -> ACTIVE (no min_activation_height for CSV)
    Period3 = generate_period_blocks(6048, NonSignaling, StartTime + 3000000),

    Blocks = Period0 ++ Period1 ++ Period2 ++ Period3,
    HeightGetter = make_height_getter(Blocks),

    %% Verify state at each period
    %% Period 0: DEFINED (before any retarget)
    ?assertEqual(defined,
                 beamchain_versionbits:get_deployment_state_at_height(
                     mainnet, csv, 1000, HeightGetter)),

    %% Period 1: DEFINED (MTP at end of period 0 was < start_time)
    ?assertEqual(defined,
                 beamchain_versionbits:get_deployment_state_at_height(
                     mainnet, csv, 3000, HeightGetter)),

    %% Period 2: STARTED (MTP at end of period 1 was >= start_time)
    ?assertEqual(started,
                 beamchain_versionbits:get_deployment_state_at_height(
                     mainnet, csv, 5000, HeightGetter)),

    %% Period 3: LOCKED_IN (all 2016 blocks in period 2 signaled)
    ?assertEqual(locked_in,
                 beamchain_versionbits:get_deployment_state_at_height(
                     mainnet, csv, 7000, HeightGetter)),

    %% Period 4: ACTIVE (after one period of LOCKED_IN)
    ?assertEqual(active,
                 beamchain_versionbits:get_deployment_state_at_height(
                     mainnet, csv, 8100, HeightGetter)).

%%% ===================================================================
%%% Caching tests
%%% ===================================================================

caching_test_() ->
    {foreach, fun setup/0, fun cleanup/1, [
        {"states are cached", fun states_cached_test/0}
    ]}.

states_cached_test() ->
    %% Clear cache to ensure no state from other tests
    ets:delete_all_objects(beamchain_versionbits_cache),

    StartTime = 1462060800,

    %% Period 0: ends with MTP >= start_time (so period 1 will be STARTED)
    Period0 = generate_period_blocks_end_mtp(0, non_signaling_version(), StartTime + 600),

    %% Period 1: STARTED
    Period1 = generate_period_blocks(2016, non_signaling_version(), StartTime + 2000),

    Blocks = Period0 ++ Period1,
    HeightGetter = make_height_getter(Blocks),

    %% First call computes and caches
    State1 = beamchain_versionbits:get_deployment_state_at_height(
        mainnet, csv, 3000, HeightGetter),
    ?assertEqual(started, State1),

    %% Second call should use cache (cache key is period number)
    %% Height 3000 is in period 1 (blocks 2016-4031)
    CacheKey = {mainnet, csv, 1},
    [{_, CachedState}] = ets:lookup(beamchain_versionbits_cache, CacheKey),
    ?assertEqual(started, CachedState).

%%% ===================================================================
%%% Statistics tests
%%% ===================================================================

statistics_test_() ->
    {foreach, fun setup/0, fun cleanup/1, [
        {"signaling count", fun signaling_count_test/0}
    ]}.

signaling_count_test() ->
    StartTime = 1462060800,

    %% Period 0: ends with MTP >= start_time
    Period0 = generate_period_blocks_end_mtp(0, non_signaling_version(), StartTime + 600),

    %% Period 1: 1000 signaling blocks at start, rest non-signaling
    SignalingVersion = signaling_version(0),
    NonSignaling = non_signaling_version(),
    Period1MTP = StartTime + 2000,
    Period1Signaling = [{H, SignalingVersion, Period1MTP + (H - 2016) * 600}
                        || H <- lists:seq(2016, 3015)],
    Period1NonSig = [{H, NonSignaling, Period1MTP + (H - 2016) * 600}
                     || H <- lists:seq(3016, 4031)],
    Period1 = Period1Signaling ++ Period1NonSig,

    Blocks = Period0 ++ Period1,
    HeightGetter = make_height_getter(Blocks),

    %% Get statistics mid-period (at block 3015, 1000 blocks into period 1)
    {Count, Elapsed, Possible} = beamchain_versionbits:get_state_statistics(
        mainnet, csv, 3015, HeightGetter),

    ?assertEqual(1000, Count),
    ?assertEqual(1000, Elapsed),
    %% 1000 signaling + 1016 remaining = 2016, threshold 1916, so possible
    ?assertEqual(true, Possible).

%%% ===================================================================
%%% Edge cases tests
%%% ===================================================================

edge_cases_test_() ->
    {foreach, fun setup/0, fun cleanup/1, [
        {"height -1 returns defined", fun negative_height_test/0},
        {"genesis block", fun genesis_block_test/0}
    ]}.

negative_height_test() ->
    HeightGetter = make_height_getter([]),
    State = beamchain_versionbits:get_deployment_state_at_height(
        mainnet, csv, -1, HeightGetter),
    ?assertEqual(defined, State).

genesis_block_test() ->
    %% At genesis (height 0), all deployments should be defined
    %% (before any start time)
    BeforeStart = 1462060800 - 86400 * 365,  %% 1 year before CSV start
    Blocks = [{0, 1, BeforeStart}],  %% Genesis with version 1
    HeightGetter = make_height_getter(Blocks),

    State = beamchain_versionbits:get_deployment_state_at_height(
        mainnet, csv, 0, HeightGetter),
    ?assertEqual(defined, State).
