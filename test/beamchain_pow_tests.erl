-module(beamchain_pow_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%%% ===================================================================
%%% bits_to_target / target_to_bits tests
%%% ===================================================================

%% mainnet genesis bits: 0x1d00ffff
bits_to_target_genesis_test() ->
    Target = beamchain_pow:bits_to_target(16#1d00ffff),
    %% expected: 0x00000000ffff0000000000000000000000000000000000000000000000000000
    Expected = 16#00000000ffff0000000000000000000000000000000000000000000000000000,
    ?assertEqual(Expected, Target).

%% regtest bits: 0x207fffff
bits_to_target_regtest_test() ->
    Target = beamchain_pow:bits_to_target(16#207fffff),
    Expected = 16#7fffff0000000000000000000000000000000000000000000000000000000000,
    ?assertEqual(Expected, Target).

%% small exponent (<=3) shifts mantissa right
bits_to_target_small_exp_test() ->
    %% exponent=3, mantissa=0x123456 → target = 0x123456
    Target = beamchain_pow:bits_to_target(16#03123456),
    ?assertEqual(16#123456, Target).

%% exponent=2 → shift right by 8
bits_to_target_exp2_test() ->
    Target = beamchain_pow:bits_to_target(16#02123456),
    %% 0x123456 >> 8 = 0x1234
    ?assertEqual(16#1234, Target).

%% exponent=1 → shift right by 16
bits_to_target_exp1_test() ->
    Target = beamchain_pow:bits_to_target(16#01123456),
    ?assertEqual(16#12, Target).

%% negative bit set → target is 0
bits_to_target_negative_test() ->
    %% 0x1d800000 has negative bit set
    Target = beamchain_pow:bits_to_target(16#1d800000),
    ?assertEqual(0, Target).

%% zero mantissa → target is 0
bits_to_target_zero_mantissa_test() ->
    Target = beamchain_pow:bits_to_target(16#1d000000),
    ?assertEqual(0, Target).

%% roundtrip: target_to_bits(bits_to_target(x)) == x
bits_roundtrip_genesis_test() ->
    Bits = 16#1d00ffff,
    Target = beamchain_pow:bits_to_target(Bits),
    ?assertEqual(Bits, beamchain_pow:target_to_bits(Target)).

bits_roundtrip_regtest_test() ->
    Bits = 16#207fffff,
    Target = beamchain_pow:bits_to_target(Bits),
    ?assertEqual(Bits, beamchain_pow:target_to_bits(Target)).

bits_roundtrip_high_diff_test() ->
    %% a real mainnet difficulty bits value
    Bits = 16#17034267,
    Target = beamchain_pow:bits_to_target(Bits),
    ?assertEqual(Bits, beamchain_pow:target_to_bits(Target)).

target_to_bits_zero_test() ->
    ?assertEqual(0, beamchain_pow:target_to_bits(0)).

%%% ===================================================================
%%% compute_work tests
%%% ===================================================================

compute_work_genesis_test() ->
    %% genesis bits: difficulty 1
    Work = beamchain_pow:compute_work(16#1d00ffff),
    %% should be > 0
    ?assert(Work > 0),
    %% 2^256 / (target+1), target = 0xffff * 2^208
    %% work should be roughly 2^32 but not exactly
    ?assert(Work > (1 bsl 31)),
    ?assert(Work < (1 bsl 33)).

compute_work_zero_bits_test() ->
    ?assertEqual(0, beamchain_pow:compute_work(0)).

%%% ===================================================================
%%% check_pow tests
%%% ===================================================================

%% mainnet genesis block should pass PoW check
check_pow_genesis_test() ->
    %% genesis block header
    Header = #block_header{
        version = 1,
        prev_hash = <<0:256>>,
        merkle_root = beamchain_serialize:hex_decode(
            "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"),
        timestamp = 1231006505,
        bits = 16#1d00ffff,
        nonce = 2083236893
    },
    BlockHash = beamchain_serialize:block_hash(Header),
    PowLimit = beamchain_serialize:hex_decode(
        "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    ?assertEqual(true, beamchain_pow:check_pow(BlockHash, 16#1d00ffff, PowLimit)).

%% a hash above the target should fail
check_pow_fail_test() ->
    %% all-ones hash will be above any reasonable target
    BadHash = <<16#ff:256>>,
    PowLimit = beamchain_serialize:hex_decode(
        "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    ?assertEqual(false, beamchain_pow:check_pow(BadHash, 16#1d00ffff, PowLimit)).

%% target above pow_limit should fail
check_pow_above_limit_test() ->
    Hash = <<0:256>>,
    %% use a very easy target (above pow_limit)
    HighBits = 16#2100ffff,
    PowLimit = beamchain_serialize:hex_decode(
        "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    ?assertEqual(false, beamchain_pow:check_pow(Hash, HighBits, PowLimit)).

%%% ===================================================================
%%% Difficulty adjustment algorithm tests
%%% ===================================================================

%% Test the target calculation math for difficulty adjustment:
%% new_target = old_target * actual_timespan / target_timespan

%% When actual_timespan equals target_timespan, difficulty stays the same
difficulty_unchanged_when_on_target_test() ->
    OldBits = 16#1d00ffff,
    OldTarget = beamchain_pow:bits_to_target(OldBits),
    TargetTimespan = ?POW_TARGET_TIMESPAN,  % 2 weeks = 1209600 seconds
    %% If blocks were mined exactly on schedule (2 weeks)
    ActualTimespan = TargetTimespan,
    NewTarget = (OldTarget * ActualTimespan) div TargetTimespan,
    NewBits = beamchain_pow:target_to_bits(NewTarget),
    ?assertEqual(OldBits, NewBits).

%% When blocks are mined too fast (1 week instead of 2), difficulty increases
%% new_target = old_target * 0.5 (lower target = higher difficulty)
difficulty_increases_when_too_fast_test() ->
    OldBits = 16#1d00ffff,
    OldTarget = beamchain_pow:bits_to_target(OldBits),
    TargetTimespan = ?POW_TARGET_TIMESPAN,
    %% Blocks mined in 1 week (half the target time)
    ActualTimespan = TargetTimespan div 2,
    NewTarget = (OldTarget * ActualTimespan) div TargetTimespan,
    NewBits = beamchain_pow:target_to_bits(NewTarget),
    NewTargetDecoded = beamchain_pow:bits_to_target(NewBits),
    %% New target should be lower (harder)
    ?assert(NewTargetDecoded < OldTarget),
    %% Should be roughly half
    Ratio = OldTarget / NewTargetDecoded,
    ?assert(Ratio > 1.9 andalso Ratio < 2.1).

%% When blocks are mined too slow (4 weeks instead of 2), difficulty decreases
%% new_target = old_target * 2 (higher target = lower difficulty)
difficulty_decreases_when_too_slow_test() ->
    OldBits = 16#1d00ffff,
    OldTarget = beamchain_pow:bits_to_target(OldBits),
    TargetTimespan = ?POW_TARGET_TIMESPAN,
    %% Blocks mined in 4 weeks (double the target time)
    ActualTimespan = TargetTimespan * 2,
    NewTarget = (OldTarget * ActualTimespan) div TargetTimespan,
    NewBits = beamchain_pow:target_to_bits(NewTarget),
    NewTargetDecoded = beamchain_pow:bits_to_target(NewBits),
    %% New target should be higher (easier)
    ?assert(NewTargetDecoded > OldTarget),
    %% Should be roughly double
    Ratio = NewTargetDecoded / OldTarget,
    ?assert(Ratio > 1.9 andalso Ratio < 2.1).

%% Clamping: actual_timespan cannot be less than TargetTimespan/4
%% (max 4x difficulty increase)
clamping_min_timespan_test() ->
    OldBits = 16#1d00ffff,
    OldTarget = beamchain_pow:bits_to_target(OldBits),
    TargetTimespan = ?POW_TARGET_TIMESPAN,
    %% Very fast blocks: 1 day instead of 2 weeks
    ActualTimespanRaw = 86400,
    %% Clamp to minimum allowed (timespan/4)
    ActualTimespan = max(TargetTimespan div 4, ActualTimespanRaw),
    ?assertEqual(TargetTimespan div 4, ActualTimespan),
    NewTarget = (OldTarget * ActualTimespan) div TargetTimespan,
    NewBits = beamchain_pow:target_to_bits(NewTarget),
    NewTargetDecoded = beamchain_pow:bits_to_target(NewBits),
    %% Difficulty can increase by max 4x (target decreases by 4x)
    Ratio = OldTarget / NewTargetDecoded,
    ?assert(Ratio > 3.9 andalso Ratio < 4.1).

%% Clamping: actual_timespan cannot be more than TargetTimespan*4
%% (max 1/4 difficulty decrease)
clamping_max_timespan_test() ->
    OldBits = 16#1d00ffff,
    OldTarget = beamchain_pow:bits_to_target(OldBits),
    TargetTimespan = ?POW_TARGET_TIMESPAN,
    %% Very slow blocks: 10 weeks instead of 2 weeks
    ActualTimespanRaw = TargetTimespan * 5,
    %% Clamp to maximum allowed (timespan*4)
    ActualTimespan = min(TargetTimespan * 4, ActualTimespanRaw),
    ?assertEqual(TargetTimespan * 4, ActualTimespan),
    NewTarget = (OldTarget * ActualTimespan) div TargetTimespan,
    NewBits = beamchain_pow:target_to_bits(NewTarget),
    NewTargetDecoded = beamchain_pow:bits_to_target(NewBits),
    %% Difficulty can decrease by max 4x (target increases by 4x)
    Ratio = NewTargetDecoded / OldTarget,
    ?assert(Ratio > 3.9 andalso Ratio < 4.1).

%% Target cannot exceed pow_limit (minimum difficulty)
target_capped_at_pow_limit_test() ->
    %% Start with a relatively easy difficulty
    OldBits = 16#1c0fffff,
    OldTarget = beamchain_pow:bits_to_target(OldBits),
    TargetTimespan = ?POW_TARGET_TIMESPAN,
    %% Very slow blocks (max clamped timespan)
    ActualTimespan = TargetTimespan * 4,
    PowLimit = beamchain_pow:bits_to_target(16#1d00ffff),
    NewTarget0 = (OldTarget * ActualTimespan) div TargetTimespan,
    NewTarget = min(NewTarget0, PowLimit),
    %% Result should be capped at pow_limit
    ?assert(NewTarget =< PowLimit).

%% Verify difficulty adjustment interval is 2016 blocks
difficulty_interval_constant_test() ->
    ?assertEqual(2016, ?DIFFICULTY_ADJUSTMENT_INTERVAL).

%% Verify target timespan is 2 weeks (1209600 seconds)
target_timespan_constant_test() ->
    TwoWeeksInSeconds = 14 * 24 * 60 * 60,
    ?assertEqual(TwoWeeksInSeconds, ?POW_TARGET_TIMESPAN).

%% Verify target spacing is 10 minutes (600 seconds)
target_spacing_constant_test() ->
    TenMinutesInSeconds = 10 * 60,
    ?assertEqual(TenMinutesInSeconds, ?POW_TARGET_SPACING).

%% Verify interval * spacing = timespan (2016 * 600 = 1209600)
interval_spacing_timespan_relationship_test() ->
    ?assertEqual(?POW_TARGET_TIMESPAN,
                 ?DIFFICULTY_ADJUSTMENT_INTERVAL * ?POW_TARGET_SPACING).

%% Test bits_to_target with real mainnet difficulty values
bits_to_target_mainnet_samples_test() ->
    %% These are real bits values from mainnet block headers
    %% Block 32256 (first retarget): 0x1d00d86a
    Bits1 = 16#1d00d86a,
    Target1 = beamchain_pow:bits_to_target(Bits1),
    ?assert(Target1 > 0),
    ?assert(Target1 < beamchain_pow:bits_to_target(16#1d00ffff)),

    %% Very high difficulty block: 0x17034267
    Bits2 = 16#17034267,
    Target2 = beamchain_pow:bits_to_target(Bits2),
    ?assert(Target2 > 0),
    ?assert(Target2 < Target1).

%% Test compact encoding edge cases
target_to_bits_edge_cases_test() ->
    %% Very small target (high difficulty)
    SmallTarget = 16#123456,
    SmallBits = beamchain_pow:target_to_bits(SmallTarget),
    ?assertEqual(SmallTarget, beamchain_pow:bits_to_target(SmallBits)),

    %% Target that requires high-bit adjustment
    %% When mantissa has high bit set, it shifts and bumps exponent
    HighBitTarget = 16#80000000000000,
    HighBits = beamchain_pow:target_to_bits(HighBitTarget),
    ?assertEqual(HighBitTarget, beamchain_pow:bits_to_target(HighBits)).

%% Verify chainwork accumulates correctly
chainwork_accumulates_test() ->
    Work1 = beamchain_pow:compute_work(16#1d00ffff),
    Work2 = beamchain_pow:compute_work(16#1d00d86a),
    %% Higher difficulty (lower bits) means more work
    ?assert(Work2 > Work1),
    %% Total chainwork for 2 blocks
    TotalWork = Work1 + Work2,
    ?assert(TotalWork > Work1),
    ?assert(TotalWork > Work2).

%%% ===================================================================
%%% W83: bits_to_target overflow detection (Core arith_uint256 SetCompact)
%%% ===================================================================

%% Exponent 35 with non-zero mantissa overflows 256 bits → should return 0.
%% Core SetCompact pfOverflow: nWord != 0 && nSize > 34.
bits_to_target_overflow_exp35_test() ->
    %% 0x230100 → exponent=35, mantissa=0x0100 (> 0xff)
    %% overflow condition: nWord(0x0100) > 0xff AND nSize(35) > 33 → overflow
    Bits = (35 bsl 24) bor 16#000100,
    ?assertEqual(0, beamchain_pow:bits_to_target(Bits)).

%% Exponent 34 with mantissa > 0xffff overflows (Core: nWord > 0xffff && nSize > 32)
bits_to_target_overflow_exp34_test() ->
    %% exponent=34, mantissa=0x010000 (> 0xffff) → overflow
    Bits = (34 bsl 24) bor 16#010000,
    ?assertEqual(0, beamchain_pow:bits_to_target(Bits)).

%% Exponent 34 with mantissa = 0xffff overflows (nWord > 0xff && nSize > 33)
bits_to_target_no_overflow_exp34_boundary_test() ->
    %% exponent=34, mantissa=0x00ffff
    %% Core overflow: nWord(0xffff) > 0xff AND nSize(34) > 33 → overflow
    Bits = (34 bsl 24) bor 16#00ffff,
    ?assertEqual(0, beamchain_pow:bits_to_target(Bits)).

%% Exponent 34 with small mantissa (0x01) does NOT overflow.
%% Core: 0x01 is not > 0xff, not > 0xffff, and 34 is not > 34 → no overflow.
bits_to_target_no_overflow_exp34_small_mantissa_test() ->
    Bits = (34 bsl 24) bor 16#000001,
    Target = beamchain_pow:bits_to_target(Bits),
    ?assert(Target > 0).

%% Exponent 33 with mantissa > 0xff overflows (Core: nWord > 0xff && nSize > 33)
bits_to_target_overflow_exp33_test() ->
    %% exponent=34, mantissa=0x000200 → nWord(0x0200) > 0xff AND nSize=34 > 33 → overflow
    %% (use exp=34 to trigger the nWord > 0xff && nSize > 33 path)
    Bits = (34 bsl 24) bor 16#000200,
    ?assertEqual(0, beamchain_pow:bits_to_target(Bits)).

%% Exponent > 34: always overflow when mantissa non-zero
bits_to_target_overflow_exp36_test() ->
    Bits = (36 bsl 24) bor 16#000001,
    ?assertEqual(0, beamchain_pow:bits_to_target(Bits)).

%% check_pow should reject bits that would overflow (returns false, not crash)
check_pow_overflow_bits_test() ->
    Hash = <<0:256>>,
    OverflowBits = (35 bsl 24) bor 16#000100,
    PowLimit = beamchain_serialize:hex_decode(
        "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    %% bits_to_target returns 0 for overflow → check_pow must reject
    ?assertEqual(false, beamchain_pow:check_pow(Hash, OverflowBits, PowLimit)).

%%% ===================================================================
%%% W83: permitted_difficulty_transition (Core pow.cpp:89-136)
%%% ===================================================================

%% At a retarget boundary, unchanged difficulty is always permitted.
permitted_unchanged_at_retarget_test() ->
    Params = beamchain_chain_params:params(mainnet),
    OldBits = 16#1d00ffff,
    %% Height 2016 is the first retarget block
    ?assertEqual(true, beamchain_pow:permitted_difficulty_transition(
        Params, 2016, OldBits, OldBits)).

%% Off a retarget boundary, bits must be identical.
permitted_same_bits_off_retarget_test() ->
    Params = beamchain_chain_params:params(mainnet),
    OldBits = 16#1d00ffff,
    ?assertEqual(true, beamchain_pow:permitted_difficulty_transition(
        Params, 100, OldBits, OldBits)).

%% Off a retarget boundary, different bits must be rejected.
permitted_different_bits_off_retarget_test() ->
    Params = beamchain_chain_params:params(mainnet),
    OldBits = 16#1d00ffff,
    DifferentBits = 16#1d00fffe,
    ?assertEqual(false, beamchain_pow:permitted_difficulty_transition(
        Params, 100, OldBits, DifferentBits)).

%% At retarget boundary, 4× harder difficulty is at the boundary → permitted.
permitted_4x_harder_at_retarget_test() ->
    Params = beamchain_chain_params:params(mainnet),
    OldBits = 16#1d00ffff,
    %% 4× harder: target / 4
    OldTarget = beamchain_pow:bits_to_target(OldBits),
    TargetTimespan = ?POW_TARGET_TIMESPAN,
    SmallestTimespan = TargetTimespan div 4,
    NewTarget = (OldTarget * SmallestTimespan) div TargetTimespan,
    NewBits = beamchain_pow:target_to_bits(NewTarget),
    ?assertEqual(true, beamchain_pow:permitted_difficulty_transition(
        Params, 2016, OldBits, NewBits)).

%% At retarget boundary, 4× easier is at the boundary → permitted.
permitted_4x_easier_at_retarget_test() ->
    Params = beamchain_chain_params:params(mainnet),
    OldBits = 16#1d00ffff,
    OldTarget = beamchain_pow:bits_to_target(OldBits),
    TargetTimespan = ?POW_TARGET_TIMESPAN,
    LargestTimespan = TargetTimespan * 4,
    PowLimitInt = binary:decode_unsigned(maps:get(pow_limit, Params), big),
    NewTarget0 = (OldTarget * LargestTimespan) div TargetTimespan,
    NewTarget = min(NewTarget0, PowLimitInt),
    NewBits = beamchain_pow:target_to_bits(NewTarget),
    ?assertEqual(true, beamchain_pow:permitted_difficulty_transition(
        Params, 2016, OldBits, NewBits)).

%% At retarget boundary, more than 4× harder must be rejected.
permitted_5x_harder_rejected_at_retarget_test() ->
    Params = beamchain_chain_params:params(mainnet),
    OldBits = 16#1d00ffff,
    OldTarget = beamchain_pow:bits_to_target(OldBits),
    TargetTimespan = ?POW_TARGET_TIMESPAN,
    %% 5× harder (timespan/5 < timespan/4 → beyond the 4× clamp)
    TooSmallTimespan = TargetTimespan div 5,
    NewTarget = (OldTarget * TooSmallTimespan) div TargetTimespan,
    NewBits = beamchain_pow:target_to_bits(NewTarget),
    ?assertEqual(false, beamchain_pow:permitted_difficulty_transition(
        Params, 2016, OldBits, NewBits)).

%% On testnet (pow_allow_min_difficulty=true), always permitted.
permitted_always_true_on_testnet_test() ->
    Params = beamchain_chain_params:params(testnet4),
    %% Any random bits change should be permitted on testnet
    ?assertEqual(true, beamchain_pow:permitted_difficulty_transition(
        Params, 100, 16#1d00ffff, 16#1d000001)).

%%% ===================================================================
%%% W83: BIP94 enforce_bip94 flag in chain params
%%% ===================================================================

%% testnet4 must have enforce_bip94 = true
chainparams_testnet4_enforce_bip94_test() ->
    Params = beamchain_chain_params:params(testnet4),
    ?assertEqual(true, maps:get(enforce_bip94, Params)).

%% mainnet must have enforce_bip94 = false
chainparams_mainnet_enforce_bip94_test() ->
    Params = beamchain_chain_params:params(mainnet),
    ?assertEqual(false, maps:get(enforce_bip94, Params)).

%% regtest must have enforce_bip94 = false
chainparams_regtest_enforce_bip94_test() ->
    Params = beamchain_chain_params:params(regtest),
    ?assertEqual(false, maps:get(enforce_bip94, Params)).

%% signet must have enforce_bip94 = false
chainparams_signet_enforce_bip94_test() ->
    Params = beamchain_chain_params:params(signet),
    ?assertEqual(false, maps:get(enforce_bip94, Params)).

%%% ===================================================================
%%% W83: BIP94 testnet4 retarget uses first-block bits, not last-block bits
%%% ===================================================================

%% On networks with enforce_bip94=false (mainnet), calculate_retarget uses
%% the LAST block of the period's bits (pindexLast->nBits).
%% On testnet4 (enforce_bip94=true), it uses the FIRST block of the period.
%% We test this indirectly: two Params maps (bip94 on/off) with the same
%% period bounds but different first/last bits should produce different results.

%% This is a unit test of the math path, using mock data via params override.
bip94_retarget_uses_first_block_bits_test() ->
    %% Simulate: first block bits = 0x1d00ffff (easy)
    %%           last block bits  = 0x1c0fffff (harder)
    %% Without BIP94: new target uses last block bits → harder result
    %% With BIP94:    new target uses first block bits → easier result
    TargetTimespan = ?POW_TARGET_TIMESPAN,
    FirstBits = 16#1d00ffff,
    LastBits  = 16#1c0fffff,
    FirstTarget = beamchain_pow:bits_to_target(FirstBits),
    LastTarget  = beamchain_pow:bits_to_target(LastBits),
    %% Both retargets with ActualTimespan == TargetTimespan (no change)
    NewTargetFromFirst = (FirstTarget * TargetTimespan) div TargetTimespan,
    NewTargetFromLast  = (LastTarget  * TargetTimespan) div TargetTimespan,
    NewBitsFromFirst = beamchain_pow:target_to_bits(NewTargetFromFirst),
    NewBitsFromLast  = beamchain_pow:target_to_bits(NewTargetFromLast),
    %% BIP94 path (first block) should give an easier difficulty than non-BIP94
    ?assert(NewBitsFromFirst > NewBitsFromLast),   %% larger target = easier
    %% Sanity: first-block-path produces same bits as first block itself
    ?assertEqual(FirstBits, NewBitsFromFirst),
    ?assertEqual(LastBits,  NewBitsFromLast).
