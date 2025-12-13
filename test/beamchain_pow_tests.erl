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
