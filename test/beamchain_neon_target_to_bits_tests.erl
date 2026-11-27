-module(beamchain_neon_target_to_bits_tests).

%% Finding 10 of the Gemini (Neon) audit of beamchain against Bitcoin Core
%% v31.1 (item verify-neon-beamchain-findings): target_to_bits/1 must be
%% Core's arith_uint256::GetCompact (arith_uint256.cpp). For a target that
%% fits in nSize <= 3 bytes Core LEFT-shifts it into the 3-byte mantissa:
%%   nCompact = GetLow64() << 8 * (3 - nSize)
%% then moves a set 0x00800000 bit into the exponent. Expected values below
%% are what GetCompact returns (worked by hand from that code, and
%% cross-checked by the round trip through SetCompact = bits_to_target/1).

-include_lib("eunit/include/eunit.hrl").

core_compact_small_targets_test_() ->
    Cases = [
        {1,        16#01010000},
        {16#7f,    16#017f0000},
        {16#80,    16#02008000},
        {16#ff,    16#0200ff00},
        {16#1234,  16#02123400},
        {16#8000,  16#03008000},
        {16#ffff,  16#0300ffff}
    ],
    [{integer_to_list(T, 16),
      ?_assertEqual(Bits, beamchain_pow:target_to_bits(T))}
     || {T, Bits} <- Cases].

%% GetCompact's result decodes back to the same target for every target
%% below 2^24 whose significant bits fit in 23 bits of mantissa: Core's
%% SetCompact(GetCompact(x)) == x there.
small_target_round_trip_test() ->
    Targets = [1, 2, 16#7f, 16#80, 16#ff, 16#100, 16#1234, 16#7fff, 16#8000,
               16#ffff, 16#10000, 16#7fffff],
    [?assertEqual(T, beamchain_pow:bits_to_target(beamchain_pow:target_to_bits(T)))
     || T <- Targets].

%% Controls: targets of 3 or more bytes were already right.
control_large_targets_test() ->
    ?assertEqual(16#1d00ffff,
                 beamchain_pow:target_to_bits(16#ffff bsl 208)),
    ?assertEqual(16#207fffff,
                 beamchain_pow:target_to_bits(16#7fffff bsl 232)),
    ?assertEqual(16#04008000, beamchain_pow:target_to_bits(16#800000)),
    ?assertEqual(16#03123456, beamchain_pow:target_to_bits(16#123456)),
    ?assertEqual(0, beamchain_pow:target_to_bits(0)).
