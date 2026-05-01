-module(beamchain_muhash_tests).

-include_lib("eunit/include/eunit.hrl").

%% Test vectors taken directly from
%% bitcoin-core/src/test/crypto_tests.cpp::muhash_tests, plus a few
%% algebraic invariants that fall out of the MuHash construction.

-define(BYTE_SIZE, 384).

%%% -------------------------------------------------------------------
%%% Helpers
%%% -------------------------------------------------------------------

%% FromInt(i): Core constructs a MuHash3072 from the 32-byte input
%% <<i, 0:248>>. The Erlang equivalent is beamchain_muhash:new(<<i, 0:248>>).
from_int(I) when is_integer(I), I >= 0, I =< 255 ->
    beamchain_muhash:new(<<I, 0:248>>).

%% Lowercase hex string -> binary.
unhex(Hex) ->
    Bytes = [list_to_integer([A, B], 16)
             || <<A:8, B:8>> <= list_to_binary(Hex)],
    list_to_binary(Bytes).

%% bin -> lowercase hex string for prettier diffs.
hex(Bin) ->
    lists:flatten([io_lib:format("~2.16.0b", [B]) || <<B>> <= Bin]).

%%% ===================================================================
%%% Modulus / arithmetic spot checks
%%% ===================================================================

modulus_value_test() ->
    P = beamchain_muhash:modulus(),
    %% 2^3072 - 1103717 has bit_length 3072 (top bit set).
    ?assertEqual(3072, bit_size_of(P)),
    %% Lowest 64 bits: 2^64 - 1103717 = 0xFFFFFFFFFFEF289B.
    ?assertEqual(16#FFFFFFFFFFEF289B, P band 16#FFFFFFFFFFFFFFFF).

%% Tiny extended-Euclid sanity: gcd(7, P) = 1, and 7 * inv(7) mod P == 1.
mod_inv_basic_test() ->
    P = beamchain_muhash:modulus(),
    Inv7 = beamchain_muhash:mod_inv(7),
    ?assert(Inv7 > 0 andalso Inv7 < P),
    ?assertEqual(1, (7 * Inv7) rem P),
    %% Inverse of 1 is 1.
    ?assertEqual(1, beamchain_muhash:mod_inv(1)),
    %% Inverse of (P-1) is (P-1) (since (P-1)^2 = 1 mod P).
    ?assertEqual(P - 1, beamchain_muhash:mod_inv(P - 1)).

%%% ===================================================================
%%% ToNum3072 byte-roundtrip
%%% ===================================================================

bytes_roundtrip_test() ->
    %% Pick a value below P, round-trip via num3072_to_bytes / bytes_to_num3072.
    N = 16#deadbeef_cafebabe_0123456789abcdef,
    Bin = beamchain_muhash:num3072_to_bytes(N),
    ?assertEqual(?BYTE_SIZE, byte_size(Bin)),
    ?assertEqual(N, beamchain_muhash:bytes_to_num3072(Bin)).

%%% ===================================================================
%%% Algebraic invariants (Core lines 1205..1243 of crypto_tests.cpp)
%%% ===================================================================

%% Order-independent reduce: applying the same ops in any of 4 permutations
%% produces the same final hash.
order_independence_test() ->
    Ops = [{mul, 1}, {mul, 2}, {div_, 3}, {mul, 0}],
    Hashes = [reduce_ops(P) || P <- permutations(Ops)],
    [H0 | Rest] = Hashes,
    [?assertEqual(H0, H) || H <- Rest],
    ok.

%% Insert(x); Remove(x) is the identity. (Stronger version of Core's
%% z*=x; z*=y; y*=x; z/=y; Finalize == empty.Finalize invariant — the
%% Core test exercises divide; we exercise add+remove which is the same
%% modular operation expressed via the denominator.)
insert_remove_is_identity_test() ->
    Acc0 = beamchain_muhash:new(),
    Acc1 = beamchain_muhash:add(<<7, 0:248>>, Acc0),
    Acc2 = beamchain_muhash:add(<<13, 0:248>>, Acc1),
    Acc3 = beamchain_muhash:remove(<<7, 0:248>>, Acc2),
    Acc4 = beamchain_muhash:remove(<<13, 0:248>>, Acc3),
    Empty = beamchain_muhash:new(),
    ?assertEqual(beamchain_muhash:finalize(Empty),
                 beamchain_muhash:finalize(Acc4)).

%%% ===================================================================
%%% Concrete vectors from Core
%%% ===================================================================

%% Core line 1245-1249 (BOOST_AUTO_TEST_CASE muhash_tests):
%%   MuHash3072 acc = FromInt(0);
%%   acc *= FromInt(1);
%%   acc /= FromInt(2);
%%   acc.Finalize(out);
%%   BOOST_CHECK_EQUAL(out, uint256{
%%     "10d312b100cbd32ada024a6646e40d3482fcff103668d2625f10002a607d5863"});
%%
%% This is the canonical end-to-end test vector for MuHash3072. It exercises
%% (1) ChaCha20 keystream expansion of SHA256 hashes, (2) modular
%% multiplication mod 2^3072 - 1103717, (3) modular inverse via Finalize,
%% and (4) SHA256 of the LE 384-byte serialization. If this passes, we
%% match Core bit-for-bit.
core_vector_finalize_test() ->
    Acc0 = from_int(0),
    %% acc *= FromInt(1) — Core multiplies the *numerator* by ToNum3072(<<1, 0:248>>),
    %% which is exactly add(<<1, 0:248>>).
    Acc1 = beamchain_muhash:add(<<1, 0:248>>, Acc0),
    %% acc /= FromInt(2) — Core multiplies the *denominator* by ToNum3072(<<2, 0:248>>),
    %% which is exactly remove(<<2, 0:248>>).
    Acc2 = beamchain_muhash:remove(<<2, 0:248>>, Acc1),
    Got = beamchain_muhash:finalize(Acc2),
    %% Core's `uint256{"<hex>"}` literal stores the displayed hex in reverse
    %% byte order — see uint256.h::base_blob::SetHexDeprecated. The raw
    %% SHA256 we return matches reverse(parse_hex(display)). To compare
    %% against the displayed Core literal, reverse the bytes here:
    Display = "10d312b100cbd32ada024a6646e40d3482fcff103668d2625f10002a607d5863",
    Expected = reverse_bytes(unhex(Display)),
    ?assertEqual(hex(Expected), hex(Got)).

%%% ===================================================================
%%% ToNum3072 ChaCha20-keystream sanity
%%% ===================================================================

%% to_num3072(<<>>) shouldn't crash and should give a value < P.
to_num3072_empty_test() ->
    N = beamchain_muhash:to_num3072(<<>>),
    P = beamchain_muhash:modulus(),
    ?assert(N >= 0 andalso N < P).

to_num3072_distinct_inputs_test() ->
    %% Different inputs should hash to different limbs (overwhelming probability).
    Na = beamchain_muhash:to_num3072(<<"a">>),
    Nb = beamchain_muhash:to_num3072(<<"b">>),
    ?assertNotEqual(Na, Nb).

%%% ===================================================================
%%% Internal helpers
%%% ===================================================================

reduce_ops(Ops) ->
    Acc = lists:foldl(
        fun({mul, I}, A) -> beamchain_muhash:add(<<I, 0:248>>, A);
           ({div_, I}, A) -> beamchain_muhash:remove(<<I, 0:248>>, A)
        end,
        beamchain_muhash:new(), Ops),
    beamchain_muhash:finalize(Acc).

permutations([]) -> [[]];
permutations(L) ->
    [[H | T] || H <- L, T <- permutations(L -- [H])].

bit_size_of(0) -> 0;
bit_size_of(N) when N > 0 -> bit_size_of(N, 0).

bit_size_of(0, Acc) -> Acc;
bit_size_of(N, Acc) -> bit_size_of(N bsr 1, Acc + 1).

reverse_bytes(Bin) when is_binary(Bin) ->
    list_to_binary(lists:reverse(binary_to_list(Bin))).
