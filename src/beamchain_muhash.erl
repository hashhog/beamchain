-module(beamchain_muhash).

%% MuHash3072 incremental, set-membership-agnostic hash.
%%
%% Mirrors bitcoin-core/src/crypto/muhash.{h,cpp}. The internal accumulator is
%% a pair (numerator, denominator) of integers modulo
%%   p = 2^3072 - 1103717   (the largest 3072-bit safe prime)
%% so that adding an element x multiplies the numerator by ToNum3072(x) and
%% removing an element divides — implemented by multiplying the *denominator*
%% by ToNum3072(x). Finalize collapses the fraction with one modular inverse
%% and produces SHA256(LE384(numerator * denominator^-1 mod p)).
%%
%% ToNum3072(in):
%%   1. h = SHA256(in)                            (32 bytes, used as ChaCha20 key)
%%   2. ks = ChaCha20-keystream(key=h, nonce=0,   (384 bytes)
%%                              block_counter=0)
%%   3. interpret ks as a little-endian 3072-bit integer.
%%
%% Erlang has arbitrary-precision integers built-in, so we don't need limb
%% arithmetic — we just use `rem` against the modulus and Fermat's little
%% theorem (or a recursive extended Euclid) for the inverse. The on-disk /
%% on-wire representation that Core serializes (48 LE64 limbs each for
%% numerator and denominator) is irrelevant here: we only ever need to feed
%% Finalize() output back to consumers.
%%
%% Public API:
%%   new/0                  -> empty accumulator
%%   new/1                  -> singleton accumulator constructed from one
%%                             element (matches Core's MuHash3072(span<byte>)
%%                             constructor).
%%   add/2  (Bytes, Acc)    -> Insert: numerator *= ToNum3072(Bytes)
%%   remove/2 (Bytes, Acc)  -> Remove: denominator *= ToNum3072(Bytes)
%%   combine/2              -> multiply two accumulators (parallel reduce)
%%   finalize/1             -> 32-byte SHA256 digest of the collapsed value.
%%
%% Test vectors (from bitcoin-core/src/test/crypto_tests.cpp muhash_tests):
%%   FromInt(0) *= FromInt(1) /= FromInt(2)
%%     -> 10d312b100cbd32ada024a6646e40d3482fcff103668d2625f10002a607d5863

-export([new/0, new/1,
         add/2, remove/2,
         combine/2,
         finalize/1,
         %% Lower-level helpers exposed for tests.
         to_num3072/1,
         num3072_to_bytes/1,
         bytes_to_num3072/1,
         modulus/0,
         mod_mul/2,
         mod_inv/1]).

-export_type([muhash/0]).

-record(muhash, {
    %% Both fields are integers in [0, p-1].
    num = 1 :: non_neg_integer(),
    den = 1 :: non_neg_integer()
}).

-opaque muhash() :: #muhash{}.

%% Modulus: 2^3072 - 1103717 (the largest 3072-bit safe prime). Erlang
%% bignums let us write this directly without a 768-hex-digit literal.
-define(P, ((1 bsl 3072) - 1103717)).
-define(BYTE_SIZE, 384).

%%% ===================================================================
%%% Public API
%%% ===================================================================

-spec new() -> muhash().
new() ->
    #muhash{num = 1, den = 1}.

-spec new(binary()) -> muhash().
new(Bytes) when is_binary(Bytes) ->
    #muhash{num = to_num3072(Bytes), den = 1}.

-spec add(binary(), muhash()) -> muhash().
add(Bytes, #muhash{num = N, den = D}) when is_binary(Bytes) ->
    M = to_num3072(Bytes),
    #muhash{num = mod_mul(N, M), den = D}.

-spec remove(binary(), muhash()) -> muhash().
remove(Bytes, #muhash{num = N, den = D}) when is_binary(Bytes) ->
    M = to_num3072(Bytes),
    #muhash{num = N, den = mod_mul(D, M)}.

-spec combine(muhash(), muhash()) -> muhash().
combine(#muhash{num = N1, den = D1}, #muhash{num = N2, den = D2}) ->
    #muhash{num = mod_mul(N1, N2), den = mod_mul(D1, D2)}.

%% @doc Finalize and return SHA256 of the collapsed value as 32-byte binary.
-spec finalize(muhash()) -> binary().
finalize(#muhash{num = N, den = D}) ->
    Combined =
        case D of
            1 -> N rem ?P;
            _ -> mod_mul(N, mod_inv(D))
        end,
    Bytes = num3072_to_bytes(Combined),
    crypto:hash(sha256, Bytes).

%%% ===================================================================
%%% ToNum3072: SHA256 -> ChaCha20 keystream(384) -> LE integer
%%% ===================================================================

%% @doc Hash `In` to a 3072-bit integer, identical to Core's
%% MuHash3072::ToNum3072. Result is in [0, 2^3072-1] (i.e. NOT yet reduced
%% modulo p — Core's mul/div reduce on the fly; we reduce here so all later
%% arithmetic is straight modular).
-spec to_num3072(binary()) -> non_neg_integer().
to_num3072(In) when is_binary(In) ->
    Key = crypto:hash(sha256, In),
    %% ChaCha20 with all-zero 12-byte nonce and block counter 0; the Erlang
    %% crypto:crypto_one_time/5 chacha20 cipher takes a 16-byte IV laid out
    %% as <<BlockCounter:32/little, Nonce:12/binary>>.
    IV = <<0:128>>,
    Plaintext = <<0:(?BYTE_SIZE * 8)>>,
    Keystream = crypto:crypto_one_time(chacha20, Key, IV, Plaintext, true),
    bytes_to_num3072(Keystream) rem ?P.

%% @doc Convert a 3072-bit non-negative integer to its little-endian
%% 384-byte representation, matching Num3072::ToBytes (LE limbs, equivalent
%% to LE bytes of the integer).
-spec num3072_to_bytes(non_neg_integer()) -> binary().
num3072_to_bytes(N) when is_integer(N), N >= 0 ->
    <<N:(?BYTE_SIZE * 8)/little>>.

%% @doc Inverse of num3072_to_bytes/1.
-spec bytes_to_num3072(binary()) -> non_neg_integer().
bytes_to_num3072(<<N:(?BYTE_SIZE * 8)/little>>) ->
    N.

-spec modulus() -> non_neg_integer().
modulus() ->
    ?P.

%%% ===================================================================
%%% Modular arithmetic on the 3072-bit prime
%%% ===================================================================

-spec mod_mul(non_neg_integer(), non_neg_integer()) -> non_neg_integer().
mod_mul(A, B) ->
    (A * B) rem ?P.

%% @doc Modular inverse via the extended Euclidean algorithm. p is prime so
%% every non-zero element has an inverse. Erlang bignums handle the 3072-bit
%% arithmetic natively.
-spec mod_inv(non_neg_integer()) -> non_neg_integer().
mod_inv(A) when is_integer(A), A > 0 ->
    A1 = A rem ?P,
    case A1 of
        0 -> erlang:error(badarg, [A]);
        _ ->
            {G, X, _Y} = ext_gcd(A1, ?P),
            case G of
                1 -> ((X rem ?P) + ?P) rem ?P;
                _ -> erlang:error({not_coprime, G})
            end
    end.

%% Iterative extended Euclidean — returns {gcd, x, y} such that a*x + b*y = gcd.
-spec ext_gcd(integer(), integer()) -> {integer(), integer(), integer()}.
ext_gcd(A, B) ->
    ext_gcd(A, B, 1, 0, 0, 1).

ext_gcd(A, 0, X, _X1, Y, _Y1) ->
    {A, X, Y};
ext_gcd(A, B, X, X1, Y, Y1) ->
    Q = A div B,
    ext_gcd(B, A - Q * B, X1, X - Q * X1, Y1, Y - Q * Y1).
