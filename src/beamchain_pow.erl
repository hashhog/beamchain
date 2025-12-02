-module(beamchain_pow).

%% Proof of work: target/bits conversion, PoW checking, chainwork.

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-export([bits_to_target/1, target_to_bits/1]).
-export([check_pow/3, compute_work/1]).

%%% -------------------------------------------------------------------
%%% Compact bits <-> 256-bit target conversion
%%% -------------------------------------------------------------------

%% @doc Convert compact "bits" representation to a 256-bit target.
%% Format: 0xAABBBBBB where AA = exponent, BBBBBB = mantissa.
%% target = mantissa * 2^(8 * (exponent - 3))
%% Negative targets (high bit of mantissa set) are treated as zero.
-spec bits_to_target(non_neg_integer()) -> non_neg_integer().
bits_to_target(Bits) ->
    Exponent = (Bits bsr 24) band 16#ff,
    Mantissa = Bits band 16#7fffff,
    %% check negative bit
    Negative = (Bits band 16#800000) =/= 0,
    case Negative orelse Mantissa =:= 0 of
        true -> 0;
        false ->
            if
                Exponent =< 3 ->
                    Mantissa bsr (8 * (3 - Exponent));
                true ->
                    Mantissa bsl (8 * (Exponent - 3))
            end
    end.

%% @doc Convert a 256-bit target integer back to compact "bits" form.
-spec target_to_bits(non_neg_integer()) -> non_neg_integer().
target_to_bits(0) -> 0;
target_to_bits(Target) ->
    %% serialize target to big-endian bytes, find size
    Bytes = target_to_bytes(Target),
    Size = byte_size(Bytes),
    %% extract top 3 bytes as mantissa
    {Mantissa, Exp} = case Size >= 3 of
        true ->
            <<B1:8, B2:8, B3:8, _/binary>> = Bytes,
            M = (B1 bsl 16) bor (B2 bsl 8) bor B3,
            {M, Size};
        false ->
            %% pad to 3 bytes
            Padded = <<0:((3 - Size) * 8), Bytes/binary>>,
            <<B1:8, B2:8, B3:8>> = Padded,
            M = (B1 bsl 16) bor (B2 bsl 8) bor B3,
            {M, Size}
    end,
    %% if the high bit of mantissa is set, shift right and bump exponent
    {Mantissa2, Exp2} = case (Mantissa band 16#800000) =/= 0 of
        true -> {Mantissa bsr 8, Exp + 1};
        false -> {Mantissa, Exp}
    end,
    (Exp2 bsl 24) bor (Mantissa2 band 16#7fffff).

%% @doc Check proof of work: block hash (as 256-bit LE integer) <= target.
%% PowLimit is the maximum allowed target for this network (32 bytes, big-endian).
-spec check_pow(binary(), non_neg_integer(), binary()) -> boolean().
check_pow(BlockHash, Bits, PowLimit) when byte_size(BlockHash) =:= 32 ->
    Target = bits_to_target(Bits),
    PowLimitInt = binary:decode_unsigned(PowLimit, big),
    case Target =< 0 orelse Target > PowLimitInt of
        true -> false;
        false ->
            %% block hash is in internal byte order (little-endian as a number)
            HashInt = binary:decode_unsigned(BlockHash, little),
            HashInt =< Target
    end.

%% @doc Calculate the chainwork contributed by a block with the given bits.
%% work = 2^256 / (target + 1)
-spec compute_work(non_neg_integer()) -> non_neg_integer().
compute_work(Bits) ->
    Target = bits_to_target(Bits),
    case Target of
        0 -> 0;
        _ ->
            %% 2^256 / (target + 1)
            (1 bsl 256) div (Target + 1)
    end.

%%% -------------------------------------------------------------------
%%% Internal helpers
%%% -------------------------------------------------------------------

%% Convert a non-negative integer to minimal big-endian bytes
target_to_bytes(0) -> <<0>>;
target_to_bytes(N) ->
    Bin = binary:encode_unsigned(N, big),
    Bin.
