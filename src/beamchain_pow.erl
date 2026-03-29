-module(beamchain_pow).

%% Proof of work: target/bits conversion, PoW checking, chainwork.

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-export([bits_to_target/1, target_to_bits/1]).
-export([compact_to_target/1, target_to_compact/1]).  %% aliases
-export([check_pow/3, compute_work/1]).
-export([get_next_work_required/3]).

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
%%% Difficulty retargeting
%%% -------------------------------------------------------------------

%% @doc Calculate the required difficulty for the next block.
%% PrevIndex is a map with keys: height, header, bits (the previous block).
%% Params is the chain params map from beamchain_chain_params.
-spec get_next_work_required(map(), #block_header{}, map()) -> non_neg_integer().
get_next_work_required(PrevIndex, Header, Params) ->
    PrevHeight = maps:get(height, PrevIndex),
    PrevHeader = maps:get(header, PrevIndex),
    PrevBits = PrevHeader#block_header.bits,
    PowNoRetargeting = maps:get(pow_no_retargeting, Params, false),
    AllowMinDiff = maps:get(pow_allow_min_difficulty, Params, false),
    PowLimitBits = pow_limit_bits(Params),
    Height = PrevHeight + 1,

    case PowNoRetargeting of
        true ->
            %% regtest: never adjust difficulty
            PrevBits;
        false ->
            case Height rem ?DIFFICULTY_ADJUSTMENT_INTERVAL of
                0 ->
                    %% Retarget boundary — always recalculate difficulty.
                    %% Min-difficulty 20-minute rule does NOT apply here
                    %% (matches Bitcoin Core ordering).
                    calculate_retarget(PrevIndex, Params);
                _ ->
                    %% Not at a retarget boundary
                    case AllowMinDiff of
                        true ->
                            %% Testnet min-difficulty rule: if timestamp
                            %% > prev + spacing*2, allow powLimit
                            Spacing = maps:get(pow_target_spacing, Params,
                                               ?POW_TARGET_SPACING),
                            case Header#block_header.timestamp >
                                 PrevHeader#block_header.timestamp + Spacing * 2 of
                                true ->
                                    PowLimitBits;
                                false ->
                                    %% Walk back to last non-min-difficulty block
                                    find_last_non_special_block(PrevIndex, Params)
                            end;
                        false ->
                            PrevBits
                    end
            end
    end.

%% Calculate new target at a retarget boundary
calculate_retarget(PrevIndex, Params) ->
    PrevHeight = maps:get(height, PrevIndex),
    PrevHeader = maps:get(header, PrevIndex),
    TargetTimespan = maps:get(pow_target_timespan, Params, ?POW_TARGET_TIMESPAN),
    PowLimit = maps:get(pow_limit, Params),
    PowLimitInt = binary:decode_unsigned(PowLimit, big),

    %% find the block at the start of this retarget period
    FirstHeight = PrevHeight - (?DIFFICULTY_ADJUSTMENT_INTERVAL - 1),
    FirstIndex = get_block_index(FirstHeight),
    FirstHeader = maps:get(header, FirstIndex),

    %% calculate actual timespan
    ActualTimespan0 = PrevHeader#block_header.timestamp -
                      FirstHeader#block_header.timestamp,

    %% clamp to [timespan/4, timespan*4]
    ActualTimespan1 = max(TargetTimespan div 4, ActualTimespan0),
    ActualTimespan = min(TargetTimespan * 4, ActualTimespan1),

    %% new_target = old_target * actual_timespan / target_timespan
    %% BIP94 (testnet4): use the first block of the period's bits for OldTarget
    %% because the first block cannot use the min-difficulty exception.
    IsBIP94 = maps:get(network, Params, mainnet) =:= testnet4,
    OldTarget = case IsBIP94 of
        true  -> bits_to_target(FirstHeader#block_header.bits);
        false -> bits_to_target(PrevHeader#block_header.bits)
    end,
    NewTarget0 = (OldTarget * ActualTimespan) div TargetTimespan,

    %% clamp to pow_limit
    NewTarget = min(NewTarget0, PowLimitInt),
    target_to_bits(NewTarget).

%% On testnet, walk back to find the last block that wasn't mined at
%% minimum difficulty. This handles the testnet difficulty reset rule.
find_last_non_special_block(Index, Params) ->
    Height = maps:get(height, Index),
    Header = maps:get(header, Index),
    PowLimitBits = pow_limit_bits(Params),
    case Height rem ?DIFFICULTY_ADJUSTMENT_INTERVAL =:= 0 of
        true ->
            Header#block_header.bits;
        false ->
            case Header#block_header.bits =:= PowLimitBits of
                true when Height > 0 ->
                    PrevIndex = get_block_index(Height - 1),
                    find_last_non_special_block(PrevIndex, Params);
                _ ->
                    Header#block_header.bits
            end
    end.

%% Look up a block index entry by height. This calls the db module.
get_block_index(Height) ->
    case beamchain_db:get_block_index(Height) of
        {ok, Entry} -> Entry;
        not_found -> error({block_index_not_found, Height})
    end.

%% Calculate the pow_limit in compact bits form
pow_limit_bits(Params) ->
    PowLimit = maps:get(pow_limit, Params),
    PowLimitInt = binary:decode_unsigned(PowLimit, big),
    target_to_bits(PowLimitInt).

%%% -------------------------------------------------------------------
%%% Aliases for compact_to_target / target_to_compact
%%% -------------------------------------------------------------------

%% @doc Alias for bits_to_target/1 (convert compact nBits to 256-bit target).
-spec compact_to_target(non_neg_integer()) -> non_neg_integer().
compact_to_target(Bits) -> bits_to_target(Bits).

%% @doc Alias for target_to_bits/1 (convert 256-bit target to compact nBits).
-spec target_to_compact(non_neg_integer()) -> non_neg_integer().
target_to_compact(Target) -> target_to_bits(Target).

%%% -------------------------------------------------------------------
%%% Internal helpers
%%% -------------------------------------------------------------------

%% Convert a non-negative integer to minimal big-endian bytes
target_to_bytes(0) -> <<0>>;
target_to_bytes(N) ->
    Bin = binary:encode_unsigned(N, big),
    Bin.
