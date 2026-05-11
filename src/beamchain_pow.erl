-module(beamchain_pow).

%% Proof of work: target/bits conversion, PoW checking, chainwork.

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-export([bits_to_target/1, target_to_bits/1]).
-export([compact_to_target/1, target_to_compact/1]).  %% aliases
-export([check_pow/3, compute_work/1]).
-export([get_next_work_required/3]).
-export([permitted_difficulty_transition/4]).

%%% -------------------------------------------------------------------
%%% Compact bits <-> 256-bit target conversion
%%% -------------------------------------------------------------------

%% @doc Convert compact "bits" representation to a 256-bit target.
%% Format: 0xAABBBBBB where AA = exponent, BBBBBB = mantissa.
%% target = mantissa * 2^(8 * (exponent - 3))
%% Negative targets (high bit of mantissa set) are treated as zero.
%% Overflow (exponent too large for the mantissa width) returns 0.
%% Mirrors Core arith_uint256::SetCompact + DeriveTarget (pow.cpp:146-158).
-spec bits_to_target(non_neg_integer()) -> non_neg_integer().
bits_to_target(Bits) ->
    Exponent = (Bits bsr 24) band 16#ff,
    %% Core uses the full 23-bit mantissa word (0x007fffff mask), not 0x7fffff
    Mantissa = Bits band 16#007fffff,
    %% check negative bit (bit 23 of the compact word)
    Negative = (Bits band 16#00800000) =/= 0,
    %% Overflow check mirrors Core SetCompact pfOverflow:
    %%   nWord != 0 && ((nSize > 34) ||
    %%                  (nWord > 0xff   && nSize > 33) ||
    %%                  (nWord > 0xffff && nSize > 32))
    Overflow = (Mantissa =/= 0) andalso
               ((Exponent > 34) orelse
                (Mantissa > 16#ff   andalso Exponent > 33) orelse
                (Mantissa > 16#ffff andalso Exponent > 32)),
    case Negative orelse Mantissa =:= 0 orelse Overflow of
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
    %% BIP94: use the first block of the period's bits for OldTarget because
    %% the first block cannot use the min-difficulty exception.
    %% Core uses params.enforce_BIP94 (a boolean), NOT a network-name check.
    %% Regtest can enable BIP94 via opts; never rely on network =:= testnet4.
    EnforceBIP94 = maps:get(enforce_bip94, Params, false),
    OldTarget = case EnforceBIP94 of
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
%%% PermittedDifficultyTransition
%%% -------------------------------------------------------------------

%% @doc Return false if the difficulty transition at Height from OldBits to
%% NewBits is not permitted by consensus rules.
%%
%% At a retarget boundary (Height rem 2016 == 0):
%%   the new target must lie within [old/4 .. old*4], clamped to pow_limit,
%%   and rounded through GetCompact/SetCompact just like Core does.
%% Off a retarget boundary:
%%   the bits must be unchanged.
%% On networks with fPowAllowMinDifficultyBlocks (testnet/regtest):
%%   always returns true — min-difficulty exceptions are permitted.
%%
%% Mirrors Core pow.cpp:89-136 PermittedDifficultyTransition.
-spec permitted_difficulty_transition(map(), non_neg_integer(),
                                      non_neg_integer(), non_neg_integer())
    -> boolean().
permitted_difficulty_transition(Params, Height, OldBits, NewBits) ->
    AllowMinDiff = maps:get(pow_allow_min_difficulty, Params, false),
    case AllowMinDiff of
        true ->
            %% testnet / regtest: any transition is permitted
            true;
        false ->
            case Height rem ?DIFFICULTY_ADJUSTMENT_INTERVAL of
                0 ->
                    %% Retarget block: check that NewBits is within [old/4 .. old*4]
                    TargetTimespan = maps:get(pow_target_timespan, Params,
                                             ?POW_TARGET_TIMESPAN),
                    SmallestTimespan = TargetTimespan div 4,
                    LargestTimespan  = TargetTimespan * 4,
                    PowLimit = maps:get(pow_limit, Params),
                    PowLimitInt = binary:decode_unsigned(PowLimit, big),

                    ObservedNewTarget = bits_to_target(NewBits),

                    %% Calculate the largest (easiest) permitted target:
                    %%   old_target * largest_timespan / target_timespan, clamped
                    LargestTarget0 = (bits_to_target(OldBits) * LargestTimespan)
                                     div TargetTimespan,
                    LargestTarget1 = min(LargestTarget0, PowLimitInt),
                    %% Round through compact encoding (mirrors Core's
                    %%   maximum_new_target.SetCompact(largest_difficulty_target.GetCompact()))
                    MaximumNewTarget = bits_to_target(target_to_bits(LargestTarget1)),

                    case MaximumNewTarget < ObservedNewTarget of
                        true -> false;  %% new target is easier than max permitted
                        false ->
                            %% Calculate the smallest (hardest) permitted target:
                            %%   old_target * smallest_timespan / target_timespan, clamped
                            SmallestTarget0 = (bits_to_target(OldBits) * SmallestTimespan)
                                              div TargetTimespan,
                            SmallestTarget1 = min(SmallestTarget0, PowLimitInt),
                            %% Round through compact encoding
                            MinimumNewTarget = bits_to_target(
                                                   target_to_bits(SmallestTarget1)),

                            case MinimumNewTarget > ObservedNewTarget of
                                true  -> false;  %% new target is harder than min permitted
                                false -> true
                            end
                    end;
                _ ->
                    %% Non-retarget block: bits must be unchanged
                    OldBits =:= NewBits
            end
    end.

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
