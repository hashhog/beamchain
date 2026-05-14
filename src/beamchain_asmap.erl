-module(beamchain_asmap).

%% ASMap (Autonomous System Map) bytecode interpreter.
%%
%% Provides a compressed mapping from IP address prefixes to Autonomous
%% System Numbers (ASNs), used for eclipse-attack-resistant peer bucketing.
%% The format is a bit-packed binary trie encoded as bytecode instructions.
%%
%% Bitcoin Core reference: src/util/asmap.cpp
%% - Interpret()         → interpret/2
%% - SanityCheckAsmap()  → sanity_check_asmap/2
%% - CheckStandardAsmap()→ check_standard_asmap/1 (128 bits for IPv6)
%% - DecodeAsmap()       → load_asmap/1
%% - AsmapVersion()      → asmap_version/1

-export([load_asmap/1,
         interpret/2,
         sanity_check_asmap/2,
         check_standard_asmap/1,
         asmap_version/1,
         get_mapped_as/2]).

%% IPv4-in-IPv6 prefix: ::ffff:0:0/96 (RFC 4291) — used when looking up
%% IPv4 addresses in the 128-bit trie.
%% 10 bytes of 0x00, then 2 bytes of 0xFF.
-define(IPV4_IN_IPV6_PREFIX, <<0,0,0,0,0,0,0,0,0,0,255,255>>).

%% Maximum file size for an asmap binary: 8 MiB.
-define(MAX_ASMAP_FILE_SIZE, 8388608).

%% Sentinel returned on decode errors — signals INVALID to the interpreter.
-define(INVALID, 16#FFFFFFFF).

%% Instruction encoding (LSB-first bit-packed):
%%   RETURN  = [0]     — return a constant ASN
%%   JUMP    = [1,0]   — branch on next IP bit; if 1, skip N bits forward
%%   MATCH   = [1,1,0] — compare N IP bits against a pattern
%%   DEFAULT = [1,1,1] — set the fallback ASN, continue execution
%%
%% Decoded via decode_bits/4 using the TYPE_BIT_SIZES class table:
%%   class 0 → value 0 (RETURN)   prefix: single 0-bit
%%   class 1 → value 1 (JUMP)     prefix: 10
%%   class 2 → value 2 (MATCH)    prefix: 110
%%   class 3 → value 3 (DEFAULT)  prefix: 111
-define(TYPE_BIT_SIZES, [0, 0, 1]).

%% ASN encoding: minval=1, bit_sizes=[15,16,...,24] (10 classes).
%% Encodes ASNs from 1 up to approximately 16.7 million.
%% ASN 0 is reserved (no match / fallback).
-define(ASN_BIT_SIZES, [15, 16, 17, 18, 19, 20, 21, 22, 23, 24]).

%% MATCH argument encoding: minval=2, bit_sizes=[1,2,...,8].
%% Values in [2, 511]. Highest set bit → match length (1–8 bits); lower
%% bits → pattern to compare against IP bits.
-define(MATCH_BIT_SIZES, [1, 2, 3, 4, 5, 6, 7, 8]).

%% JUMP offset encoding: minval=17, bit_sizes=[5,6,...,30].
%% Can encode large offsets needed to skip big subtrees.
-define(JUMP_BIT_SIZES, [5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
                          18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30]).

%%% ===================================================================
%%% Public API
%%% ===================================================================

%% @doc Load an asmap binary from disk and validate it.
%% Returns {ok, Binary} on success, {error, Reason} on failure.
%% Enforces MAX_ASMAP_FILE_SIZE (8 MiB) and validates structure with
%% check_standard_asmap/1 (128-bit SanityCheckAsmap).
%% Mirrors Bitcoin Core DecodeAsmap().
-spec load_asmap(string() | binary()) -> {ok, binary()} | {error, term()}.
load_asmap(Path) when is_binary(Path) ->
    load_asmap(binary_to_list(Path));
load_asmap(Path) when is_list(Path) ->
    case file:read_file(Path) of
        {error, Reason} ->
            logger:warning("asmap: failed to open ~s: ~p", [Path, Reason]),
            {error, Reason};
        {ok, Data} when byte_size(Data) > ?MAX_ASMAP_FILE_SIZE ->
            logger:warning("asmap: file too large (~B bytes, max ~B): ~s",
                           [byte_size(Data), ?MAX_ASMAP_FILE_SIZE, Path]),
            {error, file_too_large};
        {ok, Data} when byte_size(Data) =:= 0 ->
            logger:warning("asmap: empty file: ~s", [Path]),
            {error, empty_file};
        {ok, Data} ->
            case check_standard_asmap(Data) of
                false ->
                    logger:warning("asmap: sanity check failed: ~s", [Path]),
                    {error, invalid_asmap};
                true ->
                    logger:info("asmap: loaded ~B bytes from ~s", [byte_size(Data), Path]),
                    {ok, Data}
            end
    end.

%% @doc Execute the ASMap bytecode to find the ASN for an IP.
%%
%% Asmap   — the raw bytecode binary (LSB-first bit-packed trie).
%% IP      — the IP address as a binary (MSB-first byte order).
%%           For IPv4: 4 bytes; for IPv6: 16 bytes.
%%           IPv4 should be padded with IPV4_IN_IPV6_PREFIX before calling
%%           (use get_mapped_as/2 which handles this automatically).
%%
%% Returns the ASN (non-zero) if a match is found, or 0 if no mapping.
%% Mirrors Bitcoin Core Interpret().
-spec interpret(binary(), binary()) -> non_neg_integer().
interpret(Asmap, IP) when is_binary(Asmap), is_binary(IP) ->
    EndPos = byte_size(Asmap) * 8,
    interpret_loop(Asmap, IP, 0, EndPos, 0, 0).

%% @doc Validate ASMap bytecode structure.
%%
%% Simulates all possible execution paths to ensure well-formed bytecode,
%% valid jumps, and proper termination.
%% Bits: number of IP address bits the trie is designed to consume (128
%% for standard IPv6-including use).
%% Mirrors Bitcoin Core SanityCheckAsmap().
-spec sanity_check_asmap(binary(), non_neg_integer()) -> boolean().
sanity_check_asmap(Asmap, Bits) when is_binary(Asmap) ->
    EndPos = byte_size(Asmap) * 8,
    sanity_loop(Asmap, EndPos, 0, Bits, [], undefined, false).

%% @doc Validate a standard ASMap file (128-bit inputs for IPv6).
%% Returns true iff sanity_check_asmap(Data, 128) passes.
%% Mirrors Bitcoin Core CheckStandardAsmap().
-spec check_standard_asmap(binary()) -> boolean().
check_standard_asmap(Data) ->
    sanity_check_asmap(Data, 128).

%% @doc Compute the ASMap version: SHA-256 of the raw bytecode.
%% Used for consistency checks and peers.dat versioning (FIX-51).
%% Mirrors Bitcoin Core AsmapVersion() (SHA256d in Core, but SHA256 is
%% sufficient for a unique version identifier here — we use single SHA256
%% to match common addrman practice).
-spec asmap_version(binary()) -> binary().
asmap_version(Data) when is_binary(Data) ->
    crypto:hash(sha256, Data).

%% @doc Map an IP address (IPv4 or IPv6) to its ASN using the loaded asmap.
%%
%% Asmap — binary loaded by load_asmap/1.
%% IP    — {A,B,C,D} IPv4 tuple, or {A,B,C,D,E,F,G,H} IPv6 tuple,
%%         or a raw binary (4 or 16 bytes).
%%
%% Returns the ASN as a non-negative integer (0 = no mapping).
%% IPv4 addresses are padded with the IPv4-in-IPv6 prefix (::ffff:0:0/96)
%% before lookup, as Bitcoin Core does in netgroup.cpp GetMappedAS().
-spec get_mapped_as(binary(), term()) -> non_neg_integer().
get_mapped_as(Asmap, {A, B, C, D}) ->
    %% IPv4: pad to 128-bit IPv4-in-IPv6 representation
    IP = <<?IPV4_IN_IPV6_PREFIX/binary, A:8, B:8, C:8, D:8>>,
    interpret(Asmap, IP);
get_mapped_as(Asmap, {A, B, C, D, E, F, G, H}) ->
    %% IPv6: 16 bytes big-endian
    IP = <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>,
    interpret(Asmap, IP);
get_mapped_as(Asmap, IP) when is_binary(IP), byte_size(IP) =:= 4 ->
    %% Raw IPv4 bytes: pad to 128 bits
    PaddedIP = <<?IPV4_IN_IPV6_PREFIX/binary, IP/binary>>,
    interpret(Asmap, PaddedIP);
get_mapped_as(Asmap, IP) when is_binary(IP), byte_size(IP) =:= 16 ->
    interpret(Asmap, IP);
get_mapped_as(_Asmap, _) ->
    %% Non-IP networks (Tor, I2P, CJDNS) — no ASN lookup
    0.

%%% ===================================================================
%%% Internal: bytecode interpreter
%%% ===================================================================

%% interpret_loop(Asmap, IP, Pos, EndPos, IPBit, DefaultASN) -> ASN
%%
%% Processes instructions one by one until RETURN or EOF.
%% - Pos    : current bit position in Asmap (LSB-first)
%% - IPBit  : next bit to consume from IP (MSB-first)
%% - DefaultASN: current DEFAULT value (used on MATCH mismatch)
interpret_loop(Asmap, IP, Pos, EndPos, IPBit, DefaultASN) when Pos < EndPos ->
    IPBitsEnd = byte_size(IP) * 8,
    case decode_type(Asmap, Pos) of
        {?INVALID, _} ->
            0;
        {0, Pos1} ->
            %% RETURN: return the decoded ASN
            case decode_asn(Asmap, Pos1) of
                {?INVALID, _} -> 0;
                {ASN, _} -> ASN
            end;
        {1, Pos1} ->
            %% JUMP: branch on next IP bit
            case decode_jump(Asmap, Pos1) of
                {?INVALID, _} ->
                    0;
                {Jump, Pos2} ->
                    if
                        IPBit >= IPBitsEnd ->
                            0;
                        Jump >= (EndPos - Pos2) ->
                            0;
                        true ->
                            {IPBitVal, NewIPBit} = consume_bit_be(IP, IPBit),
                            NewPos = case IPBitVal of
                                1 -> Pos2 + Jump;  %% IP bit=1: jump to right subtree
                                0 -> Pos2           %% IP bit=0: fall through to left subtree
                            end,
                            interpret_loop(Asmap, IP, NewPos, EndPos, NewIPBit, DefaultASN)
                    end
            end;
        {2, Pos1} ->
            %% MATCH: compare multiple IP bits against a pattern
            case decode_match(Asmap, Pos1) of
                {?INVALID, _} ->
                    0;
                {Match, Pos2} ->
                    MatchLen = bit_width(Match) - 1,
                    if
                        (IPBitsEnd - IPBit) < MatchLen ->
                            0;
                        true ->
                            check_match(Asmap, IP, Pos2, EndPos, IPBit, DefaultASN,
                                        Match, MatchLen, 0)
                    end
            end;
        {3, Pos1} ->
            %% DEFAULT: update fallback ASN and continue
            case decode_asn(Asmap, Pos1) of
                {?INVALID, _} ->
                    0;
                {NewDefault, Pos2} ->
                    interpret_loop(Asmap, IP, Pos2, EndPos, IPBit, NewDefault)
            end;
        _ ->
            0
    end;
interpret_loop(_Asmap, _IP, _Pos, _EndPos, _IPBit, DefaultASN) ->
    DefaultASN.

%% @doc Check all bits of a MATCH pattern against IP bits.
%% Returns DefaultASN on first mismatch; continues loop on full match.
check_match(Asmap, IP, Pos, EndPos, IPBit, DefaultASN, _Match, 0, _BitIdx) ->
    %% All pattern bits matched — continue execution
    interpret_loop(Asmap, IP, Pos, EndPos, IPBit, DefaultASN);
check_match(Asmap, IP, Pos, EndPos, IPBit, DefaultASN, Match, RemainingBits, BitIdx) ->
    MatchLen = bit_width(Match) - 1,
    PatternBit = (Match bsr (MatchLen - 1 - BitIdx)) band 1,
    {IPBitVal, NewIPBit} = consume_bit_be(IP, IPBit),
    case IPBitVal =:= PatternBit of
        false ->
            DefaultASN;  %% mismatch — return current default
        true ->
            check_match(Asmap, IP, Pos, EndPos, NewIPBit, DefaultASN,
                        Match, RemainingBits - 1, BitIdx + 1)
    end.

%%% ===================================================================
%%% Internal: sanity checker
%%% ===================================================================

%% sanity_loop validates all execution paths by simulating the interpreter
%% symbolically. It maintains a "jump stack" of (JumpTargetPos, BitsLeft)
%% pairs that represent pending right-subtree branches.
%%
%% Returns true iff the bytecode is well-formed:
%%   - All instructions are complete (no straddling EOF)
%%   - All jumps land on instruction boundaries (no overlap)
%%   - Every path terminates with a RETURN
%%   - No consecutive DEFAULTs
%%   - RETURN is never immediately after DEFAULT (could be folded)
%%   - Padding after final RETURN is at most 7 bits, all zero
%%
%% Mirrors Bitcoin Core SanityCheckAsmap().

sanity_loop(Asmap, EndPos, Pos, Bits, Jumps, PrevOpcode, HadIncompleteMatch) ->
    if
        Pos =:= EndPos ->
            false;  %% Reached EOF without RETURN
        true ->
            %% Check we haven't jumped into the middle of the previous instruction
            case Jumps of
                [{NextJump, _} | _] when Pos > NextJump ->
                    false;
                _ ->
                    sanity_dispatch(Asmap, EndPos, Pos, Bits, Jumps,
                                    PrevOpcode, HadIncompleteMatch)
            end
    end.

sanity_dispatch(Asmap, EndPos, Pos, Bits, Jumps, PrevOpcode, HadIncompleteMatch) ->
    case decode_type(Asmap, Pos) of
        {?INVALID, _} ->
            false;  %% Instruction straddles EOF
        {0, Pos1} ->
            %% RETURN: check not immediately after DEFAULT
            case PrevOpcode of
                default ->
                    false;  %% Could combine DEFAULT+RETURN into single RETURN
                _ ->
                    case decode_asn(Asmap, Pos1) of
                        {?INVALID, _} ->
                            false;  %% ASN straddles EOF
                        {_ASN, Pos2} ->
                            sanity_return(Asmap, EndPos, Pos2, Bits, Jumps)
                    end
            end;
        {1, Pos1} ->
            %% JUMP
            case decode_jump(Asmap, Pos1) of
                {?INVALID, _} ->
                    false;
                {Jump, Pos2} ->
                    JumpTarget = Pos2 + Jump,
                    if
                        Jump > (EndPos - Pos2) ->
                            false;  %% Jump out of range
                        Bits =:= 0 ->
                            false;  %% Consuming IP bits past end
                        true ->
                            %% Validate no intersecting jumps
                            case Jumps of
                                [{ExistingJump, _} | _]
                                  when JumpTarget >= ExistingJump ->
                                    false;  %% Intersecting jump targets
                                _ ->
                                    NewJumps = [{JumpTarget, Bits - 1} | Jumps],
                                    sanity_loop(Asmap, EndPos, Pos2, Bits - 1,
                                                NewJumps, jump, false)
                            end
                    end
            end;
        {2, Pos1} ->
            %% MATCH
            case decode_match(Asmap, Pos1) of
                {?INVALID, _} ->
                    false;
                {Match, Pos2} ->
                    MatchLen = bit_width(Match) - 1,
                    %% Track incomplete matches (< 8 bits) in a sequence:
                    %% only one such incomplete match allowed per consecutive run.
                    NewHadIncomplete = case PrevOpcode of
                        match -> HadIncompleteMatch;
                        _     -> false
                    end,
                    if
                        MatchLen < 8 andalso NewHadIncomplete ->
                            false;  %% Two consecutive incomplete matches
                        Bits < MatchLen ->
                            false;  %% Consuming bits past end of input
                        true ->
                            IsIncomplete = MatchLen < 8,
                            sanity_loop(Asmap, EndPos, Pos2, Bits - MatchLen,
                                        Jumps, match, IsIncomplete)
                    end
            end;
        {3, Pos1} ->
            %% DEFAULT: check not two consecutive DEFAULTs
            case PrevOpcode of
                default ->
                    false;
                _ ->
                    case decode_asn(Asmap, Pos1) of
                        {?INVALID, _} ->
                            false;
                        {_ASN, Pos2} ->
                            sanity_loop(Asmap, EndPos, Pos2, Bits,
                                        Jumps, default, false)
                    end
            end;
        _ ->
            false
    end.

%% Handle a RETURN instruction during sanity check.
sanity_return(Asmap, EndPos, Pos2, _Bits, []) ->
    %% No more jump targets — we should be at or near EOF
    Padding = EndPos - Pos2,
    if
        Padding > 7 ->
            false;  %% Excessive padding after final RETURN
        true ->
            %% All remaining bits must be zero (padding)
            check_zero_padding(Asmap, Pos2, EndPos)
    end;
sanity_return(Asmap, EndPos, Pos2, _Bits, [{JumpTarget, JumpBits} | RestJumps]) ->
    %% There are pending jump targets to validate
    if
        Pos2 =/= JumpTarget ->
            false;  %% Unreachable code between RETURN and jump target
        true ->
            sanity_loop(Asmap, EndPos, JumpTarget, JumpBits,
                        RestJumps, jump, false)
    end.

%% Verify all bits from Pos to EndPos are zero (padding after final RETURN).
check_zero_padding(_Asmap, Pos, EndPos) when Pos >= EndPos ->
    true;
check_zero_padding(Asmap, Pos, EndPos) ->
    {Bit, _} = consume_bit_le(Asmap, Pos),
    case Bit of
        0 -> check_zero_padding(Asmap, Pos + 1, EndPos);
        1 -> false
    end.

%%% ===================================================================
%%% Internal: variable-length integer decoder
%%% ===================================================================

%% @doc Decode a variable-length integer from the ASMap bitstream.
%%
%% Encoding (same for all four tables: TYPE, ASN, MATCH, JUMP):
%%   - Read "class" bits: k leading 1-bits until a 0-bit (or end of
%%     bit_sizes list for the last class, which has no terminating 0).
%%   - Read bit_sizes[k] mantissa bits in big-endian order within the class.
%%   - Value = MinVal + sum(sizes[0..k-1] shifted) + mantissa.
%%
%% Returns {Value, NewPos} or {?INVALID, Pos} on truncation.
%%
%% Mirrors Bitcoin Core DecodeBits().
decode_bits(Asmap, Pos, MinVal, BitSizes) ->
    decode_bits_loop(Asmap, Pos, MinVal, BitSizes, byte_size(Asmap) * 8).

decode_bits_loop(Asmap, Pos, Val, [Size | Rest], EndPos) ->
    case Rest of
        [] ->
            %% Last class: no continuation bit, just read the mantissa
            decode_mantissa(Asmap, Pos, Val, Size, EndPos);
        _ ->
            %% Read continuation bit
            if
                Pos >= EndPos ->
                    {?INVALID, Pos};  %% EOF in exponent
                true ->
                    {ContinueBit, Pos1} = consume_bit_le(Asmap, Pos),
                    case ContinueBit of
                        1 ->
                            %% Continue to next class, add this class's range
                            decode_bits_loop(Asmap, Pos1, Val + (1 bsl Size),
                                             Rest, EndPos);
                        0 ->
                            %% This is our class — read mantissa
                            decode_mantissa(Asmap, Pos1, Val, Size, EndPos)
                    end
            end
    end;
decode_bits_loop(_Asmap, Pos, _Val, [], _EndPos) ->
    {?INVALID, Pos}.  %% Ran out of classes

%% Read `Size` mantissa bits in big-endian order and add to Val.
decode_mantissa(_Asmap, Pos, Val, 0, _EndPos) ->
    {Val, Pos};
decode_mantissa(Asmap, Pos, Val, BitsLeft, EndPos) ->
    if
        Pos >= EndPos ->
            {?INVALID, Pos};  %% Truncated in mantissa
        true ->
            {Bit, Pos1} = consume_bit_le(Asmap, Pos),
            %% Big-endian: most-significant mantissa bit first
            NewVal = Val + (Bit bsl (BitsLeft - 1)),
            decode_mantissa(Asmap, Pos1, NewVal, BitsLeft - 1, EndPos)
    end.

%% Instruction type: minval=0, bit_sizes=[0,0,1]
decode_type(Asmap, Pos) ->
    decode_bits(Asmap, Pos, 0, ?TYPE_BIT_SIZES).

%% ASN: minval=1, bit_sizes=[15,16,...,24]
decode_asn(Asmap, Pos) ->
    decode_bits(Asmap, Pos, 1, ?ASN_BIT_SIZES).

%% MATCH argument: minval=2, bit_sizes=[1,...,8]
decode_match(Asmap, Pos) ->
    decode_bits(Asmap, Pos, 2, ?MATCH_BIT_SIZES).

%% JUMP offset: minval=17, bit_sizes=[5,...,30]
decode_jump(Asmap, Pos) ->
    decode_bits(Asmap, Pos, 17, ?JUMP_BIT_SIZES).

%%% ===================================================================
%%% Internal: bit extraction helpers
%%% ===================================================================

%% @doc Consume one bit from Asmap at bit position Pos using LSB-first
%% ordering (as stored in the asmap bytecode).
%% Returns {Bit, NewPos}.
-spec consume_bit_le(binary(), non_neg_integer()) -> {0 | 1, non_neg_integer()}.
consume_bit_le(Asmap, Pos) ->
    ByteIdx = Pos div 8,
    BitIdx  = Pos rem 8,
    <<_:ByteIdx/binary, Byte:8, _/binary>> = Asmap,
    Bit = (Byte bsr BitIdx) band 1,
    {Bit, Pos + 1}.

%% @doc Consume one bit from IP at bit position IPBit using MSB-first
%% ordering (network byte order, as Bitcoin Core uses for IP addresses).
%% Returns {Bit, NewIPBit}.
-spec consume_bit_be(binary(), non_neg_integer()) -> {0 | 1, non_neg_integer()}.
consume_bit_be(IP, IPBit) ->
    ByteIdx = IPBit div 8,
    BitIdx  = IPBit rem 8,
    <<_:ByteIdx/binary, Byte:8, _/binary>> = IP,
    %% MSB first: bit 0 of position is the most significant bit
    Bit = (Byte bsr (7 - BitIdx)) band 1,
    {Bit, IPBit + 1}.

%% @doc Return the number of bits needed to represent N (i.e., floor(log2(N))+1).
%% Equivalent to std::bit_width in C++20 / popcount / highest set bit + 1.
%% bit_width(0) = 0, bit_width(1) = 1, bit_width(2) = 2, bit_width(3) = 2, ...
-spec bit_width(non_neg_integer()) -> non_neg_integer().
bit_width(0) -> 0;
bit_width(N) -> bit_width(N, 0).

bit_width(0, Acc) -> Acc;
bit_width(N, Acc) -> bit_width(N bsr 1, Acc + 1).
