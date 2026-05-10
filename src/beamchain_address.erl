-module(beamchain_address).

-include("beamchain.hrl").

%% Base58Check
-export([base58check_encode/2, base58check_decode/1]).

%% Bech32 / Bech32m
-export([bech32_encode/2, bech32_decode/1,
         bech32m_encode/2, bech32m_decode/1]).

%% High-level address functions
-export([script_to_address/2, address_to_script/2,
         classify_script/1]).

%% Bit conversion helpers (exported for testing)
-export([convert_bits/4]).

%%% -------------------------------------------------------------------
%%% Base58 alphabet and constants
%%% -------------------------------------------------------------------

-define(BASE58_ALPHABET, "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz").

%%% -------------------------------------------------------------------
%%% Bech32 constants
%%% -------------------------------------------------------------------

-define(BECH32_CHARSET, "qpzry9x8gf2tvdw0s3jn54khce6mua7l").
-define(BECH32_CONST, 1).
-define(BECH32M_CONST, 16#2bc830a3).
-define(BECH32_GENERATORS, [16#3b6a57b2, 16#26508e6d, 16#1ea119fa,
                            16#3d4233dd, 16#2a1462b3]).

%%% -------------------------------------------------------------------
%%% Base58Check encoding/decoding
%%% -------------------------------------------------------------------

-spec base58check_encode(byte(), binary()) -> string().
base58check_encode(Version, Payload) ->
    Data = <<Version:8, Payload/binary>>,
    <<Checksum:4/binary, _/binary>> = beamchain_crypto:hash256(Data),
    WithChecksum = <<Data/binary, Checksum/binary>>,
    %% count leading zero bytes → they become leading '1' chars
    LeadingZeros = count_leading_zeros(WithChecksum),
    Prefix = lists:duplicate(LeadingZeros, $1),
    %% convert the whole binary to a big integer, then to base58
    N = binary:decode_unsigned(WithChecksum, big),
    Prefix ++ encode_base58_int(N).

-spec base58check_decode(string()) -> {ok, {byte(), binary()}} | {error, term()}.
base58check_decode(Str) ->
    case decode_base58_str(Str) of
        {error, _} = E -> E;
        {ok, Bytes} ->
            Len = byte_size(Bytes),
            case Len >= 5 of
                false -> {error, too_short};
                true ->
                    PayloadLen = Len - 4,
                    <<Body:PayloadLen/binary, Checksum:4/binary>> = Bytes,
                    <<ExpectedChecksum:4/binary, _/binary>> =
                        beamchain_crypto:hash256(Body),
                    case Checksum =:= ExpectedChecksum of
                        true ->
                            <<Version:8, Payload/binary>> = Body,
                            {ok, {Version, Payload}};
                        false ->
                            {error, bad_checksum}
                    end
            end
    end.

%%% -------------------------------------------------------------------
%%% Bech32 encoding/decoding (BIP 173)
%%% -------------------------------------------------------------------

-spec bech32_encode(string(), [integer()]) -> string().
bech32_encode(Hrp, Data) ->
    bech32_encode_internal(Hrp, Data, ?BECH32_CONST).

-spec bech32_decode(string()) -> {ok, {string(), [integer()]}} | {error, term()}.
bech32_decode(Str) ->
    bech32_decode_internal(Str, ?BECH32_CONST).

%%% -------------------------------------------------------------------
%%% Bech32m encoding/decoding (BIP 350)
%%% -------------------------------------------------------------------

-spec bech32m_encode(string(), [integer()]) -> string().
bech32m_encode(Hrp, Data) ->
    bech32_encode_internal(Hrp, Data, ?BECH32M_CONST).

-spec bech32m_decode(string()) -> {ok, {string(), [integer()]}} | {error, term()}.
bech32m_decode(Str) ->
    bech32_decode_internal(Str, ?BECH32M_CONST).

%%% -------------------------------------------------------------------
%%% High-level: scriptPubKey → address
%%% -------------------------------------------------------------------

-spec script_to_address(binary(), mainnet | testnet) -> string() | unknown.
%% P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
script_to_address(<<16#76, 16#a9, 16#14, Hash:20/binary, 16#88, 16#ac>>, Network) ->
    Version = case Network of
        mainnet -> 16#00;
        testnet -> 16#6f
    end,
    base58check_encode(Version, Hash);

%% P2SH: OP_HASH160 <20> OP_EQUAL
script_to_address(<<16#a9, 16#14, Hash:20/binary, 16#87>>, Network) ->
    Version = case Network of
        mainnet -> 16#05;
        testnet -> 16#c4
    end,
    base58check_encode(Version, Hash);

%% Witness programs: OP_n <len> <program>
script_to_address(<<WitVer:8, Len:8, Program:Len/binary>>, Network)
  when (WitVer =:= 16#00 orelse (WitVer >= 16#51 andalso WitVer =< 16#60)),
       (Len >= 2 andalso Len =< 40) ->
    Hrp = case Network of
        mainnet -> "bc";
        testnet -> "tb"
    end,
    Version = case WitVer of
        16#00 -> 0;
        V     -> V - 16#50
    end,
    ProgramBits = convert_bits(binary_to_list(Program), 8, 5, true),
    case Version of
        0 -> bech32_encode(Hrp, [Version | ProgramBits]);
        _ -> bech32m_encode(Hrp, [Version | ProgramBits])
    end;

%% OP_RETURN
script_to_address(<<16#6a, _/binary>>, _Network) ->
    "OP_RETURN";

script_to_address(_, _) ->
    unknown.

%%% -------------------------------------------------------------------
%%% High-level: address → scriptPubKey
%%% -------------------------------------------------------------------

-spec address_to_script(string(), mainnet | testnet) -> {ok, binary()} | {error, term()}.
address_to_script(Address, Network) ->
    %% try bech32/bech32m first, then base58check
    case try_decode_segwit(Address, Network) of
        {ok, Script} -> {ok, Script};
        {error, _} ->
            case base58check_decode(Address) of
                {ok, {Version, Payload}} ->
                    address_version_to_script(Version, Payload, Network);
                {error, _} = E -> E
            end
    end.

%%% -------------------------------------------------------------------
%%% Script classification
%%% -------------------------------------------------------------------

-spec classify_script(binary()) ->
    p2pkh | p2sh | p2wpkh | p2wsh | p2tr | op_return |
    {multisig, non_neg_integer(), non_neg_integer(), [binary()]} |
    {witness, non_neg_integer(), binary()} | nonstandard.

%% P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
classify_script(<<16#76, 16#a9, 16#14, _:20/binary, 16#88, 16#ac>>) ->
    p2pkh;

%% P2SH: OP_HASH160 <20> OP_EQUAL
classify_script(<<16#a9, 16#14, _:20/binary, 16#87>>) ->
    p2sh;

%% P2WPKH: OP_0 <20>
classify_script(<<16#00, 16#14, _:20/binary>>) ->
    p2wpkh;

%% P2WSH: OP_0 <32>
classify_script(<<16#00, 16#20, _:32/binary>>) ->
    p2wsh;

%% P2TR: OP_1 <32>
classify_script(<<16#51, 16#20, _:32/binary>>) ->
    p2tr;

%% OP_RETURN
classify_script(<<16#6a, _/binary>>) ->
    op_return;

%% Bare multisig: OP_M <pk1>...<pkN> OP_N OP_CHECKMULTISIG
%% M and N are OP_1..OP_16 (0x51..0x60); each pubkey is 33 or 65 bytes.
%% Delegate to the witness_signer parser which already handles this pattern.
classify_script(Script) ->
    case beamchain_witness_signer:parse_multisig_script(Script) of
        {ok, M, N, PubKeys} -> {multisig, M, N, PubKeys};
        error -> nonstandard_or_witness(Script)
    end.

%% Internal: classify non-multisig scripts that fall through the main patterns.
nonstandard_or_witness(<<WitVer:8, Len:8, Program:Len/binary>>)
  when (WitVer =:= 16#00 orelse (WitVer >= 16#51 andalso WitVer =< 16#60)),
       (Len >= 2 andalso Len =< 40) ->
    Version = case WitVer of
        16#00 -> 0;
        V     -> V - 16#50
    end,
    {witness, Version, Program};
nonstandard_or_witness(_) ->
    nonstandard.

%%% -------------------------------------------------------------------
%%% Internal: Base58 helpers
%%% -------------------------------------------------------------------

count_leading_zeros(<<0, Rest/binary>>) ->
    1 + count_leading_zeros(Rest);
count_leading_zeros(_) ->
    0.

encode_base58_int(0) ->
    [];
encode_base58_int(N) ->
    Alphabet = ?BASE58_ALPHABET,
    encode_base58_int(N, Alphabet, []).

encode_base58_int(0, _Alphabet, Acc) ->
    Acc;
encode_base58_int(N, Alphabet, Acc) ->
    Rem = N rem 58,
    Char = lists:nth(Rem + 1, Alphabet),
    encode_base58_int(N div 58, Alphabet, [Char | Acc]).

decode_base58_str(Str) ->
    %% count leading '1' chars → leading zero bytes
    {LeadingOnes, Rest} = count_leading_char(Str, $1),
    case decode_base58_chars(Rest, 0) of
        {error, _} = E -> E;
        {ok, N} ->
            %% convert integer to binary
            NumBytes = if N =:= 0 -> <<>>;
                          true -> binary:encode_unsigned(N, big)
                       end,
            Padding = binary:copy(<<0>>, LeadingOnes),
            {ok, <<Padding/binary, NumBytes/binary>>}
    end.

count_leading_char([$1 | Rest], $1) ->
    {Count, Remaining} = count_leading_char(Rest, $1),
    {Count + 1, Remaining};
count_leading_char(Str, _) ->
    {0, Str}.

decode_base58_chars([], Acc) ->
    {ok, Acc};
decode_base58_chars([C | Rest], Acc) ->
    case base58_char_value(C) of
        error -> {error, {invalid_base58_char, C}};
        Val -> decode_base58_chars(Rest, Acc * 58 + Val)
    end.

base58_char_value(C) ->
    Alphabet = ?BASE58_ALPHABET,
    case string:chr(Alphabet, C) of
        0 -> error;
        Pos -> Pos - 1
    end.

%%% -------------------------------------------------------------------
%%% Internal: Bech32/Bech32m shared implementation
%%% -------------------------------------------------------------------

bech32_encode_internal(Hrp, Data, Spec) ->
    HrpLower = string:to_lower(Hrp),
    Expanded = hrp_expand(HrpLower),
    CheckValues = bech32_create_checksum(Expanded, Data, Spec),
    Combined = Data ++ CheckValues,
    Charset = ?BECH32_CHARSET,
    Encoded = [lists:nth(V + 1, Charset) || V <- Combined],
    HrpLower ++ "1" ++ Encoded.

bech32_decode_internal(Str, Spec) ->
    %% check all chars are in valid range (33-126)
    case lists:all(fun(C) -> C >= 33 andalso C =< 126 end, Str) of
        false -> {error, invalid_character};
        true ->
            %% must not be mixed case
            Lower = string:to_lower(Str),
            Upper = string:to_upper(Str),
            case Str =:= Lower orelse Str =:= Upper of
                false -> {error, mixed_case};
                true ->
                    WorkStr = Lower,
                    %% overall length check (max 90 for bech32)
                    case length(WorkStr) > 90 of
                        true -> {error, too_long};
                        false ->
                            bech32_decode_validated(WorkStr, Spec)
                    end
            end
    end.

bech32_decode_validated(WorkStr, Spec) ->
    %% find last '1' separator
    case string:rchr(WorkStr, $1) of
        0 -> {error, no_separator};
        Pos when Pos < 2 -> {error, hrp_too_short};
        Pos ->
            Hrp = string:substr(WorkStr, 1, Pos - 1),
            DataPart = string:substr(WorkStr, Pos + 1),
            case length(DataPart) < 6 of
                true -> {error, too_short};
                false ->
                    case decode_bech32_chars(DataPart) of
                        {error, _} = E -> E;
                        {ok, Values} ->
                            Expanded = hrp_expand(Hrp),
                            case bech32_verify_checksum(Expanded, Values, Spec) of
                                true ->
                                    DataLen = length(Values) - 6,
                                    Data = lists:sublist(Values, DataLen),
                                    {ok, {Hrp, Data}};
                                false ->
                                    {error, bad_checksum}
                            end
                    end
            end
    end.

hrp_expand(Hrp) ->
    High = [C bsr 5 || C <- Hrp],
    Low = [C band 31 || C <- Hrp],
    High ++ [0] ++ Low.

bech32_polymod(Values) ->
    lists:foldl(fun(V, Chk) ->
        B = Chk bsr 25,
        Chk1 = ((Chk band 16#1ffffff) bsl 5) bxor V,
        Gens = ?BECH32_GENERATORS,
        lists:foldl(fun({I, Gen}, Acc) ->
            case (B bsr I) band 1 of
                1 -> Acc bxor Gen;
                0 -> Acc
            end
        end, Chk1, lists:zip(lists:seq(0, 4), Gens))
    end, 1, Values).

bech32_create_checksum(HrpExpanded, Data, Spec) ->
    Values = HrpExpanded ++ Data ++ [0, 0, 0, 0, 0, 0],
    Polymod = bech32_polymod(Values) bxor Spec,
    [(Polymod bsr (5 * (5 - I))) band 31 || I <- lists:seq(0, 5)].

bech32_verify_checksum(HrpExpanded, Data, Spec) ->
    bech32_polymod(HrpExpanded ++ Data) =:= Spec.

decode_bech32_chars(Chars) ->
    decode_bech32_chars(Chars, []).

decode_bech32_chars([], Acc) ->
    {ok, lists:reverse(Acc)};
decode_bech32_chars([C | Rest], Acc) ->
    Charset = ?BECH32_CHARSET,
    case string:chr(Charset, C) of
        0 -> {error, {invalid_bech32_char, C}};
        Pos -> decode_bech32_chars(Rest, [Pos - 1 | Acc])
    end.

%%% -------------------------------------------------------------------
%%% Internal: Bit conversion (8-to-5 and 5-to-8)
%%% -------------------------------------------------------------------

-spec convert_bits([integer()], pos_integer(), pos_integer(), boolean()) ->
    [integer()] | error.
convert_bits(Data, FromBits, ToBits, Pad) ->
    MaxV = (1 bsl ToBits) - 1,
    convert_bits(Data, FromBits, ToBits, Pad, MaxV, 0, 0, []).

convert_bits([], _FromBits, ToBits, Pad, MaxV, Acc, Bits, Ret) ->
    if
        Pad andalso Bits > 0 ->
            lists:reverse([((Acc bsl (ToBits - Bits)) band MaxV) | Ret]);
        Pad ->
            lists:reverse(Ret);
        Bits > 0 andalso ((Acc bsl (ToBits - Bits)) band MaxV) =/= 0 ->
            error;
        true ->
            lists:reverse(Ret)
    end;
convert_bits([V | Rest], FromBits, ToBits, Pad, MaxV, Acc, Bits, Ret) ->
    case V < 0 orelse (V bsr FromBits) =/= 0 of
        true -> error;
        false ->
            Acc1 = (Acc bsl FromBits) bor V,
            Bits1 = Bits + FromBits,
            {Ret1, Acc2, Bits2} = extract_bits(Acc1, Bits1, ToBits, MaxV, Ret),
            convert_bits(Rest, FromBits, ToBits, Pad, MaxV, Acc2, Bits2, Ret1)
    end.

extract_bits(Acc, Bits, ToBits, MaxV, Ret) when Bits >= ToBits ->
    Bits1 = Bits - ToBits,
    Val = (Acc bsr Bits1) band MaxV,
    extract_bits(Acc, Bits1, ToBits, MaxV, [Val | Ret]);
extract_bits(Acc, Bits, _ToBits, _MaxV, Ret) ->
    {Ret, Acc, Bits}.

%%% -------------------------------------------------------------------
%%% Internal: SegWit address decode
%%% -------------------------------------------------------------------

try_decode_segwit(Address, Network) ->
    ExpectedHrp = case Network of
        mainnet -> "bc";
        testnet -> "tb"
    end,
    %% try bech32 first, then bech32m
    case try_decode_segwit_variant(Address, ExpectedHrp) of
        {ok, _} = Result -> Result;
        {error, _} -> {error, not_segwit}
    end.

try_decode_segwit_variant(Address, ExpectedHrp) ->
    %% try both bech32 and bech32m, verify version matches encoding
    case bech32_decode(Address) of
        {ok, {Hrp, [WitVer | Data5]}} when Hrp =:= ExpectedHrp, WitVer =:= 0 ->
            decode_witness_program(WitVer, Data5);
        _ ->
            case bech32m_decode(Address) of
                {ok, {Hrp, [WitVer | Data5]}} when Hrp =:= ExpectedHrp,
                                                     WitVer >= 1,
                                                     WitVer =< 16 ->
                    decode_witness_program(WitVer, Data5);
                {ok, _} ->
                    {error, invalid_witness_version};
                {error, _} = E -> E
            end
    end.

decode_witness_program(WitVer, Data5) ->
    case convert_bits(Data5, 5, 8, false) of
        error -> {error, invalid_program};
        Program when length(Program) < 2 -> {error, program_too_short};
        Program when length(Program) > 40 -> {error, program_too_long};
        Program ->
            %% witness v0 must be 20 or 32 bytes
            ProgramLen = length(Program),
            case WitVer =:= 0 andalso ProgramLen =/= 20 andalso ProgramLen =/= 32 of
                true -> {error, invalid_v0_program_length};
                false ->
                    ProgramBin = list_to_binary(Program),
                    OpVer = case WitVer of
                        0 -> 16#00;
                        N -> 16#50 + N
                    end,
                    Script = <<OpVer:8, ProgramLen:8, ProgramBin/binary>>,
                    {ok, Script}
            end
    end.

%%% -------------------------------------------------------------------
%%% Internal: Base58 version → script
%%% -------------------------------------------------------------------

address_version_to_script(16#00, Hash, mainnet) when byte_size(Hash) =:= 20 ->
    %% mainnet P2PKH
    {ok, <<16#76, 16#a9, 16#14, Hash/binary, 16#88, 16#ac>>};
address_version_to_script(16#6f, Hash, testnet) when byte_size(Hash) =:= 20 ->
    %% testnet P2PKH
    {ok, <<16#76, 16#a9, 16#14, Hash/binary, 16#88, 16#ac>>};
address_version_to_script(16#05, Hash, mainnet) when byte_size(Hash) =:= 20 ->
    %% mainnet P2SH
    {ok, <<16#a9, 16#14, Hash/binary, 16#87>>};
address_version_to_script(16#c4, Hash, testnet) when byte_size(Hash) =:= 20 ->
    %% testnet P2SH
    {ok, <<16#a9, 16#14, Hash/binary, 16#87>>};
address_version_to_script(_, _, _) ->
    {error, unknown_version}.
