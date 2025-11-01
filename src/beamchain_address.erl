-module(beamchain_address).

%% Base58Check
-export([base58check_encode/2, base58check_decode/1]).

%% Bech32 / Bech32m
-export([bech32_encode/2, bech32_decode/1,
         bech32m_encode/2, bech32m_decode/1]).

%% Bit conversion helpers
-export([convert_bits/4]).

%%% -------------------------------------------------------------------
%%% Base58 alphabet
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
%%% Bit conversion (8-to-5 and 5-to-8)
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
