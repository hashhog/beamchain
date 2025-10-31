-module(beamchain_address).

%% Base58Check
-export([base58check_encode/2, base58check_decode/1]).

%%% -------------------------------------------------------------------
%%% Base58 alphabet
%%% -------------------------------------------------------------------

-define(BASE58_ALPHABET, "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz").

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
