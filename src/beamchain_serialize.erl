-module(beamchain_serialize).

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% Varint
-export([encode_varint/1, decode_varint/1]).

%% Little-endian helpers
-export([encode_le32/1, decode_le32/1,
         encode_le64/1, decode_le64/1]).

%% Variable-length string/bytes
-export([encode_varstr/1, decode_varstr/1]).

%% Utility
-export([hex_encode/1, hex_decode/1]).

%%% -------------------------------------------------------------------
%%% Varint (CompactSize) encoding
%%% -------------------------------------------------------------------

-spec encode_varint(non_neg_integer()) -> binary().
encode_varint(N) when N >= 0, N =< 16#FC ->
    <<N:8>>;
encode_varint(N) when N =< 16#FFFF ->
    <<16#FD:8, N:16/little>>;
encode_varint(N) when N =< 16#FFFFFFFF ->
    <<16#FE:8, N:32/little>>;
encode_varint(N) when N =< 16#FFFFFFFFFFFFFFFF ->
    <<16#FF:8, N:64/little>>.

-spec decode_varint(binary()) -> {non_neg_integer(), binary()}.
decode_varint(<<16#FD:8, N:16/little, Rest/binary>>) ->
    {N, Rest};
decode_varint(<<16#FE:8, N:32/little, Rest/binary>>) ->
    {N, Rest};
decode_varint(<<16#FF:8, N:64/little, Rest/binary>>) ->
    {N, Rest};
decode_varint(<<N:8, Rest/binary>>) ->
    {N, Rest}.

%%% -------------------------------------------------------------------
%%% Little-endian integer helpers
%%% -------------------------------------------------------------------

-spec encode_le32(non_neg_integer()) -> binary().
encode_le32(N) -> <<N:32/little>>.

-spec decode_le32(binary()) -> {non_neg_integer(), binary()}.
decode_le32(<<N:32/little, Rest/binary>>) -> {N, Rest}.

-spec encode_le64(non_neg_integer()) -> binary().
encode_le64(N) -> <<N:64/little>>.

-spec decode_le64(binary()) -> {non_neg_integer(), binary()}.
decode_le64(<<N:64/little, Rest/binary>>) -> {N, Rest}.

%%% -------------------------------------------------------------------
%%% Variable-length string (varint length prefix + bytes)
%%% -------------------------------------------------------------------

-spec encode_varstr(binary()) -> binary().
encode_varstr(Bin) ->
    <<(encode_varint(byte_size(Bin)))/binary, Bin/binary>>.

-spec decode_varstr(binary()) -> {binary(), binary()}.
decode_varstr(Bin) ->
    {Len, Rest} = decode_varint(Bin),
    <<Str:Len/binary, Rest2/binary>> = Rest,
    {Str, Rest2}.

%%% -------------------------------------------------------------------
%%% Utility functions
%%% -------------------------------------------------------------------

-spec hex_encode(binary()) -> binary().
hex_encode(Bin) ->
    list_to_binary(lists:flatten(
        [io_lib:format("~2.16.0b", [B]) || <<B:8>> <= Bin]
    )).

-spec hex_decode(binary() | string()) -> binary().
hex_decode(Hex) when is_binary(Hex) ->
    hex_decode(binary_to_list(Hex));
hex_decode(Hex) when is_list(Hex) ->
    list_to_binary(hex_decode_pairs(Hex)).

hex_decode_pairs([]) -> [];
hex_decode_pairs([H1, H2 | Rest]) ->
    [list_to_integer([H1, H2], 16) | hex_decode_pairs(Rest)].
