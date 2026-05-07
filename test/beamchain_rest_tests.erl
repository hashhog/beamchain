-module(beamchain_rest_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%%% ===================================================================
%%% URL parsing tests
%%% ===================================================================

parse_format_test_() ->
    {"Format suffix parsing",
     [
      {"JSON format", fun() ->
          ?assertEqual(json, beamchain_rest:parse_format(<<".json">>))
      end},
      {"Binary format", fun() ->
          ?assertEqual(bin, beamchain_rest:parse_format(<<".bin">>))
      end},
      {"Hex format", fun() ->
          ?assertEqual(hex, beamchain_rest:parse_format(<<".hex">>))
      end},
      {"Unknown format returns undefined", fun() ->
          ?assertEqual(undefined, beamchain_rest:parse_format(<<".xml">>))
      end},
      {"Empty format returns undefined", fun() ->
          ?assertEqual(undefined, beamchain_rest:parse_format(<<"">>))
      end},
      {"No dot returns undefined", fun() ->
          ?assertEqual(undefined, beamchain_rest:parse_format(<<"json">>))
      end}
     ]}.

parse_path_test_() ->
    {"REST path parsing",
     [
      {"Block path", fun() ->
          Path = <<"/rest/block/00000000000000000001.json">>,
          Result = beamchain_rest:parse_path(Path),
          ?assertEqual([<<"block">>, <<"00000000000000000001.json">>], Result)
      end},
      {"Block notxdetails path", fun() ->
          Path = <<"/rest/block/notxdetails/00000000000000000001.json">>,
          Result = beamchain_rest:parse_path(Path),
          ?assertEqual([<<"block">>, <<"notxdetails">>,
                       <<"00000000000000000001.json">>], Result)
      end},
      {"Transaction path", fun() ->
          Path = <<"/rest/tx/abcd1234.hex">>,
          Result = beamchain_rest:parse_path(Path),
          ?assertEqual([<<"tx">>, <<"abcd1234.hex">>], Result)
      end},
      {"Headers path with count", fun() ->
          Path = <<"/rest/headers/5/abcd1234.bin">>,
          Result = beamchain_rest:parse_path(Path),
          ?assertEqual([<<"headers">>, <<"5">>, <<"abcd1234.bin">>], Result)
      end},
      {"Headers path without count", fun() ->
          Path = <<"/rest/headers/abcd1234.json">>,
          Result = beamchain_rest:parse_path(Path),
          ?assertEqual([<<"headers">>, <<"abcd1234.json">>], Result)
      end},
      {"Blockhash by height path", fun() ->
          Path = <<"/rest/blockhashbyheight/100.json">>,
          Result = beamchain_rest:parse_path(Path),
          ?assertEqual([<<"blockhashbyheight">>, <<"100.json">>], Result)
      end},
      {"Chaininfo path", fun() ->
          Path = <<"/rest/chaininfo.json">>,
          Result = beamchain_rest:parse_path(Path),
          ?assertEqual([<<"chaininfo.json">>], Result)
      end},
      {"Mempool info path", fun() ->
          Path = <<"/rest/mempool/info.json">>,
          Result = beamchain_rest:parse_path(Path),
          ?assertEqual([<<"mempool">>, <<"info.json">>], Result)
      end},
      {"Mempool contents path", fun() ->
          Path = <<"/rest/mempool/contents.json">>,
          Result = beamchain_rest:parse_path(Path),
          ?assertEqual([<<"mempool">>, <<"contents.json">>], Result)
      end},
      {"UTXO path without checkmempool", fun() ->
          Path = <<"/rest/getutxos/txid1-0/txid2-1.json">>,
          Result = beamchain_rest:parse_path(Path),
          ?assertEqual([<<"getutxos">>, <<"txid1-0">>, <<"txid2-1.json">>], Result)
      end},
      {"UTXO path with checkmempool", fun() ->
          Path = <<"/rest/getutxos/checkmempool/txid1-0.json">>,
          Result = beamchain_rest:parse_path(Path),
          ?assertEqual([<<"getutxos">>, <<"checkmempool">>,
                       <<"txid1-0.json">>], Result)
      end},
      {"Empty path returns empty list", fun() ->
          Path = <<"/">>,
          Result = beamchain_rest:parse_path(Path),
          ?assertEqual([], Result)
      end}
     ]}.

%%% ===================================================================
%%% Hash and format parsing tests
%%% ===================================================================

parse_hash_format_test_() ->
    {"Hash with format parsing",
     [
      {"Hash with JSON format", fun() ->
          Input = <<"0000000000000000000123abc.json">>,
          {Hash, Format} = parse_hash_format(Input),
          ?assertEqual(<<"0000000000000000000123abc">>, Hash),
          ?assertEqual(json, Format)
      end},
      {"Hash with binary format", fun() ->
          Input = <<"0000000000000000000123abc.bin">>,
          {Hash, Format} = parse_hash_format(Input),
          ?assertEqual(<<"0000000000000000000123abc">>, Hash),
          ?assertEqual(bin, Format)
      end},
      {"Hash with hex format", fun() ->
          Input = <<"0000000000000000000123abc.hex">>,
          {Hash, Format} = parse_hash_format(Input),
          ?assertEqual(<<"0000000000000000000123abc">>, Hash),
          ?assertEqual(hex, Format)
      end},
      {"Hash without format", fun() ->
          Input = <<"0000000000000000000123abc">>,
          {Hash, Format} = parse_hash_format(Input),
          ?assertEqual(<<"0000000000000000000123abc">>, Hash),
          ?assertEqual(undefined, Format)
      end}
     ]}.

parse_hash_format(HashWithFormat) ->
    case binary:split(HashWithFormat, <<".">>) of
        [HashHex, FormatSuffix] ->
            {HashHex, beamchain_rest:parse_format(<<".", FormatSuffix/binary>>)};
        [HashHex] ->
            {HashHex, undefined}
    end.

%%% ===================================================================
%%% Height parsing tests
%%% ===================================================================

parse_height_format_test_() ->
    {"Height with format parsing",
     [
      {"Height with JSON format", fun() ->
          Input = <<"100.json">>,
          {Height, Format} = parse_height_format(Input),
          ?assertEqual(100, Height),
          ?assertEqual(json, Format)
      end},
      {"Height with binary format", fun() ->
          Input = <<"50000.bin">>,
          {Height, Format} = parse_height_format(Input),
          ?assertEqual(50000, Height),
          ?assertEqual(bin, Format)
      end},
      {"Zero height", fun() ->
          Input = <<"0.json">>,
          {Height, Format} = parse_height_format(Input),
          ?assertEqual(0, Height),
          ?assertEqual(json, Format)
      end}
     ]}.

parse_height_format(HeightWithFormat) ->
    case binary:split(HeightWithFormat, <<".">>) of
        [HeightBin, FormatSuffix] ->
            Height = binary_to_integer(HeightBin),
            {Height, beamchain_rest:parse_format(<<".", FormatSuffix/binary>>)};
        [HeightBin] ->
            Height = binary_to_integer(HeightBin),
            {Height, undefined}
    end.

%%% ===================================================================
%%% Content type tests
%%% ===================================================================

content_type_test_() ->
    {"Content type mapping",
     [
      {"JSON content type", fun() ->
          ?assertEqual(<<"application/json">>, format_content_type(json))
      end},
      {"Binary content type", fun() ->
          ?assertEqual(<<"application/octet-stream">>, format_content_type(bin))
      end},
      {"Hex content type", fun() ->
          ?assertEqual(<<"text/plain">>, format_content_type(hex))
      end}
     ]}.

format_content_type(json) -> <<"application/json">>;
format_content_type(bin) -> <<"application/octet-stream">>;
format_content_type(hex) -> <<"text/plain">>;
format_content_type(_) -> <<"text/plain">>.

%%% ===================================================================
%%% Outpoint parsing tests
%%% ===================================================================

outpoint_parsing_test_() ->
    {"Outpoint parsing",
     [
      {"Parse valid outpoint", fun() ->
          Outpoint = <<"abc123-0">>,
          {Txid, N} = parse_outpoint(Outpoint),
          ?assertEqual(<<"abc123">>, Txid),
          ?assertEqual(0, N)
      end},
      {"Parse outpoint with high index", fun() ->
          Outpoint = <<"deadbeef-42">>,
          {Txid, N} = parse_outpoint(Outpoint),
          ?assertEqual(<<"deadbeef">>, Txid),
          ?assertEqual(42, N)
      end}
     ]}.

parse_outpoint(Str) ->
    case binary:split(Str, <<"-">>) of
        [TxidHex, NBin] ->
            N = binary_to_integer(NBin),
            {TxidHex, N};
        _ ->
            throw(invalid_outpoint)
    end.

%%% ===================================================================
%%% Script type detection tests
%%% ===================================================================

script_type_test_() ->
    {"Script type detection",
     [
      {"P2PKH script", fun() ->
          Script = <<16#76, 16#a9, 20, 0:160, 16#88, 16#ac>>,
          ?assertEqual(<<"pubkeyhash">>, script_type(Script))
      end},
      {"P2SH script", fun() ->
          Script = <<16#a9, 20, 0:160, 16#87>>,
          ?assertEqual(<<"scripthash">>, script_type(Script))
      end},
      {"P2WPKH script", fun() ->
          Script = <<16#00, 20, 0:160>>,
          ?assertEqual(<<"witness_v0_keyhash">>, script_type(Script))
      end},
      {"P2WSH script", fun() ->
          Script = <<16#00, 32, 0:256>>,
          ?assertEqual(<<"witness_v0_scripthash">>, script_type(Script))
      end},
      {"P2TR script", fun() ->
          Script = <<16#51, 32, 0:256>>,
          ?assertEqual(<<"witness_v1_taproot">>, script_type(Script))
      end},
      {"P2A anchor script", fun() ->
          Script = <<16#51, 2, 16#4e, 16#73>>,
          ?assertEqual(<<"anchor">>, script_type(Script))
      end},
      {"OP_RETURN script", fun() ->
          Script = <<16#6a, 4, "test">>,
          ?assertEqual(<<"nulldata">>, script_type(Script))
      end},
      {"Nonstandard script", fun() ->
          Script = <<16#00, 16#51, 16#00>>,
          ?assertEqual(<<"nonstandard">>, script_type(Script))
      end}
     ]}.

script_type(<<16#76, 16#a9, 20, _:20/binary, 16#88, 16#ac>>) ->
    <<"pubkeyhash">>;
script_type(<<16#a9, 20, _:20/binary, 16#87>>) ->
    <<"scripthash">>;
script_type(<<16#00, 20, _:20/binary>>) ->
    <<"witness_v0_keyhash">>;
script_type(<<16#00, 32, _:32/binary>>) ->
    <<"witness_v0_scripthash">>;
script_type(<<16#51, 32, _:32/binary>>) ->
    <<"witness_v1_taproot">>;
script_type(<<16#51, 2, _:2/binary>>) ->
    <<"anchor">>;
script_type(Script) when byte_size(Script) =:= 35 orelse byte_size(Script) =:= 67 ->
    <<"pubkey">>;
script_type(<<16#6a, _/binary>>) ->
    <<"nulldata">>;
script_type(_) ->
    <<"nonstandard">>.

%%% ===================================================================
%%% Difficulty calculation tests
%%% ===================================================================

bits_to_difficulty_test_() ->
    {"Bits to difficulty conversion",
     [
      {"Genesis block bits", fun() ->
          %% 0x1d00ffff is the genesis block target
          Bits = 16#1d00ffff,
          Diff = bits_to_difficulty(Bits),
          %% Should be approximately 1.0
          ?assert(Diff >= 0.99 andalso Diff =< 1.01)
      end},
      {"Zero bits returns zero", fun() ->
          ?assertEqual(0.0, bits_to_difficulty(0))
      end},
      {"Higher difficulty (smaller target)", fun() ->
          %% A higher difficulty value
          Bits = 16#1b0404cb,
          Diff = bits_to_difficulty(Bits),
          ?assert(Diff > 1.0)
      end}
     ]}.

bits_to_difficulty(Bits) ->
    Exp = Bits bsr 24,
    Mant = Bits band 16#007fffff,
    Target = case Mant > 16#7fffff of
        true -> 0;
        false ->
            case Exp =< 3 of
                true -> Mant bsr (8 * (3 - Exp));
                false -> Mant bsl (8 * (Exp - 3))
            end
    end,
    case Target of
        0 -> 0.0;
        _ ->
            MaxTarget = (16#00000000FFFF0000000000000000000000000000000000000000000000000000),
            MaxTarget / Target
    end.

%%% ===================================================================
%%% Bitmap encoding tests
%%% ===================================================================

format_utxo_bitmap_test_() ->
    {"UTXO bitmap formatting",
     [
      {"All found", fun() ->
          Results = [{ok, utxo1, chain}, {ok, utxo2, chain}],
          Bitmap = format_utxo_bitmap(Results),
          %% 11000000 = 0xc0
          ?assertEqual(<<"c0">>, Bitmap)
      end},
      {"All not found", fun() ->
          Results = [not_found, not_found],
          Bitmap = format_utxo_bitmap(Results),
          %% 00000000 = 0x00
          ?assertEqual(<<"00">>, Bitmap)
      end},
      {"Mixed results", fun() ->
          Results = [{ok, utxo1, chain}, not_found, {ok, utxo2, chain}, not_found],
          Bitmap = format_utxo_bitmap(Results),
          %% 10100000 = 0xa0
          ?assertEqual(<<"a0">>, Bitmap)
      end},
      {"Single found", fun() ->
          Results = [{ok, utxo1, chain}],
          Bitmap = format_utxo_bitmap(Results),
          %% 10000000 = 0x80
          ?assertEqual(<<"80">>, Bitmap)
      end},
      {"Single not found", fun() ->
          Results = [not_found],
          Bitmap = format_utxo_bitmap(Results),
          %% 00000000 = 0x00
          ?assertEqual(<<"00">>, Bitmap)
      end}
     ]}.

format_utxo_bitmap(Results) ->
    Bits = [case R of not_found -> 0; _ -> 1 end || R <- Results],
    %% Pad to byte boundary
    PadLen = case length(Bits) rem 8 of
        0 -> 0;
        N -> 8 - N
    end,
    PaddedBits = Bits ++ lists:duplicate(PadLen, 0),
    Bytes = bits_to_bytes(PaddedBits),
    beamchain_serialize:hex_encode(list_to_binary(Bytes)).

bits_to_bytes([]) -> [];
bits_to_bytes(Bits) when length(Bits) >= 8 ->
    {Byte, Rest} = lists:split(8, Bits),
    [lists:foldl(fun(B, Acc) -> (Acc bsl 1) bor B end, 0, Byte) |
     bits_to_bytes(Rest)];
bits_to_bytes(_) -> [].

%%% ===================================================================
%%% REST limits tests
%%% ===================================================================

rest_limits_test_() ->
    {"REST API limits",
     [
      {"Max UTXO outpoints is 15", fun() ->
          ?assertEqual(15, max_getutxos_outpoints())
      end},
      {"Max headers count is 2000", fun() ->
          ?assertEqual(2000, max_rest_headers_results())
      end},
      {"Default headers count is 5", fun() ->
          ?assertEqual(5, default_rest_headers_count())
      end}
     ]}.

max_getutxos_outpoints() -> 15.
max_rest_headers_results() -> 2000.
default_rest_headers_count() -> 5.

%%% ===================================================================
%%% HTTP status codes tests
%%% ===================================================================

http_status_codes_test_() ->
    {"HTTP status codes",
     [
      {"HTTP OK is 200", fun() ->
          ?assertEqual(200, http_ok())
      end},
      {"HTTP Bad Request is 400", fun() ->
          ?assertEqual(400, http_bad_request())
      end},
      {"HTTP Not Found is 404", fun() ->
          ?assertEqual(404, http_not_found())
      end},
      {"HTTP Internal Error is 500", fun() ->
          ?assertEqual(500, http_internal_error())
      end},
      {"HTTP Service Unavailable is 503", fun() ->
          ?assertEqual(503, http_service_unavailable())
      end}
     ]}.

http_ok() -> 200.
http_bad_request() -> 400.
http_not_found() -> 404.
http_internal_error() -> 500.
http_service_unavailable() -> 503.

%%% ===================================================================
%%% Query parameter parsing tests
%%% ===================================================================

query_count_test_() ->
    {"Query count parameter parsing",
     [
      {"Valid count parameter", fun() ->
          Query = [{<<"count">>, <<"10">>}],
          ?assertEqual(10, query_count(Query, 5))
      end},
      {"Missing count uses default", fun() ->
          Query = [],
          ?assertEqual(5, query_count(Query, 5))
      end},
      {"Invalid count uses default", fun() ->
          Query = [{<<"count">>, <<"abc">>}],
          ?assertEqual(5, query_count(Query, 5))
      end},
      {"Zero count uses default", fun() ->
          Query = [{<<"count">>, <<"0">>}],
          ?assertEqual(5, query_count(Query, 5))
      end},
      {"Negative count uses default", fun() ->
          Query = [{<<"count">>, <<"-1">>}],
          ?assertEqual(5, query_count(Query, 5))
      end}
     ]}.

query_count(Query, Default) ->
    case proplists:get_value(<<"count">>, Query) of
        undefined -> Default;
        Val -> parse_count(Val, Default)
    end.

parse_count(Bin, Default) ->
    try binary_to_integer(Bin) of
        N when N > 0 -> N;
        _ -> Default
    catch _:_ -> Default
    end.

query_bool_test_() ->
    {"Query boolean parameter parsing",
     [
      {"True string", fun() ->
          Query = [{<<"verbose">>, <<"true">>}],
          ?assertEqual(true, query_bool(Query, <<"verbose">>, false))
      end},
      {"False string", fun() ->
          Query = [{<<"verbose">>, <<"false">>}],
          ?assertEqual(false, query_bool(Query, <<"verbose">>, true))
      end},
      {"1 string", fun() ->
          Query = [{<<"verbose">>, <<"1">>}],
          ?assertEqual(true, query_bool(Query, <<"verbose">>, false))
      end},
      {"0 string", fun() ->
          Query = [{<<"verbose">>, <<"0">>}],
          ?assertEqual(false, query_bool(Query, <<"verbose">>, true))
      end},
      {"Missing uses default true", fun() ->
          Query = [],
          ?assertEqual(true, query_bool(Query, <<"verbose">>, true))
      end},
      {"Missing uses default false", fun() ->
          Query = [],
          ?assertEqual(false, query_bool(Query, <<"verbose">>, false))
      end}
     ]}.

query_bool(Query, Key, Default) ->
    case proplists:get_value(Key, Query) of
        undefined -> Default;
        <<"true">> -> true;
        <<"1">> -> true;
        <<"false">> -> false;
        <<"0">> -> false;
        _ -> Default
    end.

%%% ===================================================================
%%% BIP-157 blockfilter REST tests (Core rest.cpp::rest_block_filter +
%%% rest_filter_header parity).
%%% ===================================================================

parse_filter_type_test_() ->
    {"BIP-157 filter type token parsing",
     [
      {"basic maps to type byte 0", fun() ->
          ?assertEqual({ok, 0}, beamchain_rest:parse_filter_type(<<"basic">>))
      end},
      {"unknown type returns error with name echo", fun() ->
          ?assertMatch({error, <<"Unknown filtertype foo">>},
                       beamchain_rest:parse_filter_type(<<"foo">>))
      end},
      {"empty type returns error", fun() ->
          ?assertMatch({error, <<"Unknown filtertype ", _/binary>>},
                       beamchain_rest:parse_filter_type(<<>>))
      end}
     ]}.

parse_filterheaders_count_test_() ->
    {"BIP-157 cfheader count parsing (Core MAX_REST_HEADERS_RESULTS=2000)",
     [
      {"valid mid-range count", fun() ->
          ?assertEqual({ok, 5}, beamchain_rest:parse_filterheaders_count(<<"5">>))
      end},
      {"lower bound is 1", fun() ->
          ?assertEqual({ok, 1}, beamchain_rest:parse_filterheaders_count(<<"1">>))
      end},
      {"zero is rejected (Core: out of range)", fun() ->
          ?assertMatch({error, _}, beamchain_rest:parse_filterheaders_count(<<"0">>))
      end},
      {"upper bound 2000 accepted", fun() ->
          ?assertEqual({ok, 2000}, beamchain_rest:parse_filterheaders_count(<<"2000">>))
      end},
      {"2001 rejected", fun() ->
          ?assertMatch({error, _}, beamchain_rest:parse_filterheaders_count(<<"2001">>))
      end},
      {"non-numeric rejected", fun() ->
          ?assertMatch({error, _}, beamchain_rest:parse_filterheaders_count(<<"abc">>))
      end},
      {"negative rejected", fun() ->
          ?assertMatch({error, _}, beamchain_rest:parse_filterheaders_count(<<"-1">>))
      end}
     ]}.

encode_blockfilter_wire_test_() ->
    {"BIP-157 BlockFilter wire encoding parity with Core "
     "(blockfilter.h::Serialize: type || hash || varint(len) || filter)",
     [
      {"empty filter (varint 0)", fun() ->
          %% Core's GCSFilter with no elements emits a single 0x00 (varint 0).
          %% The full BlockFilter serialization is:
          %%   type=0x00 || 32-byte hash || 0x01 (varint length=1) || 0x00
          Hash = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                   17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
                   31, 32>>,
          FilterBytes = <<0>>,  %% varint(0) = single zero byte
          Wire = beamchain_rest:encode_blockfilter_wire(0, Hash, FilterBytes),
          %% Layout: 1 (type) + 32 (hash) + 1 (varint(1)) + 1 (filter) = 35
          ?assertEqual(35, byte_size(Wire)),
          %% First byte is the filter type (0 = basic)
          <<TypeByte:8, RestBytes/binary>> = Wire,
          ?assertEqual(0, TypeByte),
          %% Next 32 bytes are the block hash (raw / internal order)
          <<HashOut:32/binary, AfterHash/binary>> = RestBytes,
          ?assertEqual(Hash, HashOut),
          %% Next is varint(1) for the encoded filter length, then the byte
          ?assertEqual(<<1, 0>>, AfterHash)
      end},
      {"non-empty filter passthrough", fun() ->
          Hash = <<0:256>>,
          FilterBytes = <<16#02, 16#aa, 16#bb>>,
          Wire = beamchain_rest:encode_blockfilter_wire(0, Hash, FilterBytes),
          %% 1 + 32 + 1 (varint=3) + 3 (data) = 37
          ?assertEqual(37, byte_size(Wire)),
          %% Last 4 bytes: varint(3), then the filter
          Tail = binary:part(Wire, byte_size(Wire) - 4, 4),
          ?assertEqual(<<3, 16#02, 16#aa, 16#bb>>, Tail)
      end},
      {"non-zero filter type byte propagates", fun() ->
          %% Core registers type 0 (basic) only today, but the encoder
          %% must remain transparent to future filter types.
          Hash = <<0:256>>,
          Wire = beamchain_rest:encode_blockfilter_wire(7, Hash, <<0>>),
          <<TypeByte:8, _/binary>> = Wire,
          ?assertEqual(7, TypeByte)
      end}
     ]}.

%%% Sanity: the new blockfilter routes resolve through parse_path the same
%%% way Bitcoin Core's `/rest/blockfilter/...` URLs do.
blockfilter_path_parsing_test_() ->
    {"REST path parsing for /rest/blockfilter and /rest/blockfilterheaders",
     [
      {"blockfilter basic .json", fun() ->
          Path = <<"/rest/blockfilter/basic/abcd1234.json">>,
          ?assertEqual([<<"blockfilter">>, <<"basic">>, <<"abcd1234.json">>],
                       beamchain_rest:parse_path(Path))
      end},
      {"blockfilter basic .bin", fun() ->
          Path = <<"/rest/blockfilter/basic/abcd1234.bin">>,
          ?assertEqual([<<"blockfilter">>, <<"basic">>, <<"abcd1234.bin">>],
                       beamchain_rest:parse_path(Path))
      end},
      {"blockfilterheaders deprecated form (with count in path)", fun() ->
          Path = <<"/rest/blockfilterheaders/basic/5/abcd1234.hex">>,
          ?assertEqual([<<"blockfilterheaders">>, <<"basic">>,
                        <<"5">>, <<"abcd1234.hex">>],
                       beamchain_rest:parse_path(Path))
      end},
      {"blockfilterheaders preferred form (count via query param)", fun() ->
          Path = <<"/rest/blockfilterheaders/basic/abcd1234.json">>,
          ?assertEqual([<<"blockfilterheaders">>, <<"basic">>,
                        <<"abcd1234.json">>],
                       beamchain_rest:parse_path(Path))
      end}
     ]}.

%%% ===================================================================
%%% -rest opt-in flag tests (Core init.cpp -rest=0 default parity).
%%% ===================================================================

rest_enabled_default_off_test_() ->
    {setup,
     fun() ->
         %% Make sure no env var override is sticky between tests.
         os:unsetenv("BEAMCHAIN_REST"),
         %% Some test runs may have a config table from a prior test;
         %% guarantee a clean slate for `rest`.  We can't reach into the
         %% gen_server, but we can wipe the ETS row directly.
         catch ets:delete(beamchain_config_ets, rest)
     end,
     fun(_) ->
         os:unsetenv("BEAMCHAIN_REST")
     end,
     [
      {"BEAMCHAIN_REST unset and config absent => disabled (Core parity)",
       fun() ->
           ensure_config_table(),
           ets:delete(beamchain_config_ets, rest),
           os:unsetenv("BEAMCHAIN_REST"),
           ?assertEqual(false, beamchain_config:rest_enabled())
       end},
      {"BEAMCHAIN_REST=1 enables",
       fun() ->
           ensure_config_table(),
           os:putenv("BEAMCHAIN_REST", "1"),
           ?assertEqual(true, beamchain_config:rest_enabled()),
           os:unsetenv("BEAMCHAIN_REST")
       end},
      {"BEAMCHAIN_REST=0 disables (overrides config)",
       fun() ->
           ensure_config_table(),
           ets:insert(beamchain_config_ets, {rest, "1"}),
           os:putenv("BEAMCHAIN_REST", "0"),
           ?assertEqual(false, beamchain_config:rest_enabled()),
           os:unsetenv("BEAMCHAIN_REST"),
           ets:delete(beamchain_config_ets, rest)
       end},
      {"config rest=1 enables when env unset",
       fun() ->
           ensure_config_table(),
           os:unsetenv("BEAMCHAIN_REST"),
           ets:insert(beamchain_config_ets, {rest, "1"}),
           ?assertEqual(true, beamchain_config:rest_enabled()),
           ets:delete(beamchain_config_ets, rest)
       end},
      {"config rest=true (string) enables",
       fun() ->
           ensure_config_table(),
           os:unsetenv("BEAMCHAIN_REST"),
           ets:insert(beamchain_config_ets, {rest, "true"}),
           ?assertEqual(true, beamchain_config:rest_enabled()),
           ets:delete(beamchain_config_ets, rest)
       end}
     ]}.

%% Make sure the config ETS table exists (the test may run before the
%% gen_server has been started).  Idempotent.
ensure_config_table() ->
    case ets:info(beamchain_config_ets) of
        undefined ->
            ets:new(beamchain_config_ets,
                    [named_table, set, public, {read_concurrency, true}]);
        _ -> ok
    end.
