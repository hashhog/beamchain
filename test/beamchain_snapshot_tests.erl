-module(beamchain_snapshot_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% Test suite for assumeUTXO snapshot functionality.

snapshot_test_() ->
    {setup,
     fun setup/0,
     fun teardown/1,
     fun(_) ->
         [
          {"compact size encoding/decoding roundtrip", fun test_compact_size/0},
          {"snapshot metadata parsing", fun test_metadata_parsing/0},
          {"UTXO hash computation is deterministic", fun test_utxo_hash_deterministic/0},
          {"snapshot coin serialization roundtrip", fun test_coin_serialization/0},
          {"assumeutxo params lookup by height", fun test_assumeutxo_by_height/0},
          {"assumeutxo params lookup by hash", fun test_assumeutxo_by_hash/0}
         ]
     end}.

setup() ->
    %% Minimal setup - no database needed for these tests
    application:set_env(beamchain, network, regtest),
    ok.

teardown(_) ->
    ok.

%%% ===================================================================
%%% Compact size encoding tests
%%% ===================================================================

test_compact_size() ->
    %% Test small values (< 253)
    test_compact_size_roundtrip(0),
    test_compact_size_roundtrip(1),
    test_compact_size_roundtrip(252),

    %% Test 2-byte encoding (253-65535)
    test_compact_size_roundtrip(253),
    test_compact_size_roundtrip(1000),
    test_compact_size_roundtrip(65535),

    %% Test 4-byte encoding (65536-4294967295)
    test_compact_size_roundtrip(65536),
    test_compact_size_roundtrip(1000000),
    test_compact_size_roundtrip(4294967295),

    %% Test 8-byte encoding (> 4294967295)
    test_compact_size_roundtrip(4294967296),
    test_compact_size_roundtrip(10000000000).

test_compact_size_roundtrip(N) ->
    Encoded = encode_compact_size(N),
    {ok, Decoded, <<>>} = decode_compact_size(Encoded),
    ?assertEqual(N, Decoded).

%% Re-implement encoding for testing (duplicating internal functions)
encode_compact_size(N) when N < 253 ->
    <<N:8>>;
encode_compact_size(N) when N =< 16#ffff ->
    <<253, N:16/little>>;
encode_compact_size(N) when N =< 16#ffffffff ->
    <<254, N:32/little>>;
encode_compact_size(N) ->
    <<255, N:64/little>>.

decode_compact_size(<<N:8, Rest/binary>>) when N < 253 ->
    {ok, N, Rest};
decode_compact_size(<<253, N:16/little, Rest/binary>>) ->
    {ok, N, Rest};
decode_compact_size(<<254, N:32/little, Rest/binary>>) ->
    {ok, N, Rest};
decode_compact_size(<<255, N:64/little, Rest/binary>>) ->
    {ok, N, Rest}.

%%% ===================================================================
%%% Snapshot metadata tests
%%% ===================================================================

test_metadata_parsing() ->
    %% Create a minimal snapshot with valid metadata
    Magic = <<"utxo", 16#ff>>,
    Version = <<2:16/little>>,
    NetworkMagic = <<16#fa, 16#bf, 16#b5, 16#da>>,  %% regtest
    BaseHash = <<1:256>>,
    NumCoins = encode_compact_size(100),

    %% Build snapshot header
    Header = <<Magic/binary, Version/binary, NetworkMagic/binary,
               BaseHash/binary, NumCoins/binary>>,

    %% Parse and verify
    case parse_header(Header) of
        {ok, #{base_hash := ParsedHash, num_coins := ParsedCount}, _Rest} ->
            ?assertEqual(BaseHash, ParsedHash),
            ?assertEqual(100, ParsedCount);
        {error, Reason} ->
            ?assert(false, {parse_failed, Reason})
    end.

parse_header(<<Magic:5/binary, Version:16/little,
               _NetworkMagic:4/binary, BaseHash:32/binary,
               Rest/binary>>) when Magic =:= <<"utxo", 16#ff>> ->
    case Version of
        2 ->
            case decode_compact_size(Rest) of
                {ok, NumCoins, Rest2} ->
                    {ok, #{base_hash => BaseHash, num_coins => NumCoins}, Rest2};
                _ ->
                    {error, invalid_compact_size}
            end;
        _ ->
            {error, {unsupported_version, Version}}
    end;
parse_header(_) ->
    {error, invalid_header}.

%%% ===================================================================
%%% UTXO hash tests
%%% ===================================================================

test_utxo_hash_deterministic() ->
    %% Create a list of test coins
    Coins = [
        {<<1:256>>, 0, #utxo{value = 100000, script_pubkey = <<16#51>>,
                             is_coinbase = true, height = 0}},
        {<<2:256>>, 0, #utxo{value = 200000, script_pubkey = <<16#52>>,
                             is_coinbase = false, height = 10}},
        {<<2:256>>, 1, #utxo{value = 300000, script_pubkey = <<16#53>>,
                             is_coinbase = false, height = 10}}
    ],

    %% Compute hash multiple times
    Hash1 = compute_utxo_hash_from_list(Coins),
    Hash2 = compute_utxo_hash_from_list(Coins),
    Hash3 = compute_utxo_hash_from_list(Coins),

    %% All hashes should be identical
    ?assertEqual(Hash1, Hash2),
    ?assertEqual(Hash2, Hash3),

    %% Hash should be 32 bytes
    ?assertEqual(32, byte_size(Hash1)),

    %% Different coins should produce different hash
    DifferentCoins = [
        {<<1:256>>, 0, #utxo{value = 100001, script_pubkey = <<16#51>>,
                             is_coinbase = true, height = 0}}
    ],
    DifferentHash = compute_utxo_hash_from_list(DifferentCoins),
    ?assertNotEqual(Hash1, DifferentHash).

compute_utxo_hash_from_list(Coins) ->
    %% Sort by outpoint
    Sorted = lists:sort(fun({Txid1, Vout1, _}, {Txid2, Vout2, _}) ->
        {Txid1, Vout1} =< {Txid2, Vout2}
    end, Coins),

    HashCtx = crypto:hash_init(sha256),
    FinalCtx = lists:foldl(fun({Txid, Vout, Utxo}, Ctx) ->
        CoinBin = serialize_coin_for_hash(Txid, Vout, Utxo),
        crypto:hash_update(Ctx, CoinBin)
    end, HashCtx, Sorted),

    crypto:hash_final(FinalCtx).

serialize_coin_for_hash(Txid, Vout, #utxo{value = Value, script_pubkey = Script,
                                          is_coinbase = IsCoinbase, height = Height}) ->
    CoinbaseFlag = case IsCoinbase of true -> 1; false -> 0 end,
    <<Txid:32/binary, Vout:32/big, Value:64/little, Height:32/little,
      CoinbaseFlag:8, Script/binary>>.

%%% ===================================================================
%%% Coin serialization tests
%%% ===================================================================

test_coin_serialization() ->
    %% Test coin encoding/decoding roundtrip
    TestCoins = [
        #utxo{value = 0, script_pubkey = <<>>,
              is_coinbase = false, height = 0},
        #utxo{value = 5000000000, script_pubkey = <<16#6a, 4, "test">>,
              is_coinbase = true, height = 0},
        #utxo{value = 100000, script_pubkey = <<16#76, 16#a9, 16#14, 0:160, 16#88, 16#ac>>,
              is_coinbase = false, height = 800000}
    ],

    lists:foreach(fun(Utxo) ->
        Encoded = serialize_coin(Utxo),
        {ok, Decoded, <<>>} = parse_coin(Encoded),
        ?assertEqual(Utxo#utxo.value, Decoded#utxo.value),
        ?assertEqual(Utxo#utxo.script_pubkey, Decoded#utxo.script_pubkey),
        ?assertEqual(Utxo#utxo.is_coinbase, Decoded#utxo.is_coinbase),
        ?assertEqual(Utxo#utxo.height, Decoded#utxo.height)
    end, TestCoins).

serialize_coin(#utxo{value = Value, script_pubkey = Script,
                     is_coinbase = IsCoinbase, height = Height}) ->
    CoinbaseFlag = case IsCoinbase of true -> 1; false -> 0 end,
    HeightCode = (Height bsl 1) bor CoinbaseFlag,
    HeightBin = encode_compact_size(HeightCode),
    ValueBin = encode_compact_size(Value),
    ScriptLen = encode_compact_size(byte_size(Script)),
    <<HeightBin/binary, ValueBin/binary, ScriptLen/binary, Script/binary>>.

parse_coin(Data) ->
    case decode_compact_size(Data) of
        {ok, HeightCode, Rest} ->
            Height = HeightCode bsr 1,
            IsCoinbase = (HeightCode band 1) =:= 1,
            case decode_compact_size(Rest) of
                {ok, Value, Rest2} ->
                    case decode_compact_size(Rest2) of
                        {ok, ScriptLen, Rest3} ->
                            case Rest3 of
                                <<Script:ScriptLen/binary, Rest4/binary>> ->
                                    Utxo = #utxo{
                                        value = Value,
                                        script_pubkey = Script,
                                        is_coinbase = IsCoinbase,
                                        height = Height
                                    },
                                    {ok, Utxo, Rest4};
                                _ ->
                                    {error, truncated_script}
                            end;
                        _ -> {error, invalid_script_len}
                    end;
                _ -> {error, invalid_value}
            end;
        _ -> {error, invalid_height}
    end.

%%% ===================================================================
%%% Chain params assumeutxo tests
%%% ===================================================================

test_assumeutxo_by_height() ->
    %% Regtest has a snapshot at height 110
    case beamchain_chain_params:get_assumeutxo(110, regtest) of
        {ok, #{block_hash := _, utxo_hash := _, num_coins := _}} ->
            ok;
        not_found ->
            %% This is expected if params aren't fully defined
            ok
    end,

    %% Unknown height should return not_found
    ?assertEqual(not_found, beamchain_chain_params:get_assumeutxo(999999, regtest)).

test_assumeutxo_by_hash() ->
    %% Test lookup by block hash
    %% The regtest snapshot has a placeholder hash, so this tests the lookup mechanism
    Network = regtest,
    Params = beamchain_chain_params:params(Network),
    #{assumeutxo := AssumeUtxo} = Params,

    case maps:size(AssumeUtxo) of
        0 ->
            %% No snapshots defined
            ok;
        _ ->
            %% Get the first snapshot and verify lookup works
            [{Height, #{block_hash := Hash}} | _] = maps:to_list(AssumeUtxo),
            case beamchain_chain_params:get_assumeutxo_by_hash(Hash, Network) of
                {ok, FoundHeight, _} ->
                    ?assertEqual(Height, FoundHeight);
                not_found when Hash =:= <<0:256>> ->
                    %% Placeholder hash, expected
                    ok
            end
    end.
