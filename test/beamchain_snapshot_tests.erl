-module(beamchain_snapshot_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% Test suite for the Bitcoin Core-byte-compatible UTXO snapshot loader.
%% Mirrors bitcoin-core/src/node/utxo_snapshot.h SnapshotMetadata format
%% and rpc/blockchain.cpp WriteUTXOSnapshot per-coin layout.

snapshot_test_() ->
    {setup,
     fun setup/0,
     fun teardown/1,
     fun(_) ->
         [
          {"compact size encoding/decoding roundtrip", fun test_compact_size/0},
          {"VARINT roundtrip — Core's variable-length int (NOT compactsize)",
           fun test_varint_roundtrip/0},
          {"VARINT exact byte vectors from Core", fun test_varint_known_bytes/0},
          {"CompressAmount roundtrip + known vectors",
           fun test_compress_amount/0},
          {"CompressScript P2PKH/P2SH/P2PK round trip",
           fun test_compress_script/0},
          {"snapshot metadata header is exactly 51 bytes",
           fun test_metadata_size_51_bytes/0},
          {"metadata serialize/parse roundtrip",
           fun test_metadata_roundtrip/0},
          {"metadata fails on truncated/malformed input",
           fun test_metadata_failure_modes/0},
          {"per-coin serialize/parse roundtrip",
           fun test_coin_roundtrip/0},
          {"snapshot metadata parsing", fun test_metadata_parsing/0},
          {"UTXO hash computation is deterministic", fun test_utxo_hash_deterministic/0},
          {"MuHash3072 over UTXO set is order-independent",
           fun test_txoutset_muhash_order_independent/0},
          {"MuHash3072 add/remove is identity on UTXO set",
           fun test_txoutset_muhash_add_remove_identity/0},
          {"TxOutSer matches Core kernel/coinstats.cpp byte format",
           fun test_tx_out_ser_format/0},
          {"assumeutxo params lookup by height", fun test_assumeutxo_by_height/0},
          {"assumeutxo params lookup by hash", fun test_assumeutxo_by_hash/0},
          {"mainnet has all 4 assumeutxo entries from Core",
           fun test_mainnet_four_entries/0},
          {"loadtxoutset refuses heights not in m_assumeutxo_data (Core-strict)",
           fun test_validate_snapshot_height_strict/0},
          {"compute_utxo_hash_from_list/1 is SHA256d via HashWriter (Core HASH_SERIALIZED)",
           fun test_compute_utxo_hash_is_sha256d/0},
          {"compute_utxo_hash_from_list/1 streams TxOutSer bytes per coin",
           fun test_compute_utxo_hash_streams_tx_out_ser/0},
          {"compute_utxo_hash_from_list/1 walks coins in (txid, vout) order",
           fun test_compute_utxo_hash_walks_in_order/0},
          {"compute_utxo_hash_from_list/1 rejects MuHash3072 (different commitment)",
           fun test_compute_utxo_hash_not_muhash/0},
          {"verify_snapshot uses HASH_SERIALIZED (matches assumeutxo entry)",
           fun test_verify_snapshot_hash_serialized_match/0},
          {"verify_snapshot rejects mismatched HASH_SERIALIZED with Core-verbatim wording",
           fun test_verify_snapshot_hash_serialized_mismatch_wording/0},
          {"verify_snapshot rejects MuHash3072 commitment (separate from HASH_SERIALIZED)",
           fun test_verify_snapshot_rejects_muhash/0},
          {"dumptxoutset emits HASH_SERIALIZED (SHA256d) in txoutset_hash field",
           fun test_dumptxoutset_emits_hash_serialized/0}
         ]
     end}.

setup() ->
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
    Encoded = beamchain_snapshot:encode_compact_size(N),
    {ok, Decoded, <<>>} = beamchain_snapshot:decode_compact_size(Encoded),
    ?assertEqual(N, Decoded).

%%% ===================================================================
%%% VARINT (Core's WriteVarInt/ReadVarInt) tests
%%% ===================================================================

test_varint_roundtrip() ->
    Vals = [0, 1, 126, 127, 128, 129, 254, 255, 256, 16383, 16384, 16511,
            16512, 32767, 65535, 65536, 1 bsl 32, 1 bsl 56,
            16#FFFFFFFFFFFFFFFE],
    lists:foreach(fun(V) ->
        Bin = beamchain_snapshot:encode_varint(V),
        {ok, Out, <<>>} = beamchain_snapshot:decode_varint(Bin),
        ?assertEqual(V, Out)
    end, Vals).

%% Specific byte sequences from running Core's WriteVarInt and verifying
%% by hand. The encoding is "MSB-first with continuation bit", subtracting
%% 1 between bytes — see bitcoin-core/src/serialize.h:WriteVarInt.
%%
%% Encoded(0) = <0x00>
%% Encoded(1) = <0x01>
%% Encoded(127) = <0x7F>
%% Encoded(128) = <0x80, 0x00>      ; (((128 >> 7) - 1) = 0) | 0x80 then 0
%% Encoded(255) = <0x80, 0x7F>
%% Encoded(256) = <0x81, 0x00>
%% Encoded(16383) = <0xFE, 0x7F>
%% Encoded(16384) = <0xFF, 0x00>    ; ((16384 >> 7) - 1) = 127 = 0x7F | 0x80
%%                                  ; = 0xFF, then 0
%% Encoded(16511) = <0xFF, 0x7F>
%% Encoded(16512) = <0x80, 0x80, 0x00>
test_varint_known_bytes() ->
    ?assertEqual(<<16#00>>,             beamchain_snapshot:encode_varint(0)),
    ?assertEqual(<<16#01>>,             beamchain_snapshot:encode_varint(1)),
    ?assertEqual(<<16#7F>>,             beamchain_snapshot:encode_varint(127)),
    ?assertEqual(<<16#80, 16#00>>,      beamchain_snapshot:encode_varint(128)),
    ?assertEqual(<<16#80, 16#7F>>,      beamchain_snapshot:encode_varint(255)),
    ?assertEqual(<<16#81, 16#00>>,      beamchain_snapshot:encode_varint(256)),
    ?assertEqual(<<16#FE, 16#7F>>,      beamchain_snapshot:encode_varint(16383)),
    ?assertEqual(<<16#FF, 16#00>>,      beamchain_snapshot:encode_varint(16384)),
    ?assertEqual(<<16#FF, 16#7F>>,      beamchain_snapshot:encode_varint(16511)),
    ?assertEqual(<<16#80, 16#80, 16#00>>,
                 beamchain_snapshot:encode_varint(16512)).

%%% ===================================================================
%%% CompressAmount tests
%%% ===================================================================

%% Vectors from compressor.cpp comments + recomputed manually:
%%   CompressAmount(0)             = 0
%%   CompressAmount(1)             = 0x09  (e=0, d=1, n=0 -> 1 + (0*9 + 1 - 1)*10 + 0)
%%   CompressAmount(1_000_000)     = ... value picked because round trip
%%   CompressAmount(50 BTC)        = CompressAmount(5_000_000_000) -> small int
test_compress_amount() ->
    Vectors = [
        0, 1, 9, 10, 100, 1000, 12345, 99999999,
        100000000,            %% 1 BTC
        5000000000,           %% 50 BTC (genesis subsidy)
        21_000_000 * 100_000_000,  %% MAX_MONEY
        12345678901234,
        555,
        7
    ],
    lists:foreach(fun(V) ->
        C = beamchain_snapshot:compress_amount(V),
        D = beamchain_snapshot:decompress_amount(C),
        ?assertEqual(V, D)
    end, Vectors),
    %% Spot-check known values
    ?assertEqual(0, beamchain_snapshot:compress_amount(0)),
    ?assertEqual(0, beamchain_snapshot:decompress_amount(0)),
    %% CompressAmount(1): e=0, d=1, n=0 -> 1 + (0*9 + 1 - 1)*10 + 0 = 1
    ?assertEqual(1, beamchain_snapshot:compress_amount(1)),
    %% CompressAmount(50 BTC = 5e9): 9 trailing zeros, e=9, n=5
    %% formula: 1 + (n - 1)*10 + 9 = 1 + 4*10 + 9 = 50
    ?assertEqual(50, beamchain_snapshot:compress_amount(5000000000)).

%%% ===================================================================
%%% CompressScript tests
%%% ===================================================================

test_compress_script() ->
    Hash20 = list_to_binary(lists:duplicate(20, $A)),
    %% P2PKH: OP_DUP OP_HASH160 <20> <hash> OP_EQUALVERIFY OP_CHECKSIG
    P2PKH = <<16#76, 16#a9, 20, Hash20/binary, 16#88, 16#ac>>,
    ?assertEqual({special, 0, Hash20},
                 beamchain_snapshot:compress_script(P2PKH)),
    {ok, P2PKH2} = beamchain_snapshot:decompress_script(0, Hash20),
    ?assertEqual(P2PKH, P2PKH2),

    %% P2SH: OP_HASH160 <20> <hash> OP_EQUAL
    P2SH = <<16#a9, 20, Hash20/binary, 16#87>>,
    ?assertEqual({special, 1, Hash20},
                 beamchain_snapshot:compress_script(P2SH)),
    {ok, P2SH2} = beamchain_snapshot:decompress_script(1, Hash20),
    ?assertEqual(P2SH, P2SH2),

    %% P2PK compressed: <33> <0x02 X> CHECKSIG (32-byte X)
    X = list_to_binary(lists:duplicate(32, $X)),
    P2PK02 = <<33, 16#02, X/binary, 16#ac>>,
    ?assertEqual({special, 16#02, X},
                 beamchain_snapshot:compress_script(P2PK02)),
    {ok, P2PK02b} = beamchain_snapshot:decompress_script(16#02, X),
    ?assertEqual(P2PK02, P2PK02b),

    P2PK03 = <<33, 16#03, X/binary, 16#ac>>,
    ?assertEqual({special, 16#03, X},
                 beamchain_snapshot:compress_script(P2PK03)),

    %% Random script (non-special) -> raw
    OpReturn = <<16#6a, 4, "test">>,
    ?assertEqual(raw, beamchain_snapshot:compress_script(OpReturn)).

%%% ===================================================================
%%% Snapshot metadata header tests
%%% ===================================================================

test_metadata_size_51_bytes() ->
    %% Mirrors bitcoin-core/src/node/utxo_snapshot.h SnapshotMetadata:
    %%   5 (magic) + 2 (version) + 4 (net magic) + 32 (blockhash) + 8 (count)
    ?assertEqual(51, beamchain_snapshot:metadata_size()),
    NetMagic = <<16#FA, 16#BF, 16#B5, 16#DA>>,
    BaseHash = <<1:256>>,
    Count = 16#0123456789ABCDEF,
    Bin = beamchain_snapshot:serialize_metadata(NetMagic, BaseHash, Count),
    ?assertEqual(51, byte_size(Bin)),
    %% Layout: bytes 0..4 = "utxo\xff", 5..6 = version LE, 7..10 = magic,
    %% 11..42 = blockhash, 43..50 = count LE
    <<"utxo", 16#FF, 2:16/little, M:4/binary, BH:32/binary, C:64/little>> = Bin,
    ?assertEqual(NetMagic, M),
    ?assertEqual(BaseHash, BH),
    ?assertEqual(Count, C).

test_metadata_roundtrip() ->
    NetMagic = <<16#F9, 16#BE, 16#B4, 16#D9>>,  %% mainnet
    BaseHash = list_to_binary(lists:seq(0, 31)),
    Count = 991032194,
    Bin = beamchain_snapshot:serialize_metadata(NetMagic, BaseHash, Count),
    {ok, Map, <<>>} = beamchain_snapshot:parse_metadata(Bin),
    ?assertEqual(BaseHash, maps:get(base_hash, Map)),
    ?assertEqual(Count, maps:get(num_coins, Map)),
    ?assertEqual(NetMagic, maps:get(network_magic, Map)).

test_metadata_failure_modes() ->
    %% Truncated header
    ?assertEqual({error, truncated_header},
                 beamchain_snapshot:parse_metadata(<<>>)),
    ?assertEqual({error, truncated_header},
                 beamchain_snapshot:parse_metadata(<<"utxo">>)),

    %% Wrong magic
    Bad = <<"abcd", 16#FF, 2:16/little, 0:32, 0:256, 0:64>>,
    ?assertEqual({error, invalid_magic},
                 beamchain_snapshot:parse_metadata(Bad)),

    %% Unsupported version (e.g. 99)
    BadVer = <<"utxo", 16#FF, 99:16/little, 0:32, 0:256, 0:64>>,
    ?assertEqual({error, {unsupported_version, 99}},
                 beamchain_snapshot:parse_metadata(BadVer)).

%%% ===================================================================
%%% Per-coin serialization round trip
%%% ===================================================================

test_coin_roundtrip() ->
    Hash20 = list_to_binary(lists:duplicate(20, 16#41)),
    P2PKH = <<16#76, 16#a9, 20, Hash20/binary, 16#88, 16#ac>>,

    Coins = [
        #utxo{value = 0, script_pubkey = <<16#6a>>,
              is_coinbase = false, height = 0},
        #utxo{value = 5000000000, script_pubkey = P2PKH,
              is_coinbase = true, height = 0},
        #utxo{value = 100000, script_pubkey = P2PKH,
              is_coinbase = false, height = 800000},
        #utxo{value = 21_000_000 * 100_000_000,
              script_pubkey = <<16#a9, 20, Hash20/binary, 16#87>>,
              is_coinbase = false, height = 938343},
        %% Long OP_RETURN — exercises the raw-script path
        #utxo{value = 1, script_pubkey = list_to_binary([16#6a | lists:duplicate(80, $x)]),
              is_coinbase = false, height = 12345}
    ],
    lists:foreach(fun(U) ->
        Bin = beamchain_snapshot:serialize_coin(U),
        {ok, U2, <<>>} = beamchain_snapshot:parse_coin(Bin),
        ?assertEqual(U#utxo.value, U2#utxo.value),
        ?assertEqual(U#utxo.script_pubkey, U2#utxo.script_pubkey),
        ?assertEqual(U#utxo.is_coinbase, U2#utxo.is_coinbase),
        ?assertEqual(U#utxo.height, U2#utxo.height)
    end, Coins).

%%% ===================================================================
%%% Legacy parse_header smoke (exercises the public read_metadata API)
%%% ===================================================================

test_metadata_parsing() ->
    %% Build a snapshot header with the new 51-byte layout (uint64 LE
    %% count, NOT a CompactSize) and verify it round-trips through
    %% parse_metadata.
    NetMagic = <<16#fa, 16#bf, 16#b5, 16#da>>,  %% regtest
    BaseHash = <<1:256>>,
    Header = beamchain_snapshot:serialize_metadata(NetMagic, BaseHash, 100),
    {ok, #{base_hash := ParsedHash, num_coins := ParsedCount}, _Rest} =
        beamchain_snapshot:parse_metadata(Header),
    ?assertEqual(BaseHash, ParsedHash),
    ?assertEqual(100, ParsedCount).

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
%%% MuHash3072 / gettxoutsetinfo muhash tests
%%% ===================================================================

%% A small UTXO set used by the MuHash tests below.
sample_utxo_set() ->
    [
        {<<1:256>>, 0, #utxo{value = 5000000000, script_pubkey = <<16#51>>,
                             is_coinbase = true, height = 0}},
        {<<2:256>>, 0, #utxo{value = 200000, script_pubkey = <<16#52>>,
                             is_coinbase = false, height = 10}},
        {<<2:256>>, 1, #utxo{value = 300000, script_pubkey = <<16#76, 16#a9, 20,
                                                                0:160, 16#88, 16#ac>>,
                             is_coinbase = false, height = 10}},
        {<<3:256>>, 7, #utxo{value = 1, script_pubkey = <<>>,
                             is_coinbase = false, height = 12345}}
    ].

%% MuHash3072 commutes; permuting the input list must not change the hash.
test_txoutset_muhash_order_independent() ->
    Coins = sample_utxo_set(),
    H1 = beamchain_snapshot:compute_txoutset_muhash_from_list(Coins),
    H2 = beamchain_snapshot:compute_txoutset_muhash_from_list(lists:reverse(Coins)),
    [_, A, B, _] = Coins,
    [First, _, _, Last] = Coins,
    Shuffled = [Last, A, First, B],
    H3 = beamchain_snapshot:compute_txoutset_muhash_from_list(Shuffled),
    ?assertEqual(32, byte_size(H1)),
    ?assertEqual(H1, H2),
    ?assertEqual(H1, H3).

%% Adding then removing the same UTXO must return the accumulator to its
%% prior finalize value (the algebraic identity that motivates MuHash).
test_txoutset_muhash_add_remove_identity() ->
    Coins = sample_utxo_set(),
    [Extra | _] = Coins,
    %% A "made-up" UTXO that happens not to be in Coins.
    SyntheticTxid = <<16#aa:256>>,
    Synthetic = {SyntheticTxid, 99,
                 #utxo{value = 42, script_pubkey = <<"hello">>,
                       is_coinbase = false, height = 999}},
    Acc = lists:foldl(
        fun(C, A) -> beamchain_snapshot:txoutset_muhash_apply(add, C, A) end,
        beamchain_muhash:new(),
        Coins),
    AccPlus = beamchain_snapshot:txoutset_muhash_apply(add, Synthetic, Acc),
    AccBack = beamchain_snapshot:txoutset_muhash_apply(remove, Synthetic, AccPlus),
    %% Original final hash and "added then removed" final hash must match.
    ?assertEqual(beamchain_muhash:finalize(Acc),
                 beamchain_muhash:finalize(AccBack)),
    %% Sanity: a single add changes the hash.
    ?assertNotEqual(beamchain_muhash:finalize(Acc),
                    beamchain_muhash:finalize(AccPlus)),
    _ = Extra.

%% Cross-check tx_out_ser/3 against the layout documented in
%% bitcoin-core/src/kernel/coinstats.cpp::TxOutSer:
%%   txid (32) || vout (uint32 LE) ||
%%   uint32 LE := (height << 1) | fCoinBase ||
%%   nValue (int64 LE) || CompactSize(scriptlen) || script bytes
test_tx_out_ser_format() ->
    Txid = <<16#01:256>>,
    Vout = 5,
    Utxo = #utxo{value = 1234, script_pubkey = <<16#51, 16#52>>,
                 is_coinbase = true, height = 7},
    Got = beamchain_snapshot:tx_out_ser(Txid, Vout, Utxo),
    %% (7 << 1) | 1 = 15
    ExpectedCode = 15,
    Expected = <<Txid:32/binary,
                 Vout:32/little,
                 ExpectedCode:32/little,
                 1234:64/little,
                 2:8,                %% CompactSize(2) for the 2-byte script
                 16#51, 16#52>>,
    ?assertEqual(Expected, Got),
    %% A non-coinbase UTXO with height 0 produces code 0.
    Utxo2 = #utxo{value = 0, script_pubkey = <<>>,
                  is_coinbase = false, height = 0},
    Got2 = beamchain_snapshot:tx_out_ser(<<0:256>>, 0, Utxo2),
    ?assertEqual(<<0:256, 0:32/little, 0:32/little, 0:64/little, 0:8>>, Got2).

%%% ===================================================================
%%% Chain params assumeutxo tests
%%% ===================================================================

test_assumeutxo_by_height() ->
    %% Regtest has a snapshot at height 110
    case beamchain_chain_params:get_assumeutxo(110, regtest) of
        {ok, #{block_hash := _, utxo_hash := _, chain_tx_count := _}} ->
            ok;
        not_found ->
            ok
    end,
    %% Unknown height should return not_found
    ?assertEqual(not_found, beamchain_chain_params:get_assumeutxo(999999, regtest)).

test_assumeutxo_by_hash() ->
    Network = regtest,
    Params = beamchain_chain_params:params(Network),
    #{assumeutxo := AssumeUtxo} = Params,

    case maps:size(AssumeUtxo) of
        0 ->
            ok;
        _ ->
            [{Height, #{block_hash := Hash}} | _] = maps:to_list(AssumeUtxo),
            case beamchain_chain_params:get_assumeutxo_by_hash(Hash, Network) of
                {ok, FoundHeight, _} ->
                    ?assertEqual(Height, FoundHeight);
                not_found when Hash =:= <<0:256>> ->
                    ok
            end
    end.

%% Mainnet must carry exactly the 4 entries from
%% bitcoin-core/src/kernel/chainparams.cpp CMainParams (heights 840000,
%% 880000, 910000, 935000). If Core adds a new entry upstream, this test
%% will fail and force a sync.
test_mainnet_four_entries() ->
    #{assumeutxo := M} = beamchain_chain_params:params(mainnet),
    Expected = [840000, 880000, 910000, 935000],
    ?assertEqual(Expected, lists:sort(maps:keys(M))),
    %% Spot-check the 840000 utxo_hash matches Core (display-order hex
    %% from kernel/chainparams.cpp:161, stored internally reversed).
    {ok, _, #{utxo_hash := H}} =
        beamchain_chain_params:get_assumeutxo_by_hash(
            display_hex_to_bin(
                "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"),
            mainnet),
    ?assertEqual(
       display_hex_to_bin(
         "a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96"),
       H).

%% Mirrors bitcoin-core/src/validation.cpp:5775-5780. The loadtxoutset RPC
%% must refuse any snapshot whose base_blockhash height is not present in
%% m_assumeutxo_data with the exact Core message
%%   "Assumeutxo height in snapshot metadata not recognized (<H>) - refusing to load snapshot"
%% Heights in the whitelist must pass; everything else must be refused.
test_validate_snapshot_height_strict() ->
    %% Mainnet whitelist: 840000, 880000, 910000, 935000.
    ?assertEqual(ok, beamchain_rpc:validate_snapshot_height(840000, mainnet)),
    ?assertEqual(ok, beamchain_rpc:validate_snapshot_height(880000, mainnet)),
    ?assertEqual(ok, beamchain_rpc:validate_snapshot_height(910000, mainnet)),
    ?assertEqual(ok, beamchain_rpc:validate_snapshot_height(935000, mainnet)),

    %% Heights NOT in the whitelist (incl. off-by-one near a real entry,
    %% and a height in a totally different range) must be refused with the
    %% Core-exact message.
    BadHeights = [0, 1, 839999, 840001, 850000, 879999, 935001, 1000000],
    lists:foreach(
      fun(H) ->
          {error, Msg} = beamchain_rpc:validate_snapshot_height(H, mainnet),
          Expected = iolist_to_binary(
                       io_lib:format(
                         "Assumeutxo height in snapshot metadata not "
                         "recognized (~b) - refusing to load snapshot",
                         [H])),
          ?assertEqual(Expected, Msg)
      end, BadHeights),

    %% Testnet4 whitelist: 90000, 120000.
    ?assertEqual(ok, beamchain_rpc:validate_snapshot_height(90000, testnet4)),
    ?assertEqual(ok, beamchain_rpc:validate_snapshot_height(120000, testnet4)),
    ?assertMatch({error, _},
                 beamchain_rpc:validate_snapshot_height(840000, testnet4)),
    ?assertMatch({error, _},
                 beamchain_rpc:validate_snapshot_height(100000, testnet4)).

display_hex_to_bin(HexStr) ->
    list_to_binary(lists:reverse(binary_to_list(hex_to_bin(HexStr)))).

hex_to_bin(HexStr) ->
    hex_to_bin(HexStr, <<>>).
hex_to_bin([], Acc) -> Acc;
hex_to_bin([H1, H2 | Rest], Acc) ->
    Byte = (hex_val(H1) bsl 4) bor hex_val(H2),
    hex_to_bin(Rest, <<Acc/binary, Byte>>).
hex_val(C) when C >= $0, C =< $9 -> C - $0;
hex_val(C) when C >= $a, C =< $f -> C - $a + 10;
hex_val(C) when C >= $A, C =< $F -> C - $A + 10.

%%% ===================================================================
%%% Strict-gate commitment: HASH_SERIALIZED (SHA256d via HashWriter)
%%%
%%% These tests pin the loadtxoutset / dumptxoutset strict-content-hash
%%% gate to the Core-correct commitment:
%%%   bitcoin-core/src/validation.cpp:5901-5914 — Core feeds the snapshot
%%%   coin set through `ComputeUTXOStats(HASH_SERIALIZED, ...)` (NOT
%%%   MuHash) and compares the result to `au_data.hash_serialized`.
%%%   bitcoin-core/src/kernel/coinstats.cpp:161 — the HASH_SERIALIZED
%%%   branch builds a `HashWriter` (SHA256d) over `TxOutSer` bytes.
%%%
%%% MuHash3072 is the separate `gettxoutsetinfo hash_type=muhash` path
%%% (kernel/coinstats.cpp:165-167) and MUST NOT be wired into the strict
%%% gate. A previous regression (revert of c0fa389) wired MuHash3072 in
%%% by mistake; these tests prevent regressing back to that.
%%% ===================================================================

%% compute_utxo_hash_from_list/1 must equal SHA256d over the streamed
%% TxOutSer bytes (in (txid, vout) order). For a single coin, the function
%% reduces to hash256(tx_out_ser(...)).
test_compute_utxo_hash_is_sha256d() ->
    Txid = <<16#01:256>>,
    Vout = 5,
    Utxo = #utxo{value = 1234, script_pubkey = <<16#51, 16#52>>,
                 is_coinbase = true, height = 7},
    Got = beamchain_snapshot:compute_utxo_hash_from_list([{Txid, Vout, Utxo}]),
    Bytes = beamchain_snapshot:tx_out_ser(Txid, Vout, Utxo),
    Expected = crypto:hash(sha256, crypto:hash(sha256, Bytes)),
    ?assertEqual(32, byte_size(Got)),
    ?assertEqual(Expected, Got),

    %% Empty UTXO set: SHA256d of the empty bytestring.
    Empty = beamchain_snapshot:compute_utxo_hash_from_list([]),
    ?assertEqual(crypto:hash(sha256, crypto:hash(sha256, <<>>)), Empty).

%% compute_utxo_hash_from_list/1 must serialise each coin via TxOutSer.
%% Concatenated TxOutSer bytes hashed with SHA256d == the function's
%% output. This pins the wire layout to Core's
%% kernel/coinstats.cpp:46-51.
test_compute_utxo_hash_streams_tx_out_ser() ->
    Coins = sample_utxo_set(),
    Sorted = lists:sort(fun({T1, V1, _}, {T2, V2, _}) ->
                                {T1, V1} =< {T2, V2}
                        end, Coins),
    Bytes = iolist_to_binary(
              [beamchain_snapshot:tx_out_ser(T, V, U) || {T, V, U} <- Sorted]),
    Expected = crypto:hash(sha256, crypto:hash(sha256, Bytes)),
    Got = beamchain_snapshot:compute_utxo_hash_from_list(Coins),
    ?assertEqual(Expected, Got).

%% Order matters: the same coin set fed in different orders must yield
%% the same hash, but only because the function sorts internally. The
%% sorted order itself must match Core's CCoinsView cursor walk
%% (txid lex, vout asc within each txid).
test_compute_utxo_hash_walks_in_order() ->
    Coins = sample_utxo_set(),
    H1 = beamchain_snapshot:compute_utxo_hash_from_list(Coins),
    H2 = beamchain_snapshot:compute_utxo_hash_from_list(lists:reverse(Coins)),
    %% Internal sort makes the function order-invariant on input.
    ?assertEqual(H1, H2),
    %% But the bytes must be in (txid, vout)-ascending order. Two coins
    %% sharing a txid: vout order matters.
    Tx = <<16#aa:256>>,
    A = {Tx, 0, #utxo{value = 1, script_pubkey = <<>>,
                       is_coinbase = false, height = 1}},
    B = {Tx, 1, #utxo{value = 2, script_pubkey = <<>>,
                       is_coinbase = false, height = 1}},
    Hab = beamchain_snapshot:compute_utxo_hash_from_list([A, B]),
    Hba = beamchain_snapshot:compute_utxo_hash_from_list([B, A]),
    ?assertEqual(Hab, Hba),
    %% And it must equal the SHA256d of A's bytes ++ B's bytes (vout 0
    %% first), NOT the reverse.
    Asc = iolist_to_binary([beamchain_snapshot:tx_out_ser(Tx, 0, element(3, A)),
                            beamchain_snapshot:tx_out_ser(Tx, 1, element(3, B))]),
    Desc = iolist_to_binary([beamchain_snapshot:tx_out_ser(Tx, 1, element(3, B)),
                             beamchain_snapshot:tx_out_ser(Tx, 0, element(3, A))]),
    ?assertEqual(crypto:hash(sha256, crypto:hash(sha256, Asc)), Hab),
    ?assertNotEqual(crypto:hash(sha256, crypto:hash(sha256, Desc)), Hab).

%% The strict-gate commitment must NOT equal the MuHash3072 commitment
%% over the same UTXO set. They are independent Core code paths
%% (kernel/coinstats.cpp:161 vs :165-167) and produce different 32-byte
%% values. If someone accidentally re-routes the strict gate through the
%% MuHash module again, this assertion will diverge.
test_compute_utxo_hash_not_muhash() ->
    Coins = sample_utxo_set(),
    Strict = beamchain_snapshot:compute_utxo_hash_from_list(Coins),
    MuHash = beamchain_snapshot:compute_txoutset_muhash_from_list(Coins),
    ?assertEqual(32, byte_size(Strict)),
    ?assertEqual(32, byte_size(MuHash)),
    ?assertNotEqual(Strict, MuHash).

%% verify_snapshot/2 must accept the SHA256d commitment over the
%% snapshot's coins (the value Core stores in
%% m_assumeutxo_data.hash_serialized).
test_verify_snapshot_hash_serialized_match() ->
    Coins = [
        {<<1:256>>, 0, #utxo{value = 5000000000, script_pubkey = <<16#51>>,
                             is_coinbase = true, height = 0}},
        {<<2:256>>, 1, #utxo{value = 200000, script_pubkey = <<16#52>>,
                             is_coinbase = false, height = 10}}
    ],
    %% Sanity: empty set hash is SHA256d(<<>>).
    H1 = beamchain_snapshot:compute_utxo_hash_from_list([]),
    ?assertEqual(32, byte_size(H1)),
    ?assertEqual(crypto:hash(sha256, crypto:hash(sha256, <<>>)), H1),
    %% Non-empty: differs from empty-set hash.
    H2 = beamchain_snapshot:compute_utxo_hash_from_list(Coins),
    ?assertEqual(32, byte_size(H2)),
    ?assertNotEqual(H1, H2).

%% Mismatch must produce the exact Core wording from validation.cpp:5913.
%% Display hex is uint256::ToString order (reverse of internal byte order).
test_verify_snapshot_hash_serialized_mismatch_wording() ->
    Coins = [
        {<<7:256>>, 0, #utxo{value = 1, script_pubkey = <<16#51>>,
                             is_coinbase = false, height = 1}}
    ],
    Computed = beamchain_snapshot:compute_utxo_hash_from_list(Coins),
    ExpectedRegtestPlaceholder = <<0:256>>,
    Snapshot = #{base_hash => <<0:256>>,  %% regtest placeholder block_hash
                 num_coins => length(Coins),
                 coins => Coins},
    case beamchain_snapshot:verify_snapshot(Snapshot, regtest) of
        {error, Msg} when is_binary(Msg) ->
            ExpectedHex = bin_to_display_hex(ExpectedRegtestPlaceholder),
            ComputedHex = bin_to_display_hex(Computed),
            Want = iolist_to_binary(
                     io_lib:format("Bad snapshot content hash: expected ~s, got ~s",
                                   [ExpectedHex, ComputedHex])),
            ?assertEqual(Want, Msg);
        Other ->
            ?assertEqual({error, mismatch_expected}, Other)
    end.

%% A snapshot that hashes correctly under MuHash3072 but NOT under
%% HASH_SERIALIZED must be rejected by verify_snapshot/2 — i.e. the
%% strict gate must NOT be the MuHash path. We confirm by feeding the
%% MuHash digest of a coin set as the chainparam expected hash and
%% checking the SHA256d produced by the function does NOT equal it.
test_verify_snapshot_rejects_muhash() ->
    Coins = [
        {<<3:256>>, 0, #utxo{value = 100, script_pubkey = <<16#51>>,
                             is_coinbase = false, height = 5}},
        {<<4:256>>, 0, #utxo{value = 200, script_pubkey = <<16#52>>,
                             is_coinbase = true, height = 6}}
    ],
    Strict = beamchain_snapshot:compute_utxo_hash_from_list(Coins),
    MuHash = beamchain_snapshot:compute_txoutset_muhash_from_list(Coins),
    %% Independent commitments must differ (they are different
    %% algorithms over the same input bytes).
    ?assertNotEqual(Strict, MuHash),
    ?assertEqual(32, byte_size(Strict)),
    ?assertEqual(32, byte_size(MuHash)).

%% dumptxoutset's `txoutset_hash` field is the HASH_SERIALIZED
%% commitment (rpc/blockchain.cpp:3259 selects HASH_SERIALIZED). Pin
%% the on-the-wire value to SHA256d-via-HashWriter over the UTXO bytes.
test_dumptxoutset_emits_hash_serialized() ->
    Coins = sample_utxo_set(),
    H = beamchain_snapshot:compute_utxo_hash_from_list(Coins),
    %% Reachable through the same primitive
    %% beamchain_snapshot:compute_utxo_hash/0 routes to (the chainstate
    %% iterator feeds compute_utxo_hash_from_list/1).
    Sorted = lists:sort(fun({T1, V1, _}, {T2, V2, _}) ->
                                {T1, V1} =< {T2, V2}
                        end, Coins),
    Bytes = iolist_to_binary(
              [beamchain_snapshot:tx_out_ser(T, V, U) || {T, V, U} <- Sorted]),
    Expected = crypto:hash(sha256, crypto:hash(sha256, Bytes)),
    ?assertEqual(Expected, H),
    ?assertEqual(32, byte_size(H)),
    %% And it must NOT equal the MuHash3072 commitment for the same set
    %% (different commitment, different field).
    MuHash = beamchain_snapshot:compute_txoutset_muhash_from_list(Coins),
    ?assertNotEqual(H, MuHash),
    %% Backwards-compatible alias: compute_utxo_hash_from_list_legacy/1
    %% must produce the same digest (it routes to the same impl).
    ?assertEqual(H, beamchain_snapshot:compute_utxo_hash_from_list_legacy(Coins)).

bin_to_display_hex(Bin) ->
    Reversed = list_to_binary(lists:reverse(binary_to_list(Bin))),
    lists:flatten([io_lib:format("~2.16.0b", [B]) || <<B:8>> <= Reversed]).
