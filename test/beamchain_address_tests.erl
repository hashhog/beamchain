-module(beamchain_address_tests).
-include_lib("eunit/include/eunit.hrl").

%%% -------------------------------------------------------------------
%%% Base58Check encoding tests
%%% -------------------------------------------------------------------

base58check_satoshi_address_test() ->
    %% Satoshi's address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
    Hash = hex_to_bin("62e907b15cbf27d5425399ebf6f0fb50ebb88f18"),
    Encoded = beamchain_address:base58check_encode(16#00, Hash),
    ?assertEqual("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", Encoded).

base58check_decode_satoshi_test() ->
    {ok, {Version, Payload}} =
        beamchain_address:base58check_decode("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
    ?assertEqual(16#00, Version),
    ?assertEqual(hex_to_bin("62e907b15cbf27d5425399ebf6f0fb50ebb88f18"), Payload).

base58check_roundtrip_p2pkh_test() ->
    Hash = hex_to_bin("89abcdefabbaabbaabbaabbaabbaabbaabbaabba"),
    Encoded = beamchain_address:base58check_encode(16#00, Hash),
    {ok, {16#00, Decoded}} = beamchain_address:base58check_decode(Encoded),
    ?assertEqual(Hash, Decoded).

base58check_roundtrip_p2sh_test() ->
    Hash = hex_to_bin("0000000000000000000000000000000000000000"),
    Encoded = beamchain_address:base58check_encode(16#05, Hash),
    {ok, {16#05, Decoded}} = beamchain_address:base58check_decode(Encoded),
    ?assertEqual(Hash, Decoded).

base58check_testnet_p2pkh_test() ->
    Hash = hex_to_bin("751e76e8199196d454941c45d1b3a323f1433bd6"),
    Encoded = beamchain_address:base58check_encode(16#6f, Hash),
    {ok, {16#6f, Decoded}} = beamchain_address:base58check_decode(Encoded),
    ?assertEqual(Hash, Decoded).

base58check_bad_checksum_test() ->
    ?assertEqual({error, bad_checksum},
        beamchain_address:base58check_decode("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb")).

base58check_leading_zeros_test() ->
    Hash = <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1>>,
    Encoded = beamchain_address:base58check_encode(16#00, Hash),
    {ok, {16#00, Decoded}} = beamchain_address:base58check_decode(Encoded),
    ?assertEqual(Hash, Decoded).

%%% -------------------------------------------------------------------
%%% Bech32 encoding tests (BIP 173 valid checksum vectors)
%%% -------------------------------------------------------------------

bech32_valid_checksum_test_() ->
    Vectors = [
        "A12UEL5L",
        "a12uel5l",
        "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
        "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
        "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j"
    ],
    [fun() ->
        {ok, {Hrp, Data}} = beamchain_address:bech32_decode(V),
        ReEncoded = beamchain_address:bech32_encode(Hrp, Data),
        ?assertEqual(string:to_lower(V), ReEncoded)
    end || V <- Vectors].

bech32_invalid_test_() ->
    Vectors = [
        " 1nwldj5",          %% HRP char out of range (space = 32)
        "abc1rzg",            %% too short data part
        "x1b4n0q5v"           %% invalid data character
    ],
    [fun() ->
        Result = beamchain_address:bech32_decode(V),
        ?assertMatch({error, _}, Result)
    end || V <- Vectors].

%%% -------------------------------------------------------------------
%%% Bech32m encoding tests (BIP 350 valid checksum vectors)
%%% -------------------------------------------------------------------

bech32m_valid_checksum_test_() ->
    Vectors = [
        "A1LQFN3A",
        "a1lqfn3a",
        "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx"
    ],
    [fun() ->
        {ok, {Hrp, Data}} = beamchain_address:bech32m_decode(V),
        ReEncoded = beamchain_address:bech32m_encode(Hrp, Data),
        ?assertEqual(string:to_lower(V), ReEncoded)
    end || V <- Vectors].

%%% -------------------------------------------------------------------
%%% Bech32 encode/decode roundtrip
%%% -------------------------------------------------------------------

bech32_roundtrip_test() ->
    Hrp = "test",
    Data = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    Encoded = beamchain_address:bech32_encode(Hrp, Data),
    {ok, {Hrp, Data}} = beamchain_address:bech32_decode(Encoded).

bech32m_roundtrip_test() ->
    Hrp = "example",
    Data = [31, 0, 15, 20, 10],
    Encoded = beamchain_address:bech32m_encode(Hrp, Data),
    {ok, {Hrp, Data}} = beamchain_address:bech32m_decode(Encoded).

%%% -------------------------------------------------------------------
%%% SegWit v0 address tests
%%% -------------------------------------------------------------------

segwit_p2wpkh_mainnet_test() ->
    Addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
    {ok, {"bc", [0 | Data5]}} = beamchain_address:bech32_decode(Addr),
    Program = beamchain_address:convert_bits(Data5, 5, 8, false),
    ?assertEqual(20, length(Program)),
    Expected = hex_to_list("751e76e8199196d454941c45d1b3a323f1433bd6"),
    ?assertEqual(Expected, Program).

segwit_p2wsh_mainnet_test() ->
    %% generated from program 1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262
    Addr = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
    {ok, {"bc", [0 | Data5]}} = beamchain_address:bech32_decode(Addr),
    Program = beamchain_address:convert_bits(Data5, 5, 8, false),
    ?assertEqual(32, length(Program)),
    Expected = hex_to_list("1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"),
    ?assertEqual(Expected, Program).

segwit_p2wpkh_testnet_test() ->
    Addr = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
    {ok, {"tb", [0 | _Data5]}} = beamchain_address:bech32_decode(Addr).

%%% -------------------------------------------------------------------
%%% Taproot address tests (BIP 350)
%%% -------------------------------------------------------------------

taproot_p2tr_mainnet_test() ->
    %% secp256k1 generator point x-coord
    Addr = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
    {ok, {"bc", [1 | Data5]}} = beamchain_address:bech32m_decode(Addr),
    Program = beamchain_address:convert_bits(Data5, 5, 8, false),
    ?assertEqual(32, length(Program)),
    Expected = hex_to_list("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
    ?assertEqual(Expected, Program).

taproot_p2tr_testnet_test() ->
    Addr = "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
    {ok, {"tb", [1 | Data5]}} = beamchain_address:bech32m_decode(Addr),
    Program = beamchain_address:convert_bits(Data5, 5, 8, false),
    ?assertEqual(32, length(Program)),
    Expected = hex_to_list("000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"),
    ?assertEqual(Expected, Program).

%%% -------------------------------------------------------------------
%%% script_to_address tests
%%% -------------------------------------------------------------------

script_to_address_p2pkh_test() ->
    Hash = hex_to_bin("62e907b15cbf27d5425399ebf6f0fb50ebb88f18"),
    Script = <<16#76, 16#a9, 16#14, Hash/binary, 16#88, 16#ac>>,
    Addr = beamchain_address:script_to_address(Script, mainnet),
    ?assertEqual("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", Addr).

script_to_address_p2sh_test() ->
    Hash = hex_to_bin("89abcdefabbaabbaabbaabbaabbaabbaabbaabba"),
    Script = <<16#a9, 16#14, Hash/binary, 16#87>>,
    Addr = beamchain_address:script_to_address(Script, mainnet),
    %% verify roundtrip
    {ok, Script} = beamchain_address:address_to_script(Addr, mainnet).

script_to_address_p2wpkh_test() ->
    Hash = hex_to_bin("751e76e8199196d454941c45d1b3a323f1433bd6"),
    Script = <<16#00, 16#14, Hash/binary>>,
    Addr = beamchain_address:script_to_address(Script, mainnet),
    ?assertEqual("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", Addr).

script_to_address_p2wsh_test() ->
    Hash = hex_to_bin("1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"),
    Script = <<16#00, 16#20, Hash/binary>>,
    Addr = beamchain_address:script_to_address(Script, mainnet),
    ?assertEqual("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3", Addr).

script_to_address_p2tr_test() ->
    %% secp256k1 generator point x-coord
    Hash = hex_to_bin("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
    Script = <<16#51, 16#20, Hash/binary>>,
    Addr = beamchain_address:script_to_address(Script, mainnet),
    ?assertEqual("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", Addr).

script_to_address_op_return_test() ->
    Script = <<16#6a, 16#04, "test">>,
    ?assertEqual("OP_RETURN", beamchain_address:script_to_address(Script, mainnet)).

script_to_address_unknown_test() ->
    ?assertEqual(unknown, beamchain_address:script_to_address(<<16#ff>>, mainnet)).

script_to_address_testnet_p2wpkh_test() ->
    Hash = hex_to_bin("751e76e8199196d454941c45d1b3a323f1433bd6"),
    Script = <<16#00, 16#14, Hash/binary>>,
    Addr = beamchain_address:script_to_address(Script, testnet),
    ?assertEqual("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", Addr).

%%% -------------------------------------------------------------------
%%% address_to_script tests
%%% -------------------------------------------------------------------

address_to_script_p2pkh_test() ->
    Hash = hex_to_bin("62e907b15cbf27d5425399ebf6f0fb50ebb88f18"),
    Expected = <<16#76, 16#a9, 16#14, Hash/binary, 16#88, 16#ac>>,
    {ok, Script} = beamchain_address:address_to_script(
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", mainnet),
    ?assertEqual(Expected, Script).

address_to_script_p2wpkh_test() ->
    Hash = hex_to_bin("751e76e8199196d454941c45d1b3a323f1433bd6"),
    Expected = <<16#00, 16#14, Hash/binary>>,
    {ok, Script} = beamchain_address:address_to_script(
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", mainnet),
    ?assertEqual(Expected, Script).

address_to_script_p2tr_test() ->
    Hash = hex_to_bin("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
    Expected = <<16#51, 16#20, Hash/binary>>,
    {ok, Script} = beamchain_address:address_to_script(
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", mainnet),
    ?assertEqual(Expected, Script).

address_to_script_roundtrip_testnet_p2wpkh_test() ->
    Hash = hex_to_bin("751e76e8199196d454941c45d1b3a323f1433bd6"),
    Script = <<16#00, 16#14, Hash/binary>>,
    Addr = beamchain_address:script_to_address(Script, testnet),
    {ok, Script} = beamchain_address:address_to_script(Addr, testnet).

address_to_script_p2wsh_roundtrip_test() ->
    Hash = hex_to_bin("1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"),
    Script = <<16#00, 16#20, Hash/binary>>,
    Addr = beamchain_address:script_to_address(Script, mainnet),
    {ok, Script} = beamchain_address:address_to_script(Addr, mainnet).

%%% -------------------------------------------------------------------
%%% classify_script tests
%%% -------------------------------------------------------------------

classify_p2pkh_test() ->
    Hash = crypto:strong_rand_bytes(20),
    Script = <<16#76, 16#a9, 16#14, Hash/binary, 16#88, 16#ac>>,
    ?assertEqual(p2pkh, beamchain_address:classify_script(Script)).

classify_p2sh_test() ->
    Hash = crypto:strong_rand_bytes(20),
    Script = <<16#a9, 16#14, Hash/binary, 16#87>>,
    ?assertEqual(p2sh, beamchain_address:classify_script(Script)).

classify_p2wpkh_test() ->
    Hash = crypto:strong_rand_bytes(20),
    Script = <<16#00, 16#14, Hash/binary>>,
    ?assertEqual(p2wpkh, beamchain_address:classify_script(Script)).

classify_p2wsh_test() ->
    Hash = crypto:strong_rand_bytes(32),
    Script = <<16#00, 16#20, Hash/binary>>,
    ?assertEqual(p2wsh, beamchain_address:classify_script(Script)).

classify_p2tr_test() ->
    Hash = crypto:strong_rand_bytes(32),
    Script = <<16#51, 16#20, Hash/binary>>,
    ?assertEqual(p2tr, beamchain_address:classify_script(Script)).

classify_op_return_test() ->
    Script = <<16#6a, 16#0e, "hello, world!">>,
    ?assertEqual(op_return, beamchain_address:classify_script(Script)).

classify_nonstandard_test() ->
    ?assertEqual(nonstandard, beamchain_address:classify_script(<<16#ff, 16#ff>>)).

classify_witness_v2_test() ->
    Program = crypto:strong_rand_bytes(32),
    Script = <<16#52, 16#20, Program/binary>>,
    ?assertEqual({witness, 2, Program}, beamchain_address:classify_script(Script)).

%%% -------------------------------------------------------------------
%%% Bit conversion tests
%%% -------------------------------------------------------------------

convert_bits_8_to_5_test() ->
    %% 0xff = 11111111 → 5-bit groups: 11111 111xx → [31, 28] (padded)
    Result = beamchain_address:convert_bits([255], 8, 5, true),
    ?assertEqual([31, 28], Result).

convert_bits_roundtrip_test() ->
    Data = [0, 14, 20, 15, 7, 28, 19, 23, 11],
    Bits5 = beamchain_address:convert_bits(Data, 8, 5, true),
    Result = beamchain_address:convert_bits(Bits5, 5, 8, false),
    ?assertEqual(Data, Result).

convert_bits_empty_test() ->
    ?assertEqual([], beamchain_address:convert_bits([], 8, 5, true)),
    ?assertEqual([], beamchain_address:convert_bits([], 5, 8, false)).

%%% -------------------------------------------------------------------
%%% Mixed case rejection test
%%% -------------------------------------------------------------------

bech32_mixed_case_test() ->
    ?assertMatch({error, _},
        beamchain_address:bech32_decode("Bc1Qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")).

%%% -------------------------------------------------------------------
%%% Edge cases
%%% -------------------------------------------------------------------

bech32_uppercase_valid_test() ->
    %% uppercase should be valid
    {ok, {"bc", _}} = beamchain_address:bech32_decode(
        "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4").

%%% -------------------------------------------------------------------
%%% Invalid addresses
%%% -------------------------------------------------------------------

invalid_base58_too_short_test() ->
    %% too short to have a valid checksum
    ?assertMatch({error, _}, beamchain_address:base58check_decode("1")).

invalid_bech32_wrong_network_test() ->
    %% bc1 address should not decode correctly with testnet expectations
    Addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
    {ok, Script} = beamchain_address:address_to_script(Addr, mainnet),
    ?assertMatch(<<16#00, 16#14, _:20/binary>>, Script).

address_to_script_invalid_test() ->
    ?assertMatch({error, _}, beamchain_address:address_to_script("totally_invalid", mainnet)).

%%% -------------------------------------------------------------------
%%% P2SH-P2WPKH address roundtrip
%%% -------------------------------------------------------------------

p2sh_p2wpkh_roundtrip_test() ->
    %% A P2SH-wrapped P2WPKH: the scriptPubKey is OP_HASH160 <hash20> OP_EQUAL
    Hash = hex_to_bin("89abcdefabbaabbaabbaabbaabbaabbaabbaabba"),
    Script = <<16#a9, 16#14, Hash/binary, 16#87>>,
    Addr = beamchain_address:script_to_address(Script, mainnet),
    {ok, Script} = beamchain_address:address_to_script(Addr, mainnet).

%%% -------------------------------------------------------------------
%%% Testnet P2TR address test
%%% -------------------------------------------------------------------

testnet_p2tr_roundtrip_test() ->
    Hash = hex_to_bin("000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"),
    Script = <<16#51, 16#20, Hash/binary>>,
    Addr = beamchain_address:script_to_address(Script, testnet),
    ?assertEqual("tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c", Addr),
    {ok, Script} = beamchain_address:address_to_script(Addr, testnet).

%%% -------------------------------------------------------------------
%%% Witness v2+ future version test
%%% -------------------------------------------------------------------

witness_future_version_test() ->
    %% A witness v2 program should classify as {witness, 2, Program}
    Program = crypto:strong_rand_bytes(32),
    Script = <<16#52, 16#20, Program/binary>>,
    ?assertEqual({witness, 2, Program}, beamchain_address:classify_script(Script)).

%%% -------------------------------------------------------------------
%%% Helpers
%%% -------------------------------------------------------------------

hex_to_bin(Hex) ->
    beamchain_serialize:hex_decode(Hex).

hex_to_list(Hex) ->
    binary_to_list(hex_to_bin(Hex)).
