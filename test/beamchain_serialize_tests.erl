-module(beamchain_serialize_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%%% ===================================================================
%%% Varint tests
%%% ===================================================================

varint_encode_single_byte_test() ->
    ?assertEqual(<<0>>, beamchain_serialize:encode_varint(0)),
    ?assertEqual(<<1>>, beamchain_serialize:encode_varint(1)),
    ?assertEqual(<<252>>, beamchain_serialize:encode_varint(252)).

varint_encode_two_byte_test() ->
    ?assertEqual(<<16#FD, 253, 0>>, beamchain_serialize:encode_varint(253)),
    ?assertEqual(<<16#FD, 254, 0>>, beamchain_serialize:encode_varint(254)),
    ?assertEqual(<<16#FD, 255, 0>>, beamchain_serialize:encode_varint(255)),
    ?assertEqual(<<16#FD, 255, 255>>, beamchain_serialize:encode_varint(65535)).

varint_encode_four_byte_test() ->
    ?assertEqual(<<16#FE, 0, 0, 1, 0>>, beamchain_serialize:encode_varint(65536)),
    ?assertEqual(<<16#FE, 255, 255, 255, 255>>,
                 beamchain_serialize:encode_varint(4294967295)).

varint_encode_eight_byte_test() ->
    ?assertEqual(<<16#FF, 0, 0, 0, 0, 1, 0, 0, 0>>,
                 beamchain_serialize:encode_varint(4294967296)).

varint_roundtrip_test_() ->
    Values = [0, 1, 252, 253, 254, 255, 65535, 65536, 4294967295, 4294967296],
    [?_assertEqual({V, <<>>}, beamchain_serialize:decode_varint(
        beamchain_serialize:encode_varint(V)))
     || V <- Values].

varint_decode_with_rest_test() ->
    %% extra bytes should be returned as rest
    {253, <<16#AA, 16#BB>>} =
        beamchain_serialize:decode_varint(<<16#FD, 253, 0, 16#AA, 16#BB>>).

%%% ===================================================================
%%% Little-endian helper tests
%%% ===================================================================

le32_roundtrip_test() ->
    {42, <<>>} = beamchain_serialize:decode_le32(
        beamchain_serialize:encode_le32(42)),
    {16#DEADBEEF, <<>>} = beamchain_serialize:decode_le32(
        beamchain_serialize:encode_le32(16#DEADBEEF)).

le64_roundtrip_test() ->
    {5000000000, <<>>} = beamchain_serialize:decode_le64(
        beamchain_serialize:encode_le64(5000000000)).

%%% ===================================================================
%%% Varstr tests
%%% ===================================================================

varstr_roundtrip_test() ->
    Data = <<"hello bitcoin">>,
    Encoded = beamchain_serialize:encode_varstr(Data),
    ?assertEqual({Data, <<>>}, beamchain_serialize:decode_varstr(Encoded)).

varstr_empty_test() ->
    Encoded = beamchain_serialize:encode_varstr(<<>>),
    ?assertEqual({<<>>, <<>>}, beamchain_serialize:decode_varstr(Encoded)).

%%% ===================================================================
%%% Block header tests
%%% ===================================================================

genesis_header_bytes() ->
    %% Mainnet genesis block header (80 bytes)
    beamchain_serialize:hex_decode(
        "01000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
        "29ab5f49"
        "ffff001d"
        "1dac2b7c"
    ).

genesis_header_decode_test() ->
    Bin = genesis_header_bytes(),
    {Header, <<>>} = beamchain_serialize:decode_block_header(Bin),
    ?assertEqual(1, Header#block_header.version),
    ?assertEqual(<<0:256>>, Header#block_header.prev_hash),
    ?assertEqual(1231006505, Header#block_header.timestamp),
    ?assertEqual(16#1d00ffff, Header#block_header.bits),
    ?assertEqual(2083236893, Header#block_header.nonce).

genesis_header_roundtrip_test() ->
    Bin = genesis_header_bytes(),
    {Header, <<>>} = beamchain_serialize:decode_block_header(Bin),
    ?assertEqual(Bin, beamchain_serialize:encode_block_header(Header)).

genesis_hash_test() ->
    Bin = genesis_header_bytes(),
    {Header, <<>>} = beamchain_serialize:decode_block_header(Bin),
    Hash = beamchain_serialize:block_hash(Header),
    %% display order (reversed) should match the known genesis hash
    DisplayHash = beamchain_serialize:hex_encode(
        beamchain_serialize:reverse_bytes(Hash)),
    ?assertEqual(
        <<"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f">>,
        DisplayHash
    ).

block_header_80_bytes_test() ->
    Header = #block_header{
        version = 1,
        prev_hash = <<0:256>>,
        merkle_root = <<1:256>>,
        timestamp = 1000,
        bits = 16#1d00ffff,
        nonce = 42
    },
    Encoded = beamchain_serialize:encode_block_header(Header),
    ?assertEqual(80, byte_size(Encoded)).

%%% ===================================================================
%%% Transaction tests
%%% ===================================================================

simple_coinbase_tx() ->
    %% a minimal coinbase-style transaction
    #transaction{
        version = 1,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = <<0:256>>, index = 16#FFFFFFFF},
            script_sig = <<4, 1, 0, 0, 0>>,
            sequence = 16#FFFFFFFF,
            witness = []
        }],
        outputs = [#tx_out{
            value = 5000000000,
            script_pubkey = <<16#76, 16#a9, 16#14,  %% OP_DUP OP_HASH160 PUSH20
                              0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                              16#88, 16#ac>>          %% OP_EQUALVERIFY OP_CHECKSIG
        }],
        locktime = 0
    }.

legacy_tx_roundtrip_test() ->
    Tx = simple_coinbase_tx(),
    Encoded = beamchain_serialize:encode_transaction(Tx, no_witness),
    {Decoded, <<>>} = beamchain_serialize:decode_transaction(Encoded),
    %% re-encode and compare
    ReEncoded = beamchain_serialize:encode_transaction(Decoded, no_witness),
    ?assertEqual(Encoded, ReEncoded).

tx_hash_deterministic_test() ->
    Tx = simple_coinbase_tx(),
    Hash1 = beamchain_serialize:tx_hash(Tx),
    Hash2 = beamchain_serialize:tx_hash(Tx),
    ?assertEqual(Hash1, Hash2),
    ?assertEqual(32, byte_size(Hash1)).

witness_tx_test() ->
    %% transaction with witness data
    Tx = #transaction{
        version = 2,
        inputs = [#tx_in{
            prev_out = #outpoint{
                hash = <<1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
                          17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32>>,
                index = 0
            },
            script_sig = <<>>,
            sequence = 16#FFFFFFFE,
            witness = [
                <<16#30, 16#44, 0:544>>,  %% fake 70-byte signature
                <<16#02, 0:256>>           %% fake 33-byte compressed pubkey
            ]
        }],
        outputs = [#tx_out{
            value = 100000,
            script_pubkey = <<16#00, 16#14, 0:160>>  %% P2WPKH
        }],
        locktime = 0
    },
    %% encode as witness
    WitBin = beamchain_serialize:encode_transaction(Tx, witness),
    %% should contain the marker+flag bytes
    <<_Version:32/little, 16#00:8, 16#01:8, _Rest/binary>> = WitBin,
    %% decode it back
    {Decoded, <<>>} = beamchain_serialize:decode_transaction(WitBin),
    ?assertEqual(2, Decoded#transaction.version),
    [Input] = Decoded#transaction.inputs,
    ?assertEqual(2, length(Input#tx_in.witness)),
    %% txid != wtxid for witness tx
    Txid = beamchain_serialize:tx_hash(Tx),
    Wtxid = beamchain_serialize:wtx_hash(Tx),
    ?assertNotEqual(Txid, Wtxid).

legacy_tx_txid_equals_wtxid_test() ->
    Tx = simple_coinbase_tx(),
    Txid = beamchain_serialize:tx_hash(Tx),
    Wtxid = beamchain_serialize:wtx_hash(Tx),
    ?assertEqual(Txid, Wtxid).

%%% ===================================================================
%%% Tx input/output encoding
%%% ===================================================================

tx_in_roundtrip_test() ->
    In = #tx_in{
        prev_out = #outpoint{hash = <<42:256>>, index = 7},
        script_sig = <<1, 2, 3, 4>>,
        sequence = 16#FFFFFFFE,
        witness = []
    },
    Encoded = beamchain_serialize:encode_tx_in(In),
    {Decoded, <<>>} = beamchain_serialize:decode_tx_in(Encoded),
    ?assertEqual(In#tx_in.prev_out, Decoded#tx_in.prev_out),
    ?assertEqual(In#tx_in.script_sig, Decoded#tx_in.script_sig),
    ?assertEqual(In#tx_in.sequence, Decoded#tx_in.sequence).

tx_out_roundtrip_test() ->
    Out = #tx_out{value = 5000000000, script_pubkey = <<1, 2, 3>>},
    Encoded = beamchain_serialize:encode_tx_out(Out),
    {Decoded, <<>>} = beamchain_serialize:decode_tx_out(Encoded),
    ?assertEqual(Out, Decoded).

%%% ===================================================================
%%% Block serialization
%%% ===================================================================

simple_block_roundtrip_test() ->
    Tx = simple_coinbase_tx(),
    Header = #block_header{
        version = 1,
        prev_hash = <<0:256>>,
        merkle_root = <<0:256>>,
        timestamp = 1231006505,
        bits = 16#1d00ffff,
        nonce = 2083236893
    },
    Block = #block{header = Header, transactions = [Tx]},
    Encoded = beamchain_serialize:encode_block(Block),
    {Decoded, <<>>} = beamchain_serialize:decode_block(Encoded),
    ?assertEqual(Header, Decoded#block.header),
    ?assertEqual(1, length(Decoded#block.transactions)).

%%% ===================================================================
%%% Hash functions
%%% ===================================================================

hash256_test() ->
    %% SHA256d of empty string is known
    Result = beamchain_serialize:hash256(<<>>),
    ?assertEqual(32, byte_size(Result)),
    %% SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    %% SHA256(above) = 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456
    Expected = beamchain_serialize:hex_decode(
        "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"),
    ?assertEqual(Expected, Result).

hash160_test() ->
    Result = beamchain_serialize:hash160(<<>>),
    ?assertEqual(20, byte_size(Result)).

%%% ===================================================================
%%% Merkle tree tests
%%% ===================================================================

merkle_single_test() ->
    Hash = <<1:256>>,
    ?assertEqual(Hash, beamchain_serialize:compute_merkle_root([Hash])).

merkle_two_elements_test() ->
    A = <<1:256>>,
    B = <<2:256>>,
    Expected = beamchain_serialize:hash256(<<A/binary, B/binary>>),
    ?assertEqual(Expected, beamchain_serialize:compute_merkle_root([A, B])).

merkle_three_elements_test() ->
    A = <<1:256>>,
    B = <<2:256>>,
    C = <<3:256>>,
    %% first level: hash(A||B) and hash(C||C) (C is duplicated since odd)
    AB = beamchain_serialize:hash256(<<A/binary, B/binary>>),
    CC = beamchain_serialize:hash256(<<C/binary, C/binary>>),
    %% second level: hash(AB||CC)
    Expected = beamchain_serialize:hash256(<<AB/binary, CC/binary>>),
    ?assertEqual(Expected, beamchain_serialize:compute_merkle_root([A, B, C])).

merkle_empty_test() ->
    ?assertEqual(<<0:256>>, beamchain_serialize:compute_merkle_root([])).

%%% ===================================================================
%%% Weight / vsize tests
%%% ===================================================================

legacy_tx_weight_test() ->
    Tx = simple_coinbase_tx(),
    Weight = beamchain_serialize:tx_weight(Tx),
    Size = byte_size(beamchain_serialize:encode_transaction(Tx, no_witness)),
    %% for legacy tx, weight = size * 4
    ?assertEqual(Size * 4, Weight).

legacy_tx_vsize_test() ->
    Tx = simple_coinbase_tx(),
    Vsize = beamchain_serialize:tx_vsize(Tx),
    Size = byte_size(beamchain_serialize:encode_transaction(Tx, no_witness)),
    %% for legacy tx, vsize = size
    ?assertEqual(Size, Vsize).

witness_tx_weight_test() ->
    Tx = #transaction{
        version = 2,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = <<1:256>>, index = 0},
            script_sig = <<>>,
            sequence = 16#FFFFFFFF,
            witness = [<<0:512>>, <<0:264>>]  %% some witness data
        }],
        outputs = [#tx_out{value = 50000, script_pubkey = <<0, 20, 0:160>>}],
        locktime = 0
    },
    Weight = beamchain_serialize:tx_weight(Tx),
    NoWitSize = byte_size(beamchain_serialize:encode_transaction(Tx, no_witness)),
    WitSize = byte_size(beamchain_serialize:encode_transaction(Tx, witness)),
    %% weight = non_witness_size * 4 + witness_size
    %% witness_size = total - non_witness
    ExpectedWeight = (NoWitSize * 4) + (WitSize - NoWitSize),
    ?assertEqual(ExpectedWeight, Weight),
    %% weight should be less than size * 4 for witness tx
    ?assert(Weight < WitSize * 4).

witness_tx_vsize_test() ->
    Tx = #transaction{
        version = 2,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = <<1:256>>, index = 0},
            script_sig = <<>>,
            sequence = 16#FFFFFFFF,
            witness = [<<0:512>>, <<0:264>>]
        }],
        outputs = [#tx_out{value = 50000, script_pubkey = <<0, 20, 0:160>>}],
        locktime = 0
    },
    Vsize = beamchain_serialize:tx_vsize(Tx),
    Weight = beamchain_serialize:tx_weight(Tx),
    ?assertEqual((Weight + 3) div 4, Vsize).

%%% ===================================================================
%%% Hex encode/decode
%%% ===================================================================

hex_roundtrip_test() ->
    Bin = <<16#DE, 16#AD, 16#BE, 16#EF>>,
    Hex = beamchain_serialize:hex_encode(Bin),
    ?assertEqual(<<"deadbeef">>, Hex),
    ?assertEqual(Bin, beamchain_serialize:hex_decode(Hex)).

hex_decode_string_test() ->
    ?assertEqual(<<255, 0>>, beamchain_serialize:hex_decode("ff00")).

hex_empty_test() ->
    ?assertEqual(<<>>, beamchain_serialize:hex_decode(<<>>)),
    ?assertEqual(<<>>, beamchain_serialize:hex_encode(<<>>)).

%%% ===================================================================
%%% Reverse bytes
%%% ===================================================================

reverse_bytes_test() ->
    ?assertEqual(<<4,3,2,1>>, beamchain_serialize:reverse_bytes(<<1,2,3,4>>)),
    ?assertEqual(<<>>, beamchain_serialize:reverse_bytes(<<>>)).

%%% ===================================================================
%%% Real-world genesis coinbase transaction
%%% ===================================================================

genesis_coinbase_tx_test() ->
    %% The actual mainnet genesis coinbase transaction (serialized, no witness)
    TxHex =
        "01000000"  %% version
        "01"        %% 1 input
        "0000000000000000000000000000000000000000000000000000000000000000"  %% prev hash
        "ffffffff"  %% prev index
        "4d"        %% script length = 77
        "04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73"
        "ffffffff"  %% sequence
        "01"        %% 1 output
        "00f2052a01000000"  %% 50 BTC
        "43"        %% script length = 67
        "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac"
        "00000000",  %% locktime
    TxBin = beamchain_serialize:hex_decode(TxHex),
    {Tx, <<>>} = beamchain_serialize:decode_transaction(TxBin),
    ?assertEqual(1, Tx#transaction.version),
    ?assertEqual(1, length(Tx#transaction.inputs)),
    ?assertEqual(1, length(Tx#transaction.outputs)),
    [Out] = Tx#transaction.outputs,
    ?assertEqual(5000000000, Out#tx_out.value),
    %% roundtrip
    ReEncoded = beamchain_serialize:encode_transaction(Tx, no_witness),
    ?assertEqual(TxBin, ReEncoded),
    %% verify txid
    Txid = beamchain_serialize:tx_hash(Tx),
    DisplayTxid = beamchain_serialize:hex_encode(
        beamchain_serialize:reverse_bytes(Txid)),
    ?assertEqual(
        <<"4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b">>,
        DisplayTxid).

%%% ===================================================================
%%% Witness commitment computation
%%% ===================================================================

witness_commitment_basic_test() ->
    %% coinbase wtxid is always 32 zero bytes
    CoinbaseWtxid = <<0:256>>,
    TxWtxid = <<1:256>>,
    WitnessNonce = <<0:256>>,
    Result = beamchain_serialize:compute_witness_commitment(
        [CoinbaseWtxid, TxWtxid], WitnessNonce),
    ?assertEqual(32, byte_size(Result)).

witness_commitment_deterministic_test() ->
    Wtxids = [<<0:256>>, <<1:256>>, <<2:256>>],
    Nonce = <<0:256>>,
    R1 = beamchain_serialize:compute_witness_commitment(Wtxids, Nonce),
    R2 = beamchain_serialize:compute_witness_commitment(Wtxids, Nonce),
    ?assertEqual(R1, R2).

witness_commitment_different_nonce_test() ->
    Wtxids = [<<0:256>>, <<1:256>>],
    R1 = beamchain_serialize:compute_witness_commitment(Wtxids, <<0:256>>),
    R2 = beamchain_serialize:compute_witness_commitment(Wtxids, <<1:256>>),
    ?assertNotEqual(R1, R2).

%%% ===================================================================
%%% Merkle root with 4 elements (power of 2)
%%% ===================================================================

merkle_four_elements_test() ->
    A = <<1:256>>, B = <<2:256>>, C = <<3:256>>, D = <<4:256>>,
    AB = beamchain_serialize:hash256(<<A/binary, B/binary>>),
    CD = beamchain_serialize:hash256(<<C/binary, D/binary>>),
    Expected = beamchain_serialize:hash256(<<AB/binary, CD/binary>>),
    ?assertEqual(Expected, beamchain_serialize:compute_merkle_root([A, B, C, D])).

%%% ===================================================================
%%% Multi-output transaction test
%%% ===================================================================

multi_output_tx_test() ->
    Tx = #transaction{
        version = 1,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = <<0:256>>, index = 16#ffffffff},
            script_sig = <<4, 1, 0, 0, 0>>,
            sequence = 16#ffffffff,
            witness = []
        }],
        outputs = [
            #tx_out{value = 2500000000, script_pubkey = <<16#76, 16#a9, 16#14, 0:160, 16#88, 16#ac>>},
            #tx_out{value = 2500000000, script_pubkey = <<16#a9, 16#14, 0:160, 16#87>>}
        ],
        locktime = 0
    },
    Encoded = beamchain_serialize:encode_transaction(Tx, no_witness),
    {Decoded, <<>>} = beamchain_serialize:decode_transaction(Encoded),
    ?assertEqual(2, length(Decoded#transaction.outputs)),
    [Out1, Out2] = Decoded#transaction.outputs,
    ?assertEqual(2500000000, Out1#tx_out.value),
    ?assertEqual(2500000000, Out2#tx_out.value).

%%% ===================================================================
%%% Varint boundary precision
%%% ===================================================================

varint_boundary_exact_test() ->
    %% test exact boundaries between encoding sizes
    %% 252 -> 1 byte, 253 -> 3 bytes
    ?assertEqual(1, byte_size(beamchain_serialize:encode_varint(252))),
    ?assertEqual(3, byte_size(beamchain_serialize:encode_varint(253))),
    %% 65535 -> 3 bytes, 65536 -> 5 bytes
    ?assertEqual(3, byte_size(beamchain_serialize:encode_varint(65535))),
    ?assertEqual(5, byte_size(beamchain_serialize:encode_varint(65536))),
    %% 2^32-1 -> 5 bytes, 2^32 -> 9 bytes
    ?assertEqual(5, byte_size(beamchain_serialize:encode_varint(4294967295))),
    ?assertEqual(9, byte_size(beamchain_serialize:encode_varint(4294967296))).
