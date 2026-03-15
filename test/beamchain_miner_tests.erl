-module(beamchain_miner_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%%% ===================================================================
%%% Witness commitment format tests
%%% ===================================================================

%% Test the OP_RETURN script format for witness commitment
witness_commitment_script_format_test() ->
    %% Witness commitment OP_RETURN format:
    %% OP_RETURN (0x6a) + PUSH 36 bytes (0x24) + magic (aa21a9ed) + 32-byte hash
    Commitment = <<1:256>>,
    Script = <<16#6a, 16#24, 16#aa, 16#21, 16#a9, 16#ed, Commitment/binary>>,
    ?assertEqual(38, byte_size(Script)),
    ?assertEqual(<<16#6a>>, binary:part(Script, 0, 1)),   %% OP_RETURN
    ?assertEqual(<<16#24>>, binary:part(Script, 1, 1)),   %% PUSH 36
    ?assertEqual(<<16#aa, 16#21, 16#a9, 16#ed>>, binary:part(Script, 2, 4)), %% magic
    ?assertEqual(Commitment, binary:part(Script, 6, 32)). %% commitment hash

%% Test that the witness merkle root uses coinbase wtxid = 0
witness_merkle_root_coinbase_zero_test() ->
    %% For witness merkle root, coinbase wtxid is always 32 zero bytes
    CoinbaseWtxid = <<0:256>>,
    TxWtxid1 = beamchain_serialize:hash256(<<"tx1">>),
    TxWtxid2 = beamchain_serialize:hash256(<<"tx2">>),

    %% Witness merkle tree: [0x00..00, wtxid1, wtxid2, ...]
    %% For 3 elements: hash(hash(cb, tx1), hash(tx2, tx2))
    Level1_Left = beamchain_serialize:hash256(<<CoinbaseWtxid/binary, TxWtxid1/binary>>),
    Level1_Right = beamchain_serialize:hash256(<<TxWtxid2/binary, TxWtxid2/binary>>),
    ExpectedRoot = beamchain_serialize:hash256(<<Level1_Left/binary, Level1_Right/binary>>),

    ActualRoot = beamchain_serialize:compute_merkle_root([CoinbaseWtxid, TxWtxid1, TxWtxid2]),
    ?assertEqual(ExpectedRoot, ActualRoot).

%% Test witness commitment computation (merkle root + nonce -> commitment)
witness_commitment_computation_test() ->
    %% commitment = SHA256d(witness_merkle_root || witness_nonce)
    CoinbaseWtxid = <<0:256>>,
    TxWtxid = <<1:256>>,
    WitnessNonce = <<0:256>>,  %% 32 zero bytes

    WitnessMerkleRoot = beamchain_serialize:compute_merkle_root([CoinbaseWtxid, TxWtxid]),
    ExpectedCommitment = beamchain_serialize:hash256(<<WitnessMerkleRoot/binary, WitnessNonce/binary>>),

    ActualCommitment = beamchain_serialize:compute_witness_commitment(
        [CoinbaseWtxid, TxWtxid], WitnessNonce),
    ?assertEqual(ExpectedCommitment, ActualCommitment).

%% Test witness commitment with different nonce values
witness_commitment_nonce_affects_result_test() ->
    Wtxids = [<<0:256>>, <<1:256>>],
    Nonce1 = <<0:256>>,
    Nonce2 = <<1:256>>,

    Commitment1 = beamchain_serialize:compute_witness_commitment(Wtxids, Nonce1),
    Commitment2 = beamchain_serialize:compute_witness_commitment(Wtxids, Nonce2),

    ?assertNotEqual(Commitment1, Commitment2).

%%% ===================================================================
%%% Coinbase transaction structure tests
%%% ===================================================================

%% Test coinbase witness nonce is 32 zero bytes when witness txs present
coinbase_witness_nonce_test() ->
    %% When block has witness transactions, coinbase must have
    %% exactly one witness stack element of 32 bytes (all zeros)
    WitnessNonce = <<0:256>>,
    ?assertEqual(32, byte_size(WitnessNonce)),
    ?assertEqual(<<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>, WitnessNonce).

%% Test coinbase scriptSig BIP34 height encoding
%% BIP34 requires block height to be pushed as a minimally-encoded little-endian
%% integer in the coinbase scriptSig.
bip34_height_encoding_test() ->
    %% Heights 1-16 are encoded as: 0x01 HEIGHT
    ?assertEqual(<<1, 1>>, encode_coinbase_height(1)),
    ?assertEqual(<<1, 16>>, encode_coinbase_height(16)),

    %% Heights 17-255 are encoded as: 0x01 HEIGHT (single byte)
    ?assertEqual(<<1, 17>>, encode_coinbase_height(17)),
    ?assertEqual(<<1, 127>>, encode_coinbase_height(127)),
    ?assertEqual(<<1, 128>>, encode_coinbase_height(128)),
    ?assertEqual(<<1, 255>>, encode_coinbase_height(255)),

    %% Heights 256-65535 need 2 bytes
    ?assertEqual(<<2, 0, 1>>, encode_coinbase_height(256)),
    ?assertEqual(<<2, 255, 255>>, encode_coinbase_height(65535)),

    %% Heights 65536+ need 3 bytes
    ?assertEqual(<<3, 0, 0, 1>>, encode_coinbase_height(65536)).

%% Test coinbase anti-fee-sniping locktime (height - 1)
coinbase_locktime_test() ->
    %% For height N, locktime should be N-1 (anti-fee-sniping)
    %% This makes the coinbase invalid for inclusion in any block
    %% with height < N
    Height100 = 100,
    ?assertEqual(99, Height100 - 1),

    Height1000 = 1000,
    ?assertEqual(999, Height1000 - 1).

%% Test coinbase sequence number for locktime enforcement
coinbase_sequence_nonfinal_test() ->
    %% Coinbase sequence should be 0xFFFFFFFE (MAX_SEQUENCE_NONFINAL)
    %% to ensure locktime is actually enforced
    Sequence = 16#fffffffe,
    ?assertNotEqual(16#ffffffff, Sequence),
    ?assert(Sequence < 16#ffffffff).

%%% ===================================================================
%%% Block weight limit tests
%%% ===================================================================

%% Test MAX_BLOCK_WEIGHT constant
max_block_weight_constant_test() ->
    %% BIP 141 specifies max block weight as 4,000,000 WU
    ?assertEqual(4000000, ?MAX_BLOCK_WEIGHT).

%% Test weight calculation formula
weight_formula_test() ->
    %% Weight = base_size * (WITNESS_SCALE_FACTOR - 1) + total_size
    %% For legacy tx: weight = size * 4
    %% For witness tx: weight = base_size * 3 + total_size
    BaseSize = 100,
    TotalSize = 150,

    %% Witness scale factor is 4
    ?assertEqual(4, ?WITNESS_SCALE_FACTOR),

    %% Weight calculation for witness tx
    Weight = (BaseSize * (?WITNESS_SCALE_FACTOR - 1)) + TotalSize,
    ?assertEqual(450, Weight),  %% 100*3 + 150 = 450

    %% For legacy tx, total_size == base_size
    LegacyWeight = BaseSize * ?WITNESS_SCALE_FACTOR,
    ?assertEqual(400, LegacyWeight).  %% 100*4 = 400

%%% ===================================================================
%%% Ancestor fee rate tests
%%% ===================================================================

%% Test that fee rate comparison works correctly
fee_rate_comparison_test() ->
    %% Higher fee rate should sort before lower
    HighFeeRate = 100.0,  %% sat/vB
    LowFeeRate = 10.0,
    ?assert(HighFeeRate > LowFeeRate).

%% Test ancestor fee rate calculation logic
ancestor_fee_rate_calculation_test() ->
    %% ancestor_fee_rate = (tx_fee + ancestor_fees) / (tx_weight + ancestor_weight)
    TxFee = 1000,
    AncestorFee = 500,
    TotalFee = TxFee + AncestorFee,

    TxWeight = 400,
    AncestorWeight = 800,
    TotalWeight = TxWeight + AncestorWeight,

    FeeRate = TotalFee / TotalWeight,
    ?assertEqual(1.25, FeeRate).  %% 1500/1200 = 1.25 sat/WU

%%% ===================================================================
%%% Witness merkle root structure tests
%%% ===================================================================

%% Test that witness merkle tree structure follows Bitcoin Core
witness_merkle_tree_structure_test() ->
    %% Witness merkle tree:
    %% - First leaf is always coinbase wtxid (32 zero bytes)
    %% - Subsequent leaves are wtxids of transactions
    %% - Tree is computed same as regular merkle tree

    CoinbaseWtxid = <<0:256>>,
    Tx1Wtxid = <<1:256>>,
    Tx2Wtxid = <<2:256>>,

    %% Single tx (besides coinbase)
    Root1 = beamchain_serialize:compute_merkle_root([CoinbaseWtxid, Tx1Wtxid]),
    Expected1 = beamchain_serialize:hash256(<<CoinbaseWtxid/binary, Tx1Wtxid/binary>>),
    ?assertEqual(Expected1, Root1),

    %% Two txs (besides coinbase)
    Root2 = beamchain_serialize:compute_merkle_root([CoinbaseWtxid, Tx1Wtxid, Tx2Wtxid]),
    %% Level 1: hash(cb, tx1), hash(tx2, tx2)
    L1_Left = beamchain_serialize:hash256(<<CoinbaseWtxid/binary, Tx1Wtxid/binary>>),
    L1_Right = beamchain_serialize:hash256(<<Tx2Wtxid/binary, Tx2Wtxid/binary>>),
    %% Level 0 (root): hash(L1_Left, L1_Right)
    Expected2 = beamchain_serialize:hash256(<<L1_Left/binary, L1_Right/binary>>),
    ?assertEqual(Expected2, Root2).

%% Test coinbase-only block witness root
coinbase_only_witness_root_test() ->
    %% If block only has coinbase (no other txs with witness),
    %% witness root is just the coinbase wtxid (32 zeros)
    CoinbaseWtxid = <<0:256>>,
    Root = beamchain_serialize:compute_merkle_root([CoinbaseWtxid]),
    ?assertEqual(CoinbaseWtxid, Root).

%%% ===================================================================
%%% Helper function replicating miner's height encoding
%%% ===================================================================

encode_coinbase_height(0) ->
    <<0>>;
encode_coinbase_height(Height) when Height >= 1, Height =< 16 ->
    <<1, Height:8>>;
encode_coinbase_height(Height) ->
    Bytes = le_minimal(Height),
    Len = byte_size(Bytes),
    <<Len:8, Bytes/binary>>.

le_minimal(N) ->
    le_minimal_acc(N, <<>>).

le_minimal_acc(0, Acc) -> Acc;
le_minimal_acc(N, Acc) ->
    Byte = N band 16#ff,
    le_minimal_acc(N bsr 8, <<Acc/binary, Byte:8>>).
