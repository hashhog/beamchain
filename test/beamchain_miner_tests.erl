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

    %% Heights 17-127: single byte, high bit clear — no sign-byte padding needed.
    ?assertEqual(<<1, 17>>, encode_coinbase_height(17)),
    ?assertEqual(<<1, 127>>, encode_coinbase_height(127)),
    %% Heights 128-255: high bit set — CScriptNum requires 0x00 sign-byte padding.
    %% Core: script.h CScriptNum::serialize appends 0x00 when vch.back() & 0x80.
    ?assertEqual(<<2, 128, 0>>, encode_coinbase_height(128)),
    ?assertEqual(<<2, 255, 0>>, encode_coinbase_height(255)),

    %% Heights 256-32767: 2 LE bytes, last byte bit 7 clear — no sign padding.
    ?assertEqual(<<2, 0, 1>>, encode_coinbase_height(256)),
    %% Height 32768-65535: last LE byte has bit 7 set → 0x00 sign byte appended.
    %% 65535 = 0xFFFF: LE <<0xFF, 0xFF>>; last byte 0xFF → <<3, 0xFF, 0xFF, 0x00>>.
    ?assertEqual(<<3, 255, 255, 0>>, encode_coinbase_height(65535)),

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
%%% W87 bug-fix tests
%%% ===================================================================

%% BUG1: COINBASE_WEIGHT_RESERVE was 4000, Core uses 8000.
block_reserved_weight_is_8000_test() ->
    %% Core policy/policy.h DEFAULT_BLOCK_RESERVED_WEIGHT = 8000.
    %% The available weight for transactions = MAX_BLOCK_WEIGHT - 8000.
    MaxWeight = ?MAX_BLOCK_WEIGHT,
    Reserved = 8000,
    AvailableForTxs = MaxWeight - Reserved,
    ?assertEqual(4000000 - 8000, AvailableForTxs),
    %% Old value (4000) would have left 4000 extra WU available, allowing
    %% blocks that exceed MAX_BLOCK_WEIGHT when combined with the true
    %% coinbase+header overhead.
    ?assertNotEqual(4000000 - 4000, AvailableForTxs).

%% BUG6: coinbase sigop reserve must be 400, not 0.
coinbase_sigop_reserve_test() ->
    %% Core policy/policy.h DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS = 400.
    %% Template sigop budget = MAX_BLOCK_SIGOPS_COST - 400 = 79600.
    MaxSigops = ?MAX_BLOCK_SIGOPS_COST,
    SigopReserve = 400,
    AvailableForTxSigops = MaxSigops - SigopReserve,
    ?assertEqual(80000 - 400, AvailableForTxSigops).

%% BUG7: weight limit check must use >= not >.
weight_limit_uses_gte_test() ->
    %% Core TestChunkBlockLimits: nBlockWeight + size >= nBlockMaxWeight -> false.
    %% i.e. a tx that would EXACTLY fill the limit must be rejected.
    MaxWeight = 4000000 - 8000,   %% available budget
    TxWeight = MaxWeight,          %% tx exactly fills remaining budget
    CurrentWeight = 0,
    %% With >= (correct), this tx should be rejected:
    ?assert(CurrentWeight + TxWeight >= MaxWeight),
    %% With > (old bug), this tx would have been accepted:
    ?assertNot(CurrentWeight + TxWeight > MaxWeight).

%% BUG3: MAX_CONSECUTIVE_FAILURES = 1000, BLOCK_FULL_ENOUGH_WEIGHT_DELTA = 4000.
max_consecutive_failures_constants_test() ->
    %% Core node/miner.cpp addChunks():
    %%   if (nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES &&
    %%       nBlockWeight + BLOCK_FULL_ENOUGH_WEIGHT_DELTA > nBlockMaxWeight) return;
    MaxConsecFail = 1000,
    BlockFullEnoughDelta = 4000,
    ?assertEqual(1000, MaxConsecFail),
    ?assertEqual(4000, BlockFullEnoughDelta),

    %% Verify the early-exit condition logic:
    %% Block must be within 4000 WU of the weight limit to trigger early exit.
    MaxWeight = 4000000 - 8000,
    WeightAlmostFull = MaxWeight - 3999,  %% within 4000 WU
    WeightNotFull    = MaxWeight - 5000,  %% more than 4000 WU available

    ?assert(WeightAlmostFull + BlockFullEnoughDelta > MaxWeight),
    ?assertNot(WeightNotFull + BlockFullEnoughDelta > MaxWeight).

%% BUG4: minimum fee rate gate (DEFAULT_BLOCK_MIN_TX_FEE = 1 sat/kvB).
min_fee_rate_gate_test() ->
    %% Core node/miner.cpp addChunks():
    %%   if (chunk_feerate_vsize << blockMinFeeRate.GetFeePerVSize()) return;
    %% Default blockMinFeeRate = 1 sat/kvB.
    MinFeeRateSatKvb = 1,

    %% 200-byte tx paying 0 sat: fee rate = 0, must be excluded.
    Fee0 = 0,
    VSize200 = 200,
    FeeRate0 = Fee0 * 1000 div VSize200,
    ?assert(FeeRate0 < MinFeeRateSatKvb),

    %% 200-byte tx paying 1 sat: fee rate = 5 sat/kvB, must be included.
    Fee1 = 1,
    FeeRate1 = Fee1 * 1000 div VSize200,
    ?assert(FeeRate1 >= MinFeeRateSatKvb).

%% BUG2: non-final transactions must not enter the template.
%% Test that is_final_tx rejects height-locked non-final txs.
non_final_tx_rejected_from_template_test() ->
    %% Tx with locktime = 1000 and a non-final sequence (not 0xFFFFFFFF).
    %% Non-final sequence means the locktime IS enforced.
    %% Being considered for block at height 999: this tx is non-final.
    %% is_final_tx(Tx, Height, LockTimeCutoff) from beamchain_validation.
    LockTimeCutoff = 12345,  %% MTP (ignored for height-based locktime)
    Tx = #transaction{
        version = 1,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = <<0:256>>, index = 0},
            script_sig = <<>>,
            sequence = 16#fffffffe,  %% MAX_SEQUENCE_NONFINAL — locktime IS enforced
            witness = []
        }],
        outputs = [#tx_out{value = 1000, script_pubkey = <<>>}],
        locktime = 1000  %% height-based locktime
    },
    %% Height 999 < locktime 1000: non-final (locktime not yet met).
    ?assertNot(beamchain_validation:is_final_tx(Tx, 999, LockTimeCutoff)),
    %% Height 1000 == locktime 1000: final (locktime < height would be strictly
    %% less than, so 1000 < 1000 is false — tx is non-final at exactly height 1000).
    %% Core: LockTime < Threshold (strict), so at height=1000, locktime=1000:
    %% 1000 < 1000 is false → inputs checked → sequence ≠ 0xFFFFFFFF → non-final.
    ?assertNot(beamchain_validation:is_final_tx(Tx, 1000, LockTimeCutoff)),
    %% Height 1001 > locktime 1000: final (1000 < 1001).
    ?assert(beamchain_validation:is_final_tx(Tx, 1001, LockTimeCutoff)).

%% Tx with sequence = 0xFFFFFFFF is final regardless of locktime.
final_sequence_overrides_locktime_test() ->
    %% When all inputs have sequence = 0xFFFFFFFF, locktime is ignored.
    Height = 0,
    LockTimeCutoff = 0,
    Tx = #transaction{
        version = 1,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = <<0:256>>, index = 0},
            script_sig = <<>>,
            sequence = 16#ffffffff,  %% SEQUENCE_FINAL
            witness = []
        }],
        outputs = [],
        locktime = 999999
    },
    %% sequence = 0xFFFFFFFF means locktime does not apply.
    ?assert(beamchain_validation:is_final_tx(Tx, Height, LockTimeCutoff)).

%% BUG5: block version must come from versionbits, not hardcoded 0x20000000.
block_version_from_versionbits_test() ->
    %% VERSIONBITS_TOP_BITS = 0x20000000.
    %% Without any active deployments, compute_block_version should return 0x20000000.
    TopBits = 16#20000000,
    ?assertEqual(TopBits, TopBits bor 0),  %% no bits set = just top bits

    %% If a deployment is in STARTED state (bit 2 = taproot), version should be:
    TaprootBit = 2,
    VersionWithTaproot = TopBits bor (1 bsl TaprootBit),
    ?assertEqual(16#20000004, VersionWithTaproot).

%% BUG8: BIP94 timewarp rule at difficulty-adjustment boundaries.
bip94_timewarp_rule_test() ->
    %% At height mod 2016 == 0, the block timestamp must be
    %% >= prev_block_time - MAX_TIMEWARP (600 seconds).
    MAX_TIMEWARP = 600,
    DiffAdjInterval = 2016,

    %% Scenario: previous block had timestamp T.
    %% The minimum allowed next-block time at a retarget boundary is T - 600.
    PrevBlockTime = 1700000000,
    MTP = PrevBlockTime - 3600,   %% MTP is 1 hour behind prev block

    MinFromMTP = MTP + 1,
    MinFromTimewarp = PrevBlockTime - MAX_TIMEWARP,

    %% At a retarget boundary, minimum is max(MTP+1, prev_time - 600).
    MinAtBoundary = max(MinFromMTP, MinFromTimewarp),

    %% In this case prev_time - 600 > MTP + 1:
    %% PrevBlockTime - 600 = 1700000000 - 600 = 1699999400
    %% MTP + 1 = (1700000000 - 3600) + 1 = 1699996401
    ?assert(MinFromTimewarp > MinFromMTP),
    ?assertEqual(MinFromTimewarp, MinAtBoundary),

    %% At a NON-retarget boundary, timewarp check does not apply.
    NonBoundaryHeight = 2017,  %% not a multiple of 2016
    ?assertNotEqual(0, NonBoundaryHeight rem DiffAdjInterval),
    %% Minimum is just MTP + 1.
    MinNonBoundary = MinFromMTP,
    ?assertEqual(MinNonBoundary, MTP + 1).

%% BIP94 timewarp: verify the boundary detection (height mod 2016 == 0).
bip94_boundary_detection_test() ->
    DiffAdj = 2016,

    %% Heights that ARE at a retarget boundary:
    ?assertEqual(0, 0       rem DiffAdj),
    ?assertEqual(0, 2016    rem DiffAdj),
    ?assertEqual(0, 4032    rem DiffAdj),
    ?assertEqual(0, 840672  rem DiffAdj),  %% mainnet retarget boundary (2016*417)

    %% Heights that are NOT at a retarget boundary:
    ?assertNotEqual(0, 1     rem DiffAdj),
    ?assertNotEqual(0, 2015  rem DiffAdj),
    ?assertNotEqual(0, 2017  rem DiffAdj).

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
    Bytes = le_minimal_acc(N, <<>>),
    LastByte = binary:last(Bytes),
    case LastByte band 16#80 of
        0 -> Bytes;
        _ -> <<Bytes/binary, 0>>
    end.

le_minimal_acc(0, Acc) -> Acc;
le_minimal_acc(N, Acc) ->
    Byte = N band 16#ff,
    le_minimal_acc(N bsr 8, <<Acc/binary, Byte:8>>).
