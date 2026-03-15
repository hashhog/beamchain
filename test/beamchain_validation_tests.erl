-module(beamchain_validation_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%%% ===================================================================
%%% check_transaction tests
%%% ===================================================================

%% a valid coinbase transaction should pass
valid_coinbase_test() ->
    Tx = make_coinbase_tx(<<4, 1, 0, 0, 0>>, 5000000000),
    ?assertEqual(ok, beamchain_validation:check_transaction(Tx)).

%% a valid regular transaction should pass
valid_regular_tx_test() ->
    Tx = make_regular_tx(
        [{<<1:256>>, 0}],
        [{50000000, <<16#76, 16#a9, 16#14, 0:160, 16#88, 16#ac>>}]
    ),
    ?assertEqual(ok, beamchain_validation:check_transaction(Tx)).

%% no inputs should fail
no_inputs_test() ->
    Tx = #transaction{
        version = 1,
        inputs = [],
        outputs = [#tx_out{value = 1000, script_pubkey = <<16#6a>>}],
        locktime = 0
    },
    ?assertEqual({error, no_inputs}, beamchain_validation:check_transaction(Tx)).

%% no outputs should fail
no_outputs_test() ->
    Tx = #transaction{
        version = 1,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = <<1:256>>, index = 0},
            script_sig = <<>>,
            sequence = 16#ffffffff,
            witness = []
        }],
        outputs = [],
        locktime = 0
    },
    ?assertEqual({error, no_outputs}, beamchain_validation:check_transaction(Tx)).

%% output value > MAX_MONEY should fail
output_too_large_test() ->
    Tx = make_regular_tx(
        [{<<1:256>>, 0}],
        [{?MAX_MONEY + 1, <<16#6a>>}]
    ),
    ?assertEqual({error, output_too_large},
                 beamchain_validation:check_transaction(Tx)).

%% total output overflow should fail
total_output_overflow_test() ->
    Tx = make_regular_tx(
        [{<<1:256>>, 0}],
        [{?MAX_MONEY, <<16#6a>>}, {1, <<16#6a>>}]
    ),
    ?assertEqual({error, total_output_overflow},
                 beamchain_validation:check_transaction(Tx)).

%% duplicate inputs should fail
duplicate_inputs_test() ->
    Tx = make_regular_tx(
        [{<<1:256>>, 0}, {<<1:256>>, 0}],
        [{1000, <<16#6a>>}]
    ),
    ?assertEqual({error, duplicate_inputs},
                 beamchain_validation:check_transaction(Tx)).

%% coinbase with too-short scriptSig should fail
coinbase_short_scriptsig_test() ->
    Tx = #transaction{
        version = 1,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = <<0:256>>, index = 16#ffffffff},
            script_sig = <<1>>,  %% only 1 byte, minimum is 2
            sequence = 16#ffffffff,
            witness = []
        }],
        outputs = [#tx_out{value = 5000000000, script_pubkey = <<>>}],
        locktime = 0
    },
    ?assertEqual({error, bad_coinbase_length},
                 beamchain_validation:check_transaction(Tx)).

%% non-coinbase with null outpoint should fail
null_input_test() ->
    Tx = #transaction{
        version = 1,
        inputs = [
            #tx_in{
                prev_out = #outpoint{hash = <<0:256>>, index = 16#ffffffff},
                script_sig = <<>>,
                sequence = 16#ffffffff,
                witness = []
            },
            #tx_in{
                prev_out = #outpoint{hash = <<1:256>>, index = 0},
                script_sig = <<>>,
                sequence = 16#ffffffff,
                witness = []
            }
        ],
        outputs = [#tx_out{value = 1000, script_pubkey = <<>>}],
        locktime = 0
    },
    %% this has 2 inputs so it's not a coinbase, but first input is null
    ?assertEqual({error, null_input},
                 beamchain_validation:check_transaction(Tx)).

%%% ===================================================================
%%% check_block_header tests
%%% ===================================================================

%% genesis block header should pass (mainnet)
genesis_header_valid_test() ->
    Params = beamchain_chain_params:params(mainnet),
    Genesis = beamchain_chain_params:genesis_block(mainnet),
    ?assertEqual(ok,
                 beamchain_validation:check_block_header(
                     Genesis#block.header, Params)).

%% regtest genesis should pass
regtest_genesis_header_test() ->
    Params = beamchain_chain_params:params(regtest),
    Genesis = beamchain_chain_params:genesis_block(regtest),
    ?assertEqual(ok,
                 beamchain_validation:check_block_header(
                     Genesis#block.header, Params)).

%%% ===================================================================
%%% check_block tests
%%% ===================================================================

%% genesis block should pass full check
genesis_block_valid_test() ->
    Params = beamchain_chain_params:params(mainnet),
    Genesis = beamchain_chain_params:genesis_block(mainnet),
    ?assertEqual(ok, beamchain_validation:check_block(Genesis, Params)).

%% regtest genesis should pass
regtest_genesis_block_test() ->
    Params = beamchain_chain_params:params(regtest),
    Genesis = beamchain_chain_params:genesis_block(regtest),
    ?assertEqual(ok, beamchain_validation:check_block(Genesis, Params)).

%% block with no transactions should fail
empty_block_test() ->
    Params = beamchain_chain_params:params(regtest),
    Genesis = beamchain_chain_params:genesis_block(regtest),
    EmptyBlock = Genesis#block{transactions = []},
    ?assertMatch({error, _}, beamchain_validation:check_block(EmptyBlock, Params)).

%%% ===================================================================
%%% count_legacy_sigops tests
%%% ===================================================================

%% empty script has 0 sigops
legacy_sigops_empty_test() ->
    ?assertEqual(0, beamchain_validation:count_legacy_sigops(<<>>)).

%% OP_CHECKSIG counts as 1
legacy_sigops_checksig_test() ->
    ?assertEqual(1, beamchain_validation:count_legacy_sigops(<<16#ac>>)).

%% OP_CHECKSIGVERIFY counts as 1
legacy_sigops_checksigverify_test() ->
    ?assertEqual(1, beamchain_validation:count_legacy_sigops(<<16#ad>>)).

%% OP_CHECKMULTISIG counts as 20 (max pubkeys)
legacy_sigops_checkmultisig_test() ->
    ?assertEqual(20, beamchain_validation:count_legacy_sigops(<<16#ae>>)).

%% combined: P2PKH scriptPubKey has 1 sigop
legacy_sigops_p2pkh_test() ->
    %% OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    Script = <<16#76, 16#a9, 16#14, 0:160, 16#88, 16#ac>>,
    ?assertEqual(1, beamchain_validation:count_legacy_sigops(Script)).

%% data push is skipped correctly
legacy_sigops_with_push_test() ->
    %% push 3 bytes, then OP_CHECKSIG
    Script = <<3, 1, 2, 3, 16#ac>>,
    ?assertEqual(1, beamchain_validation:count_legacy_sigops(Script)).

%%% ===================================================================
%%% is_coinbase_tx tests
%%% ===================================================================

is_coinbase_test() ->
    Cb = make_coinbase_tx(<<4, 1, 0, 0, 0>>, 5000000000),
    ?assert(beamchain_validation:is_coinbase_tx(Cb)).

is_not_coinbase_test() ->
    Tx = make_regular_tx(
        [{<<1:256>>, 0}],
        [{1000, <<16#6a>>}]
    ),
    ?assertNot(beamchain_validation:is_coinbase_tx(Tx)).

%%% ===================================================================
%%% block_subsidy tests
%%% ===================================================================

subsidy_at_genesis_test() ->
    ?assertEqual(5000000000, beamchain_chain_params:block_subsidy(0, mainnet)).

subsidy_first_halving_test() ->
    %% at height 210000, subsidy halves to 25 BTC
    ?assertEqual(2500000000, beamchain_chain_params:block_subsidy(210000, mainnet)).

subsidy_just_before_halving_test() ->
    %% at height 209999, still 50 BTC
    ?assertEqual(5000000000, beamchain_chain_params:block_subsidy(209999, mainnet)).

subsidy_second_halving_test() ->
    ?assertEqual(1250000000, beamchain_chain_params:block_subsidy(420000, mainnet)).

subsidy_third_halving_test() ->
    ?assertEqual(625000000, beamchain_chain_params:block_subsidy(630000, mainnet)).

subsidy_after_64_halvings_test() ->
    %% 64 halvings = height 64 * 210000 = 13,440,000
    ?assertEqual(0, beamchain_chain_params:block_subsidy(13440000, mainnet)).

subsidy_at_very_high_height_test() ->
    %% well past all halvings
    ?assertEqual(0, beamchain_chain_params:block_subsidy(100000000, mainnet)).

subsidy_regtest_halving_interval_test() ->
    %% regtest halves every 150 blocks
    ?assertEqual(5000000000, beamchain_chain_params:block_subsidy(0, regtest)),
    ?assertEqual(5000000000, beamchain_chain_params:block_subsidy(149, regtest)),
    ?assertEqual(2500000000, beamchain_chain_params:block_subsidy(150, regtest)),
    ?assertEqual(1250000000, beamchain_chain_params:block_subsidy(300, regtest)).

%%% ===================================================================
%%% Genesis block tests across networks
%%% ===================================================================

testnet4_genesis_valid_test() ->
    Params = beamchain_chain_params:params(testnet4),
    Genesis = beamchain_chain_params:genesis_block(testnet4),
    ?assertEqual(ok, beamchain_validation:check_block(Genesis, Params)).

signet_genesis_valid_test() ->
    Params = beamchain_chain_params:params(signet),
    Genesis = beamchain_chain_params:genesis_block(signet),
    ?assertEqual(ok, beamchain_validation:check_block(Genesis, Params)).

%% verify genesis hashes match expected values
mainnet_genesis_hash_test() ->
    Genesis = beamchain_chain_params:genesis_block(mainnet),
    DisplayHash = beamchain_serialize:hex_encode(
        beamchain_serialize:reverse_bytes(Genesis#block.hash)),
    ?assertEqual(
        <<"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f">>,
        DisplayHash).

regtest_genesis_hash_test() ->
    Genesis = beamchain_chain_params:genesis_block(regtest),
    DisplayHash = beamchain_serialize:hex_encode(
        beamchain_serialize:reverse_bytes(Genesis#block.hash)),
    ?assertEqual(
        <<"0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206">>,
        DisplayHash).

testnet4_genesis_hash_test() ->
    Genesis = beamchain_chain_params:genesis_block(testnet4),
    DisplayHash = beamchain_serialize:hex_encode(
        beamchain_serialize:reverse_bytes(Genesis#block.hash)),
    ?assertEqual(
        <<"00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043">>,
        DisplayHash).

%%% ===================================================================
%%% chain params tests
%%% ===================================================================

params_mainnet_test() ->
    P = beamchain_chain_params:params(mainnet),
    ?assertEqual(mainnet, maps:get(network, P)),
    ?assertEqual(8333, maps:get(default_port, P)),
    ?assertEqual(8332, maps:get(rpc_port, P)),
    ?assertEqual("bc", maps:get(bech32_hrp, P)),
    ?assertEqual(0, maps:get(pubkey_prefix, P)),
    ?assertEqual(5, maps:get(script_prefix, P)).

params_testnet4_test() ->
    P = beamchain_chain_params:params(testnet4),
    ?assertEqual(testnet4, maps:get(network, P)),
    ?assertEqual(48333, maps:get(default_port, P)),
    ?assertEqual(48332, maps:get(rpc_port, P)),
    ?assertEqual("tb", maps:get(bech32_hrp, P)),
    %% testnet4 has all BIPs active from block 1
    ?assertEqual(1, maps:get(bip34_height, P)),
    ?assertEqual(1, maps:get(segwit_height, P)),
    ?assertEqual(1, maps:get(taproot_height, P)).

params_regtest_test() ->
    P = beamchain_chain_params:params(regtest),
    ?assertEqual(regtest, maps:get(network, P)),
    ?assertEqual(18444, maps:get(default_port, P)),
    ?assertEqual(true, maps:get(pow_no_retargeting, P)),
    ?assertEqual(150, maps:get(subsidy_halving_interval, P)),
    ?assertEqual("bcrt", maps:get(bech32_hrp, P)).

params_signet_test() ->
    P = beamchain_chain_params:params(signet),
    ?assertEqual(signet, maps:get(network, P)),
    ?assertEqual(38333, maps:get(default_port, P)),
    ?assertEqual("tb", maps:get(bech32_hrp, P)).

%%% ===================================================================
%%% Negative value output test
%%% ===================================================================

negative_output_test() ->
    %% output value of 0 should be ok (e.g. OP_RETURN outputs)
    Tx = make_regular_tx(
        [{<<1:256>>, 0}],
        [{0, <<16#6a, 4, "test">>}]
    ),
    ?assertEqual(ok, beamchain_validation:check_transaction(Tx)).

%%% ===================================================================
%%% Multiple sigops counting
%%% ===================================================================

legacy_sigops_multiple_test() ->
    %% OP_CHECKSIG OP_CHECKSIG OP_CHECKMULTISIG = 1 + 1 + 20 = 22
    Script = <<16#ac, 16#ac, 16#ae>>,
    ?assertEqual(22, beamchain_validation:count_legacy_sigops(Script)).

%%% ===================================================================
%%% Accurate sigops counting (for P2SH and witness scripts)
%%% ===================================================================

%% empty script has 0 sigops
accurate_sigops_empty_test() ->
    ?assertEqual(0, beamchain_validation:count_sigops_accurate(<<>>)).

%% OP_CHECKSIG counts as 1
accurate_sigops_checksig_test() ->
    ?assertEqual(1, beamchain_validation:count_sigops_accurate(<<16#ac>>)).

%% OP_CHECKSIGVERIFY counts as 1
accurate_sigops_checksigverify_test() ->
    ?assertEqual(1, beamchain_validation:count_sigops_accurate(<<16#ad>>)).

%% OP_CHECKMULTISIG with OP_2 preceding counts as 2
accurate_sigops_2of2_multisig_test() ->
    %% OP_2 OP_CHECKMULTISIG (2-of-2 multisig)
    Script = <<16#52, 16#ae>>,
    ?assertEqual(2, beamchain_validation:count_sigops_accurate(Script)).

%% OP_CHECKMULTISIG with OP_3 preceding counts as 3
accurate_sigops_2of3_multisig_test() ->
    %% OP_2 <pubkey1> <pubkey2> <pubkey3> OP_3 OP_CHECKMULTISIG
    %% Only the OP_3 preceding CHECKMULTISIG matters for sigop count
    Pk = binary:copy(<<1>>, 33),  %% 33-byte pubkey
    Script = <<16#52, 33, Pk/binary, 33, Pk/binary, 33, Pk/binary, 16#53, 16#ae>>,
    ?assertEqual(3, beamchain_validation:count_sigops_accurate(Script)).

%% OP_CHECKMULTISIG with OP_16 preceding counts as 16
accurate_sigops_16_multisig_test() ->
    %% OP_16 OP_CHECKMULTISIG
    Script = <<16#60, 16#ae>>,
    ?assertEqual(16, beamchain_validation:count_sigops_accurate(Script)).

%% OP_CHECKMULTISIG with OP_0 preceding counts as 0
accurate_sigops_0_multisig_test() ->
    %% OP_0 OP_CHECKMULTISIG (0-of-0 multisig, edge case)
    Script = <<16#00, 16#ae>>,
    ?assertEqual(0, beamchain_validation:count_sigops_accurate(Script)).

%% OP_CHECKMULTISIG without valid preceding OP_N uses max (20)
accurate_sigops_invalid_preceding_test() ->
    %% OP_DUP OP_CHECKMULTISIG (no OP_N preceding)
    Script = <<16#76, 16#ae>>,
    ?assertEqual(20, beamchain_validation:count_sigops_accurate(Script)).

%% OP_CHECKMULTISIGVERIFY with OP_5 preceding counts as 5
accurate_sigops_5of5_multisigverify_test() ->
    %% OP_5 OP_CHECKMULTISIGVERIFY
    Script = <<16#55, 16#af>>,
    ?assertEqual(5, beamchain_validation:count_sigops_accurate(Script)).

%% Multiple multisig operations in one script
accurate_sigops_multiple_multisig_test() ->
    %% OP_2 OP_CHECKMULTISIG OP_3 OP_CHECKMULTISIG = 2 + 3 = 5
    Script = <<16#52, 16#ae, 16#53, 16#ae>>,
    ?assertEqual(5, beamchain_validation:count_sigops_accurate(Script)).

%% Mixed checksig and checkmultisig
accurate_sigops_mixed_test() ->
    %% OP_CHECKSIG OP_3 OP_CHECKMULTISIG OP_CHECKSIGVERIFY = 1 + 3 + 1 = 5
    Script = <<16#ac, 16#53, 16#ae, 16#ad>>,
    ?assertEqual(5, beamchain_validation:count_sigops_accurate(Script)).

%% Data push followed by CHECKMULTISIG uses max (push opcodes aren't OP_N)
accurate_sigops_push_before_multisig_test() ->
    %% push 2 bytes, then OP_CHECKMULTISIG
    %% The push opcode (0x02) is NOT OP_2 (0x52), so it uses max
    Script = <<2, 1, 2, 16#ae>>,
    ?assertEqual(20, beamchain_validation:count_sigops_accurate(Script)).

%% Compare accurate vs legacy for 2-of-3 multisig
sigops_accurate_vs_legacy_test() ->
    %% OP_2 <pk1> <pk2> <pk3> OP_3 OP_CHECKMULTISIG
    Pk = binary:copy(<<1>>, 33),
    Script = <<16#52, 33, Pk/binary, 33, Pk/binary, 33, Pk/binary, 16#53, 16#ae>>,
    %% Legacy always counts 20 for CHECKMULTISIG
    ?assertEqual(20, beamchain_validation:count_legacy_sigops(Script)),
    %% Accurate counts the actual key count (3)
    ?assertEqual(3, beamchain_validation:count_sigops_accurate(Script)).

%%% ===================================================================
%%% Block weight enforcement (check_block rejects oversized)
%%% ===================================================================

overweight_block_test() ->
    %% create a block with a huge transaction that exceeds MAX_BLOCK_WEIGHT
    %% A single output with a very large scriptPubKey
    BigScript = binary:copy(<<16#6a>>, 1100000),  %% ~1.1MB of OP_RETURN
    Tx = #transaction{
        version = 1,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = <<0:256>>, index = 16#ffffffff},
            script_sig = <<4, 1, 0, 0, 0>>,
            sequence = 16#ffffffff,
            witness = []
        }],
        outputs = [#tx_out{value = 5000000000, script_pubkey = BigScript}],
        locktime = 0
    },
    Merkle = beamchain_serialize:tx_hash(Tx),
    Header = #block_header{
        version = 1,
        prev_hash = <<0:256>>,
        merkle_root = Merkle,
        timestamp = 1296688602,
        bits = 16#207fffff,
        nonce = 0
    },
    Block = #block{header = Header, transactions = [Tx]},
    Params = beamchain_chain_params:params(regtest),
    Result = beamchain_validation:check_block(Block, Params),
    ?assertMatch({error, _}, Result).

%%% ===================================================================
%%% BIP 68 sequence lock tests
%%% ===================================================================

%% Test that version 1 transactions skip sequence lock checks
sequence_lock_version_1_test() ->
    %% Version 1 tx should not be affected by sequence locks
    Tx = #transaction{
        version = 1,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = <<1:256>>, index = 0},
            script_sig = <<>>,
            sequence = 10,  %% would be 10-block lock if enforced
            witness = []
        }],
        outputs = [#tx_out{value = 1000, script_pubkey = <<16#6a>>}],
        locktime = 0
    },
    InputCoins = [#utxo{
        value = 2000,
        script_pubkey = <<>>,
        is_coinbase = false,
        height = 100
    }],
    %% For version 1, should return {-1, -1} regardless of sequence
    ?assertEqual({-1, -1},
                 beamchain_validation:calculate_sequence_lock_pair(
                     Tx, InputCoins, #{})).

%% Test that disable flag skips sequence lock for that input
sequence_lock_disable_flag_test() ->
    %% Bit 31 set = disable sequence lock
    DisableSeq = 16#80000010,  %% disable flag + 16 blocks
    Tx = make_tx_with_sequence([DisableSeq]),
    InputCoins = [#utxo{
        value = 2000,
        script_pubkey = <<>>,
        is_coinbase = false,
        height = 100
    }],
    %% Disable flag means no lock constraint
    ?assertEqual({-1, -1},
                 beamchain_validation:calculate_sequence_lock_pair(
                     Tx, InputCoins, #{})).

%% Test height-based sequence lock calculation
sequence_lock_height_based_test() ->
    %% 10 blocks relative lock (no type flag = height-based)
    Seq = 10,
    Tx = make_tx_with_sequence([Seq]),
    InputCoins = [#utxo{
        value = 2000,
        script_pubkey = <<>>,
        is_coinbase = false,
        height = 100
    }],
    %% MinHeight should be coinHeight + value - 1 = 100 + 10 - 1 = 109
    {MinH, MinT} = beamchain_validation:calculate_sequence_lock_pair(
        Tx, InputCoins, #{}),
    ?assertEqual(109, MinH),
    ?assertEqual(-1, MinT).

%% Test multiple inputs with height-based locks (takes max)
sequence_lock_height_multiple_inputs_test() ->
    %% Two inputs with different height locks
    Seq1 = 5,   %% 5 blocks
    Seq2 = 15,  %% 15 blocks
    Tx = make_tx_with_sequence([Seq1, Seq2]),
    InputCoins = [
        #utxo{value = 1000, script_pubkey = <<>>, is_coinbase = false, height = 100},
        #utxo{value = 1000, script_pubkey = <<>>, is_coinbase = false, height = 110}
    ],
    %% MinHeight = max(100 + 5 - 1, 110 + 15 - 1) = max(104, 124) = 124
    {MinH, MinT} = beamchain_validation:calculate_sequence_lock_pair(
        Tx, InputCoins, #{}),
    ?assertEqual(124, MinH),
    ?assertEqual(-1, MinT).

%% Test mixed inputs: one disabled, one with height lock
sequence_lock_mixed_inputs_test() ->
    DisableSeq = 16#80000020,  %% disabled
    HeightSeq = 8,              %% 8 blocks
    Tx = make_tx_with_sequence([DisableSeq, HeightSeq]),
    InputCoins = [
        #utxo{value = 1000, script_pubkey = <<>>, is_coinbase = false, height = 50},
        #utxo{value = 1000, script_pubkey = <<>>, is_coinbase = false, height = 200}
    ],
    %% Only the second input contributes: 200 + 8 - 1 = 207
    {MinH, MinT} = beamchain_validation:calculate_sequence_lock_pair(
        Tx, InputCoins, #{}),
    ?assertEqual(207, MinH),
    ?assertEqual(-1, MinT).

%% Test sequence lock mask (only lower 16 bits matter)
sequence_lock_mask_test() ->
    %% Set some bits above the mask, but only low 16 bits count
    Seq = 16#00010005,  %% upper bits set, but lock is only 5 blocks
    Tx = make_tx_with_sequence([Seq]),
    InputCoins = [#utxo{
        value = 2000,
        script_pubkey = <<>>,
        is_coinbase = false,
        height = 100
    }],
    {MinH, _} = beamchain_validation:calculate_sequence_lock_pair(
        Tx, InputCoins, #{}),
    ?assertEqual(104, MinH).  %% 100 + 5 - 1 = 104

%%% ===================================================================
%%% Helper functions
%%% ===================================================================

%% Create a version 2 transaction with specified sequence numbers
make_tx_with_sequence(Sequences) ->
    Inputs = lists:map(fun({Seq, Idx}) ->
        #tx_in{
            prev_out = #outpoint{hash = <<Idx:256>>, index = 0},
            script_sig = <<>>,
            sequence = Seq,
            witness = []
        }
    end, lists:zip(Sequences, lists:seq(1, length(Sequences)))),
    #transaction{
        version = 2,
        inputs = Inputs,
        outputs = [#tx_out{value = 1000, script_pubkey = <<16#6a>>}],
        locktime = 0
    }.

make_coinbase_tx(ScriptSig, Value) ->
    #transaction{
        version = 1,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = <<0:256>>, index = 16#ffffffff},
            script_sig = ScriptSig,
            sequence = 16#ffffffff,
            witness = []
        }],
        outputs = [#tx_out{
            value = Value,
            script_pubkey = <<16#76, 16#a9, 16#14, 0:160, 16#88, 16#ac>>
        }],
        locktime = 0
    }.

make_regular_tx(Inputs, Outputs) ->
    TxIns = lists:map(fun({Hash, Index}) ->
        #tx_in{
            prev_out = #outpoint{hash = Hash, index = Index},
            script_sig = <<>>,
            sequence = 16#ffffffff,
            witness = []
        }
    end, Inputs),
    TxOuts = lists:map(fun({Value, Script}) ->
        #tx_out{value = Value, script_pubkey = Script}
    end, Outputs),
    #transaction{
        version = 1,
        inputs = TxIns,
        outputs = TxOuts,
        locktime = 0
    }.
