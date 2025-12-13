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
%%% Helper functions
%%% ===================================================================

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
