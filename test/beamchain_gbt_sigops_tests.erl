-module(beamchain_gbt_sigops_tests).
%% getblocktemplate transactions[i].sigops is Core's GetTransactionSigOpCost
%% (legacy*4 + P2SH*4 + witness).  beamchain counted legacy sigops only, so a
%% P2WPKH spend reported 0 where Core reports 1.

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

tx(ScriptSig, Witness, OutSPK) ->
    #transaction{version = 2, locktime = 0,
        inputs = [#tx_in{prev_out = #outpoint{hash = <<7:256>>, index = 0},
                         script_sig = ScriptSig, sequence = 16#ffffffff,
                         witness = Witness}],
        outputs = [#tx_out{value = 1000, script_pubkey = OutSPK}]}.

coin(SPK) ->
    #utxo{value = 5000, script_pubkey = SPK, is_coinbase = false, height = 1}.

p2wpkh_spend_costs_one_sigop_test() ->
    SPK = <<0, 20, 0:160>>,
    Tx = tx(<<>>, [<<1:8>>, <<2:8>>], <<0, 20, 1:160>>),
    ?assertEqual(1, beamchain_miner:tx_sigop_cost(Tx, [coin(SPK)])).

p2wsh_spend_counts_witness_script_sigops_test() ->
    SPK = <<0, 32, 0:256>>,
    WS = <<16#ac, 16#ac>>,   %% two OP_CHECKSIG
    Tx = tx(<<>>, [<<1:8>>, WS], <<0, 20, 1:160>>),
    ?assertEqual(2, beamchain_miner:tx_sigop_cost(Tx, [coin(SPK)])).

p2sh_p2wpkh_spend_costs_one_sigop_test() ->
    Redeem = <<0, 20, 0:160>>,
    SPK = <<16#a9, 20, 0:160, 16#87>>,
    Tx = tx(<<22, Redeem/binary>>, [<<1:8>>, <<2:8>>], <<0, 20, 1:160>>),
    ?assertEqual(1, beamchain_miner:tx_sigop_cost(Tx, [coin(SPK)])).

legacy_output_checksig_is_scaled_test() ->
    SPK = <<16#76, 16#a9, 20, 0:160, 16#88, 16#ac>>,
    Tx = tx(<<>>, [], <<16#ac>>),
    ?assertEqual(4, beamchain_miner:tx_sigop_cost(Tx, [coin(SPK)])).
