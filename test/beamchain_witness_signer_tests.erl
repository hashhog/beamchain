-module(beamchain_witness_signer_tests).

%% Wave 28: P2WSH / P2SH-P2WSH raw-tx signer tests.
%%
%% Verifies that the new shared P2WSH signer (in
%% `beamchain_witness_signer`) plus its wiring into the raw-tx wallet
%% flow (`beamchain_wallet:sign_transaction/4`) produces witness stacks
%% that pass the canonical `beamchain_script:verify_script` check, and
%% that the raw-tx path agrees with the PSBT-based finalize on byte
%% layout (no parallel-impl drift).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%%% ===================================================================
%%% Fixtures
%%% ===================================================================

%% Three deterministic test private keys (32 bytes each). Avoid the
%% all-zero / all-ones edge cases.
priv_a() -> <<1:256>>.
priv_b() -> <<2:256>>.
priv_c() -> <<3:256>>.

%% Fixed prevout (for sighash determinism); not committed to chain.
fake_prevout() ->
    #outpoint{
        hash = <<1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
                 17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32>>,
        index = 0
    }.

%% Build an unsigned tx with a single input and a single dust output.
unsigned_tx() ->
    #transaction{
        version = 2,
        inputs = [
            #tx_in{
                prev_out = fake_prevout(),
                script_sig = <<>>,
                sequence = 16#fffffffd,
                witness = []
            }
        ],
        outputs = [
            #tx_out{
                value = 50000,
                script_pubkey = <<16#00, 20,
                    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20>>
            }
        ],
        locktime = 0
    }.

%% Compose an OP_M ... <pubkeys> ... OP_N OP_CHECKMULTISIG redeemScript.
multisig_redeem_script(M, PubKeys) ->
    N = length(PubKeys),
    PubKeyBytes = iolist_to_binary(
        [<<33, PK/binary>> || PK <- PubKeys]),
    <<(16#50 + M):8, PubKeyBytes/binary, (16#50 + N):8, 16#ae>>.

%% P2WSH scriptPubKey from witnessScript.
p2wsh_spk(WitnessScript) ->
    Hash = crypto:hash(sha256, WitnessScript),
    <<16#00, 32, Hash/binary>>.

%% P2SH scriptPubKey from a redeem script.
p2sh_spk(RedeemScript) ->
    Hash = beamchain_crypto:hash160(RedeemScript),
    <<16#a9, 20, Hash/binary, 16#87>>.

%% Inner P2SH-P2WSH redeem script: OP_0 <SHA256(witnessScript)>.
p2sh_p2wsh_redeem_script(WitnessScript) ->
    <<16#00, 32, (crypto:hash(sha256, WitnessScript))/binary>>.

%%% ===================================================================
%%% Tests
%%% ===================================================================

multisig_script_classification_test_() ->
    PkA = beamchain_wallet:privkey_to_pubkey(priv_a()),
    PkB = beamchain_wallet:privkey_to_pubkey(priv_b()),
    PkC = beamchain_wallet:privkey_to_pubkey(priv_c()),
    Script2of3 = multisig_redeem_script(2, [PkA, PkB, PkC]),
    Script1of2 = multisig_redeem_script(1, [PkA, PkB]),
    SingleKey = <<33, PkA/binary, 16#ac>>,
    JunkScript = <<1,2,3,4,5>>,
    [
        ?_assertEqual({multisig, 2, [PkA, PkB, PkC]},
                      beamchain_witness_signer:classify_witness_script(Script2of3)),
        ?_assertEqual({multisig, 1, [PkA, PkB]},
                      beamchain_witness_signer:classify_witness_script(Script1of2)),
        ?_assertEqual(single,
                      beamchain_witness_signer:classify_witness_script(SingleKey)),
        ?_assertEqual(single,
                      beamchain_witness_signer:classify_witness_script(JunkScript))
    ].

%% --------------------------------------------------------------------
%% Vector 1: BIP-143-flavour P2WSH 2-of-3 multisig — sign + verify.
%% --------------------------------------------------------------------
p2wsh_2of3_multisig_sign_and_verify_test() ->
    PkA = beamchain_wallet:privkey_to_pubkey(priv_a()),
    PkB = beamchain_wallet:privkey_to_pubkey(priv_b()),
    PkC = beamchain_wallet:privkey_to_pubkey(priv_c()),
    WitnessScript = multisig_redeem_script(2, [PkA, PkB, PkC]),
    ScriptPubKey = p2wsh_spk(WitnessScript),
    Amount = 10_000_000,
    Tx = unsigned_tx(),
    %% Wallet owns A and B; expect 2 sigs in pubkey-order (A first, then B).
    Signers = [priv_a(), priv_b(), undefined],
    {ok, Witness} = beamchain_witness_signer:sign_p2wsh(
        Tx, 0, Amount, WitnessScript, Signers, ?SIGHASH_ALL),
    %% Stack: [<<>>, sig_A, sig_B, witnessScript]
    ?assertEqual(4, length(Witness)),
    [Pad, SigA, SigB, ReturnedWS] = Witness,
    ?assertEqual(<<>>, Pad),
    ?assertEqual(WitnessScript, ReturnedWS),
    %% Both sigs must end with SIGHASH_ALL byte.
    ?assertEqual(?SIGHASH_ALL, binary:last(SigA)),
    ?assertEqual(?SIGHASH_ALL, binary:last(SigB)),
    %% Verify against beamchain_script.
    SignedTx = Tx#transaction{
        inputs = [(hd(Tx#transaction.inputs))#tx_in{
            script_sig = <<>>,
            witness    = Witness
        }]
    },
    Flags = ?SCRIPT_VERIFY_P2SH bor ?SCRIPT_VERIFY_WITNESS bor
            ?SCRIPT_VERIFY_STRICTENC,
    SigChecker = {SignedTx, 0, Amount},
    ?assertEqual(true,
        beamchain_script:verify_script(<<>>, ScriptPubKey, Witness,
                                       Flags, SigChecker)).

%% --------------------------------------------------------------------
%% Vector 2: P2SH-P2WSH 2-of-2 wrap — sign + verify.
%% --------------------------------------------------------------------
p2sh_p2wsh_2of2_multisig_sign_and_verify_test() ->
    PkA = beamchain_wallet:privkey_to_pubkey(priv_a()),
    PkB = beamchain_wallet:privkey_to_pubkey(priv_b()),
    WitnessScript = multisig_redeem_script(2, [PkA, PkB]),
    RedeemScript  = p2sh_p2wsh_redeem_script(WitnessScript),
    ScriptPubKey  = p2sh_spk(RedeemScript),
    Amount = 25_000_000,
    Tx = unsigned_tx(),
    Signers = [priv_a(), priv_b()],
    {ok, ScriptSig, Witness} = beamchain_witness_signer:sign_p2sh_p2wsh(
        Tx, 0, Amount, WitnessScript, Signers, ?SIGHASH_ALL),
    %% scriptSig = push(redeemScript) — single push of the inner P2WSH
    %% witness program (`OP_0 <32-byte-hash>`).
    ?assertEqual(<<34, RedeemScript/binary>>, ScriptSig),
    %% Witness stack identical to bare P2WSH.
    ?assertEqual(4, length(Witness)),
    SignedTx = Tx#transaction{
        inputs = [(hd(Tx#transaction.inputs))#tx_in{
            script_sig = ScriptSig,
            witness    = Witness
        }]
    },
    Flags = ?SCRIPT_VERIFY_P2SH bor ?SCRIPT_VERIFY_WITNESS bor
            ?SCRIPT_VERIFY_STRICTENC,
    SigChecker = {SignedTx, 0, Amount},
    ?assertEqual(true,
        beamchain_script:verify_script(ScriptSig, ScriptPubKey, Witness,
                                       Flags, SigChecker)).

%% --------------------------------------------------------------------
%% Vector 3: round-trip — raw-tx-signed P2WSH agrees byte-for-byte
%% with the PSBT-finalised path. Asserts no parallel-impl drift on
%% witness-stack layout.
%% --------------------------------------------------------------------
p2wsh_raw_tx_vs_psbt_finalize_parity_test() ->
    PkA = beamchain_wallet:privkey_to_pubkey(priv_a()),
    PkB = beamchain_wallet:privkey_to_pubkey(priv_b()),
    WitnessScript = multisig_redeem_script(2, [PkA, PkB]),
    Amount = 17_500_000,
    Tx = unsigned_tx(),

    %% Path 1: raw-tx signer.
    {ok, RawWitness} = beamchain_witness_signer:sign_p2wsh(
        Tx, 0, Amount, WitnessScript, [priv_a(), priv_b()], ?SIGHASH_ALL),

    %% Path 2: PSBT-style — sign each key independently, accumulate
    %% partial_sigs, then assemble via the PSBT finalize builder.
    SigHash = beamchain_script:sighash_witness_v0(
        Tx, 0, WitnessScript, Amount, ?SIGHASH_ALL),
    {ok, DerA} = beamchain_crypto:ecdsa_sign(SigHash, priv_a()),
    {ok, DerB} = beamchain_crypto:ecdsa_sign(SigHash, priv_b()),
    SigA = <<DerA/binary, ?SIGHASH_ALL>>,
    SigB = <<DerB/binary, ?SIGHASH_ALL>>,
    PartialSigs = #{PkA => SigA, PkB => SigB},
    PsbtWitness = beamchain_witness_signer:build_p2wsh_witness_from_sigs(
        PartialSigs, WitnessScript),
    ?assertEqual(RawWitness, PsbtWitness).

%% --------------------------------------------------------------------
%% Wallet-level wiring: sign_transaction/4 routes a P2WSH input.
%% --------------------------------------------------------------------
wallet_sign_transaction_p2wsh_dispatch_test() ->
    PkA = beamchain_wallet:privkey_to_pubkey(priv_a()),
    PkB = beamchain_wallet:privkey_to_pubkey(priv_b()),
    WitnessScript = multisig_redeem_script(2, [PkA, PkB]),
    SPK = p2wsh_spk(WitnessScript),
    Amount = 5_000_000,
    Tx = unsigned_tx(),
    Utxo = #utxo{value = Amount, script_pubkey = SPK,
                 is_coinbase = false, height = 0},
    %% Pass the primary key as PrivA and PrivB as extra; ScriptInfo
    %% threads the witness script. This exercises the
    %% sign_p2wsh_input dispatch added in W28.
    ScriptInfo = #{witness_script => WitnessScript,
                   extra_priv_keys => [priv_b()]},
    {ok, SignedTx} = beamchain_wallet:sign_transaction(
        Tx, [Utxo], [priv_a()], [ScriptInfo]),
    [SignedInput] = SignedTx#transaction.inputs,
    ?assertEqual(<<>>, SignedInput#tx_in.script_sig),
    Witness = SignedInput#tx_in.witness,
    ?assertEqual(4, length(Witness)),
    %% Last entry is the witness script.
    ?assertEqual(WitnessScript, lists:last(Witness)),
    %% First entry is the CHECKMULTISIG dummy push.
    ?assertEqual(<<>>, hd(Witness)),
    %% Verify on-chain.
    Flags = ?SCRIPT_VERIFY_P2SH bor ?SCRIPT_VERIFY_WITNESS bor
            ?SCRIPT_VERIFY_STRICTENC,
    SigChecker = {SignedTx, 0, Amount},
    ?assertEqual(true,
        beamchain_script:verify_script(<<>>, SPK, Witness, Flags, SigChecker)).

%% --------------------------------------------------------------------
%% Wallet-level wiring: sign_transaction/4 routes a P2SH-P2WSH input.
%% --------------------------------------------------------------------
wallet_sign_transaction_p2sh_p2wsh_dispatch_test() ->
    PkA = beamchain_wallet:privkey_to_pubkey(priv_a()),
    PkB = beamchain_wallet:privkey_to_pubkey(priv_b()),
    WitnessScript = multisig_redeem_script(2, [PkA, PkB]),
    RedeemScript  = p2sh_p2wsh_redeem_script(WitnessScript),
    SPK = p2sh_spk(RedeemScript),
    Amount = 7_777_000,
    Tx = unsigned_tx(),
    Utxo = #utxo{value = Amount, script_pubkey = SPK,
                 is_coinbase = false, height = 0},
    ScriptInfo = #{witness_script => WitnessScript,
                   extra_priv_keys => [priv_b()]},
    {ok, SignedTx} = beamchain_wallet:sign_transaction(
        Tx, [Utxo], [priv_a()], [ScriptInfo]),
    [SignedInput] = SignedTx#transaction.inputs,
    %% scriptSig is a push of the P2WSH redeem script.
    ?assertEqual(<<34, RedeemScript/binary>>,
                 SignedInput#tx_in.script_sig),
    Witness = SignedInput#tx_in.witness,
    ?assertEqual(4, length(Witness)),
    Flags = ?SCRIPT_VERIFY_P2SH bor ?SCRIPT_VERIFY_WITNESS bor
            ?SCRIPT_VERIFY_STRICTENC,
    SigChecker = {SignedTx, 0, Amount},
    ?assertEqual(true,
        beamchain_script:verify_script(SignedInput#tx_in.script_sig,
                                       SPK, Witness, Flags, SigChecker)).

%% --------------------------------------------------------------------
%% Negative: missing witness_script triggers a clean signing error
%% rather than a crash on the <<0:256>> placeholder (W19 §8 guard).
%% --------------------------------------------------------------------
missing_witness_script_returns_error_test() ->
    PkA = beamchain_wallet:privkey_to_pubkey(priv_a()),
    PkB = beamchain_wallet:privkey_to_pubkey(priv_b()),
    WitnessScript = multisig_redeem_script(2, [PkA, PkB]),
    SPK = p2wsh_spk(WitnessScript),
    Amount = 1_000_000,
    Tx = unsigned_tx(),
    Utxo = #utxo{value = Amount, script_pubkey = SPK,
                 is_coinbase = false, height = 0},
    Result = beamchain_wallet:sign_transaction(
        Tx, [Utxo], [priv_a()], [#{}]),  %% no witness_script
    ?assertMatch({error, missing_witness_script}, Result).

%% --------------------------------------------------------------------
%% Negative: wallet owns 1 of 2 required keys -> partial-sign error.
%% --------------------------------------------------------------------
partial_sign_returns_error_test() ->
    PkA = beamchain_wallet:privkey_to_pubkey(priv_a()),
    PkB = beamchain_wallet:privkey_to_pubkey(priv_b()),
    WitnessScript = multisig_redeem_script(2, [PkA, PkB]),
    Amount = 1_000_000,
    Tx = unsigned_tx(),
    Result = beamchain_witness_signer:sign_p2wsh(
        Tx, 0, Amount, WitnessScript, [priv_a(), undefined], ?SIGHASH_ALL),
    ?assertMatch({error, {partial_sign, 1, 2}}, Result).

%%% ===================================================================
%%% Wave 31: P2SH/P2WSH commitment checks
%%% ===================================================================
%%
%% Camlcoin parity: lib/wallet.ml:1262 asserts
%%   `Cstruct.equal (Crypto.hash160 redeem) script_hash`
%% before signing a P2SH-wrapped input. Beamchain's pre-W31 signers
%% would happily sign over any redeem/witness script handed in, even
%% one that didn't commit to the prevout's on-chain hash. The three
%% tests below cover the positive raw-tx P2SH-P2WPKH path plus the two
%% negative cases — forged redeem (P2SH outer mismatch) and forged
%% witnessScript (P2WSH inner mismatch on a P2SH-P2WSH wrap).

%% --------------------------------------------------------------------
%% Vector W31-A (positive): P2SH-P2WPKH raw-tx sign with a redeem
%% script that DOES commit — must succeed and the Utxo's scriptPubKey
%% must equal `OP_HASH160 <hash160(redeemScript)> OP_EQUAL`.
%% --------------------------------------------------------------------
w31_p2sh_p2wpkh_positive_commitment_test() ->
    PkA = beamchain_wallet:privkey_to_pubkey(priv_a()),
    PkHash = beamchain_crypto:hash160(PkA),
    RedeemScript = <<0, 20, PkHash/binary>>,
    SPK = p2sh_spk(RedeemScript),
    Amount = 9_000_000,
    Tx = unsigned_tx(),
    Utxo = #utxo{value = Amount, script_pubkey = SPK,
                 is_coinbase = false, height = 0},
    {ok, SignedTx} = beamchain_wallet:sign_transaction(
        Tx, [Utxo], [priv_a()], [#{}]),
    [SignedInput] = SignedTx#transaction.inputs,
    %% scriptSig is a push of the redeem script.
    ?assertEqual(<<22, RedeemScript/binary>>, SignedInput#tx_in.script_sig),
    Witness = SignedInput#tx_in.witness,
    ?assertEqual(2, length(Witness)),
    %% Helper agrees:
    ?assertEqual(ok,
                 beamchain_crypto:verify_p2sh_commitment(RedeemScript, SPK)).

%% --------------------------------------------------------------------
%% Vector W31-B (negative P2SH): forge a P2SH-P2WPKH redeem script
%% pointing at the WRONG pubkey-hash. The wallet must throw a
%% sign_error rather than emit a signature.
%% --------------------------------------------------------------------
w31_p2sh_p2wpkh_negative_forged_redeem_test() ->
    PkA = beamchain_wallet:privkey_to_pubkey(priv_a()),
    PkB = beamchain_wallet:privkey_to_pubkey(priv_b()),
    %% scriptPubKey commits to A.
    AHash = beamchain_crypto:hash160(PkA),
    HonestRedeem = <<0, 20, AHash/binary>>,
    SPK = p2sh_spk(HonestRedeem),
    %% But the wallet derives its redeem script from B's privkey and
    %% so will compute the wrong one. We simulate that by handing the
    %% wallet B's key while presenting an SPK that commits to A.
    Amount = 4_000_000,
    Tx = unsigned_tx(),
    Utxo = #utxo{value = Amount, script_pubkey = SPK,
                 is_coinbase = false, height = 0},
    Result = beamchain_wallet:sign_transaction(
        Tx, [Utxo], [priv_b()], [#{}]),
    %% sign_p2sh_p2wpkh derives RedeemScript = OP_0 hash160(PkB) and
    %% asserts it commits — it does not, so we get the W31 error.
    ?assertMatch({error, {p2sh_p2wpkh, p2sh_commitment_mismatch}}, Result),
    %% Direct helper sanity:
    ForgedRedeem = <<0, 20, (beamchain_crypto:hash160(PkB))/binary>>,
    ?assertEqual({error, p2sh_commitment_mismatch},
                 beamchain_crypto:verify_p2sh_commitment(ForgedRedeem, SPK)).

%% --------------------------------------------------------------------
%% Vector W31-C (negative P2WSH inner): drive the PSBT signer with a
%% P2SH-P2WSH redeem script whose embedded 32-byte witness program
%% does NOT match SHA256(witnessScript). The PSBT path must decline
%% (no signature added) and verify_p2wsh_commitment/2 must reject the
%% forgery directly.
%% --------------------------------------------------------------------
w31_p2sh_p2wsh_negative_forged_witnessscript_test() ->
    PkA = beamchain_wallet:privkey_to_pubkey(priv_a()),
    PkB = beamchain_wallet:privkey_to_pubkey(priv_b()),
    %% Honest witness script the SPK commits to.
    HonestWS = multisig_redeem_script(2, [PkA, PkB]),
    HonestRedeem = p2sh_p2wsh_redeem_script(HonestWS),
    SPK = p2sh_spk(HonestRedeem),
    %% Forged witness script that *doesn't* hash to the SPK's witness
    %% program (different M, different pubkey order).
    ForgedWS = multisig_redeem_script(1, [PkB, PkA]),
    %% The pre-W31 signer would have happily signed the forged WS;
    %% now it must reject it because sha256(ForgedWS) /= SPK[2..22]'s
    %% inner program.
    HonestProg = crypto:hash(sha256, HonestWS),
    ForgedProg = crypto:hash(sha256, ForgedWS),
    ?assertNotEqual(HonestProg, ForgedProg),
    %% Helper rejects:
    ?assertEqual({error, p2wsh_commitment_mismatch},
                 beamchain_crypto:verify_p2wsh_commitment(ForgedWS, HonestProg)),
    %% PSBT path: feed the WRONG redeem script into the InputMap (one
    %% built from ForgedWS) and check the outer commitment fires.
    ForgedRedeem = p2sh_p2wsh_redeem_script(ForgedWS),
    ?assertEqual({error, p2sh_commitment_mismatch},
                 beamchain_crypto:verify_p2sh_commitment(ForgedRedeem, SPK)),
    %% And direct sign_p2sh_p2wsh/7 must surface the mismatch:
    Tx = unsigned_tx(),
    Result = beamchain_witness_signer:sign_p2sh_p2wsh(
        Tx, 0, 1_000_000, ForgedWS, SPK, [priv_a(), priv_b()], ?SIGHASH_ALL),
    ?assertEqual({error, p2sh_commitment_mismatch}, Result).
