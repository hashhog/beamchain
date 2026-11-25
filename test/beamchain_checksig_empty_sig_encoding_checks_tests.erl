%%% Pre-tapscript CHECKSIG / CHECKSIGVERIFY / CHECKMULTISIG with an EMPTY
%%% signature still run FindAndDelete (CONST_SCRIPTCODE) and the pubkey
%%% encoding checks (STRICTENC -> PUBKEYTYPE, WITNESS_PUBKEYTYPE).
%%%
%%% Item r3fix-beamchain-checksig-empty-sig-encoding-checks (R3 generating
%%% differential fuzzer, night 1, seed 739943, triage group G3: rows R36,
%%% R26, R17, R18, R27, R28, R20).
%%%
%%% Core v31.1, src/script/interpreter.cpp EvalChecksigPreTapscript:
%%%
%%%     CScript scriptCode(pbegincodehash, pend);
%%%     if (sigversion == SigVersion::BASE) {
%%%         int found = FindAndDelete(scriptCode, CScript() << vchSig);
%%%         if (found > 0 && (flags & SCRIPT_VERIFY_CONST_SCRIPTCODE))
%%%             return set_error(serror, SCRIPT_ERR_SIG_FINDANDDELETE);
%%%     }
%%%     if (!CheckSignatureEncoding(vchSig, flags, serror) ||
%%%         !CheckPubKeyEncoding(vchPubKey, flags, sigversion, serror)) {
%%%         return false;
%%%     }
%%%
%%% CheckSignatureEncoding returns true for an empty signature, so
%%% CheckPubKeyEncoding still runs for it. `CScript() << <empty>` is the
%%% single byte OP_0, so FindAndDelete deletes every opcode-aligned OP_0 of
%%% the scriptCode. CHECKMULTISIG runs both encoding checks in every loop
%%% iteration (an empty signature included) and stops early once more
%%% signatures than keys remain.
%%%
%%% On master beamchain short-cut an empty signature to "false" before any
%%% of these checks, so `0 0 CHECKSIG DROP ... 1` (R36) entered the mempool.
%%%
%%% STRICTENC, WITNESS_PUBKEYTYPE and CONST_SCRIPTCODE are policy flags, so
%%% every hostile case is also run under mainnet block flags and must stay
%%% valid (or fail exactly as before) there.
-module(beamchain_checksig_empty_sig_encoding_checks_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% Opcodes are local to beamchain_script.erl, so name the ones used here.
-define(OP_1, 16#51).
-define(OP_2, 16#52).
-define(OP_3, 16#53).
-define(OP_NOT, 16#91).
-define(OP_CHECKSIG, 16#ac).
-define(OP_CHECKSIGVERIFY, 16#ad).
-define(OP_CHECKMULTISIG, 16#ae).

%% Generator point G: compressed, uncompressed and hybrid (0x06, even y).
-define(GX, "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").
-define(GY, "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8").

pk_compressed()   -> binary:decode_hex(<<"02", ?GX>>).
pk_uncompressed() -> binary:decode_hex(<<"04", ?GX, ?GY>>).
pk_hybrid()       -> binary:decode_hex(<<"06", ?GX, ?GY>>).

%% Core v31.1 policy/policy.h STANDARD_SCRIPT_VERIFY_FLAGS.
standard_flags() ->
    ?SCRIPT_VERIFY_P2SH bor ?SCRIPT_VERIFY_DERSIG bor
    ?SCRIPT_VERIFY_NULLDUMMY bor ?SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY bor
    ?SCRIPT_VERIFY_CHECKSEQUENCEVERIFY bor ?SCRIPT_VERIFY_WITNESS bor
    ?SCRIPT_VERIFY_TAPROOT bor
    ?SCRIPT_VERIFY_STRICTENC bor ?SCRIPT_VERIFY_MINIMALDATA bor
    ?SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS bor ?SCRIPT_VERIFY_CLEANSTACK bor
    ?SCRIPT_VERIFY_MINIMALIF bor ?SCRIPT_VERIFY_NULLFAIL bor
    ?SCRIPT_VERIFY_LOW_S bor
    ?SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM bor
    ?SCRIPT_VERIFY_WITNESS_PUBKEYTYPE bor ?SCRIPT_VERIFY_CONST_SCRIPTCODE bor
    ?SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION bor
    ?SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS bor
    ?SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE.

block_flags() ->
    beamchain_script:flags_for_height(900000, mainnet).

%% Minimal push of a data item (all items here are < 76 bytes).
push(<<>>) -> <<16#00>>;
push(D) when byte_size(D) < 16#4c -> <<(byte_size(D)), D/binary>>.

%% P2WSH spend: witness = Args ++ [WitnessScript]. Args are raw stack items.
p2wsh(WS, Args, Flags) ->
    SPK = <<16#00, 16#20, (crypto:hash(sha256, WS))/binary>>,
    beamchain_script:verify_script_error(<<>>, SPK, Args ++ [WS], Flags, #{}).

%% P2SH spend: scriptSig = pushes of Args, then the redeem script.
p2sh(Redeem, Args, Flags) ->
    SPK = <<16#a9, 16#14, (beamchain_crypto:hash160(Redeem))/binary, 16#87>>,
    ScriptSig = iolist_to_binary([push(A) || A <- Args] ++ [push(Redeem)]),
    beamchain_script:verify_script_error(ScriptSig, SPK, [], Flags, #{}).

%% Bare scriptPubKey spend.
bare(SPK, ScriptSig, Flags) ->
    beamchain_script:verify_script_error(ScriptSig, SPK, [], Flags, #{}).

%%% --- CHECKSIG, witness v0 -----------------------------------------------

%% Night-1 minimised case R36 (mempool verdict PUBKEYTYPE|accept):
%% p2wsh script=[0 0 CHECKSIG DROP x5 1]. The witness script is taken from
%% the minimised tx hex in the item. Core refuses with PUBKEYTYPE (the empty
%% pubkey is neither compressed nor uncompressed); master accepted.
r36_p2wsh_0_0_checksig_drop_x5_true_is_pubkeytype_test() ->
    Tx = binary:decode_hex(
           <<"020000000001018e6b8b75ceeaedd9d5fba6e4abb8ffb15e4a1d4061191060"
             "dbe572350b2847c60000000000feffffff01d07e0100000000002200204ae8"
             "1572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326001"
             "150000ac750000ac750000ac750000ac750000ac755100000000">>),
    %% Witness of the only input: 1 item, 0x15 bytes, then the locktime.
    WSLen = 16#15,
    Pre = byte_size(Tx) - 4 - WSLen,
    <<_:(Pre - 2)/binary, 16#01, WSLen, WS:WSLen/binary, 0:32>> = Tx,
    ?assertEqual(binary:decode_hex(<<"0000ac750000ac750000ac750000ac750000ac7551">>), WS),
    ?assertEqual({error, pubkeytype}, p2wsh(WS, [], standard_flags())),
    ?assertEqual(<<"Public key is neither compressed or uncompressed">>,
                 beamchain_script:script_error_string(pubkeytype)),
    %% Consensus: unchanged, the spend is valid in a block.
    ?assertEqual(ok, p2wsh(WS, [], block_flags())).

%% R26: p2wsh script=[0 0 CHECKSIG]. Core PUBKEYTYPE, master EVAL_FALSE
%% (witness_program_failed renders as Core's EVAL_FALSE text).
r26_p2wsh_0_0_checksig_is_pubkeytype_test() ->
    WS = <<16#00, 16#00, ?OP_CHECKSIG>>,
    ?assertEqual({error, pubkeytype}, p2wsh(WS, [], standard_flags())),
    ?assertEqual({error, witness_program_failed}, p2wsh(WS, [], block_flags())).

%% Empty sig, hybrid pubkey: STRICTENC fails first -> PUBKEYTYPE, not
%% WITNESS_PUBKEYTYPE (Core checks PUBKEYTYPE before WITNESS_PUBKEYTYPE).
p2wsh_empty_sig_hybrid_pk_checksig_not_is_pubkeytype_test() ->
    WS = <<(push(pk_hybrid()))/binary, ?OP_CHECKSIG, ?OP_NOT>>,
    ?assertEqual({error, pubkeytype}, p2wsh(WS, [<<>>], standard_flags())),
    ?assertEqual(ok, p2wsh(WS, [<<>>], block_flags())).

%% Empty sig, valid uncompressed pubkey in witness v0: STRICTENC passes,
%% WITNESS_PUBKEYTYPE refuses. Master accepted (`<> <04..> CHECKSIG NOT`).
p2wsh_empty_sig_uncompressed_pk_checksig_not_is_witness_pubkeytype_test() ->
    WS = <<(push(pk_uncompressed()))/binary, ?OP_CHECKSIG, ?OP_NOT>>,
    ?assertEqual({error, witness_pubkeytype},
                 p2wsh(WS, [<<>>], standard_flags())),
    ?assertEqual(ok, p2wsh(WS, [<<>>], block_flags())).

%% Control: empty sig with a valid compressed pubkey is a plain false.
control_p2wsh_empty_sig_compressed_pk_checksig_not_accepts_test() ->
    WS = <<(push(pk_compressed()))/binary, ?OP_CHECKSIG, ?OP_NOT>>,
    ?assertEqual(ok, p2wsh(WS, [<<>>], standard_flags())),
    ?assertEqual(ok, p2wsh(WS, [<<>>], block_flags())).

%%% --- CHECKSIG, base: FindAndDelete of OP_0 ------------------------------

%% R20 shape: a P2SH redeem script holding the OP_0 that is the push of the
%% empty sig. Core: FindAndDelete removes it, CONST_SCRIPTCODE ->
%% SIG_FINDANDDELETE. Master ignored it and accepted.
p2sh_redeem_0_pk_checksig_not_is_sig_findanddelete_test() ->
    Redeem = <<16#00, (push(pk_compressed()))/binary, ?OP_CHECKSIG, ?OP_NOT>>,
    ?assertEqual({error, sig_findanddelete},
                 p2sh(Redeem, [], standard_flags())),
    ?assertEqual(ok, p2sh(Redeem, [], block_flags())).

%% FindAndDelete runs before the pubkey encoding check (Core :328-335):
%% `0 0 CHECKSIG ...` in a base script is SIG_FINDANDDELETE, not PUBKEYTYPE.
p2sh_redeem_0_0_checksig_is_sig_findanddelete_before_pubkeytype_test() ->
    Redeem = <<16#00, 16#00, ?OP_CHECKSIG, ?OP_NOT>>,
    ?assertEqual({error, sig_findanddelete},
                 p2sh(Redeem, [], standard_flags())),
    ?assertEqual(ok, p2sh(Redeem, [], block_flags())).

%% Base script, no OP_0 in the scriptCode (the empty sig comes from the
%% scriptSig) but a bad pubkey: FindAndDelete finds nothing, PUBKEYTYPE.
bare_empty_sig_hybrid_pk_checksig_not_is_pubkeytype_test() ->
    SPK = <<(push(pk_hybrid()))/binary, ?OP_CHECKSIG, ?OP_NOT>>,
    ?assertEqual({error, pubkeytype}, bare(SPK, <<16#00>>, standard_flags())),
    ?assertEqual(ok, bare(SPK, <<16#00>>, block_flags())).

%% Control: the same with a compressed pubkey is accepted under policy.
control_bare_empty_sig_compressed_pk_checksig_not_accepts_test() ->
    SPK = <<(push(pk_compressed()))/binary, ?OP_CHECKSIG, ?OP_NOT>>,
    ?assertEqual(ok, bare(SPK, <<16#00>>, standard_flags())),
    ?assertEqual(ok, bare(SPK, <<16#00>>, block_flags())).

%%% --- CHECKSIGVERIFY ------------------------------------------------------

%% Witness v0 `0 0 CHECKSIGVERIFY 1`: Core PUBKEYTYPE (STRICTENC before
%% WITNESS_PUBKEYTYPE); master answered WITNESS_PUBKEYTYPE.
p2wsh_0_0_checksigverify_is_pubkeytype_test() ->
    WS = <<16#00, 16#00, ?OP_CHECKSIGVERIFY, ?OP_1>>,
    ?assertEqual({error, pubkeytype}, p2wsh(WS, [], standard_flags())),
    ?assertEqual({error, checksigverify_failed}, p2wsh(WS, [], block_flags())).

%% Base `<> <hybrid>` CHECKSIGVERIFY: Core PUBKEYTYPE; master
%% CHECKSIGVERIFY failed.
bare_empty_sig_hybrid_pk_checksigverify_is_pubkeytype_test() ->
    SPK = <<(push(pk_hybrid()))/binary, ?OP_CHECKSIGVERIFY, ?OP_1>>,
    ?assertEqual({error, pubkeytype}, bare(SPK, <<16#00>>, standard_flags())),
    ?assertEqual({error, checksigverify_failed},
                 bare(SPK, <<16#00>>, block_flags())).

%% P2SH redeem `0 <pk> CHECKSIGVERIFY 1`: SIG_FINDANDDELETE.
p2sh_redeem_0_pk_checksigverify_is_sig_findanddelete_test() ->
    Redeem = <<16#00, (push(pk_compressed()))/binary, ?OP_CHECKSIGVERIFY, ?OP_1>>,
    ?assertEqual({error, sig_findanddelete},
                 p2sh(Redeem, [], standard_flags())),
    ?assertEqual({error, checksigverify_failed},
                 p2sh(Redeem, [], block_flags())).

%% Control: empty sig + compressed pubkey CHECKSIGVERIFY just fails verify.
control_p2wsh_empty_sig_compressed_pk_checksigverify_fails_verify_test() ->
    WS = <<(push(pk_compressed()))/binary, ?OP_CHECKSIGVERIFY, ?OP_1>>,
    ?assertEqual({error, checksigverify_failed},
                 p2wsh(WS, [<<>>], standard_flags())).

%%% --- CHECKMULTISIG -------------------------------------------------------

%% `0 <> 1 <bad-pk> 1 CHECKMULTISIG NOT` in witness v0: Core checks the
%% pubkey encoding in the loop iteration of the empty sig -> PUBKEYTYPE.
%% Master skipped the key and accepted.
p2wsh_multisig_empty_sig_empty_pk_not_is_pubkeytype_test() ->
    WS = <<16#00, 16#00, ?OP_1, 16#00, ?OP_1, ?OP_CHECKMULTISIG, ?OP_NOT>>,
    ?assertEqual({error, pubkeytype}, p2wsh(WS, [], standard_flags())),
    ?assertEqual(ok, p2wsh(WS, [], block_flags())).

p2wsh_multisig_empty_sig_hybrid_pk_not_is_pubkeytype_test() ->
    WS = <<16#00, 16#00, ?OP_1, (push(pk_hybrid()))/binary, ?OP_1,
           ?OP_CHECKMULTISIG, ?OP_NOT>>,
    ?assertEqual({error, pubkeytype}, p2wsh(WS, [], standard_flags())),
    ?assertEqual(ok, p2wsh(WS, [], block_flags())).

p2wsh_multisig_empty_sig_uncompressed_pk_not_is_witness_pubkeytype_test() ->
    WS = <<16#00, 16#00, ?OP_1, (push(pk_uncompressed()))/binary, ?OP_1,
           ?OP_CHECKMULTISIG, ?OP_NOT>>,
    ?assertEqual({error, witness_pubkeytype}, p2wsh(WS, [], standard_flags())),
    ?assertEqual(ok, p2wsh(WS, [], block_flags())).

%% 2-of-3, both sigs empty, bad key pushed LAST: Core takes keys from the
%% top of the stack, so the bad key is the first one checked -> PUBKEYTYPE.
p2wsh_multisig_2of3_bad_key_checked_first_is_pubkeytype_test() ->
    PK = push(pk_compressed()),
    WS = <<16#00, 16#00, 16#00, ?OP_2, PK/binary, PK/binary,
           (push(pk_hybrid()))/binary, ?OP_3, ?OP_CHECKMULTISIG, ?OP_NOT>>,
    ?assertEqual({error, pubkeytype}, p2wsh(WS, [], standard_flags())),
    ?assertEqual(ok, p2wsh(WS, [], block_flags())).

%% Control (early exit): the same with the bad key pushed FIRST. After two
%% failed keys 2 sigs > 1 key remain, Core stops and never looks at the bad
%% key, so the spend is accepted.
control_p2wsh_multisig_2of3_bad_key_never_reached_accepts_test() ->
    PK = push(pk_compressed()),
    WS = <<16#00, 16#00, 16#00, ?OP_2, (push(pk_hybrid()))/binary,
           PK/binary, PK/binary, ?OP_3, ?OP_CHECKMULTISIG, ?OP_NOT>>,
    ?assertEqual(ok, p2wsh(WS, [], standard_flags())),
    ?assertEqual(ok, p2wsh(WS, [], block_flags())).

%% Control: all keys valid, empty sig -> plain false, NOT -> accepted.
control_p2wsh_multisig_empty_sig_compressed_pk_not_accepts_test() ->
    WS = <<16#00, 16#00, ?OP_1, (push(pk_compressed()))/binary, ?OP_1,
           ?OP_CHECKMULTISIG, ?OP_NOT>>,
    ?assertEqual(ok, p2wsh(WS, [], standard_flags())).

%% Control: CHECKMULTISIG already ran FindAndDelete for every sig (empty
%% included) on master; a P2SH redeem holding OP_0 stays SIG_FINDANDDELETE.
control_p2sh_multisig_empty_sig_is_sig_findanddelete_test() ->
    Redeem = <<16#00, 16#00, ?OP_1, (push(pk_compressed()))/binary, ?OP_1,
               ?OP_CHECKMULTISIG, ?OP_NOT>>,
    ?assertEqual({error, sig_findanddelete},
                 p2sh(Redeem, [], standard_flags())),
    ?assertEqual(ok, p2sh(Redeem, [], block_flags())).
