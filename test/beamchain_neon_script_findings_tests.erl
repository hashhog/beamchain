-module(beamchain_neon_script_findings_tests).

%% Script-interpreter findings 1, 2 and 8 of the Gemini (Neon) audit of
%% beamchain against Bitcoin Core v31.1 (item verify-neon-beamchain-findings).
%%
%%   F1  a PUSHDATA1/2/4 whose length field is cut off by the end of the
%%       script is SCRIPT_ERR_BAD_OPCODE in Core (GetScriptOp fails,
%%       script.cpp; EvalScript returns BAD_OPCODE before looking at fExec),
%%       also inside an unexecuted IF branch.
%%   F2  P2WPKH runs through ExecuteWitnessScript, which refuses a witness
%%       stack element larger than MAX_SCRIPT_ELEMENT_SIZE (520) with
%%       SCRIPT_ERR_PUSH_SIZE before evaluation (interpreter.cpp:1858-1861).
%%   F8  CheckLowS (pubkey.cpp) parses lax and asks
%%       secp256k1_ecdsa_signature_normalize: S = 0 is not high, and an
%%       R or S >= the curve order parses as the all-zero signature, which
%%       is not high either.

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-define(OP_0, 16#00).
-define(OP_1, 16#51).
-define(OP_IF, 16#63).
-define(OP_ENDIF, 16#68).
-define(OP_NOT, 16#91).
-define(OP_CHECKSIG, 16#ac).
-define(OP_PUSHDATA1, 16#4c).
-define(OP_PUSHDATA2, 16#4d).
-define(OP_PUSHDATA4, 16#4e).

-define(N, 16#FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141).

%% Mainnet block flags after segwit (P2SH|WITNESS|TAPROOT|DERSIG|CLTV|CSV|
%% NULLDUMMY) and before BIP66 (P2SH|WITNESS|TAPROOT only).
block_flags() -> beamchain_script:flags_for_height(900000, mainnet).
pre_bip66_flags() -> beamchain_script:flags_for_height(300000, mainnet).

verify(ScriptSig, SPK, Witness, Flags, Checker) ->
    ensure_sig_cache(),
    beamchain_script:verify_script_error(ScriptSig, SPK, Witness, Flags, Checker).

%% The tuple sig checker verifies through the signature cache, whose ETS
%% table its gen_server creates; start it once for this module.
ensure_sig_cache() ->
    case whereis(beamchain_sig_cache) of
        undefined -> {ok, P} = beamchain_sig_cache:start_link(), unlink(P), ok;
        _ -> ok
    end.

%% Core's ScriptErrorString for a verify result, so a test pins the error
%% Core reports and not the spelling of beamchain's internal token.
core_err(ok) -> ok;
core_err({error, E}) -> {error, beamchain_script:script_error_string(E)}.

-define(BAD_OPCODE, {error, <<"Opcode missing or not understood">>}).

%%% ===================================================================
%%% F1: cut-off PUSHDATA length field in execute/3
%%% ===================================================================

%% OP_1 OP_0 OP_IF OP_PUSHDATA2 OP_ENDIF: the 0x68 is the only byte of a
%% 2-byte length field. Core: BAD_OPCODE. master: skipped the 0x4d as a
%% one-byte unexecuted opcode and ran the 0x68 as OP_ENDIF -> {ok, [1]}.
f1_unexecuted_pushdata2_cutoff_base_is_bad_opcode_test() ->
    SPK = <<?OP_1, ?OP_0, ?OP_IF, ?OP_PUSHDATA2, ?OP_ENDIF>>,
    ?assertEqual(?BAD_OPCODE, core_err(verify(<<>>, SPK, [], block_flags(), #{}))).

f1_unexecuted_pushdata4_cutoff_base_is_bad_opcode_test() ->
    SPK = <<?OP_1, ?OP_0, ?OP_IF, ?OP_PUSHDATA4, ?OP_ENDIF>>,
    ?assertEqual(?BAD_OPCODE, core_err(verify(<<>>, SPK, [], block_flags(), #{}))).

f1_unexecuted_pushdata4_three_length_bytes_is_bad_opcode_test() ->
    SPK = <<?OP_1, ?OP_0, ?OP_IF, ?OP_PUSHDATA4, 0, 0, ?OP_ENDIF>>,
    ?assertEqual(?BAD_OPCODE, core_err(verify(<<>>, SPK, [], block_flags(), #{}))).

%% A trailing OP_PUSHDATA1 with no length byte at all, inside the
%% unexecuted branch. master reported unbalanced_conditional.
f1_unexecuted_pushdata1_no_length_is_bad_opcode_test() ->
    SPK = <<?OP_1, ?OP_0, ?OP_IF, ?OP_PUSHDATA1>>,
    ?assertEqual(?BAD_OPCODE, core_err(verify(<<>>, SPK, [], block_flags(), #{}))).

%% The same witnessScript through P2WSH (witness v0 execution path).
f1_unexecuted_pushdata2_cutoff_p2wsh_is_bad_opcode_test() ->
    WS = <<?OP_1, ?OP_0, ?OP_IF, ?OP_PUSHDATA2, ?OP_ENDIF>>,
    SPK = <<?OP_0, 32, (crypto:hash(sha256, WS))/binary>>,
    ?assertEqual(?BAD_OPCODE, core_err(verify(<<>>, SPK, [WS], block_flags(), #{}))).

%% Controls: a complete PUSHDATA2/PUSHDATA4 in the unexecuted branch is
%% skipped as a push and the script succeeds, in Core and here.
f1_control_unexecuted_complete_pushdata2_ok_test() ->
    SPK = <<?OP_1, ?OP_0, ?OP_IF, ?OP_PUSHDATA2, 1, 0, 16#aa, ?OP_ENDIF>>,
    ?assertEqual(ok, verify(<<>>, SPK, [], block_flags(), #{})).

f1_control_unexecuted_complete_pushdata4_empty_ok_test() ->
    SPK = <<?OP_1, ?OP_0, ?OP_IF, ?OP_PUSHDATA4, 0, 0, 0, 0, ?OP_ENDIF>>,
    ?assertEqual(ok, verify(<<>>, SPK, [], block_flags(), #{})).

%% Control: an executed cut-off PUSHDATA2 was already BAD_OPCODE.
f1_control_executed_pushdata2_cutoff_bad_opcode_test() ->
    SPK = <<?OP_1, ?OP_PUSHDATA2, 16#01>>,
    ?assertEqual(?BAD_OPCODE, core_err(verify(<<>>, SPK, [], block_flags(), #{}))).

%%% ===================================================================
%%% Signing helpers (secp256k1 via the node's own NIF)
%%% ===================================================================

priv() -> <<1:256>>.

pubkey() ->
    {ok, PK} = beamchain_crypto:pubkey_from_privkey(priv()),
    PK.

spend_tx() ->
    #transaction{
        version = 2,
        inputs = [#tx_in{prev_out = #outpoint{hash = <<7:256>>, index = 0},
                         script_sig = <<>>, sequence = 16#ffffffff,
                         witness = []}],
        outputs = [#tx_out{value = 40000, script_pubkey = <<?OP_1>>}],
        locktime = 0}.

%% DER R and S as unsigned big-endian magnitudes.
sign_rs(SigHash) ->
    {ok, Der} = beamchain_crypto:ecdsa_sign(SigHash, priv()),
    {ok, {R, S}} = beamchain_crypto:decode_der_lax(Der),
    {R, S}.

der_int(Mag) ->
    case Mag of
        <<B, _/binary>> when B >= 16#80 -> <<0, Mag/binary>>;
        _ -> Mag
    end.

push(Data) when byte_size(Data) =< 75 -> <<(byte_size(Data)), Data/binary>>;
push(Data) -> <<?OP_PUSHDATA1, (byte_size(Data)), Data/binary>>.

%%% ===================================================================
%%% F2: P2WPKH witness element > 520 bytes
%%% ===================================================================

%% A valid signature whose R is padded with leading zero bytes until the
%% whole element is 521 bytes, using 0x82 two-byte DER lengths (the lax
%% parser strips the zeros). Pre-BIP66 mainnet block flags (no DERSIG), so
%% the signature itself verifies in both Core and beamchain; only the
%% element size check differs.
padded_sig(R, S, Total) ->
    SInt = <<16#02, (byte_size(der_int(S))), (der_int(S))/binary>>,
    %% element = 30 82 LL LL | 02 82 RL RL <zeros> R | SInt | hashtype
    Fixed = 4 + 4 + byte_size(R) + byte_size(SInt) + 1,
    Zeros = Total - Fixed,
    RBody = <<0:(Zeros * 8), R/binary>>,
    RInt = <<16#02, 16#82, (byte_size(RBody)):16/big, RBody/binary>>,
    Body = <<RInt/binary, SInt/binary>>,
    <<16#30, 16#82, (byte_size(Body)):16/big, Body/binary, 16#01>>.

p2wpkh_case(SigLen) ->
    PK = pubkey(),
    Program = beamchain_crypto:hash160(PK),
    SPK = <<?OP_0, 20, Program/binary>>,
    Tx = spend_tx(),
    Amount = 50000,
    ScriptCode = <<16#76, 16#a9, 20, Program/binary, 16#88, ?OP_CHECKSIG>>,
    SigHash = beamchain_script:sighash_witness_v0(Tx, 0, ScriptCode, Amount, 1),
    {R, S} = sign_rs(SigHash),
    Sig = padded_sig(R, S, SigLen),
    SigLen = byte_size(Sig),
    {SPK, [Sig, PK], {Tx, 0, Amount}}.

f2_p2wpkh_521_byte_sig_is_push_size_test() ->
    {SPK, Witness, Checker} = p2wpkh_case(521),
    ?assertEqual({error, push_size_exceeded},
                 verify(<<>>, SPK, Witness, pre_bip66_flags(), Checker)).

%% Control: the same padded signature at exactly 520 bytes verifies.
%% Without this, F2 could pass because the padded signature never verified.
f2_control_p2wpkh_520_byte_sig_ok_test() ->
    {SPK, Witness, Checker} = p2wpkh_case(520),
    ?assertEqual(ok, verify(<<>>, SPK, Witness, pre_bip66_flags(), Checker)).

%% A 521-byte pubkey element (hash-committed by the program) is PUSH_SIZE
%% before evaluation in Core. master evaluated it and failed CHECKSIG.
f2_p2wpkh_521_byte_pubkey_is_push_size_test() ->
    BigPK = <<16#02, 0:(520 * 8)>>,
    SPK = <<?OP_0, 20, (beamchain_crypto:hash160(BigPK))/binary>>,
    ?assertEqual({error, push_size_exceeded},
                 verify(<<>>, SPK, [<<16#30, 16#01>>, BigPK],
                        block_flags(), {spend_tx(), 0, 50000})).

%%% ===================================================================
%%% F8: LOW_S without NULLFAIL
%%% ===================================================================

%% <sig> <pk> OP_CHECKSIG OP_NOT under LOW_S only: Core's CheckLowS says
%% "low" for these, CHECKSIG pushes false (no NULLFAIL), OP_NOT -> success.
low_s_case(RMag, SMag) ->
    Body = <<16#02, (byte_size(RMag)), RMag/binary,
             16#02, (byte_size(SMag)), SMag/binary>>,
    Sig = <<16#30, (byte_size(Body)), Body/binary, 16#01>>,
    PK = pubkey(),
    SPK = <<(byte_size(PK)), PK/binary, ?OP_CHECKSIG, ?OP_NOT>>,
    verify(push(Sig), SPK, [], ?SCRIPT_VERIFY_LOW_S, {spend_tx(), 0, 50000}).

f8_low_s_zero_s_is_low_test() ->
    ?assertEqual(ok, low_s_case(<<1>>, <<0>>)).

f8_low_s_s_equal_n_is_low_test() ->
    ?assertEqual(ok, low_s_case(<<1>>, der_int(<<?N:256>>))).

f8_low_s_r_equal_n_high_s_is_low_test() ->
    ?assertEqual(ok, low_s_case(der_int(<<?N:256>>), der_int(<<(?N - 1):256>>))).

%% Controls: a genuine high S (R, S < N) is still SIG_HIGH_S; N/2 is low.
f8_control_high_s_still_rejected_test() ->
    ?assertEqual({error, sig_high_s},
                 low_s_case(<<1>>, der_int(<<(?N - 1):256>>))).

f8_control_half_n_is_low_test() ->
    ?assertEqual(ok, low_s_case(<<1>>, der_int(<<(?N div 2):256>>))).
