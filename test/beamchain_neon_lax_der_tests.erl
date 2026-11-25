-module(beamchain_neon_lax_der_tests).

%% Finding 3 of the Gemini (Neon) audit of beamchain against Bitcoin Core
%% v31.1 (item verify-neon-beamchain-findings): ecdsa_signature_parse_der_lax
%% (pubkey.cpp) accepts a long-form length of any 0x80+k. The compound
%% (sequence) length skips k bytes and is never read; an integer (R or S)
%% length strips the leading zero bytes of its k bytes and must have fewer
%% than 4 left. Reached only without DERSIG (pre-BIP66 history): with
%% DERSIG, strict DER (lengths < 0x80) is checked first.

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-define(OP_1, 16#51).
-define(OP_CHECKSIG, 16#ac).
-define(OP_PUSHDATA1, 16#4c).

%% Mainnet block flags before BIP66: P2SH|WITNESS|TAPROOT, no DERSIG.
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
%%% F3: lax DER long-form lengths 0x83..
%%% ===================================================================

bare_checksig_case() ->
    PK = pubkey(),
    SPK = <<(byte_size(PK)), PK/binary, ?OP_CHECKSIG>>,
    Tx = spend_tx(),
    SigHash = beamchain_script:sighash_legacy(Tx, 0, SPK, 1),
    {R, S} = sign_rs(SigHash),
    {SPK, R, S, {Tx, 0, 50000}}.

%% 30 83 00 00 LL | 02 83 00 00 RL R | 02 83 00 00 SL S | 01
f3_lax_der_three_byte_lengths_verify_test() ->
    {SPK, R0, S0, Checker} = bare_checksig_case(),
    R = der_int(R0), S = der_int(S0),
    RInt = <<16#02, 16#83, 0, 0, (byte_size(R)), R/binary>>,
    SInt = <<16#02, 16#83, 0, 0, (byte_size(S)), S/binary>>,
    Body = <<RInt/binary, SInt/binary>>,
    Sig = <<16#30, 16#83, 0, 0, (byte_size(Body)), Body/binary, 16#01>>,
    ?assertEqual(ok, verify(push(Sig), SPK, [], pre_bip66_flags(), Checker)).

%% Compound length 0x84 skips 4 bytes whatever they hold (Core never reads
%% the compound length's value).
f3_lax_der_compound_length_0x84_skipped_test() ->
    {SPK, R0, S0, Checker} = bare_checksig_case(),
    R = der_int(R0), S = der_int(S0),
    Body = <<16#02, (byte_size(R)), R/binary, 16#02, (byte_size(S)), S/binary>>,
    Sig = <<16#30, 16#84, 16#ff, 16#ee, 16#dd, 16#cc, Body/binary, 16#01>>,
    ?assertEqual(ok, verify(push(Sig), SPK, [], pre_bip66_flags(), Checker)).

%% A 0x84 length whose 4 bytes are 0 0 0 LL is a 1-byte length (Core strips
%% the zeros); with 4 significant bytes it is a parse failure in Core
%% (lenbyte >= 4 after stripping zeros): the signature does not verify.
f3_lax_der_zero_padded_0x84_length_ok_four_significant_bytes_fail_test() ->
    {SPK, R0, S0, Checker} = bare_checksig_case(),
    R = der_int(R0), S = der_int(S0),
    RInt = <<16#02, 16#84, 0, 0, 0, (byte_size(R)), R/binary>>,
    RBad = <<16#02, 16#84, 1, 0, 0, (byte_size(R)), R/binary>>,
    SInt = <<16#02, (byte_size(S)), S/binary>>,
    Good = <<16#30, 16#00, RInt/binary, SInt/binary, 16#01>>,
    Bad = <<16#30, 16#00, RBad/binary, SInt/binary, 16#01>>,
    ?assertEqual(ok, verify(push(Good), SPK, [], pre_bip66_flags(), Checker)),
    ?assertMatch({error, _}, verify(push(Bad), SPK, [], pre_bip66_flags(), Checker)).

%% Control: the plain DER signature verifies under the same flags.
f3_control_plain_der_verifies_test() ->
    {SPK, R0, S0, Checker} = bare_checksig_case(),
    Sig = <<(beamchain_crypto:encode_der_signature(R0, S0))/binary, 16#01>>,
    ?assertEqual(ok, verify(push(Sig), SPK, [], pre_bip66_flags(), Checker)).
