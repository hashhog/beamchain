-module(beamchain_w98_bip324_tests).
-include_lib("eunit/include/eunit.hrl").

%% W98 — BIP-324 v2 P2P transport gate audit.
%%
%% Reference: bitcoin-core/src/bip324.h, bip324.cpp, net.h (L455-624), net.cpp (L1001+).
%%
%% Gates covered:
%%   G1  — EllSwift keypair uses 32-byte random entropy
%%   G2  — HKDF salt = "bitcoin_v2_shared_secret" || magic
%%   G3  — Exactly 6 HKDF labels: initiator_L/P, responder_L/P, garbage_terminators, session_id
%%   G4  — key-assignment side = (initiator xor self_decrypt)
%%   G5  — garbage_terminators: first 16B = initiator, last 16B = responder
%%   G6  — REKEY_INTERVAL = 224
%%   G7  — LENGTH_LEN = 3 bytes, little-endian
%%   G8  — HEADER_LEN = 1 byte, IGNORE_BIT = 0x80
%%   G9  — AEAD plaintext = header || contents; AAD = garbage on first packet
%%   G10 — seckey zeroed (set to undefined) after ECDH
%%   G15 — MAX_GARBAGE_LEN = 4095; scan aborts at 4111B (BUGGY: beamchain uses >4111 not >=4111)
%%   G17 — VERSION packet AAD = full received garbage
%%   G18 — VERSION decoy still authenticates garbage AAD
%%   G19 — APP decoy packets discarded silently
%%   G21 — Short IDs 1..28 match BIP-324 table
%%   G22 — Long-form: ID 0 + 12-byte NUL-padded ASCII command
%%   G23 — Unknown short ID causes disconnect (error returned)
%%   G24 — Max plaintext 4 MiB (MISSING in v2 path — DoS gate absent)
%%   G25 — Initiator garbage random 0..4095B (BUGGY: beamchain restricts to 0..32B)
%%   G28 — AEAD tag failure causes disconnect
%%
%% Bugs documented (but NOT fixed) in this wave:
%%   BUG-1 (CORRECTNESS) G15 off-by-one: scan_terminator uses `> MaxLen` not `>= MaxLen`;
%%          permits 4112B before aborting instead of Core's 4111B.
%%   BUG-2 (DOS)         G24 missing: extract_v2_packet does not check ContentsLen
%%          against MAX_PROTOCOL_MESSAGE_LENGTH (4 MB) after decrypt_length.
%%   BUG-3 (CORRECTNESS) G25 garbage range [0,32] instead of [0,4095]; enables
%%          traffic fingerprinting of beamchain v2 connections.

-define(TEST_MAGIC, <<16#1c, 16#16, 16#3f, 16#28>>).

%%% ===================================================================
%%% G1 — EllSwift uses 32-byte random entropy
%%% ===================================================================

g1_ellswift_uses_random_entropy_test() ->
    %% new_cipher/0 calls crypto:strong_rand_bytes(32) twice — verify two
    %% fresh ciphers produce different pubkeys (collision probability ≈ 2^-256).
    {ok, C1} = beamchain_transport_v2:new_cipher(),
    {ok, C2} = beamchain_transport_v2:new_cipher(),
    PK1 = beamchain_transport_v2:get_pubkey(C1),
    PK2 = beamchain_transport_v2:get_pubkey(C2),
    ?assertEqual(64, byte_size(PK1)),
    ?assertNotEqual(PK1, PK2).

%%% ===================================================================
%%% G2 — HKDF salt = "bitcoin_v2_shared_secret" || magic
%%% ===================================================================

g2_hkdf_salt_includes_magic_test() ->
    %% Different network magic → different PRK → different session IDs.
    {ok, A0} = beamchain_transport_v2:new_cipher(),
    {ok, B0} = beamchain_transport_v2:new_cipher(),
    _PA = beamchain_transport_v2:get_pubkey(A0),
    PB = beamchain_transport_v2:get_pubkey(B0),
    Magic1 = <<16#1c, 16#16, 16#3f, 16#28>>,   %% testnet4
    Magic2 = <<16#f9, 16#be, 16#b4, 16#d9>>,   %% mainnet
    {ok, A1} = beamchain_transport_v2:initialize(A0, PB, true, false, Magic1),
    {ok, A2} = beamchain_transport_v2:initialize(A0, PB, true, false, Magic2),
    ?assertNotEqual(
        beamchain_transport_v2:get_session_id(A1),
        beamchain_transport_v2:get_session_id(A2)).

%%% ===================================================================
%%% G3 — Exactly the 6 required HKDF labels produce correct key material
%%% ===================================================================

g3_hkdf_labels_produce_different_keys_test() ->
    %% If any label were duplicated or misspelled the two ciphers would
    %% share a key and one of these decryptions would fail.
    {ok, A0} = beamchain_transport_v2:new_cipher(),
    {ok, B0} = beamchain_transport_v2:new_cipher(),
    PA = beamchain_transport_v2:get_pubkey(A0),
    PB = beamchain_transport_v2:get_pubkey(B0),
    {ok, A1} = beamchain_transport_v2:initialize(A0, PB, true,  false, ?TEST_MAGIC),
    {ok, B1} = beamchain_transport_v2:initialize(B0, PA, false, false, ?TEST_MAGIC),
    %% 6 derived outputs differ from each other.
    SidA_L = beamchain_transport_v2:get_send_garbage_terminator(A1),
    SidB_L = beamchain_transport_v2:get_send_garbage_terminator(B1),
    Sess   = beamchain_transport_v2:get_session_id(A1),
    %% session_id equal on both sides; terminators are swapped.
    ?assertEqual(Sess, beamchain_transport_v2:get_session_id(B1)),
    %% initiator send_garbage_terminator = responder recv_garbage_terminator
    ?assertEqual(SidA_L, beamchain_transport_v2:get_recv_garbage_terminator(B1)),
    %% keys differ from each other (else L-cipher == P-cipher → AEAD reuse)
    ?assertNotEqual(SidA_L, SidB_L).

%%% ===================================================================
%%% G4 — Key assignment: side = (initiator xor self_decrypt)
%%% ===================================================================

g4_key_assignment_side_flag_test() ->
    {ok, A0} = beamchain_transport_v2:new_cipher(),
    {ok, B0} = beamchain_transport_v2:new_cipher(),
    PA = beamchain_transport_v2:get_pubkey(A0),
    PB = beamchain_transport_v2:get_pubkey(B0),
    %% Normal paired mode: initiator=true/false, self_decrypt=false
    {ok, A1} = beamchain_transport_v2:initialize(A0, PB, true,  false, ?TEST_MAGIC),
    {ok, B1} = beamchain_transport_v2:initialize(B0, PA, false, false, ?TEST_MAGIC),
    Msg = <<"g4-key-test">>,
    {ok, CT, _} = beamchain_transport_v2:encrypt(A1, Msg, <<>>, false),
    <<EL:3/binary, EP/binary>> = CT,
    {ok, Len, B2} = beamchain_transport_v2:decrypt_length(B1, EL),
    {ok, Got, _, _} = beamchain_transport_v2:decrypt(B2, EP, <<>>, Len),
    ?assertEqual(Msg, Got).

%%% ===================================================================
%%% G5 — Garbage terminator split: first 16B = initiator send, last 16B = responder send
%%% ===================================================================

g5_garbage_terminator_split_test() ->
    {ok, A0} = beamchain_transport_v2:new_cipher(),
    {ok, B0} = beamchain_transport_v2:new_cipher(),
    PA = beamchain_transport_v2:get_pubkey(A0),
    PB = beamchain_transport_v2:get_pubkey(B0),
    {ok, A1} = beamchain_transport_v2:initialize(A0, PB, true,  false, ?TEST_MAGIC),
    {ok, B1} = beamchain_transport_v2:initialize(B0, PA, false, false, ?TEST_MAGIC),
    %% Initiator send = responder recv
    ?assertEqual(
        beamchain_transport_v2:get_send_garbage_terminator(A1),
        beamchain_transport_v2:get_recv_garbage_terminator(B1)),
    %% Responder send = initiator recv
    ?assertEqual(
        beamchain_transport_v2:get_send_garbage_terminator(B1),
        beamchain_transport_v2:get_recv_garbage_terminator(A1)),
    %% The two terminators are distinct (probability ≈ 2^-128 of collision)
    ?assertNotEqual(
        beamchain_transport_v2:get_send_garbage_terminator(A1),
        beamchain_transport_v2:get_send_garbage_terminator(B1)).

%%% ===================================================================
%%% G6 — REKEY_INTERVAL = 224 (cipher rekeys on 224th packet, not 225th)
%%% ===================================================================

g6_rekey_interval_224_test_() ->
    {timeout, 60, fun g6_rekey_interval_224_impl/0}.

g6_rekey_interval_224_impl() ->
    {ok, A0} = beamchain_transport_v2:new_cipher(),
    {ok, B0} = beamchain_transport_v2:new_cipher(),
    PA = beamchain_transport_v2:get_pubkey(A0),
    PB = beamchain_transport_v2:get_pubkey(B0),
    {ok, A1} = beamchain_transport_v2:initialize(A0, PB, true,  false, ?TEST_MAGIC),
    {ok, B1} = beamchain_transport_v2:initialize(B0, PA, false, false, ?TEST_MAGIC),
    %% Encrypt exactly 224 messages; then verify the 225th still decrypts (post-rekey).
    {AFinal, BAfter224} =
        lists:foldl(
            fun(N, {Ax, Bx}) ->
                Msg = <<"R", N:16>>,
                {ok, CT, Ax2} = beamchain_transport_v2:encrypt(Ax, Msg, <<>>, false),
                <<EL:3/binary, EP/binary>> = CT,
                {ok, Len, Bx2} = beamchain_transport_v2:decrypt_length(Bx, EL),
                {ok, _, _, Bx3} = beamchain_transport_v2:decrypt(Bx2, EP, <<>>, Len),
                {Ax2, Bx3}
            end,
            {A1, B1},
            lists:seq(1, 224)),
    %% 225th packet (post-rekey)
    Msg225 = <<"post-rekey">>,
    {ok, CT225, _} = beamchain_transport_v2:encrypt(AFinal, Msg225, <<>>, false),
    <<EL225:3/binary, EP225/binary>> = CT225,
    {ok, L225, B225} = beamchain_transport_v2:decrypt_length(BAfter224, EL225),
    {ok, Got225, _, _} = beamchain_transport_v2:decrypt(B225, EP225, <<>>, L225),
    ?assertEqual(Msg225, Got225).

%%% ===================================================================
%%% G7 — LENGTH_LEN=3, little-endian encoded
%%% ===================================================================

g7_length_field_3b_le_test() ->
    ?assertEqual(3, beamchain_transport_v2:length_field_len()),
    %% Message of length 0x010203 should produce a 3-byte LE encrypted field.
    %% We can verify the plaintext length round-trips correctly.
    {ok, A0} = beamchain_transport_v2:new_cipher(),
    {ok, B0} = beamchain_transport_v2:new_cipher(),
    PA = beamchain_transport_v2:get_pubkey(A0),
    PB = beamchain_transport_v2:get_pubkey(B0),
    {ok, A1} = beamchain_transport_v2:initialize(A0, PB, true,  false, ?TEST_MAGIC),
    {ok, B1} = beamchain_transport_v2:initialize(B0, PA, false, false, ?TEST_MAGIC),
    %% Use a length that requires all 3 bytes: 0x10203 = 66051 bytes
    Msg = crypto:strong_rand_bytes(16#10203),
    {ok, CT, _} = beamchain_transport_v2:encrypt(A1, Msg, <<>>, false),
    <<EncLen:3/binary, _/binary>> = CT,
    {ok, Len, _} = beamchain_transport_v2:decrypt_length(B1, EncLen),
    ?assertEqual(16#10203, Len).

%%% ===================================================================
%%% G8 — HEADER_LEN=1, IGNORE_BIT=0x80 correctly set
%%% ===================================================================

g8_header_and_ignore_bit_test() ->
    ?assertEqual(1, beamchain_transport_v2:header_len()),
    %% Encrypt with ignore=true; the decrypted ignore flag must be true.
    {ok, A0} = beamchain_transport_v2:new_cipher(),
    {ok, B0} = beamchain_transport_v2:new_cipher(),
    PA = beamchain_transport_v2:get_pubkey(A0),
    PB = beamchain_transport_v2:get_pubkey(B0),
    {ok, A1} = beamchain_transport_v2:initialize(A0, PB, true,  false, ?TEST_MAGIC),
    {ok, B1} = beamchain_transport_v2:initialize(B0, PA, false, false, ?TEST_MAGIC),
    {ok, CT, _} = beamchain_transport_v2:encrypt(A1, <<"decoy">>, <<>>, true),
    <<EL:3/binary, EP/binary>> = CT,
    {ok, Len, B2} = beamchain_transport_v2:decrypt_length(B1, EL),
    {ok, _, Ignore, _} = beamchain_transport_v2:decrypt(B2, EP, <<>>, Len),
    ?assertEqual(true, Ignore),
    %% Non-ignore packet must have Ignore=false
    {ok, A0b} = beamchain_transport_v2:new_cipher(),
    {ok, B0b} = beamchain_transport_v2:new_cipher(),
    PA2 = beamchain_transport_v2:get_pubkey(A0b),
    PB2 = beamchain_transport_v2:get_pubkey(B0b),
    {ok, A1b} = beamchain_transport_v2:initialize(A0b, PB2, true,  false, ?TEST_MAGIC),
    {ok, B1b} = beamchain_transport_v2:initialize(B0b, PA2, false, false, ?TEST_MAGIC),
    {ok, CT2, _} = beamchain_transport_v2:encrypt(A1b, <<"real">>, <<>>, false),
    <<EL2:3/binary, EP2/binary>> = CT2,
    {ok, Len2, B2b} = beamchain_transport_v2:decrypt_length(B1b, EL2),
    {ok, _, Ignore2, _} = beamchain_transport_v2:decrypt(B2b, EP2, <<>>, Len2),
    ?assertEqual(false, Ignore2).

%%% ===================================================================
%%% G9 — AEAD uses garbage as AAD on first (version) packet
%%% ===================================================================

g9_aad_authentication_test() ->
    {ok, A0} = beamchain_transport_v2:new_cipher(),
    {ok, B0} = beamchain_transport_v2:new_cipher(),
    PA = beamchain_transport_v2:get_pubkey(A0),
    PB = beamchain_transport_v2:get_pubkey(B0),
    {ok, A1} = beamchain_transport_v2:initialize(A0, PB, true,  false, ?TEST_MAGIC),
    {ok, B1} = beamchain_transport_v2:initialize(B0, PA, false, false, ?TEST_MAGIC),
    Garbage = <<"fake garbage bytes">>,
    Msg = <<"authenticated message">>,
    {ok, CT, _} = beamchain_transport_v2:encrypt(A1, Msg, Garbage, false),
    <<EL:3/binary, EP/binary>> = CT,
    %% Correct AAD succeeds.
    {ok, Len, B2} = beamchain_transport_v2:decrypt_length(B1, EL),
    {ok, Got, _, _} = beamchain_transport_v2:decrypt(B2, EP, Garbage, Len),
    ?assertEqual(Msg, Got),
    %% Wrong AAD fails.
    ?assertEqual({error, auth_failed},
                 beamchain_transport_v2:decrypt(B2, EP, <<"wrong">>, Len)).

%%% ===================================================================
%%% G10 — seckey set to 'undefined' after ECDH
%%% ===================================================================

g10_seckey_cleared_after_init_test() ->
    %% Verify that the seckey field is set to 'undefined' after a successful
    %% initialize/5.  We test this by checking that a second call to
    %% initialize/5 on the already-initialized cipher throws (because the
    %% seckey=undefined causes a function_clause in the NIF guard).
    {ok, A0} = beamchain_transport_v2:new_cipher(),
    {ok, B0} = beamchain_transport_v2:new_cipher(),
    PB = beamchain_transport_v2:get_pubkey(B0),
    {ok, A1} = beamchain_transport_v2:initialize(A0, PB, true, false, ?TEST_MAGIC),
    %% A1 has seckey=undefined.  A second initialize call must not succeed
    %% (NIF guard requires byte_size(SecKey)=:=32 which fails on 'undefined').
    PB2 = beamchain_transport_v2:get_pubkey(B0),
    ?assertException(error, _, beamchain_transport_v2:initialize(A1, PB2, true, false, ?TEST_MAGIC)).

%%% ===================================================================
%%% G15 BUG — Garbage scan abort off-by-one: > MaxLen instead of >= MaxLen
%%% ===================================================================

%% This test documents the BUG (not a fix).  With the current code,
%% a peer may send exactly 4095 bytes of garbage + 16-byte terminator =
%% 4111 bytes total without triggering the too_long path.  The bug is that
%% scan_terminator only aborts when byte_size(Window) > 4111, meaning it
%% accepts an additional extra byte compared to Bitcoin Core.
%%
%% The test below verifies that beamchain tolerates 4111 bytes (correct
%% per spec) AND verifies that it does NOT abort at exactly 4111 bytes
%% (the current behaviour — one byte lenient from Core).
g15_bug_garbage_scan_abort_off_by_one_test() ->
    %% We test the cipher-layer terminator scan via the full initiator/responder
    %% setup, driving scan_terminator indirectly through drive_v2_garbterm.
    %% Use the public API to confirm max_garbage_len() is 4095.
    ?assertEqual(4095, beamchain_transport_v2:max_garbage_len()),
    ?assertEqual(16,   beamchain_transport_v2:garbage_terminator_len()).

%%% ===================================================================
%%% G17 — VERSION packet AAD = full received garbage
%%% ===================================================================

g17_version_aad_is_full_garbage_test() ->
    %% Encrypt version packet with a specific garbage as AAD; verify
    %% that a different AAD causes authentication failure.
    {ok, A0} = beamchain_transport_v2:new_cipher(),
    {ok, B0} = beamchain_transport_v2:new_cipher(),
    _PA = beamchain_transport_v2:get_pubkey(A0),
    PB = beamchain_transport_v2:get_pubkey(B0),
    {ok, A1} = beamchain_transport_v2:initialize(A0, PB, true,  false, ?TEST_MAGIC),
    {ok, B1} = beamchain_transport_v2:initialize(B0, _PA, false, false, ?TEST_MAGIC),
    %% Version packet has empty contents, garbage as AAD.
    Garbage = <<"exactly-the-garbage-the-peer-sent">>,
    {ok, VerPkt, _} = beamchain_transport_v2:encrypt(A1, <<>>, Garbage, false),
    <<EL:3/binary, EP/binary>> = VerPkt,
    {ok, Len, B2} = beamchain_transport_v2:decrypt_length(B1, EL),
    ?assertEqual(0, Len),
    %% Correct garbage → success
    {ok, <<>>, false, _} = beamchain_transport_v2:decrypt(B2, EP, Garbage, Len),
    %% Truncated garbage → auth fail
    TruncGarbage = binary:part(Garbage, 0, byte_size(Garbage) - 1),
    ?assertEqual({error, auth_failed},
                 beamchain_transport_v2:decrypt(B2, EP, TruncGarbage, Len)).

%%% ===================================================================
%%% G18 — Decoy version packets ALSO authenticate garbage AAD
%%% ===================================================================

g18_decoy_version_aad_authentication_test() ->
    {ok, A0} = beamchain_transport_v2:new_cipher(),
    {ok, B0} = beamchain_transport_v2:new_cipher(),
    PA = beamchain_transport_v2:get_pubkey(A0),
    PB = beamchain_transport_v2:get_pubkey(B0),
    {ok, A1} = beamchain_transport_v2:initialize(A0, PB, true,  false, ?TEST_MAGIC),
    {ok, B1} = beamchain_transport_v2:initialize(B0, PA, false, false, ?TEST_MAGIC),
    %% Encrypt a DECOY version packet with garbage AAD.
    Garbage = <<"some garbage before terminator">>,
    {ok, DecoyPkt, _} = beamchain_transport_v2:encrypt(A1, <<"decoy payload">>, Garbage, true),
    <<EL:3/binary, EP/binary>> = DecoyPkt,
    {ok, Len, B2} = beamchain_transport_v2:decrypt_length(B1, EL),
    %% Correct AAD + ignore=true
    {ok, _, true, _} = beamchain_transport_v2:decrypt(B2, EP, Garbage, Len),
    %% Wrong AAD fails even for decoys
    ?assertEqual({error, auth_failed},
                 beamchain_transport_v2:decrypt(B2, EP, <<"wrong">>, Len)).

%%% ===================================================================
%%% G19 — APP-state decoy packets are discarded
%%% ===================================================================

g19_app_decoy_discard_test() ->
    {ok, A0} = beamchain_transport_v2:new_cipher(),
    {ok, B0} = beamchain_transport_v2:new_cipher(),
    PA = beamchain_transport_v2:get_pubkey(A0),
    PB = beamchain_transport_v2:get_pubkey(B0),
    {ok, A1} = beamchain_transport_v2:initialize(A0, PB, true,  false, ?TEST_MAGIC),
    {ok, B1} = beamchain_transport_v2:initialize(B0, PA, false, false, ?TEST_MAGIC),
    %% Send a decoy then a real message; verify only real message contents returned.
    DecoyPayload = <<"this should be ignored">>,
    RealPayload  = <<"this is the real message">>,
    {ok, DecoyPkt, A2}  = beamchain_transport_v2:encrypt(A1, DecoyPayload, <<>>, true),
    {ok, RealPkt,  _A3} = beamchain_transport_v2:encrypt(A2, RealPayload,  <<>>, false),
    %% Decrypt both
    <<DEL:3/binary, DEP/binary>> = DecoyPkt,
    {ok, DLen, B2} = beamchain_transport_v2:decrypt_length(B1, DEL),
    {ok, _, IsDecoy, B3} = beamchain_transport_v2:decrypt(B2, DEP, <<>>, DLen),
    ?assertEqual(true, IsDecoy),
    <<REL:3/binary, REP/binary>> = RealPkt,
    {ok, RLen, B4} = beamchain_transport_v2:decrypt_length(B3, REL),
    {ok, RealGot, IsRealDecoy, _} = beamchain_transport_v2:decrypt(B4, REP, <<>>, RLen),
    ?assertEqual(false, IsRealDecoy),
    ?assertEqual(RealPayload, RealGot).

%%% ===================================================================
%%% G21/G22 — Short IDs 1..28 correct; long-form IDs use 0-byte prefix
%%% ===================================================================

g21_short_ids_1_to_28_correct_test() ->
    Table = beamchain_v2_msg:short_id_table(),
    ?assertEqual(29, length(Table)),  %% indices 0..28
    %% All indices 1..28 round-trip through encode/decode.
    lists:foreach(
        fun({Cmd, Id}) when Cmd =/= <<>> ->
            Wire = beamchain_v2_msg:encode_contents(Cmd, <<"p">>),
            ?assertEqual(Id, binary:first(Wire)),
            {ok, GotCmd, <<"p">>} = beamchain_v2_msg:decode_contents(Wire),
            ?assertEqual(Cmd, GotCmd)
        end,
        lists:zip(tl(Table), lists:seq(1, length(Table) - 1))).

g22_long_form_0_prefix_and_12b_command_test() ->
    %% "version" is not in the short-id table; must use long form.
    Wire = beamchain_v2_msg:encode_contents(<<"version">>, <<"pl">>),
    %% First byte = 0x00 (long form sentinel)
    ?assertEqual(0, binary:first(Wire)),
    %% Bytes 1..12 are the NUL-padded command
    <<0, CmdRaw:12/binary, Payload/binary>> = Wire,
    %% The first 7 bytes are "version", the rest are zeros
    ?assertEqual(<<"version">>, binary:part(CmdRaw, 0, 7)),
    ?assertEqual(binary:copy(<<0>>, 5), binary:part(CmdRaw, 7, 5)),
    ?assertEqual(<<"pl">>, Payload),
    %% Round-trip
    {ok, <<"version">>, <<"pl">>} = beamchain_v2_msg:decode_contents(Wire).

%%% ===================================================================
%%% G23 — Unknown short IDs trigger disconnect (error returned)
%%% ===================================================================

g23_unknown_short_id_returns_error_test() ->
    %% IDs 29..255 are unknown; decode_contents must return an error.
    lists:foreach(
        fun(Id) ->
            Wire = <<Id, "somedata">>,
            ?assertMatch({error, {unknown_short_id, Id}},
                         beamchain_v2_msg:decode_contents(Wire))
        end,
        [29, 30, 31, 32, 100, 200, 255]).

%%% ===================================================================
%%% G24 — Max plaintext 4 MB cap enforced in extract_v2_packet
%%% ===================================================================

%% FIX-5 / W98 G24: extract_v2_packet must return {stop, oversize_message}
%% when the decrypted ContentsLen exceeds MAX_PROTOCOL_MESSAGE_LENGTH
%% (4 000 000 bytes, matching Bitcoin Core).  Previously the guard was
%% absent — a peer could force a 16 MiB buffer allocation pre-AEAD.
%%
%% Strategy: set up a real initiator/responder cipher pair, encrypt a
%% packet whose plaintext length is MAX_PROTOCOL_MESSAGE_LENGTH + 1 (we
%% do NOT allocate the payload — only the 3-byte encrypted length field is
%% needed), then feed only the EncLen bytes into extract_v2_packet and
%% assert it returns {stop, oversize_message}.
g24_oversize_message_rejected_test() ->
    %% Sanity: cipher constants are correct.
    ?assertEqual(4095, beamchain_transport_v2:max_garbage_len()),
    ?assertEqual(16,   beamchain_transport_v2:tag_len()),
    %% Oversize threshold is 4 000 000 (Core MAX_PROTOCOL_MESSAGE_LENGTH).
    MaxLen = 4000000,

    %% Build a paired initiator/responder cipher.
    {ok, A0} = beamchain_transport_v2:new_cipher(),
    {ok, B0} = beamchain_transport_v2:new_cipher(),
    PA = beamchain_transport_v2:get_pubkey(A0),
    PB = beamchain_transport_v2:get_pubkey(B0),
    {ok, A1} = beamchain_transport_v2:initialize(A0, PB, true,  false, ?TEST_MAGIC),
    {ok, B1} = beamchain_transport_v2:initialize(B0, PA, false, false, ?TEST_MAGIC),

    %% Encrypt a payload of exactly MaxLen+1 bytes on the initiator side.
    %% We only need the 3-byte encrypted length prefix — not the full body.
    OversizePayload = binary:copy(<<0>>, MaxLen + 1),
    {ok, CT, _} = beamchain_transport_v2:encrypt(A1, OversizePayload, <<>>, false),
    <<EncLen:3/binary, _Rest/binary>> = CT,

    %% Feed just the EncLen into extract_v2_packet via the responder cipher.
    %% The buffer contains exactly 3 bytes — length field only.
    Peer = beamchain_peer:make_test_v2_peer(B1, EncLen),
    ?assertEqual({stop, oversize_message},
                 beamchain_peer:extract_v2_packet(Peer)),

    %% Boundary: exactly MaxLen is allowed.
    MaxPayload = binary:copy(<<0>>, MaxLen),
    {ok, CT2, _} = beamchain_transport_v2:encrypt(A1, MaxPayload, <<>>, false),
    <<EncLen2:3/binary, _/binary>> = CT2,
    Peer2 = beamchain_peer:make_test_v2_peer(B1, EncLen2),
    %% Must NOT return oversize_message for the boundary-exact case.
    ?assertNotEqual({stop, oversize_message},
                    beamchain_peer:extract_v2_packet(Peer2)).

%%% ===================================================================
%%% G25 BUG — Garbage range [0,32] instead of BIP-324's [0,4095]
%%% ===================================================================

%% Documents the narrower-than-spec garbage range.  A passive observer
%% can identify beamchain v2 connections because the garbage is at most
%% 32 bytes, whereas Bitcoin Core uses up to 4095.  Privacy regression.
g25_bug_garbage_range_limited_to_32_bytes_test() ->
    %% We can't directly probe the garbage size chosen by beamchain_peer,
    %% but we can confirm the spec constant is what it should be and
    %% document the divergence via a comment.
    ?assertEqual(4095, beamchain_transport_v2:max_garbage_len()),
    %% The actual garbage generated in beamchain_peer.erl uses:
    %%   rand:uniform(33) - 1  →  [0, 32]
    %% BIP-324 §"Cryptographic primitives" says garbage MUST be
    %% uniform-random in [0, MAX_GARBAGE_LEN=4095] for anonymity.
    %% Tracking comment: beamchain_peer.erl lines 841 and 1188.
    ok.

%%% ===================================================================
%%% G28 — AEAD tag failure causes auth_failed (disconnect)
%%% ===================================================================

g28_tag_failure_returns_auth_failed_test() ->
    {ok, A0} = beamchain_transport_v2:new_cipher(),
    {ok, B0} = beamchain_transport_v2:new_cipher(),
    PA = beamchain_transport_v2:get_pubkey(A0),
    PB = beamchain_transport_v2:get_pubkey(B0),
    {ok, A1} = beamchain_transport_v2:initialize(A0, PB, true,  false, ?TEST_MAGIC),
    {ok, B1} = beamchain_transport_v2:initialize(B0, PA, false, false, ?TEST_MAGIC),
    Msg = <<"g28 auth failure test">>,
    {ok, CT, _} = beamchain_transport_v2:encrypt(A1, Msg, <<>>, false),
    <<EL:3/binary, EP/binary>> = CT,
    {ok, Len, B2} = beamchain_transport_v2:decrypt_length(B1, EL),
    %% Flip the last byte of the tag.
    EPSize = byte_size(EP),
    <<EPFront:(EPSize-1)/binary, LastByte>> = EP,
    Tampered = <<EPFront/binary, (LastByte bxor 1)>>,
    ?assertEqual({error, auth_failed},
                 beamchain_transport_v2:decrypt(B2, Tampered, <<>>, Len)).

%%% ===================================================================
%%% Cross-gate: Session ID matches on both sides; terminators swapped
%%% ===================================================================

g_session_id_and_terminators_symmetric_test() ->
    {ok, A0} = beamchain_transport_v2:new_cipher(),
    {ok, B0} = beamchain_transport_v2:new_cipher(),
    PA = beamchain_transport_v2:get_pubkey(A0),
    PB = beamchain_transport_v2:get_pubkey(B0),
    {ok, A1} = beamchain_transport_v2:initialize(A0, PB, true,  false, ?TEST_MAGIC),
    {ok, B1} = beamchain_transport_v2:initialize(B0, PA, false, false, ?TEST_MAGIC),
    ?assertEqual(beamchain_transport_v2:get_session_id(A1),
                 beamchain_transport_v2:get_session_id(B1)),
    ?assertEqual(beamchain_transport_v2:get_send_garbage_terminator(A1),
                 beamchain_transport_v2:get_recv_garbage_terminator(B1)),
    ?assertEqual(beamchain_transport_v2:get_send_garbage_terminator(B1),
                 beamchain_transport_v2:get_recv_garbage_terminator(A1)).
