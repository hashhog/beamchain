-module(beamchain_transport_v2_tests).
-include_lib("eunit/include/eunit.hrl").

%%% ===================================================================
%%% Test suite for BIP324 v2 encrypted transport
%%% ===================================================================

%% Testnet4 network magic for testing (avoids needing to start the app)
-define(TEST_MAGIC, <<16#1c, 16#16, 16#3f, 16#28>>).

%% Test creating a new cipher
new_cipher_test() ->
    {ok, Cipher} = beamchain_transport_v2:new_cipher(),
    PubKey = beamchain_transport_v2:get_pubkey(Cipher),
    ?assertEqual(64, byte_size(PubKey)).

%% Test creating cipher with specific key
new_cipher_with_key_test() ->
    SecKey = crypto:strong_rand_bytes(32),
    AuxRand = crypto:strong_rand_bytes(32),
    {ok, Cipher} = beamchain_transport_v2:new_cipher(SecKey, AuxRand),
    PubKey = beamchain_transport_v2:get_pubkey(Cipher),
    ?assertEqual(64, byte_size(PubKey)).

%% Test HKDF extract and expand
hkdf_test() ->
    Salt = <<"test_salt">>,
    IKM = <<"input_key_material">>,
    PRK = beamchain_transport_v2:hkdf_extract(Salt, IKM),
    ?assertEqual(32, byte_size(PRK)),
    Key = beamchain_transport_v2:hkdf_expand(PRK, <<"info">>, 32),
    ?assertEqual(32, byte_size(Key)).

%% Test round-trip encryption/decryption with self_decrypt mode
roundtrip_self_decrypt_test() ->
    %% Create two ciphers (initiator and responder)
    {ok, InitCipher0} = beamchain_transport_v2:new_cipher(),
    {ok, RespCipher0} = beamchain_transport_v2:new_cipher(),
    InitPubKey = beamchain_transport_v2:get_pubkey(InitCipher0),
    RespPubKey = beamchain_transport_v2:get_pubkey(RespCipher0),
    %% Initialize both sides with explicit magic
    %% Initiator: we are party A (initiator=true)
    {ok, InitCipher1} = beamchain_transport_v2:initialize(
        InitCipher0, RespPubKey, true, false, ?TEST_MAGIC),
    %% Responder: we are party B (initiator=false)
    {ok, RespCipher1} = beamchain_transport_v2:initialize(
        RespCipher0, InitPubKey, false, false, ?TEST_MAGIC),
    %% Session IDs should match
    InitSessionId = beamchain_transport_v2:get_session_id(InitCipher1),
    RespSessionId = beamchain_transport_v2:get_session_id(RespCipher1),
    ?assertEqual(InitSessionId, RespSessionId),
    %% Garbage terminators should be swapped
    InitSendGarbage = beamchain_transport_v2:get_send_garbage_terminator(InitCipher1),
    RespRecvGarbage = beamchain_transport_v2:get_recv_garbage_terminator(RespCipher1),
    ?assertEqual(InitSendGarbage, RespRecvGarbage),
    %% Test encryption: initiator sends to responder
    Message = <<"Hello, BIP324!">>,
    AAD = <<>>,
    {ok, Ciphertext, InitCipher2} = beamchain_transport_v2:encrypt(
        InitCipher1, Message, AAD, false),
    %% Split into length and payload
    <<EncLen:3/binary, EncPayload/binary>> = Ciphertext,
    %% Responder decrypts
    {ok, Len, RespCipher2} = beamchain_transport_v2:decrypt_length(
        RespCipher1, EncLen),
    ?assertEqual(byte_size(Message), Len),
    {ok, DecMessage, Ignore, _RespCipher3} = beamchain_transport_v2:decrypt(
        RespCipher2, EncPayload, AAD, Len),
    ?assertEqual(Message, DecMessage),
    ?assertEqual(false, Ignore),
    %% Test reverse direction: responder sends to initiator
    Message2 = <<"Hello back!">>,
    {ok, Ciphertext2, RespCipher4} = beamchain_transport_v2:encrypt(
        RespCipher2, Message2, AAD, false),
    <<EncLen2:3/binary, EncPayload2/binary>> = Ciphertext2,
    {ok, Len2, InitCipher3} = beamchain_transport_v2:decrypt_length(
        InitCipher2, EncLen2),
    {ok, DecMessage2, _, _InitCipher4} = beamchain_transport_v2:decrypt(
        InitCipher3, EncPayload2, AAD, Len2),
    ?assertEqual(Message2, DecMessage2),
    ok.

%% Test ignore flag
ignore_flag_test() ->
    %% Use two properly paired ciphers to test ignore flag
    {ok, CipherA0} = beamchain_transport_v2:new_cipher(),
    {ok, CipherB0} = beamchain_transport_v2:new_cipher(),
    PubKeyA = beamchain_transport_v2:get_pubkey(CipherA0),
    PubKeyB = beamchain_transport_v2:get_pubkey(CipherB0),
    {ok, CipherA1} = beamchain_transport_v2:initialize(
        CipherA0, PubKeyB, true, false, ?TEST_MAGIC),
    {ok, CipherB1} = beamchain_transport_v2:initialize(
        CipherB0, PubKeyA, false, false, ?TEST_MAGIC),
    Message = <<"decoy message">>,
    {ok, Ciphertext, _CipherA2} = beamchain_transport_v2:encrypt(
        CipherA1, Message, <<>>, true),  %% ignore=true
    <<EncLen:3/binary, EncPayload/binary>> = Ciphertext,
    {ok, Len, CipherB2} = beamchain_transport_v2:decrypt_length(CipherB1, EncLen),
    {ok, _, Ignore, _} = beamchain_transport_v2:decrypt(
        CipherB2, EncPayload, <<>>, Len),
    ?assertEqual(true, Ignore).

%% Test AAD (additional authenticated data)
aad_test() ->
    {ok, CipherA0} = beamchain_transport_v2:new_cipher(),
    {ok, CipherB0} = beamchain_transport_v2:new_cipher(),
    PubKeyA = beamchain_transport_v2:get_pubkey(CipherA0),
    PubKeyB = beamchain_transport_v2:get_pubkey(CipherB0),
    {ok, CipherA1} = beamchain_transport_v2:initialize(
        CipherA0, PubKeyB, true, false, ?TEST_MAGIC),
    {ok, CipherB1} = beamchain_transport_v2:initialize(
        CipherB0, PubKeyA, false, false, ?TEST_MAGIC),
    Message = <<"authenticated message">>,
    AAD = <<"some garbage data">>,
    {ok, Ciphertext, _} = beamchain_transport_v2:encrypt(CipherA1, Message, AAD, false),
    <<EncLen:3/binary, EncPayload/binary>> = Ciphertext,
    {ok, Len, CipherB2} = beamchain_transport_v2:decrypt_length(CipherB1, EncLen),
    %% Correct AAD should work
    {ok, DecMessage, _, _} = beamchain_transport_v2:decrypt(
        CipherB2, EncPayload, AAD, Len),
    ?assertEqual(Message, DecMessage),
    %% Wrong AAD should fail
    ?assertEqual({error, auth_failed},
                 beamchain_transport_v2:decrypt(
                     CipherB2, EncPayload, <<"wrong aad">>, Len)).

%% Test multiple messages (to verify state updates)
multiple_messages_test() ->
    {ok, CipherA0} = beamchain_transport_v2:new_cipher(),
    {ok, CipherB0} = beamchain_transport_v2:new_cipher(),
    PubKeyA = beamchain_transport_v2:get_pubkey(CipherA0),
    PubKeyB = beamchain_transport_v2:get_pubkey(CipherB0),
    {ok, CipherA1} = beamchain_transport_v2:initialize(
        CipherA0, PubKeyB, true, false, ?TEST_MAGIC),
    {ok, CipherB1} = beamchain_transport_v2:initialize(
        CipherB0, PubKeyA, false, false, ?TEST_MAGIC),
    %% Send 10 messages
    {CipherAFinal, CipherBFinal} = lists:foldl(
        fun(N, {CA, CB}) ->
            Msg = <<"Message #", (integer_to_binary(N))/binary>>,
            {ok, CT, CA2} = beamchain_transport_v2:encrypt(CA, Msg, <<>>, false),
            <<EncLen:3/binary, EncPayload/binary>> = CT,
            {ok, Len, CB2} = beamchain_transport_v2:decrypt_length(CB, EncLen),
            {ok, DecMsg, _, CB3} = beamchain_transport_v2:decrypt(
                CB2, EncPayload, <<>>, Len),
            ?assertEqual(Msg, DecMsg),
            {CA2, CB3}
        end,
        {CipherA1, CipherB1},
        lists:seq(1, 10)),
    %% Both sides should have processed 10 messages
    ok.

%% Test rekey happens at 224 messages
rekey_test_() ->
    {timeout, 60, fun rekey_test_impl/0}.

rekey_test_impl() ->
    {ok, CipherA0} = beamchain_transport_v2:new_cipher(),
    {ok, CipherB0} = beamchain_transport_v2:new_cipher(),
    PubKeyA = beamchain_transport_v2:get_pubkey(CipherA0),
    PubKeyB = beamchain_transport_v2:get_pubkey(CipherB0),
    {ok, CipherA1} = beamchain_transport_v2:initialize(
        CipherA0, PubKeyB, true, false, ?TEST_MAGIC),
    {ok, CipherB1} = beamchain_transport_v2:initialize(
        CipherB0, PubKeyA, false, false, ?TEST_MAGIC),
    %% Send 250 messages (crosses the 224 rekey boundary)
    {_CipherAFinal, _CipherBFinal} = lists:foldl(
        fun(N, {CA, CB}) ->
            Msg = <<"M", (integer_to_binary(N))/binary>>,
            {ok, CT, CA2} = beamchain_transport_v2:encrypt(CA, Msg, <<>>, false),
            <<EncLen:3/binary, EncPayload/binary>> = CT,
            {ok, Len, CB2} = beamchain_transport_v2:decrypt_length(CB, EncLen),
            {ok, DecMsg, _, CB3} = beamchain_transport_v2:decrypt(
                CB2, EncPayload, <<>>, Len),
            ?assertEqual(Msg, DecMsg),
            {CA2, CB3}
        end,
        {CipherA1, CipherB1},
        lists:seq(1, 250)),
    ok.

%% Test empty message
empty_message_test() ->
    {ok, CipherA0} = beamchain_transport_v2:new_cipher(),
    {ok, CipherB0} = beamchain_transport_v2:new_cipher(),
    PubKeyA = beamchain_transport_v2:get_pubkey(CipherA0),
    PubKeyB = beamchain_transport_v2:get_pubkey(CipherB0),
    {ok, CipherA1} = beamchain_transport_v2:initialize(
        CipherA0, PubKeyB, true, false, ?TEST_MAGIC),
    {ok, CipherB1} = beamchain_transport_v2:initialize(
        CipherB0, PubKeyA, false, false, ?TEST_MAGIC),
    Message = <<>>,
    {ok, CT, _} = beamchain_transport_v2:encrypt(CipherA1, Message, <<>>, false),
    <<EncLen:3/binary, EncPayload/binary>> = CT,
    {ok, Len, CipherB2} = beamchain_transport_v2:decrypt_length(CipherB1, EncLen),
    ?assertEqual(0, Len),
    {ok, DecMsg, _, _} = beamchain_transport_v2:decrypt(
        CipherB2, EncPayload, <<>>, Len),
    ?assertEqual(<<>>, DecMsg).

%% Test large message
large_message_test() ->
    {ok, CipherA0} = beamchain_transport_v2:new_cipher(),
    {ok, CipherB0} = beamchain_transport_v2:new_cipher(),
    PubKeyA = beamchain_transport_v2:get_pubkey(CipherA0),
    PubKeyB = beamchain_transport_v2:get_pubkey(CipherB0),
    {ok, CipherA1} = beamchain_transport_v2:initialize(
        CipherA0, PubKeyB, true, false, ?TEST_MAGIC),
    {ok, CipherB1} = beamchain_transport_v2:initialize(
        CipherB0, PubKeyA, false, false, ?TEST_MAGIC),
    %% 1MB message
    Message = crypto:strong_rand_bytes(1024 * 1024),
    {ok, CT, _} = beamchain_transport_v2:encrypt(CipherA1, Message, <<>>, false),
    <<EncLen:3/binary, EncPayload/binary>> = CT,
    {ok, Len, CipherB2} = beamchain_transport_v2:decrypt_length(CipherB1, EncLen),
    ?assertEqual(byte_size(Message), Len),
    {ok, DecMsg, _, _} = beamchain_transport_v2:decrypt(
        CipherB2, EncPayload, <<>>, Len),
    ?assertEqual(Message, DecMsg).

%% Test ElligatorSwift NIF functions directly
ellswift_create_test() ->
    SecKey = crypto:strong_rand_bytes(32),
    AuxRand = crypto:strong_rand_bytes(32),
    {ok, EllSwift} = beamchain_crypto:ellswift_create(SecKey, AuxRand),
    ?assertEqual(64, byte_size(EllSwift)).

%% Test ECDH produces same secret for both parties
ellswift_xdh_test() ->
    %% Party A (initiator)
    SecKeyA = crypto:strong_rand_bytes(32),
    AuxRandA = crypto:strong_rand_bytes(32),
    {ok, EllA} = beamchain_crypto:ellswift_create(SecKeyA, AuxRandA),
    %% Party B (responder)
    SecKeyB = crypto:strong_rand_bytes(32),
    AuxRandB = crypto:strong_rand_bytes(32),
    {ok, EllB} = beamchain_crypto:ellswift_create(SecKeyB, AuxRandB),
    %% Both compute shared secret
    {ok, SecretA} = beamchain_crypto:ellswift_xdh(EllA, EllB, SecKeyA, 0),
    {ok, SecretB} = beamchain_crypto:ellswift_xdh(EllA, EllB, SecKeyB, 1),
    %% Secrets should match
    ?assertEqual(SecretA, SecretB).

%%% ===================================================================
%%% W90 cipher-correctness regression tests
%%%
%%% These cover the FSChaCha20 length-cipher continuous-keystream bug
%%% that bit clearbit (cb04a1f) and was latent in beamchain.  The
%%% existing ``multiple_messages`` and ``rekey`` tests run the cipher in
%%% lock-step (encrypt N, decrypt N, repeat) which happens to land on
%%% packet_counter values 0,1,2,... in either model.  The two tests
%%% below break that lock-step in different ways, exercising the
%%% wire-order pattern that real Bitcoin Core peers produce.
%%% ===================================================================

%% Two-encrypts-before-decrypt: matches the on-wire pattern where the
%% application has already written the verack on top of the version
%% before the peer's first ack arrives.  Pre-fix this would either
%% desync the length cipher or return garbage from decrypt_length on
%% packet 1.
v2_wire_order_two_encrypt_before_decrypt_test() ->
    {ok, A0} = beamchain_transport_v2:new_cipher(),
    {ok, B0} = beamchain_transport_v2:new_cipher(),
    PA = beamchain_transport_v2:get_pubkey(A0),
    PB = beamchain_transport_v2:get_pubkey(B0),
    {ok, A1} = beamchain_transport_v2:initialize(A0, PB, true,  false, ?TEST_MAGIC),
    {ok, B1} = beamchain_transport_v2:initialize(B0, PA, false, false, ?TEST_MAGIC),
    M1 = <<"first message ", 0:64>>,
    M2 = <<"second message ", 1:64>>,
    %% A encrypts BOTH messages before B decrypts either
    {ok, CT1, A2} = beamchain_transport_v2:encrypt(A1, M1, <<>>, false),
    {ok, CT2, _A3} = beamchain_transport_v2:encrypt(A2, M2, <<>>, false),
    <<EL1:3/binary, EP1/binary>> = CT1,
    <<EL2:3/binary, EP2/binary>> = CT2,
    {ok, L1, B2} = beamchain_transport_v2:decrypt_length(B1, EL1),
    ?assertEqual(byte_size(M1), L1),
    {ok, D1, _, B3} = beamchain_transport_v2:decrypt(B2, EP1, <<>>, L1),
    ?assertEqual(M1, D1),
    {ok, L2, B4} = beamchain_transport_v2:decrypt_length(B3, EL2),
    ?assertEqual(byte_size(M2), L2),
    {ok, D2, _, _B5} = beamchain_transport_v2:decrypt(B4, EP2, <<>>, L2),
    ?assertEqual(M2, D2).

%% FSChaCha20 keystream is continuous within a rekey epoch.
%%
%% Vector generated from ouroboros's spec-correct reference
%% (src/ouroboros/transport_v2.py FSChaCha20):
%%   key = bytes(range(32)), encrypt 5x3 zero bytes, expect first 15
%%   bytes of the ChaCha20(key, nonce=zeros, blk=0) keystream:
%%   39fd2b7dd9c5196a8dbd0377b8dc4a
%%
%% We can't reach the FSChaCha20 cipher from outside the module, so
%% drive it through the public encrypt() path with a constructed
%% initiator/responder pair whose initiator-L key happens to be the
%% test vector key.  Easier: assert on the raw ChaCha20 block — that's
%% what fs_chacha20_crypt now consumes — and on the wire-order test
%% above, which only succeeds if the keystream is continuous.
fs_chacha20_keystream_block_zero_test() ->
    %% Sanity: confirm Erlang's crypto:crypto_one_time(chacha20, ...) matches
    %% the BIP-324 length-cipher block-0 keystream byte-for-byte against
    %% the ouroboros / Bitcoin Core reference.  Pre-fix, fs_chacha20_crypt
    %% built a fresh nonce per packet and called this same primitive but
    %% with packet_counter stuffed into the nonce — the bytes diverged
    %% from packet 2 onwards.
    Key = list_to_binary(lists:seq(0, 31)),
    %% IV: block_counter=0 || nonce=([0,0,0,0] || LE64(0))
    IV = <<0:32/little, 0:32/little, 0:64/little>>,
    Block = crypto:crypto_one_time(chacha20, Key, IV, <<0:512>>, true),
    Expected = <<16#39, 16#fd, 16#2b, 16#7d, 16#d9, 16#c5, 16#19, 16#6a,
                 16#8d, 16#bd, 16#03, 16#77, 16#b8, 16#dc, 16#4a>>,
    ?assertEqual(Expected, binary:part(Block, 0, 15)).

%% End-to-end: drive the full BIP-324 v2 cipher handshake bytes the
%% way the inbound responder code in beamchain_peer.erl will see them
%% on the wire.  The "client" here plays the role of a Bitcoin Core
%% v2 initiator (sends 64-byte ellswift, garbage, terminator, version
%% packet).  We exercise the cipher API end-to-end so any byte-format
%% regression in encrypt/decrypt would surface here even if the gen_statem
%% wiring is exercised separately by integration tests.
v2_full_handshake_responder_view_test() ->
    %% --- Set up two ciphers ---
    {ok, ClientC0} = beamchain_transport_v2:new_cipher(),
    {ok, ServerC0} = beamchain_transport_v2:new_cipher(),
    ClientPK = beamchain_transport_v2:get_pubkey(ClientC0),
    ServerPK = beamchain_transport_v2:get_pubkey(ServerC0),
    {ok, ClientC1} = beamchain_transport_v2:initialize(
        ClientC0, ServerPK, true,  false, ?TEST_MAGIC),
    {ok, ServerC1} = beamchain_transport_v2:initialize(
        ServerC0, ClientPK, false, false, ?TEST_MAGIC),
    %% Session ids match.
    ?assertEqual(beamchain_transport_v2:get_session_id(ClientC1),
                 beamchain_transport_v2:get_session_id(ServerC1)),
    %% --- Client builds the wire bytes the responder will read ---
    ClientGarbage = crypto:strong_rand_bytes(13),
    ClientSendTerm = beamchain_transport_v2:get_send_garbage_terminator(ClientC1),
    {ok, ClientVerPkt, _ClientC2} = beamchain_transport_v2:encrypt(
        ClientC1, <<>>, ClientGarbage, false),
    %% Wire = pubkey || garbage || terminator || version-packet
    Wire = <<ClientPK/binary, ClientGarbage/binary,
             ClientSendTerm/binary, ClientVerPkt/binary>>,
    %% --- Server-side responder logic mirrors the production loop ---
    %% 1. Server already has ServerC1 and the peer's pubkey was the
    %%    first 64 bytes of Wire — already used to call initialize().
    %% 2. Scan the rest of Wire for the recv_garbage_terminator.
    AfterPK = binary:part(Wire, 64, byte_size(Wire) - 64),
    ServerRecvTerm = beamchain_transport_v2:get_recv_garbage_terminator(ServerC1),
    {RecvGarbage, AfterTerm} = scan_terminator_test(AfterPK, ServerRecvTerm),
    ?assertEqual(ClientGarbage, RecvGarbage),
    %% 3. Decrypt the version packet (AAD = recv_garbage on first decrypt).
    LL = beamchain_transport_v2:length_field_len(),
    HL = beamchain_transport_v2:header_len(),
    TL = beamchain_transport_v2:tag_len(),
    <<EncLen:LL/binary, EncRest/binary>> = AfterTerm,
    {ok, ContentsLen, ServerC2} = beamchain_transport_v2:decrypt_length(
        ServerC1, EncLen),
    ?assertEqual(0, ContentsLen),  %% BIP-324 version packet has empty contents
    BodyLen = HL + ContentsLen + TL,
    <<EncBody:BodyLen/binary, _Rest/binary>> = EncRest,
    {ok, Contents, IsDecoy, ServerC3} = beamchain_transport_v2:decrypt(
        ServerC2, EncBody, RecvGarbage, ContentsLen),
    ?assertEqual(<<>>, Contents),
    ?assertEqual(false, IsDecoy),
    %% 4. Application-layer round-trip after the handshake — exercise the
    %% short-id encoding wired in beamchain_v2_msg.
    PingPayload = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    Wrapped = beamchain_v2_msg:encode_contents(<<"ping">>, PingPayload),
    {ok, AppPkt, _} = beamchain_transport_v2:encrypt(ServerC3, Wrapped, <<>>, false),
    %% Client decrypts the ping via the now-paired cipher state.
    {ok, ClientC3} = beamchain_transport_v2:initialize(
        ClientC0, ServerPK, true,  false, ?TEST_MAGIC),
    %% Replay the client's outbound encrypt to advance its send state to
    %% match what we did on the wire (the client sent ClientVerPkt as
    %% packet 0, so its send_p is at PC=1 — no relevance to *recv*
    %% though, which is what we're about to use).
    <<EL2:LL/binary, ER2/binary>> = AppPkt,
    {ok, CL2, ClientC4} = beamchain_transport_v2:decrypt_length(ClientC3, EL2),
    BL2 = HL + CL2 + TL,
    <<EB2:BL2/binary, _/binary>> = ER2,
    {ok, DecPlain, false, _} = beamchain_transport_v2:decrypt(
        ClientC4, EB2, <<>>, CL2),
    {ok, GotCmd, GotPayload} = beamchain_v2_msg:decode_contents(DecPlain),
    ?assertEqual(<<"ping">>, GotCmd),
    ?assertEqual(PingPayload, GotPayload).

%% Test helper: byte-by-byte slide a window over Buffer until the last
%% TermLen bytes equal Term; return everything before the terminator
%% and the bytes still left in the buffer afterwards.
scan_terminator_test(Buffer, Term) ->
    scan_terminator_test(Buffer, Term, byte_size(Term), <<>>).

scan_terminator_test(<<Byte, Rest/binary>>, Term, TermLen, Window) ->
    NewWindow = <<Window/binary, Byte>>,
    case byte_size(NewWindow) >= TermLen of
        true ->
            Tail = binary:part(NewWindow, byte_size(NewWindow) - TermLen, TermLen),
            case Tail =:= Term of
                true ->
                    Garbage = binary:part(NewWindow, 0,
                                          byte_size(NewWindow) - TermLen),
                    {Garbage, Rest};
                false ->
                    scan_terminator_test(Rest, Term, TermLen, NewWindow)
            end;
        false ->
            scan_terminator_test(Rest, Term, TermLen, NewWindow)
    end.

%% Send 250 packets without lock-step decrypt: A encrypts all 250 first,
%% then B decrypts in order.  This rules out any lock-step coincidence
%% across the rekey boundary at packet 224.
v2_burst_250_then_decrypt_test_() ->
    {timeout, 60, fun v2_burst_250_then_decrypt_impl/0}.

v2_burst_250_then_decrypt_impl() ->
    {ok, A0} = beamchain_transport_v2:new_cipher(),
    {ok, B0} = beamchain_transport_v2:new_cipher(),
    PA = beamchain_transport_v2:get_pubkey(A0),
    PB = beamchain_transport_v2:get_pubkey(B0),
    {ok, A1} = beamchain_transport_v2:initialize(A0, PB, true,  false, ?TEST_MAGIC),
    {ok, B1} = beamchain_transport_v2:initialize(B0, PA, false, false, ?TEST_MAGIC),
    %% A encrypts 250 messages without B touching anything.
    {Cts, _} = lists:foldl(
        fun(N, {Acc, Ax}) ->
            Msg = <<"M-", (integer_to_binary(N))/binary>>,
            {ok, CT, Ax2} = beamchain_transport_v2:encrypt(Ax, Msg, <<>>, false),
            {[{Msg, CT} | Acc], Ax2}
        end,
        {[], A1},
        lists:seq(1, 250)),
    OrderedCts = lists:reverse(Cts),
    %% B decrypts in the same order.
    lists:foldl(
        fun({ExpMsg, CT}, Bx) ->
            <<EL:3/binary, EP/binary>> = CT,
            {ok, Len, Bx2} = beamchain_transport_v2:decrypt_length(Bx, EL),
            ?assertEqual(byte_size(ExpMsg), Len),
            {ok, GotMsg, _, Bx3} = beamchain_transport_v2:decrypt(Bx2, EP, <<>>, Len),
            ?assertEqual(ExpMsg, GotMsg),
            Bx3
        end,
        B1,
        OrderedCts),
    ok.
