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
