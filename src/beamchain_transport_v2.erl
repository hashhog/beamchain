-module(beamchain_transport_v2).

%% @doc BIP324 v2 Encrypted P2P Transport
%%
%% Implements the BIP324 encrypted transport protocol using:
%% - ElligatorSwift key exchange (64-byte indistinguishable pubkeys)
%% - HKDF-SHA256 for key derivation
%% - ChaCha20-Poly1305 AEAD encryption with forward-secure rekeying
%%
%% Message format:
%%   [3 bytes: encrypted length][encrypted payload + 16-byte tag]
%%
%% The cipher rekeys every 224 messages for forward security.

-export([new_cipher/0, new_cipher/2,
         get_pubkey/1, initialize/4, initialize/5,
         encrypt/4, decrypt_length/2, decrypt/4,
         get_session_id/1, get_send_garbage_terminator/1,
         get_recv_garbage_terminator/1]).

%% Constants exposed for the responder/initiator state machines.
-export([length_field_len/0, header_len/0, tag_len/0, max_garbage_len/0,
         garbage_terminator_len/0]).

%% HKDF helpers
-export([hkdf_extract/2, hkdf_expand/3]).

%%% -------------------------------------------------------------------
%%% Constants
%%% -------------------------------------------------------------------

-define(SESSION_ID_LEN, 32).
-define(GARBAGE_TERMINATOR_LEN, 16).
-define(REKEY_INTERVAL, 224).
-define(LENGTH_LEN, 3).
-define(HEADER_LEN, 1).
-define(TAG_LEN, 16).
-define(EXPANSION, ?LENGTH_LEN + ?HEADER_LEN + ?TAG_LEN).  %% 20 bytes
-define(IGNORE_BIT, 16#80).
-define(CHACHA_KEY_LEN, 32).
-define(CHACHA_NONCE_LEN, 12).
%% BIP-324: peer may send up to MAX_GARBAGE_LEN bytes of pre-key
%% garbage before the 16-byte send_garbage_terminator.  Beyond that the
%% receiver must treat it as a protocol violation and disconnect.
-define(MAX_GARBAGE_LEN, 4095).

%%% -------------------------------------------------------------------
%%% Cipher State
%%% -------------------------------------------------------------------

%% FSChaCha20 length cipher.
%%
%% IMPORTANT: per BIP-324, the keystream is CONTINUOUS within a rekey
%% epoch.  Each crypt() call consumes the next ``len(input)`` bytes of a
%% single ChaCha20 keystream that was initialised at the start of the
%% epoch with nonce ``[0,0,0,0] || LE64(rekey_counter)`` and block
%% counter 0.  After rekey_interval (= 224) crypt() calls the next 32
%% keystream bytes become the new key, the rekey_counter increments, and
%% the keystream buffer + block_counter reset for the new epoch.
%%
%% A naive implementation that builds a fresh nonce per call (encoding
%% ``packet_counter`` into the nonce and starting ChaCha20 at block 0
%% every time) produces a different keystream per packet starting at
%% block 0, so packet N's first byte is NOT the (N*3)th byte of a single
%% epoch keystream — diverging from Bitcoin Core / ouroboros after the
%% very first 3-byte length encryption.  Two such implementations
%% interop with each other (lock-step encrypt-then-decrypt happens to
%% land on PC=0,1,2,...), but they desync against any spec-correct peer
%% on the second packet.  See the W90 fix in clearbit cb04a1f for the
%% same bug in Zig.
-record(fs_chacha20, {
    key :: binary(),                          %% 32-byte ChaCha20 key
    packet_counter = 0 :: non_neg_integer(),  %% counter within rekey interval
    rekey_counter = 0 :: non_neg_integer(),   %% number of rekeys performed
    %% Cached keystream bytes from the most recent ChaCha20 block.  Bytes
    %% are consumed from the front; block_counter advances when this runs
    %% dry and the next 64-byte block is generated.
    keystream_buf = <<>> :: binary(),
    block_counter = 0 :: non_neg_integer()    %% resets to 0 on rekey
}).

-record(fs_chacha20_poly1305, {
    key :: binary(),              %% 32-byte AEAD key
    packet_counter = 0 :: non_neg_integer(),
    rekey_counter = 0 :: non_neg_integer()
}).

-record(bip324_cipher, {
    %% Our keypair
    seckey :: binary() | undefined,
    our_pubkey :: binary() | undefined,     %% 64-byte ElligatorSwift
    %% Ciphers (set after initialization)
    send_l :: #fs_chacha20{} | undefined,   %% length cipher
    recv_l :: #fs_chacha20{} | undefined,
    send_p :: #fs_chacha20_poly1305{} | undefined,  %% payload cipher
    recv_p :: #fs_chacha20_poly1305{} | undefined,
    %% Session data
    session_id :: binary() | undefined,
    send_garbage_terminator :: binary() | undefined,
    recv_garbage_terminator :: binary() | undefined
}).

-opaque cipher() :: #bip324_cipher{}.
-export_type([cipher/0]).

%%% ===================================================================
%%% API
%%% ===================================================================

%% @doc Create a new cipher with a fresh random keypair.
-spec new_cipher() -> {ok, cipher()} | {error, term()}.
new_cipher() ->
    SecKey = crypto:strong_rand_bytes(32),
    AuxRand = crypto:strong_rand_bytes(32),
    new_cipher(SecKey, AuxRand).

%% @doc Create a new cipher with a specific secret key and aux randomness.
-spec new_cipher(SecKey :: binary(), AuxRand :: binary()) ->
    {ok, cipher()} | {error, term()}.
new_cipher(SecKey, AuxRand) when byte_size(SecKey) =:= 32,
                                   byte_size(AuxRand) =:= 32 ->
    case beamchain_crypto:ellswift_create(SecKey, AuxRand) of
        {ok, PubKey} ->
            Cipher = #bip324_cipher{
                seckey = SecKey,
                our_pubkey = PubKey
            },
            {ok, Cipher};
        {error, _} = Err ->
            Err
    end.

%% @doc Get our 64-byte ElligatorSwift public key.
-spec get_pubkey(cipher()) -> binary().
get_pubkey(#bip324_cipher{our_pubkey = PubKey}) ->
    PubKey.

%% @doc Initialize the cipher after receiving the remote party's pubkey.
%% Initiator: true if we initiated the connection (sent our pubkey first).
%% SelfDecrypt: true for testing (use same keys for encrypt/decrypt).
%% Uses the network magic from beamchain_config.
-spec initialize(cipher(), TheirPubKey :: binary(),
                  Initiator :: boolean(), SelfDecrypt :: boolean()) ->
    {ok, cipher()} | {error, term()}.
initialize(Cipher, TheirPubKey, Initiator, SelfDecrypt) ->
    Magic = beamchain_config:magic(),
    initialize(Cipher, TheirPubKey, Initiator, SelfDecrypt, Magic).

%% @doc Initialize the cipher with explicit network magic.
%% Useful for testing without starting the full application.
-spec initialize(cipher(), TheirPubKey :: binary(),
                  Initiator :: boolean(), SelfDecrypt :: boolean(),
                  Magic :: binary()) ->
    {ok, cipher()} | {error, term()}.
initialize(#bip324_cipher{seckey = SecKey, our_pubkey = OurPubKey} = Cipher,
           TheirPubKey, Initiator, SelfDecrypt, Magic)
  when byte_size(TheirPubKey) =:= 64, byte_size(Magic) =:= 4 ->
    %% Determine party (0 = A/initiator, 1 = B/responder)
    Party = case Initiator of true -> 0; false -> 1 end,
    %% Build salt with network magic
    Salt = <<"bitcoin_v2_shared_secret", Magic/binary>>,
    %% Compute ECDH shared secret using BIP324 hash
    {EllA, EllB} = case Initiator of
        true  -> {OurPubKey, TheirPubKey};
        false -> {TheirPubKey, OurPubKey}
    end,
    case beamchain_crypto:ellswift_xdh(EllA, EllB, SecKey, Party) of
        {ok, ECDHSecret} ->
            %% HKDF key derivation
            PRK = hkdf_extract(Salt, ECDHSecret),
            %% Derive cipher keys
            InitiatorL = hkdf_expand(PRK, <<"initiator_L">>, 32),
            InitiatorP = hkdf_expand(PRK, <<"initiator_P">>, 32),
            ResponderL = hkdf_expand(PRK, <<"responder_L">>, 32),
            ResponderP = hkdf_expand(PRK, <<"responder_P">>, 32),
            %% Derive garbage terminators
            GarbageKey = hkdf_expand(PRK, <<"garbage_terminators">>, 32),
            <<InitiatorGarbage:?GARBAGE_TERMINATOR_LEN/binary,
              ResponderGarbage:?GARBAGE_TERMINATOR_LEN/binary>> = GarbageKey,
            %% Derive session ID
            SessionId = hkdf_expand(PRK, <<"session_id">>, 32),
            %% Assign keys based on direction
            Side = (Initiator xor SelfDecrypt),
            {SendL, SendP, RecvL, RecvP, SendGarbage, RecvGarbage} =
                case Side of
                    true ->
                        {InitiatorL, InitiatorP, ResponderL, ResponderP,
                         InitiatorGarbage, ResponderGarbage};
                    false ->
                        {ResponderL, ResponderP, InitiatorL, InitiatorP,
                         ResponderGarbage, InitiatorGarbage}
                end,
            Cipher2 = Cipher#bip324_cipher{
                seckey = undefined,  %% wipe secret key
                send_l = #fs_chacha20{key = SendL},
                recv_l = #fs_chacha20{key = RecvL},
                send_p = #fs_chacha20_poly1305{key = SendP},
                recv_p = #fs_chacha20_poly1305{key = RecvP},
                session_id = SessionId,
                send_garbage_terminator = SendGarbage,
                recv_garbage_terminator = RecvGarbage
            },
            {ok, Cipher2};
        {error, _} = Err ->
            Err
    end.

%% @doc Encrypt a message.
%% Returns {ok, Ciphertext, UpdatedCipher} where Ciphertext includes
%% 3-byte encrypted length + 1-byte header + payload + 16-byte tag.
-spec encrypt(cipher(), Contents :: binary(), AAD :: binary(),
              Ignore :: boolean()) ->
    {ok, binary(), cipher()}.
encrypt(#bip324_cipher{send_l = SendL, send_p = SendP} = Cipher,
        Contents, AAD, Ignore) ->
    %% Encrypt length (3 bytes, little-endian)
    Len = byte_size(Contents),
    LenBytes = <<Len:24/little>>,
    {EncLen, SendL2} = fs_chacha20_crypt(SendL, LenBytes),
    %% Build header + contents
    Header = case Ignore of true -> <<?IGNORE_BIT>>; false -> <<0>> end,
    Plaintext = <<Header/binary, Contents/binary>>,
    %% Encrypt with AEAD
    {EncPayload, SendP2} = fs_chacha20_poly1305_encrypt(SendP, Plaintext, AAD),
    Cipher2 = Cipher#bip324_cipher{send_l = SendL2, send_p = SendP2},
    {ok, <<EncLen/binary, EncPayload/binary>>, Cipher2}.

%% @doc Decrypt the 3-byte length field.
%% Returns {ok, Length, UpdatedCipher}.
-spec decrypt_length(cipher(), EncLen :: binary()) ->
    {ok, non_neg_integer(), cipher()}.
decrypt_length(#bip324_cipher{recv_l = RecvL} = Cipher, EncLen)
  when byte_size(EncLen) =:= ?LENGTH_LEN ->
    {<<Len:24/little>>, RecvL2} = fs_chacha20_crypt(RecvL, EncLen),
    Cipher2 = Cipher#bip324_cipher{recv_l = RecvL2},
    {ok, Len, Cipher2}.

%% @doc Decrypt a message payload (after length has been decrypted).
%% Input should be: 1-byte header + payload + 16-byte tag
%% Returns {ok, Contents, Ignore, UpdatedCipher} or {error, auth_failed}.
-spec decrypt(cipher(), EncPayload :: binary(), AAD :: binary(),
              ExpectedLen :: non_neg_integer()) ->
    {ok, binary(), boolean(), cipher()} | {error, auth_failed}.
decrypt(#bip324_cipher{recv_p = RecvP} = Cipher, EncPayload, AAD, ExpectedLen)
  when byte_size(EncPayload) =:= ExpectedLen + ?HEADER_LEN + ?TAG_LEN ->
    case fs_chacha20_poly1305_decrypt(RecvP, EncPayload, AAD) of
        {ok, <<Header, Contents/binary>>, RecvP2} ->
            Ignore = (Header band ?IGNORE_BIT) =:= ?IGNORE_BIT,
            Cipher2 = Cipher#bip324_cipher{recv_p = RecvP2},
            {ok, Contents, Ignore, Cipher2};
        {error, _} ->
            {error, auth_failed}
    end.

%% @doc Get the 32-byte session ID. Only valid after initialize().
-spec get_session_id(cipher()) -> binary().
get_session_id(#bip324_cipher{session_id = Id}) -> Id.

%% @doc Get the 16-byte garbage terminator we should send.
-spec get_send_garbage_terminator(cipher()) -> binary().
get_send_garbage_terminator(#bip324_cipher{send_garbage_terminator = T}) -> T.

%% @doc Get the 16-byte garbage terminator we expect to receive.
-spec get_recv_garbage_terminator(cipher()) -> binary().
get_recv_garbage_terminator(#bip324_cipher{recv_garbage_terminator = T}) -> T.

%% @doc 3-byte encrypted-length field (per packet on the wire).
-spec length_field_len() -> pos_integer().
length_field_len() -> ?LENGTH_LEN.

%% @doc 1-byte plaintext header before contents (carries IGNORE_BIT).
-spec header_len() -> pos_integer().
header_len() -> ?HEADER_LEN.

%% @doc 16-byte Poly1305 authentication tag appended to each packet.
-spec tag_len() -> pos_integer().
tag_len() -> ?TAG_LEN.

%% @doc Maximum bytes of pre-key garbage allowed before the
%% send_garbage_terminator.  Receiver MUST disconnect if the terminator
%% is not seen within this window.
-spec max_garbage_len() -> pos_integer().
max_garbage_len() -> ?MAX_GARBAGE_LEN.

%% @doc 16-byte garbage terminator length (constant).
-spec garbage_terminator_len() -> pos_integer().
garbage_terminator_len() -> ?GARBAGE_TERMINATOR_LEN.

%%% ===================================================================
%%% HKDF-SHA256 (RFC 5869)
%%% ===================================================================

%% @doc HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
-spec hkdf_extract(Salt :: binary(), IKM :: binary()) -> binary().
hkdf_extract(Salt, IKM) ->
    crypto:mac(hmac, sha256, Salt, IKM).

%% @doc HKDF-Expand: OKM = HMAC-SHA256(PRK, info || 0x01)
%% For L=32, only one round is needed.
-spec hkdf_expand(PRK :: binary(), Info :: binary(), L :: pos_integer()) ->
    binary().
hkdf_expand(PRK, Info, L) when L =< 32 ->
    %% Single round: T(1) = HMAC(PRK, info || 0x01)
    crypto:mac(hmac, sha256, PRK, <<Info/binary, 1>>);
hkdf_expand(PRK, Info, L) when L =< 64 ->
    %% Two rounds for L > 32
    T1 = crypto:mac(hmac, sha256, PRK, <<Info/binary, 1>>),
    T2 = crypto:mac(hmac, sha256, PRK, <<T1/binary, Info/binary, 2>>),
    <<Result:L/binary, _/binary>> = <<T1/binary, T2/binary>>,
    Result.

%%% ===================================================================
%%% Forward-Secure ChaCha20 (FSChaCha20)
%%% ===================================================================

%% @doc Encrypt/decrypt with FSChaCha20 and update state.
%% Rekeys every REKEY_INTERVAL packets.
%%
%% Per BIP-324 the length cipher's keystream is continuous within a
%% rekey epoch (see the comment on the #fs_chacha20{} record): each call
%% consumes the next ``byte_size(Data)`` bytes of a single ChaCha20
%% keystream initialised at the start of the epoch with nonce
%% ``[0,0,0,0] || LE64(rekey_counter)`` and block counter 0.
%%
%% Erlang crypto:crypto_one_time(chacha20, ...) expects a 16-byte IV:
%%   - First 4 bytes: block counter (32-bit LE, advances per 64-byte block)
%%   - Last 12 bytes: nonce  ([0,0,0,0] || LE64(rekey_counter))
-spec fs_chacha20_crypt(#fs_chacha20{}, binary()) ->
    {binary(), #fs_chacha20{}}.
fs_chacha20_crypt(#fs_chacha20{} = State, Data) ->
    Need = byte_size(Data),
    {KS, State1} = draw_keystream(State, Need),
    Output = crypto:exor(Data, KS),
    %% Advance schedule.  At the rekey boundary draw 32 more keystream
    %% bytes for the new key (still from the *current* epoch keystream),
    %% then reset the buffer + block counter for the next epoch.
    PC2 = State1#fs_chacha20.packet_counter + 1,
    case PC2 =:= ?REKEY_INTERVAL of
        true ->
            {NewKey, State2} = draw_keystream(State1, 32),
            State3 = State2#fs_chacha20{
                key = NewKey,
                packet_counter = 0,
                rekey_counter = State2#fs_chacha20.rekey_counter + 1,
                keystream_buf = <<>>,
                block_counter = 0
            },
            {Output, State3};
        false ->
            State4 = State1#fs_chacha20{packet_counter = PC2},
            {Output, State4}
    end.

%% Pull N bytes of keystream from the current epoch.  Refills the 64-byte
%% buffer as many times as needed, advancing block_counter per block.
-spec draw_keystream(#fs_chacha20{}, non_neg_integer()) ->
    {binary(), #fs_chacha20{}}.
draw_keystream(#fs_chacha20{} = State, N) ->
    draw_keystream(State, N, <<>>).

draw_keystream(State, 0, Acc) ->
    {Acc, State};
draw_keystream(#fs_chacha20{keystream_buf = Buf} = State, N, Acc)
  when byte_size(Buf) >= N ->
    <<Take:N/binary, Rest/binary>> = Buf,
    {<<Acc/binary, Take/binary>>, State#fs_chacha20{keystream_buf = Rest}};
draw_keystream(#fs_chacha20{keystream_buf = Buf} = State, N, Acc)
  when byte_size(Buf) > 0 ->
    Have = byte_size(Buf),
    draw_keystream(State#fs_chacha20{keystream_buf = <<>>},
                   N - Have, <<Acc/binary, Buf/binary>>);
draw_keystream(#fs_chacha20{key = Key, rekey_counter = RC,
                            block_counter = BC} = State, N, Acc) ->
    %% keystream_buf is empty; generate the next 64-byte block.
    %% IV = LE32(block_counter) || LE32(0) || LE64(rekey_counter)
    IV = <<BC:32/little, 0:32/little, RC:64/little>>,
    Block = crypto:crypto_one_time(chacha20, Key, IV, <<0:512>>, true),
    State2 = State#fs_chacha20{
        keystream_buf = Block,
        block_counter = BC + 1
    },
    draw_keystream(State2, N, Acc).

%%% ===================================================================
%%% Forward-Secure ChaCha20-Poly1305 (FSChaCha20Poly1305)
%%% ===================================================================

%% @doc Encrypt with FSChaCha20Poly1305 and update state.
%%
%% For ChaCha20-Poly1305 AEAD, the nonce is 12 bytes:
%%   nonce = packet_counter (4 bytes LE) || rekey_counter (8 bytes LE)
-spec fs_chacha20_poly1305_encrypt(#fs_chacha20_poly1305{}, binary(),
                                    binary()) ->
    {binary(), #fs_chacha20_poly1305{}}.
fs_chacha20_poly1305_encrypt(#fs_chacha20_poly1305{key = Key, packet_counter = PC,
                                                    rekey_counter = RC} = State,
                              Plaintext, AAD) ->
    %% Build 12-byte nonce: packet_counter (4 bytes LE) || rekey_counter (8 bytes LE)
    Nonce = <<PC:32/little, RC:64/little>>,
    %% AEAD encrypt
    {Ciphertext, Tag} = crypto:crypto_one_time_aead(
        chacha20_poly1305, Key, Nonce, Plaintext, AAD, true),
    Output = <<Ciphertext/binary, Tag/binary>>,
    %% Update state
    PC2 = PC + 1,
    State2 = maybe_rekey_aead(State#fs_chacha20_poly1305{packet_counter = PC2},
                               Key, RC),
    {Output, State2}.

%% @doc Decrypt with FSChaCha20Poly1305 and update state.
-spec fs_chacha20_poly1305_decrypt(#fs_chacha20_poly1305{}, binary(),
                                    binary()) ->
    {ok, binary(), #fs_chacha20_poly1305{}} | {error, auth_failed}.
fs_chacha20_poly1305_decrypt(#fs_chacha20_poly1305{key = Key, packet_counter = PC,
                                                    rekey_counter = RC} = State,
                              CiphertextWithTag, AAD) ->
    %% Split ciphertext and tag
    TagOffset = byte_size(CiphertextWithTag) - ?TAG_LEN,
    <<Ciphertext:TagOffset/binary, Tag:?TAG_LEN/binary>> = CiphertextWithTag,
    %% Build nonce
    Nonce = <<PC:32/little, RC:64/little>>,
    %% AEAD decrypt
    case crypto:crypto_one_time_aead(
           chacha20_poly1305, Key, Nonce, Ciphertext, AAD, Tag, false) of
        error ->
            {error, auth_failed};
        Plaintext ->
            %% Update state
            PC2 = PC + 1,
            State2 = maybe_rekey_aead(State#fs_chacha20_poly1305{packet_counter = PC2},
                                       Key, RC),
            {ok, Plaintext, State2}
    end.

%% Internal: rekey AEAD cipher if interval reached.
%%
%% Per BIP-324 / Bitcoin Core (bip324_cipher.cpp::FSChaCha20Poly1305::Rekey)
%% / ouroboros (transport_v2.FSChaCha20Poly1305._maybe_rekey), the new
%% AEAD key is derived by AEAD-encrypting 32 zero bytes (empty AAD) with
%% the OLD key under nonce ``\xFF\xFF\xFF\xFF || LE64(rekey_counter)``
%% and taking the first 32 bytes of the ciphertext.  This is NOT the same
%% as raw ChaCha20 keystream at block 0 — AEAD reserves block 0 for the
%% Poly1305 one-time key and starts encrypting at block 1.
maybe_rekey_aead(#fs_chacha20_poly1305{packet_counter = PC, rekey_counter = RC,
                                        key = Key} = State, _OldKey, _OldRC)
  when PC =:= ?REKEY_INTERVAL ->
    RekeyNonce = <<16#FFFFFFFF:32/little, RC:64/little>>,
    {CT, _Tag} = crypto:crypto_one_time_aead(
        chacha20_poly1305, Key, RekeyNonce, <<0:256>>, <<>>, true),
    %% First 32 bytes of the ciphertext become the new key.
    <<NewKey:32/binary, _/binary>> = CT,
    State#fs_chacha20_poly1305{key = NewKey, packet_counter = 0,
                                rekey_counter = RC + 1};
maybe_rekey_aead(State, _OldKey, _OldRC) ->
    State.
