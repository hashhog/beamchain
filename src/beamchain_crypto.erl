-module(beamchain_crypto).

%% Signature verification (NIF-backed)
-export([ecdsa_verify/3, ecdsa_verify_lax/3, schnorr_verify/3]).

%% Cached verification (checks sig cache before calling NIF)
-export([ecdsa_verify_cached/3, schnorr_verify_cached/3]).

%% Signing (NIF-backed)
-export([ecdsa_sign/2, schnorr_sign/3, seckey_tweak_add/2]).

%% Recoverable ECDSA (BIP137 / Bitcoin signed messages)
-export([ecdsa_sign_recoverable/2, ecdsa_recover/3,
         message_hash/1, sign_message/2, verify_message/3]).

%% Public key operations (NIF-backed)
-export([pubkey_from_privkey/1, pubkey_tweak_add/2,
         pubkey_compress/1, pubkey_decompress/1,
         pubkey_combine/1, xonly_pubkey_tweak_add/2]).

%% ElligatorSwift operations (BIP324 v2 transport)
-export([ellswift_create/2, ellswift_xdh/4]).

%% Hashing (NIF-accelerated with pure Erlang fallback)
-export([sha256/1, hash256/1, hash160/1,
         tagged_hash/2, hmac_sha512/2]).

%% Hardware introspection
-export([sha256_hardware_info/0]).

%% Batch verification (reduces NIF call overhead)
-export([batch_ecdsa_verify/1, batch_schnorr_verify/1]).

%% SipHash-2-4 (for BIP152 compact blocks)
-export([siphash/3, siphash_uint256/3]).

%% DER signature handling
-export([decode_der_signature/1, decode_der_lax/1, encode_der_signature/2,
         check_strict_der/1, is_low_s/1, normalize_s/1]).

%% Public key validation
-export([validate_pubkey/1, is_compressed_pubkey/1]).

-on_load(init/0).

%% secp256k1 curve constants
-define(SECP256K1_N,
    16#FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141).
-define(SECP256K1_N_HALF,
    16#7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0).

%% Track whether NIF loaded successfully for fallback logic
-define(NIF_LOADED, beamchain_crypto_nif_loaded).

%%% -------------------------------------------------------------------
%%% NIF loading
%%% -------------------------------------------------------------------

init() ->
    SoName = filename:join(priv_dir(), "beamchain_crypto_nif"),
    Ret = erlang:load_nif(SoName, 0),
    %% Track NIF load status for fallback logic
    case Ret of
        ok ->
            persistent_term:put(?NIF_LOADED, true);
        _ ->
            persistent_term:put(?NIF_LOADED, false),
            logger:warning("beamchain_crypto: NIF not loaded, using pure Erlang fallback")
    end,
    init_tag_hashes(),
    Ret.

priv_dir() ->
    case code:priv_dir(beamchain) of
        {error, _} ->
            %% fallback for dev/escript
            case code:which(?MODULE) of
                Filename when is_list(Filename) ->
                    filename:join(
                        filename:dirname(filename:dirname(Filename)),
                        "priv");
                _ ->
                    "priv"
            end;
        Dir -> Dir
    end.

%%% -------------------------------------------------------------------
%%% NIF stubs (replaced when NIF loads)
%%% -------------------------------------------------------------------

ecdsa_verify_nif(_Msg, _Sig, _PubKey) ->
    erlang:nif_error(nif_not_loaded).

schnorr_verify_nif(_Msg, _Sig, _PubKey) ->
    erlang:nif_error(nif_not_loaded).

pubkey_create_nif(_SecKey) ->
    erlang:nif_error(nif_not_loaded).

pubkey_tweak_add_nif(_PubKey, _Tweak) ->
    erlang:nif_error(nif_not_loaded).

xonly_pubkey_tweak_add_nif(_PubKey, _Tweak) ->
    erlang:nif_error(nif_not_loaded).

pubkey_compress_nif(_PubKey) ->
    erlang:nif_error(nif_not_loaded).

pubkey_decompress_nif(_PubKey) ->
    erlang:nif_error(nif_not_loaded).

pubkey_combine_nif(_PubKeys) ->
    erlang:nif_error(nif_not_loaded).

ecdsa_sign_nif(_Msg, _SecKey) ->
    erlang:nif_error(nif_not_loaded).

ecdsa_sign_recoverable_nif(_Msg, _SecKey) ->
    erlang:nif_error(nif_not_loaded).

ecdsa_recover_nif(_Msg, _RecId, _Sig) ->
    erlang:nif_error(nif_not_loaded).

schnorr_sign_nif(_Msg, _SecKey, _AuxRand) ->
    erlang:nif_error(nif_not_loaded).

seckey_tweak_add_nif(_SecKey, _Tweak) ->
    erlang:nif_error(nif_not_loaded).

ellswift_create_nif(_SecKey, _AuxRand) ->
    erlang:nif_error(nif_not_loaded).

ellswift_xdh_nif(_EllA, _EllB, _SecKey, _Party) ->
    erlang:nif_error(nif_not_loaded).

%% SHA-256 NIFs (with hardware acceleration when available)
sha256_nif(_Data) ->
    erlang:nif_error(nif_not_loaded).

double_sha256_nif(_Data) ->
    erlang:nif_error(nif_not_loaded).

sha256_hardware_info_nif() ->
    erlang:nif_error(nif_not_loaded).

%% Batch verification NIFs
batch_ecdsa_verify_nif(_Items) ->
    erlang:nif_error(nif_not_loaded).

batch_schnorr_verify_nif(_Items) ->
    erlang:nif_error(nif_not_loaded).

%%% -------------------------------------------------------------------
%%% Signature verification
%%% -------------------------------------------------------------------

-spec ecdsa_verify(Msg :: binary(), Sig :: binary(),
                   PubKey :: binary()) -> boolean().
ecdsa_verify(Msg, Sig, PubKey) when byte_size(Msg) =:= 32 ->
    case ecdsa_verify_nif(Msg, Sig, PubKey) of
        true  -> true;
        false -> false;
        {error, _} -> false
    end.

%% @doc ECDSA verify with lax DER parsing.
%% Extracts R/S from non-strict DER, normalizes S (low-S), re-encodes
%% as canonical DER, then passes to the strict NIF for verification.
%% This matches Bitcoin Core's pre-BIP66 behavior.
-spec ecdsa_verify_lax(Msg :: binary(), Sig :: binary(),
                       PubKey :: binary()) -> boolean().
ecdsa_verify_lax(Msg, Sig, PubKey) when byte_size(Msg) =:= 32 ->
    case decode_der_lax(Sig) of
        {ok, {R, S}} ->
            %% Normalize S to low-S form
            S2 = normalize_s(S),
            %% Re-encode as canonical DER
            CanonicalSig = encode_der_signature(R, S2),
            ecdsa_verify(Msg, CanonicalSig, PubKey);
        {error, _} ->
            false
    end.

-spec schnorr_verify(Msg :: binary(), Sig :: binary(),
                     PubKey :: binary()) -> boolean().
schnorr_verify(Msg, Sig, PubKey) when byte_size(Msg) =:= 32,
                                       byte_size(Sig) =:= 64,
                                       byte_size(PubKey) =:= 32 ->
    case schnorr_verify_nif(Msg, Sig, PubKey) of
        true  -> true;
        false -> false;
        {error, _} -> false
    end.

%%% -------------------------------------------------------------------
%%% Cached signature verification
%%%
%%% Checks the sig cache before hitting the NIF. On cache hit we skip
%%% the expensive secp256k1 call entirely. On successful verify the
%%% result is added to the cache for future lookups.
%%% -------------------------------------------------------------------

-spec ecdsa_verify_cached(Msg :: binary(), Sig :: binary(),
                          PubKey :: binary()) -> boolean().
ecdsa_verify_cached(Msg, Sig, PubKey) when byte_size(Msg) =:= 32 ->
    case beamchain_sig_cache:lookup(Msg, PubKey, Sig) of
        true -> true;
        false ->
            case ecdsa_verify(Msg, Sig, PubKey) of
                true ->
                    beamchain_sig_cache:insert(Msg, PubKey, Sig),
                    true;
                false ->
                    false
            end
    end.

-spec schnorr_verify_cached(Msg :: binary(), Sig :: binary(),
                            PubKey :: binary()) -> boolean().
schnorr_verify_cached(Msg, Sig, PubKey) when byte_size(Msg) =:= 32,
                                              byte_size(Sig) =:= 64,
                                              byte_size(PubKey) =:= 32 ->
    case beamchain_sig_cache:lookup(Msg, PubKey, Sig) of
        true -> true;
        false ->
            case schnorr_verify(Msg, Sig, PubKey) of
                true ->
                    beamchain_sig_cache:insert(Msg, PubKey, Sig),
                    true;
                false ->
                    false
            end
    end.

%%% -------------------------------------------------------------------
%%% Signing
%%% -------------------------------------------------------------------

%% @doc ECDSA sign: returns DER-encoded signature with low-S enforced.
-spec ecdsa_sign(Msg :: binary(), SecKey :: binary()) ->
    {ok, binary()} | {error, term()}.
ecdsa_sign(Msg, SecKey) when byte_size(Msg) =:= 32,
                              byte_size(SecKey) =:= 32 ->
    case ecdsa_sign_nif(Msg, SecKey) of
        {ok, DerSig} ->
            %% enforce low-S (BIP 62)
            {ok, {R, S}} = decode_der_signature(DerSig),
            S2 = normalize_s(S),
            {ok, encode_der_signature(R, S2)};
        {error, _} = Err ->
            Err
    end.

%% @doc Schnorr sign (BIP 340): returns 64-byte signature.
-spec schnorr_sign(Msg :: binary(), SecKey :: binary(),
                   AuxRand :: binary()) ->
    {ok, binary()} | {error, term()}.
schnorr_sign(Msg, SecKey, AuxRand) when byte_size(Msg) =:= 32,
                                         byte_size(SecKey) =:= 32,
                                         byte_size(AuxRand) =:= 32 ->
    schnorr_sign_nif(Msg, SecKey, AuxRand).

%% @doc Add tweak to secret key: result = (seckey + tweak) mod n.
%% Used for BIP 32 child key derivation.
-spec seckey_tweak_add(SecKey :: binary(), Tweak :: binary()) ->
    {ok, binary()} | {error, term()}.
seckey_tweak_add(SecKey, Tweak) when byte_size(SecKey) =:= 32,
                                      byte_size(Tweak) =:= 32 ->
    seckey_tweak_add_nif(SecKey, Tweak).

%%% -------------------------------------------------------------------
%%% Recoverable ECDSA / Bitcoin signed messages
%%%
%%% Mirrors Bitcoin Core's CKey::SignCompact / CPubKey::RecoverCompact
%%% (see bitcoin-core/src/common/signmessage.cpp). The on-the-wire
%%% format used by signmessage / verifymessage is:
%%%
%%%   <header_byte:1><r:32><s:32>
%%%
%%% where header_byte = 27 + recid + (4 if compressed). Internally we
%%% use a 65-byte recoverable representation `<recid:8><r:32><s:32>`.
%%% -------------------------------------------------------------------

%% @doc Sign Msg32 with SecKey32 and return a 65-byte recoverable
%% signature `<<RecId:8, R:32, S:32>>`. S is normalised to low-S form
%% to match Bitcoin Core's BIP62 enforcement.
-spec ecdsa_sign_recoverable(Msg :: binary(), SecKey :: binary()) ->
    {ok, binary()} | {error, term()}.
ecdsa_sign_recoverable(Msg, SecKey) when byte_size(Msg) =:= 32,
                                          byte_size(SecKey) =:= 32 ->
    case ecdsa_sign_recoverable_nif(Msg, SecKey) of
        {ok, <<RecId:8, R:32/binary, S:32/binary>>} ->
            %% Normalise to low-S. If we flipped S we also flip the
            %% odd/even bit of RecId so recover() still finds the
            %% correct pubkey.
            case is_low_s(S) of
                true ->
                    {ok, <<RecId:8, R/binary, S/binary>>};
                false ->
                    SNorm = normalize_s(S),
                    NewRecId = RecId bxor 1,
                    {ok, <<NewRecId:8, R/binary, SNorm/binary>>}
            end;
        {error, _} = Err ->
            Err
    end.

%% @doc Recover the 33-byte compressed pubkey that produced Sig64 over
%% Msg32 with the given RecId (0..3). Returns {error, _} if recovery
%% fails (malformed signature / invalid recid).
-spec ecdsa_recover(Msg :: binary(), RecId :: 0..3, Sig :: binary()) ->
    {ok, binary()} | {error, term()}.
ecdsa_recover(Msg, RecId, Sig) when byte_size(Msg) =:= 32,
                                     is_integer(RecId), RecId >= 0,
                                     RecId =< 3,
                                     byte_size(Sig) =:= 64 ->
    ecdsa_recover_nif(Msg, RecId, Sig).

%% @doc Compute the Bitcoin signed message hash:
%%
%%   hash256( varstr("Bitcoin Signed Message:\n") ||
%%            varstr(Message) )
%%
%% where varstr is `<varint(len)><bytes>`. Matches MessageHash() in
%% Bitcoin Core (common/signmessage.cpp).
-spec message_hash(binary() | string()) -> binary().
message_hash(Message) when is_list(Message) ->
    message_hash(unicode:characters_to_binary(Message));
message_hash(Message) when is_binary(Message) ->
    Magic = <<"Bitcoin Signed Message:\n">>,
    Buf = <<(beamchain_serialize:encode_varint(byte_size(Magic)))/binary,
             Magic/binary,
             (beamchain_serialize:encode_varint(byte_size(Message)))/binary,
             Message/binary>>,
    hash256(Buf).

%% @doc Sign a UTF-8 message with SecKey32 and produce the base-64
%% encoded signature used by Bitcoin's signmessage RPC. Always emits
%% a 65-byte signature with the compressed-key header byte
%% (27 + recid + 4).
-spec sign_message(Message :: binary() | string(), SecKey :: binary()) ->
    {ok, binary()} | {error, term()}.
sign_message(Message, SecKey) when byte_size(SecKey) =:= 32 ->
    Hash = message_hash(Message),
    case ecdsa_sign_recoverable(Hash, SecKey) of
        {ok, <<RecId:8, RS:64/binary>>} ->
            Header = 27 + RecId + 4,
            Sig65 = <<Header:8, RS/binary>>,
            {ok, base64:encode(Sig65)};
        {error, _} = Err ->
            Err
    end.

%% @doc Verify a base64-encoded signed-message signature against the
%% expected 20-byte HASH160(pubkey). Returns one of:
%%   ok                       - signature valid for this pubkey hash
%%   {error, malformed_signature} - bad base64 / wrong length / bad recid
%%   {error, pubkey_not_recovered} - secp256k1 recovery failed
%%   {error, not_signed}      - recovered pubkey does not hash to PKH
-spec verify_message(SignatureB64 :: binary() | string(),
                     Message :: binary() | string(),
                     ExpectedPKH :: binary()) ->
    ok | {error, term()}.
verify_message(SignatureB64, Message, ExpectedPKH)
  when byte_size(ExpectedPKH) =:= 20 ->
    SigBin = case SignatureB64 of
        L when is_list(L) -> list_to_binary(L);
        B when is_binary(B) -> B
    end,
    try base64:decode(SigBin) of
        <<Header:8, RS:64/binary>> when Header >= 27, Header =< 42 ->
            RecId = (Header - 27) band 3,
            Compressed = (Header - 27) >= 4,
            Hash = message_hash(Message),
            case ecdsa_recover(Hash, RecId, RS) of
                {ok, CompressedPubKey} ->
                    PubKey = case Compressed of
                        true -> CompressedPubKey;
                        false ->
                            case pubkey_decompress(CompressedPubKey) of
                                {ok, U} -> U;
                                {error, _} -> CompressedPubKey
                            end
                    end,
                    case hash160(PubKey) of
                        ExpectedPKH -> ok;
                        _ -> {error, not_signed}
                    end;
                {error, _} ->
                    {error, pubkey_not_recovered}
            end;
        _ ->
            {error, malformed_signature}
    catch
        _:_ -> {error, malformed_signature}
    end.

%%% -------------------------------------------------------------------
%%% Public key operations
%%% -------------------------------------------------------------------

-spec pubkey_from_privkey(binary()) -> {ok, binary()} | {error, term()}.
pubkey_from_privkey(PrivKey) when byte_size(PrivKey) =:= 32 ->
    pubkey_create_nif(PrivKey).

-spec pubkey_tweak_add(binary(), binary()) -> {ok, binary()} | {error, term()}.
pubkey_tweak_add(PubKey, Tweak) when byte_size(Tweak) =:= 32 ->
    pubkey_tweak_add_nif(PubKey, Tweak).

-spec xonly_pubkey_tweak_add(binary(), binary()) ->
    {ok, binary(), integer()} | {error, term()}.
xonly_pubkey_tweak_add(PubKey, Tweak) when byte_size(PubKey) =:= 32,
                                            byte_size(Tweak) =:= 32 ->
    xonly_pubkey_tweak_add_nif(PubKey, Tweak).

-spec pubkey_compress(binary()) -> {ok, binary()} | {error, term()}.
pubkey_compress(PubKey) ->
    pubkey_compress_nif(PubKey).

-spec pubkey_decompress(binary()) -> {ok, binary()} | {error, term()}.
pubkey_decompress(PubKey) ->
    pubkey_decompress_nif(PubKey).

-spec pubkey_combine([binary()]) -> {ok, binary()} | {error, term()}.
pubkey_combine(PubKeys) when is_list(PubKeys), length(PubKeys) >= 2 ->
    pubkey_combine_nif(PubKeys).

%%% -------------------------------------------------------------------
%%% ElligatorSwift operations (BIP324)
%%% -------------------------------------------------------------------

%% @doc Create a 64-byte ElligatorSwift-encoded public key from a private key.
%% The encoding is indistinguishable from random bytes.
-spec ellswift_create(SecKey :: binary(), AuxRand :: binary()) ->
    {ok, binary()} | {error, term()}.
ellswift_create(SecKey, AuxRand) when byte_size(SecKey) =:= 32,
                                        byte_size(AuxRand) =:= 32 ->
    ellswift_create_nif(SecKey, AuxRand).

%% @doc Compute BIP324 ECDH shared secret from ElligatorSwift-encoded pubkeys.
%% EllA: 64-byte ElligatorSwift pubkey of party A (initiator)
%% EllB: 64-byte ElligatorSwift pubkey of party B (responder)
%% SecKey: 32-byte private key of this party
%% Party: 0 if we are party A (initiator), 1 if party B (responder)
-spec ellswift_xdh(EllA :: binary(), EllB :: binary(),
                    SecKey :: binary(), Party :: 0 | 1) ->
    {ok, binary()} | {error, term()}.
ellswift_xdh(EllA, EllB, SecKey, Party) when byte_size(EllA) =:= 64,
                                               byte_size(EllB) =:= 64,
                                               byte_size(SecKey) =:= 32,
                                               (Party =:= 0 orelse Party =:= 1) ->
    ellswift_xdh_nif(EllA, EllB, SecKey, Party).

%%% -------------------------------------------------------------------
%%% Hashing (NIF-accelerated with hardware intrinsics when available)
%%% -------------------------------------------------------------------

-spec sha256(binary()) -> binary().
sha256(Data) ->
    try
        sha256_nif(Data)
    catch
        error:nif_not_loaded ->
            %% Fallback to pure Erlang
            crypto:hash(sha256, Data)
    end.

-spec hash256(binary()) -> binary().
hash256(Data) ->
    try
        double_sha256_nif(Data)
    catch
        error:nif_not_loaded ->
            %% Fallback to pure Erlang
            crypto:hash(sha256, crypto:hash(sha256, Data))
    end.

-spec hash160(binary()) -> binary().
hash160(Data) ->
    crypto:hash(ripemd160, sha256(Data)).

-spec tagged_hash(Tag :: binary(), Data :: binary()) -> binary().
tagged_hash(Tag, Data) ->
    TagHash = get_tag_hash(Tag),
    sha256(<<TagHash/binary, TagHash/binary, Data/binary>>).

-spec hmac_sha512(Key :: binary(), Data :: binary()) -> binary().
hmac_sha512(Key, Data) ->
    crypto:mac(hmac, sha512, Key, Data).

%%% -------------------------------------------------------------------
%%% Hardware introspection
%%% -------------------------------------------------------------------

%% @doc Returns which SHA-256 implementation is active.
%% Returns {ok, Algorithm} where Algorithm is:
%%   sha_ni   - Intel SHA-NI hardware extensions
%%   arm_sha  - ARM SHA hardware extensions (Apple Silicon, etc.)
%%   generic  - Portable C implementation (or pure Erlang fallback)
-spec sha256_hardware_info() -> {ok, sha_ni | arm_sha | generic}.
sha256_hardware_info() ->
    try
        sha256_hardware_info_nif()
    catch
        error:nif_not_loaded ->
            %% NIF not loaded, using pure Erlang fallback
            {ok, generic}
    end.

%%% -------------------------------------------------------------------
%%% Batch verification (reduces NIF call overhead)
%%%
%%% When verifying multiple signatures (e.g., all inputs in a block),
%%% batch verification amortizes the NIF call overhead by processing
%%% multiple signatures in a single call to C.
%%% -------------------------------------------------------------------

%% @doc Verify multiple ECDSA signatures in a single NIF call.
%% Input: list of {MsgHash32, DerSig, PubKey} tuples.
%% Output: list of booleans in the same order.
-spec batch_ecdsa_verify([{binary(), binary(), binary()}]) -> [boolean()].
batch_ecdsa_verify([]) ->
    [];
batch_ecdsa_verify(Items) when is_list(Items) ->
    try
        batch_ecdsa_verify_nif(Items)
    catch
        error:nif_not_loaded ->
            %% Fallback to individual verification
            [ecdsa_verify(Msg, Sig, PubKey) || {Msg, Sig, PubKey} <- Items]
    end.

%% @doc Verify multiple Schnorr signatures in a single NIF call.
%% Input: list of {MsgHash32, Sig64, XOnlyPubKey32} tuples.
%% Output: list of booleans in the same order.
-spec batch_schnorr_verify([{binary(), binary(), binary()}]) -> [boolean()].
batch_schnorr_verify([]) ->
    [];
batch_schnorr_verify(Items) when is_list(Items) ->
    try
        batch_schnorr_verify_nif(Items)
    catch
        error:nif_not_loaded ->
            %% Fallback to individual verification
            [schnorr_verify(Msg, Sig, PubKey) || {Msg, Sig, PubKey} <- Items]
    end.

%%% -------------------------------------------------------------------
%%% Tag hash cache (persistent_term for fast lookups)
%%% -------------------------------------------------------------------

%% Pre-warm cache for all known BIP 340/341 tags at module load time
%% so the first call to tagged_hash doesn't pay the cache miss cost
init_tag_hashes() ->
    Tags = [<<"BIP0340/challenge">>, <<"BIP0340/aux">>, <<"BIP0340/nonce">>,
            <<"TapLeaf">>, <<"TapBranch">>, <<"TapTweak">>, <<"TapSighash">>],
    lists:foreach(fun(Tag) -> get_tag_hash(Tag) end, Tags).

get_tag_hash(Tag) ->
    case persistent_term:get({beamchain_tag_hash, Tag}, undefined) of
        undefined ->
            Hash = sha256(Tag),
            persistent_term:put({beamchain_tag_hash, Tag}, Hash),
            Hash;
        Hash ->
            Hash
    end.

%%% -------------------------------------------------------------------
%%% DER signature encoding/decoding
%%% -------------------------------------------------------------------

-spec decode_der_signature(binary()) ->
    {ok, {R :: binary(), S :: binary()}} | {error, term()}.
decode_der_signature(<<16#30, TotalLen:8, Body/binary>>)
  when byte_size(Body) =:= TotalLen ->
    case Body of
        <<16#02, RLen:8, RBytes:RLen/binary,
          16#02, SLen:8, SBytes:SLen/binary>> when
              RLen > 0, SLen > 0,
              TotalLen =:= RLen + SLen + 4 ->
            case validate_der_int(RBytes) andalso
                 validate_der_int(SBytes) of
                true ->
                    R = strip_sign_byte(RBytes),
                    S = strip_sign_byte(SBytes),
                    {ok, {R, S}};
                false ->
                    {error, non_canonical_der}
            end;
        _ ->
            {error, invalid_der_format}
    end;
decode_der_signature(_) ->
    {error, invalid_der_format}.

-spec encode_der_signature(R :: binary(), S :: binary()) -> binary().
encode_der_signature(R, S) ->
    REnc = encode_der_int(R),
    SEnc = encode_der_int(S),
    TotalLen = byte_size(REnc) + byte_size(SEnc),
    <<16#30, TotalLen:8, REnc/binary, SEnc/binary>>.

-spec check_strict_der(binary()) -> boolean().
check_strict_der(<<16#30, TotalLen:8, Body/binary>>)
  when byte_size(Body) =:= TotalLen ->
    case Body of
        <<16#02, RLen:8, RBytes:RLen/binary,
          16#02, SLen:8, SBytes:SLen/binary>> when
              RLen > 0, SLen > 0,
              TotalLen =:= RLen + SLen + 4 ->
            validate_der_int(RBytes) andalso
            validate_der_int(SBytes);
        _ ->
            false
    end;
check_strict_der(_) ->
    false.

-spec is_low_s(binary()) -> boolean().
is_low_s(S) ->
    SInt = binary:decode_unsigned(S, big),
    SInt > 0 andalso SInt =< ?SECP256K1_N_HALF.

-spec normalize_s(binary()) -> binary().
normalize_s(S) ->
    SInt = binary:decode_unsigned(S, big),
    case SInt =< ?SECP256K1_N_HALF of
        true  -> S;
        false ->
            NewS = ?SECP256K1_N - SInt,
            Len = byte_size(S),
            <<NewS:Len/unit:8-big>>
    end.

%%% -------------------------------------------------------------------
%%% Public key validation
%%% -------------------------------------------------------------------

-spec validate_pubkey(binary()) -> boolean().
validate_pubkey(<<16#02, _:32/binary>>) -> true;
validate_pubkey(<<16#03, _:32/binary>>) -> true;
validate_pubkey(<<16#04, _:64/binary>>) -> true;
validate_pubkey(_) -> false.

-spec is_compressed_pubkey(binary()) -> boolean().
is_compressed_pubkey(<<16#02, _:32/binary>>) -> true;
is_compressed_pubkey(<<16#03, _:32/binary>>) -> true;
is_compressed_pubkey(_) -> false.

%%% -------------------------------------------------------------------
%%% Lax DER signature decoding
%%%
%%% Matches Bitcoin Core's ecdsa_signature_parse_der_lax from pubkey.cpp.
%%% Tolerates non-canonical DER: excess padding, negative integers,
%%% incorrect compound length, etc. Returns the raw unsigned R/S values.
%%% -------------------------------------------------------------------

-spec decode_der_lax(binary()) ->
    {ok, {R :: binary(), S :: binary()}} | {error, term()}.
decode_der_lax(Sig) ->
    try decode_der_lax_impl(Sig)
    catch _:_ -> {error, invalid_lax_der}
    end.

decode_der_lax_impl(Sig) when byte_size(Sig) < 1 ->
    {error, too_short};
decode_der_lax_impl(<<16#30, Rest/binary>>) ->
    %% Read compound length (skip it, don't validate)
    {_CompoundLen, Rest2} = read_der_length(Rest),
    %% Read R integer
    case Rest2 of
        <<16#02, Rest3/binary>> ->
            {RLen, Rest4} = read_der_length(Rest3),
            case Rest4 of
                <<RBytes:RLen/binary, Rest5/binary>> ->
                    %% Read S integer
                    case Rest5 of
                        <<16#02, Rest6/binary>> ->
                            {SLen, Rest7} = read_der_length(Rest6),
                            case Rest7 of
                                <<SBytes:SLen/binary, _/binary>> ->
                                    R = lax_int_to_unsigned(RBytes),
                                    S = lax_int_to_unsigned(SBytes),
                                    case R =:= <<>> orelse S =:= <<>> of
                                        true -> {error, zero_rs};
                                        false -> {ok, {R, S}}
                                    end;
                                _ ->
                                    {error, s_truncated}
                            end;
                        _ ->
                            {error, missing_s_tag}
                    end;
                _ ->
                    {error, r_truncated}
            end;
        _ ->
            {error, missing_r_tag}
    end;
decode_der_lax_impl(_) ->
    {error, missing_sequence_tag}.

%% Read a DER length field (handles 1-byte and multi-byte forms)
read_der_length(<<>>) -> {0, <<>>};
read_der_length(<<Len, Rest/binary>>) when Len < 16#80 ->
    {Len, Rest};
read_der_length(<<16#81, Len, Rest/binary>>) ->
    {Len, Rest};
read_der_length(<<16#82, Len:16/big, Rest/binary>>) ->
    {Len, Rest};
read_der_length(<<_, Rest/binary>>) ->
    %% Fallback: treat as zero length
    {0, Rest}.

%% Convert a lax DER integer (possibly with padding/negative) to unsigned binary.
%% Strips leading zero bytes but preserves at least 1 byte if non-zero.
lax_int_to_unsigned(<<>>) -> <<>>;
lax_int_to_unsigned(Bytes) ->
    %% Strip all leading zero bytes
    Stripped = strip_leading_zeros(Bytes),
    case Stripped of
        <<>> ->
            %% All zeros
            <<>>;
        <<B, _/binary>> when B >= 16#80 ->
            %% If the value bytes had high bit set, the leading zero was the sign byte.
            %% For secp256k1 R/S, we just want the magnitude (unsigned).
            Stripped;
        _ ->
            Stripped
    end.

strip_leading_zeros(<<0, Rest/binary>>) when byte_size(Rest) > 0 ->
    strip_leading_zeros(Rest);
strip_leading_zeros(Bin) ->
    Bin.

%%% -------------------------------------------------------------------
%%% Internal helpers
%%% -------------------------------------------------------------------

%% Validate a DER-encoded integer:
%%  - must not be empty
%%  - first byte high bit set means negative → invalid for sigs
%%  - leading 0x00 only allowed when next byte has high bit set
validate_der_int(<<>>) ->
    false;
validate_der_int(<<B, _/binary>>) when B >= 16#80 ->
    false;  %% negative value
validate_der_int(<<0, B, _/binary>>) when B < 16#80 ->
    false;  %% unnecessary leading zero
validate_der_int(_) ->
    true.

%% Strip the DER sign byte (leading 0x00) if present
strip_sign_byte(<<0, Rest/binary>>) when byte_size(Rest) > 0 -> Rest;
strip_sign_byte(Bin) -> Bin.

%% Encode a positive integer as a DER integer element
encode_der_int(Bin) ->
    Padded = case Bin of
        <<B, _/binary>> when B >= 16#80 -> <<0, Bin/binary>>;
        _ -> Bin
    end,
    <<16#02, (byte_size(Padded)):8, Padded/binary>>.

%%% -------------------------------------------------------------------
%%% SipHash-2-4 (for BIP152 compact blocks)
%%%
%%% Based on the reference implementation from:
%%% https://github.com/veorq/SipHash
%%% SipHash-2-4 with 128-bit key and 64-bit output.
%%% -------------------------------------------------------------------

%% SipHash initialization constants
-define(SIP_C0, 16#736f6d6570736575).
-define(SIP_C1, 16#646f72616e646f6d).
-define(SIP_C2, 16#6c7967656e657261).
-define(SIP_C3, 16#7465646279746573).

%% @doc Compute SipHash-2-4 of arbitrary binary data with 128-bit key.
%% K0, K1 are the two 64-bit key halves (little-endian from the key).
-spec siphash(K0 :: non_neg_integer(), K1 :: non_neg_integer(),
              Data :: binary()) -> non_neg_integer().
siphash(K0, K1, Data) ->
    %% Initialize state
    V0 = ?SIP_C0 bxor K0,
    V1 = ?SIP_C1 bxor K1,
    V2 = ?SIP_C2 bxor K0,
    V3 = ?SIP_C3 bxor K1,
    %% Process full 8-byte blocks
    {V0a, V1a, V2a, V3a} = siphash_blocks(V0, V1, V2, V3, Data),
    %% Finalize with remaining bytes + length
    Len = byte_size(Data),
    siphash_finalize(V0a, V1a, V2a, V3a, Data, Len).

%% @doc SipHash-2-4 optimized for a 32-byte input (uint256).
%% This is the hot path for BIP152 short txid computation.
-spec siphash_uint256(K0 :: non_neg_integer(), K1 :: non_neg_integer(),
                      Data32 :: binary()) -> non_neg_integer().
siphash_uint256(K0, K1, <<D0:64/little, D1:64/little,
                          D2:64/little, D3:64/little>>) ->
    %% Initialize state
    V0 = ?SIP_C0 bxor K0,
    V1 = ?SIP_C1 bxor K1,
    V2 = ?SIP_C2 bxor K0,
    V3 = ?SIP_C3 bxor K1,

    %% Process D0
    V3a = V3 bxor D0,
    {V0b, V1b, V2b, V3b} = sipround(sipround({V0, V1, V2, V3a})),
    V0c = V0b bxor D0,

    %% Process D1
    V3c = V3b bxor D1,
    {V0d, V1d, V2d, V3d} = sipround(sipround({V0c, V1b, V2b, V3c})),
    V0e = V0d bxor D1,

    %% Process D2
    V3e = V3d bxor D2,
    {V0f, V1f, V2f, V3f} = sipround(sipround({V0e, V1d, V2d, V3e})),
    V0g = V0f bxor D2,

    %% Process D3
    V3g = V3f bxor D3,
    {V0h, V1h, V2h, V3h} = sipround(sipround({V0g, V1f, V2f, V3g})),
    V0i = V0h bxor D3,

    %% Final block: length byte (32 = 0x20) in high byte position
    %% For 32 bytes: B = 32 << 56 = 0x2000000000000000
    B = 32 bsl 56,
    V3i = V3h bxor B,
    {V0j, V1j, V2j, V3j} = sipround(sipround({V0i, V1h, V2h, V3i})),
    V0k = V0j bxor B,

    %% Finalization: 4 rounds
    V2k = V2j bxor 16#ff,
    {V0l, V1l, V2l, V3l} = sipround(sipround(sipround(sipround(
        {V0k, V1j, V2k, V3j})))),
    (V0l bxor V1l bxor V2l bxor V3l) band 16#ffffffffffffffff;
siphash_uint256(K0, K1, Data) when byte_size(Data) =:= 32 ->
    %% Fallback for non-aligned data
    siphash(K0, K1, Data).

%% Process full 8-byte blocks
siphash_blocks(V0, V1, V2, V3, <<M:64/little, Rest/binary>>) ->
    V3a = V3 bxor M,
    {V0b, V1b, V2b, V3b} = sipround(sipround({V0, V1, V2, V3a})),
    V0c = V0b bxor M,
    siphash_blocks(V0c, V1b, V2b, V3b, Rest);
siphash_blocks(V0, V1, V2, V3, _Remainder) ->
    {V0, V1, V2, V3}.

%% Finalize: pack remaining bytes with length in high byte
siphash_finalize(V0, V1, V2, V3, Data, Len) ->
    Offset = (Len div 8) * 8,
    Remaining = binary:part(Data, Offset, Len - Offset),
    B = pack_remaining(Remaining, Len),
    V3a = V3 bxor B,
    {V0b, V1b, V2b, V3b} = sipround(sipround({V0, V1, V2, V3a})),
    V0c = V0b bxor B,
    %% Finalization: XOR 0xff into v2, then 4 rounds
    V2c = V2b bxor 16#ff,
    {V0d, V1d, V2d, V3d} = sipround(sipround(sipround(sipround(
        {V0c, V1b, V2c, V3b})))),
    (V0d bxor V1d bxor V2d bxor V3d) band 16#ffffffffffffffff.

%% Pack remaining bytes (0-7) with length in high byte
pack_remaining(<<>>, Len) ->
    Len bsl 56;
pack_remaining(<<B0>>, Len) ->
    (Len bsl 56) bor B0;
pack_remaining(<<B0, B1>>, Len) ->
    (Len bsl 56) bor (B1 bsl 8) bor B0;
pack_remaining(<<B0, B1, B2>>, Len) ->
    (Len bsl 56) bor (B2 bsl 16) bor (B1 bsl 8) bor B0;
pack_remaining(<<B0, B1, B2, B3>>, Len) ->
    (Len bsl 56) bor (B3 bsl 24) bor (B2 bsl 16) bor (B1 bsl 8) bor B0;
pack_remaining(<<B0, B1, B2, B3, B4>>, Len) ->
    (Len bsl 56) bor (B4 bsl 32) bor (B3 bsl 24) bor (B2 bsl 16) bor
        (B1 bsl 8) bor B0;
pack_remaining(<<B0, B1, B2, B3, B4, B5>>, Len) ->
    (Len bsl 56) bor (B5 bsl 40) bor (B4 bsl 32) bor (B3 bsl 24) bor
        (B2 bsl 16) bor (B1 bsl 8) bor B0;
pack_remaining(<<B0, B1, B2, B3, B4, B5, B6>>, Len) ->
    (Len bsl 56) bor (B6 bsl 48) bor (B5 bsl 40) bor (B4 bsl 32) bor
        (B3 bsl 24) bor (B2 bsl 16) bor (B1 bsl 8) bor B0.

%% SipHash round function
sipround({V0, V1, V2, V3}) ->
    V0a = (V0 + V1) band 16#ffffffffffffffff,
    V1a = rotl64(V1, 13),
    V1b = V1a bxor V0a,
    V0b = rotl64(V0a, 32),
    V2a = (V2 + V3) band 16#ffffffffffffffff,
    V3a = rotl64(V3, 16),
    V3b = V3a bxor V2a,
    V0c = (V0b + V3b) band 16#ffffffffffffffff,
    V3c = rotl64(V3b, 21),
    V3d = V3c bxor V0c,
    V2b = (V2a + V1b) band 16#ffffffffffffffff,
    V1c = rotl64(V1b, 17),
    V1d = V1c bxor V2b,
    V2c = rotl64(V2b, 32),
    {V0c, V1d, V2c, V3d}.

%% 64-bit left rotate
rotl64(X, N) ->
    ((X bsl N) bor (X bsr (64 - N))) band 16#ffffffffffffffff.
