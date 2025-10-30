-module(beamchain_crypto).

%% Signature verification (NIF-backed)
-export([ecdsa_verify/3, schnorr_verify/3]).

%% Public key operations (NIF-backed)
-export([pubkey_from_privkey/1, pubkey_tweak_add/2,
         pubkey_compress/1, pubkey_decompress/1,
         pubkey_combine/1, xonly_pubkey_tweak_add/2]).

%% Hashing
-export([sha256/1, hash256/1, hash160/1,
         tagged_hash/2, hmac_sha512/2]).

%% DER signature handling
-export([decode_der_signature/1, encode_der_signature/2,
         check_strict_der/1, is_low_s/1, normalize_s/1]).

%% Public key validation
-export([validate_pubkey/1, is_compressed_pubkey/1]).

-on_load(init/0).

%% secp256k1 curve constants
-define(SECP256K1_N,
    16#FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141).
-define(SECP256K1_N_HALF,
    16#7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0).

%%% -------------------------------------------------------------------
%%% NIF loading
%%% -------------------------------------------------------------------

init() ->
    SoName = filename:join(priv_dir(), "beamchain_crypto_nif"),
    Ret = erlang:load_nif(SoName, 0),
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
%%% Hashing
%%% -------------------------------------------------------------------

-spec sha256(binary()) -> binary().
sha256(Data) ->
    crypto:hash(sha256, Data).

-spec hash256(binary()) -> binary().
hash256(Data) ->
    crypto:hash(sha256, crypto:hash(sha256, Data)).

-spec hash160(binary()) -> binary().
hash160(Data) ->
    crypto:hash(ripemd160, crypto:hash(sha256, Data)).

-spec tagged_hash(Tag :: binary(), Data :: binary()) -> binary().
tagged_hash(Tag, Data) ->
    TagHash = get_tag_hash(Tag),
    crypto:hash(sha256, <<TagHash/binary, TagHash/binary, Data/binary>>).

-spec hmac_sha512(Key :: binary(), Data :: binary()) -> binary().
hmac_sha512(Key, Data) ->
    crypto:mac(hmac, sha512, Key, Data).

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
            Hash = crypto:hash(sha256, Tag),
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
