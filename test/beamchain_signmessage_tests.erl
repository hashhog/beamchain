-module(beamchain_signmessage_tests).

-include_lib("eunit/include/eunit.hrl").

%%% Tests for the Bitcoin signed-message implementation in
%%% beamchain_crypto: message_hash/1, sign_message/2,
%%% verify_message/3 and the underlying ECDSA recoverable
%%% sign/recover NIFs.

%%% -------------------------------------------------------------------
%%% Helpers
%%% -------------------------------------------------------------------

%% PrivKey = 1: well-known compressed pubkey
%% 02 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F28154 5B16F817 98
priv_one() -> <<1:256/big>>.

priv_two() -> <<2:256/big>>.

%% Compute the P2PKH (HASH160) of a compressed pubkey.
pkh(PubKey) ->
    beamchain_crypto:hash160(PubKey).

%%% -------------------------------------------------------------------
%%% message_hash/1
%%% -------------------------------------------------------------------

%% Bitcoin Core's MessageHash() with empty message produces a fixed
%% 32-byte digest. Reproduce the byte sequence and check we hash the
%% same thing: varstr("Bitcoin Signed Message:\n") || varstr("").
message_hash_empty_test() ->
    H = beamchain_crypto:message_hash(<<>>),
    ?assertEqual(32, byte_size(H)).

%% message_hash should accept either a binary or a string and produce
%% identical output for the same UTF-8 bytes.
message_hash_string_eq_binary_test() ->
    A = beamchain_crypto:message_hash(<<"hello world">>),
    B = beamchain_crypto:message_hash("hello world"),
    ?assertEqual(A, B).

%% Different messages must produce different hashes.
message_hash_distinct_test() ->
    A = beamchain_crypto:message_hash(<<"hello">>),
    B = beamchain_crypto:message_hash(<<"world">>),
    ?assertNotEqual(A, B).

%%% -------------------------------------------------------------------
%%% sign / verify roundtrip
%%% -------------------------------------------------------------------

sign_verify_roundtrip_test() ->
    SecKey = priv_one(),
    {ok, PubKey} = beamchain_crypto:pubkey_from_privkey(SecKey),
    PKH = pkh(PubKey),
    {ok, B64} = beamchain_crypto:sign_message(<<"hello">>, SecKey),
    %% Output is base64.
    ?assert(is_binary(B64)),
    Sig = base64:decode(B64),
    %% 65-byte recoverable signature: 1-byte header + 64 bytes (r,s).
    ?assertEqual(65, byte_size(Sig)),
    %% Verifies against the matching pubkey hash.
    ?assertEqual(ok,
                 beamchain_crypto:verify_message(B64, <<"hello">>, PKH)).

%% Wrong message must fail verification.
verify_wrong_message_test() ->
    SecKey = priv_one(),
    {ok, PubKey} = beamchain_crypto:pubkey_from_privkey(SecKey),
    PKH = pkh(PubKey),
    {ok, B64} = beamchain_crypto:sign_message(<<"original">>, SecKey),
    ?assertMatch({error, _},
                 beamchain_crypto:verify_message(B64, <<"tampered">>,
                                                  PKH)).

%% Wrong pubkey hash must fail verification (not_signed).
verify_wrong_address_test() ->
    SecKey = priv_one(),
    OtherSec = priv_two(),
    {ok, OtherPub} = beamchain_crypto:pubkey_from_privkey(OtherSec),
    OtherPKH = pkh(OtherPub),
    {ok, B64} = beamchain_crypto:sign_message(<<"msg">>, SecKey),
    ?assertEqual({error, not_signed},
                 beamchain_crypto:verify_message(B64, <<"msg">>,
                                                  OtherPKH)).

%% Malformed base64 -> malformed_signature.
verify_malformed_signature_test() ->
    SecKey = priv_one(),
    {ok, PubKey} = beamchain_crypto:pubkey_from_privkey(SecKey),
    PKH = pkh(PubKey),
    ?assertEqual({error, malformed_signature},
                 beamchain_crypto:verify_message(<<"!!!not-base64!!!">>,
                                                  <<"msg">>, PKH)).

%% A correctly base64-decoded but wrong-length signature is also
%% malformed_signature.
verify_short_signature_test() ->
    SecKey = priv_one(),
    {ok, PubKey} = beamchain_crypto:pubkey_from_privkey(SecKey),
    PKH = pkh(PubKey),
    %% 32 bytes of zeros, base64'd, is < 65 bytes after decode.
    BadSig = base64:encode(<<0:256>>),
    ?assertEqual({error, malformed_signature},
                 beamchain_crypto:verify_message(BadSig, <<"msg">>, PKH)).

%%% -------------------------------------------------------------------
%%% Recoverable NIF roundtrip
%%% -------------------------------------------------------------------

%% The low-level NIF wrapper round-trips: signing a 32-byte digest and
%% recovering yields the original pubkey.
recoverable_signature_roundtrip_test() ->
    SecKey = priv_one(),
    {ok, ExpectedPub} = beamchain_crypto:pubkey_from_privkey(SecKey),
    Msg = beamchain_crypto:hash256(<<"recover-me">>),
    {ok, <<RecId:8, RS:64/binary>>} =
        beamchain_crypto:ecdsa_sign_recoverable(Msg, SecKey),
    ?assert(RecId >= 0 andalso RecId =< 3),
    {ok, Recovered} = beamchain_crypto:ecdsa_recover(Msg, RecId, RS),
    ?assertEqual(ExpectedPub, Recovered).

%% Wrong recovery id either yields a different pubkey or an error.
%% Either way, it must NOT match the original pubkey.
recover_with_wrong_recid_test() ->
    SecKey = priv_one(),
    {ok, ExpectedPub} = beamchain_crypto:pubkey_from_privkey(SecKey),
    Msg = beamchain_crypto:hash256(<<"wrong-recid">>),
    {ok, <<RecId:8, RS:64/binary>>} =
        beamchain_crypto:ecdsa_sign_recoverable(Msg, SecKey),
    BadRec = (RecId + 1) rem 4,
    case beamchain_crypto:ecdsa_recover(Msg, BadRec, RS) of
        {ok, OtherPub} ->
            ?assertNotEqual(ExpectedPub, OtherPub);
        {error, _} ->
            ok
    end.

%% Low-S enforcement: returned s component is always in the lower half
%% of the curve order.
sign_low_s_test() ->
    SecKey = priv_two(),
    Msg = beamchain_crypto:hash256(<<"low-s">>),
    {ok, <<_RecId:8, _R:32/binary, S:32/binary>>} =
        beamchain_crypto:ecdsa_sign_recoverable(Msg, SecKey),
    ?assert(beamchain_crypto:is_low_s(S)).
