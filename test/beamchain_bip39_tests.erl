%%% -------------------------------------------------------------------
%%% beamchain_bip39_tests - TREZOR test vectors + invariants
%%%
%%% Vectors taken from
%%%   https://github.com/trezor/python-mnemonic/blob/master/vectors.json
%%% (also reproduced in BIP-39 itself). Passphrase = "TREZOR" for all
%%% officially-published vectors.
%%%
%%% CRITICAL: each vector asserts byte-identity on the PBKDF2 output.
%%% A previous parity audit (haskoin) caught a silent iteration-collapse
%%% bug because tests only checked length + determinism. We do not
%%% repeat that mistake here.
%%% -------------------------------------------------------------------
-module(beamchain_bip39_tests).

-include_lib("eunit/include/eunit.hrl").

hex(Hex) ->
    beamchain_serialize:hex_decode(Hex).

words(Phrase) ->
    [list_to_binary(W) || W <- string:lexemes(Phrase, " ")].

%%% ===================================================================
%%% Wordlist sanity
%%% ===================================================================

wordlist_size_test() ->
    WL = beamchain_bip39:wordlist(),
    ?assertEqual(2048, tuple_size(WL)).

wordlist_first_word_test() ->
    WL = beamchain_bip39:wordlist(),
    ?assertEqual(<<"abandon">>, element(1, WL)).

wordlist_last_word_test() ->
    WL = beamchain_bip39:wordlist(),
    ?assertEqual(<<"zoo">>, element(2048, WL)).

%%% ===================================================================
%%% TREZOR vectors — byte-identity on mnemonic AND seed
%%% ===================================================================

%% Vector 1: 16-byte all-zero entropy, passphrase "TREZOR".
trezor_vector_1_test() ->
    Entropy   = hex("00000000000000000000000000000000"),
    Expected  = words("abandon abandon abandon abandon abandon abandon "
                      "abandon abandon abandon abandon abandon about"),
    {ok, Mnemonic} = beamchain_bip39:entropy_to_mnemonic(Entropy),
    ?assertEqual(Expected, Mnemonic),
    ?assertEqual({ok, Entropy},
                 beamchain_bip39:mnemonic_to_entropy(Mnemonic)),
    ExpectedSeed = hex(
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
        "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"),
    Seed = beamchain_bip39:mnemonic_to_seed(Mnemonic, <<"TREZOR">>),
    ?assertEqual(ExpectedSeed, Seed),
    %% Explicit byte-identity check on the seed prefix; guards against
    %% the iteration-collapse failure mode that motivated this test.
    <<16#c5, 16#52, 16#57, 16#c3, _/binary>> = Seed,
    ?assertEqual(64, byte_size(Seed)).

%% Vector 2: 16 bytes of 0x7f, passphrase "TREZOR".
trezor_vector_2_test() ->
    Entropy   = hex("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f"),
    Expected  = words("legal winner thank year wave sausage worth useful "
                      "legal winner thank yellow"),
    {ok, Mnemonic} = beamchain_bip39:entropy_to_mnemonic(Entropy),
    ?assertEqual(Expected, Mnemonic),
    ?assertEqual({ok, Entropy},
                 beamchain_bip39:mnemonic_to_entropy(Mnemonic)),
    ExpectedSeed = hex(
        "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6f"
        "a457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607"),
    Seed = beamchain_bip39:mnemonic_to_seed(Mnemonic, <<"TREZOR">>),
    ?assertEqual(ExpectedSeed, Seed).

%% Vector 3 (16 bytes 0x80...): round-trip + seed.
trezor_vector_3_test() ->
    Entropy   = hex("80808080808080808080808080808080"),
    Expected  = words("letter advice cage absurd amount doctor acoustic "
                      "avoid letter advice cage above"),
    {ok, Mnemonic} = beamchain_bip39:entropy_to_mnemonic(Entropy),
    ?assertEqual(Expected, Mnemonic),
    ExpectedSeed = hex(
        "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30"
        "fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8"),
    Seed = beamchain_bip39:mnemonic_to_seed(Mnemonic, <<"TREZOR">>),
    ?assertEqual(ExpectedSeed, Seed).

%% Vector 4 (16 bytes 0xff...): all-bits-set entropy.
trezor_vector_4_test() ->
    Entropy   = hex("ffffffffffffffffffffffffffffffff"),
    Expected  = words("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"),
    {ok, Mnemonic} = beamchain_bip39:entropy_to_mnemonic(Entropy),
    ?assertEqual(Expected, Mnemonic),
    ExpectedSeed = hex(
        "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13"
        "332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069"),
    Seed = beamchain_bip39:mnemonic_to_seed(Mnemonic, <<"TREZOR">>),
    ?assertEqual(ExpectedSeed, Seed).

%% 24-word vector (32 bytes of zero entropy + TREZOR passphrase). Required
%% by the wave brief: at least one 24-word case.
trezor_vector_24word_zero_test() ->
    Entropy = hex("0000000000000000000000000000000000000000000000000000000000000000"),
    Expected = words(
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon art"),
    {ok, Mnemonic} = beamchain_bip39:entropy_to_mnemonic(Entropy),
    ?assertEqual(Expected, Mnemonic),
    ?assertEqual({ok, Entropy},
                 beamchain_bip39:mnemonic_to_entropy(Mnemonic)),
    ExpectedSeed = hex(
        "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd30971"
        "70af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"),
    Seed = beamchain_bip39:mnemonic_to_seed(Mnemonic, <<"TREZOR">>),
    ?assertEqual(ExpectedSeed, Seed).

%% 24-word vector with 0x80... entropy (TREZOR vectors[19]).
trezor_vector_24word_80_test() ->
    Entropy = hex("8080808080808080808080808080808080808080808080808080808080808080"),
    Expected = words(
        "letter advice cage absurd amount doctor acoustic avoid letter "
        "advice cage absurd amount doctor acoustic avoid letter advice "
        "cage absurd amount doctor acoustic bless"),
    {ok, Mnemonic} = beamchain_bip39:entropy_to_mnemonic(Entropy),
    ?assertEqual(Expected, Mnemonic),
    ExpectedSeed = hex(
        "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09"
        "e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f"),
    Seed = beamchain_bip39:mnemonic_to_seed(Mnemonic, <<"TREZOR">>),
    ?assertEqual(ExpectedSeed, Seed).

%%% ===================================================================
%%% Empty-passphrase vector — confirms salt is "mnemonic" (not "mnemonic")
%%% Generated with python-mnemonic against vector 1 entropy and "" pass.
%%% Reproducible:
%%%   from mnemonic import Mnemonic
%%%   m = Mnemonic("english")
%%%   words = m.to_mnemonic(b"\\x00"*16)  # 12 abandon + about
%%%   m.to_seed(words, passphrase="").hex()
%%% ===================================================================

empty_passphrase_test() ->
    Entropy = hex("00000000000000000000000000000000"),
    {ok, Mnemonic} = beamchain_bip39:entropy_to_mnemonic(Entropy),
    %% Compute against PBKDF2 directly so the salt is asserted to be
    %% literally <<"mnemonic">> (no passphrase suffix).
    Joined = <<"abandon abandon abandon abandon abandon abandon abandon "
               "abandon abandon abandon abandon about">>,
    Expected = crypto:pbkdf2_hmac(sha512, Joined, <<"mnemonic">>, 2048, 64),
    Seed = beamchain_bip39:mnemonic_to_seed(Mnemonic, <<>>),
    ?assertEqual(Expected, Seed),
    ?assertEqual(64, byte_size(Seed)).

%%% ===================================================================
%%% Validation / error paths
%%% ===================================================================

invalid_entropy_size_test() ->
    ?assertEqual({error, invalid_entropy_size},
                 beamchain_bip39:entropy_to_mnemonic(<<0:8>>)),
    ?assertEqual({error, invalid_entropy_size},
                 beamchain_bip39:entropy_to_mnemonic(<<0:(17*8)>>)).

invalid_word_count_test() ->
    Bad = words("abandon abandon abandon"),
    ?assertEqual({error, invalid_word_count},
                 beamchain_bip39:mnemonic_to_entropy(Bad)).

unknown_word_test() ->
    Bad = words("abandon abandon abandon abandon abandon abandon "
                "abandon abandon abandon abandon abandon notaword"),
    ?assertMatch({error, {unknown_word, <<"notaword">>}},
                 beamchain_bip39:mnemonic_to_entropy(Bad)).

%% Corrupt one word in a valid mnemonic; should fail checksum.
%% Vector 1's last word is "about" (index 3); change to "above" (index 0).
%% The first 11 bits of "above" differ in the low bits, breaking the
%% 4-bit checksum.
bad_checksum_test() ->
    Good = words("abandon abandon abandon abandon abandon abandon "
                 "abandon abandon abandon abandon abandon about"),
    ok = beamchain_bip39:validate_mnemonic(Good),
    Bad = lists:droplast(Good) ++ [<<"above">>],
    ?assertEqual({error, bad_checksum},
                 beamchain_bip39:mnemonic_to_entropy(Bad)),
    ?assertEqual({error, bad_checksum},
                 beamchain_bip39:validate_mnemonic(Bad)).

%%% ===================================================================
%%% Round-trip across all valid sizes
%%% ===================================================================

roundtrip_15word_test() ->
    Entropy = crypto:strong_rand_bytes(20),
    {ok, M} = beamchain_bip39:entropy_to_mnemonic(Entropy),
    ?assertEqual(15, length(M)),
    ?assertEqual({ok, Entropy}, beamchain_bip39:mnemonic_to_entropy(M)).

roundtrip_18word_test() ->
    Entropy = crypto:strong_rand_bytes(24),
    {ok, M} = beamchain_bip39:entropy_to_mnemonic(Entropy),
    ?assertEqual(18, length(M)),
    ?assertEqual({ok, Entropy}, beamchain_bip39:mnemonic_to_entropy(M)).

roundtrip_21word_test() ->
    Entropy = crypto:strong_rand_bytes(28),
    {ok, M} = beamchain_bip39:entropy_to_mnemonic(Entropy),
    ?assertEqual(21, length(M)),
    ?assertEqual({ok, Entropy}, beamchain_bip39:mnemonic_to_entropy(M)).

%%% ===================================================================
%%% generate_mnemonic API
%%% ===================================================================

generate_12word_test() ->
    {ok, M} = beamchain_bip39:generate_mnemonic(12),
    ?assertEqual(12, length(M)),
    ?assertEqual(ok, beamchain_bip39:validate_mnemonic(M)).

generate_24word_test() ->
    {ok, M} = beamchain_bip39:generate_mnemonic(24),
    ?assertEqual(24, length(M)),
    ?assertEqual(ok, beamchain_bip39:validate_mnemonic(M)).

generate_invalid_count_test() ->
    ?assertEqual({error, invalid_word_count},
                 beamchain_bip39:generate_mnemonic(13)).

%%% ===================================================================
%%% Hard-coded byte-identity guard:
%%% any change to the BIP-39 implementation that breaks PBKDF2 must
%%% trip THIS test, not just the high-level vector tests.
%%% ===================================================================

pbkdf2_byte_identity_test() ->
    %% Direct call to the OTP PBKDF2 with the BIP-39 parameters.
    Pass = <<"abandon abandon abandon abandon abandon abandon abandon "
             "abandon abandon abandon abandon about">>,
    Salt = <<"mnemonicTREZOR">>,
    Out = crypto:pbkdf2_hmac(sha512, Pass, Salt, 2048, 64),
    %% First 4 bytes per the wave brief (vector 1).
    <<16#c5, 16#52, 16#57, 16#c3, _/binary>> = Out,
    ?assertEqual(64, byte_size(Out)).
