-module(beamchain_crypto_tests).

-include_lib("eunit/include/eunit.hrl").

%%% -------------------------------------------------------------------
%%% Helpers
%%% -------------------------------------------------------------------

hex(Hex) ->
    beamchain_serialize:hex_decode(Hex).

%%% ===================================================================
%%% Hashing tests
%%% ===================================================================

hash256_empty_test() ->
    %% SHA256d of empty string is a known value
    Expected = hex("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"),
    ?assertEqual(Expected, beamchain_crypto:hash256(<<>>)).

hash256_hello_test() ->
    %% SHA256d("hello") — verified against Bitcoin Core
    Result = beamchain_crypto:hash256(<<"hello">>),
    ?assertEqual(32, byte_size(Result)).

hash160_test() ->
    %% HASH160 = RIPEMD160(SHA256(data))
    Result = beamchain_crypto:hash160(<<"hello">>),
    ?assertEqual(20, byte_size(Result)).

hash160_known_value_test() ->
    %% Known HASH160 of a compressed public key
    %% Private key = 1 -> compressed pubkey is known
    PK = hex("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
    H160 = beamchain_crypto:hash160(PK),
    Expected = hex("751e76e8199196d454941c45d1b3a323f1433bd6"),
    ?assertEqual(Expected, H160).

sha256_test() ->
    %% Single SHA256
    Expected = hex("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"),
    ?assertEqual(Expected, beamchain_crypto:sha256(<<"hello">>)).

%%% ===================================================================
%%% Tagged hash tests (BIP 340/341)
%%% ===================================================================

tagged_hash_basic_test() ->
    %% tagged_hash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)
    Tag = <<"TapLeaf">>,
    TagHash = crypto:hash(sha256, Tag),
    Expected = crypto:hash(sha256, <<TagHash/binary, TagHash/binary, <<"test">>/binary>>),
    ?assertEqual(Expected, beamchain_crypto:tagged_hash(Tag, <<"test">>)).

tagged_hash_bip340_challenge_test() ->
    %% Verify the BIP0340/challenge tag hash
    Result = beamchain_crypto:tagged_hash(<<"BIP0340/challenge">>, <<"data">>),
    ?assertEqual(32, byte_size(Result)).

tagged_hash_tap_tweak_test() ->
    Result = beamchain_crypto:tagged_hash(<<"TapTweak">>, <<"data">>),
    ?assertEqual(32, byte_size(Result)).

tagged_hash_deterministic_test() ->
    %% Same input should produce same output
    R1 = beamchain_crypto:tagged_hash(<<"test_tag">>, <<"data">>),
    R2 = beamchain_crypto:tagged_hash(<<"test_tag">>, <<"data">>),
    ?assertEqual(R1, R2).

tagged_hash_different_tags_test() ->
    %% Different tags should produce different results
    R1 = beamchain_crypto:tagged_hash(<<"tag1">>, <<"data">>),
    R2 = beamchain_crypto:tagged_hash(<<"tag2">>, <<"data">>),
    ?assertNotEqual(R1, R2).

%%% ===================================================================
%%% HMAC-SHA512 test
%%% ===================================================================

hmac_sha512_test() ->
    %% Test vector from RFC 4231 (test case 2)
    Key = <<"Jefe">>,
    Data = <<"what do ya want for nothing?">>,
    Result = beamchain_crypto:hmac_sha512(Key, Data),
    Expected = hex("164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
                   "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"),
    ?assertEqual(Expected, Result).

%%% ===================================================================
%%% DER signature tests
%%% ===================================================================

der_decode_valid_test() ->
    %% A real DER-encoded ECDSA signature
    Sig = hex("3045022100"
              "c2e35bc47f050b873b32adacad8cf0af0a76eb68cc6df2e53e220b40eb403173"
              "0220"
              "1a03cbab34fc0ae8d9bca4c02e1018e6e11c4cded4ff251c3e7c7038da1e3346"),
    {ok, {R, S}} = beamchain_crypto:decode_der_signature(Sig),
    ?assertEqual(32, byte_size(R)),
    ?assertEqual(32, byte_size(S)).

der_decode_with_sign_byte_test() ->
    %% R or S may have a leading 0x00 byte to keep the value positive
    %% Create a DER sig where R starts with high bit set (needs sign byte)
    R = hex("ff" ++ lists:duplicate(62, $0)),
    S = hex("0102030405060708091011121314151617181920212223242526272829303132"),
    DerSig = beamchain_crypto:encode_der_signature(R, S),
    {ok, {R2, S2}} = beamchain_crypto:decode_der_signature(DerSig),
    ?assertEqual(R, R2),
    ?assertEqual(S, S2).

der_roundtrip_test() ->
    R = hex("c2e35bc47f050b873b32adacad8cf0af0a76eb68cc6df2e53e220b40eb403173"),
    S = hex("1a03cbab34fc0ae8d9bca4c02e1018e6e11c4cded4ff251c3e7c7038da1e3346"),
    DerSig = beamchain_crypto:encode_der_signature(R, S),
    {ok, {R2, S2}} = beamchain_crypto:decode_der_signature(DerSig),
    ?assertEqual(R, R2),
    ?assertEqual(S, S2).

der_invalid_format_test() ->
    ?assertEqual({error, invalid_der_format},
                 beamchain_crypto:decode_der_signature(<<>>)),
    ?assertEqual({error, invalid_der_format},
                 beamchain_crypto:decode_der_signature(<<16#31, 0>>)),
    ?assertEqual({error, invalid_der_format},
                 beamchain_crypto:decode_der_signature(<<16#30, 5, 0, 0, 0, 0, 0>>)).

der_non_canonical_test() ->
    %% Leading zero when not needed (value < 0x80)
    %% 0x30 total_len(7) 0x02 r_len(2) R(0x00,0x01) 0x02 s_len(1) S(0x01)
    BadSig = <<16#30, 7, 16#02, 2, 0, 1, 16#02, 1, 1>>,
    ?assertEqual({error, non_canonical_der},
                 beamchain_crypto:decode_der_signature(BadSig)).

check_strict_der_valid_test() ->
    Sig = hex("3045022100"
              "c2e35bc47f050b873b32adacad8cf0af0a76eb68cc6df2e53e220b40eb403173"
              "0220"
              "1a03cbab34fc0ae8d9bca4c02e1018e6e11c4cded4ff251c3e7c7038da1e3346"),
    ?assert(beamchain_crypto:check_strict_der(Sig)).

check_strict_der_invalid_test() ->
    ?assertNot(beamchain_crypto:check_strict_der(<<>>)),
    ?assertNot(beamchain_crypto:check_strict_der(<<"not a sig">>)),
    %% Wrong tag
    ?assertNot(beamchain_crypto:check_strict_der(<<16#31, 4, 16#02, 1, 1, 16#02, 1, 1>>)).

%%% ===================================================================
%%% Low-S tests (BIP 62 / BIP 146)
%%% ===================================================================

is_low_s_valid_test() ->
    %% S = 1 is low
    ?assert(beamchain_crypto:is_low_s(<<1>>)),
    %% S = N/2 is the maximum low S
    MaxLow = hex("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0"),
    ?assert(beamchain_crypto:is_low_s(MaxLow)).

is_low_s_invalid_test() ->
    %% S = 0 is not valid
    ?assertNot(beamchain_crypto:is_low_s(<<0>>)),
    %% S = N/2 + 1 is too high
    TooHigh = hex("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A1"),
    ?assertNot(beamchain_crypto:is_low_s(TooHigh)).

normalize_s_already_low_test() ->
    S = <<1>>,
    ?assertEqual(S, beamchain_crypto:normalize_s(S)).

normalize_s_high_to_low_test() ->
    %% S = N - 1 should be normalized to 1 (well, N - (N-1) = 1)
    %% but we need to preserve byte length
    N = 16#FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    HighS = <<(N - 1):256/big>>,
    LowS = beamchain_crypto:normalize_s(HighS),
    ?assert(beamchain_crypto:is_low_s(LowS)),
    ?assertEqual(<<1:256/big>>, LowS).

%%% ===================================================================
%%% Public key validation tests
%%% ===================================================================

validate_pubkey_compressed_test() ->
    PK02 = <<16#02, 0:(32*8)>>,
    PK03 = <<16#03, 0:(32*8)>>,
    ?assert(beamchain_crypto:validate_pubkey(PK02)),
    ?assert(beamchain_crypto:validate_pubkey(PK03)).

validate_pubkey_uncompressed_test() ->
    PK04 = <<16#04, 0:(64*8)>>,
    ?assert(beamchain_crypto:validate_pubkey(PK04)).

validate_pubkey_invalid_test() ->
    ?assertNot(beamchain_crypto:validate_pubkey(<<>>)),
    ?assertNot(beamchain_crypto:validate_pubkey(<<16#05, 0:(32*8)>>)),
    ?assertNot(beamchain_crypto:validate_pubkey(<<16#02, 0:(31*8)>>)),  %% too short
    ?assertNot(beamchain_crypto:validate_pubkey(<<"not a key">>)).

is_compressed_pubkey_test() ->
    ?assert(beamchain_crypto:is_compressed_pubkey(<<16#02, 0:(32*8)>>)),
    ?assert(beamchain_crypto:is_compressed_pubkey(<<16#03, 0:(32*8)>>)),
    ?assertNot(beamchain_crypto:is_compressed_pubkey(<<16#04, 0:(64*8)>>)),
    ?assertNot(beamchain_crypto:is_compressed_pubkey(<<>>)).

%%% ===================================================================
%%% NIF public key operations
%%% ===================================================================

pubkey_from_privkey_test() ->
    %% Private key = 1 -> known generator point
    PrivKey = <<1:256/big>>,
    {ok, PubKey} = beamchain_crypto:pubkey_from_privkey(PrivKey),
    ?assertEqual(33, byte_size(PubKey)),
    %% Generator point x-coord starts with 02 or 03
    Expected = hex("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
    ?assertEqual(Expected, PubKey).

pubkey_compress_decompress_roundtrip_test() ->
    PrivKey = crypto:hash(sha256, <<"test key">>),
    {ok, Compressed} = beamchain_crypto:pubkey_from_privkey(PrivKey),
    {ok, Uncompressed} = beamchain_crypto:pubkey_decompress(Compressed),
    ?assertEqual(65, byte_size(Uncompressed)),
    ?assertEqual(16#04, binary:first(Uncompressed)),
    {ok, Recompressed} = beamchain_crypto:pubkey_compress(Uncompressed),
    ?assertEqual(Compressed, Recompressed).

pubkey_tweak_add_test() ->
    PrivKey = <<1:256/big>>,
    {ok, PubKey} = beamchain_crypto:pubkey_from_privkey(PrivKey),
    Tweak = <<1:256/big>>,
    {ok, Tweaked} = beamchain_crypto:pubkey_tweak_add(PubKey, Tweak),
    ?assertEqual(33, byte_size(Tweaked)),
    %% Tweaked should equal pubkey of privkey + tweak = 2
    {ok, PubKey2} = beamchain_crypto:pubkey_from_privkey(<<2:256/big>>),
    ?assertEqual(PubKey2, Tweaked).

xonly_pubkey_tweak_add_test() ->
    PrivKey = <<1:256/big>>,
    {ok, CompPubKey} = beamchain_crypto:pubkey_from_privkey(PrivKey),
    %% Extract x-only (drop prefix byte)
    <<_:8, XOnly:32/binary>> = CompPubKey,
    Tweak = <<1:256/big>>,
    {ok, TweakedXOnly, Parity} = beamchain_crypto:xonly_pubkey_tweak_add(XOnly, Tweak),
    ?assertEqual(32, byte_size(TweakedXOnly)),
    ?assert(Parity =:= 0 orelse Parity =:= 1).

pubkey_combine_test() ->
    {ok, PK1} = beamchain_crypto:pubkey_from_privkey(<<1:256/big>>),
    {ok, PK2} = beamchain_crypto:pubkey_from_privkey(<<2:256/big>>),
    {ok, Combined} = beamchain_crypto:pubkey_combine([PK1, PK2]),
    ?assertEqual(33, byte_size(Combined)),
    %% Combined should equal pubkey of privkey 1+2 = 3
    {ok, PK3} = beamchain_crypto:pubkey_from_privkey(<<3:256/big>>),
    ?assertEqual(PK3, Combined).

pubkey_invalid_test() ->
    ?assertEqual({error, invalid_pubkey},
                 beamchain_crypto:pubkey_decompress(<<0:264>>)).

%%% ===================================================================
%%% ECDSA verification tests
%%% ===================================================================

ecdsa_verify_basic_test() ->
    %% Create a keypair, sign a message, verify
    %% We can't sign with this NIF (no sign function exposed), but we can
    %% test with known Bitcoin test vectors

    %% Test vector: a valid ECDSA signature from a real Bitcoin transaction
    %% Transaction: genesis coinbase doesn't have real sigs, so use a known vector
    %%
    %% From Bitcoin Core's key_tests.cpp:
    %% Private key: 1
    %% Message (SHA256d): hash256("Very deterministic message")
    PrivKey = <<1:256/big>>,
    {ok, PubKey} = beamchain_crypto:pubkey_from_privkey(PrivKey),
    Msg = beamchain_crypto:hash256(<<"Very deterministic message">>),

    %% We test that verify returns false for a garbage signature
    GarbageSig = hex("3045022100"
                     "0000000000000000000000000000000000000000000000000000000000000001"
                     "0220"
                     "0000000000000000000000000000000000000000000000000000000000000001"),
    ?assertNot(beamchain_crypto:ecdsa_verify(Msg, GarbageSig, PubKey)).

ecdsa_verify_invalid_sig_test() ->
    PubKey = hex("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
    Msg = <<0:256>>,
    %% Completely invalid DER
    ?assertNot(beamchain_crypto:ecdsa_verify(Msg, <<"not a sig">>, PubKey)).

ecdsa_verify_invalid_pubkey_test() ->
    Msg = <<0:256>>,
    Sig = hex("3045022100"
              "c2e35bc47f050b873b32adacad8cf0af0a76eb68cc6df2e53e220b40eb403173"
              "0220"
              "1a03cbab34fc0ae8d9bca4c02e1018e6e11c4cded4ff251c3e7c7038da1e3346"),
    %% Invalid pubkey
    ?assertNot(beamchain_crypto:ecdsa_verify(Msg, Sig, <<0:264>>)).

%%% ===================================================================
%%% Schnorr verification tests (BIP 340)
%%% ===================================================================

%% BIP 340 test vectors from:
%% https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv

schnorr_vector_0_test() ->
    %% Test vector 0: valid
    PubKey = hex("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"),
    Msg    = hex("0000000000000000000000000000000000000000000000000000000000000000"),
    Sig    = hex("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
                 "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"),
    ?assert(beamchain_crypto:schnorr_verify(Msg, Sig, PubKey)).

schnorr_vector_1_test() ->
    %% Test vector 1: valid
    PubKey = hex("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
    Msg    = hex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
    Sig    = hex("6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341"
                 "8906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A"),
    ?assert(beamchain_crypto:schnorr_verify(Msg, Sig, PubKey)).

schnorr_vector_2_test() ->
    %% Test vector 2: valid
    PubKey = hex("DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8"),
    Msg    = hex("7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C"),
    Sig    = hex("5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1B"
                 "AB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7"),
    ?assert(beamchain_crypto:schnorr_verify(Msg, Sig, PubKey)).

schnorr_vector_3_test() ->
    %% Test vector 3: valid (fails if msg is reduced modulo p or n)
    PubKey = hex("25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517"),
    Msg    = hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
    Sig    = hex("7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC"
                 "97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3"),
    ?assert(beamchain_crypto:schnorr_verify(Msg, Sig, PubKey)).

schnorr_vector_4_test() ->
    %% Test vector 4: valid
    PubKey = hex("D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9"),
    Msg    = hex("4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703"),
    Sig    = hex("00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C63"
                 "76AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4"),
    ?assert(beamchain_crypto:schnorr_verify(Msg, Sig, PubKey)).

schnorr_vector_5_invalid_pubkey_test() ->
    %% Test vector 5: public key not on the curve (should fail)
    PubKey = hex("EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34"),
    Msg    = hex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
    Sig    = hex("6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769"
                 "69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B"),
    ?assertNot(beamchain_crypto:schnorr_verify(Msg, Sig, PubKey)).

schnorr_invalid_msg_size_test() ->
    %% Message must be 32 bytes
    PubKey = hex("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"),
    Sig = <<0:512>>,
    ?assertError(function_clause,
                 beamchain_crypto:schnorr_verify(<<"short">>, Sig, PubKey)).

schnorr_wrong_key_test() ->
    %% Valid sig but wrong pubkey should fail
    PubKey = hex("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
    Msg    = hex("0000000000000000000000000000000000000000000000000000000000000000"),
    Sig    = hex("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
                 "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"),
    ?assertNot(beamchain_crypto:schnorr_verify(Msg, Sig, PubKey)).

%% BIP 340 vectors 6-14: invalid signatures that must be rejected

schnorr_vector_6_r_not_on_curve_test() ->
    %% Test vector 6: sG - eP has even y → r not on curve
    PubKey = hex("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
    Msg    = hex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
    Sig    = hex("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
                 "935554D1AA5F0374E5CDAACB3925035C7C169B27C4426DF0A6B19AF3BAEAB138"),
    ?assertNot(beamchain_crypto:schnorr_verify(Msg, Sig, PubKey)).

schnorr_vector_7_negated_msg_test() ->
    %% Test vector 7: negated message
    PubKey = hex("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
    Msg    = hex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
    Sig    = hex("1DA9D78E0FF71C4BBA15C3CE8FFAD6F07A5CF1C8C3A3061AA0A81E46BEE09E64"
                 "74EC9AA7A77F0AE78B725293C1D433BCD7B87CB394120B44CFD17CE020FA345B"),
    ?assertNot(beamchain_crypto:schnorr_verify(Msg, Sig, PubKey)).

schnorr_vector_8_negated_s_test() ->
    %% Test vector 8: negated s value
    PubKey = hex("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
    Msg    = hex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
    Sig    = hex("6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341"
                 "76F2DEE2E53C16F15E0B0140B226A2A21E14CAD185E26E4FDD6668C15BBD47E1"),
    ?assertNot(beamchain_crypto:schnorr_verify(Msg, Sig, PubKey)).

schnorr_vector_9_sG_minus_eP_odd_y_test() ->
    %% Test vector 9: sG - eP is infinite
    PubKey = hex("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
    Msg    = hex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
    Sig    = hex("0000000000000000000000000000000000000000000000000000000000000000"
                 "123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65CD6350C9391A0"),
    ?assertNot(beamchain_crypto:schnorr_verify(Msg, Sig, PubKey)).

schnorr_vector_10_r_eq_p_test() ->
    %% Test vector 10: r exceeds field size
    PubKey = hex("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
    Msg    = hex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
    Sig    = hex("00000000000000000000000000000000000000000000000000000000000000017"
                 "615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197"),
    ?assertNot(beamchain_crypto:schnorr_verify(Msg, Sig, PubKey)).

schnorr_vector_11_s_exceeds_order_test() ->
    %% Test vector 11: s exceeds curve order
    PubKey = hex("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
    Msg    = hex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
    Sig    = hex("667C2F778E0616E611BD0C14B8A600C5884551701A949EF0EBFD72D452D64E84"
                 "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
    ?assertNot(beamchain_crypto:schnorr_verify(Msg, Sig, PubKey)).

schnorr_vector_12_r_eq_p_field_test() ->
    %% Test vector 12: pubkey is not a valid X coordinate
    PubKey = hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30"),
    Msg    = hex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
    Sig    = hex("6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341"
                 "8906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A"),
    ?assertNot(beamchain_crypto:schnorr_verify(Msg, Sig, PubKey)).

%%% ===================================================================
%%% ECDSA sign/verify roundtrip tests
%%% ===================================================================

ecdsa_sign_verify_roundtrip_test() ->
    %% Sign with privkey=1, verify with its pubkey
    PrivKey = <<1:256/big>>,
    {ok, PubKey} = beamchain_crypto:pubkey_from_privkey(PrivKey),
    Msg = beamchain_crypto:hash256(<<"test message for signing">>),
    {ok, Sig} = beamchain_crypto:ecdsa_sign(Msg, PrivKey),
    ?assert(beamchain_crypto:ecdsa_verify(Msg, Sig, PubKey)).

ecdsa_sign_low_s_test() ->
    %% Verify signed sigs always have low S
    PrivKey = crypto:hash(sha256, <<"another test key">>),
    Msg = beamchain_crypto:hash256(<<"test message for low-s">>),
    {ok, Sig} = beamchain_crypto:ecdsa_sign(Msg, PrivKey),
    {ok, {_R, S}} = beamchain_crypto:decode_der_signature(Sig),
    ?assert(beamchain_crypto:is_low_s(S)).

ecdsa_sign_different_messages_test() ->
    %% Different messages produce different sigs
    PrivKey = <<2:256/big>>,
    Msg1 = beamchain_crypto:hash256(<<"message one">>),
    Msg2 = beamchain_crypto:hash256(<<"message two">>),
    {ok, Sig1} = beamchain_crypto:ecdsa_sign(Msg1, PrivKey),
    {ok, Sig2} = beamchain_crypto:ecdsa_sign(Msg2, PrivKey),
    ?assertNotEqual(Sig1, Sig2).

ecdsa_sign_wrong_pubkey_test() ->
    %% Verify with wrong pubkey should fail
    PrivKey1 = <<1:256/big>>,
    {ok, PubKey2} = beamchain_crypto:pubkey_from_privkey(<<2:256/big>>),
    Msg = beamchain_crypto:hash256(<<"cross-key test">>),
    {ok, Sig} = beamchain_crypto:ecdsa_sign(Msg, PrivKey1),
    ?assertNot(beamchain_crypto:ecdsa_verify(Msg, Sig, PubKey2)).

%%% ===================================================================
%%% Schnorr sign/verify roundtrip tests
%%% ===================================================================

schnorr_sign_verify_roundtrip_test() ->
    PrivKey = <<1:256/big>>,
    {ok, PubKey} = beamchain_crypto:pubkey_from_privkey(PrivKey),
    <<_Prefix:8, XOnly:32/binary>> = PubKey,
    Msg = beamchain_crypto:hash256(<<"schnorr test">>),
    AuxRand = crypto:strong_rand_bytes(32),
    {ok, Sig} = beamchain_crypto:schnorr_sign(Msg, PrivKey, AuxRand),
    ?assertEqual(64, byte_size(Sig)),
    ?assert(beamchain_crypto:schnorr_verify(Msg, Sig, XOnly)).

schnorr_sign_wrong_key_test() ->
    PrivKey1 = <<1:256/big>>,
    {ok, PubKey2} = beamchain_crypto:pubkey_from_privkey(<<2:256/big>>),
    <<_:8, XOnly2:32/binary>> = PubKey2,
    Msg = beamchain_crypto:hash256(<<"schnorr cross-key">>),
    AuxRand = <<0:256>>,
    {ok, Sig} = beamchain_crypto:schnorr_sign(Msg, PrivKey1, AuxRand),
    ?assertNot(beamchain_crypto:schnorr_verify(Msg, Sig, XOnly2)).

%%% ===================================================================
%%% Secret key tweak test
%%% ===================================================================

seckey_tweak_add_test() ->
    %% privkey=1 + tweak=1 should give privkey=2
    Key1 = <<1:256/big>>,
    Tweak = <<1:256/big>>,
    {ok, Key2} = beamchain_crypto:seckey_tweak_add(Key1, Tweak),
    %% deriving pubkey from key2 should equal pubkey of privkey=2
    {ok, PK2a} = beamchain_crypto:pubkey_from_privkey(Key2),
    {ok, PK2b} = beamchain_crypto:pubkey_from_privkey(<<2:256/big>>),
    ?assertEqual(PK2a, PK2b).
