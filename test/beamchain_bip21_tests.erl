-module(beamchain_bip21_tests).
-include_lib("eunit/include/eunit.hrl").
-include("beamchain_bip21.hrl").

%%% -------------------------------------------------------------------
%%% Tests for BIP-21 URI parser (beamchain_bip21).
%%%
%%% Test taxonomy:
%%%
%%%   1. spec vectors            — exact strings from the BIP-21 doc
%%%   2. scheme handling         — case-insensitive scheme, missing scheme
%%%   3. percent decoding        — %20, %26, malformed, "+" stays "+"
%%%   4. param-classification    — amount/label/message/lightning/pj/pjos
%%%   5. req- rejection          — unknown req-X causes URI rejection
%%%   6. unknown non-req         — passed through in extras
%%%   7. duplicate params        — second occurrence rejected
%%%   8. amount edge cases       — too many fractional digits, neg, sci
%%%   9. case-insensitive keys   — "AMOUNT=1.0" parses same as "amount=1.0"
%%%
%%% Network handling: we use `any` for vector tests to avoid coupling
%%% the parser tests to address-codec correctness. A handful of tests
%%% pass `mainnet` to confirm the address validator wires in correctly.
%%% -------------------------------------------------------------------

%%% ===================================================================
%%% 1. Spec vectors — straight from BIP-21
%%% ===================================================================

%% Note: the spec uses example addresses that we accept under `any`.
%% These tests exist to assert the URI-level decode, not the
%% base58/bech32 layer (covered by beamchain_address_tests).

bip21_vector_just_address_test() ->
    Input = <<"bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W">>,
    {ok, U} = beamchain_bip21:parse(Input, any),
    ?assertEqual(<<"175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W">>, U#bip21_uri.address),
    ?assertEqual(undefined, U#bip21_uri.amount),
    ?assertEqual([], U#bip21_uri.extras).

bip21_vector_with_label_test() ->
    Input = <<"bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?"
              "label=Luke-Jr">>,
    {ok, U} = beamchain_bip21:parse(Input, any),
    ?assertEqual(<<"Luke-Jr">>, U#bip21_uri.label).

bip21_vector_amount_and_label_test() ->
    Input = <<"bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"
              "?amount=20.3&label=Luke-Jr">>,
    {ok, U} = beamchain_bip21:parse(Input, any),
    %% 20.3 BTC = 20.3 * 1e8 = 2030000000 sats
    ?assertEqual(2030000000, U#bip21_uri.amount),
    ?assertEqual(<<"Luke-Jr">>, U#bip21_uri.label).

bip21_vector_message_test() ->
    %% From spec: "Donation for project xyz"
    Input = <<"bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?"
              "amount=50&label=Luke-Jr&"
              "message=Donation%20for%20project%20xyz">>,
    {ok, U} = beamchain_bip21:parse(Input, any),
    ?assertEqual(5000000000, U#bip21_uri.amount),
    ?assertEqual(<<"Luke-Jr">>, U#bip21_uri.label),
    ?assertEqual(<<"Donation for project xyz">>, U#bip21_uri.message).

bip21_vector_req_unsupported_test() ->
    %% From spec: req-somethingyoudontunderstand MUST cause rejection.
    Input = <<"bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?"
              "amount=50&"
              "req-somethingyoudontunderstand=50&"
              "req-somethingelseyoudontget=999">>,
    Got = beamchain_bip21:parse(Input, any),
    ?assertMatch({error, {unsupported_required_param,
                          <<"req-somethingyoudontunderstand">>}}, Got).

bip21_vector_unknown_param_ignored_test() ->
    %% From spec: "somethingyoudontunderstand=50" — non-req param SHOULD
    %% be ignored (we retain in extras for diagnostics).
    Input = <<"bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?"
              "somethingyoudontunderstand=50&"
              "somethingelseyoudontget=999">>,
    {ok, U} = beamchain_bip21:parse(Input, any),
    ?assertEqual([{<<"somethingyoudontunderstand">>, <<"50">>},
                  {<<"somethingelseyoudontget">>, <<"999">>}],
                 U#bip21_uri.extras).

%%% ===================================================================
%%% 2. Scheme handling
%%% ===================================================================

scheme_lowercase_test() ->
    {ok, _} = beamchain_bip21:parse(
                <<"bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa">>, any).

scheme_uppercase_test() ->
    %% RFC 3986 §3.1: scheme is case-insensitive.
    {ok, U} = beamchain_bip21:parse(
                <<"BITCOIN:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa">>, any),
    ?assertEqual(<<"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa">>,
                 U#bip21_uri.address).

scheme_mixed_case_test() ->
    {ok, _} = beamchain_bip21:parse(
                <<"Bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W">>, any).

scheme_missing_test() ->
    ?assertMatch({error, not_bitcoin_uri},
                 beamchain_bip21:parse(<<"175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W">>,
                                        any)).

scheme_wrong_test() ->
    ?assertMatch({error, not_bitcoin_uri},
                 beamchain_bip21:parse(<<"litecoin:LZ...">>, any)).

scheme_too_short_test() ->
    ?assertMatch({error, not_bitcoin_uri},
                 beamchain_bip21:parse(<<"bit">>, any)).

scheme_empty_test() ->
    ?assertMatch({error, not_bitcoin_uri},
                 beamchain_bip21:parse(<<>>, any)).

empty_address_test() ->
    ?assertMatch({error, empty_address},
                 beamchain_bip21:parse(<<"bitcoin:">>, any)).

non_binary_input_test() ->
    ?assertMatch({error, not_binary},
                 beamchain_bip21:parse("bitcoin:foo", any)).

%%% ===================================================================
%%% 3. Percent decoding
%%% ===================================================================

percent_decode_space_test() ->
    {ok, U} = beamchain_bip21:parse(
                <<"bitcoin:addr?label=hello%20world">>, any),
    ?assertEqual(<<"hello world">>, U#bip21_uri.label).

percent_decode_ampersand_test() ->
    %% %26 = '&' — must NOT split the value.
    {ok, U} = beamchain_bip21:parse(
                <<"bitcoin:addr?label=A%26B&amount=1">>, any),
    ?assertEqual(<<"A&B">>, U#bip21_uri.label),
    ?assertEqual(100000000, U#bip21_uri.amount).

percent_decode_equals_test() ->
    {ok, U} = beamchain_bip21:parse(
                <<"bitcoin:addr?label=key%3Dval">>, any),
    ?assertEqual(<<"key=val">>, U#bip21_uri.label).

percent_decode_utf8_test() ->
    %% "Caf é" — é is U+00E9 encoded as %C3%A9 in UTF-8.
    {ok, U} = beamchain_bip21:parse(
                <<"bitcoin:addr?label=Caf%C3%A9">>, any),
    ?assertEqual(<<"Caf", 16#c3, 16#a9>>, U#bip21_uri.label).

percent_decode_plus_is_literal_test() ->
    %% BIP-21 is RFC 3986 generic URI, NOT form-encoded.
    %% "+" stays "+"; it is NOT decoded to space.
    {ok, U} = beamchain_bip21:parse(
                <<"bitcoin:addr?label=a+b">>, any),
    ?assertEqual(<<"a+b">>, U#bip21_uri.label).

percent_decode_uppercase_hex_test() ->
    {ok, U} = beamchain_bip21:parse(
                <<"bitcoin:addr?label=%2Ftest">>, any),
    ?assertEqual(<<"/test">>, U#bip21_uri.label).

percent_decode_lowercase_hex_test() ->
    {ok, U} = beamchain_bip21:parse(
                <<"bitcoin:addr?label=%2ftest">>, any),
    ?assertEqual(<<"/test">>, U#bip21_uri.label).

percent_decode_truncated_test() ->
    ?assertMatch({error, truncated_percent_escape},
                 beamchain_bip21:parse(<<"bitcoin:addr?label=foo%2">>, any)).

percent_decode_truncated_one_test() ->
    ?assertMatch({error, truncated_percent_escape},
                 beamchain_bip21:parse(<<"bitcoin:addr?label=foo%">>, any)).

percent_decode_bad_hex_test() ->
    ?assertMatch({error, {bad_percent_escape, _}},
                 beamchain_bip21:parse(<<"bitcoin:addr?label=%ZZ">>, any)).

percent_decode_in_key_test() ->
    %% Keys can be percent-encoded too. "%6C%61%62%65%6C" = "label".
    {ok, U} = beamchain_bip21:parse(
                <<"bitcoin:addr?%6C%61%62%65%6C=ok">>, any),
    ?assertEqual(<<"ok">>, U#bip21_uri.label).

%%% ===================================================================
%%% 4. Parameter classification
%%% ===================================================================

amount_int_test() ->
    {ok, U} = beamchain_bip21:parse(<<"bitcoin:addr?amount=1">>, any),
    ?assertEqual(100000000, U#bip21_uri.amount).

amount_decimal_test() ->
    {ok, U} = beamchain_bip21:parse(<<"bitcoin:addr?amount=0.5">>, any),
    ?assertEqual(50000000, U#bip21_uri.amount).

amount_one_sat_test() ->
    %% 0.00000001 BTC = 1 sat — the smallest representable amount.
    {ok, U} = beamchain_bip21:parse(
                <<"bitcoin:addr?amount=0.00000001">>, any),
    ?assertEqual(1, U#bip21_uri.amount).

amount_zero_test() ->
    {ok, U} = beamchain_bip21:parse(<<"bitcoin:addr?amount=0">>, any),
    ?assertEqual(0, U#bip21_uri.amount).

amount_no_int_part_test() ->
    {ok, U} = beamchain_bip21:parse(<<"bitcoin:addr?amount=.5">>, any),
    ?assertEqual(50000000, U#bip21_uri.amount).

amount_no_frac_part_test() ->
    {ok, U} = beamchain_bip21:parse(<<"bitcoin:addr?amount=5.">>, any),
    ?assertEqual(500000000, U#bip21_uri.amount).

label_value_test() ->
    {ok, U} = beamchain_bip21:parse(<<"bitcoin:addr?label=alice">>, any),
    ?assertEqual(<<"alice">>, U#bip21_uri.label).

label_empty_value_test() ->
    {ok, U} = beamchain_bip21:parse(<<"bitcoin:addr?label=">>, any),
    ?assertEqual(<<>>, U#bip21_uri.label).

message_value_test() ->
    {ok, U} = beamchain_bip21:parse(<<"bitcoin:addr?message=hi">>, any),
    ?assertEqual(<<"hi">>, U#bip21_uri.message).

lightning_value_test() ->
    {ok, U} = beamchain_bip21:parse(
                <<"bitcoin:addr?lightning=lnbc1pvjluezpp5">>, any),
    ?assertEqual(<<"lnbc1pvjluezpp5">>, U#bip21_uri.lightning).

pj_value_test() ->
    %% BIP-78 PayJoin endpoint (W119 G28).
    {ok, U} = beamchain_bip21:parse(
                <<"bitcoin:addr?pj=https://example.com/pj">>, any),
    ?assertEqual(<<"https://example.com/pj">>, U#bip21_uri.pj).

pj_percent_encoded_test() ->
    %% pj is typically percent-encoded since URLs contain reserved chars.
    {ok, U} = beamchain_bip21:parse(
                <<"bitcoin:addr?pj=https%3A%2F%2Fexample.com%2Fpj">>, any),
    ?assertEqual(<<"https://example.com/pj">>, U#bip21_uri.pj).

pjos_one_test() ->
    %% W119 G29: pjos=1 → disableoutputsubstitution
    {ok, U} = beamchain_bip21:parse(<<"bitcoin:addr?pjos=1">>, any),
    ?assertEqual(1, U#bip21_uri.pjos).

pjos_zero_test() ->
    {ok, U} = beamchain_bip21:parse(<<"bitcoin:addr?pjos=0">>, any),
    ?assertEqual(0, U#bip21_uri.pjos).

pjos_invalid_test() ->
    ?assertMatch({error, {bad_pjos, <<"yes">>}},
                 beamchain_bip21:parse(<<"bitcoin:addr?pjos=yes">>, any)).

bip78_full_uri_test() ->
    %% Realistic BIP-78 invoice URI — combines pj + pjos + amount + req-.
    Input = <<"bitcoin:bc1qexampleaddress?"
              "amount=0.01&"
              "pj=https%3A%2F%2Fexample.com%2Fpj%2Finvoice%2Fabc&"
              "pjos=1">>,
    {ok, U} = beamchain_bip21:parse(Input, any),
    ?assertEqual(1000000, U#bip21_uri.amount),
    ?assertEqual(<<"https://example.com/pj/invoice/abc">>, U#bip21_uri.pj),
    ?assertEqual(1, U#bip21_uri.pjos).

%%% ===================================================================
%%% 5. req- rejection
%%% ===================================================================

req_unknown_rejected_test() ->
    ?assertMatch({error, {unsupported_required_param, <<"req-foo">>}},
                 beamchain_bip21:parse(<<"bitcoin:addr?req-foo=1">>, any)).

req_unknown_rejected_even_if_known_first_test() ->
    %% Order MUST NOT matter — even if amount comes first, the
    %% subsequent req-X aborts the entire URI.
    ?assertMatch({error, {unsupported_required_param, _}},
                 beamchain_bip21:parse(
                   <<"bitcoin:addr?amount=1&req-x=1">>, any)).

req_bare_test() ->
    %% Literal "req-" with empty suffix — still in the req- family.
    ?assertMatch({error, {unsupported_required_param, <<"req-">>}},
                 beamchain_bip21:parse(<<"bitcoin:addr?req-=1">>, any)).

req_prefix_only_not_rejected_test() ->
    %% "request" is NOT in the req- family — req- means literally
    %% "req-" followed by the param name with a hyphen.
    {ok, U} = beamchain_bip21:parse(<<"bitcoin:addr?request=ok">>, any),
    ?assertEqual([{<<"request">>, <<"ok">>}], U#bip21_uri.extras).

%%% ===================================================================
%%% 6. Unknown non-req params land in extras
%%% ===================================================================

unknown_param_preserved_test() ->
    {ok, U} = beamchain_bip21:parse(
                <<"bitcoin:addr?foo=bar&baz=qux">>, any),
    ?assertEqual([{<<"foo">>, <<"bar">>}, {<<"baz">>, <<"qux">>}],
                 U#bip21_uri.extras).

unknown_param_order_preserved_test() ->
    {ok, U} = beamchain_bip21:parse(
                <<"bitcoin:addr?z=1&a=2&m=3">>, any),
    ?assertEqual([{<<"z">>, <<"1">>}, {<<"a">>, <<"2">>}, {<<"m">>, <<"3">>}],
                 U#bip21_uri.extras).

unknown_param_no_value_test() ->
    {ok, U} = beamchain_bip21:parse(<<"bitcoin:addr?flag">>, any),
    ?assertEqual([{<<"flag">>, <<>>}], U#bip21_uri.extras).

%%% ===================================================================
%%% 7. Duplicate first-class params
%%% ===================================================================

duplicate_amount_rejected_test() ->
    ?assertMatch({error, {duplicate_param, amount}},
                 beamchain_bip21:parse(
                   <<"bitcoin:addr?amount=1&amount=2">>, any)).

duplicate_pj_rejected_test() ->
    ?assertMatch({error, {duplicate_param, pj}},
                 beamchain_bip21:parse(
                   <<"bitcoin:addr?pj=a&pj=b">>, any)).

%%% ===================================================================
%%% 8. Amount edge cases — these are real loss-of-funds vectors.
%%%    A wallet that ignores extra fractional digits or accepts
%%%    scientific notation can over- or under-pay an invoice.
%%% ===================================================================

amount_too_many_fractional_test() ->
    ?assertMatch({error, {bad_amount, <<"0.123456789">>, _}},
                 beamchain_bip21:parse(
                   <<"bitcoin:addr?amount=0.123456789">>, any)).

amount_negative_rejected_test() ->
    ?assertMatch({error, {bad_amount, <<"-1">>, _}},
                 beamchain_bip21:parse(<<"bitcoin:addr?amount=-1">>, any)).

amount_scientific_rejected_test() ->
    ?assertMatch({error, {bad_amount, <<"1e3">>, _}},
                 beamchain_bip21:parse(<<"bitcoin:addr?amount=1e3">>, any)).

amount_hex_rejected_test() ->
    ?assertMatch({error, {bad_amount, <<"0xff">>, _}},
                 beamchain_bip21:parse(<<"bitcoin:addr?amount=0xff">>, any)).

amount_empty_rejected_test() ->
    ?assertMatch({error, {bad_amount, <<>>, _}},
                 beamchain_bip21:parse(<<"bitcoin:addr?amount=">>, any)).

amount_dot_only_rejected_test() ->
    ?assertMatch({error, {bad_amount, <<".">>, _}},
                 beamchain_bip21:parse(<<"bitcoin:addr?amount=.">>, any)).

amount_two_dots_rejected_test() ->
    ?assertMatch({error, {bad_amount, <<"1.2.3">>, _}},
                 beamchain_bip21:parse(<<"bitcoin:addr?amount=1.2.3">>, any)).

amount_leading_space_rejected_test() ->
    ?assertMatch({error, {bad_amount, <<" 1">>, _}},
                 beamchain_bip21:parse(<<"bitcoin:addr?amount=%201">>, any)).

amount_21M_test() ->
    %% Bitcoin's max supply: 21,000,000 BTC = 2,100,000,000,000,000 sats.
    %% Parser is denomination-agnostic — bounds check is downstream.
    {ok, U} = beamchain_bip21:parse(
                <<"bitcoin:addr?amount=21000000">>, any),
    ?assertEqual(2100000000000000, U#bip21_uri.amount).

%%% ===================================================================
%%% 9. Case-insensitive parameter keys
%%% ===================================================================

key_case_insensitive_amount_test() ->
    {ok, U} = beamchain_bip21:parse(
                <<"bitcoin:addr?AMOUNT=1.5">>, any),
    ?assertEqual(150000000, U#bip21_uri.amount).

key_case_insensitive_label_test() ->
    {ok, U} = beamchain_bip21:parse(
                <<"bitcoin:addr?LaBeL=Alice">>, any),
    ?assertEqual(<<"Alice">>, U#bip21_uri.label).

key_case_insensitive_pj_test() ->
    {ok, U} = beamchain_bip21:parse(
                <<"bitcoin:addr?PJ=https://x">>, any),
    ?assertEqual(<<"https://x">>, U#bip21_uri.pj).

key_case_insensitive_req_test() ->
    %% "REQ-FOO" — also rejected (key normalisation applies to req-
    %% detection too).
    ?assertMatch({error, {unsupported_required_param, <<"req-foo">>}},
                 beamchain_bip21:parse(<<"bitcoin:addr?REQ-FOO=1">>, any)).

value_case_preserved_test() ->
    %% Values are NEVER lowercased; only keys are.
    {ok, U} = beamchain_bip21:parse(
                <<"bitcoin:addr?label=MixedCASE">>, any),
    ?assertEqual(<<"MixedCASE">>, U#bip21_uri.label).

%%% ===================================================================
%%% Query edge cases — empty pieces, trailing &, leading &
%%% ===================================================================

trailing_ampersand_ignored_test() ->
    {ok, U} = beamchain_bip21:parse(<<"bitcoin:addr?amount=1&">>, any),
    ?assertEqual(100000000, U#bip21_uri.amount).

leading_ampersand_ignored_test() ->
    {ok, U} = beamchain_bip21:parse(<<"bitcoin:addr?&amount=1">>, any),
    ?assertEqual(100000000, U#bip21_uri.amount).

double_ampersand_ignored_test() ->
    {ok, U} = beamchain_bip21:parse(
                <<"bitcoin:addr?amount=1&&label=x">>, any),
    ?assertEqual(100000000, U#bip21_uri.amount),
    ?assertEqual(<<"x">>, U#bip21_uri.label).

empty_query_test() ->
    %% No '?', no query — still valid.
    {ok, U} = beamchain_bip21:parse(<<"bitcoin:addr">>, any),
    ?assertEqual([], U#bip21_uri.extras),
    ?assertEqual(undefined, U#bip21_uri.amount).

empty_query_with_question_mark_test() ->
    {ok, U} = beamchain_bip21:parse(<<"bitcoin:addr?">>, any),
    ?assertEqual([], U#bip21_uri.extras).

%%% ===================================================================
%%% Real address validation — proves the address layer wires in.
%%% ===================================================================

mainnet_address_accepted_test() ->
    %% Satoshi's address — real mainnet P2PKH.
    {ok, _} = beamchain_bip21:parse(
                <<"bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa">>, mainnet).

mainnet_bech32_accepted_test() ->
    %% BIP-173 test vector mainnet P2WPKH.
    {ok, _} = beamchain_bip21:parse(
                <<"bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4">>,
                mainnet).

mainnet_bad_checksum_rejected_test() ->
    %% Flip the final char — checksum fails, address layer rejects,
    %% parse returns {error, {bad_address, _}}.
    ?assertMatch({error, {bad_address, _}},
                 beamchain_bip21:parse(
                   <<"bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb">>,
                   mainnet)).
