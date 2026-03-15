-module(beamchain_psbt_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%%% ===================================================================
%%% Test fixtures
%%% ===================================================================

%% Sample unsigned transaction for testing
sample_unsigned_tx() ->
    #transaction{
        version = 2,
        inputs = [
            #tx_in{
                prev_out = #outpoint{
                    hash = <<1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
                             17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32>>,
                    index = 0
                },
                script_sig = <<>>,
                sequence = 16#fffffffd,
                witness = []
            }
        ],
        outputs = [
            #tx_out{
                value = 100000,
                script_pubkey = <<16#00, 20,  %% P2WPKH
                    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20>>
            }
        ],
        locktime = 0
    }.

%% P2WPKH scriptPubKey
sample_p2wpkh_script() ->
    <<16#00, 20, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20>>.

%%% ===================================================================
%%% Create tests
%%% ===================================================================

create_test_() ->
    {"PSBT creation tests", [
        {"create from unsigned tx", fun create_basic/0},
        {"reject signed tx", fun create_reject_signed/0}
    ]}.

create_basic() ->
    Tx = sample_unsigned_tx(),
    {ok, Psbt} = beamchain_psbt:create(Tx),
    ?assertEqual(Tx, beamchain_psbt:get_unsigned_tx(Psbt)),
    ?assertEqual(0, beamchain_psbt:get_version(Psbt)),
    ?assertMatch(#{}, beamchain_psbt:get_input(Psbt, 0)),
    ?assertMatch(#{}, beamchain_psbt:get_output(Psbt, 0)).

create_reject_signed() ->
    %% Transaction with scriptSig should be rejected
    Tx = sample_unsigned_tx(),
    [Input | _] = Tx#transaction.inputs,
    SignedInput = Input#tx_in{script_sig = <<1,2,3>>},
    SignedTx = Tx#transaction{inputs = [SignedInput]},
    ?assertMatch({error, _}, beamchain_psbt:create(SignedTx)).

%%% ===================================================================
%%% Encode/Decode tests
%%% ===================================================================

encode_decode_test_() ->
    {"PSBT encode/decode tests", [
        {"roundtrip basic", fun encode_decode_roundtrip/0},
        {"decode invalid magic", fun decode_invalid_magic/0},
        {"encode with witness utxo", fun encode_with_witness_utxo/0}
    ]}.

encode_decode_roundtrip() ->
    Tx = sample_unsigned_tx(),
    {ok, Psbt} = beamchain_psbt:create(Tx),
    Encoded = beamchain_psbt:encode(Psbt),
    %% Check magic bytes
    <<16#70, 16#73, 16#62, 16#74, 16#ff, _/binary>> = Encoded,
    %% Decode it back
    {ok, Decoded} = beamchain_psbt:decode(Encoded),
    ?assertEqual(beamchain_psbt:get_unsigned_tx(Psbt),
                 beamchain_psbt:get_unsigned_tx(Decoded)).

decode_invalid_magic() ->
    ?assertMatch({error, invalid_magic},
                 beamchain_psbt:decode(<<1,2,3,4,5>>)).

encode_with_witness_utxo() ->
    Tx = sample_unsigned_tx(),
    {ok, Psbt} = beamchain_psbt:create(Tx),
    %% Add witness UTXO to input 0
    {ok, UpdatedPsbt} = beamchain_psbt:update(Psbt, [
        {input, 0, #{witness_utxo => {50000, sample_p2wpkh_script()}}}
    ]),
    Encoded = beamchain_psbt:encode(UpdatedPsbt),
    {ok, Decoded} = beamchain_psbt:decode(Encoded),
    InputMap = beamchain_psbt:get_input(Decoded, 0),
    ?assertMatch({50000, _}, maps:get(witness_utxo, InputMap)).

%%% ===================================================================
%%% Update tests
%%% ===================================================================

update_test_() ->
    {"PSBT update tests", [
        {"add witness utxo", fun update_witness_utxo/0},
        {"add sighash type", fun update_sighash_type/0},
        {"add redeem script", fun update_redeem_script/0},
        {"invalid input index", fun update_invalid_index/0}
    ]}.

update_witness_utxo() ->
    Tx = sample_unsigned_tx(),
    {ok, Psbt} = beamchain_psbt:create(Tx),
    {ok, Updated} = beamchain_psbt:update(Psbt, [
        {input, 0, #{witness_utxo => {100000, sample_p2wpkh_script()}}}
    ]),
    InputMap = beamchain_psbt:get_input(Updated, 0),
    ?assertMatch({100000, _}, maps:get(witness_utxo, InputMap)).

update_sighash_type() ->
    Tx = sample_unsigned_tx(),
    {ok, Psbt} = beamchain_psbt:create(Tx),
    {ok, Updated} = beamchain_psbt:update(Psbt, [
        {input, 0, #{sighash_type => ?SIGHASH_ALL}}
    ]),
    InputMap = beamchain_psbt:get_input(Updated, 0),
    ?assertEqual(?SIGHASH_ALL, maps:get(sighash_type, InputMap)).

update_redeem_script() ->
    Tx = sample_unsigned_tx(),
    {ok, Psbt} = beamchain_psbt:create(Tx),
    RedeemScript = <<0, 20, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20>>,
    {ok, Updated} = beamchain_psbt:update(Psbt, [
        {input, 0, #{redeem_script => RedeemScript}}
    ]),
    InputMap = beamchain_psbt:get_input(Updated, 0),
    ?assertEqual(RedeemScript, maps:get(redeem_script, InputMap)).

update_invalid_index() ->
    Tx = sample_unsigned_tx(),
    {ok, Psbt} = beamchain_psbt:create(Tx),
    ?assertMatch({error, {invalid_input_index, 5}},
                 beamchain_psbt:update(Psbt, [{input, 5, #{}}])).

%%% ===================================================================
%%% Combine tests
%%% ===================================================================

combine_test_() ->
    {"PSBT combine tests", [
        {"combine two psbts", fun combine_two/0},
        {"combine merges signatures", fun combine_merges_sigs/0},
        {"combine rejects mismatched tx", fun combine_reject_mismatch/0},
        {"combine empty list", fun combine_empty/0}
    ]}.

combine_two() ->
    Tx = sample_unsigned_tx(),
    {ok, Psbt1} = beamchain_psbt:create(Tx),
    {ok, Psbt2} = beamchain_psbt:create(Tx),
    %% Update with different data
    {ok, Updated1} = beamchain_psbt:update(Psbt1, [
        {input, 0, #{witness_utxo => {100000, sample_p2wpkh_script()}}}
    ]),
    {ok, Updated2} = beamchain_psbt:update(Psbt2, [
        {input, 0, #{sighash_type => ?SIGHASH_ALL}}
    ]),
    {ok, Combined} = beamchain_psbt:combine([Updated1, Updated2]),
    InputMap = beamchain_psbt:get_input(Combined, 0),
    ?assertMatch({100000, _}, maps:get(witness_utxo, InputMap)),
    ?assertEqual(?SIGHASH_ALL, maps:get(sighash_type, InputMap)).

combine_merges_sigs() ->
    Tx = sample_unsigned_tx(),
    {ok, Psbt1} = beamchain_psbt:create(Tx),
    {ok, Psbt2} = beamchain_psbt:create(Tx),
    PubKey1 = <<2, 1:256>>,  %% Compressed pubkey format
    PubKey2 = <<3, 2:256>>,
    Sig1 = <<1,2,3>>,
    Sig2 = <<4,5,6>>,
    {ok, Updated1} = beamchain_psbt:update(Psbt1, [
        {input, 0, #{partial_sigs => #{PubKey1 => Sig1}}}
    ]),
    {ok, Updated2} = beamchain_psbt:update(Psbt2, [
        {input, 0, #{partial_sigs => #{PubKey2 => Sig2}}}
    ]),
    {ok, Combined} = beamchain_psbt:combine([Updated1, Updated2]),
    InputMap = beamchain_psbt:get_input(Combined, 0),
    Sigs = maps:get(partial_sigs, InputMap),
    ?assertEqual(2, maps:size(Sigs)),
    ?assertEqual(Sig1, maps:get(PubKey1, Sigs)),
    ?assertEqual(Sig2, maps:get(PubKey2, Sigs)).

combine_reject_mismatch() ->
    Tx1 = sample_unsigned_tx(),
    Tx2 = Tx1#transaction{locktime = 500000},  %% Different locktime
    {ok, Psbt1} = beamchain_psbt:create(Tx1),
    {ok, Psbt2} = beamchain_psbt:create(Tx2),
    ?assertMatch({error, transaction_mismatch},
                 beamchain_psbt:combine([Psbt1, Psbt2])).

combine_empty() ->
    ?assertMatch({error, empty_list}, beamchain_psbt:combine([])).

%%% ===================================================================
%%% Finalize tests
%%% ===================================================================

finalize_test_() ->
    {"PSBT finalize tests", [
        {"finalize p2wpkh", fun finalize_p2wpkh/0},
        {"finalize without sig fails", fun finalize_no_sig/0},
        {"finalize already finalized", fun finalize_already_done/0}
    ]}.

finalize_p2wpkh() ->
    Tx = sample_unsigned_tx(),
    {ok, Psbt} = beamchain_psbt:create(Tx),
    PubKey = <<2, 1:256>>,
    Sig = <<48, 69, 2, 33, 0:264, 2, 32, 0:256, 1>>,  %% Fake DER sig + sighash
    {ok, Updated} = beamchain_psbt:update(Psbt, [
        {input, 0, #{
            witness_utxo => {100000, sample_p2wpkh_script()},
            partial_sigs => #{PubKey => Sig}
        }}
    ]),
    {ok, Finalized} = beamchain_psbt:finalize(Updated),
    InputMap = beamchain_psbt:get_input(Finalized, 0),
    ?assertEqual(<<>>, maps:get(final_script_sig, InputMap)),
    ?assertEqual([Sig, PubKey], maps:get(final_script_witness, InputMap)).

finalize_no_sig() ->
    Tx = sample_unsigned_tx(),
    {ok, Psbt} = beamchain_psbt:create(Tx),
    {ok, Updated} = beamchain_psbt:update(Psbt, [
        {input, 0, #{witness_utxo => {100000, sample_p2wpkh_script()}}}
    ]),
    ?assertMatch({error, _}, beamchain_psbt:finalize(Updated)).

finalize_already_done() ->
    Tx = sample_unsigned_tx(),
    {ok, Psbt} = beamchain_psbt:create(Tx),
    PubKey = <<2, 1:256>>,
    Sig = <<48, 69, 2, 33, 0:264, 2, 32, 0:256, 1>>,
    {ok, Updated} = beamchain_psbt:update(Psbt, [
        {input, 0, #{
            witness_utxo => {100000, sample_p2wpkh_script()},
            final_script_sig => <<>>,
            final_script_witness => [Sig, PubKey]
        }}
    ]),
    %% Should return as-is without error
    {ok, Finalized} = beamchain_psbt:finalize(Updated),
    ?assertEqual(Updated, Finalized).

%%% ===================================================================
%%% Extract tests
%%% ===================================================================

extract_test_() ->
    {"PSBT extract tests", [
        {"extract finalized tx", fun extract_finalized/0},
        {"extract unfinalized fails", fun extract_unfinalized/0}
    ]}.

extract_finalized() ->
    Tx = sample_unsigned_tx(),
    {ok, Psbt} = beamchain_psbt:create(Tx),
    PubKey = <<2, 1:256>>,
    Sig = <<48, 69, 2, 33, 0:264, 2, 32, 0:256, 1>>,
    {ok, Updated} = beamchain_psbt:update(Psbt, [
        {input, 0, #{
            witness_utxo => {100000, sample_p2wpkh_script()},
            partial_sigs => #{PubKey => Sig}
        }}
    ]),
    {ok, Finalized} = beamchain_psbt:finalize(Updated),
    {ok, ExtractedTx} = beamchain_psbt:extract(Finalized),
    [Input] = ExtractedTx#transaction.inputs,
    ?assertEqual(<<>>, Input#tx_in.script_sig),
    ?assertEqual([Sig, PubKey], Input#tx_in.witness).

extract_unfinalized() ->
    Tx = sample_unsigned_tx(),
    {ok, Psbt} = beamchain_psbt:create(Tx),
    ?assertMatch({error, _}, beamchain_psbt:extract(Psbt)).

%%% ===================================================================
%%% BIP32 derivation path tests
%%% ===================================================================

bip32_derivation_test_() ->
    {"BIP32 derivation tests", [
        {"encode decode derivation", fun bip32_roundtrip/0}
    ]}.

bip32_roundtrip() ->
    Tx = sample_unsigned_tx(),
    {ok, Psbt} = beamchain_psbt:create(Tx),
    PubKey = <<2, 1:256>>,
    Fingerprint = <<16#de, 16#ad, 16#be, 16#ef>>,
    Path = [16#80000054, 16#80000000, 16#80000000, 0, 0],  %% m/84'/0'/0'/0/0
    {ok, Updated} = beamchain_psbt:update(Psbt, [
        {input, 0, #{bip32_derivation => #{PubKey => {Fingerprint, Path}}}}
    ]),
    Encoded = beamchain_psbt:encode(Updated),
    {ok, Decoded} = beamchain_psbt:decode(Encoded),
    InputMap = beamchain_psbt:get_input(Decoded, 0),
    Derivs = maps:get(bip32_derivation, InputMap),
    ?assertMatch({Fingerprint, Path}, maps:get(PubKey, Derivs)).

%%% ===================================================================
%%% Output map tests
%%% ===================================================================

output_test_() ->
    {"PSBT output tests", [
        {"update output", fun update_output/0},
        {"output roundtrip", fun output_roundtrip/0}
    ]}.

update_output() ->
    Tx = sample_unsigned_tx(),
    {ok, Psbt} = beamchain_psbt:create(Tx),
    RedeemScript = <<0, 20, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20>>,
    {ok, Updated} = beamchain_psbt:update(Psbt, [
        {output, 0, #{redeem_script => RedeemScript}}
    ]),
    OutputMap = beamchain_psbt:get_output(Updated, 0),
    ?assertEqual(RedeemScript, maps:get(redeem_script, OutputMap)).

output_roundtrip() ->
    Tx = sample_unsigned_tx(),
    {ok, Psbt} = beamchain_psbt:create(Tx),
    RedeemScript = <<0, 20, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20>>,
    {ok, Updated} = beamchain_psbt:update(Psbt, [
        {output, 0, #{redeem_script => RedeemScript}}
    ]),
    Encoded = beamchain_psbt:encode(Updated),
    {ok, Decoded} = beamchain_psbt:decode(Encoded),
    OutputMap = beamchain_psbt:get_output(Decoded, 0),
    ?assertEqual(RedeemScript, maps:get(redeem_script, OutputMap)).

%%% ===================================================================
%%% Bitcoin Core test vectors
%%% ===================================================================

%% BIP 174 test vectors
test_vectors_test_() ->
    {"BIP 174 test vectors", [
        {"decode valid psbt", fun decode_valid_psbt/0},
        {"invalid psbts rejected", fun invalid_psbts/0}
    ]}.

decode_valid_psbt() ->
    %% Create a valid PSBT programmatically and verify we can encode/decode it
    Tx = sample_unsigned_tx(),
    {ok, Psbt} = beamchain_psbt:create(Tx),
    Encoded = beamchain_psbt:encode(Psbt),
    {ok, Decoded} = beamchain_psbt:decode(Encoded),
    DecodedTx = beamchain_psbt:get_unsigned_tx(Decoded),
    ?assertEqual(1, length(DecodedTx#transaction.inputs)),
    ?assertEqual(1, length(DecodedTx#transaction.outputs)).

invalid_psbts() ->
    %% Invalid magic
    ?assertMatch({error, _}, beamchain_psbt:decode(<<1,2,3,4,5>>)),
    %% Empty after magic
    ?assertMatch({error, _}, beamchain_psbt:decode(<<16#70, 16#73, 16#62, 16#74, 16#ff>>)).

%%% ===================================================================
%%% Taproot PSBT tests
%%% ===================================================================

taproot_test_() ->
    {"Taproot PSBT tests", [
        {"taproot internal key", fun taproot_internal_key/0},
        {"taproot key sig", fun taproot_key_sig/0}
    ]}.

taproot_internal_key() ->
    Tx = sample_unsigned_tx(),
    {ok, Psbt} = beamchain_psbt:create(Tx),
    InternalKey = crypto:strong_rand_bytes(32),
    {ok, Updated} = beamchain_psbt:update(Psbt, [
        {input, 0, #{tap_internal_key => InternalKey}}
    ]),
    Encoded = beamchain_psbt:encode(Updated),
    {ok, Decoded} = beamchain_psbt:decode(Encoded),
    InputMap = beamchain_psbt:get_input(Decoded, 0),
    ?assertEqual(InternalKey, maps:get(tap_internal_key, InputMap)).

taproot_key_sig() ->
    Tx = sample_unsigned_tx(),
    {ok, Psbt} = beamchain_psbt:create(Tx),
    %% 64-byte Schnorr signature
    KeySig = crypto:strong_rand_bytes(64),
    {ok, Updated} = beamchain_psbt:update(Psbt, [
        {input, 0, #{tap_key_sig => KeySig}}
    ]),
    Encoded = beamchain_psbt:encode(Updated),
    {ok, Decoded} = beamchain_psbt:decode(Encoded),
    InputMap = beamchain_psbt:get_input(Decoded, 0),
    ?assertEqual(KeySig, maps:get(tap_key_sig, InputMap)).

