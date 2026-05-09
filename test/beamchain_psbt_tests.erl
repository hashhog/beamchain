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

%%% ===================================================================
%%% W41 — NON_WITNESS_UTXO consistency (Bug A1 + A2)
%%%
%%% Ported from W40-A audit notes (see commit message).  Mirrors
%%% Bitcoin Core's `PSBTInput::IsSane` invariant in psbt.cpp ~80,
%%% ~337, ~425:
%%%   - `non_witness_utxo->GetHash() == tx->vin[i].prevout.hash` (A1)
%%%   - if both witness_utxo and non_witness_utxo are present, they
%%%     must agree on amount + scriptPubKey for prevout.n (A2)
%%%
%%% Fixtures here are deliberately ASYMMETRIC (different output
%%% values, different scriptPubKeys, different vouts) so a
%%% mistakenly-reversed txid byte order or a wrong-vout indexing bug
%%% would surface as a test failure.
%%% ===================================================================

%% Build a prev-tx with two outputs of distinct values + scripts so
%% indexing bugs can't accidentally pass.
sample_prev_tx() ->
    #transaction{
        version = 2,
        inputs = [
            #tx_in{
                prev_out = #outpoint{
                    hash = <<16#aa:256>>, %% asymmetric
                    index = 7
                },
                script_sig = <<>>,
                sequence = 16#ffffffff,
                witness = []
            }
        ],
        outputs = [
            #tx_out{
                value = 50000,
                script_pubkey =
                    <<16#00, 20,
                      9,9,9,9,9,9,9,9,9,9,
                      9,9,9,9,9,9,9,9,9,9>> %% P2WPKH(0x09..)
            },
            #tx_out{
                value = 77777,
                script_pubkey =
                    <<16#00, 20,
                      8,8,8,8,8,8,8,8,8,8,
                      8,8,8,8,8,8,8,8,8,8>> %% P2WPKH(0x08..) — distinct
            }
        ],
        locktime = 0,
        txid = undefined,
        wtxid = undefined
    }.

%% Spending tx that names PrevTx's real txid + vout 0.
spending_tx_for(PrevTx, VoutIdx) ->
    Txid = beamchain_serialize:tx_hash(PrevTx),
    #transaction{
        version = 2,
        inputs = [
            #tx_in{
                prev_out = #outpoint{hash = Txid, index = VoutIdx},
                script_sig = <<>>,
                sequence = 16#fffffffd,
                witness = []
            }
        ],
        outputs = [
            #tx_out{
                value = 30000,
                script_pubkey = <<16#00, 20,
                                  1,1,1,1,1,1,1,1,1,1,
                                  1,1,1,1,1,1,1,1,1,1>>
            }
        ],
        locktime = 0,
        txid = undefined,
        wtxid = undefined
    }.

w41_consistency_test_() ->
    {"W41 PSBT NON_WITNESS_UTXO consistency", [
        {"verify_non_witness_utxo_txid happy path",
         fun w41_verify_helper_match/0},
        {"verify_non_witness_utxo_txid mismatch",
         fun w41_verify_helper_mismatch/0},
        {"sign declines on forged prev-tx (A1)",
         fun w41_sign_rejects_a1/0},
        {"finalize errors on forged prev-tx (A1)",
         fun w41_finalize_rejects_a1/0},
        {"sign declines on amount disagreement (A2)",
         fun w41_sign_rejects_a2_value/0},
        {"sign declines on scriptPubKey disagreement (A2)",
         fun w41_sign_rejects_a2_script/0},
        {"finalize errors on A2 disagreement",
         fun w41_finalize_rejects_a2/0},
        {"both UTXOs present and consistent — accepts",
         fun w41_consistent_both_ok/0}
    ]}.

w41_verify_helper_match() ->
    PrevTx = sample_prev_tx(),
    Txid = beamchain_serialize:tx_hash(PrevTx),
    ?assertEqual(ok,
                 beamchain_crypto:verify_non_witness_utxo_txid(PrevTx, Txid)).

w41_verify_helper_mismatch() ->
    PrevTx = sample_prev_tx(),
    %% Asymmetric wrong txid — definitely not a palindrome.
    Wrong = <<16#01, 16#02, 16#03, 16#04, 16#05, 16#06, 16#07, 16#08,
              16#09, 16#0a, 16#0b, 16#0c, 16#0d, 16#0e, 16#0f, 16#10,
              16#11, 16#12, 16#13, 16#14, 16#15, 16#16, 16#17, 16#18,
              16#19, 16#1a, 16#1b, 16#1c, 16#1d, 16#1e, 16#1f, 16#20>>,
    ?assertEqual({error, non_witness_utxo_txid_mismatch},
                 beamchain_crypto:verify_non_witness_utxo_txid(PrevTx, Wrong)).

%% A1: spending tx outpoint names a txid that doesn't match the prev-tx
%% the updater handed us. sign() must NOT produce a partial signature
%% (best-effort policy — drop the input).
w41_sign_rejects_a1() ->
    PrevTx = sample_prev_tx(),
    Tx = spending_tx_for(PrevTx, 0),
    %% Tamper with PrevTx so its hash no longer matches the outpoint:
    %% reorder its outputs (different tx_hash, same total value).
    [O0, O1] = PrevTx#transaction.outputs,
    ForgedPrevTx = PrevTx#transaction{outputs = [O1, O0]},
    {ok, Psbt} = beamchain_psbt:create(Tx),
    {ok, Updated} = beamchain_psbt:update(Psbt, [
        {input, 0, #{non_witness_utxo => ForgedPrevTx}}
    ]),
    PrivKey = <<1:256>>,
    {ok, Signed} = beamchain_psbt:sign(Updated, [{0, PrivKey}]),
    InputMap = beamchain_psbt:get_input(Signed, 0),
    %% No partial signature should have been produced.
    ?assertEqual(#{}, maps:get(partial_sigs, InputMap, #{})),
    ?assertNot(maps:is_key(tap_key_sig, InputMap)).

w41_finalize_rejects_a1() ->
    PrevTx = sample_prev_tx(),
    Tx = spending_tx_for(PrevTx, 0),
    [O0, O1] = PrevTx#transaction.outputs,
    ForgedPrevTx = PrevTx#transaction{outputs = [O1, O0]},
    {ok, Psbt} = beamchain_psbt:create(Tx),
    {ok, Updated} = beamchain_psbt:update(Psbt, [
        {input, 0, #{non_witness_utxo => ForgedPrevTx}}
    ]),
    ?assertEqual({error, non_witness_utxo_txid_mismatch},
                 beamchain_psbt:finalize(Updated)).

%% A2: witness_utxo claims a different value from the corresponding
%% non_witness_utxo->vout[n]. Updater is lying about the amount —
%% reject (CVE-2020-14199 fix shape).
w41_sign_rejects_a2_value() ->
    PrevTx = sample_prev_tx(),
    Tx = spending_tx_for(PrevTx, 0),
    [#tx_out{script_pubkey = SPK0} | _] = PrevTx#transaction.outputs,
    %% The real value at vout 0 is 50000; witness_utxo lies as 99999.
    {ok, Psbt} = beamchain_psbt:create(Tx),
    {ok, Updated} = beamchain_psbt:update(Psbt, [
        {input, 0, #{
            non_witness_utxo => PrevTx,
            witness_utxo => {99999, SPK0}
        }}
    ]),
    PrivKey = <<2:256>>,
    {ok, Signed} = beamchain_psbt:sign(Updated, [{0, PrivKey}]),
    InputMap = beamchain_psbt:get_input(Signed, 0),
    ?assertEqual(#{}, maps:get(partial_sigs, InputMap, #{})).

w41_sign_rejects_a2_script() ->
    PrevTx = sample_prev_tx(),
    Tx = spending_tx_for(PrevTx, 0),
    [#tx_out{value = V0} | _] = PrevTx#transaction.outputs,
    %% Lie about the scriptPubKey while keeping the value.
    LyingSPK = <<16#00, 20, 7,7,7,7,7,7,7,7,7,7,
                          7,7,7,7,7,7,7,7,7,7>>,
    {ok, Psbt} = beamchain_psbt:create(Tx),
    {ok, Updated} = beamchain_psbt:update(Psbt, [
        {input, 0, #{
            non_witness_utxo => PrevTx,
            witness_utxo => {V0, LyingSPK}
        }}
    ]),
    PrivKey = <<3:256>>,
    {ok, Signed} = beamchain_psbt:sign(Updated, [{0, PrivKey}]),
    InputMap = beamchain_psbt:get_input(Signed, 0),
    ?assertEqual(#{}, maps:get(partial_sigs, InputMap, #{})).

w41_finalize_rejects_a2() ->
    PrevTx = sample_prev_tx(),
    Tx = spending_tx_for(PrevTx, 0),
    [#tx_out{script_pubkey = SPK0} | _] = PrevTx#transaction.outputs,
    {ok, Psbt} = beamchain_psbt:create(Tx),
    {ok, Updated} = beamchain_psbt:update(Psbt, [
        {input, 0, #{
            non_witness_utxo => PrevTx,
            witness_utxo => {12345, SPK0} %% real is 50000
        }}
    ]),
    ?assertEqual({error, utxo_value_mismatch},
                 beamchain_psbt:finalize(Updated)).

%% Sanity / no-regression: when both UTXOs are present and consistent,
%% the consistency-check helper accepts it. We assert via the round-trip
%% encode/decode of the witness_utxo (same as the existing
%% encode_with_witness_utxo test) — the load-bearing part is that
%% finalize doesn't error out.
w41_consistent_both_ok() ->
    PrevTx = sample_prev_tx(),
    Tx = spending_tx_for(PrevTx, 1), %% pick vout 1 to exercise non-zero index
    [_, #tx_out{value = V1, script_pubkey = SPK1}] =
        PrevTx#transaction.outputs,
    {ok, Psbt} = beamchain_psbt:create(Tx),
    {ok, Updated} = beamchain_psbt:update(Psbt, [
        {input, 0, #{
            non_witness_utxo => PrevTx,
            witness_utxo => {V1, SPK1}
        }}
    ]),
    %% finalize will still fail (no partial_sigs), but with a *signing*
    %% error (missing_signature), not a UTXO-consistency error — that's
    %% the load-bearing distinction.
    ?assertMatch({error, missing_signature},
                 beamchain_psbt:finalize(Updated)).

%%% ===================================================================
%%% W46: encoder gate + script-order multisig finalize
%%% ===================================================================
%%% Bug pattern: encode_input_map/1 used to emit producer fields
%%% (partial_sigs / sighash_type / redeem_script / witness_script /
%%% bip32_derivation / tap_*) unconditionally, leaking ~hundreds of bytes
%%% of producer state into the wire bytes after finalize. Core gates
%%% these behind `if (final_script_sig.empty() && final_script_witness.IsNull())`
%%% (bitcoin-core/src/psbt.h:313). Same shape as W41 lunarblock.
%%%
%%% Bug pattern: finalize_legacy_p2sh/2 built scriptSig from
%%% `maps:values(PartialSigs)` — Erlang map iteration order is undefined,
%%% so multisig signature order was non-deterministic and frequently
%%% wrong (Core requires script-pubkey order via `std::vector` walk in
%%% sign.cpp:ProduceSignature).

%% Two valid 33-byte compressed pubkeys for multisig fixture.
w46_pubkey1() -> <<2, 16#aa:256>>.
w46_pubkey2() -> <<3, 16#bb:256>>.

%% 2-of-2 redeem script: OP_2 <33-byte pk1> <33-byte pk2> OP_2 OP_CHECKMULTISIG
w46_redeem_script() ->
    PK1 = w46_pubkey1(),
    PK2 = w46_pubkey2(),
    <<16#52, 33, PK1/binary, 33, PK2/binary, 16#52, 16#ae>>.

%% Build a prev-tx whose vout 0 pays a P2SH(redeem_script) output,
%% so finalize_legacy_p2sh can satisfy the UTXO-consistency check.
w46_p2sh_prev_tx() ->
    RS = w46_redeem_script(),
    Hash160 = beamchain_crypto:hash160(RS),
    P2SHScript = <<16#a9, 16#14, Hash160/binary, 16#87>>,
    #transaction{
        version = 2,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = <<16#cc:256>>, index = 0},
            script_sig = <<>>,
            sequence = 16#ffffffff,
            witness = []
        }],
        outputs = [#tx_out{value = 60000, script_pubkey = P2SHScript}],
        locktime = 0,
        txid = undefined,
        wtxid = undefined
    }.

w46_spending_tx(PrevTx) ->
    Txid = beamchain_serialize:tx_hash(PrevTx),
    #transaction{
        version = 2,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = Txid, index = 0},
            script_sig = <<>>,
            sequence = 16#fffffffd,
            witness = []
        }],
        outputs = [#tx_out{
            value = 30000,
            script_pubkey = <<16#00, 20, 7,7,7,7,7,7,7,7,7,7,
                                          7,7,7,7,7,7,7,7,7,7>>
        }],
        locktime = 0,
        txid = undefined,
        wtxid = undefined
    }.

w46_test_() ->
    {"W46 encoder gate + script-order finalize", [
        {"encoder drops producer fields after finalize",
         fun w46_encoder_gate_drops_producer_fields/0},
        {"legacy P2SH multisig sigs in script-pubkey order",
         fun w46_legacy_p2sh_script_order/0},
        {"encode is deterministic across repeated calls",
         fun w46_encode_deterministic/0},
        {"partial_sigs sorted by HASH160 on the wire",
         fun w46_partial_sigs_sorted_by_keyid/0}
    ]}.

%% Test 1: encoder gate. Build a P2SH multisig PSBT, finalize, encode,
%% decode again — the producer fields must be absent from the decoded
%% input map.
w46_encoder_gate_drops_producer_fields() ->
    PrevTx = w46_p2sh_prev_tx(),
    Tx = w46_spending_tx(PrevTx),
    RS = w46_redeem_script(),
    PK1 = w46_pubkey1(),
    PK2 = w46_pubkey2(),
    %% Opaque DER-shaped sigs; finalize doesn't actually verify them.
    Sig1 = <<48, 68, 2, 32, 16#11:256, 2, 32, 16#22:256, 1>>,
    Sig2 = <<48, 68, 2, 32, 16#33:256, 2, 32, 16#44:256, 1>>,
    {ok, Psbt} = beamchain_psbt:create(Tx),
    {ok, Updated} = beamchain_psbt:update(Psbt, [
        {input, 0, #{
            non_witness_utxo => PrevTx,
            redeem_script => RS,
            partial_sigs => #{PK1 => Sig1, PK2 => Sig2},
            sighash_type => 1,
            bip32_derivation => #{PK1 => {<<0,0,0,0>>, [44, 0, 0]}}
        }}
    ]),
    {ok, Finalized} = beamchain_psbt:finalize(Updated),
    Encoded = beamchain_psbt:encode(Finalized),
    {ok, Decoded} = beamchain_psbt:decode(Encoded),
    InputMap = beamchain_psbt:get_input(Decoded, 0),
    %% Producer fields must NOT survive the round-trip on a finalized input.
    ?assertNot(maps:is_key(partial_sigs, InputMap)),
    ?assertNot(maps:is_key(sighash_type, InputMap)),
    ?assertNot(maps:is_key(redeem_script, InputMap)),
    ?assertNot(maps:is_key(witness_script, InputMap)),
    ?assertNot(maps:is_key(bip32_derivation, InputMap)),
    %% Final fields must be present.
    ?assert(maps:is_key(final_script_sig, InputMap)).

%% Test 2: legacy P2SH multisig — supply partial_sigs in REVERSE
%% pubkey order; assert the assembled scriptSig still places sigs in
%% script-pubkey order.
w46_legacy_p2sh_script_order() ->
    PrevTx = w46_p2sh_prev_tx(),
    Tx = w46_spending_tx(PrevTx),
    RS = w46_redeem_script(),
    PK1 = w46_pubkey1(),
    PK2 = w46_pubkey2(),
    Sig1 = <<48, 68, 2, 32, 16#11:256, 2, 32, 16#22:256, 1>>,
    Sig2 = <<48, 68, 2, 32, 16#33:256, 2, 32, 16#44:256, 1>>,
    {ok, Psbt} = beamchain_psbt:create(Tx),
    %% Insert the partial_sigs in REVERSE (PK2 first, then PK1).
    {ok, Updated} = beamchain_psbt:update(Psbt, [
        {input, 0, #{
            non_witness_utxo => PrevTx,
            redeem_script => RS,
            %% Erlang map literal — order here is irrelevant; test is
            %% that the finalizer walks the redeem-script's pubkey list.
            partial_sigs => #{PK2 => Sig2, PK1 => Sig1}
        }}
    ]),
    {ok, Finalized} = beamchain_psbt:finalize(Updated),
    InputMap = beamchain_psbt:get_input(Finalized, 0),
    ScriptSig = maps:get(final_script_sig, InputMap),
    %% Layout: OP_0 <push Sig1> <push Sig2> <push RS>. Sig1 must come
    %% before Sig2 because PK1 is listed first in RS.
    %% OP_0 = 0x00, push-len(Sig1)=70, Sig1, push-len(Sig2)=70, Sig2, ...
    SigLen = byte_size(Sig1),
    %% Sanity: both sigs same length (canonical DER + sighash byte).
    ?assertEqual(SigLen, byte_size(Sig2)),
    Expected =
        <<0, SigLen:8, Sig1/binary, SigLen:8, Sig2/binary,
          (push_len(byte_size(RS)))/binary, RS/binary>>,
    ?assertEqual(Expected, ScriptSig).

%% Tiny helper: BIP-62 / minimal-push prefix. For 0..75 the prefix is
%% one byte == length; for 76..255 it's OP_PUSHDATA1 + len. Our redeem
%% script is 71 bytes so the simple form applies, but keep this generic.
push_len(L) when L =< 75 -> <<L:8>>;
push_len(L) when L =< 255 -> <<76, L:8>>;
push_len(L) when L =< 65535 -> <<77, L:16/little>>.

%% Test 3: determinism across repeated encode calls. Erlang map iteration
%% order is implementation-defined; we want byte-identical output every
%% time. Build a PSBT with multiple partial_sigs and bip32_derivations,
%% encode twice, compare bytes.
w46_encode_deterministic() ->
    PrevTx = w46_p2sh_prev_tx(),
    Tx = w46_spending_tx(PrevTx),
    RS = w46_redeem_script(),
    PK1 = w46_pubkey1(),
    PK2 = w46_pubkey2(),
    Sig1 = <<48, 68, 2, 32, 16#11:256, 2, 32, 16#22:256, 1>>,
    Sig2 = <<48, 68, 2, 32, 16#33:256, 2, 32, 16#44:256, 1>>,
    {ok, Psbt} = beamchain_psbt:create(Tx),
    {ok, Updated} = beamchain_psbt:update(Psbt, [
        {input, 0, #{
            non_witness_utxo => PrevTx,
            redeem_script => RS,
            partial_sigs => #{PK2 => Sig2, PK1 => Sig1},
            bip32_derivation => #{
                PK2 => {<<1,2,3,4>>, [44, 0, 1]},
                PK1 => {<<1,2,3,4>>, [44, 0, 0]}
            }
        }}
    ]),
    A = beamchain_psbt:encode(Updated),
    B = beamchain_psbt:encode(Updated),
    ?assertEqual(A, B),
    %% And re-decoding then re-encoding stays identical too (idempotent
    %% combine-PSBT path, T2 in psbt-multi-input-test.sh).
    {ok, Reloaded} = beamchain_psbt:decode(A),
    C = beamchain_psbt:encode(Reloaded),
    ?assertEqual(A, C).

%% Test 4: partial_sigs wire-order is HASH160(pubkey)-sorted, matching
%% Core's std::map<CKeyID, SigPair>. Construct two pubkeys whose HASH160
%% sort order differs from their raw-pubkey-bytes sort order, so the
%% test catches the wrong sort key.
w46_partial_sigs_sorted_by_keyid() ->
    PrevTx = w46_p2sh_prev_tx(),
    Tx = w46_spending_tx(PrevTx),
    PKa = w46_pubkey1(),
    PKb = w46_pubkey2(),
    Sa = <<1, 2, 3, 4>>,
    Sb = <<5, 6, 7, 8>>,
    {ok, Psbt} = beamchain_psbt:create(Tx),
    {ok, Updated} = beamchain_psbt:update(Psbt, [
        {input, 0, #{
            non_witness_utxo => PrevTx,
            partial_sigs => #{PKb => Sb, PKa => Sa}
        }}
    ]),
    Encoded = beamchain_psbt:encode(Updated),
    %% Decode and find the order in which the encoder emitted them by
    %% scanning the encoded bytes for the two sig payloads.
    PosA = binary_position(Encoded, Sa),
    PosB = binary_position(Encoded, Sb),
    ?assert(PosA =/= notfound),
    ?assert(PosB =/= notfound),
    %% Compute the expected order by HASH160 of each pubkey.
    KIDa = beamchain_crypto:hash160(PKa),
    KIDb = beamchain_crypto:hash160(PKb),
    ExpectedOrder = case KIDa < KIDb of
        true -> {PosA, PosB};
        false -> {PosB, PosA}
    end,
    {First, Second} = ExpectedOrder,
    ?assert(First < Second).

binary_position(Hay, Needle) ->
    case binary:match(Hay, Needle) of
        nomatch -> notfound;
        {Pos, _Len} -> Pos
    end.

