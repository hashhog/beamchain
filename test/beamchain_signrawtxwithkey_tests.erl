-module(beamchain_signrawtxwithkey_tests).

%% Focused functional tests for the `signrawtransactionwithkey` RPC
%% (beamchain_rpc:rpc_signrawtransactionwithkey/1).
%%
%% Mirrors bitcoin-core/src/rpc/rawtransaction.cpp signrawtransactionwithkey
%% + rawtransaction_util.cpp SignTransaction/SignTransactionResultToJSON.
%%
%% These tests do NOT need a running node, wallet, or chainstate: every
%% prevout is supplied via the optional `prevtxs` array (scriptPubKey +
%% amount), exactly as a caller would do for an offline cold-sign.
%%
%% Crucially, the test does NOT merely assert that scriptSig/witness is
%% non-empty — it decodes the produced signed tx and runs it through the
%% impl's OWN script verifier (beamchain_script:verify_script/5) with the
%% correct BIP-143 SigChecker, proving the signature is GENUINE over the
%% real sighash.

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%%% ===================================================================
%%% Helpers
%%% ===================================================================

%% Build a mainnet-WIF (compressed) from a 32-byte private key. The
%% handler's wif_to_privkey accepts both 0x80 (mainnet) and 0xef
%% (testnet); the produced key is network-independent.
priv_to_wif(Priv) ->
    %% 0x80 prefix + 0x01 compression flag (matches rpc:privkey_to_wif).
    Wif = beamchain_address:base58check_encode(16#80, <<Priv/binary, 16#01>>),
    list_to_binary(Wif).

%% P2WPKH scriptPubKey for a 33-byte compressed pubkey.
p2wpkh_spk(PubKey) ->
    PkHash = beamchain_crypto:hash160(PubKey),
    <<16#00, 16#14, PkHash/binary>>.

hex(Bin) -> beamchain_serialize:hex_encode(Bin).

%% Display-order (reversed) hex of an internal 32-byte hash — what the
%% prevtxs `txid` field must contain (Core/RPC display order).
display_txid(InternalHash) ->
    beamchain_serialize:hex_encode(
        beamchain_serialize:reverse_bytes(InternalHash)).

%% An unsigned single-input tx spending `PrevHash`:`PrevIdx`, paying to a
%% throwaway P2WPKH output.
unsigned_tx(PrevHash, PrevIdx, OutValue) ->
    #transaction{
        version = 2,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = PrevHash, index = PrevIdx},
            script_sig = <<>>,
            sequence = 16#fffffffd,
            witness = []}],
        outputs = [#tx_out{
            value = OutValue,
            script_pubkey = <<16#00, 16#14,
                              (crypto:strong_rand_bytes(20))/binary>>}],
        locktime = 0
    }.

%% Ensure the sig_cache ETS tables + nonce exist so the script verifier's
%% ecdsa_verify_cached path does not crash in a bare eunit context (in
%% production beamchain_sig_cache:init/1 creates these). Idempotent; same
%% helper used by script_vectors_tests.
ensure_sig_cache() ->
    case persistent_term:get(beamchain_sig_cache_nonce, undefined) of
        undefined ->
            persistent_term:put(beamchain_sig_cache_nonce,
                                crypto:strong_rand_bytes(32));
        _ -> ok
    end,
    try ets:info(beamchain_sig_cache_tab, size) of
        undefined ->
            ets:new(beamchain_sig_cache_tab, [set, public, named_table,
                                              {read_concurrency, true}]),
            ets:new(beamchain_sig_cache_order,
                    [ordered_set, public, named_table]);
        _ -> ok
    catch
        _:_ ->
            ets:new(beamchain_sig_cache_tab, [set, public, named_table,
                                              {read_concurrency, true}]),
            ets:new(beamchain_sig_cache_order,
                    [ordered_set, public, named_table])
    end.

%% Run a decoded signed P2WPKH input through the impl's REAL script
%% verifier. Returns true/false. SigChecker = {Tx, Idx, Amount} is the
%% same shape verify_tx_scripts uses for BIP-143 v0 sighash.
verify_p2wpkh_input(SignedTx, Idx, ScriptPubKey, Amount) ->
    Input = lists:nth(Idx + 1, SignedTx#transaction.inputs),
    Witness = Input#tx_in.witness,
    Flags = ?SCRIPT_VERIFY_P2SH bor ?SCRIPT_VERIFY_WITNESS bor
            ?SCRIPT_VERIFY_STRICTENC,
    SigChecker = {SignedTx, Idx, Amount},
    beamchain_script:verify_script(<<>>, ScriptPubKey, Witness,
                                   Flags, SigChecker).

%%% ===================================================================
%%% Tests
%%% ===================================================================

%% (a) {hex, complete:true} for a fully-signed single-input P2WPKH tx, and
%% (b) the produced signature VERIFIES through the impl's own verifier.
sign_p2wpkh_complete_and_verifies_test() ->
    ensure_sig_cache(),
    Priv = crypto:strong_rand_bytes(32),
    {ok, PubKey} = beamchain_crypto:pubkey_from_privkey(Priv),
    ScriptPubKey = p2wpkh_spk(PubKey),
    Amount = 100000,
    PrevHash = crypto:strong_rand_bytes(32),
    PrevIdx = 0,
    Tx = unsigned_tx(PrevHash, PrevIdx, 99000),
    RawHex = hex(beamchain_serialize:encode_transaction(Tx)),
    Wif = priv_to_wif(Priv),
    PrevTxs = [#{<<"txid">> => display_txid(PrevHash),
                 <<"vout">> => PrevIdx,
                 <<"scriptPubKey">> => hex(ScriptPubKey),
                 <<"amount">> => satoshi_to_btc(Amount)}],
    {ok, Result} =
        beamchain_rpc:rpc_signrawtransactionwithkey([RawHex, [Wif], PrevTxs]),
    %% (a) shape: complete=true, no errors[] key.
    ?assertEqual(true, maps:get(<<"complete">>, Result)),
    ?assertNot(maps:is_key(<<"errors">>, Result)),
    SignedHex = maps:get(<<"hex">>, Result),
    ?assert(is_binary(SignedHex)),
    %% (b) GENUINE-signature check: decode + run the impl's verifier.
    {SignedTx, _} = beamchain_serialize:decode_transaction(
        beamchain_serialize:hex_decode(SignedHex)),
    SignedIn = hd(SignedTx#transaction.inputs),
    ?assertEqual(2, length(SignedIn#tx_in.witness)),   %% [sig, pubkey]
    ?assertEqual(true,
        verify_p2wpkh_input(SignedTx, 0, ScriptPubKey, Amount)).

%% Negative-control: corrupting the signature must FAIL the verifier — proves
%% the verify path in the test above is non-vacuous (not rubber-stamping).
verify_path_is_non_vacuous_test() ->
    ensure_sig_cache(),
    Priv = crypto:strong_rand_bytes(32),
    {ok, PubKey} = beamchain_crypto:pubkey_from_privkey(Priv),
    ScriptPubKey = p2wpkh_spk(PubKey),
    Amount = 100000,
    PrevHash = crypto:strong_rand_bytes(32),
    Tx = unsigned_tx(PrevHash, 0, 99000),
    RawHex = hex(beamchain_serialize:encode_transaction(Tx)),
    PrevTxs = [#{<<"txid">> => display_txid(PrevHash),
                 <<"vout">> => 0,
                 <<"scriptPubKey">> => hex(ScriptPubKey),
                 <<"amount">> => satoshi_to_btc(Amount)}],
    {ok, Result} = beamchain_rpc:rpc_signrawtransactionwithkey(
        [RawHex, [priv_to_wif(Priv)], PrevTxs]),
    {SignedTx, _} = beamchain_serialize:decode_transaction(
        beamchain_serialize:hex_decode(maps:get(<<"hex">>, Result))),
    [Sig, WitPub] = (hd(SignedTx#transaction.inputs))#tx_in.witness,
    %% Flip one byte in the DER signature body (keep the trailing sighash
    %% byte) -> verifier must reject.
    SigBody = binary:part(Sig, 0, byte_size(Sig) - 1),
    HashByte = binary:last(Sig),
    <<First, Rest/binary>> = SigBody,
    BadSig = <<(First bxor 16#01), Rest/binary, HashByte>>,
    BadTx = SignedTx#transaction{
        inputs = [(hd(SignedTx#transaction.inputs))#tx_in{
            witness = [BadSig, WitPub]}]},
    ?assertEqual(false, verify_p2wpkh_input(BadTx, 0, ScriptPubKey, Amount)).

%% (c) A missing-key input -> complete:false + an errors[] entry.
%% Two inputs: input 0's key is provided (signs); input 1's key is NOT
%% provided (left unsigned + reported in errors[]).
missing_key_yields_incomplete_with_errors_test() ->
    ensure_sig_cache(),
    PrivHave = crypto:strong_rand_bytes(32),
    PrivMissing = crypto:strong_rand_bytes(32),
    {ok, PubHave} = beamchain_crypto:pubkey_from_privkey(PrivHave),
    {ok, PubMissing} = beamchain_crypto:pubkey_from_privkey(PrivMissing),
    SpkHave = p2wpkh_spk(PubHave),
    SpkMissing = p2wpkh_spk(PubMissing),
    AmtHave = 100000,
    AmtMissing = 80000,
    PrevHash0 = crypto:strong_rand_bytes(32),
    PrevHash1 = crypto:strong_rand_bytes(32),
    Tx = #transaction{
        version = 2,
        inputs = [
            #tx_in{prev_out = #outpoint{hash = PrevHash0, index = 0},
                   script_sig = <<>>, sequence = 16#fffffffd, witness = []},
            #tx_in{prev_out = #outpoint{hash = PrevHash1, index = 1},
                   script_sig = <<>>, sequence = 16#fffffffd, witness = []}
        ],
        outputs = [#tx_out{value = 170000,
            script_pubkey = <<16#00, 16#14,
                              (crypto:strong_rand_bytes(20))/binary>>}],
        locktime = 0
    },
    RawHex = hex(beamchain_serialize:encode_transaction(Tx)),
    PrevTxs = [
        #{<<"txid">> => display_txid(PrevHash0), <<"vout">> => 0,
          <<"scriptPubKey">> => hex(SpkHave),
          <<"amount">> => satoshi_to_btc(AmtHave)},
        #{<<"txid">> => display_txid(PrevHash1), <<"vout">> => 1,
          <<"scriptPubKey">> => hex(SpkMissing),
          <<"amount">> => satoshi_to_btc(AmtMissing)}
    ],
    %% Only PrivHave is supplied — input 1 cannot be signed.
    {ok, Result} = beamchain_rpc:rpc_signrawtransactionwithkey(
        [RawHex, [priv_to_wif(PrivHave)], PrevTxs]),
    ?assertEqual(false, maps:get(<<"complete">>, Result)),
    ?assert(maps:is_key(<<"errors">>, Result)),
    Errors = maps:get(<<"errors">>, Result),
    ?assertEqual(1, length(Errors)),
    [ErrEntry] = Errors,
    %% errors[] entry has the full Core TxInErrorToJSON shape.
    ?assertEqual(display_txid(PrevHash1), maps:get(<<"txid">>, ErrEntry)),
    ?assertEqual(1, maps:get(<<"vout">>, ErrEntry)),
    ?assertEqual(16#fffffffd, maps:get(<<"sequence">>, ErrEntry)),
    ?assert(maps:is_key(<<"witness">>, ErrEntry)),
    ?assert(maps:is_key(<<"scriptSig">>, ErrEntry)),
    ?assert(is_binary(maps:get(<<"error">>, ErrEntry))),
    %% The signed input (0) must still verify genuinely.
    {SignedTx, _} = beamchain_serialize:decode_transaction(
        beamchain_serialize:hex_decode(maps:get(<<"hex">>, Result))),
    ?assertEqual(true,
        verify_p2wpkh_input(SignedTx, 0, SpkHave, AmtHave)),
    %% The unsigned input (1) must have an empty witness.
    In1 = lists:nth(2, SignedTx#transaction.inputs),
    ?assertEqual([], In1#tx_in.witness),
    ?assertEqual(<<>>, In1#tx_in.script_sig).

%% Invalid params -> RPC_INVALID_PARAMS (-32602) error.
bad_params_test() ->
    ?assertMatch({error, -32602, _},
        beamchain_rpc:rpc_signrawtransactionwithkey([<<"deadbeef">>])).

%%% ===================================================================
%%% Local helpers
%%% ===================================================================

%% Satoshi -> BTC float (the prevtxs `amount` field is in BTC, decoded by
%% rpc:btc_to_satoshi). 100000 sat = 0.001 BTC.
satoshi_to_btc(Sat) -> Sat / 100000000.
