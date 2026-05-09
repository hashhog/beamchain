-module(beamchain_psbt).

%% BIP 174 Partially Signed Bitcoin Transactions (PSBT)
%%
%% Reference: Bitcoin Core /src/psbt.cpp
%% https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% Public API
-export([create/1,
         update/2,
         sign/2,
         combine/1,
         finalize/1,
         extract/1]).

%% Serialization
-export([encode/1, decode/1]).

%% Utility
-export([get_unsigned_tx/1,
         get_version/1,
         get_input/2,
         get_output/2,
         set_input/3,
         set_output/3]).

%%% -------------------------------------------------------------------
%%% PSBT Constants (BIP 174)
%%% -------------------------------------------------------------------

%% Magic bytes: "psbt" + 0xff
-define(PSBT_MAGIC, <<16#70, 16#73, 16#62, 16#74, 16#ff>>).

%% Global key types
-define(PSBT_GLOBAL_UNSIGNED_TX, 16#00).
-define(PSBT_GLOBAL_XPUB,        16#01).
-define(PSBT_GLOBAL_VERSION,     16#fb).
-define(PSBT_GLOBAL_PROPRIETARY, 16#fc).

%% Input key types
-define(PSBT_IN_NON_WITNESS_UTXO,    16#00).
-define(PSBT_IN_WITNESS_UTXO,        16#01).
-define(PSBT_IN_PARTIAL_SIG,         16#02).
-define(PSBT_IN_SIGHASH_TYPE,        16#03).
-define(PSBT_IN_REDEEM_SCRIPT,       16#04).
-define(PSBT_IN_WITNESS_SCRIPT,      16#05).
-define(PSBT_IN_BIP32_DERIVATION,    16#06).
-define(PSBT_IN_FINAL_SCRIPTSIG,     16#07).
-define(PSBT_IN_FINAL_SCRIPTWITNESS, 16#08).
-define(PSBT_IN_RIPEMD160,           16#0a).
-define(PSBT_IN_SHA256,              16#0b).
-define(PSBT_IN_HASH160,             16#0c).
-define(PSBT_IN_HASH256,             16#0d).
-define(PSBT_IN_TAP_KEY_SIG,         16#13).
-define(PSBT_IN_TAP_SCRIPT_SIG,      16#14).
-define(PSBT_IN_TAP_LEAF_SCRIPT,     16#15).
-define(PSBT_IN_TAP_BIP32_DERIVATION, 16#16).
-define(PSBT_IN_TAP_INTERNAL_KEY,    16#17).
-define(PSBT_IN_TAP_MERKLE_ROOT,     16#18).
-define(PSBT_IN_PROPRIETARY,         16#fc).

%% Output key types
-define(PSBT_OUT_REDEEM_SCRIPT,       16#00).
-define(PSBT_OUT_WITNESS_SCRIPT,      16#01).
-define(PSBT_OUT_BIP32_DERIVATION,    16#02).
-define(PSBT_OUT_TAP_INTERNAL_KEY,    16#05).
-define(PSBT_OUT_TAP_TREE,            16#06).
-define(PSBT_OUT_TAP_BIP32_DERIVATION, 16#07).
-define(PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS, 16#08).
-define(PSBT_OUT_PROPRIETARY,         16#fc).

%%% -------------------------------------------------------------------
%%% PSBT record
%%% -------------------------------------------------------------------

-record(psbt, {
    %% The unsigned transaction (inputs have empty scriptSigs, no witness)
    unsigned_tx :: #transaction{},
    %% Global xpubs: #{xpub_binary => {fingerprint, path}}
    xpubs = #{} :: map(),
    %% Global version (default 0)
    version = 0 :: non_neg_integer(),
    %% Global unknown/proprietary key-value pairs
    global_unknown = #{} :: map(),
    %% Per-input data: list of maps
    inputs = [] :: [map()],
    %% Per-output data: list of maps
    outputs = [] :: [map()]
}).

-export_type([psbt/0]).
-type psbt() :: #psbt{}.

%%% ===================================================================
%%% Public API
%%% ===================================================================

%% @doc Create a new PSBT from an unsigned transaction.
%% The transaction must have empty scriptSigs and no witness data.
-spec create(#transaction{}) -> {ok, #psbt{}} | {error, term()}.
create(#transaction{inputs = Inputs, outputs = Outputs} = Tx) ->
    %% Verify transaction is unsigned (empty scriptSigs, empty witnesses)
    case verify_unsigned_tx(Tx) of
        ok ->
            NumInputs = length(Inputs),
            NumOutputs = length(Outputs),
            Psbt = #psbt{
                unsigned_tx = Tx,
                inputs = [#{} || _ <- lists:seq(1, NumInputs)],
                outputs = [#{} || _ <- lists:seq(1, NumOutputs)]
            },
            {ok, Psbt};
        {error, _} = Err ->
            Err
    end.

%% @doc Update a PSBT with UTXO info, scripts, and derivation paths.
%% Updates is a list of {input_index, UpdateMap} or {output_index, UpdateMap}.
-spec update(#psbt{}, [{input | output, non_neg_integer(), map()}]) ->
    {ok, #psbt{}} | {error, term()}.
update(Psbt, []) ->
    {ok, Psbt};
update(Psbt, [{input, Index, Updates} | Rest]) ->
    case Index < length(Psbt#psbt.inputs) of
        true ->
            InputMap = lists:nth(Index + 1, Psbt#psbt.inputs),
            NewInputMap = maps:merge(InputMap, Updates),
            NewInputs = replace_nth(Index + 1, NewInputMap, Psbt#psbt.inputs),
            update(Psbt#psbt{inputs = NewInputs}, Rest);
        false ->
            {error, {invalid_input_index, Index}}
    end;
update(Psbt, [{output, Index, Updates} | Rest]) ->
    case Index < length(Psbt#psbt.outputs) of
        true ->
            OutputMap = lists:nth(Index + 1, Psbt#psbt.outputs),
            NewOutputMap = maps:merge(OutputMap, Updates),
            NewOutputs = replace_nth(Index + 1, NewOutputMap, Psbt#psbt.outputs),
            update(Psbt#psbt{outputs = NewOutputs}, Rest);
        false ->
            {error, {invalid_output_index, Index}}
    end.

%% @doc Sign a PSBT with the given private keys.
%% SigningData is a list of {InputIndex, PrivKey} pairs.
%% Returns the PSBT with partial signatures added.
-spec sign(#psbt{}, [{non_neg_integer(), binary()}]) -> {ok, #psbt{}}.
sign(Psbt, SigningData) ->
    Tx = Psbt#psbt.unsigned_tx,
    NewPsbt = lists:foldl(fun({InputIndex, PrivKey}, Acc) ->
        sign_input(Acc, Tx, InputIndex, PrivKey)
    end, Psbt, SigningData),
    {ok, NewPsbt}.

%% @doc Combine multiple PSBTs for the same transaction.
%% Merges partial signatures and other data.
-spec combine([#psbt{}]) -> {ok, #psbt{}} | {error, term()}.
combine([]) ->
    {error, empty_list};
combine([First]) ->
    {ok, First};
combine([First | Rest]) ->
    %% Verify all PSBTs have the same unsigned tx
    FirstTxId = tx_hash(First#psbt.unsigned_tx),
    case lists:all(fun(P) ->
        tx_hash(P#psbt.unsigned_tx) =:= FirstTxId
    end, Rest) of
        true ->
            Combined = lists:foldl(fun merge_psbt/2, First, Rest),
            {ok, Combined};
        false ->
            {error, transaction_mismatch}
    end.

%% @doc Finalize a PSBT by assembling scriptSig and witness from partial data.
%% Returns the finalized PSBT (with final_script_sig and final_script_witness set).
-spec finalize(#psbt{}) -> {ok, #psbt{}} | {error, term()}.
finalize(Psbt) ->
    try
        Tx = Psbt#psbt.unsigned_tx,
        %% W41: thread the spending TxIn through finalize_input so
        %% do_finalize_input can run the same Bug A1/A2 consistency
        %% checks as sign/build_prevouts (otherwise an attacker who
        %% controls the updater could finalise a forged prev-tx
        %% combination that we rejected at sign-time).
        NewInputs = lists:zipwith(fun(Input, InputMap) ->
            finalize_input(InputMap, Input)
        end, Tx#transaction.inputs, Psbt#psbt.inputs),
        {ok, Psbt#psbt{inputs = NewInputs}}
    catch
        throw:{finalize_error, Reason} ->
            {error, Reason}
    end.

%% @doc Extract the final signed transaction from a finalized PSBT.
-spec extract(#psbt{}) -> {ok, #transaction{}} | {error, term()}.
extract(#psbt{unsigned_tx = Tx, inputs = InputMaps}) ->
    try
        FinalInputs = lists:zipwith(fun(Input, InputMap) ->
            case {maps:get(final_script_sig, InputMap, undefined),
                  maps:get(final_script_witness, InputMap, undefined)} of
                {undefined, undefined} ->
                    throw({extract_error, input_not_finalized});
                {ScriptSig, Witness} ->
                    FinalScriptSig = case ScriptSig of
                        undefined -> <<>>;
                        _ -> ScriptSig
                    end,
                    FinalWitness = case Witness of
                        undefined -> [];
                        _ -> Witness
                    end,
                    Input#tx_in{script_sig = FinalScriptSig,
                                witness = FinalWitness}
            end
        end, Tx#transaction.inputs, InputMaps),
        {ok, Tx#transaction{inputs = FinalInputs}}
    catch
        throw:{extract_error, Reason} ->
            {error, Reason}
    end.

%%% ===================================================================
%%% Serialization
%%% ===================================================================

%% @doc Encode a PSBT to its binary format.
-spec encode(#psbt{}) -> binary().
encode(#psbt{unsigned_tx = Tx, xpubs = XPubs, version = Version,
             global_unknown = GlobalUnknown, inputs = Inputs,
             outputs = Outputs}) ->
    %% Global map
    GlobalKVs = encode_global(Tx, XPubs, Version, GlobalUnknown),
    %% Input maps
    InputKVs = [encode_input_map(I) || I <- Inputs],
    %% Output maps
    OutputKVs = [encode_output_map(O) || O <- Outputs],
    iolist_to_binary([?PSBT_MAGIC, GlobalKVs | InputKVs ++ OutputKVs]).

%% @doc Decode a PSBT from its binary format.
-spec decode(binary()) -> {ok, #psbt{}} | {error, term()}.
decode(<<16#70, 16#73, 16#62, 16#74, 16#ff, Rest/binary>>) ->
    try
        {GlobalPairs, Rest1} = decode_map(Rest),
        {Tx, XPubs, Version, GlobalUnknown} = parse_global(GlobalPairs),
        NumInputs = length(Tx#transaction.inputs),
        NumOutputs = length(Tx#transaction.outputs),
        {InputMaps, Rest2} = decode_n_maps(Rest1, NumInputs),
        {OutputMaps, _Rest3} = decode_n_maps(Rest2, NumOutputs),
        Inputs = [parse_input_map(M) || M <- InputMaps],
        Outputs = [parse_output_map(M) || M <- OutputMaps],
        {ok, #psbt{
            unsigned_tx = Tx,
            xpubs = XPubs,
            version = Version,
            global_unknown = GlobalUnknown,
            inputs = Inputs,
            outputs = Outputs
        }}
    catch
        throw:{decode_error, Reason} ->
            {error, Reason};
        error:Reason ->
            {error, {decode_failed, Reason}}
    end;
decode(_) ->
    {error, invalid_magic}.

%%% ===================================================================
%%% Utility functions
%%% ===================================================================

%% @doc Get the unsigned transaction from a PSBT.
-spec get_unsigned_tx(#psbt{}) -> #transaction{}.
get_unsigned_tx(#psbt{unsigned_tx = Tx}) -> Tx.

%% @doc Get the PSBT version.
-spec get_version(#psbt{}) -> non_neg_integer().
get_version(#psbt{version = V}) -> V.

%% @doc Get input data at the given index.
-spec get_input(#psbt{}, non_neg_integer()) -> map() | undefined.
get_input(#psbt{inputs = Inputs}, Index) when Index < length(Inputs) ->
    lists:nth(Index + 1, Inputs);
get_input(_, _) ->
    undefined.

%% @doc Get output data at the given index.
-spec get_output(#psbt{}, non_neg_integer()) -> map() | undefined.
get_output(#psbt{outputs = Outputs}, Index) when Index < length(Outputs) ->
    lists:nth(Index + 1, Outputs);
get_output(_, _) ->
    undefined.

%% @doc Set input data at the given index.
-spec set_input(#psbt{}, non_neg_integer(), map()) -> #psbt{}.
set_input(#psbt{inputs = Inputs} = Psbt, Index, InputMap)
  when Index < length(Inputs) ->
    NewInputs = replace_nth(Index + 1, InputMap, Inputs),
    Psbt#psbt{inputs = NewInputs}.

%% @doc Set output data at the given index.
-spec set_output(#psbt{}, non_neg_integer(), map()) -> #psbt{}.
set_output(#psbt{outputs = Outputs} = Psbt, Index, OutputMap)
  when Index < length(Outputs) ->
    NewOutputs = replace_nth(Index + 1, OutputMap, Outputs),
    Psbt#psbt{outputs = NewOutputs}.

%%% ===================================================================
%%% Internal: Global map encoding/decoding
%%% ===================================================================

encode_global(Tx, XPubs, Version, Unknown) ->
    %% Unsigned transaction (required)
    TxBin = beamchain_serialize:encode_transaction(Tx, no_witness),
    TxKV = encode_kv(<<?PSBT_GLOBAL_UNSIGNED_TX>>, TxBin),
    %% XPubs (optional)
    XPubKVs = maps:fold(fun(XPub, {Fingerprint, Path}, Acc) ->
        PathBin = encode_bip32_path(Fingerprint, Path),
        [encode_kv(<<?PSBT_GLOBAL_XPUB, XPub/binary>>, PathBin) | Acc]
    end, [], XPubs),
    %% Version (only if > 0)
    VersionKV = case Version of
        0 -> [];
        V -> [encode_kv(<<?PSBT_GLOBAL_VERSION>>, <<V:32/little>>)]
    end,
    %% Unknown/proprietary
    UnknownKVs = maps:fold(fun(Key, Value, Acc) ->
        [encode_kv(Key, Value) | Acc]
    end, [], Unknown),
    %% Separator
    iolist_to_binary([TxKV | XPubKVs] ++ VersionKV ++ UnknownKVs ++ [<<0>>]).

parse_global(Pairs) ->
    parse_global(Pairs, undefined, #{}, 0, #{}).

parse_global([], Tx, XPubs, Version, Unknown) ->
    case Tx of
        undefined ->
            throw({decode_error, missing_unsigned_tx});
        _ ->
            {Tx, XPubs, Version, Unknown}
    end;
parse_global([{<<?PSBT_GLOBAL_UNSIGNED_TX>>, Value} | Rest], _, XPubs, Ver, Unk) ->
    {Tx, <<>>} = beamchain_serialize:decode_transaction(Value),
    parse_global(Rest, Tx, XPubs, Ver, Unk);
parse_global([{<<?PSBT_GLOBAL_XPUB, XPub/binary>>, Value} | Rest], Tx, XPubs, Ver, Unk) ->
    {Fingerprint, Path} = decode_bip32_path(Value),
    parse_global(Rest, Tx, XPubs#{XPub => {Fingerprint, Path}}, Ver, Unk);
parse_global([{<<?PSBT_GLOBAL_VERSION>>, <<V:32/little>>} | Rest], Tx, XPubs, _, Unk) ->
    parse_global(Rest, Tx, XPubs, V, Unk);
parse_global([{Key, Value} | Rest], Tx, XPubs, Ver, Unk) ->
    %% Unknown key type
    parse_global(Rest, Tx, XPubs, Ver, Unk#{Key => Value}).

%%% ===================================================================
%%% Internal: Input map encoding/decoding
%%% ===================================================================

encode_input_map(InputMap) ->
    %% W46: BIP-174 / Core `psbt.h` SerializeInput gates the producer
    %% fields (partial_sigs, sighash_type, redeem_script, witness_script,
    %% bip32_derivation, tap_*) behind
    %%     if (final_script_sig.empty() && final_script_witness.IsNull())
    %% so a finalized input never re-emits hundreds of bytes of producer
    %% state. Without this gate, finalize+encode leaked drift vs. Core on
    %% every multi-sig path (W42-A diagnostic, same shape as W41 lunarblock).
    Finalized = is_input_finalized(InputMap),
    ProducerKVs = case Finalized of
        true ->
            [];
        false ->
            [
                %% Partial signatures — Core sorts std::map<CKeyID, SigPair>
                %% by HASH160(pubkey) on the wire. W46.
                case maps:get(partial_sigs, InputMap, undefined) of
                    undefined -> [];
                    Sigs ->
                        SortedSigs = sort_partial_sigs_by_keyid(Sigs),
                        [encode_kv(<<?PSBT_IN_PARTIAL_SIG, PK/binary>>, S)
                         || {PK, S} <- SortedSigs]
                end,
                %% Sighash type
                case maps:get(sighash_type, InputMap, undefined) of
                    undefined -> [];
                    SigHash ->
                        [encode_kv(<<?PSBT_IN_SIGHASH_TYPE>>, <<SigHash:32/little>>)]
                end,
                %% Redeem script
                case maps:get(redeem_script, InputMap, undefined) of
                    undefined -> [];
                    RS -> [encode_kv(<<?PSBT_IN_REDEEM_SCRIPT>>, RS)]
                end,
                %% Witness script
                case maps:get(witness_script, InputMap, undefined) of
                    undefined -> [];
                    WS -> [encode_kv(<<?PSBT_IN_WITNESS_SCRIPT>>, WS)]
                end,
                %% BIP32 derivation paths — Core sorts
                %% std::map<CPubKey, KeyOriginInfo> by raw pubkey bytes. W46.
                case maps:get(bip32_derivation, InputMap, undefined) of
                    undefined -> [];
                    Derivs ->
                        Sorted = lists:keysort(1, maps:to_list(Derivs)),
                        [begin
                             PathBin = encode_bip32_path(FP, P),
                             encode_kv(<<?PSBT_IN_BIP32_DERIVATION, PubKey/binary>>, PathBin)
                         end || {PubKey, {FP, P}} <- Sorted]
                end,
                %% Taproot key signature (producer field per BIP-371)
                case maps:get(tap_key_sig, InputMap, undefined) of
                    undefined -> [];
                    TKS -> [encode_kv(<<?PSBT_IN_TAP_KEY_SIG>>, TKS)]
                end,
                %% Taproot internal key (producer field per BIP-371)
                case maps:get(tap_internal_key, InputMap, undefined) of
                    undefined -> [];
                    TIK -> [encode_kv(<<?PSBT_IN_TAP_INTERNAL_KEY>>, TIK)]
                end
            ]
    end,
    KVs = lists:flatten([
        %% Non-witness UTXO (retained per BIP-174 even after finalize)
        case maps:get(non_witness_utxo, InputMap, undefined) of
            undefined -> [];
            NwUtxo ->
                TxBin = beamchain_serialize:encode_transaction(NwUtxo, no_witness),
                [encode_kv(<<?PSBT_IN_NON_WITNESS_UTXO>>, TxBin)]
        end,
        %% Witness UTXO (retained per BIP-174 even after finalize)
        case maps:get(witness_utxo, InputMap, undefined) of
            undefined -> [];
            {Value, ScriptPubKey} ->
                UtxoBin = encode_witness_utxo(Value, ScriptPubKey),
                [encode_kv(<<?PSBT_IN_WITNESS_UTXO>>, UtxoBin)]
        end,
        ProducerKVs,
        %% Final scriptSig
        case maps:get(final_script_sig, InputMap, undefined) of
            undefined -> [];
            FSS -> [encode_kv(<<?PSBT_IN_FINAL_SCRIPTSIG>>, FSS)]
        end,
        %% Final witness
        case maps:get(final_script_witness, InputMap, undefined) of
            undefined -> [];
            FSW -> [encode_kv(<<?PSBT_IN_FINAL_SCRIPTWITNESS>>, encode_witness_stack(FSW))]
        end,
        %% Unknown keys
        case maps:get(unknown, InputMap, undefined) of
            undefined -> [];
            Unk ->
                maps:fold(fun(K, V, Acc) ->
                    [encode_kv(K, V) | Acc]
                end, [], Unk)
        end
    ]),
    iolist_to_binary(KVs ++ [<<0>>]).

%% W46: shared finalized-detector. Same predicate as `finalize_input/2`
%% (lines 861-869) — once either final_script_sig or final_script_witness
%% is set, the producer fields must not appear on the wire.
is_input_finalized(InputMap) ->
    maps:is_key(final_script_sig, InputMap) orelse
    maps:is_key(final_script_witness, InputMap).

%% W46: sort partial_sigs by HASH160(pubkey). Core uses
%% std::map<CKeyID, SigPair> where CKeyID = HASH160(CPubKey), so the
%% wire-order is keyed by HASH160 even though the wire-key bytes are the
%% raw pubkey. Reference: bitcoin-core/src/psbt.h:270 and the iteration
%% at psbt.h:315.
sort_partial_sigs_by_keyid(Sigs) ->
    Tagged = [{beamchain_crypto:hash160(PK), PK, S}
              || {PK, S} <- maps:to_list(Sigs)],
    Sorted = lists:keysort(1, Tagged),
    [{PK, S} || {_KeyID, PK, S} <- Sorted].

parse_input_map(Pairs) ->
    parse_input_pairs(Pairs, #{}).

parse_input_pairs([], Acc) ->
    Acc;
parse_input_pairs([{<<?PSBT_IN_NON_WITNESS_UTXO>>, Value} | Rest], Acc) ->
    {Tx, <<>>} = beamchain_serialize:decode_transaction(Value),
    parse_input_pairs(Rest, Acc#{non_witness_utxo => Tx});
parse_input_pairs([{<<?PSBT_IN_WITNESS_UTXO>>, Value} | Rest], Acc) ->
    {UtxoValue, ScriptPubKey} = decode_witness_utxo(Value),
    parse_input_pairs(Rest, Acc#{witness_utxo => {UtxoValue, ScriptPubKey}});
parse_input_pairs([{<<?PSBT_IN_PARTIAL_SIG, PubKey/binary>>, Sig} | Rest], Acc) ->
    Sigs = maps:get(partial_sigs, Acc, #{}),
    parse_input_pairs(Rest, Acc#{partial_sigs => Sigs#{PubKey => Sig}});
parse_input_pairs([{<<?PSBT_IN_SIGHASH_TYPE>>, <<SigHash:32/little>>} | Rest], Acc) ->
    parse_input_pairs(Rest, Acc#{sighash_type => SigHash});
parse_input_pairs([{<<?PSBT_IN_REDEEM_SCRIPT>>, RS} | Rest], Acc) ->
    parse_input_pairs(Rest, Acc#{redeem_script => RS});
parse_input_pairs([{<<?PSBT_IN_WITNESS_SCRIPT>>, WS} | Rest], Acc) ->
    parse_input_pairs(Rest, Acc#{witness_script => WS});
parse_input_pairs([{<<?PSBT_IN_BIP32_DERIVATION, PubKey/binary>>, PathData} | Rest], Acc) ->
    {Fingerprint, Path} = decode_bip32_path(PathData),
    Derivs = maps:get(bip32_derivation, Acc, #{}),
    parse_input_pairs(Rest, Acc#{bip32_derivation => Derivs#{PubKey => {Fingerprint, Path}}});
parse_input_pairs([{<<?PSBT_IN_FINAL_SCRIPTSIG>>, FSS} | Rest], Acc) ->
    parse_input_pairs(Rest, Acc#{final_script_sig => FSS});
parse_input_pairs([{<<?PSBT_IN_FINAL_SCRIPTWITNESS>>, FSW} | Rest], Acc) ->
    Witness = decode_witness_stack(FSW),
    parse_input_pairs(Rest, Acc#{final_script_witness => Witness});
parse_input_pairs([{<<?PSBT_IN_TAP_KEY_SIG>>, TKS} | Rest], Acc) ->
    parse_input_pairs(Rest, Acc#{tap_key_sig => TKS});
%% PSBT_IN_TAP_SCRIPT_SIG (0x14): key = type(1) + xonly(32) + leaf_hash(32)
%%   value = Schnorr signature.  Stored as map {xonly_pubkey, leaf_hash} => sig.
parse_input_pairs([{<<16#14, XOnly:32/binary, LeafHash:32/binary>>, Sig} | Rest], Acc) ->
    Sigs = maps:get(tap_script_sigs, Acc, #{}),
    parse_input_pairs(Rest, Acc#{tap_script_sigs => Sigs#{{XOnly, LeafHash} => Sig}});
%% PSBT_IN_TAP_LEAF_SCRIPT (0x15): key = type(1) + control_block
%%   value = script || leaf_version (last byte).
%%   Stored as map control_block => {script, leaf_ver}.
parse_input_pairs([{<<16#15, ControlBlock/binary>>, LeafData} | Rest], Acc) ->
    DataLen = byte_size(LeafData),
    {Script, LeafVer} = case DataLen >= 1 of
        true ->
            SLen = DataLen - 1,
            <<S:SLen/binary, LV>> = LeafData,
            {S, LV};
        false ->
            {<<>>, 16#c0}
    end,
    Leafs = maps:get(tap_leaf_scripts, Acc, #{}),
    parse_input_pairs(Rest, Acc#{tap_leaf_scripts => Leafs#{ControlBlock => {Script, LeafVer}}});
%% PSBT_IN_TAP_BIP32_DERIVATION (0x16): key = type(1) + xonly(32)
%%   value = leaf_hash_count(varint) + leaf_hashes(32B each) + fingerprint(4B) + path.
%%   Stored as map xonly => {fingerprint, path, leaf_hashes}.
parse_input_pairs([{<<16#16, XOnly:32/binary>>, Value} | Rest], Acc) ->
    {NLeaves, Rest1} = beamchain_serialize:decode_varint(Value),
    <<LeafHashesBin:(NLeaves * 32)/binary, PathData/binary>> = Rest1,
    LeafHashes = [LH || <<LH:32/binary>> <= LeafHashesBin],
    {Fingerprint, Path} = decode_bip32_path(PathData),
    Derivs = maps:get(tap_bip32_derivation, Acc, #{}),
    parse_input_pairs(Rest, Acc#{tap_bip32_derivation =>
        Derivs#{XOnly => {Fingerprint, Path, LeafHashes}}});
parse_input_pairs([{<<?PSBT_IN_TAP_INTERNAL_KEY>>, TIK} | Rest], Acc) ->
    parse_input_pairs(Rest, Acc#{tap_internal_key => TIK});
parse_input_pairs([{<<?PSBT_IN_TAP_MERKLE_ROOT>>, TMR} | Rest], Acc) ->
    parse_input_pairs(Rest, Acc#{tap_merkle_root => TMR});
parse_input_pairs([{Key, Value} | Rest], Acc) ->
    %% Unknown key type - preserve it
    Unk = maps:get(unknown, Acc, #{}),
    parse_input_pairs(Rest, Acc#{unknown => Unk#{Key => Value}}).

%%% ===================================================================
%%% Internal: Output map encoding/decoding
%%% ===================================================================

encode_output_map(OutputMap) ->
    KVs = lists:flatten([
        %% Redeem script
        case maps:get(redeem_script, OutputMap, undefined) of
            undefined -> [];
            RS -> [encode_kv(<<?PSBT_OUT_REDEEM_SCRIPT>>, RS)]
        end,
        %% Witness script
        case maps:get(witness_script, OutputMap, undefined) of
            undefined -> [];
            WS -> [encode_kv(<<?PSBT_OUT_WITNESS_SCRIPT>>, WS)]
        end,
        %% BIP32 derivation paths
        case maps:get(bip32_derivation, OutputMap, undefined) of
            undefined -> [];
            Derivs ->
                maps:fold(fun(PubKey, {Fingerprint, Path}, Acc) ->
                    PathBin = encode_bip32_path(Fingerprint, Path),
                    [encode_kv(<<?PSBT_OUT_BIP32_DERIVATION, PubKey/binary>>, PathBin) | Acc]
                end, [], Derivs)
        end,
        %% Taproot internal key
        case maps:get(tap_internal_key, OutputMap, undefined) of
            undefined -> [];
            TIK -> [encode_kv(<<?PSBT_OUT_TAP_INTERNAL_KEY>>, TIK)]
        end,
        %% Unknown keys
        case maps:get(unknown, OutputMap, undefined) of
            undefined -> [];
            Unk ->
                maps:fold(fun(K, V, Acc) ->
                    [encode_kv(K, V) | Acc]
                end, [], Unk)
        end
    ]),
    iolist_to_binary(KVs ++ [<<0>>]).

parse_output_map(Pairs) ->
    parse_output_pairs(Pairs, #{}).

parse_output_pairs([], Acc) ->
    Acc;
parse_output_pairs([{<<?PSBT_OUT_REDEEM_SCRIPT>>, RS} | Rest], Acc) ->
    parse_output_pairs(Rest, Acc#{redeem_script => RS});
parse_output_pairs([{<<?PSBT_OUT_WITNESS_SCRIPT>>, WS} | Rest], Acc) ->
    parse_output_pairs(Rest, Acc#{witness_script => WS});
parse_output_pairs([{<<?PSBT_OUT_BIP32_DERIVATION, PubKey/binary>>, PathData} | Rest], Acc) ->
    {Fingerprint, Path} = decode_bip32_path(PathData),
    Derivs = maps:get(bip32_derivation, Acc, #{}),
    parse_output_pairs(Rest, Acc#{bip32_derivation => Derivs#{PubKey => {Fingerprint, Path}}});
parse_output_pairs([{<<?PSBT_OUT_TAP_INTERNAL_KEY>>, TIK} | Rest], Acc) ->
    parse_output_pairs(Rest, Acc#{tap_internal_key => TIK});
%% PSBT_OUT_TAP_TREE (0x06): key = type(1), value = sequence of
%%   (depth:1 + leaf_ver:1 + script_len:varint + script).
%%   Stored as list of {depth, leaf_ver, script} tuples in wire order.
parse_output_pairs([{<<?PSBT_OUT_TAP_TREE>>, Value} | Rest], Acc) ->
    Leaves = decode_tap_tree(Value, []),
    parse_output_pairs(Rest, Acc#{tap_tree => Leaves});
%% PSBT_OUT_TAP_BIP32_DERIVATION (0x07): key = type(1) + xonly(32)
%%   value = leaf_hash_count(varint) + leaf_hashes + fingerprint(4B) + path.
parse_output_pairs([{<<16#07, XOnly:32/binary>>, Value} | Rest], Acc) ->
    {NLeaves, Rest1} = beamchain_serialize:decode_varint(Value),
    <<LeafHashesBin:(NLeaves * 32)/binary, PathData/binary>> = Rest1,
    LeafHashes = [LH || <<LH:32/binary>> <= LeafHashesBin],
    {Fingerprint, Path} = decode_bip32_path(PathData),
    Derivs = maps:get(tap_bip32_derivation, Acc, #{}),
    parse_output_pairs(Rest, Acc#{tap_bip32_derivation =>
        Derivs#{XOnly => {Fingerprint, Path, LeafHashes}}});
%% PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS (0x08): key = type(1) + agg_pubkey(33)
%%   value = participant_pubkeys concatenated (33 bytes each).
parse_output_pairs([{<<16#08, AggPubKey:33/binary>>, Value} | Rest], Acc) ->
    ParticipantPubKeys = [PK || <<PK:33/binary>> <= Value],
    MuSig2 = maps:get(musig2_participant_pubkeys, Acc, #{}),
    parse_output_pairs(Rest, Acc#{musig2_participant_pubkeys =>
        MuSig2#{AggPubKey => ParticipantPubKeys}});
parse_output_pairs([{Key, Value} | Rest], Acc) ->
    %% Unknown key type - preserve it
    Unk = maps:get(unknown, Acc, #{}),
    parse_output_pairs(Rest, Acc#{unknown => Unk#{Key => Value}}).

%%% ===================================================================
%%% Internal: Signing
%%% ===================================================================

sign_input(Psbt, Tx, InputIndex, PrivKey) ->
    InputMap = lists:nth(InputIndex + 1, Psbt#psbt.inputs),
    Input = lists:nth(InputIndex + 1, Tx#transaction.inputs),
    %% W41 (Bug A1+A2): consistency-check NON_WITNESS_UTXO txid AND any
    %% (witness_utxo / non_witness_utxo) cross-disagreement before we
    %% feed an attacker-controlled (Value, ScriptPubKey) into the
    %% sighash. See get_utxo_info_checked/2 below + Core's
    %% PSBTInput::IsSane (psbt.cpp ~80, ~337, ~425). On mismatch we
    %% drop the input back unchanged rather than throwing — PSBT sign
    %% is best-effort across multiple inputs (matches the W31/W38
    %% verify_p2*_commitment pattern in sign_p2sh and the p2wsh arm).
    case get_utxo_info_checked(InputMap, Input) of
        {witness_utxo, Value, ScriptPubKey} ->
            sign_with_utxo(Psbt, Tx, InputIndex, InputMap, PrivKey, Value, ScriptPubKey);
        {non_witness_utxo, Value, ScriptPubKey} ->
            sign_with_utxo(Psbt, Tx, InputIndex, InputMap, PrivKey, Value, ScriptPubKey);
        {error, _Reason} ->
            %% Forged or inconsistent UTXO data — decline this input.
            Psbt;
        undefined ->
            %% Cannot sign without UTXO info
            Psbt
    end.

sign_with_utxo(Psbt, Tx, InputIndex, InputMap, PrivKey, Value, ScriptPubKey) ->
    PubKey = beamchain_wallet:privkey_to_pubkey(PrivKey),
    SigHashType = maps:get(sighash_type, InputMap, ?SIGHASH_ALL),

    NewInputMap = case beamchain_address:classify_script(ScriptPubKey) of
        p2wpkh ->
            %% Native P2WPKH
            PkHash = beamchain_crypto:hash160(PubKey),
            ScriptCode = <<16#76, 16#a9, 20, PkHash/binary, 16#88, 16#ac>>,
            SigHash = beamchain_script:sighash_witness_v0(
                Tx, InputIndex, ScriptCode, Value, SigHashType),
            {ok, DerSig} = beamchain_crypto:ecdsa_sign(SigHash, PrivKey),
            SigWithType = <<DerSig/binary, SigHashType>>,
            Sigs = maps:get(partial_sigs, InputMap, #{}),
            InputMap#{partial_sigs => Sigs#{PubKey => SigWithType}};

        p2pkh ->
            %% Legacy P2PKH
            PkHash = beamchain_crypto:hash160(PubKey),
            ScriptCode = <<16#76, 16#a9, 20, PkHash/binary, 16#88, 16#ac>>,
            SigHash = beamchain_script:sighash_legacy(
                Tx, InputIndex, ScriptCode, SigHashType),
            {ok, DerSig} = beamchain_crypto:ecdsa_sign(SigHash, PrivKey),
            SigWithType = <<DerSig/binary, SigHashType>>,
            Sigs = maps:get(partial_sigs, InputMap, #{}),
            InputMap#{partial_sigs => Sigs#{PubKey => SigWithType}};

        p2tr ->
            %% Taproot key path
            PrevOuts = build_prevouts(Psbt),
            %% Use SIGHASH_DEFAULT for taproot by default
            TapSigHashType = case SigHashType of
                ?SIGHASH_ALL -> ?SIGHASH_DEFAULT;
                Other -> Other
            end,
            SigHash = beamchain_script:sighash_taproot(
                Tx, InputIndex, PrevOuts, TapSigHashType,
                undefined, undefined, 16#ffffffff),
            TweakedPrivKey = beamchain_crypto:taproot_tweak_seckey(PrivKey),
            AuxRand = crypto:strong_rand_bytes(32),
            {ok, SchnorrSig} = beamchain_crypto:schnorr_sign(
                SigHash, TweakedPrivKey, AuxRand),
            %% For SIGHASH_DEFAULT, signature is 64 bytes (no suffix)
            %% For other types, append the sighash byte
            FinalSig = case TapSigHashType of
                ?SIGHASH_DEFAULT -> SchnorrSig;
                _ -> <<SchnorrSig/binary, TapSigHashType>>
            end,
            InputMap#{tap_key_sig => FinalSig};

        p2sh ->
            %% P2SH-wrapped - need redeem script
            case maps:get(redeem_script, InputMap, undefined) of
                undefined ->
                    %% Cannot sign without redeem script
                    InputMap;
                RedeemScript ->
                    sign_p2sh(Tx, InputIndex, InputMap, PrivKey, PubKey,
                              Value, RedeemScript, ScriptPubKey, SigHashType)
            end;

        p2wsh ->
            %% P2WSH - need witness script. W38: assert that
            %% sha256(witnessScript) matches the 32-byte witness
            %% program in the prevout's scriptPubKey before signing,
            %% mirroring the W31 P2SH-P2WSH inner-commitment idiom at
            %% sign_p2sh_verified/8 below. Without this the signer
            %% would happily emit a sig over any caller-supplied
            %% witness script. Decline (return InputMap unchanged) on
            %% mismatch — PSBT sign is best-effort across multiple
            %% inputs.
            case maps:get(witness_script, InputMap, undefined) of
                undefined ->
                    InputMap;
                WitnessScript ->
                    case ScriptPubKey of
                        <<16#00, 32, WitnessProg:32/binary>> ->
                            case beamchain_crypto:verify_p2wsh_commitment(
                                   WitnessScript, WitnessProg) of
                                ok ->
                                    SigHash = beamchain_script:sighash_witness_v0(
                                        Tx, InputIndex, WitnessScript, Value,
                                        SigHashType),
                                    {ok, DerSig} =
                                        beamchain_crypto:ecdsa_sign(
                                          SigHash, PrivKey),
                                    SigWithType =
                                        <<DerSig/binary, SigHashType>>,
                                    Sigs = maps:get(partial_sigs, InputMap, #{}),
                                    InputMap#{partial_sigs =>
                                        Sigs#{PubKey => SigWithType}};
                                {error, _} ->
                                    %% Forged witness script — decline.
                                    InputMap
                            end;
                        _ ->
                            %% scriptPubKey isn't a well-formed bare
                            %% P2WSH SPK (`OP_0 <32> H`); decline.
                            InputMap
                    end
            end;

        _ ->
            %% Unknown script type
            InputMap
    end,

    NewInputs = replace_nth(InputIndex + 1, NewInputMap, Psbt#psbt.inputs),
    Psbt#psbt{inputs = NewInputs}.

sign_p2sh(Tx, InputIndex, InputMap, PrivKey, PubKey, Value, RedeemScript,
          ScriptPubKey, SigHashType) ->
    %% W31: refuse to sign with a redeem script that doesn't commit to
    %% the prevout's P2SH hash. Skip the input rather than throw — PSBT
    %% sign is best-effort across multiple inputs, so a forged redeem
    %% script in one input shouldn't take down the whole signing pass.
    case beamchain_crypto:verify_p2sh_commitment(RedeemScript, ScriptPubKey) of
        ok ->
            sign_p2sh_verified(Tx, InputIndex, InputMap, PrivKey, PubKey,
                               Value, RedeemScript, SigHashType);
        {error, _Reason} ->
            %% Mismatch — drop the input back unchanged. Caller can
            %% inspect partial_sigs to see we declined.
            InputMap
    end.

sign_p2sh_verified(Tx, InputIndex, InputMap, PrivKey, PubKey, Value,
                   RedeemScript, SigHashType) ->
    %% Check if this is P2SH-P2WPKH or P2SH-P2WSH
    case RedeemScript of
        <<0, 20, _WitnessProg:20/binary>> ->
            %% P2SH-P2WPKH (W31 site 4): outer P2SH commitment was
            %% verified by sign_p2sh/9; the witness program is
            %% hash160(pubkey) so the W31 inner check is implicit in
            %% how we already build ScriptCode below.
            PkHash = beamchain_crypto:hash160(PubKey),
            ScriptCode = <<16#76, 16#a9, 20, PkHash/binary, 16#88, 16#ac>>,
            SigHash = beamchain_script:sighash_witness_v0(
                Tx, InputIndex, ScriptCode, Value, SigHashType),
            {ok, DerSig} = beamchain_crypto:ecdsa_sign(SigHash, PrivKey),
            SigWithType = <<DerSig/binary, SigHashType>>,
            Sigs = maps:get(partial_sigs, InputMap, #{}),
            InputMap#{partial_sigs => Sigs#{PubKey => SigWithType}};
        <<0, 32, WitnessProg:32/binary>> ->
            %% P2SH-P2WSH (W31 site 5): also assert
            %% sha256(witnessScript) == redeem-script witness program.
            case maps:get(witness_script, InputMap, undefined) of
                undefined ->
                    InputMap;
                WitnessScript ->
                    case beamchain_crypto:verify_p2wsh_commitment(
                           WitnessScript, WitnessProg) of
                        ok ->
                            SigHash = beamchain_script:sighash_witness_v0(
                                Tx, InputIndex, WitnessScript, Value,
                                SigHashType),
                            {ok, DerSig} =
                                beamchain_crypto:ecdsa_sign(SigHash, PrivKey),
                            SigWithType = <<DerSig/binary, SigHashType>>,
                            Sigs = maps:get(partial_sigs, InputMap, #{}),
                            InputMap#{partial_sigs =>
                                Sigs#{PubKey => SigWithType}};
                        {error, _} ->
                            %% Inner P2WSH commitment failed; decline.
                            InputMap
                    end
            end;
        _ ->
            %% Legacy P2SH (W31 site 6): outer commitment already
            %% verified by sign_p2sh/9 above.
            SigHash = beamchain_script:sighash_legacy(
                Tx, InputIndex, RedeemScript, SigHashType),
            {ok, DerSig} = beamchain_crypto:ecdsa_sign(SigHash, PrivKey),
            SigWithType = <<DerSig/binary, SigHashType>>,
            Sigs = maps:get(partial_sigs, InputMap, #{}),
            InputMap#{partial_sigs => Sigs#{PubKey => SigWithType}}
    end.

%% Resolve the (Value, ScriptPubKey) the input claims to spend.
%%
%% Pre-W41 this happily preferred witness_utxo whenever set and never
%% checked that non_witness_utxo's txid matched the outpoint hash —
%% i.e. the CVE-2020-14199 "lying-amount" oracle that the W40-A audit
%% flagged. Bug A1 (txid mismatch) and Bug A2 (witness/non-witness
%% disagreement) are both gated here; sign / build_prevouts /
%% finalize all funnel through this one helper so each fix lands
%% exactly once.
%%
%% Mirrors Bitcoin Core psbt.cpp `PSBTInput::IsSane` semantics: when
%% non_witness_utxo is present, its hash MUST equal the outpoint txid;
%% when both are present, the witness_utxo MUST equal
%% non_witness_utxo->vout[prevout.n].
%%
%% Returns:
%%   {witness_utxo,     Value, ScriptPubKey}
%%   {non_witness_utxo, Value, ScriptPubKey}
%%   {error, non_witness_utxo_txid_mismatch}
%%   {error, non_witness_utxo_vout_oob}
%%   {error, utxo_value_mismatch}
%%   {error, utxo_script_mismatch}
%%   undefined
get_utxo_info_checked(InputMap, #tx_in{prev_out = #outpoint{hash = ExpectedTxid,
                                                            index = VoutIdx}}) ->
    Witness = maps:get(witness_utxo, InputMap, undefined),
    NonWitness = maps:get(non_witness_utxo, InputMap, undefined),
    case {Witness, NonWitness} of
        {undefined, undefined} ->
            undefined;
        {undefined, PrevTx} ->
            %% Bug A1: validate the supplied prev-tx really is the
            %% one named by the outpoint.
            case beamchain_crypto:verify_non_witness_utxo_txid(
                   PrevTx, ExpectedTxid) of
                ok ->
                    case nth_output(PrevTx, VoutIdx) of
                        {ok, #tx_out{value = V, script_pubkey = SPK}} ->
                            {non_witness_utxo, V, SPK};
                        {error, _} = E ->
                            E
                    end;
                {error, _} = E ->
                    E
            end;
        {{WV, WSPK}, undefined} ->
            {witness_utxo, WV, WSPK};
        {{WV, WSPK}, PrevTx} ->
            %% Bug A1 + A2: validate the prev-tx txid AND that
            %% witness_utxo agrees with non_witness_utxo->vout[n].
            case beamchain_crypto:verify_non_witness_utxo_txid(
                   PrevTx, ExpectedTxid) of
                ok ->
                    case nth_output(PrevTx, VoutIdx) of
                        {ok, #tx_out{value = NV, script_pubkey = NSPK}} ->
                            if
                                NV =/= WV ->
                                    {error, utxo_value_mismatch};
                                NSPK =/= WSPK ->
                                    {error, utxo_script_mismatch};
                                true ->
                                    %% Both agree — prefer witness_utxo
                                    %% (matches Core's GetUTXO).
                                    {witness_utxo, WV, WSPK}
                            end;
                        {error, _} = E ->
                            E
                    end;
                {error, _} = E ->
                    E
            end
    end.

%% 0-indexed safe nth — returns {error, non_witness_utxo_vout_oob} if
%% the spending input names a vout that doesn't exist in the supplied
%% prev-tx (also a divergence from Core, which rejects in IsSane).
nth_output(#transaction{outputs = Outputs}, VoutIdx)
  when is_integer(VoutIdx), VoutIdx >= 0 ->
    if
        VoutIdx < length(Outputs) ->
            {ok, lists:nth(VoutIdx + 1, Outputs)};
        true ->
            {error, non_witness_utxo_vout_oob}
    end;
nth_output(_, _) ->
    {error, non_witness_utxo_vout_oob}.

build_prevouts(Psbt) ->
    Tx = Psbt#psbt.unsigned_tx,
    lists:zipwith(fun(Input, InputMap) ->
        %% W41: route through get_utxo_info_checked/2 so a forged
        %% non_witness_utxo can't poison the taproot prevouts vector
        %% (which feeds sighash_taproot's amounts/scriptpubkeys hash).
        case get_utxo_info_checked(InputMap, Input) of
            {witness_utxo, Value, ScriptPubKey} ->
                {Value, ScriptPubKey};
            {non_witness_utxo, Value, ScriptPubKey} ->
                {Value, ScriptPubKey};
            {error, _} ->
                %% Inconsistent — emit a sentinel so any sighash that
                %% touches this slot won't validate. Same shape we
                %% already used for the `undefined` arm.
                {0, <<>>};
            undefined ->
                {0, <<>>}
        end
    end, Tx#transaction.inputs, Psbt#psbt.inputs).

%%% ===================================================================
%%% Internal: Finalization
%%% ===================================================================

finalize_input(InputMap, Input) ->
    %% If already finalized, return as-is
    case maps:is_key(final_script_sig, InputMap) orelse
         maps:is_key(final_script_witness, InputMap) of
        true ->
            InputMap;
        false ->
            do_finalize_input(InputMap, Input)
    end.

do_finalize_input(InputMap, Input) ->
    %% W41: same get_utxo_info_checked/2 chokepoint — Bug A1/A2 errors
    %% surface as `{finalize_error, Reason}` so a forged-prev-tx PSBT
    %% can't be finalised into a misleading on-chain transaction.
    case get_utxo_info_checked(InputMap, Input) of
        {witness_utxo, _Value, ScriptPubKey} ->
            finalize_with_script(InputMap, ScriptPubKey);
        {non_witness_utxo, _Value, ScriptPubKey} ->
            finalize_with_script(InputMap, ScriptPubKey);
        {error, Reason} ->
            throw({finalize_error, Reason});
        undefined ->
            throw({finalize_error, missing_utxo})
    end.

finalize_with_script(InputMap, ScriptPubKey) ->
    case beamchain_address:classify_script(ScriptPubKey) of
        p2wpkh ->
            finalize_p2wpkh(InputMap);
        p2pkh ->
            finalize_p2pkh(InputMap);
        p2tr ->
            finalize_p2tr(InputMap);
        p2sh ->
            finalize_p2sh(InputMap);
        p2wsh ->
            finalize_p2wsh(InputMap);
        _ ->
            throw({finalize_error, unsupported_script_type})
    end.

finalize_p2wpkh(InputMap) ->
    PartialSigs = maps:get(partial_sigs, InputMap, #{}),
    case maps:to_list(PartialSigs) of
        [{PubKey, Sig}] ->
            drop_producer_fields(InputMap#{
                final_script_sig => <<>>,
                final_script_witness => [Sig, PubKey]
            });
        [] ->
            throw({finalize_error, missing_signature});
        _ ->
            throw({finalize_error, multiple_signatures_for_p2wpkh})
    end.

finalize_p2pkh(InputMap) ->
    PartialSigs = maps:get(partial_sigs, InputMap, #{}),
    case maps:to_list(PartialSigs) of
        [{PubKey, Sig}] ->
            ScriptSig = push_data(Sig, push_data(PubKey, <<>>)),
            drop_producer_fields(InputMap#{final_script_sig => ScriptSig});
        [] ->
            throw({finalize_error, missing_signature});
        _ ->
            throw({finalize_error, multiple_signatures_for_p2pkh})
    end.

finalize_p2tr(InputMap) ->
    case maps:get(tap_key_sig, InputMap, undefined) of
        undefined ->
            throw({finalize_error, missing_taproot_signature});
        Sig ->
            drop_producer_fields(InputMap#{
                final_script_sig => <<>>,
                final_script_witness => [Sig]
            })
    end.

finalize_p2sh(InputMap) ->
    RedeemScript = maps:get(redeem_script, InputMap, undefined),
    case RedeemScript of
        undefined ->
            throw({finalize_error, missing_redeem_script});
        <<0, 20, _:20/binary>> ->
            %% P2SH-P2WPKH
            PartialSigs = maps:get(partial_sigs, InputMap, #{}),
            case maps:to_list(PartialSigs) of
                [{PubKey, Sig}] ->
                    ScriptSig = push_data(RedeemScript, <<>>),
                    drop_producer_fields(InputMap#{
                        final_script_sig => ScriptSig,
                        final_script_witness => [Sig, PubKey]
                    });
                [] ->
                    throw({finalize_error, missing_signature})
            end;
        <<0, 32, _:32/binary>> ->
            %% P2SH-P2WSH
            finalize_p2sh_p2wsh(InputMap, RedeemScript);
        _ ->
            %% Legacy P2SH multisig
            finalize_legacy_p2sh(InputMap, RedeemScript)
    end.

finalize_p2sh_p2wsh(InputMap, RedeemScript) ->
    WitnessScript = maps:get(witness_script, InputMap, undefined),
    case WitnessScript of
        undefined ->
            throw({finalize_error, missing_witness_script});
        _ ->
            PartialSigs = maps:get(partial_sigs, InputMap, #{}),
            Witness = build_multisig_witness(PartialSigs, WitnessScript),
            ScriptSig = push_data(RedeemScript, <<>>),
            drop_producer_fields(InputMap#{
                final_script_sig => ScriptSig,
                final_script_witness => Witness
            })
    end.

finalize_legacy_p2sh(InputMap, RedeemScript) ->
    PartialSigs = maps:get(partial_sigs, InputMap, #{}),
    %% W46: scriptSig sigs must be in script-pubkey order, not Erlang
    %% map-iteration order (which is undefined). Same fix already lives
    %% on the witness path via build_p2wsh_witness_from_sigs/2; the
    %% legacy P2SH path was the missing twin. Reference: Core
    %% src/script/sign.cpp:ProduceSignature + the multisig scriptSig
    %% layout in BIP-11 / `OP_0 <sig1> ... <sigM> <redeemScript>` where
    %% sig_i corresponds to the i-th matched script-order pubkey.
    SortedSigs = case beamchain_witness_signer:parse_multisig_script(RedeemScript) of
        {ok, M, _N, PubKeys} ->
            Collected = [maps:get(PK, PartialSigs)
                         || PK <- PubKeys, maps:is_key(PK, PartialSigs)],
            lists:sublist(Collected, M);
        error ->
            %% Non-canonical multisig — fall back to map-iteration order
            %% (no script-pubkey order to follow). This matches the W28
            %% witness-path fallback in build_multisig_witness/2.
            maps:values(PartialSigs)
    end,
    ScriptSig = build_multisig_scriptsig(SortedSigs, RedeemScript),
    %% W46 belt-and-suspenders: drop producer fields after finalize so
    %% the encoder gate at encode_input_map/1 isn't the only line of
    %% defense (mirrors W41 lunarblock psbt.lua:1191-1195).
    drop_producer_fields(InputMap#{final_script_sig => ScriptSig}).

%% W46: drop producer-only fields once an input is finalized. Per
%% BIP-174: "producer fields ... should be cleared once a signer creates
%% the FINAL_SCRIPTSIG / FINAL_SCRIPTWITNESS values". non_witness_utxo
%% and witness_utxo are deliberately retained (extractor needs them for
%% amount verification).
drop_producer_fields(InputMap) ->
    maps:without([partial_sigs,
                  sighash_type,
                  redeem_script,
                  witness_script,
                  bip32_derivation,
                  tap_key_sig,
                  tap_internal_key], InputMap).

finalize_p2wsh(InputMap) ->
    WitnessScript = maps:get(witness_script, InputMap, undefined),
    case WitnessScript of
        undefined ->
            throw({finalize_error, missing_witness_script});
        _ ->
            PartialSigs = maps:get(partial_sigs, InputMap, #{}),
            Witness = build_multisig_witness(PartialSigs, WitnessScript),
            drop_producer_fields(InputMap#{
                final_script_sig => <<>>,
                final_script_witness => Witness
            })
    end.

%% W41: `finalize_legacy/1` removed — `do_finalize_input/2` now always
%% has the resolved scriptPubKey (via get_utxo_info_checked/2) so it
%% can dispatch through `finalize_with_script/2`. The fallback was the
%% only thing that hid the missing A1/A2 checks.

build_multisig_witness(PartialSigs, WitnessScript) ->
    %% Wave 28: delegate to the shared canonical witness builder so
    %% both the PSBT finalize path and the raw-tx wallet path agree
    %% on stack-layout (BIP-141 §"P2WSH" + the CHECKMULTISIG
    %% off-by-one pad). Pubkey-ordered when the script parses as a
    %% canonical M-of-N CHECKMULTISIG; falls back to map-iteration
    %% order otherwise.
    beamchain_witness_signer:build_p2wsh_witness_from_sigs(
        PartialSigs, WitnessScript).

build_multisig_scriptsig(Sigs, RedeemScript) ->
    %% scriptSig: OP_0 <sig1> <sig2> ... <redeemScript>
    Parts = [<<0>>] ++ [push_data(Sig, <<>>) || Sig <- Sigs] ++ [push_data(RedeemScript, <<>>)],
    iolist_to_binary(Parts).

%%% ===================================================================
%%% Internal: Merging
%%% ===================================================================

merge_psbt(Other, Base) ->
    MergedInputs = lists:zipwith(fun merge_input/2,
                                  Base#psbt.inputs,
                                  Other#psbt.inputs),
    MergedOutputs = lists:zipwith(fun merge_output/2,
                                   Base#psbt.outputs,
                                   Other#psbt.outputs),
    MergedXPubs = maps:merge(Base#psbt.xpubs, Other#psbt.xpubs),
    Base#psbt{
        inputs = MergedInputs,
        outputs = MergedOutputs,
        xpubs = MergedXPubs
    }.

merge_input(Base, Other) ->
    %% Merge partial signatures
    BaseSigs = maps:get(partial_sigs, Base, #{}),
    OtherSigs = maps:get(partial_sigs, Other, #{}),
    MergedSigs = maps:merge(BaseSigs, OtherSigs),

    %% Merge BIP32 derivations
    BaseDerivs = maps:get(bip32_derivation, Base, #{}),
    OtherDerivs = maps:get(bip32_derivation, Other, #{}),
    MergedDerivs = maps:merge(BaseDerivs, OtherDerivs),

    %% Merge unknown keys
    BaseUnk = maps:get(unknown, Base, #{}),
    OtherUnk = maps:get(unknown, Other, #{}),
    MergedUnk = maps:merge(BaseUnk, OtherUnk),

    %% For other fields, prefer non-undefined values
    Merged = maps:merge(Base, Other),
    Merged#{
        partial_sigs => MergedSigs,
        bip32_derivation => MergedDerivs,
        unknown => MergedUnk
    }.

merge_output(Base, Other) ->
    %% Merge BIP32 derivations
    BaseDerivs = maps:get(bip32_derivation, Base, #{}),
    OtherDerivs = maps:get(bip32_derivation, Other, #{}),
    MergedDerivs = maps:merge(BaseDerivs, OtherDerivs),

    %% Merge unknown keys
    BaseUnk = maps:get(unknown, Base, #{}),
    OtherUnk = maps:get(unknown, Other, #{}),
    MergedUnk = maps:merge(BaseUnk, OtherUnk),

    Merged = maps:merge(Base, Other),
    Merged#{
        bip32_derivation => MergedDerivs,
        unknown => MergedUnk
    }.

%%% ===================================================================
%%% Internal: Helpers
%%% ===================================================================

verify_unsigned_tx(#transaction{inputs = Inputs}) ->
    case lists:all(fun(#tx_in{script_sig = SS, witness = W}) ->
        SS =:= <<>> andalso
        (W =:= [] orelse W =:= undefined)
    end, Inputs) of
        true -> ok;
        false -> {error, transaction_not_unsigned}
    end.

tx_hash(Tx) ->
    beamchain_serialize:tx_hash(Tx).

encode_kv(Key, Value) ->
    KeyLen = beamchain_serialize:encode_varint(byte_size(Key)),
    ValLen = beamchain_serialize:encode_varint(byte_size(Value)),
    <<KeyLen/binary, Key/binary, ValLen/binary, Value/binary>>.

decode_map(Bin) ->
    decode_map(Bin, []).

decode_map(<<0, Rest/binary>>, Acc) ->
    {lists:reverse(Acc), Rest};
decode_map(Bin, Acc) ->
    {KeyLen, Rest1} = beamchain_serialize:decode_varint(Bin),
    <<Key:KeyLen/binary, Rest2/binary>> = Rest1,
    {ValLen, Rest3} = beamchain_serialize:decode_varint(Rest2),
    <<Value:ValLen/binary, Rest4/binary>> = Rest3,
    decode_map(Rest4, [{Key, Value} | Acc]).

decode_n_maps(Bin, 0) ->
    {[], Bin};
decode_n_maps(Bin, N) ->
    {Pairs, Rest} = decode_map(Bin),
    {MoreMaps, Rest2} = decode_n_maps(Rest, N - 1),
    {[Pairs | MoreMaps], Rest2}.

encode_bip32_path(Fingerprint, Path) when byte_size(Fingerprint) =:= 4 ->
    PathBin = << <<I:32/little>> || I <- Path >>,
    <<Fingerprint/binary, PathBin/binary>>.

decode_bip32_path(<<Fingerprint:4/binary, PathBin/binary>>) ->
    Path = [I || <<I:32/little>> <= PathBin],
    {Fingerprint, Path}.

encode_witness_utxo(Value, ScriptPubKey) ->
    ScriptLen = beamchain_serialize:encode_varint(byte_size(ScriptPubKey)),
    <<Value:64/little, ScriptLen/binary, ScriptPubKey/binary>>.

decode_witness_utxo(<<Value:64/little, Rest/binary>>) ->
    {Len, Rest2} = beamchain_serialize:decode_varint(Rest),
    <<ScriptPubKey:Len/binary, _/binary>> = Rest2,
    {Value, ScriptPubKey}.

encode_witness_stack(Items) ->
    Count = beamchain_serialize:encode_varint(length(Items)),
    Data = << <<(beamchain_serialize:encode_varstr(I))/binary>> || I <- Items >>,
    <<Count/binary, Data/binary>>.

decode_witness_stack(Bin) ->
    {Count, Rest} = beamchain_serialize:decode_varint(Bin),
    decode_n_items(Rest, Count, []).

decode_n_items(_Bin, 0, Acc) ->
    lists:reverse(Acc);
decode_n_items(Bin, N, Acc) ->
    {Item, Rest} = beamchain_serialize:decode_varstr(Bin),
    decode_n_items(Rest, N - 1, [Item | Acc]).

replace_nth(1, Elem, [_ | Rest]) -> [Elem | Rest];
replace_nth(N, Elem, [H | Rest]) -> [H | replace_nth(N - 1, Elem, Rest)].

push_data(Data, Acc) ->
    Len = byte_size(Data),
    if
        Len =< 75 ->
            <<Acc/binary, Len, Data/binary>>;
        Len =< 255 ->
            <<Acc/binary, 16#4c, Len:8, Data/binary>>;
        Len =< 65535 ->
            <<Acc/binary, 16#4d, Len:16/little, Data/binary>>;
        true ->
            <<Acc/binary, 16#4e, Len:32/little, Data/binary>>
    end.

%% decode_tap_tree/2 — parse PSBT_OUT_TAP_TREE value.
%% Wire format (BIP-371 §Output-typed fields): repeated entries of
%%   depth (1 byte) + leaf_version (1 byte) + script (varint-length-prefixed).
decode_tap_tree(<<>>, Acc) ->
    lists:reverse(Acc);
decode_tap_tree(<<Depth, LeafVer, Rest/binary>>, Acc) ->
    {ScriptLen, Rest2} = beamchain_serialize:decode_varint(Rest),
    <<Script:ScriptLen/binary, Rest3/binary>> = Rest2,
    decode_tap_tree(Rest3, [{Depth, LeafVer, Script} | Acc]).

%% NOTE: BIP-341 taproot_tweak_seckey/1 + negate_seckey/1 used to live
%% here (byte-identical to the wallet copies). They have been hoisted
%% into `beamchain_crypto` (Wave 27-E refactor). Call
%% `beamchain_crypto:taproot_tweak_seckey/1` directly.
