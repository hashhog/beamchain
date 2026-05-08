-module(beamchain_witness_signer).

%% Shared P2WSH / P2SH-P2WSH signer used by both the raw-tx wallet path
%% (`beamchain_wallet:sign_input/...`) and the PSBT finalize path
%% (`beamchain_psbt:finalize_p2wsh/...`). Centralising the witness-stack
%% assembly here is parallel-impl-drift prevention — a single source of
%% truth keeps the BIP-141 §"P2WSH" / BIP-143 sighash invariants and the
%% legacy CHECKMULTISIG off-by-one pad in one place.
%%
%% Reference: bitcoin-core/src/script/sign.cpp::ProduceSignature
%% (the `witnessversion == 0 && type == WITNESS_V0_SCRIPTHASH` branch).

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% Public API
-export([sign_p2wsh/6,
         sign_p2wsh/7,
         sign_p2sh_p2wsh/6,
         sign_p2sh_p2wsh/7,
         build_p2wsh_witness_from_sigs/2,
         classify_witness_script/1,
         find_signers_for_script/2]).

%% Exported for unit-test access
-export([parse_multisig_script/1, is_multisig_script/1]).

%% Push-data builder (mirrors `beamchain_wallet:push_data/2`).
-spec push_data(binary()) -> binary().
push_data(Data) ->
    Len = byte_size(Data),
    if
        Len =< 75 ->
            <<Len, Data/binary>>;
        Len =< 255 ->
            <<16#4c, Len:8, Data/binary>>;
        Len =< 65535 ->
            <<16#4d, Len:16/little, Data/binary>>;
        true ->
            <<16#4e, Len:32/little, Data/binary>>
    end.

%%% ===================================================================
%%% P2WSH / P2SH-P2WSH signers (raw-tx flow)
%%% ===================================================================

%% @doc Sign a P2WSH (native segwit script-hash) input. WitnessScript is
%% what's hashed into the scriptPubKey; for CHECKMULTISIG it's
%% `OP_M <pubkey1> ... <pubkeyN> OP_N OP_CHECKMULTISIG`. Signers is in
%% witness-script pubkey order; entries may be `undefined` for keys
%% the wallet does not own (partial-sign).
%%
%% Returns `{ok, WitnessStack}` where WitnessStack is a list of binaries
%% suitable for `#tx_in.witness`.
%%
%% Witness layout per BIP-141 §"P2WSH" + the legacy CHECKMULTISIG
%% off-by-one bug-compat pad:
%%
%%     [<<>>, Sig1, Sig2, ..., SigM, WitnessScript]
%%
%% The leading empty push is required iff the witness script ends in
%% OP_CHECKMULTISIG; for non-multisig P2WSH templates (single CHECKSIG)
%% the layout is `[Sig, WitnessScript]`.
-spec sign_p2wsh(#transaction{}, non_neg_integer(), non_neg_integer(),
                 binary(), [binary() | undefined], non_neg_integer()) ->
    {ok, [binary()]} | {error, term()}.
sign_p2wsh(Tx, InputIndex, Amount, WitnessScript, Signers, HashType) ->
    SigHash = beamchain_script:sighash_witness_v0(
        Tx, InputIndex, WitnessScript, Amount, HashType),
    case classify_witness_script(WitnessScript) of
        {multisig, M, _PubKeys} ->
            sign_multisig_witness(SigHash, WitnessScript, M, Signers, HashType);
        single ->
            sign_single_witness(SigHash, WitnessScript, Signers, HashType)
    end.

%% @doc W38: 7-arity wrapper around sign_p2wsh/6 that asserts the
%% prevout's scriptPubKey is a well-formed bare P2WSH (`OP_0 <32> H`)
%% AND that sha256(WitnessScript) == H before delegating. Mirrors the
%% W31 P2SH-outer-commitment idiom in sign_p2sh_p2wsh/7 below: we want
%% callers with access to the prevout's scriptPubKey to refuse to sign
%% over a caller-supplied witness script that doesn't commit to chain.
%% Without this guard the signer would happily emit a signature over an
%% attacker-controlled script.
-spec sign_p2wsh(#transaction{}, non_neg_integer(), non_neg_integer(),
                 binary(), binary(),
                 [binary() | undefined], non_neg_integer()) ->
    {ok, [binary()]} | {error, term()}.
sign_p2wsh(Tx, InputIndex, Amount, WitnessScript, ScriptPubKey, Signers,
           HashType) ->
    case ScriptPubKey of
        <<16#00, 32, WitnessProg:32/binary>> ->
            case beamchain_crypto:verify_p2wsh_commitment(
                   WitnessScript, WitnessProg) of
                ok ->
                    sign_p2wsh(Tx, InputIndex, Amount, WitnessScript,
                               Signers, HashType);
                {error, _} = Err ->
                    Err
            end;
        _ ->
            {error, p2wsh_spk_format}
    end.

%% @doc Sign a P2SH-wrapped P2WSH input. ScriptSig is a single push of
%% redeemScript (which is itself the P2WSH `OP_0 <32-byte-hash>`), and
%% the witness is the same as bare P2WSH.
%%
%% Returns `{ok, ScriptSig, WitnessStack}`.
%%
%% Two arities:
%%   - sign_p2sh_p2wsh/6 (legacy): takes no ScriptPubKey, so it cannot
%%     verify the outer P2SH commitment. The inner P2WSH commitment is
%%     satisfied by construction (we hash the caller's WitnessScript
%%     ourselves into the emitted redeem-script's witness program), but
%%     the caller is trusting that hash160(emitted-redeem) matches the
%%     prevout's on-chain SPK. Callers that have access to the
%%     prevout's scriptPubKey MUST prefer the /7 form.
%%   - sign_p2sh_p2wsh/7 (W31): asserts that hash160 of the emitted
%%     redeemScript matches scriptPubKey[2..22], catching a forged
%%     WitnessScript that doesn't commit to the prevout. The inner
%%     P2WSH commitment is satisfied by construction as in the /6
%%     form.
-spec sign_p2sh_p2wsh(#transaction{}, non_neg_integer(), non_neg_integer(),
                      binary(), [binary() | undefined], non_neg_integer()) ->
    {ok, binary(), [binary()]} | {error, term()}.
sign_p2sh_p2wsh(Tx, InputIndex, Amount, WitnessScript, Signers, HashType) ->
    case sign_p2wsh(Tx, InputIndex, Amount, WitnessScript, Signers, HashType) of
        {ok, Witness} ->
            %% scriptSig: single push of the P2WSH redeem script
            %% (`OP_0 <SHA256(witnessScript)>`).
            %%
            %% W38: the previous `verify_p2wsh_commitment(WitnessScript,
            %% sha256(WitnessScript))` here was a `H == H` tautology
            %% — it could never reject anything because both sides were
            %% derived from WitnessScript on the same line. It looked
            %% like a defensive check, wasn't, and proved nothing about
            %% the prevout's scriptPubKey. Removed. Callers that need
            %% an actual outer commitment check must use the /7 arity
            %% below.
            WitnessProg = crypto:hash(sha256, WitnessScript),
            RedeemScript = <<0, 32, WitnessProg/binary>>,
            ScriptSig = push_data(RedeemScript),
            {ok, ScriptSig, Witness};
        {error, _} = Err ->
            Err
    end.

-spec sign_p2sh_p2wsh(#transaction{}, non_neg_integer(), non_neg_integer(),
                      binary(), binary(),
                      [binary() | undefined], non_neg_integer()) ->
    {ok, binary(), [binary()]} | {error, term()}.
sign_p2sh_p2wsh(Tx, InputIndex, Amount, WitnessScript, ScriptPubKey,
                Signers, HashType) ->
    %% W31 outer P2SH commitment: hash160(redeemScript) == SPK[2..22].
    WitnessProg = crypto:hash(sha256, WitnessScript),
    RedeemScript = <<0, 32, WitnessProg/binary>>,
    case beamchain_crypto:verify_p2sh_commitment(RedeemScript, ScriptPubKey) of
        ok ->
            sign_p2sh_p2wsh(Tx, InputIndex, Amount, WitnessScript,
                            Signers, HashType);
        {error, _} = Err ->
            Err
    end.

sign_multisig_witness(SigHash, WitnessScript, M, Signers, HashType) ->
    %% Emit up to M signatures in pubkey-order from the wallet's owned
    %% keys; fail if wallet owns fewer than M of N. Mirrors
    %% bitcoin-core/src/wallet/scriptpubkeyman.cpp::SignTransaction +
    %% script/sign.cpp::ProduceSignature.
    case sign_keys_in_order(SigHash, Signers, M, HashType, []) of
        {ok, Sigs} ->
            %% Witness: [<<>> (CHECKMULTISIG off-by-one pad),
            %%           sig1, ..., sigM, witnessScript]
            Witness = [<<>>] ++ Sigs ++ [WitnessScript],
            {ok, Witness};
        {error, _} = Err ->
            Err
    end.

sign_single_witness(SigHash, WitnessScript, Signers, HashType) ->
    %% Non-multisig: assume single-CHECKSIG-style template.
    case Signers of
        [PrivKey] when is_binary(PrivKey) ->
            {ok, DerSig} = beamchain_crypto:ecdsa_sign(SigHash, PrivKey),
            SigWithType = <<DerSig/binary, HashType>>,
            {ok, [SigWithType, WitnessScript]};
        _ ->
            {error, single_witness_requires_one_signer}
    end.

sign_keys_in_order(_SigHash, [], NeededM, _HashType, Acc) ->
    Sigs = lists:reverse(Acc),
    case length(Sigs) >= NeededM of
        true ->
            %% Already collected at least M valid signatures (in
            %% witness-script pubkey order); trim to exactly M.
            {ok, lists:sublist(Sigs, NeededM)};
        false ->
            {error, {partial_sign, length(Sigs), NeededM}}
    end;
sign_keys_in_order(SigHash, [_ | Rest], NeededM, HashType, Acc)
  when length(Acc) >= NeededM ->
    %% Already at M, skip remaining keys.
    sign_keys_in_order(SigHash, Rest, NeededM, HashType, Acc);
sign_keys_in_order(SigHash, [undefined | Rest], NeededM, HashType, Acc) ->
    sign_keys_in_order(SigHash, Rest, NeededM, HashType, Acc);
sign_keys_in_order(SigHash, [PrivKey | Rest], NeededM, HashType, Acc)
  when is_binary(PrivKey) ->
    {ok, DerSig} = beamchain_crypto:ecdsa_sign(SigHash, PrivKey),
    SigWithType = <<DerSig/binary, HashType>>,
    sign_keys_in_order(SigHash, Rest, NeededM, HashType, [SigWithType | Acc]).

%%% ===================================================================
%%% Witness-script classification
%%% ===================================================================

%% @doc Classify a witness script. Returns {multisig, M, [PubKey]} for
%% the canonical CHECKMULTISIG template, otherwise `single` (which
%% covers single-CHECKSIG and any unrecognised template that signs as
%% "one sig + script").
-spec classify_witness_script(binary()) ->
    {multisig, pos_integer(), [binary()]} | single.
classify_witness_script(Script) ->
    case parse_multisig_script(Script) of
        {ok, M, _N, PubKeys} -> {multisig, M, PubKeys};
        error -> single
    end.

%% @doc Returns true iff Script is a canonical M-of-N CHECKMULTISIG
%% (`OP_M <pubkey1> ... <pubkeyN> OP_N OP_CHECKMULTISIG`).
-spec is_multisig_script(binary()) -> boolean().
is_multisig_script(Script) ->
    case parse_multisig_script(Script) of
        {ok, _M, _N, _PubKeys} -> true;
        error -> false
    end.

%% @doc Parse `OP_M <pubkey>...<pubkey> OP_N OP_CHECKMULTISIG`.
%% Returns {ok, M, N, [PubKey]} or `error`. Accepts both 33-byte
%% (compressed) and 65-byte (uncompressed) pubkeys; the caller is
%% responsible for any encoding policy beyond that.
-spec parse_multisig_script(binary()) ->
    {ok, pos_integer(), pos_integer(), [binary()]} | error.
parse_multisig_script(<<MOp:8, Rest/binary>>) when MOp >= 16#51, MOp =< 16#60 ->
    M = MOp - 16#50,
    case parse_pubkeys(Rest, []) of
        {ok, PubKeys, <<NOp:8, 16#ae>>} when NOp >= 16#51, NOp =< 16#60 ->
            N = NOp - 16#50,
            case length(PubKeys) =:= N andalso M =< N of
                true -> {ok, M, N, PubKeys};
                false -> error
            end;
        _ ->
            error
    end;
parse_multisig_script(_) ->
    error.

parse_pubkeys(<<33, PubKey:33/binary, Rest/binary>>, Acc) ->
    parse_pubkeys(Rest, [PubKey | Acc]);
parse_pubkeys(<<65, PubKey:65/binary, Rest/binary>>, Acc) ->
    parse_pubkeys(Rest, [PubKey | Acc]);
parse_pubkeys(Rest, Acc) ->
    {ok, lists:reverse(Acc), Rest}.

%%% ===================================================================
%%% Signer-list assembly
%%% ===================================================================

%% @doc Given a witness/redeem script and a pool of available private
%% keys, return a list aligned with the script's pubkey-order: each
%% slot holds either the matching PrivKey (binary) or `undefined` if
%% the wallet does not own that pubkey. The returned list is suitable
%% as the Signers argument to sign_p2wsh/sign_p2sh_p2wsh. For
%% non-multisig scripts the returned list is `[PrivKey]` if a single
%% matching key is found, else `[]`.
%%
%% PrivKeys is a flat list of 32-byte private keys held by the wallet.
-spec find_signers_for_script(binary(), [binary()]) -> [binary() | undefined].
find_signers_for_script(Script, PrivKeys) ->
    case parse_multisig_script(Script) of
        {ok, _M, _N, PubKeys} ->
            [find_priv_for_pub(PK, PrivKeys) || PK <- PubKeys];
        error ->
            %% Try single-key extraction: <33 PubKey> at start.
            case Script of
                <<33, PubKey:33/binary, _/binary>> ->
                    case find_priv_for_pub(PubKey, PrivKeys) of
                        undefined -> [];
                        Priv -> [Priv]
                    end;
                _ ->
                    []
            end
    end.

find_priv_for_pub(_, []) -> undefined;
find_priv_for_pub(PubKey, [PrivKey | Rest]) ->
    case beamchain_wallet:privkey_to_pubkey(PrivKey) of
        PubKey -> PrivKey;
        _ -> find_priv_for_pub(PubKey, Rest)
    end.

%%% ===================================================================
%%% PSBT-side witness builder (used by beamchain_psbt:finalize_p2wsh)
%%% ===================================================================

%% @doc Assemble a final P2WSH witness stack from a partial_sigs map
%% (pubkey -> sig+hashtype) and the witness script. Sigs are ordered
%% to match the pubkey-order embedded in WitnessScript when it's a
%% canonical CHECKMULTISIG; otherwise they appear in map iteration
%% order (single-key witnesses have only one sig anyway).
%%
%% This is the canonical assembler shared with the raw-tx path's
%% sign_p2wsh — keeping witness-layout decisions in one module
%% prevents parallel-impl drift on the CHECKMULTISIG off-by-one pad.
-spec build_p2wsh_witness_from_sigs(#{binary() => binary()}, binary()) ->
    [binary()].
build_p2wsh_witness_from_sigs(PartialSigs, WitnessScript) ->
    case parse_multisig_script(WitnessScript) of
        {ok, M, _N, PubKeys} ->
            %% Emit signatures in pubkey-order, taking the first M
            %% pubkeys we have signatures for.
            Sigs = collect_sigs_in_pubkey_order(PubKeys, PartialSigs, M, []),
            [<<>>] ++ Sigs ++ [WitnessScript];
        error ->
            %% Single-CHECKSIG template: take whatever sigs we have.
            Sigs = maps:values(PartialSigs),
            Sigs ++ [WitnessScript]
    end.

collect_sigs_in_pubkey_order(_PubKeys, _Sigs, 0, Acc) ->
    lists:reverse(Acc);
collect_sigs_in_pubkey_order([], _Sigs, _NeedM, Acc) ->
    lists:reverse(Acc);
collect_sigs_in_pubkey_order([PK | Rest], Sigs, NeedM, Acc) ->
    case maps:get(PK, Sigs, undefined) of
        undefined ->
            collect_sigs_in_pubkey_order(Rest, Sigs, NeedM, Acc);
        Sig ->
            collect_sigs_in_pubkey_order(Rest, Sigs, NeedM - 1, [Sig | Acc])
    end.
