-module(beamchain_payjoin).

%%% -------------------------------------------------------------------
%%% BIP-78 PayJoin shared anti-snoop validators + helpers.
%%%
%%% Spec: https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki
%%%       (§"Receiver's response" — checks the sender MUST perform on the
%%%        Payjoin PSBT the receiver returned).
%%%
%%% Closes W119 BUG-9 (G10-G15 anti-snoop rules) via reusable validators
%%% the sender (beamchain_payjoin_client) calls before signing+broadcast.
%%% Extracted into its own module so a future "receiver self-check"
%%% codepath (BIP-78 §"Sender side" suggests receivers MAY apply the
%%% same checks defensively) doesn't require a second pipeline.
%%%
%%% Each validator returns either `ok` or `{error, Reason}` where Reason
%%% is a structured term suitable for the BIP-78 sender error path.
%%%
%%% G10  outputs preserved — every Original output must survive in the
%%%      returned PSBT (we accept value-only mutation on the
%%%      `additionalfeeoutputindex` output; everything else byte-equal).
%%% G11  scriptSig types preserved — sender input scripts on the
%%%      receiver-modified inputs must remain the same script type
%%%      (a malicious receiver substituting P2SH for P2WPKH would leak
%%%      the PayJoin fingerprint).
%%% G12  no new sender inputs — every input present in the returned
%%%      PSBT that wasn't in the Original must be receiver-owned
%%%      (i.e. its scriptPubKey must NOT resolve to a wallet address
%%%      the sender controls).
%%% G13  fee within max_additional_fee_contribution — the absolute
%%%      additional fee the receiver took must be ≤ max sat.
%%% G14  disableoutputsubstitution honoured — when sender sent pjos=1,
%%%      the receiver output (every Original output other than the
%%%      `additionalfeeoutputindex` one) must be byte-equal.
%%% G15  minfeerate enforced — effective fee rate (sat/vB) of the
%%%      returned PSBT must be ≥ minfeerate.
%%%
%%% NOTE: G13 and G15 are mathematically related but operate on
%%% different inputs (G13 is an absolute-delta gate on the change
%%% output, G15 is a per-vbyte floor on the *full* tx). They MUST be
%%% checked independently.
%%% -------------------------------------------------------------------

-include("beamchain.hrl").
-include("beamchain_psbt.hrl").

-export([validate_response/4,
         g10_outputs_preserved/3,
         g11_scriptsig_types_preserved/2,
         g12_no_new_sender_inputs/3,
         g13_fee_within_cap/4,
         g14_disable_output_substitution/4,
         g15_min_fee_rate/3,
         compute_fee/2,
         classify_script_type/1,
         vsize/1]).

%%% ===================================================================
%%% Top-level driver
%%% ===================================================================

%% Run all six anti-snoop validators against the receiver's returned
%% PSBT, given the Original PSBT and the params the sender sent.
%% Returns `ok` only when every validator passes; first failure short-
%% circuits with `{error, {<gate>, Reason}}`.
%%
%% SenderOwnedFun is a 1-arity callback (ScriptPubKey :: binary()) ->
%% boolean(). Returns true when the script belongs to the sender's
%% wallet — used by G12 to distinguish receiver-added inputs from
%% sneaky sender-added ones.
validate_response(OriginalPsbt, PayjoinPsbt, Params, SenderOwnedFun) ->
    case g10_outputs_preserved(OriginalPsbt, PayjoinPsbt, Params) of
        {error, R} -> {error, {g10, R}};
        ok ->
            case g11_scriptsig_types_preserved(OriginalPsbt, PayjoinPsbt) of
                {error, R} -> {error, {g11, R}};
                ok ->
                    case g12_no_new_sender_inputs(OriginalPsbt, PayjoinPsbt,
                                                  SenderOwnedFun) of
                        {error, R} -> {error, {g12, R}};
                        ok ->
                            validate_response_finish(
                              OriginalPsbt, PayjoinPsbt, Params)
                    end
            end
    end.

validate_response_finish(OriginalPsbt, PayjoinPsbt, Params) ->
    Max = maps:get(max_additional_fee_contribution, Params, 0),
    MinFeeRate = maps:get(min_fee_rate, Params, 0),
    DisableOS = maps:get(disable_output_substitution, Params, false),
    FeeIdx = maps:get(additional_fee_output_index, Params, undefined),
    case g13_fee_within_cap(OriginalPsbt, PayjoinPsbt, Max, FeeIdx) of
        {error, R} -> {error, {g13, R}};
        ok ->
            case g14_disable_output_substitution(OriginalPsbt, PayjoinPsbt,
                                                 DisableOS, FeeIdx) of
                {error, R} -> {error, {g14, R}};
                ok ->
                    case g15_min_fee_rate(PayjoinPsbt, MinFeeRate, []) of
                        {error, R} -> {error, {g15, R}};
                        ok -> ok
                    end
            end
    end.

%%% ===================================================================
%%% G10 — outputs preserved
%%% ===================================================================

%% Every Original output must survive in the returned PSBT. The
%% receiver MAY shrink the `additionalfeeoutputindex` output (G9 fee
%% docking); we allow that one specific output to differ in `value`
%% but not in `script_pubkey`. Every other output must be byte-equal.
%% Additional NEW outputs introduced by the receiver are REJECTED —
%% BIP-78 explicitly forbids new sender-facing outputs.
g10_outputs_preserved(#psbt{unsigned_tx = OldTx},
                      #psbt{unsigned_tx = NewTx},
                      Params) ->
    Old = OldTx#transaction.outputs,
    New = NewTx#transaction.outputs,
    FeeIdx = maps:get(additional_fee_output_index, Params, undefined),
    case length(New) =:= length(Old) of
        false ->
            {error, {output_count_mismatch,
                     length(Old), length(New)}};
        true ->
            check_outputs_pairwise(Old, New, 0, FeeIdx)
    end.

check_outputs_pairwise([], [], _, _) -> ok;
check_outputs_pairwise([#tx_out{value = OldV, script_pubkey = OldS} | OT],
                       [#tx_out{value = NewV, script_pubkey = NewS} | NT],
                       Idx, FeeIdx) ->
    %% scriptPubKey must always match byte-equal (output identity).
    case OldS =:= NewS of
        false ->
            {error, {output_script_changed, Idx}};
        true ->
            %% Value: equal everywhere EXCEPT the fee-docking output
            %% (which the receiver MAY shrink within max_additional_fee).
            case Idx =:= FeeIdx of
                false when OldV =/= NewV ->
                    {error, {output_value_changed, Idx, OldV, NewV}};
                _ when NewV > OldV, Idx =:= FeeIdx ->
                    {error, {fee_output_grew, Idx, OldV, NewV}};
                _ ->
                    check_outputs_pairwise(OT, NT, Idx + 1, FeeIdx)
            end
    end.

%%% ===================================================================
%%% G11 — scriptSig types preserved
%%% ===================================================================

%% For every Original input, the returned PSBT input at the same index
%% must classify as the same script type. Mixed-script PayJoins are a
%% known fingerprint (e.g. P2WPKH + P2SH-P2WPKH on the same tx).
g11_scriptsig_types_preserved(#psbt{inputs = OldIns,
                                    unsigned_tx = OldTx},
                              #psbt{inputs = NewIns}) ->
    OldCount = length(OldTx#transaction.inputs),
    %% Only inspect the leading OldCount inputs of the new PSBT (any
    %% extras are receiver-added; G12 covers those).
    case length(NewIns) >= OldCount of
        false ->
            {error, {missing_sender_inputs,
                     OldCount, length(NewIns)}};
        true ->
            {NewHead, _} = lists:split(OldCount, NewIns),
            check_inputs_pairwise_types(OldIns, NewHead, 0)
    end.

check_inputs_pairwise_types([], [], _) -> ok;
check_inputs_pairwise_types([OldMap | OT], [NewMap | NT], Idx) ->
    case {script_from_map(OldMap), script_from_map(NewMap)} of
        {undefined, _} ->
            %% Original input had no UTXO info — receiver shouldn't be
            %% able to fix that, accept anything.
            check_inputs_pairwise_types(OT, NT, Idx + 1);
        {_, undefined} ->
            {error, {missing_utxo_in_payjoin, Idx}};
        {OldS, NewS} ->
            T1 = classify_script_type(OldS),
            T2 = classify_script_type(NewS),
            case T1 =:= T2 of
                true  -> check_inputs_pairwise_types(OT, NT, Idx + 1);
                false -> {error, {script_type_changed, Idx, T1, T2}}
            end
    end.

script_from_map(M) ->
    case maps:get(witness_utxo, M, undefined) of
        {_V, S} when is_binary(S) -> S;
        _ -> undefined
    end.

%% Coarse classification — finer-grained taproot etc. could be added
%% later. P2WPKH/P2WSH/P2PKH/P2SH cover all wallet-relevant types today.
classify_script_type(<<16#00, 20, _:20/binary>>)      -> p2wpkh;
classify_script_type(<<16#00, 32, _:32/binary>>)      -> p2wsh;
classify_script_type(<<16#51, 32, _:32/binary>>)      -> p2tr;
classify_script_type(<<16#76, 16#a9, 20, _:20/binary,
                       16#88, 16#ac>>)                -> p2pkh;
classify_script_type(<<16#a9, 20, _:20/binary, 16#87>>) -> p2sh;
classify_script_type(_)                                 -> unknown.

%%% ===================================================================
%%% G12 — no new sender inputs introduced
%%% ===================================================================

%% Every input present in the returned PSBT that wasn't in the
%% Original (by outpoint) must be NOT sender-owned. A malicious
%% receiver claiming "your wallet's UTXO got added by us" would let
%% them double-spend a sender UTXO out from under them.
g12_no_new_sender_inputs(#psbt{unsigned_tx = OldTx},
                         #psbt{unsigned_tx = NewTx, inputs = NewIns},
                         SenderOwnedFun) ->
    OldSet = sets:from_list([outpoint_key(I) ||
                                I <- OldTx#transaction.inputs]),
    NewIndexed = lists:zip(lists:seq(0, length(NewTx#transaction.inputs) - 1),
                           lists:zip(NewTx#transaction.inputs, NewIns)),
    NewIns2 = [{Idx, TxIn, Map} ||
                  {Idx, {TxIn, Map}} <- NewIndexed,
                  not sets:is_element(outpoint_key(TxIn), OldSet)],
    check_no_sender_in_new(NewIns2, SenderOwnedFun).

check_no_sender_in_new([], _) -> ok;
check_no_sender_in_new([{Idx, _TxIn, Map} | Rest], SenderOwnedFun) ->
    case maps:get(witness_utxo, Map, undefined) of
        {_, S} when is_binary(S) ->
            case SenderOwnedFun(S) of
                true  -> {error, {sender_input_added, Idx}};
                false -> check_no_sender_in_new(Rest, SenderOwnedFun)
            end;
        _ ->
            %% No utxo info — defensive: treat as suspect.
            {error, {receiver_added_input_no_utxo, Idx}}
    end.

outpoint_key(#tx_in{prev_out = #outpoint{hash = H, index = I}}) ->
    {H, I}.

%%% ===================================================================
%%% G13 — fee within max_additional_fee_contribution
%%% ===================================================================

%% The receiver MUST NOT increase the absolute fee beyond
%% max_additional_fee_contribution sat over the Original. We compute
%% fee via (sum_in - sum_out) using witness_utxo prev-amounts on each
%% input map. Missing prev info on receiver-added inputs is fatal
%% (G12 already requires them).
g13_fee_within_cap(OriginalPsbt, PayjoinPsbt, MaxAddSat, _FeeIdx) ->
    case {compute_fee(OriginalPsbt, conservative),
          compute_fee(PayjoinPsbt, conservative)} of
        {{ok, OldFee}, {ok, NewFee}} ->
            Delta = NewFee - OldFee,
            case Delta =< MaxAddSat of
                true  -> ok;
                false -> {error, {fee_cap_exceeded, OldFee, NewFee, MaxAddSat}}
            end;
        {Err, _} when element(1, Err) =:= error -> Err;
        {_, Err}                                 -> Err
    end.

%% conservative: when an input map has no witness_utxo, treat its prev
%% value as 0 (will underestimate inputs → overestimate negative fee).
compute_fee(#psbt{unsigned_tx = Tx, inputs = Inputs}, conservative) ->
    case length(Tx#transaction.inputs) =:= length(Inputs) of
        false ->
            {error, {input_count_mismatch,
                     length(Tx#transaction.inputs), length(Inputs)}};
        true ->
            SumIn = lists:foldl(fun(M, Acc) ->
                case maps:get(witness_utxo, M, undefined) of
                    {V, _} when is_integer(V) -> Acc + V;
                    _ -> Acc
                end
            end, 0, Inputs),
            SumOut = lists:sum(
                       [V || #tx_out{value = V} <- Tx#transaction.outputs]),
            {ok, SumIn - SumOut}
    end.

%%% ===================================================================
%%% G14 — disableoutputsubstitution honoured
%%% ===================================================================

%% When sender sent pjos=1 ("disable output substitution"), the
%% receiver MUST NOT mutate any output other than the
%% additionalfeeoutputindex output's value. Mutation of any other
%% output (value OR scriptPubKey) is a violation.
g14_disable_output_substitution(_, _, false, _) ->
    ok;
g14_disable_output_substitution(#psbt{unsigned_tx = OldTx},
                                #psbt{unsigned_tx = NewTx},
                                true,
                                FeeIdx) ->
    Old = OldTx#transaction.outputs,
    New = NewTx#transaction.outputs,
    case length(New) =:= length(Old) of
        false ->
            {error, {output_count_mismatch, length(Old), length(New)}};
        true ->
            check_outputs_no_subst(Old, New, 0, FeeIdx)
    end.

check_outputs_no_subst([], [], _, _) -> ok;
check_outputs_no_subst([#tx_out{value = OldV, script_pubkey = OldS} | OT],
                       [#tx_out{value = NewV, script_pubkey = NewS} | NT],
                       Idx, FeeIdx) ->
    SameScript = OldS =:= NewS,
    SameValue  = OldV =:= NewV,
    IsFeeOut   = Idx =:= FeeIdx,
    case {SameScript, SameValue, IsFeeOut} of
        {true, true, _}    -> check_outputs_no_subst(OT, NT, Idx + 1, FeeIdx);
        {true, false, true} ->
            %% value change on fee output allowed even with pjos=1
            %% (BIP-78 says output substitution = swap-out the receiver
            %%  output for a different scriptPubKey; pure fee docking is
            %%  still allowed because it doesn't change identities).
            check_outputs_no_subst(OT, NT, Idx + 1, FeeIdx);
        {true, false, false} ->
            {error, {output_value_changed_pjos, Idx, OldV, NewV}};
        {false, _, _} ->
            {error, {output_script_changed_pjos, Idx, OldS, NewS}}
    end.

%%% ===================================================================
%%% G15 — minfeerate enforced on returned Payjoin PSBT
%%% ===================================================================

%% The effective fee rate of the returned PSBT must be at least the
%% minfeerate (sat/vB) the sender specified. We use a coarse vsize
%% estimate: 4 * base + witness ≈ 4 * (10 + 41*ins + ~31*outs) plus an
%% estimated 105 wu per signed P2WPKH input (signature + pubkey). The
%% precise number doesn't matter — anything in the right ballpark
%% catches "rate dropped 10x lower than asked" attacks.
g15_min_fee_rate(_PayjoinPsbt, 0, _Hints) ->
    %% MinFeeRate=0 means "no floor" per BIP-78 — skip.
    ok;
g15_min_fee_rate(PayjoinPsbt, MinFeeRate, _Hints) ->
    case compute_fee(PayjoinPsbt, conservative) of
        {ok, Fee} ->
            VSize = vsize(PayjoinPsbt),
            case VSize > 0 of
                false -> {error, {bad_vsize, VSize}};
                true ->
                    Rate = Fee / VSize,
                    case Rate >= MinFeeRate of
                        true  -> ok;
                        false ->
                            {error, {fee_rate_below_floor, Rate, MinFeeRate}}
                    end
            end;
        Err -> Err
    end.

%% Coarse vsize estimate. 4*base + total_witness ≈ ... Good enough for
%% a sat/vB sanity floor. We assume every input is P2WPKH (~110 wu).
%% Overestimates witness for legacy → conservative on the "rate too
%% low" side (we'd reject borderline-OK txns rather than accept).
vsize(#psbt{unsigned_tx = Tx}) ->
    NumIn  = length(Tx#transaction.inputs),
    NumOut = length(Tx#transaction.outputs),
    Base   = 10 + 41 * NumIn + 31 * NumOut,
    Wit    = 110 * NumIn,
    %% vsize = ceil((4 * base + witness) / 4)
    (4 * Base + Wit + 3) div 4.
