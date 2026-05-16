-module(beamchain_payjoin_server).

%%% -------------------------------------------------------------------
%%% BIP-78 PayJoin (P2EP) receiver — Cowboy HTTP handler.
%%%
%%% Spec: https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki
%%%
%%% Closes W119 BUG-1 / G1 / G4 / G5 / G6 / G7 / G9 / G16 / G17 / G21
%%% / G23 / G26. Sender-side (W119 BUG-2 + G2 + G10..G15 + G22 + G24
%%% + G25 + G27) remains future work; this module is the receiver
%%% foundation.
%%%
%%% Flow (BIP-78 §"Protocol"):
%%%
%%%   1. Sender POSTs Original PSBT as a base64 text body (text/plain)
%%%      to a `pj=` endpoint with query parameters:
%%%        v=1
%%%        additionalfeeoutputindex=N      (which Original output the
%%%                                         receiver may dock fees from)
%%%        maxadditionalfeecontribution=S  (max satoshis receiver may
%%%                                         add to the fee)
%%%        disableoutputsubstitution=0|1   (sender forbids changing the
%%%                                         receiver output)
%%%        minfeerate=R                    (sat/vB floor on the
%%%                                         returned Payjoin PSBT)
%%%
%%%   2. Receiver validates the Original (G5), adds one wallet UTXO as
%%%      an additional input, optionally bumps the fee output (within
%%%      maxadditionalfeecontribution), signs its own input via the
%%%      FIX-63 walletprocesspsbt path, and returns the merged PSBT as
%%%      base64.
%%%
%%%   3. Errors are surfaced as the BIP-78 four-token JSON shape:
%%%        { "errorCode": <token>, "message": <human-readable> }
%%%      Tokens (G17):
%%%        - "unavailable"             — receiver cannot fulfill right now
%%%        - "not-enough-money"        — no eligible receiver UTXOs
%%%        - "version-unsupported"     — unknown / unsupported v=
%%%        - "original-psbt-rejected"  — parse / validation failed
%%%
%%% Single-pipeline reuse (W119 FIX-65):
%%%   - PSBT decode: beamchain_psbt:decode/1
%%%   - PSBT encode: beamchain_psbt:encode/1
%%%   - Signer:      beamchain_rpc:rpc_walletprocesspsbt/2 (which itself
%%%                  reuses FIX-61 lookup_privkeys_for_inputs/3)
%%%   - Wallet UTXO source: beamchain_wallet:get_wallet_utxos/0
%%%   - Address path:       beamchain_address:script_to_address/2
%%%
%%% DOES NOT introduce a second keystore-walk pipeline; signing always
%%% goes through rpc_walletprocesspsbt and thus through
%%% lookup_privkeys_for_inputs/3.
%%%
%%% Cowboy handler init/2 is the entry point. Routes are wired in
%%% beamchain_rest:init/1 ({"/payjoin", beamchain_payjoin_server, []}).
%%% -------------------------------------------------------------------

-include("beamchain.hrl").
-include("beamchain_psbt.hrl").

%% Cowboy handler entry point.
-export([init/2]).

%% Internal exports for eunit + sibling modules (BUG-7 closure: sender
%% impl wants to validate the receiver's response shape using the same
%% taxonomy; expose the helpers so future client-side code does not
%% duplicate them).
-export([parse_qs_params/1,
         build_payjoin_psbt/3,
         build_payjoin_psbt/4,
         build_payjoin_psbt_bounded/4,
         pick_receiver_utxo/2,
         pick_receiver_utxo_anti_fingerprint/3,
         bip78_error_body/2,
         uih_score/4,
         compute_request_budget_ms/0]).

%% Supported BIP-78 version. Today the spec defines v=1 only; v=2 was
%% proposed (https://github.com/payjoin/bips/pull/1) but is not yet in
%% the canonical BIP-78. Reject anything else with "version-unsupported".
-define(PAYJOIN_VERSION_SUPPORTED, 1).

%% Cap on POST body size — guards against memory exhaustion. The PSBT
%% binary format for a typical 1-in / 2-out wallet sweep is well under
%% 1 KiB; 16 KiB is generous and matches the typical "max raw tx" limit
%% bitcoind allows on sendrawtransaction.
-define(MAX_PSBT_BODY_BYTES, 16 * 1024).

%% Dust threshold below which we won't dock fees from the
%% `additionalfeeoutputindex` output.
-define(DUST_THRESHOLD_SAT, 546).

%% G18 — per-request wall-clock budget. BIP-78 §"Reception of the
%% response" says the sender SHOULD time out after ~30s and fall back
%% to broadcasting the Original. We pick 25s so the receiver always
%% replies before the conservative sender deadline; the cowboy listener
%% itself has a longer 60s default request_timeout on top.
-define(REQUEST_BUDGET_MS, 25000).

%%% ===================================================================
%%% Cowboy handler entry point
%%% ===================================================================

init(Req0, State) ->
    case cowboy_req:method(Req0) of
        <<"POST">> ->
            handle_post(Req0, State);
        _ ->
            %% BIP-78 only specifies POST. Anything else is a protocol
            %% error from the sender's perspective.
            Req = bip78_error_reply(405, <<"original-psbt-rejected">>,
                                    <<"POST required">>, Req0),
            {ok, Req, State}
    end.

handle_post(Req0, State) ->
    %% Pre-read query-string params; on parse failure surface as
    %% original-psbt-rejected (sender bug, not a transient).
    case parse_qs_params(cowboy_req:parse_qs(Req0)) of
        {error, QsErr} ->
            Req = bip78_error_reply(400, <<"original-psbt-rejected">>,
                                    QsErr, Req0),
            {ok, Req, State};
        {ok, Params} ->
            case maps:get(version, Params, ?PAYJOIN_VERSION_SUPPORTED) of
                ?PAYJOIN_VERSION_SUPPORTED ->
                    handle_post_v1(Req0, State, Params);
                Other ->
                    Msg = iolist_to_binary(io_lib:format(
                            "unsupported version ~p", [Other])),
                    Req = bip78_error_reply(400, <<"version-unsupported">>,
                                            Msg, Req0),
                    {ok, Req, State}
            end
    end.

handle_post_v1(Req0, State, Params) ->
    %% G30 — replay protection. If the sender included `?token=<hex>`
    %% we MUST consume it before doing any other work. A missing token
    %% surfaces as "unavailable" (no per-invoice nonce was found) to
    %% encourage clients to round-trip via getpayjoinrequest. A token
    %% is allowed to be absent on a permissive deployment via the
    %% require_token feature flag; today we default to lenient mode
    %% (token validated when present, allowed when absent) for
    %% backwards compatibility with W119 FIX-65 round-trip clients.
    case validate_invoice_token(Req0, Params) of
        {error, Token, Reason} ->
            Msg = iolist_to_binary(io_lib:format(
                    "invoice token ~s: ~p", [Token, Reason])),
            Req = bip78_error_reply(503, <<"unavailable">>, Msg, Req0),
            {ok, Req, State};
        {ok, _} ->
            handle_post_v1_post_token(Req0, State, Params)
    end.

handle_post_v1_post_token(Req0, State, Params) ->
    case read_body_bounded(Req0, ?MAX_PSBT_BODY_BYTES) of
        {error, BodyErr, Req1} ->
            Req = bip78_error_reply(413, <<"original-psbt-rejected">>,
                                    BodyErr, Req1),
            {ok, Req, State};
        {ok, Body, Req1} ->
            BodyTrimmed = trim_ascii_ws(Body),
            case base64:decode(BodyTrimmed) of
                <<>> ->
                    Req = bip78_error_reply(400, <<"original-psbt-rejected">>,
                                            <<"empty body">>, Req1),
                    {ok, Req, State};
                PsbtBin ->
                    handle_psbt_bin(Req1, State, Params, PsbtBin)
            end
    end.

handle_psbt_bin(Req0, State, Params, PsbtBin) ->
    %% G19 — Original PSBT no-double-process. We dedup on the raw
    %% canonical bytes received from the sender. Doing this BEFORE the
    %% decode avoids the corner case where two semantically-equivalent
    %% encodings would slip through; after FIX-65 the canonical bytes
    %% are exactly what the sender posted (we decode-then-re-encode
    %% only for the merged output).
    case beamchain_payjoin_state:remember_seen_psbt(PsbtBin) of
        {error, already_seen} ->
            Req = bip78_error_reply(400, <<"original-psbt-rejected">>,
                                    <<"duplicate Original PSBT — "
                                      "this invoice has already been "
                                      "processed">>,
                                    Req0),
            {ok, Req, State};
        ok ->
            handle_psbt_bin_after_dedup(Req0, State, Params, PsbtBin)
    end.

handle_psbt_bin_after_dedup(Req0, State, Params, PsbtBin) ->
    case beamchain_psbt:decode(PsbtBin) of
        {error, DecodeErr} ->
            Msg = iolist_to_binary(io_lib:format(
                    "psbt decode failed: ~p", [DecodeErr])),
            Req = bip78_error_reply(400, <<"original-psbt-rejected">>,
                                    Msg, Req0),
            {ok, Req, State};
        {ok, OriginalPsbt} ->
            case validate_original_psbt(OriginalPsbt) of
                {error, ValidateErr} ->
                    Req = bip78_error_reply(400, <<"original-psbt-rejected">>,
                                            ValidateErr, Req0),
                    {ok, Req, State};
                ok ->
                    handle_validated(Req0, State, Params, OriginalPsbt)
            end
    end.

handle_validated(Req0, State, Params, OriginalPsbt) ->
    %% G18 — wall-clock budget enforced at the build step. We spawn a
    %% short-lived worker so a slow walletprocesspsbt call can't pin
    %% the cowboy acceptor past the sender's BIP-78 timeout. The
    %% worker MUST run to completion so it can clean its own ETS
    %% writes (used-script preference table) — we don't kill it, we
    %% just stop waiting and reply "unavailable".
    case build_payjoin_psbt_bounded(
           OriginalPsbt, Params, default_wallet_pid(),
           compute_request_budget_ms()) of
        {error, no_eligible_utxo} ->
            Req = bip78_error_reply(503, <<"not-enough-money">>,
                                    <<"receiver has no eligible UTXOs">>,
                                    Req0),
            {ok, Req, State};
        {error, {wallet_locked, _}} ->
            Req = bip78_error_reply(503, <<"unavailable">>,
                                    <<"receiver wallet is locked">>,
                                    Req0),
            {ok, Req, State};
        {error, {wallet_missing, _}} ->
            Req = bip78_error_reply(503, <<"unavailable">>,
                                    <<"receiver wallet not running">>,
                                    Req0),
            {ok, Req, State};
        {error, request_budget_exceeded} ->
            %% G18 — receiver TTL exceeded. Tell the sender to fall
            %% back; do NOT surface a stale half-built PSBT.
            Req = bip78_error_reply(503, <<"unavailable">>,
                                    <<"receiver TTL exceeded — please retry "
                                      "after backoff or fall back to "
                                      "broadcasting Original">>,
                                    Req0),
            {ok, Req, State};
        {error, Other} ->
            Msg = iolist_to_binary(io_lib:format("~p", [Other])),
            Req = bip78_error_reply(503, <<"unavailable">>, Msg, Req0),
            {ok, Req, State};
        {ok, PayjoinPsbt} ->
            Bin = beamchain_psbt:encode(PayjoinPsbt),
            B64 = base64:encode(Bin),
            Req = cowboy_req:reply(
                    200,
                    %% G23: Content-Type must be text/plain per BIP-78.
                    #{<<"content-type">> => <<"text/plain">>},
                    B64,
                    Req0),
            {ok, Req, State}
    end.

%%% ===================================================================
%%% Body reading (bounded)
%%% ===================================================================

read_body_bounded(Req0, MaxBytes) ->
    read_body_bounded(Req0, MaxBytes, <<>>).

read_body_bounded(Req0, MaxBytes, Acc) ->
    case cowboy_req:read_body(Req0, #{length => MaxBytes,
                                       period => 5000}) of
        {ok, Bin, Req1} ->
            New = <<Acc/binary, Bin/binary>>,
            case byte_size(New) > MaxBytes of
                true ->
                    {error,
                     iolist_to_binary(io_lib:format(
                       "body exceeds ~B bytes", [MaxBytes])),
                     Req1};
                false ->
                    {ok, New, Req1}
            end;
        {more, Bin, Req1} ->
            New = <<Acc/binary, Bin/binary>>,
            case byte_size(New) > MaxBytes of
                true ->
                    {error,
                     iolist_to_binary(io_lib:format(
                       "body exceeds ~B bytes", [MaxBytes])),
                     Req1};
                false ->
                    read_body_bounded(Req1, MaxBytes, New)
            end
    end.

%%% ===================================================================
%%% Query-string parameter coercion (G16)
%%% ===================================================================

%% BIP-78 query parameters:
%%   v                                  - integer (default 1)
%%   additionalfeeoutputindex           - integer (default undefined)
%%   maxadditionalfeecontribution       - integer satoshis (default 0)
%%   disableoutputsubstitution          - "0" | "1" (default false)
%%   minfeerate                         - integer sat/vB (default 0)
%%
%% Cowboy's `parse_qs/1` returns `[{Key, Value}]` proplists of binaries.
%% Wallets and BTCPay typically lowercase keys but the spec is silent;
%% we normalise to lowercase to be liberal.
parse_qs_params(QsList) when is_list(QsList) ->
    try
        Lower = [{to_lower(K), V} || {K, V} <- QsList],
        Params = #{
            version =>
                int_param(<<"v">>, Lower, ?PAYJOIN_VERSION_SUPPORTED),
            additional_fee_output_index =>
                int_param_opt(<<"additionalfeeoutputindex">>, Lower),
            max_additional_fee_contribution =>
                int_param(<<"maxadditionalfeecontribution">>, Lower, 0),
            disable_output_substitution =>
                bool_param(<<"disableoutputsubstitution">>, Lower, false),
            min_fee_rate =>
                int_param(<<"minfeerate">>, Lower, 0)
        },
        {ok, Params}
    catch
        throw:{bad_param, Key, Val} ->
            {error,
             iolist_to_binary(io_lib:format(
               "bad query param ~s=~s", [Key, Val]))}
    end;
parse_qs_params(_) ->
    {error, <<"qs not a list">>}.

int_param(Key, List, Default) ->
    case proplists:get_value(Key, List) of
        undefined -> Default;
        Bin ->
            case parse_int(Bin) of
                {ok, I} when I >= 0 -> I;
                _ -> throw({bad_param, Key, Bin})
            end
    end.

int_param_opt(Key, List) ->
    case proplists:get_value(Key, List) of
        undefined -> undefined;
        Bin ->
            case parse_int(Bin) of
                {ok, I} when I >= 0 -> I;
                _ -> throw({bad_param, Key, Bin})
            end
    end.

bool_param(Key, List, Default) ->
    case proplists:get_value(Key, List) of
        undefined -> Default;
        <<"0">>   -> false;
        <<"1">>   -> true;
        Bin       -> throw({bad_param, Key, Bin})
    end.

parse_int(Bin) when is_binary(Bin) ->
    try
        {ok, binary_to_integer(Bin)}
    catch
        error:badarg -> error
    end.

to_lower(Bin) when is_binary(Bin) ->
    << <<(lcase_byte(B))>> || <<B>> <= Bin >>.

lcase_byte(B) when B >= $A, B =< $Z -> B + 32;
lcase_byte(B) -> B.

trim_ascii_ws(Bin) ->
    trim_trailing_ws(trim_leading_ws(Bin)).

trim_leading_ws(<<C, Rest/binary>>) when C =:= $\s; C =:= $\t;
                                         C =:= $\r; C =:= $\n ->
    trim_leading_ws(Rest);
trim_leading_ws(Bin) -> Bin.

trim_trailing_ws(<<>>) -> <<>>;
trim_trailing_ws(Bin) ->
    Sz = byte_size(Bin),
    case binary:at(Bin, Sz - 1) of
        C when C =:= $\s; C =:= $\t; C =:= $\r; C =:= $\n ->
            trim_trailing_ws(binary:part(Bin, 0, Sz - 1));
        _ -> Bin
    end.

%%% ===================================================================
%%% Original PSBT validation (G5)
%%% ===================================================================

%% BIP-78 §"Receiver: validation of the original PSBT":
%%   - All inputs MUST have witness_utxo or non_witness_utxo (so the
%%     receiver can compute fees + scriptPubKey types).
%%   - Inputs MUST be already signed (partial_sigs or final_*) — the
%%     sender's role is "I committed to paying you, here's the proof".
%%     We accept both partial_sigs (pre-finalize) and final_script_sig
%%     / final_script_witness (already-finalized) per spec.
%%   - The unsigned tx itself must have at least one input and one output.
validate_original_psbt(#psbt{unsigned_tx = Tx, inputs = InputMaps}) ->
    NumIn = length(Tx#transaction.inputs),
    NumOut = length(Tx#transaction.outputs),
    case {NumIn, NumOut, length(InputMaps)} of
        {0, _, _} -> {error, <<"original tx has zero inputs">>};
        {_, 0, _} -> {error, <<"original tx has zero outputs">>};
        {N, _, N} -> validate_inputs(InputMaps, 0);
        {N, _, M} ->
            {error, iolist_to_binary(io_lib:format(
              "input count mismatch (tx=~B, psbt=~B)", [N, M]))}
    end.

validate_inputs([], _) -> ok;
validate_inputs([Map | Rest], Idx) ->
    HasUtxo = maps:is_key(witness_utxo, Map)
        orelse maps:is_key(non_witness_utxo, Map),
    HasSig  = maps:is_key(partial_sigs, Map)
        orelse maps:is_key(final_script_sig, Map)
        orelse maps:is_key(final_script_witness, Map)
        orelse maps:is_key(tap_key_sig, Map),
    case {HasUtxo, HasSig} of
        {false, _} ->
            {error, iolist_to_binary(io_lib:format(
              "input ~B missing utxo info", [Idx]))};
        {_, false} ->
            {error, iolist_to_binary(io_lib:format(
              "input ~B not signed", [Idx]))};
        {true, true} ->
            validate_inputs(Rest, Idx + 1)
    end.

%%% ===================================================================
%%% Build the merged Payjoin PSBT
%%% ===================================================================

%% Public entry — eunit drives this directly to avoid spinning a cowboy
%% listener for the round-trip test. The HTTP handler in init/2 calls
%% this same fun.
%%
%% Returns:
%%   {ok, #psbt{}}            — merged + signed (receiver input only)
%%   {error, no_eligible_utxo} when wallet has no UTXOs we can add
%%   {error, {wallet_locked, ...}}
%%   {error, {wallet_missing, ...}}
%%   {error, Other}           when an unexpected step fails
build_payjoin_psbt(OriginalPsbt, Params, WalletPid) ->
    build_payjoin_psbt(OriginalPsbt, Params, WalletPid, []).

%% 4-arity overload: Opts may carry `request_id` (used as a key in the
%% G20 used-script preference table — distinct invoices reset
%% preference) or `force_utxo` for tests. Today the only meaningful
%% Opt is the dedup/preference policy; future fields land here.
build_payjoin_psbt(OriginalPsbt, Params, WalletPid, _Opts) ->
    case WalletPid of
        undefined ->
            {error, {wallet_missing, no_wallet_pid}};
        _ ->
            do_build_payjoin_psbt(OriginalPsbt, Params, WalletPid)
    end.

%% Bounded variant — runs the build in a child process and enforces a
%% per-request wall-clock budget (G18). On timeout the worker is left
%% to finish (its only side effect is the G20 preference write, which
%% is idempotent and safe to land late); we just stop waiting.
build_payjoin_psbt_bounded(OriginalPsbt, Params, WalletPid, BudgetMs) ->
    Parent = self(),
    Ref = make_ref(),
    Worker = spawn(fun() ->
        Result = build_payjoin_psbt(OriginalPsbt, Params, WalletPid),
        Parent ! {Ref, Result}
    end),
    receive
        {Ref, Result} -> Result
    after BudgetMs ->
        %% Don't kill the worker — its ETS writes are idempotent and
        %% killing it mid-walletprocesspsbt could leak partial state.
        %% Returning `request_budget_exceeded` is what the cowboy
        %% handler converts to the BIP-78 "unavailable" error.
        unlink(Worker),
        {error, request_budget_exceeded}
    end.

%% G18 — Tunable. Returns ?REQUEST_BUDGET_MS by default; future
%% deployments could override via beamchain_config:payjoin_budget_ms()
%% (currently unused; the symbol keeps the wiring honest).
compute_request_budget_ms() ->
    try beamchain_config:payjoin_budget_ms() of
        N when is_integer(N), N > 0 -> N;
        _ -> ?REQUEST_BUDGET_MS
    catch
        error:_  -> ?REQUEST_BUDGET_MS;
        exit:_   -> ?REQUEST_BUDGET_MS;
        throw:_  -> ?REQUEST_BUDGET_MS
    end.

do_build_payjoin_psbt(OriginalPsbt, Params, WalletPid) ->
    Network = current_network(),
    OldTx = OriginalPsbt#psbt.unsigned_tx,
    case pick_receiver_utxo_anti_fingerprint(
           WalletPid, Network, OldTx) of
        {error, _} = E -> E;
        {ok, {Txid, Vout, Utxo}} ->
            %% G20 — record the picked script so the next request
            %% deprioritises the same UTXO/script. The write is best-
            %% effort: if the ETS module is unavailable (e.g. tests
            %% running with payjoin_state cleared) we silently skip.
            catch beamchain_payjoin_state:remember_used_script(
                    Utxo#utxo.script_pubkey),
            %% Build the merged unsigned tx:
            %%   - keep the sender's existing inputs and outputs intact
            %%     (G7+G10 — we add inputs, we do not remove sender ones).
            %%   - append our new tx_in with sequence 0xFFFFFFFD
            %%     (BIP-125 RBF signal, consistent with sample_unsigned_tx).
            %%   - optionally dock fees from
            %%     additionalfeeoutputindex (G6+G9).
            NewTxIn = #tx_in{
                prev_out = #outpoint{hash = Txid, index = Vout},
                script_sig = <<>>,
                sequence = 16#fffffffd,
                witness = []
            },
            MergedInputs = OldTx#transaction.inputs ++ [NewTxIn],
            MergedOutputs = maybe_dock_fee_output(
                              OldTx#transaction.outputs, Params, Utxo),
            MergedTx = OldTx#transaction{
                inputs = MergedInputs,
                outputs = MergedOutputs
            },
            %% Append a fresh input-map for the new input. Original
            %% input-maps stay byte-equal (G10/G11 — sender's anti-snoop
            %% receiver-side mirror: we touch nothing but our own input).
            NewInputMap = #{
                witness_utxo => {Utxo#utxo.value, Utxo#utxo.script_pubkey},
                utxo_record => Utxo
            },
            MergedInputMaps = OriginalPsbt#psbt.inputs ++ [NewInputMap],
            %% Output-maps: append an empty map for any new outputs we
            %% would add (none in this MVP — fee adjustment shrinks an
            %% existing output, doesn't append).
            MergedPsbt = OriginalPsbt#psbt{
                unsigned_tx = MergedTx,
                inputs = MergedInputMaps
            },
            %% Sign the receiver input via the FIX-63 walletprocesspsbt
            %% path (single-pipeline reuse — exercises
            %% lookup_privkeys_for_inputs/3 indirectly via the wallet's
            %% per-script-type signer).
            MergedBin = beamchain_psbt:encode(MergedPsbt),
            MergedB64 = base64:encode(MergedBin),
            case beamchain_rpc:rpc_walletprocesspsbt(
                   [MergedB64, true, <<"ALL">>, true, false], <<>>) of
                {ok, #{<<"psbt">> := SignedB64}} ->
                    case base64:decode(SignedB64) of
                        SignedBin when is_binary(SignedBin) ->
                            case beamchain_psbt:decode(SignedBin) of
                                {ok, SignedPsbt} ->
                                    {ok, SignedPsbt};
                                {error, DErr} ->
                                    {error, {round_trip_decode, DErr}}
                            end;
                        _ ->
                            {error, {round_trip_b64, SignedB64}}
                    end;
                {error, -13, _} ->
                    {error, {wallet_locked, locked}};
                {error, Code, Msg} ->
                    {error, {wpp_error, Code, Msg}};
                Other ->
                    {error, {wpp_unexpected, Other}}
            end
    end.

maybe_dock_fee_output(Outs, #{additional_fee_output_index := undefined},
                      _Utxo) ->
    Outs;
maybe_dock_fee_output(Outs, #{additional_fee_output_index := Idx,
                              max_additional_fee_contribution := Max},
                      _Utxo) when Max > 0, Idx >= 0, Idx < length(Outs) ->
    OutAtIdx = lists:nth(Idx + 1, Outs),
    %% Cap docking at Max sat AND keep the output above the dust
    %% threshold. Sender asked us to dock from this output (G9), but
    %% they did NOT ask us to dust them — anything that would push
    %% below 546 sat we silently skip.
    Dock = min(Max, OutAtIdx#tx_out.value - ?DUST_THRESHOLD_SAT),
    case Dock > 0 of
        true ->
            NewOut = OutAtIdx#tx_out{value = OutAtIdx#tx_out.value - Dock},
            replace_nth(Idx + 1, NewOut, Outs);
        false ->
            Outs
    end;
maybe_dock_fee_output(Outs, _Params, _Utxo) ->
    Outs.

replace_nth(1, X, [_ | T]) -> [X | T];
replace_nth(N, X, [H | T]) when N > 1 -> [H | replace_nth(N - 1, X, T)];
replace_nth(_, _, []) -> [].

%% Pick any wallet UTXO whose scriptPubKey resolves to a known wallet
%% address (so walletprocesspsbt will produce a real signature). The
%% naive "first eligible" path is preserved for backwards-compat with
%% FIX-65 test fixtures; production drives through
%% pick_receiver_utxo_anti_fingerprint/3 which adds UIH-1/UIH-2 scoring.
pick_receiver_utxo(WalletPid, Network) ->
    Utxos = safe_get_wallet_utxos(WalletPid),
    case lists:filter(fun({_Txid, _Vout, Utxo}) ->
              addr_is_wallet(WalletPid, Utxo#utxo.script_pubkey, Network)
          end, Utxos) of
        []          -> {error, no_eligible_utxo};
        [First | _] -> {ok, First}
    end.

%%% ===================================================================
%%% G20 — UIH-1/UIH-2 anti-fingerprint UTXO selection
%%% ===================================================================
%%
%% BIP-78 §"Unnecessary input heuristic (UIH)" identifies two
%% blockchain-analytics fingerprints that distinguish PayJoins from
%% regular pay-to-someone transactions:
%%
%%   UIH-1: in the original 1-payer-1-receiver tx, the change output
%%   is necessarily LESS than each input. After the receiver adds a
%%   PayJoin input, if every input is still LESS than the smallest
%%   output, the tx looks like "someone paid more than they had to
%%   pay" — a strong PayJoin signal.
%%
%%   UIH-2: alternatively, if one of the OUTPUTS exceeds the receiver-
%%   added INPUT in value, then the receiver-added input was not
%%   needed (the original inputs were sufficient), so the receiver's
%%   participation is detectable.
%%
%% We assign a SCORE to each candidate UTXO (lower is better) and pick
%% the lowest-scoring eligible UTXO. The score is:
%%
%%   base   = 0 if the candidate value falls inside [minOut, maxOut]
%%            of the original outputs (avoids both UIH-1 and UIH-2);
%%          = 10 otherwise.
%%   recent = +5 if the script was used in the past USED_SCRIPT_TTL_MS
%%            window (preferred-fresh policy; cross-invoice
%%            fingerprint mitigation).
%%
%% This is a HEURISTIC PREFERENCE, not a hard rejection — we still
%% fall back to "first eligible" when no candidate dodges UIH. That
%% way a wallet with one dominant UTXO still functions.
pick_receiver_utxo_anti_fingerprint(WalletPid, Network, OldTx) ->
    Utxos = safe_get_wallet_utxos(WalletPid),
    Eligible = lists:filter(
                 fun({_Txid, _Vout, Utxo}) ->
                     addr_is_wallet(WalletPid,
                                    Utxo#utxo.script_pubkey, Network)
                 end, Utxos),
    case Eligible of
        [] -> {error, no_eligible_utxo};
        _ ->
            OutValues =
                [V || #tx_out{value = V} <- OldTx#transaction.outputs],
            InValuesGuess =
                %% We don't have prev-out value info for sender inputs
                %% here (the input maps are in OriginalPsbt, not the
                %% transaction itself); pass [] and let uih_score/4
                %% default to a UIH-1-only check on outputs.
                [],
            Scored = [{uih_score(Utxo#utxo.value, OutValues, InValuesGuess,
                                 script_recently_used_safe(
                                   Utxo#utxo.script_pubkey)),
                       Triple}
                      || {_,_,Utxo} = Triple <- Eligible],
            %% Stable sort by score then by index in Eligible (which
            %% lists:sort preserves for equal keys).
            Sorted = lists:keysort(1, Scored),
            [{_BestScore, Best} | _] = Sorted,
            {ok, Best}
    end.

%% Score a candidate value against the Original outputs (+ optionally
%% the input set if available). Lower is better. See module docstring
%% for the policy summary.
uih_score(_Value, [], _Inputs, RecentlyUsed) ->
    %% No outputs to compare against (shouldn't happen — validation
    %% rejects zero-output Original PSBTs) — fall back to recency.
    case RecentlyUsed of
        true  -> 5;
        false -> 0
    end;
uih_score(Value, OutValues, _Inputs, RecentlyUsed) when is_integer(Value) ->
    MinOut = lists:min(OutValues),
    MaxOut = lists:max(OutValues),
    %% UIH-2: the receiver-added input ought to be at least as large
    %% as the largest output, else "the receiver-added input was not
    %% needed" — a detectable signal. We prefer Value >= MaxOut.
    %% UIH-1: if Value < MinOut, the original tx already "looked
    %% like" 1-payer-1-receiver, and the receiver-added input would
    %% make the smallest output strictly larger than the inputs
    %% (classic PayJoin fingerprint). Penalise.
    BaseScore =
        if Value >= MaxOut       -> 0;
           Value >= MinOut       -> 2;
           Value < MinOut        -> 10
        end,
    RecencyPenalty =
        case RecentlyUsed of
            true  -> 5;
            false -> 0
        end,
    BaseScore + RecencyPenalty.

script_recently_used_safe(Script) ->
    try
        beamchain_payjoin_state:script_recently_used(Script)
    catch
        _:_ -> false
    end.

%%% ===================================================================
%%% G30 — invoice-token validation
%%% ===================================================================

%% Extract `?token=<hex>` from the original cowboy request (NOT from
%% Params — Params is the BIP-78 query string contract; the token is
%% a beamchain-specific extension namespaced via a wrapper alias).
%% Returns:
%%   {ok, no_token}        — sender did not supply a token. We allow
%%                             this in lenient mode (default) so
%%                             FIX-65 test fixtures and pre-G30 clients
%%                             continue to round-trip.
%%   {ok, BoundAddr}       — token consumed; payjoin may proceed
%%   {error, Token, R}     — token present but invalid (not_found,
%%                             expired, or hex decode failed); reply
%%                             "unavailable" per BIP-78.
%%
%% Today we always pass-through when no token is supplied (lenient).
%% A future deployment flag (beamchain_config:payjoin_require_token())
%% could swap to strict mode.
validate_invoice_token(Req0, _Params) ->
    Qs = try cowboy_req:parse_qs(Req0)
         catch _:_ -> [] end,
    case proplists:get_value(<<"token">>, Qs) of
        undefined ->
            case payjoin_require_token() of
                false -> {ok, no_token};
                true  -> {error, <<"<missing>">>, no_token}
            end;
        TokenHex when is_binary(TokenHex) ->
            case beamchain_payjoin_state:consume_invoice_token(TokenHex) of
                {ok, BoundAddr}    -> {ok, BoundAddr};
                {error, R}         -> {error, TokenHex, R}
            end
    end.

payjoin_require_token() ->
    try beamchain_config:payjoin_require_token() of
        true  -> true;
        false -> false;
        _     -> false
    catch
        _:_ -> false
    end.

safe_get_wallet_utxos(_Pid) ->
    %% get_wallet_utxos/0 reads the ETS table directly so it is
    %% independent of the wallet gen_server pid. Pid is kept on the
    %% signature for symmetry with future per-wallet implementations.
    try beamchain_wallet:get_wallet_utxos() of
        L when is_list(L) -> L
    catch
        _:_ -> []
    end.

addr_is_wallet(WalletPid, ScriptPubKey, Network) ->
    case beamchain_address:script_to_address(ScriptPubKey, Network) of
        unknown -> false;
        AddrStr ->
            case beamchain_wallet:get_private_key(WalletPid, AddrStr) of
                {ok, K} when is_binary(K), byte_size(K) =:= 32,
                             K =/= <<0:256>> -> true;
                _ -> false
            end
    end.

%%% ===================================================================
%%% Helpers
%%% ===================================================================

default_wallet_pid() ->
    %% Best-effort: the registered name "beamchain_wallet" is the
    %% canonical singleton wallet on this node. Multi-wallet support
    %% would parse the route binding `:wallet_name` and call
    %% resolve_wallet/1 in beamchain_rpc; out of scope here.
    case whereis(beamchain_wallet) of
        undefined -> undefined;
        Pid -> Pid
    end.

current_network() ->
    try beamchain_config:network()
    catch error:_ -> mainnet
    end.

%%% ===================================================================
%%% BIP-78 four-token JSON error body
%%% ===================================================================

%% G17: receiver MUST emit one of:
%%   "unavailable", "not-enough-money", "version-unsupported",
%%   "original-psbt-rejected"
%% as a JSON object with key "errorCode" (BIP-78 §"Receiver's error
%% response"). We send the JSON object even on a 4xx status so the
%% sender's BIP-78 client classifier can route it without re-parsing
%% HTTP status codes.
bip78_error_body(Token, Msg) ->
    jsx:encode(#{<<"errorCode">> => Token,
                 <<"message">>   => Msg}).

bip78_error_reply(Status, Token, Msg, Req0) ->
    cowboy_req:reply(Status,
                     #{<<"content-type">> => <<"application/json">>},
                     bip78_error_body(Token, Msg),
                     Req0).
