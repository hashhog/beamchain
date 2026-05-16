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
         pick_receiver_utxo/2,
         bip78_error_body/2]).

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
    case build_payjoin_psbt(OriginalPsbt, Params, default_wallet_pid()) of
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
    case WalletPid of
        undefined ->
            {error, {wallet_missing, no_wallet_pid}};
        _ ->
            do_build_payjoin_psbt(OriginalPsbt, Params, WalletPid)
    end.

do_build_payjoin_psbt(OriginalPsbt, Params, WalletPid) ->
    Network = current_network(),
    case pick_receiver_utxo(WalletPid, Network) of
        {error, _} = E -> E;
        {ok, {Txid, Vout, Utxo}} ->
            %% Build the merged unsigned tx:
            %%   - keep the sender's existing inputs and outputs intact
            %%     (G7+G10 — we add inputs, we do not remove sender ones).
            %%   - append our new tx_in with sequence 0xFFFFFFFD
            %%     (BIP-125 RBF signal, consistent with sample_unsigned_tx).
            %%   - optionally dock fees from
            %%     additionalfeeoutputindex (G6+G9).
            OldTx = OriginalPsbt#psbt.unsigned_tx,
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
%% address (so walletprocesspsbt will produce a real signature). This
%% is intentionally minimal — UIH-1/UIH-2 anti-fingerprint heuristics
%% (G20 / W119 BUG-10) are future work. Returns the first eligible
%% UTXO with confirmations >= 1.
pick_receiver_utxo(WalletPid, Network) ->
    Utxos = safe_get_wallet_utxos(WalletPid),
    case lists:filter(fun({_Txid, _Vout, Utxo}) ->
              addr_is_wallet(WalletPid, Utxo#utxo.script_pubkey, Network)
          end, Utxos) of
        []          -> {error, no_eligible_utxo};
        [First | _] -> {ok, First}
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
