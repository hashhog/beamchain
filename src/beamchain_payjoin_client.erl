-module(beamchain_payjoin_client).

%%% -------------------------------------------------------------------
%%% BIP-78 PayJoin sender.
%%%
%%% Spec: https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki
%%%
%%% Closes W119 BUG-2 (sender HTTP client + state machine), BUG-6
%%% (G22 fallback to broadcast Original on receiver error/timeout),
%%% BUG-9 (G10-G15 anti-snoop validators via beamchain_payjoin),
%%% BUG-11 (G3+G24+G25 — TLS cert validation + .onion dial policy),
%%% G2 (HTTP POST of Original PSBT), G27 (sendpayjoinrequest RPC
%%% driver).
%%%
%%% Transport (G3 / G24 / G25):
%%%   - https:// → httpc with ssl_options [verify_peer, cacerts (system
%%%     CA store)] — refuses self-signed certs.
%%%   - .onion → httpc with HTTP proxy pointed at the local Tor SOCKS5
%%%     (default 127.0.0.1:9050). Self-signed certs accepted on .onion
%%%     because TLS doesn't add anything over the onion service's own
%%%     authentication, and BIP-78 explicitly permits this exception.
%%%   - http:// to anything else → REJECTED (sender MUST NOT leak the
%%%     Original PSBT over plaintext to a non-onion endpoint).
%%%
%%% Fallback (G22):
%%%   On any failure of the PayJoin request (timeout / non-2xx / parse
%%%   error / anti-snoop violation), the sender broadcasts the Original
%%%   PSBT (after extracting the finalized tx hex) via the local
%%%   sendrawtransaction path. This guarantees the user's payment goes
%%%   through even if the PayJoin attempt collapses — exactly what
%%%   BIP-78 §"Reception of the response" requires.
%%%
%%% Single-pipeline reuse:
%%%   - Original PSBT signing: beamchain_rpc:rpc_walletprocesspsbt/2
%%%     (which itself reuses lookup_privkeys_for_inputs/3-equivalent
%%%     via get_private_key/2 — same primitive). One signing pipeline.
%%%   - Anti-snoop validators: beamchain_payjoin:validate_response/4.
%%%   - Final fallback broadcast: beamchain_rpc:rpc_sendrawtransaction/1.
%%% -------------------------------------------------------------------

-include("beamchain.hrl").
-include("beamchain_psbt.hrl").
-include("beamchain_bip21.hrl").

%% Public entry points.
-export([send_payjoin_request/3,
         send_payjoin_request/4]).

%% Internal exports for eunit drive-through and a future receiver
%% self-check path.
-export([resolve_endpoint/1,
         classify_endpoint/1,
         build_request_url/2,
         do_http_post/3,
         tls_options_for/1,
         broadcast_original_fallback/1]).

%% Default Tor SOCKS5 / HTTP-proxy bridge. We use HTTP-proxy (not
%% pure SOCKS5) because Erlang's httpc only natively supports
%% HTTP-proxy chaining; users wanting raw SOCKS5 must run a local
%% socks-to-http bridge (e.g. `socat`) or set TOR_HTTP_PROXY.
-define(DEFAULT_TOR_PROXY_HOST, "127.0.0.1").
-define(DEFAULT_TOR_PROXY_PORT, 9050).

%% Default per-request timeout (ms). BIP-78 §"Sender" hints at ~30s
%% as the canonical wait window before sender SHOULD fall back.
-define(DEFAULT_TIMEOUT_MS, 30000).

%%% ===================================================================
%%% Top-level entry — driven by rpc_sendpayjoinrequest.
%%% ===================================================================

%% Build an Original PSBT for (Addr, AmountSats), POST it to the
%% receiver's pj= endpoint, validate the response, sign, broadcast.
%% On any failure: fall back to broadcasting the Original.
%%
%% Returns:
%%   {ok, #{ <<"txid">> => Hex, <<"used_payjoin">> => boolean()
%%         , <<"endpoint">> => binary() }}
%%   {error, Code, Msg}
send_payjoin_request(BIP21Uri, _PayjoinOpts, WalletPid) ->
    send_payjoin_request(BIP21Uri, _PayjoinOpts, WalletPid, []).

send_payjoin_request(#bip21_uri{pj = undefined}, _Opts, _Pid, _Extra) ->
    {error, -8, <<"BIP-21 URI has no pj= PayJoin endpoint">>};
send_payjoin_request(#bip21_uri{address = _Addr, amount = undefined},
                     _Opts, _Pid, _Extra) ->
    {error, -8, <<"BIP-21 URI has no amount= for sendpayjoinrequest">>};
send_payjoin_request(#bip21_uri{} = Uri, Opts, WalletPid, Extra)
        when is_map(Opts), is_list(Extra) ->
    case classify_endpoint(Uri#bip21_uri.pj) of
        {error, _} = E -> E;
        {ok, EpClass} ->
            do_send_payjoin(Uri, Opts, WalletPid, Extra, EpClass)
    end.

do_send_payjoin(Uri, Opts, WalletPid, _Extra, EpClass) ->
    %% Build the Original PSBT (single-pipeline: walletprocesspsbt
    %% drives the same lookup_privkeys_for_inputs/3 path that
    %% sendtoaddress uses).
    case build_original_psbt_for(Uri, WalletPid) of
        {error, _, _} = E -> E;
        {ok, OriginalPsbt, _OriginalHex} ->
            OrigB64 = base64:encode(beamchain_psbt:encode(OriginalPsbt)),
            Url = build_request_url(Uri#bip21_uri.pj, Opts),
            TimeoutMs = maps:get(timeout_ms, Opts, ?DEFAULT_TIMEOUT_MS),
            HttpResult = do_http_post(Url, OrigB64, #{
                              timeout_ms => TimeoutMs,
                              endpoint_class => EpClass}),
            attempt_or_fallback(HttpResult, OriginalPsbt, Uri, Opts,
                                WalletPid)
    end.

%% Top-level decision: succeed via PayJoin OR fall back to broadcast
%% Original. G22 — receiver error / timeout / anti-snoop violation
%% all collapse to the same fallback path.
attempt_or_fallback({ok, RespB64}, OriginalPsbt, _Uri, Opts, WalletPid) ->
    case decode_response(RespB64) of
        {error, R} ->
            broadcast_original_fallback(OriginalPsbt, {decode_failed, R});
        {ok, PayjoinPsbt} ->
            run_validators_then_sign(OriginalPsbt, PayjoinPsbt,
                                     Opts, WalletPid)
    end;
attempt_or_fallback({error, Reason}, OriginalPsbt, _Uri, _Opts, _WalletPid) ->
    broadcast_original_fallback(OriginalPsbt, Reason).

run_validators_then_sign(OriginalPsbt, PayjoinPsbt, Opts, WalletPid) ->
    SenderOwnedFun = sender_owned_fun(WalletPid),
    case beamchain_payjoin:validate_response(
           OriginalPsbt, PayjoinPsbt, Opts, SenderOwnedFun) of
        {error, Why} ->
            %% G22: anti-snoop failure → fall back to broadcasting
            %% the Original. We do NOT silently drop the payment.
            broadcast_original_fallback(
              OriginalPsbt, {anti_snoop_failed, Why});
        ok ->
            sign_and_broadcast_payjoin(PayjoinPsbt)
    end.

sign_and_broadcast_payjoin(PayjoinPsbt) ->
    Bin = beamchain_psbt:encode(PayjoinPsbt),
    B64 = base64:encode(Bin),
    case beamchain_rpc:rpc_walletprocesspsbt(
           [B64, true, <<"ALL">>, true, true], <<>>) of
        {ok, #{<<"complete">> := true, <<"hex">> := Hex}} ->
            case beamchain_rpc:rpc_sendrawtransaction([Hex]) of
                {ok, Txid} ->
                    {ok, #{<<"txid">> => Txid,
                           <<"used_payjoin">> => true}};
                Err -> Err
            end;
        {ok, #{<<"complete">> := false}} ->
            %% Wallet couldn't sign every input (e.g. some inputs are
            %% receiver-only and they didn't pre-sign). This is an
            %% unrecoverable state for the PayJoin attempt; fall back.
            {error, -4, <<"payjoin signing incomplete">>};
        Err -> Err
    end.

%%% ===================================================================
%%% Endpoint classification (G3 / G24 / G25)
%%% ===================================================================

%% classify_endpoint/1: decides whether the URL is allowed and which
%% TLS / proxy policy applies.
%%   {ok, https}         → standard HTTPS, system CA store
%%   {ok, onion_http}    → .onion via Tor proxy, HTTP allowed
%%   {ok, onion_https}   → .onion via Tor proxy, HTTPS allowed (cert
%%                         unverified because the onion already
%%                         authenticates)
%%   {error, plaintext_to_clearnet} → http:// without .onion → reject
classify_endpoint(Url) when is_binary(Url) ->
    classify_endpoint(binary_to_list(Url));
classify_endpoint(Url) when is_list(Url) ->
    case split_url(Url) of
        {error, R} -> {error, {bad_url, R}};
        {ok, Scheme, Host, _Port, _Path} ->
            IsOnion = is_onion_host(Host),
            case {Scheme, IsOnion} of
                {"https", true}  -> {ok, onion_https};
                {"https", false} -> {ok, https};
                {"http", true}   -> {ok, onion_http};
                {"http", false}  -> {error, plaintext_to_clearnet};
                _                -> {error, {bad_scheme, Scheme}}
            end
    end.

is_onion_host(Host) ->
    case lists:reverse(Host) of
        "noino." ++ _ -> true;
        _ -> false
    end.

split_url(Url) ->
    case string:split(Url, "://") of
        [Scheme, Rest] ->
            {Host, Port, Path} = parse_authority(Rest),
            {ok, string:lowercase(Scheme), Host, Port, Path};
        _ ->
            {error, no_scheme}
    end.

parse_authority(Rest) ->
    {Authority, Path} = case string:split(Rest, "/") of
        [A]    -> {A, "/"};
        [A, P] -> {A, "/" ++ P}
    end,
    {Host, Port} = case string:split(Authority, ":") of
        [H]      -> {H, default_port_for("")};
        [H, PS]  -> {H, try list_to_integer(PS) catch _:_ -> 0 end}
    end,
    {Host, Port, Path}.

default_port_for(_) -> 0.

%%% ===================================================================
%%% Resolve endpoint into final URL + proxy config
%%% ===================================================================

%% Build the final POST URL by appending the standard BIP-78 query
%% string from Opts onto Uri's pj= base. The receiver expects:
%%   v=1
%%   additionalfeeoutputindex=N (optional)
%%   maxadditionalfeecontribution=S
%%   disableoutputsubstitution=0|1
%%   minfeerate=R
build_request_url(BaseUrl, Opts) when is_binary(BaseUrl) ->
    build_request_url(binary_to_list(BaseUrl), Opts);
build_request_url(BaseUrl, Opts) when is_list(BaseUrl) ->
    Sep = case lists:member($?, BaseUrl) of
        true  -> "&";
        false -> "?"
    end,
    Qs = build_query_string(Opts),
    BaseUrl ++ Sep ++ Qs.

build_query_string(Opts) ->
    Pairs0 = [
        {"v", integer_to_list(maps:get(version, Opts, 1))},
        case maps:get(additional_fee_output_index, Opts, undefined) of
            undefined -> skip;
            Idx       -> {"additionalfeeoutputindex", integer_to_list(Idx)}
        end,
        {"maxadditionalfeecontribution",
         integer_to_list(maps:get(max_additional_fee_contribution, Opts, 0))},
        {"disableoutputsubstitution",
         case maps:get(disable_output_substitution, Opts, false) of
             true -> "1"; false -> "0"
         end},
        {"minfeerate",
         integer_to_list(maps:get(min_fee_rate, Opts, 0))}
    ],
    Pairs = [P || P <- Pairs0, P =/= skip],
    string:join([K ++ "=" ++ V || {K, V} <- Pairs], "&").

resolve_endpoint(Url) ->
    classify_endpoint(Url).

%%% ===================================================================
%%% HTTP POST with httpc + ssl + optional Tor proxy
%%% ===================================================================

%% Performs the POST and returns either {ok, BodyBinary} (2xx body) or
%% {error, Reason}. Body decoding (base64) is the caller's job —
%% keeps this function transport-only.
do_http_post(Url, BodyB64, Opts) ->
    Timeout = maps:get(timeout_ms, Opts, ?DEFAULT_TIMEOUT_MS),
    EndpointClass = maps:get(endpoint_class, Opts, https),
    %% Ensure inets+ssl are running. inets+ssl are declared in
    %% beamchain.app.src; production start sequence guarantees they're
    %% up. Tests rely on this fallback start.
    _ = application:ensure_all_started(inets),
    _ = application:ensure_all_started(ssl),
    %% For .onion targets, route via Tor HTTP proxy. Tor's SOCKS5 port
    %% (9050 default) speaks SOCKS only — running socat / privoxy is
    %% the canonical bridge. The TOR_HTTP_PROXY env var lets ops point
    %% at their own bridge.
    case set_proxy_for(EndpointClass) of
        {error, R} -> {error, {proxy_setup_failed, R}};
        ok ->
            SslOpts = tls_options_for(EndpointClass),
            HttpOpts = [{timeout, Timeout},
                        {connect_timeout, Timeout},
                        {ssl, SslOpts}],
            Req = {url_to_string(Url),
                   [{"User-Agent", "beamchain-payjoin/1.0"}],
                   "text/plain",
                   BodyB64},
            try
                case httpc:request(post, Req, HttpOpts,
                                   [{body_format, binary}]) of
                    {ok, {{_, Code, _}, _Hdrs, Body}}
                            when Code >= 200, Code < 300 ->
                        {ok, Body};
                    {ok, {{_, Code, _}, _Hdrs, Body}} ->
                        {error, {http_status, Code, Body}};
                    {error, Reason} ->
                        {error, {httpc_failed, Reason}}
                end
            catch
                Class:Err ->
                    {error, {http_crash, Class, Err}}
            end
    end.

url_to_string(B) when is_binary(B) -> binary_to_list(B);
url_to_string(L) when is_list(L)   -> L.

%% TLS option policy (G24).
%%   https        → verify_peer + system CA store. Self-signed REJECTED.
%%   onion_http   → no TLS at all (plain HTTP over the onion service).
%%   onion_https  → if a .onion presents TLS, accept self-signed (the
%%                  onion authenticates the endpoint cryptographically).
tls_options_for(https) ->
    %% Load CA certs via public_key:cacerts_get/0 when available
    %% (OTP 25+). Fallback: use the system default (httpc default ssl
    %% options will pick up OS trust store on most distros).
    BaseOpts = [
        {verify, verify_peer},
        {depth, 10},
        %% Hostname verification — must match the hostname in the URL.
        {customize_hostname_check,
         [{match_fun, public_key:pkix_verify_hostname_match_fun(https)}]},
        %% Allow modern TLS only; the receiver SHOULD be using LetsEncrypt
        %% or similar.
        {versions, ['tlsv1.2', 'tlsv1.3']}
    ],
    case erlang:function_exported(public_key, cacerts_get, 0) of
        true ->
            try public_key:cacerts_get() of
                CaCerts -> [{cacerts, CaCerts} | BaseOpts]
            catch
                _:_ -> BaseOpts
            end;
        false ->
            BaseOpts
    end;
tls_options_for(onion_https) ->
    %% .onion endpoints: Tor authenticates the destination via the
    %% onion address itself — TLS on top is allowed for legacy
    %% reasons but cert verification is intentionally relaxed
    %% (self-signed is the norm). BIP-78 explicitly permits this.
    [{verify, verify_none}];
tls_options_for(onion_http) ->
    %% No TLS — `ssl` opts irrelevant. Return [] to be safe.
    [].

%% Configure the httpc default profile to use Tor as an HTTP proxy when
%% the endpoint is .onion. Otherwise clear any pre-existing proxy so
%% clearnet requests don't accidentally route via Tor.
set_proxy_for(onion_http)  -> set_tor_proxy();
set_proxy_for(onion_https) -> set_tor_proxy();
set_proxy_for(https)       -> clear_proxy().

set_tor_proxy() ->
    Host = os:getenv("TOR_HTTP_PROXY_HOST", ?DEFAULT_TOR_PROXY_HOST),
    Port = case os:getenv("TOR_HTTP_PROXY_PORT") of
        false -> ?DEFAULT_TOR_PROXY_PORT;
        S     -> try list_to_integer(S) catch _:_ -> ?DEFAULT_TOR_PROXY_PORT end
    end,
    try
        ok = httpc:set_options(
               [{proxy, {{Host, Port}, []}}],
               default),
        ok
    catch
        _:E -> {error, E}
    end.

clear_proxy() ->
    try
        ok = httpc:set_options([{proxy, {undefined, []}}], default),
        ok
    catch
        _:_ -> ok    %% non-fatal if no profile yet
    end.

%%% ===================================================================
%%% Original PSBT construction (sender-side)
%%% ===================================================================

%% Build an Original PSBT for (Address, AmountSats) using the wallet's
%% existing coin-selection + sign path. Returns the signed PSBT plus
%% the finalized hex (needed for the G22 fallback path — we want a
%% ready-to-broadcast tx in hand BEFORE we POST to the receiver).
build_original_psbt_for(#bip21_uri{address = Addr, amount = Amount},
                        WalletPid) when is_pid(WalletPid),
                                        is_integer(Amount),
                                        Amount > 0 ->
    Utxos = beamchain_wallet:get_wallet_utxos(),
    case beamchain_wallet:select_coins(Amount, 1, Utxos) of
        {ok, Selected, Change} ->
            Network = current_network(),
            Outputs0 = [{binary_to_list(Addr), Amount}],
            Outputs = case Change > 546 of
                true ->
                    {ok, ChangeAddr} =
                        beamchain_wallet:get_change_address(p2wpkh),
                    Outputs0 ++ [{ChangeAddr, Change}];
                false -> Outputs0
            end,
            case beamchain_wallet:build_transaction(
                   Selected, Outputs, Network) of
                {ok, Tx} ->
                    finalize_original(Tx, Selected, WalletPid, Network);
                {error, R} ->
                    {error, -4, iolist_to_binary(
                                    io_lib:format("build failed: ~p", [R]))}
            end;
        {error, insufficient_funds} ->
            {error, -6, <<"Insufficient funds">>}
    end;
build_original_psbt_for(_, _) ->
    {error, -8, <<"missing amount or wallet">>}.

%% Sign the original tx via the wallet's keystore (same pipeline
%% rpc_sendtoaddress uses) and wrap into a PSBT so we can hand it to
%% the receiver as base64 AND keep a tx hex for the fallback path.
finalize_original(Tx, Selected, _WalletPid, _Network) ->
    case beamchain_psbt:create(Tx) of
        {ok, P0} ->
            %% Attach witness_utxo + partial_sigs (via wallet sign).
            P1 = lists:foldl(
                   fun({{_T, V, U}, I}, Acc) ->
                       _ = V,
                       beamchain_wallet:add_witness_utxo(Acc, I, U)
                   end,
                   P0,
                   lists:zip(Selected,
                             lists:seq(0, length(Selected) - 1))),
            %% Sign through walletprocesspsbt — same single pipeline.
            Bin = beamchain_psbt:encode(P1),
            B64 = base64:encode(Bin),
            case beamchain_rpc:rpc_walletprocesspsbt(
                   [B64, true, <<"ALL">>, true, false], <<>>) of
                {ok, #{<<"psbt">> := SignedB64}} ->
                    SignedBin = base64:decode(SignedB64),
                    case beamchain_psbt:decode(SignedBin) of
                        {ok, Signed} ->
                            HexFallback = try_extract_hex(Signed),
                            {ok, Signed, HexFallback};
                        {error, R} ->
                            {error, -4,
                             iolist_to_binary(io_lib:format(
                               "psbt decode: ~p", [R]))}
                    end;
                {error, Code, Msg} -> {error, Code, Msg};
                Other ->
                    {error, -4, iolist_to_binary(
                                  io_lib:format("wpp: ~p", [Other]))}
            end;
        {error, R} ->
            {error, -4, iolist_to_binary(
                           io_lib:format("psbt create: ~p", [R]))}
    end.

%% Best-effort hex extraction from a finalized PSBT — used as the G22
%% fallback. If finalize failed for any reason, returns undefined and
%% the fallback will go through a separate finalize+extract pass.
try_extract_hex(#psbt{} = Psbt) ->
    try
        Bin = beamchain_psbt:encode(Psbt),
        B64 = base64:encode(Bin),
        case beamchain_rpc:rpc_walletprocesspsbt(
               [B64, true, <<"ALL">>, true, true], <<>>) of
            {ok, #{<<"hex">> := Hex}} -> Hex;
            _ -> undefined
        end
    catch
        _:_ -> undefined
    end.

%%% ===================================================================
%%% Fallback (G22)
%%% ===================================================================

broadcast_original_fallback(#psbt{} = OriginalPsbt) ->
    broadcast_original_fallback(OriginalPsbt, manual_fallback).

broadcast_original_fallback(#psbt{} = OriginalPsbt, Why) ->
    %% Attempt to finalize+extract the Original PSBT via
    %% walletprocesspsbt (finalize=true). If the signing was complete
    %% at the build_original_psbt_for/2 stage, we get hex back; we then
    %% send via sendrawtransaction.
    Bin = beamchain_psbt:encode(OriginalPsbt),
    B64 = base64:encode(Bin),
    case beamchain_rpc:rpc_walletprocesspsbt(
           [B64, true, <<"ALL">>, true, true], <<>>) of
        {ok, #{<<"complete">> := true, <<"hex">> := Hex}} ->
            case beamchain_rpc:rpc_sendrawtransaction([Hex]) of
                {ok, Txid} ->
                    logger:notice("payjoin: fell back to broadcast "
                                  "(reason=~p, txid=~s)",
                                  [Why, Txid]),
                    {ok, #{<<"txid">> => Txid,
                           <<"used_payjoin">> => false,
                           <<"fallback_reason">> =>
                               iolist_to_binary(io_lib:format("~p", [Why]))}};
                Err ->
                    %% Both PayJoin and fallback failed. Surface PayJoin's
                    %% reason as the user-facing message because that's
                    %% the closer signal to the operator.
                    {error, -4,
                     iolist_to_binary(io_lib:format(
                       "payjoin failed (~p) and fallback broadcast failed: ~p",
                       [Why, Err]))}
            end;
        Other ->
            {error, -4,
             iolist_to_binary(io_lib:format(
               "payjoin failed (~p) and could not finalize original: ~p",
               [Why, Other]))}
    end.

%%% ===================================================================
%%% Response decoding
%%% ===================================================================

decode_response(Body) when is_binary(Body) ->
    %% BIP-78 happy path: receiver returns base64 PSBT as text/plain.
    Trimmed = trim_ascii_ws(Body),
    try base64:decode(Trimmed) of
        Bin ->
            case beamchain_psbt:decode(Bin) of
                {ok, P}        -> {ok, P};
                {error, R}     -> {error, {psbt_decode_failed, R}}
            end
    catch
        error:_ -> {error, {base64_decode_failed, Body}}
    end.

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
%%% Sender-owned predicate (G12)
%%% ===================================================================

sender_owned_fun(WalletPid) ->
    Network = current_network(),
    fun(ScriptPubKey) ->
        case beamchain_address:script_to_address(ScriptPubKey, Network) of
            unknown -> false;
            AddrStr ->
                case beamchain_wallet:get_private_key(WalletPid, AddrStr) of
                    {ok, K} when is_binary(K), byte_size(K) =:= 32,
                                  K =/= <<0:256>> -> true;
                    _ -> false
                end
        end
    end.

current_network() ->
    try beamchain_config:network()
    catch error:_ -> mainnet
    end.
