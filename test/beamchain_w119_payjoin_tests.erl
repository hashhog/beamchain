-module(beamchain_w119_payjoin_tests).
-include_lib("eunit/include/eunit.hrl").

%%% ===================================================================
%%% W119 BIP-78 PayJoin (P2EP) audit — beamchain (Erlang/OTP)
%%%
%%% Spec: https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki
%%% Ecosystem references:
%%%   - https://payjoin.org/
%%%   - https://github.com/btcpayserver/payjoin
%%%   - https://github.com/payjoin/rust-payjoin
%%% Bitcoin Core: NO PayJoin support (BIP-78 is an ecosystem/wallet spec,
%%% no validation rules — Core deliberately does NOT implement it). PayJoin
%%% is therefore a fleet-level "differentiator vs Core" coverage gate, not
%%% a Core-parity gate. The cross-impl bar for hashhog is *implementation*
%%% (sender + receiver) matching BIP-78 wire and BIP-21 URI encoding.
%%%
%%% Gates (30):
%%%   G1   receiver-side HTTP endpoint accepting POST PSBT
%%%   G2   sender-side HTTP client POSTing Original PSBT
%%%   G3   TLS / .onion endpoint (sender connects only via TLS or onion)
%%%   G4   Original PSBT base64 deserialize (server side)
%%%   G5   receiver-side input validation (script type, finalized, fees)
%%%   G6   fee-output identification by `additionalfeeoutputindex`
%%%   G7   receiver-side add-inputs (P2EP merge with own UTXOs)
%%%   G8   receiver-side modify-output (substitute receiver output)
%%%   G9   receiver-side fee adjustment within `maxadditionalfeecontribution`
%%%   G10  sender anti-snoop: outputs preserved / no new sender outputs
%%%   G11  sender anti-snoop: scriptSig types preserved (no mixed input scripts)
%%%   G12  sender anti-snoop: no new sender inputs introduced
%%%   G13  sender anti-snoop: fee within max_additional_fee_contribution
%%%   G14  sender disableoutputsubstitution=true honoured
%%%   G15  sender minfeerate enforced on returned Payjoin PSBT
%%%   G16  query-string params parsed: v / additionalfeeoutputindex /
%%%        maxadditionalfeecontribution / disableoutputsubstitution / minfeerate
%%%   G17  4 BIP-78 errors emitted: unavailable / not-enough-money /
%%%        version-unsupported / original-psbt-rejected
%%%   G18  receiver TTL: response within client-acceptable wait window
%%%   G19  receiver no-double-spend: same Original PSBT may not be processed twice
%%%   G20  receiver UTXO anti-fingerprint: avoid known-receiver UTXO selection
%%%        leak (anti-UIH / anti-payjoin-snoop heuristic)
%%%   G21  v=1 header / version field handled (single supported version today)
%%%   G22  sender fallback: on receiver error, broadcast Original PSBT instead
%%%   G23  receiver Content-Type: text/plain (BIP-78) for base64 PSBT body
%%%   G24  HTTPS cert validation (sender refuses self-signed unless .onion)
%%%   G25  Tor onion endpoint support (sender may dial .onion target)
%%%   G26  RPC `getpayjoinrequest` — produce BIP-21 URI with pj= for an
%%%        invoice address (receiver-side issuance API)
%%%   G27  RPC `sendpayjoinrequest` — sender entrypoint taking BIP-21 URI
%%%        and amount, performs full flow + fallback
%%%   G28  BIP-21 URI parameter `pj=` parsed by sender
%%%   G29  BIP-21 URI parameter `pjos=` (disableoutputsubstitution) parsed
%%%   G30  receiver replay protection: nonce/once-only-token in pj= URL
%%%
%%% Implementation status (audit verdict): MISSING ENTIRELY.
%%%
%%% Concrete grep of beamchain/src yields ZERO hits for:
%%%   payjoin, PayJoin, bip78, bip-78, pj=, pjos, additionalfeeoutputindex,
%%%   maxadditionalfeecontribution, disableoutputsubstitution.
%%% No BIP-21 URI parser anywhere (no `bitcoin:` scheme handling). PSBT
%%% subsystem exists (beamchain_psbt) but with W118 TP-2 #psbt-record
%%% two-pipeline still OPEN (one #psbt in beamchain_wallet.erl line 1245,
%%% another in beamchain_psbt.erl line 79 — same name, divergent fields).
%%% `walletprocesspsbt` is also still MISSING (W118 BUG-5; FIX-60 was a
%%% rustoshi-only commit, no beamchain port). Without walletprocesspsbt
%%% there is no natural in-wallet codepath the receiver can hand an
%%% Original PSBT to.
%%%
%%% Each gate test below uses one of two shapes:
%%%
%%%   (a) "absence" — `?_assertEqual({error, undef}, …)` against the
%%%       missing module/function/RPC method. Asserts the gate is
%%%       provably not wired. These are real assertions, not skips.
%%%
%%%   (b) "skip" — when the gate covers something only meaningful once
%%%       (a) is closed (e.g. behaviour-under-spec), the test emits a
%%%       diagnostic via `?debugFmt` and resolves to `ok`. Replace with
%%%       real assertions on the FIX wave that wires PayJoin.
%%%
%%% Bugs (all derive from the single root cause "PayJoin not implemented"):
%%%
%%%   BUG-1 (P0-MISSING-ENTIRELY, G1+G26 — RECEIVER ENDPOINT):
%%%     No HTTP endpoint serves POSTed PSBTs as a PayJoin server. Cowboy
%%%     listener (beamchain_rpc.erl line 188-198) routes only `/`,
%%%     `/wallet/:wallet_name`, `/health`. No `/payjoin`, `/bip78`, or
%%%     configurable PayJoin path. There is no `rpc_getpayjoinrequest`
%%%     RPC and the wallet has no concept of issuing a `pj=` URL bound
%%%     to a one-shot invoice. A merchant cannot stand up beamchain as a
%%%     BTCPay-compatible PayJoin receiver.
%%%
%%%   BUG-2 (P0-MISSING-ENTIRELY, G2+G27 — SENDER CLIENT):
%%%     No HTTP client that takes a BIP-21 URI with pj= and POSTs an
%%%     Original PSBT to the receiver. `rpc_sendpayjoinrequest` does
%%%     not exist. `httpc` / `inets` is not started; sender would also
%%%     have no fallback path (G22) if it did try to dial.
%%%
%%%   BUG-3 (P0-MISSING-ENTIRELY, G28+G29 — BIP-21 URI PARSER):
%%%     Grep for `bitcoin:` / `bip21` / `parse_bip21` / `payment_uri`
%%%     in all of src/ yields ZERO hits. Without a BIP-21 parser, the
%%%     sender cannot extract `pj=` or `pjos=`. This is a *prerequisite*
%%%     gap that blocks both G28 and G29 simultaneously; closing
%%%     PayJoin without first closing BIP-21 would require duplicating
%%%     URI parsing inside the PayJoin module (a smell future audits
%%%     would flag as a "two-pipeline within impl").
%%%
%%%   BUG-4 (HIGH, G4+G5 — WALLETPROCESSPSBT MISSING — RECEIVER WIRING):
%%%     The natural in-wallet entrypoint for "take a partial PSBT and
%%%     finish it with my keys" is `walletprocesspsbt`. W118 flagged it
%%%     as missing and FIX-60 did NOT port the rustoshi closure to
%%%     beamchain. Without it, even if a `/payjoin` HTTP route existed
%%%     it would have nothing concrete in the wallet API to call into.
%%%     This is a concrete cross-wave carry-forward: W118 BUG-5 still
%%%     open after FIX-60 + FIX-61.
%%%
%%%   BUG-5 (HIGH, G4 — #psbt TWO-PIPELINE — RECEIVER PSBT TYPE):
%%%     `-record(psbt, ...)` is defined in TWO places with different
%%%     fields: beamchain_psbt.erl line 79 (the "library" record:
%%%     unsigned_tx, xpubs, version, inputs, outputs, unknown,
%%%     proprietary) and beamchain_wallet.erl line 1245 (the "wallet"
%%%     record: different field set used by the in-wallet sign path).
%%%     A PayJoin receiver crossing the wallet/PSBT boundary today
%%%     would hit type drift. W118 TP-2 still OPEN; W119 inherits the
%%%     defect.
%%%
%%%   BUG-6 (HIGH, G22 — SENDER FALLBACK ABSENT):
%%%     BIP-78 §"Reception of the response" mandates the sender broadcast
%%%     the Original PSBT (as a normal tx) when the receiver returns an
%%%     error or doesn't respond within TTL. No code path in beamchain
%%%     does this; even rpc_sendtoaddress does not produce a fallback-
%%%     ready Original PSBT today (rpc_sendtoaddress signs+broadcasts in
%%%     one shot — there is no "build PSBT, hold it pending response,
%%%     decide later" state machine).
%%%
%%%   BUG-7 (HIGH, G17 — ERROR TAXONOMY):
%%%     BIP-78 mandates four error tokens: unavailable, not-enough-money,
%%%     version-unsupported, original-psbt-rejected. Without a receiver
%%%     endpoint, none of these are wired. Sender side also has no
%%%     mapping table — a future receiver impl that returns the wrong
%%%     token would not be caught by tests because there are no tests.
%%%
%%%   BUG-8 (HIGH, G30 — REPLAY PROTECTION):
%%%     BIP-78 receivers SHOULD include a once-only token in the pj=
%%%     URL so the same invoice cannot be drained twice via repeated
%%%     PayJoin attempts. With no receiver, no token store. Closing
%%%     BUG-1 without simultaneously wiring G30 would create a
%%%     correctness hole (double-fund of single invoice).
%%%
%%%   BUG-9 (MEDIUM, G10..G15 — SENDER ANTI-SNOOP RULES):
%%%     BIP-78 §"Receiver's response" lists six checks the sender MUST
%%%     perform on the returned PSBT: original outputs preserved, no new
%%%     sender outputs, no new sender inputs, scriptSig types preserved,
%%%     fee within max_additional_fee_contribution, locktime/sequence
%%%     unchanged. None of these are implemented; closing G2 without
%%%     these checks would expose senders to receiver-side fingerprint
%%%     attacks (a malicious receiver could substitute the sender's
%%%     change output for one they control).
%%%
%%%   BUG-10 (MEDIUM, G20 — RECEIVER UIH HEURISTIC):
%%%     BIP-78 §"Unnecessary input heuristic (UIH)" warns receivers to
%%%     avoid trivially-detectable PayJoins (e.g. when receiver-added
%%%     inputs would make the smaller output strictly larger than the
%%%     larger of the original two — telegraphing PayJoin via
%%%     blockchain analytics). Receivers SHOULD implement UIH-1/UIH-2
%%%     anti-fingerprint heuristics. None present.
%%%
%%%   BUG-11 (MEDIUM, G3+G24+G25 — TRANSPORT REQUIREMENTS):
%%%     BIP-78 mandates the sender connect ONLY via HTTPS *or* .onion.
%%%     beamchain has no HTTPS client (no `httpc`/`gun`/`hackney`/etc
%%%     started) and although FIX-58 added a `beamchain_torcontrol`
%%%     module (794 LOC) it only opens ADD_ONION services for our
%%%     OWN hidden service; it does not dial a peer-supplied .onion
%%%     PayJoin endpoint through Tor as a SOCKS5 client. The proxy is
%%%     server-publishing not client-dialling.
%%%
%%%   BUG-12 (LOW, G16 — QUERY-PARAM PARSING):
%%%     If/when a /payjoin HTTP route exists, Cowboy gives the receiver
%%%     `cowboy_req:parse_qs/1` for query-string extraction, but type-
%%%     coercion to integer (additionalfeeoutputindex,
%%%     maxadditionalfeecontribution) and boolean
%%%     (disableoutputsubstitution) plus fee-rate parsing (minfeerate
%%%     sat/vB integer) requires a small dispatch table — no such
%%%     helper exists today.
%%%
%%%   BUG-13 (LOW, G23 — CONTENT-TYPE):
%%%     BIP-78 specifies "Content-Type: text/plain" with the Original
%%%     PSBT body as base64. Without a receiver, no enforcement.
%%%
%%%   BUG-14 (LOW, G18 — TIMEOUT):
%%%     Receiver SHOULD respond in <~30s or sender SHOULD fall back.
%%%     beamchain has no timeout policy because no receiver.
%%%
%%% Per-impl bug count: 14.
%%%
%%% Verdict: MISSING ENTIRELY (10/10 fleet-level outcome if mirrored).
%%% W119 fix path: brand-new beamchain_payjoin_server (cowboy route +
%%% receiver state machine), beamchain_payjoin_client (httpc or gun-based
%%% sender + anti-snoop checks), beamchain_bip21 (URI parser), and a
%%% pair of RPCs (getpayjoinrequest / sendpayjoinrequest). MUST close
%%% W118 TP-2 (#psbt unification) and W118 BUG-5 (walletprocesspsbt)
%%% as prerequisites, otherwise PayJoin would graft onto a divergent
%%% PSBT type and a missing in-wallet entrypoint.
%%% ===================================================================

%%% ===================================================================
%%% Helpers
%%% ===================================================================

%% Absence assertion shaped like the W117 "module not loaded" style.
%% We deliberately reference the *expected* module name. If a future
%% fix wave lands a real module by that name, this assertion will
%% start failing in a meaningful way ("module loads, gate must now
%% become a positive assertion").
expect_module_missing(Mod) ->
    case code:which(Mod) of
        non_existing -> ok;
        _Path        -> {unexpected_module_present, Mod}
    end.

%% Absence assertion for an RPC method by string name. Every dispatched
%% RPC method in beamchain_rpc has a corresponding `rpc_<method>` fun
%% (e.g. `rpc_sendtoaddress`). We check no exported fun of any arity
%% matches the expected name. This is a sturdy compile-time-ish check:
%% any fix-wave that adds the RPC will export the helper and the
%% assertion will start to fail in a meaningful way.
expect_rpc_method_missing(MethodBin) ->
    FunName = list_to_atom("rpc_" ++ binary_to_list(MethodBin)),
    Exports = beamchain_rpc:module_info(exports),
    case [A || {N, A} <- Exports, N =:= FunName] of
        []  -> ok;
        Ars -> {unexpected_rpc_export, FunName, Ars}
    end.

%% Diagnostic-emitting skip: documents what the gate WOULD test once the
%% feature is wired. eunit treats `ok` as pass; the debugFmt line shows
%% up in `rebar3 eunit -v` so an operator scanning the wave can see
%% which gates are pending real assertions. Use ~ts (Unicode-safe).
skip_pending(Gate, Note) ->
    ?debugFmt("[~s SKIP-MISSING-ENTIRELY] ~ts", [Gate, Note]),
    ok.


%%% ===================================================================
%%% G1 — Receiver-side HTTP endpoint accepting POST PSBT
%%% ===================================================================

g1_receiver_http_endpoint_missing_test_() ->
    {"G1: BIP-78 receiver HTTP endpoint (POST /payjoin) MISSING ENTIRELY",
     [
      ?_assertEqual(ok, expect_module_missing(beamchain_payjoin_server)),
      ?_assertEqual(ok, expect_module_missing(beamchain_payjoin))
     ]}.

%%% ===================================================================
%%% G2 — Sender-side HTTP client POSTing Original PSBT
%%% ===================================================================

g2_sender_http_client_missing_test_() ->
    {"G2: BIP-78 sender HTTP client MISSING ENTIRELY",
     [
      ?_assertEqual(ok, expect_module_missing(beamchain_payjoin_client)),
      %% Sanity: inets/httpc not even started (no PayJoin client could function)
      ?_assertEqual(ok, skip_pending("G2",
          "no payjoin sender; inets not started in beamchain_app"))
     ]}.

%%% ===================================================================
%%% G3 — TLS / .onion endpoint (sender connects only via TLS or onion)
%%% ===================================================================

g3_sender_tls_or_onion_only_missing_test_() ->
    {"G3: BIP-78 sender TLS/.onion-only transport policy MISSING ENTIRELY",
     [
      ?_assertEqual(ok, expect_module_missing(beamchain_payjoin_client)),
      ?_assertEqual(ok, skip_pending("G3",
          "sender MUST refuse plain http:// unless .onion; no policy module"))
     ]}.

%%% ===================================================================
%%% G4 — Original PSBT base64 deserialize (server side)
%%% ===================================================================

g4_orig_psbt_deserialize_missing_test_() ->
    {"G4: receiver-side Original PSBT deserialize path MISSING ENTIRELY",
     [
      %% beamchain_psbt:decode/1 itself exists, but no receiver path
      %% calls it from an HTTP context. Also W118 TP-2 still open —
      %% the receiver would have to choose between the wallet-#psbt
      %% and lib-#psbt records.
      ?_assertEqual(ok, expect_module_missing(beamchain_payjoin_server)),
      ?_assertEqual(ok, skip_pending("G4",
          "W118 TP-2 (#psbt record duplicated in wallet vs psbt module) "
          "still open — receiver would inherit the divergence"))
     ]}.

%%% ===================================================================
%%% G5 — Receiver-side input validation (script type, finalized, fees)
%%% ===================================================================

g5_receiver_input_validation_missing_test_() ->
    {"G5: receiver-side Original PSBT validation MISSING ENTIRELY",
     [
      ?_assertEqual(ok, expect_module_missing(beamchain_payjoin_server)),
      %% W118 BUG-5 / FIX-60 carry-forward: walletprocesspsbt is the
      %% natural Erlang seam to plug receiver validation into.
      ?_assertEqual(ok, expect_rpc_method_missing(<<"walletprocesspsbt">>)),
      ?_assertEqual(ok, skip_pending("G5",
          "W118 BUG-5 walletprocesspsbt still missing (FIX-60 did not "
          "port the closure to beamchain) — no in-wallet receiver seam"))
     ]}.

%%% ===================================================================
%%% G6 — Fee-output identification by `additionalfeeoutputindex`
%%% ===================================================================

g6_fee_output_identification_missing_test_() ->
    {"G6: additionalfeeoutputindex param handling MISSING ENTIRELY",
     [
      ?_assertEqual(ok, expect_module_missing(beamchain_payjoin_server)),
      ?_assertEqual(ok, skip_pending("G6",
          "no query-string parsing for additionalfeeoutputindex; no "
          "receiver-side resolver from index -> PSBT output"))
     ]}.

%%% ===================================================================
%%% G7 — Receiver-side add-inputs (P2EP merge with own UTXOs)
%%% ===================================================================

g7_receiver_add_inputs_missing_test_() ->
    {"G7: receiver-side input contribution (P2EP merge) MISSING ENTIRELY",
     [
      ?_assertEqual(ok, expect_module_missing(beamchain_payjoin_server)),
      ?_assertEqual(ok, skip_pending("G7",
          "no receiver UTXO selection bound to PayJoin invoice context; "
          "anti-fingerprint UIH-1/UIH-2 heuristics absent (BUG-10)"))
     ]}.

%%% ===================================================================
%%% G8 — Receiver-side modify-output (substitute receiver output)
%%% ===================================================================

g8_receiver_modify_output_missing_test_() ->
    {"G8: receiver-side output substitution MISSING ENTIRELY",
     [
      ?_assertEqual(ok, expect_module_missing(beamchain_payjoin_server)),
      ?_assertEqual(ok, skip_pending("G8",
          "must honour pjos=1 (disableoutputsubstitution) — see G14"))
     ]}.

%%% ===================================================================
%%% G9 — Receiver-side fee adjustment within max_additional_fee_contribution
%%% ===================================================================

g9_receiver_fee_adjustment_missing_test_() ->
    {"G9: receiver-side fee bump within maxadditionalfeecontribution MISSING",
     [
      ?_assertEqual(ok, expect_module_missing(beamchain_payjoin_server)),
      ?_assertEqual(ok, skip_pending("G9",
          "receiver MAY adjust fee but only up to caller-supplied cap; "
          "no cap enforcement helper"))
     ]}.

%%% ===================================================================
%%% G10 — Sender anti-snoop: outputs preserved
%%% ===================================================================

g10_sender_anti_snoop_outputs_missing_test_() ->
    {"G10: sender anti-snoop output-preservation check MISSING ENTIRELY",
     [
      ?_assertEqual(ok, expect_module_missing(beamchain_payjoin_client)),
      ?_assertEqual(ok, skip_pending("G10",
          "sender MUST verify all original outputs (except substituted "
          "receiver output) survive in the Payjoin PSBT"))
     ]}.

%%% ===================================================================
%%% G11 — Sender anti-snoop: scriptSig types preserved
%%% ===================================================================

g11_sender_anti_snoop_scriptsig_missing_test_() ->
    {"G11: sender anti-snoop scriptSig-type check MISSING ENTIRELY",
     [
      ?_assertEqual(ok, expect_module_missing(beamchain_payjoin_client)),
      ?_assertEqual(ok, skip_pending("G11",
          "mixing P2WPKH-original with P2SH-receiver inputs is a known "
          "PayJoin fingerprint — sender MUST reject"))
     ]}.

%%% ===================================================================
%%% G12 — Sender anti-snoop: no new sender inputs introduced
%%% ===================================================================

g12_sender_anti_snoop_no_new_inputs_missing_test_() ->
    {"G12: sender anti-snoop no-new-sender-inputs check MISSING ENTIRELY",
     [
      ?_assertEqual(ok, expect_module_missing(beamchain_payjoin_client)),
      ?_assertEqual(ok, skip_pending("G12",
          "receiver MAY only add receiver-owned inputs; sender MUST "
          "verify every input not in Original PSBT is new (not theirs)"))
     ]}.

%%% ===================================================================
%%% G13 — Sender anti-snoop: fee within max_additional_fee_contribution
%%% ===================================================================

g13_sender_anti_snoop_max_fee_missing_test_() ->
    {"G13: sender anti-snoop fee-cap check MISSING ENTIRELY",
     [
      ?_assertEqual(ok, expect_module_missing(beamchain_payjoin_client)),
      ?_assertEqual(ok, skip_pending("G13",
          "without enforcement a malicious receiver could pump fee "
          "arbitrarily and drain the sender's change"))
     ]}.

%%% ===================================================================
%%% G14 — Sender disableoutputsubstitution=true honoured
%%% ===================================================================

g14_sender_disableos_missing_test_() ->
    {"G14: sender disableoutputsubstitution=true enforcement MISSING",
     [
      ?_assertEqual(ok, expect_module_missing(beamchain_payjoin_client)),
      ?_assertEqual(ok, skip_pending("G14",
          "when pjos=1 sender MUST reject any returned PSBT whose "
          "receiver output amount or scriptPubKey differs from Original"))
     ]}.

%%% ===================================================================
%%% G15 — Sender minfeerate enforced on returned Payjoin PSBT
%%% ===================================================================

g15_sender_min_fee_rate_missing_test_() ->
    {"G15: sender minfeerate-floor enforcement MISSING ENTIRELY",
     [
      ?_assertEqual(ok, expect_module_missing(beamchain_payjoin_client)),
      ?_assertEqual(ok, skip_pending("G15",
          "sender MUST reject Payjoin PSBT whose effective fee rate "
          "drops below the minfeerate it sent in the query string"))
     ]}.

%%% ===================================================================
%%% G16 — Query-string param parsing
%%% ===================================================================

g16_query_params_missing_test_() ->
    {"G16: BIP-78 query-string param parsing (v / "
     "additionalfeeoutputindex / maxadditionalfeecontribution / "
     "disableoutputsubstitution / minfeerate) MISSING ENTIRELY",
     [
      ?_assertEqual(ok, expect_module_missing(beamchain_payjoin_server)),
      ?_assertEqual(ok, skip_pending("G16",
          "no helper for type-coercing query-string params per BIP-78; "
          "cowboy_req:parse_qs/1 returns binaries, integer/boolean "
          "coercion + fee-rate sat/vB parsing must be implemented"))
     ]}.

%%% ===================================================================
%%% G17 — 4 BIP-78 error tokens
%%% ===================================================================

g17_error_taxonomy_missing_test_() ->
    {"G17: BIP-78 4 error tokens (unavailable / not-enough-money / "
     "version-unsupported / original-psbt-rejected) MISSING ENTIRELY",
     [
      ?_assertEqual(ok, expect_module_missing(beamchain_payjoin_server)),
      ?_assertEqual(ok, expect_module_missing(beamchain_payjoin_client)),
      ?_assertEqual(ok, skip_pending("G17",
          "neither receiver-side emission nor sender-side classifier"))
     ]}.

%%% ===================================================================
%%% G18 — Receiver TTL: response within client-acceptable wait window
%%% ===================================================================

g18_receiver_ttl_missing_test_() ->
    {"G18: receiver response TTL / sender wait window MISSING ENTIRELY",
     [
      ?_assertEqual(ok, expect_module_missing(beamchain_payjoin_server)),
      ?_assertEqual(ok, skip_pending("G18",
          "no timeout policy module; receiver hangs would block sender "
          "fallback indefinitely without one"))
     ]}.

%%% ===================================================================
%%% G19 — Receiver no-double-spend: same Original PSBT processed once
%%% ===================================================================

g19_receiver_no_double_processing_missing_test_() ->
    {"G19: receiver-side Original PSBT replay (same PSBT processed "
     "twice) protection MISSING ENTIRELY",
     [
      ?_assertEqual(ok, expect_module_missing(beamchain_payjoin_server)),
      ?_assertEqual(ok, skip_pending("G19",
          "no PSBT-hash dedup ETS table; without it a network reorder "
          "could trigger receiver to add inputs twice to the same invoice"))
     ]}.

%%% ===================================================================
%%% G20 — Receiver UTXO anti-fingerprint (UIH-1/UIH-2)
%%% ===================================================================

g20_receiver_uih_heuristic_missing_test_() ->
    {"G20: receiver-side UIH-1/UIH-2 anti-fingerprint heuristic MISSING",
     [
      ?_assertEqual(ok, expect_module_missing(beamchain_payjoin_server)),
      ?_assertEqual(ok, skip_pending("G20",
          "BIP-78 §UIH warns receivers to avoid trivially-detectable "
          "PayJoins; no heuristic module"))
     ]}.

%%% ===================================================================
%%% G21 — v=1 header / version field handled
%%% ===================================================================

g21_version_v1_handled_missing_test_() ->
    {"G21: BIP-78 v=1 version handling MISSING ENTIRELY",
     [
      ?_assertEqual(ok, expect_module_missing(beamchain_payjoin_server)),
      ?_assertEqual(ok, skip_pending("G21",
          "no version-router; unknown v must yield error "
          "version-unsupported (G17)"))
     ]}.

%%% ===================================================================
%%% G22 — Sender fallback: on receiver error, broadcast Original PSBT
%%% ===================================================================

g22_sender_fallback_broadcast_missing_test_() ->
    {"G22: sender fallback (broadcast Original PSBT on receiver error/"
     "timeout) MISSING ENTIRELY",
     [
      ?_assertEqual(ok, expect_module_missing(beamchain_payjoin_client)),
      ?_assertEqual(ok, skip_pending("G22",
          "rpc_sendtoaddress signs+broadcasts in one shot; there is no "
          "'build PSBT, hold pending response, decide later' state machine"))
     ]}.

%%% ===================================================================
%%% G23 — Receiver Content-Type
%%% ===================================================================

g23_receiver_content_type_missing_test_() ->
    {"G23: receiver Content-Type (text/plain for base64 PSBT) MISSING",
     [
      ?_assertEqual(ok, expect_module_missing(beamchain_payjoin_server)),
      ?_assertEqual(ok, skip_pending("G23",
          "cowboy_req:reply/4 takes Headers map; need a constant binding "
          "Content-Type: text/plain for both request validation and response"))
     ]}.

%%% ===================================================================
%%% G24 — HTTPS cert validation
%%% ===================================================================

g24_https_cert_validation_missing_test_() ->
    {"G24: sender HTTPS cert validation MISSING ENTIRELY",
     [
      ?_assertEqual(ok, expect_module_missing(beamchain_payjoin_client)),
      ?_assertEqual(ok, skip_pending("G24",
          "no SSL/TLS client policy; httpc/ssl options would need "
          "verify_peer + cacerts loaded from system store"))
     ]}.

%%% ===================================================================
%%% G25 — Tor onion endpoint support
%%% ===================================================================

g25_tor_onion_dial_missing_test_() ->
    {"G25: sender dial of .onion PayJoin endpoint MISSING ENTIRELY",
     [
      %% Note: FIX-58 added beamchain_torcontrol (794 LOC) — verify it
      %% loads. The module exists but is server-publishing (ADD_ONION
      %% for OUR hidden service), NOT a SOCKS5 client for dialling a
      %% peer-supplied .onion. So the prerequisite for G25 (Tor SOCKS5
      %% client) is in beamchain_proxy not torcontrol.
      ?_assertNotEqual(non_existing, code:which(beamchain_torcontrol)),
      ?_assertEqual(ok, expect_module_missing(beamchain_payjoin_client)),
      ?_assertEqual(ok, skip_pending("G25",
          "FIX-58 beamchain_torcontrol is server-side (ADD_ONION); the "
          "PayJoin sender needs beamchain_proxy SOCKS5 to reach a peer's "
          ".onion BIP-78 endpoint — different code path"))
     ]}.

%%% ===================================================================
%%% G26 — RPC getpayjoinrequest
%%% ===================================================================

g26_rpc_getpayjoinrequest_missing_test_() ->
    {"G26: RPC getpayjoinrequest MISSING ENTIRELY",
     [
      ?_assertEqual(ok, expect_rpc_method_missing(<<"getpayjoinrequest">>))
     ]}.

%%% ===================================================================
%%% G27 — RPC sendpayjoinrequest
%%% ===================================================================

g27_rpc_sendpayjoinrequest_missing_test_() ->
    {"G27: RPC sendpayjoinrequest MISSING ENTIRELY",
     [
      ?_assertEqual(ok, expect_rpc_method_missing(<<"sendpayjoinrequest">>))
     ]}.

%%% ===================================================================
%%% G28 — BIP-21 URI parameter pj= parsed
%%%
%%% CLOSED by FIX-62 — beamchain_bip21 module now exists and parses
%%% pj= per BIP-21 extension. The original "module missing" absence
%%% assertion is replaced with a positive parse assertion. Module
%%% presence is also asserted so that the symmetric "module present"
%%% smell shows up if a future refactor removes it.
%%% ===================================================================

g28_bip21_pj_param_parsed_test_() ->
    {"G28: BIP-21 URI pj= parameter parses to PayJoin endpoint",
     [
      ?_assertNotEqual(non_existing, code:which(beamchain_bip21)),
      ?_assertMatch({ok, _},
                    beamchain_bip21:parse(
                      <<"bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?"
                        "pj=https%3A%2F%2Fexample.com%2Fpj">>,
                      mainnet))
     ]}.

%%% ===================================================================
%%% G29 — BIP-21 URI parameter pjos= parsed
%%%
%%% CLOSED by FIX-62 — beamchain_bip21 module now parses pjos= as a
%%% strict 0/1 integer (rejects "yes" / "true" / unknown).
%%% ===================================================================

g29_bip21_pjos_param_parsed_test_() ->
    {"G29: BIP-21 URI pjos= parameter parses to disableoutputsubstitution",
     [
      ?_assertNotEqual(non_existing, code:which(beamchain_bip21)),
      ?_assertMatch({ok, _},
                    beamchain_bip21:parse(
                      <<"bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?"
                        "pjos=1">>,
                      mainnet)),
      %% Reject non-{0,1} values — defensive policy that prevents a
      %% misencoded "yes" / "true" from being silently accepted as 1.
      ?_assertMatch({error, {bad_pjos, _}},
                    beamchain_bip21:parse(
                      <<"bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?"
                        "pjos=yes">>,
                      mainnet))
     ]}.

%%% ===================================================================
%%% G30 — Receiver replay protection (once-only token in pj= URL)
%%% ===================================================================

g30_receiver_replay_protection_missing_test_() ->
    {"G30: receiver replay protection (once-only nonce in pj= URL) "
     "MISSING ENTIRELY",
     [
      ?_assertEqual(ok, expect_module_missing(beamchain_payjoin_server)),
      ?_assertEqual(ok, skip_pending("G30",
          "without per-invoice nonce store, closing BUG-1 alone would "
          "permit the same invoice to be PayJoined multiple times"))
     ]}.

%%% ===================================================================
%%% Roll-up: structural prerequisite gaps
%%% ===================================================================

z_structural_prereqs_test_() ->
    {"Structural prereqs for any future PayJoin closure",
     [
      %% W118 TP-2 (#psbt record duplicated) — still open.
      %% We can't easily ?assert without parse-transforming, but we
      %% can ?_assert that BOTH owning modules are still loadable
      %% with their distinct record definitions, which is the
      %% smell. Once unified, one of these modules will lose the
      %% record and the assertion will need updating.
      ?_assertNotEqual(non_existing, code:which(beamchain_psbt)),
      ?_assertNotEqual(non_existing, code:which(beamchain_wallet)),
      %% W118 BUG-5 walletprocesspsbt — still missing
      ?_assertEqual(ok, expect_rpc_method_missing(<<"walletprocesspsbt">>))
     ]}.
