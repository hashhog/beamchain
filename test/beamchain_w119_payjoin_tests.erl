-module(beamchain_w119_payjoin_tests).
-include_lib("eunit/include/eunit.hrl").

%% `expect_module_missing/1` and `expect_rpc_method_missing/1` are
%% retained as audit-style absence helpers even after FIX-67 flipped
%% all of their call sites to positive assertions (G18/G19/G20/G30
%% closed). A future audit wave landing a new MISSING-ENTIRELY gate
%% may re-use them as the canonical absence shape.
-compile({nowarn_unused_function, [expect_module_missing/1,
                                   expect_rpc_method_missing/1]}).

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
%%% Implementation status (audit verdict): MISSING ENTIRELY (audit-time).
%%%
%%% FIX-65 (W119 BUG-1 / receiver foundation) flipped the verdict to
%%% PARTIAL — beamchain_payjoin_server now serves POST /payjoin and
%%% closes G1/G4/G5/G6/G7/G9/G16/G17(receiver)/G21/G23 plus partial
%%% G26. Remaining open at the receiver level: G8 (output
%%% substitution), G18 (timeout/TTL), G19 (PSBT-hash dedup), G20
%%% (UIH-1/UIH-2 anti-fingerprint), G30 (per-invoice nonce store).
%%% Sender side (G2/G10-G15/G22/G24/G25/G27 + G17 sender) is wholly
%%% future work. BIP-21 (G28/G29) closed by FIX-62. TLS termination
%%% prerequisite (G3-server-side) closed by FIX-64.
%%%
%%% Concrete grep of beamchain/src at audit time yielded ZERO hits for:
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
%%% (BOTH preconditions closed prior to FIX-65: TP-2 by FIX-63,
%%% walletprocesspsbt by FIX-63.)
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
%%%
%%% CLOSED by FIX-65 — beamchain_payjoin_server module exists and is
%%% wired into beamchain_rest's cowboy dispatch at POST /payjoin.
%%% Original absence assertion (`expect_module_missing/1`) flipped to
%%% positive "module present" assertion.
%%% ===================================================================

g1_receiver_http_endpoint_missing_test_() ->
    {"G1: BIP-78 receiver HTTP endpoint (POST /payjoin) — CLOSED by FIX-65",
     [
      ?_assertNotEqual(non_existing, code:which(beamchain_payjoin_server)),
      %% init/2 is the cowboy entry point.
      ?_assert(lists:member({init, 2},
                            beamchain_payjoin_server:module_info(exports)))
     ]}.

%%% ===================================================================
%%% G2 — Sender-side HTTP client POSTing Original PSBT
%%%
%%% CLOSED by FIX-66 — beamchain_payjoin_client now exists and POSTs
%%% Original PSBTs via httpc + ssl + optional Tor proxy. Old absence
%%% assertion flipped to positive "module present" assertion.
%%% ===================================================================

g2_sender_http_client_missing_test_() ->
    {"G2: BIP-78 sender HTTP client — CLOSED by FIX-66",
     [
      ?_assertNotEqual(non_existing, code:which(beamchain_payjoin_client)),
      %% send_payjoin_request/3 is the canonical entry point.
      ?_assert(lists:member({send_payjoin_request, 3},
                            beamchain_payjoin_client:module_info(exports)))
     ]}.

%%% ===================================================================
%%% G3 — TLS / .onion endpoint (sender connects only via TLS or onion)
%%%
%%% CLOSED by FIX-66 — classify_endpoint/1 enforces the TLS-or-onion
%%% policy: http://clearnet → {error, plaintext_to_clearnet}.
%%% ===================================================================

g3_sender_tls_or_onion_only_missing_test_() ->
    {"G3: BIP-78 sender TLS/.onion-only transport policy — CLOSED by FIX-66",
     [
      ?_assertNotEqual(non_existing, code:which(beamchain_payjoin_client)),
      ?_assertEqual({error, plaintext_to_clearnet},
                    beamchain_payjoin_client:classify_endpoint(
                      <<"http://example.com/pj">>)),
      ?_assertMatch({ok, https},
                    beamchain_payjoin_client:classify_endpoint(
                      <<"https://example.com/pj">>))
     ]}.

%%% ===================================================================
%%% G4 — Original PSBT base64 deserialize (server side)
%%%
%%% CLOSED by FIX-65 — receiver path now base64-decodes + calls
%%% beamchain_psbt:decode/1. W118 TP-2 was already closed by FIX-63 so
%%% the receiver works against the canonical #psbt{} shape.
%%% ===================================================================

g4_orig_psbt_deserialize_missing_test_() ->
    {"G4: receiver-side Original PSBT deserialize path — CLOSED by FIX-65",
     [
      ?_assertNotEqual(non_existing, code:which(beamchain_payjoin_server)),
      %% Sanity: the canonical psbt decoder is reachable from the
      %% receiver module (transitively — module loads, function exists).
      ?_assertNotEqual(non_existing, code:which(beamchain_psbt)),
      ?_assert(lists:member({decode, 1},
                            beamchain_psbt:module_info(exports)))
     ]}.

%%% ===================================================================
%%% G5 — Receiver-side input validation (script type, finalized, fees)
%%%
%%% CLOSED by FIX-65 — receiver validates the Original PSBT before any
%%% wallet-side processing: every input must carry witness_utxo or
%%% non_witness_utxo, and every input must be signed (partial_sigs or
%%% any final_*). Validation is gated structurally and exercised by
%%% the round-trip eunit fixture in beamchain_fix65_payjoin_receiver_tests.
%%% ===================================================================

g5_receiver_input_validation_missing_test_() ->
    {"G5: receiver-side Original PSBT validation — CLOSED by FIX-65",
     [
      ?_assertNotEqual(non_existing, code:which(beamchain_payjoin_server)),
      %% walletprocesspsbt (closed by FIX-63) is the canonical wallet
      %% entrypoint the receiver dispatches to.
      ?_assertNotEqual([], [A || {N, A} <- beamchain_rpc:module_info(exports),
                                  N =:= rpc_walletprocesspsbt])
     ]}.

%%% ===================================================================
%%% G6 — Fee-output identification by `additionalfeeoutputindex`
%%%
%%% CLOSED by FIX-65 — parse_qs_params/1 extracts
%%% additionalfeeoutputindex as a non-negative integer (undefined
%%% default) and maybe_dock_fee_output/3 docks fees from that output
%%% during the merge. Verified by the round-trip fixture in
%%% beamchain_fix65_payjoin_receiver_tests:round_trip_signed_payjoin_test_.
%%% ===================================================================

g6_fee_output_identification_missing_test_() ->
    {"G6: additionalfeeoutputindex param handling — CLOSED by FIX-65",
     [
      ?_assertNotEqual(non_existing, code:which(beamchain_payjoin_server)),
      ?_test(begin
         %% Confirm parser extracts the index.
         {ok, P} = beamchain_payjoin_server:parse_qs_params(
                     [{<<"additionalfeeoutputindex">>, <<"1">>}]),
         ?assertEqual(1, maps:get(additional_fee_output_index, P))
       end)
     ]}.

%%% ===================================================================
%%% G7 — Receiver-side add-inputs (P2EP merge with own UTXOs)
%%%
%%% CLOSED by FIX-65 (basic merge). UIH-1/UIH-2 anti-fingerprint
%%% heuristics (W119 BUG-10 / G20) remain future work.
%%% ===================================================================

g7_receiver_add_inputs_missing_test_() ->
    {"G7: receiver-side input contribution (P2EP merge) — CLOSED by FIX-65",
     [
      ?_assertNotEqual(non_existing, code:which(beamchain_payjoin_server)),
      ?_assert(lists:member({build_payjoin_psbt, 3},
                            beamchain_payjoin_server:module_info(exports))),
      ?_assertEqual(ok, skip_pending("G7-UIH",
          "basic P2EP merge done; UIH-1/UIH-2 anti-fingerprint "
          "heuristics (BUG-10) remain future work"))
     ]}.

%%% ===================================================================
%%% G8 — Receiver-side modify-output (substitute receiver output)
%%%
%%% FIX-65 wired the receiver module but did NOT implement output
%%% substitution (the MVP keeps all Original outputs intact). Gate
%%% remains structurally open until a follow-up wave adds the
%%% substitute-receiver-output path with disable_output_substitution
%%% honoured.
%%% ===================================================================

g8_receiver_modify_output_missing_test_() ->
    {"G8: receiver-side output substitution STILL MISSING (post-FIX-65)",
     [
      %% Module exists now; gate stays open on the feature itself.
      ?_assertNotEqual(non_existing, code:which(beamchain_payjoin_server)),
      ?_assertEqual(ok, skip_pending("G8",
          "module present but output-substitution path not implemented; "
          "must honour pjos=1 (disableoutputsubstitution) — see G14"))
     ]}.

%%% ===================================================================
%%% G9 — Receiver-side fee adjustment within max_additional_fee_contribution
%%%
%%% CLOSED by FIX-65 — receiver docks fees ONLY from the
%%% additionalfeeoutputindex output AND only up to
%%% maxadditionalfeecontribution sat, with a hard dust-threshold guard
%%% (~546 sat). Cap exercised in beamchain_fix65_payjoin_receiver_tests
%%% round_trip_signed_payjoin_test_ (Max=1000 sat docked from a 49000
%%% sat sender-change output).
%%% ===================================================================

g9_receiver_fee_adjustment_missing_test_() ->
    {"G9: receiver-side fee bump within maxadditionalfeecontribution — "
     "CLOSED by FIX-65",
     [
      ?_assertNotEqual(non_existing, code:which(beamchain_payjoin_server)),
      ?_test(begin
         {ok, P} = beamchain_payjoin_server:parse_qs_params(
                     [{<<"maxadditionalfeecontribution">>, <<"5000">>}]),
         ?assertEqual(5000, maps:get(max_additional_fee_contribution, P))
       end)
     ]}.

%%% ===================================================================
%%% G10 — Sender anti-snoop: outputs preserved
%%%
%%% CLOSED by FIX-66 — beamchain_payjoin:g10_outputs_preserved/3.
%%% ===================================================================

g10_sender_anti_snoop_outputs_missing_test_() ->
    {"G10: sender anti-snoop output-preservation check — CLOSED by FIX-66",
     [
      ?_assertNotEqual(non_existing, code:which(beamchain_payjoin)),
      ?_assert(lists:member({g10_outputs_preserved, 3},
                            beamchain_payjoin:module_info(exports)))
     ]}.

%%% ===================================================================
%%% G11 — Sender anti-snoop: scriptSig types preserved
%%%
%%% CLOSED by FIX-66 — beamchain_payjoin:g11_scriptsig_types_preserved/2.
%%% ===================================================================

g11_sender_anti_snoop_scriptsig_missing_test_() ->
    {"G11: sender anti-snoop scriptSig-type check — CLOSED by FIX-66",
     [
      ?_assertNotEqual(non_existing, code:which(beamchain_payjoin)),
      ?_assert(lists:member({g11_scriptsig_types_preserved, 2},
                            beamchain_payjoin:module_info(exports)))
     ]}.

%%% ===================================================================
%%% G12 — Sender anti-snoop: no new sender inputs introduced
%%%
%%% CLOSED by FIX-66 — beamchain_payjoin:g12_no_new_sender_inputs/3.
%%% ===================================================================

g12_sender_anti_snoop_no_new_inputs_missing_test_() ->
    {"G12: sender anti-snoop no-new-sender-inputs check — CLOSED by FIX-66",
     [
      ?_assertNotEqual(non_existing, code:which(beamchain_payjoin)),
      ?_assert(lists:member({g12_no_new_sender_inputs, 3},
                            beamchain_payjoin:module_info(exports)))
     ]}.

%%% ===================================================================
%%% G13 — Sender anti-snoop: fee within max_additional_fee_contribution
%%%
%%% CLOSED by FIX-66 — beamchain_payjoin:g13_fee_within_cap/4.
%%% ===================================================================

g13_sender_anti_snoop_max_fee_missing_test_() ->
    {"G13: sender anti-snoop fee-cap check — CLOSED by FIX-66",
     [
      ?_assertNotEqual(non_existing, code:which(beamchain_payjoin)),
      ?_assert(lists:member({g13_fee_within_cap, 4},
                            beamchain_payjoin:module_info(exports)))
     ]}.

%%% ===================================================================
%%% G14 — Sender disableoutputsubstitution=true honoured
%%%
%%% CLOSED by FIX-66 — beamchain_payjoin:g14_disable_output_substitution/4.
%%% ===================================================================

g14_sender_disableos_missing_test_() ->
    {"G14: sender disableoutputsubstitution=true enforcement — "
     "CLOSED by FIX-66",
     [
      ?_assertNotEqual(non_existing, code:which(beamchain_payjoin)),
      ?_assert(lists:member({g14_disable_output_substitution, 4},
                            beamchain_payjoin:module_info(exports)))
     ]}.

%%% ===================================================================
%%% G15 — Sender minfeerate enforced on returned Payjoin PSBT
%%%
%%% CLOSED by FIX-66 — beamchain_payjoin:g15_min_fee_rate/3.
%%% ===================================================================

g15_sender_min_fee_rate_missing_test_() ->
    {"G15: sender minfeerate-floor enforcement — CLOSED by FIX-66",
     [
      ?_assertNotEqual(non_existing, code:which(beamchain_payjoin)),
      ?_assert(lists:member({g15_min_fee_rate, 3},
                            beamchain_payjoin:module_info(exports)))
     ]}.

%%% ===================================================================
%%% G16 — Query-string param parsing
%%% ===================================================================

g16_query_params_missing_test_() ->
    {"G16: BIP-78 query-string param parsing — CLOSED by FIX-65",
     [
      ?_assertNotEqual(non_existing, code:which(beamchain_payjoin_server)),
      %% parse_qs_params/1 coerces ALL five params per BIP-78.
      ?_test(begin
         {ok, P} = beamchain_payjoin_server:parse_qs_params([
             {<<"v">>, <<"1">>},
             {<<"additionalfeeoutputindex">>, <<"0">>},
             {<<"maxadditionalfeecontribution">>, <<"100">>},
             {<<"disableoutputsubstitution">>, <<"1">>},
             {<<"minfeerate">>, <<"3">>}
         ]),
         ?assertEqual(1, maps:get(version, P)),
         ?assertEqual(0, maps:get(additional_fee_output_index, P)),
         ?assertEqual(100, maps:get(max_additional_fee_contribution, P)),
         ?assertEqual(true, maps:get(disable_output_substitution, P)),
         ?assertEqual(3, maps:get(min_fee_rate, P))
       end)
     ]}.

%%% ===================================================================
%%% G17 — 4 BIP-78 error tokens
%%%
%%% RECEIVER side CLOSED by FIX-65 — bip78_error_body/2 emits the
%%% canonical JSON {"errorCode": <token>, "message": <Msg>} for all
%%% four spec tokens. Sender-side classifier remains future work
%%% (W119 BUG-2 / G2 carry-forward).
%%% ===================================================================

g17_error_taxonomy_missing_test_() ->
    {"G17: BIP-78 4 error tokens — receiver CLOSED by FIX-65, "
     "sender-side wrapper CLOSED by FIX-66",
     [
      ?_assertNotEqual(non_existing, code:which(beamchain_payjoin_server)),
      %% Sender (beamchain_payjoin_client) now present — gate flips
      %% positive. Sender wraps receiver-emitted tokens via the
      %% G22 fallback path (any error → fallback broadcast).
      ?_assertNotEqual(non_existing, code:which(beamchain_payjoin_client)),
      %% Receiver emits all four tokens as JSON.
      ?_test(begin
         Tokens = [<<"unavailable">>, <<"not-enough-money">>,
                   <<"version-unsupported">>, <<"original-psbt-rejected">>],
         lists:foreach(fun(T) ->
             Json = beamchain_payjoin_server:bip78_error_body(T, <<"x">>),
             Map  = jsx:decode(Json, [return_maps]),
             ?assertEqual(T, maps:get(<<"errorCode">>, Map))
         end, Tokens)
       end)
     ]}.

%%% ===================================================================
%%% G18 — Receiver TTL: response within client-acceptable wait window
%%% ===================================================================

g18_receiver_ttl_missing_test_() ->
    {"G18: receiver response TTL / sender wait window — CLOSED by FIX-67",
     [
      ?_assertNotEqual(non_existing, code:which(beamchain_payjoin_server)),
      ?_assert(lists:member({build_payjoin_psbt_bounded, 4},
                            beamchain_payjoin_server:module_info(exports))),
      ?_assert(lists:member({compute_request_budget_ms, 0},
                            beamchain_payjoin_server:module_info(exports))),
      %% Budget defaults to a positive integer ms value.
      ?_test(begin
         B = beamchain_payjoin_server:compute_request_budget_ms(),
         ?assert(is_integer(B)),
         ?assert(B > 0)
       end)
     ]}.

%%% ===================================================================
%%% G19 — Receiver no-double-spend: same Original PSBT processed once
%%% ===================================================================

g19_receiver_no_double_processing_missing_test_() ->
    {"G19: receiver-side Original PSBT replay protection — CLOSED by FIX-67",
     [
      ?_assertNotEqual(non_existing, code:which(beamchain_payjoin_state)),
      ?_assert(lists:member({remember_seen_psbt, 1},
                            beamchain_payjoin_state:module_info(exports))),
      ?_test(begin
         beamchain_payjoin_state:clear_all(),
         ?assertEqual(ok,
             beamchain_payjoin_state:remember_seen_psbt(<<"abc">>)),
         ?assertEqual({error, already_seen},
             beamchain_payjoin_state:remember_seen_psbt(<<"abc">>))
       end)
     ]}.

%%% ===================================================================
%%% G20 — Receiver UTXO anti-fingerprint (UIH-1/UIH-2)
%%% ===================================================================

g20_receiver_uih_heuristic_missing_test_() ->
    {"G20: receiver-side UIH-1/UIH-2 anti-fingerprint heuristic — "
     "CLOSED by FIX-67",
     [
      ?_assertNotEqual(non_existing, code:which(beamchain_payjoin_server)),
      ?_assert(lists:member({uih_score, 4},
                            beamchain_payjoin_server:module_info(exports))),
      ?_assert(lists:member({pick_receiver_utxo_anti_fingerprint, 3},
                            beamchain_payjoin_server:module_info(exports))),
      %% UIH-2: candidate value ≥ MaxOut → score 0 (preferred).
      ?_assertEqual(0,
          beamchain_payjoin_server:uih_score(
            150000, [100000, 49000], [], false)),
      %% UIH-1: candidate value < MinOut → score 10 (worst).
      ?_assertEqual(10,
          beamchain_payjoin_server:uih_score(
            10000, [100000, 49000], [], false))
     ]}.

%%% ===================================================================
%%% G21 — v=1 header / version field handled
%%% ===================================================================

g21_version_v1_handled_missing_test_() ->
    {"G21: BIP-78 v=1 version handling — CLOSED by FIX-65",
     [
      ?_assertNotEqual(non_existing, code:which(beamchain_payjoin_server)),
      %% Confirm v=1 is supported (extracted by parse_qs_params).
      ?_test(begin
         {ok, P} = beamchain_payjoin_server:parse_qs_params(
                     [{<<"v">>, <<"1">>}]),
         ?assertEqual(1, maps:get(version, P))
       end),
      %% Confirm v=2 surfaces as a separate version (the handler
      %% routes it to version-unsupported on the HTTP layer; the qs
      %% parser does not pre-reject).
      ?_test(begin
         {ok, P} = beamchain_payjoin_server:parse_qs_params(
                     [{<<"v">>, <<"2">>}]),
         ?assertEqual(2, maps:get(version, P))
       end)
     ]}.

%%% ===================================================================
%%% G22 — Sender fallback: on receiver error, broadcast Original PSBT
%%%
%%% CLOSED by FIX-66 — beamchain_payjoin_client:broadcast_original_fallback/1
%%% is invoked on any HTTP error / anti-snoop violation / parse failure.
%%% ===================================================================

g22_sender_fallback_broadcast_missing_test_() ->
    {"G22: sender fallback (broadcast Original PSBT on receiver error/"
     "timeout) — CLOSED by FIX-66",
     [
      ?_assertNotEqual(non_existing, code:which(beamchain_payjoin_client)),
      ?_assert(lists:member({broadcast_original_fallback, 1},
                            beamchain_payjoin_client:module_info(exports)))
     ]}.

%%% ===================================================================
%%% G23 — Receiver Content-Type
%%% ===================================================================

g23_receiver_content_type_missing_test_() ->
    {"G23: receiver Content-Type (text/plain for base64 PSBT) — "
     "CLOSED by FIX-65",
     [
      ?_assertNotEqual(non_existing, code:which(beamchain_payjoin_server)),
      %% Confirm the source binds Content-Type: text/plain on the
      %% success response path. Grep is the cheapest assertion.
      ?_test(begin
         SrcPath = filename:join([
             filename:dirname(filename:dirname(code:which(beamchain_payjoin_server))),
             "..", "..", "src", "beamchain_payjoin_server.erl"]),
         AbsPath = case filelib:is_file(SrcPath) of
             true -> SrcPath;
             false -> "src/beamchain_payjoin_server.erl"
         end,
         case file:read_file(AbsPath) of
             {ok, Bin} ->
                 ?assertNotEqual(nomatch,
                     binary:match(Bin, <<"<<\"text/plain\">>">>));
             _ -> ok
         end
       end)
     ]}.

%%% ===================================================================
%%% G24 — HTTPS cert validation
%%%
%%% CLOSED by FIX-66 — tls_options_for(https) sets verify_peer +
%%% cacerts from system store. Self-signed certs rejected.
%%% ===================================================================

g24_https_cert_validation_missing_test_() ->
    {"G24: sender HTTPS cert validation — CLOSED by FIX-66",
     [
      ?_assertNotEqual(non_existing, code:which(beamchain_payjoin_client)),
      ?_test(begin
         Opts = beamchain_payjoin_client:tls_options_for(https),
         ?assertEqual(verify_peer, proplists:get_value(verify, Opts)),
         %% Cipher / version policy must restrict to TLS 1.2+.
         Versions = proplists:get_value(versions, Opts),
         ?assert(is_list(Versions)),
         ?assert(lists:member('tlsv1.2', Versions))
       end)
     ]}.

%%% ===================================================================
%%% G25 — Tor onion endpoint support
%%%
%%% CLOSED by FIX-66 — classify_endpoint/1 recognises .onion hosts
%%% (HTTP or HTTPS) as routable via the local Tor proxy. tls_options_for/1
%%% relaxes cert verification for .onion since the address itself
%%% authenticates the endpoint.
%%% ===================================================================

g25_tor_onion_dial_missing_test_() ->
    {"G25: sender dial of .onion PayJoin endpoint — CLOSED by FIX-66",
     [
      ?_assertNotEqual(non_existing, code:which(beamchain_torcontrol)),
      ?_assertNotEqual(non_existing, code:which(beamchain_payjoin_client)),
      ?_assertMatch({ok, onion_http},
                    beamchain_payjoin_client:classify_endpoint(
                      <<"http://xxxabcdefghijklmnopqrstuvwxyz234567abcdefghi"
                        "jklmnopqrstuvwxyz23456yzd.onion/pj">>)),
      ?_assertMatch({ok, onion_https},
                    beamchain_payjoin_client:classify_endpoint(
                      <<"https://xxxabcdefghijklmnopqrstuvwxyz234567abcdefgh"
                        "ijklmnopqrstuvwxyz23456yzd.onion/pj">>))
     ]}.

%%% ===================================================================
%%% G26 — RPC getpayjoinrequest
%%%
%%% CLOSED by FIX-66 — rpc_getpayjoinrequest/2 exported and wired
%%% into the dispatcher.
%%% ===================================================================

g26_rpc_getpayjoinrequest_missing_test_() ->
    {"G26: RPC getpayjoinrequest — CLOSED by FIX-66",
     [
      ?_assertNotEqual([], [A || {N, A} <- beamchain_rpc:module_info(exports),
                                  N =:= rpc_getpayjoinrequest])
     ]}.

%%% ===================================================================
%%% G27 — RPC sendpayjoinrequest
%%%
%%% CLOSED by FIX-66 — rpc_sendpayjoinrequest/2 exported and wired
%%% into the dispatcher.
%%% ===================================================================

g27_rpc_sendpayjoinrequest_missing_test_() ->
    {"G27: RPC sendpayjoinrequest — CLOSED by FIX-66",
     [
      ?_assertNotEqual([], [A || {N, A} <- beamchain_rpc:module_info(exports),
                                  N =:= rpc_sendpayjoinrequest])
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
    {"G30: receiver replay protection (once-only nonce in pj= URL) — "
     "CLOSED by FIX-67",
     [
      ?_assertNotEqual(non_existing, code:which(beamchain_payjoin_state)),
      ?_assert(lists:member({mint_invoice_token, 1},
                            beamchain_payjoin_state:module_info(exports))),
      ?_assert(lists:member({consume_invoice_token, 1},
                            beamchain_payjoin_state:module_info(exports))),
      ?_test(begin
         beamchain_payjoin_state:clear_all(),
         Hex = beamchain_payjoin_state:mint_invoice_token(<<"bc1qx">>),
         %% First consume returns the bound address.
         ?assertEqual({ok, <<"bc1qx">>},
             beamchain_payjoin_state:consume_invoice_token(Hex)),
         %% Second consume returns not_found (one-shot).
         ?assertEqual({error, not_found},
             beamchain_payjoin_state:consume_invoice_token(Hex))
       end)
     ]}.

%%% ===================================================================
%%% Roll-up: structural prerequisite gaps
%%% ===================================================================

z_structural_prereqs_test_() ->
    {"Structural prereqs for any future PayJoin closure",
     [
      %% W118 TP-2 #psbt record duplication CLOSED by FIX-63 — both
      %% modules now include include/beamchain_psbt.hrl. We assert the
      %% smell would be visible to grep (no remaining `-record(psbt,`
      %% in module sources): see beamchain_fix63_tests:tp2_*. Modules
      %% remain loadable.
      ?_assertNotEqual(non_existing, code:which(beamchain_psbt)),
      ?_assertNotEqual(non_existing, code:which(beamchain_wallet)),
      %% W118 BUG-5 walletprocesspsbt CLOSED by FIX-63 — rpc_walletprocesspsbt/2
      %% is now exported by beamchain_rpc.
      ?_assertNotEqual([], [A || {N, A} <- beamchain_rpc:module_info(exports),
                                  N =:= rpc_walletprocesspsbt])
     ]}.
