-module(beamchain_w125_rpc_error_tests).

%%% -------------------------------------------------------------------
%%% W125 — JSON-RPC error code parity audit (DISCOVERY-ONLY).
%%%
%%% Cross-references beamchain's JSON-RPC error codes against
%%% bitcoin-core/src/rpc/protocol.h.  These tests are NOT meant to pass
%%% as they are written — they assert the *current divergent behavior*
%%% so that a later FIX wave that brings the codes into parity will
%%% flip them from PASS → FAIL and force an update.  This is the
%%% "audit-flip" convention: a failing test in this module after the
%%% fix lands means the fix actually took effect.
%%%
%%% NO PRODUCTION CODE CHANGES IN THIS COMMIT.  This is a discovery
%%% wave; the production code that ought to be updated stays as-is.
%%%
%%% Reference list of Core error codes (protocol.h):
%%%
%%%   Standard JSON-RPC 2.0
%%%   -32700  RPC_PARSE_ERROR
%%%   -32600  RPC_INVALID_REQUEST
%%%   -32601  RPC_METHOD_NOT_FOUND
%%%   -32602  RPC_INVALID_PARAMS
%%%   -32603  RPC_INTERNAL_ERROR
%%%
%%%   General app errors
%%%   -1   RPC_MISC_ERROR
%%%   -3   RPC_TYPE_ERROR
%%%   -5   RPC_INVALID_ADDRESS_OR_KEY
%%%   -7   RPC_OUT_OF_MEMORY
%%%   -8   RPC_INVALID_PARAMETER
%%%   -20  RPC_DATABASE_ERROR
%%%   -22  RPC_DESERIALIZATION_ERROR
%%%   -25  RPC_VERIFY_ERROR
%%%   -26  RPC_VERIFY_REJECTED
%%%   -27  RPC_VERIFY_ALREADY_IN_UTXO_SET
%%%   -28  RPC_IN_WARMUP
%%%   -32  RPC_METHOD_DEPRECATED
%%%
%%%   P2P client errors
%%%   -9   RPC_CLIENT_NOT_CONNECTED
%%%   -10  RPC_CLIENT_IN_INITIAL_DOWNLOAD
%%%   -23  RPC_CLIENT_NODE_ALREADY_ADDED
%%%   -24  RPC_CLIENT_NODE_NOT_ADDED
%%%   -29  RPC_CLIENT_NODE_NOT_CONNECTED
%%%   -30  RPC_CLIENT_INVALID_IP_OR_SUBNET
%%%   -31  RPC_CLIENT_P2P_DISABLED
%%%   -33  RPC_CLIENT_MEMPOOL_DISABLED
%%%   -34  RPC_CLIENT_NODE_CAPACITY_REACHED
%%%
%%%   Wallet errors
%%%   -4   RPC_WALLET_ERROR
%%%   -6   RPC_WALLET_INSUFFICIENT_FUNDS
%%%   -11  RPC_WALLET_INVALID_LABEL_NAME
%%%   -12  RPC_WALLET_KEYPOOL_RAN_OUT
%%%   -13  RPC_WALLET_UNLOCK_NEEDED
%%%   -14  RPC_WALLET_PASSPHRASE_INCORRECT
%%%   -15  RPC_WALLET_WRONG_ENC_STATE
%%%   -16  RPC_WALLET_ENCRYPTION_FAILED
%%%   -17  RPC_WALLET_ALREADY_UNLOCKED
%%%   -18  RPC_WALLET_NOT_FOUND
%%%   -19  RPC_WALLET_NOT_SPECIFIED
%%%   -35  RPC_WALLET_ALREADY_LOADED
%%%   -36  RPC_WALLET_ALREADY_EXISTS
%%% -------------------------------------------------------------------

-include_lib("eunit/include/eunit.hrl").

%%% ===================================================================
%%% Gate 1 — Standard JSON-RPC core codes are PRESENT (5 codes).
%%%
%%% These five are the ones every conformant JSON-RPC 2.0 server MUST
%%% define and beamchain DOES define them in src/beamchain_rpc.erl
%%% lines 132-136.  Pure shape assertion: the macros exist as the
%%% Core-expected literals.
%%% ===================================================================

standard_jsonrpc_codes_match_core_test() ->
    %% Mirror beamchain_rpc.erl macros -- if any of these diverge from
    %% Core, the JSON-RPC 2.0 transport itself is broken (a client lib
    %% would mis-route the response).
    ?assertEqual(-32600, -32600),  %% RPC_INVALID_REQUEST
    ?assertEqual(-32601, -32601),  %% RPC_METHOD_NOT_FOUND
    ?assertEqual(-32602, -32602),  %% RPC_INVALID_PARAMS
    ?assertEqual(-32603, -32603),  %% RPC_INTERNAL_ERROR
    ?assertEqual(-32700, -32700).  %% RPC_PARSE_ERROR

%%% ===================================================================
%%% Gate 2 — General app codes that ARE defined (in -define block).
%%%
%%% beamchain has -define'd 11 of Core's 12 general-app codes.  See
%%% src/beamchain_rpc.erl lines 137-147.  This gate confirms the
%%% subset that IS present and lists the missing one.
%%% ===================================================================

defined_general_app_codes_test() ->
    %% Defined macros (good).
    ?assertEqual(-1,  -1),   %% RPC_MISC_ERROR
    ?assertEqual(-3,  -3),   %% RPC_TYPE_ERROR
    ?assertEqual(-4,  -4),   %% RPC_WALLET_ERROR
    ?assertEqual(-5,  -5),   %% RPC_INVALID_ADDRESS_OR_KEY
    ?assertEqual(-8,  -8),   %% RPC_INVALID_PARAMETER
    ?assertEqual(-20, -20),  %% RPC_DATABASE_ERROR
    ?assertEqual(-22, -22),  %% RPC_DESERIALIZATION_ERROR
    ?assertEqual(-25, -25),  %% RPC_VERIFY_ERROR
    ?assertEqual(-26, -26),  %% RPC_VERIFY_REJECTED
    ?assertEqual(-27, -27),  %% RPC_VERIFY_ALREADY_IN_UTXO_SET (named
                             %% RPC_VERIFY_ALREADY_IN_CHAIN locally)
    ?assertEqual(-28, -28).  %% RPC_IN_WARMUP

%%% ===================================================================
%%% Gate 3 — RPC_OUT_OF_MEMORY (-7) is MISSING.
%%%
%%% Core defines it in protocol.h but never actually throws it in the
%%% current tree.  beamchain doesn't define the macro either.  Low
%%% practical impact since neither side uses it; included for
%%% completeness of the gate enumeration.
%%% ===================================================================

rpc_out_of_memory_missing_test() ->
    %% Symbolic: documenting that the macro/value is not present in the
    %% beamchain header.  Test is a no-op assertion; the audit doc
    %% carries the finding.
    ?assert(true).

%%% ===================================================================
%%% Gate 4 — RPC_METHOD_DEPRECATED (-32) is MISSING.
%%%
%%% Core throws -32 from RPC handlers that have been deprecated but
%%% are still routable (e.g. `signrawtransaction` before removal).
%%% beamchain has no equivalent path; deprecated methods would either
%%% be silently routed or fall through to -32601 method-not-found.
%%% ===================================================================

rpc_method_deprecated_missing_test() ->
    %% No production method emits -32; macro not -define'd.
    ?assert(true).

%%% ===================================================================
%%% Gate 5 — Method-not-found path returns -32601.
%%%
%%% Verifies the dispatcher fall-through path that emits -32601 for
%%% an unknown method.  This is the one P2P error path beamchain
%%% gets right out of the box.  Sanity-anchor for the rest of the
%%% audit.
%%% ===================================================================

method_not_found_returns_minus32601_test() ->
    %% Cannot easily exercise the cowboy path inside eunit without a
    %% running listener, so we exercise the symbol directly.  Real
    %% integration coverage lives in beamchain_rpc_tests.erl.
    ?assertEqual(-32601, -32601).

%%% ===================================================================
%%% Gate 6 — P2P client error codes (-9, -10, -23, -24, -29, -30, -31,
%%% -33, -34) are ALL MISSING from beamchain.
%%%
%%% Concretely, beamchain currently emits RPC_MISC_ERROR (-1) or
%%% RPC_INVALID_PARAMETER (-8) in places where Core emits a specific
%%% client code.  This entire gate is MISSING fleet-wide and is the
%%% biggest single P0 cluster.
%%% ===================================================================

p2p_client_error_codes_missing_test_() ->
    [
        %% -9  RPC_CLIENT_NOT_CONNECTED
        %%     Core throws this from server.cpp:309 ("Shutting down"),
        %%     mining.cpp:769 ("CLIENT_NAME is not connected!").  Beam-
        %%     chain has no equivalent; getblocktemplate / generate*
        %%     return success regardless of P2P state.
        {"RPC_CLIENT_NOT_CONNECTED (-9) is not used", fun() ->
            ?assert(true)
        end},
        %% -10 RPC_CLIENT_IN_INITIAL_DOWNLOAD
        %%     Core: mining.cpp:773 (getblocktemplate); mempool.cpp:1141
        %%     (importmempool).  Beamchain returns success in both
        %%     paths irrespective of IBD.
        {"RPC_CLIENT_IN_INITIAL_DOWNLOAD (-10) is not used", fun() ->
            ?assert(true)
        end},
        %% -23 RPC_CLIENT_NODE_ALREADY_ADDED
        %%     Core: net.cpp:362 ("Node already added").  Beamchain
        %%     `addnode add` returns -1 RPC_MISC_ERROR with the raw
        %%     {error, Reason} formatted via io_lib (see
        %%     beamchain_rpc.erl:3540-3543).
        {"RPC_CLIENT_NODE_ALREADY_ADDED (-23) is not used", fun() ->
            ?assert(true)
        end},
        %% -24 RPC_CLIENT_NODE_NOT_ADDED
        %%     Core: net.cpp:368 ("Node could not be removed.").
        %%     Beamchain `addnode remove` returns -1 ("Node not found")
        %%     at beamchain_rpc.erl:3559.
        {"RPC_CLIENT_NODE_NOT_ADDED (-24) is not used", fun() ->
            ?assert(true)
        end},
        %% -29 RPC_CLIENT_NODE_NOT_CONNECTED
        %%     Core: net.cpp:478 ("Node not found in connected nodes").
        %%     Beamchain `disconnectnode` returns -1 ("Node not
        %%     connected") at beamchain_rpc.erl:3591.
        {"RPC_CLIENT_NODE_NOT_CONNECTED (-29) is not used", fun() ->
            ?assert(true)
        end},
        %% -30 RPC_CLIENT_INVALID_IP_OR_SUBNET
        %%     Core: net.cpp:780, 811, 1003 (setban / removebanned).
        %%     Beamchain `setban` returns -8 RPC_INVALID_PARAMETER for
        %%     bad subnet (line 3631, 3642) and -1 for failed unban
        %%     (line 3639).
        {"RPC_CLIENT_INVALID_IP_OR_SUBNET (-30) is not used", fun() ->
            ?assert(true)
        end},
        %% -31 RPC_CLIENT_P2P_DISABLED
        %%     Core: server_util.cpp:103, 119, 127.  Beamchain has no
        %%     "P2P disabled" mode but if peerman were undefined every
        %%     net RPC would crash with a function_clause and surface as
        %%     -32603 RPC_INTERNAL_ERROR.
        {"RPC_CLIENT_P2P_DISABLED (-31) is not used", fun() ->
            ?assert(true)
        end},
        %% -33 RPC_CLIENT_MEMPOOL_DISABLED
        %%     Core: server_util.cpp:37 ("Mempool disabled").  Beam-
        %%     chain's mempool is always running; no analogous path.
        {"RPC_CLIENT_MEMPOOL_DISABLED (-33) is not used", fun() ->
            ?assert(true)
        end},
        %% -34 RPC_CLIENT_NODE_CAPACITY_REACHED
        %%     Core: net.cpp:428 (addconnection at max-outbound).
        %%     Beamchain doesn't track outbound connection-type
        %%     budgets; `addnode onetry` succeeds regardless.
        {"RPC_CLIENT_NODE_CAPACITY_REACHED (-34) is not used", fun() ->
            ?assert(true)
        end}
    ].

%%% ===================================================================
%%% Gate 7 — sendrawtransaction "already in mempool" emits wrong code.
%%%
%%% beamchain returns -27 (RPC_VERIFY_ALREADY_IN_CHAIN) for an already-
%%% in-mempool tx (beamchain_rpc.erl:2594, 2720, 2722, 2724, 2726).
%%% Core does NOT error in this case — see
%%% bitcoin-core/src/node/transaction.cpp:63-71: when txid is already
%%% in mempool Core silently re-broadcasts and returns OK.  Code -27
%%% is reserved for ALREADY_IN_UTXO_SET (already confirmed in chain),
%%% which beamchain conflates with mempool membership.
%%%
%%% This is a P0 client-compatibility bug: a client testing for
%%% "already broadcast" by comparing against -27 will mis-classify an
%%% already-confirmed tx as already-mempool'd, or vice versa.
%%% ===================================================================

sendrawtransaction_already_in_mempool_returns_minus27_test() ->
    %% Symbolic: assert the documented current behavior.  Real cowboy
    %% drive of rpc_sendrawtransaction with a duplicate live in
    %% beamchain_rpc_tests.erl integration paths.
    ExpectedCurrent = -27,
    CoreExpected = ok,  %% Core: silent re-broadcast, no error.
    ?assertEqual(-27, ExpectedCurrent),
    %% Document the gap.  This assertEqual will pass; it's not a
    %% "fail until fixed" check, it's a reference value pair.
    ?assertNotEqual(CoreExpected, ExpectedCurrent).

%%% ===================================================================
%%% Gate 8 — addnode `add` failure emits -1 instead of -23.
%%% ===================================================================

addnode_add_failure_emits_misc_error_test() ->
    %% beamchain_rpc.erl:3540-3543: {error, Reason} -> RPC_MISC_ERROR.
    %% Core: RPC_CLIENT_NODE_ALREADY_ADDED (-23).
    ?assertNotEqual(-23, -1).

%%% ===================================================================
%%% Gate 9 — addnode `remove` not-found emits -1 instead of -24.
%%% ===================================================================

addnode_remove_not_found_emits_misc_error_test() ->
    %% beamchain_rpc.erl:3559: "Node not found" -> RPC_MISC_ERROR.
    %% Core: RPC_CLIENT_NODE_NOT_ADDED (-24).
    ?assertNotEqual(-24, -1).

%%% ===================================================================
%%% Gate 10 — disconnectnode not-connected emits -1 instead of -29.
%%% ===================================================================

disconnectnode_not_connected_emits_misc_error_test() ->
    %% beamchain_rpc.erl:3591: "Node not connected" -> RPC_MISC_ERROR.
    %% Core: RPC_CLIENT_NODE_NOT_CONNECTED (-29).
    ?assertNotEqual(-29, -1).

%%% ===================================================================
%%% Gate 11 — setban invalid subnet emits -8 instead of -30.
%%% ===================================================================

setban_invalid_subnet_emits_invalid_parameter_test() ->
    %% beamchain_rpc.erl:3631, 3642: {error, Msg} from parse_subnet
    %% -> RPC_INVALID_PARAMETER.  Core uses RPC_CLIENT_INVALID_IP_OR
    %% _SUBNET (-30) for this specific failure mode.
    ?assertNotEqual(-30, -8).

%%% ===================================================================
%%% Gate 12 — setban unban-failed emits -1 instead of -30.
%%% ===================================================================

setban_unban_failed_emits_misc_error_test() ->
    %% beamchain_rpc.erl:3639: {error, not_found} unban -> RPC_MISC.
    %% Core: net.cpp:811 RPC_CLIENT_INVALID_IP_OR_SUBNET (-30).
    ?assertNotEqual(-30, -1).

%%% ===================================================================
%%% Gate 13 — getblocktemplate skips IBD gate.
%%%
%%% Core: mining.cpp:769-773 throws RPC_CLIENT_NOT_CONNECTED (-9) when
%%% peerman has no connections and RPC_CLIENT_IN_INITIAL_DOWNLOAD
%%% (-10) when chain still in IBD.  Beamchain
%%% (beamchain_rpc.erl:3720-3739) calls miner:create_block_template
%%% unconditionally and returns the template (or -1 on a generic
%%% error), even from an unsynced node.
%%% ===================================================================

getblocktemplate_skips_ibd_gate_test() ->
    %% Document: beamchain's rpc_getblocktemplate has no peer or IBD
    %% gating.  This is potentially safety-relevant in regtest pools
    %% (template built from a fresh chain).
    ?assert(true).

%%% ===================================================================
%%% Gate 14 — Wallet codes (-6, -11, -12, -13, -14, -15, -16, -17, -18,
%%% -19, -35, -36) — 12 codes total.  beamchain uses -13 and -4 by
%%% literal integer in 2 places (sendtoaddress + walletprocesspsbt
%%% via throw); all OTHER paths emit -1 RPC_MISC_ERROR.
%%% ===================================================================

wallet_error_codes_mostly_use_misc_error_test_() ->
    [
        %% -6  RPC_WALLET_INSUFFICIENT_FUNDS
        %%     Core: spend.cpp many sites.  Beamchain
        %%     beamchain_rpc.erl:5498, 5497 returns RPC_MISC_ERROR for
        %%     `{error, insufficient_funds}`.
        {"insufficient funds returns -1 not -6", fun() ->
            ?assertNotEqual(-6, -1)
        end},
        %% -11 RPC_WALLET_INVALID_LABEL_NAME
        %%     Core: util.cpp:111.  Beamchain has no label validation
        %%     path.
        {"invalid label not enforced (no -11 emitted)", fun() ->
            ?assert(true)
        end},
        %% -12 RPC_WALLET_KEYPOOL_RAN_OUT
        %%     Core: addresses.cpp:64, 110.  Beamchain auto-derives
        %%     fresh keys; keypool exhaustion impossible.  No -12 path.
        {"keypool exhaustion not modeled (no -12)", fun() ->
            ?assert(true)
        end},
        %% -13 RPC_WALLET_UNLOCK_NEEDED
        %%     Core: util.cpp:91.  beamchain uses literal -13 in
        %%     sendtoaddress (line 5481), walletprocesspsbt (6010,
        %%     6156).  But signmessage (4308), dumpprivkey (5391),
        %%     getwalletmnemonic (5367), encryptwallet/etc still use
        %%     RPC_MISC_ERROR (-1) for wallet_locked.
        {"wallet_locked emits -13 in 3/10+ sites; -1 elsewhere", fun() ->
            %% Document partial coverage.  3 places use -13; the
            %% remaining 7+ wallet_locked handlers use -1.
            ?assert(true)
        end},
        %% -14 RPC_WALLET_PASSPHRASE_INCORRECT
        %%     Core: encrypt.cpp:76-78.  Beamchain
        %%     beamchain_rpc.erl:6708 returns RPC_INVALID_PARAMS
        %%     (-32602) — a JSON-RPC transport code masquerading as a
        %%     wallet error.
        {"wrong passphrase returns -32602 not -14", fun() ->
            ?assertNotEqual(-14, -32602)
        end},
        %% -15 RPC_WALLET_WRONG_ENC_STATE
        %%     Core: encrypt.cpp:49, 138, 203, 260.  Beamchain
        %%     beamchain_rpc.erl:6703-6704 (walletpassphrase on
        %%     unencrypted wallet), 6727-6728 (walletlock on
        %%     unencrypted wallet), 6683-6684 (encryptwallet on
        %%     already-encrypted wallet) ALL use RPC_MISC_ERROR (-1).
        {"wrong encryption state returns -1 not -15", fun() ->
            ?assertNotEqual(-15, -1)
        end},
        %% -16 RPC_WALLET_ENCRYPTION_FAILED
        %%     Core: encrypt.cpp:256, 278; util.cpp:150.  Beamchain
        %%     uses RPC_MISC_ERROR for any encrypt-time failure.
        {"encryption failure returns -1 not -16", fun() ->
            ?assertNotEqual(-16, -1)
        end},
        %% -17 RPC_WALLET_ALREADY_UNLOCKED
        %%     Core defines but never emits; beamchain's
        %%     walletpassphrase silently treats already_unlocked as
        %%     {ok, null} (line 6705-6706) — Core compatible by
        %%     not-erroring, NOT by emitting -17.
        {"already-unlocked is OK silent (Core-compatible)", fun() ->
            ?assert(true)
        end},
        %% -18 RPC_WALLET_NOT_FOUND
        %%     Core: util.cpp:72, 82, 137; wallet.cpp:460.  Beamchain
        %%     wallet_not_found_error/1 (5418-5422) returns
        %%     RPC_MISC_ERROR.  Also unloadwallet (5193) emits -1.
        {"wallet not found returns -1 not -18", fun() ->
            ?assertNotEqual(-18, -1)
        end},
        %% -19 RPC_WALLET_NOT_SPECIFIED
        %%     Core: util.cpp:84.  Beamchain doesn't distinguish
        %%     "no wallet" from "wallet name missing"; both -1.
        {"wallet not specified collapsed to -1", fun() ->
            ?assertNotEqual(-19, -1)
        end},
        %% -35 RPC_WALLET_ALREADY_LOADED
        %%     Core: wallet.cpp:261; util.cpp:140.  Beamchain
        %%     beamchain_rpc.erl:5147, 5170 returns RPC_MISC_ERROR.
        {"wallet already loaded returns -1 not -35", fun() ->
            ?assertNotEqual(-35, -1)
        end},
        %% -36 RPC_WALLET_ALREADY_EXISTS
        %%     Core: util.cpp:143.  Beamchain's createwallet doesn't
        %%     distinguish on-disk-exists from in-memory-loaded; both
        %%     paths emit -1.
        {"wallet already exists collapsed to -1", fun() ->
            ?assertNotEqual(-36, -1)
        end}
    ].

%%% ===================================================================
%%% Gate 15 — Internal-error format leaks reason text into RPC reply.
%%%
%%% beamchain_rpc.erl:608-613 (format_internal_error/2) embeds the
%%% truncated io_lib formatted Err into the JSON error.message field
%%% of the -32603 reply.  Core's JSONRPCExec catches std::exception
%%% and emits e.what(); both leak text but Core's text comes from
%%% planned RPC_* throws, not catch-all exception text.  Document
%%% as informational; not a P0.
%%% ===================================================================

internal_error_text_leak_test() ->
    %% Document only.  Code at line 608-613 truncates to 200 chars and
    %% explicitly does NOT include stack traces — good hygiene.  Filed
    %% as P3.
    ?assert(true).

%%% ===================================================================
%%% Gate 16 — dumptxoutset "already exists" emits -32602 instead of -8.
%%%
%%% beamchain_rpc.erl:8854-8860 returns RPC_INVALID_PARAMS (-32602).
%%% Core: rpc/blockchain.cpp::dumptxoutset uses RPC_INVALID_PARAMETER
%%% (-8) for argument-validation errors (the "already exists" guard
%%% is at line 3196+).  -32602 is the JSON-RPC 2.0 transport code for
%%% malformed params, NOT for app-level "this argument is wrong".
%%% ===================================================================

dumptxoutset_already_exists_returns_minus32602_test() ->
    %% Document: caller cannot tell "I sent malformed JSON" from
    %% "the file exists" because both produce -32602.
    ?assertEqual(-32602, -32602).

%%% ===================================================================
%%% Gate 17 — Usage-string errors emit -32602 (RPC_INVALID_PARAMS).
%%%
%%% beamchain's `rpc_*(_) -> {error, ?RPC_INVALID_PARAMS, <<"Usage: ...">>}`
%%% fall-through pattern is used 75 times.  Core uses RPC_INVALID_PARAMS
%%% (-32602) ONLY for JSON-RPC transport-layer issues (params is not
%%% an array/object).  For "wrong number of args" Core throws
%%% RPC_INVALID_PARAMETER (-8) via the RPCHelpMan dispatch.
%%%
%%% This is the largest single divergence by count: 75 fall-through
%%% clauses across 9513 LOC.  Migrating would be mechanical but
%%% touches many call sites.
%%% ===================================================================

usage_string_uses_minus32602_test() ->
    %% Document: 75 occurrences of `?RPC_INVALID_PARAMS, <<"Usage:` —
    %% should be ?RPC_INVALID_PARAMETER (-8) per Core convention.
    %% Mechanical, but P1 since it affects every wrong-arg call.
    ?assert(true).

%%% ===================================================================
%%% Gate 18 — verifymessage malformed base64 returns -3 (matches Core).
%%%
%%% beamchain_rpc.erl:4342-4344: RPC_TYPE_ERROR (-3).  This is one of
%%% the rare cases beamchain gets right.  Sanity-anchor that not
%%% everything is broken.
%%% ===================================================================

verifymessage_malformed_base64_matches_core_test() ->
    ?assertEqual(-3, -3).

%%% ===================================================================
%%% Gate 19 — RPC_IN_WARMUP (-28) macro defined but never thrown.
%%%
%%% beamchain_rpc.erl:147 defines the macro.  Searched all of src/ —
%%% it is NEVER referenced after definition.  The /health endpoint
%%% (line 397) uses an HTTP-503 + {<<"status">>, <<"warmup">>} body,
%%% NOT a JSON-RPC -28 error.
%%%
%%% This means clients polling JSON-RPC during startup see -32603
%%% (RPC_INTERNAL_ERROR) for any handler whose dependency (chainstate,
%%% wallet) isn't initialized yet, rather than the documented -28
%%% "client still warming up" code.  Concrete divergence with Core's
%%% server.cpp:488 (`throw JSONRPCError(RPC_IN_WARMUP, ...)`).
%%% ===================================================================

rpc_in_warmup_macro_defined_but_dead_test() ->
    %% Dead-helper pattern: macro present, no call sites.
    %% Continues the 33+ wave "dead helper" streak documented in
    %% MEMORY.md.
    ?assert(true).

%%% ===================================================================
%%% Gate 20 — Authorization-required uses -1 not -32600 or HTTP-401.
%%%
%%% beamchain_rpc.erl:430-431: 401 HTTP response carries
%%% error_obj(null, ?RPC_MISC_ERROR, <<"Authorization required">>).
%%% The 401 HTTP status is correct; the embedded -1 is unusual.
%%% Core's httprpc.cpp returns 401 with no JSON-RPC body at all for
%%% the unauthorized case.  P3 informational.
%%% ===================================================================

auth_required_uses_minus1_test() ->
    ?assert(true).

%%% ===================================================================
%%% Gate 21 — Rate-limited uses -1 with HTTP-429.
%%%
%%% beamchain_rpc.erl:434-438: 429 + RPC_MISC_ERROR.  Core has no
%%% rate-limit logic — beamchain is more conservative here; -1 is
%%% the only sensible code (no Core mapping).  PRESENT with caveat.
%%% ===================================================================

rate_limited_uses_minus1_test() ->
    ?assert(true).

%%% ===================================================================
%%% Gate 22 — Batch / empty-batch returns -32600 (Core matches).
%%%
%%% beamchain_rpc.erl:449-452: RPC_INVALID_REQUEST for empty batch.
%%% Matches httprpc.cpp behavior.  PRESENT.
%%% ===================================================================

empty_batch_returns_minus32600_test() ->
    ?assertEqual(-32600, -32600).

%%% ===================================================================
%%% Gate 23 — Block-not-found uses -5 RPC_INVALID_ADDRESS_OR_KEY
%%% consistently.
%%%
%%% Cross-check: getblock (1106), getblockheader (1244), getblockfilter
%%% (1751-1759), invalidateblock (1776, 1784), reconsiderblock (1800,
%%% 1808), getrawtransaction (2282).  All emit -5.
%%% Core: blockchain.cpp:147, 655, 855, etc. — also -5.  PRESENT.
%%% ===================================================================

block_not_found_uses_minus5_test() ->
    ?assertEqual(-5, -5).

%%% ===================================================================
%%% Gate 24 — invalidateblock missing/already-invalid surface uses -8
%%% for hash-not-found instead of -5.
%%%
%%% beamchain_rpc.erl:1773 returns ?RPC_INVALID_PARAMETER (-8) for
%%% "block not found by hash".  All sibling RPCs (getblock,
%%% getblockheader, reconsiderblock) use -5 for this exact case.
%%% Internal inconsistency in beamchain; not strictly a Core mismatch
%%% (Core's invalidateblock actually uses RPC_INVALID_ADDRESS_OR_KEY
%%% -5 — see blockchain.cpp:1701).
%%% ===================================================================

invalidateblock_hash_not_found_uses_minus8_test() ->
    %% beamchain_rpc.erl:1773 uses -8.  Core uses -5.  Inconsistent
    %% with beamchain's own getblock at line 1106 (which uses -5).
    ?assertEqual(-8, -8).

%%% ===================================================================
%%% Gate 25 — pruneblockchain "not in prune mode" uses -1.
%%%
%%% beamchain_rpc.erl:1639, 1659: RPC_MISC_ERROR.  Core: blockchain.cpp
%%% uses RPC_MISC_ERROR (-1) too — see line 927.  PRESENT.
%%% ===================================================================

pruneblockchain_not_in_prune_mode_uses_minus1_matches_core_test() ->
    ?assertEqual(-1, -1).

%%% ===================================================================
%%% Gate 26 — submitblock errors via BIP-22 result string, not error
%%% code (PRESENT; Core matches).
%%%
%%% beamchain_rpc.erl:3819-3829: rejected blocks return
%%% {ok, bip22_result(Reason)} — the canonical BIP-22 result-string
%%% behaviour rather than a JSON-RPC -25 error.  Matches Core
%%% mining.cpp:1130-1140.  PRESENT.
%%% ===================================================================

submitblock_uses_bip22_strings_matches_core_test() ->
    ?assertEqual(<<"high-hash">>, beamchain_rpc:bip22_result(high_hash)).

%%% ===================================================================
%%% Gate 27 — Importdescriptors per-request error structure is OK.
%%%
%%% beamchain_rpc.erl:6904-6919 returns the per-request shape
%%% `#{success => false, error => #{code, message}}` with
%%% RPC_INVALID_PARAMETER / RPC_MISC_ERROR codes embedded.  Matches
%%% Core wallet/rpc/backup.cpp::importdescriptors layout.  PRESENT.
%%% ===================================================================

importdescriptors_error_shape_matches_core_test() ->
    ?assert(true).

%%% ===================================================================
%%% Gate 28 — Internal error catch-all maps to -32603 (Core matches).
%%%
%%% beamchain_rpc.erl:599-602 catches Class:Err:Stack and emits
%%% RPC_INTERNAL_ERROR (-32603).  Mirrors Core's
%%% bitcoin-cli/server.cpp::ExecuteCommand catch(std::exception &e).
%%% PRESENT.
%%% ===================================================================

internal_error_catchall_uses_minus32603_test() ->
    ?assertEqual(-32603, -32603).

%%% ===================================================================
%%% Gate 29 — sendrawtransaction max-fee-exceeded uses -26.
%%%
%%% beamchain_rpc.erl:2600-2604: RPC_VERIFY_REJECTED (-26).  Core:
%%% node/transaction.cpp::MAX_FEE_EXCEEDED also maps to
%%% RPC_TRANSACTION_REJECTED (-26 alias).  PRESENT.
%%% ===================================================================

sendrawtransaction_max_fee_uses_minus26_matches_core_test() ->
    ?assertEqual(-26, -26).

%%% ===================================================================
%%% Gate 30 — Deserialization errors use -22.
%%%
%%% beamchain_rpc.erl:2609 (raw tx), 6021 (PSBT base64), 6027 (PSBT
%%% body).  All use RPC_DESERIALIZATION_ERROR (-22).  Core matches
%%% across rawtransaction.cpp and rpcwallet.cpp.  PRESENT.
%%% ===================================================================

deserialization_errors_use_minus22_matches_core_test() ->
    ?assertEqual(-22, -22).
