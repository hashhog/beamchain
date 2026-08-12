-module(beamchain_bip22_result_tests).

%%% -------------------------------------------------------------------
%%% BIP-22 reject-reason token parity for submitblock.
%%%
%%% Asserts the reason STRING beamchain returns from rpc_submitblock (via
%%% beamchain_rpc:bip22_result/1) for each block/tx rejection class matches
%%% Bitcoin Core's canonical BIP-22 token.  Decisions are unchanged (every
%%% one of these still REJECTS); this module pins the strings that the
%%% version-dup diff-test corpus compares against a live bitcoind.
%%%
%%% Core references:
%%%   validation.cpp:4116   ContextualCheckBlockHeader
%%%                         strprintf("bad-version(0x%08x)", nVersion)
%%%   validation.cpp:866    ConnectBlock TX_MISSING_INPUTS
%%%                         "bad-txns-inputs-missingorspent"
%%%   validation.cpp:2471   ConnectBlock BIP30 "bad-txns-BIP30"
%%%   consensus/tx_check.cpp:15  "bad-txns-vout-empty"
%%%   consensus/tx_check.cpp:13  "bad-txns-vin-empty"
%%%   consensus/tx_check.cpp:44  "bad-txns-inputs-duplicate"
%%%   validation.cpp:4157   ContextualCheckBlock BIP34 "bad-cb-height"
%%%
%%% bip22_result/1 is exported for test via the -ifdef(TEST) export in
%%% beamchain_rpc.erl (rebar3 compiles test profile with TEST defined).
%%% -------------------------------------------------------------------

-include_lib("eunit/include/eunit.hrl").

r(Reason) -> beamchain_rpc:bip22_result(Reason).

%%% --- block-version height gate (bad-version(0x%08x)) ----------------
%%% The reason atom carries the block's signed int32 nVersion; the string
%%% reinterprets it UNSIGNED, zero-padded to 8 lowercase hex digits.

bad_version_format_test_() ->
    [
     ?_assertEqual(<<"bad-version(0x00000001)">>, r({bad_version, 1})),
     ?_assertEqual(<<"bad-version(0x00000002)">>, r({bad_version, 2})),
     ?_assertEqual(<<"bad-version(0x00000003)">>, r({bad_version, 3})),
     %% high-bit set: 0x80000000 decodes little-signed to -2147483648.
     ?_assertEqual(<<"bad-version(0x80000000)">>,
                   r({bad_version, -2147483648})),
     %% nVersion = -1 (0xffffffff): the signed/unsigned differential case.
     ?_assertEqual(<<"bad-version(0xffffffff)">>, r({bad_version, -1}))
    ].

%%% --- CheckTransaction family (wrapped {bad_tx, Atom}) ---------------
%%% These fire at CheckTransaction BEFORE script verification, so they must
%%% NOT fall through to {bad_tx, _} -> block-script-verify-flag-failed.

check_transaction_family_test_() ->
    [
     %% coinbase-empty-vout AND empty-vout both surface as {bad_tx, no_outputs}.
     ?_assertEqual(<<"bad-txns-vout-empty">>, r({bad_tx, no_outputs})),
     ?_assertEqual(<<"bad-txns-vin-empty">>, r({bad_tx, no_inputs})),
     %% dup-inputs-within-tx.
     ?_assertEqual(<<"bad-txns-inputs-duplicate">>,
                   r({bad_tx, duplicate_inputs})),
     %% bare atom pinned to the same canonical token (not bad-txns-duplicate).
     ?_assertEqual(<<"bad-txns-inputs-duplicate">>, r(duplicate_inputs))
    ].

%%% --- double-spend across two txs -----------------------------------

double_spend_test() ->
    ?assertEqual(<<"bad-txns-inputs-missingorspent">>, r(missing_inputs)).

%%% --- already-correct tokens preserved (regression guards) ----------

preserved_tokens_test_() ->
    [
     ?_assertEqual(<<"bad-txns-BIP30">>,  r(bad_txns_bip30)),
     ?_assertEqual(<<"bad-cb-height">>,   r(bad_cb_height)),
     ?_assertEqual(<<"bad-txns-in-belowout">>, r(insufficient_input)),
     %% dup_txid (duplicate non-coinbase txid) still maps to missingorspent.
     ?_assertEqual(<<"bad-txns-inputs-missingorspent">>, r(dup_txid)),
     %% genuine script-verify failures still map to the flag-failed token.
     ?_assertEqual(<<"block-script-verify-flag-failed">>,
                   r({script_verify_failed, 0})),
     %% unknown reason still falls back to the generic BIP-22 "rejected".
     ?_assertEqual(<<"rejected">>, r(some_unknown_reason))
    ].
