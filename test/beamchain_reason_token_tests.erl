-module(beamchain_reason_token_tests).

%%% -------------------------------------------------------------------
%%% Reject-reason token parity for testmempoolaccept / sendrawtransaction.
%%%
%%% Asserts the reject-reason STRING beamchain emits for each mempool
%%% rejection class matches Bitcoin Core's canonical token.  Decisions are
%%% out of scope here (unchanged by the fix); this module pins the strings.
%%%
%%% Two surfaces:
%%%   sendrawtransaction  -> beamchain_rpc:format_mempool_error/2 (the
%%%                          {error, Code, Msg} the RPC throws).
%%%   testmempoolaccept   -> beamchain_rpc:mempool_reject_reason/2 (the
%%%                          "reject-reason" field; Core rpc/mempool.cpp
%%%                          remaps ONLY TX_MISSING_INPUTS -> "missing-inputs").
%%%
%%% Core references:
%%%   consensus/tx_check.cpp   CheckTransaction family tokens
%%%   policy/policy.cpp        IsStandardTx standardness tokens
%%%   validation.cpp:814       "tx-size-small" (<65B nonwitness, CVE-2017-12842)
%%%   validation.cpp CheckFeeRate  "mempool min fee not met" (rolling) vs
%%%                                "min relay fee not met" (static floor)
%%%   rpc/mempool.cpp:399-401  TX_MISSING_INPUTS -> "missing-inputs"
%%% -------------------------------------------------------------------

-include_lib("eunit/include/eunit.hrl").

-define(TXID, <<0:256>>).

%% sendrawtransaction surface: strip the {error, Code, Msg} envelope.
frm(Reason) ->
    {error, _Code, Msg} = beamchain_rpc:format_mempool_error(Reason, ?TXID),
    Msg.

%% testmempoolaccept surface: reject-reason field.
mrr(Reason) ->
    beamchain_rpc:mempool_reject_reason(Reason, ?TXID).

%%% --- CheckTransaction family (consensus/tx_check.cpp) ---------------
%%% sendrawtransaction throws these wrapped as {validation, Atom}; the
%%% dry-run (testmempoolaccept) catch unwraps to the bare Atom.  Both must
%%% surface the same Core token.

check_transaction_family_test_() ->
    Cases = [
        {no_inputs,             <<"bad-txns-vin-empty">>},
        {no_outputs,            <<"bad-txns-vout-empty">>},
        {negative_output,       <<"bad-txns-vout-negative">>},
        {output_too_large,      <<"bad-txns-vout-toolarge">>},
        {total_output_overflow, <<"bad-txns-txouttotal-toolarge">>},
        {duplicate_inputs,      <<"bad-txns-inputs-duplicate">>},
        {null_input,            <<"bad-txns-prevout-null">>},
        {bad_coinbase_length,   <<"bad-cb-length">>}
    ],
    lists:map(fun({Atom, Token}) ->
        [
         %% sendrawtransaction: wrapped {validation, Atom}
         ?_assertEqual(Token, frm({validation, Atom})),
         %% testmempoolaccept dry-run: bare Atom
         ?_assertEqual(Token, mrr(Atom))
        ]
    end, Cases).

%% tx_underweight has no Core CheckTransaction counterpart -> falls back to
%% the raw atom rather than an invented token (regression guard so a future
%% edit does not silently coin a fake Core token for it).
tx_underweight_falls_back_test() ->
    ?assertEqual(<<"tx_underweight">>, frm({validation, tx_underweight})).

%%% --- Standardness tokens (policy/policy.cpp IsStandardTx) -----------

standardness_tokens_test_() ->
    Cases = [
        {version,                <<"version">>},
        {tx_size,                <<"tx-size">>},
        {tx_size_small,          <<"tx-size-small">>},
        {scriptsig_size,         <<"scriptsig-size">>},
        {scriptsig_not_pushonly, <<"scriptsig-not-pushonly">>},
        {scriptpubkey,           <<"scriptpubkey">>},
        %% datacarrier IS the current Core reason (policy.cpp datacarrier_bytes_left
        %% model) — NOT remapped to the obsolete "multi-op-return".
        {datacarrier,            <<"datacarrier">>}
    ],
    [ ?_assertEqual(Token, frm(Atom)) || {Atom, Token} <- Cases ].

%%% --- min-relay split (validation.cpp CheckFeeRate) ------------------

min_relay_split_test_() ->
    [
     ?_assertEqual(<<"mempool min fee not met">>,
                   frm('mempool min fee not met')),
     ?_assertEqual(<<"min relay fee not met">>,
                   frm('min relay fee not met'))
    ].

%%% --- missing-inputs remap (rpc/mempool.cpp) ------------------------
%%% testmempoolaccept surface -> "missing-inputs"; sendrawtransaction keeps
%%% its own "Missing inputs" prose (only the reject-reason field is remapped).

missing_inputs_remap_test_() ->
    [
     ?_assertEqual(<<"missing-inputs">>, mrr(orphan)),
     ?_assertEqual(<<"missing-inputs">>, mrr('bad-txns-inputs-missingorspent')),
     ?_assertEqual(<<"missing-inputs">>, mrr(missing_inputs)),
     %% sendrawtransaction prose is intentionally left as-is.
     ?_assertEqual(<<"Missing inputs">>, frm(orphan)),
     ?_assertEqual(<<"Missing inputs">>, frm('bad-txns-inputs-missingorspent'))
    ].

%%% --- already-correct tokens preserved (regression guards) ----------

preserved_tokens_test_() ->
    Cases = [
        {'bad-txns-in-belowout',            <<"bad-txns-in-belowout">>},
        {'bad-txns-fee-outofrange',         <<"bad-txns-fee-outofrange">>},
        {{'bad-txns-too-many-sigops', 9999},<<"bad-txns-too-many-sigops">>},
        {'too-long-mempool-chain',          <<"too-long-mempool-chain">>},
        {'bad-txns-coinbase',               <<"coinbase">>},
        {rbf_spends_conflicting_tx,         <<"bad-txns-spends-conflicting-tx">>}
    ],
    [ ?_assertEqual(Token, frm(Atom)) || {Atom, Token} <- Cases ].
