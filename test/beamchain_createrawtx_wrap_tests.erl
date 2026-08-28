-module(beamchain_createrawtx_wrap_tests).

%%% -------------------------------------------------------------------
%%% createrawtransaction: numeric arguments must be RANGE-CHECKED, not
%%% silently truncated into the 32-bit serializer.
%%%
%%% Found 2026-08-28 by the fleet sweep that began with clearbit's
%%% unchecked-cast node-kill on this same RPC.  beamchain neither crashed
%%% nor errored -- it answered SUCCESS, having truncated the value.
%%% beamchain_serialize encodes index/sequence/locktime with
%%% <<X:32/little>>, and Erlang's bit syntax TRUNCATES silently rather
%%% than failing, so:
%%%
%%%   vout     -1           -> 16#FFFFFFFF  the reserved null/coinbase
%%%                                         outpoint index
%%%                                         (Core COutPoint::SetNull)
%%%   sequence 16#100000000 -> 0            CLEARS the BIP-68 disable bit
%%%                                         AND signals BIP-125 RBF
%%%   locktime -1           -> 16#FFFFFFFF  the maximum locktime
%%%
%%% Each wrapped value carries the OPPOSITE consensus meaning to the one
%%% the caller asked for, and there was no error and no log line to say
%%% so.  Core rejects all three
%%% (bitcoin-core/src/rpc/rawtransaction_util.cpp AddInputs:38-65 and
%%% ConstructTransaction:151-155).
%%%
%%% Observed on the LIVE mainnet node before the fix:
%%%   createrawtransaction [{"txid":"aa..aa","vout":-1}] {}
%%%     -> 0200000001aa..aa ffffffff 00 fdffffff 0000000000
%%%                        ^^^^^^^^ the null-outpoint sentinel
%%%
%%% Unlike the W125 audit module, these are NOT audit-flip tests: they
%%% assert the CORRECT (Core-parity) behaviour and fail at the parent
%%% commit.
%%% -------------------------------------------------------------------

-include_lib("eunit/include/eunit.hrl").

-define(TXID, <<"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">>).

rpc(Params) ->
    beamchain_rpc:handle_method(<<"createrawtransaction">>, Params, undefined).

input(Fields) ->
    [maps:from_list(Fields)].

%%% --- the three wraps ------------------------------------------------

vout_negative_is_rejected_test() ->
    ?assertEqual({error, -8, <<"Invalid parameter, vout cannot be negative">>},
                 rpc([input([{<<"txid">>, ?TXID}, {<<"vout">>, -1}]), #{}])).

sequence_above_max_is_rejected_test() ->
    ?assertEqual({error, -8, <<"Invalid parameter, sequence number is out of range">>},
                 rpc([input([{<<"txid">>, ?TXID}, {<<"vout">>, 0},
                             {<<"sequence">>, 16#100000000}]), #{}])).

locktime_negative_is_rejected_test() ->
    ?assertEqual({error, -8, <<"Invalid parameter, locktime out of range">>},
                 rpc([input([{<<"txid">>, ?TXID}, {<<"vout">>, 0}]), #{}, -1])).

%%% --- the same shape, other directions -------------------------------

sequence_negative_is_rejected_test() ->
    ?assertEqual({error, -8, <<"Invalid parameter, sequence number is out of range">>},
                 rpc([input([{<<"txid">>, ?TXID}, {<<"vout">>, 0},
                             {<<"sequence">>, -1}]), #{}])).

locktime_above_max_is_rejected_test() ->
    ?assertEqual({error, -8, <<"Invalid parameter, locktime out of range">>},
                 rpc([input([{<<"txid">>, ?TXID}, {<<"vout">>, 0}]),
                      #{}, 16#100000000])).

%%% Core's ordering is univalue's, not the obvious one: getInt<int>()
%%% runs BEFORE the sign test, so a vout outside int32 is "JSON integer
%%% out of range" at RPC_MISC_ERROR (-1), even though it is also
%%% out-of-domain for a vout.
vout_beyond_int32_is_range_error_not_negative_error_test() ->
    ?assertEqual({error, -1, <<"JSON integer out of range">>},
                 rpc([input([{<<"txid">>, ?TXID}, {<<"vout">>, 2147483648}]), #{}])).

%%% --- raw Erlang terms must not leak as error messages ----------------
%%%
%%% Before the fix these fell through to the catch-all and surfaced as
%%% RPC_MISC_ERROR with "Error: function_clause" / "Error: badarg" --
%%% an internal term shipped to an RPC client as if it were a message.

missing_vout_reports_core_message_not_function_clause_test() ->
    ?assertEqual({error, -8, <<"Invalid parameter, missing vout key">>},
                 rpc([input([{<<"txid">>, ?TXID}]), #{}])).

malformed_txid_reports_core_message_not_badarg_test() ->
    ?assertEqual({error, -8, <<"txid must be of length 64 (not 3, for 'abc')">>},
                 rpc([input([{<<"txid">>, <<"abc">>}, {<<"vout">>, 0}]), #{}])).

right_length_non_hex_txid_reports_hex_message_test() ->
    Bad = binary:copy(<<"z">>, 64),
    ?assertEqual({error, -8,
                  iolist_to_binary([<<"txid must be hexadecimal string (not '">>,
                                    Bad, <<"')">>])},
                 rpc([input([{<<"txid">>, Bad}, {<<"vout">>, 0}]), #{}])).

%%% --- controls --------------------------------------------------------
%%%
%%% Without these, every assertion above is satisfiable by a handler that
%%% rejects everything.

valid_input_still_builds_the_transaction_test() ->
    {ok, Hex} = rpc([input([{<<"txid">>, ?TXID}, {<<"vout">>, 0}]), #{}]),
    %% version 2, one input, the outpoint present, vout 0, default RBF
    %% sequence fdffffff, no outputs, locktime 0.
    ?assertEqual(<<"0200000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                   "aaaaaaaaaaaaaaaaaaaa0000000000fdffffff0000000000">>, Hex).

boundary_values_are_accepted_test() ->
    %% vout = int32 max and sequence = SEQUENCE_FINAL are both legal;
    %% an over-tight check would reject them.
    ?assertMatch({ok, _}, rpc([input([{<<"txid">>, ?TXID}, {<<"vout">>, 2147483647},
                                      {<<"sequence">>, 16#FFFFFFFF}]), #{}])),
    ?assertMatch({ok, _}, rpc([input([{<<"txid">>, ?TXID}, {<<"vout">>, 0},
                                      {<<"sequence">>, 0}]), #{}, 16#FFFFFFFF])).

%%% Core only range-checks `sequence` when it IS a number
%%% (rawtransaction_util.cpp: `if (sequenceObj.isNum())`); a non-numeric
%%% one is ignored and the default applies.  Pinned so a later
%%% tightening pass cannot diverge from Core by accident.
non_numeric_sequence_is_ignored_matching_core_isnum_guard_test() ->
    ?assertMatch({ok, _}, rpc([input([{<<"txid">>, ?TXID}, {<<"vout">>, 0},
                                      {<<"sequence">>, <<"nope">>}]), #{}])).

%%% -------------------------------------------------------------------
%%% createrawtransaction: `replaceable=true` together with an input set
%%% that signals NO opt-in RBF is a CONTRADICTION, and Core refuses to
%%% guess which half the caller meant.
%%%
%%%   bitcoin-core/src/rpc/rawtransaction_util.cpp ConstructTransaction,
%%%   the last statement before the tx is returned -- after AddInputs AND
%%%   AddOutputs:
%%%     if (rbf.has_value() && rbf.value() && rawTx.vin.size() > 0 &&
%%%         !SignalsOptInRBF(CTransaction(rawTx)))
%%%         throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter
%%%             combination: Sequence number(s) contradict replaceable option");
%%%
%%%   bitcoin-core/src/util/rbf.cpp SignalsOptInRBF: true when ANY input
%%%   has nSequence =< MAX_BIP125_RBF_SEQUENCE (util/rbf.h, 0xfffffffd).
%%%
%%% Nine of the ten nodes in this repo silently ACCEPT the contradiction:
%%% they resolve it in favour of the sequence and hand back a transaction
%%% that CANNOT be fee-bumped, with no error and no log line, so the
%%% caller only discovers it when the later bump fails.
%%%
%%% The ABSENT-vs-EXPLICIT asymmetry below is real and deliberate in
%%% Core, not a rounding of the rule: `std::optional<bool> rbf` stays
%%% nullopt when params[3].isNull() (rawtransaction.cpp:398-401);
%%% AddInputs reads it as rbf.value_or(true), so an absent arg still
%%% CHOOSES the RBF sequence, while the check above is gated on
%%% rbf.has_value(), so an absent arg can never CONTRADICT.  jsx decodes
%%% JSON null to the atom `null`, and Core's isNull() covers both the
%%% omitted arg and an explicit null -- so both are "absent" here.
%%%
%%% Every row below was checked against a LIVE Bitcoin Core node.  The
%%% ACCEPT rows are not filler: they are what stops an over-eager check
%%% from breaking ordinary RBF usage, and rows 1 and 6 are exactly the
%%% two an approximate implementation gets wrong.
%%% -------------------------------------------------------------------

%% Pinned serialization of a one-input, zero-output, locktime-0 tx, in
%% the shape already pinned by valid_input_still_builds_the_transaction:
%% version 2 | 1 input | ?TXID outpoint at vout 0 | empty scriptSig |
%% the given little-endian sequence | 0 outputs | locktime 0.
one_input_hex(SeqLittleEndianHex) ->
    iolist_to_binary([<<"0200000001">>, ?TXID, <<"0000000000">>,
                      SeqLittleEndianHex, <<"0000000000">>]).

%%% Row 1 -- rbf ABSENT, sequence 0xFFFFFFFF -> ACCEPT.
%%% Rule 1 fails: no EXPLICIT replaceable, so there is nothing to
%%% contradict, even though the absent arg would itself have defaulted to
%%% the RBF sequence.  This is the row an implementation that collapses
%%% "absent" into "true" breaks; boundary_values_are_accepted_test above
%%% asserts the same case and must keep passing.
rbf_absent_with_final_sequence_is_accepted_test() ->
    ?assertEqual({ok, one_input_hex(<<"ffffffff">>)},
                 rpc([input([{<<"txid">>, ?TXID}, {<<"vout">>, 0},
                             {<<"sequence">>, 16#FFFFFFFF}]), #{}])).

%%% Row 2 -- rbf true, sequence 0xFFFFFFFD -> ACCEPT.
%%% MAX_BIP125_RBF_SEQUENCE itself signals (the test is `=<`, not `<`).
rbf_true_with_max_bip125_sequence_is_accepted_test() ->
    ?assertEqual({ok, one_input_hex(<<"fdffffff">>)},
                 rpc([input([{<<"txid">>, ?TXID}, {<<"vout">>, 0},
                             {<<"sequence">>, 16#FFFFFFFD}]), #{}, 0, true])).

%%% Row 3 -- rbf true, sequence 0xFFFFFFFE -> REJECT.
%%% MAX_SEQUENCE_NONFINAL is one above the BIP-125 threshold: it still
%%% enables nLockTime but opts OUT of replacement.
rbf_true_with_nonfinal_sequence_is_rejected_test() ->
    ?assertEqual({error, -8, <<"Invalid parameter combination: Sequence "
                               "number(s) contradict replaceable option">>},
                 rpc([input([{<<"txid">>, ?TXID}, {<<"vout">>, 0},
                             {<<"sequence">>, 16#FFFFFFFE}]), #{}, 0, true])).

%%% Row 4 -- rbf true, sequence 0xFFFFFFFF (SEQUENCE_FINAL) -> REJECT.
rbf_true_with_final_sequence_is_rejected_test() ->
    ?assertEqual({error, -8, <<"Invalid parameter combination: Sequence "
                               "number(s) contradict replaceable option">>},
                 rpc([input([{<<"txid">>, ?TXID}, {<<"vout">>, 0},
                             {<<"sequence">>, 16#FFFFFFFF}]), #{}, 0, true])).

%%% Row 5 -- rbf true, NO inputs -> ACCEPT.
%%% Rule 2 fails: `rawTx.vin.size() > 0`.  An empty vin makes
%%% SignalsOptInRBF false vacuously, so without the size guard this would
%%% reject the (legal) empty-input skeleton that PSBT/funding flows build.
rbf_true_with_no_inputs_is_accepted_test() ->
    %% version 2 | 0 inputs | 0 outputs | locktime 0.
    ?assertEqual({ok, <<"02000000000000000000">>},
                 rpc([[], #{}, 0, true])).

%%% Row 6 -- rbf true, two inputs, only ONE of which signals -> ACCEPT.
%%% Rule 3 fails: SignalsOptInRBF is ANY, not ALL.  BIP-125 makes this
%%% deliberate for multi-party protocols -- no single co-signer may opt
%%% the whole transaction out of replacement via their own input.  An
%%% implementation that tests every input rejects this valid request.
rbf_true_with_one_signalling_input_of_two_is_accepted_test() ->
    {ok, Hex} = rpc([input([{<<"txid">>, ?TXID}, {<<"vout">>, 0},
                            {<<"sequence">>, 16#FFFFFFFF}]) ++
                     input([{<<"txid">>, ?TXID}, {<<"vout">>, 1},
                            {<<"sequence">>, 0}]),
                     #{}, 0, true]),
    ?assertEqual(iolist_to_binary([<<"0200000002">>,
                                   ?TXID, <<"0000000000ffffffff">>,
                                   ?TXID, <<"010000000000000000">>,
                                   <<"0000000000">>]),
                 Hex).

%%% Row 7 -- rbf false, sequence 0xFFFFFFFF -> ACCEPT.
%%% Rule 1 again: the guard is has_value() AND value(), so an explicit
%%% false is as harmless as an absent arg.
rbf_false_with_final_sequence_is_accepted_test() ->
    ?assertEqual({ok, one_input_hex(<<"ffffffff">>)},
                 rpc([input([{<<"txid">>, ?TXID}, {<<"vout">>, 0},
                             {<<"sequence">>, 16#FFFFFFFF}]), #{}, 0, false])).

%%% Row 8 -- rbf true, input with NO explicit sequence -> ACCEPT.
%%% The default AddInputs picks for replaceable=true IS the signalling
%%% sequence 0xFFFFFFFD, so the ordinary RBF call can never trip the
%%% check.  If this row fails, the check is running before the default is
%%% applied.
rbf_true_with_default_sequence_is_accepted_test() ->
    ?assertEqual({ok, one_input_hex(<<"fdffffff">>)},
                 rpc([input([{<<"txid">>, ?TXID}, {<<"vout">>, 0}]),
                      #{}, 0, true])).

%%% Not in the oracle table, but the rule names it: jsx decodes JSON null
%%% to the atom `null`, and Core's params[3].isNull() is true for both an
%%% omitted arg and an explicit null -- so an explicit null must behave
%%% like row 1, not like row 4.
rbf_explicit_json_null_counts_as_absent_test() ->
    ?assertEqual({ok, one_input_hex(<<"ffffffff">>)},
                 rpc([input([{<<"txid">>, ?TXID}, {<<"vout">>, 0},
                             {<<"sequence">>, 16#FFFFFFFF}]), #{}, 0, null])).
