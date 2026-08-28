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
