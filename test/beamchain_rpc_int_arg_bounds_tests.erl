-module(beamchain_rpc_int_arg_bounds_tests).

%%% -------------------------------------------------------------------
%%% RPC integer arguments must be read at CORE'S WIDTH -- and honoured.
%%%
%%% Core reads every numeric argument through UniValue::getInt<T>()
%%% (univalue.h), which runs std::from_chars INTO THE DESTINATION WIDTH.
%%% The width check therefore lives INSIDE the conversion and fires
%%% BEFORE the handler's own domain test:
%%%
%%%   out of width / fractional -> "JSON integer out of range", -1
%%%   converts, violates range  -> RPC_INVALID_PARAMETER, -8
%%%
%%% Erlang integers are arbitrary-precision, so nothing wraps and nothing
%%% crashes -- the handler simply ACTS on a value Core refuses.  Measured
%%% against a regtest Core oracle (tools/rpc-arg-differential.py),
%%% beamchain ACCEPTED 18 such arguments.
%%%
%%% Four of them were not merely unbounded but FABRICATIONS -- an
%%% argument read and then not honoured:
%%%
%%%   * estimatesmartfee answered for ANY conf_target, and ignored
%%%     estimate_mode entirely.
%%%   * createpsbt took locktime raw where createrawtransaction bounded
%%%     it, though Core builds BOTH from one ConstructTransaction.
%%%   * walletcreatefundedpsbt had the same gap on the same argument.
%%%   * prioritisetransaction accepted a TWO-argument form and mutated
%%%     the mempool; Core requires fee_delta at positional 2 and rejects.
%%%
%%% These assert the CORRECT behaviour and fail at the parent commit.
%%% -------------------------------------------------------------------

-include_lib("eunit/include/eunit.hrl").

-define(TXID, <<"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">>).
-define(OUT_OF_INT32, [2147483648, -2147483649, 4294967296, -4294967297]).
-define(RANGE_ERR, {error, -1, <<"JSON integer out of range">>}).

rpc(M, Params) ->
    beamchain_rpc:handle_method(M, Params, undefined).

%%% --- wait family: getInt<int> ---------------------------------------

waitforblockheight_height_out_of_int32_test() ->
    [?assertEqual(?RANGE_ERR, rpc(<<"waitforblockheight">>, [V]))
     || V <- ?OUT_OF_INT32].

waitforblockheight_timeout_out_of_int32_test() ->
    [?assertEqual(?RANGE_ERR, rpc(<<"waitforblockheight">>, [1, V]))
     || V <- ?OUT_OF_INT32].

%% CONTROL: an in-range negative timeout still reaches Core's own domain
%% message, which is what proves the width check runs FIRST rather than
%% replacing the handler's test.
waitforblockheight_negative_timeout_keeps_core_message_test() ->
    ?assertEqual({error, -1, <<"Negative timeout">>},
                 rpc(<<"waitforblockheight">>, [1, -1])).

%%% --- getnodeaddresses: getInt<int>, then -8 -------------------------

getnodeaddresses_count_out_of_int32_test() ->
    [?assertEqual(?RANGE_ERR, rpc(<<"getnodeaddresses">>, [V]))
     || V <- ?OUT_OF_INT32].

%% CONTROL: in-range negative converts fine and reaches the -8 test.
getnodeaddresses_negative_count_is_domain_error_test() ->
    ?assertEqual({error, -8, <<"Address count out of range">>},
                 rpc(<<"getnodeaddresses">>, [-1])).

%%% --- gettxout: n is getInt<uint32_t> --------------------------------

gettxout_vout_out_of_uint32_test() ->
    [?assertEqual(?RANGE_ERR, rpc(<<"gettxout">>, [?TXID, V]))
     || V <- [4294967296, -1, -2147483649]].

%%% --- estimatesmartfee: ParseConfirmTarget ---------------------------

estimatesmartfee_conf_target_out_of_int32_test() ->
    [?assertEqual(?RANGE_ERR, rpc(<<"estimatesmartfee">>, [V]))
     || V <- ?OUT_OF_INT32].

estimatesmartfee_conf_target_above_max_is_rejected_not_clamped_test() ->
    ?assertEqual({error, -8, <<"Invalid conf_target, must be between 1 and 1008">>},
                 rpc(<<"estimatesmartfee">>, [99999])).

estimatesmartfee_conf_target_below_one_is_rejected_test() ->
    ?assertEqual({error, -8, <<"Invalid conf_target, must be between 1 and 1008">>},
                 rpc(<<"estimatesmartfee">>, [0])).

estimatesmartfee_unknown_estimate_mode_is_rejected_test() ->
    Expect = {error, -8,
              <<"Invalid estimate_mode parameter, must be one of: "
                "\"unset\", \"economical\", \"conservative\"">>},
    [?assertEqual(Expect, rpc(<<"estimatesmartfee">>, [6, M]))
     || M <- [<<>>, <<"garbage">>, <<"ECONOMICALLY">>]].

%% CONTROL: a valid conf_target -- with each accepted fee mode, in any case --
%% gets PAST argument validation and reaches the estimator.  eunit runs without
%% the estimator gen_server, so "reached it" surfaces as a noproc exit from
%% gen_server:call, and that is precisely the proof wanted here: the handler
%% did NOT answer with an argument error.  Without these controls, a handler
%% that rejected every call would satisfy every assertion above.
reaches_estimator(Params) ->
    case (catch rpc(<<"estimatesmartfee">>, Params)) of
        {ok, _} -> ok;
        {'EXIT', {noproc, {gen_server, call, [beamchain_fee_estimator | _]}}} -> ok;
        Other -> erlang:error({valid_call_rejected_by_argument_validation, Other})
    end.

estimatesmartfee_valid_modes_accepted_test() ->
    [reaches_estimator([6, M])
     || M <- [<<"unset">>, <<"economical">>, <<"CONSERVATIVE">>, <<"Economical">>]].

estimatesmartfee_plain_target_still_answers_test() ->
    reaches_estimator([6]).

%%% --- createpsbt locktime: the SAME argument as createrawtransaction --

createpsbt_locktime_out_of_range_is_rejected_test() ->
    In = [#{<<"txid">> => ?TXID, <<"vout">> => 0}],
    %% outputs as a LIST: beamchain's createpsbt clause only matches a JSON
    %% array here (createrawtransaction accepts both shapes -- a separate
    %% drift, recorded not fixed).
    [?assertEqual({error, -8, <<"Invalid parameter, locktime out of range">>},
                  rpc(<<"createpsbt">>, [In, [], V]))
     || V <- [4294967296, -1]].

%%% --- prioritisetransaction arity ------------------------------------

prioritisetransaction_two_arg_form_is_rejected_test() ->
    ?assertMatch({error, _, _}, rpc(<<"prioritisetransaction">>, [?TXID, 1000])),
    %% and specifically NOT a success
    ?assertNotMatch({ok, _}, rpc(<<"prioritisetransaction">>, [?TXID, 1000])).
