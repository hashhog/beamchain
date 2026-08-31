%% #103 -- Core's central argument-count gate.
%%
%% Core validates argument COUNT in one place, after the method lookup and
%% before any handler runs (rpc/util.cpp:644 -> IsValidNumArgs, :733):
%%
%%     Required =< N =< Declared
%%
%% A violation throws the help text, which surfaces as error -1. beamchain
%% dispatched straight into handle_method/3, so surplus positional arguments
%% were silently dropped.
%%
%% Verified read-only against the live Core oracle on 2026-08-31:
%%   getblockhash []            -> code=-1  "getblockhash height"
%%   getblockcount ["surplus"]  -> code=-1  "getblockcount"
%%   getblockhash [1]           -> OK (control)
%%
%% Live evidence that beamchain had the gap, same day:
%%   savemempool ["ARITY-WRITER-PROBE-beamchain"] -> {"result":true}
-module(beamchain_core_arity_tests).
-include_lib("eunit/include/eunit.hrl").

%% ---------------------------------------------------------------------------
%% Guard: everything below is vacuous if the compiled-in table is empty.
%% ---------------------------------------------------------------------------
table_is_populated_test() ->
    T = beamchain_core_arity:table(),
    ?assert(maps:size(T) >= 80),
    ?assertEqual({ok, {0, 0}}, beamchain_core_arity:lookup(<<"savemempool">>)),
    ?assertEqual({ok, {0, 0}}, beamchain_core_arity:lookup(<<"clearbanned">>)),
    ?assertEqual({ok, {2, 3}}, beamchain_core_arity:lookup(<<"gettxout">>)),
    ?assertEqual({ok, {1, 3}}, beamchain_core_arity:lookup(<<"sendrawtransaction">>)).

unlisted_method_lookup_is_error_test() ->
    %% Coverage is 87 of 103. Callers MUST fail open on `error'.
    ?assertEqual(error, beamchain_core_arity:lookup(<<"definitely-not-an-rpc">>)).

%% ---------------------------------------------------------------------------
%% The method list the gate consults must actually contain methods.
%% ---------------------------------------------------------------------------
method_names_are_bare_names_test() ->
    Names = beamchain_rpc:beamchain_method_names(),
    ?assert(length(Names) >= 50),
    %% Signatures must be stripped down to the bare name...
    ?assert(lists:member(<<"getblockcount">>, Names)),
    ?assert(lists:member(<<"getblockhash">>, Names)),
    ?assert(lists:member(<<"savemempool">>, Names)),
    %% ...and section headers must not leak in as if they were methods.
    ?assertNot(lists:any(fun(N) ->
                             binary:match(N, <<"==">>) =/= nomatch
                         end, Names)),
    ?assertNot(lists:member(<<>>, Names)).

%% ---------------------------------------------------------------------------
%% Violations
%% ---------------------------------------------------------------------------
surplus_argument_is_a_violation_test() ->
    ?assert(beamchain_rpc:core_arity_violation(<<"savemempool">>, [<<"x">>])),
    ?assert(beamchain_rpc:core_arity_violation(<<"clearbanned">>, [<<"x">>])),
    ?assert(beamchain_rpc:core_arity_violation(<<"getblockcount">>, [<<"x">>])).

missing_required_argument_is_a_violation_test() ->
    ?assert(beamchain_rpc:core_arity_violation(<<"getblockhash">>, [])),
    ?assert(beamchain_rpc:core_arity_violation(<<"gettxout">>, [<<"ab">>])).

too_many_optional_arguments_is_a_violation_test() ->
    ?assert(beamchain_rpc:core_arity_violation(
              <<"gettxout">>, [<<"ab">>, 0, true, <<"extra">>])).

%% ---------------------------------------------------------------------------
%% CONTROLS. Without these a gate that refused everything would pass the block
%% above. Every count from Required..Declared inclusive must be accepted.
%% ---------------------------------------------------------------------------
control_every_legal_count_is_accepted_test() ->
    ?assertNot(beamchain_rpc:core_arity_violation(<<"savemempool">>, [])),
    ?assertNot(beamchain_rpc:core_arity_violation(<<"clearbanned">>, [])),
    ?assertNot(beamchain_rpc:core_arity_violation(<<"getblockcount">>, [])),
    ?assertNot(beamchain_rpc:core_arity_violation(<<"getblockhash">>, [1])),
    ?assertNot(beamchain_rpc:core_arity_violation(<<"gettxout">>, [<<"ab">>, 0])),
    ?assertNot(beamchain_rpc:core_arity_violation(
                 <<"gettxout">>, [<<"ab">>, 0, true])).

control_unknown_method_is_not_an_arity_violation_test() ->
    %% Core looks the method up first, so an unknown name must stay -32601 and
    %% never become -1. beamchain's handle_method/3 both resolves and executes,
    %% so the gate deliberately fires only for methods beamchain serves.
    ?assertNot(beamchain_rpc:core_arity_violation(
                 <<"definitely-not-an-rpc">>, [<<"a">>, <<"b">>])).

control_method_core_declares_but_beamchain_lacks_falls_through_test() ->
    %% If beamchain does not serve it, the gate must stay out of the way so the
    %% -32601 clause still answers -- even though Core's table has the method.
    Names = beamchain_rpc:beamchain_method_names(),
    Unserved = [M || M <- maps:keys(beamchain_core_arity:table()),
                     not lists:member(M, Names)],
    lists:foreach(
      fun(M) ->
              ?assertNot(beamchain_rpc:core_arity_violation(M, [<<"a">>, <<"b">>, <<"c">>, <<"d">>, <<"e">>, <<"f">>]))
      end, Unserved).

control_named_params_are_exempt_test() ->
    %% Core resolves a named-argument object by name, not by position.
    ?assertNot(beamchain_rpc:core_arity_violation(
                 <<"getblockhash">>, #{<<"height">> => 1})).
