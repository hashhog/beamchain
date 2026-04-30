-module(beamchain_estimaterawfee_tests).

-include_lib("eunit/include/eunit.hrl").

%%% Tests for beamchain_fee_estimator:estimate_raw_fee/2 — the
%%% gen_server API backing the estimaterawfee RPC. The estimator is
%%% started as a real gen_server (it owns its own ETS tables and
%%% subscribes to chain state). Tests run against a freshly started
%%% server with no tracked transactions.

%%% -------------------------------------------------------------------
%%% Server lifecycle
%%% -------------------------------------------------------------------

setup() ->
    %% beamchain_fee_estimator reads the chain tip via
    %% beamchain_chainstate:get_tip on init, which does an ETS lookup
    %% on the beamchain_chain_meta table. Provide an empty table so
    %% get_tip/0 cleanly returns `not_found' and the estimator
    %% defaults to height 0.
    case ets:info(beamchain_chain_meta) of
        undefined ->
            ets:new(beamchain_chain_meta,
                    [set, public, named_table]);
        _ -> ok
    end,
    case whereis(beamchain_fee_estimator) of
        undefined -> ok;
        Pid ->
            unlink(Pid),
            exit(Pid, kill),
            wait_dead(Pid)
    end,
    %% Drop persisted state from prior runs.
    Files = filelib:wildcard("fee_estimates.dat"),
    lists:foreach(fun file:delete/1, Files),
    {ok, NewPid} = beamchain_fee_estimator:start_link(),
    NewPid.

teardown(Pid) ->
    case is_process_alive(Pid) of
        true ->
            unlink(Pid),
            exit(Pid, kill),
            wait_dead(Pid);
        false -> ok
    end.

wait_dead(Pid) ->
    case is_process_alive(Pid) of
        false -> ok;
        true ->
            timer:sleep(10),
            wait_dead(Pid)
    end.

%%% -------------------------------------------------------------------
%%% Tests
%%% -------------------------------------------------------------------

%% With no tracked transactions, estimate_raw_fee returns a single
%% "medium" horizon entry containing the canonical decay/scale plus
%% an `errors' list and an empty `fail' bucket — never a `feerate'.
empty_estimator_returns_errors_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) ->
        [fun() ->
             Result = beamchain_fee_estimator:estimate_raw_fee(6, 0.95),
             ?assert(is_map(Result)),
             ?assert(maps:is_key(<<"medium">>, Result)),
             Med = maps:get(<<"medium">>, Result),
             ?assert(is_map(Med)),
             ?assertNot(maps:is_key(<<"feerate">>, Med)),
             ?assertEqual(true, maps:is_key(<<"errors">>, Med)),
             ?assertEqual(true, maps:is_key(<<"decay">>, Med)),
             ?assertEqual(true, maps:is_key(<<"scale">>, Med)),
             ?assertEqual(true, maps:is_key(<<"fail">>, Med)),
             %% Errors list contains the Core-style sentinel string.
             [Err | _] = maps:get(<<"errors">>, Med),
             ?assert(is_binary(Err))
         end]
     end}.

%% Out-of-range conf_target / threshold are rejected.
invalid_conf_target_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) ->
        [
         ?_assertEqual(#{},
            beamchain_fee_estimator:estimate_raw_fee(0, 0.5)),
         ?_assertEqual(#{},
            beamchain_fee_estimator:estimate_raw_fee(2000, 0.5)),
         ?_assertEqual(#{},
            beamchain_fee_estimator:estimate_raw_fee(6, -0.1)),
         ?_assertEqual(#{},
            beamchain_fee_estimator:estimate_raw_fee(6, 1.5))
        ]
     end}.

%% Estimator returns the same shape for the canonical default
%% threshold of 0.95 used by Bitcoin Core.
default_threshold_shape_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) ->
        [fun() ->
             Result = beamchain_fee_estimator:estimate_raw_fee(6, 0.95),
             Med = maps:get(<<"medium">>, Result),
             FailBucket = maps:get(<<"fail">>, Med),
             %% The empty-state "fail" bucket has all the Core fields.
             ExpectedKeys = lists:sort([<<"startrange">>,
                                        <<"endrange">>,
                                        <<"withintarget">>,
                                        <<"totalconfirmed">>,
                                        <<"inmempool">>,
                                        <<"leftmempool">>]),
             ?assertEqual(ExpectedKeys,
                          lists:sort(maps:keys(FailBucket)))
         end]
     end}.
