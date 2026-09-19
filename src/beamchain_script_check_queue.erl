-module(beamchain_script_check_queue).

%% CCheckQueue analogue for ConnectBlock script verification.
%%
%% Bitcoin Core (checkqueue.h, validation.cpp CheckInputScripts /
%% ConnectBlock, init.cpp -par, validation.h MAX_SCRIPTCHECK_THREADS=15):
%% push one CScriptCheck per input onto a bounded queue, N worker threads
%% drain it, the block is accepted only if every check returns true, and
%% the accept/reject decision must not depend on how the work was split.
%%
%% BEAM adaptation:
%%   * ECDSA/Schnorr NIFs are already ERL_NIF_DIRTY_JOB_CPU_BOUND, so a
%%     pool of ordinary processes actually occupies extra cores. There is
%%     no GIL.
%%   * The caller does not join the pool (it only waits), so -par=0 auto
%%     uses every dirty-CPU scheduler, not cores-1.
%%   * Jobs live in one ETS table (one copy of the block's checks). Workers
%%     claim the next index via atomics and copy out a single check. More
%%     workers therefore cannot mean unbounded buffers.
%%   * Every check runs. Among failures we keep the minimum {tx,in} order
%%     so reject reasons are identical at 1 worker and at N (Core's first
%%     writer wins, which is racy at N>1; we are stricter).
%%
%% The previous verify_scripts_parallel/2 spawned one process per
%% transaction with a FIFO collector — unbounded, and a late-spawned
%% failure waited on the head. That is the thing this module replaces.

-include("beamchain.hrl").

-export([verify/2, verify/3, verify_funs/2]).
-export([resolve_threads/1, max_scriptcheck_threads/0, last_stats/0]).
-export([worker_max_heap_words/0]).

%% Core's cap is 15 extra threads. This box has 32 cores and the queue
%% item is "use them"; 32 bounds RSS without leaving 17 cores idle.
-define(MAX_SCRIPTCHECK_THREADS, 32).
-define(WORKER_MAX_HEAP_WORDS, 1_000_000).
-define(STATS_KEY, beamchain_script_check_queue_stats).

-record(script_check, {
    order       :: {non_neg_integer(), non_neg_integer()},
    n_in        :: non_neg_integer() | undefined,
    flags       :: integer() | undefined,
    script_sig  :: binary() | undefined,
    script_pubkey :: binary() | undefined,
    witness     :: [binary()] | undefined,
    sig_checker :: term() | undefined,
    check_fun   :: fun(() -> ok | {error, term()}) | undefined
}).

%%% ===================================================================
%%% Public API
%%% ===================================================================

-spec max_scriptcheck_threads() -> pos_integer().
max_scriptcheck_threads() ->
    ?MAX_SCRIPTCHECK_THREADS.

-spec worker_max_heap_words() -> pos_integer().
worker_max_heap_words() ->
    ?WORKER_MAX_HEAP_WORDS.

%% @doc Map a Core-style -par value to a worker count.
%%   N > 0  → N, clamped to [1, MAX]
%%   N = 0  → auto = dirty CPU schedulers (every core)
%%   N < 0  → auto, leaving |N| cores free
-spec resolve_threads(integer()) -> pos_integer().
resolve_threads(N) when is_integer(N), N > 0 ->
    clamp(N);
resolve_threads(N) when is_integer(N), N =< 0 ->
    clamp(cores() + N);
resolve_threads(_) ->
    clamp(cores()).

-spec last_stats() -> map().
last_stats() ->
    persistent_term:get(?STATS_KEY, #{}).

%% @doc Verify `{Tx, InputCoins}` jobs (ConnectBlock shape) with auto
%% worker count. Throws `{script_verify_failed, InIdx}` on failure.
-spec verify([{#transaction{}, [#utxo{}]}], integer()) -> ok.
verify(Jobs, Flags) ->
    verify(Jobs, Flags, resolve_threads(0)).

-spec verify([{#transaction{}, [#utxo{}]}] | [fun()], integer(), integer()) -> ok.
verify(Jobs, Flags, N) when is_integer(N), N < 1 ->
    verify(Jobs, Flags, 1);
verify(Jobs, Flags, N) when is_integer(N) ->
    Checks = expand_jobs(Jobs, Flags),
    case Checks of
        [] ->
            record_stats(#{workers => 0, jobs => 0, ets_objects => 0,
                           max_heap_words => ?WORKER_MAX_HEAP_WORDS}),
            ok;
        _ ->
            run_pool(Checks, N)
    end.

%% @doc Test helper: run 0-arity funs returning `ok | {error, Reason}`.
-spec verify_funs([fun(() -> ok | {error, term()})], integer()) -> ok.
verify_funs(Funs, N) ->
    verify(Funs, 0, N).

%%% ===================================================================
%%% Expand ConnectBlock jobs to per-input checks (Core CScriptCheck)
%%% ===================================================================

expand_jobs(Jobs, Flags) ->
    {PerTx, _} = lists:mapfoldl(fun(Job, TxIdx) ->
        {expand_job(Job, Flags, TxIdx), TxIdx + 1}
    end, 0, Jobs),
    lists:append(PerTx).

expand_job(Fun, _Flags, TxIdx) when is_function(Fun, 0) ->
    [#script_check{order = {TxIdx, 0}, check_fun = Fun}];
expand_job({Tx, Coins}, Flags, TxIdx) ->
    AllPrevOuts = [{C#utxo.value, C#utxo.script_pubkey} || C <- Coins],
    expand_inputs(Tx#transaction.inputs, Coins, Tx, Flags, TxIdx, 0,
                  AllPrevOuts, []).

expand_inputs([], [], _Tx, _Flags, _TxIdx, _Idx, _Prev, Acc) ->
    lists:reverse(Acc);
expand_inputs([In | Ins], [Coin | Coins], Tx, Flags, TxIdx, Idx, Prev, Acc) ->
    Witness = case In#tx_in.witness of
        undefined -> [];
        W -> W
    end,
    Check = #script_check{
        order = {TxIdx, Idx},
        n_in = Idx,
        flags = Flags,
        script_sig = In#tx_in.script_sig,
        script_pubkey = Coin#utxo.script_pubkey,
        witness = Witness,
        sig_checker = {Tx, Idx, Coin#utxo.value, Prev}
    },
    expand_inputs(Ins, Coins, Tx, Flags, TxIdx, Idx + 1, Prev, [Check | Acc]).

%%% ===================================================================
%%% Bounded pool
%%% ===================================================================

run_pool(Checks, NWorkers) ->
    NJobs = length(Checks),
    N = max(1, min(NWorkers, NJobs)),
    Tab = ets:new(beamchain_script_check_jobs,
                  [public, set, {read_concurrency, true}]),
    true = ets:insert(Tab, lists:zip(lists:seq(1, NJobs), Checks)),
    %% Starts at 0 so the first add_get returns 1, matching ETS keys
    %% 1..NJobs. Putting 1 here skipped job 1 — a 1-input block would
    %% have accepted without running its only script check.
    Counter = atomics:new(1, [{signed, false}]),
    record_stats(#{workers => N,
                   jobs => NJobs,
                   ets_objects => ets:info(Tab, size),
                   max_heap_words => ?WORKER_MAX_HEAP_WORDS}),
    try
        spawn_and_collect(Tab, Counter, N)
    after
        ets:delete(Tab)
    end.

spawn_and_collect(Tab, Counter, N) ->
    SpawnOpts = [
        monitor,
        {max_heap_size, #{size => ?WORKER_MAX_HEAP_WORDS,
                          kill => true,
                          error_logger => false}}
    ],
    Monitors = lists:foldl(fun(_, Acc) ->
        {_Pid, Ref} = erlang:spawn_opt(fun() ->
            Fail = worker_drain(Tab, Counter, undefined),
            exit({check_ok, Fail})
        end, SpawnOpts),
        Acc#{Ref => true}
    end, #{}, lists:seq(1, N)),
    case collect(Monitors, undefined) of
        undefined -> ok;
        {_Order, Reason} -> throw(Reason)
    end.

worker_drain(Tab, Counter, Acc) ->
    Idx = atomics:add_get(Counter, 1, 1),
    case ets:lookup(Tab, Idx) of
        [] ->
            Acc;
        [{Idx, Check}] ->
            Acc1 = case run_check(Check) of
                ok -> Acc;
                {error, Reason} ->
                    min_fail(Acc, {Check#script_check.order, Reason})
            end,
            worker_drain(Tab, Counter, Acc1)
    end.

collect(Map, Acc) when map_size(Map) =:= 0 ->
    Acc;
collect(Map, Acc) ->
    receive
        {'DOWN', Ref, process, _Pid, {check_ok, Fail}} ->
            case maps:is_key(Ref, Map) of
                true ->
                    collect(maps:remove(Ref, Map), min_fail(Acc, Fail));
                false ->
                    collect(Map, Acc)
            end;
        {'DOWN', Ref, process, _Pid, Reason} ->
            case maps:is_key(Ref, Map) of
                true ->
                    Crash = {{16#7fffffff, 16#7fffffff},
                             {script_verify_failed, Reason}},
                    collect(maps:remove(Ref, Map), min_fail(Acc, Crash));
                false ->
                    collect(Map, Acc)
            end
    end.

run_check(#script_check{check_fun = Fun}) when is_function(Fun, 0) ->
    try Fun() of
        ok -> ok;
        {error, _} = E -> E;
        true -> ok;
        false -> {error, {script_verify_failed, 0}}
    catch
        throw:Reason -> {error, Reason};
        _Class:R -> {error, {script_verify_failed, R}}
    end;
run_check(#script_check{n_in = Idx, flags = Flags,
                        script_sig = ScriptSig, script_pubkey = SPK,
                        witness = Witness, sig_checker = Checker}) ->
    case beamchain_script:verify_script(ScriptSig, SPK, Witness, Flags, Checker) of
        true -> ok;
        false -> {error, {script_verify_failed, Idx}}
    end.

min_fail(undefined, F) -> F;
min_fail(F, undefined) -> F;
min_fail({O1, _} = A, {O2, _} = B) ->
    case O2 < O1 of
        true -> B;
        false -> A
    end.

clamp(N) ->
    max(1, min(N, ?MAX_SCRIPTCHECK_THREADS)).

cores() ->
    try erlang:system_info(dirty_cpu_schedulers) of
        D when is_integer(D), D > 0 -> D
    catch
        _:_ -> erlang:system_info(schedulers)
    end.

record_stats(Map) ->
    persistent_term:put(?STATS_KEY, Map).
