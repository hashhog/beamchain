-module(beamchain_fatal).

%%% Process-wide fatal latch: beamchain's AbortNode.
%%%
%%% Core (node/abort.cpp AbortNode, validation.cpp FatalError): a system
%%% fault the node cannot recover from -- a failed block/undo/coins write,
%%% a failed flush, an internal error inside script verification -- sets
%%% the fatal flag, starts shutdown and makes the process exit non-zero.
%%% The block being connected is NEVER marked invalid or valid, nobody is
%%% punished. Gate 6 (docs/RELEASE-CHECKLIST.md): a system fault leads to
%%% retry or halt, never to a reject or an accept.
%%%
%%% Once latched:
%%%   * chainstate refuses connect/submit/reorg (no tip movement);
%%%   * block_sync stops connecting and stops retrying;
%%%   * submitblock answers RPC_VERIFY_ERROR (-25), never a BIP-22 token;
%%%   * the mempool refuses new transactions (nothing remembered as
%%%     rejected, nobody punished);
%%%   * shutdown SKIPS the chainstate flush (the in-memory coins view may
%%%     be ahead of / inconsistent with disk -- the last good flush is the
%%%     recovery point, exactly like a crash, which gate 4 covers);
%%%   * the VM halts with status 1.
%%%
%%% The latch is a persistent_term (one read per check, written once).

-export([abort_node/1, is_aborted/0, reason/0, refusal/0]).
-export([is_system_fault/1]).
-export([reset_for_test/0]).

-define(LATCH, {?MODULE, latch}).
%% Grace for the supervision tree to stop (mempool dump etc.) before the
%% VM is halted anyway. stop_mainnet.sh waits 120 s.
-define(STOP_GRACE_MS, 60000).

%% @doc Latch the node as aborted (idempotent; the first reason wins) and
%% start the non-zero shutdown. Returns ok immediately; callers then fail
%% their own operation with a non-verdict.
-spec abort_node(term()) -> ok.
abort_node(Reason) ->
    case persistent_term:get(?LATCH, undefined) of
        undefined ->
            persistent_term:put(?LATCH, {Reason, erlang:system_time(second)}),
            logger:emergency("FATAL (AbortNode): ~p -- a system fault is "
                             "never a consensus verdict: no block marked, "
                             "no peer punished; stopping without flushing "
                             "the chainstate, exit status 1", [Reason]),
            start_shutdown(),
            ok;
        _ ->
            logger:error("FATAL (AbortNode) again: ~p (already latched)",
                         [Reason]),
            ok
    end.

-spec is_aborted() -> boolean().
is_aborted() ->
    persistent_term:get(?LATCH, undefined) =/= undefined.

-spec reason() -> undefined | term().
reason() ->
    case persistent_term:get(?LATCH, undefined) of
        undefined -> undefined;
        {R, _} -> R
    end.

%% @doc The non-verdict error term a refused operation returns.
-spec refusal() -> {node_aborted, term()}.
refusal() ->
    {node_aborted, reason()}.

%% @doc STRICT ALLOW-LIST: is a connect/submit failure a local system fault
%% (I/O, timeout, dead worker, internal script error, latched node) rather
%% than something about the block? Used by submitblock (-25 instead of a
%% BIP-22 token). Not used to decide verdicts -- that is
%% beamchain_block_sync:is_consensus_verdict/1, whose unknown answer is
%% already "not a verdict".
-spec is_system_fault(term()) -> boolean().
is_system_fault({node_aborted, _}) -> true;
is_system_fault({internal_error, _}) -> true;
is_system_fault({exit_during_connect, _}) -> true;
is_system_fault({post_validation_failure, _}) -> true;
is_system_fault({script_check_worker_crash, _}) -> true;
is_system_fault({script_internal, _}) -> true;
is_system_fault({system_fault, _}) -> true;
is_system_fault({reorg_connect_failed, R}) -> is_system_fault(R);
is_system_fault({reorg_disconnect_failed, R}) -> is_system_fault(R);
is_system_fault({reorg_exception, _}) -> true;
is_system_fault({timeout, _}) -> true;
is_system_fault(_) -> false.

%% @doc Test-only: clear the latch.
-spec reset_for_test() -> ok.
reset_for_test() ->
    _ = persistent_term:erase(?LATCH),
    ok.

%%% -------------------------------------------------------------------

%% Shutdown runs in its own process: the caller may be the chainstate
%% gen_server itself (a failed flush), which must return before the
%% supervision tree can stop it. `fatal_halt` = false (eunit) latches
%% without stopping the VM.
start_shutdown() ->
    case application:get_env(beamchain, fatal_halt, true) of
        false ->
            ok;
        _ ->
            _ = spawn(fun shutdown/0),
            ok
    end.

shutdown() ->
    _ = (catch beamchain_cli:remove_pidfile()),
    {Pid, Ref} = spawn_monitor(fun() -> application:stop(beamchain) end),
    receive
        {'DOWN', Ref, process, Pid, _} -> ok
    after ?STOP_GRACE_MS ->
        logger:emergency("FATAL (AbortNode): application stop did not "
                         "finish in ~B ms; halting anyway",
                         [?STOP_GRACE_MS])
    end,
    erlang:halt(1).
