-module(beamchain_mempool_refill_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% gen_server callbacks for the in-test stub mempool.  Explicit
%% exports because the test profile compiles without `export_all`
%% (`nowarn_export_all` in rebar.config flags the absence as
%% intentional, not as a "fix me with export_all" warning).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2]).

%% ============================================================
%% Pattern B (mempool refill on reorg) closure tests for beamchain.
%%
%% Pin the refill_mempool_after_reorg/1 helper and the gen_server
%% return-shape change in submit_block/1's reorg path.  Per the audit
%% (CORE-PARITY-AUDIT/_mempool-refill-on-reorg-fleet-result-2026-05-05.md),
%% beamchain previously discarded DisconnectedTxs in the submitblock
%% path (do_promote_side_branch line 1132 `_DisconnectedTxs`) so any
%% reorg silently dropped the old chain's mempool-bound txs.
%%
%% These tests exercise the helper in isolation by registering a
%% stub gen_server under the `beamchain_mempool` name; the helper's
%% gen_server:call to `accept_to_memory_pool` is captured and the
%% txs / per-tx replies are inspected.
%%
%% End-to-end coverage (full chainstate + real mempool + real reorg)
%% lives in tools/diff-test-corpus/regression/mempool-refill-on-reorg
%% (the cross-impl harness).
%% ============================================================

mempool_refill_test_() ->
    {foreach,
     fun setup/0,
     fun teardown/1,
     [
       fun test_refill_empty_list_is_noop/1,
       fun test_refill_calls_mempool_per_tx/1,
       fun test_refill_tolerates_per_tx_errors/1,
       fun test_refill_tolerates_throws/1,
       fun test_refill_preserves_input_order/1
     ]}.

%% ----------------------------------------------------------------
%% Stub mempool — registered as `beamchain_mempool` so the
%% accept_to_memory_pool/1 entry point routes through here.  The
%% stub's State is a list of received txs (newest first); the test
%% inspects via the {get_calls} introspection message.
%% ----------------------------------------------------------------

-record(stub_state, {
    calls = []     :: [#transaction{}],   %% txs received, newest-first
    reply_fun      :: fun((#transaction{}) ->
                            {ok, binary()} | {error, term()})
                      | throw_per_tx
}).

setup() ->
    %% In case a real beamchain_mempool is left over from another
    %% test, take it down cleanly.
    case whereis(beamchain_mempool) of
        undefined -> ok;
        Pid when is_pid(Pid) -> exit(Pid, kill), wait_unregister(beamchain_mempool, 50)
    end,
    {ok, _StubPid} = stub_mempool_start(default_reply_fun()),
    ok.

teardown(_) ->
    case whereis(beamchain_mempool) of
        undefined -> ok;
        Pid when is_pid(Pid) ->
            exit(Pid, normal),
            wait_unregister(beamchain_mempool, 50)
    end,
    ok.

wait_unregister(_Name, 0) -> ok;
wait_unregister(Name, N) ->
    case whereis(Name) of
        undefined -> ok;
        _ -> timer:sleep(10), wait_unregister(Name, N - 1)
    end.

default_reply_fun() ->
    fun(_Tx) -> {ok, <<0:256>>} end.

stub_mempool_start(ReplyFun) ->
    %% This test module itself implements the gen_server callbacks
    %% (init/1, handle_call/3, ...) for the stub — so we pass
    %% ?MODULE as the callback module.  Registering as
    %% `beamchain_mempool` makes the helper's
    %% `beamchain_mempool:accept_to_memory_pool(Tx)` route into us.
    %%
    %% Use start/3 (NOT start_link/3) so a stub crash in the
    %% throw-per-tx test does not propagate to the EUnit runner.
    gen_server:start({local, beamchain_mempool}, ?MODULE, ReplyFun, []).

%%% gen_server callbacks for the stub (re-using ?MODULE via init/1).

init(ReplyFun) ->
    {ok, #stub_state{reply_fun = ReplyFun}}.

handle_call({add_tx, _Tx}, _From, #stub_state{
                                     reply_fun = throw_per_tx}) ->
    %% Deliberately error on every call so refill helper exercises
    %% its catch-all branch.  This crashes the gen_server, which
    %% surfaces inside the caller's gen_server:call as an exit;
    %% the helper's `catch _:_` traps it.  No state update — the
    %% server is about to die.
    erlang:error(simulated_mempool_failure);
handle_call({add_tx, Tx}, _From,
            #stub_state{calls = Calls, reply_fun = F} = St) ->
    Reply = F(Tx),
    {reply, Reply, St#stub_state{calls = [Tx | Calls]}};
handle_call(get_calls, _From, #stub_state{calls = Calls} = St) ->
    {reply, lists:reverse(Calls), St};
handle_call(_Other, _From, St) ->
    {reply, ok, St}.

handle_cast(_Msg, St) -> {noreply, St}.
handle_info(_Info, St) -> {noreply, St}.
terminate(_Reason, _St) -> ok.

%%% ===================================================================
%%% Test cases
%%% ===================================================================

test_refill_empty_list_is_noop(_) ->
    fun() ->
        ?assertEqual(ok, beamchain_chainstate:refill_mempool_after_reorg([])),
        Calls = gen_server:call(beamchain_mempool, get_calls),
        ?assertEqual([], Calls)
    end.

test_refill_calls_mempool_per_tx(_) ->
    fun() ->
        Tx1 = mk_tx(1),
        Tx2 = mk_tx(2),
        Tx3 = mk_tx(3),
        ?assertEqual(ok,
            beamchain_chainstate:refill_mempool_after_reorg([Tx1, Tx2, Tx3])),
        Calls = gen_server:call(beamchain_mempool, get_calls),
        ?assertEqual(3, length(Calls)),
        ?assertEqual([Tx1, Tx2, Tx3], Calls)
    end.

test_refill_tolerates_per_tx_errors(_) ->
    fun() ->
        %% Restart stub with a reply fun that returns {error, ...} so
        %% we exercise the {error, _Reason} match arm in the helper.
        ok = restart_stub(fun(_Tx) -> {error, mempool_full} end),
        Tx1 = mk_tx(11),
        Tx2 = mk_tx(12),
        %% Helper must NOT crash, must NOT propagate the error, and
        %% must STILL attempt every tx (no short-circuit on first err).
        ?assertEqual(ok,
            beamchain_chainstate:refill_mempool_after_reorg([Tx1, Tx2])),
        Calls = gen_server:call(beamchain_mempool, get_calls),
        ?assertEqual([Tx1, Tx2], Calls)
    end.

test_refill_tolerates_throws(_) ->
    fun() ->
        %% Stub with reply_fun = throw_per_tx makes every {add_tx, _}
        %% call exit the stub gen_server with an error.  The helper's
        %% try/catch must absorb it and continue with the next tx.
        ok = restart_stub(throw_per_tx),
        Tx1 = mk_tx(21),
        Tx2 = mk_tx(22),
        %% Note: the stub records the tx BEFORE throwing, but the
        %% throw kills the stub gen_server.  After the first call the
        %% stub is dead, so the second call should error-out cleanly
        %% and the helper must STILL return ok (not crash the caller).
        ?assertEqual(ok,
            beamchain_chainstate:refill_mempool_after_reorg([Tx1, Tx2]))
        %% No call to get_calls — the stub may be dead.  The
        %% load-bearing assertion is "helper returned ok despite
        %% mempool throwing", proving the catch-all branch works.
    end.

test_refill_preserves_input_order(_) ->
    fun() ->
        %% Bitcoin Core's MaybeUpdateMempoolForReorg processes
        %% disconnected txs in iteration order; we must do the same
        %% so any topological dependency between disconnected txs
        %% has a chance to resolve (parents before children, when
        %% the disconnect order put them that way).
        Txs = [mk_tx(N) || N <- lists:seq(100, 110)],
        ?assertEqual(ok,
            beamchain_chainstate:refill_mempool_after_reorg(Txs)),
        Calls = gen_server:call(beamchain_mempool, get_calls),
        ?assertEqual(Txs, Calls)
    end.

%%% ===================================================================
%%% Helpers
%%% ===================================================================

restart_stub(NewReplyFun) ->
    case whereis(beamchain_mempool) of
        undefined -> ok;
        Pid -> exit(Pid, kill), wait_unregister(beamchain_mempool, 50)
    end,
    {ok, _} = stub_mempool_start(NewReplyFun),
    ok.

mk_tx(N) ->
    #transaction{
        version  = 2,
        inputs   = [#tx_in{
            prev_out   = #outpoint{hash = <<N:256>>, index = 0},
            script_sig = <<>>,
            sequence   = 16#FFFFFFFF,
            witness    = undefined
        }],
        outputs  = [#tx_out{value = N * 1000,
                             script_pubkey = <<>>}],
        locktime = 0,
        txid     = <<N:256>>,
        wtxid    = <<N:256>>
    }.
