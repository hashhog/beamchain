-module(beamchain_tip_notifier).
-behaviour(gen_server).

%% Tip-change notification primitive for the wait-family RPCs
%% (waitfornewblock / waitforblock / waitforblockheight).
%%
%% Bitcoin Core registers a `WaitTipChanged` condition variable
%% (kernel Notifications / KernelNotifications::blockTip) that is
%% signalled on every active-chain tip update.  The wait-family RPCs
%% (rpc/blockchain.cpp:290-471) block on it with a deadline, re-checking
%% their predicate (new tip / hash match / height >=) after every wake
%% and returning the current tip {hash, height} on match OR on timeout.
%%
%% This module is the beamchain analogue.  Erlang has no shared mutex /
%% condition variable, so the wake mechanism is selective receive: the
%% notifier is a registered gen_server that holds a monotonic generation
%% counter + a set of subscribed waiter pids, and `notify/0` bumps the
%% generation and sends a `{tip_notify, NewGen}` message to every
%% subscriber.  A waiter runs `wait_for_tip/2` IN ITS OWN (cowboy request)
%% process, so blocking a waiter never blocks the notifier, the
%% chainstate gen_server, or any other request.
%%
%% Lost-wakeup safety (the whole point):
%%   * A waiter subscribes FIRST, then snapshots the generation, then
%%     checks its predicate against the AUTHORITATIVE chainstate tip
%%     (beamchain_chainstate:get_tip/0 — an ETS read, never a value
%%     cached in this server).  Because the waiter is already a
%%     subscriber, any notify that fires after subscription lands in the
%%     waiter's mailbox.  The selective receive that follows therefore
%%     observes a notify that raced in between the predicate check and
%%     the receive — it is NOT lost.
%%   * The monotonic `generation` lets the waiter discard a stale /
%%     coalesced `{tip_notify, G}` (G =< snapshot) without spinning,
%%     but correctness does NOT depend on the generation matching any
%%     particular tip: the waiter ALWAYS re-reads the real tip after
%%     every wake, exactly like Core.  Two blocks connected back-to-back
%%     before a waiter wakes, a missed notify, or a coalesced notify can
%%     never produce a wrong answer.
%%
%% notify/0 is best-effort and crash-proof for its callers: it is a cast,
%% and if the server is somehow not running the call is swallowed.  A
%% notifier fault must never stall block connect / reorg.

-include_lib("kernel/include/logger.hrl").

%% API
-export([start_link/0, notify/0, generation/0]).
-export([subscribe/0, unsubscribe/0, wait/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {
    %% Monotonic tip-change counter, bumped on every notify/0.
    generation = 0 :: non_neg_integer(),
    %% Subscribed waiter pids -> monitor ref (so a waiter that dies
    %% without unsubscribing is reaped and never accumulates).
    subs = #{} :: #{pid() => reference()}
}).

%%% ===================================================================
%%% API
%%% ===================================================================

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc Signal that the active-chain tip advanced.  Bumps the generation
%% and wakes every current waiter.  Safe to call from any connect / reorg
%% chokepoint; best-effort (never raises into the caller).
-spec notify() -> ok.
notify() ->
    %% A bare cast to a registered name is silently dropped if the server
    %% is not registered, so this can never raise into the connect path.
    %% Wrap defensively anyway.
    try
        gen_server:cast(?SERVER, notify)
    catch
        _:_ -> ok
    end,
    ok.

%% @doc Current tip-change generation (bumped on every notify/0).
-spec generation() -> non_neg_integer().
generation() ->
    try
        gen_server:call(?SERVER, generation, 5000)
    catch
        %% Degraded boot / server unavailable: report 0 so a waiter does
        %% not crash.  A waiter that gets a constant 0 simply falls back
        %% to a pure timeout (it still re-reads the authoritative tip each
        %% loop), which is the safe Core-on-shutdown behaviour.
        _:_ -> 0
    end.

%% @doc Register the calling process as a waiter and return the current
%% generation.  MUST be called BEFORE the first predicate check so a
%% notify that races in after the check is delivered to this process.
-spec subscribe() -> non_neg_integer().
subscribe() ->
    try
        gen_server:call(?SERVER, {subscribe, self()}, 5000)
    catch
        _:_ -> 0
    end.

%% @doc Deregister the calling process.  Idempotent; safe in `after`.
-spec unsubscribe() -> ok.
unsubscribe() ->
    try
        gen_server:cast(?SERVER, {unsubscribe, self()})
    catch
        _:_ -> ok
    end,
    %% Drain any tip_notify already in our mailbox so a later request on
    %% this (pooled) process is not confused by a stale message.
    flush_notifies(),
    ok.

%% @doc Block until a tip change is observed after `LastGen`, or until
%% `Timeout` (ms) elapses; `infinity` waits forever.  Returns
%% `tip_changed` if a notify newer than LastGen arrived, `timeout`
%% otherwise.  Either way the caller MUST re-read the authoritative tip
%% and re-evaluate its predicate (this only provides a prompt wake).
%%
%% Must be called from a process that has previously subscribe/0'd.
-spec wait(non_neg_integer(), timeout()) -> tip_changed | timeout.
wait(LastGen, Timeout) ->
    %% Compute an absolute monotonic deadline ONCE so that looping on
    %% strictly-stale notifies cannot extend the caller's deadline.  The
    %% previous version recursed with the full original Timeout, so N stale
    %% messages could each reset the wait to the full value and overshoot the
    %% deadline by up to N*Timeout.
    Deadline = case Timeout of
                   infinity -> infinity;
                   _ -> erlang:monotonic_time(millisecond) + Timeout
               end,
    wait_until(LastGen, Deadline).

-spec wait_until(non_neg_integer(), integer() | infinity) ->
    tip_changed | timeout.
wait_until(LastGen, Deadline) ->
    Remaining = case Deadline of
                    infinity -> infinity;
                    _ -> max(0, Deadline - erlang:monotonic_time(millisecond))
                end,
    receive
        {tip_notify, G} when G > LastGen ->
            tip_changed;
        {tip_notify, _StaleG} ->
            %% A coalesced / out-of-order notify no newer than our snapshot.
            %% Don't treat as a wake (would busy-spin); keep waiting for a
            %% genuinely newer generation, preserving the REMAINING deadline
            %% (not the full original Timeout).  Terminates because we only
            %% loop on strictly-stale messages and Remaining is monotone
            %% non-increasing.
            wait_until(LastGen, Deadline)
    after Remaining ->
        timeout
    end.

%%% ===================================================================
%%% gen_server callbacks
%%% ===================================================================

init([]) ->
    {ok, #state{}}.

handle_call(generation, _From, #state{generation = G} = State) ->
    {reply, G, State};
handle_call({subscribe, Pid}, _From,
            #state{generation = G, subs = Subs} = State) ->
    %% Already subscribed? return the current generation, keep one monitor.
    case maps:is_key(Pid, Subs) of
        true ->
            {reply, G, State};
        false ->
            Ref = erlang:monitor(process, Pid),
            {reply, G, State#state{subs = Subs#{Pid => Ref}}}
    end;
handle_call(_Req, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast(notify, #state{generation = G, subs = Subs} = State) ->
    NewGen = G + 1,
    %% Edge-triggered pulse to every current waiter.  Each waiter's
    %% selective receive picks up the {tip_notify, NewGen} and re-reads
    %% the authoritative tip.
    maps:foreach(
        fun(Pid, _Ref) -> Pid ! {tip_notify, NewGen} end,
        Subs),
    {noreply, State#state{generation = NewGen}};
handle_cast({unsubscribe, Pid}, #state{subs = Subs} = State) ->
    {noreply, State#state{subs = demonitor_remove(Pid, Subs)}};
handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({'DOWN', _Ref, process, Pid, _Reason},
            #state{subs = Subs} = State) ->
    %% A waiter died without unsubscribing — reap it.
    {noreply, State#state{subs = maps:remove(Pid, Subs)}};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_Old, State, _Extra) ->
    {ok, State}.

%%% ===================================================================
%%% Internal
%%% ===================================================================

demonitor_remove(Pid, Subs) ->
    case maps:take(Pid, Subs) of
        {Ref, Subs2} ->
            erlang:demonitor(Ref, [flush]),
            Subs2;
        error ->
            Subs
    end.

%% Discard any tip_notify messages still sitting in the calling process's
%% mailbox (used by unsubscribe/0 so a pooled cowboy process does not
%% carry a stale wake into its next request).
flush_notifies() ->
    receive
        {tip_notify, _} -> flush_notifies()
    after 0 ->
        ok
    end.
