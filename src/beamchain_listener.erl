-module(beamchain_listener).

%% Shared cowboy listener bootstrap with exponential-backoff retry.
%%
%% Problem: on a SIGTERM -> restart cycle, the previous BEAM process leaves
%% its listening socket in TIME_WAIT. Without SO_REUSEADDR, ranch's
%% ranch_acceptors_sup crashes once with {listen_error, _, eaddrinuse} at
%% startup, and the wrapping gen_server (beamchain_rpc / _rest / _metrics)
%% logs a warning and returns {ok, State}. The supervisor never sees a
%% reason to restart it, so the HTTP endpoint stays dark for the life of
%% the BEAM process.
%%
%% Fix: (a) pass {reuseaddr, true} to cowboy's transport opts so the new
%% bind succeeds over a residual TIME_WAIT socket; (b) wrap
%% cowboy:start_clear/3 in a bounded exponential-backoff retry loop to
%% cover genuine races where the previous socket owner has not fully torn
%% down yet.
%%
%% Retry schedule (6 attempts): 1s, 2s, 4s, 8s, 16s, 32s -> ~63s total
%% worst-case wait. Matches the spec in
%% overnight-2026-04-13/BEAMCHAIN-RPC-RETRY-FIX.md.

-export([start_clear_with_retry/4]).

-define(MAX_ATTEMPTS, 6).
-define(BASE_BACKOFF_MS, 1000).

-spec start_clear_with_retry(ranch:ref(), ranch:opts(), cowboy:opts(),
                             iodata()) ->
    {ok, pid()} | {error, term()}.
start_clear_with_retry(Ref, TransportOpts, ProtoOpts, LogTag) ->
    start_clear_with_retry(Ref, TransportOpts, ProtoOpts, LogTag, 1).

start_clear_with_retry(Ref, TransportOpts, ProtoOpts, LogTag, Attempt) ->
    case cowboy:start_clear(Ref, TransportOpts, ProtoOpts) of
        {ok, Pid} ->
            {ok, Pid};
        {error, {already_started, Pid}} ->
            {ok, Pid};
        {error, eaddrinuse = Reason} when Attempt < ?MAX_ATTEMPTS ->
            Backoff = ?BASE_BACKOFF_MS bsl (Attempt - 1),
            logger:warning("~s: port busy (attempt ~B/~B, retry in ~Bms): ~p",
                           [LogTag, Attempt, ?MAX_ATTEMPTS, Backoff, Reason]),
            timer:sleep(Backoff),
            start_clear_with_retry(Ref, TransportOpts, ProtoOpts, LogTag,
                                   Attempt + 1);
        {error, {listen_error, _, eaddrinuse}} when Attempt < ?MAX_ATTEMPTS ->
            %% Older / differently-wrapped ranch error shape. Belt and
            %% suspenders: match both.
            Backoff = ?BASE_BACKOFF_MS bsl (Attempt - 1),
            logger:warning("~s: port busy (attempt ~B/~B, retry in ~Bms)",
                           [LogTag, Attempt, ?MAX_ATTEMPTS, Backoff]),
            timer:sleep(Backoff),
            start_clear_with_retry(Ref, TransportOpts, ProtoOpts, LogTag,
                                   Attempt + 1);
        {error, Reason} ->
            {error, Reason}
    end.
