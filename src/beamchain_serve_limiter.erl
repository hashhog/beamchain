-module(beamchain_serve_limiter).
-behaviour(gen_server).

%%% Global bound on concurrent peer data-request serving (BC-S).
%%%
%%% getdata / getheaders / mempool / getcf* are served in each requesting
%%% peer's own process (beamchain_peer serve_request/3) so a slow read can
%%% no longer block the peer manager. Every block / header read still goes
%%% through the single beamchain_db gen_server, though, and before the move
%%% the manager serialised them: at most ONE serving read was ever queued
%%% in beamchain_db. Unbounded per-peer serving would let N peers put N
%%% block reads (or N x 2000 header reads) in front of header_sync and
%%% chainstate -- the 2026-10-05 status-repair incident class (callers of
%%% beamchain_db hitting the 30 s gen_server:call timeout). This process
%%% hands out at most `serve_concurrency` (default 1, the old manager's
%%% effective concurrency) slots; a peer waits
%%% for one in its own process. Slots are released on return and on the
%%% holder's death (monitor), so a killed peer can never leak one.
%%%
%%% The limiter only does bookkeeping (no I/O), so it cannot itself become
%%% the bottleneck it replaces. If it is not running (early boot, tests),
%%% with_slot/1 serves unlimited.

-export([start_link/0, with_slot/1, limit/0, stats/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(DEFAULT_LIMIT, 1).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% @doc Run Fun holding a serving slot.
-spec with_slot(fun(() -> T)) -> T.
with_slot(Fun) ->
    case whereis(?MODULE) of
        undefined ->
            Fun();
        _ ->
            case catch gen_server:call(?MODULE, acquire, infinity) of
                ok ->
                    try Fun()
                    after gen_server:cast(?MODULE, {release, self()})
                    end;
                _ ->
                    Fun()
            end
    end.

-spec limit() -> pos_integer().
limit() ->
    case application:get_env(beamchain, serve_concurrency) of
        {ok, N} when is_integer(N), N > 0 -> N;
        _ -> ?DEFAULT_LIMIT
    end.

stats() ->
    gen_server:call(?MODULE, stats).

%%% -------------------------------------------------------------------

init([]) ->
    {ok, #{limit => limit(), holders => #{}, waiting => queue:new()}}.

handle_call(acquire, {Pid, _} = From, #{limit := L, holders := H} = S) ->
    case maps:is_key(Pid, H) of
        true ->
            %% Re-entrant acquire by the same holder: never deadlock.
            {reply, ok, S};
        false when map_size(H) < L ->
            {reply, ok, S#{holders := H#{Pid => erlang:monitor(process, Pid)}}};
        false ->
            {noreply, S#{waiting := queue:in(From, maps:get(waiting, S))}}
    end;
handle_call(stats, _From, #{holders := H, waiting := W, limit := L} = S) ->
    {reply, #{limit => L, holders => map_size(H), waiting => queue:len(W)}, S}.

handle_cast({release, Pid}, S) ->
    {noreply, grant(drop_holder(Pid, S))};
handle_cast(_, S) ->
    {noreply, S}.

handle_info({'DOWN', _Ref, process, Pid, _}, S) ->
    {noreply, grant(drop_holder(Pid, S))};
handle_info(_, S) ->
    {noreply, S}.

drop_holder(Pid, #{holders := H} = S) ->
    case maps:take(Pid, H) of
        {Ref, H2} -> erlang:demonitor(Ref, [flush]), S#{holders := H2};
        error -> S
    end.

grant(#{limit := L, holders := H, waiting := W} = S) when map_size(H) < L ->
    case queue:out(W) of
        {empty, _} ->
            S;
        {{value, {Pid, _} = From}, W2} ->
            case is_process_alive(Pid) of
                true ->
                    gen_server:reply(From, ok),
                    grant(S#{holders := H#{Pid => erlang:monitor(process, Pid)},
                             waiting := W2});
                false ->
                    grant(S#{waiting := W2})
            end
    end;
grant(S) ->
    S.
