-module(beamchain_tx_ingest).
-behaviour(gen_server).

%%% P2P `tx` ingest, OFF the header/block sync loop.
%%%
%%% Every peer `tx` message used to be validated inside beamchain_sync,
%%% the one process that also routes every `headers`, `block`, `cmpctblock`
%%% and `inv`. AcceptToMemoryPool is a gen_server:call into the mempool with
%%% a 30 s timeout, so headers and blocks queued behind every tx in sync's
%%% mailbox. On mainnet (2026-10-07, 970297 and 970314) sync fell so far
%%% behind under box load that every getheaders reply reached header_sync
%%% after its 20 s probe window -- header sync never accepted a header for
%%% 30+ minutes and block download wedged (see beamchain_header_sync and
%%% beamchain_block_sync for the two latches that made it permanent).
%%%
%%% Core never lets transaction relay delay block relay: ProcessMessage
%%% handles each peer's messages in turn and ATMP is bounded per message
%%% (net_processing.cpp ProcessMessages, one message per peer per pass), and
%%% headers/blocks never wait in a queue behind another peer's txs.
%%%
%%% This process runs ATMP + relay for P2P txs, one at a time (the mempool
%%% serialises admission anyway). Tx relay is best effort, so when the
%%% backlog exceeds ?MAX_BACKLOG we drop the tx instead of growing the
%%% mailbox without bound (Core: a tx we fail to take is simply
%%% re-requested from another announcer later).
%%%
%%% If the process is not running (tests, early boot) submit/2 falls back
%%% to the old path through beamchain_sync, so behaviour degrades to the
%%% previous code, never to a lost message.

-export([start_link/0, submit/2, stats/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(SERVER, ?MODULE).
-define(MAX_BACKLOG, 2000).

-record(state, {
    processed = 0 :: non_neg_integer(),
    dropped   = 0 :: non_neg_integer(),
    last_drop_log = 0 :: integer()
}).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc Hand a P2P `tx` payload to the ingest process. Returns true when
%% it was taken, false when no ingest process is running (the caller then
%% routes it the old way).
-spec submit(pid(), binary()) -> boolean().
submit(Peer, Payload) ->
    case whereis(?SERVER) of
        undefined -> false;
        Pid -> gen_server:cast(Pid, {tx, Peer, Payload}), true
    end.

stats() ->
    gen_server:call(?SERVER, stats).

init([]) ->
    {ok, #state{}}.

handle_call(stats, _From, #state{processed = P, dropped = D} = State) ->
    {message_queue_len, Q} = process_info(self(), message_queue_len),
    {reply, #{processed => P, dropped => D, backlog => Q}, State};
handle_call(_Req, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast({tx, Peer, Payload}, State) ->
    {message_queue_len, Q} = process_info(self(), message_queue_len),
    case Q > ?MAX_BACKLOG of
        true ->
            {noreply, note_drop(Q, State)};
        false ->
            %% Never crash on one tx: a crash would lose the whole backlog.
            try beamchain_sync:process_tx(Peer, Payload)
            catch C:R ->
                logger:warning("tx_ingest: tx from ~p not processed: ~p:~p",
                               [Peer, C, R])
            end,
            {noreply, State#state{processed = State#state.processed + 1}}
    end;
handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

note_drop(Q, #state{dropped = D, last_drop_log = Last} = State) ->
    Now = erlang:monotonic_time(second),
    Last2 = case Now - Last >= 60 of
        true ->
            logger:warning("tx_ingest: backlog ~B > ~B -- dropping P2P txs "
                           "(~B dropped so far); block/header sync is "
                           "unaffected", [Q, ?MAX_BACKLOG, D + 1]),
            Now;
        false ->
            Last
    end,
    State#state{dropped = D + 1, last_drop_log = Last2}.
