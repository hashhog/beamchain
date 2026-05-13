-module(beamchain_sync).
-behaviour(gen_server).

%% Sync coordinator: routes P2P messages to the appropriate sync
%% sub-module (header_sync, block_sync) and manages overall sync
%% lifecycle.

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% Dialyzer suppressions for false positives:
%% route_message/4: _Error catch-all clauses are defensive; dialyzer infers
%% decode_payload always returns {ok,_} from the specific call sites here.
-dialyzer({nowarn_function, route_message/4}).

%% API
-export([start_link/0]).
-export([handle_peer_message/3]).
-export([notify_peer_connected/2, notify_peer_disconnected/1]).
-export([notify_headers_complete/1]).
-export([notify_blocks_complete/1]).
-export([get_sync_status/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2]).

-define(SERVER, ?MODULE).

%% How often to poll header sync status when waiting for completion
-define(HEADER_CHECK_INTERVAL, 2000).

-record(state, {
    %% Current sync phase: idle | headers | blocks | complete
    phase = idle :: idle | headers | blocks | complete,
    %% Header sync process
    header_sync :: pid() | undefined,
    %% Timer for checking header sync completion
    header_check_timer :: reference() | undefined
}).

%%% ===================================================================
%%% API
%%% ===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc Route a peer message to the correct sync handler.
%% Called by peer_manager when it gets a sync-related message.
-spec handle_peer_message(pid(), atom(), binary()) -> ok.
handle_peer_message(Peer, Command, Payload) ->
    gen_server:cast(?SERVER, {peer_message, Peer, Command, Payload}).

%% @doc Notify sync that a peer completed handshake.
-spec notify_peer_connected(pid(), map()) -> ok.
notify_peer_connected(Peer, Info) ->
    gen_server:cast(?SERVER, {peer_connected, Peer, Info}).

%% @doc Notify sync that a peer disconnected.
-spec notify_peer_disconnected(pid()) -> ok.
notify_peer_disconnected(Peer) ->
    gen_server:cast(?SERVER, {peer_disconnected, Peer}).

%% @doc Notify that header sync has completed with given tip height.
-spec notify_headers_complete(non_neg_integer()) -> ok.
notify_headers_complete(TipHeight) ->
    gen_server:cast(?SERVER, {headers_complete, TipHeight}).

%% @doc Notify that block sync has completed.
-spec notify_blocks_complete(non_neg_integer()) -> ok.
notify_blocks_complete(Height) ->
    gen_server:cast(?SERVER, {blocks_complete, Height}).

%% @doc Get overall sync status.
-spec get_sync_status() -> map().
get_sync_status() ->
    gen_server:call(?SERVER, get_sync_status).

%%% ===================================================================
%%% gen_server callbacks
%%% ===================================================================

init([]) ->
    {ok, #state{phase = idle}}.

handle_call(get_sync_status, _From, State) ->
    HeaderStatus = try beamchain_header_sync:get_status()
                   catch _:_ -> #{status => not_running} end,
    BlockStatus = try beamchain_block_sync:get_status()
                  catch _:_ -> #{status => not_running} end,
    Status = #{
        phase => State#state.phase,
        header_sync => HeaderStatus,
        block_sync => BlockStatus
    },
    {reply, Status, State};

handle_call(_Request, _From, State) ->
    {reply, {error, not_implemented}, State}.

%% Peer completed handshake — tell both header_sync and block_sync
handle_cast({peer_connected, Peer, Info}, State) ->
    beamchain_header_sync:handle_peer_connected(Peer, Info),
    beamchain_block_sync:handle_peer_connected(Peer, Info),
    %% If we're idle or complete, kick off header sync
    State2 = maybe_start_header_sync(State),
    {noreply, State2};

%% Peer disconnected
handle_cast({peer_disconnected, Peer}, State) ->
    beamchain_header_sync:handle_peer_disconnected(Peer),
    beamchain_block_sync:handle_peer_disconnected(Peer),
    {noreply, State};

%% Header sync completed — transition to block download phase
handle_cast({headers_complete, TipHeight}, #state{phase = headers} = State) ->
    logger:info("sync: headers complete at ~B, starting block download",
                [TipHeight]),
    State2 = cancel_header_check_timer(State),
    State3 = start_block_sync(TipHeight, State2),
    {noreply, State3};
handle_cast({headers_complete, TipHeight}, #state{phase = complete} = State) ->
    %% Re-entered header sync after being complete; download new blocks
    logger:info("sync: new headers found at ~B, starting block download",
                [TipHeight]),
    State2 = start_block_sync(TipHeight, State),
    {noreply, State2};
%% headers_complete arriving in phase=blocks (header_sync ran another round
%% while block download was still draining): forward the new target so
%% block_sync can extend its download queue. W18 fix: previously this was a
%% silent no-op, so any headers-tip advance during block download was lost.
handle_cast({headers_complete, TipHeight}, #state{phase = blocks} = State) ->
    logger:info("sync: headers advanced to ~B during block download, "
                "extending block_sync target", [TipHeight]),
    beamchain_block_sync:start_sync(#{target_height => TipHeight}),
    {noreply, State};
handle_cast({headers_complete, _TipHeight}, State) ->
    {noreply, State};

%% Block sync completed
handle_cast({blocks_complete, Height}, #state{phase = blocks} = State) ->
    logger:info("sync: block download complete at height ~B", [Height]),
    {noreply, State#state{phase = complete}};
handle_cast({blocks_complete, _Height}, State) ->
    {noreply, State};

%% Route peer messages to the right handler
handle_cast({peer_message, Peer, Command, Payload}, State) ->
    State2 = route_message(Peer, Command, Payload, State),
    {noreply, State2};

handle_cast(_Msg, State) ->
    {noreply, State}.

%% Periodically check if header sync has completed
handle_info(check_header_sync, #state{phase = headers} = State) ->
    State2 = check_header_sync_status(State),
    {noreply, State2};
handle_info(check_header_sync, State) ->
    {noreply, State#state{header_check_timer = undefined}};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, State) ->
    cancel_header_check_timer(State),
    ok.

%%% ===================================================================
%%% Internal: message routing
%%% ===================================================================

route_message(Peer, headers, Payload, State) ->
    case beamchain_p2p_msg:decode_payload(headers, Payload) of
        {ok, #{headers := Headers}} ->
            beamchain_header_sync:handle_headers(Peer, Headers);
        _Error ->
            beamchain_peer:add_misbehavior(Peer, 20)
    end,
    State;

route_message(Peer, block, Payload, State) ->
    case beamchain_p2p_msg:decode_payload(block, Payload) of
        {ok, Block} ->
            beamchain_block_sync:handle_block(Peer, Block);
        _Error ->
            beamchain_peer:add_misbehavior(Peer, 20)
    end,
    State;

route_message(Peer, notfound, Payload, State) ->
    case beamchain_p2p_msg:decode_payload(notfound, Payload) of
        {ok, #{items := Items}} ->
            %% Filter to block items and forward to block_sync
            BlockItems = [{Type, Hash} || #{type := Type, hash := Hash} <- Items,
                          Type =:= ?MSG_BLOCK orelse
                          Type =:= ?MSG_WITNESS_BLOCK],
            case BlockItems of
                [] -> ok;
                _ -> beamchain_block_sync:handle_notfound(Peer, BlockItems)
            end;
        _Error ->
            ok
    end,
    State;

route_message(Peer, inv, Payload, State) ->
    case beamchain_p2p_msg:decode_payload(inv, Payload) of
        {ok, #{items := Items}} ->
            %% Collect block inv items we don't already have
            BlockItems = lists:filter(fun(#{type := Type, hash := Hash}) ->
                (Type =:= ?MSG_BLOCK orelse Type =:= ?MSG_WITNESS_BLOCK)
                    andalso not beamchain_db:has_block(Hash);
                (_) -> false
            end, Items),
            case BlockItems of
                [] ->
                    State;
                _ ->
                    %% Directly request the announced blocks via getdata
                    %% so we don't depend on a getheaders round-trip.
                    %% Core protocol.h:482 — MAX_GETDATA_SZ=1000: an outgoing
                    %% getdata must not exceed 1000 items; chunk larger requests.
                    GetDataItems = [#{type => ?MSG_WITNESS_BLOCK,
                                      hash => Hash}
                                    || #{hash := Hash} <- BlockItems],
                    Chunks = beamchain_peer_manager:chunk_inv_items(
                                 GetDataItems, ?MAX_GETDATA_SZ),
                    lists:foreach(fun(Chunk) ->
                        beamchain_peer:send_message(Peer,
                            {getdata, #{items => Chunk}})
                    end, Chunks),
                    logger:info("sync: received block inv from ~p, "
                                "requesting ~B blocks via getdata (~B msg(s))",
                                [Peer, length(GetDataItems), length(Chunks)]),
                    %% Also kick off header sync if we think we're done,
                    %% so the header chain catches up too
                    case State#state.phase =:= complete of
                        true ->
                            beamchain_header_sync:start_sync(#{}),
                            Timer = erlang:send_after(?HEADER_CHECK_INTERVAL,
                                                      self(), check_header_sync),
                            State#state{phase = headers,
                                        header_check_timer = Timer};
                        false ->
                            State
                    end
            end;
        _Error ->
            State
    end;

%% BIP152 compact block messages
route_message(Peer, cmpctblock, Payload, State) ->
    case beamchain_p2p_msg:decode_payload(cmpctblock, Payload) of
        {ok, CmpctBlock} ->
            beamchain_block_sync:handle_cmpctblock(Peer, CmpctBlock);
        _Error ->
            beamchain_peer:add_misbehavior(Peer, 20)
    end,
    State;

route_message(Peer, blocktxn, Payload, State) ->
    case beamchain_p2p_msg:decode_payload(blocktxn, Payload) of
        {ok, BlockTxn} ->
            beamchain_block_sync:handle_blocktxn(Peer, BlockTxn);
        _Error ->
            beamchain_peer:add_misbehavior(Peer, 20)
    end,
    State;

%% BIP152: Handle getblocktxn - peer requests missing transactions for a compact block
route_message(Peer, getblocktxn, Payload, State) ->
    case beamchain_p2p_msg:decode_payload(getblocktxn, Payload) of
        {ok, #{block_hash := BlockHash, indexes := Indexes}} ->
            logger:debug("sync: getblocktxn from ~p for ~s (~B indexes)",
                         [Peer, beamchain_serialize:hex_encode(BlockHash),
                          length(Indexes)]),
            %% Look up the full block and respond with requested transactions
            case beamchain_db:get_block(BlockHash) of
                {ok, Block} ->
                    Txs = Block#block.transactions,
                    TxArray = list_to_tuple(Txs),
                    RequestedTxs = lists:filtermap(
                        fun(Idx) ->
                            %% Indexes are 0-based
                            ArrIdx = Idx + 1,
                            if ArrIdx >= 1, ArrIdx =< tuple_size(TxArray) ->
                                {true, element(ArrIdx, TxArray)};
                               true ->
                                false
                            end
                        end, Indexes),
                    beamchain_peer:send_message(Peer,
                        {blocktxn, #{block_hash => BlockHash,
                                     transactions => RequestedTxs}});
                not_found ->
                    logger:debug("sync: getblocktxn block not found: ~s",
                                 [beamchain_serialize:hex_encode(BlockHash)])
            end;
        _Error ->
            beamchain_peer:add_misbehavior(Peer, 20)
    end,
    State;

%% Handle incoming tx message: validate via AcceptToMemoryPool and relay
route_message(Peer, tx, Payload, State) ->
    case beamchain_p2p_msg:decode_payload(tx, Payload) of
        {ok, Tx} ->
            case beamchain_mempool:accept_to_memory_pool(Tx) of
                {ok, Txid} ->
                    logger:info("sync: accepted tx ~s from ~p",
                                [beamchain_serialize:hex_encode(Txid), Peer]),
                    %% Relay to all peers via inv
                    beamchain_peer_manager:broadcast(inv, #{
                        items => [#{type => ?MSG_TX, hash => Txid}]
                    });
                {error, Reason} ->
                    logger:debug("sync: rejected tx from ~p: ~p", [Peer, Reason])
            end;
        _Error ->
            beamchain_peer:add_misbehavior(Peer, 20)
    end,
    State;

route_message(_Peer, _Command, _Payload, State) ->
    State.

%%% ===================================================================
%%% Internal: sync lifecycle
%%% ===================================================================

maybe_start_header_sync(#state{phase = idle} = State) ->
    beamchain_header_sync:start_sync(#{}),
    %% Start polling for header sync completion
    Timer = erlang:send_after(?HEADER_CHECK_INTERVAL, self(),
                               check_header_sync),
    State#state{phase = headers, header_check_timer = Timer};
maybe_start_header_sync(#state{phase = complete} = State) ->
    %% After completing sync, allow re-entering header sync when new
    %% peers connect that may have newer blocks.
    beamchain_header_sync:start_sync(#{}),
    Timer = erlang:send_after(?HEADER_CHECK_INTERVAL, self(),
                               check_header_sync),
    State#state{phase = headers, header_check_timer = Timer};
maybe_start_header_sync(State) ->
    State.

%% Poll header sync status and transition if complete.
check_header_sync_status(State) ->
    try
        Status = beamchain_header_sync:get_status(),
        case maps:get(status, Status, undefined) of
            complete ->
                TipHeight = maps:get(tip_height, Status, 0),
                logger:info("sync: detected header sync complete at ~B",
                            [TipHeight]),
                start_block_sync(TipHeight, State);
            _ ->
                %% Not complete yet, keep polling
                Timer = erlang:send_after(?HEADER_CHECK_INTERVAL, self(),
                                           check_header_sync),
                State#state{header_check_timer = Timer}
        end
    catch
        _:_ ->
            Timer2 = erlang:send_after(?HEADER_CHECK_INTERVAL, self(),
                                        check_header_sync),
            State#state{header_check_timer = Timer2}
    end.

%% Start the block sync phase.
start_block_sync(TargetHeight, State) ->
    beamchain_block_sync:start_sync(#{
        target_height => TargetHeight
    }),
    State#state{phase = blocks, header_check_timer = undefined}.

cancel_header_check_timer(#state{header_check_timer = undefined} = State) ->
    State;
cancel_header_check_timer(#state{header_check_timer = Ref} = State) ->
    erlang:cancel_timer(Ref),
    receive check_header_sync -> ok after 0 -> ok end,
    State#state{header_check_timer = undefined}.
