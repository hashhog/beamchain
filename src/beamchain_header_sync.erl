-module(beamchain_header_sync).
-behaviour(gen_server).

%% Header-first synchronization: download and validate the full
%% header chain from peers before downloading blocks.
%%
%% Algorithm:
%%  1. Build block locator from current tip
%%  2. Send getheaders to best peer
%%  3. Receive up to 2000 headers
%%  4. Validate each: prev_hash, PoW, difficulty, MTP, checkpoints
%%  5. Store in block_index with accumulated chainwork
%%  6. Repeat until peer has no more headers

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% API
-export([start_link/0,
         start_sync/1,
         stop_sync/0,
         handle_headers/2,
         handle_peer_connected/2,
         handle_peer_disconnected/1,
         get_status/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2]).

-define(SERVER, ?MODULE).

%% Timeout for a getheaders request before trying a different peer
-define(GETHEADERS_TIMEOUT, 20000).

%% Maximum future time for a block header (2 hours)
-define(MAX_FUTURE_DRIFT, 7200).

%% Number of timestamps to keep for MTP calculation
-define(MTP_WINDOW, 11).

%% Anti-DoS: Maximum unconnecting headers per peer before disconnect.
%% If a peer sends more than this many headers that don't connect to our
%% chain, we consider them misbehaving and disconnect.
-define(MAX_UNCONNECTING_HEADERS, 10).

%% Anti-DoS: Minimum reorg depth requiring more cumulative work.
%% Headers forking more than this many blocks deep must have more
%% cumulative work than our current tip to be accepted.
-define(MIN_FORK_DEPTH_FOR_WORK_CHECK, 288).

-record(state, {
    %% Current sync status: idle | syncing | complete
    status = idle           :: idle | syncing | complete,
    %% The peer we're syncing from
    sync_peer               :: pid() | undefined,
    %% Current best header tip (height, hash)
    tip_height = -1         :: integer(),
    tip_hash = <<0:256>>    :: binary(),
    %% Accumulated chainwork at the tip (big integer as binary)
    tip_chainwork = <<0:256>> :: binary(),
    %% Sliding window of last 11 timestamps for MTP
    mtp_window = []         :: [{non_neg_integer(), non_neg_integer()}],
    %% Chain params map
    params = #{}            :: map(),
    %% Timer reference for getheaders timeout
    timer_ref               :: reference() | undefined,
    %% Number of headers received in this sync session
    headers_received = 0    :: non_neg_integer(),
    %% Estimated total (from peer's start_height), 0 = unknown
    estimated_tip = 0       :: non_neg_integer(),
    %% Progress callback: fun(InfoMap) or undefined
    progress_cb             :: function() | undefined,
    %% Known connected peers with their heights: #{Pid => Height}
    peer_heights = #{}      :: #{pid() => non_neg_integer()},
    %% Anti-DoS: Per-peer state tracking
    %% #{Pid => #{unconnecting_count => N, last_header_hash => Hash}}
    peer_header_state = #{} :: #{pid() => map()}
}).

%%% ===================================================================
%%% API
%%% ===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc Start syncing headers from peers.
%% Options: #{progress_cb => fun(InfoMap)}
-spec start_sync(map()) -> ok | {error, term()}.
start_sync(Opts) ->
    gen_server:cast(?SERVER, {start_sync, Opts}).

%% @doc Stop the current sync.
-spec stop_sync() -> ok.
stop_sync() ->
    gen_server:cast(?SERVER, stop_sync).

%% @doc Called when a peer sends us a headers message.
-spec handle_headers(pid(), [#block_header{}]) -> ok.
handle_headers(Peer, Headers) ->
    gen_server:cast(?SERVER, {headers, Peer, Headers}).

%% @doc Notify that a peer completed handshake.
-spec handle_peer_connected(pid(), map()) -> ok.
handle_peer_connected(Peer, Info) ->
    gen_server:cast(?SERVER, {peer_connected, Peer, Info}).

%% @doc Notify that a peer disconnected.
-spec handle_peer_disconnected(pid()) -> ok.
handle_peer_disconnected(Peer) ->
    gen_server:cast(?SERVER, {peer_disconnected, Peer}).

%% @doc Get current sync status.
-spec get_status() -> map().
get_status() ->
    gen_server:call(?SERVER, get_status).

%%% ===================================================================
%%% gen_server callbacks
%%% ===================================================================

init([]) ->
    Network = beamchain_config:network(),
    Params = beamchain_chain_params:params(Network),
    %% Load current chain tip from DB
    {TipHeight, TipHash, TipChainwork, MTPWindow} = load_chain_tip(Params),
    logger:info("header_sync: initialized at height ~B", [TipHeight]),
    {ok, #state{
        tip_height = TipHeight,
        tip_hash = TipHash,
        tip_chainwork = TipChainwork,
        mtp_window = MTPWindow,
        params = Params
    }}.

handle_call(get_status, _From, State) ->
    Status = #{
        status => State#state.status,
        tip_height => State#state.tip_height,
        tip_hash => State#state.tip_hash,
        headers_received => State#state.headers_received,
        estimated_tip => State#state.estimated_tip,
        sync_peer => State#state.sync_peer,
        peer_count => maps:size(State#state.peer_heights)
    },
    {reply, Status, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast({start_sync, Opts}, #state{status = Status} = State)
  when Status =:= idle; Status =:= complete ->
    ProgressCb = maps:get(progress_cb, Opts, undefined),
    State2 = State#state{progress_cb = ProgressCb, status = idle},
    State3 = pick_sync_peer_and_start(State2),
    {noreply, State3};
handle_cast({start_sync, _Opts}, State) ->
    %% Already syncing
    {noreply, State};

handle_cast(stop_sync, State) ->
    State2 = cancel_timer(State),
    {noreply, State2#state{status = idle, sync_peer = undefined}};

handle_cast({headers, Peer, Headers}, #state{status = syncing,
                                              sync_peer = Peer} = State) ->
    State2 = cancel_timer(State),
    %% Anti-DoS: Validate PoW and continuity before any processing
    case check_headers_pow_and_continuity(Headers, State2) of
        ok ->
            State3 = process_headers(Headers, Peer, State2),
            {noreply, State3};
        {error, invalid_pow} ->
            logger:warning("header_sync: peer ~p sent header with invalid PoW", [Peer]),
            {noreply, handle_misbehaving_peer(Peer, 100, State2)};
        {error, non_continuous} ->
            logger:warning("header_sync: peer ~p sent non-continuous headers", [Peer]),
            {noreply, handle_misbehaving_peer(Peer, 100, State2)}
    end;
handle_cast({headers, _Peer, _Headers}, State) ->
    %% Headers from a peer we're not syncing from, ignore
    {noreply, State};

handle_cast({peer_connected, Peer, Info}, State) ->
    PeerHeight = maps:get(start_height, Info, 0),
    PeerHeights = maps:put(Peer, PeerHeight, State#state.peer_heights),
    State2 = State#state{peer_heights = PeerHeights},
    %% If we're idle or complete and this peer is ahead, start syncing
    case State2#state.status of
        Status when (Status =:= idle orelse Status =:= complete),
                    PeerHeight > State2#state.tip_height ->
            State3 = State2#state{status = idle},
            State4 = pick_sync_peer_and_start(State3),
            {noreply, State4};
        _ ->
            {noreply, State2}
    end;

handle_cast({peer_disconnected, Peer}, State) ->
    %% Clean up all peer state
    State2 = remove_peer_state(Peer, State),
    case State2#state.sync_peer of
        Peer ->
            %% Our sync peer disconnected, try another
            logger:info("header_sync: sync peer disconnected, trying another"),
            State3 = cancel_timer(State2),
            State4 = State3#state{sync_peer = undefined, status = idle},
            State5 = pick_sync_peer_and_start(State4),
            {noreply, State5};
        _ ->
            {noreply, State2}
    end;

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(getheaders_timeout, #state{status = syncing} = State) ->
    logger:debug("header_sync: getheaders timed out from ~p",
                 [State#state.sync_peer]),
    %% Try a different peer
    OldPeer = State#state.sync_peer,
    State2 = State#state{sync_peer = undefined, timer_ref = undefined},
    State3 = pick_sync_peer_and_start(State2),
    case State3#state.sync_peer of
        OldPeer ->
            %% Same peer picked again (only one available), retry anyway
            {noreply, State3};
        _ ->
            {noreply, State3}
    end;
handle_info(getheaders_timeout, State) ->
    {noreply, State#state{timer_ref = undefined}};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

%%% ===================================================================
%%% Internal: sync orchestration
%%% ===================================================================

%% Pick the best peer (highest start_height) and begin sync.
pick_sync_peer_and_start(#state{peer_heights = PeerHeights,
                                 tip_height = TipHeight} = State) ->
    case select_best_peer(PeerHeights, TipHeight) of
        {ok, Peer, PeerHeight} ->
            logger:info("header_sync: syncing from ~p (height ~B, we have ~B)",
                        [Peer, PeerHeight, TipHeight]),
            State2 = State#state{
                status = syncing,
                sync_peer = Peer,
                estimated_tip = PeerHeight,
                headers_received = 0
            },
            send_getheaders(State2);
        none ->
            %% No peer ahead of us. If we have any peers, we're caught up.
            case maps:size(PeerHeights) > 0 andalso TipHeight > 0 of
                true ->
                    logger:info("header_sync: already at tip ~B, marking complete",
                                [TipHeight]),
                    beamchain_sync:notify_headers_complete(TipHeight),
                    State#state{status = complete, sync_peer = undefined};
                false ->
                    logger:debug("header_sync: no suitable peer to sync from"),
                    State#state{status = idle}
            end
    end.

%% Select the connected peer with the most work (highest announced height).
select_best_peer(PeerHeights, OurHeight) ->
    Candidates = maps:to_list(PeerHeights),
    Ahead = [{Pid, H} || {Pid, H} <- Candidates, H > OurHeight],
    case Ahead of
        [] -> none;
        _ ->
            {BestPid, BestHeight} = lists:foldl(
                fun({P, H}, {_BP, BH}) when H > BH -> {P, H};
                   (_, Best) -> Best
                end, hd(Ahead), tl(Ahead)),
            {ok, BestPid, BestHeight}
    end.

%% Build block locator and send getheaders to the sync peer.
send_getheaders(#state{sync_peer = Peer, tip_height = TipHeight,
                        tip_hash = TipHash} = State) ->
    Locator = build_block_locator(TipHeight, TipHash),
    Msg = #{
        version => ?PROTOCOL_VERSION,
        locators => Locator,
        stop_hash => <<0:256>>
    },
    beamchain_peer:send_message(Peer, {getheaders, Msg}),
    %% Set timeout
    TimerRef = erlang:send_after(?GETHEADERS_TIMEOUT, self(),
                                 getheaders_timeout),
    report_progress(State),
    State#state{timer_ref = TimerRef}.

%%% ===================================================================
%%% Internal: block locator construction
%%% ===================================================================

%% Build a block locator: exponentially spaced hashes going back
%% from the tip, ending with genesis.
%% [tip, tip-1, tip-2, tip-4, tip-8, ..., genesis]
-spec build_block_locator(integer(), binary()) -> [binary()].
build_block_locator(Height, _TipHash) when Height < 0 ->
    %% No headers at all, use genesis hash in internal byte order
    Network = beamchain_config:network(),
    Params = beamchain_chain_params:params(Network),
    Genesis = maps:get(genesis_block, Params),
    [beamchain_serialize:block_hash(Genesis#block.header)];
build_block_locator(Height, TipHash) ->
    build_locator_hashes(Height, TipHash, 1, []).

build_locator_hashes(Height, Hash, _Step, Acc) when Height =< 0 ->
    %% Always include genesis at the end
    case beamchain_db:get_block_index(0) of
        {ok, #{hash := GenesisHash}} ->
            Hashes = lists:reverse([Hash | Acc]),
            case lists:last(Hashes) =:= GenesisHash of
                true -> Hashes;
                false -> Hashes ++ [GenesisHash]
            end;
        not_found ->
            lists:reverse([Hash | Acc])
    end;
build_locator_hashes(Height, Hash, Step, Acc) ->
    %% Add current hash
    Acc2 = [Hash | Acc],
    %% Calculate next height to include
    NextHeight = max(0, Height - Step),
    %% After 10 entries, start doubling the step
    Step2 = case length(Acc2) >= 10 of
        true -> Step * 2;
        false -> 1
    end,
    %% Look up the hash at the next height
    case beamchain_db:get_block_index(NextHeight) of
        {ok, #{hash := NextHash}} ->
            build_locator_hashes(NextHeight, NextHash, Step2, Acc2);
        not_found ->
            lists:reverse(Acc2)
    end.

%%% ===================================================================
%%% Internal: header processing
%%% ===================================================================

process_headers([], _Peer, State) ->
    %% Empty response: peer has no new headers for us
    %% Check if we should try another peer or declare complete
    logger:info("header_sync: peer sent 0 headers, checking if in sync"),
    check_sync_complete(State);

process_headers(Headers, Peer, State) ->
    %% Check if headers connect to our chain
    FirstHeader = hd(Headers),
    case headers_connect_to_chain(FirstHeader, State) of
        true ->
            %% Headers connect - reset unconnecting counter and process
            State2 = reset_unconnecting_count(Peer, State),
            process_connecting_headers(Headers, Peer, State2);
        false ->
            %% Headers don't connect to our tip. Check if this is a
            %% reorg: the headers may connect to an earlier known block
            %% in our chain (or a known fork block).
            case check_reorg(FirstHeader, Headers, State) of
                {reorg, ForkHeight, _ForkHash, _ForkCW, State2} ->
                    %% Reorg detected: headers connect to a known block
                    %% that is an ancestor of our tip. Roll back and
                    %% process the new (more-work) chain.
                    logger:info("header_sync: reorg detected at height ~B, "
                                "rolling back from ~B",
                                [ForkHeight, State#state.tip_height]),
                    State3 = reset_unconnecting_count(Peer, State2),
                    process_connecting_headers(Headers, Peer, State3);
                no_reorg ->
                    %% Not a recognized reorg - handle as unconnecting
                    handle_unconnecting_headers(Headers, Peer, State)
            end
    end.

%% Check if a header connects to our current chain tip
headers_connect_to_chain(Header, #state{tip_hash = TipHash}) ->
    Header#block_header.prev_hash =:= TipHash.

%% Check if unconnecting headers represent a reorg (fork with more work).
%% If the first header's prev_hash points to a known block in our index,
%% the peer is offering an alternative chain from that fork point.
check_reorg(FirstHeader, Headers, #state{tip_height = TipHeight,
                                          tip_chainwork = TipCW,
                                          params = Params} = State) ->
    PrevHash = FirstHeader#block_header.prev_hash,
    case beamchain_db:get_block_index_by_hash(PrevHash) of
        {ok, #{height := ForkHeight, chainwork := ForkCW}} ->
            %% The headers connect to a known block at ForkHeight.
            %% Estimate the incoming chain's work: fork chainwork +
            %% work from the new headers.
            NewWork = lists:foldl(fun(H, Acc) ->
                Acc + beamchain_pow:compute_work(H#block_header.bits)
            end, 0, Headers),
            ForkCWInt = binary:decode_unsigned(ForkCW, big),
            IncomingCWInt = ForkCWInt + NewWork,
            TipCWInt = binary:decode_unsigned(TipCW, big),
            case IncomingCWInt > TipCWInt orelse
                 (length(Headers) + ForkHeight > TipHeight andalso
                  ForkHeight >= TipHeight - 10) of
                true ->
                    %% More work (or a shallow fork where the peer
                    %% likely has more headers to send). Accept reorg.
                    logger:info("header_sync: fork at height ~B "
                                "(depth ~B), incoming work ~B vs tip ~B",
                                [ForkHeight,
                                 TipHeight - ForkHeight,
                                 IncomingCWInt, TipCWInt]),
                    %% Mark orphaned blocks as invalid in the index
                    mark_orphaned_blocks(ForkHeight + 1, TipHeight),
                    %% Roll back state to the fork point
                    State2 = rollback_to(ForkHeight, PrevHash, ForkCW,
                                          Params, State),
                    {reorg, ForkHeight, PrevHash, ForkCW, State2};
                false ->
                    %% Less work - don't reorg
                    logger:debug("header_sync: ignoring fork at ~B "
                                 "(less work)", [ForkHeight]),
                    no_reorg
            end;
        not_found ->
            %% prev_hash not in our index at all
            no_reorg
    end.

%% Mark blocks from StartHeight to EndHeight as orphaned (failed valid).
mark_orphaned_blocks(StartHeight, EndHeight) when StartHeight > EndHeight ->
    ok;
mark_orphaned_blocks(Height, EndHeight) ->
    case beamchain_db:get_block_index(Height) of
        {ok, #{hash := Hash}} ->
            %% Mark as failed validation (orphaned)
            beamchain_db:update_block_status(Hash, 32),
            mark_orphaned_blocks(Height + 1, EndHeight);
        not_found ->
            ok
    end.

%% Roll back the header sync state to a given fork point.
rollback_to(ForkHeight, ForkHash, ForkCW, Params, State) ->
    %% Update header tip in DB
    ok = beamchain_db:set_header_tip(ForkHash, ForkHeight),
    %% Also disconnect blocks from the chainstate (UTXO set) back to
    %% the fork point. Without this, the UTXO set still contains
    %% outputs from the orphaned blocks, causing BIP30 failures.
    disconnect_chainstate_to(ForkHeight),
    %% Rebuild MTP window from the fork point
    MTPWindow = load_mtp_window(ForkHeight, Params),
    State#state{
        tip_height = ForkHeight,
        tip_hash = ForkHash,
        tip_chainwork = ForkCW,
        mtp_window = MTPWindow
    }.

%% Disconnect blocks from the chainstate until the chainstate tip is
%% at or below TargetHeight. Uses undo data to reverse UTXO changes.
disconnect_chainstate_to(TargetHeight) ->
    case beamchain_chainstate:get_tip() of
        {ok, {_Hash, TipHeight}} when TipHeight > TargetHeight ->
            logger:info("header_sync: disconnecting chainstate from ~B to ~B",
                        [TipHeight, TargetHeight]),
            disconnect_chainstate_loop(TargetHeight);
        _ ->
            %% Chainstate is already at or below fork point
            ok
    end.

disconnect_chainstate_loop(TargetHeight) ->
    case beamchain_chainstate:get_tip() of
        {ok, {_Hash, TipHeight}} when TipHeight > TargetHeight ->
            case beamchain_chainstate:disconnect_block() of
                ok ->
                    disconnect_chainstate_loop(TargetHeight);
                {error, Reason} ->
                    logger:error("header_sync: chainstate disconnect failed: ~p",
                                 [Reason]),
                    %% Continue anyway — block sync will handle the mismatch
                    ok
            end;
        _ ->
            ok
    end.

%% Process headers that connect to our chain
process_connecting_headers(Headers, Peer, State) ->
    case validate_and_store_headers(Headers, State) of
        {ok, State2} ->
            NumReceived = length(Headers),
            Total = State2#state.headers_received + NumReceived,
            State3 = State2#state{headers_received = Total},
            report_progress(State3),
            case NumReceived >= ?MAX_HEADERS_RESULTS of
                true ->
                    %% Peer likely has more, request next batch
                    send_getheaders(State3);
                false ->
                    %% Got fewer than 2000, peer's tip reached
                    logger:info("header_sync: received ~B headers "
                                "(~B total, tip at ~B)",
                                [NumReceived, Total,
                                 State3#state.tip_height]),
                    check_sync_complete(State3)
            end;
        {error, Reason, State2} ->
            logger:warning("header_sync: validation failed: ~p", [Reason]),
            %% Misbehaving peer, try another
            beamchain_peer:add_misbehavior(Peer, 20),
            State3 = State2#state{sync_peer = undefined, status = idle},
            pick_sync_peer_and_start(State3)
    end.

%% Handle headers that don't connect to our chain tip
handle_unconnecting_headers(Headers, Peer, State) ->
    %% Increment unconnecting counter for this peer
    PeerState = get_peer_header_state(Peer, State),
    UnconnectingCount = maps:get(unconnecting_count, PeerState, 0) + 1,

    case UnconnectingCount > ?MAX_UNCONNECTING_HEADERS of
        true ->
            %% Peer has sent too many unconnecting headers - disconnect
            logger:warning("header_sync: peer ~p exceeded max unconnecting "
                          "headers (~B), disconnecting",
                          [Peer, ?MAX_UNCONNECTING_HEADERS]),
            handle_misbehaving_peer(Peer, 100, State);
        false ->
            %% Check if this might be a deep fork requiring more work
            FirstHeader = hd(Headers),
            case check_deep_fork(FirstHeader, State) of
                ok ->
                    %% Send getheaders to try to connect the chain
                    State2 = update_peer_unconnecting_count(Peer, UnconnectingCount, State),
                    logger:debug("header_sync: unconnecting headers from ~p "
                                "(count ~B), sending getheaders",
                                [Peer, UnconnectingCount]),
                    %% Record last unconnecting header for potential later use
                    LastHash = beamchain_serialize:block_hash(lists:last(Headers)),
                    State3 = update_peer_last_header(Peer, LastHash, State2),
                    send_getheaders(State3);
                {error, deep_fork_insufficient_work} ->
                    %% Deep fork without sufficient work - reject
                    logger:warning("header_sync: peer ~p sent deep fork headers "
                                  "without sufficient work", [Peer]),
                    handle_misbehaving_peer(Peer, 20, State)
            end
    end.

%%% ===================================================================
%%% Anti-DoS: PoW and continuity checks
%%% ===================================================================

%% Validate PoW on all headers and check continuity before any processing.
%% This prevents memory exhaustion from invalid headers.
-spec check_headers_pow_and_continuity([#block_header{}], #state{}) ->
    ok | {error, invalid_pow | non_continuous}.
check_headers_pow_and_continuity([], _State) ->
    ok;
check_headers_pow_and_continuity(Headers, #state{params = Params}) ->
    PowLimit = maps:get(pow_limit, Params),
    check_headers_pow_and_continuity(Headers, PowLimit, undefined).

check_headers_pow_and_continuity([], _PowLimit, _PrevHash) ->
    ok;
check_headers_pow_and_continuity([Header | Rest], PowLimit, PrevHash) ->
    BlockHash = beamchain_serialize:block_hash(Header),
    %% Check PoW: block hash must be <= target <= pow_limit
    case beamchain_pow:check_pow(BlockHash, Header#block_header.bits, PowLimit) of
        false ->
            {error, invalid_pow};
        true ->
            %% Check continuity: each header's prev_hash must match previous
            case PrevHash of
                undefined ->
                    %% First header - skip continuity check (will check connection later)
                    check_headers_pow_and_continuity(Rest, PowLimit, BlockHash);
                _ when Header#block_header.prev_hash =:= PrevHash ->
                    check_headers_pow_and_continuity(Rest, PowLimit, BlockHash);
                _ ->
                    {error, non_continuous}
            end
    end.

%% Handle a misbehaving peer: add misbehavior score and try another peer
handle_misbehaving_peer(Peer, Score, State) ->
    beamchain_peer:add_misbehavior(Peer, Score),
    %% Remove peer from tracking
    State2 = remove_peer_state(Peer, State),
    State3 = State2#state{sync_peer = undefined, status = idle},
    pick_sync_peer_and_start(State3).

%%% ===================================================================
%%% Anti-DoS: Per-peer state management
%%% ===================================================================

%% Get the header state for a specific peer
get_peer_header_state(Peer, #state{peer_header_state = PeerStates}) ->
    maps:get(Peer, PeerStates, #{}).

%% Reset the unconnecting header count for a peer (they sent connecting headers)
reset_unconnecting_count(Peer, #state{peer_header_state = PeerStates} = State) ->
    PeerState = maps:get(Peer, PeerStates, #{}),
    PeerState2 = PeerState#{unconnecting_count => 0},
    State#state{peer_header_state = maps:put(Peer, PeerState2, PeerStates)}.

%% Update the unconnecting header count for a peer
update_peer_unconnecting_count(Peer, Count, #state{peer_header_state = PeerStates} = State) ->
    PeerState = maps:get(Peer, PeerStates, #{}),
    PeerState2 = PeerState#{unconnecting_count => Count},
    State#state{peer_header_state = maps:put(Peer, PeerState2, PeerStates)}.

%% Record the last header hash received from a peer (for future download)
update_peer_last_header(Peer, Hash, #state{peer_header_state = PeerStates} = State) ->
    PeerState = maps:get(Peer, PeerStates, #{}),
    PeerState2 = PeerState#{last_header_hash => Hash},
    State#state{peer_header_state = maps:put(Peer, PeerState2, PeerStates)}.

%% Remove all state for a peer
remove_peer_state(Peer, #state{peer_header_state = PeerStates,
                                peer_heights = PeerHeights} = State) ->
    State#state{
        peer_header_state = maps:remove(Peer, PeerStates),
        peer_heights = maps:remove(Peer, PeerHeights)
    }.

%%% ===================================================================
%%% Anti-DoS: Deep fork protection
%%% ===================================================================

%% Check if headers represent a deep fork that requires more work.
%% If headers fork more than 288 blocks from our tip, they must have
%% more cumulative work to be accepted.
check_deep_fork(FirstHeader, #state{tip_height = TipHeight,
                                     tip_chainwork = TipCW,
                                     params = Params}) ->
    %% Try to find where this header connects to our chain
    case find_fork_point(FirstHeader#block_header.prev_hash) of
        {ok, ForkHeight, _ForkChainwork} ->
            Depth = TipHeight - ForkHeight,
            case Depth > ?MIN_FORK_DEPTH_FOR_WORK_CHECK of
                true ->
                    %% Deep fork - would need to check if incoming chain has more work
                    %% Since we don't have all headers yet, we can't know the work
                    %% For now, we allow it if we haven't passed min_chainwork
                    MinChainwork = maps:get(min_chainwork, Params, <<0:256>>),
                    TipCWInt = binary:decode_unsigned(TipCW, big),
                    MinCWInt = binary:decode_unsigned(MinChainwork, big),
                    case TipCWInt < MinCWInt of
                        true ->
                            %% Still in IBD, allow deep forks
                            ok;
                        false ->
                            %% Past minimum chainwork - reject deep forks without proof
                            %% Note: In a full implementation, we'd track the fork's
                            %% claimed work and verify it exceeds ours
                            {error, deep_fork_insufficient_work}
                    end;
                false ->
                    %% Shallow fork, allow
                    ok
            end;
        not_found ->
            %% Can't find fork point - this is an unconnecting header
            %% Allow it for now, the getheaders will try to connect
            ok
    end.

%% Find the fork point for a given previous hash
find_fork_point(PrevHash) ->
    case beamchain_db:get_block_index_by_hash(PrevHash) of
        {ok, #{height := Height, chainwork := CW}} ->
            {ok, Height, CW};
        not_found ->
            not_found
    end.

%%% ===================================================================
%%% Internal: sync completion check
%%% ===================================================================

%% Check if we're fully synced or need to try another peer.
check_sync_complete(#state{peer_heights = PeerHeights,
                            tip_height = TipHeight} = State) ->
    %% See if any peer claims to have more headers
    MaxPeerHeight = maps:fold(fun(_Pid, H, Max) ->
        max(H, Max)
    end, 0, PeerHeights),
    case MaxPeerHeight > TipHeight of
        true ->
            %% Some peer claims to be ahead, try syncing from them
            State2 = State#state{sync_peer = undefined, status = idle},
            pick_sync_peer_and_start(State2);
        false ->
            logger:info("header_sync: sync complete at height ~B",
                        [TipHeight]),
            %% Notify sync coordinator that headers are done
            beamchain_sync:notify_headers_complete(TipHeight),
            State#state{status = complete, sync_peer = undefined}
    end.

%% Validate a batch of headers and store them.
validate_and_store_headers([], State) ->
    {ok, State};
validate_and_store_headers([Header | Rest], State) ->
    case validate_one_header(Header, State) of
        {ok, State2} ->
            validate_and_store_headers(Rest, State2);
        {error, Reason} ->
            {error, Reason, State}
    end.

%% Validate a single header against our current tip.
validate_one_header(Header, #state{tip_height = TipHeight,
                                    tip_hash = TipHash,
                                    tip_chainwork = TipCW,
                                    mtp_window = MTPWindow,
                                    params = Params} = State) ->
    NewHeight = TipHeight + 1,
    BlockHash = beamchain_serialize:block_hash(Header),
    PowLimit = maps:get(pow_limit, Params),

    try
        %% 1. prev_hash must connect to our tip
        Header#block_header.prev_hash =:= TipHash
            orelse throw(bad_prev_hash),

        %% 2. PoW: block hash <= target, target <= pow_limit
        beamchain_pow:check_pow(BlockHash, Header#block_header.bits, PowLimit)
            orelse throw(high_hash),

        %% 3. Timestamp must be > MTP
        MTP = compute_mtp(MTPWindow),
        Header#block_header.timestamp > MTP
            orelse throw(time_too_old),

        %% 4. Timestamp must be < now + 2 hours
        Now = erlang:system_time(second),
        Header#block_header.timestamp =< Now + ?MAX_FUTURE_DRIFT
            orelse throw(time_too_new),

        %% 5. Difficulty must match expected
        PrevIndex = #{height => TipHeight, header => prev_header(State),
                      chainwork => TipCW},
        ExpectedBits = beamchain_pow:get_next_work_required(
            PrevIndex, Header, Params),
        Header#block_header.bits =:= ExpectedBits
            orelse throw(bad_diffbits),

        %% 6. Checkpoint enforcement (exact match at checkpoint heights)
        check_checkpoint(NewHeight, BlockHash, Params),

        %% 6b. Enhanced checkpoint enforcement: reject headers that would
        %% fork below the last checkpoint (anti-DoS measure)
        case check_checkpoint_ancestry(NewHeight, BlockHash, Params) of
            ok -> ok;
            {error, checkpoint_ancestry_mismatch} -> throw(checkpoint_ancestry_mismatch)
        end,

        %% 7. BIP94 (testnet4): first block of retarget period
        check_bip94(NewHeight, Header, State),

        %% 8. Calculate chainwork
        BlockWork = beamchain_pow:compute_work(Header#block_header.bits),
        PrevCWInt = binary:decode_unsigned(TipCW, big),
        NewCWInt = PrevCWInt + BlockWork,
        NewCW = chainwork_to_binary(NewCWInt),

        %% 9. Store in block index
        %% Status 1 = headers only (not fully validated with block data)
        ok = beamchain_db:store_block_index(NewHeight, BlockHash, Header,
                                             NewCW, 1),

        %% 10. Update chain tip in DB
        ok = beamchain_db:set_header_tip(BlockHash, NewHeight),

        %% 11. Update MTP window
        NewMTPWindow = update_mtp_window(MTPWindow, NewHeight,
                                          Header#block_header.timestamp),

        {ok, State#state{
            tip_height = NewHeight,
            tip_hash = BlockHash,
            tip_chainwork = NewCW,
            mtp_window = NewMTPWindow
        }}
    catch
        throw:Reason -> {error, Reason}
    end.

%% Get the header record for the current tip (needed for difficulty calc).
prev_header(#state{tip_height = -1, params = Params}) ->
    Genesis = maps:get(genesis_block, Params),
    Genesis#block.header;
prev_header(#state{tip_height = Height}) ->
    case beamchain_db:get_block_index(Height) of
        {ok, #{header := Header}} -> Header;
        not_found -> error({block_index_not_found, Height})
    end.

%%% ===================================================================
%%% Internal: MTP sliding window
%%% ===================================================================

%% Compute MTP from the sliding window.
%% The window stores [{Height, Timestamp}] for the last 11 blocks.
compute_mtp([]) ->
    0;
compute_mtp(Window) ->
    Timestamps = [Ts || {_H, Ts} <- Window],
    Sorted = lists:sort(Timestamps),
    lists:nth((length(Sorted) div 2) + 1, Sorted).

%% Add a new timestamp and keep only the last 11.
update_mtp_window(Window, Height, Timestamp) ->
    Window2 = Window ++ [{Height, Timestamp}],
    case length(Window2) > ?MTP_WINDOW of
        true -> tl(Window2);
        false -> Window2
    end.

%% Load the last 11 timestamps from DB for the MTP window.
load_mtp_window(Height, _Params) when Height < 0 ->
    [];
load_mtp_window(Height, _Params) ->
    StartHeight = max(0, Height - ?MTP_WINDOW + 1),
    lists:filtermap(fun(H) ->
        case beamchain_db:get_block_index(H) of
            {ok, #{header := Hdr}} ->
                {true, {H, Hdr#block_header.timestamp}};
            not_found ->
                false
        end
    end, lists:seq(StartHeight, Height)).

%%% ===================================================================
%%% Internal: checkpoint enforcement
%%% ===================================================================

%% Check if a header matches any checkpoint at its height.
%% If the height has a checkpoint, the hash must match.
check_checkpoint(Height, BlockHash, Params) ->
    Checkpoints = maps:get(checkpoints, Params, #{}),
    case maps:find(Height, Checkpoints) of
        {ok, ExpectedHash} ->
            %% Config checkpoint hashes are in display byte order,
            %% but BlockHash is in internal byte order. Reverse to compare.
            case BlockHash =:= beamchain_serialize:reverse_bytes(ExpectedHash) of
                true -> ok;
                false -> throw(checkpoint_mismatch)
            end;
        error ->
            ok
    end.

%% Enhanced checkpoint enforcement: reject headers on a chain that
%% forks before the last checkpoint. This prevents an attacker from
%% feeding us a fake chain that diverges early in history.
%% Returns ok if the header is acceptable, or {error, Reason} if not.
-spec check_checkpoint_ancestry(non_neg_integer(), binary(), map()) ->
    ok | {error, term()}.
check_checkpoint_ancestry(Height, BlockHash, Params) ->
    Checkpoints = maps:get(checkpoints, Params, #{}),
    case maps:size(Checkpoints) of
        0 ->
            %% No checkpoints configured (testnet4, regtest)
            ok;
        _ ->
            LastCheckpointHeight = get_last_checkpoint_height(Checkpoints),
            case Height < LastCheckpointHeight of
                true ->
                    %% We're below the last checkpoint - must be on checkpoint chain
                    %% Check if our chain of headers leads to the checkpoint
                    %% For now, we just verify any checkpoints at this height match
                    case maps:find(Height, Checkpoints) of
                        {ok, ExpectedHash} ->
                            case BlockHash =:= beamchain_serialize:reverse_bytes(ExpectedHash) of
                                true -> ok;
                                false -> {error, checkpoint_ancestry_mismatch}
                            end;
                        error ->
                            %% No checkpoint at this exact height - allow
                            %% The actual checkpoint enforcement happens when we reach
                            %% a checkpoint height
                            ok
                    end;
                false ->
                    %% Above last checkpoint - allow
                    ok
            end
    end.

%% Get the highest checkpoint height
get_last_checkpoint_height(Checkpoints) ->
    maps:fold(fun(H, _, Max) -> max(H, Max) end, 0, Checkpoints).

%%% ===================================================================
%%% Internal: BIP94 (testnet4 difficulty adjustment)
%%% ===================================================================

%% BIP94: On testnet4, the first block of a retarget period must have
%% a timestamp >= the last block of the previous period.
check_bip94(Height, Header, #state{params = Params} = State) ->
    Network = maps:get(network, Params),
    case Network of
        testnet4 ->
            case Height rem ?DIFFICULTY_ADJUSTMENT_INTERVAL =:= 0
                 andalso Height > 0 of
                true ->
                    PrevHeader = prev_header(State),
                    Header#block_header.timestamp >=
                        PrevHeader#block_header.timestamp - 600
                        orelse throw(bip94_timestamp);
                false ->
                    ok
            end;
        _ ->
            ok
    end.

%%% ===================================================================
%%% Internal: chain tip loading
%%% ===================================================================

%% Load the current chain tip from the database.
%% Returns {Height, Hash, Chainwork, MTPWindow}.
load_chain_tip(Params) ->
    case beamchain_db:get_header_tip() of
        {ok, #{hash := Hash, height := Height}} ->
            %% Load the chainwork from block_index
            Chainwork = case beamchain_db:get_block_index(Height) of
                {ok, #{chainwork := CW}} -> CW;
                not_found -> <<0:256>>
            end,
            MTPWindow = load_mtp_window(Height, Params),
            {Height, Hash, Chainwork, MTPWindow};
        not_found ->
            %% Fresh database — store genesis block index
            init_genesis(Params)
    end.

%% Initialize the block index with the genesis block.
init_genesis(Params) ->
    Genesis = maps:get(genesis_block, Params),
    GenesisHeader = Genesis#block.header,
    %% Compute the hash from the header (internal byte order) rather than
    %% using the config's genesis_hash which is in display byte order.
    GenesisHash = beamchain_serialize:block_hash(GenesisHeader),
    GenesisWork = beamchain_pow:compute_work(GenesisHeader#block_header.bits),
    CW = chainwork_to_binary(GenesisWork),
    ok = beamchain_db:store_block_index(0, GenesisHash, GenesisHeader, CW, 1),
    ok = beamchain_db:set_header_tip(GenesisHash, 0),
    MTPWindow = [{0, GenesisHeader#block_header.timestamp}],
    {0, GenesisHash, CW, MTPWindow}.

%%% ===================================================================
%%% Internal: progress reporting
%%% ===================================================================

report_progress(#state{progress_cb = undefined}) ->
    ok;
report_progress(#state{progress_cb = Cb, tip_height = Height,
                         estimated_tip = EstTip,
                         peer_heights = PeerHeights,
                         headers_received = Count} = _State) ->
    TotalKnown = EstTip > 0 andalso Height >= EstTip,
    Info = #{
        phase => headers,
        current => Height,
        total => EstTip,
        total_known => TotalKnown,
        headers_received => Count,
        peer_count => maps:size(PeerHeights)
    },
    try Cb(Info)
    catch _:_ -> ok
    end.

%%% ===================================================================
%%% Internal: helpers
%%% ===================================================================

cancel_timer(#state{timer_ref = undefined} = State) ->
    State;
cancel_timer(#state{timer_ref = Ref} = State) ->
    erlang:cancel_timer(Ref),
    %% Flush any pending timeout message
    receive getheaders_timeout -> ok after 0 -> ok end,
    State#state{timer_ref = undefined}.

%% Encode a chainwork integer as a minimal big-endian binary,
%% padded to at least 32 bytes.
chainwork_to_binary(0) ->
    <<0:256>>;
chainwork_to_binary(N) ->
    Bin = binary:encode_unsigned(N, big),
    case byte_size(Bin) < 32 of
        true ->
            Pad = 32 - byte_size(Bin),
            <<0:(Pad * 8), Bin/binary>>;
        false ->
            Bin
    end.
