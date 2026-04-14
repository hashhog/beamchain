-module(beamchain_block_sync).
-behaviour(gen_server).

%% Parallel block download for Initial Block Download (IBD).
%%
%% After headers are synced, downloads blocks out-of-order from
%% multiple peers but validates them strictly in-order.
%%
%% Architecture:
%%   - download_queue: heights remaining to fetch
%%   - in_flight: height -> {peer, requested_at, hash}
%%   - downloaded: height -> block (awaiting sequential validation)
%%   - next_to_validate: counter for in-order processing

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% Dialyzer suppressions for false positives:
%% validate_sequential/2: recursive decrement from 50 reaches 0 but dialyzer
%%   infers the type from the entry point call-site (literal 50) and flags the
%%   base-case clause matching 0.  refresh_in_flight_timestamps/1 is only
%%   reachable from that base case.  maybe_complete/1 catch-all clause is
%%   valid defensive code; dialyzer infers the exhaustive type from one path.
-dialyzer({nowarn_function, [validate_sequential/2,
                              refresh_in_flight_timestamps/1,
                              maybe_complete/1]}).

%% API
-export([start_link/0,
         start_sync/1,
         stop_sync/0,
         handle_block/2,
         handle_notfound/2,
         handle_peer_connected/2,
         handle_peer_disconnected/1,
         handle_cmpctblock/2,
         handle_blocktxn/2,
         get_status/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2]).

-define(SERVER, ?MODULE).

%% Download limits
-define(MAX_IN_FLIGHT, 128).
-define(MAX_PER_PEER, 16).

%% Stall detection
-define(INITIAL_TIMEOUT_MS, 30000).
-define(MAX_TIMEOUT_MS, 120000).
-define(STALL_CHECK_INTERVAL, 15000).

%% UTXO batch flush every N blocks during IBD
-define(UTXO_FLUSH_INTERVAL, 1000).

%% Memory cap: max blocks downloaded ahead of validation.
%% Mainnet blocks average ~1.5 MB; 256 blocks ≈ 384 MB.
%% Previous value of 5000 caused 5+ GB RSS on mainnet.
-define(MAX_DOWNLOADED_AHEAD, 256).

%% Max blocks to validate per gen_server iteration (yield to process messages)
-define(MAX_VALIDATE_BATCH, 50).

%% Max times to retry validation for the same block height before giving up.
%% Prevents infinite retry loops (e.g. BIP30 false positive from stale UTXOs).
-define(MAX_VALIDATION_RETRIES, 3).

%% Progress reporting interval
-define(PROGRESS_INTERVAL, 1000).

%% Per-peer tracking
-record(peer_stats, {
    in_flight_count = 0  :: non_neg_integer(),
    stall_count = 0      :: non_neg_integer(),
    avg_response_ms = 0  :: non_neg_integer(),
    total_blocks = 0     :: non_neg_integer(),
    total_time_ms = 0    :: non_neg_integer()
}).

-record(state, {
    %% Current sync status
    status = idle          :: idle | syncing | complete,

    %% Heights remaining to fetch (list used as queue, front = next to dequeue)
    download_queue = []    :: [non_neg_integer()],

    %% Height -> {Peer, RequestedAtMs, Hash}
    in_flight = #{}        :: #{non_neg_integer() =>
                                {pid(), integer(), binary()}},

    %% Reverse index: Hash -> Height (for fast block arrival lookup)
    hash_to_height = #{}   :: #{binary() => non_neg_integer()},

    %% Height -> #block{} — downloaded but not yet validated
    downloaded = #{}       :: #{non_neg_integer() => #block{}},

    %% Next height that needs sequential validation
    next_to_validate = 0   :: non_neg_integer(),

    %% Target height (from header sync tip)
    target_height = 0      :: non_neg_integer(),

    %% Per-peer stats: Pid -> #peer_stats{}
    peer_stats = #{}       :: #{pid() => #peer_stats{}},

    %% Known connected peers: Pid -> Info map
    peers = #{}            :: #{pid() => map()},

    %% Chain params
    params = #{}           :: map(),

    %% Stall check timer
    stall_timer            :: reference() | undefined,

    %% Progress report timer
    progress_timer         :: reference() | undefined,

    %% Progress callback
    progress_cb            :: function() | undefined,

    %% Rolling stats for progress
    blocks_validated = 0   :: non_neg_integer(),
    last_progress_time = 0 :: integer(),
    last_progress_height = 0 :: non_neg_integer(),

    %% Assumevalid: block hash below which we skip scripts
    assume_valid = <<0:256>> :: binary(),
    %% Cached height of the assumevalid block (avoids repeated DB lookups)
    assume_valid_height = -1 :: integer(),

    %% BIP152 compact block state
    %% Hash -> {CompactState, RequestedAt, Peer} for partial compact blocks
    pending_compact = #{}    :: #{binary() => {term(), integer(), pid()}},
    %% Recently seen transactions for compact block reconstruction
    recent_txns = []         :: [#transaction{}],
    %% Max recent txns to keep
    max_recent_txns = 100    :: non_neg_integer(),

    %% Height -> retry count — tracks how many times validation failed
    %% for a given height. After MAX_VALIDATION_RETRIES, skip the block
    %% and halt sync to avoid infinite retry loops.
    validation_failures = #{} :: #{non_neg_integer() => non_neg_integer()},

    %% Consecutive stall_check ticks where next_to_validate did not advance.
    %% Used to escalate the watchdog to force_unstick/2 when a single peer
    %% silently dropped a block request (no notfound, no block, no timeout).
    stuck_ticks = 0        :: non_neg_integer()
}).

%%% ===================================================================
%%% API
%%% ===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc Start block download. Called after header sync completes.
%% Opts: #{target_height => N, progress_cb => fun(Map)}
-spec start_sync(map()) -> ok.
start_sync(Opts) ->
    gen_server:cast(?SERVER, {start_sync, Opts}).

%% @doc Stop block sync.
-spec stop_sync() -> ok.
stop_sync() ->
    gen_server:cast(?SERVER, stop_sync).

%% @doc Handle a received block from a peer.
-spec handle_block(pid(), #block{}) -> ok.
handle_block(Peer, Block) ->
    gen_server:cast(?SERVER, {block, Peer, Block}).

%% @doc Handle a notfound response from a peer.
%% Re-queues the requested blocks for download from another peer.
-spec handle_notfound(pid(), [{integer(), binary()}]) -> ok.
handle_notfound(Peer, Items) ->
    gen_server:cast(?SERVER, {notfound, Peer, Items}).

%% @doc Peer completed handshake.
-spec handle_peer_connected(pid(), map()) -> ok.
handle_peer_connected(Peer, Info) ->
    gen_server:cast(?SERVER, {peer_connected, Peer, Info}).

%% @doc Peer disconnected.
-spec handle_peer_disconnected(pid()) -> ok.
handle_peer_disconnected(Peer) ->
    gen_server:cast(?SERVER, {peer_disconnected, Peer}).

%% @doc Handle a BIP152 compact block message.
-spec handle_cmpctblock(pid(), map()) -> ok.
handle_cmpctblock(Peer, CmpctBlock) ->
    gen_server:cast(?SERVER, {cmpctblock, Peer, CmpctBlock}).

%% @doc Handle a BIP152 blocktxn response.
-spec handle_blocktxn(pid(), map()) -> ok.
handle_blocktxn(Peer, BlockTxn) ->
    gen_server:cast(?SERVER, {blocktxn, Peer, BlockTxn}).

%% @doc Get current block sync status.
-spec get_status() -> map().
get_status() ->
    gen_server:call(?SERVER, get_status).

%%% ===================================================================
%%% gen_server callbacks
%%% ===================================================================

init([]) ->
    Network = beamchain_config:network(),
    Params = beamchain_chain_params:params(Network),
    AssumeValidDisplay = maps:get(assume_valid, Params, <<0:256>>),
    %% Convert from display byte order to internal byte order
    AssumeValid = case AssumeValidDisplay of
        <<0:256>> -> <<0:256>>;
        _ -> beamchain_serialize:reverse_bytes(AssumeValidDisplay)
    end,
    %% Cache the height of the assumevalid block
    AVHeight = lookup_assume_valid_height(AssumeValid),
    {ok, #state{params = Params, assume_valid = AssumeValid,
                assume_valid_height = AVHeight}}.

handle_call(get_status, _From, State) ->
    Status = #{
        status => State#state.status,
        next_to_validate => State#state.next_to_validate,
        target_height => State#state.target_height,
        in_flight_count => maps:size(State#state.in_flight),
        downloaded_count => maps:size(State#state.downloaded),
        queue_length => length(State#state.download_queue),
        peer_count => maps:size(State#state.peers),
        blocks_validated => State#state.blocks_validated
    },
    {reply, Status, State};

handle_call(_Request, _From, State) ->
    {reply, {error, not_implemented}, State}.

handle_cast({start_sync, Opts}, #state{status = idle,
                                         assume_valid = AV} = State) ->
    TargetHeight = maps:get(target_height, Opts, 0),
    ProgressCb = maps:get(progress_cb, Opts, undefined),

    %% Determine where to start: after last fully validated block
    StartHeight = find_start_height(),

    logger:info("block_sync: starting IBD from ~B to ~B",
                [StartHeight, TargetHeight]),

    %% Build the download queue
    Queue = case TargetHeight > StartHeight of
        true -> lists:seq(StartHeight, TargetHeight);
        false -> []
    end,

    %% Re-lookup assumevalid height now that headers are synced
    AVHeight = lookup_assume_valid_height(AV),
    case AVHeight > 0 of
        true ->
            logger:info("block_sync: assumevalid active, skipping scripts "
                        "below height ~B", [AVHeight]);
        false -> ok
    end,

    %% Gather currently connected peers
    Peers = gather_connected_peers(),

    Now = erlang:monotonic_time(millisecond),
    State2 = State#state{
        status = syncing,
        download_queue = Queue,
        in_flight = #{},
        hash_to_height = #{},
        downloaded = #{},
        next_to_validate = StartHeight,
        target_height = TargetHeight,
        peers = Peers,
        peer_stats = maps:from_list(
            [{Pid, #peer_stats{}} || Pid <- maps:keys(Peers)]),
        progress_cb = ProgressCb,
        blocks_validated = 0,
        last_progress_time = Now,
        last_progress_height = StartHeight,
        assume_valid_height = AVHeight
    },

    %% Start timers
    StallTimer = erlang:send_after(?STALL_CHECK_INTERVAL, self(),
                                    stall_check),
    ProgressTimer = erlang:send_after(?PROGRESS_INTERVAL, self(),
                                       progress_tick),
    State3 = State2#state{stall_timer = StallTimer,
                           progress_timer = ProgressTimer},

    %% Fill the pipeline
    State4 = fill_pipeline(State3),
    {noreply, State4};

handle_cast({start_sync, _Opts}, State) ->
    %% Already syncing
    {noreply, State};

handle_cast(stop_sync, State) ->
    State2 = cancel_timers(State),
    {noreply, State2#state{status = idle, in_flight = #{},
                            hash_to_height = #{},
                            downloaded = #{}, download_queue = []}};

handle_cast({block, Peer, Block}, #state{status = syncing} = State) ->
    State2 = handle_block_received(Peer, Block, State),
    {noreply, State2};
handle_cast({block, Peer, Block}, State) ->
    %% Unsolicited block (not in syncing state) — validate and connect
    %% directly. This handles blocks fetched via getdata from inv
    %% announcements when we're idle or complete.
    State2 = handle_unsolicited_block(Peer, Block, State),
    {noreply, State2};

handle_cast({notfound, Peer, Items}, #state{status = syncing} = State) ->
    State2 = handle_notfound_items(Peer, Items, State),
    State3 = fill_pipeline(State2),
    {noreply, State3};
handle_cast({notfound, _Peer, _Items}, State) ->
    {noreply, State};

handle_cast({peer_connected, Peer, Info}, State) ->
    Peers = maps:put(Peer, Info, State#state.peers),
    PeerStats = case maps:is_key(Peer, State#state.peer_stats) of
        true -> State#state.peer_stats;
        false -> maps:put(Peer, #peer_stats{}, State#state.peer_stats)
    end,
    State2 = State#state{peers = Peers, peer_stats = PeerStats},
    %% If syncing, try to use the new peer
    State3 = case State2#state.status of
        syncing -> fill_pipeline(State2);
        _ -> State2
    end,
    {noreply, State3};

handle_cast({peer_disconnected, Peer}, State) ->
    State2 = handle_peer_disconnect(Peer, State),
    {noreply, State2};

%% BIP152 compact block received
handle_cast({cmpctblock, Peer, CmpctBlock}, #state{status = syncing} = State) ->
    State2 = handle_cmpctblock_received(Peer, CmpctBlock, State),
    {noreply, State2};
handle_cast({cmpctblock, _Peer, _CmpctBlock}, State) ->
    {noreply, State};

%% BIP152 blocktxn response
handle_cast({blocktxn, Peer, BlockTxn}, #state{status = syncing} = State) ->
    State2 = handle_blocktxn_received(Peer, BlockTxn, State),
    {noreply, State2};
handle_cast({blocktxn, _Peer, _BlockTxn}, State) ->
    {noreply, State};

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(stall_check, #state{status = syncing,
                                next_to_validate = NextH} = State) ->
    State2 = check_stalls(State),
    %% Also try to validate — the next block may have arrived since
    %% the last validate_sequential call but no event triggered it.
    State3 = validate_sequential(State2),
    %% Reschedule
    Timer = erlang:send_after(?STALL_CHECK_INTERVAL, self(), stall_check),
    State4 = fill_pipeline(State3#state{stall_timer = Timer}),
    %% Log stall detection and escalate if wedged at same height.
    Stuck = State4#state.next_to_validate =:= NextH
            andalso (maps:size(State4#state.downloaded) > 0
                     orelse maps:size(State4#state.in_flight) > 0),
    State5 = case Stuck of
        true ->
            NewCount = State4#state.stuck_ticks + 1,
            logger:info("block_sync: watchdog — stuck at ~B, "
                        "downloaded=~B in_flight=~B ticks=~B",
                        [NextH, maps:size(State4#state.downloaded),
                         maps:size(State4#state.in_flight), NewCount]),
            %% Escalation: after 2 ticks (~30s) stuck, force-evict the
            %% in_flight entry for NextH and blast-request it from all peers.
            %% This routes around a peer that silently dropped the request
            %% (no notfound, no block, just dead) — the existing check_stalls
            %% would need its 30s-per-entry timeout to fire, but that relies on
            %% RequestedAt not being refreshed by validation cycles.
            case NewCount >= 2 of
                true ->
                    force_unstick(NextH, State4#state{stuck_ticks = 0});
                false ->
                    State4#state{stuck_ticks = NewCount}
            end;
        false ->
            State4#state{stuck_ticks = 0}
    end,
    {noreply, State5};
handle_info(stall_check, State) ->
    {noreply, State#state{stall_timer = undefined}};

handle_info(progress_tick, #state{status = syncing} = State) ->
    report_progress(State),
    Now = erlang:monotonic_time(millisecond),
    Timer = erlang:send_after(?PROGRESS_INTERVAL, self(), progress_tick),
    {noreply, State#state{
        progress_timer = Timer,
        last_progress_time = Now,
        last_progress_height = State#state.next_to_validate
    }};
handle_info(progress_tick, State) ->
    {noreply, State#state{progress_timer = undefined}};

handle_info(continue_validation, #state{status = syncing} = State) ->
    %% Continue validating downloaded blocks after yielding
    State2 = validate_sequential(State),
    State3 = fill_pipeline(State2),
    {noreply, State3};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, State) ->
    cancel_timers(State),
    ok.

%%% ===================================================================
%%% Internal: sync lifecycle
%%% ===================================================================

%% Find the height to start downloading from.
%% Use the chainstate tip (last connected block) as the authoritative source.
find_start_height() ->
    case beamchain_chainstate:get_tip() of
        {ok, {_Hash, TipHeight}} when TipHeight >= 0 ->
            TipHeight + 1;
        _ ->
            0
    end.

%% Gather currently connected peers from peer_manager.
gather_connected_peers() ->
    AllPeers = beamchain_peer_manager:get_peers(),
    lists:foldl(fun(PeerMap, Acc) ->
        case maps:get(connected, PeerMap, false) of
            true ->
                Pid = maps:get(pid, PeerMap),
                Info = maps:get(info, PeerMap, #{}),
                maps:put(Pid, Info, Acc);
            false ->
                Acc
        end
    end, #{}, AllPeers).

%%% ===================================================================
%%% Internal: pipeline fill — request blocks from peers
%%% ===================================================================

fill_pipeline(#state{status = syncing, download_queue = []} = State) ->
    %% Queue is empty. Check if we're done.
    maybe_complete(State);

fill_pipeline(#state{status = syncing,
                     next_to_validate = NextH,
                     downloaded = Downloaded} = State) ->
    TotalInFlight = maps:size(State#state.in_flight),
    DownloadedAhead = maps:size(Downloaded),
    NeedNext = not maps:is_key(NextH, Downloaded),
    NextInFlight = maps:is_key(NextH, State#state.in_flight),

    %% Deadlock detection — two cases:
    %% 1) Hard deadlock: in_flight=0, buffer full, needed block missing
    %% 2) Soft deadlock: needed block not in buffer AND not in flight,
    %%    but buffer is full so no new requests can be made
    IsHardDeadlock = NeedNext
                     andalso TotalInFlight =:= 0
                     andalso DownloadedAhead >= (?MAX_DOWNLOADED_AHEAD - 32),
    IsSoftDeadlock = NeedNext
                     andalso (not NextInFlight)
                     andalso DownloadedAhead >= ?MAX_DOWNLOADED_AHEAD,

    State1 = case IsHardDeadlock orelse IsSoftDeadlock of
        true ->
            %% Evict enough of the highest buffered blocks to get below
            %% MAX_DOWNLOADED_AHEAD so the normal pipeline can resume.
            %% Previous approach of evicting only 1 caused an infinite
            %% evict-request-stall loop; evicting 32 was still not enough
            %% when the buffer exceeded 256+32 due to arrival races.
            EvictTarget = max(0, DownloadedAhead - (?MAX_DOWNLOADED_AHEAD - 64)),
            EvictCount = max(EvictTarget, 32),
            AllHeights = lists:sort(fun(A, B) -> A >= B end,
                                    maps:keys(Downloaded)),
            {ToEvict, _Keep} = take_from_queue(EvictCount, AllHeights),
            Downloaded2 = lists:foldl(fun maps:remove/2, Downloaded, ToEvict),
            OldQueue = State#state.download_queue,
            %% Remove NextH from queue if already there (avoid duplicates)
            CleanQueue = lists:delete(NextH, OldQueue),
            %% Put NextH at front, then re-queue evicted heights
            NewQueue = [NextH | ToEvict ++ CleanQueue],
            logger:info("block_sync: deadlock — need height ~B, "
                        "evicted ~B blocks (in_flight=~B), "
                        "blast-requesting gap from all peers",
                        [NextH, length(ToEvict), TotalInFlight]),
            %% Blast-request NextH from ALL connected peers for redundancy
            State_tmp = State#state{downloaded = Downloaded2,
                                     download_queue = NewQueue},
            blast_request_height(NextH, State_tmp);
        false ->
            State
    end,
    %% Get available peers with capacity
    AvailablePeers = get_available_peers(State1),
    case AvailablePeers of
        [] ->
            State1;
        _ ->
            TotalInFlight2 = maps:size(State1#state.in_flight),
            case TotalInFlight2 >= ?MAX_IN_FLIGHT of
                true ->
                    State1;
                false ->
                    DownloadedAhead2 = maps:size(State1#state.downloaded),
                    case DownloadedAhead2 >= ?MAX_DOWNLOADED_AHEAD of
                        true ->
                            %% Buffer full — but if next_to_validate is
                            %% missing and not in flight, force-request it
                            %% to prevent starvation.
                            NextH1 = State1#state.next_to_validate,
                            NextMissing = not maps:is_key(NextH1,
                                            State1#state.downloaded),
                            NextNotInFlight = not maps:is_key(NextH1,
                                                State1#state.in_flight),
                            case NextMissing andalso NextNotInFlight of
                                true ->
                                    blast_request_height(NextH1, State1);
                                false ->
                                    State1
                            end;
                        false ->
                            assign_blocks_to_peers(AvailablePeers, State1)
                    end
            end
    end;
fill_pipeline(State) ->
    State.

%% Get peers that have capacity for more in-flight blocks.
get_available_peers(#state{peer_stats = PeerStats, peers = Peers}) ->
    lists:filtermap(fun({Pid, Stats}) ->
        case maps:is_key(Pid, Peers) andalso
             Stats#peer_stats.in_flight_count < ?MAX_PER_PEER of
            true -> {true, Pid};
            false -> false
        end
    end, maps:to_list(PeerStats)).

%% Blast-request a specific height from ALL connected peers simultaneously.
%% Used during deadlock recovery to maximise the chance of getting the
%% needed block quickly.  Only the first arrival is kept (duplicates are
%% ignored in handle_block_received via hash_to_height lookup).
blast_request_height(Height, #state{peers = Peers,
                                     in_flight = InFlight,
                                     hash_to_height = H2H,
                                     peer_stats = AllStats} = State) ->
    case beamchain_db:get_block_index(Height) of
        {ok, #{hash := Hash}} ->
            Item = #{type => ?MSG_WITNESS_BLOCK, hash => Hash},
            Now = erlang:monotonic_time(millisecond),
            PeerList = maps:keys(Peers),
            %% Pick the first peer as the "official" in_flight owner
            case PeerList of
                [] ->
                    State;
                [Primary | _Others] ->
                    InFlight2 = maps:put(Height, {Primary, Now, Hash}, InFlight),
                    H2H2 = maps:put(Hash, Height, H2H),
                    %% Send getdata to ALL peers
                    lists:foreach(fun(P) ->
                        beamchain_peer:send_message(P,
                            {getdata, #{items => [Item]}})
                    end, PeerList),
                    %% Only count the primary peer's in_flight
                    PStats = maps:get(Primary, AllStats, #peer_stats{}),
                    PStats2 = PStats#peer_stats{
                        in_flight_count = PStats#peer_stats.in_flight_count + 1
                    },
                    AllStats2 = maps:put(Primary, PStats2, AllStats),
                    %% Remove Height from download_queue since it's now in_flight
                    Queue2 = lists:delete(Height, State#state.download_queue),
                    State#state{in_flight = InFlight2,
                                hash_to_height = H2H2,
                                peer_stats = AllStats2,
                                download_queue = Queue2}
            end;
        not_found ->
            logger:warning("block_sync: blast_request — no block index "
                           "for height ~B", [Height]),
            State
    end.

%% Assign blocks from the queue to available peers.
%% Batches multiple block requests per peer in a single getdata message
%% for more efficient downloading.
assign_blocks_to_peers(Peers, State) ->
    assign_blocks_round_robin(Peers, Peers, State).

assign_blocks_round_robin([], _AllPeers, State) ->
    State;
assign_blocks_round_robin(_Peers, _AllPeers,
                           #state{download_queue = []} = State) ->
    State;
assign_blocks_round_robin([Peer | RestPeers], AllPeers, State) ->
    TotalInFlight = maps:size(State#state.in_flight),
    DownloadedAhead = maps:size(State#state.downloaded),
    case TotalInFlight >= ?MAX_IN_FLIGHT orelse
         DownloadedAhead >= ?MAX_DOWNLOADED_AHEAD of
        true ->
            State;
        false ->
            %% How many blocks can this peer take?
            PeerStats = maps:get(Peer, State#state.peer_stats,
                                  #peer_stats{}),
            PeerCapacity = ?MAX_PER_PEER -
                           PeerStats#peer_stats.in_flight_count,
            GlobalCapacity = ?MAX_IN_FLIGHT - TotalInFlight,
            MemCapacity = ?MAX_DOWNLOADED_AHEAD - DownloadedAhead,
            BatchSize = min(PeerCapacity,
                            min(GlobalCapacity, MemCapacity)),
            case BatchSize > 0 of
                true ->
                    State2 = request_batch(Peer, BatchSize, State),
                    assign_blocks_round_robin(RestPeers, AllPeers, State2);
                false ->
                    assign_blocks_round_robin(RestPeers, AllPeers, State)
            end
    end.

%% Take up to BatchSize heights from the queue and send a batched
%% getdata message to the peer.
request_batch(Peer, BatchSize,
              #state{download_queue = Queue,
                     in_flight = InFlight,
                     hash_to_height = H2H,
                     peer_stats = AllStats} = State) ->
    {Heights, RestQueue} = take_from_queue(BatchSize, Queue),
    case Heights of
        [] ->
            State;
        _ ->
            Now = erlang:monotonic_time(millisecond),
            %% Look up hashes and build getdata items
            {Items, InFlight2, H2H2, _Skipped} = lists:foldl(
                fun(Height, {ItemsAcc, IFAcc, H2HAcc, SkipAcc}) ->
                    case beamchain_db:get_block_index(Height) of
                        {ok, #{hash := Hash}} ->
                            Item = #{type => ?MSG_WITNESS_BLOCK, hash => Hash},
                            IF = maps:put(Height, {Peer, Now, Hash}, IFAcc),
                            H2HNew = maps:put(Hash, Height, H2HAcc),
                            {[Item | ItemsAcc], IF, H2HNew, SkipAcc};
                        not_found ->
                            logger:warning("block_sync: no block index "
                                           "for height ~B", [Height]),
                            {ItemsAcc, IFAcc, H2HAcc, SkipAcc + 1}
                    end
                end, {[], InFlight, H2H, 0}, Heights),

            %% Send getdata with all items at once
            case Items of
                [] ->
                    State#state{download_queue = RestQueue,
                                hash_to_height = H2H2};
                _ ->
                    beamchain_peer:send_message(Peer,
                        {getdata, #{items => lists:reverse(Items)}}),
                    %% Update peer stats
                    NumRequested = length(Items),
                    Stats = maps:get(Peer, AllStats, #peer_stats{}),
                    Stats2 = Stats#peer_stats{
                        in_flight_count =
                            Stats#peer_stats.in_flight_count + NumRequested
                    },
                    AllStats2 = maps:put(Peer, Stats2, AllStats),
                    State#state{
                        download_queue = RestQueue,
                        in_flight = InFlight2,
                        hash_to_height = H2H2,
                        peer_stats = AllStats2
                    }
            end
    end.

%% Take up to N items from the front of a list.
take_from_queue(N, List) ->
    take_from_queue(N, List, []).

take_from_queue(0, Rest, Acc) ->
    {lists:reverse(Acc), Rest};
take_from_queue(_N, [], Acc) ->
    {lists:reverse(Acc), []};
take_from_queue(N, [H | T], Acc) ->
    take_from_queue(N - 1, T, [H | Acc]).

%%% ===================================================================
%%% Internal: block arrival and validation
%%% ===================================================================

handle_block_received(Peer, Block, State) ->
    BlockHash = beamchain_serialize:block_hash(Block#block.header),

    %% Use hash_to_height reverse index for O(1) lookup
    case maps:find(BlockHash, State#state.hash_to_height) of
        {ok, Height} ->
            %% Remove from reverse index
            H2H2 = maps:remove(BlockHash, State#state.hash_to_height),

            case maps:find(Height, State#state.in_flight) of
                {ok, {RequestPeer, RequestedAt, _Hash}} ->
                    Now = erlang:monotonic_time(millisecond),
                    ResponseMs = Now - RequestedAt,

                    %% Remove from in_flight
                    InFlight2 = maps:remove(Height, State#state.in_flight),

                    %% Update requesting peer's stats
                    AllStats = update_peer_block_received(
                        RequestPeer, ResponseMs, State#state.peer_stats),

                    %% Store in downloaded map
                    Downloaded2 = maps:put(Height, Block,
                                           State#state.downloaded),

                    State2 = State#state{
                        in_flight = InFlight2,
                        hash_to_height = H2H2,
                        peer_stats = AllStats,
                        downloaded = Downloaded2
                    },

                    %% Try to validate as many sequential blocks as possible
                    State3 = validate_sequential(State2),

                    %% Fill pipeline with freed capacity
                    fill_pipeline(State3);

                error ->
                    %% Height was in hash index but not in_flight (race)
                    State#state{hash_to_height = H2H2}
            end;

        error ->
            %% Unsolicited block, ignore
            logger:debug("block_sync: unsolicited block ~s from ~p",
                         [hash_hex(BlockHash), Peer]),
            State
    end.

%% Handle an unsolicited block (received outside of IBD syncing state).
%% Validates and connects the block directly to the chain tip.
%% chainstate:connect_block/1 handles full validation, storage, and tip update.
handle_unsolicited_block(Peer, Block, State) ->
    BlockHash = beamchain_serialize:block_hash(Block#block.header),
    case beamchain_db:has_block(BlockHash) of
        true ->
            %% Already have this block, ignore
            State;
        false ->
            Params = State#state.params,
            %% 1. Context-free validation
            case beamchain_validation:check_block(Block, Params) of
                ok ->
                    %% 2. Connect via chainstate — this does contextual
                    %%    validation, UTXO updates, block storage, block
                    %%    index, and tip update all in one call.
                    case beamchain_chainstate:connect_block(Block) of
                        ok ->
                            {ok, {_, Height}} = beamchain_chainstate:get_tip(),
                            %% 3. Store tx index entries (not done by chainstate)
                            store_tx_index(Block, Height),
                            logger:info("block_sync: connected unsolicited "
                                        "block ~s at height ~B from ~p",
                                        [hash_hex(BlockHash), Height, Peer]),
                            State;
                        {error, Reason} ->
                            logger:debug("block_sync: unsolicited block ~s "
                                         "failed connect: ~p",
                                         [hash_hex(BlockHash), Reason]),
                            State
                    end;
                {error, Reason} ->
                    logger:warning("block_sync: unsolicited block ~s "
                                   "failed validation: ~p",
                                   [hash_hex(BlockHash), Reason]),
                    beamchain_peer:add_misbehavior(Peer, 20),
                    State
            end
    end.

%% Update peer stats after receiving a block.
update_peer_block_received(Peer, ResponseMs, AllStats) ->
    Stats = maps:get(Peer, AllStats, #peer_stats{}),
    NewTotal = Stats#peer_stats.total_blocks + 1,
    NewTotalTime = Stats#peer_stats.total_time_ms + ResponseMs,
    AvgMs = NewTotalTime div max(1, NewTotal),
    Stats2 = Stats#peer_stats{
        in_flight_count = max(0, Stats#peer_stats.in_flight_count - 1),
        total_blocks = NewTotal,
        total_time_ms = NewTotalTime,
        avg_response_ms = AvgMs
    },
    maps:put(Peer, Stats2, AllStats).

%% Validate blocks sequentially starting from next_to_validate.
%% Limits to MAX_VALIDATE_BATCH blocks per call to avoid blocking
%% the gen_server loop (which would prevent stall checks and new blocks).
validate_sequential(State) ->
    validate_sequential(State, ?MAX_VALIDATE_BATCH).

validate_sequential(State, 0) ->
    %% Batch limit reached — schedule continuation to yield to gen_server.
    %% Refresh in-flight timestamps so validation time isn't counted as stall.
    self() ! continue_validation,
    refresh_in_flight_timestamps(State);
validate_sequential(#state{next_to_validate = NextH,
                            downloaded = Downloaded} = State, Remaining) ->
    %% Fast-forward: if next_to_validate is behind the chainstate tip,
    %% skip directly to tip+1 (avoids re-downloading already-connected blocks)
    case beamchain_chainstate:get_tip() of
        {ok, {_, TipH}} when TipH >= NextH ->
            logger:info("block_sync: fast-forward next_to_validate "
                        "from ~B to ~B (chainstate tip ahead)",
                        [NextH, TipH + 1]),
            StaleKeys = [K || K <- maps:keys(Downloaded), K =< TipH],
            Downloaded2 = lists:foldl(fun maps:remove/2, Downloaded, StaleKeys),
            Queue2 = [H || H <- State#state.download_queue, H > TipH],
            State2 = State#state{
                next_to_validate = TipH + 1,
                downloaded = Downloaded2,
                download_queue = Queue2
            },
            validate_sequential_inner(State2, Remaining);
        _ ->
            validate_sequential_inner(State, Remaining)
    end.

validate_sequential_inner(#state{next_to_validate = NextH,
                            downloaded = Downloaded} = State, Remaining) ->
    case maps:find(NextH, Downloaded) of
        {ok, Block} ->
            case validate_and_connect(NextH, Block, State) of
                {ok, State2} ->
                    %% Remove from downloaded, advance counter
                    Downloaded2 = maps:remove(NextH, State2#state.downloaded),
                    State3 = State2#state{
                        next_to_validate = NextH + 1,
                        downloaded = Downloaded2,
                        blocks_validated = State2#state.blocks_validated + 1
                    },
                    %% Continue validating the next one
                    validate_sequential_inner(State3, Remaining - 1);
                {skip_to, SkipH, State2} ->
                    %% Block was already connected — jump next_to_validate
                    %% to TipH+1 and discard any stale buffered blocks below
                    %% that height to avoid re-downloading them.
                    logger:info("block_sync: skipping next_to_validate "
                                "from ~B to ~B (tip already ahead)",
                                [NextH, SkipH]),
                    StaleKeys = [K || K <- maps:keys(Downloaded)
                                    , K < SkipH],
                    Downloaded2 = lists:foldl(fun maps:remove/2,
                                              Downloaded, StaleKeys),
                    %% Also clear any stale entries from download_queue
                    Queue2 = [H || H <- State2#state.download_queue,
                                   H >= SkipH],
                    State3 = State2#state{
                        next_to_validate = SkipH,
                        downloaded = Downloaded2,
                        download_queue = Queue2
                    },
                    validate_sequential_inner(State3, Remaining - 1);
                {error, Reason} ->
                    Failures = State#state.validation_failures,
                    RetryCount = maps:get(NextH, Failures, 0) + 1,
                    Failures2 = maps:put(NextH, RetryCount, Failures),
                    case RetryCount >= ?MAX_VALIDATION_RETRIES of
                        true ->
                            logger:error("block_sync: validation failed at height ~B "
                                         "after ~B retries (~p), halting sync",
                                         [NextH, RetryCount, Reason]),
                            %% Stop sync entirely — operator must investigate.
                            %% Clear downloaded buffer for this height.
                            Downloaded2 = maps:remove(NextH, State#state.downloaded),
                            State#state{status = idle,
                                        downloaded = Downloaded2,
                                        download_queue = [],
                                        validation_failures = Failures2};
                        false ->
                            logger:error("block_sync: validation failed at height ~B: ~p "
                                         "(retry ~B/~B)",
                                         [NextH, Reason, RetryCount,
                                          ?MAX_VALIDATION_RETRIES]),
                            %% Re-queue the failed block for retry.
                            Downloaded2 = maps:remove(NextH, State#state.downloaded),
                            Queue = [NextH | State#state.download_queue],
                            State#state{downloaded = Downloaded2,
                                        download_queue = Queue,
                                        validation_failures = Failures2}
                    end
            end;
        error ->
            %% Not yet downloaded, nothing to do
            State
    end.

%% Validate and connect a single block.
%% Delegates to beamchain_chainstate which manages the UTXO cache,
%% then stores block data and updates the block index.
validate_and_connect(Height, Block,
                     #state{params = Params,
                            assume_valid = AssumeValid,
                            assume_valid_height = AVHeight} = State) ->
    try
        %% 0. Guard against replaying a block that was already connected
        %%    (e.g. after a gen_server call timeout where the chainstate
        %%    processed the block but the caller didn't see the reply).
        case beamchain_chainstate:get_tip() of
            {ok, {_, TipH}} when TipH >= Height ->
                logger:info("block_sync: height ~B already connected "
                            "(tip=~B), skipping ahead", [Height, TipH]),
                throw(already_connected);
            _ -> ok
        end,

        %% 1. Context-free block check
        case beamchain_validation:check_block(Block, Params) of
            ok -> ok;
            {error, E1} -> throw(E1)
        end,

        %% 2. Connect block via chainstate (validation + UTXO update + tip)
        case beamchain_chainstate:connect_block(Block) of
            ok -> ok;
            {error, E2} -> throw(E2)
        end,

        %% 3. Store the block
        ok = beamchain_db:store_block(Block, Height),

        %% 4. Store tx index entries
        store_tx_index(Block, Height),

        %% 5. Update block_index status to fully validated (status=2).
        %% direct_atomic_connect_writes already stored the entry with the
        %% correct NTx count; re-read and preserve it so we don't clobber
        %% it with the default-zero written by store_block_index/5.
        case beamchain_db:get_block_index(Height) of
            {ok, #{hash := BH, header := Hdr, chainwork := CW, n_tx := NTx}} ->
                beamchain_db:store_block_index(Height, BH, Hdr, CW, 2, NTx);
            {ok, #{hash := BH, header := Hdr, chainwork := CW}} ->
                beamchain_db:store_block_index(Height, BH, Hdr, CW, 2);
            not_found ->
                ok
        end,

        %% 6. Log checkpoint every UTXO_FLUSH_INTERVAL blocks
        SkipScripts = AssumeValid =/= <<0:256>> andalso
                      AVHeight > 0 andalso Height =< AVHeight,
        case Height rem 1000 =:= 0 of
            true ->
                logger:info("block_sync: checkpoint at height ~B "
                            "(~s scripts)",
                            [Height,
                             case SkipScripts of
                                 true -> "skipping";
                                 false -> "verifying"
                             end]);
            false ->
                ok
        end,

        {ok, State}
    catch
        throw:already_connected ->
            %% Re-query tip to find skip target (catch vars are unsafe)
            SkipTarget = case beamchain_chainstate:get_tip() of
                {ok, {_, CurTip}} -> CurTip + 1;
                _ -> Height + 1
            end,
            {skip_to, SkipTarget, State};
        throw:Reason -> {error, Reason};
        exit:Reason ->
            logger:error("block_sync: exit at height ~B: ~p",
                         [Height, Reason]),
            {error, Reason};
        error:Reason:Stack ->
            logger:error("block_sync: error at height ~B: ~p~n~p",
                         [Height, Reason, Stack]),
            {error, Reason}
    end.

%% Look up the height of the assumevalid block at startup.
lookup_assume_valid_height(<<0:256>>) ->
    -1;
lookup_assume_valid_height(Hash) ->
    case beamchain_db:get_block_index_by_hash(Hash) of
        {ok, #{height := H}} -> H;
        not_found -> -1  %% headers not yet synced, will update later
    end.

%% Store transaction index entries for all txs in a block.
%% Only stores if txindex is enabled in config.
store_tx_index(#block{header = Header, transactions = Txs}, Height) ->
    case beamchain_config:txindex_enabled() of
        true ->
            BlockHash = beamchain_serialize:block_hash(Header),
            lists:foldl(fun(Tx, Pos) ->
                Txid = beamchain_serialize:tx_hash(Tx),
                beamchain_db:store_tx_index(Txid, BlockHash, Height, Pos),
                Pos + 1
            end, 0, Txs);
        false ->
            ok
    end.

%% Reset in-flight request timestamps so validation time isn't counted
%% as network stall time. Called after a batch of validation completes.
refresh_in_flight_timestamps(#state{in_flight = InFlight} = State) ->
    Now = erlang:monotonic_time(millisecond),
    InFlight2 = maps:map(fun(_Height, {Peer, _OldTime, Hash}) ->
        {Peer, Now, Hash}
    end, InFlight),
    State#state{in_flight = InFlight2}.

%%% ===================================================================
%%% Internal: stall detection
%%% ===================================================================

check_stalls(#state{in_flight = InFlight} = State) ->
    Now = erlang:monotonic_time(millisecond),
    maps:fold(fun(Height, {Peer, RequestedAt, _Hash}, AccState) ->
        %% Adaptive timeout: base * 2^stall_count
        PeerStallCount = case maps:get(Peer, AccState#state.peer_stats, undefined) of
            undefined -> 0;
            PS -> PS#peer_stats.stall_count
        end,
        Timeout = min(?MAX_TIMEOUT_MS,
                      ?INITIAL_TIMEOUT_MS * (1 bsl PeerStallCount)),
        Elapsed = Now - RequestedAt,
        case Elapsed > Timeout of
            true ->
                logger:debug("block_sync: stall at height ~B from ~p "
                             "(~Bms > ~Bms)",
                             [Height, Peer, Elapsed, Timeout]),
                handle_stall(Height, Peer, AccState);
            false ->
                AccState
        end
    end, State, InFlight).

%% Watchdog escalation: called when next_to_validate has not advanced for
%% multiple stall_check ticks. Evict any in_flight entry at Height, force-
%% kill the stuck peer (the gentle disconnect cast may not have propagated),
%% then blast-request Height from ALL connected peers so the next arrival
%% unblocks us regardless of which peer is actually healthy.
force_unstick(Height, State) ->
    {State1, StuckPeer} = case maps:find(Height, State#state.in_flight) of
        {ok, {P, _, Hash}} ->
            logger:warning("block_sync: force_unstick — evicting in_flight "
                           "height ~B from peer ~p", [Height, P]),
            beamchain_peer:disconnect(P),
            catch exit(P, stall_unstick),
            InFlight2 = maps:remove(Height, State#state.in_flight),
            H2H2 = maps:remove(Hash, State#state.hash_to_height),
            AllStats2 = decrement_peer_in_flight(P, State#state.peer_stats),
            Peers2 = maps:remove(P, State#state.peers),
            PeerStats3 = maps:remove(P, AllStats2),
            {State#state{in_flight = InFlight2, hash_to_height = H2H2,
                         peers = Peers2, peer_stats = PeerStats3}, P};
        error ->
            {State, undefined}
    end,
    %% Re-gather peers in case peer_manager has new connections since start_sync.
    Fresh = gather_connected_peers(),
    Merged = maps:merge(Fresh, State1#state.peers),
    Merged2 = case StuckPeer of
        undefined -> Merged;
        _ -> maps:remove(StuckPeer, Merged)
    end,
    MergedStats = maps:merge(
        maps:from_list([{P, #peer_stats{}} || P <- maps:keys(Merged2),
                                              not maps:is_key(P, State1#state.peer_stats)]),
        State1#state.peer_stats),
    State2 = State1#state{peers = Merged2, peer_stats = MergedStats},
    blast_request_height(Height, State2).

handle_stall(Height, Peer, #state{in_flight = InFlight,
                                    hash_to_height = H2H,
                                    peer_stats = AllStats} = State) ->
    %% Remove from in_flight and reverse index, re-queue
    StallHash = case maps:get(Height, InFlight, undefined) of
        {_, _, H} -> H;
        _ -> undefined
    end,
    InFlight2 = maps:remove(Height, InFlight),
    H2H2 = case StallHash of
        undefined -> H2H;
        _ -> maps:remove(StallHash, H2H)
    end,
    Queue = [Height | State#state.download_queue],

    %% Update peer stall count
    Stats = maps:get(Peer, AllStats, #peer_stats{}),
    Stats2 = Stats#peer_stats{
        stall_count = Stats#peer_stats.stall_count + 1,
        in_flight_count = max(0, Stats#peer_stats.in_flight_count - 1)
    },
    AllStats2 = maps:put(Peer, Stats2, AllStats),

    %% Score misbehavior for stalling block downloads (+50 per stall)
    beamchain_peer:add_misbehavior(Peer, 50),

    %% If peer has stalled too many times, disconnect
    case Stats2#peer_stats.stall_count >= 3 of
        true ->
            logger:info("block_sync: disconnecting stalling peer ~p", [Peer]),
            beamchain_peer:disconnect(Peer),
            %% Re-queue ALL blocks from this peer
            requeue_peer_blocks(Peer,
                State#state{in_flight = InFlight2,
                            hash_to_height = H2H2,
                            download_queue = Queue,
                            peer_stats = AllStats2});
        false ->
            State#state{in_flight = InFlight2,
                        hash_to_height = H2H2,
                        download_queue = Queue,
                        peer_stats = AllStats2}
    end.

%%% ===================================================================
%%% Internal: notfound handling
%%% ===================================================================

%% Handle notfound response — peer doesn't have the requested blocks.
%% Re-queue those blocks for download from other peers.
handle_notfound_items(Peer, Items, State) ->
    lists:foldl(fun({_Type, Hash}, AccState) ->
        case maps:find(Hash, AccState#state.hash_to_height) of
            {ok, Height} ->
                %% Remove from in_flight and reverse index, re-queue
                InFlight2 = maps:remove(Height, AccState#state.in_flight),
                H2H2 = maps:remove(Hash, AccState#state.hash_to_height),
                Queue = [Height | AccState#state.download_queue],
                AllStats = decrement_peer_in_flight(Peer,
                    AccState#state.peer_stats),
                AccState#state{
                    in_flight = InFlight2,
                    hash_to_height = H2H2,
                    download_queue = Queue,
                    peer_stats = AllStats
                };
            error ->
                AccState
        end
    end, State, Items).

%%% ===================================================================
%%% Internal: BIP152 compact block handling
%%% ===================================================================

%% Handle a compact block message.
%% Try to reconstruct the full block using mempool transactions.
%% If successful, process it like a regular block.
%% If missing transactions, send getblocktxn request.
handle_cmpctblock_received(Peer, CmpctBlock, State) ->
    #{header := Header} = CmpctBlock,
    BlockHash = beamchain_serialize:block_hash(Header),

    %% Check if we requested this block
    case maps:find(BlockHash, State#state.hash_to_height) of
        {ok, Height} ->
            do_handle_cmpctblock(Peer, CmpctBlock, BlockHash, Height, State);
        error ->
            %% Unsolicited compact block (maybe high-bandwidth mode)
            %% For now, ignore unsolicited compact blocks during IBD
            logger:debug("block_sync: unsolicited cmpctblock ~s from ~p",
                         [hash_hex(BlockHash), Peer]),
            State
    end.

do_handle_cmpctblock(Peer, CmpctBlock, BlockHash, Height, State) ->
    case beamchain_compact_block:init_compact_block(CmpctBlock) of
        {ok, CompactState} ->
            %% Try to reconstruct using mempool + recent transactions
            RecentTxns = State#state.recent_txns,
            case beamchain_compact_block:try_reconstruct(CompactState,
                                                         RecentTxns) of
                {ok, Block} ->
                    %% Full reconstruction successful
                    logger:debug("block_sync: reconstructed compact block "
                                 "at height ~B from mempool", [Height]),
                    handle_block_received(Peer, Block, State);

                {partial, PartialState} ->
                    %% Need to request missing transactions
                    MissingIdxs = beamchain_compact_block:get_missing_indices(
                        PartialState),
                    logger:debug("block_sync: compact block at ~B missing ~B "
                                 "txns, requesting", [Height, length(MissingIdxs)]),
                    %% Send getblocktxn request
                    send_getblocktxn(Peer, BlockHash, MissingIdxs),
                    %% Store pending compact block state
                    Now = erlang:monotonic_time(millisecond),
                    PendingCompact = maps:put(BlockHash,
                                               {PartialState, Now, Peer},
                                               State#state.pending_compact),
                    State#state{pending_compact = PendingCompact};

                {error, Reason} ->
                    logger:warning("block_sync: compact block init failed: ~p",
                                   [Reason]),
                    %% Fall back to full block request
                    request_full_block(Peer, BlockHash, State)
            end;
        {error, Reason} ->
            logger:warning("block_sync: invalid compact block: ~p", [Reason]),
            beamchain_peer:add_misbehavior(Peer, 20),
            State
    end.

%% Handle blocktxn response (missing transactions for a compact block)
handle_blocktxn_received(Peer, BlockTxn, State) ->
    #{block_hash := BlockHash, transactions := Txns} = BlockTxn,

    case maps:find(BlockHash, State#state.pending_compact) of
        {ok, {PartialState, _RequestedAt, _RequestPeer}} ->
            %% Try to fill in the block
            case beamchain_compact_block:fill_block(PartialState, Txns) of
                {ok, Block} ->
                    %% Remove from pending
                    PendingCompact = maps:remove(BlockHash,
                                                  State#state.pending_compact),
                    State2 = State#state{pending_compact = PendingCompact},
                    %% Add received transactions to recent_txns cache
                    State3 = add_recent_txns(Txns, State2),
                    %% Process like a regular block
                    handle_block_received(Peer, Block, State3);

                {error, Reason} ->
                    logger:warning("block_sync: blocktxn fill failed: ~p",
                                   [Reason]),
                    %% Request full block instead
                    PendingCompact = maps:remove(BlockHash,
                                                  State#state.pending_compact),
                    State2 = State#state{pending_compact = PendingCompact},
                    request_full_block(Peer, BlockHash, State2)
            end;

        error ->
            %% No pending compact block for this hash
            logger:debug("block_sync: unexpected blocktxn for ~s",
                         [hash_hex(BlockHash)]),
            State
    end.

%% Send getblocktxn request for missing transactions
send_getblocktxn(Peer, BlockHash, MissingIdxs) ->
    Msg = {getblocktxn, #{block_hash => BlockHash, indexes => MissingIdxs}},
    beamchain_peer:send_message(Peer, Msg).

%% Request full block (fallback from compact block)
request_full_block(Peer, BlockHash, State) ->
    Item = #{type => ?MSG_WITNESS_BLOCK, hash => BlockHash},
    beamchain_peer:send_message(Peer, {getdata, #{items => [Item]}}),
    State.

%% Add transactions to the recent transactions cache
add_recent_txns(Txns, #state{recent_txns = Recent,
                              max_recent_txns = MaxRecent} = State) ->
    NewRecent = Txns ++ Recent,
    Trimmed = case length(NewRecent) > MaxRecent of
        true -> lists:sublist(NewRecent, MaxRecent);
        false -> NewRecent
    end,
    State#state{recent_txns = Trimmed}.

%%% ===================================================================
%%% Internal: peer disconnect handling
%%% ===================================================================

handle_peer_disconnect(Peer, State) ->
    %% Re-queue all blocks that were in flight from this peer
    State2 = requeue_peer_blocks(Peer, State),
    %% Remove peer from tracking
    Peers2 = maps:remove(Peer, State2#state.peers),
    PeerStats2 = maps:remove(Peer, State2#state.peer_stats),
    State3 = State2#state{peers = Peers2, peer_stats = PeerStats2},
    case State3#state.status of
        syncing -> fill_pipeline(State3);
        _ -> State3
    end.

%% Re-queue all in-flight blocks from a given peer.
requeue_peer_blocks(Peer, #state{in_flight = InFlight,
                                   hash_to_height = H2H,
                                   download_queue = Queue} = State) ->
    {ReQueued, Remaining, H2H2} = maps:fold(
        fun(Height, {P, _At, Hash}, {RQ, Rem, H2HAcc}) when P =:= Peer ->
            {[Height | RQ], Rem, maps:remove(Hash, H2HAcc)};
           (Height, Entry, {RQ, Rem, H2HAcc}) ->
            {RQ, maps:put(Height, Entry, Rem), H2HAcc}
        end, {[], #{}, H2H}, InFlight),

    %% Sort re-queued heights and prepend to queue for sequential fetch
    SortedRQ = lists:sort(ReQueued),
    State#state{in_flight = Remaining,
                hash_to_height = H2H2,
                download_queue = SortedRQ ++ Queue}.

%%% ===================================================================
%%% Internal: completion check
%%% ===================================================================

maybe_complete(#state{in_flight = InFlight, downloaded = Downloaded,
                       download_queue = [], next_to_validate = NextH,
                       target_height = TargetH} = State) ->
    case maps:size(InFlight) =:= 0 andalso maps:size(Downloaded) =:= 0
         andalso NextH > TargetH of
        true ->
            logger:info("block_sync: IBD complete at height ~B",
                        [TargetH]),
            State2 = cancel_timers(State),
            report_progress(State2),
            %% Notify sync coordinator
            beamchain_sync:notify_blocks_complete(TargetH),
            State2#state{status = complete};
        false ->
            %% Still have in-flight or downloaded blocks to process
            State
    end;
maybe_complete(State) ->
    State.

%%% ===================================================================
%%% Internal: progress reporting
%%% ===================================================================

report_progress(#state{progress_cb = undefined}) ->
    ok;
report_progress(#state{progress_cb = Cb,
                         next_to_validate = NextH,
                         target_height = TargetH,
                         blocks_validated = Validated,
                         last_progress_time = LastTime,
                         last_progress_height = LastHeight,
                         in_flight = InFlight,
                         peers = Peers} = _State) ->
    Now = erlang:monotonic_time(millisecond),
    Elapsed = max(1, Now - LastTime),
    BlocksSince = NextH - LastHeight,
    BlocksPerSec = (BlocksSince * 1000) / max(1, Elapsed),
    Remaining = max(0, TargetH - NextH + 1),
    Eta = case BlocksPerSec > 0.1 of
        true -> round(Remaining / BlocksPerSec);
        false -> 0
    end,
    Progress = case TargetH > 0 of
        true ->
            min(100.0, ((NextH - 1) * 100.0) / max(1, TargetH));
        false ->
            0.0
    end,
    Info = #{
        phase => block,
        current_height => NextH - 1,
        total_height => TargetH,
        progress_percent => Progress,
        blocks_per_second => BlocksPerSec,
        eta_seconds => Eta,
        peer_count => maps:size(Peers),
        in_flight_count => maps:size(InFlight),
        blocks_validated => Validated
    },
    try Cb(Info)
    catch _:_ -> ok
    end.

%%% ===================================================================
%%% Internal: helpers
%%% ===================================================================

cancel_timers(#state{stall_timer = ST, progress_timer = PT} = State) ->
    case ST of
        undefined -> ok;
        _ -> erlang:cancel_timer(ST)
    end,
    case PT of
        undefined -> ok;
        _ -> erlang:cancel_timer(PT)
    end,
    %% Flush timer messages
    receive stall_check -> ok after 0 -> ok end,
    receive progress_tick -> ok after 0 -> ok end,
    State#state{stall_timer = undefined, progress_timer = undefined}.

decrement_peer_in_flight(Peer, AllStats) ->
    case maps:get(Peer, AllStats, undefined) of
        undefined -> AllStats;
        Stats ->
            Stats2 = Stats#peer_stats{
                in_flight_count = max(0,
                    Stats#peer_stats.in_flight_count - 1)
            },
            maps:put(Peer, Stats2, AllStats)
    end.

%% Format a hash as hex for logging (first 8 chars).
hash_hex(<<H:4/binary, _/binary>>) ->
    lists:flatten(io_lib:format("~s...", [binary_to_hex_str(H)]));
hash_hex(_) ->
    "???".

binary_to_hex_str(Bin) ->
    lists:flatten([io_lib:format("~2.16.0b", [B]) || <<B:8>> <= Bin]).
