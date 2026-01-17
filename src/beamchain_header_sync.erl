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
    peer_heights = #{}      :: #{pid() => non_neg_integer()}
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

handle_cast({start_sync, Opts}, #state{status = idle} = State) ->
    ProgressCb = maps:get(progress_cb, Opts, undefined),
    State2 = State#state{progress_cb = ProgressCb},
    State3 = pick_sync_peer_and_start(State2),
    {noreply, State3};
handle_cast({start_sync, _Opts}, State) ->
    %% Already syncing or complete
    {noreply, State};

handle_cast(stop_sync, State) ->
    State2 = cancel_timer(State),
    {noreply, State2#state{status = idle, sync_peer = undefined}};

handle_cast({headers, Peer, Headers}, #state{status = syncing,
                                              sync_peer = Peer} = State) ->
    State2 = cancel_timer(State),
    State3 = process_headers(Headers, State2),
    {noreply, State3};
handle_cast({headers, _Peer, _Headers}, State) ->
    %% Headers from a peer we're not syncing from, ignore
    {noreply, State};

handle_cast({peer_connected, Peer, Info}, State) ->
    PeerHeight = maps:get(start_height, Info, 0),
    PeerHeights = maps:put(Peer, PeerHeight, State#state.peer_heights),
    State2 = State#state{peer_heights = PeerHeights},
    %% If we're idle and this peer is ahead of us, start syncing
    case State2#state.status of
        idle when PeerHeight > State2#state.tip_height ->
            State3 = pick_sync_peer_and_start(State2),
            {noreply, State3};
        _ ->
            {noreply, State2}
    end;

handle_cast({peer_disconnected, Peer}, State) ->
    PeerHeights = maps:remove(Peer, State#state.peer_heights),
    State2 = State#state{peer_heights = PeerHeights},
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
            logger:debug("header_sync: no suitable peer to sync from"),
            State#state{status = idle}
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
    %% No headers at all, use genesis
    Network = beamchain_config:network(),
    Params = beamchain_chain_params:params(Network),
    [maps:get(genesis_hash, Params)];
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

process_headers([], State) ->
    %% Empty response: peer has no new headers for us
    %% Check if we should try another peer or declare complete
    logger:info("header_sync: peer sent 0 headers, checking if in sync"),
    check_sync_complete(State);

process_headers(Headers, State) ->
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
            case State2#state.sync_peer of
                undefined -> ok;
                Peer -> beamchain_peer:add_misbehavior(Peer, 20)
            end,
            State3 = State2#state{sync_peer = undefined, status = idle},
            pick_sync_peer_and_start(State3)
    end.

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

        %% 6. Checkpoint enforcement
        check_checkpoint(NewHeight, BlockHash, Params),

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
        ok = beamchain_db:set_chain_tip(BlockHash, NewHeight),

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

check_checkpoint(Height, BlockHash, Params) ->
    Checkpoints = maps:get(checkpoints, Params, #{}),
    case maps:find(Height, Checkpoints) of
        {ok, ExpectedHash} ->
            case BlockHash =:= ExpectedHash of
                true -> ok;
                false -> throw(checkpoint_mismatch)
            end;
        error ->
            ok
    end.

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
                        PrevHeader#block_header.timestamp
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
    case beamchain_db:get_chain_tip() of
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
    GenesisHash = maps:get(genesis_hash, Params),
    GenesisHeader = Genesis#block.header,
    GenesisWork = beamchain_pow:compute_work(GenesisHeader#block_header.bits),
    CW = chainwork_to_binary(GenesisWork),
    ok = beamchain_db:store_block_index(0, GenesisHash, GenesisHeader, CW, 1),
    ok = beamchain_db:set_chain_tip(GenesisHash, 0),
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
