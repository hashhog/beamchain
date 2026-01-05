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
    {noreply, State};

handle_cast({peer_connected, Peer, Info}, State) ->
    PeerHeight = maps:get(start_height, Info, 0),
    PeerHeights = maps:put(Peer, PeerHeight, State#state.peer_heights),
    State2 = State#state{peer_heights = PeerHeights},
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
    OldPeer = State#state.sync_peer,
    State2 = State#state{sync_peer = undefined, timer_ref = undefined},
    State3 = pick_sync_peer_and_start(State2),
    case State3#state.sync_peer of
        OldPeer -> {noreply, State3};
        _       -> {noreply, State3}
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

send_getheaders(#state{sync_peer = Peer, tip_height = TipHeight,
                        tip_hash = TipHash} = State) ->
    Locator = build_block_locator(TipHeight, TipHash),
    Msg = #{
        version => ?PROTOCOL_VERSION,
        locators => Locator,
        stop_hash => <<0:256>>
    },
    beamchain_peer:send_message(Peer, {getheaders, Msg}),
    TimerRef = erlang:send_after(?GETHEADERS_TIMEOUT, self(),
                                 getheaders_timeout),
    State#state{timer_ref = TimerRef}.

%%% ===================================================================
%%% Internal: block locator construction
%%% ===================================================================

%% Build a block locator: exponentially spaced hashes going back
%% from the tip, ending with genesis.
%% [tip, tip-1, tip-2, tip-4, tip-8, ..., genesis]
-spec build_block_locator(integer(), binary()) -> [binary()].
build_block_locator(Height, _TipHash) when Height < 0 ->
    Network = beamchain_config:network(),
    Params = beamchain_chain_params:params(Network),
    [maps:get(genesis_hash, Params)];
build_block_locator(Height, TipHash) ->
    build_locator_hashes(Height, TipHash, 1, []).

build_locator_hashes(Height, Hash, _Step, Acc) when Height =< 0 ->
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
    Acc2 = [Hash | Acc],
    NextHeight = max(0, Height - Step),
    Step2 = case length(Acc2) >= 10 of
        true -> Step * 2;
        false -> 1
    end,
    case beamchain_db:get_block_index(NextHeight) of
        {ok, #{hash := NextHash}} ->
            build_locator_hashes(NextHeight, NextHash, Step2, Acc2);
        not_found ->
            lists:reverse(Acc2)
    end.

%%% ===================================================================
%%% Internal: header processing (TODO: validation)
%%% ===================================================================

process_headers([], State) ->
    logger:info("header_sync: peer sent 0 headers, checking if in sync"),
    check_sync_complete(State);

process_headers(Headers, State) ->
    %% TODO: validate headers before storing
    NumReceived = length(Headers),
    Total = State#state.headers_received + NumReceived,
    State2 = State#state{headers_received = Total},
    case NumReceived >= ?MAX_HEADERS_RESULTS of
        true ->
            send_getheaders(State2);
        false ->
            logger:info("header_sync: received ~B headers (~B total, tip at ~B)",
                        [NumReceived, Total, State2#state.tip_height]),
            check_sync_complete(State2)
    end.

check_sync_complete(#state{peer_heights = PeerHeights,
                            tip_height = TipHeight} = State) ->
    MaxPeerHeight = maps:fold(fun(_Pid, H, Max) ->
        max(H, Max)
    end, 0, PeerHeights),
    case MaxPeerHeight > TipHeight of
        true ->
            State2 = State#state{sync_peer = undefined, status = idle},
            pick_sync_peer_and_start(State2);
        false ->
            logger:info("header_sync: sync complete at height ~B", [TipHeight]),
            State#state{status = complete, sync_peer = undefined}
    end.

%%% ===================================================================
%%% Internal: chain tip loading
%%% ===================================================================

load_chain_tip(Params) ->
    case beamchain_db:get_chain_tip() of
        {ok, #{hash := Hash, height := Height}} ->
            Chainwork = case beamchain_db:get_block_index(Height) of
                {ok, #{chainwork := CW}} -> CW;
                not_found -> <<0:256>>
            end,
            MTPWindow = load_mtp_window(Height),
            {Height, Hash, Chainwork, MTPWindow};
        not_found ->
            init_genesis(Params)
    end.

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

load_mtp_window(Height) when Height < 0 -> [];
load_mtp_window(Height) ->
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
%%% Internal: helpers
%%% ===================================================================

cancel_timer(#state{timer_ref = undefined} = State) ->
    State;
cancel_timer(#state{timer_ref = Ref} = State) ->
    erlang:cancel_timer(Ref),
    receive getheaders_timeout -> ok after 0 -> ok end,
    State#state{timer_ref = undefined}.

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
