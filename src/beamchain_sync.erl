-module(beamchain_sync).
-behaviour(gen_server).

%% Sync coordinator: routes P2P messages to the appropriate sync
%% sub-module (header_sync, block_sync) and manages overall sync
%% lifecycle.

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% API
-export([start_link/0]).
-export([handle_peer_message/3]).
-export([notify_peer_connected/2, notify_peer_disconnected/1]).
-export([get_sync_status/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2]).

-define(SERVER, ?MODULE).

-record(state, {
    %% Current sync phase: idle | headers | blocks | complete
    phase = idle :: idle | headers | blocks | complete,
    %% Header sync process
    header_sync :: pid() | undefined
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
    Status = #{
        phase => State#state.phase,
        header_sync => HeaderStatus
    },
    {reply, Status, State};

handle_call(_Request, _From, State) ->
    {reply, {error, not_implemented}, State}.

%% Peer completed handshake — tell header sync
handle_cast({peer_connected, Peer, Info}, State) ->
    beamchain_header_sync:handle_peer_connected(Peer, Info),
    %% If we're idle, kick off header sync
    State2 = maybe_start_header_sync(State),
    {noreply, State2};

%% Peer disconnected
handle_cast({peer_disconnected, Peer}, State) ->
    beamchain_header_sync:handle_peer_disconnected(Peer),
    {noreply, State};

%% Route peer messages to the right handler
handle_cast({peer_message, Peer, Command, Payload}, State) ->
    State2 = route_message(Peer, Command, Payload, State),
    {noreply, State2};

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
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

route_message(_Peer, inv, _Payload, State) ->
    %% TODO: handle block announcements via inv
    State;

route_message(_Peer, block, _Payload, State) ->
    %% TODO: route to block_sync
    State;

route_message(_Peer, _Command, _Payload, State) ->
    State.

%%% ===================================================================
%%% Internal: sync lifecycle
%%% ===================================================================

maybe_start_header_sync(#state{phase = idle} = State) ->
    beamchain_header_sync:start_sync(#{}),
    State#state{phase = headers};
maybe_start_header_sync(State) ->
    State.
