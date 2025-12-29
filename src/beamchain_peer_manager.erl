-module(beamchain_peer_manager).
-behaviour(gen_server).

%% Manages the pool of peer connections.
%%
%% Maintains an ETS table of active peers indexed by pid and address.
%% Monitors all peer processes and cleans up on exit. Acts as the
%% handler for peer callbacks (peer_connected, peer_disconnected, etc).

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% API
-export([start_link/0,
         connect_to/2,
         get_peers/0,
         get_peer/1,
         peer_count/0,
         outbound_count/0,
         inbound_count/0,
         disconnect_peer/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2]).

-define(SERVER, ?MODULE).
-define(PEER_TABLE, beamchain_peers).

-record(peer_entry, {
    pid         :: pid(),
    address     :: {inet:ip_address(), inet:port_number()},
    direction   :: inbound | outbound,
    mon_ref     :: reference(),
    connected   :: boolean(),    %% true after handshake complete
    info = #{}  :: map()         %% version, services, user_agent, etc
}).

-record(state, {
    %% Our random nonce for self-connection detection across peers
    our_nonce   :: non_neg_integer(),
    %% Address -> ban_until (erlang:system_time(second))
    banned = #{} :: #{term() => non_neg_integer()}
}).

%%% ===================================================================
%%% API
%%% ===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc Connect to a peer at the given address.
-spec connect_to(inet:ip_address(), inet:port_number()) ->
    {ok, pid()} | {error, term()}.
connect_to(IP, Port) ->
    gen_server:call(?SERVER, {connect_to, IP, Port}).

%% @doc Return a list of all connected peer entries.
-spec get_peers() -> [map()].
get_peers() ->
    ets:foldl(fun(#peer_entry{} = E, Acc) ->
        [entry_to_map(E) | Acc]
    end, [], ?PEER_TABLE).

%% @doc Get info about a single peer by pid.
-spec get_peer(pid()) -> {ok, map()} | {error, not_found}.
get_peer(Pid) ->
    case ets:lookup(?PEER_TABLE, Pid) of
        [#peer_entry{} = E] -> {ok, entry_to_map(E)};
        [] -> {error, not_found}
    end.

%% @doc Total number of connected peers.
-spec peer_count() -> non_neg_integer().
peer_count() ->
    ets:info(?PEER_TABLE, size).

%% @doc Number of outbound peers.
-spec outbound_count() -> non_neg_integer().
outbound_count() ->
    count_by_direction(outbound).

%% @doc Number of inbound peers.
-spec inbound_count() -> non_neg_integer().
inbound_count() ->
    count_by_direction(inbound).

%% @doc Disconnect a specific peer.
-spec disconnect_peer(pid()) -> ok.
disconnect_peer(Pid) ->
    gen_server:cast(?SERVER, {disconnect_peer, Pid}).

%%% ===================================================================
%%% gen_server callbacks
%%% ===================================================================

init([]) ->
    %% Create ETS table for peer registry — set with pid as key,
    %% public reads so other processes can look up peers quickly
    ets:new(?PEER_TABLE, [named_table, set, public,
                          {keypos, #peer_entry.pid},
                          {read_concurrency, true}]),
    Nonce = generate_nonce(),
    {ok, #state{our_nonce = Nonce}}.

handle_call({connect_to, IP, Port}, _From, State) ->
    Address = {IP, Port},
    case is_banned(Address, State) of
        true ->
            {reply, {error, banned}, State};
        false ->
            case find_peer_by_address(Address) of
                {ok, _Pid} ->
                    {reply, {error, already_connected}, State};
                error ->
                    case do_connect(Address) of
                        {ok, Pid} ->
                            MonRef = erlang:monitor(process, Pid),
                            Entry = #peer_entry{
                                pid = Pid,
                                address = Address,
                                direction = outbound,
                                mon_ref = MonRef,
                                connected = false
                            },
                            ets:insert(?PEER_TABLE, Entry),
                            {reply, {ok, Pid}, State};
                        {error, Reason} ->
                            {reply, {error, Reason}, State}
                    end
            end
    end;

handle_call(get_state, _From, State) ->
    {reply, State, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast({disconnect_peer, Pid}, State) ->
    case ets:lookup(?PEER_TABLE, Pid) of
        [_] -> beamchain_peer:disconnect(Pid);
        []  -> ok
    end,
    {noreply, State};

handle_cast(_Msg, State) ->
    {noreply, State}.

%% Peer handshake completed
handle_info({peer_connected, Pid, Info}, State) ->
    case ets:lookup(?PEER_TABLE, Pid) of
        [#peer_entry{} = Entry] ->
            Entry2 = Entry#peer_entry{
                connected = true,
                info = Info
            },
            ets:insert(?PEER_TABLE, Entry2),
            logger:info("peer manager: ~p connected (~s)",
                        [Entry2#peer_entry.address,
                         maps:get(user_agent, Info, <<"unknown">>)]);
        [] ->
            %% Unknown peer, ignore
            ok
    end,
    {noreply, State};

%% Peer disconnected gracefully
handle_info({peer_disconnected, Pid, Reason}, State) ->
    logger:debug("peer manager: ~p disconnected: ~p",
                 [Pid, Reason]),
    remove_peer(Pid),
    {noreply, State};

%% Peer banned due to misbehavior
handle_info({peer_banned, Pid, Address}, State) ->
    logger:info("peer manager: banning ~p", [Address]),
    remove_peer(Pid),
    %% Ban for 24 hours
    BanUntil = erlang:system_time(second) + 86400,
    Banned2 = maps:put(Address, BanUntil, State#state.banned),
    {noreply, State#state{banned = Banned2}};

%% Peer messages (forwarded from peer process)
handle_info({peer_message, Pid, Command, Payload}, State) ->
    handle_peer_message(Pid, Command, Payload, State);

%% Monitored peer process died
handle_info({'DOWN', _MonRef, process, Pid, Reason}, State) ->
    case ets:lookup(?PEER_TABLE, Pid) of
        [#peer_entry{address = Addr}] ->
            logger:debug("peer ~p (~p) process down: ~p",
                         [Addr, Pid, Reason]),
            remove_peer(Pid);
        [] ->
            ok
    end,
    {noreply, State};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    %% Disconnect all peers
    ets:foldl(fun(#peer_entry{pid = Pid}, _) ->
        catch beamchain_peer:disconnect(Pid)
    end, ok, ?PEER_TABLE),
    ok.

%%% ===================================================================
%%% Internal: connection
%%% ===================================================================

do_connect(Address) ->
    beamchain_peer:connect(Address, self(), #{}).

%%% ===================================================================
%%% Internal: peer registry helpers
%%% ===================================================================

remove_peer(Pid) ->
    case ets:lookup(?PEER_TABLE, Pid) of
        [#peer_entry{mon_ref = MonRef}] ->
            erlang:demonitor(MonRef, [flush]),
            ets:delete(?PEER_TABLE, Pid);
        [] ->
            ok
    end.

find_peer_by_address(Address) ->
    case ets:match_object(?PEER_TABLE,
                          #peer_entry{address = Address, _ = '_'}) of
        [#peer_entry{pid = Pid} | _] -> {ok, Pid};
        [] -> error
    end.

count_by_direction(Dir) ->
    ets:foldl(fun(#peer_entry{direction = D}, Count) ->
        case D of
            Dir -> Count + 1;
            _   -> Count
        end
    end, 0, ?PEER_TABLE).

entry_to_map(#peer_entry{pid = Pid, address = Addr, direction = Dir,
                         connected = Conn, info = Info}) ->
    #{pid => Pid, address => Addr, direction => Dir,
      connected => Conn, info => Info}.

%%% ===================================================================
%%% Internal: message handling
%%% ===================================================================

handle_peer_message(_Pid, _Command, _Payload, State) ->
    %% For now just ignore — sync module will handle these
    {noreply, State}.

%%% ===================================================================
%%% Internal: ban management
%%% ===================================================================

is_banned(Address, #state{banned = Banned}) ->
    case maps:find(Address, Banned) of
        {ok, BanUntil} ->
            erlang:system_time(second) < BanUntil;
        error ->
            false
    end.

%%% ===================================================================
%%% Internal: helpers
%%% ===================================================================

generate_nonce() ->
    <<N:64>> = crypto:strong_rand_bytes(8),
    N.
