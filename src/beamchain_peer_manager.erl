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
         disconnect_peer/1,
         resolve_dns_seeds/0,
         is_banned/1,
         broadcast/2,
         broadcast/3,
         request_addresses/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2]).

-define(SERVER, ?MODULE).
-define(PEER_TABLE, beamchain_peers).

%% Connection loop intervals
-define(CONNECT_INTERVAL, 500).        %% 500ms between connection attempts
-define(CONNECT_INTERVAL_SLOW, 10000). %% 10s when at target count
-define(CONNECT_INTERVAL_FAST, 3000).  %% 3s when below minimum

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
    banned = #{} :: #{term() => non_neg_integer()},
    %% Addresses discovered from DNS seeds [{IP, Port}]
    discovered = [] :: [{inet:ip_address(), inet:port_number()}],
    %% Whether DNS resolution is in progress
    dns_pending = false :: boolean(),
    %% Connection loop timer reference
    connect_timer :: reference() | undefined,
    %% Set of /16 netgroups we're connected to (for diversity)
    netgroups = sets:new([{version, 2}]) :: sets:set(term()),
    %% Listening socket for inbound connections
    listen_socket :: gen_tcp:socket() | undefined,
    %% Acceptor process
    acceptor :: pid() | undefined
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

%% @doc Resolve DNS seeds and return discovered addresses.
%% Runs asynchronously — spawns one process per seed.
-spec resolve_dns_seeds() -> ok.
resolve_dns_seeds() ->
    gen_server:cast(?SERVER, resolve_dns_seeds).

%% @doc Check if an address is currently banned.
-spec is_banned({inet:ip_address(), inet:port_number()}) -> boolean().
is_banned(Address) ->
    gen_server:call(?SERVER, {is_banned, Address}).

%% @doc Broadcast a message to all ready peers.
-spec broadcast(atom(), map()) -> ok.
broadcast(Command, Payload) ->
    broadcast(Command, Payload, fun(_) -> true end).

%% @doc Broadcast a message to peers matching a filter function.
%% FilterFun receives a peer entry map and returns true to include.
-spec broadcast(atom(), map(), fun((map()) -> boolean())) -> ok.
broadcast(Command, Payload, FilterFun) ->
    ets:foldl(fun(#peer_entry{pid = Pid, connected = true} = E, _) ->
        case FilterFun(entry_to_map(E)) of
            true  -> beamchain_peer:send_message(Pid, {Command, Payload});
            false -> ok
        end;
    (_, _) -> ok
    end, ok, ?PEER_TABLE).

%% @doc Send a getaddr to a specific peer.
-spec request_addresses(pid()) -> ok.
request_addresses(Pid) ->
    beamchain_peer:send_message(Pid, {getaddr, #{}}).

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
    %% Start listening for inbound connections
    {ListenSock, Acceptor} = start_listener(),
    %% Kick off DNS seed resolution
    self() ! bootstrap,
    %% Start connection maintenance loop
    Timer = erlang:send_after(?CONNECT_INTERVAL, self(), connect_tick),
    {ok, #state{our_nonce = Nonce, connect_timer = Timer,
                listen_socket = ListenSock, acceptor = Acceptor}}.

handle_call({connect_to, IP, Port}, _From, State) ->
    Address = {IP, Port},
    case is_banned_internal(Address, State) of
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

handle_call({is_banned, Address}, _From, State) ->
    {reply, is_banned_internal(Address, State), State};

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

handle_cast(resolve_dns_seeds, #state{dns_pending = true} = State) ->
    %% Already resolving, skip
    {noreply, State};
handle_cast(resolve_dns_seeds, State) ->
    Self = self(),
    Params = beamchain_config:network_params(),
    Seeds = Params#network_params.dns_seeds,
    Port = Params#network_params.default_port,
    %% Spawn a process to resolve all seeds concurrently
    spawn_link(fun() ->
        Addrs = resolve_seeds(Seeds, Port),
        Self ! {dns_seeds_resolved, Addrs}
    end),
    {noreply, State#state{dns_pending = true}};

handle_cast(_Msg, State) ->
    {noreply, State}.

%% Peer handshake completed
handle_info({peer_connected, Pid, Info}, State) ->
    case ets:lookup(?PEER_TABLE, Pid) of
        [#peer_entry{address = Addr} = Entry] ->
            Entry2 = Entry#peer_entry{
                connected = true,
                info = Info
            },
            ets:insert(?PEER_TABLE, Entry2),
            %% Mark as tried in addrman
            beamchain_addrman:mark_tried(Addr),
            %% Track netgroup
            NG = netgroup(Addr),
            Netgroups2 = sets:add_element(NG, State#state.netgroups),
            logger:info("peer manager: ~p connected (~s)",
                        [Addr, maps:get(user_agent, Info, <<"unknown">>)]),
            %% Request addresses from new outbound peers
            case Entry#peer_entry.direction of
                outbound ->
                    beamchain_peer:send_message(Pid, {getaddr, #{}});
                inbound ->
                    ok
            end,
            {noreply, State#state{netgroups = Netgroups2}};
        [] ->
            %% Unknown peer, ignore
            {noreply, State}
    end;

%% Peer disconnected gracefully
handle_info({peer_disconnected, Pid, Reason}, State) ->
    logger:debug("peer manager: ~p disconnected: ~p",
                 [Pid, Reason]),
    State2 = remove_peer_and_update(Pid, State),
    {noreply, State2};

%% Peer banned due to misbehavior
handle_info({peer_banned, Pid, Address}, State) ->
    logger:info("peer manager: banning ~p", [Address]),
    State2 = remove_peer_and_update(Pid, State),
    %% Ban for 24 hours
    BanUntil = erlang:system_time(second) + 86400,
    Banned2 = maps:put(Address, BanUntil, State2#state.banned),
    {noreply, State2#state{banned = Banned2}};

%% Bootstrap: resolve DNS seeds and load from addrman on first start
handle_info(bootstrap, State) ->
    %% Check if addrman has enough addresses
    case beamchain_addrman:count() of
        {New, Tried} when New + Tried < 10 ->
            %% Not enough addresses, resolve DNS seeds
            gen_server:cast(self(), resolve_dns_seeds);
        _ ->
            ok
    end,
    {noreply, State};

%% Connection maintenance tick
handle_info(connect_tick, State) ->
    State2 = maybe_open_connection(State),
    %% Schedule next tick based on how many outbounds we need
    Outbound = outbound_count(),
    Target = ?MAX_OUTBOUND_FULL_RELAY + ?MAX_BLOCK_RELAY_ONLY,
    Interval = case Outbound of
        N when N >= Target -> ?CONNECT_INTERVAL_SLOW;
        N when N < 4       -> ?CONNECT_INTERVAL;
        _                  -> ?CONNECT_INTERVAL_FAST
    end,
    Timer = erlang:send_after(Interval, self(), connect_tick),
    {noreply, State2#state{connect_timer = Timer}};

%% DNS seed resolution completed
handle_info({dns_seeds_resolved, Addrs}, State) ->
    logger:info("dns seeds: discovered ~B addresses", [length(Addrs)]),
    %% Shuffle to avoid always connecting in the same order
    Shuffled = shuffle(Addrs),
    %% Merge with existing discovered addresses, dedup
    Existing = State#state.discovered,
    Merged = lists:usort(Shuffled ++ Existing),
    {noreply, State#state{discovered = Merged, dns_pending = false}};

%% Peer messages (forwarded from peer process)
handle_info({peer_message, Pid, Command, Payload}, State) ->
    handle_peer_message(Pid, Command, Payload, State);

%% Inbound connection accepted
handle_info({accepted, Socket, Address}, State) ->
    State2 = handle_inbound(Socket, Address, State),
    %% Restart acceptor
    Acceptor = spawn_acceptor(State2#state.listen_socket),
    {noreply, State2#state{acceptor = Acceptor}};

%% Acceptor process died (maybe listen socket closed)
handle_info({'DOWN', _MonRef, process, Pid, Reason},
            #state{acceptor = Pid} = State) ->
    logger:warning("acceptor died: ~p", [Reason]),
    %% Restart acceptor if we still have a listen socket
    case State#state.listen_socket of
        undefined ->
            {noreply, State#state{acceptor = undefined}};
        LSock ->
            Acceptor = spawn_acceptor(LSock),
            {noreply, State#state{acceptor = Acceptor}}
    end;

%% Monitored peer process died
handle_info({'DOWN', _MonRef, process, Pid, Reason}, State) ->
    case ets:lookup(?PEER_TABLE, Pid) of
        [#peer_entry{address = Addr}] ->
            logger:debug("peer ~p (~p) process down: ~p",
                         [Addr, Pid, Reason]),
            State2 = remove_peer_and_update(Pid, State),
            {noreply, State2};
        [] ->
            {noreply, State}
    end;

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, State) ->
    %% Close listen socket
    case State#state.listen_socket of
        undefined -> ok;
        LSock -> gen_tcp:close(LSock)
    end,
    %% Disconnect all peers
    ets:foldl(fun(#peer_entry{pid = Pid}, _) ->
        catch beamchain_peer:disconnect(Pid)
    end, ok, ?PEER_TABLE),
    ok.

%%% ===================================================================
%%% Internal: outbound connection logic
%%% ===================================================================

maybe_open_connection(State) ->
    Outbound = outbound_count(),
    Target = ?MAX_OUTBOUND_FULL_RELAY + ?MAX_BLOCK_RELAY_ONLY,
    case Outbound >= Target of
        true ->
            State;   %% at capacity
        false ->
            try_connect_one(State)
    end.

try_connect_one(State) ->
    %% First try addrman
    case beamchain_addrman:select_address() of
        {ok, Address} ->
            attempt_connection(Address, State);
        empty ->
            %% Fall back to discovered DNS addresses
            case State#state.discovered of
                [] ->
                    %% No addresses at all, trigger DNS if needed
                    case State#state.dns_pending of
                        false ->
                            gen_server:cast(self(), resolve_dns_seeds);
                        true ->
                            ok
                    end,
                    State;
                [Address | Rest] ->
                    State2 = State#state{discovered = Rest},
                    attempt_connection(Address, State2)
            end
    end.

attempt_connection(Address, State) ->
    case can_connect(Address, State) of
        true ->
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
                    %% Also add to addrman so it knows about this addr
                    beamchain_addrman:add_address(Address, 0, dns),
                    State;
                {error, Reason} ->
                    logger:debug("failed to connect to ~p: ~p",
                                 [Address, Reason]),
                    beamchain_addrman:mark_failed(Address),
                    State
            end;
        false ->
            State
    end.

%% Check if we should connect to this address
can_connect(Address, State) ->
    not is_banned_internal(Address, State)
        andalso find_peer_by_address(Address) =:= error
        andalso has_netgroup_diversity(Address, State).

%% Ensure we don't connect to too many peers in the same /16 subnet
has_netgroup_diversity(Address, #state{netgroups = _NGs}) ->
    NG = netgroup(Address),
    %% Allow up to 2 peers per netgroup
    Count = ets:foldl(fun(#peer_entry{address = A, direction = outbound}, C) ->
        case netgroup(A) =:= NG of
            true  -> C + 1;
            false -> C
        end;
    (_, C) -> C
    end, 0, ?PEER_TABLE),
    Count < 2.

%% /16 netgroup for IPv4
netgroup({{A, B, _, _}, _Port}) -> {A, B};
netgroup({_IPv6Addr, _Port}) -> other.

do_connect(Address) ->
    beamchain_peer:connect(Address, self(), #{}).

%%% ===================================================================
%%% Internal: peer registry helpers
%%% ===================================================================

remove_peer_and_update(Pid, State) ->
    case ets:lookup(?PEER_TABLE, Pid) of
        [#peer_entry{address = _Addr, mon_ref = MonRef}] ->
            erlang:demonitor(MonRef, [flush]),
            ets:delete(?PEER_TABLE, Pid),
            %% Rebuild netgroups (simpler than tracking removal)
            NGs = rebuild_netgroups(),
            State#state{netgroups = NGs};
        [] ->
            State
    end.

rebuild_netgroups() ->
    ets:foldl(fun(#peer_entry{address = A, direction = outbound,
                               connected = true}, Acc) ->
        sets:add_element(netgroup(A), Acc);
    (_, Acc) -> Acc
    end, sets:new([{version, 2}]), ?PEER_TABLE).

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

handle_peer_message(Pid, addr, Payload, State) ->
    handle_addr_msg(Pid, Payload, State);
handle_peer_message(Pid, getaddr, _Payload, State) ->
    handle_getaddr_msg(Pid, State);
handle_peer_message(_Pid, _Command, _Payload, State) ->
    %% Everything else gets forwarded to sync module later
    {noreply, State}.

handle_addr_msg(Pid, Payload, State) ->
    case beamchain_p2p_msg:decode_payload(addr, Payload) of
        {ok, #{addrs := Addrs}} when length(Addrs) =< 1000 ->
            %% Feed addresses to addrman
            lists:foreach(fun(#{ip := IP, port := Port} = Entry) ->
                Svc = maps:get(services, Entry, 0),
                beamchain_addrman:add_address({IP, Port}, Svc, Pid)
            end, Addrs),
            logger:debug("received ~B addresses from ~p",
                         [length(Addrs), Pid]),
            {noreply, State};
        {ok, #{addrs := Addrs}} when length(Addrs) > 1000 ->
            %% Too many addresses, misbehaving
            beamchain_peer:add_misbehavior(Pid, 20),
            {noreply, State};
        _ ->
            {noreply, State}
    end.

handle_getaddr_msg(Pid, State) ->
    %% Respond with up to 1000 addresses from addrman
    Addrs = beamchain_addrman:get_addresses(1000),
    Now = erlang:system_time(second),
    Entries = [#{timestamp => Now, services => 0,
                 ip => IP, port => Port} || {IP, Port} <- Addrs],
    case Entries of
        [] -> ok;
        _  -> beamchain_peer:send_message(Pid, {addr, #{addrs => Entries}})
    end,
    {noreply, State}.

%%% ===================================================================
%%% Internal: ban management
%%% ===================================================================

is_banned_internal(Address, #state{banned = Banned}) ->
    case maps:find(Address, Banned) of
        {ok, BanUntil} ->
            erlang:system_time(second) < BanUntil;
        error ->
            false
    end.

%%% ===================================================================
%%% Internal: inbound connections
%%% ===================================================================

start_listener() ->
    Params = beamchain_config:network_params(),
    Port = Params#network_params.default_port,
    case gen_tcp:listen(Port, [binary, {active, false}, {packet, raw},
                                {reuseaddr, true}, {nodelay, true},
                                {backlog, 128}]) of
        {ok, LSock} ->
            logger:info("listening on port ~B", [Port]),
            Acceptor = spawn_acceptor(LSock),
            {LSock, Acceptor};
        {error, eaddrinuse} ->
            logger:warning("port ~B already in use, skipping listener", [Port]),
            {undefined, undefined};
        {error, Reason} ->
            logger:warning("failed to listen on port ~B: ~p", [Port, Reason]),
            {undefined, undefined}
    end.

spawn_acceptor(undefined) -> undefined;
spawn_acceptor(LSock) ->
    Self = self(),
    Pid = spawn_link(fun() -> accept_loop(LSock, Self) end),
    Pid.

accept_loop(LSock, Manager) ->
    case gen_tcp:accept(LSock) of
        {ok, Socket} ->
            case inet:peername(Socket) of
                {ok, {IP, Port}} ->
                    %% Transfer socket ownership to manager temporarily
                    Manager ! {accepted, Socket, {IP, Port}};
                {error, _} ->
                    gen_tcp:close(Socket)
            end,
            accept_loop(LSock, Manager);
        {error, closed} ->
            ok;
        {error, _Reason} ->
            %% Brief pause before retrying
            timer:sleep(100),
            accept_loop(LSock, Manager)
    end.

handle_inbound(Socket, Address, State) ->
    case can_accept_inbound(Address, State) of
        true ->
            case beamchain_peer:accept(Socket, Address, self()) of
                {ok, Pid} ->
                    %% Transfer socket ownership to peer process
                    gen_tcp:controlling_process(Socket, Pid),
                    MonRef = erlang:monitor(process, Pid),
                    Entry = #peer_entry{
                        pid = Pid,
                        address = Address,
                        direction = inbound,
                        mon_ref = MonRef,
                        connected = false
                    },
                    ets:insert(?PEER_TABLE, Entry),
                    logger:debug("accepted inbound from ~p", [Address]),
                    State;
                {error, Reason} ->
                    logger:debug("failed to accept from ~p: ~p",
                                 [Address, Reason]),
                    gen_tcp:close(Socket),
                    State
            end;
        false ->
            gen_tcp:close(Socket),
            State
    end.

can_accept_inbound(Address, State) ->
    Inbound = inbound_count(),
    not is_banned_internal(Address, State)
        andalso find_peer_by_address(Address) =:= error
        andalso Inbound < ?MAX_INBOUND.

%%% ===================================================================
%%% Internal: DNS seed resolution
%%% ===================================================================

%% @doc Resolve all DNS seeds concurrently, return [{IP, Port}].
resolve_seeds(Seeds, Port) ->
    Parent = self(),
    Refs = lists:map(fun(Seed) ->
        Ref = make_ref(),
        spawn(fun() ->
            Result = resolve_one_seed(Seed, Port),
            Parent ! {dns_result, Ref, Result}
        end),
        Ref
    end, Seeds),
    %% Collect results with a timeout per seed
    collect_dns_results(Refs, []).

collect_dns_results([], Acc) ->
    lists:flatten(Acc);
collect_dns_results([Ref | Rest], Acc) ->
    receive
        {dns_result, Ref, Addrs} ->
            collect_dns_results(Rest, [Addrs | Acc])
    after 5000 ->
        %% Timed out on this seed, move on
        collect_dns_results(Rest, Acc)
    end.

resolve_one_seed(Seed, Port) ->
    case inet_res:lookup(Seed, in, a, [], 5000) of
        [] ->
            logger:debug("dns seed ~s: no results", [Seed]),
            [];
        IPs ->
            logger:debug("dns seed ~s: ~B addresses", [Seed, length(IPs)]),
            [{IP, Port} || IP <- IPs]
    end.

%%% ===================================================================
%%% Internal: helpers
%%% ===================================================================

generate_nonce() ->
    <<N:64>> = crypto:strong_rand_bytes(8),
    N.

shuffle(List) ->
    Tagged = [{rand:uniform(), X} || X <- List],
    [X || {_, X} <- lists:sort(Tagged)].
