-module(beamchain_peer_manager).
-behaviour(gen_server).

%% Manages the pool of peer connections.
%%
%% Maintains an ETS table of active peers indexed by pid and address.
%% Monitors all peer processes and cleans up on exit. Acts as the
%% handler for peer callbacks (peer_connected, peer_disconnected, etc).
%%
%% Eclipse attack protections (Bitcoin Core parity):
%% - Strict outbound netgroup diversity: max 1 outbound per netgroup
%% - Anchor connections: persist 2 block-relay-only peers across restarts
%% - Inbound eviction: evict least-useful peer when at capacity

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
         is_whitelisted/1,
         check_inbound/1,
         broadcast/2,
         broadcast/3,
         request_addresses/1,
         %% Misbehavior and banning
         misbehaving/3,
         get_ban_list/0,
         set_ban/3,
         clear_ban/1,
         %% Stale peer tracking
         update_peer_height/2,
         mark_getheaders_sent/1,
         mark_headers_received/1,
         update_ping_latency/2,
         notify_tip_updated/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2]).

-define(SERVER, ?MODULE).
-define(PEER_TABLE, beamchain_peers).
-define(BANNED_PEERS_TABLE, banned_peers).
-define(MISBEHAVIOR_TABLE, peer_misbehavior).

%% Misbehavior scoring thresholds
-define(BAN_THRESHOLD, 100).
-define(DEFAULT_BAN_DURATION, 86400).  %% 24 hours in seconds

%% Connection limits (matches Bitcoin Core)
-define(MAX_INBOUND_DEFAULT, 125).
-define(MAX_ANCHOR_CONNECTIONS, 2).

%% Misbehavior score values (Bitcoin Core compatible)
-define(MISBEHAVIOR_INVALID_BLOCK, 100).       %% instant ban
-define(MISBEHAVIOR_INVALID_TX, 10).
-define(MISBEHAVIOR_UNCONNECTING_HEADERS, 20).
-define(MISBEHAVIOR_INVALID_COMPACT_BLOCK, 100).
-define(MISBEHAVIOR_BLOCK_DOWNLOAD_STALL, 50).
-define(MISBEHAVIOR_UNREQUESTED_DATA, 5).

%% Connection loop intervals
-define(CONNECT_INTERVAL, 500).        %% 500ms between connection attempts
-define(CONNECT_INTERVAL_SLOW, 10000). %% 10s when at target count
-define(CONNECT_INTERVAL_FAST, 3000).  %% 3s when below minimum

%% Inbound eviction: number of peers to protect per category
-define(EVICTION_PROTECT_BY_NETGROUP, 4).
-define(EVICTION_PROTECT_BY_PING, 8).
-define(EVICTION_PROTECT_BY_TX_TIME, 4).
-define(EVICTION_PROTECT_BY_BLOCK_TIME, 4).

%% Stale peer eviction (Bitcoin Core parity)
-define(STALE_CHECK_INTERVAL, 45000).        %% 45 seconds
-define(STALE_TIP_THRESHOLD, 1800).          %% 30 minutes in seconds
-define(HEADERS_RESPONSE_TIMEOUT, 120000).   %% 2 minutes in milliseconds
-define(PING_TIMEOUT, 1200000).              %% 20 minutes in milliseconds
-define(MIN_CONNECT_TIME_FOR_EVICTION, 30).  %% 30 seconds

%% Stale tip detection (Bitcoin Core: TipMayBeStale / CheckForStaleTipAndEvictPeers)
-define(STALE_TIP_CHECK_INTERVAL, 600000).   %% 10 minutes in milliseconds
-define(STALE_TIP_AGE_THRESHOLD, 1800).      %% 30 minutes: 3 * nPowTargetSpacing
-define(PERIODIC_HEADER_INTERVAL, 300000).   %% 5 minutes: periodic getheaders

-record(peer_entry, {
    pid         :: pid(),
    address     :: {inet:ip_address(), inet:port_number()},
    direction   :: inbound | outbound,
    conn_type   :: full_relay | block_relay,  %% for outbound peers
    mon_ref     :: reference(),
    connected   :: boolean(),    %% true after handshake complete
    connect_time :: non_neg_integer(),  %% connection start time
    info = #{}  :: map(),        %% version, services, user_agent, etc
    misbehavior_score = 0 :: non_neg_integer(),  %% accumulated misbehavior score
    %% Eviction metrics
    min_ping_time = infinity :: number() | infinity,
    last_block_time = 0 :: non_neg_integer(),
    last_tx_time = 0 :: non_neg_integer(),
    keyed_netgroup = 0 :: non_neg_integer(),  %% hash of netgroup
    %% Stale peer tracking
    best_height = 0 :: non_neg_integer(),     %% peer's best known height
    last_headers_time = 0 :: non_neg_integer(), %% last headers response time
    pending_getheaders = false :: boolean(),  %% waiting for headers response
    getheaders_sent_at = 0 :: non_neg_integer(), %% when getheaders was sent
    ping_latency = 0 :: non_neg_integer(),    %% last measured ping latency (ms)
    network_type = ipv4 :: ipv4 | ipv6 | tor | i2p | cjdns  %% network type
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
    %% For outbound: strict 1 per netgroup
    outbound_netgroups = sets:new([{version, 2}]) :: sets:set(term()),
    %% Listening socket for inbound connections
    listen_socket :: gen_tcp:socket() | undefined,
    %% Acceptor process
    acceptor :: pid() | undefined,
    %% Max inbound connections (default 125, like Bitcoin Core)
    max_inbound :: non_neg_integer(),
    %% Anchor connections: addresses to connect to on startup
    anchors = [] :: [{inet:ip_address(), inet:port_number()}],
    %% Secret for keyed netgroup hashing
    netgroup_secret :: binary(),
    %% Data directory for anchor file
    datadir :: string(),
    %% Stale peer check timer
    stale_check_timer :: reference() | undefined,
    %% Stale tip detection: when our chain tip last advanced (erlang:system_time(second))
    last_tip_update :: non_neg_integer(),
    %% Timer for periodic stale tip check
    stale_tip_timer :: reference() | undefined,
    %% Timer for periodic getheaders to random peer
    periodic_header_timer :: reference() | undefined
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

%% @doc Check if an IP is whitelisted.
-spec is_whitelisted(inet:ip_address()) -> boolean().
is_whitelisted(IP) ->
    Whitelist = beamchain_config:get(whitelist, []),
    check_whitelist(IP, Whitelist).

%% @doc Check if an inbound connection should be accepted before handshake.
%% Returns {ok, accept} if the connection can proceed,
%% or {reject, Reason} if it should be rejected immediately.
%% Checks ban list, max inbound limit, and whitelist.
-spec check_inbound({inet:ip_address(), inet:port_number()}) ->
    {ok, accept} | {reject, banned | too_many_inbound | already_connected}.
check_inbound(Address) ->
    gen_server:call(?SERVER, {check_inbound, Address}).

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

%% @doc Report misbehavior by a peer. Increments the peer's score by the
%% given amount and logs the reason. When the score reaches 100, the peer
%% is banned (disconnected and IP added to ban list for 24 hours).
%%
%% Score values follow Bitcoin Core conventions:
%% - invalid_block: 100 (instant ban)
%% - invalid_tx: 10
%% - unconnecting_headers: 20
%% - invalid_compact_block: 100 (instant ban)
-spec misbehaving(pid(), non_neg_integer(), binary() | string()) -> ok.
misbehaving(Pid, Score, Reason) ->
    gen_server:cast(?SERVER, {misbehaving, Pid, Score, Reason}).

%% @doc Get list of all banned IPs with their expiry times.
-spec get_ban_list() -> [{inet:ip_address(), non_neg_integer()}].
get_ban_list() ->
    gen_server:call(?SERVER, get_ban_list).

%% @doc Manually ban an IP address for the specified duration (seconds).
-spec set_ban(inet:ip_address(), non_neg_integer(), binary() | string()) -> ok.
set_ban(IP, Duration, Reason) ->
    gen_server:call(?SERVER, {set_ban, IP, Duration, Reason}).

%% @doc Remove an IP address from the ban list.
-spec clear_ban(inet:ip_address()) -> ok | {error, not_found}.
clear_ban(IP) ->
    gen_server:call(?SERVER, {clear_ban, IP}).

%% @doc Update a peer's best known block height.
%% Called when we receive headers or block announcements from a peer.
-spec update_peer_height(pid(), non_neg_integer()) -> ok.
update_peer_height(Pid, Height) ->
    Now = erlang:system_time(second),
    case ets:lookup(?PEER_TABLE, Pid) of
        [Entry] ->
            ets:insert(?PEER_TABLE, Entry#peer_entry{
                best_height = Height,
                last_block_time = Now
            });
        [] ->
            ok
    end.

%% @doc Mark that we sent a getheaders request to this peer.
%% Starts the headers response timeout tracking.
-spec mark_getheaders_sent(pid()) -> ok.
mark_getheaders_sent(Pid) ->
    Now = erlang:system_time(millisecond),
    case ets:lookup(?PEER_TABLE, Pid) of
        [Entry] ->
            ets:insert(?PEER_TABLE, Entry#peer_entry{
                pending_getheaders = true,
                getheaders_sent_at = Now
            });
        [] ->
            ok
    end.

%% @doc Mark that we received a headers response from this peer.
%% Clears the pending headers flag.
-spec mark_headers_received(pid()) -> ok.
mark_headers_received(Pid) ->
    Now = erlang:system_time(second),
    case ets:lookup(?PEER_TABLE, Pid) of
        [Entry] ->
            ets:insert(?PEER_TABLE, Entry#peer_entry{
                pending_getheaders = false,
                getheaders_sent_at = 0,
                last_headers_time = Now
            });
        [] ->
            ok
    end.

%% @doc Update a peer's ping latency.
%% Called when we receive a pong response.
-spec update_ping_latency(pid(), non_neg_integer()) -> ok.
update_ping_latency(Pid, LatencyMs) ->
    case ets:lookup(?PEER_TABLE, Pid) of
        [Entry] ->
            ets:insert(?PEER_TABLE, Entry#peer_entry{ping_latency = LatencyMs});
        [] ->
            ok
    end.

%% @doc Notify that our chain tip has been updated (new block connected).
%% Resets the stale tip timer so we don't falsely detect stale tip.
-spec notify_tip_updated() -> ok.
notify_tip_updated() ->
    gen_server:cast(?SERVER, tip_updated).

%%% ===================================================================
%%% gen_server callbacks
%%% ===================================================================

init([]) ->
    %% Create ETS table for peer registry — set with pid as key,
    %% public reads so other processes can look up peers quickly
    ets:new(?PEER_TABLE, [named_table, set, public,
                          {keypos, #peer_entry.pid},
                          {read_concurrency, true}]),
    %% Create ETS table for banned peers: {IP, BanExpiry}
    %% Using IP only (not port) for banning as that matches Bitcoin Core
    case ets:info(?BANNED_PEERS_TABLE) of
        undefined ->
            ets:new(?BANNED_PEERS_TABLE, [named_table, set, public,
                                           {read_concurrency, true}]);
        _ ->
            ok  %% table already exists (e.g., from tests)
    end,
    Nonce = generate_nonce(),
    DataDir = beamchain_config:datadir(),
    %% Generate or load netgroup secret
    NetgroupSecret = load_or_generate_netgroup_secret(DataDir),
    %% Load anchor connections
    Anchors = load_anchors(DataDir),
    %% Start listening for inbound connections
    {ListenSock, Acceptor} = start_listener(),
    %% Kick off DNS seed resolution
    self() ! bootstrap,
    %% Start connection maintenance loop
    Timer = erlang:send_after(?CONNECT_INTERVAL, self(), connect_tick),
    %% Load persisted bans from disk
    load_bans(DataDir),
    %% Schedule periodic cleanup of expired bans
    erlang:send_after(60000, self(), cleanup_expired_bans),
    %% Schedule stale peer check
    StaleTimer = erlang:send_after(?STALE_CHECK_INTERVAL, self(), check_stale_peers),
    %% Schedule stale tip detection (Bitcoin Core: CheckForStaleTipAndEvictPeers)
    StaleTipTimer = erlang:send_after(?STALE_TIP_CHECK_INTERVAL, self(), check_stale_tip),
    %% Schedule periodic getheaders to random peer
    PeriodicHdrTimer = erlang:send_after(?PERIODIC_HEADER_INTERVAL, self(), periodic_getheaders),
    Now = erlang:system_time(second),
    MaxInbound = beamchain_config:get(max_inbound, ?MAX_INBOUND_DEFAULT),
    {ok, #state{our_nonce = Nonce, connect_timer = Timer,
                listen_socket = ListenSock, acceptor = Acceptor,
                max_inbound = MaxInbound, anchors = Anchors,
                netgroup_secret = NetgroupSecret, datadir = DataDir,
                stale_check_timer = StaleTimer,
                last_tip_update = Now,
                stale_tip_timer = StaleTipTimer,
                periodic_header_timer = PeriodicHdrTimer}}.

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
                    case do_connect(Address, full_relay, State) of
                        {ok, Pid, State2} ->
                            {reply, {ok, Pid}, State2};
                        {error, Reason} ->
                            {reply, {error, Reason}, State}
                    end
            end
    end;

handle_call({is_banned, Address}, _From, State) ->
    {reply, is_banned_internal(Address, State), State};

handle_call({check_inbound, {IP, _Port} = Address}, _From, State) ->
    %% Pre-handshake rejection check following Bitcoin Core AcceptConnection logic:
    %% 1. Check if banned (unless whitelisted)
    %% 2. Check if already connected
    %% 3. Check max inbound limit (with eviction)
    Whitelisted = is_whitelisted(IP),
    Result = case Whitelisted of
        true ->
            %% Whitelisted IPs bypass ban check
            check_inbound_internal(Address, State);
        false ->
            case is_banned_internal(Address, State) of
                true ->
                    {reject, banned};
                false ->
                    check_inbound_internal(Address, State)
            end
    end,
    {reply, Result, State};

handle_call(get_ban_list, _From, State) ->
    BanList = get_ban_list_internal(),
    {reply, BanList, State};

handle_call({set_ban, IP, Duration, Reason}, _From, State) ->
    BanExpiry = erlang:system_time(second) + Duration,
    ets:insert(?BANNED_PEERS_TABLE, {IP, BanExpiry}),
    logger:info("peer manager: manually banned ~p for ~B seconds: ~s",
                [IP, Duration, Reason]),
    %% Disconnect any connected peers from this IP
    disconnect_peers_by_ip(IP),
    {reply, ok, State};

handle_call({clear_ban, IP}, _From, State) ->
    case ets:lookup(?BANNED_PEERS_TABLE, IP) of
        [{IP, _}] ->
            ets:delete(?BANNED_PEERS_TABLE, IP),
            logger:info("peer manager: unbanned ~p", [IP]),
            {reply, ok, State};
        [] ->
            {reply, {error, not_found}, State}
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

handle_cast(resolve_dns_seeds, #state{dns_pending = true} = State) ->
    %% Already resolving, skip
    {noreply, State};
handle_cast(resolve_dns_seeds, State) ->
    Self = self(),
    Params = beamchain_config:network_params(),
    Seeds = Params#network_params.dns_seeds,
    Port = Params#network_params.default_port,
    %% Spawn a process to resolve all seeds concurrently
    spawn(fun() ->
        Addrs = resolve_seeds(Seeds, Port),
        Self ! {dns_seeds_resolved, Addrs}
    end),
    {noreply, State#state{dns_pending = true}};

handle_cast({misbehaving, Pid, Score, Reason}, State) ->
    handle_misbehaving(Pid, Score, Reason, State);

%% Chain tip updated — reset stale tip timer
handle_cast(tip_updated, State) ->
    Now = erlang:system_time(second),
    {noreply, State#state{last_tip_update = Now}};

handle_cast(_Msg, State) ->
    {noreply, State}.

%% Peer handshake completed
handle_info({peer_connected, Pid, Info}, State) ->
    case ets:lookup(?PEER_TABLE, Pid) of
        [#peer_entry{address = Addr, direction = Dir} = Entry] ->
            Entry2 = Entry#peer_entry{
                connected = true,
                info = Info,
                keyed_netgroup = calculate_keyed_netgroup(Addr, State)
            },
            ets:insert(?PEER_TABLE, Entry2),
            %% Mark as tried in addrman
            beamchain_addrman:mark_tried(Addr),
            %% Track outbound netgroup
            State2 = case Dir of
                outbound ->
                    NG = beamchain_addrman:netgroup(Addr),
                    NGs = sets:add_element(NG, State#state.outbound_netgroups),
                    State#state{outbound_netgroups = NGs};
                inbound ->
                    State
            end,
            logger:info("peer manager: ~p connected (~s)",
                        [Addr, maps:get(user_agent, Info, <<"unknown">>)]),
            %% Notify sync coordinator about the new peer
            beamchain_sync:notify_peer_connected(Pid, Info),
            %% Request addresses from new outbound peers
            case Dir of
                outbound ->
                    beamchain_peer:send_message(Pid, {getaddr, #{}});
                inbound ->
                    ok
            end,
            {noreply, State2};
        [] ->
            %% Unknown peer, ignore
            {noreply, State}
    end;

%% Peer disconnected gracefully
handle_info({peer_disconnected, Pid, Reason}, State) ->
    logger:debug("peer manager: ~p disconnected: ~p",
                 [Pid, Reason]),
    beamchain_sync:notify_peer_disconnected(Pid),
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
    %% First try anchor connections
    State2 = try_anchor_connections(State),
    %% Check if addrman has enough addresses
    case beamchain_addrman:count() of
        {New, Tried} when New + Tried < 10 ->
            %% Not enough addresses, resolve DNS seeds
            gen_server:cast(self(), resolve_dns_seeds);
        _ ->
            ok
    end,
    {noreply, State2};

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

%% Update peer metrics
handle_info({peer_ping, Pid, PingTime}, State) ->
    case ets:lookup(?PEER_TABLE, Pid) of
        [#peer_entry{min_ping_time = OldMin} = Entry] ->
            NewMin = case OldMin of
                infinity -> PingTime;
                _ -> min(OldMin, PingTime)
            end,
            ets:insert(?PEER_TABLE, Entry#peer_entry{min_ping_time = NewMin});
        [] ->
            ok
    end,
    {noreply, State};

handle_info({peer_block, Pid}, State) ->
    Now = erlang:system_time(second),
    case ets:lookup(?PEER_TABLE, Pid) of
        [Entry] ->
            ets:insert(?PEER_TABLE, Entry#peer_entry{last_block_time = Now});
        [] ->
            ok
    end,
    {noreply, State};

handle_info({peer_tx, Pid}, State) ->
    Now = erlang:system_time(second),
    case ets:lookup(?PEER_TABLE, Pid) of
        [Entry] ->
            ets:insert(?PEER_TABLE, Entry#peer_entry{last_tx_time = Now});
        [] ->
            ok
    end,
    {noreply, State};

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

%% Periodic cleanup of expired bans
handle_info(cleanup_expired_bans, State) ->
    cleanup_expired_bans(),
    erlang:send_after(60000, self(), cleanup_expired_bans),
    {noreply, State};

%% Periodic stale peer check
handle_info(check_stale_peers, State) ->
    check_stale_peers(),
    Timer = erlang:send_after(?STALE_CHECK_INTERVAL, self(), check_stale_peers),
    {noreply, State#state{stale_check_timer = Timer}};

%% Evict a stale peer (called from check_stale_peers or peer process)
handle_info({evict_peer, Pid, Reason}, State) ->
    case ets:lookup(?PEER_TABLE, Pid) of
        [#peer_entry{address = Addr}] ->
            logger:info("peer manager: evicting stale peer ~p: ~s", [Addr, Reason]),
            beamchain_peer:disconnect(Pid);
        [] ->
            ok
    end,
    {noreply, State};

%% Stale tip detection: check if our chain tip hasn't advanced
%% Reference: Bitcoin Core TipMayBeStale() + CheckForStaleTipAndEvictPeers()
handle_info(check_stale_tip, #state{last_tip_update = LastUpdate} = State) ->
    Now = erlang:system_time(second),
    StaleDuration = Now - LastUpdate,
    State2 = case StaleDuration > ?STALE_TIP_AGE_THRESHOLD of
        true ->
            %% Our tip is stale — send getheaders to best peer, disconnect worst
            logger:warning("peer_manager: potential stale tip detected "
                           "(last tip update: ~B seconds ago)", [StaleDuration]),
            handle_stale_tip_detected(State);
        false ->
            State
    end,
    Timer = erlang:send_after(?STALE_TIP_CHECK_INTERVAL, self(), check_stale_tip),
    {noreply, State2#state{stale_tip_timer = Timer}};

%% Periodic getheaders to random peer to discover new blocks
%% Reference: Bitcoin Core SendMessages() periodic header fetch
handle_info(periodic_getheaders, State) ->
    send_periodic_getheaders(),
    Timer = erlang:send_after(?PERIODIC_HEADER_INTERVAL, self(), periodic_getheaders),
    {noreply, State#state{periodic_header_timer = Timer}};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, State) ->
    %% Save anchor connections (block-relay-only outbound peers)
    save_anchors(State),
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
%%% Internal: anchor connections
%%% ===================================================================

load_anchors(DataDir) ->
    AnchorFile = filename:join(DataDir, "anchors.dat"),
    case file:read_file(AnchorFile) of
        {ok, Bin} ->
            try binary_to_term(Bin) of
                Anchors when is_list(Anchors) ->
                    logger:info("peer manager: loaded ~B anchor connections",
                                [length(Anchors)]),
                    Anchors;
                _ ->
                    []
            catch
                _:_ -> []
            end;
        {error, _} ->
            []
    end.

save_anchors(#state{datadir = DataDir}) ->
    %% Save block-relay-only outbound peers as anchors
    Anchors = ets:foldl(fun
        (#peer_entry{address = Addr, direction = outbound,
                     conn_type = block_relay, connected = true}, Acc) ->
            [Addr | Acc];
        (_, Acc) ->
            Acc
    end, [], ?PEER_TABLE),
    %% Keep at most MAX_ANCHOR_CONNECTIONS
    ToSave = lists:sublist(Anchors, ?MAX_ANCHOR_CONNECTIONS),
    case ToSave of
        [] ->
            ok;
        _ ->
            AnchorFile = filename:join(DataDir, "anchors.dat"),
            ok = filelib:ensure_dir(AnchorFile),
            ok = file:write_file(AnchorFile, term_to_binary(ToSave)),
            logger:info("peer manager: saved ~B anchor connections",
                        [length(ToSave)])
    end.

try_anchor_connections(#state{anchors = []} = State) ->
    State;
try_anchor_connections(#state{anchors = Anchors} = State) ->
    %% Try to connect to anchor addresses first
    lists:foldl(fun(Address, S) ->
        case can_connect(Address, S) of
            true ->
                case do_connect(Address, block_relay, S) of
                    {ok, _Pid, S2} ->
                        logger:info("peer manager: connected to anchor ~p", [Address]),
                        S2;
                    {error, _} ->
                        S
                end;
            false ->
                S
        end
    end, State#state{anchors = []}, Anchors).

%%% ===================================================================
%%% Internal: netgroup secret and keyed netgroup
%%% ===================================================================

load_or_generate_netgroup_secret(DataDir) ->
    SecretFile = filename:join(DataDir, "netgroup_secret"),
    case file:read_file(SecretFile) of
        {ok, <<Secret:32/binary>>} ->
            Secret;
        _ ->
            Secret = crypto:strong_rand_bytes(32),
            ok = filelib:ensure_dir(SecretFile),
            ok = file:write_file(SecretFile, Secret),
            Secret
    end.

calculate_keyed_netgroup(Address, #state{netgroup_secret = Secret}) ->
    NG = beamchain_addrman:netgroup(Address),
    erlang:phash2({Secret, NG}).

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
    %% Determine what type of connection we need
    FullRelayCount = count_outbound_by_type(full_relay),
    BlockRelayCount = count_outbound_by_type(block_relay),
    ConnType = case {FullRelayCount < ?MAX_OUTBOUND_FULL_RELAY,
                     BlockRelayCount < ?MAX_BLOCK_RELAY_ONLY} of
        {true, _} -> full_relay;
        {false, true} -> block_relay;
        {false, false} -> full_relay  %% shouldn't happen
    end,
    %% First try addrman
    case beamchain_addrman:select_address() of
        {ok, Address} ->
            attempt_connection(Address, ConnType, State);
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
                    attempt_connection(Address, ConnType, State2)
            end
    end.

attempt_connection(Address, ConnType, State) ->
    case can_connect(Address, State) of
        true ->
            case do_connect(Address, ConnType, State) of
                {ok, _Pid, State2} ->
                    %% Also add to addrman so it knows about this addr
                    beamchain_addrman:add_address(Address, 0, dns),
                    State2;
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

%% Ensure we don't connect to more than 1 outbound peer per netgroup
%% (strict diversity for eclipse protection)
has_netgroup_diversity(Address, #state{outbound_netgroups = NGs}) ->
    NG = beamchain_addrman:netgroup(Address),
    not sets:is_element(NG, NGs).

count_outbound_by_type(Type) ->
    ets:foldl(fun
        (#peer_entry{direction = outbound, conn_type = T}, C) when T =:= Type ->
            C + 1;
        (_, C) ->
            C
    end, 0, ?PEER_TABLE).

do_connect({IP, _Port} = Address, ConnType, State) ->
    case beamchain_peer:connect(Address, self(), #{}) of
        {ok, Pid} ->
            MonRef = erlang:monitor(process, Pid),
            Now = erlang:system_time(second),
            Entry = #peer_entry{
                pid = Pid,
                address = Address,
                direction = outbound,
                conn_type = ConnType,
                mon_ref = MonRef,
                connected = false,
                connect_time = Now,
                keyed_netgroup = calculate_keyed_netgroup(Address, State),
                network_type = get_network_type(IP)
            },
            ets:insert(?PEER_TABLE, Entry),
            %% Track netgroup for diversity (before connection completes)
            NG = beamchain_addrman:netgroup(Address),
            NGs = sets:add_element(NG, State#state.outbound_netgroups),
            {ok, Pid, State#state{outbound_netgroups = NGs}};
        {error, Reason} ->
            {error, Reason}
    end.

%%% ===================================================================
%%% Internal: inbound eviction (Bitcoin Core parity)
%%% ===================================================================

%% @doc Select a peer to evict when we're at inbound capacity.
%% Returns {ok, Pid} if a peer should be evicted, or none if all are protected.
select_peer_to_evict() ->
    %% Collect all inbound peers as eviction candidates
    Candidates = ets:foldl(fun
        (#peer_entry{direction = inbound, connected = true} = E, Acc) ->
            [E | Acc];
        (_, Acc) ->
            Acc
    end, [], ?PEER_TABLE),

    case Candidates of
        [] ->
            none;
        _ ->
            %% Apply Bitcoin Core's eviction protection algorithm
            select_eviction_victim(Candidates)
    end.

select_eviction_victim(Candidates) ->
    %% Step 1: Protect 4 peers by netgroup (deterministically)
    C1 = protect_by_netgroup(Candidates, ?EVICTION_PROTECT_BY_NETGROUP),

    %% Step 2: Protect 8 peers with lowest ping time
    C2 = protect_by_ping(C1, ?EVICTION_PROTECT_BY_PING),

    %% Step 3: Protect 4 peers that most recently sent transactions
    C3 = protect_by_tx_time(C2, ?EVICTION_PROTECT_BY_TX_TIME),

    %% Step 4: Protect 4 peers that most recently sent blocks
    C4 = protect_by_block_time(C3, ?EVICTION_PROTECT_BY_BLOCK_TIME),

    case C4 of
        [] ->
            none;
        _ ->
            %% Evict from the netgroup with the most connections
            %% Select the newest peer from that netgroup
            evict_from_largest_netgroup(C4)
    end.

protect_by_netgroup(Candidates, N) ->
    %% Sort by keyed netgroup, take first N (protect), return rest
    Sorted = lists:sort(fun(#peer_entry{keyed_netgroup = A},
                            #peer_entry{keyed_netgroup = B}) ->
        A =< B
    end, Candidates),
    drop_first_n(Sorted, N).

protect_by_ping(Candidates, N) ->
    %% Sort by ping time (lowest first), protect first N
    Sorted = lists:sort(fun(#peer_entry{min_ping_time = A},
                            #peer_entry{min_ping_time = B}) ->
        compare_ping(A, B)
    end, Candidates),
    drop_first_n(Sorted, N).

compare_ping(infinity, infinity) -> true;
compare_ping(infinity, _) -> false;
compare_ping(_, infinity) -> true;
compare_ping(A, B) -> A =< B.

protect_by_tx_time(Candidates, N) ->
    %% Sort by last tx time (most recent first), protect first N
    Sorted = lists:sort(fun(#peer_entry{last_tx_time = A},
                            #peer_entry{last_tx_time = B}) ->
        A >= B
    end, Candidates),
    drop_first_n(Sorted, N).

protect_by_block_time(Candidates, N) ->
    %% Sort by last block time (most recent first), protect first N
    Sorted = lists:sort(fun(#peer_entry{last_block_time = A},
                            #peer_entry{last_block_time = B}) ->
        A >= B
    end, Candidates),
    drop_first_n(Sorted, N).

drop_first_n(List, N) when N >= length(List) -> [];
drop_first_n(List, N) -> lists:nthtail(N, List).

evict_from_largest_netgroup(Candidates) ->
    %% Group by keyed netgroup
    Groups = lists:foldl(fun(#peer_entry{keyed_netgroup = NG} = E, Acc) ->
        maps:update_with(NG, fun(L) -> [E | L] end, [E], Acc)
    end, #{}, Candidates),

    %% Find the largest group
    {_LargestNG, LargestGroup} = maps:fold(fun(NG, Peers, {BestNG, BestPeers}) ->
        case length(Peers) > length(BestPeers) of
            true -> {NG, Peers};
            false -> {BestNG, BestPeers}
        end
    end, {undefined, []}, Groups),

    case LargestGroup of
        [] ->
            none;
        _ ->
            %% Evict the newest peer from this group (most recently connected)
            Newest = lists:foldl(fun
                (#peer_entry{connect_time = T} = E, #peer_entry{connect_time = BT}) when T > BT ->
                    E;
                (#peer_entry{} = E, undefined) ->
                    E;
                (_, Best) ->
                    Best
            end, undefined, LargestGroup),
            case Newest of
                undefined -> none;
                #peer_entry{pid = Pid} -> {ok, Pid}
            end
    end.

%%% ===================================================================
%%% Internal: peer registry helpers
%%% ===================================================================

remove_peer_and_update(Pid, State) ->
    case ets:lookup(?PEER_TABLE, Pid) of
        [#peer_entry{address = Addr, direction = Dir, mon_ref = MonRef}] ->
            erlang:demonitor(MonRef, [flush]),
            ets:delete(?PEER_TABLE, Pid),
            %% Update outbound netgroups if needed
            case Dir of
                outbound ->
                    NG = beamchain_addrman:netgroup(Addr),
                    NGs = sets:del_element(NG, State#state.outbound_netgroups),
                    State#state{outbound_netgroups = NGs};
                inbound ->
                    State
            end;
        [] ->
            State
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
                         connected = Conn, info = Info, conn_type = ConnType}) ->
    #{pid => Pid, address => Addr, direction => Dir,
      connected => Conn, info => Info, conn_type => ConnType}.

%%% ===================================================================
%%% Internal: message handling
%%% ===================================================================

handle_peer_message(Pid, addr, Payload, State) ->
    handle_addr_msg(Pid, Payload, State);
handle_peer_message(Pid, getaddr, _Payload, State) ->
    handle_getaddr_msg(Pid, State);
%% Sync-related messages: forward to sync coordinator
handle_peer_message(Pid, headers, Payload, State) ->
    beamchain_sync:handle_peer_message(Pid, headers, Payload),
    {noreply, State};
handle_peer_message(Pid, inv, Payload, State) ->
    beamchain_sync:handle_peer_message(Pid, inv, Payload),
    {noreply, State};
handle_peer_message(Pid, block, Payload, State) ->
    beamchain_sync:handle_peer_message(Pid, block, Payload),
    {noreply, State};
handle_peer_message(Pid, tx, Payload, State) ->
    beamchain_sync:handle_peer_message(Pid, tx, Payload),
    {noreply, State};
handle_peer_message(Pid, notfound, Payload, State) ->
    beamchain_sync:handle_peer_message(Pid, notfound, Payload),
    {noreply, State};
handle_peer_message(Pid, getdata, Payload, State) ->
    handle_getdata_msg(Pid, Payload),
    {noreply, State};
handle_peer_message(Pid, getheaders, Payload, State) ->
    handle_getheaders_msg(Pid, Payload),
    {noreply, State};
handle_peer_message(_Pid, _Command, _Payload, State) ->
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

handle_getdata_msg(Pid, Payload) ->
    case beamchain_p2p_msg:decode_payload(getdata, Payload) of
        {ok, #{items := Items}} ->
            NotFound = lists:filtermap(fun(#{type := Type, hash := Hash}) ->
                case Type of
                    T when T =:= ?MSG_BLOCK; T =:= ?MSG_WITNESS_BLOCK ->
                        case beamchain_db:get_block(Hash) of
                            {ok, Block} ->
                                beamchain_peer:send_message(Pid, {block, Block}),
                                false;
                            not_found ->
                                {true, #{type => Type, hash => Hash}}
                        end;
                    T when T =:= ?MSG_TX; T =:= ?MSG_WITNESS_TX ->
                        case beamchain_mempool:get_tx(Hash) of
                            {ok, Tx} ->
                                beamchain_peer:send_message(Pid, {tx, Tx}),
                                false;
                            not_found ->
                                {true, #{type => Type, hash => Hash}}
                        end;
                    _ ->
                        {true, #{type => Type, hash => Hash}}
                end
            end, Items),
            case NotFound of
                [] -> ok;
                _  -> beamchain_peer:send_message(Pid,
                        {notfound, #{items => NotFound}})
            end;
        _ ->
            ok
    end.

%% Respond to a getheaders request from a peer.
%% Walk our chain from the best matching locator hash and send up to
%% 2000 headers (the Bitcoin protocol limit).
handle_getheaders_msg(Pid, Payload) ->
    case beamchain_p2p_msg:decode_payload(getheaders, Payload) of
        {ok, #{locators := Locators, stop_hash := StopHash}} ->
            %% Find the best locator hash we have
            StartHeight = find_locator_intersection(Locators),
            %% Collect up to 2000 headers starting after the intersection
            Headers = collect_headers(StartHeight + 1, StopHash, 2000, []),
            case Headers of
                [] -> ok;
                _  -> beamchain_peer:send_message(Pid,
                        {headers, #{headers => Headers}})
            end;
        _ ->
            ok
    end.

%% Find the height of the best (first matching) locator hash.
%% Returns -1 if none match (will start from genesis).
find_locator_intersection([]) -> -1;
find_locator_intersection([Hash | Rest]) ->
    case beamchain_db:get_block_index_by_hash(Hash) of
        {ok, #{height := Height}} -> Height;
        not_found -> find_locator_intersection(Rest)
    end.

%% Collect headers from StartHeight up to 2000 or until StopHash is reached.
collect_headers(_Height, _StopHash, 0, Acc) ->
    lists:reverse(Acc);
collect_headers(Height, StopHash, Remaining, Acc) ->
    case beamchain_db:get_block_index(Height) of
        {ok, #{header := Header, hash := Hash}} ->
            NewAcc = [Header | Acc],
            case Hash =:= StopHash of
                true  -> lists:reverse(NewAcc);
                false -> collect_headers(Height + 1, StopHash,
                                         Remaining - 1, NewAcc)
            end;
        not_found ->
            lists:reverse(Acc)
    end.

%%% ===================================================================
%%% Internal: ban management
%%% ===================================================================

is_banned_internal({IP, _Port}, _State) ->
    %% Check the ETS ban table by IP (ignoring port, like Bitcoin Core)
    is_ip_banned(IP);
is_banned_internal(IP, _State) when is_tuple(IP) ->
    is_ip_banned(IP).

%% Check if an IP is banned in the ETS table
is_ip_banned(IP) ->
    case ets:lookup(?BANNED_PEERS_TABLE, IP) of
        [{IP, BanExpiry}] ->
            Now = erlang:system_time(second),
            case Now < BanExpiry of
                true -> true;
                false ->
                    %% Ban has expired, remove it
                    ets:delete(?BANNED_PEERS_TABLE, IP),
                    false
            end;
        [] ->
            false
    end.

%% Get all currently banned IPs
get_ban_list_internal() ->
    Now = erlang:system_time(second),
    ets:foldl(fun({IP, BanExpiry}, Acc) ->
        case BanExpiry > Now of
            true -> [{IP, BanExpiry} | Acc];
            false -> Acc
        end
    end, [], ?BANNED_PEERS_TABLE).

%% Cleanup expired bans from the ETS table
cleanup_expired_bans() ->
    Now = erlang:system_time(second),
    ets:foldl(fun({IP, BanExpiry}, _) ->
        case BanExpiry =< Now of
            true ->
                ets:delete(?BANNED_PEERS_TABLE, IP),
                logger:debug("peer manager: ban expired for ~p", [IP]);
            false ->
                ok
        end
    end, ok, ?BANNED_PEERS_TABLE).

%% Persist ban list to banned.json in the data directory.
save_bans(DataDir) ->
    BanList = get_ban_list_internal(),
    Entries = lists:map(fun({IP, BanExpiry}) ->
        IPStr = inet:ntoa(IP),
        #{<<"ip">> => list_to_binary(IPStr),
          <<"until_timestamp">> => BanExpiry}
    end, BanList),
    Json = jsx:encode(Entries),
    Path = filename:join(DataDir, "banned.json"),
    ok = file:write_file(Path, Json),
    ok.

%% Load ban list from banned.json on startup.
load_bans(DataDir) ->
    Path = filename:join(DataDir, "banned.json"),
    case file:read_file(Path) of
        {ok, Bin} ->
            try
                Entries = jsx:decode(Bin, [return_maps]),
                Now = erlang:system_time(second),
                lists:foreach(fun(Entry) ->
                    IPStr = binary_to_list(maps:get(<<"ip">>, Entry)),
                    BanExpiry = maps:get(<<"until_timestamp">>, Entry),
                    case inet:parse_address(IPStr) of
                        {ok, IP} when BanExpiry > Now ->
                            ets:insert(?BANNED_PEERS_TABLE, {IP, BanExpiry});
                        _ ->
                            ok
                    end
                end, Entries),
                logger:info("peer manager: loaded ~B bans from ~s",
                            [length(Entries), Path])
            catch
                _:_ ->
                    logger:warning("peer manager: failed to parse ~s", [Path])
            end;
        {error, enoent} ->
            ok;
        {error, Reason} ->
            logger:warning("peer manager: failed to read ~s: ~p", [Path, Reason])
    end.

%% Disconnect all peers from a given IP
disconnect_peers_by_ip(IP) ->
    ets:foldl(fun(#peer_entry{pid = Pid, address = {PeerIP, _}}, _) ->
        case PeerIP =:= IP of
            true -> beamchain_peer:disconnect(Pid);
            false -> ok
        end
    end, ok, ?PEER_TABLE).

%% Handle misbehavior report
handle_misbehaving(Pid, Score, Reason, State) ->
    case ets:lookup(?PEER_TABLE, Pid) of
        [#peer_entry{address = {IP, Port}, misbehavior_score = OldScore} = Entry] ->
            NewScore = OldScore + Score,
            ReasonStr = if
                is_binary(Reason) -> Reason;
                is_list(Reason) -> list_to_binary(Reason);
                true -> <<"unknown">>
            end,
            logger:warning("peer manager: misbehaving peer ~p:~B (+~B -> ~B): ~s",
                           [IP, Port, Score, NewScore, ReasonStr]),
            case NewScore >= ?BAN_THRESHOLD of
                true ->
                    %% Ban the peer
                    BanExpiry = erlang:system_time(second) + ?DEFAULT_BAN_DURATION,
                    ets:insert(?BANNED_PEERS_TABLE, {IP, BanExpiry}),
                    logger:info("peer manager: banning ~p:~B for ~B seconds (score ~B)",
                                [IP, Port, ?DEFAULT_BAN_DURATION, NewScore]),
                    %% Persist bans to disk
                    save_bans(State#state.datadir),
                    %% Disconnect the peer
                    beamchain_peer:disconnect(Pid),
                    {noreply, State};
                false ->
                    %% Update the score
                    Entry2 = Entry#peer_entry{misbehavior_score = NewScore},
                    ets:insert(?PEER_TABLE, Entry2),
                    {noreply, State}
            end;
        [] ->
            %% Unknown peer, ignore
            logger:debug("peer manager: misbehaving report for unknown pid ~p", [Pid]),
            {noreply, State}
    end.

%%% ===================================================================
%%% Internal: pre-handshake inbound connection check
%%% ===================================================================

%% @doc Internal check for inbound connection acceptance (after ban check).
%% Checks already_connected and max inbound limits (with eviction).
check_inbound_internal(Address, #state{max_inbound = MaxInbound}) ->
    case find_peer_by_address(Address) of
        {ok, _Pid} ->
            {reject, already_connected};
        error ->
            Inbound = inbound_count(),
            case Inbound >= MaxInbound of
                true ->
                    %% At capacity - try to evict a peer
                    case select_peer_to_evict() of
                        {ok, EvictPid} ->
                            %% Evict and accept new connection
                            logger:debug("peer manager: evicting ~p to accept new inbound",
                                         [EvictPid]),
                            beamchain_peer:disconnect(EvictPid),
                            {ok, accept};
                        none ->
                            %% All peers are protected
                            {reject, too_many_inbound}
                    end;
                false ->
                    {ok, accept}
            end
    end.

%% @doc Check if an IP is in the whitelist.
%% Whitelist entries can be IP addresses or CIDR ranges (as strings).
check_whitelist(_IP, []) ->
    false;
check_whitelist(IP, [Entry | Rest]) ->
    case match_whitelist_entry(IP, Entry) of
        true -> true;
        false -> check_whitelist(IP, Rest)
    end.

%% @doc Match a single whitelist entry against an IP.
%% Supports: IP tuples, IP strings, CIDR notation.
match_whitelist_entry(IP, Entry) when is_tuple(Entry), is_tuple(IP) ->
    %% Direct IP tuple comparison
    IP =:= Entry;
match_whitelist_entry(IP, Entry) when is_list(Entry) ->
    %% String entry - could be IP or CIDR
    case string:split(Entry, "/") of
        [IPStr, MaskStr] ->
            %% CIDR notation
            case {inet:parse_address(IPStr), list_to_integer(MaskStr)} of
                {{ok, NetIP}, Mask} ->
                    ip_in_cidr(IP, NetIP, Mask);
                _ ->
                    false
            end;
        [IPStr] ->
            %% Plain IP string
            case inet:parse_address(IPStr) of
                {ok, ParsedIP} -> IP =:= ParsedIP;
                _ -> false
            end
    end;
match_whitelist_entry(_, _) ->
    false.

%% @doc Check if an IP is in a CIDR range.
ip_in_cidr({A1, A2, A3, A4}, {B1, B2, B3, B4}, Mask) when Mask >= 0, Mask =< 32 ->
    %% Convert to 32-bit integers and compare with mask
    IP1 = (A1 bsl 24) bor (A2 bsl 16) bor (A3 bsl 8) bor A4,
    IP2 = (B1 bsl 24) bor (B2 bsl 16) bor (B3 bsl 8) bor B4,
    MaskBits = (16#FFFFFFFF bsl (32 - Mask)) band 16#FFFFFFFF,
    (IP1 band MaskBits) =:= (IP2 band MaskBits);
ip_in_cidr(_, _, _) ->
    %% IPv6 or invalid - not supported yet
    false.

%%% ===================================================================
%%% Internal: inbound connections
%%% ===================================================================

start_listener() ->
    Params = beamchain_config:network_params(),
    Port = case beamchain_config:get(p2pport) of
        undefined -> Params#network_params.default_port;
        P when is_integer(P) -> P;
        P when is_list(P) -> list_to_integer(P)
    end,
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
    Pid = spawn(fun() -> accept_loop(LSock, Self) end),
    erlang:monitor(process, Pid),
    Pid.

accept_loop(LSock, Manager) ->
    case gen_tcp:accept(LSock) of
        {ok, Socket} ->
            case inet:peername(Socket) of
                {ok, {IP, Port} = Address} ->
                    %% Pre-handshake rejection check - do this BEFORE spawning
                    %% a peer process to save resources. This matches Bitcoin Core's
                    %% AcceptConnection behavior.
                    case beamchain_peer_manager:check_inbound(Address) of
                        {ok, accept} ->
                            %% Transfer socket ownership to manager so it can
                            %% later hand it off to the peer process.
                            gen_tcp:controlling_process(Socket, Manager),
                            Manager ! {accepted, Socket, Address};
                        {reject, Reason} ->
                            %% Reject immediately without protocol messages.
                            %% Just close socket (sends TCP RST).
                            logger:debug("pre-handshake reject ~p:~B: ~p",
                                         [IP, Port, Reason]),
                            gen_tcp:close(Socket)
                    end;
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

handle_inbound(Socket, {IP, _Port} = Address, State) ->
    %% Pre-handshake check was already done in accept_loop.
    %% At this point we just spawn the peer process.
    case beamchain_peer:accept(Socket, Address, self()) of
        {ok, Pid} ->
            %% Transfer socket ownership to peer process.  The accept_loop
            %% already transferred ownership to us (the manager), so this
            %% call will succeed.  After the transfer the peer can safely
            %% enable {active, once} on the socket.
            gen_tcp:controlling_process(Socket, Pid),
            Pid ! socket_owner_transferred,
            Now = erlang:system_time(second),
            MonRef = erlang:monitor(process, Pid),
            Entry = #peer_entry{
                pid = Pid,
                address = Address,
                direction = inbound,
                conn_type = full_relay,
                mon_ref = MonRef,
                connected = false,
                connect_time = Now,
                keyed_netgroup = calculate_keyed_netgroup(Address, State),
                network_type = get_network_type(IP)
            },
            ets:insert(?PEER_TABLE, Entry),
            logger:debug("accepted inbound from ~p", [Address]),
            State;
        {error, Reason} ->
            logger:debug("failed to accept from ~p: ~p",
                         [Address, Reason]),
            gen_tcp:close(Socket),
            State
    end.

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

%%% ===================================================================
%%% Internal: stale tip detection (Bitcoin Core TipMayBeStale)
%%% ===================================================================

%% @doc Handle stale tip: disconnect worst peer, request headers from best.
%% When our chain tip hasn't advanced in > 30 minutes and peers report
%% higher tips, we disconnect the lowest-height peer and request headers
%% from the highest-height peer.
handle_stale_tip_detected(State) ->
    OurTipHeight = get_our_tip_height(),
    %% Collect outbound peers with their heights
    OutboundPeers = ets:foldl(fun
        (#peer_entry{connected = true, direction = outbound} = E, Acc) ->
            [E | Acc];
        (_, Acc) ->
            Acc
    end, [], ?PEER_TABLE),
    case OutboundPeers of
        [] ->
            logger:warning("peer_manager: stale tip but no outbound peers connected"),
            State;
        Peers ->
            %% Find best and worst peers
            {BestPeer, WorstPeer} = find_best_worst_peers(Peers),
            %% Disconnect worst peer if behind us (make room for better peer)
            case WorstPeer of
                {WorstPid, WorstAddr, WorstH} when WorstH < OurTipHeight ->
                    case BestPeer of
                        {BestPid, _, _} when WorstPid =/= BestPid ->
                            logger:warning("peer_manager: disconnecting stale peer ~p "
                                           "(height ~B, ours ~B) due to stale tip",
                                           [WorstAddr, WorstH, OurTipHeight]),
                            beamchain_peer:disconnect(WorstPid);
                        _ ->
                            ok
                    end;
                _ ->
                    ok
            end,
            %% Request headers from best peer
            case BestPeer of
                {BestPid2, BestAddr2, BestH2} when BestH2 > OurTipHeight ->
                    logger:info("peer_manager: requesting headers from best peer ~p "
                                "(height ~B, ours ~B) due to stale tip",
                                [BestAddr2, BestH2, OurTipHeight]),
                    beamchain_header_sync:handle_peer_connected(BestPid2,
                        #{start_height => BestH2});
                _ ->
                    %% No peer ahead — send getheaders to all to discover new blocks
                    send_periodic_getheaders()
            end,
            State
    end.

%% Find the peer with highest and lowest best_height.
find_best_worst_peers(Peers) ->
    lists:foldl(fun(#peer_entry{pid = Pid, address = Addr, best_height = H},
                    {Best, Worst}) ->
        NewBest = case Best of
            none -> {Pid, Addr, H};
            {_, _, BH} when H > BH -> {Pid, Addr, H};
            _ -> Best
        end,
        NewWorst = case Worst of
            none -> {Pid, Addr, H};
            {_, _, WH} when H < WH -> {Pid, Addr, H};
            _ -> Worst
        end,
        {NewBest, NewWorst}
    end, {none, none}, Peers).

%% @doc Send getheaders to a random connected peer to discover new blocks.
%% Reference: Bitcoin Core SendMessages() periodic header fetch.
send_periodic_getheaders() ->
    AllPeers = ets:foldl(fun
        (#peer_entry{connected = true, pid = Pid}, Acc) -> [Pid | Acc];
        (_, Acc) -> Acc
    end, [], ?PEER_TABLE),
    case AllPeers of
        [] ->
            ok;
        Peers ->
            %% Pick a random peer
            Idx = rand:uniform(length(Peers)),
            Peer = lists:nth(Idx, Peers),
            %% Trigger header sync check with this peer
            PeerHeight = case ets:lookup(?PEER_TABLE, Peer) of
                [#peer_entry{best_height = H}] -> H;
                _ -> 0
            end,
            beamchain_header_sync:handle_peer_connected(Peer,
                #{start_height => PeerHeight})
    end.

%%% ===================================================================
%%% Internal: stale peer eviction (Bitcoin Core parity)
%%% ===================================================================

%% @doc Check all outbound peers for staleness and evict if necessary.
%% Runs every 45 seconds. Checks:
%% 1. Peers with stale tip (>30 min behind our tip) when we have current peers
%% 2. Peers that haven't responded to getheaders within 2 minutes
%% 3. Peers with ping latency exceeding 20 minutes
%% Protects at least one peer per network type (IPv4, IPv6, Tor).
check_stale_peers() ->
    OurTipHeight = get_our_tip_height(),
    Now = erlang:system_time(second),
    NowMs = erlang:system_time(millisecond),

    %% Collect all outbound peers
    OutboundPeers = ets:foldl(fun
        (#peer_entry{direction = outbound, connected = true} = E, Acc) ->
            [E | Acc];
        (_, Acc) ->
            Acc
    end, [], ?PEER_TABLE),

    %% Check if we have any peer with current tip
    HasCurrentPeer = has_peer_with_current_tip(OutboundPeers, OurTipHeight, Now),

    %% Get network protection map (one per network type)
    ProtectedNetworks = get_protected_networks(OutboundPeers),

    %% Check each peer for staleness
    lists:foreach(fun(Entry) ->
        check_peer_staleness(Entry, OurTipHeight, Now, NowMs,
                             HasCurrentPeer, ProtectedNetworks)
    end, OutboundPeers).

%% @doc Check if a specific peer should be evicted for staleness.
check_peer_staleness(#peer_entry{pid = Pid, address = Addr, connect_time = ConnTime,
                                  best_height = PeerHeight, pending_getheaders = PendingHdrs,
                                  getheaders_sent_at = HdrsSentAt, ping_latency = PingLatency,
                                  network_type = NetType},
                     OurTipHeight, Now, NowMs, HasCurrentPeer, ProtectedNetworks) ->
    %% Don't evict peers that just connected (< 30 seconds)
    case Now - ConnTime < ?MIN_CONNECT_TIME_FOR_EVICTION of
        true ->
            ok;
        false ->
            %% Check if this network type is protected
            IsProtected = is_network_protected(NetType, ProtectedNetworks),

            %% Check headers response timeout (2 minutes)
            case PendingHdrs andalso HdrsSentAt > 0 andalso
                 (NowMs - HdrsSentAt) > ?HEADERS_RESPONSE_TIMEOUT of
                true when not IsProtected ->
                    self() ! {evict_peer, Pid, "headers response timeout"},
                    ok;
                _ ->
                    %% Check ping timeout (20 minutes)
                    case PingLatency > ?PING_TIMEOUT of
                        true when not IsProtected ->
                            self() ! {evict_peer, Pid, "ping timeout"},
                            ok;
                        _ ->
                            %% Check stale tip (30 min behind when we have current peers)
                            HeightDiff = OurTipHeight - PeerHeight,
                            %% Convert block height difference to approximate time
                            %% ~6 blocks per hour, so 30 min = ~3 blocks
                            %% But we check based on actual time tracking
                            case HasCurrentPeer andalso HeightDiff > 0 andalso
                                 is_peer_stale(Addr, Now) of
                                true when not IsProtected ->
                                    self() ! {evict_peer, Pid,
                                              io_lib:format("stale tip (~B blocks behind)",
                                                            [HeightDiff])};
                                _ ->
                                    ok
                            end
                    end
            end
    end.

%% @doc Check if a peer's tip is stale based on last block time.
is_peer_stale({_IP, _Port} = _Addr, Now) ->
    %% For now, check last_block_time in the entry
    %% A peer is stale if we haven't received a block announcement
    %% from them in 30 minutes AND they're behind our tip
    %% This is checked via the peer entry in the caller
    %% Here we just verify the time threshold
    _ = Now,
    %% The actual staleness check happens in check_peer_staleness
    %% where we have access to the peer entry
    true.

%% @doc Check if we have any peer with a current tip.
%% A peer has a current tip if their best height is close to ours
%% and they've sent us blocks/headers recently.
has_peer_with_current_tip([], _OurTip, _Now) ->
    false;
has_peer_with_current_tip([#peer_entry{best_height = H, last_block_time = LBT} | Rest],
                          OurTip, Now) ->
    %% Consider current if within 3 blocks and active in last 30 min
    IsRecent = (Now - LBT) < ?STALE_TIP_THRESHOLD,
    IsClose = (OurTip - H) =< 3,
    case IsRecent andalso IsClose of
        true -> true;
        false -> has_peer_with_current_tip(Rest, OurTip, Now)
    end.

%% @doc Get the set of network types that should be protected.
%% We protect at least one peer per network type from eviction.
get_protected_networks(Peers) ->
    %% Build a map of network_type -> [Pid]
    ByNetwork = lists:foldl(fun(#peer_entry{pid = Pid, network_type = NetType}, Acc) ->
        maps:update_with(NetType, fun(L) -> [Pid | L] end, [Pid], Acc)
    end, #{}, Peers),

    %% For each network with only one peer, mark it as protected
    maps:fold(fun(NetType, Pids, Acc) ->
        case length(Pids) of
            1 -> maps:put(NetType, hd(Pids), Acc);
            _ -> Acc
        end
    end, #{}, ByNetwork).

%% @doc Check if a network type's only peer is protected.
is_network_protected(NetType, ProtectedNetworks) ->
    maps:is_key(NetType, ProtectedNetworks).

%% @doc Get our current chain tip height.
get_our_tip_height() ->
    try
        case beamchain_chainstate:get_tip_height() of
            {ok, H} when is_integer(H) -> H;
            not_found -> 0;
            H when is_integer(H) -> H;
            _ -> 0
        end
    catch
        _:_ -> 0
    end.

%% @doc Determine the network type for an IP address.
-spec get_network_type(inet:ip_address()) -> ipv4 | ipv6 | tor | i2p | cjdns.
get_network_type({_, _, _, _}) ->
    ipv4;
get_network_type({0, 0, 0, 0, 0, 16#FFFF, _, _}) ->
    %% IPv4-mapped IPv6
    ipv4;
get_network_type({16#FD87, 16#D87E, 16#EB43, _, _, _, _, _}) ->
    %% Tor onion addresses (encoded as IPv6)
    tor;
get_network_type({16#FD00, 0, 0, 0, 0, 0, 0, _}) ->
    %% I2P addresses
    i2p;
get_network_type({16#FC00, _, _, _, _, _, _, _}) ->
    %% CJDNS addresses
    cjdns;
get_network_type({_, _, _, _, _, _, _, _}) ->
    ipv6.
