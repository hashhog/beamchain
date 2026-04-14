-module(beamchain_peer).
-behaviour(gen_statem).

%% gen_statem managing a single peer TCP connection.
%%
%% States: connecting -> handshaking -> ready
%%
%% Each peer runs in its own process. Outbound peers do a TCP
%% connect then send a version message. Both sides exchange
%% version + verack to complete the handshake.

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% API
-export([connect/3, accept/3,
         send_message/2, add_misbehavior/2,
         disconnect/1, info/1,
         queue_tx_inv/2]).

%% gen_statem callbacks
-export([callback_mode/0, init/1, terminate/3]).
-export([connecting/3, handshaking/3, ready/3]).

%%% -------------------------------------------------------------------
%%% Timeouts
%%% -------------------------------------------------------------------

-define(CONNECT_TIMEOUT, 10000).       %% 10 seconds
-define(HANDSHAKE_TIMEOUT, 10000).     %% 10 seconds
-define(PING_INTERVAL, 120000).        %% 2 minutes
-define(PONG_TIMEOUT, 1200000).        %% 20 minutes
-define(INACTIVITY_TIMEOUT, 1800000).  %% 30 minutes

-define(BAN_SCORE, 100).

%%% -------------------------------------------------------------------
%%% BIP 133 feefilter constants
%%% -------------------------------------------------------------------

%% Average delay between feefilter broadcasts (10 minutes)
-define(FEEFILTER_BROADCAST_INTERVAL_MS, 600000).
%% Maximum delay after significant fee change (5 minutes)
-define(FEEFILTER_MAX_CHANGE_DELAY_MS, 300000).
%% Minimum protocol version for feefilter (BIP 133)
-define(FEEFILTER_VERSION, 70013).
%% Default minimum relay fee (1000 sat/kvB = 1 sat/vB)
-define(DEFAULT_MIN_RELAY_FEE, 1000).

%%% -------------------------------------------------------------------
%%% Inv trickling constants (per Bitcoin Core net_processing.cpp)
%%% -------------------------------------------------------------------

%% Average delay between trickled inventory transmissions for inbound peers
-define(INBOUND_INV_INTERVAL_MS, 5000).   %% 5 seconds
%% Average delay for outbound peers (less privacy concern)
-define(OUTBOUND_INV_INTERVAL_MS, 2000).  %% 2 seconds
%% Target number of tx inv items per tick (14/sec * 5s = 70)
-define(INV_BROADCAST_TARGET, 70).
%% Maximum number of tx inv items per tick
-define(INV_BROADCAST_MAX, 1000).

%%% -------------------------------------------------------------------
%%% State data
%%% -------------------------------------------------------------------

-record(peer_data, {
    socket                  :: gen_tcp:socket() | undefined,
    address                 :: {inet:ip_address(), inet:port_number()},
    direction               :: inbound | outbound,
    buffer = <<>>           :: binary(),
    %% Handshake flags
    version_sent = false    :: boolean(),
    version_recv = false    :: boolean(),
    verack_sent = false     :: boolean(),
    verack_recv = false     :: boolean(),
    %% Peer info (from their version message)
    peer_version            :: non_neg_integer() | undefined,
    peer_services = 0       :: non_neg_integer(),
    peer_user_agent = <<>>  :: binary(),
    peer_height = 0         :: integer(),
    peer_relay = true       :: boolean(),
    peer_nonce              :: non_neg_integer() | undefined,
    %% Feature negotiation
    wants_headers = false   :: boolean(),
    wants_cmpct = false     :: boolean(),
    cmpct_version = 0       :: non_neg_integer(),
    wants_addrv2 = false    :: boolean(),
    wtxidrelay = false      :: boolean(),
    fee_filter = 0          :: non_neg_integer(),
    %% BIP330 Erlay
    erlay_enabled = false   :: boolean(),          %% peer supports erlay
    erlay_local_salt        :: non_neg_integer() | undefined,  %% our salt for sendtxrcncl
    erlay_version = 0       :: non_neg_integer(),  %% negotiated erlay version
    %% Our state
    our_nonce               :: non_neg_integer(),
    magic                   :: binary(),
    handler                 :: pid(),
    handler_mon             :: reference() | undefined,
    %% Stats
    connected_at            :: non_neg_integer() | undefined,
    last_recv               :: non_neg_integer() | undefined,
    last_ping_nonce         :: non_neg_integer() | undefined,
    ping_sent_at            :: non_neg_integer() | undefined,
    latency_ms              :: non_neg_integer() | undefined,
    bytes_sent = 0          :: non_neg_integer(),
    bytes_recv = 0          :: non_neg_integer(),
    misbehavior = 0         :: non_neg_integer(),
    %% Inv trickling (privacy: randomized tx relay)
    pending_tx_inv = []     :: [binary()],  %% txids waiting to be sent
    trickle_timer_ref       :: reference() | undefined,
    %% BIP 133 feefilter
    our_fee_filter = ?DEFAULT_MIN_RELAY_FEE :: non_neg_integer(),  %% our feefilter sent to peer
    feefilter_sent_at       :: non_neg_integer() | undefined,      %% when we last sent feefilter
    feefilter_timer_ref     :: reference() | undefined             %% timer for periodic updates
}).

%%% ===================================================================
%%% API
%%% ===================================================================

%% @doc Start an outbound peer connection.
-spec connect({inet:ip_address(), inet:port_number()}, pid(), map()) ->
    {ok, pid()} | {error, term()}.
connect(Address, Handler, Opts) ->
    %% Use start (not start_link) so connection failures don't crash the caller
    gen_statem:start(?MODULE, {outbound, Address, Handler, Opts}, []).

%% @doc Accept an inbound peer connection on an existing socket.
-spec accept(gen_tcp:socket(), {inet:ip_address(), inet:port_number()}, pid()) ->
    {ok, pid()} | {error, term()}.
accept(Socket, Address, Handler) ->
    gen_statem:start_link(?MODULE, {inbound, Socket, Address, Handler}, []).

%% @doc Send a P2P message to this peer.
%% The payload may be a map (common case) or any structured term (e.g.
%% a #block{} or #transaction{} record for in-process relay).
-spec send_message(pid(), {atom(), term()}) -> ok.
send_message(Pid, {Command, Payload}) ->
    gen_statem:cast(Pid, {send, Command, Payload}).

%% @doc Add misbehavior points. Peer is banned at >= 100.
-spec add_misbehavior(pid(), non_neg_integer()) -> ok.
add_misbehavior(Pid, Score) ->
    gen_statem:cast(Pid, {misbehavior, Score}).

%% @doc Disconnect the peer gracefully.
-spec disconnect(pid()) -> ok.
disconnect(Pid) ->
    gen_statem:cast(Pid, disconnect).

%% @doc Get peer connection info.
-spec info(pid()) -> {ok, map()} | {error, term()}.
info(Pid) ->
    gen_statem:call(Pid, info).

%% @doc Queue a transaction for trickling via inv. Instead of immediate
%% broadcast, txids are batched and sent with randomized Poisson delays
%% to prevent timing-based deanonymization.
-spec queue_tx_inv(pid(), binary()) -> ok.
queue_tx_inv(Pid, Txid) when is_binary(Txid), byte_size(Txid) =:= 32 ->
    gen_statem:cast(Pid, {queue_tx_inv, Txid}).

%%% ===================================================================
%%% gen_statem callbacks
%%% ===================================================================

callback_mode() -> [state_functions, state_enter].

init({outbound, {Host, Port} = Addr, Handler, _Opts}) when is_list(Host); is_binary(Host) ->
    %% Hostname connection (for .onion, .b32.i2p, or regular hostnames)
    %% Route through appropriate proxy based on address type
    Nonce = generate_nonce(),
    Magic = beamchain_config:magic(),
    MonRef = erlang:monitor(process, Handler),
    Data = #peer_data{
        address = Addr,
        direction = outbound,
        our_nonce = Nonce,
        magic = Magic,
        handler = Handler,
        handler_mon = MonRef
    },
    HostStr = to_string(Host),
    ConnectOpts = #{timeout => ?CONNECT_TIMEOUT},
    case beamchain_proxy:connect(HostStr, Port, ConnectOpts) of
        {ok, Socket} ->
            inet:setopts(Socket, [{active, once},
                                   {recbuf, 262144}, {sndbuf, 262144}]),
            Data2 = Data#peer_data{
                socket = Socket,
                connected_at = erlang:system_time(millisecond)
            },
            {ok, connecting, Data2};
        {error, Reason} ->
            %% Wrap in {shutdown, _} so SASL does not log a crash report
            %% for an expected outcome (dead peer, timeout, refused). The
            %% peer manager receives {error, Reason} from gen_statem:start
            %% and calls beamchain_addrman:mark_failed/1 either way.
            {stop, {shutdown, {connection_failed, Reason}}}
    end;
init({outbound, {IP, Port} = Addr, Handler, _Opts}) ->
    %% Standard IP address connection (tuple IP)
    Nonce = generate_nonce(),
    Magic = beamchain_config:magic(),
    MonRef = erlang:monitor(process, Handler),
    Data = #peer_data{
        address = Addr,
        direction = outbound,
        our_nonce = Nonce,
        magic = Magic,
        handler = Handler,
        handler_mon = MonRef
    },
    case gen_tcp:connect(IP, Port,
                         [binary, {active, false}, {packet, raw},
                          {nodelay, true}, {send_timeout, 5000},
                          {recbuf, 262144}, {sndbuf, 262144}],
                         ?CONNECT_TIMEOUT) of
        {ok, Socket} ->
            inet:setopts(Socket, [{active, once}]),
            Data2 = Data#peer_data{
                socket = Socket,
                connected_at = erlang:system_time(millisecond)
            },
            {ok, connecting, Data2};
        {error, Reason} ->
            %% See comment above: shutdown tuple keeps SASL quiet on expected
            %% connect failures (timeout / econnrefused / enetunreach, etc.).
            {stop, {shutdown, {connection_failed, Reason}}}
    end;

init({inbound, Socket, Addr, Handler}) ->
    Nonce = generate_nonce(),
    Magic = beamchain_config:magic(),
    MonRef = erlang:monitor(process, Handler),
    %% Only set buffer sizes here.  Do NOT enable {active, once} yet —
    %% the socket's controlling process is still the peer manager at this
    %% point.  We wait for a socket_owner_transferred message (sent by
    %% the manager after gen_tcp:controlling_process/2) before activating.
    inet:setopts(Socket, [{recbuf, 262144}, {sndbuf, 262144}]),
    Data = #peer_data{
        socket = Socket,
        address = Addr,
        direction = inbound,
        our_nonce = Nonce,
        magic = Magic,
        handler = Handler,
        handler_mon = MonRef,
        connected_at = erlang:system_time(millisecond)
    },
    %% Inbound: go straight to handshaking, wait for their version
    {ok, handshaking, Data}.

%%% -------------------------------------------------------------------
%%% connecting - TCP socket is open, send version
%%% -------------------------------------------------------------------

connecting(enter, _OldState, _Data) ->
    %% Cannot use next_event from enter callbacks in state_enter mode.
    %% Use state_timeout with 0ms to trigger immediately.
    {keep_state_and_data, [{state_timeout, 0, send_version}]};

connecting(state_timeout, send_version, Data) ->
    Data2 = do_send_version(Data),
    {next_state, handshaking, Data2};

connecting(internal, send_version, Data) ->
    Data2 = do_send_version(Data),
    {next_state, handshaking, Data2};

connecting(info, {tcp_closed, _}, _Data) ->
    {stop, connection_closed};

connecting(info, {tcp_error, _, Reason}, _Data) ->
    {stop, {tcp_error, Reason}};

connecting(cast, disconnect, _Data) ->
    {stop, normal};

connecting(_EventType, _Event, _Data) ->
    keep_state_and_data.

%%% -------------------------------------------------------------------
%%% handshaking - waiting for remote version + verack
%%% -------------------------------------------------------------------

handshaking(enter, _OldState, _Data) ->
    {keep_state_and_data,
     [{state_timeout, ?HANDSHAKE_TIMEOUT, handshake_timeout}]};

handshaking(state_timeout, handshake_timeout, Data) ->
    logger:info("peer ~p handshake timeout", [Data#peer_data.address]),
    {stop, handshake_timeout};

handshaking(info, socket_owner_transferred, #peer_data{socket = Socket} = Data) ->
    %% The peer manager has transferred socket ownership to us.
    %% Now it is safe to enable active-once delivery.
    inet:setopts(Socket, [{active, once}]),
    {keep_state, Data};

handshaking(info, {tcp, Socket, Bin}, #peer_data{socket = Socket} = Data) ->
    case handle_tcp_data(Bin, Data) of
        {ok, Data2} ->
            case handshake_complete(Data2) of
                true  -> {next_state, ready, Data2};
                false -> {keep_state, Data2}
            end;
        {stop, Reason} ->
            {stop, Reason}
    end;

handshaking(info, {tcp_closed, _}, Data) ->
    logger:info("peer ~p closed during handshake", [Data#peer_data.address]),
    {stop, normal};

handshaking(info, {tcp_error, _, Reason}, Data) ->
    logger:warning("peer ~p tcp error: ~p", [Data#peer_data.address, Reason]),
    {stop, {tcp_error, Reason}};

handshaking(info, {'DOWN', Ref, process, _, _}, #peer_data{handler_mon = Ref}) ->
    {stop, {shutdown, handler_down}};

handshaking(cast, disconnect, _Data) ->
    {stop, normal};

handshaking(cast, {misbehavior, Score}, Data) ->
    check_ban(Data#peer_data{
        misbehavior = Data#peer_data.misbehavior + Score});

handshaking({call, From}, info, Data) ->
    {keep_state_and_data, [{reply, From, {ok, build_info(Data)}}]};

handshaking(_EventType, _Event, _Data) ->
    keep_state_and_data.

%%% -------------------------------------------------------------------
%%% ready - handshake complete, normal operation
%%% -------------------------------------------------------------------

ready(enter, handshaking, Data) ->
    logger:info("peer ~p ready (~s, height=~B)",
                [Data#peer_data.address,
                 Data#peer_data.peer_user_agent,
                 Data#peer_data.peer_height]),
    %% Send feature negotiation messages
    Data2 = send_feature_msgs(Data),
    %% Notify handler
    Data2#peer_data.handler ! {peer_connected, self(), build_info(Data2)},
    %% Schedule first inv trickle with Poisson delay
    Data3 = schedule_trickle_timer(Data2),
    %% Start ping timer and inactivity timeout
    {keep_state, Data3,
     [{{timeout, ping}, ?PING_INTERVAL, send_ping},
      {{timeout, inactivity}, ?INACTIVITY_TIMEOUT, inactive}]};

ready({timeout, ping}, send_ping, Data) ->
    Data2 = do_send_ping(Data),
    {keep_state, Data2,
     [{{timeout, ping}, ?PING_INTERVAL, send_ping},
      {{timeout, pong}, ?PONG_TIMEOUT, pong_timeout}]};

ready({timeout, inactivity}, inactive, Data) ->
    logger:info("peer ~p inactivity timeout", [Data#peer_data.address]),
    {stop, inactivity_timeout};

ready({timeout, pong}, pong_timeout, Data) ->
    logger:info("peer ~p pong timeout", [Data#peer_data.address]),
    {stop, pong_timeout};

ready(info, {tcp, Socket, Bin}, #peer_data{socket = Socket} = Data) ->
    case handle_tcp_data(Bin, Data) of
        {ok, Data2} ->
            Actions = [{{timeout, inactivity}, ?INACTIVITY_TIMEOUT, inactive}],
            %% Cancel pong timeout if pong was received (nonce cleared)
            Actions2 = case Data2#peer_data.last_ping_nonce of
                undefined -> [{{timeout, pong}, infinity, pong_timeout} | Actions];
                _         -> Actions
            end,
            {keep_state, Data2, Actions2};
        {stop, Reason} ->
            {stop, Reason}
    end;

ready(info, {tcp_closed, _}, Data) ->
    logger:info("peer ~p disconnected", [Data#peer_data.address]),
    Data#peer_data.handler ! {peer_disconnected, self(), closed},
    {stop, normal};

ready(info, {tcp_error, _, Reason}, Data) ->
    logger:warning("peer ~p tcp error: ~p", [Data#peer_data.address, Reason]),
    Data#peer_data.handler ! {peer_disconnected, self(), {tcp_error, Reason}},
    {stop, {tcp_error, Reason}};

ready(info, {'DOWN', Ref, process, _, _}, #peer_data{handler_mon = Ref}) ->
    {stop, {shutdown, handler_down}};

ready(cast, {send, Command, PayloadData}, Data) ->
    Data2 = do_send_msg(Command, PayloadData, Data),
    {keep_state, Data2};

ready(cast, disconnect, Data) ->
    Data#peer_data.handler ! {peer_disconnected, self(), requested},
    {stop, normal};

ready(cast, {misbehavior, Score}, Data) ->
    check_ban(Data#peer_data{
        misbehavior = Data#peer_data.misbehavior + Score});

ready(cast, {queue_tx_inv, Txid}, Data) ->
    %% Add txid to pending queue if not already there
    Pending = Data#peer_data.pending_tx_inv,
    case lists:member(Txid, Pending) of
        true  -> {keep_state, Data};
        false -> {keep_state, Data#peer_data{pending_tx_inv = [Txid | Pending]}}
    end;

ready(info, trickle_inv, Data) ->
    %% Flush queued inv items with randomized ordering
    Data2 = do_trickle_inv(Data),
    Data3 = schedule_trickle_timer(Data2),
    {keep_state, Data3};

ready(info, check_feefilter, Data) ->
    %% Periodic feefilter check - update if fee changed
    Data2 = maybe_update_feefilter(Data),
    Data3 = schedule_feefilter_timer(Data2),
    {keep_state, Data3};

ready(info, send_feefilter_now, Data) ->
    %% Accelerated feefilter update due to significant fee change
    CurrentFee = get_mempool_min_fee(),
    Data2 = do_send_feefilter(CurrentFee, Data),
    {keep_state, Data2};

ready({call, From}, info, Data) ->
    {keep_state_and_data, [{reply, From, {ok, build_info(Data)}}]};

ready(_EventType, _Event, _Data) ->
    keep_state_and_data.

%%% -------------------------------------------------------------------
%%% terminate
%%% -------------------------------------------------------------------

terminate(_Reason, _State, #peer_data{socket = undefined}) -> ok;
terminate(_Reason, _State, #peer_data{socket = Socket}) ->
    gen_tcp:close(Socket),
    ok.

%%% ===================================================================
%%% Internal: TCP receive and buffering
%%% ===================================================================

handle_tcp_data(NewBytes, #peer_data{socket = Socket, buffer = Buf} = Data) ->
    Buffer = <<Buf/binary, NewBytes/binary>>,
    BytesRecv = Data#peer_data.bytes_recv + byte_size(NewBytes),
    Data2 = Data#peer_data{
        buffer = Buffer,
        bytes_recv = BytesRecv,
        last_recv = erlang:system_time(millisecond)
    },
    case process_buffer(Data2) of
        {ok, Data3} ->
            inet:setopts(Socket, [{active, once}]),
            {ok, Data3};
        {stop, Reason} ->
            {stop, Reason}
    end.

process_buffer(#peer_data{buffer = Buffer} = Data) ->
    case beamchain_p2p_msg:decode_msg(Buffer) of
        {ok, Command, Payload, Rest} ->
            Data2 = Data#peer_data{buffer = Rest},
            case dispatch_message(Command, Payload, Data2) of
                {ok, Data3}    -> process_buffer(Data3);
                {stop, Reason} -> {stop, Reason}
            end;
        incomplete ->
            {ok, Data};
        {error, Reason} ->
            logger:warning("peer ~p frame error: ~p",
                           [Data#peer_data.address, Reason]),
            {stop, Reason}
    end.

%%% ===================================================================
%%% Internal: Message dispatch
%%% ===================================================================

dispatch_message(version, Payload, Data) ->
    handle_version_msg(Payload, Data);
dispatch_message(verack, _Payload, Data) ->
    handle_verack_msg(Data);
dispatch_message(ping, Payload, Data) ->
    handle_ping_msg(Payload, Data);
dispatch_message(pong, Payload, Data) ->
    handle_pong_msg(Payload, Data);
dispatch_message(sendheaders, _Payload, Data) ->
    {ok, Data#peer_data{wants_headers = true}};
dispatch_message(sendcmpct, Payload, Data) ->
    handle_sendcmpct_msg(Payload, Data);
dispatch_message(sendaddrv2, _Payload, Data) ->
    %% BIP 155: only valid before handshake complete
    case handshake_complete(Data) of
        false -> {ok, Data#peer_data{wants_addrv2 = true}};
        true  -> {ok, Data}
    end;
dispatch_message(wtxidrelay, _Payload, Data) ->
    %% BIP 339: only valid before handshake complete
    case handshake_complete(Data) of
        false -> {ok, Data#peer_data{wtxidrelay = true}};
        true  -> {ok, Data}
    end;
dispatch_message(sendtxrcncl, Payload, Data) ->
    %% BIP 330: Erlay reconciliation handshake
    handle_sendtxrcncl_msg(Payload, Data);
dispatch_message(feefilter, Payload, Data) ->
    handle_feefilter_msg(Payload, Data);
dispatch_message(Command, Payload, Data) ->
    %% Forward everything else to handler
    Data#peer_data.handler ! {peer_message, self(), Command, Payload},
    {ok, Data}.

%%% ===================================================================
%%% Internal: Handshake
%%% ===================================================================

do_send_version(#peer_data{address = {IP, Port}, our_nonce = Nonce} = Data) ->
    Params = beamchain_config:network_params(),
    Services = ?NODE_NETWORK bor ?NODE_WITNESS,
    Now = erlang:system_time(second),
    Payload = beamchain_p2p_msg:encode_payload(version, #{
        version     => ?PROTOCOL_VERSION,
        services    => Services,
        timestamp   => Now,
        addr_recv   => #{services => 0, ip => IP, port => Port},
        addr_from   => #{services => Services, ip => {0,0,0,0},
                         port => Params#network_params.default_port},
        nonce       => Nonce,
        user_agent  => <<"/beamchain:0.1.0/">>,
        start_height => 0,
        relay       => true
    }),
    Data2 = do_send_raw(version, Payload, Data),
    Data2#peer_data{version_sent = true}.

handle_version_msg(_Payload, #peer_data{version_recv = true} = Data) ->
    logger:warning("peer ~p duplicate version", [Data#peer_data.address]),
    {stop, protocol_violation};
handle_version_msg(Payload, Data) ->
    case beamchain_p2p_msg:decode_payload(version, Payload) of
        {ok, #{version := V, services := Svc, user_agent := UA,
               start_height := Height, relay := Relay, nonce := PeerNonce}} ->
            %% Self-connection detection
            case PeerNonce =:= Data#peer_data.our_nonce of
                true ->
                    logger:info("peer ~p self-connection detected",
                                [Data#peer_data.address]),
                    {stop, self_connection};
                false ->
                    Data2 = Data#peer_data{
                        version_recv = true,
                        peer_version = V,
                        peer_services = Svc,
                        peer_user_agent = UA,
                        peer_height = Height,
                        peer_relay = Relay,
                        peer_nonce = PeerNonce
                    },
                    %% Inbound: send our version if we haven't yet
                    Data3 = maybe_send_version(Data2),
                    %% Send wtxidrelay and sendaddrv2 before verack (BIP 339/155)
                    Data4 = do_send_raw(wtxidrelay, <<>>, Data3),
                    Data5 = do_send_raw(sendaddrv2, <<>>, Data4),
                    %% BIP330: Send sendtxrcncl before verack (if peer supports wtxidrelay and tx relay)
                    Data6 = maybe_send_sendtxrcncl(Data5),
                    %% Send verack
                    Data7 = do_send_raw(verack, <<>>, Data6),
                    {ok, Data7#peer_data{verack_sent = true}}
            end;
        {error, _} ->
            logger:warning("peer ~p bad version", [Data#peer_data.address]),
            {stop, bad_version}
    end.

maybe_send_version(#peer_data{direction = inbound, version_sent = false} = Data) ->
    do_send_version(Data);
maybe_send_version(Data) ->
    Data.

handle_verack_msg(Data) ->
    {ok, Data#peer_data{verack_recv = true}}.

handshake_complete(#peer_data{version_sent = true, version_recv = true,
                              verack_sent = true, verack_recv = true}) ->
    true;
handshake_complete(_) ->
    false.

%%% ===================================================================
%%% Internal: BIP330 Erlay
%%% ===================================================================

%% Send sendtxrcncl if conditions are met:
%% - Peer supports wtxidrelay (required for Erlay)
%% - Peer allows tx relay (not block-only)
%% - We're in protocol version >= 70016 (WTXID relay version)
maybe_send_sendtxrcncl(#peer_data{peer_relay = true, wtxidrelay = true,
                                   peer_version = V} = Data) when V >= 70016 ->
    %% Pre-register with Erlay module to get our local salt
    LocalSalt = beamchain_erlay:pre_register_peer(self()),
    ErlayVersion = beamchain_erlay:version(),
    Payload = beamchain_p2p_msg:encode_payload(sendtxrcncl, #{
        version => ErlayVersion,
        salt => LocalSalt
    }),
    Data2 = do_send_raw(sendtxrcncl, Payload, Data),
    Data2#peer_data{erlay_local_salt = LocalSalt};
maybe_send_sendtxrcncl(Data) ->
    %% Conditions not met for Erlay
    Data.

%% Handle received sendtxrcncl message
handle_sendtxrcncl_msg(Payload, Data) ->
    case handshake_complete(Data) of
        true ->
            %% Protocol violation: sendtxrcncl after verack
            logger:warning("peer ~p sent sendtxrcncl after verack",
                           [Data#peer_data.address]),
            {stop, protocol_violation};
        false ->
            case beamchain_p2p_msg:decode_payload(sendtxrcncl, Payload) of
                {ok, #{version := PeerVersion, salt := PeerSalt}} when PeerVersion >= 1 ->
                    %% Check if we can support Erlay with this peer
                    case Data#peer_data.peer_relay andalso Data#peer_data.erlay_local_salt =/= undefined of
                        true ->
                            %% Register with Erlay module
                            IsPeerInbound = (Data#peer_data.direction =:= inbound),
                            case beamchain_erlay:register_peer(self(), IsPeerInbound,
                                                                PeerVersion, PeerSalt) of
                                ok ->
                                    ErlayVersion = min(PeerVersion, beamchain_erlay:version()),
                                    logger:debug("peer ~p erlay enabled (version ~p)",
                                                 [Data#peer_data.address, ErlayVersion]),
                                    {ok, Data#peer_data{erlay_enabled = true,
                                                        erlay_version = ErlayVersion}};
                                {error, Reason} ->
                                    logger:warning("peer ~p erlay registration failed: ~p",
                                                   [Data#peer_data.address, Reason]),
                                    {ok, Data}
                            end;
                        false ->
                            %% We didn't send sendtxrcncl or peer doesn't relay txs
                            {ok, Data}
                    end;
                {ok, #{version := V}} when V < 1 ->
                    %% Protocol violation: version below 1
                    logger:warning("peer ~p sent sendtxrcncl with invalid version ~p",
                                   [Data#peer_data.address, V]),
                    {stop, protocol_violation};
                {error, _} ->
                    logger:warning("peer ~p bad sendtxrcncl", [Data#peer_data.address]),
                    {ok, Data}
            end
    end.

%%% ===================================================================
%%% Internal: Ping / Pong
%%% ===================================================================

handle_ping_msg(Payload, Data) ->
    case beamchain_p2p_msg:decode_payload(ping, Payload) of
        {ok, #{nonce := Nonce}} ->
            Pong = beamchain_p2p_msg:encode_payload(pong, #{nonce => Nonce}),
            {ok, do_send_raw(pong, Pong, Data)};
        _ ->
            {ok, Data}
    end.

handle_pong_msg(Payload, Data) ->
    case beamchain_p2p_msg:decode_payload(pong, Payload) of
        {ok, #{nonce := Nonce}} ->
            case Data#peer_data.last_ping_nonce of
                Nonce when Data#peer_data.ping_sent_at =/= undefined ->
                    Now = erlang:system_time(millisecond),
                    Latency = Now - Data#peer_data.ping_sent_at,
                    {ok, Data#peer_data{
                        latency_ms = Latency,
                        last_ping_nonce = undefined,
                        ping_sent_at = undefined
                    }};
                _ ->
                    %% Stale or unexpected pong, ignore
                    {ok, Data}
            end;
        _ ->
            {ok, Data}
    end.

do_send_ping(Data) ->
    Nonce = generate_nonce(),
    Payload = beamchain_p2p_msg:encode_payload(ping, #{nonce => Nonce}),
    Data2 = do_send_raw(ping, Payload, Data),
    Data2#peer_data{
        last_ping_nonce = Nonce,
        ping_sent_at = erlang:system_time(millisecond)
    }.

%%% ===================================================================
%%% Internal: Feature negotiation
%%% ===================================================================

handle_sendcmpct_msg(Payload, Data) ->
    case beamchain_p2p_msg:decode_payload(sendcmpct, Payload) of
        {ok, #{announce := Ann, version := V}} ->
            {ok, Data#peer_data{wants_cmpct = Ann, cmpct_version = V}};
        _ ->
            {ok, Data}
    end.

handle_feefilter_msg(Payload, Data) ->
    case beamchain_p2p_msg:decode_payload(feefilter, Payload) of
        {ok, #{feerate := Fee}} ->
            {ok, Data#peer_data{fee_filter = Fee}};
        _ ->
            {ok, Data}
    end.

%%% ===================================================================
%%% Internal: BIP 133 feefilter
%%% ===================================================================

%% @doc Send initial feefilter after handshake if peer supports it.
%% Only sent to peers with protocol version >= 70013 that accept tx relay.
maybe_send_initial_feefilter(#peer_data{peer_version = V, peer_relay = Relay} = Data)
        when V >= ?FEEFILTER_VERSION, Relay =:= true ->
    %% Get current mempool minimum fee
    FeeRate = get_mempool_min_fee(),
    Data2 = do_send_feefilter(FeeRate, Data),
    %% Schedule periodic feefilter updates with exponential distribution
    schedule_feefilter_timer(Data2);
maybe_send_initial_feefilter(Data) ->
    %% Peer doesn't support feefilter or doesn't want tx relay
    Data.

%% @doc Send a feefilter message to the peer.
do_send_feefilter(FeeRate, Data) ->
    %% Ensure minimum relay fee floor
    FilterToSend = max(FeeRate, ?DEFAULT_MIN_RELAY_FEE),
    Payload = beamchain_p2p_msg:encode_payload(feefilter, #{feerate => FilterToSend}),
    Data2 = do_send_raw(feefilter, Payload, Data),
    Now = erlang:system_time(millisecond),
    Data2#peer_data{
        our_fee_filter = FilterToSend,
        feefilter_sent_at = Now
    }.

%% @doc Schedule next feefilter update using exponential distribution.
%% Average interval is 10 minutes for privacy.
schedule_feefilter_timer(Data) ->
    %% Cancel any existing timer
    case Data#peer_data.feefilter_timer_ref of
        undefined -> ok;
        OldRef -> erlang:cancel_timer(OldRef)
    end,
    %% Exponential distribution: -ln(U) * mean
    Interval = feefilter_poisson_interval(?FEEFILTER_BROADCAST_INTERVAL_MS),
    Ref = erlang:send_after(Interval, self(), check_feefilter),
    Data#peer_data{feefilter_timer_ref = Ref}.

%% @doc Generate Poisson-distributed interval.
feefilter_poisson_interval(MeanMs) ->
    U = rand:uniform(),
    Interval = round(-math:log(U) * MeanMs),
    %% Clamp to reasonable bounds (1 second to 30 minutes)
    max(1000, min(Interval, 1800000)).

%% @doc Check if feefilter should be updated and send if necessary.
maybe_update_feefilter(Data) ->
    CurrentFee = get_mempool_min_fee(),
    SentFee = Data#peer_data.our_fee_filter,
    Now = erlang:system_time(millisecond),
    SentAt = Data#peer_data.feefilter_sent_at,

    %% Check if fee changed significantly (>25% drop or >33% increase)
    %% Bitcoin Core uses: currentFilter < 3 * sent / 4 || currentFilter > 4 * sent / 3
    SignificantChange = (CurrentFee * 4 < SentFee * 3) orelse
                        (CurrentFee * 3 > SentFee * 4),

    case SignificantChange of
        true when SentAt =/= undefined ->
            %% Significant change - schedule accelerated update with random delay
            %% up to MAX_FEEFILTER_CHANGE_DELAY_MS for privacy
            Delay = rand:uniform(?FEEFILTER_MAX_CHANGE_DELAY_MS),
            NextSendAt = SentAt + ?FEEFILTER_BROADCAST_INTERVAL_MS,
            %% Only accelerate if we weren't going to send soon anyway
            case Now + Delay < NextSendAt of
                true ->
                    %% Update now with small random delay
                    erlang:send_after(Delay, self(), send_feefilter_now),
                    Data;
                false ->
                    Data
            end;
        _ ->
            %% No significant change or first update - send if filter value changed
            case CurrentFee =/= SentFee of
                true ->
                    do_send_feefilter(CurrentFee, Data);
                false ->
                    Data
            end
    end.

%% @doc Get current mempool minimum fee rate in sat/kvB.
get_mempool_min_fee() ->
    try
        case beamchain_mempool:get_info() of
            #{min_fee := MinFee} when is_number(MinFee) ->
                %% Convert sat/vB to sat/kvB (multiply by 1000)
                round(MinFee * 1000);
            _ ->
                ?DEFAULT_MIN_RELAY_FEE
        end
    catch
        _:_ -> ?DEFAULT_MIN_RELAY_FEE
    end.

send_feature_msgs(Data) ->
    %% sendheaders and sendcmpct are sent after handshake complete.
    %% wtxidrelay and sendaddrv2 are sent before verack (see handle_version_msg).
    D1 = do_send_raw(sendheaders, <<>>, Data),
    CmpctPayload = beamchain_p2p_msg:encode_payload(sendcmpct,
                       #{announce => false, version => 2}),
    D2 = do_send_raw(sendcmpct, CmpctPayload, D1),
    %% BIP 133: Send feefilter if peer supports it
    maybe_send_initial_feefilter(D2).

%%% ===================================================================
%%% Internal: Misbehavior
%%% ===================================================================

check_ban(#peer_data{misbehavior = Score, address = Addr} = Data)
        when Score >= ?BAN_SCORE ->
    logger:info("peer ~p banned (score=~B)", [Addr, Score]),
    Data#peer_data.handler ! {peer_banned, self(), Addr},
    {stop, banned};
check_ban(Data) ->
    {keep_state, Data}.

%%% ===================================================================
%%% Internal: Send helpers
%%% ===================================================================

do_send_msg(Command, PayloadData, Data) ->
    Payload = beamchain_p2p_msg:encode_payload(Command, PayloadData),
    do_send_raw(Command, Payload, Data).

do_send_raw(Command, Payload, #peer_data{socket = Socket, magic = Magic} = Data) ->
    Msg = beamchain_p2p_msg:encode_msg(Magic, Command, Payload),
    gen_tcp:send(Socket, Msg),
    Data#peer_data{bytes_sent = Data#peer_data.bytes_sent + byte_size(Msg)}.

%%% ===================================================================
%%% Internal: Helpers
%%% ===================================================================

generate_nonce() ->
    <<N:64>> = crypto:strong_rand_bytes(8),
    N.

build_info(#peer_data{} = D) ->
    #{address       => D#peer_data.address,
      direction     => D#peer_data.direction,
      version       => D#peer_data.peer_version,
      services      => D#peer_data.peer_services,
      user_agent    => D#peer_data.peer_user_agent,
      start_height  => D#peer_data.peer_height,
      relay         => D#peer_data.peer_relay,
      latency_ms    => D#peer_data.latency_ms,
      bytes_sent    => D#peer_data.bytes_sent,
      bytes_recv    => D#peer_data.bytes_recv,
      connected_at  => D#peer_data.connected_at}.

%%% ===================================================================
%%% Internal: Inv trickling (privacy-preserving tx relay)
%%% ===================================================================

%% Schedule the next trickle timer using Poisson distribution.
%% For exponentially distributed intervals: -ln(U) * mean
%% where U is uniform random in (0,1].
schedule_trickle_timer(#peer_data{direction = Dir} = Data) ->
    %% Cancel any existing timer
    case Data#peer_data.trickle_timer_ref of
        undefined -> ok;
        OldRef -> erlang:cancel_timer(OldRef)
    end,
    %% Calculate Poisson-distributed interval
    BaseInterval = case Dir of
        inbound  -> ?INBOUND_INV_INTERVAL_MS;
        outbound -> ?OUTBOUND_INV_INTERVAL_MS
    end,
    Interval = poisson_interval(BaseInterval),
    Ref = erlang:send_after(Interval, self(), trickle_inv),
    Data#peer_data{trickle_timer_ref = Ref}.

%% Generate Poisson-distributed interval: -ln(U) * mean
%% where U is uniform random in (0,1]. We use rand:uniform() which
%% returns (0.0, 1.0] and apply the transformation.
poisson_interval(MeanMs) ->
    U = rand:uniform(),  %% (0.0, 1.0]
    Interval = round(-math:log(U) * MeanMs),
    %% Clamp to reasonable bounds (1ms to 60s)
    max(1, min(Interval, 60000)).

%% Flush pending tx inv items to the peer.
%% Randomize order to prevent timing analysis, limit per tick.
%% Filter by peer's feefilter (BIP 133) before sending.
do_trickle_inv(#peer_data{pending_tx_inv = []} = Data) ->
    Data;
do_trickle_inv(#peer_data{pending_tx_inv = Pending, peer_relay = Relay,
                          fee_filter = PeerFeeFilter} = Data) ->
    case Relay of
        false ->
            %% Peer requested no tx relay, clear queue
            Data#peer_data{pending_tx_inv = []};
        true ->
            %% Filter by peer's feefilter (BIP 133)
            %% Skip txs with fee rate below peer's minimum
            Filtered = filter_by_feefilter(Pending, PeerFeeFilter),
            %% Calculate broadcast max: target + 5 per 1000 pending
            BroadcastMax = min(?INV_BROADCAST_MAX,
                               ?INV_BROADCAST_TARGET + (length(Filtered) div 1000) * 5),
            %% Shuffle and take up to max
            Shuffled = shuffle_list(Filtered),
            {ToSend, Remaining} = lists:split(min(BroadcastMax, length(Shuffled)), Shuffled),
            %% Send inv message if we have items
            Data2 = case ToSend of
                [] -> Data;
                _  -> send_tx_inv(ToSend, Data)
            end,
            %% Remove filtered txs from queue (they'll never pass the filter)
            FilteredOut = Pending -- Filtered,
            Data2#peer_data{pending_tx_inv = Remaining -- FilteredOut}
    end.

%% @doc Filter txids by peer's feefilter value.
%% Returns only txids whose fee rate >= peer's feefilter.
filter_by_feefilter(Txids, PeerFeeFilter) when PeerFeeFilter =< 0 ->
    %% No feefilter or peer accepts all fees
    Txids;
filter_by_feefilter(Txids, PeerFeeFilter) ->
    lists:filter(fun(Txid) ->
        tx_passes_feefilter(Txid, PeerFeeFilter)
    end, Txids).

%% @doc Check if a transaction's fee rate passes the peer's feefilter.
%% feefilter is in sat/kvB, we need to compare with tx fee rate.
tx_passes_feefilter(Txid, PeerFeeFilter) ->
    case beamchain_mempool:get_tx_fee_rate(Txid) of
        {ok, FeeRateKvB} ->
            %% FeeRateKvB is already in sat/kvB
            FeeRateKvB >= PeerFeeFilter;
        not_found ->
            %% Tx no longer in mempool, filter it out
            false
    end.

%% Send inv message for a list of txids
send_tx_inv(Txids, Data) ->
    Items = [#{type => 1, hash => Txid} || Txid <- Txids],  %% 1 = MSG_TX
    do_send_msg(inv, #{items => Items}, Data).

%% Fisher-Yates shuffle for randomizing inv order
shuffle_list([]) -> [];
shuffle_list([X]) -> [X];
shuffle_list(List) ->
    %% Use a simple random sort for small lists
    lists:sort(fun(_, _) -> rand:uniform() > 0.5 end, List).

%% Convert binary to string for hostname handling
to_string(S) when is_list(S) -> S;
to_string(B) when is_binary(B) -> binary_to_list(B).
