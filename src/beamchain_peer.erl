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
         disconnect/1, info/1]).

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
    misbehavior = 0         :: non_neg_integer()
}).

%%% ===================================================================
%%% API
%%% ===================================================================

%% @doc Start an outbound peer connection.
-spec connect({inet:ip_address(), inet:port_number()}, pid(), map()) ->
    {ok, pid()} | {error, term()}.
connect(Address, Handler, Opts) ->
    gen_statem:start_link(?MODULE, {outbound, Address, Handler, Opts}, []).

%% @doc Accept an inbound peer connection on an existing socket.
-spec accept(gen_tcp:socket(), {inet:ip_address(), inet:port_number()}, pid()) ->
    {ok, pid()} | {error, term()}.
accept(Socket, Address, Handler) ->
    gen_statem:start_link(?MODULE, {inbound, Socket, Address, Handler}, []).

%% @doc Send a P2P message to this peer.
-spec send_message(pid(), {atom(), map()}) -> ok.
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

%%% ===================================================================
%%% gen_statem callbacks
%%% ===================================================================

callback_mode() -> [state_functions, state_enter].

init({outbound, {IP, Port} = Addr, Handler, _Opts}) ->
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
            {stop, {connection_failed, Reason}}
    end;

init({inbound, Socket, Addr, Handler}) ->
    Nonce = generate_nonce(),
    Magic = beamchain_config:magic(),
    MonRef = erlang:monitor(process, Handler),
    inet:setopts(Socket, [{active, once},
                           {recbuf, 262144}, {sndbuf, 262144}]),
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
    {keep_state_and_data, [{next_event, internal, send_version}]};

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
    {stop, handler_down};

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
    %% Start ping timer and inactivity timeout
    {keep_state, Data2,
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
    {stop, handler_down};

ready(cast, {send, Command, PayloadData}, Data) ->
    Data2 = do_send_msg(Command, PayloadData, Data),
    {keep_state, Data2};

ready(cast, disconnect, Data) ->
    Data#peer_data.handler ! {peer_disconnected, self(), requested},
    {stop, normal};

ready(cast, {misbehavior, Score}, Data) ->
    check_ban(Data#peer_data{
        misbehavior = Data#peer_data.misbehavior + Score});

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
                    %% Send verack
                    Data6 = do_send_raw(verack, <<>>, Data5),
                    {ok, Data6#peer_data{verack_sent = true}}
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

send_feature_msgs(Data) ->
    %% sendheaders and sendcmpct are sent after handshake complete.
    %% wtxidrelay and sendaddrv2 are sent before verack (see handle_version_msg).
    D1 = do_send_raw(sendheaders, <<>>, Data),
    CmpctPayload = beamchain_p2p_msg:encode_payload(sendcmpct,
                       #{announce => false, version => 2}),
    do_send_raw(sendcmpct, CmpctPayload, D1).

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
