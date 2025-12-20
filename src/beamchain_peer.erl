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
-export([connect/3, disconnect/1]).

%% gen_statem callbacks
-export([callback_mode/0, init/1, terminate/3]).
-export([connecting/3, handshaking/3, ready/3]).

%%% -------------------------------------------------------------------
%%% Timeouts
%%% -------------------------------------------------------------------

-define(CONNECT_TIMEOUT, 10000).       %% 10 seconds
-define(HANDSHAKE_TIMEOUT, 10000).     %% 10 seconds

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
    %% Our state
    our_nonce               :: non_neg_integer(),
    magic                   :: binary(),
    handler                 :: pid(),
    handler_mon             :: reference() | undefined,
    %% Stats
    connected_at            :: non_neg_integer() | undefined,
    last_recv               :: non_neg_integer() | undefined,
    bytes_sent = 0          :: non_neg_integer(),
    bytes_recv = 0          :: non_neg_integer()
}).

%%% ===================================================================
%%% API
%%% ===================================================================

%% @doc Start an outbound peer connection.
-spec connect({inet:ip_address(), inet:port_number()}, pid(), map()) ->
    {ok, pid()} | {error, term()}.
connect(Address, Handler, Opts) ->
    gen_statem:start_link(?MODULE, {outbound, Address, Handler, Opts}, []).

%% @doc Disconnect the peer gracefully.
-spec disconnect(pid()) -> ok.
disconnect(Pid) ->
    gen_statem:cast(Pid, disconnect).

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
                          {nodelay, true}, {send_timeout, 5000}],
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
    end.

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

handshaking(cast, disconnect, _Data) ->
    {stop, normal};

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
    Data#peer_data.handler ! {peer_connected, self(), Data#peer_data.address},
    keep_state_and_data;

ready(info, {tcp, Socket, Bin}, #peer_data{socket = Socket} = Data) ->
    case handle_tcp_data(Bin, Data) of
        {ok, Data2}    -> {keep_state, Data2};
        {stop, Reason} -> {stop, Reason}
    end;

ready(info, {tcp_closed, _}, Data) ->
    logger:info("peer ~p disconnected", [Data#peer_data.address]),
    {stop, normal};

ready(info, {tcp_error, _, Reason}, Data) ->
    logger:warning("peer ~p tcp error: ~p", [Data#peer_data.address, Reason]),
    {stop, {tcp_error, Reason}};

ready(cast, disconnect, _Data) ->
    {stop, normal};

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
            Data2 = Data#peer_data{
                version_recv = true,
                peer_version = V,
                peer_services = Svc,
                peer_user_agent = UA,
                peer_height = Height,
                peer_relay = Relay,
                peer_nonce = PeerNonce
            },
            %% Send verack
            Data3 = do_send_raw(verack, <<>>, Data2),
            {ok, Data3#peer_data{verack_sent = true}};
        {error, _} ->
            logger:warning("peer ~p bad version", [Data#peer_data.address]),
            {stop, bad_version}
    end.

handle_verack_msg(Data) ->
    {ok, Data#peer_data{verack_recv = true}}.

handshake_complete(#peer_data{version_sent = true, version_recv = true,
                              verack_sent = true, verack_recv = true}) ->
    true;
handshake_complete(_) ->
    false.

%%% ===================================================================
%%% Internal: Send helpers
%%% ===================================================================

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
