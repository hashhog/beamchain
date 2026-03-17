-module(beamchain_proxy).

%% Tor (SOCKS5) and I2P (SAM) proxy support for anonymous P2P connections.
%%
%% This module provides:
%% - SOCKS5 proxy connections for Tor .onion addresses
%% - I2P SAM 3.1 protocol for .b32.i2p addresses
%% - v3 onion address generation from ed25519 keys
%% - Network type detection and routing

-export([
    %% Connection routing
    connect/3,
    detect_network/1,
    route_for_address/1,

    %% SOCKS5 protocol
    socks5_connect/4,
    socks5_connect/5,
    socks5_error_code/1,  %% Exported for testing

    %% I2P SAM protocol
    i2p_connect/3,
    i2p_session_create/2,
    i2p_session_close/1,
    i2p_stream_connect/3,
    i2p_generate_destination/1,

    %% Onion address handling
    onion_address_from_pubkey/1,
    parse_onion_address/1,
    is_onion_address/1,
    is_i2p_address/1,

    %% Stream isolation
    new_stream_isolation_generator/0,
    generate_credentials/1
]).

-include("beamchain.hrl").

%% SOCKS5 protocol constants (RFC 1928)
-define(SOCKS5_VERSION, 5).
-define(SOCKS5_AUTH_NONE, 0).
-define(SOCKS5_AUTH_USERPASS, 2).
-define(SOCKS5_AUTH_NOACCEPTABLE, 16#ff).
-define(SOCKS5_CMD_CONNECT, 1).
-define(SOCKS5_ATYP_IPV4, 1).
-define(SOCKS5_ATYP_DOMAIN, 3).
-define(SOCKS5_ATYP_IPV6, 4).

%% SOCKS5 reply codes
-define(SOCKS5_REP_SUCCEEDED, 0).
-define(SOCKS5_REP_GENERAL_FAILURE, 1).
-define(SOCKS5_REP_NOT_ALLOWED, 2).
-define(SOCKS5_REP_NET_UNREACHABLE, 3).
-define(SOCKS5_REP_HOST_UNREACHABLE, 4).
-define(SOCKS5_REP_CONN_REFUSED, 5).
-define(SOCKS5_REP_TTL_EXPIRED, 6).
-define(SOCKS5_REP_CMD_NOT_SUPPORTED, 7).
-define(SOCKS5_REP_ATYP_NOT_SUPPORTED, 8).

%% Tor extended error codes (from Bitcoin Core)
-define(TOR_HS_DESC_NOT_FOUND, 16#f0).
-define(TOR_HS_DESC_INVALID, 16#f1).
-define(TOR_HS_INTRO_FAILED, 16#f2).
-define(TOR_HS_REND_FAILED, 16#f3).
-define(TOR_HS_MISSING_CLIENT_AUTH, 16#f4).
-define(TOR_HS_WRONG_CLIENT_AUTH, 16#f5).
-define(TOR_HS_BAD_ADDRESS, 16#f6).
-define(TOR_HS_INTRO_TIMEOUT, 16#f7).

%% I2P SAM constants
-define(SAM_DEFAULT_PORT, 7656).
-define(SAM_VERSION_MIN, "3.1").
-define(SAM_VERSION_MAX, "3.1").
-define(SAM_SIGNATURE_TYPE, 7).  %% EdDSA_SHA512_Ed25519

%% Timeouts
-define(SOCKS5_TIMEOUT, 20000).  %% 20 seconds (per Bitcoin Core)
-define(SAM_TIMEOUT, 180000).    %% 3 minutes for I2P name lookup

%% Network types (matching Bitcoin Core)
-type network() :: ipv4 | ipv6 | onion | i2p | cjdns.
-type proxy_config() :: #{
    host := inet:ip_address() | string(),
    port := inet:port_number(),
    auth => {string(), string()}
}.

%% I2P session state
-record(i2p_session, {
    control_sock :: gen_tcp:socket(),
    session_id   :: string(),
    private_key  :: binary() | undefined,
    my_dest      :: string(),  %% full base64 destination
    my_addr      :: string()   %% .b32.i2p address
}).

%% Stream isolation generator for Tor
-record(stream_isolation_gen, {
    prefix :: string(),
    counter :: atomics:atomics_ref()
}).

%%% ===================================================================
%%% Connection Routing
%%% ===================================================================

%% @doc Connect to a peer address through the appropriate proxy.
%% Routes based on address type: .onion -> Tor, .b32.i2p -> I2P, else direct.
-spec connect(Address :: term(), Port :: inet:port_number(), Opts :: map()) ->
    {ok, gen_tcp:socket()} | {error, term()}.
connect({_,_,_,_} = IP, Port, Opts) ->
    connect_routed(ipv4, ip_to_string(IP), Port, Opts);
connect({_,_,_,_,_,_,_,_} = IP, Port, Opts) ->
    connect_routed(ipv6, ip_to_string(IP), Port, Opts);
connect(Address, Port, Opts) when is_list(Address); is_binary(Address) ->
    AddrStr = to_string(Address),
    Network = detect_network(AddrStr),
    connect_routed(Network, AddrStr, Port, Opts).

connect_routed(Network, Address, Port, Opts) ->
    case route_for_address(Network) of
        direct ->
            connect_direct(Address, Port, Opts);
        {socks5, Proxy} ->
            socks5_connect(Proxy, Address, Port, Opts);
        {i2p_sam, Proxy} ->
            i2p_connect(Proxy, Address, Port)
    end.

%% @doc Determine routing for a network type.
%% Checks proxy configuration and returns routing decision.
-spec route_for_address(network() | string()) ->
    direct | {socks5, proxy_config()} | {i2p_sam, proxy_config()}.
route_for_address(Network) when is_atom(Network) ->
    case Network of
        onion ->
            case get_onion_proxy() of
                undefined -> direct;  %% No Tor proxy configured
                Proxy -> {socks5, Proxy}
            end;
        i2p ->
            case get_i2p_proxy() of
                undefined -> direct;  %% No I2P SAM configured
                Proxy -> {i2p_sam, Proxy}
            end;
        _ ->
            case get_default_proxy() of
                undefined -> direct;
                Proxy -> {socks5, Proxy}
            end
    end;
route_for_address(Address) when is_list(Address); is_binary(Address) ->
    route_for_address(detect_network(Address)).

%% @doc Detect network type from address string.
-spec detect_network(string() | binary()) -> network().
detect_network(Address) when is_binary(Address) ->
    detect_network(binary_to_list(Address));
detect_network(Address) when is_list(Address) ->
    LowerAddr = string:lowercase(Address),
    case lists:suffix(".onion", LowerAddr) of
        true -> onion;
        false ->
            case lists:suffix(".b32.i2p", LowerAddr) of
                true -> i2p;
                false ->
                    case inet:parse_address(Address) of
                        {ok, {_,_,_,_}} -> ipv4;
                        {ok, {_,_,_,_,_,_,_,_}} -> ipv6;
                        _ -> ipv4  %% Default to IPv4 for hostnames
                    end
            end
    end.

%%% ===================================================================
%%% SOCKS5 Protocol
%%% ===================================================================

%% @doc Connect to a host through a SOCKS5 proxy.
-spec socks5_connect(proxy_config(), string(), inet:port_number(), map()) ->
    {ok, gen_tcp:socket()} | {error, term()}.
socks5_connect(Proxy, Host, Port, Opts) ->
    socks5_connect(Proxy, Host, Port, Opts, undefined).

%% @doc Connect through SOCKS5 with optional stream isolation credentials.
-spec socks5_connect(proxy_config(), string(), inet:port_number(),
                     map(), {string(), string()} | undefined) ->
    {ok, gen_tcp:socket()} | {error, term()}.
socks5_connect(#{host := ProxyHost, port := ProxyPort} = Proxy, Host, Port, Opts, IsolationCreds) ->
    Timeout = maps:get(timeout, Opts, ?SOCKS5_TIMEOUT),
    SocketOpts = [binary, {active, false}, {packet, raw}, {nodelay, true}],

    case gen_tcp:connect(proxy_host_to_ip(ProxyHost), ProxyPort, SocketOpts, Timeout) of
        {ok, Socket} ->
            %% Determine auth method
            Auth = case IsolationCreds of
                undefined -> maps:get(auth, Proxy, undefined);
                Creds -> Creds
            end,
            case socks5_handshake(Socket, Host, Port, Auth, Timeout) of
                ok ->
                    {ok, Socket};
                {error, Reason} ->
                    gen_tcp:close(Socket),
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, {proxy_connect_failed, Reason}}
    end.

%% SOCKS5 handshake: method selection -> auth -> connect
socks5_handshake(Socket, Host, Port, Auth, Timeout) ->
    %% Step 1: Send greeting with supported methods
    Methods = case Auth of
        undefined -> [?SOCKS5_AUTH_NONE];
        _ -> [?SOCKS5_AUTH_USERPASS, ?SOCKS5_AUTH_NONE]
    end,
    Greeting = <<?SOCKS5_VERSION, (length(Methods)):8,
                 (list_to_binary(Methods))/binary>>,
    case gen_tcp:send(Socket, Greeting) of
        ok ->
            case socks5_recv(Socket, 2, Timeout) of
                {ok, <<?SOCKS5_VERSION, Method>>} ->
                    socks5_authenticate(Socket, Method, Auth, Host, Port, Timeout);
                {ok, _} ->
                    {error, invalid_socks5_response};
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

%% Step 2: Authenticate if required
socks5_authenticate(Socket, ?SOCKS5_AUTH_NONE, _, Host, Port, Timeout) ->
    socks5_connect_cmd(Socket, Host, Port, Timeout);
socks5_authenticate(Socket, ?SOCKS5_AUTH_USERPASS, Auth, Host, Port, Timeout) ->
    case Auth of
        {Username, Password} when is_list(Username), is_list(Password) ->
            ULen = length(Username),
            PLen = length(Password),
            AuthMsg = <<1, ULen, (list_to_binary(Username))/binary,
                        PLen, (list_to_binary(Password))/binary>>,
            case gen_tcp:send(Socket, AuthMsg) of
                ok ->
                    case socks5_recv(Socket, 2, Timeout) of
                        {ok, <<1, 0>>} ->
                            socks5_connect_cmd(Socket, Host, Port, Timeout);
                        {ok, <<1, _Status>>} ->
                            {error, socks5_auth_failed};
                        {ok, _} ->
                            {error, invalid_socks5_auth_response};
                        {error, _} = Err ->
                            Err
                    end;
                {error, _} = Err ->
                    Err
            end;
        _ ->
            {error, socks5_auth_required}
    end;
socks5_authenticate(_Socket, ?SOCKS5_AUTH_NOACCEPTABLE, _, _, _, _) ->
    {error, socks5_no_acceptable_auth}.

%% Step 3: Send CONNECT command
socks5_connect_cmd(Socket, Host, Port, Timeout) ->
    HostBin = list_to_binary(Host),
    HostLen = byte_size(HostBin),
    %% Use domain name addressing (ATYP = 3)
    ConnectMsg = <<?SOCKS5_VERSION, ?SOCKS5_CMD_CONNECT, 0,
                   ?SOCKS5_ATYP_DOMAIN, HostLen, HostBin/binary,
                   Port:16/big>>,
    case gen_tcp:send(Socket, ConnectMsg) of
        ok ->
            socks5_recv_connect_reply(Socket, Timeout);
        {error, _} = Err ->
            Err
    end.

%% Receive and parse CONNECT reply
socks5_recv_connect_reply(Socket, Timeout) ->
    case socks5_recv(Socket, 4, Timeout) of
        {ok, <<?SOCKS5_VERSION, Rep, 0, Atyp>>} ->
            case Rep of
                ?SOCKS5_REP_SUCCEEDED ->
                    %% Skip bound address
                    socks5_skip_bound_addr(Socket, Atyp, Timeout);
                _ ->
                    {error, socks5_error_code(Rep)}
            end;
        {ok, _} ->
            {error, invalid_socks5_connect_response};
        {error, _} = Err ->
            Err
    end.

%% Skip bound address in CONNECT reply
socks5_skip_bound_addr(Socket, ?SOCKS5_ATYP_IPV4, Timeout) ->
    case socks5_recv(Socket, 6, Timeout) of  %% 4 bytes IPv4 + 2 bytes port
        {ok, _} -> ok;
        {error, _} = Err -> Err
    end;
socks5_skip_bound_addr(Socket, ?SOCKS5_ATYP_IPV6, Timeout) ->
    case socks5_recv(Socket, 18, Timeout) of  %% 16 bytes IPv6 + 2 bytes port
        {ok, _} -> ok;
        {error, _} = Err -> Err
    end;
socks5_skip_bound_addr(Socket, ?SOCKS5_ATYP_DOMAIN, Timeout) ->
    case socks5_recv(Socket, 1, Timeout) of
        {ok, <<Len>>} ->
            case socks5_recv(Socket, Len + 2, Timeout) of  %% domain + port
                {ok, _} -> ok;
                {error, _} = Err -> Err
            end;
        {error, _} = Err -> Err
    end.

%% Receive exactly N bytes with timeout
socks5_recv(Socket, N, Timeout) ->
    gen_tcp:recv(Socket, N, Timeout).

%% Convert SOCKS5 reply code to error atom
socks5_error_code(?SOCKS5_REP_GENERAL_FAILURE) -> socks5_general_failure;
socks5_error_code(?SOCKS5_REP_NOT_ALLOWED) -> socks5_not_allowed;
socks5_error_code(?SOCKS5_REP_NET_UNREACHABLE) -> socks5_network_unreachable;
socks5_error_code(?SOCKS5_REP_HOST_UNREACHABLE) -> socks5_host_unreachable;
socks5_error_code(?SOCKS5_REP_CONN_REFUSED) -> socks5_connection_refused;
socks5_error_code(?SOCKS5_REP_TTL_EXPIRED) -> socks5_ttl_expired;
socks5_error_code(?SOCKS5_REP_CMD_NOT_SUPPORTED) -> socks5_command_not_supported;
socks5_error_code(?SOCKS5_REP_ATYP_NOT_SUPPORTED) -> socks5_address_type_not_supported;
%% Tor extended errors
socks5_error_code(?TOR_HS_DESC_NOT_FOUND) -> tor_hs_descriptor_not_found;
socks5_error_code(?TOR_HS_DESC_INVALID) -> tor_hs_descriptor_invalid;
socks5_error_code(?TOR_HS_INTRO_FAILED) -> tor_hs_intro_failed;
socks5_error_code(?TOR_HS_REND_FAILED) -> tor_hs_rendezvous_failed;
socks5_error_code(?TOR_HS_MISSING_CLIENT_AUTH) -> tor_hs_missing_client_auth;
socks5_error_code(?TOR_HS_WRONG_CLIENT_AUTH) -> tor_hs_wrong_client_auth;
socks5_error_code(?TOR_HS_BAD_ADDRESS) -> tor_hs_bad_address;
socks5_error_code(?TOR_HS_INTRO_TIMEOUT) -> tor_hs_intro_timeout;
socks5_error_code(Code) -> {socks5_unknown_error, Code}.

%%% ===================================================================
%%% I2P SAM 3.1 Protocol
%%% ===================================================================

%% @doc Connect to an I2P address through SAM.
-spec i2p_connect(proxy_config(), string(), inet:port_number()) ->
    {ok, gen_tcp:socket()} | {error, term()}.
i2p_connect(#{host := SamHost, port := SamPort}, Address, Port) ->
    %% For I2P, we need to:
    %% 1. Connect to SAM bridge
    %% 2. Create a transient session
    %% 3. Look up the destination
    %% 4. Connect stream
    SocketOpts = [binary, {active, false}, {packet, line}, {nodelay, true}],
    case gen_tcp:connect(proxy_host_to_ip(SamHost), SamPort, SocketOpts, ?SAM_TIMEOUT) of
        {ok, Sock} ->
            case i2p_handshake_and_connect(Sock, Address, Port) of
                {ok, StreamSock} ->
                    {ok, StreamSock};
                {error, Reason} ->
                    gen_tcp:close(Sock),
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, {sam_connect_failed, Reason}}
    end.

%% SAM handshake and stream connect
i2p_handshake_and_connect(Sock, Address, _Port) ->
    %% Step 1: HELLO VERSION handshake
    case sam_hello(Sock) of
        ok ->
            %% Step 2: Create transient session
            SessionId = generate_session_id(),
            case sam_session_create(Sock, SessionId, transient) of
                {ok, _MyDest} ->
                    %% Step 3: Look up destination
                    case sam_naming_lookup(Sock, Address) of
                        {ok, DestBase64} ->
                            %% Step 4: Open stream connection
                            %% Need new socket for the stream
                            sam_stream_connect(Sock, SessionId, DestBase64);
                        {error, _} = Err ->
                            Err
                    end;
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

%% SAM HELLO VERSION handshake
sam_hello(Sock) ->
    Msg = io_lib:format("HELLO VERSION MIN=~s MAX=~s~n",
                        [?SAM_VERSION_MIN, ?SAM_VERSION_MAX]),
    case gen_tcp:send(Sock, Msg) of
        ok ->
            case sam_recv_reply(Sock) of
                {ok, Reply} ->
                    case sam_parse_reply(Reply) of
                        #{request := <<"HELLO">>, <<"RESULT">> := <<"OK">>} ->
                            ok;
                        #{request := <<"HELLO">>, <<"RESULT">> := Result} ->
                            {error, {sam_hello_failed, Result}};
                        _ ->
                            {error, invalid_sam_hello_response}
                    end;
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

%% Create SAM session
sam_session_create(Sock, SessionId, transient) ->
    %% Use TRANSIENT destination for outbound-only connections
    Msg = io_lib:format("SESSION CREATE STYLE=STREAM ID=~s DESTINATION=TRANSIENT "
                        "i2cp.leaseSetEncType=4,0 inbound.quantity=1 outbound.quantity=1~n",
                        [SessionId]),
    case gen_tcp:send(Sock, Msg) of
        ok ->
            case sam_recv_reply(Sock) of
                {ok, Reply} ->
                    case sam_parse_reply(Reply) of
                        #{request := <<"SESSION">>, <<"RESULT">> := <<"OK">>,
                          <<"DESTINATION">> := Dest} ->
                            {ok, binary_to_list(Dest)};
                        #{request := <<"SESSION">>, <<"RESULT">> := <<"OK">>} ->
                            {ok, ""};  %% Transient doesn't always return dest
                        #{request := <<"SESSION">>, <<"RESULT">> := Result} ->
                            {error, {sam_session_failed, Result}};
                        _ ->
                            {error, invalid_sam_session_response}
                    end;
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            Err
    end;
sam_session_create(Sock, SessionId, {persistent, PrivateKey}) ->
    %% Use provided private key for persistent identity
    PrivKeyB64 = base64:encode(PrivateKey),
    Msg = io_lib:format("SESSION CREATE STYLE=STREAM ID=~s DESTINATION=~s "
                        "i2cp.leaseSetEncType=4,0~n",
                        [SessionId, binary_to_list(PrivKeyB64)]),
    case gen_tcp:send(Sock, Msg) of
        ok ->
            case sam_recv_reply(Sock) of
                {ok, Reply} ->
                    case sam_parse_reply(Reply) of
                        #{request := <<"SESSION">>, <<"RESULT">> := <<"OK">>} ->
                            {ok, binary_to_list(PrivKeyB64)};
                        #{request := <<"SESSION">>, <<"RESULT">> := Result} ->
                            {error, {sam_session_failed, Result}};
                        _ ->
                            {error, invalid_sam_session_response}
                    end;
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

%% SAM NAMING LOOKUP to resolve .b32.i2p address
sam_naming_lookup(Sock, Address) ->
    Msg = io_lib:format("NAMING LOOKUP NAME=~s~n", [Address]),
    case gen_tcp:send(Sock, Msg) of
        ok ->
            case sam_recv_reply(Sock) of
                {ok, Reply} ->
                    case sam_parse_reply(Reply) of
                        #{request := <<"NAMING">>, <<"RESULT">> := <<"OK">>,
                          <<"VALUE">> := Dest} ->
                            {ok, binary_to_list(Dest)};
                        #{request := <<"NAMING">>, <<"RESULT">> := Result} ->
                            {error, {sam_lookup_failed, Result}};
                        _ ->
                            {error, invalid_sam_lookup_response}
                    end;
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

%% SAM STREAM CONNECT
sam_stream_connect(Sock, SessionId, DestBase64) ->
    Msg = io_lib:format("STREAM CONNECT ID=~s DESTINATION=~s SILENT=false~n",
                        [SessionId, DestBase64]),
    case gen_tcp:send(Sock, Msg) of
        ok ->
            case sam_recv_reply(Sock) of
                {ok, Reply} ->
                    case sam_parse_reply(Reply) of
                        #{request := <<"STREAM">>, <<"RESULT">> := <<"OK">>} ->
                            %% Switch to raw mode for the data stream
                            inet:setopts(Sock, [{packet, raw}]),
                            {ok, Sock};
                        #{request := <<"STREAM">>, <<"RESULT">> := Result} ->
                            {error, {sam_stream_failed, Result}};
                        _ ->
                            {error, invalid_sam_stream_response}
                    end;
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

%% Receive SAM reply line
sam_recv_reply(Sock) ->
    case gen_tcp:recv(Sock, 0, ?SAM_TIMEOUT) of
        {ok, Line} ->
            %% Remove trailing newline
            {ok, string:trim(Line, trailing, "\r\n")};
        {error, _} = Err ->
            Err
    end.

%% Parse SAM reply into map
sam_parse_reply(Reply) when is_binary(Reply) ->
    Tokens = binary:split(Reply, <<" ">>, [global]),
    parse_sam_tokens(Tokens, #{});
sam_parse_reply(Reply) when is_list(Reply) ->
    sam_parse_reply(list_to_binary(Reply)).

parse_sam_tokens([Request | Rest], Acc) when map_size(Acc) =:= 0 ->
    parse_sam_tokens(Rest, Acc#{request => Request});
parse_sam_tokens([Token | Rest], Acc) ->
    case binary:split(Token, <<"=">>) of
        [Key, Value] ->
            parse_sam_tokens(Rest, Acc#{Key => Value});
        [_] ->
            %% Single word (like "REPLY", "STATUS") - add as flag
            parse_sam_tokens(Rest, Acc#{Token => true})
    end;
parse_sam_tokens([], Acc) ->
    Acc.

%% @doc Create a persistent I2P session.
-spec i2p_session_create(proxy_config(), binary() | transient) ->
    {ok, #i2p_session{}} | {error, term()}.
i2p_session_create(#{host := SamHost, port := SamPort}, PrivateKeyOrTransient) ->
    SocketOpts = [binary, {active, false}, {packet, line}, {nodelay, true}],
    case gen_tcp:connect(proxy_host_to_ip(SamHost), SamPort, SocketOpts, ?SAM_TIMEOUT) of
        {ok, Sock} ->
            case sam_hello(Sock) of
                ok ->
                    SessionId = generate_session_id(),
                    {DestArg, StoredPrivKey} = case PrivateKeyOrTransient of
                        transient -> {transient, undefined};
                        PK when is_binary(PK) -> {{persistent, PK}, PK}
                    end,
                    case sam_session_create(Sock, SessionId, DestArg) of
                        {ok, MyDest} ->
                            MyAddr = i2p_dest_to_b32(MyDest),
                            {ok, #i2p_session{
                                control_sock = Sock,
                                session_id = SessionId,
                                private_key = StoredPrivKey,
                                my_dest = MyDest,
                                my_addr = MyAddr
                            }};
                        {error, _} = Err ->
                            gen_tcp:close(Sock),
                            Err
                    end;
                {error, _} = Err ->
                    gen_tcp:close(Sock),
                    Err
            end;
        {error, Reason} ->
            {error, {sam_connect_failed, Reason}}
    end.

%% @doc Close an I2P session.
-spec i2p_session_close(#i2p_session{}) -> ok.
i2p_session_close(#i2p_session{control_sock = Sock}) ->
    gen_tcp:close(Sock),
    ok.

%% @doc Connect to an I2P peer using an existing session.
-spec i2p_stream_connect(#i2p_session{}, string(), inet:port_number()) ->
    {ok, gen_tcp:socket()} | {error, term()}.
i2p_stream_connect(#i2p_session{control_sock = CtrlSock, session_id = SessionId},
                   Address, _Port) ->
    %% First look up the destination
    case sam_naming_lookup(CtrlSock, Address) of
        {ok, DestBase64} ->
            %% Open new socket for stream
            %% Note: In production, this should reuse the SAM bridge connection
            %% or open a new one for the stream
            {ok, {SamHost, SamPort}} = inet:peername(CtrlSock),
            SocketOpts = [binary, {active, false}, {packet, line}, {nodelay, true}],
            case gen_tcp:connect(SamHost, SamPort, SocketOpts, ?SAM_TIMEOUT) of
                {ok, StreamSock} ->
                    case sam_hello(StreamSock) of
                        ok ->
                            sam_stream_connect(StreamSock, SessionId, DestBase64);
                        {error, _} = Err ->
                            gen_tcp:close(StreamSock),
                            Err
                    end;
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

%% @doc Generate a new I2P destination (keypair).
-spec i2p_generate_destination(proxy_config()) ->
    {ok, #{public := binary(), private := binary(), address := string()}} |
    {error, term()}.
i2p_generate_destination(#{host := SamHost, port := SamPort}) ->
    SocketOpts = [binary, {active, false}, {packet, line}, {nodelay, true}],
    case gen_tcp:connect(proxy_host_to_ip(SamHost), SamPort, SocketOpts, ?SAM_TIMEOUT) of
        {ok, Sock} ->
            Result = case sam_hello(Sock) of
                ok ->
                    Msg = io_lib:format("DEST GENERATE SIGNATURE_TYPE=~B~n",
                                        [?SAM_SIGNATURE_TYPE]),
                    case gen_tcp:send(Sock, Msg) of
                        ok ->
                            case sam_recv_reply(Sock) of
                                {ok, Reply} ->
                                    case sam_parse_reply(Reply) of
                                        #{request := <<"DEST">>,
                                          <<"PUB">> := Pub,
                                          <<"PRIV">> := Priv} ->
                                            PubBin = base64:decode(Pub),
                                            PrivBin = base64:decode(Priv),
                                            Addr = i2p_dest_to_b32(binary_to_list(Pub)),
                                            {ok, #{public => PubBin,
                                                   private => PrivBin,
                                                   address => Addr}};
                                        _ ->
                                            {error, invalid_sam_dest_response}
                                    end;
                                {error, _} = Err ->
                                    Err
                            end;
                        {error, _} = Err ->
                            Err
                    end;
                {error, _} = Err ->
                    Err
            end,
            gen_tcp:close(Sock),
            Result;
        {error, Reason} ->
            {error, {sam_connect_failed, Reason}}
    end.

%% Convert I2P destination to .b32.i2p address
i2p_dest_to_b32(DestBase64) when is_list(DestBase64) ->
    i2p_dest_to_b32(list_to_binary(DestBase64));
i2p_dest_to_b32(DestBase64) when is_binary(DestBase64) ->
    %% Convert from I2P's modified base64 to standard
    StdBase64 = i2p_to_std_base64(DestBase64),
    DestBin = base64:decode(StdBase64),
    %% SHA256 hash of destination
    Hash = beamchain_crypto:sha256(DestBin),
    %% Base32 encode (lowercase, no padding)
    Base32 = base32_encode_lower(Hash),
    Base32 ++ ".b32.i2p".

%% Convert I2P base64 to standard base64
%% I2P uses: - for + and ~ for /
i2p_to_std_base64(Bin) when is_binary(Bin) ->
    << <<(i2p_b64_char(C))>> || <<C>> <= Bin >>;
i2p_to_std_base64(Str) when is_list(Str) ->
    binary_to_list(i2p_to_std_base64(list_to_binary(Str))).

i2p_b64_char($-) -> $+;
i2p_b64_char($~) -> $/;
i2p_b64_char(C) -> C.

%% Generate random session ID
generate_session_id() ->
    Bytes = crypto:strong_rand_bytes(8),
    "beamchain_" ++ binary_to_list(binary:encode_hex(Bytes)).

%%% ===================================================================
%%% V3 Onion Address Generation
%%% ===================================================================

%% @doc Generate a v3 onion address from an Ed25519 public key.
%% Returns a 56-character base32 address + ".onion" suffix.
-spec onion_address_from_pubkey(binary()) -> string().
onion_address_from_pubkey(PubKey) when byte_size(PubKey) =:= 32 ->
    %% TORv3 CHECKSUM = SHA3-256(".onion checksum" | PUBKEY | VERSION)[:2]
    Prefix = <<".onion checksum">>,
    Version = <<3>>,
    ChecksumInput = <<Prefix/binary, PubKey/binary, Version/binary>>,
    <<Checksum:2/binary, _/binary>> = sha3_256(ChecksumInput),

    %% Address = base32(PUBKEY || CHECKSUM || VERSION)
    AddrBin = <<PubKey/binary, Checksum/binary, Version/binary>>,
    Base32 = base32_encode_lower(AddrBin),
    Base32 ++ ".onion".

%% @doc Parse a v3 onion address and extract the public key.
-spec parse_onion_address(string()) -> {ok, binary()} | {error, term()}.
parse_onion_address(Address) when is_list(Address) ->
    LowerAddr = string:lowercase(Address),
    case lists:suffix(".onion", LowerAddr) of
        true ->
            Base32Part = lists:sublist(LowerAddr, length(LowerAddr) - 6),
            case base32_decode_lower(Base32Part) of
                {ok, <<PubKey:32/binary, Checksum:2/binary, Version>>} when Version =:= 3 ->
                    %% Verify checksum
                    Prefix = <<".onion checksum">>,
                    VersionBin = <<Version>>,
                    ChecksumInput = <<Prefix/binary, PubKey/binary, VersionBin/binary>>,
                    <<ExpectedChecksum:2/binary, _/binary>> = sha3_256(ChecksumInput),
                    case Checksum =:= ExpectedChecksum of
                        true -> {ok, PubKey};
                        false -> {error, invalid_checksum}
                    end;
                {ok, _} ->
                    {error, invalid_onion_format};
                {error, _} = Err ->
                    Err
            end;
        false ->
            {error, not_onion_address}
    end.

%% @doc Check if an address is a v3 onion address.
-spec is_onion_address(string() | binary()) -> boolean().
is_onion_address(Address) when is_binary(Address) ->
    is_onion_address(binary_to_list(Address));
is_onion_address(Address) when is_list(Address) ->
    LowerAddr = string:lowercase(Address),
    lists:suffix(".onion", LowerAddr) andalso
    length(Address) =:= 62.  %% 56 chars base32 + ".onion"

%% @doc Check if an address is an I2P address.
-spec is_i2p_address(string() | binary()) -> boolean().
is_i2p_address(Address) when is_binary(Address) ->
    is_i2p_address(binary_to_list(Address));
is_i2p_address(Address) when is_list(Address) ->
    LowerAddr = string:lowercase(Address),
    lists:suffix(".b32.i2p", LowerAddr).

%%% ===================================================================
%%% Stream Isolation for Tor
%%% ===================================================================

%% @doc Create a new stream isolation credential generator.
%% Each connection gets unique credentials to prevent circuit reuse.
-spec new_stream_isolation_generator() -> #stream_isolation_gen{}.
new_stream_isolation_generator() ->
    %% Generate random 8-byte prefix
    PrefixBytes = crypto:strong_rand_bytes(8),
    Prefix = binary_to_list(binary:encode_hex(PrefixBytes)) ++ "-",
    Counter = atomics:new(1, [{signed, false}]),
    #stream_isolation_gen{prefix = Prefix, counter = Counter}.

%% @doc Generate unique credentials for stream isolation.
-spec generate_credentials(#stream_isolation_gen{}) -> {string(), string()}.
generate_credentials(#stream_isolation_gen{prefix = Prefix, counter = Counter}) ->
    N = atomics:add_get(Counter, 1, 1),
    Cred = Prefix ++ integer_to_list(N),
    {Cred, Cred}.  %% Same for username and password

%%% ===================================================================
%%% Internal Helpers
%%% ===================================================================

%% Connect directly without proxy
connect_direct(Address, Port, _Opts) when is_list(Address) ->
    case inet:parse_address(Address) of
        {ok, IP} ->
            connect_direct_ip(IP, Port);
        {error, _} ->
            %% Try as hostname
            SocketOpts = [binary, {active, false}, {packet, raw}, {nodelay, true}],
            gen_tcp:connect(Address, Port, SocketOpts, 10000)
    end.

connect_direct_ip(IP, Port) ->
    SocketOpts = [binary, {active, false}, {packet, raw}, {nodelay, true}],
    gen_tcp:connect(IP, Port, SocketOpts, 10000).

%% Convert IP tuple to string
ip_to_string({A, B, C, D}) ->
    lists:flatten(io_lib:format("~B.~B.~B.~B", [A, B, C, D]));
ip_to_string({A, B, C, D, E, F, G, H}) ->
    lists:flatten(io_lib:format("~.16B:~.16B:~.16B:~.16B:~.16B:~.16B:~.16B:~.16B",
                                [A, B, C, D, E, F, G, H])).

to_string(S) when is_list(S) -> S;
to_string(B) when is_binary(B) -> binary_to_list(B).

proxy_host_to_ip(Host) when is_tuple(Host) -> Host;
proxy_host_to_ip(Host) when is_list(Host) ->
    case inet:parse_address(Host) of
        {ok, IP} -> IP;
        {error, _} -> Host
    end.

%% Get proxy configuration from beamchain_config
get_onion_proxy() ->
    get_proxy_config([onion, proxy]).

get_i2p_proxy() ->
    case beamchain_config:get(i2psam) of
        undefined -> undefined;
        Addr -> parse_proxy_addr(Addr, ?SAM_DEFAULT_PORT)
    end.

get_default_proxy() ->
    get_proxy_config([proxy]).

get_proxy_config(Keys) ->
    get_proxy_config_env(Keys).

get_proxy_config_env([onion | _]) ->
    case os:getenv("BEAMCHAIN_ONION") of
        false ->
            case os:getenv("BEAMCHAIN_PROXY") of
                false -> undefined;
                Addr -> parse_proxy_addr(Addr, 9050)
            end;
        Addr -> parse_proxy_addr(Addr, 9050)
    end;
get_proxy_config_env([proxy]) ->
    case os:getenv("BEAMCHAIN_PROXY") of
        false -> undefined;
        Addr -> parse_proxy_addr(Addr, 9050)
    end;
get_proxy_config_env(_) ->
    undefined.

parse_proxy_addr(Addr, DefaultPort) when is_list(Addr) ->
    %% Parse formats: "host:port", "socks5://host:port", "host"
    Addr2 = case lists:prefix("socks5://", Addr) of
        true -> lists:nthtail(9, Addr);
        false -> Addr
    end,
    case string:split(Addr2, ":") of
        [Host, PortStr] ->
            case catch list_to_integer(PortStr) of
                Port when is_integer(Port) ->
                    #{host => Host, port => Port};
                _ ->
                    #{host => Addr2, port => DefaultPort}
            end;
        [Host] ->
            #{host => Host, port => DefaultPort}
    end.

%%% ===================================================================
%%% Cryptographic Helpers
%%% ===================================================================

%% SHA3-256 using Erlang crypto
sha3_256(Data) ->
    crypto:hash(sha3_256, Data).

%% Base32 encoding (lowercase, no padding) - RFC 4648
base32_encode_lower(Bin) ->
    Encoded = base32_encode(Bin),
    string:lowercase(Encoded).

base32_encode(Bin) ->
    base32_encode(Bin, []).

base32_encode(<<>>, Acc) ->
    lists:reverse(Acc);
base32_encode(<<A:5, B:5, C:5, D:5, E:5, F:5, G:5, H:5, Rest/binary>>, Acc) ->
    Chars = [base32_char(A), base32_char(B), base32_char(C), base32_char(D),
             base32_char(E), base32_char(F), base32_char(G), base32_char(H)],
    base32_encode(Rest, lists:reverse(Chars) ++ Acc);
base32_encode(<<A:5, B:5, C:5, D:5, E:5, F:5, G:2>>, Acc) ->
    G2 = G bsl 3,
    Chars = [base32_char(A), base32_char(B), base32_char(C), base32_char(D),
             base32_char(E), base32_char(F), base32_char(G2)],
    lists:reverse(lists:reverse(Chars) ++ Acc);
base32_encode(<<A:5, B:5, C:5, D:5, E:4>>, Acc) ->
    E2 = E bsl 1,
    Chars = [base32_char(A), base32_char(B), base32_char(C), base32_char(D),
             base32_char(E2)],
    lists:reverse(lists:reverse(Chars) ++ Acc);
base32_encode(<<A:5, B:5, C:5, D:1>>, Acc) ->
    D2 = D bsl 4,
    Chars = [base32_char(A), base32_char(B), base32_char(C), base32_char(D2)],
    lists:reverse(lists:reverse(Chars) ++ Acc);
base32_encode(<<A:5, B:3>>, Acc) ->
    B2 = B bsl 2,
    Chars = [base32_char(A), base32_char(B2)],
    lists:reverse(lists:reverse(Chars) ++ Acc).

base32_char(N) when N >= 0, N =< 25 -> N + $A;
base32_char(N) when N >= 26, N =< 31 -> N - 26 + $2.

%% Base32 decoding (lowercase input)
base32_decode_lower(Str) ->
    Upper = string:uppercase(Str),
    base32_decode(Upper).

base32_decode(Str) ->
    case catch base32_decode_impl(Str, <<>>) of
        {'EXIT', _} -> {error, invalid_base32};
        Result -> {ok, Result}
    end.

base32_decode_impl([], Acc) ->
    Acc;
base32_decode_impl([A,B,C,D,E,F,G,H | Rest], Acc) ->
    Byte1 = (base32_val(A) bsl 3) bor (base32_val(B) bsr 2),
    Byte2 = ((base32_val(B) band 3) bsl 6) bor (base32_val(C) bsl 1) bor (base32_val(D) bsr 4),
    Byte3 = ((base32_val(D) band 15) bsl 4) bor (base32_val(E) bsr 1),
    Byte4 = ((base32_val(E) band 1) bsl 7) bor (base32_val(F) bsl 2) bor (base32_val(G) bsr 3),
    Byte5 = ((base32_val(G) band 7) bsl 5) bor base32_val(H),
    base32_decode_impl(Rest, <<Acc/binary, Byte1, Byte2, Byte3, Byte4, Byte5>>);
base32_decode_impl([A,B,C,D,E,F,G], Acc) ->
    Byte1 = (base32_val(A) bsl 3) bor (base32_val(B) bsr 2),
    Byte2 = ((base32_val(B) band 3) bsl 6) bor (base32_val(C) bsl 1) bor (base32_val(D) bsr 4),
    Byte3 = ((base32_val(D) band 15) bsl 4) bor (base32_val(E) bsr 1),
    Byte4 = ((base32_val(E) band 1) bsl 7) bor (base32_val(F) bsl 2) bor (base32_val(G) bsr 3),
    <<Acc/binary, Byte1, Byte2, Byte3, Byte4>>;
base32_decode_impl([A,B,C,D,E], Acc) ->
    Byte1 = (base32_val(A) bsl 3) bor (base32_val(B) bsr 2),
    Byte2 = ((base32_val(B) band 3) bsl 6) bor (base32_val(C) bsl 1) bor (base32_val(D) bsr 4),
    Byte3 = ((base32_val(D) band 15) bsl 4) bor (base32_val(E) bsr 1),
    <<Acc/binary, Byte1, Byte2, Byte3>>;
base32_decode_impl([A,B,C,D], Acc) ->
    Byte1 = (base32_val(A) bsl 3) bor (base32_val(B) bsr 2),
    Byte2 = ((base32_val(B) band 3) bsl 6) bor (base32_val(C) bsl 1) bor (base32_val(D) bsr 4),
    <<Acc/binary, Byte1, Byte2>>;
base32_decode_impl([A,B], Acc) ->
    Byte1 = (base32_val(A) bsl 3) bor (base32_val(B) bsr 2),
    <<Acc/binary, Byte1>>.

base32_val(C) when C >= $A, C =< $Z -> C - $A;
base32_val(C) when C >= $a, C =< $z -> C - $a;
base32_val(C) when C >= $2, C =< $7 -> C - $2 + 26.
