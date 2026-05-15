-module(beamchain_torcontrol).
-behaviour(gen_server).

%% Tor control-port client for inbound v3 hidden service registration.
%%
%% Implements the Tor control protocol (control-spec.txt) command sequence:
%%   PROTOCOLINFO  -> AUTHENTICATE  -> ADD_ONION  -> hold the connection.
%%
%% On a successful ADD_ONION, the returned ServiceID (the 56-char
%% base32 prefix of the v3 .onion address) is published as a local
%% address so that getnetworkinfo can advertise it, and the
%% accompanying ED25519-V3 private key is persisted to
%% <datadir>/tor_v3_secret_key so the hidden service is stable across
%% restarts.
%%
%% Authentication methods supported (priority order, matches
%% bitcoin-core/src/torcontrol.cpp protocolinfo_cb):
%%   1. HASHEDPASSWORD when a torpassword is configured (highest priority).
%%   2. NULL           when the control port has authentication disabled.
%%   3. SAFECOOKIE     when the cookie file is readable
%%                     (HMAC-SHA256 challenge/response per spec S3.5).
%%
%% This module is started by beamchain_node_sup only when
%% beamchain_config:listen_onion/0 returns true; otherwise the
%% gen_server is never started and the previous (outbound-only) Tor
%% behavior is unchanged.
%%
%% Bitcoin Core reference: src/torcontrol.cpp / src/torcontrol.h
%% (TorController class and the StartTorControl entrypoint).

-include("beamchain.hrl").

%% API
-export([start_link/0, start_link/1,
         add_onion/3,
         del_onion/1,
         get_onion_address/0,
         is_running/0]).

%% Test helpers (exported so the unit test suite can exercise the
%% protocol parsers without spinning up a real Tor control connection).
-export([parse_reply_line/1,
         parse_reply_mapping/1,
         split_reply_line/1,
         compute_safecookie_response/4,
         private_key_file/1,
         make_add_onion_cmd/3]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2]).

-define(SERVER, ?MODULE).

%% Tor reply codes (subset we care about — see control-spec.txt S4)
-define(TOR_REPLY_OK,           250).
-define(TOR_REPLY_UNRECOGNIZED, 510).
-define(TOR_REPLY_SYNTAX_ERROR, 513).

%% SAFECOOKIE key strings (control-spec.txt S3.24)
-define(SAFE_SERVERKEY,
        "Tor safe cookie authentication server-to-controller hash").
-define(SAFE_CLIENTKEY,
        "Tor safe cookie authentication controller-to-server hash").

-define(TOR_COOKIE_SIZE, 32).
-define(TOR_NONCE_SIZE,  32).

%% Reconnect backoff (mirrors Bitcoin Core RECONNECT_TIMEOUT_*)
-define(RECONNECT_INITIAL_MS, 1000).
-define(RECONNECT_MAX_MS,     600000).
-define(RECONNECT_MULT,       1.5).

%% Socket timeouts
-define(SEND_TIMEOUT_MS,      10000).
-define(RECV_TIMEOUT_MS,      30000).
-define(CONNECT_TIMEOUT_MS,   10000).

%%% -------------------------------------------------------------------
%%% State
%%% -------------------------------------------------------------------

-record(state, {
    host           :: string(),
    port           :: inet:port_number(),
    password       :: undefined | string(),
    virt_port      :: inet:port_number(),
    target_host    :: string(),
    target_port    :: inet:port_number(),
    socket         :: gen_tcp:socket() | undefined,
    private_key    :: undefined | string(),
    service_id     :: undefined | string(),
    onion_addr     :: undefined | string(),
    datadir        :: string(),
    reconnect_ms   :: pos_integer(),
    %% Pid that owns the read loop for the current connection (so we
    %% can monitor and clean up on disconnect).
    reader         :: undefined | pid()
}).

%%% ===================================================================
%%% API
%%% ===================================================================

start_link() ->
    start_link(default_config()).

%% @doc Start the Tor control client.  Config map keys:
%%   host        -- control-port host (default 127.0.0.1)
%%   port        -- control-port TCP port (default 9051)
%%   password    -- optional HASHEDPASSWORD (default undefined)
%%   virt_port   -- onion service VIRTPORT (default = network default_port)
%%   target_host -- local target host (default 127.0.0.1)
%%   target_port -- local target port (default = virt_port)
%%   datadir     -- where to persist tor_v3_secret_key
start_link(Config) when is_map(Config) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, Config, []).

%% @doc Send an ADD_ONION command on the current control connection.
%% Synchronous; returns {ok, OnionAddress, PrivateKey} on success.
%% Used both by the gen_server itself (on startup) and by tests.
-spec add_onion(inet:port_number(), string(), inet:port_number()) ->
    {ok, OnionAddress :: string(), PrivKey :: string()} | {error, term()}.
add_onion(VirtPort, TargetHost, TargetPort) ->
    gen_server:call(?SERVER, {add_onion, VirtPort, TargetHost, TargetPort},
                    ?RECV_TIMEOUT_MS).

%% @doc Send a DEL_ONION command to tear down the hidden service.
-spec del_onion(string()) -> ok | {error, term()}.
del_onion(ServiceID) ->
    gen_server:call(?SERVER, {del_onion, ServiceID}, ?RECV_TIMEOUT_MS).

%% @doc Return the .onion address registered by this node, or undefined.
-spec get_onion_address() -> undefined | string().
get_onion_address() ->
    case whereis(?SERVER) of
        undefined -> undefined;
        _ -> gen_server:call(?SERVER, get_onion_address, 5000)
    end.

%% @doc Return true when the torcontrol process is currently running.
-spec is_running() -> boolean().
is_running() ->
    whereis(?SERVER) =/= undefined.

%%% ===================================================================
%%% gen_server callbacks
%%% ===================================================================

init(Config) ->
    process_flag(trap_exit, true),
    State = #state{
        host        = maps:get(host, Config, "127.0.0.1"),
        port        = maps:get(port, Config, 9051),
        password    = maps:get(password, Config, undefined),
        virt_port   = maps:get(virt_port, Config, default_p2p_port()),
        target_host = maps:get(target_host, Config, "127.0.0.1"),
        target_port = maps:get(target_port, Config,
                               maps:get(virt_port, Config, default_p2p_port())),
        datadir      = maps:get(datadir, Config, default_datadir()),
        private_key  = load_cached_private_key(maps:get(datadir, Config,
                                                        default_datadir())),
        reconnect_ms = ?RECONNECT_INITIAL_MS
    },
    %% Kick off the connection asynchronously so init/1 does not block
    %% the supervisor start. The handle_info(connect, _) callback does
    %% the real work and reschedules on failure.
    self() ! connect,
    {ok, State}.

handle_call({add_onion, VPort, THost, TPort}, _From,
            #state{socket = Sock} = State) when Sock =/= undefined ->
    case do_add_onion(Sock, State#state.private_key, VPort, THost, TPort) of
        {ok, ServiceID, PrivKey} ->
            OnionAddr = ServiceID ++ ".onion",
            State1 = State#state{private_key = PrivKey,
                                 service_id  = ServiceID,
                                 onion_addr  = OnionAddr},
            persist_private_key(State1#state.datadir, PrivKey),
            {reply, {ok, OnionAddr, PrivKey}, State1};
        {error, _} = Err ->
            {reply, Err, State}
    end;
handle_call({add_onion, _, _, _}, _From, State) ->
    {reply, {error, not_connected}, State};

handle_call({del_onion, ServiceID}, _From, #state{socket = Sock} = State)
  when Sock =/= undefined ->
    case do_del_onion(Sock, ServiceID) of
        ok ->
            State1 = case State#state.service_id of
                ServiceID -> State#state{service_id = undefined,
                                         onion_addr = undefined};
                _ -> State
            end,
            {reply, ok, State1};
        {error, _} = Err ->
            {reply, Err, State}
    end;
handle_call({del_onion, _}, _From, State) ->
    {reply, {error, not_connected}, State};

handle_call(get_onion_address, _From, State) ->
    {reply, State#state.onion_addr, State};

handle_call(_Req, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(connect, State) ->
    case try_connect_and_register(State) of
        {ok, NewState} ->
            {noreply, NewState#state{reconnect_ms = ?RECONNECT_INITIAL_MS}};
        {error, Reason} ->
            logger:warning("torcontrol: connect failed: ~p, retrying in ~Bms",
                           [Reason, State#state.reconnect_ms]),
            erlang:send_after(State#state.reconnect_ms, self(), connect),
            NextMs = min(round(State#state.reconnect_ms * ?RECONNECT_MULT),
                          ?RECONNECT_MAX_MS),
            {noreply, State#state{reconnect_ms = NextMs}}
    end;

handle_info({tcp_closed, Sock}, #state{socket = Sock} = State) ->
    logger:warning("torcontrol: control connection closed by peer"),
    erlang:send_after(?RECONNECT_INITIAL_MS, self(), connect),
    {noreply, State#state{socket = undefined,
                           service_id = undefined,
                           onion_addr = undefined,
                           reader = undefined}};

handle_info({tcp_error, Sock, Reason}, #state{socket = Sock} = State) ->
    logger:warning("torcontrol: control connection error: ~p", [Reason]),
    catch gen_tcp:close(Sock),
    erlang:send_after(?RECONNECT_INITIAL_MS, self(), connect),
    {noreply, State#state{socket = undefined,
                           service_id = undefined,
                           onion_addr = undefined,
                           reader = undefined}};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{socket = Sock, service_id = SID}) ->
    %% Try to clean up the hidden service before exiting; ignore errors.
    case {Sock, SID} of
        {S, undefined} when S =/= undefined ->
            catch gen_tcp:close(S);
        {S, ID} when S =/= undefined, ID =/= undefined ->
            catch do_del_onion(S, ID),
            catch gen_tcp:close(S);
        _ -> ok
    end,
    ok.

%%% ===================================================================
%%% Connection lifecycle
%%% ===================================================================

try_connect_and_register(State0) ->
    case open_control_socket(State0#state.host, State0#state.port) of
        {ok, Sock} ->
            case do_protocolinfo(Sock) of
                {ok, AuthInfo} ->
                    case do_authenticate(Sock, AuthInfo,
                                         State0#state.password) of
                        ok ->
                            register_service(State0#state{socket = Sock});
                        {error, _} = Err ->
                            catch gen_tcp:close(Sock),
                            Err
                    end;
                {error, _} = Err ->
                    catch gen_tcp:close(Sock),
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

open_control_socket(Host, Port) ->
    Opts = [binary, {active, false}, {packet, line},
            {nodelay, true}, {reuseaddr, true}],
    H = case inet:parse_address(Host) of
        {ok, IP} -> IP;
        {error, _} -> Host
    end,
    gen_tcp:connect(H, Port, Opts, ?CONNECT_TIMEOUT_MS).

register_service(#state{socket = Sock,
                        virt_port = VP,
                        target_host = TH,
                        target_port = TP,
                        private_key = PK,
                        datadir = DD} = State) ->
    case do_add_onion(Sock, PK, VP, TH, TP) of
        {ok, ServiceID, NewPrivKey} ->
            OnionAddr = ServiceID ++ ".onion",
            persist_private_key(DD, NewPrivKey),
            logger:info("torcontrol: registered hidden service ~s "
                        "(virt=~B target=~s:~B)",
                        [OnionAddr, VP, TH, TP]),
            %% Spawn a reader process so we get tcp_closed/tcp_error
            %% notifications.  Keep the socket in {active, false} for
            %% the reader to receive into.
            Reader = spawn_link(fun() -> reader_loop(Sock, self()) end),
            {ok, State#state{service_id = ServiceID,
                              onion_addr = OnionAddr,
                              private_key = NewPrivKey,
                              reader = Reader}};
        {error, _} = Err ->
            Err
    end.

%% Drains the control socket so subsequent async notifications
%% (e.g. tcp_closed) reach the owning gen_server.
reader_loop(Sock, Owner) ->
    case gen_tcp:recv(Sock, 0, infinity) of
        {ok, _Line} ->
            reader_loop(Sock, Owner);
        {error, closed} ->
            Owner ! {tcp_closed, Sock},
            ok;
        {error, Reason} ->
            Owner ! {tcp_error, Sock, Reason},
            ok
    end.

%%% ===================================================================
%%% Protocol: PROTOCOLINFO
%%% ===================================================================

do_protocolinfo(Sock) ->
    case send_line(Sock, "PROTOCOLINFO 1") of
        ok ->
            case read_reply(Sock) of
                {ok, ?TOR_REPLY_OK, Lines} ->
                    {ok, parse_protocolinfo(Lines)};
                {ok, Code, _} ->
                    {error, {protocolinfo_failed, Code}};
                {error, _} = Err -> Err
            end;
        {error, _} = Err -> Err
    end.

parse_protocolinfo(Lines) ->
    lists:foldl(fun(Line, Acc) ->
        {Type, Args} = split_reply_line(Line),
        case Type of
            "AUTH" ->
                M = parse_reply_mapping(Args),
                Methods = case maps:find("METHODS", M) of
                    {ok, MStr} -> string:tokens(MStr, ",");
                    error -> []
                end,
                CookieFile = maps:get("COOKIEFILE", M, undefined),
                Acc#{methods => Methods, cookie_file => CookieFile};
            _ ->
                Acc
        end
    end, #{methods => [], cookie_file => undefined}, Lines).

%%% ===================================================================
%%% Protocol: AUTHENTICATE (NULL / HASHEDPASSWORD / SAFECOOKIE)
%%% ===================================================================

do_authenticate(Sock, AuthInfo, Password) ->
    Methods = maps:get(methods, AuthInfo, []),
    CookieFile = maps:get(cookie_file, AuthInfo, undefined),
    case pick_auth_method(Methods, Password) of
        {hashedpassword, P} ->
            auth_hashedpassword(Sock, P);
        null ->
            auth_null(Sock);
        safecookie ->
            auth_safecookie(Sock, CookieFile);
        none ->
            {error, no_supported_auth_method}
    end.

%% Priority matches Bitcoin Core:
%%   1. HASHEDPASSWORD if a password was supplied AND the server lists it.
%%   2. NULL
%%   3. SAFECOOKIE
pick_auth_method(Methods, Password) ->
    case {Password, lists:member("HASHEDPASSWORD", Methods)} of
        {P, true} when P =/= undefined -> {hashedpassword, P};
        _ ->
            case lists:member("NULL", Methods) of
                true -> null;
                false ->
                    case lists:member("SAFECOOKIE", Methods) of
                        true -> safecookie;
                        false -> none
                    end
            end
    end.

auth_null(Sock) ->
    case send_line(Sock, "AUTHENTICATE") of
        ok ->
            case read_reply(Sock) of
                {ok, ?TOR_REPLY_OK, _} -> ok;
                {ok, Code, _} -> {error, {auth_failed, Code}};
                {error, _} = E -> E
            end;
        {error, _} = E -> E
    end.

auth_hashedpassword(Sock, Password) ->
    Escaped = escape_quoted(Password),
    Cmd = "AUTHENTICATE \"" ++ Escaped ++ "\"",
    case send_line(Sock, Cmd) of
        ok ->
            case read_reply(Sock) of
                {ok, ?TOR_REPLY_OK, _} -> ok;
                {ok, Code, _} -> {error, {auth_failed, Code}};
                {error, _} = E -> E
            end;
        {error, _} = E -> E
    end.

%% SAFECOOKIE:
%%   1. Read cookie file (must be exactly TOR_COOKIE_SIZE bytes).
%%   2. Generate 32-byte client nonce.
%%   3. AUTHCHALLENGE SAFECOOKIE <hex(client_nonce)>.
%%   4. Verify server hash with HMAC-SHA256(SERVER_KEY, cookie||cn||sn).
%%   5. AUTHENTICATE <hex(HMAC-SHA256(CLIENT_KEY, cookie||cn||sn))>.
auth_safecookie(_Sock, undefined) ->
    {error, safecookie_no_cookie_file};
auth_safecookie(Sock, CookieFile) ->
    case file:read_file(CookieFile) of
        {ok, Cookie} when byte_size(Cookie) =:= ?TOR_COOKIE_SIZE ->
            ClientNonce = crypto:strong_rand_bytes(?TOR_NONCE_SIZE),
            Cmd = "AUTHCHALLENGE SAFECOOKIE " ++ to_hex(ClientNonce),
            case send_line(Sock, Cmd) of
                ok ->
                    case read_reply(Sock) of
                        {ok, ?TOR_REPLY_OK, [Line | _]} ->
                            handle_authchallenge(Sock, Line, Cookie,
                                                  ClientNonce);
                        {ok, Code, _} ->
                            {error, {authchallenge_failed, Code}};
                        {error, _} = E -> E
                    end;
                {error, _} = E -> E
            end;
        {ok, _Other} ->
            {error, safecookie_wrong_cookie_size};
        {error, Reason} ->
            {error, {safecookie_read_failed, Reason}}
    end.

handle_authchallenge(Sock, Line, Cookie, ClientNonce) ->
    {Type, Args} = split_reply_line(Line),
    case Type of
        "AUTHCHALLENGE" ->
            M = parse_reply_mapping(Args),
            ServerHash = from_hex(maps:get("SERVERHASH", M, "")),
            ServerNonce = from_hex(maps:get("SERVERNONCE", M, "")),
            case byte_size(ServerNonce) of
                ?TOR_NONCE_SIZE ->
                    Expected = compute_safecookie_response(
                        ?SAFE_SERVERKEY, Cookie, ClientNonce, ServerNonce),
                    case Expected =:= ServerHash of
                        true ->
                            ClientHash = compute_safecookie_response(
                                ?SAFE_CLIENTKEY, Cookie, ClientNonce,
                                ServerNonce),
                            FinalCmd = "AUTHENTICATE " ++ to_hex(ClientHash),
                            case send_line(Sock, FinalCmd) of
                                ok ->
                                    case read_reply(Sock) of
                                        {ok, ?TOR_REPLY_OK, _} -> ok;
                                        {ok, Code, _} ->
                                            {error, {auth_failed, Code}};
                                        {error, _} = E -> E
                                    end;
                                {error, _} = E -> E
                            end;
                        false ->
                            {error, server_hash_mismatch}
                    end;
                _ ->
                    {error, invalid_server_nonce_size}
            end;
        _ ->
            {error, invalid_authchallenge_response}
    end.

%% Exported for testing.  HMAC-SHA256 with the given key over
%% (Cookie || ClientNonce || ServerNonce).
compute_safecookie_response(Key, Cookie, ClientNonce, ServerNonce) ->
    crypto:mac(hmac, sha256, list_to_binary(Key),
               <<Cookie/binary, ClientNonce/binary, ServerNonce/binary>>).

%%% ===================================================================
%%% Protocol: ADD_ONION / DEL_ONION
%%% ===================================================================

%% Build the ADD_ONION command string. KeyOrNew is either the literal
%% private key blob "ED25519-V3:<base64>" (reuse a previously-cached
%% identity) or "NEW:ED25519-V3" to request a fresh ED25519 v3 key.
make_add_onion_cmd(KeyOrNew, VirtPort, Target) ->
    %% Format mirrors Core's MakeAddOnionCmd in src/torcontrol.cpp.
    %% PoW defenses flag is intentionally not included on the first
    %% attempt -- older Tor versions don't understand it.
    io_lib:format("ADD_ONION ~s Port=~B,~s",
                  [KeyOrNew, VirtPort, Target]).

do_add_onion(Sock, CachedKey, VirtPort, TargetHost, TargetPort) ->
    KeyArg = case CachedKey of
        undefined -> "NEW:ED25519-V3";
        _ -> CachedKey
    end,
    Target = io_lib:format("~s:~B", [TargetHost, TargetPort]),
    Cmd = lists:flatten(make_add_onion_cmd(KeyArg, VirtPort, Target)),
    case send_line(Sock, Cmd) of
        ok ->
            case read_reply(Sock) of
                {ok, ?TOR_REPLY_OK, Lines} ->
                    parse_add_onion_reply(Lines, CachedKey);
                {ok, Code, Lines} ->
                    {error, {add_onion_failed, Code, Lines}};
                {error, _} = E -> E
            end;
        {error, _} = E -> E
    end.

parse_add_onion_reply(Lines, CachedKey) ->
    {SID, PK} = lists:foldl(fun(Line, {S, P}) ->
        M = parse_reply_mapping(Line),
        S1 = case maps:find("ServiceID", M) of
            {ok, V} -> V;
            error -> S
        end,
        P1 = case maps:find("PrivateKey", M) of
            {ok, V2} -> V2;
            error -> P
        end,
        {S1, P1}
    end, {undefined, undefined}, Lines),
    case SID of
        undefined ->
            {error, {add_onion_no_service_id, Lines}};
        _ ->
            %% If Tor didn't return the private key (because we sent
            %% the cached key), the cached key is still authoritative.
            %% Otherwise the spec returns the value AS "ED25519-V3:<b64>"
            %% in the mapping value -- only prefix if it isn't there.
            PrivKey = case PK of
                undefined when CachedKey =/= undefined -> CachedKey;
                undefined -> "";
                _ ->
                    case lists:prefix("ED25519-V3:", PK) of
                        true  -> PK;
                        false -> "ED25519-V3:" ++ PK
                    end
            end,
            {ok, SID, PrivKey}
    end.

do_del_onion(Sock, ServiceID) ->
    Cmd = "DEL_ONION " ++ ServiceID,
    case send_line(Sock, Cmd) of
        ok ->
            case read_reply(Sock) of
                {ok, ?TOR_REPLY_OK, _} -> ok;
                {ok, Code, _} -> {error, {del_onion_failed, Code}};
                {error, _} = E -> E
            end;
        {error, _} = E -> E
    end.

%%% ===================================================================
%%% Reply parsing
%%% ===================================================================

%% Read one complete reply (one or more lines with codes <NNN><sep><data>)
%% terminating at the line where the separator is ' '. Returns
%% {ok, Code, [DataLine, ...]} or {error, Reason}.
read_reply(Sock) ->
    read_reply(Sock, undefined, []).

read_reply(Sock, CurCode, Acc) ->
    case gen_tcp:recv(Sock, 0, ?RECV_TIMEOUT_MS) of
        {ok, Bin} ->
            Line = binary_to_list(strip_trailing_crlf(Bin)),
            case parse_reply_line(Line) of
                {ok, Code, Data, more} ->
                    read_reply(Sock, Code, [Data | Acc]);
                {ok, Code, Data, final} ->
                    {ok, Code, lists:reverse([Data | Acc])};
                {error, _} = E ->
                    %% Try to keep going on a malformed line but bail
                    %% if we have no state.
                    case CurCode of
                        undefined -> E;
                        _ -> read_reply(Sock, CurCode, Acc)
                    end
            end;
        {error, _} = E ->
            E
    end.

%% Parse a single Tor reply line of the form  NNN(-| |+)DATA
%% Returns {ok, Code, Data, more|final} or {error, Reason}.
parse_reply_line([D0, D1, D2, Sep | Rest])
  when D0 >= $0, D0 =< $9,
       D1 >= $0, D1 =< $9,
       D2 >= $0, D2 =< $9 ->
    Code = ((D0 - $0) * 100) + ((D1 - $0) * 10) + (D2 - $0),
    case Sep of
        $\s -> {ok, Code, Rest, final};
        $-  -> {ok, Code, Rest, more};
        $+  -> {ok, Code, Rest, more};
        _   -> {error, invalid_separator}
    end;
parse_reply_line(_) ->
    {error, short_reply_line}.

%% Split "AUTH METHODS=X,Y COOKIEFILE=..." into {"AUTH","METHODS=..."}.
split_reply_line(S) ->
    case string:split(S, " ") of
        [Type, Rest] -> {Type, Rest};
        [Type] -> {Type, ""}
    end.

%% Parse "KEY=VAL KEY2=\"quoted val\" KEY3=Unquoted" into a #{}.
parse_reply_mapping(S) when is_list(S) ->
    parse_reply_mapping_loop(S, #{});
parse_reply_mapping(S) when is_binary(S) ->
    parse_reply_mapping(binary_to_list(S)).

parse_reply_mapping_loop([], Acc) -> Acc;
parse_reply_mapping_loop([$\s | Rest], Acc) ->
    parse_reply_mapping_loop(Rest, Acc);
parse_reply_mapping_loop(S, Acc) ->
    case parse_kv(S) of
        {Key, Value, Rest} ->
            parse_reply_mapping_loop(Rest, Acc#{Key => Value});
        eol ->
            Acc
    end.

parse_kv(S) ->
    case split_on_eq(S, []) of
        eol -> eol;
        {Key, [$\" | Rest]} ->
            {Value, Rest1} = read_quoted(Rest, []),
            {Key, Value, Rest1};
        {Key, Rest} ->
            {Value, Rest1} = read_unquoted(Rest, []),
            {Key, Value, Rest1}
    end.

split_on_eq([], _Acc) -> eol;
split_on_eq([$\s | _], _Acc) -> eol;
split_on_eq([$= | Rest], Acc) -> {lists:reverse(Acc), Rest};
split_on_eq([C | Rest], Acc) -> split_on_eq(Rest, [C | Acc]).

read_quoted([], Acc) -> {lists:reverse(Acc), []};
read_quoted([$\" | Rest], Acc) -> {lists:reverse(Acc), Rest};
read_quoted([$\\, C | Rest], Acc) ->
    %% Minimal C-style escape support (control-spec.txt 2.1.1)
    Escaped = case C of
        $n -> $\n;
        $r -> $\r;
        $t -> $\t;
        Other -> Other
    end,
    read_quoted(Rest, [Escaped | Acc]);
read_quoted([C | Rest], Acc) ->
    read_quoted(Rest, [C | Acc]).

read_unquoted([], Acc) -> {lists:reverse(Acc), []};
read_unquoted([$\s | Rest], Acc) -> {lists:reverse(Acc), Rest};
read_unquoted([C | Rest], Acc) -> read_unquoted(Rest, [C | Acc]).

%%% ===================================================================
%%% Persistent state
%%% ===================================================================

%% Path to the cached ED25519-V3 private key, mirrors Core's
%% TorController::GetPrivateKeyFile (onion_v3_private_key) but renamed
%% to tor_v3_secret_key for clarity with the rest of the beamchain
%% data-dir layout (and to match the FIX-58 spec).
private_key_file(DataDir) ->
    filename:join(DataDir, "tor_v3_secret_key").

load_cached_private_key(DataDir) ->
    File = private_key_file(DataDir),
    case file:read_file(File) of
        {ok, Bin} when byte_size(Bin) > 0 ->
            string:trim(binary_to_list(Bin));
        _ ->
            undefined
    end.

persist_private_key(_DataDir, "") -> ok;
persist_private_key(_DataDir, undefined) -> ok;
persist_private_key(DataDir, PrivKey) when is_list(PrivKey) ->
    File = private_key_file(DataDir),
    ok = filelib:ensure_dir(File),
    %% chmod 0600 because the private key controls the hidden service.
    case file:write_file(File, list_to_binary(PrivKey)) of
        ok ->
            _ = file:change_mode(File, 8#600),
            ok;
        {error, Reason} ->
            logger:warning("torcontrol: failed to persist private key "
                           "to ~s: ~p", [File, Reason]),
            {error, Reason}
    end.

%%% ===================================================================
%%% Misc helpers
%%% ===================================================================

send_line(Sock, Line) when is_list(Line) ->
    gen_tcp:send(Sock, [Line, "\r\n"]).

strip_trailing_crlf(Bin) when is_binary(Bin) ->
    Sz = byte_size(Bin),
    case Bin of
        <<Head:(Sz - 2)/binary, "\r\n">> -> Head;
        <<Head:(Sz - 1)/binary, "\n">> -> Head;
        _ -> Bin
    end.

to_hex(Bin) when is_binary(Bin) ->
    [hex_nybble(N) || <<N:4>> <= Bin].

hex_nybble(N) when N < 10 -> $0 + N;
hex_nybble(N) -> $a + (N - 10).

from_hex([]) -> <<>>;
from_hex(S) when is_list(S) ->
    list_to_binary(parse_hex_pairs(S)).

parse_hex_pairs([]) -> [];
parse_hex_pairs([A, B | Rest]) ->
    [(hex_val(A) bsl 4) bor hex_val(B) | parse_hex_pairs(Rest)];
parse_hex_pairs([_]) -> [].  %% odd length -- drop trailing nybble.

hex_val(C) when C >= $0, C =< $9 -> C - $0;
hex_val(C) when C >= $a, C =< $f -> C - $a + 10;
hex_val(C) when C >= $A, C =< $F -> C - $A + 10.

escape_quoted(S) ->
    lists:flatten([escape_char(C) || C <- S]).

escape_char($\\) -> "\\\\";
escape_char($\") -> "\\\"";
escape_char(C) -> C.

default_config() ->
    %% Resolve from beamchain_config when running inside a node;
    %% fall back to safe defaults otherwise.
    Addr = try beamchain_config:torcontrol_addr()
           catch _:_ -> #{host => "127.0.0.1", port => 9051}
           end,
    Password = try beamchain_config:torcontrol_password()
               catch _:_ -> undefined end,
    DataDir = default_datadir(),
    P2PPort = default_p2p_port(),
    #{host        => maps:get(host, Addr, "127.0.0.1"),
      port        => maps:get(port, Addr, 9051),
      password    => Password,
      virt_port   => P2PPort,
      target_host => "127.0.0.1",
      target_port => P2PPort,
      datadir     => DataDir}.

default_datadir() ->
    try beamchain_config:datadir()
    catch _:_ -> "."
    end.

default_p2p_port() ->
    %% Try the configured p2p_port override first, then the chain
    %% params default.  Fall back to 8333 if neither is available
    %% (e.g. during tests where config isn't running).
    try
        case beamchain_config:get(p2pport) of
            P when is_integer(P) -> P;
            P when is_list(P) -> list_to_integer(P);
            _ ->
                Params = beamchain_config:network_params(),
                Params#network_params.default_port
        end
    catch _:_ -> 8333
    end.
