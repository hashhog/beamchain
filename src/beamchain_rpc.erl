-module(beamchain_rpc).
-behaviour(gen_server).

%% Bitcoin Core-compatible JSON-RPC server using Cowboy.

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% API
-export([start_link/0]).

%% Cowboy handler
-export([init/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-define(SERVER, ?MODULE).

%%% -------------------------------------------------------------------
%%% RPC error codes (Bitcoin Core compatible)
%%% -------------------------------------------------------------------

-define(RPC_INVALID_REQUEST, -32600).
-define(RPC_METHOD_NOT_FOUND, -32601).
-define(RPC_INVALID_PARAMS, -32602).
-define(RPC_INTERNAL_ERROR, -32603).
-define(RPC_PARSE_ERROR, -32700).
-define(RPC_MISC_ERROR, -1).
-define(RPC_TYPE_ERROR, -3).
-define(RPC_INVALID_ADDRESS_OR_KEY, -5).
-define(RPC_INVALID_PARAMETER, -8).
-define(RPC_DATABASE_ERROR, -20).
-define(RPC_DESERIALIZATION_ERROR, -22).
-define(RPC_VERIFY_ERROR, -25).
-define(RPC_VERIFY_REJECTED, -26).
-define(RPC_VERIFY_ALREADY_IN_CHAIN, -27).
-define(RPC_IN_WARMUP, -28).

%%% -------------------------------------------------------------------
%%% Tables and limits
%%% -------------------------------------------------------------------

-define(RPC_AUTH_TABLE, rpc_auth).
-define(RATE_LIMIT_TABLE, rpc_rate_limit).
-define(MAX_REQUESTS_PER_MINUTE, 100).

-record(state, {
    start_time :: non_neg_integer()
}).

%%% ===================================================================
%%% API
%%% ===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%%% ===================================================================
%%% gen_server callbacks
%%% ===================================================================

init([]) ->
    %% Auth table for cookie and rpc credentials
    ets:new(?RPC_AUTH_TABLE, [named_table, set, public,
                              {read_concurrency, true}]),
    %% Rate limit: {IP, Count, WindowStart}
    ets:new(?RATE_LIMIT_TABLE, [named_table, set, public]),

    setup_auth(),

    %% Start Cowboy listener
    Params = beamchain_config:network_params(),
    Port = rpc_port(Params),
    Dispatch = cowboy_router:compile([
        {'_', [{"/", ?MODULE, []}]}
    ]),
    case cowboy:start_clear(beamchain_rpc_listener,
            [{port, Port}],
            #{env => #{dispatch => Dispatch}}) of
        {ok, _} ->
            logger:info("rpc: listening on port ~B", [Port]);
        {error, {already_started, _}} ->
            logger:info("rpc: already listening on port ~B", [Port]);
        {error, Reason} ->
            logger:warning("rpc: failed to start on port ~B: ~p",
                           [Port, Reason])
    end,

    erlang:send_after(60000, self(), cleanup_rate_limits),
    {ok, #state{start_time = erlang:system_time(second)}}.

handle_call(get_start_time, _From, #state{start_time = T} = State) ->
    {reply, T, State};
handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(cleanup_rate_limits, State) ->
    Now = erlang:system_time(second),
    ets:foldl(fun({IP, _Count, WindowStart}, _) ->
        case Now - WindowStart > 60 of
            true  -> ets:delete(?RATE_LIMIT_TABLE, IP);
            false -> ok
        end
    end, ok, ?RATE_LIMIT_TABLE),
    erlang:send_after(60000, self(), cleanup_rate_limits),
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    catch cowboy:stop_listener(beamchain_rpc_listener),
    %% Clean up cookie file
    DataDir = beamchain_config:datadir(),
    CookiePath = filename:join(DataDir, ".cookie"),
    file:delete(CookiePath),
    logger:info("rpc: stopped"),
    ok.

%%% ===================================================================
%%% Cowboy handler
%%% ===================================================================

%% Cowboy calls init/2 for each HTTP request.
init(Req0, CowboyState) ->
    case cowboy_req:method(Req0) of
        <<"POST">> ->
            handle_post(Req0, CowboyState);
        _ ->
            Req = cowboy_req:reply(405, #{}, <<"Method Not Allowed">>, Req0),
            {ok, Req, CowboyState}
    end.

handle_post(Req0, CowboyState) ->
    {IP, _} = cowboy_req:peer(Req0),
    case check_rate_limit(IP) of
        ok ->
            case check_auth(Req0) of
                ok ->
                    process_body(Req0, CowboyState);
                {error, _} ->
                    Req = cowboy_req:reply(401, #{
                        <<"content-type">> => <<"application/json">>,
                        <<"www-authenticate">> => <<"Basic realm=\"jsonrpc\"">>
                    }, jsx:encode(error_obj(null, ?RPC_MISC_ERROR,
                        <<"Authorization required">>)), Req0),
                    {ok, Req, CowboyState}
            end;
        rate_limited ->
            Req = cowboy_req:reply(429, #{
                <<"content-type">> => <<"application/json">>
            }, jsx:encode(error_obj(null, ?RPC_MISC_ERROR,
                <<"Rate limit exceeded">>)), Req0),
            {ok, Req, CowboyState}
    end.

process_body(Req0, CowboyState) ->
    {ok, Body, Req1} = cowboy_req:read_body(Req0),
    try jsx:decode(Body, [return_maps]) of
        Request when is_map(Request) ->
            Response = dispatch(Request),
            reply_json(Response, Req1, CowboyState);
        Batch when is_list(Batch) ->
            Responses = [dispatch(R) || R <- Batch, is_map(R)],
            reply_json(Responses, Req1, CowboyState);
        _ ->
            reply_json(error_obj(null, ?RPC_PARSE_ERROR,
                <<"Parse error">>), Req1, CowboyState)
    catch
        _:_ ->
            reply_json(error_obj(null, ?RPC_PARSE_ERROR,
                <<"Parse error">>), Req1, CowboyState)
    end.

reply_json(Body, Req0, CowboyState) ->
    Req = cowboy_req:reply(200, #{
        <<"content-type">> => <<"application/json">>
    }, jsx:encode(Body), Req0),
    {ok, Req, CowboyState}.

%%% ===================================================================
%%% Authentication
%%% ===================================================================

setup_auth() ->
    %% Generate random cookie and write to .cookie file
    Cookie = beamchain_serialize:hex_encode(crypto:strong_rand_bytes(32)),
    DataDir = beamchain_config:datadir(),
    CookiePath = filename:join(DataDir, ".cookie"),
    CookieContent = <<"__cookie__:", Cookie/binary>>,
    case file:write_file(CookiePath, CookieContent) of
        ok ->
            file:change_mode(CookiePath, 8#0600),
            ets:insert(?RPC_AUTH_TABLE, {cookie, Cookie}),
            logger:info("rpc: cookie written to ~s", [CookiePath]);
        {error, Reason} ->
            logger:warning("rpc: failed to write cookie: ~p", [Reason])
    end,
    %% Optional rpcuser/rpcpassword from config
    case {beamchain_config:get(rpcuser), beamchain_config:get(rpcpassword)} of
        {undefined, _} -> ok;
        {_, undefined} -> ok;
        {U, P} ->
            ets:insert(?RPC_AUTH_TABLE,
                {rpc_credentials, to_bin(U), to_bin(P)})
    end.

check_auth(Req) ->
    case cowboy_req:parse_header(<<"authorization">>, Req) of
        {basic, User, Pass} ->
            verify_credentials(User, Pass);
        _ ->
            {error, missing_auth}
    end.

verify_credentials(<<"__cookie__">>, Pass) ->
    case ets:lookup(?RPC_AUTH_TABLE, cookie) of
        [{cookie, Pass}] -> ok;
        _ -> {error, bad_cookie}
    end;
verify_credentials(User, Pass) ->
    case ets:lookup(?RPC_AUTH_TABLE, rpc_credentials) of
        [{rpc_credentials, User, Pass}] -> ok;
        [{rpc_credentials, _, _}] -> {error, bad_credentials};
        [] ->
            %% No rpc credentials configured, try as cookie
            verify_credentials(<<"__cookie__">>, Pass)
    end.

%%% ===================================================================
%%% Rate limiting
%%% ===================================================================

check_rate_limit(IP) ->
    Now = erlang:system_time(second),
    case ets:lookup(?RATE_LIMIT_TABLE, IP) of
        [{IP, Count, WindowStart}] when Now - WindowStart < 60 ->
            case Count >= ?MAX_REQUESTS_PER_MINUTE of
                true  -> rate_limited;
                false ->
                    ets:insert(?RATE_LIMIT_TABLE, {IP, Count + 1, WindowStart}),
                    ok
            end;
        _ ->
            ets:insert(?RATE_LIMIT_TABLE, {IP, 1, Now}),
            ok
    end.

%%% ===================================================================
%%% JSON-RPC dispatch
%%% ===================================================================

dispatch(Request) ->
    Id = maps:get(<<"id">>, Request, null),
    try
        case maps:get(<<"method">>, Request, undefined) of
            undefined ->
                error_obj(Id, ?RPC_INVALID_REQUEST, <<"Missing method">>);
            Method ->
                Params = maps:get(<<"params">>, Request, []),
                case handle_method(Method, Params) of
                    {ok, Result} ->
                        result_obj(Id, Result);
                    {error, Code, Msg} ->
                        error_obj(Id, Code, Msg)
                end
        end
    catch
        _:Err ->
            logger:warning("rpc dispatch error: ~p", [Err]),
            error_obj(Id, ?RPC_INTERNAL_ERROR, <<"Internal error">>)
    end.

result_obj(Id, Result) ->
    #{<<"result">> => Result, <<"error">> => null, <<"id">> => Id}.

error_obj(Id, Code, Message) ->
    #{<<"result">> => null,
      <<"error">> => #{<<"code">> => Code, <<"message">> => Message},
      <<"id">> => Id}.

%%% ===================================================================
%%% Method dispatch
%%% ===================================================================

%% -- Control --
handle_method(<<"help">>, Params) -> rpc_help(Params);
handle_method(<<"stop">>, _) -> rpc_stop();
handle_method(<<"uptime">>, _) -> rpc_uptime();

%% -- Blockchain (basic) --
handle_method(<<"getblockcount">>, _) -> rpc_getblockcount();
handle_method(<<"getbestblockhash">>, _) -> rpc_getbestblockhash();

handle_method(Method, _) ->
    {error, ?RPC_METHOD_NOT_FOUND,
     <<"Method not found: ", Method/binary>>}.

%%% ===================================================================
%%% Control methods
%%% ===================================================================

rpc_help([]) -> rpc_help_list();
rpc_help([Command]) when is_binary(Command) -> rpc_help_command(Command);
rpc_help(_) -> rpc_help_list().

rpc_help_list() ->
    Lines = [
        <<"== Blockchain ==">>,
        <<"getbestblockhash">>,
        <<"getblock \"blockhash\" ( verbosity )">>,
        <<"getblockchaininfo">>,
        <<"getblockcount">>,
        <<"getblockhash height">>,
        <<"getblockheader \"blockhash\" ( verbose )">>,
        <<"getchaintips">>,
        <<"getdifficulty">>,
        <<"verifychain ( checklevel nblocks )">>,
        <<"">>,
        <<"== Control ==">>,
        <<"help ( \"command\" )">>,
        <<"stop">>,
        <<"uptime">>,
        <<"">>,
        <<"== Generating ==">>,
        <<"getblocktemplate ( \"template_request\" )">>,
        <<"getmininginfo">>,
        <<"submitblock \"hexdata\"">>,
        <<"">>,
        <<"== Mempool ==">>,
        <<"getmempoolentry \"txid\"">>,
        <<"getmempoolinfo">>,
        <<"getrawmempool ( verbose )">>,
        <<"">>,
        <<"== Network ==">>,
        <<"addnode \"node\" \"command\"">>,
        <<"disconnectnode ( \"address\" nodeid )">>,
        <<"getconnectioncount">>,
        <<"getnetworkinfo">>,
        <<"getpeerinfo">>,
        <<"">>,
        <<"== Rawtransactions ==">>,
        <<"decoderawtransaction \"hexstring\"">>,
        <<"decodescript \"hexstring\"">>,
        <<"getrawtransaction \"txid\" ( verbose \"blockhash\" )">>,
        <<"sendrawtransaction \"hexstring\"">>,
        <<"testmempoolaccept [\"rawtx\"]">>,
        <<"">>,
        <<"== Util ==">>,
        <<"estimatesmartfee conf_target ( \"estimate_mode\" )">>,
        <<"validateaddress \"address\"">>,
        <<"">>,
        <<"== Wallet ==">>,
        <<"gettxout \"txid\" n ( include_mempool )">>
    ],
    {ok, iolist_to_binary(lists:join(<<"\n">>, Lines))}.

rpc_help_command(_Command) ->
    {ok, <<"No detailed help available for this command yet">>}.

rpc_stop() ->
    spawn(fun() ->
        timer:sleep(200),
        init:stop()
    end),
    {ok, <<"Beamchain server stopping">>}.

rpc_uptime() ->
    StartTime = gen_server:call(?SERVER, get_start_time),
    Now = erlang:system_time(second),
    {ok, Now - StartTime}.

%%% ===================================================================
%%% Blockchain methods (basic)
%%% ===================================================================

rpc_getblockcount() ->
    case beamchain_chainstate:get_tip() of
        {ok, {_Hash, Height}} -> {ok, Height};
        not_found -> {ok, 0}
    end.

rpc_getbestblockhash() ->
    case beamchain_chainstate:get_tip() of
        {ok, {Hash, _Height}} ->
            {ok, hash_to_hex(Hash)};
        not_found ->
            {error, ?RPC_MISC_ERROR, <<"No blocks yet">>}
    end.

%%% ===================================================================
%%% Internal helpers
%%% ===================================================================

rpc_port(Params) ->
    case beamchain_config:get(rpcport) of
        undefined -> Params#network_params.rpc_port;
        P when is_integer(P) -> P;
        P when is_list(P) -> list_to_integer(P)
    end.

to_bin(V) when is_binary(V) -> V;
to_bin(V) when is_list(V) -> list_to_binary(V).

%% Display-order hash hex (reversed bytes).
hash_to_hex(Hash) when byte_size(Hash) =:= 32 ->
    beamchain_serialize:hex_encode(
        beamchain_serialize:reverse_bytes(Hash));
hash_to_hex(_) ->
    <<"0000000000000000000000000000000000000000000000000000000000000000">>.

network_name(mainnet)  -> <<"main">>;
network_name(testnet)  -> <<"test">>;
network_name(testnet4) -> <<"testnet4">>;
network_name(regtest)  -> <<"regtest">>;
network_name(signet)   -> <<"signet">>;
network_name(N)        -> atom_to_binary(N, utf8).
