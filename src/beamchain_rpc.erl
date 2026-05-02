-module(beamchain_rpc).
-behaviour(gen_server).

%% Bitcoin Core-compatible JSON-RPC server using Cowboy.

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% Dialyzer suppressions for false positives:
%% format_mempool_entry/1: catch-all clause is defensive for unexpected input.
%% rpc_unloadwallet/1, rpc_sendtoaddress/2, rpc_signrawtransactionwithwallet/2:
%%   defensive {error,_} handlers kept for robustness even though dialyzer
%%   infers the called functions always return {ok,_} from current code paths.
-dialyzer({nowarn_function, [format_mempool_entry/1,
                              rpc_unloadwallet/1,
                              rpc_sendtoaddress/2,
                              rpc_signrawtransactionwithwallet/2]}).

%% API
-export([start_link/0]).

%% Exported for testing — shared deployment-state helper.
-export([build_deployment_map/3]).

%% Exported for testing — Core-strict assumeutxo height whitelist check.
-export([validate_snapshot_height/2]).

%% Exported for testing — dumptxoutset rollback target resolution.
%% Pure function; no side effects beyond DB lookups for height/hash → index.
-export([resolve_dump_target/5]).

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
-define(MAX_REQUESTS_PER_MINUTE, 100000).

-record(state, {
    start_time :: non_neg_integer()
}).

%% Re-define mempool_entry record (internal to beamchain_mempool).
-record(mempool_entry, {
    txid, wtxid, tx, fee, size, vsize, weight, fee_rate,
    time_added, height_added,
    ancestor_count, ancestor_size, ancestor_fee,
    descendant_count, descendant_size, descendant_fee,
    spends_coinbase, rbf_signaling
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
        {'_', [
            {"/", ?MODULE, []},
            {"/wallet/:wallet_name", ?MODULE, []},
            %% /health: unauthenticated GET endpoint for process supervisors
            %% (systemd, k8s, watchdog scripts). Mirrors the spirit of
            %% Bitcoin Core's getrpcinfo + initialblockdownload status,
            %% without requiring rpc cookie auth.
            {"/health", beamchain_rpc, [health]}
        ]}
    ]),
    TransportOpts = #{socket_opts => [{port, Port}, {reuseaddr, true}]},
    ProtoOpts = #{env => #{dispatch => Dispatch}},
    case beamchain_listener:start_clear_with_retry(
            beamchain_rpc_listener, TransportOpts, ProtoOpts, "rpc") of
        {ok, _} ->
            logger:info("rpc: listening on port ~B", [Port]);
        {error, Reason} ->
            logger:error("rpc: failed to bind port ~B after retries: ~p",
                         [Port, Reason]),
            %% Crash the gen_server so the supervisor restarts it; the
            %% rest_for_one strategy will re-attempt the RPC/REST/metrics
            %% tail. Supervisor intensity gives us bounded further tries.
            exit({listener_bind_failed, rpc, Port, Reason})
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
%%% Parallel map for batch processing
%%% ===================================================================

%% Parallel map using spawn_link and message passing.
%% Executes Fun on each element of List concurrently and returns results
%% in the same order as the input list.
pmap(Fun, List) ->
    Parent = self(),
    Refs = [begin
        Ref = make_ref(),
        spawn_link(fun() -> Parent ! {Ref, Fun(E)} end),
        Ref
    end || E <- List],
    [receive {Ref, R} -> R end || Ref <- Refs].

%%% ===================================================================
%%% Cowboy handler
%%% ===================================================================

%% Cowboy calls init/2 for each HTTP request.
init(Req0, [health] = CowboyState) ->
    %% GET /health -- liveness/readiness probe for supervisors.
    %% Returns 200 + JSON when the chainstate is reachable, 503 otherwise.
    %% No auth (cookie/credentials) required by design; the endpoint
    %% exposes only public liveness info already visible via P2P.
    case cowboy_req:method(Req0) of
        Verb when Verb =:= <<"GET">>; Verb =:= <<"HEAD">> ->
            handle_health(Req0, CowboyState);
        _ ->
            Req = cowboy_req:reply(405, #{}, <<"Method Not Allowed">>, Req0),
            {ok, Req, CowboyState}
    end;
init(Req0, CowboyState) ->
    case cowboy_req:method(Req0) of
        <<"POST">> ->
            handle_post(Req0, CowboyState);
        _ ->
            Req = cowboy_req:reply(405, #{}, <<"Method Not Allowed">>, Req0),
            {ok, Req, CowboyState}
    end.

handle_health(Req0, CowboyState) ->
    {Status, Body} =
        try
            case beamchain_chainstate:get_tip() of
                {ok, {Hash, Height}} ->
                    IBD = case catch beamchain_chainstate:is_synced() of
                        true -> false;
                        false -> true;
                        _    -> true
                    end,
                    {200, jsx:encode(#{
                        <<"status">>     => <<"ok">>,
                        <<"height">>     => Height,
                        <<"bestblock">>  => bin_to_hex(Hash),
                        <<"ibd">>        => IBD
                    })};
                _ ->
                    {503, jsx:encode(#{<<"status">> => <<"warmup">>})}
            end
        catch
            _:_ ->
                {503, jsx:encode(#{<<"status">> => <<"unavailable">>})}
        end,
    Headers = #{<<"content-type">> => <<"application/json">>},
    Req = cowboy_req:reply(Status, Headers, Body, Req0),
    {ok, Req, CowboyState}.

%% Lightweight binary->hex (cowboy handler-local; we don't depend on
%% the larger crypto helpers here so /health stays cheap).
bin_to_hex(Bin) when is_binary(Bin) ->
    list_to_binary(
      lists:flatten(
        [io_lib:format("~2.16.0b", [B]) || <<B>> <= Bin])).

handle_post(Req0, CowboyState) ->
    {IP, _} = cowboy_req:peer(Req0),
    case check_rate_limit(IP) of
        ok ->
            case check_auth(Req0) of
                ok ->
                    %% Extract wallet name from URL path if present
                    WalletName = case cowboy_req:binding(wallet_name, Req0) of
                        undefined -> <<>>;
                        Name -> Name
                    end,
                    process_body(Req0, CowboyState, WalletName);
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

process_body(Req0, CowboyState, WalletName) ->
    {ok, Body, Req1} = cowboy_req:read_body(Req0),
    try jsx:decode(Body, [return_maps]) of
        Request when is_map(Request) ->
            %% Single request
            Response = dispatch(Request, WalletName),
            reply_json(Response, Req1, CowboyState);
        [] ->
            %% Empty batch is an invalid request per JSON-RPC 2.0 spec
            reply_json(error_obj(null, ?RPC_INVALID_REQUEST,
                <<"Invalid Request: empty batch">>), Req1, CowboyState);
        Batch when is_list(Batch) ->
            %% Batch request: process each independently with parallel execution
            Responses = handle_batch(Batch, WalletName),
            reply_json(Responses, Req1, CowboyState);
        _ ->
            reply_json(error_obj(null, ?RPC_PARSE_ERROR,
                <<"Parse error">>), Req1, CowboyState)
    catch
        _:_ ->
            reply_json(error_obj(null, ?RPC_PARSE_ERROR,
                <<"Parse error">>), Req1, CowboyState)
    end.

%% Handle a batch of JSON-RPC requests.
%% Each request is processed independently; individual failures don't
%% affect other requests. Non-object elements return invalid request errors.
%% Uses parallel execution for better throughput.
handle_batch(Batch, WalletName) ->
    pmap(fun(Req) -> handle_batch_element(Req, WalletName) end, Batch).

%% Handle a single element in a batch request.
%% Returns a proper error for non-object elements.
handle_batch_element(Request, WalletName) when is_map(Request) ->
    dispatch(Request, WalletName);
handle_batch_element(_NonObject, _WalletName) ->
    %% Non-object array elements are invalid requests
    error_obj(null, ?RPC_INVALID_REQUEST, <<"Invalid Request">>).

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

dispatch(Request, WalletName) ->
    Id = maps:get(<<"id">>, Request, null),
    try
        case maps:get(<<"method">>, Request, undefined) of
            undefined ->
                error_obj(Id, ?RPC_INVALID_REQUEST, <<"Missing method">>);
            Method ->
                Params = maps:get(<<"params">>, Request, []),
                case handle_method(Method, Params, WalletName) of
                    {ok, Result} ->
                        result_obj(Id, Result);
                    {error, Code, Msg} ->
                        error_obj(Id, Code, Msg)
                end
        end
    catch
        Class:Err:Stack ->
            logger:warning("rpc dispatch error: ~p:~p~n~p", [Class, Err, Stack]),
            error_obj(Id, ?RPC_INTERNAL_ERROR, format_internal_error(Class, Err))
    end.

%% Format a caught exception for the -32603 response body.
%% Includes class and a short reason description (truncated to 200 chars).
%% Does NOT leak stack traces or absolute file paths — those go to the log only.
format_internal_error(Class, Err) ->
    ClassBin = atom_to_binary(Class, utf8),
    ReasonBin = truncate_binary(
                  iolist_to_binary(io_lib:format("~0p", [Err])),
                  200),
    <<"Internal error: ", ClassBin/binary, ": ", ReasonBin/binary>>.

truncate_binary(Bin, Max) when byte_size(Bin) =< Max ->
    Bin;
truncate_binary(Bin, Max) ->
    Head = binary:part(Bin, 0, Max),
    <<Head/binary, "...">>.

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
handle_method(<<"help">>, Params, _W) -> rpc_help(Params);
handle_method(<<"stop">>, _, _W) -> rpc_stop();
handle_method(<<"uptime">>, _, _W) -> rpc_uptime();

%% -- Blockchain --
handle_method(<<"getblockcount">>, _, _W) -> rpc_getblockcount();
handle_method(<<"getbestblockhash">>, _, _W) -> rpc_getbestblockhash();
handle_method(<<"getsyncstate">>, _, _W) -> rpc_getsyncstate();
handle_method(<<"getblockchaininfo">>, _, _W) -> rpc_getblockchaininfo();
handle_method(<<"getdeploymentinfo">>, P, _W) -> rpc_getdeploymentinfo(P);
handle_method(<<"getblockhash">>, P, _W) -> rpc_getblockhash(P);
handle_method(<<"getblock">>, P, _W) -> rpc_getblock(P);
handle_method(<<"getblockheader">>, P, _W) -> rpc_getblockheader(P);
handle_method(<<"getdifficulty">>, _, _W) -> rpc_getdifficulty();
handle_method(<<"getchaintips">>, _, _W) -> rpc_getchaintips();
handle_method(<<"getblockstats">>, P, _W) -> rpc_getblockstats(P);
handle_method(<<"getchaintxstats">>, P, _W) -> rpc_getchaintxstats(P);
handle_method(<<"verifychain">>, _, _W) -> rpc_verifychain();
handle_method(<<"invalidateblock">>, P, _W) -> rpc_invalidateblock(P);
handle_method(<<"reconsiderblock">>, P, _W) -> rpc_reconsiderblock(P);
handle_method(<<"flushchainstate">>, _, _W) -> rpc_flushchainstate();
handle_method(<<"scrubunspendable">>, _, _W) -> rpc_scrubunspendable();

%% -- Transactions --
handle_method(<<"getrawtransaction">>, P, _W) -> rpc_getrawtransaction(P);
handle_method(<<"decoderawtransaction">>, P, _W) -> rpc_decoderawtransaction(P);
handle_method(<<"sendrawtransaction">>, P, _W) -> rpc_sendrawtransaction(P);
handle_method(<<"createrawtransaction">>, P, _W) -> rpc_createrawtransaction(P);
handle_method(<<"testmempoolaccept">>, P, _W) -> rpc_testmempoolaccept(P);
handle_method(<<"gettxout">>, P, _W) -> rpc_gettxout(P);
handle_method(<<"gettxoutsetinfo">>, P, _W) -> rpc_gettxoutsetinfo(P);

%% -- Mempool --
handle_method(<<"getmempoolinfo">>, _, _W) -> rpc_getmempoolinfo();
handle_method(<<"getrawmempool">>, P, _W) -> rpc_getrawmempool(P);
handle_method(<<"getmempoolentry">>, P, _W) -> rpc_getmempoolentry(P);
handle_method(<<"getmempoolancestors">>, P, _W) -> rpc_getmempoolancestors(P);
handle_method(<<"getmempooldescendants">>, P, _W) -> rpc_getmempooldescendants(P);
handle_method(<<"savemempool">>, _, _W) -> rpc_dumpmempool();
handle_method(<<"dumpmempool">>, _, _W) -> rpc_dumpmempool();
handle_method(<<"loadmempool">>, _, _W) -> rpc_loadmempool();

%% -- Network --
handle_method(<<"getnetworkinfo">>, _, _W) -> rpc_getnetworkinfo();
handle_method(<<"getpeerinfo">>, _, _W) -> rpc_getpeerinfo();
handle_method(<<"getconnectioncount">>, _, _W) -> rpc_getconnectioncount();
handle_method(<<"addnode">>, P, _W) -> rpc_addnode(P);
handle_method(<<"disconnectnode">>, P, _W) -> rpc_disconnectnode(P);
handle_method(<<"listbanned">>, _, _W) -> rpc_listbanned();
handle_method(<<"setban">>, P, _W) -> rpc_setban(P);
handle_method(<<"clearbanned">>, _, _W) -> rpc_clearbanned();

%% -- Mining --
handle_method(<<"getmininginfo">>, _, _W) -> rpc_getmininginfo();
handle_method(<<"getblocktemplate">>, P, _W) -> rpc_getblocktemplate(P);
handle_method(<<"submitblock">>, P, _W) -> rpc_submitblock(P);

%% -- Generating (regtest only) --
handle_method(<<"generatetoaddress">>, P, _W) -> rpc_generatetoaddress(P);
handle_method(<<"generateblock">>, P, _W) -> rpc_generateblock(P);
handle_method(<<"generate">>, P, _W) -> rpc_generate(P);

%% -- Fee estimation --
handle_method(<<"estimatesmartfee">>, P, _W) -> rpc_estimatesmartfee(P);
handle_method(<<"estimaterawfee">>, P, _W) -> rpc_estimaterawfee(P);

%% -- Utility --
handle_method(<<"validateaddress">>, P, _W) -> rpc_validateaddress(P);
handle_method(<<"decodescript">>, P, _W) -> rpc_decodescript(P);
handle_method(<<"signmessagewithprivkey">>, P, _W) -> rpc_signmessagewithprivkey(P);
handle_method(<<"signmessage">>, P, W) -> rpc_signmessage(P, W);
handle_method(<<"verifymessage">>, P, _W) -> rpc_verifymessage(P);

%% -- Wallet (multi-wallet aware) --
handle_method(<<"createwallet">>, P, _W) -> rpc_createwallet(P);
handle_method(<<"loadwallet">>, P, _W) -> rpc_loadwallet(P);
handle_method(<<"unloadwallet">>, P, _W) -> rpc_unloadwallet(P);
handle_method(<<"listwallets">>, _, _W) -> rpc_listwallets();
handle_method(<<"getnewaddress">>, P, W) -> rpc_getnewaddress(P, W);
handle_method(<<"getrawchangeaddress">>, P, W) -> rpc_getrawchangeaddress(P, W);
handle_method(<<"getbalance">>, _, W) -> rpc_getbalance(W);
handle_method(<<"listaddresses">>, _, W) -> rpc_listaddresses(W);
handle_method(<<"getwalletinfo">>, _, W) -> rpc_getwalletinfo(W);
handle_method(<<"dumpprivkey">>, P, W) -> rpc_dumpprivkey(P, W);
handle_method(<<"sendtoaddress">>, P, W) -> rpc_sendtoaddress(P, W);
handle_method(<<"listunspent">>, P, W) -> rpc_listunspent(P, W);
handle_method(<<"listtransactions">>, P, W) -> rpc_listtransactions(P, W);
handle_method(<<"encryptwallet">>, P, W) -> rpc_encryptwallet(P, W);
handle_method(<<"walletpassphrase">>, P, W) -> rpc_walletpassphrase(P, W);
handle_method(<<"walletlock">>, _, W) -> rpc_walletlock(W);
handle_method(<<"signrawtransactionwithwallet">>, P, W) -> rpc_signrawtransactionwithwallet(P, W);
handle_method(<<"importdescriptors">>, P, W) -> rpc_importdescriptors(P, W);

%% -- PSBT --
handle_method(<<"createpsbt">>, P, _W) -> rpc_createpsbt(P);
handle_method(<<"decodepsbt">>, P, _W) -> rpc_decodepsbt(P);
handle_method(<<"combinepsbt">>, P, _W) -> rpc_combinepsbt(P);
handle_method(<<"finalizepsbt">>, P, _W) -> rpc_finalizepsbt(P);

%% -- Descriptors --
handle_method(<<"deriveaddresses">>, P, _W) -> rpc_deriveaddresses(P);
handle_method(<<"getdescriptorinfo">>, P, _W) -> rpc_getdescriptorinfo(P);

%% -- assumeUTXO --
handle_method(<<"loadtxoutset">>, P, _W) -> rpc_loadtxoutset(P);
handle_method(<<"dumptxoutset">>, P, _W) -> rpc_dumptxoutset(P);

handle_method(Method, _, _W) ->
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
        <<"getsyncstate">>,
        <<"getdeploymentinfo ( \"blockhash\" )">>,
        <<"getblockhash height">>,
        <<"getblockheader \"blockhash\" ( verbose )">>,
        <<"getblockstats \"hash_or_height\" ( stats )">>,
        <<"getchaintips">>,
        <<"getchaintxstats ( nblocks \"blockhash\" )">>,
        <<"getdifficulty">>,
        <<"gettxoutsetinfo ( \"hash_type\" )">>,
        <<"invalidateblock \"blockhash\"">>,
        <<"reconsiderblock \"blockhash\"">>,
        <<"verifychain ( checklevel nblocks )">>,
        <<"flushchainstate">>,
        <<"scrubunspendable">>,
        <<"">>,
        <<"== Control ==">>,
        <<"help ( \"command\" )">>,
        <<"stop">>,
        <<"uptime">>,
        <<"">>,
        <<"== Generating ==">>,
        <<"generate nblocks ( maxtries ) [regtest only]">>,
        <<"generateblock \"output\" [\"rawtx/txid\",...] ( submit ) [regtest only]">>,
        <<"generatetoaddress nblocks \"address\" ( maxtries ) [regtest only]">>,
        <<"getblocktemplate ( \"template_request\" )">>,
        <<"getmininginfo">>,
        <<"submitblock \"hexdata\"">>,
        <<"">>,
        <<"== Mempool ==">>,
        <<"dumpmempool">>,
        <<"getmempoolancestors \"txid\" ( verbose )">>,
        <<"getmempooldescendants \"txid\" ( verbose )">>,
        <<"getmempoolentry \"txid\"">>,
        <<"getmempoolinfo">>,
        <<"getrawmempool ( verbose )">>,
        <<"loadmempool">>,
        <<"savemempool">>,
        <<"">>,
        <<"== Network ==">>,
        <<"addnode \"node\" \"command\"">>,
        <<"clearbanned">>,
        <<"disconnectnode ( \"address\" nodeid )">>,
        <<"getconnectioncount">>,
        <<"getnetworkinfo">>,
        <<"getpeerinfo">>,
        <<"listbanned">>,
        <<"setban \"subnet\" \"command\" ( bantime )">>,
        <<"">>,
        <<"== Rawtransactions ==">>,
        <<"combinepsbt [\"psbt\",...]">>,
        <<"createpsbt [{\"txid\":\"hex\",\"vout\":n},...] [{\"address\":amount},...] ( locktime )">>,
        <<"createrawtransaction [{\"txid\":\"hex\",\"vout\":n},...] [{\"address\":amount},...] ( locktime replaceable )">>,
        <<"decoderawtransaction \"hexstring\"">>,
        <<"decodepsbt \"psbt\"">>,
        <<"decodescript \"hexstring\"">>,
        <<"finalizepsbt \"psbt\" ( extract )">>,
        <<"getrawtransaction \"txid\" ( verbose \"blockhash\" )">>,
        <<"sendrawtransaction \"hexstring\"">>,
        <<"testmempoolaccept [\"rawtx\"]">>,
        <<"">>,
        <<"== Util ==">>,
        <<"deriveaddresses \"descriptor\" ( range )">>,
        <<"estimatesmartfee conf_target ( \"estimate_mode\" )">>,
        <<"estimaterawfee conf_target ( threshold )">>,
        <<"signmessage \"address\" \"message\"">>,
        <<"signmessagewithprivkey \"privkey\" \"message\"">>,
        <<"verifymessage \"address\" \"signature\" \"message\"">>,
        <<"getdescriptorinfo \"descriptor\"">>,
        <<"validateaddress \"address\"">>,
        <<"">>,
        <<"== Wallet ==">>,
        <<"createwallet ( \"name\" )">>,
        <<"dumpprivkey \"address\"">>,
        <<"encryptwallet \"passphrase\"">>,
        <<"getbalance">>,
        <<"getnewaddress ( \"label\" \"address_type\" )">>,
        <<"getrawchangeaddress ( \"address_type\" )">>,
        <<"gettxout \"txid\" n ( include_mempool )">>,
        <<"getwalletinfo">>,
        <<"listaddresses">>,
        <<"listtransactions ( \"label\" count skip )">>,
        <<"listunspent ( minconf maxconf )">>,
        <<"listwallets">>,
        <<"loadwallet \"name\"">>,
        <<"importdescriptors \"requests\"">>,
        <<"sendtoaddress \"address\" amount ( \"comment\" )">>,
        <<"signrawtransactionwithwallet \"hexstring\" ( [{\"txid\":\"hex\",\"vout\":n,\"scriptPubKey\":\"hex\"},...] )">>,
        <<"unloadwallet ( \"name\" )">>,
        <<"walletlock">>,
        <<"walletpassphrase \"passphrase\" timeout">>,
        <<"">>,
        <<"== assumeUTXO ==">>,
        <<"loadtxoutset \"path\"">>,
        <<"dumptxoutset \"path\" ( \"type\" {\"rollback\":n|\"hash\"} )">>
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
%%% Blockchain methods
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

%% hashhog W70: uniform fleet-wide sync-state report.
%% Spec: meta-repo `spec/getsyncstate.md`.
rpc_getsyncstate() ->
    Network = beamchain_config:network(),
    {TipHeight, TipHash} = case beamchain_chainstate:get_tip() of
        {ok, {H, Height}} -> {Height, hash_to_hex(H)};
        not_found -> {0, <<"0000000000000000000000000000000000000000000000000000000000000000">>}
    end,
    IsIbd = not beamchain_chainstate:is_synced(),
    NumPeers = try beamchain_peer_manager:peer_count() catch _:_ -> 0 end,
    InFlight = try
        Status = beamchain_block_sync:get_status(),
        maps:get(in_flight_count, Status, null)
    catch _:_ -> null end,
    Progress = case IsIbd of
        true -> 0.999;
        false -> 1.0
    end,
    {ok, #{
        <<"tip_height">> => TipHeight,
        <<"tip_hash">> => TipHash,
        <<"best_header_height">> => TipHeight,
        <<"best_header_hash">> => TipHash,
        <<"initial_block_download">> => IsIbd,
        <<"num_peers">> => NumPeers,
        <<"verification_progress">> => Progress,
        <<"blocks_in_flight">> => InFlight,
        <<"blocks_pending_connect">> => null,
        <<"last_block_received_time">> => null,
        <<"chain">> => network_name(Network),
        <<"protocol_version">> => ?PROTOCOL_VERSION
    }}.

rpc_getblockchaininfo() ->
    Network = beamchain_config:network(),
    case beamchain_chainstate:get_tip() of
        {ok, {TipHash, TipHeight}} ->
            MTP = beamchain_chainstate:get_mtp(),
            Synced = beamchain_chainstate:is_synced(),
            %% Get chainwork and timestamp from block index
            {Chainwork, BlockTime} = case beamchain_db:get_block_index(TipHeight) of
                {ok, #{chainwork := CW, header := Hdr}} ->
                    {CW, Hdr#block_header.timestamp};
                _ ->
                    {<<0:256>>, 0}
            end,
            Difficulty = tip_difficulty(),
            %% Use the shared deployment helper — same source of truth as getdeploymentinfo.
            HeightGetter = fun(H) -> beamchain_db:get_block_index(H) end,
            Softforks = build_deployment_map(Network, TipHeight, HeightGetter),
            {ok, #{
                <<"chain">> => network_name(Network),
                <<"blocks">> => TipHeight,
                <<"headers">> => TipHeight,
                <<"bestblockhash">> => hash_to_hex(TipHash),
                <<"difficulty">> => Difficulty,
                <<"time">> => BlockTime,
                <<"mediantime">> => MTP,
                <<"verificationprogress">> => case Synced of
                    true -> 1.0;
                    false -> 0.999
                end,
                <<"initialblockdownload">> => not Synced,
                <<"chainwork">> => beamchain_serialize:hex_encode(Chainwork),
                <<"pruned">> => false,
                <<"softforks">> => Softforks,
                <<"warnings">> => <<>>
            }};
        not_found ->
            {ok, #{
                <<"chain">> => network_name(Network),
                <<"blocks">> => 0,
                <<"headers">> => 0,
                <<"bestblockhash">> => <<>>,
                <<"difficulty">> => 0,
                <<"time">> => 0,
                <<"mediantime">> => 0,
                <<"verificationprogress">> => 0.0,
                <<"initialblockdownload">> => true,
                <<"chainwork">> => <<"0000000000000000000000000000000000000000000000000000000000000000">>,
                <<"pruned">> => false,
                <<"softforks">> => #{},
                <<"warnings">> => <<>>
            }}
    end.

%% getdeploymentinfo ( "blockhash" )
%%
%% Returns deployment state for all known soft forks at a given block.
%% If no blockhash is given, uses the current chain tip.
%%
%% Returns:
%%   hash         - the block hash queried
%%   height       - the block height queried
%%   deployments  - map of deployment name => deployment info
%%
%% Each deployment entry contains:
%%   type                  - "buried" | "bip9"
%%   active                - whether the deployment is active at this block
%%   height                - activation height (buried) or since (bip9)
%%   min_activation_height - minimum height for activation (bip9)
%%   For bip9 deployments, also: bit, start_time, timeout, status,
%%     count, elapsed, possible (signaling stats for current period)
%%
rpc_getdeploymentinfo([]) ->
    rpc_getdeploymentinfo_at_tip();
rpc_getdeploymentinfo([null]) ->
    rpc_getdeploymentinfo_at_tip();
rpc_getdeploymentinfo([HashHex]) when is_binary(HashHex) ->
    Hash = hex_to_internal_hash(HashHex),
    case beamchain_db:get_block_index_by_hash(Hash) of
        {ok, #{height := Height}} ->
            rpc_getdeploymentinfo_at(Hash, Height);
        not_found ->
            {error, ?RPC_INVALID_ADDRESS_OR_KEY, <<"Block not found">>}
    end;
rpc_getdeploymentinfo(_) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: getdeploymentinfo ( \"blockhash\" )">>}.

rpc_getdeploymentinfo_at_tip() ->
    case beamchain_chainstate:get_tip() of
        {ok, {TipHash, TipHeight}} ->
            rpc_getdeploymentinfo_at(TipHash, TipHeight);
        not_found ->
            %% No blocks yet — return empty deployments
            {ok, #{
                <<"hash">>        => <<"0000000000000000000000000000000000000000000000000000000000000000">>,
                <<"height">>      => 0,
                <<"deployments">> => #{}
            }}
    end.

rpc_getdeploymentinfo_at(BlockHash, Height) ->
    Network = beamchain_config:network(),
    HeightGetter = fun(H) -> beamchain_db:get_block_index(H) end,
    Deployments = build_deployment_map(Network, Height, HeightGetter),
    {ok, #{
        <<"hash">>        => hash_to_hex(BlockHash),
        <<"height">>      => Height,
        <<"deployments">> => Deployments
    }}.

%% build_deployment_map/3 — shared source of truth for ALL softfork/deployment state.
%%
%% Both getblockchaininfo (softforks field) and getdeploymentinfo (deployments field)
%% derive their data from this single function.  Neither RPC reads from a stale cache
%% or a hard-coded table; both call into beamchain_chain_params + beamchain_versionbits
%% the same way.
%%
%% Returns a map of deployment-name (binary) => deployment-info map.
%% Buried entries take precedence over BIP9 entries of the same name: once a
%% deployment is height-activated it is always-active and the activation height
%% is the authoritative record.
build_deployment_map(Network, Height, HeightGetter) ->
    Params = beamchain_chain_params:params(Network),

    %% ---- Buried deployments ----
    BuriedDefs = [
        {<<"bip34">>, bip34_height},
        {<<"bip65">>, bip65_height},
        {<<"bip66">>, bip66_height},
        {<<"csv">>,   csv_height},
        {<<"segwit">>, segwit_height},
        {<<"taproot">>, taproot_height}
    ],
    BuriedMap = lists:foldl(fun({Name, Key}, Acc) ->
        ActivationHeight = maps:get(Key, Params, 0),
        IsActive = Height >= ActivationHeight,
        maps:put(Name, #{
            <<"type">>   => <<"buried">>,
            <<"active">> => IsActive,
            <<"height">> => ActivationHeight
        }, Acc)
    end, #{}, BuriedDefs),

    %% ---- BIP9 deployments (versionbits) ----
    %% These share names with some buried deployments on mainnet (csv/segwit/taproot
    %% are buried there) but are valid BIP9 entries on testnet/signet.
    %% We merge them under the same key so caller always sees type=bip9 when the
    %% deployment comes from the versionbits state machine.
    Bip9Deployments = beamchain_versionbits:deployment_maps(Network),
    Bip9Map = lists:foldl(fun(Dep, Acc) ->
        NameAtom = maps:get(name_atom, Dep),
        Name     = maps:get(name, Dep),
        State    = beamchain_versionbits:get_deployment_state_at_height(
                       Network, NameAtom, Height, HeightGetter),
        IsActive = State =:= active,

        %% Signaling stats for the current period
        {Count, Elapsed, Possible} =
            beamchain_versionbits:get_state_statistics(
                Network, NameAtom, Height, HeightGetter),

        Entry = #{
            <<"type">>                  => <<"bip9">>,
            <<"active">>                => IsActive,
            <<"height">>                => Height,
            <<"min_activation_height">> => maps:get(min_activation_height, Dep),
            <<"bit">>                   => maps:get(bit, Dep),
            <<"start_time">>            => maps:get(start_time, Dep),
            <<"timeout">>               => maps:get(timeout, Dep),
            <<"status">>                => atom_to_binary(State, utf8),
            <<"count">>                 => Count,
            <<"elapsed">>               => Elapsed,
            <<"possible">>              => Possible
        },
        maps:put(Name, Entry, Acc)
    end, #{}, Bip9Deployments),

    %% Merge: buried entries take precedence for named deployments that are
    %% buried on this network (they are always-active and the buried record is
    %% the authoritative activation height).  BIP9 entries not also buried are
    %% kept as-is.
    maps:merge(Bip9Map, BuriedMap).

rpc_getblockhash([Height]) when is_integer(Height), Height >= 0 ->
    case beamchain_db:get_block_index(Height) of
        {ok, #{hash := Hash}} ->
            {ok, hash_to_hex(Hash)};
        not_found ->
            {error, ?RPC_INVALID_PARAMETER,
             <<"Block height out of range">>}
    end;
rpc_getblockhash(_) ->
    {error, ?RPC_INVALID_PARAMS, <<"Usage: getblockhash height">>}.

rpc_getblock([HashHex]) ->
    rpc_getblock([HashHex, 1]);
rpc_getblock([HashHex, Verbosity]) when is_binary(HashHex) ->
    Hash = hex_to_internal_hash(HashHex),
    case beamchain_db:get_block(Hash) of
        {ok, Block} ->
            case Verbosity of
                0 ->
                    %% Raw hex
                    Hex = beamchain_serialize:hex_encode(
                        beamchain_serialize:encode_block(Block)),
                    {ok, Hex};
                1 ->
                    %% JSON with txids
                    {ok, format_block_json(Block, Hash, false)};
                2 ->
                    %% JSON with decoded txs
                    {ok, format_block_json(Block, Hash, true)};
                _ ->
                    {error, ?RPC_INVALID_PARAMETER,
                     <<"Invalid verbosity value">>}
            end;
        not_found ->
            {error, ?RPC_INVALID_ADDRESS_OR_KEY, <<"Block not found">>}
    end;
rpc_getblock(_) ->
    {error, ?RPC_INVALID_PARAMS, <<"Usage: getblock \"hash\" ( verbosity )">>}.

rpc_getblockheader([HashHex]) ->
    rpc_getblockheader([HashHex, true]);
rpc_getblockheader([HashHex, Verbose]) when is_binary(HashHex) ->
    Hash = hex_to_internal_hash(HashHex),
    case beamchain_db:get_block_index_by_hash(Hash) of
        {ok, #{height := Height, header := Header, chainwork := Chainwork, n_tx := NTx}} ->
            case Verbose of
                false ->
                    Hex = beamchain_serialize:hex_encode(
                        beamchain_serialize:encode_block_header(Header)),
                    {ok, Hex};
                _ ->
                    %% Get next block hash if it exists
                    NextHash = case beamchain_db:get_block_index(Height + 1) of
                        {ok, #{hash := NH}} -> hash_to_hex(NH);
                        not_found -> null
                    end,
                    Bits = Header#block_header.bits,
                    {ok, #{
                        <<"hash">> => hash_to_hex(Hash),
                        <<"confirmations">> => confirmations(Height),
                        <<"height">> => Height,
                        <<"version">> => Header#block_header.version,
                        <<"versionHex">> => beamchain_serialize:hex_encode(
                            <<(Header#block_header.version):32/big>>),
                        <<"merkleroot">> => hash_to_hex(
                            Header#block_header.merkle_root),
                        <<"time">> => Header#block_header.timestamp,
                        <<"mediantime">> => block_mtp(Height),
                        <<"nonce">> => Header#block_header.nonce,
                        <<"bits">> => beamchain_serialize:hex_encode(
                            <<Bits:32/big>>),
                        <<"difficulty">> => bits_to_difficulty(Bits),
                        <<"chainwork">> => beamchain_serialize:hex_encode(
                            Chainwork),
                        <<"nTx">> => NTx,
                        <<"previousblockhash">> => hash_to_hex(
                            Header#block_header.prev_hash),
                        <<"nextblockhash">> => NextHash
                    }}
            end;
        {ok, IndexInfo} ->
            %% Fallback for old format without n_tx in index, count from block
            case Verbose of
                false ->
                    Hex = beamchain_serialize:hex_encode(
                        beamchain_serialize:encode_block_header(maps:get(header, IndexInfo))),
                    {ok, Hex};
                _ ->
                    Header = maps:get(header, IndexInfo),
                    Chainwork = maps:get(chainwork, IndexInfo),
                    Height = maps:get(height, IndexInfo),
                    %% Get next block hash if it exists
                    NextHash = case beamchain_db:get_block_index(Height + 1) of
                        {ok, #{hash := NH}} -> hash_to_hex(NH);
                        not_found -> null
                    end,
                    Bits = Header#block_header.bits,
                    {ok, #{
                        <<"hash">> => hash_to_hex(Hash),
                        <<"confirmations">> => confirmations(Height),
                        <<"height">> => Height,
                        <<"version">> => Header#block_header.version,
                        <<"versionHex">> => beamchain_serialize:hex_encode(
                            <<(Header#block_header.version):32/big>>),
                        <<"merkleroot">> => hash_to_hex(
                            Header#block_header.merkle_root),
                        <<"time">> => Header#block_header.timestamp,
                        <<"mediantime">> => block_mtp(Height),
                        <<"nonce">> => Header#block_header.nonce,
                        <<"bits">> => beamchain_serialize:hex_encode(
                            <<Bits:32/big>>),
                        <<"difficulty">> => bits_to_difficulty(Bits),
                        <<"chainwork">> => beamchain_serialize:hex_encode(
                            Chainwork),
                        <<"nTx">> => count_block_txs(Hash),
                        <<"previousblockhash">> => hash_to_hex(
                            Header#block_header.prev_hash),
                        <<"nextblockhash">> => NextHash
                    }}
            end;
        not_found ->
            {error, ?RPC_INVALID_ADDRESS_OR_KEY, <<"Block not found">>}
    end;
rpc_getblockheader(_) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: getblockheader \"hash\" ( verbose )">>}.

rpc_getdifficulty() ->
    {ok, tip_difficulty()}.

rpc_getchaintips() ->
    %% We only track the active chain, so return one tip
    case beamchain_chainstate:get_tip() of
        {ok, {Hash, Height}} ->
            {ok, [#{
                <<"height">> => Height,
                <<"hash">> => hash_to_hex(Hash),
                <<"branchlen">> => 0,
                <<"status">> => <<"active">>
            }]};
        not_found ->
            {ok, []}
    end.

rpc_verifychain() ->
    %% Simplified: return true if we have a chain tip
    case beamchain_chainstate:get_tip() of
        {ok, _} -> {ok, true};
        not_found -> {ok, true}
    end.

%% @doc flushchainstate — synchronously flush the in-memory UTXO cache
%% to RocksDB and return the tip height and hash that are now durably
%% persisted.  Useful as a pre-shutdown checkpoint or before taking a
%% snapshot of the data directory.
rpc_flushchainstate() ->
    ok = beamchain_chainstate:flush(),
    case beamchain_chainstate:get_tip() of
        {ok, {TipHash, TipHeight}} ->
            {ok, #{
                <<"flushed">> => true,
                <<"height">> => TipHeight,
                <<"hash">>   => hash_to_hex(TipHash)
            }};
        not_found ->
            {ok, #{
                <<"flushed">> => true,
                <<"height">> => 0,
                <<"hash">>   => <<"0000000000000000000000000000000000000000000000000000000000000000">>
            }}
    end.

%% @doc scrubunspendable — one-shot scrub of orphan unspendable coins.
%%
%% Walks the chainstate column family on disk and removes any UTXO whose
%% scriptPubKey is unspendable per Core's CScript::IsUnspendable() —
%% scripts beginning with OP_RETURN (0x6a) or larger than MAX_SCRIPT_SIZE
%% (10000). These coins should never have entered the UTXO set; the
%% IsUnspendable filter at AddCoin time was added in beamchain commit
%% 79fa3e5, but datadirs that ingested blocks before that commit still
%% carry orphan SegWit-witness-commitment outputs in the chainstate CF.
%%
%% First flushes the in-memory UTXO cache so we operate on the
%% authoritative on-disk view, then iterates and deletes via batched
%% RocksDB writes. Idempotent — a second call finds zero entries because
%% AddCoin now rejects them at write time.
%%
%% Returns {"removed": N, "bytes_freed": X} where bytes_freed is the
%% summed key+value byte count of removed entries (raw, pre-compaction).
rpc_scrubunspendable() ->
    %% Flush so the on-disk CF reflects all dirty in-memory entries — the
    %% cache may hold spent or fresh coins that the iterator would
    %% otherwise miss or re-process.
    ok = beamchain_chainstate:flush(),
    {Removed, BytesFreed} = beamchain_db:scrub_unspendable(),
    {ok, #{
        <<"removed">>     => Removed,
        <<"bytes_freed">> => BytesFreed
    }}.

%% @doc invalidateblock - mark a block and all its descendants as invalid
%% If the block is on the active chain, rewinds to just before it and switches
%% to the next-best valid chain.
rpc_invalidateblock([HashHex]) when is_binary(HashHex) ->
    try
        Hash = hex_to_internal_hash(HashHex),
        case beamchain_chainstate:invalidate_block(Hash) of
            ok ->
                {ok, null};
            {error, cannot_invalidate_genesis} ->
                {error, ?RPC_INVALID_PARAMETER,
                 <<"Cannot invalidate genesis block">>};
            {error, block_not_found} ->
                {error, ?RPC_INVALID_ADDRESS_OR_KEY,
                 <<"Block not found">>};
            {error, Reason} ->
                {error, ?RPC_DATABASE_ERROR,
                 iolist_to_binary(io_lib:format("Failed to invalidate block: ~p", [Reason]))}
        end
    catch
        _:_ ->
            {error, ?RPC_INVALID_ADDRESS_OR_KEY,
             <<"Invalid block hash">>}
    end;
rpc_invalidateblock(_) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: invalidateblock \"blockhash\"">>}.

%% @doc reconsiderblock - remove invalid status from a block and its descendants
%% Clears the invalid flag and switches to the reconsidered chain if it has more work.
rpc_reconsiderblock([HashHex]) when is_binary(HashHex) ->
    try
        Hash = hex_to_internal_hash(HashHex),
        case beamchain_chainstate:reconsider_block(Hash) of
            ok ->
                {ok, null};
            {error, block_not_found} ->
                {error, ?RPC_INVALID_ADDRESS_OR_KEY,
                 <<"Block not found">>};
            {error, Reason} ->
                {error, ?RPC_DATABASE_ERROR,
                 iolist_to_binary(io_lib:format("Failed to reconsider block: ~p", [Reason]))}
        end
    catch
        _:_ ->
            {error, ?RPC_INVALID_ADDRESS_OR_KEY,
             <<"Invalid block hash">>}
    end;
rpc_reconsiderblock(_) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: reconsiderblock \"blockhash\"">>}.

%% @doc getblockstats - compute per-block statistics
rpc_getblockstats([HashOrHeight]) ->
    rpc_getblockstats([HashOrHeight, []]);
rpc_getblockstats([HashOrHeight, Stats]) when is_list(Stats) ->
    case resolve_block_hash_or_height(HashOrHeight) of
        {ok, Hash, Height} ->
            calculate_and_format_blockstats(Hash, Height, Stats);
        {error, Code, Msg} ->
            {error, Code, Msg}
    end;
rpc_getblockstats(_) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: getblockstats \"hash_or_height\" ( stats )">>}.

%% @doc getchaintxstats - compute chain transaction statistics
rpc_getchaintxstats([]) ->
    %% Default: ~1 month (4320 blocks at 10 min/block for mainnet)
    DefaultBlocks = 4320,
    case beamchain_chainstate:get_tip() of
        {ok, {Hash, Height}} ->
            NBlocks = min(DefaultBlocks, Height),
            calculate_and_format_chaintxstats(Hash, Height, NBlocks);
        not_found ->
            {error, ?RPC_MISC_ERROR, <<"Chain not found">>}
    end;
rpc_getchaintxstats([NBlocks]) when is_integer(NBlocks) ->
    case beamchain_chainstate:get_tip() of
        {ok, {Hash, Height}} ->
            calculate_and_format_chaintxstats(Hash, Height, NBlocks);
        not_found ->
            {error, ?RPC_MISC_ERROR, <<"Chain not found">>}
    end;
rpc_getchaintxstats([NBlocks, BlockHashHex]) when is_integer(NBlocks), is_binary(BlockHashHex) ->
    BlockHash = hex_to_internal_hash(BlockHashHex),
    case beamchain_db:get_block_index_by_hash(BlockHash) of
        {ok, #{height := Height}} ->
            %% Verify block is in active chain
            case is_block_in_active_chain(BlockHash) of
                true ->
                    calculate_and_format_chaintxstats(BlockHash, Height, NBlocks);
                false ->
                    {error, ?RPC_INVALID_PARAMETER, <<"Block is not in main chain">>}
            end;
        not_found ->
            {error, ?RPC_INVALID_ADDRESS_OR_KEY, <<"Block not found">>}
    end;
rpc_getchaintxstats(_) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: getchaintxstats ( nblocks \"blockhash\" )">>}.

%% Helper: resolve hash or height to {ok, Hash, Height} or {error, ...}
resolve_block_hash_or_height(Height) when is_integer(Height), Height >= 0 ->
    case beamchain_db:get_block_index(Height) of
        {ok, #{hash := Hash}} ->
            {ok, Hash, Height};
        not_found ->
            {error, ?RPC_INVALID_PARAMETER, <<"Block height out of range">>}
    end;
resolve_block_hash_or_height(HashHex) when is_binary(HashHex) ->
    Hash = hex_to_internal_hash(HashHex),
    case beamchain_db:get_block_index_by_hash(Hash) of
        {ok, #{height := Height}} ->
            {ok, Hash, Height};
        not_found ->
            {error, ?RPC_INVALID_ADDRESS_OR_KEY, <<"Block not found">>}
    end;
resolve_block_hash_or_height(_) ->
    {error, ?RPC_INVALID_PARAMETER, <<"Invalid hash or height">>}.

%% Calculate and format block statistics
calculate_and_format_blockstats(Hash, Height, RequestedStats) ->
    %% Check if we have cached stats
    case beamchain_db:get_block_stats(Hash) of
        {ok, CachedStats} ->
            filter_stats(CachedStats, RequestedStats, Hash, Height);
        not_found ->
            %% Need to compute stats from block data
            case beamchain_db:get_block(Hash) of
                {ok, Block} ->
                    Stats = compute_block_stats(Block, Height),
                    %% Cache for future queries
                    beamchain_db:store_block_stats(Hash, Stats),
                    filter_stats(Stats, RequestedStats, Hash, Height);
                not_found ->
                    {error, ?RPC_MISC_ERROR, <<"Block data not found (pruned?)">>}
            end
    end.

%% Filter stats to only include requested fields
filter_stats(AllStats, [], Hash, Height) ->
    %% Return all stats if none specifically requested
    Result = AllStats#{
        <<"blockhash">> => hash_to_hex(Hash),
        <<"height">> => Height,
        <<"mediantime">> => block_mtp(Height)
    },
    {ok, Result};
filter_stats(AllStats, RequestedStats, Hash, Height) ->
    %% Only return requested stats
    RequestedBins = [to_bin(S) || S <- RequestedStats],
    AllStatsWithMeta = AllStats#{
        <<"blockhash">> => hash_to_hex(Hash),
        <<"height">> => Height,
        <<"mediantime">> => block_mtp(Height)
    },
    Result = maps:filter(fun(K, _V) ->
        lists:member(K, RequestedBins)
    end, AllStatsWithMeta),
    case maps:size(Result) of
        0 ->
            %% No valid stats requested
            {error, ?RPC_INVALID_PARAMETER, <<"Invalid selected statistics">>};
        _ ->
            {ok, Result}
    end.

%% Compute block statistics from block data
compute_block_stats(#block{transactions = Txs, header = Header}, Height) ->
    %% Initialize accumulators
    InitAcc = #{
        txs => length(Txs),
        inputs => 0,
        outputs => 0,
        total_size => 0,
        total_weight => 0,
        total_out => 0,
        totalfee => 0,
        swtxs => 0,
        swtotal_size => 0,
        swtotal_weight => 0,
        fees => [],
        feerates => [],
        txsizes => []
    },

    %% Process each transaction
    {_Idx, FinalAcc} = lists:foldl(fun(Tx, {Idx, Acc}) ->
        {Idx + 1, process_tx_for_stats(Tx, Idx, Acc)}
    end, {0, InitAcc}, Txs),

    %% Calculate derived statistics
    #{txs := TxCount, inputs := Ins, outputs := Outs,
      total_size := TotalSize, total_weight := TotalWeight,
      total_out := TotalOut, totalfee := TotalFee,
      swtxs := SwTxs, swtotal_size := SwTotalSize, swtotal_weight := SwTotalWeight,
      fees := Fees, feerates := FeeRates, txsizes := TxSizes} = FinalAcc,

    %% Non-coinbase tx count for averages
    NonCoinbaseCount = max(1, TxCount - 1),

    %% Compute median values
    MedianFee = truncated_median(Fees),
    MedianTxSize = truncated_median(TxSizes),

    %% Compute fee rate percentiles (weighted by transaction weight)
    FeeRatePercentiles = calculate_feerate_percentiles(FeeRates, TotalWeight),

    %% Min/max values
    {MinFee, MaxFee} = case Fees of
        [] -> {0, 0};
        _ -> {lists:min(Fees), lists:max(Fees)}
    end,
    {MinFeeRate, MaxFeeRate} = case FeeRates of
        [] -> {0, 0};
        _ ->
            FeeRatesOnly = [F || {F, _W} <- FeeRates],
            {lists:min(FeeRatesOnly), lists:max(FeeRatesOnly)}
    end,
    {MinTxSize, MaxTxSize} = case TxSizes of
        [] -> {0, 0};
        _ -> {lists:min(TxSizes), lists:max(TxSizes)}
    end,

    %% Block subsidy
    Subsidy = block_subsidy(Height),

    #{
        <<"avgfee">> => TotalFee div NonCoinbaseCount,
        <<"avgfeerate">> => avg_feerate(TotalFee, TotalWeight),
        <<"avgtxsize">> => TotalSize div NonCoinbaseCount,
        <<"feerate_percentiles">> => FeeRatePercentiles,
        <<"ins">> => Ins,
        <<"maxfee">> => MaxFee,
        <<"maxfeerate">> => MaxFeeRate,
        <<"maxtxsize">> => MaxTxSize,
        <<"medianfee">> => MedianFee,
        <<"mediantxsize">> => MedianTxSize,
        <<"minfee">> => MinFee,
        <<"minfeerate">> => MinFeeRate,
        <<"mintxsize">> => MinTxSize,
        <<"outs">> => Outs,
        <<"subsidy">> => Subsidy,
        <<"swtotal_size">> => SwTotalSize,
        <<"swtotal_weight">> => SwTotalWeight,
        <<"swtxs">> => SwTxs,
        <<"time">> => Header#block_header.timestamp,
        <<"total_out">> => TotalOut,
        <<"total_size">> => TotalSize,
        <<"total_weight">> => TotalWeight,
        <<"totalfee">> => TotalFee,
        <<"txs">> => TxCount,
        <<"utxo_increase">> => Outs - Ins,
        <<"utxo_size_inc">> => 0  %% Simplified: would need actual UTXO size tracking
    }.

%% Process a single transaction for statistics accumulation
process_tx_for_stats(Tx, Idx, Acc) ->
    #transaction{inputs = Inputs, outputs = Outputs} = Tx,

    OutputCount = length(Outputs),
    TxWeight = beamchain_serialize:tx_weight(Tx),
    TxSize = beamchain_serialize:tx_size(Tx),
    TotalOut = lists:sum([V || #tx_out{value = V} <- Outputs]),
    HasWitness = tx_has_witness(Tx),

    %% Update outputs count
    Acc2 = Acc#{outputs => maps:get(outputs, Acc) + OutputCount},

    %% Skip coinbase for most stats (Idx == 0 is coinbase)
    case Idx of
        0 ->
            %% Coinbase: only count outputs
            Acc2;
        _ ->
            InputCount = length(Inputs),

            %% Calculate fee by looking up input values
            InputTotal = sum_input_values(Inputs),
            Fee = max(0, InputTotal - TotalOut),

            %% Fee rate in satoshis per virtual byte
            FeeRate = case TxWeight of
                0 -> 0;
                _ -> (Fee * 4) div TxWeight  %% sat/vB = (fee * 4) / weight
            end,

            %% Update accumulators
            Acc3 = Acc2#{
                inputs => maps:get(inputs, Acc2) + InputCount,
                total_size => maps:get(total_size, Acc2) + TxSize,
                total_weight => maps:get(total_weight, Acc2) + TxWeight,
                total_out => maps:get(total_out, Acc2) + TotalOut,
                totalfee => maps:get(totalfee, Acc2) + Fee,
                fees => [Fee | maps:get(fees, Acc2)],
                feerates => [{FeeRate, TxWeight} | maps:get(feerates, Acc2)],
                txsizes => [TxSize | maps:get(txsizes, Acc2)]
            },

            %% SegWit stats
            case HasWitness of
                true ->
                    Acc3#{
                        swtxs => maps:get(swtxs, Acc3) + 1,
                        swtotal_size => maps:get(swtotal_size, Acc3) + TxSize,
                        swtotal_weight => maps:get(swtotal_weight, Acc3) + TxWeight
                    };
                false ->
                    Acc3
            end
    end.

%% Check if transaction has witness data
tx_has_witness(#transaction{inputs = Inputs}) ->
    lists:any(fun(#tx_in{witness = W}) ->
        W =/= [] andalso W =/= undefined
    end, Inputs).

%% Sum input values (lookup UTXOs)
sum_input_values(Inputs) ->
    lists:foldl(fun(#tx_in{prev_out = #outpoint{hash = H, index = I}}, Acc) ->
        case beamchain_chainstate:get_utxo(H, I) of
            {ok, #utxo{value = V}} -> Acc + V;
            not_found ->
                %% May be in mempool or missing
                case beamchain_mempool:get_mempool_utxo(H, I) of
                    {ok, #utxo{value = V}} -> Acc + V;
                    not_found -> Acc
                end
        end
    end, 0, Inputs).

%% Calculate truncated median (Bitcoin Core style)
truncated_median([]) -> 0;
truncated_median(Values) ->
    Sorted = lists:sort(Values),
    Size = length(Sorted),
    case Size rem 2 of
        0 ->
            %% Even: average of two middle values (truncated)
            Mid = Size div 2,
            (lists:nth(Mid, Sorted) + lists:nth(Mid + 1, Sorted)) div 2;
        1 ->
            %% Odd: middle value
            lists:nth((Size div 2) + 1, Sorted)
    end.

%% Calculate average fee rate (sat/vB)
avg_feerate(_, 0) -> 0;
avg_feerate(TotalFee, TotalWeight) ->
    (TotalFee * 4) div TotalWeight.

%% Calculate fee rate percentiles weighted by transaction weight
%% Returns [10th, 25th, 50th, 75th, 90th] percentiles
calculate_feerate_percentiles([], _TotalWeight) ->
    [0, 0, 0, 0, 0];
calculate_feerate_percentiles(_FeeRates, TotalWeight) when TotalWeight =< 0 ->
    [0, 0, 0, 0, 0];
calculate_feerate_percentiles(FeeRates, TotalWeight) ->
    %% Sort by fee rate
    Sorted = lists:sort(fun({A, _}, {B, _}) -> A =< B end, FeeRates),

    %% Target weights for percentiles
    Targets = [
        TotalWeight / 10,        %% 10th
        TotalWeight / 4,         %% 25th
        TotalWeight / 2,         %% 50th
        TotalWeight * 3 / 4,     %% 75th
        TotalWeight * 9 / 10     %% 90th
    ],

    calculate_percentiles_helper(Sorted, Targets, 0, []).

calculate_percentiles_helper(_Sorted, [], _CumWeight, Acc) ->
    lists:reverse(Acc);
calculate_percentiles_helper([], [_|RestTargets], _CumWeight, Acc) ->
    %% Fill remaining with last value or 0
    LastVal = case Acc of [] -> 0; [V|_] -> V end,
    calculate_percentiles_helper([], RestTargets, 0, [LastVal | Acc]);
calculate_percentiles_helper([{FeeRate, Weight} | RestRates], [Target | RestTargets] = Targets,
                             CumWeight, Acc) ->
    NewCumWeight = CumWeight + Weight,
    case NewCumWeight >= Target of
        true ->
            %% This fee rate covers this percentile
            calculate_percentiles_helper([{FeeRate, Weight} | RestRates], RestTargets,
                                          CumWeight, [FeeRate | Acc]);
        false ->
            %% Need more weight
            calculate_percentiles_helper(RestRates, Targets, NewCumWeight, Acc)
    end.

%% Calculate block subsidy
block_subsidy(Height) ->
    Params = beamchain_config:network_params(),
    HalvingInterval = Params#network_params.subsidy_halving,
    Halvings = Height div HalvingInterval,
    case Halvings >= 64 of
        true -> 0;
        false -> (50 * 100000000) bsr Halvings  %% 50 BTC in satoshis
    end.

%% Calculate and format chain transaction statistics
calculate_and_format_chaintxstats(BlockHash, Height, NBlocks) ->
    %% Validate nblocks
    case NBlocks < 0 orelse (NBlocks > 0 andalso NBlocks >= Height) of
        true ->
            {error, ?RPC_INVALID_PARAMETER,
             <<"Invalid block count: should be between 0 and the block's height - 1">>};
        false ->
            %% Get block header for timestamp
            case beamchain_db:get_block_index_by_hash(BlockHash) of
                {ok, #{header := Header}} ->
                    %% Get window start block
                    StartHeight = Height - NBlocks,
                    case beamchain_db:get_block_index(StartHeight) of
                        {ok, #{header := StartHeader}} ->
                            format_chaintxstats(BlockHash, Height, Header,
                                                StartHeight, StartHeader, NBlocks);
                        not_found ->
                            {error, ?RPC_MISC_ERROR, <<"Start block not found">>}
                    end;
                not_found ->
                    {error, ?RPC_MISC_ERROR, <<"Block not found">>}
            end
    end.

format_chaintxstats(BlockHash, Height, Header, StartHeight, _StartHeader, NBlocks) ->
    %% Use median time past for time calculations
    EndMTP = block_mtp(Height),
    StartMTP = block_mtp(StartHeight),
    TimeDiff = EndMTP - StartMTP,

    %% Get cumulative tx counts if available
    TxCount = get_cumulative_txcount_for_height(Height),
    StartTxCount = get_cumulative_txcount_for_height(StartHeight),

    Result = #{
        <<"time">> => Header#block_header.timestamp,
        <<"window_final_block_hash">> => hash_to_hex(BlockHash),
        <<"window_final_block_height">> => Height,
        <<"window_block_count">> => NBlocks
    },

    %% Add txcount if known
    Result2 = case TxCount of
        undefined -> Result;
        _ -> Result#{<<"txcount">> => TxCount}
    end,

    %% Add window stats if nblocks > 0
    Result3 = case NBlocks > 0 of
        true ->
            R = Result2#{<<"window_interval">> => TimeDiff},
            case {TxCount, StartTxCount} of
                {undefined, _} -> R;
                {_, undefined} -> R;
                {End, Start} when End > 0, Start >= 0 ->
                    WindowTxCount = End - Start,
                    R2 = R#{<<"window_tx_count">> => WindowTxCount},
                    case TimeDiff > 0 of
                        true ->
                            TxRate = WindowTxCount / TimeDiff,
                            R2#{<<"txrate">> => TxRate};
                        false ->
                            R2
                    end;
                _ -> R
            end;
        false ->
            Result2
    end,

    {ok, Result3}.

%% Get cumulative tx count for a height (estimate if not stored)
get_cumulative_txcount_for_height(Height) ->
    case beamchain_db:get_cumulative_tx_count(Height) of
        {ok, Count} ->
            Count;
        not_found ->
            %% Estimate by counting tx in blocks (expensive, so only do for recent blocks)
            estimate_cumulative_txcount(Height)
    end.

%% Estimate cumulative tx count by counting backwards
estimate_cumulative_txcount(Height) when Height =< 0 ->
    0;
estimate_cumulative_txcount(_Height) ->
    %% For now, return undefined if not stored
    %% A full implementation would scan blocks and cache results
    undefined.

%%% ===================================================================
%%% Transaction methods
%%% ===================================================================

rpc_getrawtransaction([TxidHex]) ->
    rpc_getrawtransaction([TxidHex, 0, null]);
rpc_getrawtransaction([TxidHex, Verbose]) ->
    rpc_getrawtransaction([TxidHex, Verbose, null]);
rpc_getrawtransaction([TxidHex, Verbose, BlockHashParam]) when is_binary(TxidHex) ->
    Txid = hex_to_internal_hash(TxidHex),
    %% Parse verbosity: 0/false = hex, 1/true = JSON, 2 = JSON with prevout (not yet supported)
    Verbosity = parse_verbosity(Verbose),

    %% Handle optional blockhash parameter
    case BlockHashParam of
        null ->
            %% No blockhash provided - search mempool then txindex
            find_and_format_tx(Txid, Verbosity, undefined);
        BlockHashHex when is_binary(BlockHashHex) ->
            %% Blockhash provided - only search that specific block
            BlockHash = hex_to_internal_hash(BlockHashHex),
            case beamchain_db:get_block(BlockHash) of
                {ok, Block} ->
                    find_tx_in_block_and_format(Txid, Block, BlockHash, Verbosity);
                not_found ->
                    {error, ?RPC_INVALID_ADDRESS_OR_KEY, <<"Block hash not found">>}
            end;
        _ ->
            {error, ?RPC_INVALID_PARAMS, <<"Invalid blockhash parameter">>}
    end;
rpc_getrawtransaction(_) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: getrawtransaction \"txid\" ( verbose \"blockhash\" )">>}.

%% Parse verbosity parameter (0/false = hex, 1/true = JSON, 2 = JSON with prevout)
parse_verbosity(0) -> 0;
parse_verbosity(1) -> 1;
parse_verbosity(2) -> 2;
parse_verbosity(false) -> 0;
parse_verbosity(true) -> 1;
parse_verbosity(V) when is_integer(V), V >= 0 -> min(V, 2);
parse_verbosity(_) -> 0.

%% Find transaction and format according to verbosity
find_and_format_tx(Txid, Verbosity, ProvidedBlockHash) ->
    case find_transaction(Txid) of
        {ok, Tx, BlockHash, Height, _Pos} ->
            format_getrawtransaction_result(Tx, BlockHash, Height, Verbosity,
                                             ProvidedBlockHash =/= undefined);
        not_found ->
            %% Generate appropriate error message based on txindex status
            TxIndexEnabled = beamchain_config:txindex_enabled(),
            ErrMsg = case TxIndexEnabled of
                true ->
                    <<"No such mempool or blockchain transaction. Use gettransaction for wallet transactions.">>;
                false ->
                    <<"No such mempool transaction. Use -txindex or provide a block hash to enable blockchain transaction queries. Use gettransaction for wallet transactions.">>
            end,
            {error, ?RPC_INVALID_ADDRESS_OR_KEY, ErrMsg}
    end.

%% Find a transaction in a specific block and format result
find_tx_in_block_and_format(Txid, #block{transactions = Txs},
                             BlockHash, Verbosity) ->
    Height = case beamchain_db:get_block_index_by_hash(BlockHash) of
        {ok, #{height := H}} -> H;
        _ -> -1
    end,
    case find_tx_in_list(Txid, Txs, 0) of
        {ok, Tx, _Pos} ->
            %% Check if block is in active chain
            InActiveChain = is_block_in_active_chain(BlockHash),
            format_getrawtransaction_result(Tx, BlockHash, Height, Verbosity,
                                             true, InActiveChain);
        not_found ->
            {error, ?RPC_INVALID_ADDRESS_OR_KEY,
             <<"No such transaction found in the provided block">>}
    end.

%% Find transaction in a list by txid
find_tx_in_list(_Txid, [], _Pos) -> not_found;
find_tx_in_list(Txid, [Tx | Rest], Pos) ->
    case beamchain_serialize:tx_hash(Tx) of
        Txid -> {ok, Tx, Pos};
        _ -> find_tx_in_list(Txid, Rest, Pos + 1)
    end.

%% Check if a block hash is in the active chain
is_block_in_active_chain(BlockHash) ->
    case beamchain_db:get_block_index_by_hash(BlockHash) of
        {ok, #{height := Height}} ->
            %% Verify the block at this height has the same hash
            case beamchain_db:get_block_index(Height) of
                {ok, #{hash := Hash}} -> Hash =:= BlockHash;
                _ -> false
            end;
        _ -> false
    end.

%% Format getrawtransaction result based on verbosity
format_getrawtransaction_result(Tx, BlockHash, Height, Verbosity, BlockHashProvided) ->
    format_getrawtransaction_result(Tx, BlockHash, Height, Verbosity,
                                     BlockHashProvided, true).

format_getrawtransaction_result(Tx, _BlockHash, _Height, 0, _BlockHashProvided,
                                 _InActiveChain) ->
    %% Verbosity 0: return raw hex
    Hex = beamchain_serialize:hex_encode(
        beamchain_serialize:encode_transaction(Tx)),
    {ok, Hex};
format_getrawtransaction_result(Tx, BlockHash, Height, Verbosity, BlockHashProvided,
                                 InActiveChain) when Verbosity >= 1 ->
    %% Verbosity 1+: return JSON object
    TxJson = format_tx_json(Tx),
    TxJson2 = case BlockHash of
        undefined ->
            TxJson;
        _ ->
            BlockTime = block_time(Height),
            TxJson#{
                <<"blockhash">> => hash_to_hex(BlockHash),
                <<"confirmations">> => confirmations(Height),
                <<"time">> => BlockTime,
                <<"blocktime">> => BlockTime
            }
    end,
    %% Add in_active_chain only when blockhash was explicitly provided
    TxJson3 = case BlockHashProvided of
        true when BlockHash =/= undefined ->
            TxJson2#{<<"in_active_chain">> => InActiveChain};
        _ ->
            TxJson2
    end,
    {ok, TxJson3}.

rpc_decoderawtransaction([HexStr]) when is_binary(HexStr) ->
    try
        Bin = beamchain_serialize:hex_decode(HexStr),
        {Tx, _Rest} = beamchain_serialize:decode_transaction(Bin),
        {ok, format_tx_json(Tx)}
    catch
        _:_ ->
            {error, ?RPC_DESERIALIZATION_ERROR,
             <<"TX decode failed">>}
    end;
rpc_decoderawtransaction(_) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: decoderawtransaction \"hexstring\"">>}.

%% Default max fee rate: 0.10 BTC/kvB = 10,000,000 sat/kvB
-define(DEFAULT_MAX_RAW_TX_FEE_RATE, 10000000).

rpc_sendrawtransaction([HexStr]) when is_binary(HexStr) ->
    rpc_sendrawtransaction([HexStr, ?DEFAULT_MAX_RAW_TX_FEE_RATE / 100000000.0]);
rpc_sendrawtransaction([HexStr, MaxFeeRateBtcKvB]) when is_binary(HexStr) ->
    %% MaxFeeRateBtcKvB is in BTC/kvB; convert to sat/vB for comparison
    MaxFeeRateSatVB = case MaxFeeRateBtcKvB of
        N when is_number(N) -> N * 100000000.0 / 1000.0;  %% BTC/kvB to sat/vB
        _ -> ?DEFAULT_MAX_RAW_TX_FEE_RATE / 1000.0
    end,
    try
        Bin = beamchain_serialize:hex_decode(HexStr),
        {Tx, _} = beamchain_serialize:decode_transaction(Bin),
        Txid = beamchain_serialize:tx_hash(Tx),

        %% Check if already in mempool
        case beamchain_mempool:has_tx(Txid) of
            true ->
                throw({already_in_mempool, Txid});
            false ->
                ok
        end,

        %% Check if already in blockchain
        case beamchain_db:get_tx_location(Txid) of
            {ok, _} ->
                throw({already_in_chain, Txid});
            not_found ->
                ok
        end,

        %% Check max fee rate if non-zero (anti-fat-finger protection)
        case MaxFeeRateSatVB > 0 of
            true ->
                check_max_fee_rate(Tx, MaxFeeRateSatVB);
            false ->
                ok
        end,

        case beamchain_mempool:accept_to_memory_pool(Tx) of
            {ok, AcceptedTxid} ->
                %% Broadcast to all connected peers via inv message
                relay_transaction(AcceptedTxid),
                {ok, hash_to_hex(AcceptedTxid)};
            {error, Reason} ->
                format_mempool_error(Reason, Txid)
        end
    catch
        throw:{already_in_mempool, _} ->
            {error, ?RPC_VERIFY_ALREADY_IN_CHAIN,
             <<"Transaction already in mempool">>};
        throw:{already_in_chain, _} ->
            {error, ?RPC_VERIFY_ALREADY_IN_CHAIN,
             <<"Transaction already in block chain">>};
        throw:{max_fee_exceeded, FeeRate} ->
            {error, ?RPC_VERIFY_REJECTED,
             iolist_to_binary(io_lib:format(
                 "Fee rate (~.2f sat/vB) exceeds maximum (~.2f sat/vB)",
                 [FeeRate, MaxFeeRateSatVB]))};
        throw:{missing_inputs, _} ->
            {error, ?RPC_VERIFY_ERROR,
             <<"Missing inputs">>};
        _:_ ->
            {error, ?RPC_DESERIALIZATION_ERROR,
             <<"TX decode failed. Make sure the tx has at least one input.">>}
    end;
rpc_sendrawtransaction(_) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: sendrawtransaction \"hexstring\" ( maxfeerate )">>}.

%% @doc createrawtransaction: Create a raw transaction from inputs and outputs.
%% Returns hex-encoded unsigned transaction.
rpc_createrawtransaction([Inputs, Outputs]) when is_list(Inputs), is_list(Outputs) ->
    rpc_createrawtransaction([Inputs, Outputs, 0, false]);
rpc_createrawtransaction([Inputs, Outputs, Locktime]) when is_list(Inputs), is_list(Outputs) ->
    rpc_createrawtransaction([Inputs, Outputs, Locktime, false]);
rpc_createrawtransaction([Inputs, Outputs, Locktime, Replaceable])
  when is_list(Inputs), is_list(Outputs) ->
    try
        %% Parse inputs
        TxInputs = lists:map(fun(#{<<"txid">> := TxidHex, <<"vout">> := Vout} = InMap) ->
            Txid = hex_to_internal_hash(TxidHex),
            Sequence = case maps:get(<<"sequence">>, InMap, undefined) of
                undefined ->
                    case Replaceable of
                        true -> 16#FFFFFFFD;  %% BIP125 replaceable
                        _ -> 16#FFFFFFFF
                    end;
                Seq -> Seq
            end,
            #tx_in{prev_out = #outpoint{hash = Txid, index = Vout},
                   script_sig = <<>>,
                   sequence = Sequence,
                   witness = []}
        end, Inputs),
        %% Parse outputs (list of maps, each with address:amount or data:hex)
        TxOutputs = lists:flatmap(fun(OutMap) ->
            maps:fold(fun
                (<<"data">>, HexData, Acc) ->
                    Script = <<16#6a, (beamchain_serialize:hex_decode(HexData))/binary>>,
                    [#tx_out{value = 0, script_pubkey = Script} | Acc];
                (Address, Amount, Acc) ->
                    Satoshis = btc_to_satoshi(Amount),
                    {ok, Script} = beamchain_address:address_to_script(
                        binary_to_list(Address), beamchain_config:network()),
                    [#tx_out{value = Satoshis, script_pubkey = Script} | Acc]
            end, [], OutMap)
        end, Outputs),
        Tx = #transaction{
            version = 2,
            inputs = TxInputs,
            outputs = TxOutputs,
            locktime = Locktime
        },
        HexTx = beamchain_serialize:hex_encode(beamchain_serialize:encode_transaction(Tx)),
        {ok, HexTx}
    catch
        _:Err ->
            {error, ?RPC_MISC_ERROR,
             iolist_to_binary(io_lib:format("Error: ~p", [Err]))}
    end;
rpc_createrawtransaction(_) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: createrawtransaction [{\"txid\":\"hex\",\"vout\":n},...] [{\"address\":amount},...] ( locktime replaceable )">>}.

%% Check if transaction fee rate exceeds the maximum allowed.
%% Throws {max_fee_exceeded, ActualFeeRate} if exceeded.
check_max_fee_rate(Tx, MaxFeeRateSatVB) ->
    %% Look up inputs to calculate fee
    TotalIn = compute_tx_input_value(Tx),
    TotalOut = lists:foldl(fun(#tx_out{value = V}, Acc) -> Acc + V end,
                           0, Tx#transaction.outputs),
    case TotalIn of
        0 ->
            %% Can't determine fee without inputs
            ok;
        _ ->
            Fee = TotalIn - TotalOut,
            VSize = beamchain_serialize:tx_vsize(Tx),
            FeeRate = Fee / max(1, VSize),
            case FeeRate > MaxFeeRateSatVB of
                true -> throw({max_fee_exceeded, FeeRate});
                false -> ok
            end
    end.

%% Compute total input value for a transaction.
compute_tx_input_value(#transaction{inputs = Inputs}) ->
    lists:foldl(fun(#tx_in{prev_out = #outpoint{hash = H, index = I}}, Acc) ->
        case beamchain_chainstate:get_utxo(H, I) of
            {ok, #utxo{value = V}} -> Acc + V;
            not_found ->
                case beamchain_mempool:get_mempool_utxo(H, I) of
                    {ok, #utxo{value = V}} -> Acc + V;
                    not_found -> Acc
                end
        end
    end, 0, Inputs).

%% Relay a transaction to all connected peers.
relay_transaction(Txid) ->
    try
        beamchain_peer_manager:broadcast(inv, #{
            items => [#{type => ?MSG_TX, hash => Txid}]
        })
    catch
        _:_ -> ok
    end.

%% Format mempool rejection errors with appropriate RPC error codes.
format_mempool_error(orphan, _Txid) ->
    {error, ?RPC_VERIFY_ERROR, <<"Missing inputs">>};
format_mempool_error(already_in_mempool, _Txid) ->
    {error, ?RPC_VERIFY_ALREADY_IN_CHAIN, <<"Transaction already in mempool">>};
format_mempool_error(insufficient_fee, _Txid) ->
    {error, ?RPC_VERIFY_REJECTED, <<"Insufficient fee">>};
format_mempool_error(mempool_min_fee_not_met, _Txid) ->
    {error, ?RPC_VERIFY_REJECTED, <<"mempool min fee not met">>};
format_mempool_error(dust, _Txid) ->
    {error, ?RPC_VERIFY_REJECTED, <<"dust">>};
format_mempool_error(too_long_mempool_chain, _Txid) ->
    {error, ?RPC_VERIFY_REJECTED, <<"too-long-mempool-chain">>};
format_mempool_error(rbf_not_signaled, _Txid) ->
    {error, ?RPC_VERIFY_REJECTED, <<"txn-mempool-conflict">>};
format_mempool_error(rbf_insufficient_fee, _Txid) ->
    {error, ?RPC_VERIFY_REJECTED, <<"insufficient fee">>};
format_mempool_error(rbf_insufficient_additional_fee, _Txid) ->
    {error, ?RPC_VERIFY_REJECTED, <<"insufficient fee">>};
format_mempool_error(rbf_insufficient_fee_rate, _Txid) ->
    {error, ?RPC_VERIFY_REJECTED, <<"insufficient fee">>};
format_mempool_error(rbf_too_many_evictions, _Txid) ->
    {error, ?RPC_VERIFY_REJECTED, <<"too many potential replacements">>};
format_mempool_error(rbf_new_unconfirmed_inputs, _Txid) ->
    {error, ?RPC_VERIFY_REJECTED, <<"replacement-adds-unconfirmed">>};
format_mempool_error({script_verify_failed, Idx}, _Txid) ->
    {error, ?RPC_VERIFY_ERROR,
     iolist_to_binary(io_lib:format("mandatory-script-verify-flag-failed (input ~B)", [Idx]))};
format_mempool_error({validation, Reason}, _Txid) ->
    {error, ?RPC_VERIFY_ERROR,
     iolist_to_binary(io_lib:format("~p", [Reason]))};
format_mempool_error(Reason, _Txid) ->
    {error, ?RPC_VERIFY_REJECTED,
     iolist_to_binary(io_lib:format("~p", [Reason]))}.

rpc_testmempoolaccept([RawTxs]) when is_list(RawTxs) ->
    Results = lists:map(fun(HexStr) ->
        try
            Bin = beamchain_serialize:hex_decode(HexStr),
            {Tx, _} = beamchain_serialize:decode_transaction(Bin),
            Txid = beamchain_serialize:tx_hash(Tx),
            case beamchain_mempool:accept_to_memory_pool(Tx) of
                {ok, _} ->
                    %% Remove it right away (this was just a test)
                    beamchain_mempool:remove_for_block([Txid]),
                    #{<<"txid">> => hash_to_hex(Txid),
                      <<"allowed">> => true};
                {error, Reason} ->
                    #{<<"txid">> => hash_to_hex(Txid),
                      <<"allowed">> => false,
                      <<"reject-reason">> =>
                          iolist_to_binary(io_lib:format("~p", [Reason]))}
            end
        catch
            _:_ ->
                #{<<"txid">> => <<>>,
                  <<"allowed">> => false,
                  <<"reject-reason">> => <<"TX decode failed">>}
        end
    end, RawTxs),
    {ok, Results};
rpc_testmempoolaccept(_) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: testmempoolaccept [\"rawtx\"]">>}.

rpc_gettxout([TxidHex, N]) ->
    rpc_gettxout([TxidHex, N, true]);
rpc_gettxout([TxidHex, N, IncludeMempool]) when is_binary(TxidHex),
                                                  is_integer(N) ->
    Txid = hex_to_internal_hash(TxidHex),
    %% Check mempool first if requested
    MempoolResult = case IncludeMempool of
        true ->
            beamchain_mempool:get_mempool_utxo(Txid, N);
        _ ->
            not_found
    end,
    case MempoolResult of
        {ok, #utxo{value = V, script_pubkey = Script}} ->
            {ok, format_utxo_result(V, Script, 0, true)};
        not_found ->
            case beamchain_chainstate:get_utxo(Txid, N) of
                {ok, #utxo{value = V, script_pubkey = Script,
                           is_coinbase = IsCb, height = Height}} ->
                    {ok, format_utxo_result(V, Script,
                        confirmations(Height), IsCb)};
                not_found ->
                    {ok, null}
            end
    end;
rpc_gettxout(_) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: gettxout \"txid\" n ( include_mempool )">>}.

rpc_gettxoutsetinfo([]) ->
    rpc_gettxoutsetinfo([<<"none">>]);
rpc_gettxoutsetinfo([HashType | _]) ->
    %% Get UTXO set statistics. Per Core's gettxoutsetinfo (rpc/blockchain.cpp
    %% around line 1090), hash_type ∈ {none, hash_serialized_3, muhash}
    %% selects which UTXO-set commitment to surface. We honour this so callers
    %% can ask for either commitment by name.
    case beamchain_chainstate:get_tip() of
        {ok, {TipHash, TipHeight}} ->
            %% Get cache statistics from chainstate
            CacheStats = beamchain_chainstate:cache_stats(),
            CacheEntries = maps:get(cache_entries, CacheStats, 0),
            %% Estimate total UTXOs (cache + flushed to disk)
            %% This is approximate since we don't iterate the full DB
            TxOuts = CacheEntries,
            %% Approximate bogosize (150 bytes per UTXO on average)
            Bogosize = TxOuts * 150,
            Base = #{
                <<"height">> => TipHeight,
                <<"bestblock">> => hash_to_hex(TipHash),
                <<"txouts">> => TxOuts,
                <<"bogosize">> => Bogosize,
                <<"total_amount">> => 0.0,  %% Would require iterating all UTXOs
                <<"disk_size">> => 0  %% Would require DB stats
            },
            {ok, maybe_attach_utxo_commitment(HashType, Base)};
        not_found ->
            {ok, #{
                <<"height">> => 0,
                <<"bestblock">> => <<"0000000000000000000000000000000000000000000000000000000000000000">>,
                <<"txouts">> => 0,
                <<"bogosize">> => 0,
                <<"total_amount">> => 0.0,
                <<"disk_size">> => 0
            }}
    end.

%% Append the requested UTXO-set commitment to the gettxoutsetinfo result.
%% Mirrors rpc/blockchain.cpp:1090-1119 — `hash_serialized_3` and `muhash`
%% are surfaced under their own keys, `none` adds nothing.
maybe_attach_utxo_commitment(HashType, Base) when is_binary(HashType) ->
    case HashType of
        <<"hash_serialized_3">> ->
            UtxoHash = beamchain_snapshot:compute_utxo_hash(),
            Base#{<<"hash_serialized_3">> =>
                      beamchain_serialize:hex_encode(
                        beamchain_serialize:reverse_bytes(UtxoHash))};
        <<"muhash">> ->
            %% MuHash3072 finalize digest. Order-independent; surfaced as a
            %% display-order hex string (uint256::ToString).
            MuHash = beamchain_chainstate:compute_utxo_muhash(),
            Base#{<<"muhash">> =>
                      beamchain_serialize:hex_encode(
                        beamchain_serialize:reverse_bytes(MuHash))};
        _ ->
            Base
    end;
maybe_attach_utxo_commitment(_, Base) ->
    Base.

%%% ===================================================================
%%% Mempool methods
%%% ===================================================================

rpc_getmempoolinfo() ->
    Info = beamchain_mempool:get_info(),
    Size = maps:get(size, Info, 0),
    Bytes = maps:get(bytes, Info, 0),
    {ok, #{
        <<"loaded">> => true,
        <<"size">> => Size,
        <<"bytes">> => Bytes,
        <<"usage">> => Bytes,
        <<"maxmempool">> => ?DEFAULT_MEMPOOL_MAX_SIZE,
        <<"mempoolminfee">> => ?DEFAULT_MIN_RELAY_TX_FEE / 100000.0,
        <<"minrelaytxfee">> => ?DEFAULT_MIN_RELAY_TX_FEE / 100000.0,
        <<"incrementalrelayfee">> => 0.00001,
        <<"unbroadcastcount">> => 0,
        <<"fullrbf">> => beamchain_config:mempool_full_rbf()
    }}.

rpc_getrawmempool([]) ->
    rpc_getrawmempool([false]);
rpc_getrawmempool([Verbose]) ->
    Txids = beamchain_mempool:get_all_txids(),
    case Verbose of
        true ->
            Entries = lists:filtermap(fun(Txid) ->
                case beamchain_mempool:get_entry(Txid) of
                    {ok, Entry} ->
                        {true, {hash_to_hex(Txid), format_mempool_entry(Entry)}};
                    not_found ->
                        false
                end
            end, Txids),
            {ok, maps:from_list(Entries)};
        _ ->
            {ok, [hash_to_hex(T) || T <- Txids]}
    end;
rpc_getrawmempool(_) ->
    Txids = beamchain_mempool:get_all_txids(),
    {ok, [hash_to_hex(T) || T <- Txids]}.

rpc_getmempoolentry([TxidHex]) when is_binary(TxidHex) ->
    Txid = hex_to_internal_hash(TxidHex),
    case beamchain_mempool:get_entry(Txid) of
        {ok, Entry} ->
            {ok, format_mempool_entry(Entry)};
        not_found ->
            {error, ?RPC_INVALID_ADDRESS_OR_KEY,
             <<"Transaction not in mempool">>}
    end;
rpc_getmempoolentry(_) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: getmempoolentry \"txid\"">>}.

rpc_getmempoolancestors([TxidHex]) when is_binary(TxidHex) ->
    rpc_getmempoolancestors([TxidHex, false]);
rpc_getmempoolancestors([TxidHex, Verbose]) when is_binary(TxidHex) ->
    Txid = hex_to_internal_hash(TxidHex),
    case beamchain_mempool:get_entry(Txid) of
        {ok, _Entry} ->
            AncestorTxids = beamchain_mempool:get_ancestors(Txid),
            case Verbose of
                true ->
                    Entries = lists:map(fun(AncTxid) ->
                        case beamchain_mempool:get_entry(AncTxid) of
                            {ok, AncEntry} ->
                                {hash_to_hex(AncTxid), format_mempool_entry(AncEntry)};
                            not_found ->
                                {hash_to_hex(AncTxid), #{}}
                        end
                    end, AncestorTxids),
                    {ok, maps:from_list(Entries)};
                _ ->
                    {ok, [hash_to_hex(T) || T <- AncestorTxids]}
            end;
        not_found ->
            {error, ?RPC_INVALID_ADDRESS_OR_KEY,
             <<"Transaction not in mempool">>}
    end;
rpc_getmempoolancestors(_) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: getmempoolancestors \"txid\" ( verbose )">>}.

%% Mirrors Bitcoin Core rpc/mempool.cpp `getmempooldescendants`:
%% returns the in-mempool descendants of `txid`, excluding the
%% queried tx itself.
rpc_getmempooldescendants([TxidHex]) when is_binary(TxidHex) ->
    rpc_getmempooldescendants([TxidHex, false]);
rpc_getmempooldescendants([TxidHex, Verbose]) when is_binary(TxidHex) ->
    Txid = hex_to_internal_hash(TxidHex),
    case beamchain_mempool:get_entry(Txid) of
        {ok, _Entry} ->
            DescTxids = beamchain_mempool:get_descendants(Txid),
            case Verbose of
                true ->
                    Entries = lists:map(fun(DescTxid) ->
                        case beamchain_mempool:get_entry(DescTxid) of
                            {ok, DescEntry} ->
                                {hash_to_hex(DescTxid),
                                 format_mempool_entry(DescEntry)};
                            not_found ->
                                {hash_to_hex(DescTxid), #{}}
                        end
                    end, DescTxids),
                    {ok, maps:from_list(Entries)};
                _ ->
                    {ok, [hash_to_hex(T) || T <- DescTxids]}
            end;
        not_found ->
            {error, ?RPC_INVALID_ADDRESS_OR_KEY,
             <<"Transaction not in mempool">>}
    end;
rpc_getmempooldescendants(_) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: getmempooldescendants \"txid\" ( verbose )">>}.

%% Persist mempool to <datadir>/mempool.dat (Bitcoin Core compatible).
rpc_dumpmempool() ->
    case beamchain_mempool:dump_mempool() of
        {ok, _N} ->
            {ok, true};
        {error, Reason} ->
            {error, ?RPC_MISC_ERROR,
             list_to_binary(io_lib:format("dumpmempool failed: ~p",
                                          [Reason]))}
    end.

%% Load mempool from <datadir>/mempool.dat. Returns {tx_count, expired,
%% failed, already, total} as Core-style fields.
rpc_loadmempool() ->
    case beamchain_mempool:load_mempool() of
        {ok, Stats} ->
            {ok, #{
                <<"loaded">>  => maps:get(accepted, Stats, 0),
                <<"expired">> => maps:get(expired, Stats, 0),
                <<"failed">>  => maps:get(failed, Stats, 0),
                <<"already">> => maps:get(already, Stats, 0),
                <<"total">>   => maps:get(total, Stats, 0)
            }};
        {error, no_file} ->
            {ok, #{<<"loaded">> => 0, <<"expired">> => 0,
                   <<"failed">> => 0, <<"already">> => 0,
                   <<"total">> => 0}};
        {error, Reason} ->
            {error, ?RPC_MISC_ERROR,
             list_to_binary(io_lib:format("loadmempool failed: ~p",
                                          [Reason]))}
    end.

%%% ===================================================================
%%% Network methods
%%% ===================================================================

rpc_getnetworkinfo() ->
    Connections = beamchain_peer_manager:peer_count(),
    {ok, #{
        <<"version">> => 260000,
        <<"subversion">> => <<"/beamchain:0.1.0/">>,
        <<"protocolversion">> => ?PROTOCOL_VERSION,
        <<"localservices">> => <<"0000000000000009">>,
        <<"localservicesnames">> => [<<"NETWORK">>, <<"WITNESS">>],
        <<"localrelay">> => true,
        <<"timeoffset">> => 0,
        <<"networkactive">> => true,
        <<"connections">> => Connections,
        <<"connections_in">> => beamchain_peer_manager:inbound_count(),
        <<"connections_out">> => beamchain_peer_manager:outbound_count(),
        <<"networks">> => [#{
            <<"name">> => <<"ipv4">>,
            <<"limited">> => false,
            <<"reachable">> => true,
            <<"proxy">> => <<>>,
            <<"proxy_randomize_credentials">> => false
        }],
        <<"relayfee">> => ?DEFAULT_MIN_RELAY_TX_FEE / 100000.0,
        <<"incrementalfee">> => 0.00001,
        <<"localaddresses">> => [],
        <<"warnings">> => <<>>
    }}.

rpc_getpeerinfo() ->
    Peers = beamchain_peer_manager:get_peers(),
    PeerInfoList = lists:map(fun(#{pid := Pid, address := {IP, Port},
                                   direction := Dir, connected := _Conn,
                                   info := StaleInfo}) ->
        Now = erlang:system_time(second),
        %% Pull live stats from the peer gen_statem; fall back to the
        %% manager's stored Info (set at peer_connected) on timeout so the
        %% RPC never blocks behind a slow peer process.
        Info = case catch gen_statem:call(Pid, info, 500) of
            {ok, Live} when is_map(Live) -> Live;
            _ -> StaleInfo
        end,
        ConnTime = case maps:get(connected_at, Info, undefined) of
            undefined -> Now;
            Ms -> Ms div 1000
        end,
        LastSend = case maps:get(last_send, Info, undefined) of
            undefined -> Now;
            Ms2 -> Ms2 div 1000
        end,
        LastRecv = case maps:get(last_recv, Info, undefined) of
            undefined -> Now;
            Ms3 -> Ms3 div 1000
        end,
        PingTime = case maps:get(latency_ms, Info, undefined) of
            undefined -> 0.0;
            L -> L / 1000.0
        end,
        #{
            <<"id">> => erlang:phash2({IP, Port}),
            <<"addr">> => format_addr(IP, Port),
            <<"addrbind">> => <<>>,
            <<"services">> => beamchain_serialize:hex_encode(
                <<(maps:get(services, Info, 0)):64/big>>),
            <<"servicesnames">> => services_to_names(
                maps:get(services, Info, 0)),
            <<"relaytxes">> => maps:get(relay, Info, true),
            <<"lastsend">> => LastSend,
            <<"lastrecv">> => LastRecv,
            <<"last_transaction">> => 0,
            <<"last_block">> => 0,
            <<"bytessent">> => maps:get(bytes_sent, Info, 0),
            <<"bytesrecv">> => maps:get(bytes_recv, Info, 0),
            <<"conntime">> => ConnTime,
            <<"timeoffset">> => case maps:get(peer_version_timestamp, Info, undefined) of
                undefined -> 0;
                PeerTs -> PeerTs - Now
            end,
            <<"pingtime">> => PingTime,
            <<"version">> => maps:get(version, Info, 0),
            <<"subver">> => maps:get(user_agent, Info, <<"/unknown/">>),
            <<"inbound">> => Dir =:= inbound,
            <<"bip152_hb_to">> => false,
            <<"bip152_hb_from">> => false,
            <<"startingheight">> => maps:get(start_height, Info, 0),
            <<"presynced_headers">> => 0,
            <<"synced_headers">> => -1,
            <<"synced_blocks">> => -1,
            <<"connection_type">> => case Dir of
                outbound -> <<"outbound-full-relay">>;
                inbound -> <<"inbound">>
            end
        }
    end, Peers),
    {ok, PeerInfoList}.

rpc_getconnectioncount() ->
    {ok, beamchain_peer_manager:peer_count()}.

rpc_addnode([NodeStr, CommandStr]) when is_binary(NodeStr),
                                        is_binary(CommandStr) ->
    case CommandStr of
        <<"add">> ->
            case parse_node_addr(NodeStr) of
                {ok, IP, Port} ->
                    case beamchain_peer_manager:connect_to(IP, Port) of
                        {ok, _Pid} -> {ok, null};
                        {error, Reason} ->
                            {error, ?RPC_MISC_ERROR,
                             iolist_to_binary(io_lib:format("~p", [Reason]))}
                    end;
                {error, Msg} ->
                    {error, ?RPC_INVALID_PARAMETER, Msg}
            end;
        <<"remove">> ->
            %% Find and disconnect
            case parse_node_addr(NodeStr) of
                {ok, IP, Port} ->
                    Peers = beamchain_peer_manager:get_peers(),
                    case lists:filter(fun(#{address := {PIP, PPort}}) ->
                        PIP =:= IP andalso PPort =:= Port
                    end, Peers) of
                        [#{pid := Pid} | _] ->
                            beamchain_peer_manager:disconnect_peer(Pid),
                            {ok, null};
                        [] ->
                            {error, ?RPC_MISC_ERROR, <<"Node not found">>}
                    end;
                {error, Msg} ->
                    {error, ?RPC_INVALID_PARAMETER, Msg}
            end;
        <<"onetry">> ->
            case parse_node_addr(NodeStr) of
                {ok, IP, Port} ->
                    beamchain_peer_manager:connect_to(IP, Port),
                    {ok, null};
                {error, Msg} ->
                    {error, ?RPC_INVALID_PARAMETER, Msg}
            end;
        _ ->
            {error, ?RPC_INVALID_PARAMETER,
             <<"Command must be add, remove, or onetry">>}
    end;
rpc_addnode(_) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: addnode \"node\" \"command\"">>}.

rpc_disconnectnode([Address]) when is_binary(Address) ->
    case parse_node_addr(Address) of
        {ok, IP, Port} ->
            Peers = beamchain_peer_manager:get_peers(),
            case lists:filter(fun(#{address := {PIP, PPort}}) ->
                PIP =:= IP andalso PPort =:= Port
            end, Peers) of
                [#{pid := Pid} | _] ->
                    beamchain_peer_manager:disconnect_peer(Pid),
                    {ok, null};
                [] ->
                    {error, ?RPC_MISC_ERROR, <<"Node not connected">>}
            end;
        {error, Msg} ->
            {error, ?RPC_INVALID_PARAMETER, Msg}
    end;
rpc_disconnectnode(_) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: disconnectnode \"address\"">>}.

rpc_listbanned() ->
    BanList = beamchain_peer_manager:get_ban_list(),
    Now = erlang:system_time(second),
    Entries = lists:map(fun({IP, BanExpiry}) ->
        #{
            <<"address">> => format_ip(IP),
            <<"ban_created">> => BanExpiry - 86400,  %% approximate
            <<"banned_until">> => BanExpiry,
            <<"ban_duration">> => BanExpiry - Now,
            <<"ban_reason">> => <<"node misbehaving">>
        }
    end, BanList),
    {ok, Entries}.

rpc_setban([Subnet, Command]) ->
    rpc_setban([Subnet, Command, 86400]);  %% default 24 hours
rpc_setban([Subnet, Command, BanTime]) when is_binary(Subnet),
                                             is_binary(Command) ->
    case Command of
        <<"add">> ->
            case parse_subnet(Subnet) of
                {ok, IP} ->
                    Duration = if
                        is_integer(BanTime) -> BanTime;
                        is_binary(BanTime) ->
                            binary_to_integer(BanTime);
                        true -> 86400
                    end,
                    beamchain_peer_manager:set_ban(IP, Duration, <<"manual">>),
                    {ok, null};
                {error, Msg} ->
                    {error, ?RPC_INVALID_PARAMETER, Msg}
            end;
        <<"remove">> ->
            case parse_subnet(Subnet) of
                {ok, IP} ->
                    case beamchain_peer_manager:clear_ban(IP) of
                        ok -> {ok, null};
                        {error, not_found} ->
                            {error, ?RPC_MISC_ERROR, <<"Error: Unban failed">>}
                    end;
                {error, Msg} ->
                    {error, ?RPC_INVALID_PARAMETER, Msg}
            end;
        _ ->
            {error, ?RPC_INVALID_PARAMETER,
             <<"Command must be add or remove">>}
    end;
rpc_setban(_) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: setban \"subnet\" \"command\" ( bantime )">>}.

rpc_clearbanned() ->
    BanList = beamchain_peer_manager:get_ban_list(),
    lists:foreach(fun({IP, _}) ->
        beamchain_peer_manager:clear_ban(IP)
    end, BanList),
    {ok, null}.

%% Parse a subnet or IP address string (e.g., "192.168.1.1" or "192.168.1.0/24")
%% For now, we only support single IPs (no CIDR notation)
parse_subnet(Subnet) when is_binary(Subnet) ->
    parse_subnet(binary_to_list(Subnet));
parse_subnet(Subnet) when is_list(Subnet) ->
    %% Strip any /32 or CIDR suffix for now (we only support single IPs)
    IPStr = case string:split(Subnet, "/") of
        [IpPart, _Mask] -> IpPart;
        [IpPart] -> IpPart
    end,
    case inet:parse_address(IPStr) of
        {ok, ParsedIP} -> {ok, ParsedIP};
        {error, _} -> {error, <<"Invalid IP address">>}
    end.

%% Format IP address for display
format_ip({A, B, C, D}) ->
    iolist_to_binary(io_lib:format("~B.~B.~B.~B", [A, B, C, D]));
format_ip(IP) ->
    iolist_to_binary(io_lib:format("~p", [IP])).

%%% ===================================================================
%%% Mining methods
%%% ===================================================================

rpc_getmininginfo() ->
    Network = beamchain_config:network(),
    {Blocks, Difficulty} = case beamchain_chainstate:get_tip() of
        {ok, {_Hash, Height}} ->
            {Height, tip_difficulty()};
        not_found ->
            {0, 0.0}
    end,
    PooledTx = length(beamchain_mempool:get_all_txids()),
    {ok, #{
        <<"blocks">> => Blocks,
        <<"difficulty">> => Difficulty,
        <<"networkhashps">> => 0,
        <<"pooledtx">> => PooledTx,
        <<"chain">> => network_name(Network),
        <<"warnings">> => <<>>
    }}.

rpc_getblocktemplate([]) ->
    rpc_getblocktemplate([#{}]);
rpc_getblocktemplate([TemplateRequest]) when is_map(TemplateRequest) ->
    %% Use a default coinbase script (OP_TRUE) for template generation
    DefaultScript = <<16#51>>,
    CoinbaseScript = maps:get(<<"coinbasescript">>, TemplateRequest,
                               DefaultScript),
    case beamchain_miner:create_block_template(CoinbaseScript) of
        {ok, Template} ->
            %% Strip internal fields (prefixed with _)
            Public = maps:filter(fun(<<"_", _/binary>>, _) -> false;
                                     (_, _) -> true
                                 end, Template),
            {ok, Public};
        {error, Reason} ->
            {error, ?RPC_MISC_ERROR,
             iolist_to_binary(io_lib:format("~p", [Reason]))}
    end;
rpc_getblocktemplate(_) ->
    rpc_getblocktemplate([#{}]).

rpc_submitblock([HexData]) when is_binary(HexData) ->
    case beamchain_miner:submit_block(HexData) of
        ok ->
            {ok, null};
        {error, Reason} ->
            {error, ?RPC_VERIFY_ERROR,
             iolist_to_binary(io_lib:format("~p", [Reason]))}
    end;
rpc_submitblock(_) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: submitblock \"hexdata\"">>}.

%%% ===================================================================
%%% Generating methods (regtest only)
%%% ===================================================================

%% generatetoaddress nblocks address [maxtries]
%% Mine nblocks blocks with coinbase paying to address.
%% Only works on regtest.
rpc_generatetoaddress([NBlocks, Address]) ->
    rpc_generatetoaddress([NBlocks, Address, 1000000]);
rpc_generatetoaddress([NBlocks, Address, MaxTries])
  when is_integer(NBlocks), is_binary(Address), is_integer(MaxTries) ->
    %% Check if regtest
    case beamchain_config:network() of
        regtest ->
            %% Convert address to scriptPubKey
            Network = beamchain_config:network(),
            NetType = case Network of mainnet -> mainnet; _ -> testnet end,
            AddrStr = binary_to_list(Address),
            case beamchain_address:address_to_script(AddrStr, NetType) of
                {ok, Script} ->
                    case beamchain_miner:generate_blocks(Script, NBlocks, MaxTries) of
                        {ok, BlockHashes} ->
                            {ok, BlockHashes};
                        {error, Reason} ->
                            {error, ?RPC_MISC_ERROR,
                             iolist_to_binary(io_lib:format("~p", [Reason]))}
                    end;
                {error, _} ->
                    {error, ?RPC_INVALID_ADDRESS_OR_KEY,
                     <<"Error: Invalid address">>}
            end;
        _ ->
            {error, ?RPC_METHOD_NOT_FOUND,
             <<"Method not found (regtest only)">>}
    end;
rpc_generatetoaddress(_) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: generatetoaddress nblocks \"address\" ( maxtries )">>}.

%% generateblock output transactions [submit]
%% Mine a block with specific transactions.
%% output: address or descriptor to pay coinbase to
%% transactions: array of txids (from mempool) or raw tx hex
%% submit: whether to submit the block (default true)
rpc_generateblock([Output, Transactions]) ->
    rpc_generateblock([Output, Transactions, true]);
rpc_generateblock([Output, Transactions, Submit])
  when is_binary(Output), is_list(Transactions), is_boolean(Submit) ->
    %% Check if regtest
    case beamchain_config:network() of
        regtest ->
            %% Convert output address to scriptPubKey
            Network = beamchain_config:network(),
            NetType = case Network of mainnet -> mainnet; _ -> testnet end,
            OutputStr = binary_to_list(Output),
            case beamchain_address:address_to_script(OutputStr, NetType) of
                {ok, Script} ->
                    %% Parse transactions (txids from mempool or raw tx hex)
                    case parse_generate_transactions(Transactions) of
                        {ok, Txs} ->
                            case beamchain_miner:generate_block_with_txs(Script, Txs, Submit) of
                                {ok, Result} ->
                                    {ok, Result};
                                {error, Reason} ->
                                    {error, ?RPC_MISC_ERROR,
                                     iolist_to_binary(io_lib:format("~p", [Reason]))}
                            end;
                        {error, Reason} ->
                            {error, ?RPC_INVALID_PARAMETER, Reason}
                    end;
                {error, _} ->
                    {error, ?RPC_INVALID_ADDRESS_OR_KEY,
                     <<"Error: Invalid address or descriptor">>}
            end;
        _ ->
            {error, ?RPC_METHOD_NOT_FOUND,
             <<"Method not found (regtest only)">>}
    end;
rpc_generateblock(_) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: generateblock \"output\" [\"rawtx/txid\",...] ( submit )">>}.

%% generate nblocks
%% Deprecated in Bitcoin Core. We implement a simple version that uses OP_TRUE.
rpc_generate([NBlocks]) when is_integer(NBlocks) ->
    rpc_generate([NBlocks, 1000000]);
rpc_generate([NBlocks, MaxTries]) when is_integer(NBlocks), is_integer(MaxTries) ->
    %% Check if regtest
    case beamchain_config:network() of
        regtest ->
            %% Use OP_TRUE (0x51) as the coinbase script
            Script = <<16#51>>,
            case beamchain_miner:generate_blocks(Script, NBlocks, MaxTries) of
                {ok, BlockHashes} ->
                    {ok, BlockHashes};
                {error, Reason} ->
                    {error, ?RPC_MISC_ERROR,
                     iolist_to_binary(io_lib:format("~p", [Reason]))}
            end;
        _ ->
            {error, ?RPC_METHOD_NOT_FOUND,
             <<"Method not found (regtest only)">>}
    end;
rpc_generate(_) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: generate nblocks ( maxtries )">>}.

%% Parse transaction list for generateblock.
%% Each element is either a txid (look up in mempool) or raw tx hex.
parse_generate_transactions(TxList) ->
    parse_generate_transactions(TxList, []).

parse_generate_transactions([], Acc) ->
    {ok, lists:reverse(Acc)};
parse_generate_transactions([TxIdOrHex | Rest], Acc) when is_binary(TxIdOrHex) ->
    case byte_size(TxIdOrHex) of
        64 ->
            %% Looks like a txid (64 hex chars = 32 bytes)
            try
                TxidBin = beamchain_serialize:hex_decode(TxIdOrHex),
                %% Txids in RPC are display order (reversed)
                TxidInternal = beamchain_serialize:reverse_bytes(TxidBin),
                case beamchain_mempool:get_tx(TxidInternal) of
                    {ok, Tx} ->
                        parse_generate_transactions(Rest, [Tx | Acc]);
                    not_found ->
                        {error, iolist_to_binary(
                            io_lib:format("Transaction ~s not in mempool", [TxIdOrHex]))}
                end
            catch
                _:_ ->
                    %% Not valid hex, try as raw tx
                    try_parse_raw_tx(TxIdOrHex, Rest, Acc)
            end;
        _ ->
            %% Try to decode as raw transaction hex
            try_parse_raw_tx(TxIdOrHex, Rest, Acc)
    end;
parse_generate_transactions([_ | _], _Acc) ->
    {error, <<"Invalid transaction format">>}.

try_parse_raw_tx(TxHex, Rest, Acc) ->
    try
        TxBin = beamchain_serialize:hex_decode(TxHex),
        {Tx, _} = beamchain_serialize:decode_transaction(TxBin),
        parse_generate_transactions(Rest, [Tx | Acc])
    catch
        _:_ ->
            {error, iolist_to_binary(
                io_lib:format("Transaction decode failed for ~s", [TxHex]))}
    end.

%%% ===================================================================
%%% Fee estimation
%%% ===================================================================

rpc_estimatesmartfee([ConfTarget | _]) when is_integer(ConfTarget) ->
    case beamchain_fee_estimator:estimate_fee(ConfTarget) of
        {ok, FeeRate} ->
            %% Convert sat/vB to BTC/kvB
            BtcPerKvB = FeeRate * 1000.0 / 100000000.0,
            {ok, #{
                <<"feerate">> => BtcPerKvB,
                <<"blocks">> => ConfTarget,
                <<"errors">> => []
            }};
        {error, _Reason} ->
            {ok, #{
                <<"errors">> => [<<"Insufficient data">>],
                <<"blocks">> => ConfTarget
            }}
    end;
rpc_estimatesmartfee(_) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: estimatesmartfee conf_target">>}.

%% estimaterawfee — Core hidden RPC. Returns per-horizon raw bucket
%% estimate. We expose a single "medium" horizon (beamchain's
%% exponential-decay estimator collapses Core's three horizons).
rpc_estimaterawfee([ConfTarget]) when is_integer(ConfTarget) ->
    rpc_estimaterawfee([ConfTarget, 0.95]);
rpc_estimaterawfee([ConfTarget, Threshold])
  when is_integer(ConfTarget),
       (is_float(Threshold) orelse is_integer(Threshold)) ->
    Thr = case Threshold of
        I when is_integer(I) -> float(I);
        F -> F
    end,
    case Thr >= 0.0 andalso Thr =< 1.0 of
        false ->
            {error, ?RPC_INVALID_PARAMETER, <<"Invalid threshold">>};
        true ->
            case ConfTarget < 1 orelse ConfTarget > 1008 of
                true ->
                    {error, ?RPC_INVALID_PARAMETER,
                     <<"Invalid conf_target">>};
                false ->
                    Result = beamchain_fee_estimator:estimate_raw_fee(
                                ConfTarget, Thr),
                    {ok, Result}
            end
    end;
rpc_estimaterawfee(_) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: estimaterawfee conf_target ( threshold )">>}.

%%% ===================================================================
%%% Utility methods
%%% ===================================================================

rpc_validateaddress([Address]) when is_binary(Address) ->
    AddrStr = binary_to_list(Address),
    Network = beamchain_config:network(),
    NetType = case Network of mainnet -> mainnet; _ -> testnet end,
    case beamchain_address:address_to_script(AddrStr, NetType) of
        {ok, Script} ->
            Type = beamchain_address:classify_script(Script),
            IsWitness = case Type of
                p2wpkh -> true;
                p2wsh -> true;
                p2tr -> true;
                {witness, _, _} -> true;
                _ -> false
            end,
            IsScript = case Type of
                p2sh -> true;
                p2wsh -> true;
                _ -> false
            end,
            {ok, #{
                <<"isvalid">> => true,
                <<"address">> => Address,
                <<"scriptPubKey">> => beamchain_serialize:hex_encode(Script),
                <<"isscript">> => IsScript,
                <<"iswitness">> => IsWitness,
                <<"witness_version">> => case Type of
                    p2wpkh -> 0;
                    p2wsh -> 0;
                    p2tr -> 1;
                    {witness, V, _} -> V;
                    _ -> null
                end,
                <<"witness_program">> => case Script of
                    <<_WitVer:8, Len:8, Prog:Len/binary>> when IsWitness ->
                        beamchain_serialize:hex_encode(Prog);
                    _ -> null
                end
            }};
        {error, _} ->
            {ok, #{
                <<"isvalid">> => false,
                <<"address">> => Address
            }}
    end;
rpc_validateaddress(_) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: validateaddress \"address\"">>}.

rpc_decodescript([HexStr]) when is_binary(HexStr) ->
    try
        Script = beamchain_serialize:hex_decode(HexStr),
        Type = beamchain_address:classify_script(Script),
        Network = beamchain_config:network(),
        NetType = case Network of mainnet -> mainnet; _ -> testnet end,
        Address = beamchain_address:script_to_address(Script, NetType),
        %% P2SH address of this script
        ScriptHash = beamchain_crypto:hash160(Script),
        P2SHScript = <<16#a9, 16#14, ScriptHash/binary, 16#87>>,
        P2SH = beamchain_address:script_to_address(P2SHScript, NetType),
        {ok, #{
            <<"asm">> => beamchain_serialize:hex_encode(Script),
            <<"type">> => script_type_name(Type),
            <<"address">> => case Address of
                unknown -> null;
                "OP_RETURN" -> null;
                Addr -> iolist_to_binary(Addr)
            end,
            <<"p2sh">> => case P2SH of
                unknown -> null;
                Addr2 -> iolist_to_binary(Addr2)
            end
        }}
    catch
        _:_ ->
            {error, ?RPC_DESERIALIZATION_ERROR,
             <<"Script decode failed">>}
    end;
rpc_decodescript(_) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: decodescript \"hexstring\"">>}.

%%% ===================================================================
%%% Message signing / verification (Bitcoin Signed Message)
%%% ===================================================================

%% signmessagewithprivkey "privkey" "message"
%%
%% Mirrors Bitcoin Core rpc/signmessage.cpp signmessagewithprivkey().
%% Returns base64-encoded recoverable ECDSA signature.
rpc_signmessagewithprivkey([WifKey, Message])
  when is_binary(WifKey), is_binary(Message) ->
    case wif_to_privkey(WifKey) of
        {ok, {PrivKey, _Compressed}} ->
            case beamchain_crypto:sign_message(Message, PrivKey) of
                {ok, B64} -> {ok, B64};
                {error, _} ->
                    {error, ?RPC_INVALID_ADDRESS_OR_KEY,
                     <<"Sign failed">>}
            end;
        {error, _} ->
            {error, ?RPC_INVALID_ADDRESS_OR_KEY,
             <<"Invalid private key">>}
    end;
rpc_signmessagewithprivkey(_) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: signmessagewithprivkey \"privkey\" \"message\"">>}.

%% signmessage "address" "message" — wallet-aware variant. Looks up
%% the privkey for `address` in the (default or named) wallet and
%% delegates to the privkey path.
rpc_signmessage([Address, Message], WalletName)
  when is_binary(Address), is_binary(Message) ->
    case resolve_wallet(WalletName) of
        {ok, Pid} ->
            case beamchain_wallet:get_private_key(
                    Pid, binary_to_list(Address)) of
                {ok, PrivKey} ->
                    case beamchain_crypto:sign_message(Message, PrivKey) of
                        {ok, B64} -> {ok, B64};
                        {error, _} ->
                            {error, ?RPC_INVALID_ADDRESS_OR_KEY,
                             <<"Sign failed">>}
                    end;
                {error, not_found} ->
                    {error, ?RPC_INVALID_ADDRESS_OR_KEY,
                     <<"Private key not available">>};
                {error, wallet_locked} ->
                    {error, ?RPC_MISC_ERROR,
                     <<"Error: Please enter the wallet passphrase with "
                       "walletpassphrase first.">>};
                {error, Reason} ->
                    {error, ?RPC_MISC_ERROR,
                     iolist_to_binary(io_lib:format("~p", [Reason]))}
            end;
        {error, _} ->
            wallet_not_found_error(WalletName)
    end;
rpc_signmessage(_, _) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: signmessage \"address\" \"message\"">>}.

%% verifymessage "address" "signature" "message"
%%
%% Mirrors Bitcoin Core rpc/signmessage.cpp verifymessage().
%% Only legacy P2PKH addresses are supported (Core requires PKHash).
rpc_verifymessage([Address, Signature, Message])
  when is_binary(Address), is_binary(Signature), is_binary(Message) ->
    Network = beamchain_config:network(),
    NetType = case Network of mainnet -> mainnet; _ -> testnet end,
    AddrStr = binary_to_list(Address),
    case beamchain_address:address_to_script(AddrStr, NetType) of
        {ok, Script} ->
            case beamchain_address:classify_script(Script) of
                p2pkh ->
                    %% Extract the 20-byte HASH160 from the P2PKH script.
                    %% Format: OP_DUP OP_HASH160 <20> ... OP_EQUALVERIFY OP_CHECKSIG
                    <<16#76, 16#a9, 16#14, PKH:20/binary,
                      16#88, 16#ac>> = Script,
                    case beamchain_crypto:verify_message(Signature,
                                                          Message, PKH) of
                        ok -> {ok, true};
                        {error, malformed_signature} ->
                            {error, ?RPC_TYPE_ERROR,
                             <<"Malformed base64 encoding">>};
                        {error, pubkey_not_recovered} -> {ok, false};
                        {error, not_signed} -> {ok, false};
                        {error, _} -> {ok, false}
                    end;
                _ ->
                    {error, ?RPC_TYPE_ERROR,
                     <<"Address does not refer to key">>}
            end;
        {error, _} ->
            {error, ?RPC_INVALID_ADDRESS_OR_KEY, <<"Invalid address">>}
    end;
rpc_verifymessage(_) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: verifymessage \"address\" \"signature\" \"message\"">>}.

%% Decode a WIF-encoded private key. Accepts mainnet (0x80) and
%% testnet/regtest (0xef) prefixes; supports both compressed (33-byte
%% payload ending in 0x01) and uncompressed (32-byte payload) forms.
%% Returns {ok, {PrivKey32, IsCompressed}} or {error, Reason}.
wif_to_privkey(WifBin) when is_binary(WifBin) ->
    wif_to_privkey(binary_to_list(WifBin));
wif_to_privkey(WifStr) when is_list(WifStr) ->
    case beamchain_address:base58check_decode(WifStr) of
        {ok, {Prefix, Payload}} when Prefix =:= 16#80; Prefix =:= 16#ef ->
            case Payload of
                <<Priv:32/binary, 16#01>> -> {ok, {Priv, true}};
                <<Priv:32/binary>>        -> {ok, {Priv, false}};
                _                         -> {error, invalid_payload}
            end;
        {ok, _} -> {error, wrong_network};
        {error, _} = E -> E
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

%% Convert display-order hex hash to internal byte order.
hex_to_internal_hash(HexStr) ->
    beamchain_serialize:reverse_bytes(
        beamchain_serialize:hex_decode(HexStr)).

network_name(mainnet)  -> <<"main">>;
network_name(testnet)  -> <<"test">>;
network_name(testnet4) -> <<"testnet4">>;
network_name(regtest)  -> <<"regtest">>;
network_name(signet)   -> <<"signet">>;
network_name(N)        -> atom_to_binary(N, utf8).

%% Compute difficulty from compact bits.
%% difficulty = max_target / current_target
bits_to_difficulty(Bits) ->
    Target = beamchain_pow:bits_to_target(Bits),
    case Target of
        0 -> 0.0;
        _ ->
            MaxTarget = beamchain_pow:bits_to_target(16#1d00ffff),
            MaxTarget / Target
    end.

%% Current tip difficulty.
tip_difficulty() ->
    case beamchain_chainstate:get_tip() of
        {ok, {_Hash, Height}} ->
            case beamchain_db:get_block_index(Height) of
                {ok, #{header := Hdr}} ->
                    bits_to_difficulty(Hdr#block_header.bits);
                _ -> 0.0
            end;
        _ -> 0.0
    end.

%% Number of confirmations for a block at the given height.
confirmations(BlockHeight) ->
    case beamchain_chainstate:get_tip() of
        {ok, {_, TipHeight}} -> TipHeight - BlockHeight + 1;
        not_found -> 0
    end.

%% Median time past for a specific block height.
block_mtp(Height) when Height < 11 ->
    %% Not enough blocks for full MTP, just use block's own timestamp
    case beamchain_db:get_block_index(Height) of
        {ok, #{header := Hdr}} -> Hdr#block_header.timestamp;
        _ -> 0
    end;
block_mtp(Height) ->
    Timestamps = lists:filtermap(fun(H) ->
        case beamchain_db:get_block_index(H) of
            {ok, #{header := Hdr}} -> {true, Hdr#block_header.timestamp};
            _ -> false
        end
    end, lists:seq(Height - 10, Height)),
    case Timestamps of
        [] -> 0;
        Ts ->
            Sorted = lists:sort(Ts),
            lists:nth((length(Sorted) div 2) + 1, Sorted)
    end.

%% Count transactions in a block.
count_block_txs(Hash) ->
    case beamchain_db:get_block(Hash) of
        {ok, #block{transactions = Txs}} -> length(Txs);
        _ -> 0
    end.

%% Format a block as JSON (verbosity 1 or 2).
format_block_json(#block{header = Header, transactions = Txs} = Block,
                  Hash, DecodeTxs) ->
    Height = case beamchain_db:get_block_index_by_hash(Hash) of
        {ok, #{height := H}} -> H;
        _ -> Block#block.height
    end,
    Chainwork = case beamchain_db:get_block_index_by_hash(Hash) of
        {ok, #{chainwork := CW}} -> CW;
        _ -> <<0:256>>
    end,
    NextHash = case beamchain_db:get_block_index(Height + 1) of
        {ok, #{hash := NH}} -> hash_to_hex(NH);
        not_found -> null
    end,
    Bits = Header#block_header.bits,
    %% Compute block size and weight
    BlockBin = beamchain_serialize:encode_block(Block),
    Size = byte_size(BlockBin),
    Weight = block_weight(Block),
    %% Transaction list
    TxList = case DecodeTxs of
        true ->
            [format_tx_json(Tx) || Tx <- Txs];
        false ->
            [hash_to_hex(beamchain_serialize:tx_hash(Tx)) || Tx <- Txs]
    end,
    #{
        <<"hash">> => hash_to_hex(Hash),
        <<"confirmations">> => confirmations(Height),
        <<"height">> => Height,
        <<"version">> => Header#block_header.version,
        <<"versionHex">> => beamchain_serialize:hex_encode(
            <<(Header#block_header.version):32/big>>),
        <<"merkleroot">> => hash_to_hex(Header#block_header.merkle_root),
        <<"time">> => Header#block_header.timestamp,
        <<"mediantime">> => block_mtp(Height),
        <<"nonce">> => Header#block_header.nonce,
        <<"bits">> => beamchain_serialize:hex_encode(<<Bits:32/big>>),
        <<"difficulty">> => bits_to_difficulty(Bits),
        <<"chainwork">> => beamchain_serialize:hex_encode(Chainwork),
        <<"nTx">> => length(Txs),
        <<"previousblockhash">> => hash_to_hex(
            Header#block_header.prev_hash),
        <<"nextblockhash">> => NextHash,
        <<"size">> => Size,
        <<"weight">> => Weight,
        <<"strippedsize">> => stripped_size(Block),
        <<"tx">> => TxList
    }.

%% Format a transaction as JSON (for getblock verbosity=2).
format_tx_json(#transaction{} = Tx) ->
    Txid = beamchain_serialize:tx_hash(Tx),
    Wtxid = beamchain_serialize:wtx_hash(Tx),
    TxBin = beamchain_serialize:encode_transaction(Tx),
    #{
        <<"txid">> => hash_to_hex(Txid),
        <<"hash">> => hash_to_hex(Wtxid),
        <<"version">> => Tx#transaction.version,
        <<"size">> => byte_size(TxBin),
        <<"vsize">> => beamchain_serialize:tx_vsize(Tx),
        <<"weight">> => beamchain_serialize:tx_weight(Tx),
        <<"locktime">> => Tx#transaction.locktime,
        <<"vin">> => [format_vin(In) || In <- Tx#transaction.inputs],
        <<"vout">> => format_vouts(Tx#transaction.outputs, 0),
        <<"hex">> => beamchain_serialize:hex_encode(TxBin)
    }.

format_vin(#tx_in{prev_out = #outpoint{hash = <<0:256>>,
                                        index = 16#ffffffff},
                  script_sig = ScriptSig, sequence = Seq}) ->
    %% Coinbase
    #{<<"coinbase">> => beamchain_serialize:hex_encode(ScriptSig),
      <<"sequence">> => Seq};
format_vin(#tx_in{prev_out = #outpoint{hash = Hash, index = Idx},
                  script_sig = ScriptSig, sequence = Seq,
                  witness = Witness}) ->
    Base = #{
        <<"txid">> => hash_to_hex(Hash),
        <<"vout">> => Idx,
        <<"scriptSig">> => #{
            <<"hex">> => beamchain_serialize:hex_encode(ScriptSig)
        },
        <<"sequence">> => Seq
    },
    case Witness of
        W when is_list(W), W =/= [] ->
            Base#{<<"txinwitness">> =>
                [beamchain_serialize:hex_encode(Item) || Item <- W]};
        _ ->
            Base
    end.

format_vouts([], _N) -> [];
format_vouts([#tx_out{value = Value, script_pubkey = Script} | Rest], N) ->
    Network = beamchain_config:network(),
    NetType = case Network of
        mainnet -> mainnet;
        _ -> testnet
    end,
    Type = beamchain_address:classify_script(Script),
    Address = beamchain_address:script_to_address(Script, NetType),
    Vout = #{
        <<"value">> => satoshi_to_btc(Value),
        <<"n">> => N,
        <<"scriptPubKey">> => #{
            <<"hex">> => beamchain_serialize:hex_encode(Script),
            <<"type">> => script_type_name(Type),
            <<"address">> => case Address of
                unknown -> null;
                "OP_RETURN" -> null;
                Addr -> iolist_to_binary(Addr)
            end
        }
    },
    [Vout | format_vouts(Rest, N + 1)].

script_type_name(p2pkh)     -> <<"pubkeyhash">>;
script_type_name(p2sh)      -> <<"scripthash">>;
script_type_name(p2wpkh)    -> <<"witness_v0_keyhash">>;
script_type_name(p2wsh)     -> <<"witness_v0_scripthash">>;
script_type_name(p2tr)      -> <<"witness_v1_taproot">>;
script_type_name(op_return)  -> <<"nulldata">>;
script_type_name({witness, V, _}) ->
    iolist_to_binary(io_lib:format("witness_v~B", [V]));
script_type_name(_)          -> <<"nonstandard">>.

satoshi_to_btc(Satoshis) ->
    Satoshis / 100000000.0.

%% Approximate block weight.
block_weight(#block{transactions = Txs} = Block) ->
    %% Header weight: 80 * 4 = 320
    HeaderWeight = 80 * ?WITNESS_SCALE_FACTOR,
    %% Each tx weight
    TxWeights = lists:sum([beamchain_serialize:tx_weight(Tx) || Tx <- Txs]),
    %% Varint for tx count (approximate)
    VarintWeight = byte_size(beamchain_serialize:encode_varint(
        length(Block#block.transactions))) * ?WITNESS_SCALE_FACTOR,
    HeaderWeight + VarintWeight + TxWeights.

%% Block size without witness data.
stripped_size(#block{} = Block) ->
    %% Encode without witness
    NoWitness = beamchain_serialize:encode_block(
        Block#block{transactions =
            [strip_witness(Tx) || Tx <- Block#block.transactions]}),
    byte_size(NoWitness).

strip_witness(#transaction{inputs = Inputs} = Tx) ->
    Tx#transaction{inputs =
        [In#tx_in{witness = []} || In <- Inputs]}.

%% Find a transaction in the mempool or on-chain.
%% Returns {ok, Tx, BlockHash | undefined, Height | -1, Position | -1}
find_transaction(Txid) ->
    %% Check mempool first
    case beamchain_mempool:get_tx(Txid) of
        {ok, Tx} ->
            {ok, Tx, undefined, -1, -1};
        not_found ->
            %% Check tx index
            case beamchain_db:get_tx_location(Txid) of
                {ok, #{block_hash := BlockHash, height := Height,
                       position := Pos}} ->
                    case beamchain_db:get_block(BlockHash) of
                        {ok, #block{transactions = Txs}} ->
                            case Pos < length(Txs) of
                                true ->
                                    Tx = lists:nth(Pos + 1, Txs),
                                    {ok, Tx, BlockHash, Height, Pos};
                                false ->
                                    not_found
                            end;
                        _ -> not_found
                    end;
                not_found ->
                    not_found
            end
    end.

%% Get block timestamp by height.
block_time(Height) ->
    case beamchain_db:get_block_index(Height) of
        {ok, #{header := Hdr}} -> Hdr#block_header.timestamp;
        _ -> 0
    end.

%% Format a UTXO for gettxout response.
format_utxo_result(Value, Script, Confirmations, IsCoinbase) ->
    Network = beamchain_config:network(),
    NetType = case Network of mainnet -> mainnet; _ -> testnet end,
    Type = beamchain_address:classify_script(Script),
    Address = beamchain_address:script_to_address(Script, NetType),
    #{
        <<"bestblock">> => case beamchain_chainstate:get_tip() of
            {ok, {H, _}} -> hash_to_hex(H);
            _ -> <<>>
        end,
        <<"confirmations">> => Confirmations,
        <<"value">> => satoshi_to_btc(Value),
        <<"scriptPubKey">> => #{
            <<"hex">> => beamchain_serialize:hex_encode(Script),
            <<"type">> => script_type_name(Type),
            <<"address">> => case Address of
                unknown -> null;
                "OP_RETURN" -> null;
                Addr -> iolist_to_binary(Addr)
            end
        },
        <<"coinbase">> => IsCoinbase
    }.

%% Format IP:Port as binary string.
format_addr({A, B, C, D}, Port) ->
    iolist_to_binary(io_lib:format("~B.~B.~B.~B:~B", [A, B, C, D, Port]));
format_addr(IP, Port) ->
    iolist_to_binary(io_lib:format("~p:~B", [IP, Port])).

%% Parse "host:port" into {ok, IP, Port} or {error, Msg}.
parse_node_addr(Str) when is_binary(Str) ->
    parse_node_addr(binary_to_list(Str));
parse_node_addr(Str) when is_list(Str) ->
    Params = beamchain_config:network_params(),
    DefaultPort = Params#network_params.default_port,
    case string:split(Str, ":") of
        [Host, PortStr] ->
            case catch list_to_integer(PortStr) of
                Port when is_integer(Port) ->
                    resolve_host(Host, Port);
                _ ->
                    {error, <<"Invalid port">>}
            end;
        [Host] ->
            resolve_host(Host, DefaultPort);
        _ ->
            {error, <<"Invalid address format">>}
    end.

resolve_host(Host, Port) ->
    case inet:parse_address(Host) of
        {ok, IP} ->
            {ok, IP, Port};
        {error, _} ->
            case inet:getaddr(Host, inet) of
                {ok, IP} -> {ok, IP, Port};
                {error, _} -> {error, <<"Could not resolve host">>}
            end
    end.

%% Convert service flags to names.
services_to_names(Services) ->
    Flags = [
        {?NODE_NETWORK, <<"NETWORK">>},
        {?NODE_BLOOM, <<"BLOOM">>},
        {?NODE_WITNESS, <<"WITNESS">>},
        {?NODE_NETWORK_LIMITED, <<"NETWORK_LIMITED">>}
    ],
    [Name || {Flag, Name} <- Flags, (Services band Flag) =/= 0].

%% Format a mempool entry for getrawmempool verbose / getmempoolentry.
format_mempool_entry(#mempool_entry{fee = Fee, vsize = Vsize,
        weight = Weight, time_added = TimeAdded,
        height_added = HeightAdded,
        ancestor_count = AncCount, ancestor_size = AncSize,
        ancestor_fee = AncFee,
        descendant_count = DescCount, descendant_size = DescSize,
        descendant_fee = DescFee, rbf_signaling = Bip125}) ->
    #{
        <<"vsize">> => Vsize,
        <<"weight">> => Weight,
        <<"fee">> => satoshi_to_btc(Fee),
        <<"modifiedfee">> => satoshi_to_btc(Fee),
        <<"time">> => TimeAdded,
        <<"height">> => HeightAdded,
        <<"descendantcount">> => DescCount,
        <<"descendantsize">> => DescSize,
        <<"descendantfees">> => DescFee,
        <<"ancestorcount">> => AncCount,
        <<"ancestorsize">> => AncSize,
        <<"ancestorfees">> => AncFee,
        <<"depends">> => [],
        <<"spentby">> => [],
        <<"bip125-replaceable">> => Bip125,
        <<"fees">> => #{
            <<"base">> => satoshi_to_btc(Fee),
            <<"modified">> => satoshi_to_btc(Fee),
            <<"ancestor">> => satoshi_to_btc(AncFee),
            <<"descendant">> => satoshi_to_btc(DescFee)
        }
    };
format_mempool_entry(_) ->
    #{<<"error">> => <<"failed to format entry">>}.

%%% ===================================================================
%%% Wallet methods
%%% ===================================================================

%% @doc Create a new wallet.
%% createwallet "name" - Creates a new wallet with the given name.
rpc_createwallet([]) ->
    rpc_createwallet([<<>>]);  %% Default wallet name
rpc_createwallet([Name]) when is_binary(Name) ->
    case beamchain_wallet_sup:create_wallet(Name) of
        {ok, _Pid} ->
            WalletName = case Name of
                <<>> -> <<"default">>;
                _ -> Name
            end,
            {ok, #{
                <<"name">> => WalletName,
                <<"warning">> => <<>>
            }};
        {error, wallet_already_loaded} ->
            {error, ?RPC_MISC_ERROR, <<"Wallet already loaded">>};
        {error, Reason} ->
            {error, ?RPC_MISC_ERROR, iolist_to_binary(
                io_lib:format("Failed to create wallet: ~p", [Reason]))}
    end;
rpc_createwallet(_) ->
    {error, ?RPC_INVALID_PARAMS, <<"createwallet ( \"name\" )">>}.

%% @doc Load a wallet from file.
%% loadwallet "name" - Loads wallet with the given name.
rpc_loadwallet([Name]) when is_binary(Name) ->
    case beamchain_wallet_sup:load_wallet(Name) of
        {ok, _Pid} ->
            WalletName = case Name of
                <<>> -> <<"default">>;
                _ -> Name
            end,
            {ok, #{
                <<"name">> => WalletName,
                <<"warning">> => <<>>
            }};
        {error, wallet_already_loaded} ->
            {error, ?RPC_MISC_ERROR, <<"Wallet already loaded">>};
        {error, Reason} ->
            {error, ?RPC_MISC_ERROR, iolist_to_binary(
                io_lib:format("Failed to load wallet: ~p", [Reason]))}
    end;
rpc_loadwallet(_) ->
    {error, ?RPC_INVALID_PARAMS, <<"loadwallet \"name\"">>}.

%% @doc Unload a wallet.
%% unloadwallet "name" - Unloads the wallet with the given name.
rpc_unloadwallet([]) ->
    rpc_unloadwallet([<<>>]);  %% Default wallet
rpc_unloadwallet([Name]) when is_binary(Name) ->
    case beamchain_wallet_sup:unload_wallet(Name) of
        ok ->
            WalletName = case Name of
                <<>> -> <<"default">>;
                _ -> Name
            end,
            {ok, #{
                <<"name">> => WalletName,
                <<"warning">> => <<>>
            }};
        {error, wallet_not_found} ->
            {error, ?RPC_MISC_ERROR, <<"Wallet not found">>};
        {error, Reason} ->
            {error, ?RPC_MISC_ERROR, iolist_to_binary(
                io_lib:format("Failed to unload wallet: ~p", [Reason]))}
    end;
rpc_unloadwallet(_) ->
    {error, ?RPC_INVALID_PARAMS, <<"unloadwallet ( \"name\" )">>}.

%% @doc List all loaded wallets.
rpc_listwallets() ->
    Names = beamchain_wallet_sup:list_wallets(),
    DisplayNames = [case N of <<>> -> <<"default">>; _ -> N end || N <- Names],
    {ok, DisplayNames}.

%% @doc Get a new address from the specified wallet.
rpc_getnewaddress(Params, WalletName) ->
    case resolve_wallet(WalletName) of
        {ok, Pid} ->
            {_Label, Type} = parse_getnewaddress_params(Params),
            AddrType = address_type_from_rpc(Type),
            case beamchain_wallet:get_new_address(Pid, AddrType) of
                {ok, Address} ->
                    {ok, iolist_to_binary(Address)};
                {error, no_wallet} ->
                    {error, ?RPC_MISC_ERROR, <<"No wallet loaded">>};
                {error, Reason} ->
                    {error, ?RPC_MISC_ERROR, iolist_to_binary(
                        io_lib:format("~p", [Reason]))}
            end;
        {error, _} ->
            wallet_not_found_error(WalletName)
    end.

parse_getnewaddress_params([]) -> {<<>>, <<"bech32">>};
parse_getnewaddress_params([Label]) -> {Label, <<"bech32">>};
parse_getnewaddress_params([Label, Type]) -> {Label, Type};
parse_getnewaddress_params(_) -> {<<>>, <<"bech32">>}.

%% @doc Get a change address from the specified wallet.
rpc_getrawchangeaddress(Params, WalletName) ->
    case resolve_wallet(WalletName) of
        {ok, Pid} ->
            Type = case Params of
                [] -> <<"bech32">>;
                [T] -> T;
                _ -> <<"bech32">>
            end,
            AddrType = address_type_from_rpc(Type),
            case beamchain_wallet:get_change_address(Pid, AddrType) of
                {ok, Address} ->
                    {ok, iolist_to_binary(Address)};
                {error, no_wallet} ->
                    {error, ?RPC_MISC_ERROR, <<"No wallet loaded">>};
                {error, Reason} ->
                    {error, ?RPC_MISC_ERROR, iolist_to_binary(
                        io_lib:format("~p", [Reason]))}
            end;
        {error, _} ->
            wallet_not_found_error(WalletName)
    end.

%% @doc Get balance from the specified wallet.
rpc_getbalance(WalletName) ->
    case resolve_wallet(WalletName) of
        {ok, Pid} ->
            case beamchain_wallet:get_balance(Pid) of
                {ok, Satoshis} ->
                    {ok, satoshi_to_btc(Satoshis)};
                {error, no_wallet} ->
                    {error, ?RPC_MISC_ERROR, <<"No wallet loaded">>};
                {error, Reason} ->
                    {error, ?RPC_MISC_ERROR, iolist_to_binary(
                        io_lib:format("~p", [Reason]))}
            end;
        {error, _} ->
            wallet_not_found_error(WalletName)
    end.

%% @doc List addresses from the specified wallet.
rpc_listaddresses(WalletName) ->
    case resolve_wallet(WalletName) of
        {ok, Pid} ->
            case beamchain_wallet:list_addresses(Pid) of
                {ok, Addresses} ->
                    {ok, Addresses};
                {error, no_wallet} ->
                    {error, ?RPC_MISC_ERROR, <<"No wallet loaded">>};
                {error, Reason} ->
                    {error, ?RPC_MISC_ERROR, iolist_to_binary(
                        io_lib:format("~p", [Reason]))}
            end;
        {error, _} ->
            wallet_not_found_error(WalletName)
    end.

%% @doc Get wallet info from the specified wallet.
rpc_getwalletinfo(WalletName) ->
    case resolve_wallet(WalletName) of
        {ok, Pid} ->
            case beamchain_wallet:get_wallet_info(Pid) of
                {ok, Info} ->
                    Balance = case beamchain_wallet:get_balance(Pid) of
                        {ok, B} -> B;
                        _ -> 0
                    end,
                    WalletNameDisplay = case maps:get(wallet_name, Info, <<>>) of
                        <<>> -> <<"default">>;
                        N -> N
                    end,
                    Encrypted = maps:get(encrypted, Info, false),
                    Locked = maps:get(locked, Info, false),
                    BaseInfo = #{
                        <<"walletname">> => WalletNameDisplay,
                        <<"walletversion">> => 1,
                        <<"format">> => <<"json">>,
                        <<"balance">> => satoshi_to_btc(Balance),
                        <<"unconfirmed_balance">> => 0.0,
                        <<"immature_balance">> => 0.0,
                        <<"txcount">> => 0,
                        <<"keypoolsize">> => maps:get(addresses, Info, 0),
                        <<"paytxfee">> => 0.0,
                        <<"private_keys_enabled">> => true,
                        <<"avoid_reuse">> => false,
                        <<"scanning">> => false
                    },
                    InfoWithEncryption = case Encrypted of
                        true ->
                            BaseInfo#{
                                <<"unlocked_until">> => case Locked of
                                    true -> 0;
                                    false -> 9999999999
                                end
                            };
                        false ->
                            BaseInfo
                    end,
                    {ok, InfoWithEncryption};
                {error, Reason} ->
                    {error, ?RPC_MISC_ERROR, iolist_to_binary(
                        io_lib:format("~p", [Reason]))}
            end;
        {error, _} ->
            wallet_not_found_error(WalletName)
    end.

%% @doc Dump private key for an address from the specified wallet.
rpc_dumpprivkey([Address], WalletName) when is_binary(Address) ->
    case resolve_wallet(WalletName) of
        {ok, Pid} ->
            case beamchain_wallet:get_private_key(Pid, binary_to_list(Address)) of
                {ok, PrivKey} ->
                    WIF = privkey_to_wif(PrivKey),
                    {ok, iolist_to_binary(WIF)};
                {error, not_found} ->
                    {error, ?RPC_INVALID_ADDRESS_OR_KEY,
                     <<"Private key for address not found">>};
                {error, wallet_locked} ->
                    {error, ?RPC_MISC_ERROR,
                     <<"Error: Please enter the wallet passphrase with walletpassphrase first.">>};
                {error, Reason} ->
                    {error, ?RPC_MISC_ERROR, iolist_to_binary(
                        io_lib:format("~p", [Reason]))}
            end;
        {error, _} ->
            wallet_not_found_error(WalletName)
    end;
rpc_dumpprivkey(_, _WalletName) ->
    {error, ?RPC_INVALID_PARAMS, <<"dumpprivkey \"address\"">>}.

%% @doc Resolve wallet name to pid.
%% For default wallet (<<>> or URL without wallet path), use registered beamchain_wallet.
%% For named wallets, look up in wallet_sup registry.
resolve_wallet(<<>>) ->
    %% Default wallet - try registered name first, then wallet_sup
    case whereis(beamchain_wallet) of
        undefined ->
            beamchain_wallet_sup:get_wallet(<<>>);
        Pid ->
            {ok, Pid}
    end;
resolve_wallet(Name) when is_binary(Name) ->
    beamchain_wallet_sup:get_wallet(Name).

%% @doc Return error for wallet not found.
wallet_not_found_error(<<>>) ->
    {error, ?RPC_MISC_ERROR, <<"No wallet loaded">>};
wallet_not_found_error(Name) ->
    {error, ?RPC_MISC_ERROR, iolist_to_binary(
        io_lib:format("Wallet \"~s\" not found", [Name]))}.

%% @doc Send to address (multi-wallet aware).
rpc_sendtoaddress([Address, AmountBtc], WalletName) when is_binary(Address) ->
    rpc_sendtoaddress([Address, AmountBtc, <<>>], WalletName);
rpc_sendtoaddress([Address, AmountBtc, _Comment], WalletName) when is_binary(Address) ->
    case resolve_wallet(WalletName) of
        {ok, _Pid} ->
            Amount = btc_to_satoshi(AmountBtc),
            %% Get wallet UTXOs for coin selection
            Utxos = beamchain_wallet:get_wallet_utxos(),
            %% Use default fee rate (1 sat/vB for now)
            FeeRate = 1,
            case beamchain_wallet:select_coins(Amount, FeeRate, Utxos) of
                {ok, Selected, Change} ->
                    %% Build and sign transaction
                    Network = beamchain_config:network(),
                    Outputs = [{binary_to_list(Address), Amount}],
                    %% Add change output if needed
                    FinalOutputs = case Change > 546 of  %% Dust threshold
                        true ->
                            {ok, ChangeAddr} = beamchain_wallet:get_change_address(p2wpkh),
                            Outputs ++ [{ChangeAddr, Change}];
                        false ->
                            Outputs
                    end,
                    case beamchain_wallet:build_transaction(Selected, FinalOutputs, Network) of
                        {ok, Tx} ->
                            %% Get private keys for inputs
                            PrivKeys = lists:map(fun({_Txid, _Vout, _Utxo}) ->
                                %% TODO: Look up privkey from address
                                %% For now, this is a placeholder
                                <<0:256>>
                            end, Selected),
                            InputUtxos = [U || {_, _, U} <- Selected],
                            case beamchain_wallet:sign_transaction(Tx, InputUtxos, PrivKeys) of
                                {ok, SignedTx} ->
                                    %% Broadcast transaction
                                    case beamchain_mempool:accept_to_memory_pool(SignedTx) of
                                        {ok, Txid} ->
                                            {ok, beamchain_serialize:hex_encode(Txid)};
                                        {error, Reason} ->
                                            {error, ?RPC_VERIFY_REJECTED, iolist_to_binary(
                                                io_lib:format("TX rejected: ~p", [Reason]))}
                                    end;
                                {error, Reason} ->
                                    {error, ?RPC_MISC_ERROR, iolist_to_binary(
                                        io_lib:format("Signing failed: ~p", [Reason]))}
                            end;
                        {error, Reason} ->
                            {error, ?RPC_MISC_ERROR, iolist_to_binary(
                                io_lib:format("TX build failed: ~p", [Reason]))}
                    end;
                {error, insufficient_funds} ->
                    {error, ?RPC_MISC_ERROR, <<"Insufficient funds">>}
            end;
        {error, _} ->
            wallet_not_found_error(WalletName)
    end;
rpc_sendtoaddress(_, _WalletName) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"sendtoaddress \"address\" amount ( \"comment\" )">>}.

%% @doc List unspent outputs (multi-wallet aware).
rpc_listunspent(Params, WalletName) ->
    case resolve_wallet(WalletName) of
        {ok, _Pid} ->
            {MinConf, MaxConf} = case Params of
                [] -> {0, 9999999};
                [Min, Max] -> {Min, Max};
                _ -> {0, 9999999}
            end,
            Utxos = beamchain_wallet:get_wallet_utxos(),
            case beamchain_chainstate:get_tip() of
                {ok, {_, CurrentHeight}} ->
                    Filtered = lists:filtermap(fun({Txid, Vout, Utxo}) ->
                        Confs = CurrentHeight - Utxo#utxo.height + 1,
                        case Confs >= MinConf andalso Confs =< MaxConf of
                            true ->
                                Network = beamchain_config:network(),
                                Address = case beamchain_address:script_to_address(
                                              Utxo#utxo.script_pubkey, Network) of
                                    unknown -> <<>>;
                                    A -> iolist_to_binary(A)
                                end,
                                {true, #{
                                    <<"txid">> => beamchain_serialize:hex_encode(Txid),
                                    <<"vout">> => Vout,
                                    <<"address">> => Address,
                                    <<"amount">> => satoshi_to_btc(Utxo#utxo.value),
                                    <<"confirmations">> => Confs,
                                    <<"spendable">> => true,
                                    <<"solvable">> => true,
                                    <<"safe">> => true
                                }};
                            false ->
                                false
                        end
                    end, Utxos),
                    {ok, Filtered};
                not_found ->
                    {ok, []}
            end;
        {error, _} ->
            wallet_not_found_error(WalletName)
    end.

%% @doc List transactions (multi-wallet aware).
rpc_listtransactions(_Params, WalletName) ->
    case resolve_wallet(WalletName) of
        {ok, _Pid} ->
            %% TODO: Implement transaction history
            %% For now, return empty list
            {ok, []};
        {error, _} ->
            wallet_not_found_error(WalletName)
    end.

%% @doc Encrypt the wallet with a passphrase (multi-wallet aware).
rpc_encryptwallet([Passphrase], WalletName) when is_binary(Passphrase) ->
    case resolve_wallet(WalletName) of
        {ok, Pid} ->
            case gen_server:call(Pid, {encryptwallet, Passphrase}) of
                ok ->
                    {ok, <<"wallet encrypted; The keypool has been flushed and a new HD seed "
                           "was generated. You need to make a new backup.">>};
                {error, no_wallet} ->
                    {error, ?RPC_MISC_ERROR, <<"No wallet loaded">>};
                {error, already_encrypted} ->
                    {error, ?RPC_MISC_ERROR, <<"Wallet is already encrypted">>};
                {error, Reason} ->
                    {error, ?RPC_MISC_ERROR, iolist_to_binary(
                        io_lib:format("Failed to encrypt wallet: ~p", [Reason]))}
            end;
        {error, _} ->
            wallet_not_found_error(WalletName)
    end;
rpc_encryptwallet(_, _WalletName) ->
    {error, ?RPC_INVALID_PARAMS, <<"encryptwallet \"passphrase\"">>}.

%% @doc Unlock the wallet for the specified timeout (multi-wallet aware).
rpc_walletpassphrase([Passphrase, Timeout], WalletName) when is_binary(Passphrase), is_integer(Timeout) ->
    case resolve_wallet(WalletName) of
        {ok, Pid} ->
            case gen_server:call(Pid, {walletpassphrase, Passphrase, Timeout}) of
                ok ->
                    {ok, null};
                {error, not_encrypted} ->
                    {error, ?RPC_MISC_ERROR,
                     <<"Error: running with an unencrypted wallet, but walletpassphrase was called.">>};
                {error, already_unlocked} ->
                    {ok, null};
                {error, wrong_passphrase} ->
                    {error, ?RPC_INVALID_PARAMS, <<"Error: The wallet passphrase entered was incorrect.">>};
                {error, Reason} ->
                    {error, ?RPC_MISC_ERROR, iolist_to_binary(
                        io_lib:format("Failed to unlock wallet: ~p", [Reason]))}
            end;
        {error, _} ->
            wallet_not_found_error(WalletName)
    end;
rpc_walletpassphrase(_, _WalletName) ->
    {error, ?RPC_INVALID_PARAMS, <<"walletpassphrase \"passphrase\" timeout">>}.

%% @doc Lock the wallet immediately (multi-wallet aware).
rpc_walletlock(WalletName) ->
    case resolve_wallet(WalletName) of
        {ok, Pid} ->
            case gen_server:call(Pid, walletlock) of
                ok ->
                    {ok, null};
                {error, not_encrypted} ->
                    {error, ?RPC_MISC_ERROR,
                     <<"Error: running with an unencrypted wallet, but walletlock was called.">>};
                {error, Reason} ->
                    {error, ?RPC_MISC_ERROR, iolist_to_binary(
                        io_lib:format("Failed to lock wallet: ~p", [Reason]))}
            end;
        {error, _} ->
            wallet_not_found_error(WalletName)
    end.

%% Helper: Convert RPC address type to atom
address_type_from_rpc(Type) when is_binary(Type) ->
    case string:lowercase(binary_to_list(Type)) of
        "bech32" -> p2wpkh;
        "bech32m" -> p2tr;
        "p2sh-segwit" -> p2wpkh;  %% Map to native segwit for simplicity
        "legacy" -> p2pkh;
        _ -> p2wpkh  %% Default to native segwit
    end;
address_type_from_rpc(_) ->
    p2wpkh.

%% Helper: Convert private key to WIF (Wallet Import Format)
privkey_to_wif(PrivKey) ->
    Network = beamchain_config:network(),
    Prefix = case Network of
        mainnet -> 16#80;
        _ -> 16#ef  %% testnet/regtest
    end,
    %% Add compression flag (0x01) for compressed keys
    Payload = <<PrivKey/binary, 16#01>>,
    beamchain_address:base58check_encode(Prefix, Payload).

%% Helper: Convert BTC to satoshis
btc_to_satoshi(Btc) when is_float(Btc) ->
    round(Btc * 100000000);
btc_to_satoshi(Btc) when is_integer(Btc) ->
    Btc * 100000000.

%%% ===================================================================
%%% Wallet signing and descriptor import
%%% ===================================================================

%% @doc signrawtransactionwithwallet: Sign inputs of a raw transaction using wallet keys.
%% Returns the signed hex and whether it is complete.
rpc_signrawtransactionwithwallet([HexStr], WalletName) when is_binary(HexStr) ->
    rpc_signrawtransactionwithwallet([HexStr, []], WalletName);
rpc_signrawtransactionwithwallet([HexStr, PrevTxs], WalletName) when is_binary(HexStr) ->
    case resolve_wallet(WalletName) of
        {ok, Pid} ->
            try
                TxBin = beamchain_serialize:hex_decode(HexStr),
                {Tx, _} = beamchain_serialize:decode_transaction(TxBin),
                %% Gather UTXO data for signing (from prevtxs param or UTXO set)
                InputUtxos = lists:map(fun(#tx_in{prev_out = #outpoint{hash = H, index = I}}) ->
                    case find_prevtx(PrevTxs, H, I) of
                        {ok, Utxo} -> Utxo;
                        not_found ->
                            case beamchain_chainstate:get_utxo(H, I) of
                                {ok, Utxo} -> Utxo;
                                not_found -> throw({missing_input, H, I})
                            end
                    end
                end, Tx#transaction.inputs),
                %% Get private keys from wallet for each input
                PrivKeys = lists:map(fun(Utxo) ->
                    Address = beamchain_address:script_to_address(
                        Utxo#utxo.script_pubkey, beamchain_config:network()),
                    case beamchain_wallet:get_private_key(Pid, Address) of
                        {ok, Key} -> Key;
                        _ -> <<0:256>>  %% Placeholder for keys not in this wallet
                    end
                end, InputUtxos),
                case beamchain_wallet:sign_transaction(Tx, InputUtxos, PrivKeys) of
                    {ok, SignedTx} ->
                        SignedHex = beamchain_serialize:hex_encode(
                            beamchain_serialize:encode_transaction(SignedTx)),
                        Complete = lists:all(fun(K) -> K =/= <<0:256>> end, PrivKeys),
                        {ok, #{
                            <<"hex">> => SignedHex,
                            <<"complete">> => Complete
                        }};
                    {error, Reason} ->
                        {error, ?RPC_MISC_ERROR, iolist_to_binary(
                            io_lib:format("Signing error: ~p", [Reason]))}
                end
            catch
                _:Err ->
                    {error, ?RPC_MISC_ERROR,
                     iolist_to_binary(io_lib:format("Error: ~p", [Err]))}
            end;
        {error, _} ->
            wallet_not_found_error(WalletName)
    end;
rpc_signrawtransactionwithwallet(_, _) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: signrawtransactionwithwallet \"hexstring\" ( prevtxs )">>}.

%% Helper: find a previous tx output from the prevtxs parameter.
find_prevtx([], _Hash, _Index) -> not_found;
find_prevtx([#{<<"txid">> := TxidHex, <<"vout">> := Vout,
               <<"scriptPubKey">> := ScriptHex} = Map | Rest], Hash, Index) ->
    case {hex_to_internal_hash(TxidHex), Vout} of
        {Hash, Index} ->
            Amount = maps:get(<<"amount">>, Map, 0),
            {ok, #utxo{
                value = btc_to_satoshi(Amount),
                script_pubkey = beamchain_serialize:hex_decode(ScriptHex),
                height = 0,
                is_coinbase = false
            }};
        _ ->
            find_prevtx(Rest, Hash, Index)
    end;
find_prevtx([_ | Rest], Hash, Index) ->
    find_prevtx(Rest, Hash, Index).

%% @doc importdescriptors: Import descriptors into the wallet.
%% Takes an array of descriptor request objects.
rpc_importdescriptors([Requests], WalletName) when is_list(Requests) ->
    case resolve_wallet(WalletName) of
        {ok, Pid} ->
            Results = lists:map(fun(#{<<"desc">> := DescStr} = Req) ->
                Timestamp = maps:get(<<"timestamp">>, Req, <<"now">>),
                Internal = maps:get(<<"internal">>, Req, false),
                Range = maps:get(<<"range">>, Req, null),
                Label = maps:get(<<"label">>, Req, <<>>),
                try
                    case beamchain_descriptor:parse(DescStr) of
                        {ok, Desc} ->
                            %% Derive addresses for the descriptor range
                            Addresses = case Range of
                                [Start, End] when is_integer(Start), is_integer(End) ->
                                    case beamchain_descriptor:expand(Desc, {Start, End}) of
                                        {ok, Addrs} -> Addrs;
                                        {error, _} -> []
                                    end;
                                _ ->
                                    case beamchain_descriptor:derive(Desc, 0) of
                                        {ok, Addr} -> [Addr];
                                        {error, _} -> []
                                    end
                            end,
                            %% Import each derived address into the wallet
                            lists:foreach(fun(Addr) ->
                                beamchain_wallet:import_address(Pid, Addr, Label,
                                    Internal, Timestamp)
                            end, Addresses),
                            #{<<"success">> => true};
                        {error, ParseErr} ->
                            #{<<"success">> => false,
                              <<"error">> => #{
                                  <<"code">> => ?RPC_INVALID_PARAMETER,
                                  <<"message">> => iolist_to_binary(
                                      io_lib:format("Invalid descriptor: ~p", [ParseErr]))
                              }}
                    end
                catch
                    _:Err ->
                        #{<<"success">> => false,
                          <<"error">> => #{
                              <<"code">> => ?RPC_MISC_ERROR,
                              <<"message">> => iolist_to_binary(
                                  io_lib:format("Error: ~p", [Err]))
                          }}
                end;
            (_InvalidReq) ->
                #{<<"success">> => false,
                  <<"error">> => #{
                      <<"code">> => ?RPC_INVALID_PARAMS,
                      <<"message">> => <<"Missing required field 'desc'">>
                  }}
            end, Requests),
            {ok, Results};
        {error, _} ->
            wallet_not_found_error(WalletName)
    end;
rpc_importdescriptors(_, _) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: importdescriptors \"requests\"">>}.

%%% ===================================================================
%%% PSBT methods (BIP 174)
%%% ===================================================================

%% @doc Create a PSBT from inputs and outputs.
%% createpsbt [{"txid":"hex","vout":n},...] [{"address":amount},...] (locktime)
rpc_createpsbt([Inputs, Outputs]) ->
    rpc_createpsbt([Inputs, Outputs, 0]);
rpc_createpsbt([Inputs, Outputs, Locktime]) when is_list(Inputs),
                                                   is_list(Outputs) ->
    try
        Network = beamchain_config:network(),
        %% Build transaction inputs
        TxIns = lists:map(fun(InputObj) ->
            TxidHex = maps:get(<<"txid">>, InputObj),
            Vout = maps:get(<<"vout">>, InputObj),
            Txid = hex_to_internal_hash(TxidHex),
            Seq = maps:get(<<"sequence">>, InputObj, 16#fffffffd),
            #tx_in{
                prev_out = #outpoint{hash = Txid, index = Vout},
                script_sig = <<>>,
                sequence = Seq,
                witness = []
            }
        end, Inputs),
        %% Build transaction outputs
        TxOuts = lists:flatmap(fun(OutputObj) ->
            maps:fold(fun(AddrBin, Amount, Acc) ->
                Address = binary_to_list(AddrBin),
                {ok, Script} = beamchain_address:address_to_script(Address, Network),
                Satoshis = btc_to_satoshi(Amount),
                [#tx_out{value = Satoshis, script_pubkey = Script} | Acc]
            end, [], OutputObj)
        end, Outputs),
        %% Create unsigned transaction
        Tx = #transaction{
            version = 2,
            inputs = TxIns,
            outputs = TxOuts,
            locktime = Locktime
        },
        %% Create PSBT
        case beamchain_psbt:create(Tx) of
            {ok, Psbt} ->
                PsbtBin = beamchain_psbt:encode(Psbt),
                PsbtB64 = base64:encode(PsbtBin),
                {ok, PsbtB64};
            {error, Reason} ->
                {error, ?RPC_MISC_ERROR,
                 iolist_to_binary(io_lib:format("PSBT creation failed: ~p", [Reason]))}
        end
    catch
        _:Err ->
            {error, ?RPC_INVALID_PARAMS,
             iolist_to_binary(io_lib:format("Invalid parameters: ~p", [Err]))}
    end;
rpc_createpsbt(_) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"createpsbt [{\"txid\":\"hex\",\"vout\":n},...] [{\"address\":amount},...] (locktime)">>}.

%% @doc Decode a PSBT and return its structure.
rpc_decodepsbt([PsbtB64]) when is_binary(PsbtB64) ->
    try
        PsbtBin = base64:decode(PsbtB64),
        case beamchain_psbt:decode(PsbtBin) of
            {ok, Psbt} ->
                {ok, format_psbt_decode(Psbt)};
            {error, Reason} ->
                {error, ?RPC_DESERIALIZATION_ERROR,
                 iolist_to_binary(io_lib:format("PSBT decode failed: ~p", [Reason]))}
        end
    catch
        error:badarg ->
            {error, ?RPC_DESERIALIZATION_ERROR, <<"Invalid base64 encoding">>};
        _:Err ->
            {error, ?RPC_DESERIALIZATION_ERROR,
             iolist_to_binary(io_lib:format("Decode error: ~p", [Err]))}
    end;
rpc_decodepsbt(_) ->
    {error, ?RPC_INVALID_PARAMS, <<"decodepsbt \"psbt\"">>}.

%% @doc Combine multiple PSBTs into one.
rpc_combinepsbt([Psbts]) when is_list(Psbts) ->
    try
        DecodedPsbts = lists:map(fun(PsbtB64) ->
            PsbtBin = base64:decode(PsbtB64),
            case beamchain_psbt:decode(PsbtBin) of
                {ok, P} -> P;
                {error, R} -> throw({decode_error, R})
            end
        end, Psbts),
        case beamchain_psbt:combine(DecodedPsbts) of
            {ok, Combined} ->
                CombinedBin = beamchain_psbt:encode(Combined),
                {ok, base64:encode(CombinedBin)};
            {error, CombineReason} ->
                {error, ?RPC_MISC_ERROR,
                 iolist_to_binary(io_lib:format("Combine failed: ~p", [CombineReason]))}
        end
    catch
        throw:{decode_error, DecodeReason} ->
            {error, ?RPC_DESERIALIZATION_ERROR,
             iolist_to_binary(io_lib:format("PSBT decode failed: ~p", [DecodeReason]))};
        error:badarg ->
            {error, ?RPC_DESERIALIZATION_ERROR, <<"Invalid base64 encoding">>};
        _:Err ->
            {error, ?RPC_MISC_ERROR,
             iolist_to_binary(io_lib:format("Error: ~p", [Err]))}
    end;
rpc_combinepsbt(_) ->
    {error, ?RPC_INVALID_PARAMS, <<"combinepsbt [\"psbt\",...]">>}.

%% @doc Finalize a PSBT and optionally extract the final transaction.
rpc_finalizepsbt([PsbtB64]) ->
    rpc_finalizepsbt([PsbtB64, true]);
rpc_finalizepsbt([PsbtB64, Extract]) when is_binary(PsbtB64) ->
    try
        PsbtBin = base64:decode(PsbtB64),
        case beamchain_psbt:decode(PsbtBin) of
            {ok, Psbt} ->
                case beamchain_psbt:finalize(Psbt) of
                    {ok, FinalizedPsbt} ->
                        FinalizedBin = beamchain_psbt:encode(FinalizedPsbt),
                        FinalizedB64 = base64:encode(FinalizedBin),
                        case Extract of
                            true ->
                                case beamchain_psbt:extract(FinalizedPsbt) of
                                    {ok, Tx} ->
                                        TxHex = beamchain_serialize:hex_encode(
                                            beamchain_serialize:encode_transaction(Tx)),
                                        {ok, #{
                                            <<"hex">> => TxHex,
                                            <<"complete">> => true
                                        }};
                                    {error, _} ->
                                        {ok, #{
                                            <<"psbt">> => FinalizedB64,
                                            <<"complete">> => false
                                        }}
                                end;
                            _ ->
                                {ok, #{
                                    <<"psbt">> => FinalizedB64,
                                    <<"complete">> => true
                                }}
                        end;
                    {error, Reason} ->
                        %% Return incomplete PSBT
                        {ok, #{
                            <<"psbt">> => PsbtB64,
                            <<"complete">> => false,
                            <<"error">> => iolist_to_binary(
                                io_lib:format("~p", [Reason]))
                        }}
                end;
            {error, Reason} ->
                {error, ?RPC_DESERIALIZATION_ERROR,
                 iolist_to_binary(io_lib:format("PSBT decode failed: ~p", [Reason]))}
        end
    catch
        error:badarg ->
            {error, ?RPC_DESERIALIZATION_ERROR, <<"Invalid base64 encoding">>};
        _:Err ->
            {error, ?RPC_MISC_ERROR,
             iolist_to_binary(io_lib:format("Error: ~p", [Err]))}
    end;
rpc_finalizepsbt(_) ->
    {error, ?RPC_INVALID_PARAMS, <<"finalizepsbt \"psbt\" (extract)">>}.

%% Helper: Format PSBT for decodepsbt RPC
format_psbt_decode(Psbt) ->
    Tx = beamchain_psbt:get_unsigned_tx(Psbt),
    #{
        <<"tx">> => format_tx_json(Tx),
        <<"global_xpubs">> => [],  %% Simplified
        <<"psbt_version">> => beamchain_psbt:get_version(Psbt),
        <<"proprietary">> => [],
        <<"unknown">> => #{},
        <<"inputs">> => format_psbt_inputs(Psbt),
        <<"outputs">> => format_psbt_outputs(Psbt),
        <<"fee">> => null  %% Would need UTXO lookup
    }.

format_psbt_inputs(Psbt) ->
    Tx = beamchain_psbt:get_unsigned_tx(Psbt),
    lists:zipwith(fun(Input, Idx) ->
        InputMap = beamchain_psbt:get_input(Psbt, Idx),
        format_psbt_input(Input, InputMap)
    end, Tx#transaction.inputs, lists:seq(0, length(Tx#transaction.inputs) - 1)).

format_psbt_input(_Input, InputMap) ->
    Base = #{},
    %% Witness UTXO
    B1 = case maps:get(witness_utxo, InputMap, undefined) of
        {Value, ScriptPubKey} ->
            Base#{<<"witness_utxo">> => #{
                <<"amount">> => Value / 100000000.0,
                <<"scriptPubKey">> => #{
                    <<"hex">> => beamchain_serialize:hex_encode(ScriptPubKey)
                }
            }};
        _ -> Base
    end,
    %% Partial sigs
    B2 = case maps:get(partial_sigs, InputMap, undefined) of
        undefined -> B1;
        Sigs when map_size(Sigs) > 0 ->
            SigList = maps:fold(fun(PubKey, Sig, Acc) ->
                [#{<<"pubkey">> => beamchain_serialize:hex_encode(PubKey),
                   <<"signature">> => beamchain_serialize:hex_encode(Sig)} | Acc]
            end, [], Sigs),
            B1#{<<"partial_signatures">> => SigList};
        _ -> B1
    end,
    %% Sighash type
    B3 = case maps:get(sighash_type, InputMap, undefined) of
        undefined -> B2;
        SH -> B2#{<<"sighash">> => sighash_name(SH)}
    end,
    %% Redeem script
    B4 = case maps:get(redeem_script, InputMap, undefined) of
        undefined -> B3;
        RS -> B3#{<<"redeem_script">> => #{
            <<"hex">> => beamchain_serialize:hex_encode(RS)
        }}
    end,
    %% Witness script
    B5 = case maps:get(witness_script, InputMap, undefined) of
        undefined -> B4;
        WS -> B4#{<<"witness_script">> => #{
            <<"hex">> => beamchain_serialize:hex_encode(WS)
        }}
    end,
    %% Final scriptsig
    B6 = case maps:get(final_script_sig, InputMap, undefined) of
        undefined -> B5;
        FSS -> B5#{<<"final_scriptSig">> => #{
            <<"hex">> => beamchain_serialize:hex_encode(FSS)
        }}
    end,
    %% Final witness
    B7 = case maps:get(final_script_witness, InputMap, undefined) of
        undefined -> B6;
        FSW -> B6#{<<"final_scriptwitness">> =>
            [beamchain_serialize:hex_encode(W) || W <- FSW]}
    end,
    B7.

format_psbt_outputs(Psbt) ->
    Tx = beamchain_psbt:get_unsigned_tx(Psbt),
    lists:zipwith(fun(_Output, Idx) ->
        OutputMap = beamchain_psbt:get_output(Psbt, Idx),
        format_psbt_output(OutputMap)
    end, Tx#transaction.outputs, lists:seq(0, length(Tx#transaction.outputs) - 1)).

format_psbt_output(OutputMap) ->
    Base = #{},
    B1 = case maps:get(redeem_script, OutputMap, undefined) of
        undefined -> Base;
        RS -> Base#{<<"redeem_script">> => #{
            <<"hex">> => beamchain_serialize:hex_encode(RS)
        }}
    end,
    B2 = case maps:get(witness_script, OutputMap, undefined) of
        undefined -> B1;
        WS -> B1#{<<"witness_script">> => #{
            <<"hex">> => beamchain_serialize:hex_encode(WS)
        }}
    end,
    B2.

sighash_name(?SIGHASH_ALL) -> <<"ALL">>;
sighash_name(?SIGHASH_NONE) -> <<"NONE">>;
sighash_name(?SIGHASH_SINGLE) -> <<"SINGLE">>;
sighash_name(?SIGHASH_DEFAULT) -> <<"DEFAULT">>;
sighash_name(N) when N band ?SIGHASH_ANYONECANPAY =/= 0 ->
    Base = sighash_name(N band 16#1f),
    <<Base/binary, "|ANYONECANPAY">>;
sighash_name(N) ->
    iolist_to_binary(io_lib:format("UNKNOWN(~B)", [N])).

%%% ===================================================================
%%% Descriptor methods
%%% ===================================================================

%% deriveaddresses "descriptor" ( range )
%% Derives one or more addresses from an output descriptor.
rpc_deriveaddresses([DescStr]) ->
    %% Non-ranged descriptor: derive single address
    rpc_deriveaddresses([DescStr, 0]);
rpc_deriveaddresses([DescStr, Range]) when is_binary(DescStr) ->
    Network = beamchain_config:network(),
    try
        case beamchain_descriptor:parse(binary_to_list(DescStr)) of
            {ok, Desc} ->
                case beamchain_descriptor:is_solvable(Desc) of
                    false ->
                        {error, ?RPC_INVALID_ADDRESS_OR_KEY,
                         <<"Descriptor is not solvable">>};
                    true ->
                        derive_addresses_range(Desc, Range, Network)
                end;
            {error, Reason} ->
                {error, ?RPC_INVALID_PARAMETER,
                 iolist_to_binary(io_lib:format("Invalid descriptor: ~p", [Reason]))}
        end
    catch
        _:Err ->
            {error, ?RPC_MISC_ERROR,
             iolist_to_binary(io_lib:format("Error: ~p", [Err]))}
    end;
rpc_deriveaddresses(_) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"deriveaddresses \"descriptor\" ( range )">>}.

derive_addresses_range(Desc, Range, Network) ->
    IsRange = beamchain_descriptor:is_range(Desc),
    {Start, End} = parse_range(Range, IsRange),
    case Start > End of
        true ->
            {error, ?RPC_INVALID_PARAMETER, <<"Invalid range">>};
        false ->
            case beamchain_descriptor:expand(Desc, {Start, End}, Network) of
                {ok, Results} ->
                    Addresses = lists:map(fun({_Idx, Script}) ->
                        script_to_address_bin(Script, Network)
                    end, Results),
                    {ok, Addresses};
                {error, Reason} ->
                    {error, ?RPC_MISC_ERROR,
                     iolist_to_binary(io_lib:format("Derivation failed: ~p", [Reason]))}
            end
    end.

parse_range(N, _IsRange) when is_integer(N), N >= 0 ->
    %% Single index
    {N, N};
parse_range([Start, End], true) when is_integer(Start), is_integer(End) ->
    %% [start, end] range
    {Start, End};
parse_range([Start], true) when is_integer(Start) ->
    %% [start] means [0, start]
    {0, Start};
parse_range(_, false) ->
    %% Non-ranged descriptor, just use index 0
    {0, 0};
parse_range(_, _) ->
    {0, 0}.

script_to_address_bin(Script, Network) ->
    case beamchain_address:script_to_address(Script, Network) of
        unknown -> <<"unknown">>;
        "OP_RETURN" -> <<"OP_RETURN">>;
        Addr -> list_to_binary(Addr)
    end.

%% getdescriptorinfo "descriptor"
%% Analyses a descriptor string and returns information about it.
rpc_getdescriptorinfo([DescStr]) when is_binary(DescStr) ->
    try
        DescStrList = binary_to_list(DescStr),
        %% Strip checksum if present for computing the canonical descriptor
        Stripped = case string:rchr(DescStrList, $#) of
            0 -> DescStrList;
            Pos -> string:substr(DescStrList, 1, Pos - 1)
        end,
        case beamchain_descriptor:parse(Stripped) of
            {ok, Desc} ->
                Checksum = beamchain_descriptor:checksum(Stripped),
                WithChecksum = Stripped ++ "#" ++ Checksum,
                Result = #{
                    <<"descriptor">> => list_to_binary(WithChecksum),
                    <<"checksum">> => list_to_binary(Checksum),
                    <<"isrange">> => beamchain_descriptor:is_range(Desc),
                    <<"issolvable">> => beamchain_descriptor:is_solvable(Desc),
                    <<"hasprivatekeys">> => beamchain_descriptor:has_private_keys(Desc)
                },
                {ok, Result};
            {error, Reason} ->
                {error, ?RPC_INVALID_PARAMETER,
                 iolist_to_binary(io_lib:format("Invalid descriptor: ~p", [Reason]))}
        end
    catch
        _:Err ->
            {error, ?RPC_MISC_ERROR,
             iolist_to_binary(io_lib:format("Error: ~p", [Err]))}
    end;
rpc_getdescriptorinfo(_) ->
    {error, ?RPC_INVALID_PARAMS, <<"getdescriptorinfo \"descriptor\"">>}.

%%% ===================================================================
%%% assumeUTXO methods
%%% ===================================================================

%% @doc Core-strict whitelist check on a snapshot's base block height.
%% Mirrors bitcoin-core/src/validation.cpp:5775-5780. Returns `ok` if the
%% height is recognized in this network's `m_assumeutxo_data`, otherwise
%% `{error, BinMessage}` carrying the verbatim Core refusal string.
%% Exported so eunit can exercise the whitelist semantics without spinning
%% up beamchain_db / beamchain_chainstate.
-spec validate_snapshot_height(non_neg_integer(), atom()) ->
    ok | {error, binary()}.
validate_snapshot_height(BaseHeight, Network) ->
    case beamchain_chain_params:get_assumeutxo(BaseHeight, Network) of
        {ok, _AuData} ->
            ok;
        not_found ->
            Msg = iolist_to_binary(
                    io_lib:format(
                      "Assumeutxo height in snapshot metadata not "
                      "recognized (~b) - refusing to load snapshot",
                      [BaseHeight])),
            {error, Msg}
    end.

%% @doc Load a UTXO set snapshot from file.
%% Implements Bitcoin Core's loadtxoutset RPC.
%% The snapshot allows the node to start validating new blocks immediately
%% while validating the historical chain in the background.
rpc_loadtxoutset([Path]) when is_binary(Path) ->
    PathStr = binary_to_list(Path),

    %% First, read the snapshot metadata
    case beamchain_snapshot:read_metadata(PathStr) of
        {ok, #{base_hash := BaseHash, num_coins := NumCoins}} ->
            Network = beamchain_config:network(),

            %% Mirror bitcoin-core/src/validation.cpp:5765-5780. Core looks up
            %% the snapshot's base block in the block index to discover its
            %% height, then refuses if that height is not in
            %% m_assumeutxo_data. We do the same: resolve the hash via the
            %% block index, then strictly whitelist by height.
            case beamchain_db:get_block_index_by_hash(BaseHash) of
                {ok, #{height := BaseHeight}} ->
                    case validate_snapshot_height(BaseHeight, Network) of
                        ok ->
                            %% Load the snapshot into chainstate
                            case beamchain_chainstate:load_snapshot(PathStr) of
                                {ok, LoadedHeight} ->
                                    {ok, #{
                                        <<"base_blockhash">> => beamchain_serialize:hex_encode(BaseHash),
                                        <<"coins_loaded">> => NumCoins,
                                        <<"base_height">> => LoadedHeight,
                                        <<"message">> => <<"Snapshot loaded successfully. Background validation started.">>
                                    }};
                                {error, {snapshot_content_hash_mismatch, BinMsg}} ->
                                    %% Verbatim Core wording from
                                    %% validation.cpp:5912-5914 — surface
                                    %% it unwrapped so callers can match
                                    %% byte-for-byte.
                                    {error, ?RPC_MISC_ERROR, BinMsg};
                                {error, Reason} ->
                                    {error, ?RPC_MISC_ERROR,
                                     iolist_to_binary(io_lib:format("Failed to load snapshot: ~p", [Reason]))}
                            end;
                        {error, Msg} ->
                            {error, ?RPC_MISC_ERROR, Msg}
                    end;
                not_found ->
                    %% Mirrors validation.cpp:5770-5771 ("Did not find snapshot
                    %% start blockheader %s"). The hash is rendered in display
                    %% (big-endian) order to match Core's uint256::ToString.
                    DisplayHash = beamchain_serialize:hex_encode(
                                    beamchain_serialize:reverse_bytes(BaseHash)),
                    {error, ?RPC_MISC_ERROR,
                     iolist_to_binary([<<"Did not find snapshot start blockheader ">>,
                                       DisplayHash])}
            end;
        {error, Reason} ->
            {error, ?RPC_MISC_ERROR,
             iolist_to_binary(io_lib:format("Failed to read snapshot: ~p", [Reason]))}
    end;
rpc_loadtxoutset(_) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: loadtxoutset \"path/to/snapshot.dat\"">>}.

%% @doc Dump the current UTXO set to a file.
%% Creates a snapshot that can be loaded with loadtxoutset.
%%
%% Mirrors bitcoin-core/src/rpc/blockchain.cpp dumptxoutset which returns:
%%   coins_written  : NUM      - number of coins in the snapshot
%%   base_hash      : STR_HEX  - block hash at the snapshot's base
%%   base_height    : NUM      - block height at the snapshot's base
%%   path           : STR      - absolute path the snapshot was written to
%%   txoutset_hash  : STR_HEX  - HASH_SERIALIZED commitment over the UTXO set
%%   nchaintx       : NUM      - chain_tx_count up to and including the base
%%
%% Three modes (Core rpc/blockchain.cpp:3074):
%%   - "latest"   (default): dump current tip's UTXO set.
%%   - "rollback" (no height): rewind to the latest assumeutxo snapshot
%%     height ≤ tip, dump, then re-apply blocks back to the original tip.
%%   - "rollback" with options.rollback = <height|hash>: rewind to that
%%     specific block (must be on the active chain), dump, re-apply.
%%
%% txoutset_hash is the HASH_SERIALIZED commitment — SHA256d via HashWriter
%% over Core's TxOutSer per-coin layout (rpc/blockchain.cpp:3259 +
%% kernel/coinstats.cpp:161). Same digest that
%% m_assumeutxo_data.hash_serialized is matched against by loadtxoutset's
%% strict-content-hash gate. Display hex is uint256::ToString order
%% (reverse of internal byte order).
rpc_dumptxoutset([Path]) when is_binary(Path) ->
    rpc_dumptxoutset([Path, <<"latest">>, #{}]);
rpc_dumptxoutset([Path, Type]) when is_binary(Path), is_binary(Type) ->
    rpc_dumptxoutset([Path, Type, #{}]);
rpc_dumptxoutset([Path, Type, Options])
  when is_binary(Path), is_binary(Type), is_map(Options) ->
    case beamchain_chainstate:get_tip() of
        {ok, {TipHash, TipHeight}} ->
            Network = beamchain_config:network(),
            case resolve_dump_target(Type, Options, TipHash, TipHeight,
                                     Network) of
                {ok, {TipHash, TipHeight}} ->
                    %% Target == tip: simple dump, no rollback dance.
                    do_dump_at_tip(Path, TipHash, TipHeight, Network);
                {ok, {TargetHash, TargetHeight}} ->
                    do_dump_with_rollback(Path, TargetHash, TargetHeight,
                                          TipHash, TipHeight, Network);
                {error, Code, Msg} ->
                    {error, Code, Msg}
            end;
        not_found ->
            {error, ?RPC_MISC_ERROR, <<"No chain tip available">>}
    end;
rpc_dumptxoutset(_) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: dumptxoutset \"path\" ( \"type\" {\"rollback\":n|\"hash\"} )">>}.

%% Resolve the rollback target index from (Type, Options).
%% Returns {ok, {TargetHash, TargetHeight}} or {error, Code, Msg}.
%%
%% Mirrors bitcoin-core/src/rpc/blockchain.cpp:3115 — options.rollback
%% takes precedence; "rollback" without explicit height picks the latest
%% assumeutxo snapshot height ≤ tip; "latest"/"" returns the current tip;
%% any other type string is rejected.
resolve_dump_target(Type, Options, TipHash, TipHeight, Network) ->
    HasRollbackOpt = maps:is_key(<<"rollback">>, Options),
    case {Type, HasRollbackOpt} of
        {_, true} when Type =/= <<>>, Type =/= <<"rollback">> ->
            {error, ?RPC_INVALID_PARAMETER,
             <<"Invalid snapshot type \"", Type/binary,
               "\" specified with rollback option">>};
        {_, true} ->
            resolve_rollback_to_value(maps:get(<<"rollback">>, Options),
                                      TipHeight, Network);
        {<<"rollback">>, false} ->
            resolve_rollback_to_latest_assumeutxo(TipHeight, Network);
        {<<"latest">>, false} ->
            {ok, {TipHash, TipHeight}};
        {<<>>, false} ->
            {ok, {TipHash, TipHeight}};
        {_, false} ->
            {error, ?RPC_INVALID_PARAMETER,
             <<"Invalid snapshot type \"", Type/binary,
               "\" specified. Please specify \"rollback\" or \"latest\"">>}
    end.

%% Pick the highest assumeutxo snapshot height that is ≤ TipHeight.
%% Mirrors bitcoin-core/src/rpc/blockchain.cpp:3122 (max_element of
%% GetAvailableSnapshotHeights). beamchain_chain_params:list_assumeutxo_heights/1
%% returns ascending; we filter by TipHeight cap and take the max.
resolve_rollback_to_latest_assumeutxo(TipHeight, Network) ->
    Heights = beamchain_chain_params:list_assumeutxo_heights(Network),
    Eligible = [H || H <- Heights, H =< TipHeight],
    case Eligible of
        [] ->
            {error, ?RPC_MISC_ERROR,
             <<"No assumeutxo snapshot height available at or below current tip">>};
        _ ->
            Height = lists:max(Eligible),
            case beamchain_db:get_block_index(Height) of
                {ok, #{hash := H}} -> {ok, {H, Height}};
                not_found ->
                    {error, ?RPC_MISC_ERROR,
                     <<"Block index missing for assumeutxo snapshot height">>}
            end
    end.

%% Resolve options.rollback which can be:
%%   - integer: a height (must be ≤ tip and on the active chain)
%%   - hex string: a block hash (display order; must be on the active chain)
%% Mirrors ParseHashOrHeight from bitcoin-core/src/rpc/blockchain.cpp.
resolve_rollback_to_value(V, TipHeight, _Network) when is_integer(V) ->
    case V >= 0 andalso V =< TipHeight of
        false ->
            {error, ?RPC_INVALID_PARAMETER,
             iolist_to_binary(
               io_lib:format("Target block height ~B out of range [0, ~B]",
                             [V, TipHeight]))};
        true ->
            case beamchain_db:get_block_index(V) of
                {ok, #{hash := H}} -> {ok, {H, V}};
                not_found ->
                    {error, ?RPC_MISC_ERROR,
                     <<"Block index missing for target height">>}
            end
    end;
resolve_rollback_to_value(V, TipHeight, _Network) when is_binary(V) ->
    %% Display-order hex → internal byte order.
    try hex_to_internal_hash(V) of
        Hash when byte_size(Hash) =:= 32 ->
            case beamchain_db:get_block_index_by_hash(Hash) of
                {ok, #{height := H}} when H >= 0, H =< TipHeight ->
                    %% Verify the block is on the active chain (at this
                    %% height the active chain's hash must equal Hash).
                    case beamchain_db:get_block_index(H) of
                        {ok, #{hash := ActiveHash}} when ActiveHash =:= Hash ->
                            {ok, {Hash, H}};
                        _ ->
                            {error, ?RPC_INVALID_PARAMETER,
                             <<"Target block is not on the active chain">>}
                    end;
                {ok, #{height := H}} ->
                    {error, ?RPC_INVALID_PARAMETER,
                     iolist_to_binary(
                       io_lib:format(
                         "Target block height ~B out of range [0, ~B]",
                         [H, TipHeight]))};
                not_found ->
                    {error, ?RPC_INVALID_ADDRESS_OR_KEY,
                     <<"Target block hash not found">>}
            end;
        _ ->
            {error, ?RPC_INVALID_PARAMETER, <<"Invalid block hash length">>}
    catch
        _:_ ->
            {error, ?RPC_INVALID_PARAMETER,
             <<"Invalid rollback parameter (expected height integer or block hash hex)">>}
    end;
resolve_rollback_to_value(_, _, _) ->
    {error, ?RPC_INVALID_PARAMETER,
     <<"Invalid rollback parameter (expected height integer or block hash hex)">>}.

%% Dump the UTXO set at the current tip — no rollback dance.
do_dump_at_tip(Path, TipHash, TipHeight, Network) ->
    PathStr = binary_to_list(Path),
    ok = beamchain_chainstate:flush(),
    SnapshotBin = beamchain_snapshot:serialize_snapshot(TipHash, Network),
    UtxoHash = beamchain_snapshot:compute_utxo_hash(),
    case file:write_file(PathStr, SnapshotBin) of
        ok ->
            {ok, #{
                <<"coins_written">> => count_coins_in_snapshot(SnapshotBin),
                <<"base_hash">> =>
                    beamchain_serialize:hex_encode(
                      beamchain_serialize:reverse_bytes(TipHash)),
                <<"base_height">> => TipHeight,
                <<"path">> => Path,
                <<"txoutset_hash">> =>
                    beamchain_serialize:hex_encode(
                      beamchain_serialize:reverse_bytes(UtxoHash)),
                <<"nchaintx">> =>
                    chain_tx_count_for_height(TipHeight, Network)
            }};
        {error, Reason} ->
            {error, ?RPC_MISC_ERROR,
             iolist_to_binary(
               io_lib:format("Failed to write snapshot: ~p", [Reason]))}
    end.

%% Dump-with-rollback: disconnect blocks back to TargetHeight, dump, then
%% re-connect the disconnected blocks back to OrigTipHeight. Mirrors the
%% TemporaryRollback RAII guard in bitcoin-core/src/rpc/blockchain.cpp.
%%
%% Composes only the public reorg primitives:
%%   beamchain_chainstate:disconnect_block/0  — for the rewind
%%   beamchain_chainstate:connect_block/1     — for the forward replay
%%
%% Captures the disconnected blocks in a list so forward replay does not
%% depend on the active chain index pointing at them. (Disconnect leaves
%% block data + per-height index entries in RocksDB, but the safest
%% replay path is to feed the captured #block{} record back through
%% connect_block/1, which handles full validation.)
%%
%% On any failure during dump or replay, re-applies whatever was
%% captured so the chain returns to its original tip on a best-effort
%% basis. If the replay itself fails we leave the chain at the partial
%% height and surface a misc-error — the operator can drive
%% reconsiderblock / a restart to recover. This matches Core's
%% LogWarning-then-throw fallback in rpc/blockchain.cpp:3208.
do_dump_with_rollback(Path, TargetHash, TargetHeight,
                      OrigTipHash, OrigTipHeight, Network) ->
    case rewind_to(TargetHash, TargetHeight, OrigTipHeight, []) of
        {ok, Disconnected} ->
            %% Disconnected = [#block{}], oldest-first (so reversing gives
            %% replay order from TargetHeight+1 → OrigTipHeight).
            DumpResult = do_dump_at_tip(Path, TargetHash, TargetHeight,
                                        Network),
            %% Always try to forward-replay even if the dump itself
            %% failed, so we leave the node where the operator left it.
            case replay_forward(Disconnected) of
                ok ->
                    DumpResult;
                {error, ReplayReason} ->
                    logger:error(
                      "dumptxoutset: forward replay failed at "
                      "height after ~B (target=~B, orig_tip=~B): ~p",
                      [TargetHeight, TargetHeight, OrigTipHeight,
                       ReplayReason]),
                    case DumpResult of
                        {ok, _} ->
                            {error, ?RPC_MISC_ERROR,
                             iolist_to_binary(
                               io_lib:format(
                                 "Snapshot written but forward replay failed: ~p",
                                 [ReplayReason]))};
                        Err ->
                            Err
                    end
            end;
        {error, Code, Msg} ->
            _ = mark_orig_tip_for_log(OrigTipHash),
            {error, Code, Msg}
    end.

%% Rewind the chain to TargetHash/TargetHeight, capturing the disconnected
%% blocks (oldest-first) for later forward replay. We re-fetch each block
%% from the DB before disconnecting so replay does not depend on
%% block-index lookups after the rewind.
rewind_to(_TargetHash, TargetHeight, CurHeight, Acc)
  when CurHeight =:= TargetHeight ->
    {ok, Acc};
rewind_to(_TargetHash, TargetHeight, CurHeight, _Acc)
  when CurHeight < TargetHeight ->
    {error, ?RPC_MISC_ERROR,
     iolist_to_binary(
       io_lib:format(
         "rewind underflow: cur=~B target=~B", [CurHeight, TargetHeight]))};
rewind_to(TargetHash, TargetHeight, CurHeight, Acc) ->
    case beamchain_chainstate:get_tip() of
        {ok, {CurHash, CurHeight}} ->
            case beamchain_db:get_block(CurHash) of
                {ok, Block} ->
                    case beamchain_chainstate:disconnect_block() of
                        ok ->
                            rewind_to(TargetHash, TargetHeight,
                                      CurHeight - 1, [Block | Acc]);
                        {error, Reason} ->
                            {error, ?RPC_MISC_ERROR,
                             iolist_to_binary(
                               io_lib:format(
                                 "disconnect_block failed at height ~B: ~p",
                                 [CurHeight, Reason]))}
                    end;
                not_found ->
                    {error, ?RPC_MISC_ERROR,
                     iolist_to_binary(
                       io_lib:format(
                         "block data missing at height ~B during rewind",
                         [CurHeight]))}
            end;
        {ok, {OtherHash, OtherHeight}} ->
            {error, ?RPC_MISC_ERROR,
             iolist_to_binary(
               io_lib:format(
                 "tip moved during rewind: expected height ~B, "
                 "got height ~B (hash ~s)",
                 [CurHeight, OtherHeight,
                  beamchain_serialize:hex_encode(
                    beamchain_serialize:reverse_bytes(OtherHash))]))};
        not_found ->
            {error, ?RPC_MISC_ERROR,
             <<"Chain tip disappeared during rewind">>}
    end.

%% Replay the captured blocks (oldest-first) back through connect_block/1.
replay_forward([]) ->
    ok;
replay_forward([Block | Rest]) ->
    case beamchain_chainstate:connect_block(Block) of
        ok -> replay_forward(Rest);
        {error, Reason} -> {error, Reason}
    end.

mark_orig_tip_for_log(OrigTipHash) ->
    logger:warning("dumptxoutset: leaving chain at non-original tip; "
                   "original tip was ~s",
                   [beamchain_serialize:hex_encode(
                      beamchain_serialize:reverse_bytes(OrigTipHash))]),
    ok.

%% Read the coins_count field out of the metadata header we just wrote.
%% Cheap and avoids re-iterating the chainstate.
count_coins_in_snapshot(SnapshotBin) ->
    case beamchain_snapshot:parse_metadata(SnapshotBin) of
        {ok, #{num_coins := N}, _Rest} -> N;
        _ -> 0
    end.

%% Best-effort chain_tx_count lookup. If the height matches an
%% m_assumeutxo_data entry we report the canonical Core value; otherwise
%% the base block index is consulted, falling back to 0 when neither is
%% available (regtest / pre-snapshot dev runs).
chain_tx_count_for_height(Height, Network) ->
    case beamchain_chain_params:get_assumeutxo(Height, Network) of
        {ok, #{chain_tx_count := N}} -> N;
        not_found -> 0
    end.
