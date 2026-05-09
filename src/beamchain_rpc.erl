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

%% Exported for testing — atomic dump write helper. Writes Payload to
%% TmpPath, fsyncs, and renames to FinalPath. Cleans up TmpPath on any
%% failure. Mirrors bitcoin-core/src/rpc/blockchain.cpp::dumptxoutset's
%% "temppath = path + .incomplete" → fsync → rename flow.
-export([write_snapshot_atomic/3]).

%% NetworkDisable RAII: Bitcoin Core's `NetworkDisable` (rpc/blockchain.cpp)
%% wraps `dumptxoutset rollback`'s rewind→dump→replay dance so peers and
%% submitblock RPC callers cannot race a new block into the chain mid-rewind.
%% Erlang has no destructors; we simulate with a `persistent_term` flag set
%% by the rollback handler and cleared on exit (success or failure). The
%% submitblock handler short-circuits when the flag is set.
-export([is_block_submission_paused/0,
         set_block_submission_paused/1,
         bip22_result/1]).

%% Exported for testing — verifychain RPC handler.
-export([rpc_verifychain/1]).

%% Exported for EUnit so tests can drive the BIP-157 RPC handler
%% directly without spinning up the cowboy listener.
-export([rpc_getblockfilter/1]).

%% Test-only exports — confirmations helpers (Pattern C1 regression tests).
-ifdef(TEST).
-export([confirmations/1, confirmations/2, is_block_in_active_chain/1]).
%% Test-only exports — submitpackage helpers (mempool wave 2026-05-06).
-export([rpc_submitpackage/1, decode_package_tx/1]).
%% Test-only exports — wallet wave (lockunspent + analyzepsbt + walletcreatefundedpsbt).
-export([rpc_analyzepsbt/1, rpc_lockunspent/2, rpc_listlockunspent/1,
         rpc_walletcreatefundedpsbt/2,
         analyze_psbt/1]).
-endif.

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

%% PSBT role enum — mirrors `bitcoin-core/src/psbt.h::PSBTRole`.
%% Values are ordered so `min/2` ratchets toward the earliest role still
%% needed; CREATOR is unreachable here because every PSBT we analyze has
%% at minimum been created.  Used by `analyzepsbt` and exposed to tests.
-define(PSBT_ROLE_CREATOR,    0).
-define(PSBT_ROLE_UPDATER,    1).
-define(PSBT_ROLE_SIGNER,     2).
-define(PSBT_ROLE_FINALIZER,  3).
-define(PSBT_ROLE_EXTRACTOR,  4).

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
%%% NetworkDisable: persistent-term gate for inbound block submission
%%% ===================================================================

%% Mirrors Bitcoin Core's NetworkDisable RAII guard around
%% `TemporaryRollback` in rpc/blockchain.cpp::dumptxoutset. Set during
%% the rewind→dump→replay dance so peers / submitblock callers cannot
%% race a new block into the chain mid-rewind. Cleared on every exit
%% path (success or failure).
%%
%% persistent_term is the right primitive here: O(1) read, atomic write,
%% no gen_server hop, and the data is read-mostly (toggled at most a few
%% times per node lifetime).

-define(BLOCK_SUBMISSION_PAUSED_KEY, {beamchain_rpc, block_submission_paused}).

is_block_submission_paused() ->
    case persistent_term:get(?BLOCK_SUBMISSION_PAUSED_KEY, false) of
        true -> true;
        _ -> false
    end.

set_block_submission_paused(true) ->
    persistent_term:put(?BLOCK_SUBMISSION_PAUSED_KEY, true);
set_block_submission_paused(false) ->
    %% Use erase to avoid retaining the key forever (persistent_term
    %% retention has a process-tracking cost). Equivalent semantics for
    %% the read path because is_block_submission_paused/0 defaults to
    %% false on missing key.
    _ = persistent_term:erase(?BLOCK_SUBMISSION_PAUSED_KEY),
    ok.

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
            %% Serialize batch: mix of normal maps and {raw_json, Bin} items.
            reply_json_batch(Responses, Req1, CowboyState);
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

reply_json({raw_json, Binary}, Req0, CowboyState) ->
    %% Pre-encoded JSON (from decodepsbt raw-json path): skip jsx:encode.
    Req = cowboy_req:reply(200, #{
        <<"content-type">> => <<"application/json">>
    }, Binary, Req0),
    {ok, Req, CowboyState};
reply_json(Body, Req0, CowboyState) ->
    Req = cowboy_req:reply(200, #{
        <<"content-type">> => <<"application/json">>
    }, jsx:encode(Body), Req0),
    {ok, Req, CowboyState}.

%% reply_json_batch/3 — serialize a batch response list that may contain
%% a mix of normal Erlang maps and {raw_json, Bin} pre-encoded items.
reply_json_batch(Responses, Req0, CowboyState) ->
    Parts = lists:map(fun
        ({raw_json, Bin}) -> Bin;
        (R)               -> jsx:encode(R)
    end, Responses),
    Batch = iolist_to_binary(["[", lists:join(",", Parts), "]"]),
    Req = cowboy_req:reply(200, #{
        <<"content-type">> => <<"application/json">>
    }, Batch, Req0),
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
                    {ok_raw_json, JsonBin} ->
                        %% Pre-encoded JSON result: bypass jsx encoding.
                        %% Used by decodepsbt to emit exact numeric literals
                        %% (e.g. "1.00000000") that jsx would reformat.
                        {raw_json, raw_result_obj(Id, JsonBin)};
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

%% raw_result_obj/2 — builds the JSON-RPC wrapper around a pre-encoded
%% JSON binary.  Used when the result value contains exact numeric literals
%% that jsx would reformat (e.g. "1.00000000" → "1.0").
raw_result_obj(Id, JsonBin) ->
    IdJson = jsx:encode(Id),
    <<"{"
      "\"result\":", JsonBin/binary,
      ",\"error\":null"
      ",\"id\":", IdJson/binary,
      "}">>.


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
handle_method(<<"verifychain">>, P, _W) -> rpc_verifychain(P);
handle_method(<<"getblockfilter">>, P, _W) -> rpc_getblockfilter(P);
handle_method(<<"invalidateblock">>, P, _W) -> rpc_invalidateblock(P);
handle_method(<<"reconsiderblock">>, P, _W) -> rpc_reconsiderblock(P);
handle_method(<<"flushchainstate">>, _, _W) -> rpc_flushchainstate();
handle_method(<<"scrubunspendable">>, _, _W) -> rpc_scrubunspendable();
handle_method(<<"pruneblockchain">>, P, _W) -> rpc_pruneblockchain(P);

%% -- Transactions --
handle_method(<<"getrawtransaction">>, P, _W) -> rpc_getrawtransaction(P);
handle_method(<<"decoderawtransaction">>, P, _W) -> rpc_decoderawtransaction(P);
handle_method(<<"sendrawtransaction">>, P, _W) -> rpc_sendrawtransaction(P);
handle_method(<<"createrawtransaction">>, P, _W) -> rpc_createrawtransaction(P);
handle_method(<<"testmempoolaccept">>, P, _W) -> rpc_testmempoolaccept(P);
handle_method(<<"submitpackage">>, P, _W) -> rpc_submitpackage(P);
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
handle_method(<<"getwalletmnemonic">>, _, W) -> rpc_getwalletmnemonic(W);
handle_method(<<"dumpprivkey">>, P, W) -> rpc_dumpprivkey(P, W);
handle_method(<<"sendtoaddress">>, P, W) -> rpc_sendtoaddress(P, W);
handle_method(<<"listunspent">>, P, W) -> rpc_listunspent(P, W);
handle_method(<<"listtransactions">>, P, W) -> rpc_listtransactions(P, W);
handle_method(<<"lockunspent">>, P, W) -> rpc_lockunspent(P, W);
handle_method(<<"listlockunspent">>, _, W) -> rpc_listlockunspent(W);
handle_method(<<"encryptwallet">>, P, W) -> rpc_encryptwallet(P, W);
handle_method(<<"walletpassphrase">>, P, W) -> rpc_walletpassphrase(P, W);
handle_method(<<"walletlock">>, _, W) -> rpc_walletlock(W);
handle_method(<<"signrawtransactionwithwallet">>, P, W) -> rpc_signrawtransactionwithwallet(P, W);
handle_method(<<"importdescriptors">>, P, W) -> rpc_importdescriptors(P, W);
handle_method(<<"walletcreatefundedpsbt">>, P, W) -> rpc_walletcreatefundedpsbt(P, W);

%% -- PSBT --
handle_method(<<"createpsbt">>, P, _W) -> rpc_createpsbt(P);
handle_method(<<"decodepsbt">>, P, _W) -> rpc_decodepsbt(P);
handle_method(<<"combinepsbt">>, P, _W) -> rpc_combinepsbt(P);
handle_method(<<"finalizepsbt">>, P, _W) -> rpc_finalizepsbt(P);
handle_method(<<"analyzepsbt">>, P, _W) -> rpc_analyzepsbt(P);

%% -- Descriptors --
handle_method(<<"deriveaddresses">>, P, _W) -> rpc_deriveaddresses(P);
handle_method(<<"getdescriptorinfo">>, P, _W) -> rpc_getdescriptorinfo(P);

%% -- assumeUTXO --
handle_method(<<"loadtxoutset">>, P, _W) -> rpc_loadtxoutset(P);
handle_method(<<"dumptxoutset">>, P, _W) -> rpc_dumptxoutset(P);

%% -- Wave-47b --
handle_method(<<"getnetworkhashps">>, P, _W) -> rpc_getnetworkhashps(P);
handle_method(<<"gettxoutproof">>, P, _W) -> rpc_gettxoutproof(P);
handle_method(<<"verifytxoutproof">>, P, _W) -> rpc_verifytxoutproof(P);
handle_method(<<"getrpcinfo">>, _, _W) -> rpc_getrpcinfo();

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
        <<"getblockfilter \"blockhash\" ( \"filtertype\" )">>,
        <<"flushchainstate">>,
        <<"scrubunspendable">>,
        <<"pruneblockchain height">>,
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
        <<"analyzepsbt \"psbt\"">>,
        <<"combinepsbt [\"psbt\",...]">>,
        <<"createpsbt [{\"txid\":\"hex\",\"vout\":n},...] [{\"address\":amount},...] ( locktime )">>,
        <<"createrawtransaction [{\"txid\":\"hex\",\"vout\":n},...] [{\"address\":amount},...] ( locktime replaceable )">>,
        <<"decoderawtransaction \"hexstring\"">>,
        <<"decodepsbt \"psbt\"">>,
        <<"decodescript \"hexstring\"">>,
        <<"finalizepsbt \"psbt\" ( extract )">>,
        <<"getrawtransaction \"txid\" ( verbose \"blockhash\" )">>,
        <<"sendrawtransaction \"hexstring\"">>,
        <<"submitpackage [\"rawtx\",...] ( maxfeerate maxburnamount )">>,
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
        <<"getwalletmnemonic">>,
        <<"listaddresses">>,
        <<"listlockunspent">>,
        <<"listtransactions ( \"label\" count skip )">>,
        <<"listunspent ( minconf maxconf )">>,
        <<"listwallets">>,
        <<"loadwallet \"name\"">>,
        <<"lockunspent unlock ( [{\"txid\":\"hex\",\"vout\":n},...] persistent )">>,
        <<"importdescriptors \"requests\"">>,
        <<"sendtoaddress \"address\" amount ( \"comment\" )">>,
        <<"signrawtransactionwithwallet \"hexstring\" ( [{\"txid\":\"hex\",\"vout\":n,\"scriptPubKey\":\"hex\"},...] )">>,
        <<"unloadwallet ( \"name\" )">>,
        <<"walletcreatefundedpsbt [{\"txid\":\"hex\",\"vout\":n},...] [{\"address\":amount},...] ( locktime options bip32derivs )">>,
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
    PruneFields = build_prune_fields(),
    %% BIP-157/158: surface whether the local node has the basic block
    %% filter index running.  Wallet light clients (and our own
    %% test-suite) consult this to decide whether `getblockfilter` will
    %% succeed without a round-trip.  Field name matches Core's recent
    %% `getblockchaininfo` extension (`compact_filters_enabled`,
    %% rpc/blockchain.cpp ~line 1432).
    CompactFiltersEnabled = beamchain_blockfilter_index:is_enabled(),
    CompactFiltersFields = #{
        <<"compact_filters_enabled">> => CompactFiltersEnabled
    },
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
            %% Extract tip bits for bits/target fields
            TipBits = case beamchain_db:get_block_index(TipHeight) of
                {ok, #{header := TipHdr}} -> TipHdr#block_header.bits;
                _ -> 16#1d00ffff
            end,
            %% Use the shared deployment helper — same source of truth as getdeploymentinfo.
            HeightGetter = fun(H) -> beamchain_db:get_block_index(H) end,
            Softforks = build_deployment_map(Network, TipHeight, HeightGetter),
            BaseInfo = #{
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
                <<"bits">> => beamchain_serialize:hex_encode(<<TipBits:32/big>>),
                <<"target">> => bits_to_target_hex(TipBits),
                <<"softforks">> => Softforks,
                <<"warnings">> => <<>>
            },
            {ok, maps:merge(maps:merge(BaseInfo, PruneFields),
                            CompactFiltersFields)};
        not_found ->
            BaseInfo = #{
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
                <<"softforks">> => #{},
                <<"warnings">> => <<>>
            },
            {ok, maps:merge(maps:merge(BaseInfo, PruneFields),
                            CompactFiltersFields)}
    end.

%% Build the pruning subset of the getblockchaininfo response.
%% Mirrors Bitcoin Core's blockchain.cpp::getblockchaininfo:
%%   * `pruned` — boolean
%%   * `pruneheight` — only when pruned=true
%%   * `automatic_pruning` — only when pruned=true
%%   * `prune_target_size` (bytes) — only when pruned=true and auto
build_prune_fields() ->
    try beamchain_db:get_prune_state() of
        #{enabled := false} ->
            #{<<"pruned">> => false};
        #{enabled := true,
          manual_mode := ManualMode,
          automatic_pruning := AutoPruning,
          target_bytes := TargetBytes,
          prune_height := PruneHeight} ->
            Base = #{
                <<"pruned">>            => true,
                <<"pruneheight">>       => PruneHeight,
                <<"automatic_pruning">> => AutoPruning
            },
            %% Match Core: prune_target_size is reported only when an
            %% automatic target is configured (i.e. NOT manual-only mode).
            case ManualMode of
                true  -> Base;
                false -> Base#{<<"prune_target_size">> => TargetBytes}
            end
    catch
        _:_ ->
            %% Defensive: if the db gen_server is busy / down, surface
            %% a "not pruned" answer rather than blocking the RPC call.
            #{<<"pruned">> => false}
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
                        <<"confirmations">> => confirmations(Height, Hash),
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
                        <<"confirmations">> => confirmations(Height, Hash),
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

%% @doc verifychain — actually walk the chain.
%%
%% Mirrors bitcoin-core/src/rpc/blockchain.cpp::verifychain.
%%
%% Args (positional, all optional):
%%   1. checklevel  (0..4, default 3)
%%   2. nblocks     (0..tip_height, default 6, 0 = entire chain)
%%
%% Per-level work, descending from tip for nblocks blocks:
%%   0: read block from disk
%%   1: + check_block (header sanity, merkle root, tx structure, weight, sigops)
%%   2: + verify undo data exists and decodes
%%   3: + verify undo entry count matches block's spent-input count
%%      (best-effort: full Core-parity disconnect/reconnect-into-sandbox-UTXO
%%       is not implemented because beamchain's UTXO cache is process-global;
%%       a true disconnect/reconnect would mutate live chainstate.)
%%   4: + re-verify scripts for every non-coinbase tx using stored undo coins
%%        as the prevout source (same SigChecker shape as connect_block).
%%
%% Returns true on success, false on any failure. Halts on first failure
%% and logs the failing block hash + reason.
%%
%% Reference: Core checklevel = consensus::DEFAULT_CHECKLEVEL = 3,
%%            nblocks = consensus::DEFAULT_CHECKBLOCKS = 6.
rpc_verifychain(Params) ->
    CheckLevel = case Params of
        [] -> 3;
        [L | _] when is_integer(L) -> L;
        _ -> 3
    end,
    NBlocks = case Params of
        [_, N | _] when is_integer(N) -> N;
        _ -> 6
    end,
    case CheckLevel < 0 orelse CheckLevel > 4 of
        true ->
            {error, ?RPC_INVALID_PARAMETER,
             <<"checklevel must be in range [0, 4]">>};
        false ->
            do_verifychain(CheckLevel, NBlocks)
    end.

do_verifychain(CheckLevel, NBlocks) ->
    case beamchain_chainstate:get_tip() of
        not_found ->
            %% No chain → vacuously valid (matches Core behaviour with
            %% a fresh datadir: nothing to verify, return true).
            {ok, true};
        {ok, {TipHash, TipHeight}} ->
            Network = beamchain_config:network(),
            ChainParams = beamchain_chain_params:params(Network),
            %% Compute how many blocks to actually walk.
            %% nblocks=0 means the entire chain; otherwise clamp to TipHeight+1.
            Walk = case NBlocks of
                0 -> TipHeight + 1;
                N when N > TipHeight + 1 -> TipHeight + 1;
                N -> N
            end,
            verifychain_walk(TipHash, TipHeight, Walk, CheckLevel,
                             ChainParams, Network)
    end.

%% Walk descending from current hash for Remaining blocks.
verifychain_walk(_Hash, _Height, 0, _Lvl, _Params, _Network) ->
    {ok, true};
verifychain_walk(Hash, Height, Remaining, Lvl, Params, Network)
        when Height < 0 ->
    %% Walked past genesis; we're done.
    _ = Hash, _ = Remaining, _ = Lvl, _ = Params, _ = Network,
    {ok, true};
verifychain_walk(Hash, Height, Remaining, Lvl, Params, Network) ->
    case verify_one_block(Hash, Height, Lvl, Params, Network) of
        {ok, PrevHash} ->
            verifychain_walk(PrevHash, Height - 1, Remaining - 1,
                             Lvl, Params, Network);
        {error, Reason} ->
            HashHex = hash_to_hex(Hash),
            logger:error("verifychain: block ~s at height ~B failed: ~p",
                         [HashHex, Height, Reason]),
            {ok, false}
    end.

%% Verify a single block at the requested level.
%% Returns {ok, PrevHash} on success (so the walk can continue) or
%% {error, Reason} on failure.
verify_one_block(Hash, Height, Lvl, Params, Network) ->
    %% Level 0: read block from disk.
    case beamchain_db:get_block(Hash) of
        not_found ->
            {error, block_not_found};
        {ok, Block} ->
            Header = Block#block.header,
            PrevHash = Header#block_header.prev_hash,
            %% Genesis sentinel: 32 zero bytes. Don't recurse past it.
            verify_one_block_levels(Block, Hash, Height, Lvl, Params, Network,
                                    PrevHash)
    end.

verify_one_block_levels(Block, Hash, Height, Lvl, Params, Network, PrevHash) ->
    Steps = [
        {1, fun() -> level1_check_block(Block, Params) end},
        {2, fun() -> level2_check_undo(Hash) end},
        {3, fun() -> level3_check_undo_shape(Block, Hash) end},
        {4, fun() -> level4_check_scripts(Block, Hash, Height, Network) end}
    ],
    case run_levels(Lvl, Steps) of
        ok -> {ok, PrevHash};
        {error, _} = E -> E
    end.

run_levels(_Lvl, []) -> ok;
run_levels(Lvl, [{N, _Fun} | Rest]) when N > Lvl -> run_levels(Lvl, Rest);
run_levels(Lvl, [{_N, Fun} | Rest]) ->
    case Fun() of
        ok -> run_levels(Lvl, Rest);
        {error, _} = E -> E
    end.

%% Level 1: context-free block validation (Core's CheckBlock).
level1_check_block(Block, Params) ->
    case beamchain_validation:check_block(Block, Params) of
        ok -> ok;
        {error, R} -> {error, {check_block_failed, R}}
    end.

%% Level 2: undo data exists and decodes.
%%
%% Genesis has no undo data (no inputs to spend). Every other block on
%% the active chain stored undo data when it was connected; absence is a
%% storage-integrity failure.
level2_check_undo(Hash) ->
    case beamchain_db:get_undo(Hash) of
        {ok, UndoBin} ->
            try
                _ = beamchain_validation:decode_undo_data(UndoBin),
                ok
            catch
                _:R -> {error, {undo_decode_failed, R}}
            end;
        not_found ->
            %% Tolerate missing undo for genesis (height 0). For any
            %% other block, missing undo is a real integrity failure —
            %% but we can't cheaply distinguish "this is genesis" from
            %% the block alone here; treat missing undo as ok and let
            %% the level-3 spent-input-count check do the real work.
            ok
    end.

%% Level 3: spent-input count from undo data matches block.
%%
%% Best-effort: a Core-parity check would disconnect the block, reconnect
%% it, and confirm the resulting UTXO state matches. beamchain's UTXO
%% cache is process-global, so a real disconnect/reconnect would mutate
%% live state mid-RPC. We instead verify the structural invariant that
%% the undo data has exactly one spent-coin entry per non-coinbase input.
level3_check_undo_shape(#block{transactions = Txs}, Hash) ->
    %% Coinbase has no inputs to undo; everything else contributes inputs.
    [_Coinbase | RestTxs] = Txs,
    ExpectedInputs = lists:foldl(
        fun(Tx, Acc) -> Acc + length(Tx#transaction.inputs) end,
        0, RestTxs),
    case beamchain_db:get_undo(Hash) of
        {ok, UndoBin} ->
            try
                Coins = beamchain_validation:decode_undo_data(UndoBin),
                case length(Coins) of
                    ExpectedInputs -> ok;
                    Got ->
                        {error, {undo_count_mismatch,
                                 #{expected => ExpectedInputs,
                                   got => Got}}}
                end
            catch
                _:R -> {error, {undo_decode_failed, R}}
            end;
        not_found when ExpectedInputs =:= 0 ->
            %% Coinbase-only block (e.g. genesis); no undo expected.
            ok;
        not_found ->
            {error, missing_undo_data}
    end.

%% Level 4: re-verify scripts for every non-coinbase tx using stored
%% undo coins. This is the heaviest check: it reproduces the script
%% verification that ran at connect_block time, with the same SigChecker
%% shape (Tx, InputIdx, Amount, AllPrevOuts).
%%
%% Assumes level 3 already passed (undo entry count matches input count).
level4_check_scripts(_Block, _Hash, 0, _Network) ->
    %% Genesis has no scripts to verify.
    ok;
level4_check_scripts(#block{transactions = Txs}, Hash, Height, Network) ->
    case beamchain_db:get_undo(Hash) of
        not_found ->
            %% Either coinbase-only (already handled by level 3) or a
            %% real failure flagged by level 3. Treat missing undo here
            %% as a soft-pass since level 3 is the authoritative check.
            ok;
        {ok, UndoBin} ->
            try
                Coins = beamchain_validation:decode_undo_data(UndoBin),
                Flags = beamchain_script:flags_for_height(Height, Network),
                [_Coinbase | RestTxs] = Txs,
                level4_verify_txs(RestTxs, Coins, Flags),
                ok
            catch
                throw:{script_verify_failed, _} = R -> {error, R};
                _:R -> {error, {script_check_exception, R}}
            end
    end.

%% Walk non-coinbase txs in order; consume undo coins from the head.
level4_verify_txs([], [], _Flags) -> ok;
level4_verify_txs([], _Leftover, _Flags) -> ok;  %% level 3 should have caught
level4_verify_txs([Tx | RestTxs], UndoCoins, Flags) ->
    NumInputs = length(Tx#transaction.inputs),
    {InputCoinPairs, RemainingUndo} = take_n(UndoCoins, NumInputs),
    InputCoins = [Coin || {_OutPoint, Coin} <- InputCoinPairs],
    AllPrevOuts = [{C#utxo.value, C#utxo.script_pubkey} || C <- InputCoins],
    Inputs = Tx#transaction.inputs,
    %% lists:zip on equal-length lists; level 3 ensures equal length.
    lists:foldl(
      fun({Input, Coin}, Idx) ->
          ScriptSig = Input#tx_in.script_sig,
          ScriptPubKey = Coin#utxo.script_pubkey,
          Witness = case Input#tx_in.witness of
              undefined -> [];
              W -> W
          end,
          Amount = Coin#utxo.value,
          SigChecker = {Tx, Idx, Amount, AllPrevOuts},
          case beamchain_script:verify_script(
                 ScriptSig, ScriptPubKey, Witness, Flags, SigChecker) of
              true -> Idx + 1;
              false -> throw({script_verify_failed, Idx})
          end
      end, 0, lists:zip(Inputs, InputCoins)),
    level4_verify_txs(RestTxs, RemainingUndo, Flags).

%% Take the first N elements of a list; return {Taken, Rest}.
take_n(List, N) -> take_n(List, N, []).
take_n(Rest, 0, Acc) -> {lists:reverse(Acc), Rest};
take_n([], _N, Acc) -> {lists:reverse(Acc), []};
take_n([H | T], N, Acc) -> take_n(T, N - 1, [H | Acc]).

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

%% @doc pruneblockchain RPC — manually prune block-and-undo files.
%% Mirrors `bitcoin-core/src/rpc/blockchain.cpp::pruneblockchain`:
%%   * Param is either a block height (>0, <=tip) or a unix timestamp
%%     (>=1e9, mapped to the latest block at-or-before that time).
%%   * Rejects when prune mode is off entirely.
%%   * Clamps the effective height to `tip - 288` to preserve the
%%     reorg-safety window.
%%   * Returns the height of the last block pruned.
rpc_pruneblockchain([N]) when is_integer(N), N >= 0 ->
    do_pruneblockchain(N);
rpc_pruneblockchain([Other]) when is_float(Other), Other >= 0 ->
    do_pruneblockchain(trunc(Other));
rpc_pruneblockchain(_) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: pruneblockchain height_or_unix_timestamp">>}.

do_pruneblockchain(N) ->
    %% Reject if pruning is not enabled at all.
    case beamchain_config:prune_enabled() of
        false ->
            {error, ?RPC_MISC_ERROR,
             <<"Cannot prune blocks because node is not in prune mode.">>};
        true ->
            %% Resolve the parameter: heights are typically <= 5e8 for
            %% the foreseeable future, while unix timestamps are >=1e9.
            %% Core uses the same threshold (rpc/blockchain.cpp).
            Height = case N >= 1000000000 of
                false ->
                    N;
                true ->
                    case beamchain_chainstate:get_tip() of
                        not_found -> 0;
                        {ok, {_TipHash, TipH}} ->
                            timestamp_to_height(N, TipH)
                    end
            end,
            case beamchain_db:prune_block_files_manual(Height) of
                {ok, #{effective_height := Eff}} ->
                    {ok, Eff};
                {error, prune_disabled} ->
                    {error, ?RPC_MISC_ERROR,
                     <<"Cannot prune blocks because node is not in prune mode.">>};
                {error, Reason} ->
                    {error, ?RPC_DATABASE_ERROR,
                     iolist_to_binary(io_lib:format("Manual prune failed: ~p",
                                                    [Reason]))}
            end
    end.

%% Map a unix timestamp to the height of the last block whose
%% timestamp is <= the supplied value. Walks backward from the tip;
%% O(tip-target) but fine because the manual-prune RPC is rare. Returns
%% 0 if no block matches.
timestamp_to_height(_T, TipH) when TipH =< 0 ->
    0;
timestamp_to_height(T, TipH) ->
    timestamp_to_height_walk(T, TipH).

timestamp_to_height_walk(_T, H) when H < 0 ->
    0;
timestamp_to_height_walk(T, H) ->
    case beamchain_db:get_block_index(H) of
        {ok, #{header := Hdr}} ->
            case (Hdr#block_header.timestamp) =< T of
                true  -> H;
                false -> timestamp_to_height_walk(T, H - 1)
            end;
        _ ->
            timestamp_to_height_walk(T, H - 1)
    end.

%% @doc getblockfilter — return the BIP-158 GCS filter and BIP-157
%% cfheader for a block.  Mirrors Bitcoin Core's
%% `rpc/blockchain.cpp::getblockfilter`:
%%   * First param: block hash (display byte order, hex).
%%   * Second param (optional): filter type. Currently only "basic"
%%     (== filter type 0) is supported and is the default.
%%   * Returns `{filter: <hex>, header: <hex>}`.
%%
%% Errors:
%%   -1   (RPC_MISC_ERROR)            — index disabled
%%   -8   (RPC_INVALID_PARAMETER)     — unknown filter type
%%   -5   (RPC_INVALID_ADDRESS_OR_KEY)— block / filter not found
%%
%% Reference: bitcoin-core/src/rpc/blockchain.cpp ~line 1235.
rpc_getblockfilter([HashHex]) ->
    rpc_getblockfilter([HashHex, <<"basic">>]);
rpc_getblockfilter([HashHex, FilterType]) when is_binary(HashHex) ->
    case validate_filter_type(FilterType) of
        {ok, _FT} ->
            case beamchain_blockfilter_index:is_enabled() of
                false ->
                    {error, ?RPC_MISC_ERROR,
                     <<"Index is not enabled for filtertype basic">>};
                true ->
                    do_getblockfilter(HashHex)
            end;
        {error, Msg} ->
            {error, ?RPC_INVALID_PARAMETER, Msg}
    end;
rpc_getblockfilter(_) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: getblockfilter \"blockhash\" ( \"filtertype\" )">>}.

validate_filter_type(<<"basic">>) -> {ok, 0};
validate_filter_type(0)            -> {ok, 0};
validate_filter_type(Other) ->
    {error,
        iolist_to_binary(
          io_lib:format("Unknown filtertype ~p", [Other]))}.

do_getblockfilter(HashHex) ->
    Hash = hex_to_internal_hash(HashHex),
    case beamchain_db:get_block_index_by_hash(Hash) of
        {ok, _Info} ->
            case beamchain_blockfilter_index:get_filter(Hash) of
                {ok, FilterBytes} ->
                    case beamchain_blockfilter_index:get_header(Hash) of
                        {ok, Header} ->
                            {ok, #{
                                <<"filter">> =>
                                    beamchain_serialize:hex_encode(FilterBytes),
                                <<"header">> =>
                                    %% cfheader is a 32-byte hash; surface in
                                    %% display (reversed) byte order to match
                                    %% Core, which prints uint256 hashes
                                    %% big-endian via uint256::ToString().
                                    beamchain_serialize:hex_encode(
                                        beamchain_serialize:reverse_bytes(
                                            Header))
                            }};
                        not_found ->
                            {error, ?RPC_INVALID_ADDRESS_OR_KEY,
                             <<"Filter header not available for this block">>}
                    end;
                not_found ->
                    {error, ?RPC_INVALID_ADDRESS_OR_KEY,
                     <<"Filter not available for this block">>}
            end;
        _ ->
            {error, ?RPC_INVALID_ADDRESS_OR_KEY,
             <<"Block not found">>}
    end.

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
                <<"confirmations">> => confirmations(Height, BlockHash),
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
    %% Decode a raw transaction hex to a TxToUniv-shaped JSON object.
    %%
    %% Reference: bitcoin-core/src/rpc/rawtransaction.cpp decoderawtransaction()
    %% → core_io.cpp TxToUniv(tx, block_hash=uint256(), entry, include_hex=false)
    %%
    %% Shape: {txid, hash, version, size, vsize, weight, locktime, vin[], vout[]}.
    %% No top-level "hex" field (Core's include_hex=false).
    %%
    %% Uses format_psbt_tx_json (the same helper as decodepsbt) so that:
    %%   - amounts are Core-exact 8-decimal via sentinel + replace_btc_sentinels
    %%   - scriptPubKey has {asm, desc, hex, address?, type} with rawtr() for P2TR
    %%   - vin has scriptSig.asm (sighash-decode), txinwitness, coinbase detection
    %%
    %% Returns {ok_raw_json, Bin} so the sentinel numerics bypass jsx re-encoding.
    try
        Bin = beamchain_serialize:hex_decode(HexStr),
        {Tx, _Rest} = beamchain_serialize:decode_transaction(Bin),
        TxJson = format_psbt_tx_json(Tx),
        Encoded = jsx:encode(TxJson),
        {ok_raw_json, replace_btc_sentinels(Encoded)}
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

%% @doc submitpackage: Submit a package of related transactions atomically.
%% Mirrors Bitcoin Core's `rpc/mempool.cpp::submitpackage`. The package is
%% an array of raw (hex-encoded) transactions in topological order, with
%% the child as the last element. Acceptance is all-or-nothing: if any
%% transaction fails policy/consensus, none are admitted to the mempool.
%%
%% Returns a JSON object with three top-level fields, matching Core:
%%   - "package_msg":          "success" on full acceptance, otherwise an
%%                              error string identifying the rejection.
%%   - "tx-results":           map keyed by wtxid; each entry carries the
%%                              txid (and on success vsize + fees object,
%%                              on failure an "error" string).
%%   - "replaced-transactions": list of txids evicted via RBF (always
%%                              empty until beamchain wires per-package
%%                              RBF replacement reporting).
%%
%% Reference: bitcoin-core/src/rpc/mempool.cpp::submitpackage (height ~1302).
rpc_submitpackage([RawTxs]) when is_list(RawTxs) ->
    rpc_submitpackage([RawTxs, ?DEFAULT_MAX_RAW_TX_FEE_RATE / 100000000.0, 0]);
rpc_submitpackage([RawTxs, MaxFeeRate]) when is_list(RawTxs) ->
    rpc_submitpackage([RawTxs, MaxFeeRate, 0]);
rpc_submitpackage([RawTxs, _MaxFeeRate, _MaxBurnAmount]) when is_list(RawTxs) ->
    %% 1. Up-front bounds check (matches Core's RPC_INVALID_PARAMETER path).
    Count = length(RawTxs),
    case Count >= 1 andalso Count =< ?MAX_PACKAGE_COUNT of
        false ->
            Msg = iolist_to_binary(io_lib:format(
                "Array must contain between 1 and ~B transactions.",
                [?MAX_PACKAGE_COUNT])),
            {error, ?RPC_INVALID_PARAMETER, Msg};
        true ->
            try
                %% 2. Decode every entry; bail on the first deser failure
                %%    so we surface a Core-shaped RPC error.
                Txs = [decode_package_tx(Hex) || Hex <- RawTxs],
                Wtxids = [beamchain_serialize:wtx_hash(Tx) || Tx <- Txs],
                Txids = [beamchain_serialize:tx_hash(Tx) || Tx <- Txs],

                %% 3. Hand off to the package validator. accept_package/1
                %%    enforces topology + atomicity in beamchain_mempool.
                {PackageMsg, AcceptedSet} =
                    case beamchain_mempool:accept_package(Txs) of
                        {ok, AcceptedTxids} ->
                            {<<"success">>, sets:from_list(AcceptedTxids)};
                        {error, Reason} ->
                            ReasonBin = iolist_to_binary(
                                io_lib:format("~p", [Reason])),
                            {ReasonBin, sets:new()}
                        end,

                %% 4. Per-tx result map keyed by wtxid (Core shape).
                TxResultMap = lists:foldl(
                    fun({Tx, Wtxid, Txid}, Acc) ->
                        WtxidHex = hash_to_hex(Wtxid),
                        Inner = build_pkg_tx_result(Tx, Txid, AcceptedSet,
                                                     PackageMsg),
                        maps:put(WtxidHex, Inner, Acc)
                    end,
                    #{},
                    lists:zip3(Txs, Wtxids, Txids)),

                %% 5. Relay every accepted tx (matches Core's broadcast pass).
                lists:foreach(fun(Txid) ->
                    case sets:is_element(Txid, AcceptedSet) of
                        true -> relay_transaction(Txid);
                        false -> ok
                    end
                end, Txids),

                {ok, #{
                    <<"package_msg">> => PackageMsg,
                    <<"tx-results">> => TxResultMap,
                    %% beamchain's package validator does not yet emit
                    %% a per-package replaced-tx list. Empty array keeps
                    %% the field shape parity with Core.
                    <<"replaced-transactions">> => []
                }}
            catch
                throw:{decode_failed, BadHex} ->
                    {error, ?RPC_DESERIALIZATION_ERROR,
                     iolist_to_binary(io_lib:format(
                         "TX decode failed: ~s Make sure the tx has at "
                         "least one input.", [BadHex]))};
                _:_ ->
                    {error, ?RPC_DESERIALIZATION_ERROR,
                     <<"TX decode failed. Make sure the tx has at least "
                       "one input.">>}
            end
    end;
rpc_submitpackage(_) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: submitpackage [\"rawtx\",...] ( maxfeerate maxburnamount )">>}.

%% Decode one hex-encoded raw tx, throwing a tagged error on failure so
%% the caller can return Core's RPC_DESERIALIZATION_ERROR message verbatim.
decode_package_tx(Hex) when is_binary(Hex) ->
    try
        Bin = beamchain_serialize:hex_decode(Hex),
        {Tx, _} = beamchain_serialize:decode_transaction(Bin),
        Tx
    catch
        _:_ -> throw({decode_failed, Hex})
    end;
decode_package_tx(_) ->
    throw({decode_failed, <<"<non-string>">>}).

%% Build the inner "tx-results" entry for one transaction.
%% Accepted txs report vsize + fees (Core's MempoolAcceptResult::VALID
%% shape); rejected txs report an error string. When the package was
%% rejected before any tx was even probed (e.g. structural failure),
%% Core emits "package-not-validated" and we mirror that here.
build_pkg_tx_result(Tx, Txid, AcceptedSet, PackageMsg) ->
    Base = #{<<"txid">> => hash_to_hex(Txid)},
    case sets:is_element(Txid, AcceptedSet) of
        true ->
            %% Accepted: pull fee/vsize from the mempool entry that
            %% accept_package just inserted.
            case beamchain_mempool:get_entry(Txid) of
                {ok, #mempool_entry{vsize = VSize, fee = Fee}} ->
                    Fees = #{<<"base">> => satoshi_to_btc(Fee)},
                    Base#{<<"vsize">> => VSize,
                          <<"fees">>  => Fees};
                not_found ->
                    %% Should not happen on the success path, but stay
                    %% defensive — emit txid + minimal vsize fallback.
                    VSize = beamchain_serialize:tx_vsize(Tx),
                    Base#{<<"vsize">> => VSize,
                          <<"fees">>  => #{<<"base">> => 0.0}}
            end;
        false ->
            %% Rejected. If the package aborted before per-tx
            %% processing (PackageMsg ≠ "success" and there are no
            %% accepted txs), report Core's "package-not-validated"
            %% sentinel.
            ErrorStr = case PackageMsg of
                <<"success">> -> <<"package-not-validated">>;
                _             -> PackageMsg
            end,
            Base#{<<"error">> => ErrorStr}
    end.

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
    %% Per Core (rpc/blockchain.cpp:1017), the default hash_type is
    %% "hash_serialized_3" — NOT "none". Tooling like the cross-impl
    %% diff-test harness calls gettxoutsetinfo with no args and expects a
    %% UTXO-set commitment back; defaulting to "none" silently strips the
    %% commitment field and breaks the harness probe.
    rpc_gettxoutsetinfo([<<"hash_serialized_3">>]);
rpc_gettxoutsetinfo([HashType | _]) ->
    %% Get UTXO set statistics. Per Core's gettxoutsetinfo (rpc/blockchain.cpp
    %% around line 1090), hash_type ∈ {none, hash_serialized_3, muhash}
    %% selects which UTXO-set commitment to surface. We honour this so callers
    %% can ask for either commitment by name. Anything else → invalid.
    case is_valid_utxo_hash_type(HashType) of
        false ->
            {error, ?RPC_INVALID_PARAMS,
             <<"'", HashType/binary, "' is not a valid hash_type">>};
        true ->
            do_rpc_gettxoutsetinfo(HashType)
    end.

is_valid_utxo_hash_type(<<"none">>)              -> true;
is_valid_utxo_hash_type(<<"hash_serialized_3">>) -> true;
is_valid_utxo_hash_type(<<"muhash">>)            -> true;
is_valid_utxo_hash_type(_)                       -> false.

do_rpc_gettxoutsetinfo(HashType) ->
    case beamchain_chainstate:get_tip() of
        {ok, {TipHash, TipHeight}} ->
            %% For "none" we keep the cheap cache-stat path so callers
            %% asking only for {height,bestblock} don't pay for a full
            %% disk walk. For hash_serialized_3 / muhash we MUST walk the
            %% chainstate column family — the ETS cache is only a partial
            %% view (clean entries can be evicted post-flush) so any
            %% commitment computed from the cache is silently wrong.
            case HashType of
                <<"none">> ->
                    CacheStats = beamchain_chainstate:cache_stats(),
                    CacheEntries = maps:get(cache_entries, CacheStats, 0),
                    Base = #{
                        <<"height">>       => TipHeight,
                        <<"bestblock">>    => hash_to_hex(TipHash),
                        <<"txouts">>       => CacheEntries,
                        <<"bogosize">>     => CacheEntries * 150,
                        <<"total_amount">> => 0.0,
                        <<"disk_size">>    => 0
                    },
                    {ok, Base};
                _ ->
                    %% Walk the on-disk UTXO set once and derive every
                    %% scalar plus the requested commitment from a single
                    %% pass. Core's `ComputeUTXOStats` is also one cursor
                    %% walk per call (kernel/coinstats.cpp:75-130).
                    {Stats, CommitHex} =
                        compute_utxo_set_stats(HashType),
                    Base = #{
                        <<"height">>       => TipHeight,
                        <<"bestblock">>    => hash_to_hex(TipHash),
                        <<"txouts">>       => maps:get(txouts,    Stats),
                        <<"bogosize">>     => maps:get(bogosize,  Stats),
                        <<"total_amount">> =>
                            maps:get(total_amount, Stats) / 100000000.0,
                        <<"disk_size">>    => 0
                    },
                    {ok, Base#{HashType => CommitHex}}
            end;
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

%% Single-pass UTXO-set walk that returns both Core-parity scalars
%% (txouts, bogosize, total_amount in sat) and the requested commitment.
%%
%% Mirrors bitcoin-core/src/kernel/coinstats.cpp::ComputeUTXOStats — Core
%% iterates the chainstate cursor once and feeds every coin to ApplyHash
%% while also tallying nTransactionOutputs / nBogoSize / nTotalAmount.
%%
%% bogosize per coin matches Core: 50 bytes fixed overhead (txid + vout +
%% height/coinbase + amount + scriptlen) plus the script length itself
%% (kernel/coinstats.cpp:78-86).
compute_utxo_set_stats(<<"hash_serialized_3">>) ->
    %% Flush dirty cache → disk so the cursor walk sees the authoritative
    %% UTXO set at the current tip. Same idiom Core uses for its cursor
    %% (the cache is force-promoted by FlushStateToDisk before the walk
    %% in coinstats.cpp:69-72).
    beamchain_chainstate:flush(),
    Coins = beamchain_db:fold_utxos(
              fun(Coin, Acc) -> [Coin | Acc] end, []),
    CoinList = case Coins of L when is_list(L) -> L; _ -> [] end,
    Stats = tally_coins(CoinList),
    UtxoHash = beamchain_snapshot:compute_utxo_hash_from_list(CoinList),
    Hex = beamchain_serialize:hex_encode(
            beamchain_serialize:reverse_bytes(UtxoHash)),
    {Stats, Hex};
compute_utxo_set_stats(<<"muhash">>) ->
    beamchain_chainstate:flush(),
    Coins = beamchain_db:fold_utxos(
              fun(Coin, Acc) -> [Coin | Acc] end, []),
    CoinList = case Coins of L when is_list(L) -> L; _ -> [] end,
    Stats = tally_coins(CoinList),
    MuHash = beamchain_snapshot:compute_txoutset_muhash_from_list(CoinList),
    Hex = beamchain_serialize:hex_encode(
            beamchain_serialize:reverse_bytes(MuHash)),
    {Stats, Hex}.

tally_coins(Coins) ->
    lists:foldl(
      fun({_Txid, _Vout, #utxo{script_pubkey = SPK, value = Value}}, Acc) ->
              ScriptLen = byte_size(SPK),
              %% Core: 50 + scriptPubKey.size() — see
              %% kernel/coinstats.cpp ComputeBogoSize (49 + 1 amount byte
              %% per Core's accounting; we follow Core's actual constant).
              Bogo = 50 + ScriptLen,
              #{txouts := T, bogosize := B, total_amount := A} = Acc,
              Acc#{txouts       => T + 1,
                   bogosize     => B + Bogo,
                   total_amount => A + Value}
      end,
      #{txouts => 0, bogosize => 0, total_amount => 0},
      Coins).

%%% ===================================================================
%%% Mempool methods
%%% ===================================================================

rpc_getmempoolinfo() ->
    Info = beamchain_mempool:get_info(),
    Size = maps:get(size, Info, 0),
    Bytes = maps:get(bytes, Info, 0),
    %% Compute total_fee by summing fees across all mempool entries.
    %% Bitcoin Core src/rpc/mempool.cpp::getmempoolinfo surfaces this as
    %% "total_fee" in BTC (float). We convert from satoshis.
    Entries = beamchain_mempool:get_all_entries(),
    TotalFeeSat = lists:foldl(
        fun(Entry, Acc) -> Acc + Entry#mempool_entry.fee end,
        0,
        Entries
    ),
    TotalFeeBtc = TotalFeeSat / 100000000.0,
    {ok, #{
        <<"loaded">> => true,
        <<"size">> => Size,
        <<"bytes">> => Bytes,
        <<"usage">> => Bytes,
        <<"total_fee">> => TotalFeeBtc,
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
            <<"network">> => <<"ipv4">>,
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
            <<"minping">> => PingTime,
            <<"version">> => maps:get(version, Info, 0),
            <<"subver">> => maps:get(user_agent, Info, <<"/unknown/">>),
            <<"inbound">> => Dir =:= inbound,
            <<"bip152_hb_to">> => false,
            <<"bip152_hb_from">> => false,
            <<"startingheight">> => maps:get(start_height, Info, 0),
            <<"presynced_headers">> => -1,
            <<"synced_headers">> => -1,
            <<"synced_blocks">> => -1,
            <<"inflight">> => [],
            <<"addr_relay_enabled">> => true,
            <<"addr_processed">> => 0,
            <<"addr_rate_limited">> => 0,
            <<"permissions">> => [],
            <<"minfeefilter">> => 0.0,
            <<"bytessent_per_msg">> => #{},
            <<"bytesrecv_per_msg">> => #{},
            <<"connection_type">> => case Dir of
                outbound -> <<"outbound-full-relay">>;
                inbound -> <<"inbound">>
            end,
            <<"transport_protocol_type">> => <<"v1">>,
            <<"session_id">> => <<>>
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
    {Blocks, Difficulty, TipBits} = case beamchain_chainstate:get_tip() of
        {ok, {_Hash, Height}} ->
            Bits = case beamchain_db:get_block_index(Height) of
                {ok, #{header := Hdr}} -> Hdr#block_header.bits;
                _ -> 16#1d00ffff
            end,
            {Height, tip_difficulty(), Bits};
        not_found ->
            {0, 0.0, 16#1d00ffff}
    end,
    BitsHex = beamchain_serialize:hex_encode(<<TipBits:32/big>>),
    TargetHex = bits_to_target_hex(TipBits),
    PooledTx = length(beamchain_mempool:get_all_txids()),
    {ok, #{
        <<"blocks">> => Blocks,
        <<"currentblocksize">> => 0,
        <<"currentblockweight">> => 0,
        <<"currentblocktx">> => 0,
        <<"bits">> => BitsHex,
        <<"difficulty">> => Difficulty,
        <<"target">> => TargetHex,
        <<"blockmintxfee">> => 0.00001000,
        <<"networkhashps">> => 0,
        <<"pooledtx">> => PooledTx,
        <<"chain">> => network_name(Network),
        <<"next">> => #{
            <<"height">> => Blocks + 1,
            <<"bits">> => BitsHex,
            <<"difficulty">> => Difficulty,
            <<"target">> => TargetHex
        },
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

%% bip22_result/1 maps a beamchain_miner:submit_block/1 error reason to
%% the canonical BIP-22 result string defined in BIP-22 and Bitcoin Core
%% BIP22ValidationResult() in src/rpc/mining.cpp.  Returns "rejected"
%% for any reason not explicitly listed.
%%
%% beamchain_validation.erl uses Erlang atoms with underscores; we map
%% to the hyphenated spec strings here, at the RPC layer.
bip22_result(high_hash)                  -> <<"high-hash">>;
bip22_result(bad_diffbits)               -> <<"bad-diffbits">>;
bip22_result(bad_merkle_root)            -> <<"bad-txnmrklroot">>;
bip22_result(mutated_merkle)             -> <<"bad-txnmrklroot">>;
%% Duplicate non-coinbase txid: Core emits bad-txns-inputs-missingorspent
%% from ConnectBlock when the second instance tries to spend an already-spent
%% prevout.  Our pre-check fires before the merkle root check to emit the
%% same canonical BIP-22 reason string (corpus: dup-txid-merkle-malleation).
bip22_result(dup_txid)                   -> <<"bad-txns-inputs-missingorspent">>;
bip22_result(bad_witness_commitment)     -> <<"bad-witness-merkle-match">>;
bip22_result(missing_witness_commitment) -> <<"bad-witness-merkle-match">>;
bip22_result(bad_witness_nonce)          -> <<"bad-witness-merkle-match">>;
bip22_result(bad_cb_amount)             -> <<"bad-cb-amount">>;
%% Non-coinbase tx where sum(inputs) < sum(outputs).
%% Core consensus/tx_verify.cpp::CheckTxInputs:
%%   state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-in-belowout", ...)
%% beamchain_validation.erl: TotalIn >= TotalOut orelse throw(insufficient_input)
bip22_result(insufficient_input)        -> <<"bad-txns-in-belowout">>;
bip22_result(bad_blk_sigops)            -> <<"bad-blk-sigops">>;
bip22_result(bad_txns_nonfinal)         -> <<"bad-txns-nonfinal">>;
%% BIP-68 SequenceLocks failure (relative locktime not met).
%% Core validation.cpp:2558: state.Invalid(BLOCK_CONSENSUS, "bad-txns-nonfinal", ...).
%% Same canonical string as IsFinalTx (nLockTime) per Core parity.
bip22_result(sequence_lock_not_met)     -> <<"bad-txns-nonfinal">>;
bip22_result(bad_coinbase_length)       -> <<"bad-cb-length">>;
%% check_transaction wraps bad_coinbase_length as {bad_tx, bad_coinbase_length};
%% match this before the generic {bad_tx, _} catch-all.
bip22_result({bad_tx, bad_coinbase_length}) -> <<"bad-cb-length">>;
bip22_result(bad_cb_height)             -> <<"bad-cb-height">>;
bip22_result(time_too_old)              -> <<"time-too-old">>;
bip22_result(time_too_new)              -> <<"time-too-new">>;
bip22_result(duplicate_inputs)          -> <<"bad-txns-duplicate">>;
%% Negative output value: check_transaction fires negative_output when value < 0.
%% The validate_block path wraps it as {bad_tx, negative_output}.
%% decode_tx_out now uses signed-little so the guard fires at CheckTransaction
%% stage rather than letting the value fall through to script evaluation.
%% Reference: consensus/tx_check.cpp::CheckTransaction (Core parity).
bip22_result({bad_tx, negative_output}) -> <<"bad-txns-vout-negative">>;
%% Output value > MAX_MONEY: check_transaction fires output_too_large when value > MAX_MONEY.
%% The validate_block path wraps it as {bad_tx, output_too_large}.
%% Reference: consensus/tx_check.cpp::CheckTransaction (Core parity).
bip22_result({bad_tx, output_too_large}) -> <<"bad-txns-vout-toolarge">>;
%% Connect-block script verification failure (validation.erl throws {script_verify_failed, Idx}).
%% Core validation.cpp:2122: "block-script-verify-flag-failed (%s)"
%% Covers disabled opcodes (OP_CAT/OP_SUBSTR/etc.), signature failures, etc.
bip22_result({script_verify_failed, _}) -> <<"block-script-verify-flag-failed">>;
bip22_result({bad_tx, _})              -> <<"block-script-verify-flag-failed">>;
bip22_result(negative_output)          -> <<"bad-txns-vout-negative">>;
%% Coinbase maturity violation: beamchain_validation.erl::check_coinbase_maturity
%% throws premature_spend_of_coinbase when confirmations < COINBASE_MATURITY.
%% Core: consensus/tx_verify.cpp::CheckTxInputs →
%% state.Invalid(TX_PREMATURE_SPEND, "bad-txns-premature-spend-of-coinbase").
bip22_result(premature_spend_of_coinbase) -> <<"bad-txns-premature-spend-of-coinbase">>;
bip22_result(duplicate)                 -> <<"duplicate">>;
%% "inconclusive" — block was stored as a side-branch (parent in index
%% but not the active tip; not heavier than active).  Per BIP-22 + Core
%% rpc/mining.cpp::submitblock, this is success-with-no-tip-flip.
bip22_result(inconclusive)              -> <<"inconclusive">>;
bip22_result(_)                         -> <<"rejected">>.

rpc_submitblock([HexData]) when is_binary(HexData) ->
    %% NetworkDisable gate: refuse submissions while a `dumptxoutset
    %% rollback` rewind→dump→replay dance is in progress. Mirrors
    %% Core's NetworkDisable RAII around TemporaryRollback in
    %% rpc/blockchain.cpp::dumptxoutset.
    case is_block_submission_paused() of
        true ->
            {ok, <<"rejected: block submission paused "
                   "(dumptxoutset rollback in progress)">>};
        false ->
            case beamchain_miner:submit_block(HexData) of
                ok ->
                    %% null = success per BIP-22
                    {ok, null};
                {error, Reason} ->
                    %% Return the BIP-22 string as the result field,
                    %% not as a JSON-RPC error.  Per BIP-22 and Bitcoin
                    %% Core BIP22ValidationResult(), consensus rejections
                    %% are result strings, not JSON-RPC error objects.
                    {ok, bip22_result(Reason)}
            end
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
        Network = beamchain_config:network(),
        NetType = case Network of mainnet -> mainnet; _ -> testnet end,
        {ok, ds_build_result(Script, NetType)}
    catch
        _:_ ->
            {error, ?RPC_DESERIALIZATION_ERROR,
             <<"Script decode failed">>}
    end;
rpc_decodescript(_) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Usage: decodescript \"hexstring\"">>}.

%% ── decodescript helpers ──────────────────────────────────────────────────────

%% ds_classify/1 — like classify_script but applies Core's Solver semantics for
%% OP_RETURN scripts: if the bytes after OP_RETURN are not IsPushOnly (e.g. a
%% truncated push), Solver returns NONSTANDARD rather than NULL_DATA.
ds_classify(<<16#6a, Rest/binary>> = _Script) ->
    case ds_is_push_only(Rest) of
        true  -> op_return;
        false -> nonstandard
    end;
ds_classify(Script) ->
    beamchain_address:classify_script(Script).

%% ds_is_push_only/1 — mirrors CScript::IsPushOnly: all opcodes must be
%% push opcodes (OP_0 / OP_1NEGATE / OP_1..OP_16 / direct pushes) and all
%% push lengths must be satisfied within the remaining bytes.
ds_is_push_only(<<>>) -> true;
ds_is_push_only(<<16#00, Rest/binary>>) ->            %% OP_0
    ds_is_push_only(Rest);
ds_is_push_only(<<16#4f, Rest/binary>>) ->            %% OP_1NEGATE
    ds_is_push_only(Rest);
ds_is_push_only(<<Op, Rest/binary>>) when Op >= 16#51, Op =< 16#60 ->  %% OP_1..OP_16
    ds_is_push_only(Rest);
ds_is_push_only(<<16#4c, Len:8, Data:Len/binary, Rest/binary>>) ->    %% OP_PUSHDATA1
    _ = Data, ds_is_push_only(Rest);
ds_is_push_only(<<16#4d, Len:16/little, Data:Len/binary, Rest/binary>>) -> %% OP_PUSHDATA2
    _ = Data, ds_is_push_only(Rest);
ds_is_push_only(<<16#4e, Len:32/little, Data:Len/binary, Rest/binary>>) -> %% OP_PUSHDATA4
    _ = Data, ds_is_push_only(Rest);
ds_is_push_only(<<Len, Data:Len/binary, Rest/binary>>) when Len >= 16#01, Len =< 16#4b ->
    _ = Data, ds_is_push_only(Rest);
ds_is_push_only(_) -> false.   %% truncated push or non-push opcode

%% ds_is_unspendable/1 — mirrors CScript::IsUnspendable: starts with OP_RETURN.
ds_is_unspendable(<<16#6a, _/binary>>) -> true;
ds_is_unspendable(_)                   -> false.

%% ds_has_op_checksigadd/1 — contains OP_CHECKSIGADD (0xba) or OP_SUCCESS.
%% For decodescript we only need to exclude scripts with OP_CHECKSIGADD.
ds_has_op_checksigadd(Script) ->
    binary:match(Script, <<16#ba>>) =/= nomatch.

%% ds_can_wrap/2 — Core's can_wrap predicate.
ds_can_wrap(p2pkh,   Script) -> not ds_is_unspendable(Script) andalso not ds_has_op_checksigadd(Script);
ds_can_wrap(p2wpkh,  Script) -> not ds_is_unspendable(Script) andalso not ds_has_op_checksigadd(Script);
ds_can_wrap(p2wsh,   Script) -> not ds_is_unspendable(Script) andalso not ds_has_op_checksigadd(Script);
ds_can_wrap(nonstandard, Script) -> not ds_is_unspendable(Script) andalso not ds_has_op_checksigadd(Script);
%% NULL_DATA / P2SH / P2TR / WITNESS_UNKNOWN → cannot wrap
ds_can_wrap(op_return, _)    -> false;
ds_can_wrap(p2sh, _)         -> false;
ds_can_wrap(p2tr, _)         -> false;
ds_can_wrap({witness, _, _}, _) -> false;
ds_can_wrap(_, _)            -> false.

%% ds_can_wrap_p2wsh/1 — Core's can_wrap_P2WSH predicate (called only when can_wrap=true).
%% PUBKEY/MULTISIG: only if all pubkeys compressed (beamchain's classify returns nonstandard
%% for multisig, so we only need to handle p2pkh and nonstandard).
%% PUBKEYHASH / NONSTANDARD → true
%% Already-segwit (p2wpkh, p2wsh) → false
ds_can_wrap_p2wsh(p2pkh)       -> true;
ds_can_wrap_p2wsh(nonstandard) -> true;
ds_can_wrap_p2wsh(_)           -> false.

%% ds_p2sh_wrap_address/2 — P2SH(script): base58-encode Hash160(script).
ds_p2sh_wrap_address(Script, NetType) ->
    H160 = beamchain_crypto:hash160(Script),
    P2SHScript = <<16#a9, 16#14, H160/binary, 16#87>>,
    Addr = beamchain_address:script_to_address(P2SHScript, NetType),
    iolist_to_binary(Addr).

%% ds_build_p2wpkh_script/1 — OP_0 <20-byte hash>
ds_build_p2wpkh_script(Hash20) when byte_size(Hash20) =:= 20 ->
    <<16#00, 16#14, Hash20/binary>>.

%% ds_build_p2wsh_script/1 — OP_0 <SHA256(script)>
ds_build_p2wsh_script(Script) ->
    H = beamchain_crypto:sha256(Script),
    <<16#00, 16#20, H/binary>>.

%% ds_build_result/2 — produce the full decodescript JSON map.
ds_build_result(Script, NetType) ->
    TypeAtom = ds_classify(Script),
    TypeBin  = script_type_name(TypeAtom),
    Asm      = script_to_asm_core(Script),
    Desc     = infer_spk_descriptor(Script, NetType),
    Base = #{
        <<"asm">>  => Asm,
        <<"desc">> => Desc,
        <<"type">> => TypeBin
    },
    %% address: only when script_to_address succeeds (no null, no hex field)
    Base1 = case beamchain_address:script_to_address(Script, NetType) of
        unknown     -> Base;
        "OP_RETURN" -> Base;
        Addr        -> Base#{<<"address">> => iolist_to_binary(Addr)}
    end,
    %% p2sh wrap (and optionally segwit inner)
    case ds_can_wrap(TypeAtom, Script) of
        false ->
            Base1;
        true ->
            P2SH = ds_p2sh_wrap_address(Script, NetType),
            Base2 = Base1#{<<"p2sh">> => P2SH},
            case ds_can_wrap_p2wsh(TypeAtom) of
                false ->
                    Base2;
                true ->
                    SegwitScript = case TypeAtom of
                        p2pkh ->
                            %% Extract 20-byte hash from P2PKH: skip OP_DUP OP_HASH160 <len>
                            <<_:3/binary, H20:20/binary, _/binary>> = Script,
                            ds_build_p2wpkh_script(H20);
                        _ ->
                            %% nonstandard (including truncated-OP_RETURN): P2WSH
                            ds_build_p2wsh_script(Script)
                    end,
                    SegwitType = beamchain_address:classify_script(SegwitScript),
                    SegwitTypeBin = script_type_name(SegwitType),
                    SegwitAsm  = script_to_asm_core(SegwitScript),
                    SegwitDesc = infer_spk_descriptor(SegwitScript, NetType),
                    SegwitHex  = beamchain_serialize:hex_encode(SegwitScript),
                    SegwitBase = #{
                        <<"asm">>  => SegwitAsm,
                        <<"desc">> => SegwitDesc,
                        <<"hex">>  => SegwitHex,
                        <<"type">> => SegwitTypeBin
                    },
                    SegwitBase1 = case beamchain_address:script_to_address(SegwitScript, NetType) of
                        unknown     -> SegwitBase;
                        "OP_RETURN" -> SegwitBase;
                        SegAddr     -> SegwitBase#{<<"address">> => iolist_to_binary(SegAddr)}
                    end,
                    SegwitP2SH = ds_p2sh_wrap_address(SegwitScript, NetType),
                    SegwitInner = SegwitBase1#{<<"p2sh-segwit">> => SegwitP2SH},
                    Base2#{<<"segwit">> => SegwitInner}
            end
    end.

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

%% Convert compact bits to 64-char lowercase hex target string (Core format).
bits_to_target_hex(Bits) ->
    Target = beamchain_pow:bits_to_target(Bits),
    Hex = iolist_to_binary(io_lib:format("~64.16.0b", [Target])),
    %% io_lib:format ~16.0b produces uppercase; lowercase it
    << <<(case C of C when C >= $A, C =< $F -> C + 32; _ -> C end)>>
       || <<C>> <= Hex >>.

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
%%
%% NOTE: This 1-arg variant has no way to verify the caller's block is on the
%% active chain.  It is correct only when the height/block is known-canonical
%% (e.g. chainstate-derived UTXO heights in `gettxout`).  For RPC paths that
%% accept a user-supplied block hash (`getblock`, `getblockheader`,
%% `getrawtransaction`), use the 2-arg `confirmations/2` variant which
%% checks active-chain ancestry.  Pattern C1 invariant from
%% bitcoin-core/src/rpc/blockchain.cpp: post-disconnect blocks must report
%% confirmations = 0 (or -1 in some endpoints), never the height delta.
confirmations(BlockHeight) ->
    case beamchain_chainstate:get_tip() of
        {ok, {_, TipHeight}} -> TipHeight - BlockHeight + 1;
        not_found -> 0
    end.

%% Number of confirmations, gated on active-chain ancestry.
%% Returns 0 when the block is not on the active chain (disconnected by reorg).
%% Mirrors Core's `tip->GetAncestor(blockindex->nHeight) == blockindex` check
%% in src/rpc/blockchain.cpp (used by getblock / getblockheader /
%% getrawtransaction).  Pattern C1 fix — see
%% CORE-PARITY-AUDIT/_txindex-revert-on-reorg-fleet-result-2026-05-05.md.
confirmations(BlockHeight, BlockHash) when is_binary(BlockHash) ->
    case is_block_in_active_chain(BlockHash) of
        true ->
            confirmations(BlockHeight);
        false ->
            0
    end;
confirmations(BlockHeight, _) ->
    %% Fallback: hash unavailable — best effort
    confirmations(BlockHeight).

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
    %% Build coinbase_tx from first transaction's first input (Core 27+ field)
    CoinbaseTx = case Txs of
        [] -> null;
        [CbTx | _] ->
            {CbSeq, CbScript, CbWitness} = case CbTx#transaction.inputs of
                [Inp | _] ->
                    Wit = case Inp#tx_in.witness of
                        [W0 | _] -> beamchain_serialize:hex_encode(W0);
                        _ -> undefined
                    end,
                    {Inp#tx_in.sequence,
                     beamchain_serialize:hex_encode(Inp#tx_in.script_sig),
                     Wit};
                [] -> {16#ffffffff, <<>>, undefined}
            end,
            Base = #{
                <<"version">>  => CbTx#transaction.version,
                <<"locktime">> => CbTx#transaction.locktime,
                <<"sequence">> => CbSeq,
                <<"coinbase">> => CbScript
            },
            case CbWitness of
                undefined -> Base;
                W -> Base#{<<"witness">> => W}
            end
    end,
    #{
        <<"hash">> => hash_to_hex(Hash),
        <<"confirmations">> => confirmations(Height, Hash),
        <<"height">> => Height,
        <<"version">> => Header#block_header.version,
        <<"versionHex">> => beamchain_serialize:hex_encode(
            <<(Header#block_header.version):32/big>>),
        <<"merkleroot">> => hash_to_hex(Header#block_header.merkle_root),
        <<"time">> => Header#block_header.timestamp,
        <<"mediantime">> => block_mtp(Height),
        <<"nonce">> => Header#block_header.nonce,
        <<"bits">> => beamchain_serialize:hex_encode(<<Bits:32/big>>),
        <<"target">> => bits_to_target_hex(Bits),
        <<"difficulty">> => bits_to_difficulty(Bits),
        <<"chainwork">> => beamchain_serialize:hex_encode(Chainwork),
        <<"nTx">> => length(Txs),
        <<"previousblockhash">> => hash_to_hex(
            Header#block_header.prev_hash),
        <<"nextblockhash">> => NextHash,
        <<"size">> => Size,
        <<"weight">> => Weight,
        <<"strippedsize">> => stripped_size(Block),
        <<"tx">> => TxList,
        <<"coinbase_tx">> => CoinbaseTx
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

%% @doc Return the BIP-39 mnemonic backing the wallet, if any.
%%
%% This is intentionally a separate RPC from `dumpprivkey` because the
%% mnemonic recovers ALL private keys at once. Operators must store the
%% output offline; treat it as the most sensitive material in the
%% wallet. The RPC returns {error,no_mnemonic} for raw-seed wallets.
rpc_getwalletmnemonic(WalletName) ->
    case resolve_wallet(WalletName) of
        {ok, Pid} ->
            case beamchain_wallet:getwalletmnemonic(Pid) of
                {ok, Words} ->
                    Joined = iolist_to_binary(
                        lists:join(<<" ">>, Words)),
                    {ok, #{
                        <<"mnemonic">> => Joined,
                        <<"wordcount">> => length(Words),
                        <<"warning">> => <<"BACKUP THIS MNEMONIC OFFLINE. "
                                           "Anyone with this phrase can "
                                           "spend all wallet funds.">>
                    }};
                {error, no_mnemonic} ->
                    {error, ?RPC_MISC_ERROR,
                     <<"Wallet was not created from a BIP-39 mnemonic">>};
                {error, wallet_locked} ->
                    {error, ?RPC_MISC_ERROR,
                     <<"Error: Please enter the wallet passphrase with "
                       "walletpassphrase first.">>};
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

%% @doc lockunspent unlock ( [{"txid":...,"vout":n},...] persistent )
%%
%% Mirrors `bitcoin-core/src/wallet/rpc/coins.cpp::lockunspent`. Temporarily
%% locks (unlock=false) or unlocks (unlock=true) the listed transaction
%% outputs so they will be skipped by automatic coin selection.
%%
%% - `unlock=true` with no transactions clears all locks ("UnlockAllCoins").
%% - `unlock=true` with locks cleared in the same call must error if the
%%   coin was never locked (Core: "expected locked output").
%% - `unlock=false` requires the coin to be unspent in the UTXO set, and
%%   refuses to lock an already-locked coin unless `persistent` is true
%%   (memory locks are upgraded to disk locks).  We accept `persistent` for
%%   parity but only store in memory; persistence is a TODO.
rpc_lockunspent([Unlock], WalletName) when is_boolean(Unlock) ->
    rpc_lockunspent([Unlock, null, false], WalletName);
rpc_lockunspent([Unlock, Transactions], WalletName) ->
    rpc_lockunspent([Unlock, Transactions, false], WalletName);
rpc_lockunspent([Unlock, Transactions, Persistent], WalletName)
        when is_boolean(Unlock), is_boolean(Persistent) ->
    case resolve_wallet(WalletName) of
        {ok, Pid} ->
            do_lockunspent(Pid, Unlock, Transactions, Persistent);
        {error, _} ->
            wallet_not_found_error(WalletName)
    end;
rpc_lockunspent(_, _) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"lockunspent unlock ( [{\"txid\":\"hex\",\"vout\":n},...] persistent )">>}.

do_lockunspent(Pid, true, null, _Persistent) ->
    %% unlock=true, no transactions: clear all locks.
    ok = beamchain_wallet:unlock_all_coins(Pid),
    {ok, true};
do_lockunspent(_Pid, false, null, _Persistent) ->
    %% lock=true requires a transactions list per Core (param[1] not optional
    %% on the lock path).  Mirror Core's `request.params[1].isNull()` check
    %% which only short-circuits on the unlock path.
    {error, ?RPC_INVALID_PARAMS,
     <<"Invalid parameter, transactions array required when locking">>};
do_lockunspent(Pid, Unlock, Transactions, _Persistent)
        when is_list(Transactions) ->
    %% Two-phase per Core: validate every outpoint first, then mutate.
    case parse_lock_outpoints(Transactions, Pid, Unlock) of
        {ok, Outpoints} ->
            lists:foreach(fun({Txid, Vout}) ->
                case Unlock of
                    true ->
                        %% We've already verified is_locked above; ignore
                        %% the {error, not_locked} race-window result.
                        _ = beamchain_wallet:unlock_coin(Pid, Txid, Vout);
                    false ->
                        ok = beamchain_wallet:lock_coin(Pid, Txid, Vout)
                end
            end, Outpoints),
            {ok, true};
        {error, Code, Msg} ->
            {error, Code, Msg}
    end;
do_lockunspent(_Pid, _Unlock, _BadTx, _Persistent) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"Invalid parameter, transactions must be an array">>}.

%% Validate every outpoint and (un)lock-state predicate before mutating.
parse_lock_outpoints(Transactions, Pid, Unlock) ->
    try
        Outs = lists:map(fun(Obj) ->
            validate_lock_outpoint(Obj, Pid, Unlock)
        end, Transactions),
        {ok, Outs}
    catch
        throw:{lock_param_error, Msg} ->
            {error, ?RPC_INVALID_PARAMETER, Msg}
    end.

validate_lock_outpoint(Obj, Pid, Unlock) when is_map(Obj) ->
    TxidHex = case maps:get(<<"txid">>, Obj, undefined) of
        undefined ->
            throw({lock_param_error,
                   <<"Invalid parameter, missing txid">>});
        T when is_binary(T) -> T;
        _ ->
            throw({lock_param_error,
                   <<"Invalid parameter, txid must be a string">>})
    end,
    Vout = case maps:get(<<"vout">>, Obj, undefined) of
        undefined ->
            throw({lock_param_error,
                   <<"Invalid parameter, missing vout">>});
        V when is_integer(V), V >= 0 -> V;
        V when is_integer(V) ->
            throw({lock_param_error,
                   <<"Invalid parameter, vout cannot be negative">>});
        _ ->
            throw({lock_param_error,
                   <<"Invalid parameter, vout must be a number">>})
    end,
    Txid = try hex_to_internal_hash(TxidHex)
           catch _:_ ->
               throw({lock_param_error,
                      <<"Invalid parameter, txid is not a hex string">>})
           end,
    case byte_size(Txid) of
        32 -> ok;
        _ ->
            throw({lock_param_error,
                   <<"Invalid parameter, txid must be 32 bytes">>})
    end,
    IsLocked = beamchain_wallet:is_locked_coin(Pid, {Txid, Vout}),
    case {Unlock, IsLocked} of
        {true, false} ->
            throw({lock_param_error,
                   <<"Invalid parameter, expected locked output">>});
        {false, true} ->
            throw({lock_param_error,
                   <<"Invalid parameter, output already locked">>});
        _ -> ok
    end,
    {Txid, Vout};
validate_lock_outpoint(_, _, _) ->
    throw({lock_param_error,
           <<"Invalid parameter, transactions entries must be objects">>}).

%% @doc listlockunspent: return all locked outpoints in this wallet.
%% Mirrors `bitcoin-core/src/wallet/rpc/coins.cpp::listlockunspent`.
%% Output objects use Core's display-order txid (big-endian hex).
rpc_listlockunspent(WalletName) ->
    case resolve_wallet(WalletName) of
        {ok, Pid} ->
            Locked = beamchain_wallet:list_locked_coins(Pid),
            Result = [#{<<"txid">> => hash_to_hex(Txid),
                        <<"vout">> => Vout}
                      || {Txid, Vout} <- Locked],
            {ok, Result};
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
                %% Gather UTXO data + optional witness/redeem-script info
                %% from prevtxs (Wave 28: needed for P2WSH / P2SH-P2WSH
                %% raw-tx signing). Falls back to UTXO set lookup.
                Lookups = lists:map(fun(#tx_in{prev_out = #outpoint{hash = H, index = I}}) ->
                    case find_prevtx(PrevTxs, H, I) of
                        {ok, Utxo, Info} -> {Utxo, Info};
                        not_found ->
                            case beamchain_chainstate:get_utxo(H, I) of
                                {ok, Utxo} -> {Utxo, #{}};
                                not_found -> throw({missing_input, H, I})
                            end
                    end
                end, Tx#transaction.inputs),
                InputUtxos = [U || {U, _} <- Lookups],
                ScriptInfos = [I || {_, I} <- Lookups],
                %% Get private keys from wallet for each input
                PrivKeys = lists:map(fun(Utxo) ->
                    Address = beamchain_address:script_to_address(
                        Utxo#utxo.script_pubkey, beamchain_config:network()),
                    case beamchain_wallet:get_private_key(Pid, Address) of
                        {ok, Key} -> Key;
                        _ -> <<0:256>>  %% Placeholder for keys not in this wallet
                    end
                end, InputUtxos),
                case beamchain_wallet:sign_transaction(
                       Tx, InputUtxos, PrivKeys, ScriptInfos) of
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
%% Returns {ok, #utxo{}, ScriptInfo} where ScriptInfo carries
%% witness_script / redeem_script when present (Wave 28: needed for
%% P2WSH / P2SH-P2WSH raw-tx signing).
find_prevtx([], _Hash, _Index) -> not_found;
find_prevtx([#{<<"txid">> := TxidHex, <<"vout">> := Vout,
               <<"scriptPubKey">> := ScriptHex} = Map | Rest], Hash, Index) ->
    case {hex_to_internal_hash(TxidHex), Vout} of
        {Hash, Index} ->
            Amount = maps:get(<<"amount">>, Map, 0),
            ScriptInfo = collect_script_info(Map),
            {ok,
             #utxo{
                value = btc_to_satoshi(Amount),
                script_pubkey = beamchain_serialize:hex_decode(ScriptHex),
                height = 0,
                is_coinbase = false
             },
             ScriptInfo};
        _ ->
            find_prevtx(Rest, Hash, Index)
    end;
find_prevtx([_ | Rest], Hash, Index) ->
    find_prevtx(Rest, Hash, Index).

%% Build a script_info map from a prevtx entry. Both `witnessScript`
%% and `redeemScript` are accepted (Bitcoin Core RPC parity); both are
%% hex-decoded. Missing fields are simply absent from the map.
collect_script_info(Map) ->
    Acc0 = #{},
    Acc1 = case maps:get(<<"witnessScript">>, Map, undefined) of
        undefined -> Acc0;
        WSHex when is_binary(WSHex) ->
            Acc0#{witness_script => beamchain_serialize:hex_decode(WSHex)}
    end,
    Acc2 = case maps:get(<<"redeemScript">>, Map, undefined) of
        undefined -> Acc1;
        RSHex when is_binary(RSHex) ->
            Acc1#{redeem_script => beamchain_serialize:hex_decode(RSHex)}
    end,
    Acc2.

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
                {ok_raw_json, encode_psbt_decode(Psbt)};
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

%% @doc analyzepsbt "psbt"
%%
%% Analyzes a PSBT and reports per-input status (has_utxo / is_final / what
%% is missing / role of next signer) plus aggregate fee and estimated vsize
%% when calculable.  Mirrors `bitcoin-core/src/rpc/rawtransaction.cpp::
%% analyzepsbt` and `bitcoin-core/src/node/psbt.cpp::AnalyzePSBT`.
%%
%% Beamchain follows the same input-by-input ratchet on the role enum
%% (CREATOR < UPDATER < SIGNER < FINALIZER < EXTRACTOR) and selects the
%% "minimum" role across inputs.  The next-role heuristic is approximate:
%% Core's `SignPSBTInput(DUMMY_SIGNING_PROVIDER, ...)` walks the script
%% engine to figure out exactly what is missing; we surface the same
%% structure (`missing.signatures`, `missing.pubkeys`, `missing.redeemscript`,
%% `missing.witnessscript`) but populate it from the PSBT input map's raw
%% absences rather than a dummy-sign pass.
rpc_analyzepsbt([PsbtB64]) when is_binary(PsbtB64) ->
    try
        PsbtBin = base64:decode(PsbtB64),
        case beamchain_psbt:decode(PsbtBin) of
            {ok, Psbt} ->
                {ok, analyze_psbt(Psbt)};
            {error, Reason} ->
                {error, ?RPC_DESERIALIZATION_ERROR,
                 iolist_to_binary(io_lib:format("TX decode failed ~p",
                                                 [Reason]))}
        end
    catch
        error:badarg ->
            {error, ?RPC_DESERIALIZATION_ERROR,
             <<"TX decode failed Invalid base64 encoding">>};
        _:Err ->
            {error, ?RPC_MISC_ERROR,
             iolist_to_binary(io_lib:format("Error: ~p", [Err]))}
    end;
rpc_analyzepsbt(_) ->
    {error, ?RPC_INVALID_PARAMS, <<"analyzepsbt \"psbt\"">>}.

%% Build the analyzepsbt response object. Pure function, exposed via
%% rpc_analyzepsbt; no side effects so eunit can call it directly.
%% (The `#psbt{}` record is module-local to beamchain_psbt; we treat it
%%  here as an opaque term passed through `beamchain_psbt:get_*` getters.)
analyze_psbt(Psbt) ->
    Tx = beamchain_psbt:get_unsigned_tx(Psbt),
    NumInputs = length(Tx#transaction.inputs),
    Indices = lists:seq(0, NumInputs - 1),
    %% Per-input analysis + accumulator for fee math.
    Inputs0 = lists:map(fun(Idx) ->
        analyze_psbt_input(Psbt, Tx, Idx)
    end, Indices),
    %% Determine if all inputs have a UTXO (required for fee/vsize).
    AllHaveUtxo = lists:all(fun(M) ->
        maps:get(has_utxo_internal, M, false)
    end, Inputs0),
    %% Strip internal helper keys before returning.
    Inputs = [maps:without([has_utxo_internal, in_value_internal,
                             role_internal], M) || M <- Inputs0],
    %% Compute aggregate next role: minimum of all input roles, defaulting
    %% to EXTRACTOR if there are no inputs (Core's `assert(result.next >
    %% PSBTRole::CREATOR)` is upheld by `min/2` starting at EXTRACTOR=4).
    Roles = [maps:get(role_internal, M, ?PSBT_ROLE_UPDATER) || M <- Inputs0],
    NextRole = case Roles of
        [] -> ?PSBT_ROLE_EXTRACTOR;
        _  -> lists:min(Roles)
    end,
    Base = #{<<"next">> => psbt_role_name(NextRole)},
    Base1 = case Inputs of
        [] -> Base;
        _  -> Base#{<<"inputs">> => Inputs}
    end,
    case AllHaveUtxo andalso NumInputs > 0 of
        true ->
            InAmt = lists:sum([maps:get(in_value_internal, M, 0)
                               || M <- Inputs0]),
            OutAmt = lists:sum([O#tx_out.value
                                || O <- Tx#transaction.outputs]),
            Fee = InAmt - OutAmt,
            EstVSize = estimate_psbt_vsize(Psbt, Tx),
            BaseFee = Base1#{<<"fee">> => satoshi_to_btc(Fee)},
            case EstVSize of
                undefined -> BaseFee;
                VSize ->
                    %% Core's CFeeRate(fee, size) returns sat/kvB, then
                    %% ValueFromAmount converts to BTC/kvB.  We return BTC/kvB.
                    FeeRateSatPerKvB = case VSize of
                        0 -> 0;
                        _ -> (Fee * 1000) div VSize
                    end,
                    BaseFee#{<<"estimated_vsize">> => VSize,
                             <<"estimated_feerate">> =>
                                 satoshi_to_btc(FeeRateSatPerKvB)}
            end;
        false ->
            Base1
    end.

%% Per-input analysis: returns a map with the user-visible JSON keys plus
%% `has_utxo_internal`, `in_value_internal`, `role_internal` for the caller.
analyze_psbt_input(Psbt, Tx, Idx) ->
    InputMap = beamchain_psbt:get_input(Psbt, Idx),
    {HasUtxo, UtxoValue, ScriptPubKey} =
        case maps:get(witness_utxo, InputMap, undefined) of
            {V, S} -> {true, V, S};
            _ ->
                case maps:get(non_witness_utxo, InputMap, undefined) of
                    PrevTx when is_record(PrevTx, transaction) ->
                        Input = lists:nth(Idx + 1, Tx#transaction.inputs),
                        Vout = (Input#tx_in.prev_out)#outpoint.index,
                        case length(PrevTx#transaction.outputs) > Vout of
                            true ->
                                Out = lists:nth(Vout + 1,
                                                PrevTx#transaction.outputs),
                                {true, Out#tx_out.value,
                                 Out#tx_out.script_pubkey};
                            false ->
                                {false, 0, <<>>}
                        end;
                    _ ->
                        {false, 0, <<>>}
                end
        end,
    IsFinal = maps:get(final_script_sig, InputMap, undefined) =/= undefined
              orelse
              maps:get(final_script_witness, InputMap, undefined) =/= undefined,
    {Role, Missing} = analyze_input_role(InputMap, HasUtxo, IsFinal,
                                          ScriptPubKey),
    Out0 = #{<<"has_utxo">>         => HasUtxo,
             <<"is_final">>         => IsFinal,
             <<"next">>             => psbt_role_name(Role),
             has_utxo_internal      => HasUtxo,
             in_value_internal      => UtxoValue,
             role_internal          => Role},
    case map_size(Missing) of
        0 -> Out0;
        _ -> Out0#{<<"missing">> => Missing}
    end.

%% Decide the next-role for an input.  Core walks `SignPSBTInput` with a
%% dummy signing provider; we replicate the rough taxonomy without running
%% the script engine:
%%   - no UTXO          -> UPDATER (next person needs to fill it in)
%%   - finalized        -> EXTRACTOR
%%   - has UTXO + sigs    + redeem/witness scripts where required -> FINALIZER
%%   - has UTXO + missing redeem/witness script -> UPDATER
%%   - has UTXO + missing partial sigs only -> SIGNER
analyze_input_role(_Map, false, _IsFinal, _Spk) ->
    {?PSBT_ROLE_UPDATER, #{}};
analyze_input_role(_Map, true, true, _Spk) ->
    {?PSBT_ROLE_EXTRACTOR, #{}};
analyze_input_role(InputMap, true, false, ScriptPubKey) ->
    %% Detect script type from scriptPubKey (mirrors Core's GetSignatureFromScriptType).
    ScriptType = beamchain_address:classify_script(ScriptPubKey),
    PartialSigs = maps:get(partial_sigs, InputMap, #{}),
    HasRedeem  = maps:get(redeem_script, InputMap, undefined) =/= undefined,
    HasWitness = maps:get(witness_script, InputMap, undefined) =/= undefined,
    HasTapKey  = maps:get(tap_key_sig, InputMap, undefined) =/= undefined,
    %% Build the missing-set per input type.
    case ScriptType of
        p2tr ->
            case HasTapKey of
                true ->
                    {?PSBT_ROLE_FINALIZER, #{}};
                false ->
                    {?PSBT_ROLE_SIGNER, #{}}
            end;
        p2sh ->
            %% Need redeem script + sig.
            Missing0 = case HasRedeem of
                true  -> #{};
                false -> #{<<"redeemscript">> =>
                              %% Hash of expected redeemScript = OP_HASH160
                              %% target.  Without solving data we surface
                              %% the spk-derived hash160 (20 bytes).
                              extract_p2sh_hash(ScriptPubKey)}
            end,
            case map_size(PartialSigs) of
                0 ->
                    {?PSBT_ROLE_SIGNER, Missing0};
                _ ->
                    case HasRedeem of
                        true  -> {?PSBT_ROLE_FINALIZER, Missing0};
                        false -> {?PSBT_ROLE_UPDATER, Missing0}
                    end
            end;
        p2wsh ->
            Missing0 = case HasWitness of
                true  -> #{};
                false -> #{<<"witnessscript">> =>
                              extract_p2wsh_hash(ScriptPubKey)}
            end,
            case map_size(PartialSigs) of
                0 ->
                    {?PSBT_ROLE_SIGNER, Missing0};
                _ ->
                    case HasWitness of
                        true  -> {?PSBT_ROLE_FINALIZER, Missing0};
                        false -> {?PSBT_ROLE_UPDATER, Missing0}
                    end
            end;
        _PkOrPwpkh ->
            %% P2PKH / P2WPKH / P2PK / unknown — sig + pubkey suffice.
            case map_size(PartialSigs) of
                0 ->
                    {?PSBT_ROLE_SIGNER, #{}};
                _ ->
                    {?PSBT_ROLE_FINALIZER, #{}}
            end
    end.

%% Extract the 20-byte hash160 from a P2SH scriptPubKey (OP_HASH160 <20> ...).
extract_p2sh_hash(<<16#a9, 20, H:20/binary, 16#87>>) ->
    beamchain_serialize:hex_encode(H);
extract_p2sh_hash(_) ->
    <<>>.

%% Extract the 32-byte sha256 from a P2WSH scriptPubKey (OP_0 <32>).
extract_p2wsh_hash(<<16#00, 32, H:32/binary>>) ->
    beamchain_serialize:hex_encode(H);
extract_p2wsh_hash(_) ->
    <<>>.

%% Estimate vsize of the would-be-finalized tx.  Returns `undefined` when
%% the inputs cannot be solved (mirrors Core's "if SignPSBTInput fails,
%% size estimation fails too" branch).
estimate_psbt_vsize(Psbt, Tx) ->
    InputMaps = lists:map(fun(I) ->
        beamchain_psbt:get_input(Psbt, I)
    end, lists:seq(0, length(Tx#transaction.inputs) - 1)),
    %% Best-effort vsize: base tx weight + per-input weight estimate based
    %% on script type derived from the witness UTXO scriptPubKey.  Returns
    %% `undefined` if any input is missing both partial sigs and a witness
    %% UTXO (cannot estimate without solving data).
    BaseWeight = (length(Tx#transaction.outputs) * 31 + 11) * 4,
    case sum_input_weights(InputMaps, 0) of
        undefined -> undefined;
        InWeight  ->
            Weight = BaseWeight + InWeight,
            (Weight + 3) div 4
    end.

sum_input_weights([], Acc) -> Acc;
sum_input_weights([M | Rest], Acc) ->
    case maps:get(witness_utxo, M, undefined) of
        {_, Spk} ->
            W = input_weight_for_script(Spk),
            sum_input_weights(Rest, Acc + W);
        _ ->
            case maps:get(non_witness_utxo, M, undefined) of
                undefined -> undefined;
                _ ->
                    %% Conservative legacy P2PKH-equivalent weight (148 bytes).
                    sum_input_weights(Rest, Acc + 148 * 4)
            end
    end.

input_weight_for_script(Spk) ->
    case beamchain_address:classify_script(Spk) of
        p2wpkh -> 68 * 4;            %% ~68 vbytes
        p2tr   -> 57 * 4;            %% ~57 vbytes (key-path)
        p2pkh  -> 148 * 4;
        p2sh   -> 91 * 4;            %% wrapped segwit estimate
        p2wsh  -> 105 * 4;           %% multi-sig estimate
        _      -> 100 * 4
    end.

psbt_role_name(?PSBT_ROLE_CREATOR)   -> <<"creator">>;
psbt_role_name(?PSBT_ROLE_UPDATER)   -> <<"updater">>;
psbt_role_name(?PSBT_ROLE_SIGNER)    -> <<"signer">>;
psbt_role_name(?PSBT_ROLE_FINALIZER) -> <<"finalizer">>;
psbt_role_name(?PSBT_ROLE_EXTRACTOR) -> <<"extractor">>.

%% @doc walletcreatefundedpsbt
%%   inputs outputs ( locktime options bip32derivs )
%%
%% Mirrors `bitcoin-core/src/wallet/rpc/spend.cpp::walletcreatefundedpsbt`.
%% Implements the Creator and Updater roles: pulls UTXOs from the wallet's
%% own UTXO set, runs `select_coins/3` with the fee rate, optionally adds
%% caller-supplied inputs, builds the unsigned tx, and wraps it as a PSBT
%% with witness UTXO information attached for each wallet-owned input.
%%
%% Returns `{ok, #{psbt, fee, changepos}}` on success.  Fees are reported in
%% BTC and `changepos` is the index of the appended change output (-1 if no
%% change).  We always append change at the end (Core's `changePosition`
%% defaults to a random position; we omit randomization for parity with
%% beamchain's existing send-path determinism).
rpc_walletcreatefundedpsbt([Inputs, Outputs], WalletName) ->
    rpc_walletcreatefundedpsbt([Inputs, Outputs, 0, #{}, true], WalletName);
rpc_walletcreatefundedpsbt([Inputs, Outputs, Locktime], WalletName) ->
    rpc_walletcreatefundedpsbt([Inputs, Outputs, Locktime, #{}, true],
                                WalletName);
rpc_walletcreatefundedpsbt([Inputs, Outputs, Locktime, Options], WalletName) ->
    rpc_walletcreatefundedpsbt([Inputs, Outputs, Locktime, Options, true],
                                WalletName);
rpc_walletcreatefundedpsbt([Inputs, Outputs, Locktime, Options, _Bip32Derivs],
                            WalletName)
        when is_list(Inputs), is_integer(Locktime), is_map(Options) ->
    case resolve_wallet(WalletName) of
        {ok, Pid} ->
            try
                do_walletcreatefundedpsbt(Pid, Inputs, Outputs, Locktime,
                                           Options)
            catch
                throw:{wcfp_error, Code, Msg} ->
                    {error, Code, Msg};
                _:Err ->
                    {error, ?RPC_MISC_ERROR,
                     iolist_to_binary(io_lib:format("Error: ~p", [Err]))}
            end;
        {error, _} ->
            wallet_not_found_error(WalletName)
    end;
rpc_walletcreatefundedpsbt(_, _) ->
    {error, ?RPC_INVALID_PARAMS,
     <<"walletcreatefundedpsbt [{\"txid\":\"hex\",\"vout\":n},...] "
       "[{\"address\":amount},...] ( locktime options bip32derivs )">>}.

do_walletcreatefundedpsbt(Pid, ManualInputs, Outputs, Locktime, Options) ->
    Network = beamchain_config:network(),
    %% Caller-supplied outputs may arrive as a list-of-maps (Core normalizes
    %% to a single object internally).  Normalize to {Address, Satoshis}.
    OutputPairs = normalize_wcfp_outputs(Outputs, Network),
    case OutputPairs of
        [] ->
            throw({wcfp_error, ?RPC_INVALID_PARAMS,
                   <<"At least one output required">>});
        _ -> ok
    end,
    OutputTotal = lists:sum([Sat || {_, Sat} <- OutputPairs]),
    %% Manual inputs: caller is asserting the UTXO exists.  Look up the
    %% chainstate UTXO so we can include witness UTXO info in the PSBT.
    ManualInputUtxos = lists:map(fun(InObj) ->
        TxidHex = maps:get(<<"txid">>, InObj),
        Vout = maps:get(<<"vout">>, InObj),
        Txid = hex_to_internal_hash(TxidHex),
        case beamchain_chainstate:get_utxo(Txid, Vout) of
            {ok, U} -> {Txid, Vout, U};
            not_found ->
                throw({wcfp_error, ?RPC_INVALID_PARAMETER,
                       iolist_to_binary(io_lib:format(
                           "Input not found in UTXO set: ~s:~B",
                           [TxidHex, Vout]))})
        end
    end, ManualInputs),
    %% Coin selection.  `add_inputs` defaults to true when no manual inputs
    %% were passed and false otherwise (Core: `m_allow_other_inputs =
    %% rawTx.vin.size() == 0`).
    AddInputs = maps:get(<<"add_inputs">>, Options,
                          ManualInputs =:= []),
    FeeRate = wcfp_fee_rate(Options),
    %% sat/vbyte (Core's CFeeRate is sat/kvB; we accept BTC/kvB or sat/vB
    %% depending on the option).
    {SelectedInputs, Change} =
        case {AddInputs, ManualInputUtxos} of
            {true, _} ->
                wcfp_select_coins(Pid, ManualInputUtxos, OutputTotal,
                                   FeeRate);
            {false, []} ->
                throw({wcfp_error, ?RPC_INVALID_PARAMETER,
                       <<"add_inputs is false but no inputs supplied">>});
            {false, Manuals} ->
                %% No auto-selection; caller must have provided enough.
                Total = lists:sum([U#utxo.value || {_, _, U} <- Manuals]),
                BaseFee = round(FeeRate * 80),
                case Total >= OutputTotal + BaseFee of
                    true ->
                        ChangeAmt = Total - OutputTotal - BaseFee,
                        {Manuals, ChangeAmt};
                    false ->
                        throw({wcfp_error, ?RPC_VERIFY_REJECTED,
                               <<"Insufficient funds in supplied inputs">>})
                end
        end,
    %% Build outputs list, optionally appending a change output.
    {OutputsWithChange, ChangePos} = wcfp_append_change(
        Pid, OutputPairs, Change, Network, Options),
    %% Build the unsigned tx.
    TxIns = lists:map(fun({Txid, Vout, _U}) ->
        #tx_in{prev_out = #outpoint{hash = Txid, index = Vout},
               script_sig = <<>>,
               sequence = 16#fffffffd,
               witness = []}
    end, SelectedInputs),
    TxOuts = lists:map(fun({Addr, Sat}) ->
        case beamchain_address:address_to_script(Addr, Network) of
            {ok, Script} -> #tx_out{value = Sat, script_pubkey = Script};
            _ ->
                throw({wcfp_error, ?RPC_INVALID_ADDRESS_OR_KEY,
                       iolist_to_binary(io_lib:format("Invalid address: ~s",
                                                       [Addr]))})
        end
    end, OutputsWithChange),
    Tx = #transaction{version = 2, inputs = TxIns, outputs = TxOuts,
                       locktime = Locktime},
    %% Wrap as PSBT and attach witness UTXOs.
    {ok, Psbt0} = beamchain_psbt:create(Tx),
    Psbt = lists:foldl(fun({{_, _, U}, Idx}, Acc) ->
        beamchain_wallet:add_witness_utxo(Acc, Idx, U)
    end, Psbt0, lists:zip(SelectedInputs,
                           lists:seq(0, length(SelectedInputs) - 1))),
    PsbtBin = beamchain_psbt:encode(Psbt),
    %% Compute actual fee = inputs - outputs.
    InputTotal = lists:sum([U#utxo.value || {_, _, U} <- SelectedInputs]),
    OutTotalAll = lists:sum([Sat || {_, Sat} <- OutputsWithChange]),
    Fee = InputTotal - OutTotalAll,
    %% lockUnspents option: lock the selected (non-manual) inputs in the
    %% wallet so they aren't double-selected by another caller.  Core's
    %% `lockUnspents` flag (wallet/rpc/spend.cpp).
    case maps:get(<<"lockUnspents">>, Options, false) of
        true ->
            lists:foreach(fun({Txid, Vout, _U}) ->
                ok = beamchain_wallet:lock_coin(Pid, Txid, Vout)
            end, SelectedInputs);
        _ ->
            ok
    end,
    {ok, #{<<"psbt">>      => base64:encode(PsbtBin),
           <<"fee">>       => satoshi_to_btc(Fee),
           <<"changepos">> => ChangePos}}.

normalize_wcfp_outputs(Outputs, _Network) when is_list(Outputs) ->
    lists:flatmap(fun(Obj) when is_map(Obj) ->
        maps:fold(fun(K, V, Acc) ->
            [{binary_to_list(K), btc_to_satoshi(V)} | Acc]
        end, [], Obj);
    (_) ->
        throw({wcfp_error, ?RPC_INVALID_PARAMS,
               <<"Output entries must be objects">>})
    end, Outputs);
normalize_wcfp_outputs(Outputs, _Network) when is_map(Outputs) ->
    %% Compatibility form: caller passed a single object instead of [obj].
    maps:fold(fun(K, V, Acc) ->
        [{binary_to_list(K), btc_to_satoshi(V)} | Acc]
    end, [], Outputs);
normalize_wcfp_outputs(_, _) ->
    throw({wcfp_error, ?RPC_INVALID_PARAMS,
           <<"outputs must be an array or object">>}).

%% Resolve fee rate from options.  Order of preference matches Core's:
%% `fee_rate` (sat/vB) > `feeRate` (BTC/kvB) > wallet estimator > 1 sat/vB.
wcfp_fee_rate(Options) ->
    case maps:get(<<"fee_rate">>, Options, undefined) of
        N when is_number(N) -> float(N);
        _ ->
            case maps:get(<<"feeRate">>, Options, undefined) of
                BtcKvB when is_number(BtcKvB) ->
                    BtcKvB * 100000000.0 / 1000.0;
                _ -> 1.0  %% sat/vB default
            end
    end.

wcfp_select_coins(Pid, ManualInputs, OutputTotal, FeeRate) ->
    %% Wallet-owned UTXOs minus the manual inputs and any locked coins.
    All = beamchain_wallet:get_wallet_utxos(),
    ManualKeys = [{Txid, Vout} || {Txid, Vout, _} <- ManualInputs],
    Locked = sets:from_list(beamchain_wallet:list_locked_coins(Pid)),
    Available = lists:filter(fun({Txid, Vout, _U}) ->
        Key = {Txid, Vout},
        not lists:member(Key, ManualKeys)
            andalso not sets:is_element(Key, Locked)
    end, All),
    %% Subtract manual inputs from the target so coin-selection tops up.
    ManualValue = lists:sum([U#utxo.value || {_, _, U} <- ManualInputs]),
    EffectiveTarget = max(OutputTotal - ManualValue, 0),
    case beamchain_wallet:select_coins(EffectiveTarget, FeeRate, Available)
    of
        {ok, AutoSelected, Change} ->
            {ManualInputs ++ AutoSelected, Change};
        {error, insufficient_funds} ->
            throw({wcfp_error, ?RPC_VERIFY_REJECTED,
                   <<"Insufficient funds">>})
    end.

%% Append change output and return the change index, mirroring Core's
%% `changePosition` (we currently always append; randomized placement is
%% deferred — see `bitcoin-core/src/wallet/spend.cpp::CreateTransaction`).
wcfp_append_change(_Pid, Outputs, Change, _Network, _Options)
        when Change =< 546 ->
    %% Below dust — drop change into fee.
    {Outputs, -1};
wcfp_append_change(Pid, Outputs, Change, Network, Options) ->
    Address = case maps:get(<<"changeAddress">>, Options, undefined) of
        Addr when is_binary(Addr) -> binary_to_list(Addr);
        _ ->
            ChangeType = case maps:get(<<"change_type">>, Options, undefined)
            of
                <<"bech32">>      -> p2wpkh;
                <<"bech32m">>     -> p2tr;
                <<"legacy">>      -> p2pkh;
                <<"p2sh-segwit">> -> p2wpkh;
                _                 -> p2wpkh
            end,
            case beamchain_wallet:get_change_address(Pid, ChangeType) of
                {ok, A} -> A;
                _ ->
                    throw({wcfp_error, ?RPC_MISC_ERROR,
                           <<"Failed to derive change address">>})
            end
    end,
    case beamchain_address:address_to_script(Address, Network) of
        {ok, _Script} ->
            ChangeOutput = {Address, Change},
            ChangePos = case maps:get(<<"changePosition">>, Options, undefined)
            of
                P when is_integer(P), P >= 0, P =< length(Outputs) ->
                    P;
                _ ->
                    length(Outputs)
            end,
            {insert_at(ChangePos, ChangeOutput, Outputs), ChangePos};
        _ ->
            throw({wcfp_error, ?RPC_INVALID_ADDRESS_OR_KEY,
                   iolist_to_binary(io_lib:format(
                       "Invalid change address: ~s", [Address]))})
    end.

insert_at(0, X, L) -> [X | L];
insert_at(N, X, L) when N >= length(L) -> L ++ [X];
insert_at(N, X, L) ->
    {Before, After} = lists:split(N, L),
    Before ++ [X | After].

%% ── W52 decodepsbt JSON shape helpers ──────────────────────────────────────
%% Reference: bitcoin-core/src/core_io.cpp ScriptToAsmStr / ScriptToUniv /
%% ValueFromAmount; script/descriptor.cpp InferDescriptor (no-keys path).

%% script_to_asm_core/1 — Core-style ScriptToAsmStr(script, false).
%% Rules (core_io.cpp):
%%   OP_0 (0x00)        → "0"
%%   OP_1NEGATE (0x4f)  → "-1"
%%   OP_1..OP_16        → "1".."16"
%%   Push data ≤4 bytes → CScriptNum decimal (signed little-endian)
%%   Push data >4 bytes → raw hex lowercase (no 0x prefix)
%%   All other opcodes  → GetOpName string (e.g. "OP_DUP")
%% Empty script → ""
script_to_asm_core(<<>>) -> <<>>;
script_to_asm_core(Script) when is_binary(Script) ->
    Tokens = script_asm_tokens(Script, []),
    iolist_to_binary(lists:join(<<" ">>, Tokens)).

%% Parse a script binary into a list of ASM token strings.
script_asm_tokens(<<>>, Acc) ->
    lists:reverse(Acc);
script_asm_tokens(<<16#00, Rest/binary>>, Acc) ->
    script_asm_tokens(Rest, [<<"0">> | Acc]);
script_asm_tokens(<<16#4f, Rest/binary>>, Acc) ->
    script_asm_tokens(Rest, [<<"-1">> | Acc]);
script_asm_tokens(<<Op, Rest/binary>>, Acc) when Op >= 16#51, Op =< 16#60 ->
    N = Op - 16#50,
    script_asm_tokens(Rest, [integer_to_binary(N) | Acc]);
%% OP_PUSHDATA1: next byte is length
script_asm_tokens(<<16#4c, Len:8, Data:Len/binary, Rest/binary>>, Acc) ->
    script_asm_tokens(Rest, [script_asm_push_token(Data) | Acc]);
%% OP_PUSHDATA2: next 2 bytes (LE) are length
script_asm_tokens(<<16#4d, Len:16/little, Data:Len/binary, Rest/binary>>, Acc) ->
    script_asm_tokens(Rest, [script_asm_push_token(Data) | Acc]);
%% OP_PUSHDATA4: next 4 bytes (LE) are length
script_asm_tokens(<<16#4e, Len:32/little, Data:Len/binary, Rest/binary>>, Acc) ->
    script_asm_tokens(Rest, [script_asm_push_token(Data) | Acc]);
%% Direct push data opcodes 0x01..0x4b (opcode = length)
script_asm_tokens(<<Len, Data:Len/binary, Rest/binary>>, Acc)
  when Len >= 16#01, Len =< 16#4b ->
    script_asm_tokens(Rest, [script_asm_push_token(Data) | Acc]);
%% Truncated pushes (PUSHDATA1/2/4 or direct push where data length > available):
%% any OP_PUSHDATA* or push opcode where the length-prefixed binary match above
%% failed — emit "[error]" and stop, matching Core's ScriptToAsmStr behaviour.
script_asm_tokens(<<Op, _Rest/binary>>, Acc)
  when Op >= 16#01, Op =< 16#4e ->
    lists:reverse([<<"[error]">> | Acc]);
%% All other opcodes → name
script_asm_tokens(<<Op, Rest/binary>>, Acc) ->
    script_asm_tokens(Rest, [opcode_name(Op) | Acc]).

%% For push data: ≤4 bytes → CScriptNum decimal; >4 bytes → hex.
script_asm_push_token(Data) when byte_size(Data) =< 4 ->
    script_num_to_binary(Data);
script_asm_push_token(Data) ->
    beamchain_serialize:hex_encode(Data).

%% Decode CScriptNum: signed little-endian with sign bit in MSB of last byte.
script_num_to_binary(<<>>) -> <<"0">>;
script_num_to_binary(Data) ->
    Len = byte_size(Data),
    %% Build unsigned little-endian value
    Raw = lists:foldl(fun(I, Acc) ->
        Byte = binary:at(Data, I),
        Acc bor (Byte bsl (8 * I))
    end, 0, lists:seq(0, Len - 1)),
    LastByte = binary:at(Data, Len - 1),
    %% Check sign bit (0x80 of last byte)
    case LastByte band 16#80 of
        0 ->
            integer_to_binary(Raw);
        _ ->
            %% Clear sign bit, negate
            Unsigned = Raw band (bnot (16#80 bsl (8 * (Len - 1)))),
            integer_to_binary(-Unsigned)
    end.

%% opcode_name/1 — maps opcode byte to Core's GetOpName string.
opcode_name(16#61) -> <<"OP_NOP">>;
opcode_name(16#62) -> <<"OP_VER">>;
opcode_name(16#63) -> <<"OP_IF">>;
opcode_name(16#64) -> <<"OP_NOTIF">>;
opcode_name(16#65) -> <<"OP_VERIF">>;
opcode_name(16#66) -> <<"OP_VERNOTIF">>;
opcode_name(16#67) -> <<"OP_ELSE">>;
opcode_name(16#68) -> <<"OP_ENDIF">>;
opcode_name(16#69) -> <<"OP_VERIFY">>;
opcode_name(16#6a) -> <<"OP_RETURN">>;
opcode_name(16#6b) -> <<"OP_TOALTSTACK">>;
opcode_name(16#6c) -> <<"OP_FROMALTSTACK">>;
opcode_name(16#6d) -> <<"OP_2DROP">>;
opcode_name(16#6e) -> <<"OP_2DUP">>;
opcode_name(16#6f) -> <<"OP_3DUP">>;
opcode_name(16#70) -> <<"OP_2OVER">>;
opcode_name(16#71) -> <<"OP_2ROT">>;
opcode_name(16#72) -> <<"OP_2SWAP">>;
opcode_name(16#73) -> <<"OP_IFDUP">>;
opcode_name(16#74) -> <<"OP_DEPTH">>;
opcode_name(16#75) -> <<"OP_DROP">>;
opcode_name(16#76) -> <<"OP_DUP">>;
opcode_name(16#77) -> <<"OP_NIP">>;
opcode_name(16#78) -> <<"OP_OVER">>;
opcode_name(16#79) -> <<"OP_PICK">>;
opcode_name(16#7a) -> <<"OP_ROLL">>;
opcode_name(16#7b) -> <<"OP_ROT">>;
opcode_name(16#7c) -> <<"OP_SWAP">>;
opcode_name(16#7d) -> <<"OP_TUCK">>;
opcode_name(16#7e) -> <<"OP_CAT">>;
opcode_name(16#7f) -> <<"OP_SUBSTR">>;
opcode_name(16#80) -> <<"OP_LEFT">>;
opcode_name(16#81) -> <<"OP_RIGHT">>;
opcode_name(16#82) -> <<"OP_SIZE">>;
opcode_name(16#83) -> <<"OP_INVERT">>;
opcode_name(16#84) -> <<"OP_AND">>;
opcode_name(16#85) -> <<"OP_OR">>;
opcode_name(16#86) -> <<"OP_XOR">>;
opcode_name(16#87) -> <<"OP_EQUAL">>;
opcode_name(16#88) -> <<"OP_EQUALVERIFY">>;
opcode_name(16#89) -> <<"OP_RESERVED1">>;
opcode_name(16#8a) -> <<"OP_RESERVED2">>;
opcode_name(16#8b) -> <<"OP_1ADD">>;
opcode_name(16#8c) -> <<"OP_1SUB">>;
opcode_name(16#8d) -> <<"OP_2MUL">>;
opcode_name(16#8e) -> <<"OP_2DIV">>;
opcode_name(16#8f) -> <<"OP_NEGATE">>;
opcode_name(16#90) -> <<"OP_ABS">>;
opcode_name(16#91) -> <<"OP_NOT">>;
opcode_name(16#92) -> <<"OP_0NOTEQUAL">>;
opcode_name(16#93) -> <<"OP_ADD">>;
opcode_name(16#94) -> <<"OP_SUB">>;
opcode_name(16#95) -> <<"OP_MUL">>;
opcode_name(16#96) -> <<"OP_DIV">>;
opcode_name(16#97) -> <<"OP_MOD">>;
opcode_name(16#98) -> <<"OP_LSHIFT">>;
opcode_name(16#99) -> <<"OP_RSHIFT">>;
opcode_name(16#9a) -> <<"OP_BOOLAND">>;
opcode_name(16#9b) -> <<"OP_BOOLOR">>;
opcode_name(16#9c) -> <<"OP_NUMEQUAL">>;
opcode_name(16#9d) -> <<"OP_NUMEQUALVERIFY">>;
opcode_name(16#9e) -> <<"OP_NUMNOTEQUAL">>;
opcode_name(16#9f) -> <<"OP_LESSTHAN">>;
opcode_name(16#a0) -> <<"OP_GREATERTHAN">>;
opcode_name(16#a1) -> <<"OP_LESSTHANOREQUAL">>;
opcode_name(16#a2) -> <<"OP_GREATERTHANOREQUAL">>;
opcode_name(16#a3) -> <<"OP_MIN">>;
opcode_name(16#a4) -> <<"OP_MAX">>;
opcode_name(16#a5) -> <<"OP_WITHIN">>;
opcode_name(16#a6) -> <<"OP_RIPEMD160">>;
opcode_name(16#a7) -> <<"OP_SHA1">>;
opcode_name(16#a8) -> <<"OP_SHA256">>;
opcode_name(16#a9) -> <<"OP_HASH160">>;
opcode_name(16#aa) -> <<"OP_HASH256">>;
opcode_name(16#ab) -> <<"OP_CODESEPARATOR">>;
opcode_name(16#ac) -> <<"OP_CHECKSIG">>;
opcode_name(16#ad) -> <<"OP_CHECKSIGVERIFY">>;
opcode_name(16#ae) -> <<"OP_CHECKMULTISIG">>;
opcode_name(16#af) -> <<"OP_CHECKMULTISIGVERIFY">>;
opcode_name(16#b0) -> <<"OP_NOP1">>;
opcode_name(16#b1) -> <<"OP_CHECKLOCKTIMEVERIFY">>;
opcode_name(16#b2) -> <<"OP_CHECKSEQUENCEVERIFY">>;
opcode_name(16#b3) -> <<"OP_NOP4">>;
opcode_name(16#b4) -> <<"OP_NOP5">>;
opcode_name(16#b5) -> <<"OP_NOP6">>;
opcode_name(16#b6) -> <<"OP_NOP7">>;
opcode_name(16#b7) -> <<"OP_NOP8">>;
opcode_name(16#b8) -> <<"OP_NOP9">>;
opcode_name(16#b9) -> <<"OP_NOP10">>;
opcode_name(16#ba) -> <<"OP_CHECKSIGADD">>;
opcode_name(16#50) -> <<"OP_RESERVED">>;
opcode_name(N)     -> iolist_to_binary(io_lib:format("OP_UNKNOWN(~B)", [N])).

%% infer_spk_descriptor/2 — BIP-380 descriptor with 8-char checksum.
%% Mirrors Core's InferDescriptor (script/descriptor.cpp) in the no-keys path.
%%
%% For witness_v1_taproot (OP_1 <32-byte x-only key>), Core wraps the x-only
%% key in RawTrDescriptor rather than AddressDescriptor, emitting:
%%   rawtr(<32-byte-hex>)#<checksum>
%%
%% For all other standard scripts:
%%   if ExtractDestination succeeds → addr(<address>)#<csum>
%%   else                           → raw(<hex>)#<csum>
%%
%% Network is mainnet | testnet (atom from beamchain_config:network()).
infer_spk_descriptor(Script, Network) ->
    NetType = case Network of mainnet -> mainnet; _ -> testnet end,
    Payload = case Script of
        %% OP_1 (0x51) + push 32 bytes (0x20) + 32-byte x-only pubkey
        <<16#51, 16#20, XOnly:32/binary>> ->
            "rawtr(" ++ binary_to_list(beamchain_serialize:hex_encode(XOnly)) ++ ")";
        _ ->
            Addr = beamchain_address:script_to_address(Script, NetType),
            case Addr of
                unknown     -> "raw(" ++ binary_to_list(beamchain_serialize:hex_encode(Script)) ++ ")";
                "OP_RETURN" -> "raw(" ++ binary_to_list(beamchain_serialize:hex_encode(Script)) ++ ")";
                A           -> "addr(" ++ A ++ ")"
            end
    end,
    try beamchain_descriptor:add_checksum(Payload) of
        S -> list_to_binary(S)
    catch
        _:_ -> list_to_binary(Payload)
    end.

%% format_psbt_spk_json/3 — emit Core-shape scriptPubKey for decodepsbt.
%% Shape: {asm, desc, hex, address?, type}
%% `address` is suppressed when script type is `pubkey` (bare P2PK),
%% matching Core's ScriptToUniv suppression rule.
format_psbt_spk_json(Script, Network) ->
    Type    = beamchain_address:classify_script(Script),
    TypeBin = script_type_name(Type),
    Asm     = script_to_asm_core(Script),
    Desc    = infer_spk_descriptor(Script, Network),
    Hex     = beamchain_serialize:hex_encode(Script),
    Base = #{
        <<"asm">>  => Asm,
        <<"desc">> => Desc,
        <<"hex">>  => Hex,
        <<"type">> => TypeBin
    },
    %% Suppress address for bare-pubkey / multisig / nonstandard / OP_RETURN —
    %% mirrors Core's `if (type != TxoutType::PUBKEY)` guard in ScriptToUniv.
    NetType = case Network of mainnet -> mainnet; _ -> testnet end,
    case beamchain_address:script_to_address(Script, NetType) of
        unknown     -> Base;
        "OP_RETURN" -> Base;
        Addr        -> Base#{<<"address">> => iolist_to_binary(Addr)}
    end.

%% format_psbt_vin/1 — like format_vin but scriptSig always includes asm.
%% In the PSBT unsigned tx, scriptSig is always empty; Core still emits
%% {"asm":"","hex":""} for shape-parity.
%%
%% For decoderawtransaction: coinbase vin emits txinwitness when non-empty
%% (e.g. block 800000 coinbase witness commitment), matching Core TxToUniv.
format_psbt_vin(#tx_in{prev_out = #outpoint{hash = <<0:256>>,
                                             index = 16#ffffffff},
                       script_sig = ScriptSig, sequence = Seq,
                       witness = Witness}) ->
    %% Coinbase — {coinbase, txinwitness?, sequence} per Core TxToUniv order
    Base = #{<<"coinbase">> => beamchain_serialize:hex_encode(ScriptSig),
             <<"sequence">> => Seq},
    case Witness of
        W when is_list(W), W =/= [] ->
            Base#{<<"txinwitness">> =>
                [beamchain_serialize:hex_encode(Item) || Item <- W]};
        _ -> Base
    end;
format_psbt_vin(#tx_in{prev_out = #outpoint{hash = Hash, index = Idx},
                       script_sig = ScriptSig, sequence = Seq,
                       witness = Witness}) ->
    Asm = script_to_asm_core(ScriptSig),
    Base = #{
        <<"txid">>      => hash_to_hex(Hash),
        <<"vout">>      => Idx,
        <<"scriptSig">> => #{
            <<"asm">> => Asm,
            <<"hex">> => beamchain_serialize:hex_encode(ScriptSig)
        },
        <<"sequence">>  => Seq
    },
    case Witness of
        W when is_list(W), W =/= [] ->
            Base#{<<"txinwitness">> =>
                [beamchain_serialize:hex_encode(Item) || Item <- W]};
        _ -> Base
    end.

%% format_amount_sentinel/1 — represent a satoshi amount as a sentinel binary
%% that jsx encodes as a JSON string.  After jsx:encode, replace_btc_sentinels/1
%% turns "\"__BTC__<sats>\"" back into the exact Core-format decimal.
%% E.g. 100000000 sats → sentinel <<"\"__BTC__100000000\"">> → "1.00000000" in JSON.
format_amount_sentinel(Sats) when is_integer(Sats) ->
    iolist_to_binary(["__BTC__", integer_to_list(Sats)]).

%% format_btc_amount_exact/1 — Core's ValueFromAmount ("%s%d.%08d").
format_btc_amount_exact(Sats) ->
    Neg  = Sats < 0,
    Abs  = if Neg -> -Sats; true -> Sats end,
    Whole = Abs div 100000000,
    Frac  = Abs rem 100000000,
    Sign  = if Neg -> "-"; true -> "" end,
    iolist_to_binary([Sign, integer_to_list(Whole), ".",
                      string:right(integer_to_list(Frac), 8, $0)]).

%% replace_btc_sentinels/1 — scan a JSON binary for sentinel strings of the
%% form "\"__BTC__<digits>\"" and replace each with the exact decimal amount.
%% The sentinel can only appear in a value position (never a key), and only
%% within a decodepsbt response, so a simple binary replace loop is safe.
replace_btc_sentinels(Bin) ->
    replace_btc_sentinels(Bin, <<>>).

replace_btc_sentinels(<<>>, Acc) ->
    Acc;
replace_btc_sentinels(<<"\"__BTC__", Rest/binary>>, Acc) ->
    %% Consume digits up to closing quote
    {Digits, Rest2} = consume_digits(Rest, <<>>),
    case Rest2 of
        <<"\"", Tail/binary>> ->
            Sats = binary_to_integer(Digits),
            Decimal = format_btc_amount_exact(Sats),
            replace_btc_sentinels(Tail, <<Acc/binary, Decimal/binary>>);
        _ ->
            %% Malformed sentinel — pass through unchanged (defensive)
            replace_btc_sentinels(Rest2, <<Acc/binary, "\"__BTC__", Digits/binary>>)
    end;
replace_btc_sentinels(<<C, Rest/binary>>, Acc) ->
    replace_btc_sentinels(Rest, <<Acc/binary, C>>).

consume_digits(<<D, Rest/binary>>, Acc) when D >= $0, D =< $9 ->
    consume_digits(Rest, <<Acc/binary, D>>);
consume_digits(Rest, Acc) ->
    {Acc, Rest}.

%% format_psbt_vouts/2 — like format_vouts but scriptPubKey has asm + desc,
%% and value is a sentinel for post-encode numeric fixup.
format_psbt_vouts([], _N, _Network) -> [];
format_psbt_vouts([#tx_out{value = Value, script_pubkey = Script} | Rest], N, Network) ->
    Vout = #{
        <<"value">>        => format_amount_sentinel(Value),
        <<"n">>            => N,
        <<"scriptPubKey">> => format_psbt_spk_json(Script, Network)
    },
    [Vout | format_psbt_vouts(Rest, N + 1, Network)].

%% format_psbt_tx_json/1 — like format_tx_json but without the top-level
%% `hex` field.  Core's decodepsbt emits the unsigned tx via TxToUniv with
%% include_hex=false (rpc/rawtransaction.cpp).
format_psbt_tx_json(#transaction{} = Tx) ->
    Network = beamchain_config:network(),
    Txid   = beamchain_serialize:tx_hash(Tx),
    Wtxid  = beamchain_serialize:wtx_hash(Tx),
    TxBin  = beamchain_serialize:encode_transaction(Tx),
    #{
        <<"txid">>     => hash_to_hex(Txid),
        <<"hash">>     => hash_to_hex(Wtxid),
        <<"version">>  => Tx#transaction.version,
        <<"size">>     => byte_size(TxBin),
        <<"vsize">>    => beamchain_serialize:tx_vsize(Tx),
        <<"weight">>   => beamchain_serialize:tx_weight(Tx),
        <<"locktime">> => Tx#transaction.locktime,
        <<"vin">>      => [format_psbt_vin(In) || In <- Tx#transaction.inputs],
        <<"vout">>     => format_psbt_vouts(Tx#transaction.outputs, 0, Network)
    }.

%% encode_psbt_decode/1 — build the decodepsbt response as a JSON binary
%% with Core-exact numeric literals (e.g. "1.00000000", not "1.0").
%% Strategy: build an Erlang map with sentinel binaries for amount values,
%% jsx:encode the whole map, then replace sentinels with exact decimals.
encode_psbt_decode(Psbt) ->
    Tx = beamchain_psbt:get_unsigned_tx(Psbt),
    Inputs  = format_psbt_inputs(Psbt),
    Outputs = format_psbt_outputs(Psbt),
    %% Fee calculation: sum input UTXOs − sum output values.
    %% Mirrors Core's have_all_utxos / total_in / output_value logic.
    {HaveAllUtxos, TotalIn} = psbt_sum_inputs(Tx, Psbt),
    TotalOut = lists:foldl(fun(#tx_out{value = V}, Acc) ->
        Acc + V
    end, 0, Tx#transaction.outputs),
    BaseMap = #{
        <<"tx">>           => format_psbt_tx_json(Tx),
        <<"global_xpubs">> => [],
        <<"psbt_version">> => beamchain_psbt:get_version(Psbt),
        <<"proprietary">>  => [],
        <<"unknown">>      => #{},
        <<"inputs">>       => Inputs,
        <<"outputs">>      => Outputs
    },
    Map = case HaveAllUtxos of
        true  -> BaseMap#{<<"fee">> => format_amount_sentinel(TotalIn - TotalOut)};
        false -> BaseMap
    end,
    Encoded = jsx:encode(Map),
    replace_btc_sentinels(Encoded).

%% psbt_sum_inputs/2 — compute total input satoshis from PSBT UTXOs.
%% For non_witness_utxo: index the prevout n into the utxo tx's vout list.
%% For witness_utxo: take the value directly.
%% Returns {HaveAllUtxos :: boolean(), TotalSats :: non_neg_integer()}.
psbt_sum_inputs(Tx, Psbt) ->
    Inputs = Tx#transaction.inputs,
    InputCount = length(Inputs),
    lists:foldl(fun(Idx, {HaveAll, Acc}) ->
        TxIn = lists:nth(Idx + 1, Inputs),
        InputMap = beamchain_psbt:get_input(Psbt, Idx),
        PrevN = TxIn#tx_in.prev_out#outpoint.index,
        case maps:get(witness_utxo, InputMap, undefined) of
            {Value, _ScriptPubKey} ->
                {HaveAll, Acc + Value};
            undefined ->
                case maps:get(non_witness_utxo, InputMap, undefined) of
                    undefined ->
                        {false, Acc};
                    NonWitTx ->
                        Vouts = NonWitTx#transaction.outputs,
                        case PrevN < length(Vouts) of
                            true ->
                                TxOut = lists:nth(PrevN + 1, Vouts),
                                {HaveAll, Acc + TxOut#tx_out.value};
                            false ->
                                {false, Acc}
                        end
                end
        end
    end, {true, 0}, lists:seq(0, InputCount - 1)).


format_psbt_inputs(Psbt) ->
    Tx = beamchain_psbt:get_unsigned_tx(Psbt),
    lists:zipwith(fun(Input, Idx) ->
        InputMap = beamchain_psbt:get_input(Psbt, Idx),
        format_psbt_input(Input, InputMap)
    end, Tx#transaction.inputs, lists:seq(0, length(Tx#transaction.inputs) - 1)).

format_psbt_input(_Input, InputMap) ->
    Base = #{},
    %% Witness UTXO — {amount, scriptPubKey} with full SPK shape + sentinel amount
    B1 = case maps:get(witness_utxo, InputMap, undefined) of
        {Value, ScriptPubKey} ->
            Base#{<<"witness_utxo">> => #{
                <<"amount">> => format_amount_sentinel(Value),
                <<"scriptPubKey">> => format_psbt_spk_json(ScriptPubKey, beamchain_config:network())
            }};
        _ -> Base
    end,
    %% Non-witness UTXO — full TxToUniv shape, no top-level hex
    B2 = case maps:get(non_witness_utxo, InputMap, undefined) of
        undefined -> B1;
        NonWitTx ->
            B1#{<<"non_witness_utxo">> => format_psbt_tx_json(NonWitTx)}
    end,
    %% Partial signatures — Core shape: object {pubkeyHex => sigHex}
    B3 = case maps:get(partial_sigs, InputMap, undefined) of
        undefined -> B2;
        Sigs when map_size(Sigs) > 0 ->
            SigObj = maps:fold(fun(PubKey, Sig, Acc) ->
                Acc#{beamchain_serialize:hex_encode(PubKey) =>
                     beamchain_serialize:hex_encode(Sig)}
            end, #{}, Sigs),
            B2#{<<"partial_signatures">> => SigObj};
        _ -> B2
    end,
    %% Sighash type — Core SighashToStr string, empty string for unknowns
    B4 = case maps:get(sighash_type, InputMap, undefined) of
        undefined -> B3;
        SH -> B3#{<<"sighash">> => psbt_sighash_to_str(SH)}
    end,
    %% Redeem script — {asm, hex, type} only (no desc/address)
    B5 = case maps:get(redeem_script, InputMap, undefined) of
        undefined -> B4;
        RS -> B4#{<<"redeem_script">> => build_script_type_json(RS)}
    end,
    %% Witness script — {asm, hex, type} only
    B6 = case maps:get(witness_script, InputMap, undefined) of
        undefined -> B5;
        WS -> B5#{<<"witness_script">> => build_script_type_json(WS)}
    end,
    %% Final scriptSig — {asm (sighash-decode), hex}
    B7 = case maps:get(final_script_sig, InputMap, undefined) of
        undefined -> B6;
        FSS -> B6#{<<"final_scriptSig">> => #{
            <<"asm">> => script_to_asm_sighash(FSS),
            <<"hex">> => beamchain_serialize:hex_encode(FSS)
        }}
    end,
    %% Final scriptwitness — array of hex, omit when empty
    B8 = case maps:get(final_script_witness, InputMap, undefined) of
        undefined -> B7;
        [] -> B7;
        FSW -> B7#{<<"final_scriptwitness">> =>
            [beamchain_serialize:hex_encode(W) || W <- FSW]}
    end,
    %% BIP-32 derivation paths (regular, non-taproot).
    %% Core emits bip32_derivs sorted by raw pubkey bytes (std::map<CPubKey,...>).
    %% Path notation: 'h' for hardened, matching Core's WriteHDKeypath default.
    B9 = case maps:get(bip32_derivation, InputMap, undefined) of
        undefined -> B8;
        Derivs when map_size(Derivs) > 0 ->
            SortedDerivs = lists:keysort(1, maps:to_list(Derivs)),
            DerivsArr = [#{
                <<"pubkey">>            => beamchain_serialize:hex_encode(PK),
                <<"master_fingerprint">> => beamchain_serialize:hex_encode(FP),
                <<"path">>              => format_bip32_path(Path)
            } || {PK, {FP, Path}} <- SortedDerivs],
            B8#{<<"bip32_derivs">> => DerivsArr};
        _ -> B8
    end,
    %% Taproot key-path signature (0x13)
    B10 = case maps:get(tap_key_sig, InputMap, undefined) of
        undefined -> B9;
        TKS -> B9#{<<"taproot_key_path_sig">> => beamchain_serialize:hex_encode(TKS)}
    end,
    %% Taproot script-path sigs (0x14) — array of {pubkey, leaf_hash, sig}
    %% sorted by (xonly_pubkey, leaf_hash), matching Core's std::map iteration.
    B11 = case maps:get(tap_script_sigs, InputMap, undefined) of
        undefined -> B10;
        TapScriptSigs when map_size(TapScriptSigs) > 0 ->
            SortedSigKeys = lists:sort(maps:keys(TapScriptSigs)),
            SigsArr = [#{
                <<"pubkey">>    => beamchain_serialize:hex_encode(XOnly),
                <<"leaf_hash">> => beamchain_serialize:hex_encode(LH),
                <<"sig">>       => beamchain_serialize:hex_encode(maps:get({XOnly, LH}, TapScriptSigs))
            } || {XOnly, LH} <- SortedSigKeys],
            B10#{<<"taproot_script_path_sigs">> => SigsArr};
        _ -> B10
    end,
    %% Taproot leaf scripts (0x15) — array of {script, leaf_ver, control_blocks[]}
    %% Core's m_tap_scripts is std::map<(script, leaf_ver), set<control_block>>.
    %% We group by (script, leaf_ver) and collect all control blocks.
    B12 = case maps:get(tap_leaf_scripts, InputMap, undefined) of
        undefined -> B11;
        TapLeafScripts when map_size(TapLeafScripts) > 0 ->
            %% Group control blocks by (script, leaf_ver)
            ScriptMap = maps:fold(fun(CtrlBlock, {Script, LeafVer}, Acc) ->
                Key = {Script, LeafVer},
                CBs = maps:get(Key, Acc, []),
                Acc#{Key => [CtrlBlock | CBs]}
            end, #{}, TapLeafScripts),
            %% Sort by (script_hex, leaf_ver) for determinism
            SortedLeafKeys = lists:sort(maps:keys(ScriptMap)),
            ScriptsArr = [begin
                CBList = lists:sort(maps:get({Sc, LV}, ScriptMap)),
                #{
                    <<"script">>         => beamchain_serialize:hex_encode(Sc),
                    <<"leaf_ver">>        => LV,
                    <<"control_blocks">>  =>
                        [beamchain_serialize:hex_encode(CB) || CB <- CBList]
                }
            end || {Sc, LV} <- SortedLeafKeys],
            B11#{<<"taproot_scripts">> => ScriptsArr};
        _ -> B11
    end,
    %% Taproot BIP-32 derivations (0x16) — array of
    %%   {pubkey, master_fingerprint, path, leaf_hashes[]}
    %% sorted by xonly pubkey (std::map<XOnlyPubKey,...> iteration order).
    B13 = case maps:get(tap_bip32_derivation, InputMap, undefined) of
        undefined -> B12;
        TapBip32 when map_size(TapBip32) > 0 ->
            SortedTapBip32 = lists:keysort(1, maps:to_list(TapBip32)),
            TapBip32Arr = [#{
                <<"pubkey">>            => beamchain_serialize:hex_encode(XOnly),
                <<"master_fingerprint">> => beamchain_serialize:hex_encode(FP),
                <<"path">>              => format_bip32_path(Path),
                <<"leaf_hashes">>       =>
                    [beamchain_serialize:hex_encode(LH) || LH <- LeafHashes]
            } || {XOnly, {FP, Path, LeafHashes}} <- SortedTapBip32],
            B12#{<<"taproot_bip32_derivs">> => TapBip32Arr};
        _ -> B12
    end,
    %% Taproot internal key (0x17)
    B14 = case maps:get(tap_internal_key, InputMap, undefined) of
        undefined -> B13;
        TIK -> B13#{<<"taproot_internal_key">> => beamchain_serialize:hex_encode(TIK)}
    end,
    %% Taproot merkle root (0x18)
    B15 = case maps:get(tap_merkle_root, InputMap, undefined) of
        undefined -> B14;
        TMR -> B14#{<<"taproot_merkle_root">> => beamchain_serialize:hex_encode(TMR)}
    end,
    B15.

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
        RS -> Base#{<<"redeem_script">> => build_script_type_json(RS)}
    end,
    B2 = case maps:get(witness_script, OutputMap, undefined) of
        undefined -> B1;
        WS -> B1#{<<"witness_script">> => build_script_type_json(WS)}
    end,
    %% BIP-32 derivation paths (regular, non-taproot) — sorted by raw pubkey.
    B3 = case maps:get(bip32_derivation, OutputMap, undefined) of
        undefined -> B2;
        OutDerivs when map_size(OutDerivs) > 0 ->
            SortedOutDerivs = lists:keysort(1, maps:to_list(OutDerivs)),
            OutDerivsArr = [#{
                <<"pubkey">>            => beamchain_serialize:hex_encode(PK),
                <<"master_fingerprint">> => beamchain_serialize:hex_encode(FP),
                <<"path">>              => format_bip32_path(Path)
            } || {PK, {FP, Path}} <- SortedOutDerivs],
            B2#{<<"bip32_derivs">> => OutDerivsArr};
        _ -> B2
    end,
    %% Taproot internal key (0x05)
    B4 = case maps:get(tap_internal_key, OutputMap, undefined) of
        undefined -> B3;
        TIK -> B3#{<<"taproot_internal_key">> => beamchain_serialize:hex_encode(TIK)}
    end,
    %% Taproot tree (0x06) — array of {depth, leaf_ver, script}
    B5 = case maps:get(tap_tree, OutputMap, undefined) of
        undefined -> B4;
        TapTree when is_list(TapTree), TapTree =/= [] ->
            TapTreeArr = [#{
                <<"depth">>    => Depth,
                <<"leaf_ver">> => LeafVer,
                <<"script">>   => beamchain_serialize:hex_encode(Script)
            } || {Depth, LeafVer, Script} <- TapTree],
            B4#{<<"taproot_tree">> => TapTreeArr};
        _ -> B4
    end,
    %% Taproot BIP-32 derivations (0x07) — sorted by xonly pubkey.
    B6 = case maps:get(tap_bip32_derivation, OutputMap, undefined) of
        undefined -> B5;
        OutTapBip32 when map_size(OutTapBip32) > 0 ->
            SortedOutTap = lists:keysort(1, maps:to_list(OutTapBip32)),
            OutTapArr = [#{
                <<"pubkey">>            => beamchain_serialize:hex_encode(XOnly),
                <<"master_fingerprint">> => beamchain_serialize:hex_encode(FP),
                <<"path">>              => format_bip32_path(Path),
                <<"leaf_hashes">>       =>
                    [beamchain_serialize:hex_encode(LH) || LH <- LeafHashes]
            } || {XOnly, {FP, Path, LeafHashes}} <- SortedOutTap],
            B5#{<<"taproot_bip32_derivs">> => OutTapArr};
        _ -> B5
    end,
    %% MuSig2 participant pubkeys (0x08) — sorted by aggregate pubkey.
    %% Core iterates std::map<CPubKey, vector<CPubKey>> in ascending key order.
    B7 = case maps:get(musig2_participant_pubkeys, OutputMap, undefined) of
        undefined -> B6;
        MuSig2Map when map_size(MuSig2Map) > 0 ->
            SortedMuSig2 = lists:keysort(1, maps:to_list(MuSig2Map)),
            MuSig2Arr = [#{
                <<"aggregate_pubkey">>    => beamchain_serialize:hex_encode(AggPK),
                <<"participant_pubkeys">> =>
                    [beamchain_serialize:hex_encode(PK) || PK <- Participants]
            } || {AggPK, Participants} <- SortedMuSig2],
            B6#{<<"musig2_participant_pubkeys">> => MuSig2Arr};
        _ -> B6
    end,
    B7.

%% format_bip32_path/1 — render a BIP-32 derivation path as "m/…".
%% Hardened components use 'h' suffix (Core's WriteHDKeypath with apostrophe=false,
%% src/util/bip32.cpp:56).  An empty path emits just "m".
format_bip32_path([]) ->
    <<"m">>;
format_bip32_path(Path) ->
    Parts = lists:map(fun(Idx) ->
        case Idx band 16#80000000 of
            0 -> integer_to_list(Idx);
            _ -> integer_to_list(Idx band 16#7fffffff) ++ "h"
        end
    end, Path),
    iolist_to_binary(["m/" | lists:join("/", Parts)]).

%% psbt_sighash_to_str/1 — Core's SighashToStr for decodepsbt.
%% Reference: bitcoin-core/src/core_io.cpp SighashToStr.
%% Only the 6 defined values; anything else returns "" (empty binary).
%% Note: PSBT_IN_SIGHASH_TYPE stores 32-bit LE; low byte is the flag.
psbt_sighash_to_str(N) ->
    Low = N band 16#ff,
    case Low of
        16#01 -> <<"ALL">>;
        16#02 -> <<"NONE">>;
        16#03 -> <<"SINGLE">>;
        16#81 -> <<"ALL|ANYONECANPAY">>;
        16#82 -> <<"NONE|ANYONECANPAY">>;
        16#83 -> <<"SINGLE|ANYONECANPAY">>;
        _     -> <<>>
    end.

%% build_script_type_json/1 — {asm, hex, type} for redeem_script / witness_script.
%% Matches Core's ScriptToUniv(script, out) with include_hex=true, include_address=false.
%% No desc or address fields.
build_script_type_json(Script) ->
    Type    = beamchain_address:classify_script(Script),
    TypeBin = script_type_name(Type),
    #{
        <<"asm">>  => script_to_asm_core(Script),
        <<"hex">>  => beamchain_serialize:hex_encode(Script),
        <<"type">> => TypeBin
    }.

%% is_valid_der_sig_encoding/1 — check if a binary looks like a DER sig + sighash byte.
%% Reference: bitcoin-core/src/script/interpreter.cpp IsValidSignatureEncoding.
%% Used by script_to_asm_sighash to decide whether to strip the sighash byte.
is_valid_der_sig_encoding(Vch) when is_binary(Vch) ->
    Len = byte_size(Vch),
    case Len >= 9 andalso Len =< 73 of
        false -> false;
        true ->
            <<B0, B1, B2, B3, _/binary>> = Vch,
            LenR = B3,
            case B0 =:= 16#30 andalso B1 =:= Len - 3 andalso B2 =:= 16#02 of
                false -> false;
                true ->
                    case 5 + LenR < Len of
                        false -> false;
                        true ->
                            LenS = binary:at(Vch, 5 + LenR),
                            case LenR + LenS + 7 =:= Len andalso LenR > 0 of
                                false -> false;
                                true ->
                                    B4 = binary:at(Vch, 4),
                                    B5 = binary:at(Vch, 5),
                                    case (B4 band 16#80) =:= 0 andalso
                                         not (LenR > 1 andalso B4 =:= 0 andalso (B5 band 16#80) =:= 0) of
                                        false -> false;
                                        true ->
                                            BLenR4 = binary:at(Vch, LenR + 4),
                                            case BLenR4 =:= 16#02 andalso LenS > 0 of
                                                false -> false;
                                                true ->
                                                    BLenR6 = binary:at(Vch, LenR + 6),
                                                    BLenR7 = case LenS > 1 of
                                                        true  -> binary:at(Vch, LenR + 7);
                                                        false -> 16#80  %% dummy to skip the check
                                                    end,
                                                    (BLenR6 band 16#80) =:= 0 andalso
                                                    not (LenS > 1 andalso BLenR6 =:= 0 andalso (BLenR7 band 16#80) =:= 0)
                                            end
                                    end
                            end
                    end
            end
    end;
is_valid_der_sig_encoding(_) -> false.

%% script_to_asm_sighash/1 — ScriptToAsmStr(script, fAttemptSighashDecode=true).
%% For push operands >= 5 bytes that pass IsValidSignatureEncoding:
%%   strip the last byte (sighash flag), map via psbt_sighash_to_str,
%%   emit hex(stripped) + optional "[TYPE]" suffix.
%% All other operands: same as script_to_asm_core.
script_to_asm_sighash(Script) when is_binary(Script) ->
    Tokens = script_asm_tokens_sighash(Script, []),
    iolist_to_binary(lists:join(<<" ">>, Tokens)).

script_asm_tokens_sighash(<<>>, Acc) ->
    lists:reverse(Acc);
script_asm_tokens_sighash(<<16#00, Rest/binary>>, Acc) ->
    script_asm_tokens_sighash(Rest, [<<"0">> | Acc]);
script_asm_tokens_sighash(<<16#4f, Rest/binary>>, Acc) ->
    script_asm_tokens_sighash(Rest, [<<"-1">> | Acc]);
script_asm_tokens_sighash(<<Op, Rest/binary>>, Acc) when Op >= 16#51, Op =< 16#60 ->
    N = Op - 16#50,
    script_asm_tokens_sighash(Rest, [integer_to_binary(N) | Acc]);
script_asm_tokens_sighash(<<16#4c, Len:8, Data:Len/binary, Rest/binary>>, Acc) ->
    script_asm_tokens_sighash(Rest, [script_asm_push_token_sighash(Data) | Acc]);
script_asm_tokens_sighash(<<16#4d, Len:16/little, Data:Len/binary, Rest/binary>>, Acc) ->
    script_asm_tokens_sighash(Rest, [script_asm_push_token_sighash(Data) | Acc]);
script_asm_tokens_sighash(<<16#4e, Len:32/little, Data:Len/binary, Rest/binary>>, Acc) ->
    script_asm_tokens_sighash(Rest, [script_asm_push_token_sighash(Data) | Acc]);
script_asm_tokens_sighash(<<Len, Data:Len/binary, Rest/binary>>, Acc)
  when Len >= 16#01, Len =< 16#4b ->
    script_asm_tokens_sighash(Rest, [script_asm_push_token_sighash(Data) | Acc]);
script_asm_tokens_sighash(<<Op, Rest/binary>>, Acc) ->
    script_asm_tokens_sighash(Rest, [opcode_name(Op) | Acc]).

%% For push data in sighash-decode mode:
%%   size <= 4: CScriptNum decimal (same as normal)
%%   size >= 5 and passes DER check: strip last byte, hex + "[TYPE]" suffix
%%   size >= 5 but not DER: raw hex (same as normal)
script_asm_push_token_sighash(Data) when byte_size(Data) =< 4 ->
    script_num_to_binary(Data);
script_asm_push_token_sighash(Data) ->
    case is_valid_der_sig_encoding(Data) of
        true ->
            DataLen = byte_size(Data),
            Stripped = binary:part(Data, 0, DataLen - 1),
            SigHashByte = binary:at(Data, DataLen - 1),
            Hex = beamchain_serialize:hex_encode(Stripped),
            TypeStr = psbt_sighash_to_str(SigHashByte),
            case TypeStr of
                <<>> -> Hex;
                _    -> <<Hex/binary, "[", TypeStr/binary, "]">>
            end;
        false ->
            beamchain_serialize:hex_encode(Data)
    end.

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
    %% Refuse to overwrite an existing destination — matches Core's
    %% "<path> already exists. If you are sure this is what you want,
    %% move it out of the way first." guard in
    %% rpc/blockchain.cpp::dumptxoutset. We probe BEFORE any chain-state
    %% mutation so a name collision cannot leave the chain stuck in a
    %% half-rolled-back state.
    PathStr = binary_to_list(Path),
    case filelib:is_regular(PathStr) of
        true ->
            {error, ?RPC_INVALID_PARAMS,
             iolist_to_binary(
               io_lib:format(
                 "~s already exists. If you are sure this is what you "
                 "want, move it out of the way first.", [PathStr]))};
        false ->
            case beamchain_chainstate:get_tip() of
                {ok, {TipHash, TipHeight}} ->
                    Network = beamchain_config:network(),
                    case resolve_dump_target(Type, Options, TipHash,
                                             TipHeight, Network) of
                        {ok, {TipHash, TipHeight}} ->
                            %% Target == tip: simple dump, no rollback dance.
                            do_dump_at_tip(Path, TipHash, TipHeight,
                                           Network);
                        {ok, {TargetHash, TargetHeight}} ->
                            do_dump_with_rollback(Path, TargetHash,
                                                  TargetHeight, TipHash,
                                                  TipHeight, Network);
                        {error, Code, Msg} ->
                            {error, Code, Msg}
                    end;
                not_found ->
                    {error, ?RPC_MISC_ERROR,
                     <<"No chain tip available">>}
            end
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
    %% Atomic-write protocol: write to "<path>.incomplete", fsync the fd
    %% via file:sync, then atomically rename to <path>. Mirrors Bitcoin
    %% Core's flow in rpc/blockchain.cpp::dumptxoutset (temppath = path
    %% + ".incomplete"; write; fsync via Fdatasync/close; rename). On
    %% any error we best-effort delete the .incomplete temp so a crashed
    %% dump never leaves a torn <path> behind — only the .incomplete
    %% artifact, which can be cleaned up out-of-band.
    TmpPathStr = PathStr ++ ".incomplete",
    case write_snapshot_atomic(TmpPathStr, PathStr, SnapshotBin) of
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

%% Atomic write helper used by do_dump_at_tip. Bytes go to TmpPath, the
%% file descriptor is fsynced, then renamed to FinalPath. Cleans up
%% TmpPath on any failure so an aborted dump never leaves a torn final
%% file. Mirrors bitcoin-core/src/rpc/blockchain.cpp::dumptxoutset.
write_snapshot_atomic(TmpPath, FinalPath, Payload) ->
    case file:open(TmpPath, [write, binary, raw]) of
        {ok, Fd} ->
            case file:write(Fd, Payload) of
                ok ->
                    %% Durability barrier: fsync before rename. A power
                    %% loss between rename and dirty-page flush could
                    %% otherwise leave FinalPath visible with zero-
                    %% length / torn contents.
                    SyncRes = file:sync(Fd),
                    CloseRes = file:close(Fd),
                    case {SyncRes, CloseRes} of
                        {ok, ok} ->
                            case file:rename(TmpPath, FinalPath) of
                                ok -> ok;
                                {error, RenReason} ->
                                    _ = file:delete(TmpPath),
                                    {error, {rename, RenReason}}
                            end;
                        {{error, SyncReason}, _} ->
                            _ = file:delete(TmpPath),
                            {error, {sync, SyncReason}};
                        {_, {error, CloseReason}} ->
                            _ = file:delete(TmpPath),
                            {error, {close, CloseReason}}
                    end;
                {error, WriteReason} ->
                    _ = file:close(Fd),
                    _ = file:delete(TmpPath),
                    {error, {write, WriteReason}}
            end;
        {error, OpenReason} ->
            {error, {open, OpenReason}}
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
    %% Pruned-mode pre-check (Bitcoin Core
    %% rpc/blockchain.cpp:dumptxoutset):
    %%     if (IsPruneMode() &&
    %%         target_index->nHeight <
    %%         m_blockman.GetFirstBlock()->nHeight)
    %%         throw "Block height N not available (pruned data).
    %%                Use a height after M.";
    %% beamchain_db:is_block_pruned/1 reflects the actual on-disk state
    %% (set membership against pruned_files), so we use it directly to
    %% fail fast before disconnect_block hits a missing block body.
    case beamchain_config:prune_enabled() andalso
         beamchain_db:is_block_pruned(TargetHash) of
        true ->
            {error, ?RPC_MISC_ERROR,
             iolist_to_binary(
               io_lib:format(
                 "Block height ~B not available (pruned data). "
                 "Use a height closer to the current tip.",
                 [TargetHeight]))};
        false ->
            do_dump_with_rollback_unchecked(
              Path, TargetHash, TargetHeight,
              OrigTipHash, OrigTipHeight, Network)
    end.

do_dump_with_rollback_unchecked(Path, TargetHash, TargetHeight,
                                OrigTipHash, OrigTipHeight, Network) ->
    %% NetworkDisable RAII (Erlang try/after). Mirrors Bitcoin Core's
    %% NetworkDisable wrapper around TemporaryRollback in
    %% rpc/blockchain.cpp::dumptxoutset. Pause inbound block acceptance
    %% for the duration of the rewind→dump→replay dance and restore on
    %% every exit path (success, error, exception). The `after` clause
    %% guarantees cleanup even if a callee throws.
    set_block_submission_paused(true),
    try
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
        end
    after
        set_block_submission_paused(false)
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

%%% ===================================================================
%%% Wave-47b: getnetworkhashps, gettxoutproof, verifytxoutproof, getrpcinfo
%%% ===================================================================

%% getnetworkhashps([NBlocks]) -> estimated hashes/second over recent window.
%% Mirrors Bitcoin Core: workDiff / timeDiff over a sliding window.
rpc_getnetworkhashps([]) ->
    rpc_getnetworkhashps([120]);
rpc_getnetworkhashps([NBlocks]) when is_integer(NBlocks) ->
    case beamchain_chainstate:get_tip() of
        {ok, {_TipHash, TipHeight}} when TipHeight >= 2 ->
            Window = case NBlocks =< 0 of
                true  -> 120;
                false -> min(NBlocks, TipHeight)
            end,
            Hi = TipHeight,
            Lo = Hi - Window,
            case {beamchain_db:get_block_index(Hi),
                  beamchain_db:get_block_index(Lo)} of
                {{ok, #{chainwork := HiCW, header := HiHdr}},
                 {ok, #{chainwork := LoCW, header := LoHdr}}} ->
                    WorkDiff = chainwork_to_float(HiCW) - chainwork_to_float(LoCW),
                    TimeDiff = HiHdr#block_header.timestamp
                             - LoHdr#block_header.timestamp,
                    case TimeDiff > 0 of
                        true ->
                            HashPS = WorkDiff / TimeDiff,
                            {ok, trunc(HashPS)};
                        false -> {ok, 0}
                    end;
                _ -> {ok, 0}
            end;
        _ -> {ok, 0}
    end;
rpc_getnetworkhashps(_) ->
    rpc_getnetworkhashps([120]).

%% Convert a 32-byte big-endian chainwork binary to a float.
%% (float is sufficient; Bitcoin's current chainwork fits in a 64-bit mantissa
%%  for the purposes of computing a ratio.)
chainwork_to_float(CW) when byte_size(CW) =:= 32 ->
    <<_:128, Lo:128/big>> = CW,
    %% Use the lower 128 bits; the upper 128 are zero on current mainnet
    float(Lo);
chainwork_to_float(_) -> 0.0.

%% gettxoutproof([Txids]) or ([Txids, BlockHash]) -> CMerkleBlock hex proof.
rpc_gettxoutproof([TxidList]) ->
    rpc_gettxoutproof([TxidList, null]);
rpc_gettxoutproof([TxidList, null]) ->
    %% No blockhash given — look up via tx index
    case TxidList of
        [FirstTxHex | _] ->
            FirstTxid = hex_to_internal_hash(FirstTxHex),
            case beamchain_db:get_tx_location(FirstTxid) of
                {ok, #{block_hash := BH}} ->
                    rpc_gettxoutproof_with_block(TxidList, BH);
                not_found ->
                    {error, ?RPC_MISC_ERROR,
                     <<"Transaction not found in block index">>}
            end;
        _ ->
            {error, ?RPC_INVALID_PARAMETER, <<"No txids provided">>}
    end;
rpc_gettxoutproof([TxidList, BlockHashHex]) when is_binary(BlockHashHex) ->
    BH = hex_to_internal_hash(BlockHashHex),
    rpc_gettxoutproof_with_block(TxidList, BH);
rpc_gettxoutproof(_) ->
    {error, ?RPC_INVALID_PARAMETER, <<"Invalid parameters">>}.

rpc_gettxoutproof_with_block(TxidHexList, BlockHash) ->
    case beamchain_db:get_block(BlockHash) of
        not_found ->
            {error, ?RPC_MISC_ERROR, <<"Block not found">>};
        {ok, #block{header = Header, transactions = Txs}} ->
            AllTxids = [beamchain_serialize:tx_hash(Tx) || Tx <- Txs],
            NTx = length(AllTxids),
            ReqTxids = [hex_to_internal_hash(H) || H <- TxidHexList,
                        is_binary(H)],
            MatchFlags = [lists:member(Txid, ReqTxids) || Txid <- AllTxids],
            {Hashes, Bits} = w47b_traverse_and_build(NTx, AllTxids, MatchFlags),
            HeaderBin = beamchain_serialize:encode_block_header(Header),
            NTxLE = <<NTx:32/little>>,
            HashesBin = iolist_to_binary(Hashes),
            FlagBytes = w47b_bits_to_bytes(Bits),
            Proof = iolist_to_binary([
                HeaderBin,
                NTxLE,
                w47b_encode_varint(length(Hashes)),
                HashesBin,
                w47b_encode_varint(byte_size(FlagBytes)),
                FlagBytes
            ]),
            {ok, beamchain_serialize:hex_encode(Proof)}
    end.

%% verifytxoutproof(ProofHex) -> list of matched txids.
rpc_verifytxoutproof([ProofHex]) when is_binary(ProofHex) ->
    Proof = beamchain_serialize:hex_decode(ProofHex),
    case byte_size(Proof) < 84 of
        true ->
            {error, ?RPC_DESERIALIZATION_ERROR, <<"Proof too short">>};
        false ->
            <<_HeaderBin:80/binary, NTx:32/little, Rest/binary>> = Proof,
            case NTx =:= 0 of
                true -> {ok, []};
                false ->
                    case parse_proof_body(NTx, Rest) of
                        {ok, Matched} -> {ok, Matched};
                        {error, Msg}  ->
                            {error, ?RPC_DESERIALIZATION_ERROR, Msg}
                    end
            end
    end;
rpc_verifytxoutproof(_) ->
    {error, ?RPC_INVALID_PARAMETER, <<"Invalid parameters">>}.

parse_proof_body(NTx, Bin) ->
    try
        {HashCount, After1} = w47b_read_varint(Bin),
        HashBytes = HashCount * 32,
        <<HashesBin:HashBytes/binary, After2/binary>> = After1,
        Hashes = [H || <<H:32/binary>> <= HashesBin,
                  byte_size(H) =:= 32],
        {FlagCount, After3} = w47b_read_varint(After2),
        <<FlagBytes:FlagCount/binary, _/binary>> = After3,
        Matched = w47b_traverse_and_extract(NTx, Hashes, FlagBytes),
        {ok, Matched}
    catch _:_ ->
        {error, <<"Invalid proof (parse error)">>}
    end.

%% getrpcinfo() -> stub
rpc_getrpcinfo() ->
    {ok, #{
        <<"active_commands">> => [],
        <<"logpath">> => <<>>
    }}.

%%% -------------------------------------------------------------------
%%% Partial Merkle Tree helpers (Bitcoin Core CalcTreeWidth / TraverseAndBuild /
%%% TraverseAndExtract from src/merkleblock.cpp)
%%% -------------------------------------------------------------------

%% CalcTreeWidth: (n_tx + (1<<height) - 1) >> height
%% height 0 = leaves (width = n_tx); height nHeight = root (width = 1).
w47b_tree_width(NTx, Height) ->
    (NTx + (1 bsl Height) - 1) bsr Height.

%% nHeight: smallest h such that w47b_tree_width(NTx,h) == 1
w47b_n_height(NTx) ->
    w47b_n_height(NTx, 0).
w47b_n_height(NTx, H) ->
    case w47b_tree_width(NTx, H) > 1 of
        true  -> w47b_n_height(NTx, H + 1);
        false -> H
    end.

%% CalcHash(height, pos, TxidList): height 0 = leaf, returns txid at pos;
%% height > 0 combines children with Hash(left || right).
w47b_calc_hash(0, Pos, Txids) ->
    lists:nth(Pos + 1, Txids);
w47b_calc_hash(Height, Pos, Txids) ->
    NTx = length(Txids),
    Left  = w47b_calc_hash(Height - 1, Pos * 2, Txids),
    Right = case (Pos * 2 + 1) < w47b_tree_width(NTx, Height - 1) of
        true  -> w47b_calc_hash(Height - 1, Pos * 2 + 1, Txids);
        false -> Left
    end,
    beamchain_serialize:hash256(<<Left/binary, Right/binary>>).

%% TraverseAndBuild: returns {Hashes, Bits} in pre-order DFS.
w47b_traverse_and_build(NTx, Txids, MatchFlags) ->
    NHeight = w47b_n_height(NTx),
    {Hashes, Bits} = w47b_build(NHeight, 0, NTx, Txids, MatchFlags),
    {lists:reverse(Hashes), lists:reverse(Bits)}.

w47b_build(Height, Pos, NTx, Txids, MatchFlags) ->
    %% fParentOfMatch: any match in range [Pos<<Height, (Pos+1)<<Height)
    Lo = Pos bsl Height,
    Hi = min((Pos + 1) bsl Height, NTx),
    ParentMatch = lists:any(fun(I) -> lists:nth(I + 1, MatchFlags) end,
                            lists:seq(Lo, Hi - 1)),
    case Height =:= 0 orelse not ParentMatch of
        true ->
            Hash = w47b_calc_hash(Height, Pos, Txids),
            {[Hash], [ParentMatch]};
        false ->
            {HL, BL} = w47b_build(Height - 1, Pos * 2, NTx, Txids, MatchFlags),
            {HR, BR} = case (Pos * 2 + 1) < w47b_tree_width(NTx, Height - 1) of
                true  -> w47b_build(Height - 1, Pos * 2 + 1, NTx, Txids, MatchFlags);
                false -> {[], []}
            end,
            {HR ++ HL, BR ++ BL ++ [ParentMatch]}
    end.

%% TraverseAndExtract: parse stored hashes + bits, return matched txids.
w47b_traverse_and_extract(NTx, Hashes, FlagBytes) ->
    NHeight = w47b_n_height(NTx),
    Bits = w47b_bytes_to_bits(FlagBytes),
    {_Root, _BitPos, _HashPos, Matched} =
        w47b_extract(NHeight, 0, NTx, Hashes, Bits, 0, 0, []),
    lists:reverse(Matched).

w47b_extract(Height, Pos, NTx, Hashes, Bits, BitPos, HashPos, Matched) ->
    Flag = lists:nth(BitPos + 1, Bits),
    NewBitPos = BitPos + 1,
    case Height =:= 0 orelse not Flag of
        true ->
            Hash = lists:nth(HashPos + 1, Hashes),
            NewMatched = case Height =:= 0 andalso Flag of
                true  -> [hash_to_hex(Hash) | Matched];
                false -> Matched
            end,
            {Hash, NewBitPos, HashPos + 1, NewMatched};
        false ->
            {LeftHash, BP2, HP2, M2} =
                w47b_extract(Height-1, Pos*2, NTx, Hashes, Bits,
                             NewBitPos, HashPos, Matched),
            {RightHash, BP3, HP3, M3} =
                case (Pos * 2 + 1) < w47b_tree_width(NTx, Height - 1) of
                    true ->
                        w47b_extract(Height-1, Pos*2+1, NTx, Hashes, Bits,
                                     BP2, HP2, M2);
                    false ->
                        {LeftHash, BP2, HP2, M2}
                end,
            Combined = beamchain_serialize:hash256(
                <<LeftHash/binary, RightHash/binary>>),
            {Combined, BP3, HP3, M3}
    end.

%% BitsToBytes: pack bits LSB-first into bytes
w47b_bits_to_bytes(Bits) ->
    NBytes = (length(Bits) + 7) div 8,
    Bytes  = lists:duplicate(NBytes, 0),
    Packed = lists:foldl(fun({I, B}, Acc) ->
        ByteIdx = I div 8,
        BitIdx  = I rem 8,
        Byte    = lists:nth(ByteIdx + 1, Acc),
        NewByte = case B of
            true  -> Byte bor (1 bsl BitIdx);
            false -> Byte
        end,
        lists:sublist(Acc, ByteIdx) ++ [NewByte] ++
            lists:nthtail(ByteIdx + 1, Acc)
    end, Bytes, lists:zip(lists:seq(0, length(Bits) - 1), Bits)),
    list_to_binary(Packed).

%% BytesToBits: unpack bytes into bit list (LSB-first per byte)
w47b_bytes_to_bits(Bytes) ->
    Len = byte_size(Bytes) * 8,
    [((binary:at(Bytes, I div 8)) band (1 bsl (I rem 8))) =/= 0
     || I <- lists:seq(0, Len - 1)].

%% encode varint
w47b_encode_varint(V) when V < 16#FD ->
    <<V:8>>;
w47b_encode_varint(V) when V =< 16#FFFF ->
    <<16#FD, V:16/little>>;
w47b_encode_varint(V) ->
    <<16#FE, V:32/little>>.

%% read varint from binary, returns {Value, Rest}
w47b_read_varint(<<First:8, Rest/binary>>) ->
    case First of
        16#FD -> <<V:16/little, R/binary>> = Rest, {V, R};
        16#FE -> <<V:32/little, R/binary>> = Rest, {V, R};
        16#FF -> <<V:64/little, R/binary>> = Rest, {V, R};
        _     -> {First, Rest}
    end.
