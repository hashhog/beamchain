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

%% -- Blockchain --
handle_method(<<"getblockcount">>, _) -> rpc_getblockcount();
handle_method(<<"getbestblockhash">>, _) -> rpc_getbestblockhash();
handle_method(<<"getblockchaininfo">>, _) -> rpc_getblockchaininfo();
handle_method(<<"getblockhash">>, P) -> rpc_getblockhash(P);
handle_method(<<"getblock">>, P) -> rpc_getblock(P);
handle_method(<<"getblockheader">>, P) -> rpc_getblockheader(P);
handle_method(<<"getdifficulty">>, _) -> rpc_getdifficulty();
handle_method(<<"getchaintips">>, _) -> rpc_getchaintips();
handle_method(<<"verifychain">>, _) -> rpc_verifychain();

%% -- Transactions --
handle_method(<<"getrawtransaction">>, P) -> rpc_getrawtransaction(P);
handle_method(<<"decoderawtransaction">>, P) -> rpc_decoderawtransaction(P);
handle_method(<<"sendrawtransaction">>, P) -> rpc_sendrawtransaction(P);
handle_method(<<"testmempoolaccept">>, P) -> rpc_testmempoolaccept(P);
handle_method(<<"gettxout">>, P) -> rpc_gettxout(P);
handle_method(<<"gettxoutsetinfo">>, P) -> rpc_gettxoutsetinfo(P);

%% -- Mempool --
handle_method(<<"getmempoolinfo">>, _) -> rpc_getmempoolinfo();
handle_method(<<"getrawmempool">>, P) -> rpc_getrawmempool(P);
handle_method(<<"getmempoolentry">>, P) -> rpc_getmempoolentry(P);

%% -- Network --
handle_method(<<"getnetworkinfo">>, _) -> rpc_getnetworkinfo();
handle_method(<<"getpeerinfo">>, _) -> rpc_getpeerinfo();
handle_method(<<"getconnectioncount">>, _) -> rpc_getconnectioncount();
handle_method(<<"addnode">>, P) -> rpc_addnode(P);
handle_method(<<"disconnectnode">>, P) -> rpc_disconnectnode(P);
handle_method(<<"listbanned">>, _) -> rpc_listbanned();
handle_method(<<"setban">>, P) -> rpc_setban(P);
handle_method(<<"clearbanned">>, _) -> rpc_clearbanned();

%% -- Mining --
handle_method(<<"getmininginfo">>, _) -> rpc_getmininginfo();
handle_method(<<"getblocktemplate">>, P) -> rpc_getblocktemplate(P);
handle_method(<<"submitblock">>, P) -> rpc_submitblock(P);

%% -- Fee estimation --
handle_method(<<"estimatesmartfee">>, P) -> rpc_estimatesmartfee(P);

%% -- Utility --
handle_method(<<"validateaddress">>, P) -> rpc_validateaddress(P);
handle_method(<<"decodescript">>, P) -> rpc_decodescript(P);

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
        <<"gettxoutsetinfo ( \"hash_type\" )">>,
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
        <<"clearbanned">>,
        <<"disconnectnode ( \"address\" nodeid )">>,
        <<"getconnectioncount">>,
        <<"getnetworkinfo">>,
        <<"getpeerinfo">>,
        <<"listbanned">>,
        <<"setban \"subnet\" \"command\" ( bantime )">>,
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
            Softforks = get_softfork_status(Network, TipHeight),
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
        {ok, #{height := Height, header := Header, chainwork := Chainwork}} ->
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

        case beamchain_mempool:add_transaction(Tx) of
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
            case beamchain_mempool:add_transaction(Tx) of
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
rpc_gettxoutsetinfo([_HashType | _]) ->
    %% Get UTXO set statistics
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
            {ok, #{
                <<"height">> => TipHeight,
                <<"bestblock">> => hash_to_hex(TipHash),
                <<"txouts">> => TxOuts,
                <<"bogosize">> => Bogosize,
                <<"total_amount">> => 0.0,  %% Would require iterating all UTXOs
                <<"disk_size">> => 0  %% Would require DB stats
            }};
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
        <<"fullrbf">> => false
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
    PeerInfoList = lists:map(fun(#{pid := _Pid, address := {IP, Port},
                                   direction := Dir, connected := _Conn,
                                   info := Info}) ->
        Now = erlang:system_time(second),
        #{
            <<"id">> => erlang:phash2({IP, Port}),
            <<"addr">> => format_addr(IP, Port),
            <<"addrbind">> => <<>>,
            <<"services">> => beamchain_serialize:hex_encode(
                <<(maps:get(services, Info, 0)):64/big>>),
            <<"servicesnames">> => services_to_names(
                maps:get(services, Info, 0)),
            <<"lastsend">> => Now,
            <<"lastrecv">> => Now,
            <<"last_transaction">> => 0,
            <<"last_block">> => 0,
            <<"bytessent">> => 0,
            <<"bytesrecv">> => 0,
            <<"conntime">> => maps:get(connect_time, Info, Now),
            <<"timeoffset">> => 0,
            <<"pingtime">> => maps:get(ping_time, Info, 0.0),
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
%%% Internal helpers
%%% ===================================================================

%% Get soft fork deployment status for getblockchaininfo.
%% Returns a map of softfork name => status info.
get_softfork_status(Network, TipHeight) ->
    Params = beamchain_chain_params:params(Network),
    %% Buried deployments (height-based activation)
    Buried = [
        {<<"bip34">>, maps:get(bip34_height, Params, 0)},
        {<<"bip66">>, maps:get(bip66_height, Params, 0)},
        {<<"bip65">>, maps:get(bip65_height, Params, 0)},
        {<<"csv">>, maps:get(csv_height, Params, 0)},
        {<<"segwit">>, maps:get(segwit_height, Params, 0)},
        {<<"taproot">>, maps:get(taproot_height, Params, 0)}
    ],
    lists:foldl(fun({Name, ActivationHeight}, Acc) ->
        IsActive = TipHeight >= ActivationHeight,
        maps:put(Name, #{
            <<"type">> => <<"buried">>,
            <<"active">> => IsActive,
            <<"height">> => ActivationHeight
        }, Acc)
    end, #{}, Buried).

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
