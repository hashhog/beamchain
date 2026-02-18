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
