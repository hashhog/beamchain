-module(beamchain_rest).
-behaviour(gen_server).

%% REST API server providing block, transaction, and chain data over HTTP
%% in multiple formats (JSON, binary, hex). A simpler alternative to JSON-RPC
%% for read-only queries.
%%
%% Reference: Bitcoin Core /home/max/hashhog/bitcoin/src/rest.cpp

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% API
-export([start_link/0]).

%% Cowboy handler
-export([init/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

%% Internal exports for URL handling
-export([parse_format/1, parse_path/1]).

-define(SERVER, ?MODULE).

%% REST limits (matching Bitcoin Core)
-define(MAX_GETUTXOS_OUTPOINTS, 15).
-define(MAX_REST_HEADERS_RESULTS, 2000).
-define(DEFAULT_REST_HEADERS_COUNT, 5).

%% HTTP status codes
-define(HTTP_OK, 200).
-define(HTTP_BAD_REQUEST, 400).
-define(HTTP_NOT_FOUND, 404).
-define(HTTP_INTERNAL_ERROR, 500).
-define(HTTP_SERVICE_UNAVAILABLE, 503).

-record(state, {
    port :: non_neg_integer()
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
    %% Start Cowboy listener for REST API
    Params = beamchain_config:network_params(),
    Port = rest_port(Params),
    Dispatch = cowboy_router:compile([
        {'_', [
            {"/rest/[...]", ?MODULE, []}
        ]}
    ]),
    case cowboy:start_clear(beamchain_rest_listener,
            [{port, Port}],
            #{env => #{dispatch => Dispatch}}) of
        {ok, _} ->
            logger:info("rest: listening on port ~B", [Port]);
        {error, {already_started, _}} ->
            logger:info("rest: already listening on port ~B", [Port]);
        {error, Reason} ->
            logger:warning("rest: failed to start on port ~B: ~p",
                           [Port, Reason])
    end,
    {ok, #state{port = Port}}.

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    catch cowboy:stop_listener(beamchain_rest_listener),
    logger:info("rest: stopped"),
    ok.

%%% ===================================================================
%%% Cowboy handler
%%% ===================================================================

init(Req0, CowboyState) ->
    %% Only GET is allowed for REST API
    case cowboy_req:method(Req0) of
        <<"GET">> ->
            handle_rest(Req0, CowboyState);
        _ ->
            Req = cowboy_req:reply(405,
                #{<<"content-type">> => <<"text/plain">>},
                <<"Method Not Allowed\r\n">>, Req0),
            {ok, Req, CowboyState}
    end.

handle_rest(Req0, CowboyState) ->
    %% Parse the path after /rest/
    Path = cowboy_req:path(Req0),
    PathInfo = parse_path(Path),
    QueryParams = cowboy_req:parse_qs(Req0),

    case route_request(PathInfo, QueryParams) of
        {ok, Format, Body} ->
            reply_success(Format, Body, Req0, CowboyState);
        {error, Status, Message} ->
            reply_error(Status, Message, Req0, CowboyState)
    end.

%%% ===================================================================
%%% Request routing
%%% ===================================================================

route_request([<<"block">>, HashWithFormat], _Query) ->
    %% GET /rest/block/<hash>.<format>
    {Hash, Format} = parse_hash_format(HashWithFormat),
    rest_block(Hash, Format, true);

route_request([<<"block">>, <<"notxdetails">>, HashWithFormat], _Query) ->
    %% GET /rest/block/notxdetails/<hash>.<format>
    {Hash, Format} = parse_hash_format(HashWithFormat),
    rest_block(Hash, Format, false);

route_request([<<"tx">>, TxidWithFormat], _Query) ->
    %% GET /rest/tx/<txid>.<format>
    {Txid, Format} = parse_hash_format(TxidWithFormat),
    rest_tx(Txid, Format);

route_request([<<"headers">>, CountBin, HashWithFormat], _Query) ->
    %% GET /rest/headers/<count>/<hash>.<format> (deprecated format)
    {Hash, Format} = parse_hash_format(HashWithFormat),
    Count = parse_count(CountBin, ?DEFAULT_REST_HEADERS_COUNT),
    rest_headers(Hash, Count, Format);

route_request([<<"headers">>, HashWithFormat], Query) ->
    %% GET /rest/headers/<hash>.<format>?count=N
    {Hash, Format} = parse_hash_format(HashWithFormat),
    Count = query_count(Query, ?DEFAULT_REST_HEADERS_COUNT),
    rest_headers(Hash, Count, Format);

route_request([<<"blockhashbyheight">>, HeightWithFormat], _Query) ->
    %% GET /rest/blockhashbyheight/<height>.<format>
    {Height, Format} = parse_height_format(HeightWithFormat),
    rest_blockhash_by_height(Height, Format);

route_request([<<"chaininfo", Format0/binary>>], _Query) ->
    %% GET /rest/chaininfo.json
    Format = parse_format(Format0),
    rest_chaininfo(Format);

route_request([<<"mempool">>, <<"info", Format0/binary>>], _Query) ->
    %% GET /rest/mempool/info.json
    Format = parse_format(Format0),
    rest_mempool_info(Format);

route_request([<<"mempool">>, <<"contents", Format0/binary>>], Query) ->
    %% GET /rest/mempool/contents.json
    Format = parse_format(Format0),
    Verbose = query_bool(Query, <<"verbose">>, true),
    rest_mempool_contents(Format, Verbose);

route_request([<<"getutxos">>, <<"checkmempool">> | OutpointsWithFormat], _Query) ->
    %% GET /rest/getutxos/checkmempool/<outpoint>/....<format>
    rest_getutxos(OutpointsWithFormat, true);

route_request([<<"getutxos">> | OutpointsWithFormat], _Query) ->
    %% GET /rest/getutxos/<outpoint>/....<format>
    rest_getutxos(OutpointsWithFormat, false);

route_request(_, _Query) ->
    {error, ?HTTP_NOT_FOUND, <<"Endpoint not found">>}.

%%% ===================================================================
%%% REST endpoint implementations
%%% ===================================================================

%% GET /rest/block/<hash>.<format>
rest_block(HashHex, Format, IncludeTxDetails) ->
    case Format of
        json -> rest_block_json(HashHex, IncludeTxDetails);
        bin -> rest_block_bin(HashHex);
        hex -> rest_block_hex(HashHex);
        undefined -> {error, ?HTTP_BAD_REQUEST, <<"Invalid format (available: json, bin, hex)">>}
    end.

rest_block_json(HashHex, IncludeTxDetails) ->
    Hash = hex_to_internal_hash(HashHex),
    case beamchain_db:get_block(Hash) of
        {ok, Block} ->
            case beamchain_db:get_block_index_by_hash(Hash) of
                {ok, #{height := Height}} ->
                    Json = format_block_json(Block, Hash, Height, IncludeTxDetails),
                    {ok, json, jsx:encode(Json)};
                not_found ->
                    {error, ?HTTP_NOT_FOUND, <<"Block index not found">>}
            end;
        not_found ->
            {error, ?HTTP_NOT_FOUND, <<"Block not found">>}
    end.

rest_block_bin(HashHex) ->
    Hash = hex_to_internal_hash(HashHex),
    case beamchain_db:get_block(Hash) of
        {ok, Block} ->
            Bin = beamchain_serialize:encode_block(Block),
            {ok, bin, Bin};
        not_found ->
            {error, ?HTTP_NOT_FOUND, <<"Block not found">>}
    end.

rest_block_hex(HashHex) ->
    Hash = hex_to_internal_hash(HashHex),
    case beamchain_db:get_block(Hash) of
        {ok, Block} ->
            Bin = beamchain_serialize:encode_block(Block),
            Hex = beamchain_serialize:hex_encode(Bin),
            {ok, hex, <<Hex/binary, "\n">>};
        not_found ->
            {error, ?HTTP_NOT_FOUND, <<"Block not found">>}
    end.

%% GET /rest/tx/<txid>.<format>
rest_tx(TxidHex, Format) ->
    case Format of
        json -> rest_tx_json(TxidHex);
        bin -> rest_tx_bin(TxidHex);
        hex -> rest_tx_hex(TxidHex);
        undefined -> {error, ?HTTP_BAD_REQUEST, <<"Invalid format (available: json, bin, hex)">>}
    end.

rest_tx_json(TxidHex) ->
    Txid = hex_to_internal_hash(TxidHex),
    case find_transaction(Txid) of
        {ok, Tx, BlockHash, Height, _Pos} ->
            Json = format_tx_json(Tx, BlockHash, Height),
            {ok, json, jsx:encode(Json)};
        not_found ->
            {error, ?HTTP_NOT_FOUND, <<"Transaction not found">>}
    end.

rest_tx_bin(TxidHex) ->
    Txid = hex_to_internal_hash(TxidHex),
    case find_transaction(Txid) of
        {ok, Tx, _BlockHash, _Height, _Pos} ->
            Bin = beamchain_serialize:encode_transaction(Tx),
            {ok, bin, Bin};
        not_found ->
            {error, ?HTTP_NOT_FOUND, <<"Transaction not found">>}
    end.

rest_tx_hex(TxidHex) ->
    Txid = hex_to_internal_hash(TxidHex),
    case find_transaction(Txid) of
        {ok, Tx, _BlockHash, _Height, _Pos} ->
            Bin = beamchain_serialize:encode_transaction(Tx),
            Hex = beamchain_serialize:hex_encode(Bin),
            {ok, hex, <<Hex/binary, "\n">>};
        not_found ->
            {error, ?HTTP_NOT_FOUND, <<"Transaction not found">>}
    end.

%% GET /rest/headers/<count>/<hash>.<format>
rest_headers(HashHex, Count0, Format) ->
    Count = min(Count0, ?MAX_REST_HEADERS_RESULTS),
    case Format of
        json -> rest_headers_json(HashHex, Count);
        bin -> rest_headers_bin(HashHex, Count);
        hex -> rest_headers_hex(HashHex, Count);
        undefined -> {error, ?HTTP_BAD_REQUEST, <<"Invalid format (available: json, bin, hex)">>}
    end.

rest_headers_json(HashHex, Count) ->
    Hash = hex_to_internal_hash(HashHex),
    case collect_headers(Hash, Count) of
        {ok, Headers} ->
            Json = [format_header_json(H, HHash, Height) ||
                    {H, HHash, Height} <- Headers],
            {ok, json, jsx:encode(Json)};
        {error, Reason} ->
            {error, ?HTTP_NOT_FOUND, Reason}
    end.

rest_headers_bin(HashHex, Count) ->
    Hash = hex_to_internal_hash(HashHex),
    case collect_headers(Hash, Count) of
        {ok, Headers} ->
            Bins = [beamchain_serialize:encode_block_header(H) ||
                    {H, _HHash, _Height} <- Headers],
            {ok, bin, iolist_to_binary(Bins)};
        {error, Reason} ->
            {error, ?HTTP_NOT_FOUND, Reason}
    end.

rest_headers_hex(HashHex, Count) ->
    Hash = hex_to_internal_hash(HashHex),
    case collect_headers(Hash, Count) of
        {ok, Headers} ->
            Bins = [beamchain_serialize:encode_block_header(H) ||
                    {H, _HHash, _Height} <- Headers],
            Hex = beamchain_serialize:hex_encode(iolist_to_binary(Bins)),
            {ok, hex, <<Hex/binary, "\n">>};
        {error, Reason} ->
            {error, ?HTTP_NOT_FOUND, Reason}
    end.

%% GET /rest/blockhashbyheight/<height>.<format>
rest_blockhash_by_height(Height, Format) when is_integer(Height), Height >= 0 ->
    case Format of
        json -> rest_blockhash_json(Height);
        bin -> rest_blockhash_bin(Height);
        hex -> rest_blockhash_hex(Height);
        undefined -> {error, ?HTTP_BAD_REQUEST, <<"Invalid format (available: json, bin, hex)">>}
    end;
rest_blockhash_by_height(_, _) ->
    {error, ?HTTP_BAD_REQUEST, <<"Invalid height">>}.

rest_blockhash_json(Height) ->
    case beamchain_db:get_block_index(Height) of
        {ok, #{hash := Hash}} ->
            Json = #{<<"blockhash">> => hash_to_hex(Hash)},
            {ok, json, jsx:encode(Json)};
        not_found ->
            {error, ?HTTP_NOT_FOUND, <<"Block height out of range">>}
    end.

rest_blockhash_bin(Height) ->
    case beamchain_db:get_block_index(Height) of
        {ok, #{hash := Hash}} ->
            %% Return hash in display order (reversed)
            {ok, bin, beamchain_serialize:reverse_bytes(Hash)};
        not_found ->
            {error, ?HTTP_NOT_FOUND, <<"Block height out of range">>}
    end.

rest_blockhash_hex(Height) ->
    case beamchain_db:get_block_index(Height) of
        {ok, #{hash := Hash}} ->
            Hex = hash_to_hex(Hash),
            {ok, hex, <<Hex/binary, "\n">>};
        not_found ->
            {error, ?HTTP_NOT_FOUND, <<"Block height out of range">>}
    end.

%% GET /rest/chaininfo.json
rest_chaininfo(json) ->
    case beamchain_chainstate:get_tip() of
        {ok, {Hash, Height}} ->
            %% Get chain params for network name
            Network = beamchain_config:network(),
            %% Calculate verification progress (estimate)
            Progress = calculate_sync_progress(Height),
            Json = #{
                <<"chain">> => atom_to_binary(Network, utf8),
                <<"blocks">> => Height,
                <<"headers">> => get_header_count(),
                <<"bestblockhash">> => hash_to_hex(Hash),
                <<"difficulty">> => tip_difficulty(),
                <<"time">> => tip_time(),
                <<"mediantime">> => get_mtp(),
                <<"verificationprogress">> => Progress,
                <<"initialblockdownload">> => not beamchain_chainstate:is_synced(),
                <<"chainwork">> => get_chainwork(Hash),
                <<"size_on_disk">> => get_disk_size(),
                <<"pruned">> => beamchain_config:prune_enabled()
            },
            {ok, json, jsx:encode(Json)};
        not_found ->
            {error, ?HTTP_SERVICE_UNAVAILABLE, <<"Chain not available">>}
    end;
rest_chaininfo(_) ->
    {error, ?HTTP_BAD_REQUEST, <<"Only JSON format supported for chaininfo">>}.

%% GET /rest/mempool/info.json
rest_mempool_info(json) ->
    Info = beamchain_mempool:get_info(),
    Size = maps:get(size, Info, 0),
    Bytes = maps:get(bytes, Info, 0),
    Json = #{
        <<"loaded">> => true,
        <<"size">> => Size,
        <<"bytes">> => Bytes,
        <<"usage">> => Bytes,
        <<"total_fee">> => maps:get(total_fee, Info, 0) / 100000000.0,
        <<"maxmempool">> => 300000000,
        <<"mempoolminfee">> => maps:get(min_fee_rate, Info, 1) / 100000.0,
        <<"minrelaytxfee">> => 0.00001000,
        <<"incrementalrelayfee">> => 0.00001000,
        <<"unbroadcastcount">> => 0,
        <<"fullrbf">> => beamchain_config:mempool_full_rbf()
    },
    {ok, json, jsx:encode(Json)};
rest_mempool_info(_) ->
    {error, ?HTTP_BAD_REQUEST, <<"Only JSON format supported for mempool/info">>}.

%% GET /rest/mempool/contents.json
rest_mempool_contents(json, Verbose) ->
    case Verbose of
        true ->
            Entries = beamchain_mempool:get_all_entries(),
            Json = format_mempool_contents(Entries),
            {ok, json, jsx:encode(Json)};
        false ->
            Txids = beamchain_mempool:get_all_txids(),
            Json = #{<<"txids">> => [hash_to_hex(T) || T <- Txids]},
            {ok, json, jsx:encode(Json)}
    end;
rest_mempool_contents(_, _) ->
    {error, ?HTTP_BAD_REQUEST, <<"Only JSON format supported for mempool/contents">>}.

%% GET /rest/getutxos[/checkmempool]/<outpoint>/....<format>
rest_getutxos(OutpointsWithFormat, CheckMempool) ->
    %% The last element contains the format suffix
    case parse_outpoints_and_format(OutpointsWithFormat) of
        {ok, Outpoints, _Format} when length(Outpoints) > ?MAX_GETUTXOS_OUTPOINTS ->
            {error, ?HTTP_BAD_REQUEST,
             iolist_to_binary(io_lib:format("Too many outpoints (max ~B)",
                                           [?MAX_GETUTXOS_OUTPOINTS]))};
        {ok, [], _Format} ->
            {error, ?HTTP_BAD_REQUEST, <<"No outpoints specified">>};
        {ok, Outpoints, Format} ->
            rest_getutxos_impl(Outpoints, CheckMempool, Format);
        {error, Reason} ->
            {error, ?HTTP_BAD_REQUEST, Reason}
    end.

rest_getutxos_impl(Outpoints, CheckMempool, Format) ->
    %% Look up each outpoint
    Results = [lookup_utxo(Txid, N, CheckMempool) || {Txid, N} <- Outpoints],

    %% Get chain tip info
    {ChainHeight, ChainHash} = case beamchain_chainstate:get_tip() of
        {ok, {H, Ht}} -> {Ht, H};
        not_found -> {0, <<0:256>>}
    end,

    case Format of
        json ->
            Json = #{
                <<"chainHeight">> => ChainHeight,
                <<"chaintipHash">> => hash_to_hex(ChainHash),
                <<"bitmap">> => format_utxo_bitmap(Results),
                <<"utxos">> => [format_utxo_entry(R) || R <- Results, R =/= not_found]
            },
            {ok, json, jsx:encode(Json)};
        bin ->
            Bin = encode_utxos_binary(ChainHeight, ChainHash, Results),
            {ok, bin, Bin};
        hex ->
            Bin = encode_utxos_binary(ChainHeight, ChainHash, Results),
            Hex = beamchain_serialize:hex_encode(Bin),
            {ok, hex, <<Hex/binary, "\n">>};
        undefined ->
            {error, ?HTTP_BAD_REQUEST, <<"Invalid format (available: json, bin, hex)">>}
    end.

%%% ===================================================================
%%% Helper functions
%%% ===================================================================

%% Parse the path into segments
parse_path(Path) ->
    %% Remove /rest/ prefix
    case binary:split(Path, <<"/rest/">>) of
        [<<>>, Rest] ->
            binary:split(Rest, <<"/">>, [global]);
        _ ->
            []
    end.

%% Parse format from suffix (e.g., ".json" -> json)
parse_format(<<".json">>) -> json;
parse_format(<<".bin">>) -> bin;
parse_format(<<".hex">>) -> hex;
parse_format(_) -> undefined.

%% Parse hash with format suffix
parse_hash_format(HashWithFormat) ->
    case binary:split(HashWithFormat, <<".">>) of
        [HashHex, FormatSuffix] ->
            {HashHex, parse_format(<<".", FormatSuffix/binary>>)};
        [HashHex] ->
            {HashHex, undefined}
    end.

%% Parse height with format suffix
parse_height_format(HeightWithFormat) ->
    case binary:split(HeightWithFormat, <<".">>) of
        [HeightBin, FormatSuffix] ->
            Height = binary_to_integer(HeightBin),
            {Height, parse_format(<<".", FormatSuffix/binary>>)};
        [HeightBin] ->
            Height = binary_to_integer(HeightBin),
            {Height, undefined}
    end.

%% Parse count from path segment
parse_count(Bin, Default) ->
    try binary_to_integer(Bin) of
        N when N > 0 -> N;
        _ -> Default
    catch _:_ -> Default
    end.

%% Get count from query string
query_count(Query, Default) ->
    case proplists:get_value(<<"count">>, Query) of
        undefined -> Default;
        Val -> parse_count(Val, Default)
    end.

%% Get boolean from query string
query_bool(Query, Key, Default) ->
    case proplists:get_value(Key, Query) of
        undefined -> Default;
        <<"true">> -> true;
        <<"1">> -> true;
        <<"false">> -> false;
        <<"0">> -> false;
        _ -> Default
    end.

%% Parse outpoints list and extract format from the last one
parse_outpoints_and_format([]) ->
    {error, <<"No outpoints specified">>};
parse_outpoints_and_format(Parts) ->
    %% The last part contains the format suffix
    [LastWithFormat | RevRest] = lists:reverse(Parts),
    {LastOutpoint, Format} = parse_hash_format(LastWithFormat),
    AllOutpointStrs = lists:reverse([LastOutpoint | RevRest]),
    case parse_outpoint_list(AllOutpointStrs) of
        {ok, Outpoints} -> {ok, Outpoints, Format};
        Error -> Error
    end.

parse_outpoint_list(Strs) ->
    try
        Outpoints = [parse_outpoint(S) || S <- Strs],
        {ok, Outpoints}
    catch
        _:_ -> {error, <<"Invalid outpoint format">>}
    end.

%% Parse "txid-n" to {Txid, N}
parse_outpoint(Str) ->
    case binary:split(Str, <<"-">>) of
        [TxidHex, NBin] ->
            Txid = hex_to_internal_hash(TxidHex),
            N = binary_to_integer(NBin),
            {Txid, N};
        _ ->
            throw(invalid_outpoint)
    end.

%% Convert hex to internal hash format (reverse bytes)
hex_to_internal_hash(Hex) ->
    Bin = beamchain_serialize:hex_decode(Hex),
    beamchain_serialize:reverse_bytes(Bin).

%% Convert internal hash to hex display format
hash_to_hex(Hash) ->
    beamchain_serialize:hex_encode(beamchain_serialize:reverse_bytes(Hash)).

%% Find a transaction in mempool or blockchain
find_transaction(Txid) ->
    %% Check mempool first
    case beamchain_mempool:get_entry(Txid) of
        {ok, Entry} ->
            Tx = element(3, Entry),  %% tx is 3rd field in mempool_entry
            {ok, Tx, undefined, -1, -1};
        not_found ->
            %% Check txindex
            case beamchain_config:txindex_enabled() of
                true ->
                    case beamchain_db:get_tx_location(Txid) of
                        {ok, BlockHash, Pos} ->
                            case beamchain_db:get_block(BlockHash) of
                                {ok, Block} ->
                                    Txs = Block#block.transactions,
                                    case length(Txs) > Pos of
                                        true ->
                                            Tx = lists:nth(Pos + 1, Txs),
                                            Height = case beamchain_db:get_block_index_by_hash(BlockHash) of
                                                {ok, #{height := H}} -> H;
                                                _ -> -1
                                            end,
                                            {ok, Tx, BlockHash, Height, Pos};
                                        false ->
                                            not_found
                                    end;
                                not_found ->
                                    not_found
                            end;
                        not_found ->
                            not_found
                    end;
                false ->
                    not_found
            end
    end.

%% Collect N headers starting from a hash
collect_headers(StartHash, Count) ->
    case beamchain_db:get_block_index_by_hash(StartHash) of
        {ok, #{height := StartHeight}} ->
            collect_headers_from_height(StartHeight, Count, []);
        not_found ->
            {error, <<"Block not found">>}
    end.

collect_headers_from_height(_Height, 0, Acc) ->
    {ok, lists:reverse(Acc)};
collect_headers_from_height(Height, Count, Acc) ->
    case beamchain_db:get_block_index(Height) of
        {ok, #{hash := Hash, header := Header}} ->
            collect_headers_from_height(Height + 1, Count - 1,
                                        [{Header, Hash, Height} | Acc]);
        not_found ->
            {ok, lists:reverse(Acc)}
    end.

%% Look up a UTXO
lookup_utxo(Txid, N, CheckMempool) ->
    case CheckMempool of
        true ->
            case beamchain_mempool:get_mempool_utxo(Txid, N) of
                {ok, Utxo} -> {ok, Utxo, mempool};
                not_found -> lookup_chain_utxo(Txid, N)
            end;
        false ->
            lookup_chain_utxo(Txid, N)
    end.

lookup_chain_utxo(Txid, N) ->
    case beamchain_chainstate:get_utxo(Txid, N) of
        {ok, Utxo} -> {ok, Utxo, chain};
        not_found -> not_found
    end.

%%% ===================================================================
%%% Response formatting
%%% ===================================================================

reply_success(Format, Body, Req0, CowboyState) ->
    ContentType = format_content_type(Format),
    Headers = #{
        <<"content-type">> => ContentType,
        <<"access-control-allow-origin">> => <<"*">>
    },
    Req = cowboy_req:reply(?HTTP_OK, Headers, Body, Req0),
    {ok, Req, CowboyState}.

reply_error(Status, Message, Req0, CowboyState) ->
    Headers = #{
        <<"content-type">> => <<"text/plain">>,
        <<"access-control-allow-origin">> => <<"*">>
    },
    Req = cowboy_req:reply(Status, Headers, <<Message/binary, "\r\n">>, Req0),
    {ok, Req, CowboyState}.

format_content_type(json) -> <<"application/json">>;
format_content_type(bin) -> <<"application/octet-stream">>;
format_content_type(hex) -> <<"text/plain">>;
format_content_type(_) -> <<"text/plain">>.

%%% ===================================================================
%%% JSON formatting
%%% ===================================================================

format_block_json(Block, Hash, Height, IncludeTxDetails) ->
    Header = Block#block.header,
    Txs = Block#block.transactions,
    Bits = Header#block_header.bits,

    Base = #{
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
        <<"nTx">> => length(Txs),
        <<"previousblockhash">> => hash_to_hex(Header#block_header.prev_hash),
        <<"strippedsize">> => calculate_stripped_size(Block),
        <<"size">> => calculate_block_size(Block),
        <<"weight">> => calculate_block_weight(Block)
    },

    TxField = case IncludeTxDetails of
        true ->
            [format_tx_json(Tx, Hash, Height) || Tx <- Txs];
        false ->
            [hash_to_hex(beamchain_serialize:tx_hash(Tx)) || Tx <- Txs]
    end,

    %% Add next block hash if available
    NextHash = case beamchain_db:get_block_index(Height + 1) of
        {ok, #{hash := NH}} -> hash_to_hex(NH);
        not_found -> null
    end,

    Base#{<<"tx">> => TxField, <<"nextblockhash">> => NextHash}.

format_tx_json(Tx, BlockHash, Height) ->
    Txid = beamchain_serialize:tx_hash(Tx),
    Wtxid = beamchain_serialize:wtx_hash(Tx),
    Size = beamchain_serialize:tx_size(Tx),
    VSize = beamchain_serialize:tx_vsize(Tx),
    Weight = beamchain_serialize:tx_weight(Tx),

    Base = #{
        <<"txid">> => hash_to_hex(Txid),
        <<"hash">> => hash_to_hex(Wtxid),
        <<"version">> => Tx#transaction.version,
        <<"size">> => Size,
        <<"vsize">> => VSize,
        <<"weight">> => Weight,
        <<"locktime">> => Tx#transaction.locktime,
        <<"vin">> => [format_vin(In) || In <- Tx#transaction.inputs],
        <<"vout">> => format_vouts(Tx#transaction.outputs)
    },

    %% Add block info if in a block
    case BlockHash of
        undefined ->
            Base;
        _ ->
            Base#{
                <<"blockhash">> => hash_to_hex(BlockHash),
                <<"confirmations">> => confirmations(Height),
                <<"blocktime">> => block_time(BlockHash)
            }
    end.

format_vin(#tx_in{prev_out = #outpoint{hash = PrevHash, index = PrevIdx},
                  script_sig = ScriptSig, sequence = Seq}) ->
    IsCoinbase = (PrevHash =:= <<0:256>>) andalso (PrevIdx =:= 16#ffffffff),
    case IsCoinbase of
        true ->
            #{
                <<"coinbase">> => beamchain_serialize:hex_encode(ScriptSig),
                <<"sequence">> => Seq
            };
        false ->
            #{
                <<"txid">> => hash_to_hex(PrevHash),
                <<"vout">> => PrevIdx,
                <<"scriptSig">> => #{
                    <<"asm">> => <<"">>,  %% TODO: disassemble
                    <<"hex">> => beamchain_serialize:hex_encode(ScriptSig)
                },
                <<"sequence">> => Seq
            }
    end.

format_vouts(Outputs) ->
    format_vouts(Outputs, 0).

format_vouts([], _N) -> [];
format_vouts([#tx_out{value = Value, script_pubkey = Script} | Rest], N) ->
    [#{
        <<"value">> => Value / 100000000.0,
        <<"n">> => N,
        <<"scriptPubKey">> => #{
            <<"asm">> => <<"">>,  %% TODO: disassemble
            <<"hex">> => beamchain_serialize:hex_encode(Script),
            <<"type">> => script_type(Script)
        }
    } | format_vouts(Rest, N + 1)].

format_header_json(Header, Hash, Height) ->
    Bits = Header#block_header.bits,
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
        <<"previousblockhash">> => hash_to_hex(Header#block_header.prev_hash),
        <<"nextblockhash">> => next_block_hash(Height)
    }.

format_mempool_contents(Entries) ->
    lists:foldl(fun(Entry, Acc) ->
        Txid = element(1, Entry),  %% txid is 1st field
        TxidHex = hash_to_hex(Txid),
        Info = format_mempool_entry(Entry),
        Acc#{TxidHex => Info}
    end, #{}, Entries).

format_mempool_entry(Entry) ->
    %% mempool_entry record fields
    Fee = element(4, Entry),
    VSize = element(6, Entry),
    Weight = element(7, Entry),
    TimeAdded = element(9, Entry),
    AncestorSize = element(12, Entry),
    AncestorFee = element(13, Entry),
    DescendantSize = element(15, Entry),
    DescendantFee = element(16, Entry),
    #{
        <<"vsize">> => VSize,
        <<"weight">> => Weight,
        <<"time">> => TimeAdded,
        <<"fees">> => #{
            <<"base">> => Fee / 100000000.0,
            <<"ancestor">> => AncestorFee / 100000000.0,
            <<"descendant">> => DescendantFee / 100000000.0
        },
        <<"ancestorsize">> => AncestorSize,
        <<"descendantsize">> => DescendantSize
    }.

format_utxo_bitmap(Results) ->
    %% Create a hex-encoded bitmap of found/not-found
    Bits = [case R of not_found -> 0; _ -> 1 end || R <- Results],
    %% Pad to byte boundary
    PadLen = case length(Bits) rem 8 of
        0 -> 0;
        N -> 8 - N
    end,
    PaddedBits = Bits ++ lists:duplicate(PadLen, 0),
    Bytes = bits_to_bytes(PaddedBits),
    beamchain_serialize:hex_encode(list_to_binary(Bytes)).

bits_to_bytes([]) -> [];
bits_to_bytes(Bits) when length(Bits) >= 8 ->
    {Byte, Rest} = lists:split(8, Bits),
    [lists:foldl(fun(B, Acc) -> (Acc bsl 1) bor B end, 0, Byte) |
     bits_to_bytes(Rest)];
bits_to_bytes(_) -> [].

format_utxo_entry(not_found) ->
    null;
format_utxo_entry({ok, Utxo, _Source}) ->
    Value = Utxo#utxo.value,
    Script = Utxo#utxo.script_pubkey,
    Height = Utxo#utxo.height,
    #{
        <<"height">> => Height,
        <<"value">> => Value / 100000000.0,
        <<"scriptPubKey">> => #{
            <<"hex">> => beamchain_serialize:hex_encode(Script),
            <<"type">> => script_type(Script)
        }
    }.

encode_utxos_binary(ChainHeight, ChainHash, Results) ->
    %% Encode in Bitcoin Core format
    HeightBin = <<ChainHeight:32/little>>,
    HashBin = beamchain_serialize:reverse_bytes(ChainHash),
    %% Bitmap
    Bits = [case R of not_found -> 0; _ -> 1 end || R <- Results],
    BitmapBytes = bits_to_bytes(Bits),
    BitmapBin = list_to_binary(BitmapBytes),
    %% UTXOs
    UtxoBins = [encode_ccoin(R) || R <- Results, R =/= not_found],
    iolist_to_binary([HeightBin, HashBin,
                      beamchain_serialize:encode_varint(length(BitmapBytes)),
                      BitmapBin,
                      beamchain_serialize:encode_varint(length(UtxoBins)),
                      UtxoBins]).

encode_ccoin({ok, Utxo, _Source}) ->
    Height = Utxo#utxo.height,
    Value = Utxo#utxo.value,
    Script = Utxo#utxo.script_pubkey,
    %% CCoin format: version (dummy), height, TxOut
    <<0:32/little, Height:32/little, Value:64/little,
      (beamchain_serialize:encode_varstr(Script))/binary>>.

%%% ===================================================================
%%% Chain info helpers
%%% ===================================================================

confirmations(Height) when Height < 0 -> 0;
confirmations(Height) ->
    case beamchain_chainstate:get_tip() of
        {ok, {_Hash, TipHeight}} ->
            max(0, TipHeight - Height + 1);
        not_found ->
            0
    end.

block_mtp(Height) when Height < 0 -> 0;
block_mtp(_Height) ->
    case beamchain_chainstate:get_mtp() of
        {ok, MTP} -> MTP;
        _ -> 0
    end.

block_time(BlockHash) ->
    case beamchain_db:get_block_index_by_hash(BlockHash) of
        {ok, #{header := H}} -> H#block_header.timestamp;
        not_found -> 0
    end.

next_block_hash(Height) ->
    case beamchain_db:get_block_index(Height + 1) of
        {ok, #{hash := Hash}} -> hash_to_hex(Hash);
        not_found -> null
    end.

tip_difficulty() ->
    case beamchain_chainstate:get_tip() of
        {ok, {Hash, _Height}} ->
            case beamchain_db:get_block_index_by_hash(Hash) of
                {ok, #{header := H}} ->
                    bits_to_difficulty(H#block_header.bits);
                not_found -> 0.0
            end;
        not_found -> 0.0
    end.

tip_time() ->
    case beamchain_chainstate:get_tip() of
        {ok, {Hash, _Height}} ->
            case beamchain_db:get_block_index_by_hash(Hash) of
                {ok, #{header := H}} ->
                    H#block_header.timestamp;
                not_found -> 0
            end;
        not_found -> 0
    end.

get_mtp() ->
    case beamchain_chainstate:get_mtp() of
        {ok, MTP} -> MTP;
        _ -> 0
    end.

get_header_count() ->
    %% In a full node, headers count equals block count
    case beamchain_chainstate:get_tip() of
        {ok, {_Hash, Height}} -> Height;
        not_found -> 0
    end.

get_chainwork(BlockHash) ->
    case beamchain_db:get_block_index_by_hash(BlockHash) of
        {ok, #{chainwork := CW}} when is_binary(CW) ->
            beamchain_serialize:hex_encode(CW);
        {ok, _} ->
            <<"0000000000000000000000000000000000000000000000000000000000000000">>;
        not_found ->
            <<"0000000000000000000000000000000000000000000000000000000000000000">>
    end.

get_disk_size() ->
    %% Estimate disk usage
    DataDir = beamchain_config:datadir(),
    ChainDataDir = filename:join(DataDir, "chaindata"),
    case file:list_dir(ChainDataDir) of
        {ok, Files} ->
            lists:sum([file_size(filename:join(ChainDataDir, F)) || F <- Files]);
        _ ->
            0
    end.

file_size(Path) ->
    case file:read_file_info(Path) of
        {ok, Info} -> element(2, Info);  %% size field
        _ -> 0
    end.

calculate_sync_progress(_Height) ->
    %% Estimate based on current time vs block time
    Now = erlang:system_time(second),
    case beamchain_chainstate:get_tip() of
        {ok, {Hash, _}} ->
            case beamchain_db:get_block_index_by_hash(Hash) of
                {ok, #{header := H}} ->
                    BlockTime = H#block_header.timestamp,
                    %% Assume Bitcoin started 2009-01-03
                    GenesisTime = 1231006505,
                    TotalTime = Now - GenesisTime,
                    BlockAge = BlockTime - GenesisTime,
                    min(1.0, BlockAge / TotalTime);
                _ -> 0.0
            end;
        _ -> 0.0
    end.

bits_to_difficulty(Bits) ->
    %% Convert compact bits to difficulty
    Exp = Bits bsr 24,
    Mant = Bits band 16#007fffff,
    Target = case Mant > 16#7fffff of
        true -> 0;
        false ->
            case Exp =< 3 of
                true -> Mant bsr (8 * (3 - Exp));
                false -> Mant bsl (8 * (Exp - 3))
            end
    end,
    case Target of
        0 -> 0.0;
        _ ->
            %% Mainnet genesis difficulty target
            MaxTarget = (16#00000000FFFF0000000000000000000000000000000000000000000000000000),
            MaxTarget / Target
    end.

calculate_stripped_size(Block) ->
    %% Size without witness data
    StrippedTxs = [strip_witness(Tx) || Tx <- Block#block.transactions],
    Bin = beamchain_serialize:encode_block(Block#block{transactions = StrippedTxs}),
    byte_size(Bin).

%% Strip witness data from a transaction
strip_witness(Tx) ->
    StrippedInputs = [In#tx_in{witness = []} || In <- Tx#transaction.inputs],
    Tx#transaction{inputs = StrippedInputs}.

calculate_block_size(Block) ->
    Bin = beamchain_serialize:encode_block(Block),
    byte_size(Bin).

calculate_block_weight(Block) ->
    StrippedSize = calculate_stripped_size(Block),
    TotalSize = calculate_block_size(Block),
    (StrippedSize * 3) + TotalSize.

script_type(<<16#76, 16#a9, 20, _:20/binary, 16#88, 16#ac>>) ->
    <<"pubkeyhash">>;
script_type(<<16#a9, 20, _:20/binary, 16#87>>) ->
    <<"scripthash">>;
script_type(<<16#00, 20, _:20/binary>>) ->
    <<"witness_v0_keyhash">>;
script_type(<<16#00, 32, _:32/binary>>) ->
    <<"witness_v0_scripthash">>;
script_type(<<16#51, 32, _:32/binary>>) ->
    <<"witness_v1_taproot">>;
script_type(<<16#51, 2, _:2/binary>>) ->
    <<"anchor">>;
script_type(Script) when byte_size(Script) =:= 35 orelse byte_size(Script) =:= 67 ->
    <<"pubkey">>;
script_type(<<16#6a, _/binary>>) ->
    <<"nulldata">>;
script_type(_) ->
    <<"nonstandard">>.

%%% ===================================================================
%%% Configuration
%%% ===================================================================

rest_port(Params) ->
    %% Use RPC port + 10 for REST by default, or read from config.
    %% Using +10 instead of +1 to avoid collision with P2P port
    %% (e.g., testnet4: rpc=48332, p2p=48333, rest=48342).
    case os:getenv("BEAMCHAIN_REST_PORT") of
        false ->
            RpcPort = case beamchain_config:get(rpcport) of
                undefined -> Params#network_params.rpc_port;
                P when is_integer(P) -> P;
                P when is_list(P) -> list_to_integer(P)
            end,
            RpcPort + 10;
        PortStr ->
            list_to_integer(PortStr)
    end.
