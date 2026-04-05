-module(beamchain_utxo_repair).
-export([repair_for_block/1, repair_range/2]).

%% @doc Check all input UTXOs for a block and report missing ones.
%% Uses Bitcoin Core RPC to fetch the creating transaction's output details
%% and adds missing UTXOs to the chainstate.
%%
%% Usage from remote shell:
%%   beamchain_utxo_repair:repair_for_block(399870).
%%   beamchain_utxo_repair:repair_range(399870, 412438).

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-define(CORE_RPC_URL, "http://127.0.0.1:8332/").
-define(CORE_COOKIE_PATH, "/data/nvme1/hashhog-mainnet/bitcoin-core/.cookie").

%% Repair UTXOs for a range of blocks, submitting each after repair.
repair_range(From, To) ->
    repair_range_loop(From, To).

repair_range_loop(Current, To) when Current > To ->
    logger:info("repair: completed range up to ~B", [To]),
    ok;
repair_range_loop(Current, To) ->
    %% Check if already past this block
    case beamchain_chainstate:get_tip() of
        {ok, {_, Tip}} when Tip >= Current ->
            logger:info("repair: block ~B already at tip ~B, skipping",
                        [Current, Tip]),
            repair_range_loop(Tip + 1, To);
        _ ->
            case repair_for_block(Current) of
                ok ->
                    %% Submit the block
                    case submit_from_core(Current) of
                        ok ->
                            timer:sleep(100),
                            {ok, {_, NewTip}} = beamchain_chainstate:get_tip(),
                            case NewTip rem 100 of
                                0 -> logger:info("repair: tip=~B", [NewTip]);
                                _ -> ok
                            end,
                            repair_range_loop(NewTip + 1, To);
                        {error, Reason} ->
                            logger:error("repair: submit failed at ~B: ~p",
                                         [Current, Reason]),
                            %% Wait and check if block_sync advanced
                            timer:sleep(5000),
                            {ok, {_, NewTip}} = beamchain_chainstate:get_tip(),
                            case NewTip >= Current of
                                true ->
                                    repair_range_loop(NewTip + 1, To);
                                false ->
                                    {error, {submit_failed, Current, Reason}}
                            end
                    end;
                {error, Reason} ->
                    logger:error("repair: failed at block ~B: ~p",
                                 [Current, Reason]),
                    {error, {repair_failed, Current, Reason}}
            end
    end.

%% Repair missing UTXOs for a single block.
repair_for_block(Height) ->
    %% Get the block from Core
    case core_rpc(<<"getblockhash">>, [Height]) of
        {ok, BlockHash} ->
            case core_rpc(<<"getblock">>, [BlockHash, 2]) of
                {ok, BlockInfo} ->
                    repair_block_utxos(Height, BlockInfo);
                {error, E} ->
                    {error, {getblock_failed, E}}
            end;
        {error, E} ->
            {error, {getblockhash_failed, E}}
    end.

%% Check all inputs and repair missing UTXOs.
repair_block_utxos(Height, BlockInfo) ->
    Txs = maps:get(<<"tx">>, BlockInfo, []),

    %% Collect all needed UTXOs
    Needed = lists:foldl(fun(Tx, OuterAcc) ->
        Vins = maps:get(<<"vin">>, Tx, []),
        lists:foldl(fun(Vin, InnerAcc) ->
            case maps:is_key(<<"coinbase">>, Vin) of
                true -> InnerAcc;
                false ->
                    Txid = maps:get(<<"txid">>, Vin),
                    Vout = maps:get(<<"vout">>, Vin),
                    Prevout = maps:get(<<"prevout">>, Vin, undefined),
                    [{Txid, Vout, Prevout} | InnerAcc]
            end
        end, OuterAcc, Vins)
    end, [], Txs),

    %% Check which are missing
    Missing = lists:filter(fun({Txid, Vout, _Prevout}) ->
        TxHash = hex_to_internal_txid(Txid),
        case beamchain_chainstate:get_utxo(TxHash, Vout) of
            {ok, _} -> false;
            not_found -> true
        end
    end, Needed),

    case Missing of
        [] ->
            ok;
        _ ->
            logger:info("repair: block ~B has ~B/~B missing UTXOs",
                        [Height, length(Missing), length(Needed)]),
            repair_missing(Height, Missing)
    end.

%% Repair a list of missing UTXOs.
repair_missing(_Height, []) ->
    ok;
repair_missing(Height, [{Txid, Vout, Prevout} | Rest]) ->
    case repair_single_utxo(Height, Txid, Vout, Prevout) of
        ok ->
            repair_missing(Height, Rest);
        {error, Reason} ->
            logger:error("repair: cannot repair ~s:~B: ~p",
                         [Txid, Vout, Reason]),
            %% Continue with others
            repair_missing(Height, Rest)
    end.

%% Repair a single UTXO.
repair_single_utxo(_SpendingHeight, Txid, Vout, Prevout) ->
    %% Try to get details from prevout (Core 24+ includes this in verbose)
    case Prevout of
        undefined ->
            repair_via_core_lookup(Txid, Vout);
        _ when is_map(Prevout) ->
            Value = maps:get(<<"value">>, Prevout, 0),
            ScriptPubKey = maps:get(<<"scriptPubKey">>, Prevout, #{}),
            ScriptHex = maps:get(<<"hex">>, ScriptPubKey, <<>>),
            ValueSats0 = round(Value * 100000000),
            Script0 = binary:decode_hex(ScriptHex),
            TxHash0 = hex_to_internal_txid(Txid),
            %% Look up height and coinbase status from our tx index
            {CreateHeight0, IsCoinbase0} = lookup_tx_metadata(Txid),
            Utxo0 = #utxo{
                value = ValueSats0,
                script_pubkey = Script0,
                is_coinbase = IsCoinbase0,
                height = CreateHeight0
            },
            beamchain_chainstate:add_utxo(TxHash0, Vout, Utxo0),
            ok;
        _ ->
            repair_via_core_lookup(Txid, Vout)
    end.

%% Look up UTXO details from Core by finding the creating block.
repair_via_core_lookup(Txid, Vout) ->
    %% Try our tx index first
    TxHash = hex_to_internal_txid(Txid),
    case beamchain_db:get_tx_location(TxHash) of
        {ok, #{height := H, block_hash := BH}} ->
            BHDisplay = internal_to_display_hex(BH),
            case core_rpc(<<"getrawtransaction">>, [Txid, true, BHDisplay]) of
                {ok, TxInfo} ->
                    add_utxo_from_tx_info(TxHash, Vout, TxInfo, H);
                {error, _} ->
                    {error, core_rpc_failed}
            end;
        not_found ->
            %% TX not in our index. Cannot look up without Core's txindex.
            {error, tx_not_indexed}
    end.

%% Add UTXO from Core's transaction info.
add_utxo_from_tx_info(TxHash, Vout, TxInfo, CreateHeight) ->
    Vouts = maps:get(<<"vout">>, TxInfo, []),
    case find_vout(Vouts, Vout) of
        {ok, Output} ->
            Value1 = maps:get(<<"value">>, Output, 0),
            ScriptPubKey1 = maps:get(<<"scriptPubKey">>, Output, #{}),
            ScriptHex1 = maps:get(<<"hex">>, ScriptPubKey1, <<>>),
            ValueSats1 = round(Value1 * 100000000),
            Script1 = binary:decode_hex(ScriptHex1),
            Vins1 = maps:get(<<"vin">>, TxInfo, []),
            IsCoinbase1 = case Vins1 of
                [First1 | _] -> maps:is_key(<<"coinbase">>, First1);
                _ -> false
            end,
            Utxo1 = #utxo{
                value = ValueSats1,
                script_pubkey = Script1,
                is_coinbase = IsCoinbase1,
                height = CreateHeight
            },
            beamchain_chainstate:add_utxo(TxHash, Vout, Utxo1),
            ok;
        not_found ->
            {error, vout_not_found}
    end.

find_vout([], _N) -> not_found;
find_vout([Output | Rest], N) ->
    case maps:get(<<"n">>, Output, -1) of
        N -> {ok, Output};
        _ -> find_vout(Rest, N)
    end.

%% Look up tx metadata from our tx index.
lookup_tx_metadata(TxidHex) ->
    TxHash = hex_to_internal_txid(TxidHex),
    case beamchain_db:get_tx_location(TxHash) of
        {ok, #{height := H}} ->
            %% Check if it's a coinbase by checking the block
            IsCB = case beamchain_db:get_block_by_height(H) of
                {ok, Block} ->
                    [First | _] = Block#block.transactions,
                    FirstHash = beamchain_serialize:tx_hash(First),
                    FirstHash =:= TxHash;
                _ -> false
            end,
            {H, IsCB};
        not_found ->
            {0, false}
    end.

%% Submit a block from Core to beamchain.
submit_from_core(Height) ->
    case core_rpc(<<"getblockhash">>, [Height]) of
        {ok, BlockHash} ->
            case core_rpc(<<"getblock">>, [BlockHash, 0]) of
                {ok, HexBlock} ->
                    case beamchain_miner:submit_block(HexBlock) of
                        ok -> ok;
                        {error, R} -> {error, R}
                    end;
                {error, E} -> {error, E}
            end;
        {error, E} -> {error, E}
    end.

%%% ===================================================================
%%% Core RPC
%%% ===================================================================

core_rpc(Method, Params) ->
    Cookie = read_core_cookie(),
    Body = jsx:encode(#{
        <<"jsonrpc">> => <<"1.0">>,
        <<"id">> => 1,
        <<"method">> => Method,
        <<"params">> => Params
    }),
    Auth = base64:encode(Cookie),
    Headers = [
        {"Content-Type", "application/json"},
        {"Authorization", "Basic " ++ binary_to_list(Auth)}
    ],
    case httpc:request(post, {?CORE_RPC_URL, Headers, "application/json",
                              Body}, [{timeout, 120000}], []) of
        {ok, {{_, 200, _}, _, RespBody}} ->
            Decoded = jsx:decode(list_to_binary(RespBody), [return_maps]),
            case maps:get(<<"error">>, Decoded, null) of
                null -> {ok, maps:get(<<"result">>, Decoded)};
                Err -> {error, Err}
            end;
        {ok, {{_, Code, _}, _, RespBody}} ->
            %% Try to parse error response
            try
                Decoded = jsx:decode(list_to_binary(RespBody), [return_maps]),
                {error, maps:get(<<"error">>, Decoded, {http, Code})}
            catch _:_ ->
                {error, {http, Code, RespBody}}
            end;
        {error, Reason} ->
            {error, {httpc, Reason}}
    end.

read_core_cookie() ->
    {ok, Bin} = file:read_file(?CORE_COOKIE_PATH),
    string:trim(binary_to_list(Bin)).

%%% ===================================================================
%%% Hex utilities
%%% ===================================================================

hex_to_internal_txid(HexBin) when is_binary(HexBin) ->
    Bytes = binary:decode_hex(HexBin),
    beamchain_serialize:reverse_bytes(Bytes).

internal_to_display_hex(Bytes) ->
    Reversed = beamchain_serialize:reverse_bytes(Bytes),
    string:lowercase(binary_to_list(binary:encode_hex(Reversed))).
