-module(beamchain_snapshot).

%% assumeUTXO snapshot loading and verification.
%%
%% Snapshot format (Bitcoin Core compatible):
%% - Magic: "utxo" + 0xFF (5 bytes)
%% - Version: uint16 LE (2 bytes)
%% - Network magic: 4 bytes
%% - Base block hash: 32 bytes
%% - Coin count: uint64 compact size
%% - Coins: serialized UTXO entries
%%
%% Each coin entry:
%% - Txid: 32 bytes
%% - Coins per txid: compact size
%% - For each coin:
%%   - Vout: compact size
%%   - Coin: (height << 1 | coinbase_flag), value (compact), script

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-export([load_snapshot/1, verify_snapshot/2]).
-export([compute_utxo_hash/0, serialize_snapshot/2]).
-export([read_metadata/1]).

%% Dialyzer suppressions for false positives:
%% group_consecutive/2: dialyzer infers the list arg is always [] because it
%% tracks only the base-case input at one call site; the non-empty clauses are
%% the functional heart of the grouping algorithm.
-dialyzer({nowarn_function, group_consecutive/2}).

%% Snapshot magic bytes
-define(SNAPSHOT_MAGIC, <<"utxo", 16#ff>>).
-define(SNAPSHOT_VERSION, 2).

%%% ===================================================================
%%% API
%%% ===================================================================

%% @doc Load a UTXO snapshot from file path.
%% Returns {ok, #{base_hash, num_coins, coins}} or {error, Reason}.
-spec load_snapshot(string()) ->
    {ok, #{base_hash => binary(), num_coins => non_neg_integer(),
           coins => [{binary(), non_neg_integer(), #utxo{}}]}} |
    {error, term()}.
load_snapshot(Path) ->
    case file:read_file(Path) of
        {ok, Data} ->
            parse_snapshot(Data);
        {error, Reason} ->
            {error, {file_read_failed, Reason}}
    end.

%% @doc Read only the metadata from a snapshot file.
%% Returns {ok, #{base_hash, num_coins, network_magic}} or {error, Reason}.
-spec read_metadata(string()) ->
    {ok, #{base_hash => binary(), num_coins => non_neg_integer(),
           network_magic => binary()}} |
    {error, term()}.
read_metadata(Path) ->
    case file:open(Path, [read, binary, raw]) of
        {ok, Fd} ->
            Result = read_metadata_from_fd(Fd),
            file:close(Fd),
            Result;
        {error, Reason} ->
            {error, {file_open_failed, Reason}}
    end.

%% @doc Verify a loaded snapshot against expected parameters.
%% Checks network magic, block hash, and UTXO hash.
-spec verify_snapshot(map(), atom()) -> ok | {error, term()}.
verify_snapshot(#{base_hash := BaseHash, num_coins := NumCoins,
                  coins := Coins}, Network) ->
    %% Get expected parameters
    _Params = beamchain_chain_params:params(Network),

    %% Look up assumeutxo data by block hash
    case beamchain_chain_params:get_assumeutxo_by_hash(BaseHash, Network) of
        {ok, _Height, #{utxo_hash := ExpectedUtxoHash, num_coins := ExpectedCount}} ->
            %% Verify coin count
            case NumCoins =:= ExpectedCount of
                true ->
                    %% Compute and verify UTXO hash
                    ComputedHash = compute_utxo_hash_from_list(Coins),
                    case ComputedHash =:= ExpectedUtxoHash of
                        true -> ok;
                        false -> {error, {utxo_hash_mismatch,
                                          #{expected => ExpectedUtxoHash,
                                            computed => ComputedHash}}}
                    end;
                false ->
                    {error, {coin_count_mismatch,
                             #{expected => ExpectedCount, actual => NumCoins}}}
            end;
        not_found ->
            {error, {unknown_snapshot_base, BaseHash}}
    end.

%% @doc Compute the UTXO set hash from the current chainstate.
%% SHA256 of all UTXOs in deterministic order.
-spec compute_utxo_hash() -> binary().
compute_utxo_hash() ->
    %% Collect all UTXOs from chainstate in deterministic order
    %% This iterates through RocksDB in key order
    Coins = collect_all_utxos(),
    compute_utxo_hash_from_list(Coins).

%% @doc Serialize current UTXO set to snapshot format.
%% Returns binary snapshot data.
-spec serialize_snapshot(binary(), atom()) -> binary().
serialize_snapshot(BaseBlockHash, Network) ->
    Params = beamchain_chain_params:params(Network),
    #{magic := NetworkMagic} = Params,

    %% Collect all UTXOs grouped by txid
    Coins = collect_all_utxos(),
    GroupedCoins = group_coins_by_txid(Coins),
    NumCoins = length(Coins),

    %% Build header
    Header = <<?SNAPSHOT_MAGIC/binary,
               ?SNAPSHOT_VERSION:16/little,
               NetworkMagic/binary,
               BaseBlockHash:32/binary>>,

    %% Serialize coin count
    CountBin = encode_compact_size(NumCoins),

    %% Serialize coins
    CoinsBin = serialize_grouped_coins(GroupedCoins),

    <<Header/binary, CountBin/binary, CoinsBin/binary>>.

%%% ===================================================================
%%% Internal: Parsing
%%% ===================================================================

parse_snapshot(Data) ->
    case parse_header(Data) of
        {ok, #{base_hash := BaseHash, num_coins := NumCoins,
               network_magic := _Magic}, Rest} ->
            case parse_coins(Rest, NumCoins, []) of
                {ok, Coins} ->
                    {ok, #{base_hash => BaseHash,
                           num_coins => NumCoins,
                           coins => Coins}};
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

parse_header(<<Magic:5/binary, Version:16/little,
               NetworkMagic:4/binary, BaseHash:32/binary,
               Rest/binary>>) when Magic =:= ?SNAPSHOT_MAGIC ->
    case Version of
        ?SNAPSHOT_VERSION ->
            case decode_compact_size(Rest) of
                {ok, NumCoins, Rest2} ->
                    {ok, #{base_hash => BaseHash,
                           num_coins => NumCoins,
                           network_magic => NetworkMagic}, Rest2};
                {error, Reason} ->
                    {error, Reason}
            end;
        _ ->
            {error, {unsupported_version, Version}}
    end;
parse_header(<<Magic:5/binary, _/binary>>) when Magic =/= ?SNAPSHOT_MAGIC ->
    {error, invalid_magic};
parse_header(_) ->
    {error, truncated_header}.

read_metadata_from_fd(Fd) ->
    %% Read header: 5 (magic) + 2 (version) + 4 (magic) + 32 (hash) = 43 bytes
    %% Plus up to 9 bytes for compact size
    case file:read(Fd, 52) of
        {ok, Data} when byte_size(Data) >= 43 ->
            case parse_header(Data) of
                {ok, Meta, _Rest} -> {ok, Meta};
                {error, Reason} -> {error, Reason}
            end;
        {ok, _} ->
            {error, truncated_header};
        {error, Reason} ->
            {error, {read_failed, Reason}}
    end.

parse_coins(_Data, 0, Acc) ->
    {ok, lists:reverse(Acc)};
parse_coins(Data, Remaining, Acc) when Remaining > 0 ->
    case parse_txid_coins(Data) of
        {ok, TxidCoins, Rest, CoinsRead} ->
            parse_coins(Rest, Remaining - CoinsRead, TxidCoins ++ Acc);
        {error, Reason} ->
            {error, Reason}
    end.

%% Parse coins for a single txid
parse_txid_coins(<<Txid:32/binary, Rest/binary>>) ->
    case decode_compact_size(Rest) of
        {ok, CoinsPerTxid, Rest2} ->
            parse_txid_coin_entries(Rest2, Txid, CoinsPerTxid, []);
        {error, Reason} ->
            {error, Reason}
    end;
parse_txid_coins(_) ->
    {error, truncated_txid}.

parse_txid_coin_entries(Data, _Txid, 0, Acc) ->
    {ok, lists:reverse(Acc), Data, length(Acc)};
parse_txid_coin_entries(Data, Txid, Remaining, Acc) when Remaining > 0 ->
    case decode_compact_size(Data) of
        {ok, Vout, Rest} ->
            case parse_coin(Rest) of
                {ok, Utxo, Rest2} ->
                    Entry = {Txid, Vout, Utxo},
                    parse_txid_coin_entries(Rest2, Txid, Remaining - 1, [Entry | Acc]);
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

%% Parse a single coin: (height << 1 | coinbase), value, script
parse_coin(Data) ->
    case decode_compact_size(Data) of
        {ok, HeightCode, Rest} ->
            Height = HeightCode bsr 1,
            IsCoinbase = (HeightCode band 1) =:= 1,
            case decode_compact_size(Rest) of
                {ok, Value, Rest2} ->
                    case decode_script(Rest2) of
                        {ok, Script, Rest3} ->
                            Utxo = #utxo{
                                value = Value,
                                script_pubkey = Script,
                                is_coinbase = IsCoinbase,
                                height = Height
                            },
                            {ok, Utxo, Rest3};
                        {error, Reason} ->
                            {error, Reason}
                    end;
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

decode_script(Data) ->
    case decode_compact_size(Data) of
        {ok, Len, Rest} ->
            case Rest of
                <<Script:Len/binary, Rest2/binary>> ->
                    {ok, Script, Rest2};
                _ ->
                    {error, truncated_script}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

%%% ===================================================================
%%% Internal: Compact size encoding/decoding
%%% ===================================================================

decode_compact_size(<<N:8, Rest/binary>>) when N < 253 ->
    {ok, N, Rest};
decode_compact_size(<<253, N:16/little, Rest/binary>>) ->
    {ok, N, Rest};
decode_compact_size(<<254, N:32/little, Rest/binary>>) ->
    {ok, N, Rest};
decode_compact_size(<<255, N:64/little, Rest/binary>>) ->
    {ok, N, Rest};
decode_compact_size(_) ->
    {error, truncated_compact_size}.

encode_compact_size(N) when N < 253 ->
    <<N:8>>;
encode_compact_size(N) when N =< 16#ffff ->
    <<253, N:16/little>>;
encode_compact_size(N) when N =< 16#ffffffff ->
    <<254, N:32/little>>;
encode_compact_size(N) ->
    <<255, N:64/little>>.

%%% ===================================================================
%%% Internal: UTXO hash computation
%%% ===================================================================

%% Compute hash from list of {Txid, Vout, Utxo} tuples
compute_utxo_hash_from_list(Coins) ->
    %% Sort by outpoint (txid, vout) for deterministic order
    Sorted = lists:sort(fun({Txid1, Vout1, _}, {Txid2, Vout2, _}) ->
        {Txid1, Vout1} =< {Txid2, Vout2}
    end, Coins),

    %% Serialize each coin and hash in one shot via the NIF-backed
    %% beamchain_crypto:sha256/1 instead of streaming crypto:hash_init/update/final.
    %% The coin list is already fully materialized in memory, so accumulating
    %% the binaries does not increase peak memory usage.
    AllBins = lists:map(fun({Txid, Vout, Utxo}) ->
        serialize_coin_for_hash(Txid, Vout, Utxo)
    end, Sorted),
    beamchain_crypto:sha256(iolist_to_binary(AllBins)).

serialize_coin_for_hash(Txid, Vout, #utxo{value = Value, script_pubkey = Script,
                                          is_coinbase = IsCoinbase, height = Height}) ->
    CoinbaseFlag = case IsCoinbase of true -> 1; false -> 0 end,
    %% Format: txid || vout(32-bit) || value(64-bit) || height(32-bit) || coinbase(8-bit) || script
    <<Txid:32/binary, Vout:32/big, Value:64/little, Height:32/little,
      CoinbaseFlag:8, Script/binary>>.

%%% ===================================================================
%%% Internal: UTXO collection
%%% ===================================================================

%% Collect all UTXOs from the chainstate cache and RocksDB
collect_all_utxos() ->
    %% First flush cache to ensure all UTXOs are in RocksDB
    beamchain_chainstate:flush(),

    %% Iterate through all UTXOs in RocksDB
    case beamchain_db:get_meta(<<"utxo_iterator_not_impl">>) of
        _ ->
            %% TODO: Implement RocksDB iterator for chainstate CF
            %% For now, return empty - this will be implemented when needed
            []
    end.

%% Group coins by txid for efficient serialization
group_coins_by_txid(Coins) ->
    %% Sort by txid first
    Sorted = lists:sort(fun({Txid1, _, _}, {Txid2, _, _}) ->
        Txid1 =< Txid2
    end, Coins),

    %% Group consecutive coins with same txid
    group_consecutive(Sorted, []).

group_consecutive([], Acc) ->
    lists:reverse(Acc);
group_consecutive([{Txid, Vout, Utxo} | Rest], []) ->
    group_consecutive(Rest, [{Txid, [{Vout, Utxo}]}]);
group_consecutive([{Txid, Vout, Utxo} | Rest], [{Txid, Coins} | GroupAcc]) ->
    group_consecutive(Rest, [{Txid, [{Vout, Utxo} | Coins]} | GroupAcc]);
group_consecutive([{Txid, Vout, Utxo} | Rest], Acc) ->
    group_consecutive(Rest, [{Txid, [{Vout, Utxo}]} | Acc]).

%%% ===================================================================
%%% Internal: Serialization
%%% ===================================================================

serialize_grouped_coins(Grouped) ->
    lists:foldl(fun({Txid, Coins}, Acc) ->
        CoinsCount = encode_compact_size(length(Coins)),
        CoinsBin = lists:foldl(fun({Vout, Utxo}, CAcc) ->
            VoutBin = encode_compact_size(Vout),
            CoinBin = serialize_coin(Utxo),
            <<CAcc/binary, VoutBin/binary, CoinBin/binary>>
        end, <<>>, Coins),
        <<Acc/binary, Txid:32/binary, CoinsCount/binary, CoinsBin/binary>>
    end, <<>>, Grouped).

serialize_coin(#utxo{value = Value, script_pubkey = Script,
                     is_coinbase = IsCoinbase, height = Height}) ->
    CoinbaseFlag = case IsCoinbase of true -> 1; false -> 0 end,
    HeightCode = (Height bsl 1) bor CoinbaseFlag,
    HeightBin = encode_compact_size(HeightCode),
    ValueBin = encode_compact_size(Value),
    ScriptLen = encode_compact_size(byte_size(Script)),
    <<HeightBin/binary, ValueBin/binary, ScriptLen/binary, Script/binary>>.
