-module(beamchain_hdog_import).

%% AssumeUTXO snapshot import from HDOG binary format.
%%
%% HDOG format:
%%   Header (52 bytes):
%%     Magic:        4 bytes    "HDOG"
%%     Version:      uint32 LE  (1)
%%     Block Hash:   32 bytes   (little-endian)
%%     Block Height: uint32 LE
%%     UTXO Count:   uint64 LE
%%
%%   Per UTXO (repeated UTXO_COUNT times):
%%     TxID:         32 bytes   (little-endian)
%%     Vout:         uint32 LE
%%     Amount:       int64 LE   (satoshis)
%%     Height+CB:    uint32 LE  (height in bits [31:1], coinbase flag in bit [0])
%%     Script Len:   uint16 LE
%%     Script:       N bytes    (raw scriptPubKey)
%%
%% Streams the file and writes UTXOs directly to RocksDB in batches,
%% bypassing the ETS UTXO cache entirely.

-include("beamchain.hrl").

-export([run/1]).

%% Batch size: flush every 100K UTXOs
-define(BATCH_SIZE, 100000).

%% Progress report interval: every 1M UTXOs
-define(PROGRESS_INTERVAL, 1000000).

%% HDOG magic bytes
-define(HDOG_MAGIC, <<"HDOG">>).

%% Read buffer size for streaming (256 KB)
-define(READ_BUF, 262144).

%%% ===================================================================
%%% Entry point (called from beamchain_cli)
%%% ===================================================================

-spec run(map()) -> no_return().
run(Opts) ->
    Path = maps:get(import_utxo, Opts),
    log("beamchain UTXO import: reading HDOG snapshot from ~s~n", [Path]),

    %% Open the file
    case file:open(Path, [read, binary, raw, {read_ahead, ?READ_BUF}]) of
        {ok, Fd} ->
            try
                do_import(Fd)
            after
                file:close(Fd)
            end;
        {error, Reason} ->
            log("Error opening ~s: ~p~n", [Path, Reason]),
            halt(1)
    end.

%%% ===================================================================
%%% Import implementation
%%% ===================================================================

do_import(Fd) ->
    %% 1. Read and verify header (52 bytes)
    case file:read(Fd, 52) of
        {ok, <<Magic:4/binary, Version:32/little,
               BlockHash:32/binary, BlockHeight:32/little,
               UtxoCount:64/little>>} when Magic =:= ?HDOG_MAGIC ->
            log("  Version:    ~B~n", [Version]),
            log("  Block hash: ~s~n", [hex(BlockHash)]),
            log("  Height:     ~B~n", [BlockHeight]),
            log("  UTXO count: ~B~n~n", [UtxoCount]),

            case Version of
                1 -> ok;
                _ ->
                    log("Unsupported HDOG version: ~B~n", [Version]),
                    halt(1)
            end,

            %% 2. Clear existing UTXO data from the chainstate column family.
            %%    We do this by deleting the chainstate range via a batch of
            %%    delete_range or by iterating. For simplicity, we'll just
            %%    proceed — a fresh datadir is expected for snapshot import.
            log("Importing UTXOs into RocksDB...~n", []),

            StartTime = erlang:monotonic_time(second),

            %% 3. Stream UTXOs and batch-write to RocksDB
            {ok, Imported} = import_utxos(Fd, UtxoCount, 0, [], 0, StartTime),

            Elapsed = max(1, erlang:monotonic_time(second) - StartTime),
            Rate = Imported / Elapsed,
            log("~nImported ~B UTXOs in ~Bs (~B utxo/s)~n",
                      [Imported, Elapsed, round(Rate)]),

            %% 4. Set chain tip and header tip
            set_tips(BlockHash, BlockHeight),

            log("Chain tip set to height ~B~n", [BlockHeight]),
            log("Import complete.~n", []),
            halt(0);

        {ok, Data} when byte_size(Data) =:= 52 ->
            <<BadMagic:4/binary, _/binary>> = Data,
            log( "Invalid HDOG magic: ~p (expected \"HDOG\")~n",
                      [BadMagic]),
            halt(1);
        {ok, _} ->
            log( "Truncated HDOG header~n", []),
            halt(1);
        eof ->
            log( "Empty file~n", []),
            halt(1);
        {error, Reason} ->
            log( "Error reading header: ~p~n", [Reason]),
            halt(1)
    end.

%%% ===================================================================
%%% Streaming UTXO import
%%% ===================================================================

%% import_utxos(Fd, Remaining, BatchCount, BatchOps, TotalImported, StartTime)
import_utxos(_Fd, 0, _BatchCount, BatchOps, Total, _StartTime) ->
    %% Flush any remaining batch
    flush_batch(BatchOps),
    {ok, Total};

import_utxos(Fd, Remaining, BatchCount, BatchOps, Total, StartTime) ->
    %% Read one UTXO: 32 (txid) + 4 (vout) + 8 (amount) + 4 (height+cb) + 2 (script_len) = 50 bytes fixed
    case file:read(Fd, 50) of
        {ok, <<Txid:32/binary, Vout:32/little,
               Amount:64/little-signed, HeightCB:32/little,
               ScriptLen:16/little>>} ->
            %% Read the script
            Script = case ScriptLen of
                0 -> <<>>;
                _ ->
                    case file:read(Fd, ScriptLen) of
                        {ok, S} when byte_size(S) =:= ScriptLen -> S;
                        {ok, _} ->
                            log(
                                      "~nTruncated script at UTXO ~B~n", [Total]),
                            halt(1);
                        eof ->
                            log(
                                      "~nEOF reading script at UTXO ~B~n", [Total]),
                            halt(1);
                        {error, Reason} ->
                            log(
                                      "~nError reading script at UTXO ~B: ~p~n",
                                      [Total, Reason]),
                            halt(1)
                    end
            end,

            %% Decode height and coinbase flag from HeightCB
            Height = HeightCB bsr 1,
            CoinbaseFlag = HeightCB band 1,

            %% Encode in beamchain's RocksDB format:
            %%   Key:   <<Txid:32/binary, Vout:32/big>>
            %%   Value: <<Value:64/little, Height:32/little, CoinbaseFlag:8, Script/binary>>
            Key = <<Txid:32/binary, Vout:32/big>>,
            Value = <<Amount:64/little, Height:32/little, CoinbaseFlag:8, Script/binary>>,
            Op = {put, chainstate, Key, Value},

            NewBatchOps = [Op | BatchOps],
            NewBatchCount = BatchCount + 1,
            NewTotal = Total + 1,

            %% Progress report every 1M UTXOs
            case NewTotal rem ?PROGRESS_INTERVAL of
                0 ->
                    Elapsed = max(1, erlang:monotonic_time(second) - StartTime),
                    Rate = round(NewTotal / Elapsed),
                    TotalExpected = NewTotal + Remaining - 1,
                    Pct = NewTotal / TotalExpected * 100,
                    log("  ~.1f%  ~B / ~B UTXOs  (~B utxo/s)~n",
                        [float(Pct), NewTotal, TotalExpected, Rate]);
                _ -> ok
            end,

            %% Flush batch when it reaches BATCH_SIZE
            case NewBatchCount >= ?BATCH_SIZE of
                true ->
                    flush_batch(NewBatchOps),
                    import_utxos(Fd, Remaining - 1, 0, [], NewTotal, StartTime);
                false ->
                    import_utxos(Fd, Remaining - 1, NewBatchCount, NewBatchOps,
                                 NewTotal, StartTime)
            end;

        {ok, _} ->
            log( "~nTruncated UTXO at position ~B~n", [Total]),
            flush_batch(BatchOps),
            {ok, Total};
        eof ->
            log( "~nUnexpected EOF at UTXO ~B (expected ~B more)~n",
                      [Total, Remaining]),
            flush_batch(BatchOps),
            {ok, Total};
        {error, Reason} ->
            log( "~nRead error at UTXO ~B: ~p~n", [Total, Reason]),
            flush_batch(BatchOps),
            {ok, Total}
    end.

%%% ===================================================================
%%% Batch flush
%%% ===================================================================

flush_batch([]) -> ok;
flush_batch(Ops) ->
    case beamchain_db:write_batch(Ops) of
        ok -> ok;
        {error, Reason} ->
            log( "~nRocksDB write_batch error: ~p~n", [Reason]),
            halt(1)
    end.

%%% ===================================================================
%%% Set chain tip and header tip after import
%%% ===================================================================

set_tips(BlockHash, BlockHeight) ->
    TipValue = <<BlockHash:32/binary, BlockHeight:64/big>>,

    %% Try to fetch the block header from a local Bitcoin Core RPC
    %% so we can create a proper block index entry.
    HeaderOps = case fetch_block_header(BlockHash) of
        {ok, HeaderBin, Chainwork} ->
            %% Store block index entry: height -> entry
            HeightKey = <<BlockHeight:64/big>>,
            %% Block index status: VALID_SCRIPTS (5) | HAVE_DATA (8) = 13
            Status = 5 bor 8,
            CWLen = byte_size(Chainwork),
            IndexValue = <<BlockHash:32/binary, HeaderBin:80/binary,
                           CWLen:16/big, Chainwork:CWLen/binary,
                           Status:32/little>>,
            %% Reverse index: hash -> height
            RevKey = <<"blkidx:", BlockHash/binary>>,
            log("  Block index entry created (chainwork ~B bytes)~n", [CWLen]),
            [
                {put, block_index, HeightKey, IndexValue},
                {put, meta, RevKey, HeightKey}
            ];
        {error, _Reason} ->
            log("Warning: could not fetch block header from Bitcoin Core, "
                "skipping block index~n", []),
            []
    end,

    %% NOTE: We do NOT set header_tip here. The header sync must start
    %% from genesis and sync all headers so the node has the full header
    %% chain needed for difficulty calculations and checkpoint validation.
    %% The chain_tip (UTXO tip) is set to the snapshot height so the
    %% chainstate knows where it is.
    Ops = HeaderOps ++ [
        {put, meta, <<"chain_tip">>, TipValue},
        {put, meta, <<"utxo_flush_height">>, <<BlockHeight:64/big>>}
    ],
    case beamchain_db:write_batch(Ops) of
        ok -> ok;
        {error, Reason} ->
            log("Error setting chain tip: ~p~n", [Reason]),
            halt(1)
    end.

%%% ===================================================================
%%% Fetch block header from local Bitcoin Core RPC
%%% ===================================================================

fetch_block_header(BlockHash) ->
    %% Try to read the cookie from the Bitcoin Core data directory
    CookiePaths = [
        "/data/nvme1/hashhog-mainnet/bitcoin-core/.cookie",
        "/home/work/.bitcoin/.cookie"
    ],
    case read_first_cookie(CookiePaths) of
        {ok, Cookie} ->
            %% Block hash in HDOG is internal byte order (little-endian),
            %% Bitcoin Core RPC expects display order (reversed).
            HashHex = hex(reverse_bytes(BlockHash)),
            %% Fetch raw header (hex)
            case rpc_call(Cookie, <<"getblockheader">>,
                          [list_to_binary(HashHex), false]) of
                {ok, HeaderHex} when is_binary(HeaderHex) ->
                    HeaderBin = hex_to_bin(binary_to_list(HeaderHex)),
                    %% Fetch JSON header for chainwork
                    case rpc_call(Cookie, <<"getblockheader">>,
                                  [list_to_binary(HashHex), true]) of
                        {ok, Info} when is_map(Info) ->
                            CWHex = binary_to_list(
                                maps:get(<<"chainwork">>, Info, <<"00">>)),
                            CW = hex_to_bin(CWHex),
                            {ok, HeaderBin, CW};
                        _ ->
                            %% Use empty chainwork
                            {ok, HeaderBin, <<0:256>>}
                    end;
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

read_first_cookie([]) ->
    {error, no_cookie_found};
read_first_cookie([Path | Rest]) ->
    case file:read_file(Path) of
        {ok, Data} -> {ok, string:trim(binary_to_list(Data))};
        {error, _} -> read_first_cookie(Rest)
    end.

rpc_call(Cookie, Method, Params) ->
    %% Ensure inets is started
    inets:start(),
    ssl:start(),
    Auth = base64:encode_to_string(Cookie),
    Url = "http://127.0.0.1:8332/",
    Body = jsx:encode(#{
        <<"jsonrpc">> => <<"1.0">>,
        <<"id">> => <<"hdog-import">>,
        <<"method">> => Method,
        <<"params">> => Params
    }),
    Headers = [{"Content-Type", "application/json"},
               {"Authorization", "Basic " ++ Auth}],
    case httpc:request(post,
                       {Url, Headers, "application/json", Body},
                       [{timeout, 10000}, {connect_timeout, 5000}],
                       [{body_format, binary}]) of
        {ok, {{_, 200, _}, _, RespBody}} ->
            Map = jsx:decode(RespBody, [return_maps]),
            case maps:get(<<"error">>, Map, null) of
                null -> {ok, maps:get(<<"result">>, Map, null)};
                Err -> {error, Err}
            end;
        {ok, {{_, Code, _}, _, _}} ->
            {error, {http_error, Code}};
        {error, Reason} ->
            {error, Reason}
    end.

hex_to_bin(HexStr) ->
    hex_to_bin(HexStr, <<>>).
hex_to_bin([], Acc) ->
    Acc;
hex_to_bin([H1, H2 | Rest], Acc) ->
    Byte = list_to_integer([H1, H2], 16),
    hex_to_bin(Rest, <<Acc/binary, Byte:8>>).

%%% ===================================================================
%%% Hex encoding helper
%%% ===================================================================

hex(Bin) ->
    lists:flatten([io_lib:format("~2.16.0b", [B]) || <<B>> <= Bin]).

reverse_bytes(Bin) ->
    list_to_binary(lists:reverse(binary_to_list(Bin))).

%%% ===================================================================
%%% Logging helper — writes directly to a file to avoid io device issues
%%% in rebar3 shell.
%%% ===================================================================

log(Fmt, Args) ->
    Msg = lists:flatten(io_lib:format(Fmt, Args)),
    file:write(get_log_fd(), list_to_binary(Msg)).

get_log_fd() ->
    case get(hdog_log_fd) of
        undefined ->
            %% Open /dev/stderr for direct output
            {ok, Fd} = file:open("/dev/stderr", [write, binary, raw]),
            put(hdog_log_fd, Fd),
            Fd;
        Fd -> Fd
    end.
