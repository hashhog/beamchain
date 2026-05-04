-module(beamchain_import).

%% Block import from stdin or file using the framed format:
%%   [4 bytes height LE] [4 bytes size LE] [size bytes raw block]
%%
%% Usage:
%%   beamchain import --network=testnet4 --datadir=/path/to/data
%%   cat blocks.bin | beamchain import --network=testnet4
%%   tools/block_reader.py ... | beamchain import --network=testnet4

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-export([run/1]).

%% Read buffer size for stdin (64 KiB)
-define(READ_BUF, 65536).

%% Progress report interval (blocks)
-define(PROGRESS_INTERVAL, 1000).

%%% ===================================================================
%%% Entry point (called from beamchain_cli)
%%% ===================================================================

-spec run(map()) -> no_return().
run(Opts) ->
    %% Open the source: file path from opts, or stdin
    Source = case maps:get(import_file, Opts, undefined) of
        undefined -> stdin;
        Path -> {file, Path}
    end,
    Fd = case Source of
        stdin ->
            %% Set stdin to binary mode
            io:setopts(standard_io, [binary]),
            standard_io;
        {file, FilePath} ->
            case file:open(FilePath, [read, binary, raw]) of
                {ok, F} -> F;
                {error, Reason} ->
                    io:format(standard_error, "Error opening ~s: ~p~n",
                              [FilePath, Reason]),
                    halt(1)
            end
    end,
    io:format("beamchain import: reading blocks from ~s~n",
              [case Source of stdin -> "stdin"; {file, P} -> P end]),
    StartTime = erlang:monotonic_time(second),
    import_loop(Fd, Source, 0, StartTime).

%%% ===================================================================
%%% Import loop
%%% ===================================================================

import_loop(Fd, Source, Count, StartTime) ->
    %% Read 8-byte frame header: [height:32/little, size:32/little]
    case read_exact(Fd, Source, 8) of
        eof ->
            finish(Count, StartTime);
        {error, Reason} ->
            io:format(standard_error, "Read error after ~B blocks: ~p~n",
                      [Count, Reason]),
            finish(Count, StartTime);
        {ok, <<Height:32/little, Size:32/little>>} ->
            case read_exact(Fd, Source, Size) of
                eof ->
                    io:format(standard_error,
                              "Unexpected EOF reading block ~B (need ~B bytes)~n",
                              [Height, Size]),
                    finish(Count, StartTime);
                {error, Reason2} ->
                    io:format(standard_error,
                              "Read error at block ~B: ~p~n",
                              [Height, Reason2]),
                    finish(Count, StartTime);
                {ok, BlockData} ->
                    %% Skip blocks at or below current tip
                    TipHeight = case beamchain_chainstate:get_tip_height() of
                        {ok, H} -> H;
                        not_found -> -1
                    end,
                    case Height =< TipHeight of
                        true ->
                            %% Already have this block, skip
                            import_loop(Fd, Source, Count, StartTime);
                        false ->
                            %% Deserialize the raw block
                            {Block, _Rest} = beamchain_serialize:decode_block(BlockData),
                            %% Context-free block check (PoW, merkle root, weight,
                            %% sigops, dup-txid scan) — mirrors Bitcoin Core CheckBlock()
                            %% called from ProcessNewBlock. Replicates the same gate
                            %% used by the submitblock and P2P paths (miner.erl:340,
                            %% block_sync.erl:985).
                            Params = beamchain_chain_params:params(
                                         beamchain_config:network()),
                            case beamchain_validation:check_block(Block, Params) of
                                {error, CheckErr} ->
                                    io:format(standard_error,
                                              "~nFailed check_block at height ~B: ~p~n",
                                              [Height, CheckErr]),
                                    finish(Count, StartTime);
                                ok ->
                                    %% Connect the block via chainstate
                                    case beamchain_chainstate:connect_block(Block) of
                                        ok ->
                                            NewCount = Count + 1,
                                            maybe_progress(NewCount, Height, StartTime),
                                            import_loop(Fd, Source, NewCount, StartTime);
                                        {error, Reason3} ->
                                            io:format(standard_error,
                                                      "~nFailed to connect block at height ~B: ~p~n",
                                                      [Height, Reason3]),
                                            finish(Count, StartTime)
                                    end
                            end
                    end
            end
    end.

%%% ===================================================================
%%% Progress reporting
%%% ===================================================================

maybe_progress(Count, Height, StartTime) ->
    case Count rem ?PROGRESS_INTERVAL of
        0 ->
            Elapsed = erlang:monotonic_time(second) - StartTime,
            Rate = case Elapsed of
                0 -> 0.0;
                _ -> Count / Elapsed
            end,
            io:format("\rImported ~B blocks (height ~B, ~.1f blk/s)",
                      [Count, Height, Rate]);
        _ ->
            ok
    end.

finish(Count, StartTime) ->
    Elapsed = max(1, erlang:monotonic_time(second) - StartTime),
    Rate = Count / Elapsed,
    io:format("~nImport complete: ~B blocks in ~Bs (~.1f blk/s)~n",
              [Count, Elapsed, Rate]),
    %% Flush UTXO cache to disk
    try beamchain_chainstate:flush()
    catch _:_ -> ok end,
    halt(0).

%%% ===================================================================
%%% Binary I/O helpers
%%% ===================================================================

%% Read exactly N bytes from the source.
%% Returns {ok, Binary} | eof | {error, Reason}
read_exact(Fd, stdin, N) ->
    read_exact_stdin(Fd, N, <<>>);
read_exact(Fd, {file, _}, N) ->
    case file:read(Fd, N) of
        {ok, Data} when byte_size(Data) =:= N -> {ok, Data};
        {ok, _Partial} -> eof;
        eof -> eof;
        {error, _} = Err -> Err
    end.

read_exact_stdin(_Fd, 0, Acc) ->
    {ok, Acc};
read_exact_stdin(Fd, Remaining, Acc) ->
    case io:get_chars(Fd, '', Remaining) of
        eof -> eof;
        {error, _} = Err -> Err;
        Data when is_binary(Data) ->
            Got = byte_size(Data),
            case Got of
                Remaining -> {ok, <<Acc/binary, Data/binary>>};
                _ when Got < Remaining ->
                    read_exact_stdin(Fd, Remaining - Got,
                                     <<Acc/binary, Data/binary>>);
                _ -> {ok, <<Acc/binary, Data/binary>>}
            end;
        Data when is_list(Data) ->
            Bin = list_to_binary(Data),
            Got = byte_size(Bin),
            case Got of
                Remaining -> {ok, <<Acc/binary, Bin/binary>>};
                _ when Got < Remaining ->
                    read_exact_stdin(Fd, Remaining - Got,
                                     <<Acc/binary, Bin/binary>>);
                _ -> {ok, <<Acc/binary, Bin/binary>>}
            end
    end.
