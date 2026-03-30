#!/usr/bin/env escript
%%% Reset the chainstate (UTXO set) and chain_tip to force
%%% a full block re-validation from genesis while keeping
%%% header data and block data intact.

-mode(compile).

main([DataDir]) ->
    DbPath = filename:join([DataDir, "chaindata"]),
    io:format("Opening RocksDB at ~s~n", [DbPath]),

    %% Load rocksdb NIF
    code:add_pathz("_build/default/lib/rocksdb/ebin"),
    code:add_pathz("_build/prod/rel/beamchain/lib/rocksdb-1.8.0/ebin"),

    CFDescriptors = [
        {"default", []},
        {"blocks", []},
        {"block_index", []},
        {"chainstate", []},
        {"tx_index", []},
        {"meta", []},
        {"undo", []}
    ],

    case rocksdb:open(DbPath, [{create_if_missing, false}], CFDescriptors) of
        {ok, Db, [_DefaultCF, _BlocksCF, _BlockIdxCF,
                   ChainstateCF, _TxIdxCF, MetaCF, _UndoCF]} ->

            %% Delete chain_tip from meta
            io:format("Deleting chain_tip from meta...~n"),
            ok = rocksdb:delete(Db, MetaCF, <<"chain_tip">>, []),

            %% Delete utxo_flush_height from meta
            io:format("Deleting utxo_flush_height from meta...~n"),
            rocksdb:delete(Db, MetaCF, <<"utxo_flush_height">>, []),

            %% Wipe the chainstate (UTXO) column family by iterating and deleting
            io:format("Wiping chainstate (UTXO) column family...~n"),
            {ok, Iter} = rocksdb:iterator(Db, ChainstateCF, []),
            Count = wipe_cf(Db, ChainstateCF, Iter, rocksdb:iterator_move(Iter, first), 0),
            rocksdb:iterator_close(Iter),
            io:format("Deleted ~B UTXO entries~n", [Count]),

            rocksdb:close(Db),
            io:format("Done. Chainstate reset. Node will re-validate all blocks.~n");
        {error, Reason} ->
            io:format("Failed to open DB: ~p~n", [Reason]),
            halt(1)
    end;

main(_) ->
    io:format("Usage: reset_chainstate.escript <datadir>~n"),
    io:format("  e.g.: reset_chainstate.escript testnet4-data/beamchain/testnet4~n"),
    halt(1).

wipe_cf(_Db, _CF, _Iter, {error, invalid_iterator}, Count) ->
    Count;
wipe_cf(Db, CF, Iter, {ok, Key, _Value}, Count) ->
    ok = rocksdb:delete(Db, CF, Key, []),
    wipe_cf(Db, CF, Iter, rocksdb:iterator_move(Iter, next), Count + 1).
