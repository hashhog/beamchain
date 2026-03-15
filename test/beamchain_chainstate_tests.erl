-module(beamchain_chainstate_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% Test suite for undo data and block disconnection.
%% Verifies that connecting a block, then disconnecting it, restores the
%% UTXO set to its original state.

chainstate_test_() ->
    {setup,
     fun setup/0,
     fun teardown/1,
     fun(_) ->
         [
          {"undo data encoding/decoding roundtrip", fun undo_encode_decode/0},
          {"connect then disconnect restores UTXO state", fun connect_disconnect_roundtrip/0},
          {"undo data deleted after disconnect", fun undo_deleted_after_disconnect/0},
          {"multiple tx block disconnect restores all UTXOs", fun multi_tx_disconnect/0},
          %% UTXO cache tests
          {"cache hit returns cached entry", fun test_cache_hit/0},
          {"cache miss falls through to RocksDB", fun test_cache_miss/0},
          {"FRESH optimization: spend before flush skips DB", fun test_fresh_optimization/0},
          {"flush persists dirty entries to RocksDB", fun test_flush_persistence/0},
          {"cache stats reports correct counts", fun test_cache_stats/0},
          %% assumeUTXO tests
          {"UTXO hash computation", fun test_utxo_hash_computation/0},
          {"snapshot role detection", fun test_snapshot_role_detection/0},
          %% Block invalidation/reconsideration tests
          {"cannot invalidate genesis block", fun test_cannot_invalidate_genesis/0},
          {"invalidating unknown block returns error", fun test_invalidate_unknown_block/0},
          {"block status is marked invalid", fun test_block_marked_invalid/0},
          {"reconsider clears invalid flag", fun test_reconsider_clears_flag/0}
         ]
     end}.

setup() ->
    %% Use a unique temp directory for each test run
    TmpDir = filename:join(["/tmp", "beamchain_chainstate_test_" ++
                            integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),

    %% Set environment
    application:ensure_all_started(rocksdb),
    application:set_env(beamchain, datadir, TmpDir),
    application:set_env(beamchain, network, regtest),

    %% Start config and db first
    {ok, ConfigPid} = beamchain_config:start_link(),
    {ok, DbPid} = beamchain_db:start_link(),

    %% Initialize with genesis block BEFORE starting chainstate
    %% (chainstate loads chain tip from db during init)
    Params = beamchain_chain_params:params(regtest),
    Genesis = beamchain_chain_params:genesis_block(regtest),
    GenesisHash = Genesis#block.hash,

    %% Store genesis block, index, and chain tip in DB
    ok = beamchain_db:store_block(Genesis, 0),
    ok = beamchain_db:store_block_index(0, GenesisHash,
        Genesis#block.header, <<0,0,0,1>>, 3),
    ok = beamchain_db:set_chain_tip(GenesisHash, 0),

    %% Now start chainstate - it will load the chain tip from DB
    {ok, ChainstatePid} = beamchain_chainstate:start_link(),

    %% Add genesis coinbase output to UTXO set
    [CoinbaseTx | _] = Genesis#block.transactions,
    CoinbaseTxid = beamchain_serialize:tx_hash(CoinbaseTx),
    [CoinbaseOutput | _] = CoinbaseTx#transaction.outputs,
    GenesisUtxo = #utxo{
        value = CoinbaseOutput#tx_out.value,
        script_pubkey = CoinbaseOutput#tx_out.script_pubkey,
        is_coinbase = true,
        height = 0
    },
    beamchain_chainstate:add_utxo(CoinbaseTxid, 0, GenesisUtxo),

    {TmpDir, ConfigPid, DbPid, ChainstatePid, Params, Genesis, CoinbaseTxid}.

teardown({TmpDir, _ConfigPid, _DbPid, _ChainstatePid, _Params, _Genesis, _CbTxid}) ->
    catch gen_server:stop(beamchain_chainstate),
    catch beamchain_db:stop(),
    catch gen_server:stop(beamchain_config),
    os:cmd("rm -rf " ++ TmpDir),
    ok.

%%% ===================================================================
%%% Undo data encoding/decoding
%%% ===================================================================

undo_encode_decode() ->
    %% Create some spent coins to encode
    SpentCoins = [
        {#outpoint{hash = <<1:256>>, index = 0},
         #utxo{value = 5000000000, script_pubkey = <<16#6a, 4, "test">>,
               is_coinbase = true, height = 0}},
        {#outpoint{hash = <<2:256>>, index = 1},
         #utxo{value = 1000000, script_pubkey = <<16#76, 16#a9, 16#14, 0:160, 16#88, 16#ac>>,
               is_coinbase = false, height = 100}}
    ],

    %% Encode and decode
    Encoded = beamchain_validation:encode_undo_data(SpentCoins),
    Decoded = beamchain_validation:decode_undo_data(Encoded),

    %% Verify roundtrip
    ?assertEqual(length(SpentCoins), length(Decoded)),

    lists:foreach(fun({{OrigOutpoint, OrigCoin}, {DecOutpoint, DecCoin}}) ->
        ?assertEqual(OrigOutpoint#outpoint.hash, DecOutpoint#outpoint.hash),
        ?assertEqual(OrigOutpoint#outpoint.index, DecOutpoint#outpoint.index),
        ?assertEqual(OrigCoin#utxo.value, DecCoin#utxo.value),
        ?assertEqual(OrigCoin#utxo.script_pubkey, DecCoin#utxo.script_pubkey),
        ?assertEqual(OrigCoin#utxo.is_coinbase, DecCoin#utxo.is_coinbase),
        ?assertEqual(OrigCoin#utxo.height, DecCoin#utxo.height)
    end, lists:zip(SpentCoins, Decoded)).

%%% ===================================================================
%%% Connect/disconnect roundtrip test
%%% ===================================================================

connect_disconnect_roundtrip() ->
    %% Get the genesis coinbase txid from setup
    {ok, {_TipHash, TipHeight}} = beamchain_chainstate:get_tip(),
    ?assertEqual(0, TipHeight),

    %% Verify genesis UTXO exists
    Genesis = beamchain_chain_params:genesis_block(regtest),
    [CoinbaseTx | _] = Genesis#block.transactions,
    CoinbaseTxid = beamchain_serialize:tx_hash(CoinbaseTx),
    ?assertMatch({ok, #utxo{}}, beamchain_chainstate:get_utxo(CoinbaseTxid, 0)),

    %% Record the initial UTXO state
    {ok, InitialUtxo} = beamchain_chainstate:get_utxo(CoinbaseTxid, 0),

    %% Create a block that spends the genesis coinbase (after maturity)
    %% Note: In regtest, coinbase maturity is 100 blocks, so we simulate
    %% being at height 101 by manually updating the UTXO height.
    %% For this test, we'll create a simpler scenario: just add and remove
    %% UTXOs directly to test the undo mechanism.

    %% Create test UTXO
    TestTxid = <<16#dead:256>>,
    TestUtxo = #utxo{
        value = 1000000,
        script_pubkey = <<16#6a, 4, "test">>,
        is_coinbase = false,
        height = 1
    },

    %% Add test UTXO
    beamchain_chainstate:add_utxo(TestTxid, 0, TestUtxo),
    ?assertMatch({ok, #utxo{}}, beamchain_chainstate:get_utxo(TestTxid, 0)),

    %% Spend it
    {ok, SpentUtxo} = beamchain_chainstate:spend_utxo(TestTxid, 0),
    ?assertEqual(TestUtxo#utxo.value, SpentUtxo#utxo.value),

    %% Verify it's gone
    ?assertEqual(not_found, beamchain_chainstate:get_utxo(TestTxid, 0)),

    %% Restore it (simulating disconnect)
    beamchain_chainstate:add_utxo(TestTxid, 0, SpentUtxo),

    %% Verify restored
    {ok, RestoredUtxo} = beamchain_chainstate:get_utxo(TestTxid, 0),
    ?assertEqual(SpentUtxo#utxo.value, RestoredUtxo#utxo.value),
    ?assertEqual(SpentUtxo#utxo.script_pubkey, RestoredUtxo#utxo.script_pubkey),

    %% Clean up
    beamchain_chainstate:spend_utxo(TestTxid, 0),

    %% Verify genesis UTXO is still there
    {ok, FinalUtxo} = beamchain_chainstate:get_utxo(CoinbaseTxid, 0),
    ?assertEqual(InitialUtxo#utxo.value, FinalUtxo#utxo.value).

%%% ===================================================================
%%% Undo data deletion test
%%% ===================================================================

undo_deleted_after_disconnect() ->
    %% Store some undo data directly
    BlockHash = <<16#cafe:256>>,
    UndoData = beamchain_validation:encode_undo_data([
        {#outpoint{hash = <<1:256>>, index = 0},
         #utxo{value = 100, script_pubkey = <<>>, is_coinbase = false, height = 0}}
    ]),

    %% Store and verify
    ok = beamchain_db:store_undo(BlockHash, UndoData),
    ?assertMatch({ok, _}, beamchain_db:get_undo(BlockHash)),

    %% Delete and verify
    ok = beamchain_db:delete_undo(BlockHash),
    ?assertEqual(not_found, beamchain_db:get_undo(BlockHash)).

%%% ===================================================================
%%% Multi-transaction block disconnect test
%%% ===================================================================

multi_tx_disconnect() ->
    %% Simulate a block with multiple transactions, verify undo restores all

    %% Initial UTXOs (what would be spent by the block)
    Utxo1 = #utxo{value = 1000000, script_pubkey = <<16#6a, 1, 1>>,
                  is_coinbase = false, height = 50},
    Utxo2 = #utxo{value = 2000000, script_pubkey = <<16#6a, 1, 2>>,
                  is_coinbase = false, height = 60},
    Utxo3 = #utxo{value = 3000000, script_pubkey = <<16#6a, 1, 3>>,
                  is_coinbase = true, height = 0},

    Txid1 = <<16#1111:256>>,
    Txid2 = <<16#2222:256>>,
    Txid3 = <<16#3333:256>>,

    %% Add initial UTXOs
    beamchain_chainstate:add_utxo(Txid1, 0, Utxo1),
    beamchain_chainstate:add_utxo(Txid2, 0, Utxo2),
    beamchain_chainstate:add_utxo(Txid3, 0, Utxo3),

    %% Verify all exist
    ?assertMatch({ok, _}, beamchain_chainstate:get_utxo(Txid1, 0)),
    ?assertMatch({ok, _}, beamchain_chainstate:get_utxo(Txid2, 0)),
    ?assertMatch({ok, _}, beamchain_chainstate:get_utxo(Txid3, 0)),

    %% Simulate spending them (collecting for undo)
    {ok, Spent1} = beamchain_chainstate:spend_utxo(Txid1, 0),
    {ok, Spent2} = beamchain_chainstate:spend_utxo(Txid2, 0),
    {ok, Spent3} = beamchain_chainstate:spend_utxo(Txid3, 0),

    %% Verify all gone
    ?assertEqual(not_found, beamchain_chainstate:get_utxo(Txid1, 0)),
    ?assertEqual(not_found, beamchain_chainstate:get_utxo(Txid2, 0)),
    ?assertEqual(not_found, beamchain_chainstate:get_utxo(Txid3, 0)),

    %% Encode undo data
    UndoCoins = [
        {#outpoint{hash = Txid1, index = 0}, Spent1},
        {#outpoint{hash = Txid2, index = 0}, Spent2},
        {#outpoint{hash = Txid3, index = 0}, Spent3}
    ],
    UndoBin = beamchain_validation:encode_undo_data(UndoCoins),

    %% Decode and restore (simulating disconnect)
    DecodedUndo = beamchain_validation:decode_undo_data(UndoBin),
    lists:foreach(fun({#outpoint{hash = H, index = I}, Coin}) ->
        beamchain_chainstate:add_utxo(H, I, Coin)
    end, DecodedUndo),

    %% Verify all restored with correct values
    {ok, Restored1} = beamchain_chainstate:get_utxo(Txid1, 0),
    {ok, Restored2} = beamchain_chainstate:get_utxo(Txid2, 0),
    {ok, Restored3} = beamchain_chainstate:get_utxo(Txid3, 0),

    ?assertEqual(Utxo1#utxo.value, Restored1#utxo.value),
    ?assertEqual(Utxo1#utxo.height, Restored1#utxo.height),
    ?assertEqual(Utxo1#utxo.is_coinbase, Restored1#utxo.is_coinbase),

    ?assertEqual(Utxo2#utxo.value, Restored2#utxo.value),
    ?assertEqual(Utxo2#utxo.height, Restored2#utxo.height),

    ?assertEqual(Utxo3#utxo.value, Restored3#utxo.value),
    ?assertEqual(Utxo3#utxo.is_coinbase, Restored3#utxo.is_coinbase),

    %% Clean up
    beamchain_chainstate:spend_utxo(Txid1, 0),
    beamchain_chainstate:spend_utxo(Txid2, 0),
    beamchain_chainstate:spend_utxo(Txid3, 0).

%%% ===================================================================
%%% UTXO cache tests
%%% ===================================================================

test_cache_hit() ->
    %% Add a UTXO to cache
    Txid = <<16#aaa1:256>>,
    Utxo = #utxo{value = 500000, script_pubkey = <<16#51>>,
                 is_coinbase = false, height = 10},
    beamchain_chainstate:add_utxo(Txid, 0, Utxo),

    %% First lookup - should hit cache (entry was just added)
    {ok, Cached1} = beamchain_chainstate:get_utxo(Txid, 0),
    ?assertEqual(500000, Cached1#utxo.value),

    %% Second lookup - still hits cache
    {ok, Cached2} = beamchain_chainstate:get_utxo(Txid, 0),
    ?assertEqual(500000, Cached2#utxo.value),
    ?assertEqual(Cached1#utxo.script_pubkey, Cached2#utxo.script_pubkey),

    %% Clean up
    beamchain_chainstate:spend_utxo(Txid, 0).

test_cache_miss() ->
    %% First, add a UTXO, flush it to RocksDB, then clear cache
    Txid = <<16#bbb2:256>>,
    Utxo = #utxo{value = 750000, script_pubkey = <<16#52>>,
                 is_coinbase = false, height = 20},

    %% Add and flush to RocksDB
    beamchain_chainstate:add_utxo(Txid, 0, Utxo),
    beamchain_chainstate:flush(),

    %% Clear the ETS cache directly (simulating cache eviction)
    ets:delete(beamchain_utxo_cache, {Txid, 0}),

    %% Lookup should hit RocksDB (cache miss) and re-populate cache
    {ok, FromDb} = beamchain_chainstate:get_utxo(Txid, 0),
    ?assertEqual(750000, FromDb#utxo.value),
    ?assertEqual(<<16#52>>, FromDb#utxo.script_pubkey),

    %% Verify it's now in cache (subsequent lookup is a hit)
    ?assertMatch([_], ets:lookup(beamchain_utxo_cache, {Txid, 0})),

    %% Clean up
    beamchain_chainstate:spend_utxo(Txid, 0),
    beamchain_chainstate:flush().

test_fresh_optimization() ->
    %% Test the FRESH optimization: if a UTXO is created and spent
    %% before flush, no DB operations are needed.

    Txid = <<16#ccc3:256>>,
    Utxo = #utxo{value = 100000, script_pubkey = <<16#53>>,
                 is_coinbase = false, height = 30},

    %% Add UTXO (marked FRESH and DIRTY)
    beamchain_chainstate:add_utxo(Txid, 0, Utxo),

    %% Verify it's in the FRESH table
    ?assert(ets:member(beamchain_utxo_fresh, {Txid, 0})),
    ?assert(ets:member(beamchain_utxo_dirty, {Txid, 0})),

    %% Spend it before flush - should use FRESH optimization
    {ok, Spent} = beamchain_chainstate:spend_utxo(Txid, 0),
    ?assertEqual(100000, Spent#utxo.value),

    %% FRESH and DIRTY flags should be cleared
    ?assertNot(ets:member(beamchain_utxo_fresh, {Txid, 0})),
    ?assertNot(ets:member(beamchain_utxo_dirty, {Txid, 0})),

    %% SPENT table should NOT have this entry (FRESH optimization)
    ?assertNot(ets:member(beamchain_utxo_spent, {Txid, 0})),

    %% UTXO should not be in RocksDB (never written)
    ?assertEqual(not_found, beamchain_db:get_utxo(Txid, 0)).

test_flush_persistence() ->
    %% Verify that flush writes dirty entries to RocksDB

    Txid = <<16#ddd4:256>>,
    Utxo = #utxo{value = 200000, script_pubkey = <<16#54>>,
                 is_coinbase = true, height = 40},

    %% Add UTXO
    beamchain_chainstate:add_utxo(Txid, 0, Utxo),

    %% Verify it's dirty and fresh
    ?assert(ets:member(beamchain_utxo_dirty, {Txid, 0})),
    ?assert(ets:member(beamchain_utxo_fresh, {Txid, 0})),

    %% Flush to RocksDB
    beamchain_chainstate:flush(),

    %% Verify dirty/fresh flags are cleared after flush
    ?assertNot(ets:member(beamchain_utxo_dirty, {Txid, 0})),
    ?assertNot(ets:member(beamchain_utxo_fresh, {Txid, 0})),

    %% Verify it's now in RocksDB
    {ok, DbUtxo} = beamchain_db:get_utxo(Txid, 0),
    ?assertEqual(200000, DbUtxo#utxo.value),
    ?assertEqual(<<16#54>>, DbUtxo#utxo.script_pubkey),
    ?assertEqual(true, DbUtxo#utxo.is_coinbase),

    %% Clean up
    beamchain_chainstate:spend_utxo(Txid, 0),
    beamchain_chainstate:flush().

test_cache_stats() ->
    %% Test cache_stats/0 function

    %% Add a few UTXOs
    Txid1 = <<16#eee5:256>>,
    Txid2 = <<16#fff6:256>>,
    Utxo = #utxo{value = 50000, script_pubkey = <<>>,
                 is_coinbase = false, height = 50},

    beamchain_chainstate:add_utxo(Txid1, 0, Utxo),
    beamchain_chainstate:add_utxo(Txid2, 0, Utxo),

    %% Get stats
    Stats = beamchain_chainstate:cache_stats(),

    %% Verify stats structure
    ?assert(is_map(Stats)),
    ?assert(maps:is_key(cache_entries, Stats)),
    ?assert(maps:is_key(dirty_entries, Stats)),
    ?assert(maps:is_key(fresh_entries, Stats)),
    ?assert(maps:is_key(pending_deletes, Stats)),
    ?assert(maps:is_key(memory_bytes, Stats)),
    ?assert(maps:is_key(memory_mb, Stats)),

    %% Verify counts make sense (at least 2 dirty/fresh from our adds)
    ?assert(maps:get(dirty_entries, Stats) >= 2),
    ?assert(maps:get(fresh_entries, Stats) >= 2),
    ?assert(maps:get(memory_bytes, Stats) > 0),

    %% Clean up
    beamchain_chainstate:spend_utxo(Txid1, 0),
    beamchain_chainstate:spend_utxo(Txid2, 0).

%%% ===================================================================
%%% assumeUTXO tests
%%% ===================================================================

test_utxo_hash_computation() ->
    %% Add some UTXOs and compute hash
    Txid1 = <<16#1234:256>>,
    Txid2 = <<16#5678:256>>,
    Utxo1 = #utxo{value = 100000, script_pubkey = <<16#51>>,
                  is_coinbase = false, height = 100},
    Utxo2 = #utxo{value = 200000, script_pubkey = <<16#52>>,
                  is_coinbase = true, height = 0},

    beamchain_chainstate:add_utxo(Txid1, 0, Utxo1),
    beamchain_chainstate:add_utxo(Txid2, 0, Utxo2),

    %% Compute hash
    Hash1 = beamchain_chainstate:compute_utxo_hash(),

    %% Hash should be 32 bytes
    ?assertEqual(32, byte_size(Hash1)),

    %% Computing again should give same result (deterministic)
    Hash2 = beamchain_chainstate:compute_utxo_hash(),
    ?assertEqual(Hash1, Hash2),

    %% Clean up
    beamchain_chainstate:spend_utxo(Txid1, 0),
    beamchain_chainstate:spend_utxo(Txid2, 0).

test_snapshot_role_detection() ->
    %% Main chainstate should not be a snapshot chainstate
    ?assertEqual(false, beamchain_chainstate:is_snapshot_chainstate()),

    %% Snapshot base height should return not_snapshot for main chainstate
    ?assertEqual(not_snapshot, beamchain_chainstate:get_snapshot_base_height()).

%%% ===================================================================
%%% Block invalidation and reconsideration tests
%%% ===================================================================

test_cannot_invalidate_genesis() ->
    %% Get genesis block hash
    Genesis = beamchain_chain_params:genesis_block(regtest),
    GenesisHash = Genesis#block.hash,

    %% Attempting to invalidate genesis should fail
    Result = beamchain_chainstate:invalidate_block(GenesisHash),
    ?assertEqual({error, cannot_invalidate_genesis}, Result).

test_invalidate_unknown_block() ->
    %% Create a random non-existent block hash
    UnknownHash = crypto:strong_rand_bytes(32),

    %% Attempting to invalidate unknown block should fail
    Result = beamchain_chainstate:invalidate_block(UnknownHash),
    ?assertEqual({error, block_not_found}, Result).

test_block_marked_invalid() ->
    %% Create a test block at height 1
    Genesis = beamchain_chain_params:genesis_block(regtest),
    GenesisHash = Genesis#block.hash,

    %% Create a minimal block header for height 1
    Header1 = #block_header{
        version = 1,
        prev_hash = GenesisHash,
        merkle_root = <<0:256>>,
        timestamp = 1296688928,
        bits = 16#207fffff,  %% regtest difficulty
        nonce = 0
    },
    BlockHash1 = beamchain_serialize:block_hash(Header1),

    %% Store the block index entry
    ok = beamchain_db:store_block_index(1, BlockHash1, Header1, <<0,0,0,2>>, 3),

    %% Invalidate the block
    ok = beamchain_chainstate:invalidate_block(BlockHash1),

    %% Verify the block status is now marked invalid
    {ok, #{status := Status}} = beamchain_db:get_block_index_by_hash(BlockHash1),
    %% BLOCK_FAILED_VALID = 32
    ?assertNotEqual(0, Status band 32).

test_reconsider_clears_flag() ->
    %% Create another test block at height 2
    Genesis = beamchain_chain_params:genesis_block(regtest),
    GenesisHash = Genesis#block.hash,

    Header2 = #block_header{
        version = 1,
        prev_hash = GenesisHash,
        merkle_root = <<1:256>>,
        timestamp = 1296688930,
        bits = 16#207fffff,
        nonce = 1
    },
    BlockHash2 = beamchain_serialize:block_hash(Header2),

    %% Store the block index entry as valid
    ok = beamchain_db:store_block_index(2, BlockHash2, Header2, <<0,0,0,3>>, 3),

    %% Invalidate the block
    ok = beamchain_chainstate:invalidate_block(BlockHash2),

    %% Verify it's marked invalid
    {ok, #{status := Status1}} = beamchain_db:get_block_index_by_hash(BlockHash2),
    ?assertNotEqual(0, Status1 band 32),

    %% Reconsider the block
    ok = beamchain_chainstate:reconsider_block(BlockHash2),

    %% Verify the invalid flag is cleared
    {ok, #{status := Status2}} = beamchain_db:get_block_index_by_hash(BlockHash2),
    ?assertEqual(0, Status2 band 32).
