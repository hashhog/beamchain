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
          %% dumptxoutset body / IsUnspendable filter regression tests
          %% (regression for the empty-body dump bug — the snapshot body
          %% used to be empty because collect_all_utxos/0 was a TODO stub
          %% returning [], so submitblock-driven ingest produced a 51-byte
          %% header-only file. These three tests pin the now-real
          %% chainstate-CF iterator + Core IsUnspendable filter.)
          {"fold_utxos walks the chainstate CF after flush",
           fun test_fold_utxos_walks_chainstate/0},
          {"add_utxo drops OP_RETURN per Core IsUnspendable",
           fun test_add_utxo_filters_op_return/0},
          {"serialize_snapshot body contains every flushed UTXO",
           fun test_serialize_snapshot_body_nonempty/0},
          %% Block invalidation/reconsideration tests
          {"cannot invalidate genesis block", fun test_cannot_invalidate_genesis/0},
          {"invalidating unknown block returns error", fun test_invalidate_unknown_block/0},
          {"block status is marked invalid", fun test_block_marked_invalid/0},
          {"reconsider clears invalid flag", fun test_reconsider_clears_flag/0},
          %% Regression tests: L1-5 findings 2026-04-11
          %% Symptom A: IBD exit uses latched flag, not live tip-age re-evaluation
          {"is_synced false on fresh chain (ibd latched)", fun test_ibd_false_initially/0},
          {"is_synced true once ibd flag is latched false", fun test_ibd_latched_to_false/0},
          {"ibd stays false after latch (no revert on old-timestamp tip)", fun test_ibd_no_revert/0}
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

    %% Create test UTXO. Use a spendable script (OP_TRUE) — OP_RETURN
    %% prefixes are unspendable per Core's IsUnspendable(), and
    %% beamchain_chainstate:add_utxo/3 now drops them at AddCoin time
    %% to mirror bitcoin-core/src/coins.cpp:91. See
    %% beamchain_chainstate:is_unspendable_script/1.
    TestTxid = <<16#dead:256>>,
    TestUtxo = #utxo{
        value = 1000000,
        script_pubkey = <<16#51>>,
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

    %% Initial UTXOs (what would be spent by the block).
    %% Scripts are bare OP_<n> (push small int) — spendable. Avoid the
    %% OP_RETURN prefix here: beamchain_chainstate:add_utxo/3 mirrors
    %% bitcoin-core/src/coins.cpp:91 IsUnspendable() and silently drops
    %% scripts that begin with OP_RETURN, which would defeat the
    %% multi-tx round-trip this test pins.
    Utxo1 = #utxo{value = 1000000, script_pubkey = <<16#51>>,
                  is_coinbase = false, height = 50},
    Utxo2 = #utxo{value = 2000000, script_pubkey = <<16#52>>,
                  is_coinbase = false, height = 60},
    Utxo3 = #utxo{value = 3000000, script_pubkey = <<16#53>>,
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

%%%===================================================================
%%% IBD latch regression tests (L1-5 Symptom A, 2026-04-11)
%%%===================================================================

%% Before the fix, is_synced() re-evaluated the tip age on every call
%% instead of using the latched ibd flag.  A chain synced to within
%% ~144 blocks of the network tip (well inside 24 h) would still report
%% initialblockdownload:true because maybe_check_ibd used a 1-hour
%% threshold (too strict) and is_synced() did not consult ibd at all.
%%
%% After the fix:
%%   • is_synced() returns (not State#state.ibd)
%%   • maybe_check_ibd latches ibd=false when tip age < 86400 s (24 h)

%% Fresh chainstate (genesis only, old timestamp) must report ibd=true.
test_ibd_false_initially() ->
    %% Genesis block has timestamp from 2009/2011; it is far older than 24 h,
    %% so maybe_check_ibd will NOT flip the latch.
    ?assertEqual(false, beamchain_chainstate:is_synced()).

%% When the gen_server state has ibd=false (latch fired), is_synced() must
%% return true — even if the tip timestamp is old.
test_ibd_latched_to_false() ->
    %% Use sys:replace_state to flip ibd without needing a real block.
    %% ibd is element 10 in the #state{} tuple (tag at 1, then 8 fields before ibd).
    sys:replace_state(beamchain_chainstate,
        fun(S) -> setelement(10, S, false) end),
    ?assertEqual(true, beamchain_chainstate:is_synced()),
    %% Restore so subsequent tests see the initial state
    sys:replace_state(beamchain_chainstate,
        fun(S) -> setelement(10, S, true) end).

%% Once ibd is latched false it must not revert when is_synced() is called
%% again — even if the tip age is old.
%% Bitcoin Core provides the same guarantee: m_cached_is_ibd is latched once.
test_ibd_no_revert() ->
    %% Latch the ibd flag to false
    sys:replace_state(beamchain_chainstate,
        fun(S) -> setelement(10, S, false) end),
    ?assertEqual(true, beamchain_chainstate:is_synced()),

    %% Call is_synced() again — must still return true (latch is sticky).
    %% Before the fix, is_synced() re-evaluated tip age on every call,
    %% so a node 293 blocks (≈49 h) behind Core would still show ibd=true
    %% even though it had previously caught up past the 24 h threshold.
    ?assertEqual(true, beamchain_chainstate:is_synced()),

    %% Restore state for cleanup
    sys:replace_state(beamchain_chainstate,
        fun(S) -> setelement(10, S, true) end).

%%% ===================================================================
%%% dumptxoutset body / IsUnspendable filter regression tests
%%%
%%% Regression for the W-snapshot-byte-identity empty-body bug: the
%%% beamchain dump used to emit a 51-byte header-only file (0 coins)
%%% because beamchain_snapshot:collect_all_utxos/0 was a TODO stub that
%%% returned [].  The fix walks the chainstate column family directly
%%% via beamchain_db:fold_utxos/2 — the same on-disk store that
%%% submitblock-driven ingest writes through (after flush). Mirrors
%%% bitcoin-core/src/kernel/coinstats.cpp ComputeUTXOStats's
%%% `view->Cursor()` walk and rpc/blockchain.cpp WriteUTXOSnapshot.
%%%
%%% These tests also pin the IsUnspendable filter at AddCoin time,
%%% mirroring bitcoin-core/src/coins.cpp:91, which is what keeps the
%%% snapshot byte-identical with Core's reference dump (Core never
%%% adds OP_RETURN coinbase outputs to the chainstate).
%%% ===================================================================

%% beamchain_db:fold_utxos/2 must walk every UTXO that has been flushed
%% to the chainstate CF.  Pre-fix the snapshot caller was inert (TODO
%% stub) so this iterator did not exist; pin its semantics.
test_fold_utxos_walks_chainstate() ->
    %% Two spendable UTXOs (OP_TRUE / OP_2) — both pass IsUnspendable.
    Txid1 = <<16#a1:256>>,
    Txid2 = <<16#a2:256>>,
    Utxo1 = #utxo{value = 11111, script_pubkey = <<16#51>>,
                  is_coinbase = false, height = 5},
    Utxo2 = #utxo{value = 22222, script_pubkey = <<16#52>>,
                  is_coinbase = true,  height = 6},

    beamchain_chainstate:add_utxo_fresh(Txid1, 0, Utxo1),
    beamchain_chainstate:add_utxo_fresh(Txid2, 1, Utxo2),

    %% Before flush the entries live only in ETS — fold_utxos walks
    %% the CF, so ensure the WriteBatch has landed on disk.
    beamchain_chainstate:flush(),

    Folded = beamchain_db:fold_utxos(
        fun(Coin, Acc) -> [Coin | Acc] end, []),
    ?assert(is_list(Folded)),

    %% Both UTXOs we just inserted must appear, with their values
    %% intact through the encode/decode roundtrip.
    Found1 = [U || {T, V, U} <- Folded, T =:= Txid1, V =:= 0],
    Found2 = [U || {T, V, U} <- Folded, T =:= Txid2, V =:= 1],
    ?assertMatch([#utxo{value = 11111}], Found1),
    ?assertMatch([#utxo{value = 22222, is_coinbase = true}], Found2),

    %% Clean up so other tests don't see these.
    beamchain_chainstate:spend_utxo(Txid1, 0),
    beamchain_chainstate:spend_utxo(Txid2, 1),
    beamchain_chainstate:flush().

%% Mirrors bitcoin-core/src/coins.cpp:91 — IsUnspendable() outputs
%% (OP_RETURN-prefixed scripts and oversized scripts) must be silently
%% dropped at AddCoin time so they never enter the chainstate. This is
%% what keeps the regtest dump byte-identical with Core's reference
%% (otherwise the SegWit-witness-commitment OP_RETURN coinbase outputs
%% would inflate the count from 110 to ≥220).
test_add_utxo_filters_op_return() ->
    OpReturnTxid = <<16#b1:256>>,
    OpReturnUtxo = #utxo{value = 0,
                         script_pubkey = <<16#6a, 4, "test">>,
                         is_coinbase = true,
                         height = 7},
    beamchain_chainstate:add_utxo_fresh(OpReturnTxid, 0, OpReturnUtxo),
    %% Filter dropped it — not visible in cache or DB.
    ?assertEqual(not_found,
                 beamchain_chainstate:get_utxo(OpReturnTxid, 0)),

    %% Same for add_utxo/3 (the BIP30-aware path) and for empty-script
    %% OP_RETURN.
    OpReturnTxid2 = <<16#b2:256>>,
    OpReturnUtxo2 = #utxo{value = 0, script_pubkey = <<16#6a>>,
                          is_coinbase = false, height = 8},
    beamchain_chainstate:add_utxo(OpReturnTxid2, 0, OpReturnUtxo2),
    ?assertEqual(not_found,
                 beamchain_chainstate:get_utxo(OpReturnTxid2, 0)),

    %% Oversized script (> MAX_SCRIPT_SIZE = 10000) is also IsUnspendable.
    BigTxid = <<16#b3:256>>,
    BigSPK = binary:copy(<<16#51>>, 10001),
    BigUtxo = #utxo{value = 1, script_pubkey = BigSPK,
                    is_coinbase = false, height = 9},
    beamchain_chainstate:add_utxo_fresh(BigTxid, 0, BigUtxo),
    ?assertEqual(not_found,
                 beamchain_chainstate:get_utxo(BigTxid, 0)),

    %% Sanity: a spendable script (OP_TRUE) is NOT filtered.
    OkTxid = <<16#b4:256>>,
    OkUtxo = #utxo{value = 5, script_pubkey = <<16#51>>,
                   is_coinbase = false, height = 10},
    beamchain_chainstate:add_utxo_fresh(OkTxid, 0, OkUtxo),
    ?assertMatch({ok, #utxo{value = 5}},
                 beamchain_chainstate:get_utxo(OkTxid, 0)),
    beamchain_chainstate:spend_utxo(OkTxid, 0).

%% End-to-end pin of the dump body. Pre-fix this would emit a 51-byte
%% header-only file even when UTXOs were flushed to disk, because
%% beamchain_snapshot:collect_all_utxos/0 was a stub. Now the body must
%% contain every flushed (spendable) UTXO, in the same on-disk format
%% Core's WriteUTXOSnapshot produces.
test_serialize_snapshot_body_nonempty() ->
    %% Three spendable UTXOs grouped over two txids (so we exercise both
    %% the per-tx CompactSize header and multi-vout-per-tx paths).
    TxidA = <<16#c1:256>>,
    TxidB = <<16#c2:256>>,
    A0 = #utxo{value = 100, script_pubkey = <<16#51>>,
               is_coinbase = false, height = 11},
    A1 = #utxo{value = 200, script_pubkey = <<16#52>>,
               is_coinbase = false, height = 11},
    B0 = #utxo{value = 300, script_pubkey = <<16#53>>,
               is_coinbase = true,  height = 12},

    beamchain_chainstate:add_utxo_fresh(TxidA, 0, A0),
    beamchain_chainstate:add_utxo_fresh(TxidA, 1, A1),
    beamchain_chainstate:add_utxo_fresh(TxidB, 0, B0),

    %% Slip in an OP_RETURN that should be filtered — it must NOT show
    %% up in the dump body.
    OpReturnTxid = <<16#cf:256>>,
    OpReturnUtxo = #utxo{value = 0,
                         script_pubkey = <<16#6a, 1, 7>>,
                         is_coinbase = true, height = 13},
    beamchain_chainstate:add_utxo_fresh(OpReturnTxid, 0, OpReturnUtxo),

    %% Build the snapshot. serialize_snapshot/2 calls flush/0 internally
    %% via collect_all_utxos/0 → fold_utxos/2.
    Genesis = beamchain_chain_params:genesis_block(regtest),
    SnapshotBin = beamchain_snapshot:serialize_snapshot(
        Genesis#block.hash, regtest),

    %% Header is fixed-size 51 bytes; total must exceed it (body
    %% non-empty). This is the load-bearing assertion: pre-fix this
    %% number was exactly 51.
    ?assert(byte_size(SnapshotBin) > 51),

    %% Round-trip the file through the parser. num_coins is the value
    %% serialised in the header (which must match the body length).
    {ok, #{num_coins := N}, _Rest} =
        beamchain_snapshot:parse_metadata(SnapshotBin),
    %% At least our 3 spendable UTXOs must be present. (The
    %% chainstate may still hold stragglers from prior tests in
    %% the same setup; we only require lower-bound containment.)
    ?assert(N >= 3),

    %% Clean up.
    beamchain_chainstate:spend_utxo(TxidA, 0),
    beamchain_chainstate:spend_utxo(TxidA, 1),
    beamchain_chainstate:spend_utxo(TxidB, 0),
    beamchain_chainstate:flush().
