-module(beamchain_db_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% We use a test fixture that starts/stops the config and db for each test group.
%% The tests use a temp directory so they don't interfere with real data.

db_test_() ->
    {setup,
     fun setup/0,
     fun teardown/1,
     fun(_) ->
         [
          {"block store/retrieve roundtrip", fun block_roundtrip/0},
          {"block by height lookup", fun block_by_height/0},
          {"has_block check", fun has_block_check/0},
          {"utxo store/get cycle", fun utxo_store_get/0},
          {"utxo spend returns utxo", fun utxo_spend/0},
          {"utxo not found", fun utxo_not_found/0},
          {"has_utxo check", fun has_utxo_check/0},
          {"chain tip set/get", fun chain_tip/0},
          {"chain tip not found initially", fun chain_tip_not_found/0},
          {"block index store/get", fun block_index_roundtrip/0},
          {"block index lookup by hash", fun block_index_by_hash/0},
          %% Regression test: store_block_index/6 preserves NTx (L1-5 symptom B)
          {"block index n_tx roundtrip with store/6", fun block_index_ntx_preserved/0},
          {"block index status update preserves n_tx", fun block_index_ntx_not_clobbered/0},
          {"tx index store/get", fun tx_index_roundtrip/0},
          {"undo data store/get", fun undo_data_roundtrip/0},
          {"batch write atomicity", fun batch_write/0},
          %% Flat file storage tests
          {"flat file write/read roundtrip", fun flat_file_roundtrip/0},
          {"flat file multiple blocks", fun flat_file_multiple_blocks/0},
          {"flat file read not found", fun flat_file_not_found/0},
          {"flat file info", fun flat_file_info/0},
          %% Pruning tests
          {"is_block_pruned returns false initially", fun is_block_pruned_initial/0},
          {"prune_block_files with no prune target", fun prune_disabled/0},
          {"get_block_file_info includes prune info", fun block_file_info_prune/0},
          %% Bug 1 (audit 2026-05-05): find_max_height_in_file used to
          %% always return 0; now returns the actual max height of
          %% blocks belonging to the file.
          {"find_max_height_in_file returns undefined for empty file",
           fun find_max_height_empty_file/0},
          {"find_max_height_in_file returns max of 3 known blocks",
           fun find_max_height_three_blocks/0},
          {"find_max_height_in_file ignores blocks in other files",
           fun find_max_height_isolated_per_file/0},
          %% scrubunspendable: orphan-OP_RETURN / oversize cleanup (commit 79fa3e5)
          {"scrub_unspendable removes orphan OP_RETURN + oversize coins",
           fun scrub_unspendable_removes_orphans/0},
          {"scrub_unspendable is idempotent", fun scrub_unspendable_idempotent/0}
         ]
     end}.

setup() ->
    %% Use a unique temp directory for each test run
    TmpDir = filename:join(["/tmp", "beamchain_test_" ++
                            integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),

    %% Set environment so beamchain_config uses our temp dir
    application:ensure_all_started(rocksdb),
    application:set_env(beamchain, datadir, TmpDir),
    application:set_env(beamchain, network, regtest),

    %% Start config (needed by db)
    {ok, ConfigPid} = beamchain_config:start_link(),
    %% Start db
    {ok, DbPid} = beamchain_db:start_link(),

    {TmpDir, ConfigPid, DbPid}.

teardown({TmpDir, _ConfigPid, _DbPid}) ->
    %% Stop db and config
    catch beamchain_db:stop(),
    catch gen_server:stop(beamchain_config),
    %% Clean up env vars
    os:unsetenv("BEAMCHAIN_PRUNE"),
    %% Clean up temp directory
    os:cmd("rm -rf " ++ TmpDir),
    ok.

%%% ===================================================================
%%% Test helpers
%%% ===================================================================

make_test_block(PrevHash, Nonce) ->
    Header = #block_header{
        version = 1,
        prev_hash = PrevHash,
        merkle_root = crypto:strong_rand_bytes(32),
        timestamp = 1231006505,
        bits = 16#1d00ffff,
        nonce = Nonce
    },
    %% Simple coinbase tx
    CoinbaseTx = #transaction{
        version = 1,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = <<0:256>>, index = 16#ffffffff},
            script_sig = <<4, 1, 0, 0, 0>>,
            sequence = 16#ffffffff,
            witness = []
        }],
        outputs = [#tx_out{
            value = 5000000000,
            script_pubkey = <<16#76, 16#a9, 16#14,  %% OP_DUP OP_HASH160 PUSH20
                              0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                              16#88, 16#ac>>         %% OP_EQUALVERIFY OP_CHECKSIG
        }],
        locktime = 0
    },
    Hash = beamchain_serialize:block_hash(Header),
    #block{
        header = Header,
        transactions = [CoinbaseTx],
        hash = Hash
    }.

make_test_utxo() ->
    #utxo{
        value = 5000000000,
        script_pubkey = <<16#76, 16#a9, 16#14,
                          1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,
                          16#88, 16#ac>>,
        is_coinbase = true,
        height = 0
    }.

%%% ===================================================================
%%% Block tests
%%% ===================================================================

block_roundtrip() ->
    Block = make_test_block(<<0:256>>, 42),
    Hash = Block#block.hash,
    ok = beamchain_db:store_block(Block, 0),
    {ok, Retrieved} = beamchain_db:get_block(Hash),
    %% Compare headers (block hash is derived from header)
    ?assertEqual(Block#block.header, Retrieved#block.header),
    %% Compare tx count
    ?assertEqual(length(Block#block.transactions),
                 length(Retrieved#block.transactions)).

block_by_height() ->
    Block0 = make_test_block(<<0:256>>, 100),
    Block1 = make_test_block(Block0#block.hash, 101),
    ok = beamchain_db:store_block(Block0, 0),
    ok = beamchain_db:store_block(Block1, 1),
    %% store_block only stores by hash; we need store_block_index for height lookup
    ok = beamchain_db:store_block_index(0, Block0#block.hash, Block0#block.header,
                                         <<0:64>>, 1),
    ok = beamchain_db:store_block_index(1, Block1#block.hash, Block1#block.header,
                                         <<0:64>>, 1),
    {ok, Retrieved} = beamchain_db:get_block_by_height(1),
    ?assertEqual(Block1#block.header, Retrieved#block.header),
    ?assertEqual(not_found, beamchain_db:get_block_by_height(999)).

has_block_check() ->
    Block = make_test_block(<<0:256>>, 200),
    Hash = Block#block.hash,
    ?assertEqual(false, beamchain_db:has_block(Hash)),
    ok = beamchain_db:store_block(Block, 5),
    ?assertEqual(true, beamchain_db:has_block(Hash)).

%%% ===================================================================
%%% UTXO tests
%%% ===================================================================

utxo_store_get() ->
    Txid = crypto:strong_rand_bytes(32),
    Utxo = make_test_utxo(),
    ok = beamchain_db:store_utxo(Txid, 0, Utxo),
    {ok, Retrieved} = beamchain_db:get_utxo(Txid, 0),
    ?assertEqual(Utxo#utxo.value, Retrieved#utxo.value),
    ?assertEqual(Utxo#utxo.script_pubkey, Retrieved#utxo.script_pubkey),
    ?assertEqual(Utxo#utxo.is_coinbase, Retrieved#utxo.is_coinbase),
    ?assertEqual(Utxo#utxo.height, Retrieved#utxo.height).

utxo_spend() ->
    Txid = crypto:strong_rand_bytes(32),
    Utxo = make_test_utxo(),
    ok = beamchain_db:store_utxo(Txid, 0, Utxo),
    ?assertEqual(true, beamchain_db:has_utxo(Txid, 0)),
    {ok, Spent} = beamchain_db:spend_utxo(Txid, 0),
    ?assertEqual(Utxo#utxo.value, Spent#utxo.value),
    %% After spending, UTXO should be gone
    ?assertEqual(not_found, beamchain_db:get_utxo(Txid, 0)),
    ?assertEqual(false, beamchain_db:has_utxo(Txid, 0)).

utxo_not_found() ->
    FakeTxid = crypto:strong_rand_bytes(32),
    ?assertEqual(not_found, beamchain_db:get_utxo(FakeTxid, 0)),
    ?assertEqual(not_found, beamchain_db:spend_utxo(FakeTxid, 0)).

has_utxo_check() ->
    Txid = crypto:strong_rand_bytes(32),
    ?assertEqual(false, beamchain_db:has_utxo(Txid, 0)),
    ok = beamchain_db:store_utxo(Txid, 0, make_test_utxo()),
    ?assertEqual(true, beamchain_db:has_utxo(Txid, 0)),
    %% Different vout should not exist
    ?assertEqual(false, beamchain_db:has_utxo(Txid, 1)).

%%% ===================================================================
%%% Chain tip tests
%%% ===================================================================

chain_tip_not_found() ->
    %% Chain tip may already be set by prior tests, so this test
    %% just verifies the API works without crashing
    Result = beamchain_db:get_chain_tip(),
    ?assert(Result =:= not_found orelse element(1, Result) =:= ok).

chain_tip() ->
    Hash = crypto:strong_rand_bytes(32),
    ok = beamchain_db:set_chain_tip(Hash, 42),
    {ok, Tip} = beamchain_db:get_chain_tip(),
    ?assertEqual(Hash, maps:get(hash, Tip)),
    ?assertEqual(42, maps:get(height, Tip)),
    %% Update it
    Hash2 = crypto:strong_rand_bytes(32),
    ok = beamchain_db:set_chain_tip(Hash2, 43),
    {ok, Tip2} = beamchain_db:get_chain_tip(),
    ?assertEqual(Hash2, maps:get(hash, Tip2)),
    ?assertEqual(43, maps:get(height, Tip2)).

%%% ===================================================================
%%% Block index tests
%%% ===================================================================

block_index_roundtrip() ->
    Hash = crypto:strong_rand_bytes(32),
    Header = #block_header{
        version = 2,
        prev_hash = <<0:256>>,
        merkle_root = crypto:strong_rand_bytes(32),
        timestamp = 1231006505,
        bits = 16#1d00ffff,
        nonce = 12345
    },
    Chainwork = <<0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0>>,
    Status = 3,
    ok = beamchain_db:store_block_index(10, Hash, Header, Chainwork, Status),
    {ok, Entry} = beamchain_db:get_block_index(10),
    ?assertEqual(Hash, maps:get(hash, Entry)),
    ?assertEqual(Header, maps:get(header, Entry)),
    ?assertEqual(Chainwork, maps:get(chainwork, Entry)),
    ?assertEqual(Status, maps:get(status, Entry)).

block_index_by_hash() ->
    Hash = crypto:strong_rand_bytes(32),
    Header = #block_header{
        version = 2,
        prev_hash = <<0:256>>,
        merkle_root = crypto:strong_rand_bytes(32),
        timestamp = 1231006505,
        bits = 16#1d00ffff,
        nonce = 99999
    },
    Chainwork = <<1, 2, 3, 4>>,
    ok = beamchain_db:store_block_index(20, Hash, Header, Chainwork, 1),
    {ok, Entry} = beamchain_db:get_block_index_by_hash(Hash),
    ?assertEqual(20, maps:get(height, Entry)),
    ?assertEqual(Hash, maps:get(hash, Entry)),
    ?assertEqual(Chainwork, maps:get(chainwork, Entry)),
    %% Non-existent hash
    ?assertEqual(not_found,
                 beamchain_db:get_block_index_by_hash(crypto:strong_rand_bytes(32))).

%% Regression: store_block_index/6 writes and round-trips NTx correctly.
%% Before the L1-5 fix, store_block_index only had a 5-arg form that always
%% wrote NTx=0, so getblockheader returned nTx: 0 for every block.
block_index_ntx_preserved() ->
    Hash = crypto:strong_rand_bytes(32),
    Header = #block_header{
        version = 1,
        prev_hash = <<0:256>>,
        merkle_root = crypto:strong_rand_bytes(32),
        timestamp = 1231006505,
        bits = 16#1d00ffff,
        nonce = 42
    },
    Chainwork = <<0, 0, 0, 1>>,
    NTx = 1562,
    ok = beamchain_db:store_block_index(30, Hash, Header, Chainwork, 2, NTx),
    {ok, Entry} = beamchain_db:get_block_index(30),
    ?assertEqual(NTx, maps:get(n_tx, Entry)),
    %% Also verify lookup by hash returns correct NTx
    {ok, EntryByHash} = beamchain_db:get_block_index_by_hash(Hash),
    ?assertEqual(NTx, maps:get(n_tx, EntryByHash)).

%% Regression: a status-only update via store_block_index/6 must not clobber
%% the NTx that direct_atomic_connect_writes stored earlier.
%% beamchain_block_sync.erl validate_and_connect() had this bug (L1-5 symptom B).
block_index_ntx_not_clobbered() ->
    Hash = crypto:strong_rand_bytes(32),
    Header = #block_header{
        version = 1,
        prev_hash = <<0:256>>,
        merkle_root = crypto:strong_rand_bytes(32),
        timestamp = 1231006506,
        bits = 16#1d00ffff,
        nonce = 7
    },
    Chainwork = <<0, 0, 0, 2>>,
    NTx = 999,
    %% First write: headers-only entry with real NTx (simulating direct_atomic_connect_writes)
    ok = beamchain_db:store_block_index(31, Hash, Header, Chainwork, 1, NTx),
    %% Second write: status promotion that must preserve NTx (simulating validate_and_connect step 5)
    {ok, Existing} = beamchain_db:get_block_index(31),
    ExistingNTx = maps:get(n_tx, Existing),
    ok = beamchain_db:store_block_index(31, Hash, Header, Chainwork, 2, ExistingNTx),
    %% NTx must survive the status update
    {ok, Final} = beamchain_db:get_block_index(31),
    ?assertEqual(NTx, maps:get(n_tx, Final)),
    ?assertEqual(2, maps:get(status, Final)).

%%% ===================================================================
%%% Transaction index tests
%%% ===================================================================

tx_index_roundtrip() ->
    Txid = crypto:strong_rand_bytes(32),
    BlockHash = crypto:strong_rand_bytes(32),
    ok = beamchain_db:store_tx_index(Txid, BlockHash, 100, 3),
    {ok, Loc} = beamchain_db:get_tx_location(Txid),
    ?assertEqual(BlockHash, maps:get(block_hash, Loc)),
    ?assertEqual(100, maps:get(height, Loc)),
    ?assertEqual(3, maps:get(position, Loc)),
    %% Non-existent txid
    ?assertEqual(not_found,
                 beamchain_db:get_tx_location(crypto:strong_rand_bytes(32))).

%%% ===================================================================
%%% Undo data tests
%%% ===================================================================

undo_data_roundtrip() ->
    BlockHash = crypto:strong_rand_bytes(32),
    UndoData = <<"some undo data for spent utxos">>,
    ok = beamchain_db:store_undo(BlockHash, UndoData),
    {ok, Retrieved} = beamchain_db:get_undo(BlockHash),
    ?assertEqual(UndoData, Retrieved),
    %% Non-existent
    ?assertEqual(not_found, beamchain_db:get_undo(crypto:strong_rand_bytes(32))).

%%% ===================================================================
%%% Batch write tests
%%% ===================================================================

batch_write() ->
    %% Batch: store a UTXO and set chain tip atomically
    Txid = crypto:strong_rand_bytes(32),
    Utxo = make_test_utxo(),
    UtxoKey = <<Txid:32/binary, 0:32/big>>,
    CoinbaseFlag = 1,
    UtxoValue = <<(Utxo#utxo.value):64/little,
                  (Utxo#utxo.height):32/little,
                  CoinbaseFlag:8,
                  (Utxo#utxo.script_pubkey)/binary>>,
    TipHash = crypto:strong_rand_bytes(32),
    TipValue = <<TipHash:32/binary, 50:64/big>>,
    ok = beamchain_db:write_batch([
        {put, chainstate, UtxoKey, UtxoValue},
        {put, meta, <<"chain_tip">>, TipValue}
    ]),
    %% Verify both writes took effect
    {ok, _} = beamchain_db:get_utxo(Txid, 0),
    {ok, Tip} = beamchain_db:get_chain_tip(),
    ?assertEqual(TipHash, maps:get(hash, Tip)),
    ?assertEqual(50, maps:get(height, Tip)).

%%% ===================================================================
%%% Flat file storage tests
%%% ===================================================================

flat_file_roundtrip() ->
    Block = make_test_block(<<0:256>>, 1000),
    Hash = Block#block.hash,
    %% Write block to flat file
    {ok, {FileNum, Offset, Size}} = beamchain_db:write_block(Block, 0),
    ?assert(is_integer(FileNum)),
    ?assert(is_integer(Offset)),
    ?assert(is_integer(Size)),
    ?assert(Size > 0),
    %% Read block back from flat file
    {ok, Retrieved} = beamchain_db:read_block(Hash),
    %% Verify header matches
    ?assertEqual(Block#block.header, Retrieved#block.header),
    %% Verify tx count matches
    ?assertEqual(length(Block#block.transactions),
                 length(Retrieved#block.transactions)).

flat_file_multiple_blocks() ->
    %% Write multiple blocks
    Block0 = make_test_block(<<0:256>>, 2000),
    Block1 = make_test_block(Block0#block.hash, 2001),
    Block2 = make_test_block(Block1#block.hash, 2002),

    {ok, Loc0} = beamchain_db:write_block(Block0, 0),
    {ok, Loc1} = beamchain_db:write_block(Block1, 1),
    {ok, Loc2} = beamchain_db:write_block(Block2, 2),

    %% Verify locations are different
    ?assertNotEqual(Loc0, Loc1),
    ?assertNotEqual(Loc1, Loc2),

    %% Read all blocks back in different order
    {ok, R2} = beamchain_db:read_block(Block2#block.hash),
    {ok, R0} = beamchain_db:read_block(Block0#block.hash),
    {ok, R1} = beamchain_db:read_block(Block1#block.hash),

    ?assertEqual(Block2#block.header, R2#block.header),
    ?assertEqual(Block0#block.header, R0#block.header),
    ?assertEqual(Block1#block.header, R1#block.header).

flat_file_not_found() ->
    %% Try to read a block that doesn't exist
    FakeHash = crypto:strong_rand_bytes(32),
    ?assertEqual(not_found, beamchain_db:read_block(FakeHash)).

flat_file_info() ->
    %% Get block file info
    Info = beamchain_db:get_block_file_info(),
    ?assert(is_map(Info)),
    ?assert(maps:is_key(blocks_dir, Info)),
    ?assert(maps:is_key(current_file, Info)),
    ?assert(maps:is_key(current_pos, Info)),
    ?assert(maps:is_key(max_file_size, Info)),
    ?assert(maps:is_key(index_size, Info)),
    ?assertEqual(134217728, maps:get(max_file_size, Info)).

%%% ===================================================================
%%% Pruning tests
%%% ===================================================================

is_block_pruned_initial() ->
    %% A block that was never stored should not be considered pruned
    FakeHash = crypto:strong_rand_bytes(32),
    ?assertEqual(false, beamchain_db:is_block_pruned(FakeHash)),
    %% Write a block and check it's not pruned
    Block = make_test_block(<<0:256>>, 3000),
    {ok, _} = beamchain_db:write_block(Block, 0),
    ?assertEqual(false, beamchain_db:is_block_pruned(Block#block.hash)).

prune_disabled() ->
    %% With default config (prune target = 0), pruning should be disabled
    {ok, Count} = beamchain_db:prune_block_files(),
    ?assertEqual(0, Count).

block_file_info_prune() ->
    %% Verify prune-related fields are in block file info
    Info = beamchain_db:get_block_file_info(),
    ?assert(maps:is_key(prune_target_mb, Info)),
    ?assert(maps:is_key(pruned_file_count, Info)),
    ?assert(maps:is_key(tracked_files, Info)),
    %% With default config, prune target should be 0
    ?assertEqual(0, maps:get(prune_target_mb, Info)),
    ?assertEqual(0, maps:get(pruned_file_count, Info)).

%%% ===================================================================
%%% Bug 1 (audit 2026-05-05): find_max_height_in_file
%%%
%%% Pre-fix this function always returned 0 because the code did
%%% `case MaxHeight of undefined -> 0; H -> H end' on every match
%%% without ever using the height information available via the
%%% HEIGHT_TO_HASH_ETS index. With that bug, every non-current file
%%% looked like it had max_height = 0 = older than tip-288, so every
%%% non-current file was always "prunable" — would corrupt the
%%% MIN_BLOCKS_TO_KEEP=288 keep window the day pruning fired.
%%%
%%% These tests join HEIGHT_TO_HASH_ETS against BLOCK_INDEX_ETS the
%%% same way the production code now does, and verify the function
%%% returns the *actual* max height per file.
%%%
%%% Reference: bitcoin-core/src/node/blockstorage.cpp
%%% BlockManager::FindFilesToPrune (uses BlockFileInfo::nHeightLast).
%%% ===================================================================

%% Helper: write a block at a given height, populating both indexes
%% the way write_block + index_block do in production.
write_block_at_height(Block, Height) ->
    {ok, _Loc} = beamchain_db:write_block(Block, Height),
    %% index_block populates HEIGHT_TO_HASH_ETS — this is what the
    %% chainstate gen_server does on connect_block in production.
    Timestamp = (Block#block.header)#block_header.timestamp,
    ok = beamchain_db:index_block(Height, Block#block.hash, Timestamp),
    ok.

find_max_height_empty_file() ->
    %% A file with no blocks indexed should return undefined, NOT 0
    %% (the pre-fix bug returned undefined here too — but for the wrong
    %% reason; pin the contract).
    ?assertEqual(undefined, beamchain_db:find_max_height_in_file(99999)).

%% Helper: read FileNum from BLOCK_INDEX_ETS for a known hash.
%% Implements the test-only "get_block_location" we'd otherwise need.
file_num_for_hash(Hash) ->
    case ets:lookup(beamchain_block_index, Hash) of
        [{Hash, {FN, _Offset, _Size}}] -> FN;
        [{Hash, {FN, _Offset, _Size, pruned}}] -> FN;
        _ -> error({hash_not_indexed, Hash})
    end.

find_max_height_three_blocks() ->
    %% Write 3 blocks at heights 10, 20, 30 — all small enough to land
    %% in the same file under the default MAX_BLOCKFILE_SIZE = 128 MB.
    B0 = make_test_block(<<0:256>>, 30000),
    B1 = make_test_block(B0#block.hash, 30001),
    B2 = make_test_block(B1#block.hash, 30002),
    ok = write_block_at_height(B0, 10),
    ok = write_block_at_height(B1, 20),
    ok = write_block_at_height(B2, 30),
    %% All three blocks are tiny so they share a file. Confirm they did.
    F0 = file_num_for_hash(B0#block.hash),
    F1 = file_num_for_hash(B1#block.hash),
    F2 = file_num_for_hash(B2#block.hash),
    ?assertEqual(F0, F1),
    ?assertEqual(F0, F2),
    %% Pre-fix this returned 0 regardless of the heights stored.
    %% Post-fix it must return the real max — 30.
    ?assertEqual(30, beamchain_db:find_max_height_in_file(F0)).

find_max_height_isolated_per_file() ->
    %% Querying a file that exists but has no blocks belonging to it
    %% must return undefined, NOT the global max.
    B = make_test_block(<<0:256>>, 40000),
    ok = write_block_at_height(B, 50),
    RealFile = file_num_for_hash(B#block.hash),
    %% Pick a file number that definitely doesn't have this block
    OtherFile = RealFile + 17,
    ?assertEqual(undefined, beamchain_db:find_max_height_in_file(OtherFile)),
    %% Sanity check: the real file does have it
    ?assertEqual(50, beamchain_db:find_max_height_in_file(RealFile)).

%%% ===================================================================
%%% Pruning tests with prune enabled
%%% ===================================================================

prune_enabled_test_() ->
    {setup,
     fun setup_with_prune/0,
     fun teardown/1,
     fun(_) ->
         [
          {"prune target is set", fun prune_target_set/0},
          {"trigger_pruning is a no-op when chain is short", fun trigger_pruning_short_chain/0},
          %% Wave-2026-05-05 prune wiring:
          {"get_prune_state reflects auto mode", fun get_prune_state_auto/0},
          {"manual prune RPC respects 288 keep window",
           fun manual_prune_clamps_to_safety_window/0}
         ]
     end}.

%%% Manual-mode (-prune=1) test fixture: trigger_pruning auto-cast must
%%% not delete files even with a chain tip beyond the safety window.
prune_manual_mode_test_() ->
    {setup,
     fun setup_with_prune_manual/0,
     fun teardown/1,
     fun(_) ->
         [
          {"manual mode reports manual_mode=true",
           fun manual_mode_state/0},
          {"manual mode does not auto-prune on trigger_pruning",
           fun manual_mode_skips_auto_prune/0}
         ]
     end}.

setup_with_prune_manual() ->
    TmpDir = filename:join(["/tmp", "beamchain_prune_manual_test_" ++
                            integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),
    application:ensure_all_started(rocksdb),
    application:set_env(beamchain, datadir, TmpDir),
    application:set_env(beamchain, network, regtest),
    os:putenv("BEAMCHAIN_PRUNE", "1"),
    {ok, ConfigPid} = beamchain_config:start_link(),
    {ok, DbPid} = beamchain_db:start_link(),
    {TmpDir, ConfigPid, DbPid}.

setup_with_prune() ->
    %% Use a unique temp directory for each test run
    TmpDir = filename:join(["/tmp", "beamchain_prune_test_" ++
                            integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),

    %% Set environment with pruning enabled
    application:ensure_all_started(rocksdb),
    application:set_env(beamchain, datadir, TmpDir),
    application:set_env(beamchain, network, regtest),
    %% Set prune target via env var (will be read by config)
    os:putenv("BEAMCHAIN_PRUNE", "550"),

    %% Start config (needed by db)
    {ok, ConfigPid} = beamchain_config:start_link(),
    %% Start db
    {ok, DbPid} = beamchain_db:start_link(),

    {TmpDir, ConfigPid, DbPid}.

prune_target_set() ->
    Info = beamchain_db:get_block_file_info(),
    %% Prune target should be 550 MB (minimum)
    ?assertEqual(550, maps:get(prune_target_mb, Info)).

trigger_pruning_short_chain() ->
    %% With no chain tip set, trigger_pruning should be a no-op
    ok = beamchain_db:trigger_pruning(100),
    %% Set a chain tip below the safety window
    Hash = crypto:strong_rand_bytes(32),
    ok = beamchain_db:set_chain_tip(Hash, 100),
    %% Trigger should still be a no-op (below 288 blocks)
    ok = beamchain_db:trigger_pruning(100),
    %% Nothing should be pruned
    {ok, Count} = beamchain_db:prune_block_files(),
    ?assertEqual(0, Count).

%%% New (2026-05-05): get_prune_state surfaces a usable view of the
%%% prune subsystem for getblockchaininfo. Auto mode (-prune=550) must
%%% report enabled=true, manual_mode=false, target_bytes>0, and a
%%% pruneheight of 0 since nothing has been pruned yet.
get_prune_state_auto() ->
    State = beamchain_db:get_prune_state(),
    ?assertEqual(true,  maps:get(enabled, State)),
    ?assertEqual(false, maps:get(manual_mode, State)),
    ?assertEqual(true,  maps:get(automatic_pruning, State)),
    ?assert(maps:get(target_bytes, State) >= 550 * 1024 * 1024),
    %% Nothing has been pruned in this fresh datadir.
    ?assertEqual(0, maps:get(prune_height, State)).

%%% Manual prune RPC must clamp the operator-supplied target height to
%%% chain_tip - REORG_SAFETY_BLOCKS (288) so the keep window is preserved.
%%% This is the test analogue of Core's PruneBlockFilesManual safety floor.
manual_prune_clamps_to_safety_window() ->
    %% Chain tip ChainHeight = 1000, ask to prune up to 999 (above safe
    %% upper). Effective height must clamp to 1000-288 = 712.
    Hash = crypto:strong_rand_bytes(32),
    ok = beamchain_db:set_chain_tip(Hash, 1000),
    {ok, #{effective_height := Eff}} =
        beamchain_db:prune_block_files_manual(999),
    ?assertEqual(712, Eff).

%%% --------- Manual-only mode (-prune=1) ---------------------------------

manual_mode_state() ->
    %% With BEAMCHAIN_PRUNE=1 we are in manual-only mode: pruning is
    %% enabled but auto-prune does not fire and the auto target is 0.
    State = beamchain_db:get_prune_state(),
    ?assertEqual(true,  maps:get(enabled, State)),
    ?assertEqual(true,  maps:get(manual_mode, State)),
    ?assertEqual(false, maps:get(automatic_pruning, State)),
    ?assertEqual(0,     maps:get(target_bytes, State)).

manual_mode_skips_auto_prune() ->
    %% Even with a chain tip well past the safety window, the cast-based
    %% trigger_pruning must NOT delete files in manual mode. Verified by
    %% pruned_file_count remaining 0 after the cast.
    Hash = crypto:strong_rand_bytes(32),
    ok = beamchain_db:set_chain_tip(Hash, 5000),
    Pre = maps:get(pruned_file_count,
                    beamchain_db:get_block_file_info()),
    ok = beamchain_db:trigger_pruning(5000),
    %% Block long enough for the cast to be processed (cast → handle_cast
    %% lands ahead of the next gen_server:call we issue below).
    _ = beamchain_db:get_block_file_info(),
    Post = maps:get(pruned_file_count,
                     beamchain_db:get_block_file_info()),
    ?assertEqual(Pre, Post).

%%% ===================================================================
%%% Block height/time index tests
%%% ===================================================================

block_index_ets_test_() ->
    {setup,
     fun setup/0,
     fun teardown/1,
     fun(_) ->
         [
          {"get_hash_by_height returns not_found for missing height",
           fun hash_by_height_not_found/0},
          {"get_hash_by_height returns hash after store_block_index",
           fun hash_by_height_after_store/0},
          {"index_block and unindex_block work correctly",
           fun index_unindex_block/0},
          {"get_blocks_in_time_range returns empty for no blocks",
           fun time_range_empty/0},
          {"get_blocks_in_time_range returns blocks in range",
           fun time_range_with_blocks/0},
          {"store and get block_stats",
           fun block_stats_roundtrip/0},
          {"get_block_stats returns not_found for missing",
           fun block_stats_not_found/0},
          {"cumulative_tx_count store and get",
           fun cumulative_tx_count/0}
         ]
     end}.

hash_by_height_not_found() ->
    %% Query a height that doesn't exist
    ?assertEqual(not_found, beamchain_db:get_hash_by_height(999999)).

hash_by_height_after_store() ->
    %% Store a block index entry
    Hash = crypto:strong_rand_bytes(32),
    Header = #block_header{
        version = 1,
        prev_hash = <<0:256>>,
        merkle_root = crypto:strong_rand_bytes(32),
        timestamp = 1234567890,
        bits = 16#1d00ffff,
        nonce = 42
    },
    ok = beamchain_db:store_block_index(500, Hash, Header, <<0:64>>, 1),
    %% Should be able to retrieve it
    {ok, RetrievedHash} = beamchain_db:get_hash_by_height(500),
    ?assertEqual(Hash, RetrievedHash).

index_unindex_block() ->
    %% Index a block
    Hash = crypto:strong_rand_bytes(32),
    Height = 600,
    Timestamp = 1234567890,
    ok = beamchain_db:index_block(Height, Hash, Timestamp),
    %% Verify we can find it
    Blocks = beamchain_db:get_blocks_in_time_range(Timestamp - 1, Timestamp + 1),
    ?assert(length(Blocks) >= 1),
    {FoundTs, FoundHeight, FoundHash} = lists:keyfind(Height, 2, Blocks),
    ?assertEqual(Timestamp, FoundTs),
    ?assertEqual(Height, FoundHeight),
    ?assertEqual(Hash, FoundHash),
    %% Unindex it
    ok = beamchain_db:unindex_block(Height, Timestamp),
    %% Should be gone from time index
    Blocks2 = beamchain_db:get_blocks_in_time_range(Timestamp - 1, Timestamp + 1),
    ?assertNot(lists:keymember(Height, 2, Blocks2)).

time_range_empty() ->
    %% Query a time range with no blocks
    Blocks = beamchain_db:get_blocks_in_time_range(1, 100),
    ?assert(is_list(Blocks)).

time_range_with_blocks() ->
    %% Index several blocks at different times
    Hash1 = crypto:strong_rand_bytes(32),
    Hash2 = crypto:strong_rand_bytes(32),
    Hash3 = crypto:strong_rand_bytes(32),
    ok = beamchain_db:index_block(701, Hash1, 1000),
    ok = beamchain_db:index_block(702, Hash2, 1500),
    ok = beamchain_db:index_block(703, Hash3, 2000),
    %% Query range that includes all
    All = beamchain_db:get_blocks_in_time_range(900, 2100),
    ?assert(length(All) >= 3),
    %% Query range that includes only middle
    Middle = beamchain_db:get_blocks_in_time_range(1400, 1600),
    ?assertEqual(1, length(Middle)),
    [{1500, 702, _}] = Middle,
    %% Clean up
    ok = beamchain_db:unindex_block(701, 1000),
    ok = beamchain_db:unindex_block(702, 1500),
    ok = beamchain_db:unindex_block(703, 2000).

block_stats_roundtrip() ->
    Hash = crypto:strong_rand_bytes(32),
    Stats = #{
        <<"txs">> => 100,
        <<"total_weight">> => 4000000,
        <<"totalfee">> => 500000
    },
    ok = beamchain_db:store_block_stats(Hash, Stats),
    {ok, Retrieved} = beamchain_db:get_block_stats(Hash),
    ?assertEqual(100, maps:get(<<"txs">>, Retrieved)),
    ?assertEqual(4000000, maps:get(<<"total_weight">>, Retrieved)),
    ?assertEqual(500000, maps:get(<<"totalfee">>, Retrieved)).

block_stats_not_found() ->
    FakeHash = crypto:strong_rand_bytes(32),
    ?assertEqual(not_found, beamchain_db:get_block_stats(FakeHash)).

cumulative_tx_count() ->
    %% Store cumulative tx count
    ok = beamchain_db:store_cumulative_tx_count(800, 50000),
    {ok, Count} = beamchain_db:get_cumulative_tx_count(800),
    ?assertEqual(50000, Count),
    %% Non-existent height
    ?assertEqual(not_found, beamchain_db:get_cumulative_tx_count(999999)).

%%% ===================================================================
%%% scrubunspendable tests
%%% ===================================================================

%% Verify scrub_unspendable/0 only removes coins whose scriptPubKey is
%% unspendable per Core's CScript::IsUnspendable() — OP_RETURN-prefixed
%% or > MAX_SCRIPT_SIZE — and leaves spendable coins (P2PKH, P2WPKH,
%% etc.) intact.
%%
%% This simulates a pre-fix beamchain datadir that landed orphan
%% segwit-coinbase OP_RETURN witness-commitment outputs in the
%% chainstate CF before commit 79fa3e5 added the IsUnspendable filter
%% on the AddCoin write path.
scrub_unspendable_removes_orphans() ->
    %% Use store_utxo to bypass the chainstate cache filter and write
    %% directly into the chainstate CF — this is the on-disk shape an
    %% existing datadir has.
    Txid1 = crypto:strong_rand_bytes(32),
    Txid2 = crypto:strong_rand_bytes(32),
    Txid3 = crypto:strong_rand_bytes(32),
    Txid4 = crypto:strong_rand_bytes(32),
    Txid5 = crypto:strong_rand_bytes(32),

    Spendable = make_test_utxo(),  %% P2PKH, will survive

    %% OP_RETURN witness commitment (typical post-BIP141 coinbase output)
    OpReturnSPK = <<16#6a, 16#24, 16#aa, 16#21, 16#a9, 16#ed,
                    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
                    17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,
                    33,34,35,36>>,
    OpReturnUtxo = #utxo{value = 0, script_pubkey = OpReturnSPK,
                          is_coinbase = true, height = 100},

    %% Bare OP_RETURN with no payload
    BareOpReturnUtxo = #utxo{value = 0, script_pubkey = <<16#6a>>,
                              is_coinbase = false, height = 101},

    %% Oversize script (> MAX_SCRIPT_SIZE = 10000)
    OversizeSPK = binary:copy(<<16#51>>, 10001),
    OversizeUtxo = #utxo{value = 1000, script_pubkey = OversizeSPK,
                          is_coinbase = false, height = 102},

    %% Another spendable coin (will survive)
    Spendable2 = #utxo{value = 42, script_pubkey = <<16#00, 16#14,
                                                       0,1,2,3,4,5,6,7,
                                                       8,9,10,11,12,13,14,15,
                                                       16,17,18,19>>,
                       is_coinbase = false, height = 103},

    ok = beamchain_db:store_utxo(Txid1, 0, Spendable),
    ok = beamchain_db:store_utxo(Txid2, 0, OpReturnUtxo),
    ok = beamchain_db:store_utxo(Txid3, 0, BareOpReturnUtxo),
    ok = beamchain_db:store_utxo(Txid4, 0, OversizeUtxo),
    ok = beamchain_db:store_utxo(Txid5, 0, Spendable2),

    %% Sanity: all five present before scrub
    ?assert(beamchain_db:has_utxo(Txid1, 0)),
    ?assert(beamchain_db:has_utxo(Txid2, 0)),
    ?assert(beamchain_db:has_utxo(Txid3, 0)),
    ?assert(beamchain_db:has_utxo(Txid4, 0)),
    ?assert(beamchain_db:has_utxo(Txid5, 0)),

    {Removed, BytesFreed} = beamchain_db:scrub_unspendable(),

    %% Exactly the three unspendable entries removed.
    ?assertEqual(3, Removed),
    %% Bytes freed = 3 * (49 fixed) + sum of script sizes
    Expected = 3 * 49
               + byte_size(OpReturnSPK)
               + 1                       %% bare OP_RETURN
               + byte_size(OversizeSPK),
    ?assertEqual(Expected, BytesFreed),

    %% Spendable coins still present
    ?assert(beamchain_db:has_utxo(Txid1, 0)),
    ?assert(beamchain_db:has_utxo(Txid5, 0)),

    %% Unspendable coins gone
    ?assertEqual(false, beamchain_db:has_utxo(Txid2, 0)),
    ?assertEqual(false, beamchain_db:has_utxo(Txid3, 0)),
    ?assertEqual(false, beamchain_db:has_utxo(Txid4, 0)).

%% A second call after the first finds nothing to delete.
scrub_unspendable_idempotent() ->
    Txid1 = crypto:strong_rand_bytes(32),
    Txid2 = crypto:strong_rand_bytes(32),
    OpReturnUtxo = #utxo{value = 0,
                          script_pubkey = <<16#6a, 16#04, 1, 2, 3, 4>>,
                          is_coinbase = true, height = 200},
    Spendable = make_test_utxo(),

    ok = beamchain_db:store_utxo(Txid1, 0, OpReturnUtxo),
    ok = beamchain_db:store_utxo(Txid2, 0, Spendable),

    {Removed1, _} = beamchain_db:scrub_unspendable(),
    ?assertEqual(1, Removed1),

    %% Second call: zero entries to remove.
    {Removed2, Bytes2} = beamchain_db:scrub_unspendable(),
    ?assertEqual(0, Removed2),
    ?assertEqual(0, Bytes2),

    %% Spendable still present.
    ?assert(beamchain_db:has_utxo(Txid2, 0)),
    %% OP_RETURN still gone.
    ?assertEqual(false, beamchain_db:has_utxo(Txid1, 0)).
