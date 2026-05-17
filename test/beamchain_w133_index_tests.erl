-module(beamchain_w133_index_tests).

%% W133 Index databases — txindex + coinstatsindex audit (beamchain).
%%
%% Reference: bitcoin-core/src/index/base.{h,cpp},
%%            bitcoin-core/src/index/txindex.{h,cpp},
%%            bitcoin-core/src/index/coinstatsindex.{h,cpp},
%%            bitcoin-core/src/index/disktxpos.h,
%%            bitcoin-core/src/index/db_key.h.
%%
%% Scope (audit/w133_index_databases.md): 30 gates, 24 BUGs
%% (0 CDIV / 6 HIGH / 11 MEDIUM / 7 LOW).
%%
%% Audit-flip: every test below asserts the current (divergent) behavior
%% so it PASSES today; a follow-up FIX wave that brings the implementation
%% into parity will flip these PASS -> FAIL.

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

%%% ===================================================================
%%% Source-path helpers (mirrors FIX-66 / W129 convention)
%%% ===================================================================

beamchain_src_dir() ->
    Beam = code:which(beamchain_db),
    case Beam of
        non_existing -> "src";
        _ ->
            Ebin = filename:dirname(Beam),
            Lib  = filename:dirname(Ebin),
            Src  = filename:join([Lib, "src"]),
            case filelib:is_dir(Src) of
                true -> Src;
                false -> "src"
            end
    end.

beamchain_db_src()         -> filename:join(beamchain_src_dir(), "beamchain_db.erl").
beamchain_block_sync_src() -> filename:join(beamchain_src_dir(), "beamchain_block_sync.erl").
beamchain_chainstate_src() -> filename:join(beamchain_src_dir(), "beamchain_chainstate.erl").
beamchain_rpc_src()        -> filename:join(beamchain_src_dir(), "beamchain_rpc.erl").
beamchain_rest_src()       -> filename:join(beamchain_src_dir(), "beamchain_rest.erl").
beamchain_config_src()     -> filename:join(beamchain_src_dir(), "beamchain_config.erl").
beamchain_blockfilter_index_src() ->
    filename:join(beamchain_src_dir(), "beamchain_blockfilter_index.erl").

read_src(Path) ->
    case file:read_file(Path) of
        {ok, Bin} -> Bin;
        {error, _} -> <<>>
    end.

%%% ===================================================================
%%% G1 — BUG-1: No `BaseIndex` shared abstraction
%%% ===================================================================

g1_no_base_index_abstraction_test_() ->
    {"G1: BUG-1 (HIGH) — beamchain has no shared base-index "
     "behaviour. blockfilter_index is bespoke; tx_index is inline. "
     "A coinstatsindex would re-derive the scaffolding a third time.",
     [
      ?_test(begin
         %% No beamchain_base_index module exists.
         ?assertEqual(non_existing, code:which(beamchain_base_index)),
         %% blockfilter_index is its own gen_server with no -behaviour
         %% line that points at a shared base.
         Src = read_src(beamchain_blockfilter_index_src()),
         ?assertNotEqual(nomatch, binary:match(Src, <<"-behaviour(gen_server)">>)),
         ?assertEqual(nomatch, binary:match(Src, <<"-behaviour(beamchain_base_index)">>))
       end)
     ]}.

%%% ===================================================================
%%% G2 — BUG-2: No coinstatsindex
%%% ===================================================================

g2_no_coinstatsindex_test_() ->
    {"G2: BUG-2 (HIGH) — coinstatsindex absent. gettxoutsetinfo walks "
     "the full UTXO CF on every call instead of doing an O(1) per-height "
     "lookup.",
     [
      ?_test(begin
         ?assertEqual(non_existing, code:which(beamchain_coinstatsindex)),
         ?assertEqual(non_existing, code:which(beamchain_coin_stats_index)),
         %% gettxoutsetinfo path in beamchain_rpc walks utxos via
         %% beamchain_db:fold_utxos, not a per-height index read.
         RpcSrc = read_src(beamchain_rpc_src()),
         ?assertNotEqual(nomatch, binary:match(RpcSrc, <<"fold_utxos">>)),
         %% No LookUpStats analog
         ?assertEqual(nomatch, binary:match(RpcSrc, <<"lookup_stats">>)),
         ?assertEqual(nomatch, binary:match(RpcSrc, <<"LookUpStats">>))
       end)
     ]}.

%%% ===================================================================
%%% G3 — BUG-3: txindex stores logical Position, not CDiskTxPos
%%% ===================================================================

g3_txindex_stores_logical_position_test_() ->
    {"G3: BUG-3 (HIGH) — tx_index value is "
     "<BlockHash:32, Height:64/big, Position:32/big> (logical index in "
     "vtx). Core stores CDiskTxPos {nFile, nPos, nTxOffset}.",
     [
      ?_test(begin
         DbSrc = read_src(beamchain_db_src()),
         %% Confirm the literal binary template used to encode tx_index
         %% values in beamchain_db.erl handle_call.
         Pattern = <<"<<BlockHash:32/binary, Height:64/big, "
                     "Position:32/big>>">>,
         ?assertNotEqual(nomatch, binary:match(DbSrc, Pattern)),
         %% No file_number / nTxOffset / data_pos terms appear in
         %% beamchain_db.erl in the tx_index code path.
         ?assertEqual(nomatch, binary:match(DbSrc, <<"nTxOffset">>)),
         ?assertEqual(nomatch, binary:match(DbSrc, <<"CDiskTxPos">>)),
         ?assertEqual(nomatch, binary:match(DbSrc, <<"disktxpos">>))
       end)
     ]}.

%%% ===================================================================
%%% G4 — BUG-4: No remove_tx_index on disconnect/reorg
%%% ===================================================================

g4_no_remove_tx_index_on_disconnect_test_() ->
    {"G4: BUG-4 (HIGH) — do_disconnect_block never deletes tx_index "
     "rows for the disconnected block. Read-time filter via "
     "is_block_in_active_chain is a partial Pattern-C1 workaround.",
     [
      ?_test(begin
         %% No remove_tx_index export on beamchain_db.
         _ = beamchain_db:module_info(exports),
         %% Walk and assert the export list is missing the remover.
         Exports = beamchain_db:module_info(exports),
         ?assertNot(lists:member({remove_tx_index, 1}, Exports)),
         ?assertNot(lists:member({delete_tx_index, 1}, Exports)),
         ?assertNot(lists:member({remove_tx_index, 2}, Exports)),
         %% do_disconnect_block in chainstate references blockfilter
         %% remove_block (correct) but not tx_index remove (BUG-4).
         CsSrc = read_src(beamchain_chainstate_src()),
         ?assertNotEqual(nomatch,
             binary:match(CsSrc, <<"beamchain_blockfilter_index:remove_block">>)),
         ?assertEqual(nomatch,
             binary:match(CsSrc, <<"remove_tx_index">>)),
         ?assertEqual(nomatch,
             binary:match(CsSrc, <<"delete_tx_index">>))
       end)
     ]}.

%%% ===================================================================
%%% G5 — BUG-5: No block locator persisted for tx_index
%%% ===================================================================

g5_no_locator_persisted_test_() ->
    {"G5: BUG-5 (HIGH) — tx_index has no CBlockLocator-equivalent. "
     "Cold-start cannot distinguish 'caught up' from 'mid-block crash'. "
     "Core writes DB_BEST_BLOCK in base.cpp:90-93.",
     [
      ?_test(begin
         DbSrc = read_src(beamchain_db_src()),
         %% No DB_BEST_BLOCK or write_best_block in tx_index path.
         ?assertEqual(nomatch, binary:match(DbSrc, <<"DB_BEST_BLOCK">>)),
         ?assertEqual(nomatch, binary:match(DbSrc, <<"write_best_block">>)),
         ?assertEqual(nomatch, binary:match(DbSrc, <<"index_locator">>)),
         %% No tx_index-specific tip/locator helpers either.
         Exports = beamchain_db:module_info(exports),
         ?assertNot(lists:member({tx_index_tip, 0}, Exports)),
         ?assertNot(lists:member({get_tx_index_locator, 0}, Exports))
       end)
     ]}.

%%% ===================================================================
%%% G6 — BUG-6: Genesis coinbase indexed in beamchain
%%% ===================================================================

g6_genesis_coinbase_indexed_test_() ->
    {"G6: BUG-6 (HIGH) — store_tx_index has no height-zero exception. "
     "Core skips at txindex.cpp:77 ('if (block.height == 0) return true').",
     [
      ?_test(begin
         BsSrc = read_src(beamchain_block_sync_src()),
         %% The store_tx_index function in block_sync.erl unconditionally
         %% iterates txs without a height guard.
         %% Match the function head + immediate case-clause structure.
         ?assertNotEqual(nomatch,
             binary:match(BsSrc,
                 <<"store_tx_index(#block{header = Header, "
                   "transactions = Txs}, Height) ->">>)),
         %% No "Height =/= 0" or "Height > 0" guard around the lists:foldl.
         %% Extract the function body window starting at the function head
         %% so we can grep for guards locally without false positives from
         %% unrelated code earlier or later in the file.
         Tail = case binary:match(BsSrc, <<"store_tx_index(#block">>) of
             {Start, _Len} ->
                 binary:part(BsSrc, Start,
                             min(800, byte_size(BsSrc) - Start));
             nomatch -> <<>>
         end,
         ?assertEqual(nomatch, binary:match(Tail, <<"Height > 0">>)),
         ?assertEqual(nomatch, binary:match(Tail, <<"Height =/= 0">>)),
         ?assertEqual(nomatch, binary:match(Tail, <<"Height /= 0">>))
       end)
     ]}.

%%% ===================================================================
%%% G7 — BUG-7: No background sync thread for tx_index
%%% ===================================================================

g7_no_background_sync_thread_test_() ->
    {"G7: BUG-7 (MEDIUM) — tx_index has no Sync()/m_thread_sync "
     "background thread. Indexing happens inline during block-connect.",
     [
      ?_test(begin
         DbSrc = read_src(beamchain_db_src()),
         %% No spawn or process_flag terms in tx_index code path
         %% (beamchain_db is a gen_server but has no separate sync
         %% thread for tx_index).
         %% The store_tx_index code path uses synchronous gen_server:call.
         ?assertNotEqual(nomatch,
             binary:match(DbSrc, <<"gen_server:call(?SERVER, "
                                   "{store_tx_index">>)),
         %% No "sync_index" / "background_sync" terms in db.
         ?assertEqual(nomatch, binary:match(DbSrc, <<"sync_index">>)),
         ?assertEqual(nomatch, binary:match(DbSrc, <<"background_sync">>)),
         %% Confirm we don't accidentally spawn a sync worker.
         BsSrc = read_src(beamchain_block_sync_src()),
         %% store_tx_index is called synchronously from block-connect.
         ?assertNotEqual(nomatch,
             binary:match(BsSrc, <<"store_tx_index(Block, Height)">>)),
         %% No proc_lib:spawn_link nor erlang:spawn for tx_index path.
         ?assertEqual(nomatch,
             binary:match(BsSrc, <<"spawn(fun store_tx_index">>)),
         ?assertEqual(nomatch,
             binary:match(BsSrc, <<"spawn_link(fun store_tx_index">>))
       end)
     ]}.

%%% ===================================================================
%%% G8 — BUG-8: No BlockUntilSyncedToCurrentChain handshake
%%% ===================================================================

g8_no_block_until_synced_test_() ->
    {"G8: BUG-8 (MEDIUM) — no BlockUntilSyncedToCurrentChain "
     "equivalent. Callers cannot wait for tx_index to catch up before "
     "querying.",
     [
      ?_test(begin
         %% Search across all major modules for the API name.
         AllSrcs = [
             read_src(beamchain_db_src()),
             read_src(beamchain_rpc_src()),
             read_src(beamchain_rest_src()),
             read_src(beamchain_chainstate_src())
         ],
         lists:foreach(fun(Src) ->
             ?assertEqual(nomatch,
                 binary:match(Src, <<"block_until_synced">>)),
             ?assertEqual(nomatch,
                 binary:match(Src, <<"BlockUntilSyncedToCurrentChain">>)),
             ?assertEqual(nomatch,
                 binary:match(Src, <<"wait_for_index_sync">>))
         end, AllSrcs)
       end)
     ]}.

%%% ===================================================================
%%% G9 — BUG-9: No getindexinfo RPC
%%% ===================================================================

g9_no_getindexinfo_rpc_test_() ->
    {"G9: BUG-9 (MEDIUM) — getindexinfo RPC not implemented. "
     "Monitoring scripts cannot probe txindex status.",
     [
      ?_test(begin
         RpcSrc = read_src(beamchain_rpc_src()),
         %% The handle_method dispatcher has rows like
         %%   handle_method(<<"getblock">>, ...) -> ...
         %% Verify <<"getindexinfo">> is NOT one of them.
         ?assertEqual(nomatch,
             binary:match(RpcSrc,
                 <<"handle_method(<<\"getindexinfo\">>">>)),
         ?assertEqual(nomatch, binary:match(RpcSrc, <<"getindexinfo">>))
       end)
     ]}.

%%% ===================================================================
%%% G10 — BUG-10: No IndexSummary struct
%%% ===================================================================

g10_no_index_summary_struct_test_() ->
    {"G10: BUG-10 (MEDIUM) — no IndexSummary equivalent. Even if "
     "getindexinfo were added there's no record to populate from.",
     [
      ?_test(begin
         AllSrcs = [
             read_src(beamchain_db_src()),
             read_src(beamchain_rpc_src()),
             read_src(beamchain_chainstate_src())
         ],
         lists:foreach(fun(Src) ->
             ?assertEqual(nomatch,
                 binary:match(Src, <<"index_summary">>)),
             ?assertEqual(nomatch,
                 binary:match(Src, <<"IndexSummary">>))
         end, AllSrcs),
         %% No record `index_summary` defined in any module.
         ?assertEqual(nomatch,
             binary:match(read_src(beamchain_blockfilter_index_src()),
                          <<"-record(index_summary">>))
       end)
     ]}.

%%% ===================================================================
%%% G11 — BUG-11: No prune lock interaction for tx_index
%%% ===================================================================

g11_no_prune_lock_for_tx_index_test_() ->
    {"G11: BUG-11 (MEDIUM) — tx_index never holds a prune lock. "
     "Pruner can delete blocks tx_index still needs for "
     "get_tx_location's full-block read path.",
     [
      ?_test(begin
         DbSrc = read_src(beamchain_db_src()),
         %% No update_prune_lock / prune_lock_for_index helpers.
         ?assertEqual(nomatch, binary:match(DbSrc, <<"prune_lock_for_index">>)),
         ?assertEqual(nomatch, binary:match(DbSrc, <<"UpdatePruneLock">>)),
         %% prune_block_files only checks REORG_SAFETY_BLOCKS, not per-index needs.
         ?assertNotEqual(nomatch,
             binary:match(DbSrc, <<"REORG_SAFETY_BLOCKS">>)),
         ?assertEqual(nomatch,
             binary:match(DbSrc, <<"tx_index_prune_height">>))
       end)
     ]}.

%%% ===================================================================
%%% G12 — BUG-12: No AllowPrune() per-index policy
%%% ===================================================================

g12_no_allow_prune_per_index_test_() ->
    {"G12: BUG-12 (MEDIUM) — no AllowPrune() per index policy. "
     "Core: txindex=false, coinstatsindex=true.",
     [
      ?_test(begin
         AllSrcs = [
             read_src(beamchain_db_src()),
             read_src(beamchain_blockfilter_index_src())
         ],
         lists:foreach(fun(Src) ->
             ?assertEqual(nomatch, binary:match(Src, <<"allow_prune">>)),
             ?assertEqual(nomatch, binary:match(Src, <<"AllowPrune">>))
         end, AllSrcs)
       end)
     ]}.

%%% ===================================================================
%%% G13 — BUG-13: No CustomInit consistency check
%%% ===================================================================

g13_no_custom_init_consistency_test_() ->
    {"G13: BUG-13 (MEDIUM) — no CustomInit consistency check. "
     "coinstatsindex absent → no DB_MUHASH-vs-in-memory probe at "
     "start-up.",
     [
      ?_test(begin
         %% Searching for the literal Core idiom "DB_MUHASH" in any
         %% beamchain source must return nothing (the only mentions of
         %% muhash in beamchain are the gettxoutsetinfo on-demand walk).
         AllSrcs = [
             read_src(beamchain_db_src()),
             read_src(beamchain_rpc_src()),
             read_src(beamchain_chainstate_src())
         ],
         lists:foreach(fun(Src) ->
             ?assertEqual(nomatch, binary:match(Src, <<"DB_MUHASH">>))
         end, AllSrcs)
       end)
     ]}.

%%% ===================================================================
%%% G14 — BUG-14: No CustomCommit atomic batch of muhash + best block
%%% ===================================================================

g14_no_custom_commit_atomic_batch_test_() ->
    {"G14: BUG-14 (MEDIUM) — no atomic-batch commit of muhash with "
     "best-block locator. Moot until coinstatsindex exists.",
     [
      ?_test(begin
         ?assertEqual(non_existing, code:which(beamchain_coinstatsindex)),
         %% Verify the absence of a Commit-style batched write for any
         %% per-block muhash state in blockfilter_index either.
         BfSrc = read_src(beamchain_blockfilter_index_src()),
         ?assertEqual(nomatch, binary:match(BfSrc, <<"custom_commit">>))
       end)
     ]}.

%%% ===================================================================
%%% G15 — BUG-15: No connect_undo_data flag awareness
%%% ===================================================================

g15_no_connect_undo_data_flag_test_() ->
    {"G15: BUG-15 (MEDIUM) — index-side has no connect_undo_data / "
     "disconnect_undo_data option. coinstatsindex (if added) would have "
     "to re-fetch undo data from disk per block.",
     [
      ?_test(begin
         AllSrcs = [
             read_src(beamchain_db_src()),
             read_src(beamchain_chainstate_src()),
             read_src(beamchain_blockfilter_index_src())
         ],
         lists:foreach(fun(Src) ->
             ?assertEqual(nomatch,
                 binary:match(Src, <<"connect_undo_data">>)),
             ?assertEqual(nomatch,
                 binary:match(Src, <<"disconnect_undo_data">>))
         end, AllSrcs)
       end)
     ]}.

%%% ===================================================================
%%% G16 — BUG-16: No DBHeightKey big-endian for ordered scans
%%% ===================================================================

g16_no_dbheightkey_be_ordering_test_() ->
    {"G16: BUG-16 (MEDIUM) — tx_index keyed by raw txid; no height-keyed "
     "secondary index. Height-range scans impossible.",
     [
      ?_test(begin
         DbSrc = read_src(beamchain_db_src()),
         %% The tx_index put uses Key=Txid (not Height).
         %% Match the put call directly.
         ?assertNotEqual(nomatch,
             binary:match(DbSrc, <<"rocksdb:put(Db, CF, Txid, Value, [])">>)),
         %% No DBHeightKey-equivalent helper.
         ?assertEqual(nomatch, binary:match(DbSrc, <<"DBHeightKey">>)),
         ?assertEqual(nomatch, binary:match(DbSrc, <<"db_height_key">>))
       end)
     ]}.

%%% ===================================================================
%%% G17 — BUG-17: No DBHashKey fork-fallback on reorg
%%% ===================================================================

g17_no_dbhashkey_fork_fallback_test_() ->
    {"G17: BUG-17 (MEDIUM) — no CopyHeightIndexToHashIndex equivalent. "
     "Core uses this in coinstatsindex.cpp:222-225 on reorg. beamchain "
     "has no analog because no per-height MuHash exists.",
     [
      ?_test(begin
         AllSrcs = [
             read_src(beamchain_db_src()),
             read_src(beamchain_blockfilter_index_src()),
             read_src(beamchain_chainstate_src())
         ],
         lists:foreach(fun(Src) ->
             ?assertEqual(nomatch, binary:match(Src, <<"DBHashKey">>)),
             ?assertEqual(nomatch,
                 binary:match(Src, <<"copy_height_to_hash">>))
         end, AllSrcs)
       end)
     ]}.

%%% ===================================================================
%%% G18 — BUG-18: No assumeUTXO interaction
%%% ===================================================================

g18_no_assumeutxo_interaction_test_() ->
    {"G18: BUG-18 (MEDIUM) — tx_index unaware of assumeUTXO state. "
     "On a snapshot load the foreground block-connect path would index "
     "snapshot tip's descendants only.",
     [
      ?_test(begin
         %% W102 added assumeUTXO support in chainstate; verify tx_index
         %% paths don't check the chainstate role.
         BsSrc = read_src(beamchain_block_sync_src()),
         %% store_tx_index has no assumeUTXO role check.
         ?assertEqual(nomatch,
             binary:match(BsSrc, <<"chainstate_role">>)),
         ?assertEqual(nomatch,
             binary:match(BsSrc, <<"is_background_chainstate">>)),
         ?assertEqual(nomatch,
             binary:match(BsSrc, <<"assumeutxo_active">>))
       end)
     ]}.

%%% ===================================================================
%%% G19 — BUG-19 (LOW): txindex enabled by default
%%% ===================================================================

g19_txindex_default_enabled_test_() ->
    {"G19: BUG-19 (LOW) — beamchain defaults txindex to ENABLED. "
     "Core defaults to DISABLED (DEFAULT_TXINDEX=false in txindex.h:19).",
     [
      ?_test(begin
         %% Set the env explicitly absent.
         os:unsetenv("BEAMCHAIN_TXINDEX"),
         %% Note: beamchain_config:get/2 falls back to the proc-dict
         %% default; the code reads `get(txindex, "1")` so a fresh
         %% process sees txindex enabled.
         %% Test by source-level inspection rather than runtime startup.
         CfgSrc = read_src(beamchain_config_src()),
         ?assertNotEqual(nomatch,
             binary:match(CfgSrc, <<"get(txindex, \"1\")">>)),
         %% Core-parity would be `get(txindex, "0")`.
         ?assertEqual(nomatch,
             binary:match(CfgSrc, <<"get(txindex, \"0\")">>))
       end)
     ]}.

%%% ===================================================================
%%% G20 — BUG-20: No f_obfuscate on index DB
%%% ===================================================================

g20_no_f_obfuscate_test_() ->
    {"G20: BUG-20 (LOW) — no per-index obfuscate flag. Core uses "
     "f_obfuscate so on-disk index bytes don't trip antivirus on "
     "coinbase strings.",
     [
      ?_test(begin
         DbSrc = read_src(beamchain_db_src()),
         BfSrc = read_src(beamchain_blockfilter_index_src()),
         ?assertEqual(nomatch, binary:match(DbSrc, <<"obfuscate">>)),
         ?assertEqual(nomatch, binary:match(BfSrc, <<"obfuscate">>))
       end)
     ]}.

%%% ===================================================================
%%% G21 — BUG-21: tx_index CF shares main RocksDB
%%% ===================================================================

g21_tx_index_shares_main_rocksdb_test_() ->
    {"G21: BUG-21 (LOW) — tx_index is a column family of the main "
     "RocksDB. Core gives each index its own indexes/<name>/ folder.",
     [
      ?_test(begin
         DbSrc = read_src(beamchain_db_src()),
         %% Confirm tx_index CF is declared in the main DB's CFDescriptors.
         ?assertNotEqual(nomatch, binary:match(DbSrc, <<"?CF_TX_INDEX">>)),
         ?assertNotEqual(nomatch,
             binary:match(DbSrc, <<"-define(CF_TX_INDEX, \"tx_index\").">>)),
         %% No "indexes/txindex" path string anywhere.
         AllSrcs = [DbSrc,
                    read_src(beamchain_chainstate_src()),
                    read_src(beamchain_rpc_src())],
         lists:foreach(fun(S) ->
             ?assertEqual(nomatch, binary:match(S, <<"indexes/txindex">>))
         end, AllSrcs)
       end)
     ]}.

%%% ===================================================================
%%% G22 — BUG-22: FindTx-equivalent loads the full block
%%% ===================================================================

g22_findtx_loads_full_block_test_() ->
    {"G22: BUG-22 (LOW) — get_tx_location returns a location; the "
     "caller then calls beamchain_db:get_block(BlockHash) and walks "
     "the full vtx via lists:nth/2. No per-tx seek.",
     [
      ?_test(begin
         RestSrc = read_src(beamchain_rest_src()),
         RpcSrc  = read_src(beamchain_rpc_src()),
         %% rest path: get_tx_location -> get_block -> lists:nth(Pos+1, Txs)
         ?assertNotEqual(nomatch,
             binary:match(RestSrc,
                 <<"beamchain_db:get_tx_location(Txid)">>)),
         ?assertNotEqual(nomatch,
             binary:match(RestSrc, <<"beamchain_db:get_block(BlockHash)">>)),
         ?assertNotEqual(nomatch,
             binary:match(RestSrc, <<"lists:nth(Pos + 1, Txs)">>)),
         %% rpc path: find_transaction does the same.
         ?assertNotEqual(nomatch,
             binary:match(RpcSrc, <<"beamchain_db:get_tx_location(Txid)">>)),
         %% No "seek_to_tx" / "read_tx_at" helper.
         ?assertEqual(nomatch, binary:match(RpcSrc, <<"seek_to_tx">>)),
         ?assertEqual(nomatch, binary:match(RestSrc, <<"seek_to_tx">>))
       end)
     ]}.

%%% ===================================================================
%%% G23 — BUG-23: No legacy indexes/coinstats migration warning
%%% ===================================================================

g23_no_legacy_coinstats_migration_test_() ->
    {"G23: BUG-23 (LOW) — coinstatsindex absent; no migration courtesy "
     "for a future on-disk layout v2.",
     [
      ?_test(begin
         %% A future coinstatsindex should imitate Core's
         %% coinstatsindex.cpp:97-101 ('indexes/coinstats' legacy warning).
         ?assertEqual(non_existing, code:which(beamchain_coinstatsindex)),
         %% No legacy-path string anywhere.
         AllSrcs = [
             read_src(beamchain_db_src()),
             read_src(beamchain_rpc_src()),
             read_src(beamchain_chainstate_src())
         ],
         lists:foreach(fun(Src) ->
             ?assertEqual(nomatch,
                 binary:match(Src, <<"indexes/coinstats">>))
         end, AllSrcs)
       end)
     ]}.

%%% ===================================================================
%%% G24 — BUG-24: No BlockInfo-style shared decoded artifacts
%%% ===================================================================

g24_no_blockinfo_shared_artifact_test_() ->
    {"G24: BUG-24 (LOW) — no BlockInfo-equivalent passes decoded block "
     "+ undo data to per-index hooks. store_tx_index DOES reuse the "
     "decoded block (good!), but a future coinstatsindex would re-read "
     "undo data because there's no shared artifact.",
     [
      ?_test(begin
         BsSrc = read_src(beamchain_block_sync_src()),
         %% store_tx_index takes #block{} (decoded) — that's good.
         ?assertNotEqual(nomatch,
             binary:match(BsSrc, <<"store_tx_index(#block">>)),
         %% But there's no BlockInfo wrapper carrying both block + undo.
         ?assertEqual(nomatch, binary:match(BsSrc, <<"block_info">>)),
         ?assertEqual(nomatch, binary:match(BsSrc, <<"-record(block_info">>))
       end)
     ]}.

%%% ===================================================================
%%% G25 — SYNC_LOCATOR_WRITE_INTERVAL cadence absent
%%% ===================================================================

g25_no_locator_write_interval_test_() ->
    {"G25: confirms the absence of any 30s locator-write cadence "
     "(Core base.cpp:50 SYNC_LOCATOR_WRITE_INTERVAL). Per BUG-16 this "
     "is moot until BUG-5 (no locator) is fixed.",
     [
      ?_test(begin
         AllSrcs = [
             read_src(beamchain_db_src()),
             read_src(beamchain_blockfilter_index_src()),
             read_src(beamchain_chainstate_src())
         ],
         lists:foreach(fun(Src) ->
             ?assertEqual(nomatch,
                 binary:match(Src, <<"SYNC_LOCATOR_WRITE_INTERVAL">>)),
             ?assertEqual(nomatch,
                 binary:match(Src, <<"locator_write_interval">>))
         end, AllSrcs)
       end)
     ]}.

%%% ===================================================================
%%% G26 — PARTIAL: txindex default semantics
%%% ===================================================================

g26_txindex_default_partial_test_() ->
    {"G26: PARTIAL — txindex_enabled/0 honors env + config but the "
     "DEFAULT is flipped vs Core. Confirms the surface integration is "
     "PARTIAL (not MISSING) — only the default differs.",
     [
      ?_test(begin
         CfgSrc = read_src(beamchain_config_src()),
         %% txindex_enabled/0 reads BEAMCHAIN_TXINDEX env first,
         %% then config dict.
         ?assertNotEqual(nomatch,
             binary:match(CfgSrc, <<"os:getenv(\"BEAMCHAIN_TXINDEX\")">>)),
         ?assertNotEqual(nomatch,
             binary:match(CfgSrc, <<"get(txindex,">>)),
         %% Defaults to enabled (BUG-19 surface). Source-level check
         %% only — beamchain_config:txindex_enabled/0 depends on the
         %% ?CONFIG_TABLE ETS table which is owned by the config
         %% gen_server (not started in this EUnit run).
         %% The string-match assertions above already pin the default to "1".
         _ = os:unsetenv("BEAMCHAIN_TXINDEX")
       end)
     ]}.

%%% ===================================================================
%%% G27 — PARTIAL: tx_index CF in main DB
%%% ===================================================================

g27_tx_index_cf_in_main_db_partial_test_() ->
    {"G27: PARTIAL — tx_index CF is co-located with chainstate in the "
     "main RocksDB. Performance-OK, ops-regression (no per-index "
     "wipe-and-rebuild without nuking chainstate too).",
     [
      ?_test(begin
         DbSrc = read_src(beamchain_db_src()),
         %% CF descriptors list includes ?CF_TX_INDEX next to ?CF_CHAINSTATE.
         ?assertNotEqual(nomatch,
             binary:match(DbSrc, <<"?CF_TX_INDEX">>)),
         ?assertNotEqual(nomatch,
             binary:match(DbSrc, <<"?CF_CHAINSTATE">>)),
         %% No standalone DB open for tx_index.
         ?assertEqual(nomatch, binary:match(DbSrc, <<"indexes/txindex">>))
       end)
     ]}.

%%% ===================================================================
%%% G28 — PARTIAL: FindTx semantics differ
%%% ===================================================================

g28_findtx_semantics_partial_test_() ->
    {"G28: PARTIAL — get_tx_location returns sufficient data to find "
     "the tx, but the caller does the heavy lifting (load block + walk "
     "vtx) instead of a direct disk seek.",
     [
      ?_test(begin
         DbSrc = read_src(beamchain_db_src()),
         %% Confirm get_tx_location's return type structure: %{block_hash,
         %% height, position}.
         ?assertNotEqual(nomatch,
             binary:match(DbSrc, <<"{ok, #{block_hash => BlockHash">>)),
         %% No nFile / nPos style fields.
         ?assertEqual(nomatch, binary:match(DbSrc, <<"file_num">>)),
         ?assertEqual(nomatch, binary:match(DbSrc, <<"data_pos">>))
       end)
     ]}.

%%% ===================================================================
%%% G29 — PRESENT: atomic_connect_writes coalesces block + idx + tx_index
%%% ===================================================================

g29_atomic_connect_writes_present_test_() ->
    {"G29: PRESENT — atomic_connect_writes batches block + block_index + "
     "tx_index in one RocksDB WriteBatch. This is BETTER than Core's "
     "split commits but the rollback symmetry is BUG-4 (no remove on "
     "disconnect).",
     [
      ?_test(begin
         DbSrc = read_src(beamchain_db_src()),
         %% atomic_connect_writes function is exported and present.
         Exports = beamchain_db:module_info(exports),
         ?assert(lists:member({atomic_connect_writes, 5}, Exports)),
         ?assert(lists:member({direct_atomic_connect_writes, 5}, Exports)),
         %% Body coalesces BlockOp + IdxOp + TxOps in a single
         %% rocksdb:write call.
         ?assertNotEqual(nomatch,
             binary:match(DbSrc,
                 <<"AllOps = [BlockOp, IdxOp, RevOp | TxOps]">>)),
         ?assertNotEqual(nomatch,
             binary:match(DbSrc, <<"build_tx_index_ops">>))
       end)
     ]}.

%%% ===================================================================
%%% G30 — PRESENT: tx_index CF created on first start
%%% ===================================================================

g30_tx_index_cf_created_present_test_() ->
    {"G30: PRESENT — tx_index column family is created with "
     "create_missing_column_families=true on first start.",
     [
      ?_test(begin
         DbSrc = read_src(beamchain_db_src()),
         ?assertNotEqual(nomatch,
             binary:match(DbSrc,
                 <<"{create_missing_column_families, true}">>)),
         %% tx_index appears in the CFDescriptors list.
         ?assertNotEqual(nomatch,
             binary:match(DbSrc, <<"{?CF_TX_INDEX, CFOpts}">>))
       end)
     ]}.

%%% ===================================================================
%%% Audit summary self-check
%%% ===================================================================

audit_summary_test_() ->
    {"summary: 30 gates, 24 BUGs (0 CDIV / 6 HIGH / 11 MEDIUM / 7 LOW). "
     "PRESENT=3 (G29 atomic_connect, G30 CF created, plus G26's hosting "
     "config integration counted as PARTIAL). The audit-flip convention "
     "means every test passes today and a FIX wave will flip them.",
     [
      ?_test(begin
         %% Sentinel: every source the audit cites must be readable. If
         %% any of these binaries is empty, an earlier `read_src/1` call
         %% silently returned `<<>>` and every `nomatch` assertion in the
         %% suite would have been a false negative. This sentinel catches
         %% that failure mode in one place.
         DbSrc   = read_src(beamchain_db_src()),
         BsSrc   = read_src(beamchain_block_sync_src()),
         CsSrc   = read_src(beamchain_chainstate_src()),
         RpcSrc  = read_src(beamchain_rpc_src()),
         RestSrc = read_src(beamchain_rest_src()),
         CfgSrc  = read_src(beamchain_config_src()),
         BfSrc   = read_src(beamchain_blockfilter_index_src()),
         ?assert(byte_size(DbSrc)   > 1024),
         ?assert(byte_size(BsSrc)   > 1024),
         ?assert(byte_size(CsSrc)   > 1024),
         ?assert(byte_size(RpcSrc)  > 1024),
         ?assert(byte_size(RestSrc) > 1024),
         ?assert(byte_size(CfgSrc)  > 1024),
         ?assert(byte_size(BfSrc)   > 1024)
       end)
     ]}.
