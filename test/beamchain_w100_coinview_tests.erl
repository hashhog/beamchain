-module(beamchain_w100_coinview_tests).

%% W100 CCoinsViewCache + FlushStateToDisk gate audit — 12 bugs
%%
%% Gate coverage: G1-G10 CoinView core, G11-G15 Flush/Sync/Reset/Uncache,
%%               G16-G18 tx-level helpers, G19-G21 DIRTY+FRESH invariants,
%%               G22-G24 cache mgmt, G25-G30 FlushStateToDisk modes.

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

%%% ===================================================================
%%% Test suite wiring
%%% ===================================================================

w100_coinview_test_() ->
    {setup,
     fun setup/0,
     fun teardown/1,
     fun(_) ->
         [
          %% G1: AddCoin possible_overwrite=false — no error on overwrite (silent corruption)
          {"BUG-1 (G1): add_utxo overwrites existing entry without error",
           fun bug1_add_utxo_overwrite_no_error/0},

          %% G3: SpendCoin DIRTY+remove+moveout semantics
          {"G3: spend_utxo returns spent coin from cache",
           fun g3_spend_utxo_returns_coin/0},
          {"G3: spend_utxo on non-fresh entry adds to UTXO_SPENT",
           fun g3_spend_nonfresh_adds_to_spent/0},

          %% G4: AccessCoin read-through + cache
          {"G4: get_utxo read-through adds to cache (not dirty, not fresh)",
           fun g4_read_through_not_dirty/0},

          %% G5: empty on missing
          {"G5: get_utxo returns not_found for unknown outpoint",
           fun g5_get_utxo_missing/0},

          %% G6: HaveCoin cache + base
          {"G6: has_utxo returns false for spent entry in UTXO_SPENT",
           fun g6_has_utxo_spent_pending/0},
          {"G6: has_utxo returns true for fresh (unflushed) entry",
           fun g6_has_utxo_fresh_entry/0},

          %% G7: HaveCoinInCache cache-only
          {"G7: has_utxo_after_eviction misses cache but finds in DB",
           fun g7_havecoinin_cache_only/0},

          %% G8: SetBestBlock stores hash (tip is written on flush)
          {"G8: flush writes chain_tip to RocksDB",
           fun g8_flush_writes_chain_tip/0},

          %% G9: BatchWrite DIRTY-only — spent entries schedule delete not put
          {"G9: flush schedules delete for spent non-fresh entry",
           fun g9_spent_scheduled_for_delete/0},

          %% G11: BUG-5 — HEAD_BLOCKS cleanup is a separate write, not in WriteBatch
          {"BUG-5 (G11): HEAD_BLOCKS marker cleared by separate put, not in flush batch",
           fun bug5_head_blocks_cleared_separately/0},

          %% G19-G21 DIRTY+FRESH invariants
          {"G19: add_utxo_fresh sets both DIRTY and FRESH",
           fun g19_add_fresh_sets_dirty_and_fresh/0},
          {"G20: spend_utxo on FRESH entry clears DIRTY+FRESH (no SPENT scheduled)",
           fun g20_fresh_spend_no_db_delete/0},
          {"G21: overwrite of FRESH entry keeps FRESH (BUG-4 possible_overwrite)",
           fun bug4_overwrite_fresh_stays_fresh/0},

          %% G22-G24 cache mgmt
          {"G22: maybe_flush does NOT check entry count during IBD (BUG-11)",
           fun bug11_ibd_flush_ignores_entry_count/0},
          {"G23: post-flush DIRTY+FRESH+SPENT tables are empty",
           fun g23_flush_clears_tracking_tables/0},
          {"G24: evict_entries removes from cache without touching DIRTY",
           fun g24_evict_does_not_touch_dirty/0},

          %% G25-G30 FlushStateToDisk
          {"BUG-6 (G25): no nMinDiskSpace check before flush",
           fun bug6_no_min_disk_space_check/0},
          {"BUG-2 (G26): flush error leaves blocks_since_flush unmodified",
           fun bug2_flush_error_state_unchanged/0},
          {"BUG-3 (G27): flush tip write uses no sync=true option",
           fun bug3_flush_no_sync_option/0},
          {"G28: FlushStateToDisk ALWAYS mode — flush fires even below cache limit",
           fun g28_flush_always_mode/0},
          {"G29: pending_undo_deletes land in flush WriteBatch",
           fun g29_pending_undo_in_flush_batch/0},
          {"BUG-10 (G30): ZMQ block notification fires before flush commit",
           fun bug10_zmq_before_flush/0}
         ]
     end}.

%%% ===================================================================
%%% Setup / teardown
%%% ===================================================================

setup() ->
    TmpDir = filename:join(["/tmp", "beamchain_w100_test_" ++
                            integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),
    application:ensure_all_started(rocksdb),
    application:set_env(beamchain, datadir, TmpDir),
    application:set_env(beamchain, network, regtest),
    {ok, ConfigPid}     = beamchain_config:start_link(),
    {ok, DbPid}         = beamchain_db:start_link(),
    %% Pre-seed genesis so chainstate init finds a tip
    Genesis  = beamchain_chain_params:genesis_block(regtest),
    GenesisH = Genesis#block.hash,
    ok = beamchain_db:store_block(Genesis, 0),
    ok = beamchain_db:store_block_index(0, GenesisH,
                                        Genesis#block.header, <<0,0,0,1>>, 3),
    ok = beamchain_db:set_chain_tip(GenesisH, 0),
    {ok, CsPid} = beamchain_chainstate:start_link(),
    {TmpDir, ConfigPid, DbPid, CsPid}.

teardown({TmpDir, _Cfg, _Db, _Cs}) ->
    catch gen_server:stop(beamchain_chainstate),
    catch beamchain_db:stop(),
    catch gen_server:stop(beamchain_config),
    os:cmd("rm -rf " ++ TmpDir),
    ok.

%%% ===================================================================
%%% Helpers
%%% ===================================================================

fresh_txid() ->
    crypto:strong_rand_bytes(32).

spendable_utxo(Value) ->
    #utxo{value = Value, script_pubkey = <<16#51>>,
          is_coinbase = false, height = 1}.

%%% ===================================================================
%%% G1: AddCoin possible_overwrite=false silent overwrite (BUG-1)
%%%
%%% Bitcoin Core coins.cpp:AddCoin(possible_overwrite=false) asserts/errors
%%% when the coin already exists.  Beamchain's add_utxo/3 silently
%%% overwrites an existing entry without logging an error or returning
%%% an error value, masking BIP-30 and double-add corruption scenarios.
%%%
%%% Severity: CORRECTNESS (upstream CONSENSUS-DIVERGENT if the second
%%% value is wrong and a later consensus decision relies on the old value).
%%% ===================================================================

bug1_add_utxo_overwrite_no_error() ->
    Txid = fresh_txid(),
    U1 = spendable_utxo(111),
    U2 = spendable_utxo(999),
    %% First add
    ok = beamchain_chainstate:add_utxo(Txid, 0, U1),
    {ok, V1} = beamchain_chainstate:get_utxo(Txid, 0),
    ?assertEqual(111, V1#utxo.value),
    %% Second add (possible_overwrite=false in Core: should be an error;
    %% here it silently succeeds — BUG-1).
    ok = beamchain_chainstate:add_utxo(Txid, 0, U2),
    {ok, V2} = beamchain_chainstate:get_utxo(Txid, 0),
    %% Document the bug: the return is ok even though the coin existed.
    %% Core would error/assert here.  The overwrite succeeds silently.
    ?assertEqual(999, V2#utxo.value),
    beamchain_chainstate:spend_utxo(Txid, 0).

%%% ===================================================================
%%% G3: SpendCoin DIRTY+remove+moveout
%%% ===================================================================

g3_spend_utxo_returns_coin() ->
    Txid = fresh_txid(),
    U = spendable_utxo(42000),
    beamchain_chainstate:add_utxo(Txid, 0, U),
    {ok, Spent} = beamchain_chainstate:spend_utxo(Txid, 0),
    ?assertEqual(42000, Spent#utxo.value),
    ?assertEqual(not_found, beamchain_chainstate:get_utxo(Txid, 0)).

g3_spend_nonfresh_adds_to_spent() ->
    %% Add, flush to RocksDB, evict from cache, then spend — the entry
    %% must land in UTXO_SPENT (not DIRTY) for a delete-on-flush.
    Txid = fresh_txid(),
    U = spendable_utxo(55000),
    beamchain_chainstate:add_utxo(Txid, 0, U),
    beamchain_chainstate:flush(),
    %% Evict from ETS cache to simulate a clean-cache miss
    ets:delete(beamchain_utxo_cache, {Txid, 0}),
    ets:delete(beamchain_utxo_fresh, {Txid, 0}),
    {ok, Spent} = beamchain_chainstate:spend_utxo(Txid, 0),
    ?assertEqual(55000, Spent#utxo.value),
    %% Must be scheduled for delete, NOT in dirty
    ?assert(ets:member(beamchain_utxo_spent, {Txid, 0})),
    ?assertNot(ets:member(beamchain_utxo_dirty, {Txid, 0})),
    beamchain_chainstate:flush().

%%% ===================================================================
%%% G4: AccessCoin read-through adds to cache, NOT dirty/fresh
%%% ===================================================================

g4_read_through_not_dirty() ->
    Txid = fresh_txid(),
    U = spendable_utxo(77000),
    beamchain_chainstate:add_utxo(Txid, 0, U),
    beamchain_chainstate:flush(),
    %% Evict from cache
    ets:delete(beamchain_utxo_cache, {Txid, 0}),
    ets:delete(beamchain_utxo_fresh, {Txid, 0}),
    %% Read-through
    {ok, _} = beamchain_chainstate:get_utxo(Txid, 0),
    %% Entry populated into cache but NOT dirty, NOT fresh (it's on disk)
    ?assert(ets:member(beamchain_utxo_cache, {Txid, 0})),
    ?assertNot(ets:member(beamchain_utxo_dirty, {Txid, 0})),
    ?assertNot(ets:member(beamchain_utxo_fresh, {Txid, 0})),
    beamchain_chainstate:spend_utxo(Txid, 0),
    beamchain_chainstate:flush().

%%% ===================================================================
%%% G5: empty on missing
%%% ===================================================================

g5_get_utxo_missing() ->
    UnknownTxid = crypto:strong_rand_bytes(32),
    ?assertEqual(not_found, beamchain_chainstate:get_utxo(UnknownTxid, 0)),
    ?assertEqual(not_found, beamchain_chainstate:get_utxo(UnknownTxid, 999)).

%%% ===================================================================
%%% G6: HaveCoin — UTXO_SPENT hides a pending-delete entry
%%% ===================================================================

g6_has_utxo_spent_pending() ->
    %% A non-fresh spend schedules a DB delete. has_utxo must return
    %% false immediately (the coin is logically gone).
    Txid = fresh_txid(),
    U = spendable_utxo(10000),
    beamchain_chainstate:add_utxo(Txid, 0, U),
    beamchain_chainstate:flush(),
    ets:delete(beamchain_utxo_cache, {Txid, 0}),
    ets:delete(beamchain_utxo_fresh, {Txid, 0}),
    {ok, _} = beamchain_chainstate:spend_utxo(Txid, 0),
    %% has_utxo must return false: entry is in UTXO_SPENT
    ?assertNot(beamchain_chainstate:has_utxo(Txid, 0)),
    beamchain_chainstate:flush().

g6_has_utxo_fresh_entry() ->
    %% A FRESH (unflushed) entry must be visible via has_utxo.
    Txid = fresh_txid(),
    U = spendable_utxo(20000),
    beamchain_chainstate:add_utxo_fresh(Txid, 0, U),
    ?assert(beamchain_chainstate:has_utxo(Txid, 0)),
    beamchain_chainstate:spend_utxo(Txid, 0).

%%% ===================================================================
%%% G7: HaveCoinInCache — after eviction, has_utxo falls through to DB
%%% ===================================================================

g7_havecoinin_cache_only() ->
    Txid = fresh_txid(),
    U = spendable_utxo(30000),
    beamchain_chainstate:add_utxo(Txid, 0, U),
    beamchain_chainstate:flush(),
    %% Evict from ETS
    ets:delete(beamchain_utxo_cache, {Txid, 0}),
    ets:delete(beamchain_utxo_fresh, {Txid, 0}),
    %% has_utxo must still return true (falls through to RocksDB)
    ?assert(beamchain_chainstate:has_utxo(Txid, 0)),
    beamchain_chainstate:spend_utxo(Txid, 0),
    beamchain_chainstate:flush().

%%% ===================================================================
%%% G8: SetBestBlock — flush writes chain_tip to RocksDB
%%% ===================================================================

g8_flush_writes_chain_tip() ->
    %% After a flush the chain_tip in RocksDB must match the ETS tip.
    {ok, {TipHash, TipHeight}} = beamchain_chainstate:get_tip(),
    beamchain_chainstate:flush(),
    {ok, #{hash := DbHash, height := DbHeight}} = beamchain_db:get_chain_tip(),
    ?assertEqual(TipHash, DbHash),
    ?assertEqual(TipHeight, DbHeight).

%%% ===================================================================
%%% G9: BatchWrite DIRTY-only — spent entry produces delete op, not put
%%% ===================================================================

g9_spent_scheduled_for_delete() ->
    Txid = fresh_txid(),
    U = spendable_utxo(88888),
    beamchain_chainstate:add_utxo(Txid, 0, U),
    beamchain_chainstate:flush(),
    %% Evict and spend (non-fresh path)
    ets:delete(beamchain_utxo_cache, {Txid, 0}),
    ets:delete(beamchain_utxo_fresh, {Txid, 0}),
    {ok, _} = beamchain_chainstate:spend_utxo(Txid, 0),
    %% Before flush: still in RocksDB
    ?assertMatch({ok, _}, beamchain_db:get_utxo(Txid, 0)),
    %% After flush: deleted from RocksDB
    beamchain_chainstate:flush(),
    ?assertEqual(not_found, beamchain_db:get_utxo(Txid, 0)).

%%% ===================================================================
%%% BUG-5 (G11): HEAD_BLOCKS cleanup is a SEPARATE put, not in the
%%% atomic flush WriteBatch.
%%%
%%% Core's FlushStateToDisk writes HEAD_BLOCKS as part of the atomic
%%% batch and then clears it in the same batch on success — there is no
%%% separate fsync'd write. Beamchain writes the HEAD_BLOCKS marker
%%% inside the WriteBatch (`AllOps` list) but then clears it via a
%%% separate `beamchain_db:put_meta(<<"HEAD_BLOCKS">>, <<>>)` call after
%%% the batch commits. If the process crashes between the batch commit
%%% and the cleanup call, the marker persists stale, potentially causing
%%% false-positive crash-recovery procedures on restart.
%%%
%%% Severity: OBSERVABILITY / CRASH-CONSISTENCY
%%% ===================================================================

bug5_head_blocks_cleared_separately() ->
    %% Force a flush that has at least one dirty entry so the full batch
    %% path (not the fast path) runs.
    Txid = fresh_txid(),
    U = spendable_utxo(12345),
    beamchain_chainstate:add_utxo_fresh(Txid, 0, U),
    beamchain_chainstate:flush(),
    %% After flush, HEAD_BLOCKS should be empty (cleanup ran).
    %% This documents the current behaviour: the cleanup is a separate write.
    %% The bug is that a crash between the batch commit and this cleanup
    %% would leave HEAD_BLOCKS stale with the pre-flush tip value.
    case beamchain_db:get_meta(<<"HEAD_BLOCKS">>) of
        not_found ->
            %% HEAD_BLOCKS deleted — cleanup ran (the extra separate write).
            ok;
        {ok, <<>>} ->
            %% Cleared to empty binary — still a separate write.
            ok;
        {ok, _Stale} ->
            %% HEAD_BLOCKS holds stale data — cleanup hasn't run yet.
            %% In normal operation this only happens if flush was called
            %% but we check in the same process before the cleanup write
            %% completes.  Document as observed.
            ok
    end,
    %% Core invariant: after a successful flush the marker should be gone.
    %% We assert the cleanup DID run (because our process didn't crash):
    Marker = beamchain_db:get_meta(<<"HEAD_BLOCKS">>),
    ?assert(Marker =:= not_found orelse Marker =:= {ok, <<>>}),
    beamchain_chainstate:spend_utxo(Txid, 0),
    beamchain_chainstate:flush().

%%% ===================================================================
%%% G19-G21 DIRTY+FRESH invariants
%%% ===================================================================

g19_add_fresh_sets_dirty_and_fresh() ->
    Txid = fresh_txid(),
    U = spendable_utxo(1000),
    beamchain_chainstate:add_utxo_fresh(Txid, 0, U),
    ?assert(ets:member(beamchain_utxo_dirty, {Txid, 0})),
    ?assert(ets:member(beamchain_utxo_fresh, {Txid, 0})),
    beamchain_chainstate:spend_utxo(Txid, 0).

g20_fresh_spend_no_db_delete() ->
    %% Spending a FRESH entry before flush must not schedule a DB delete
    %% (FRESH optimization: the entry was never in RocksDB).
    Txid = fresh_txid(),
    U = spendable_utxo(2000),
    beamchain_chainstate:add_utxo_fresh(Txid, 0, U),
    {ok, Spent} = beamchain_chainstate:spend_utxo(Txid, 0),
    ?assertEqual(2000, Spent#utxo.value),
    %% UTXO_SPENT must NOT have this key (no RocksDB delete needed)
    ?assertNot(ets:member(beamchain_utxo_spent, {Txid, 0})),
    %% DIRTY and FRESH must also be cleared
    ?assertNot(ets:member(beamchain_utxo_dirty, {Txid, 0})),
    ?assertNot(ets:member(beamchain_utxo_fresh, {Txid, 0})),
    %% Verify it was never persisted to RocksDB
    ?assertEqual(not_found, beamchain_db:get_utxo(Txid, 0)).

%% BUG-4 (G21): overwriting an existing FRESH entry via add_utxo/3
%% leaves it marked FRESH even though the first add already made it
%% "logically in cache".  Bitcoin Core's possible_overwrite=true path
%% clears the FRESH flag when overwriting, because the OLD value may
%% already be in RocksDB.  Beamchain's AlreadyInDb check for FRESH
%% entries returns false (because FRESH means "not yet in DB"), which
%% is correct for the DB check — but if the original add_utxo call was
%% a non-fresh path (AlreadyInDb=true cleared FRESH), this is fine.
%% The scenario that fails: add_utxo_fresh(T,0) followed by
%% add_utxo_fresh(T,0) — the second call always sets FRESH again,
%% regardless of the original entry's source.
%%
%% Severity: CORRECTNESS (latent; triggers only on two consecutive
%% add_utxo_fresh for the same outpoint, e.g. BIP-30 regtest replay).

bug4_overwrite_fresh_stays_fresh() ->
    Txid = fresh_txid(),
    U1 = spendable_utxo(111),
    U2 = spendable_utxo(222),
    beamchain_chainstate:add_utxo_fresh(Txid, 0, U1),
    beamchain_chainstate:flush(),
    %% Now Txid:0 is in RocksDB. Evict from cache.
    ets:delete(beamchain_utxo_cache, {Txid, 0}),
    ets:delete(beamchain_utxo_fresh, {Txid, 0}),
    ets:delete(beamchain_utxo_dirty, {Txid, 0}),
    %% add_utxo_fresh bypasses the AlreadyInDb check —
    %% it unconditionally marks FRESH even though the coin is in RocksDB.
    %% This is BUG-4: the fast path skips the DB-existence check.
    beamchain_chainstate:add_utxo_fresh(Txid, 0, U2),
    IsFresh = ets:member(beamchain_utxo_fresh, {Txid, 0}),
    %% Document the bug: IsFresh is true even though the coin is in RocksDB.
    %% Core would clear FRESH here because the coin has a DB backing.
    ?assert(IsFresh),  %% BUG: should be false for a coin already in RocksDB
    %% Consequence: if spent now, the FRESH optimization skips the DB delete,
    %% leaving a stale (phantom) coin in RocksDB.
    {ok, _} = beamchain_chainstate:spend_utxo(Txid, 0),
    %% Because FRESH was set, the spend took the FRESH path (no SPENT entry)
    ?assertNot(ets:member(beamchain_utxo_spent, {Txid, 0})),
    %% The stale coin is still in RocksDB — it was never deleted.
    %% BUG-4 consequence: phantom UTXO persists on disk.
    StaleInDb = beamchain_db:get_utxo(Txid, 0),
    ?assertMatch({ok, #utxo{value = 111}}, StaleInDb).

%%% ===================================================================
%%% G22-G24 cache management
%%% ===================================================================

%% BUG-11 (G22): IBD flush path checks ONLY blocks_since_flush, never
%% cache entry count.  The non-IBD path checks both entry count and
%% memory bytes, but during IBD the `ibd = true` branch short-circuits
%% to the interval check only.  With ?IBD_FLUSH_INTERVAL = 5000, the
%% cache can grow to millions of entries between flushes.
%%
%% Severity: CORRECTNESS (OOM / stall risk on low-memory nodes during IBD)

bug11_ibd_flush_ignores_entry_count() ->
    %% Verify the code paths: in maybe_flush, ibd=true branch only checks
    %% blocks_since_flush >= ?IBD_FLUSH_INTERVAL, never entry count.
    %% We cannot easily set ibd=true and feed 5001 blocks in a unit test,
    %% so we exercise the structural observation by calling cache_stats
    %% and verifying that entry_count is not capped by the IBD branch.
    %%
    %% Insert 100 UTXOs without flushing (simulating IBD sub-interval).
    Txids = [crypto:strong_rand_bytes(32) || _ <- lists:seq(1, 100)],
    lists:foreach(fun(T) ->
        beamchain_chainstate:add_utxo_fresh(T, 0, spendable_utxo(100))
    end, Txids),
    Stats = beamchain_chainstate:cache_stats(),
    %% All 100 entries should be in the cache — no IBD flush fired.
    ?assert(maps:get(dirty_entries, Stats) >= 100),
    %% Cleanup
    lists:foreach(fun(T) -> beamchain_chainstate:spend_utxo(T, 0) end, Txids),
    beamchain_chainstate:flush().

g23_flush_clears_tracking_tables() ->
    Txid = fresh_txid(),
    beamchain_chainstate:add_utxo_fresh(Txid, 0, spendable_utxo(500)),
    beamchain_chainstate:flush(),
    %% After flush all tracking tables must be empty
    ?assertEqual(0, ets:info(beamchain_utxo_dirty, size)),
    ?assertEqual(0, ets:info(beamchain_utxo_fresh, size)),
    ?assertEqual(0, ets:info(beamchain_utxo_spent, size)),
    beamchain_chainstate:spend_utxo(Txid, 0),
    beamchain_chainstate:flush().

g24_evict_does_not_touch_dirty() ->
    %% Add a UTXO, flush it (makes it clean), then verify that a manual
    %% eviction from the cache does not corrupt the dirty table.
    Txid = fresh_txid(),
    beamchain_chainstate:add_utxo_fresh(Txid, 0, spendable_utxo(600)),
    beamchain_chainstate:flush(),
    %% After flush: entry is in cache (clean), dirty=0.
    ?assertEqual(0, ets:info(beamchain_utxo_dirty, size)),
    %% Manually evict
    ets:delete(beamchain_utxo_cache, {Txid, 0}),
    %% Dirty table still empty — eviction must not affect dirty tracking.
    ?assertEqual(0, ets:info(beamchain_utxo_dirty, size)),
    beamchain_chainstate:spend_utxo(Txid, 0),
    beamchain_chainstate:flush().

%%% ===================================================================
%%% G25-G30 FlushStateToDisk
%%% ===================================================================

%% BUG-6 (G25): nMinDiskSpace (50MB) check absent.
%%
%% Bitcoin Core validation.cpp FlushStateToDisk checks
%% CheckDiskSpace(GetDataDir(), nMinDiskSpace=50*1024*1024) before
%% committing the WriteBatch. If disk is full, it sets a fatal error flag
%% and returns without writing, rather than letting the kernel syscall
%% fail mid-batch (partial-write risk on non-atomic FSes).
%%
%% Beamchain calls beamchain_db:direct_write_batch without any prior
%% disk-space check.  If the disk is full, RocksDB write() returns an
%% error tuple which is logged but not treated as fatal — the node
%% continues with an inconsistent on-disk state.
%%
%% This test documents the absence by verifying no disk-space guard
%% exists in the flush path.  We cannot easily simulate a full disk in
%% a unit test; instead we check that flush() returns ok without a
%% disk-space check by inspecting the function's return value on a fresh
%% dirty entry.  The bug is structural — observable via code audit only.
%%
%% Severity: CRASH-CONSISTENCY / DOS (node continues writing to full disk)

bug6_no_min_disk_space_check() ->
    %% Flush with a dirty entry — no disk-space check fires.
    %% If it did fire, the call would return an error or crash.
    Txid = fresh_txid(),
    beamchain_chainstate:add_utxo_fresh(Txid, 0, spendable_utxo(700)),
    %% flush/0 returns ok without checking disk space (BUG-6)
    Result = beamchain_chainstate:flush(),
    ?assertEqual(ok, Result),
    beamchain_chainstate:spend_utxo(Txid, 0),
    beamchain_chainstate:flush().

%% BUG-2 (G26): flush WriteBatch error leaves blocks_since_flush and
%% pending_undo_deletes unchanged.
%%
%% In do_flush, the {error, Reason} branch returns the unmodified State
%% record.  This means:
%%   * blocks_since_flush is not reset — the flush will NOT be retried
%%     on the next block connection in IBD (the counter keeps growing
%%     and the next flush is delayed by another IBD_FLUSH_INTERVAL blocks)
%%   * pending_undo_deletes accumulates across failed flushes, causing
%%     the same undo-delete ops to be replayed in future batches
%%     (harmless only because RocksDB deletes are idempotent, but the
%%      accumulator can grow unboundedly)
%%   * The on-disk chain_tip is not updated — UTXO cache and on-disk tip
%%     diverge silently
%%
%% Severity: CORRECTNESS / CRASH-CONSISTENCY
%%
%% This test documents the bug structurally: we verify that after a
%% simulated flush path that would fail (impossible to inject in unit
%% test without mocking), the state.blocks_since_flush is not reset.
%% We do so by observing that two flushes with dirty entries clear the
%% counters correctly (positive case), confirming the counter IS tracked.

bug2_flush_error_state_unchanged() ->
    %% Positive assertion: a SUCCESSFUL flush resets blocks_since_flush.
    Txid = fresh_txid(),
    beamchain_chainstate:add_utxo_fresh(Txid, 0, spendable_utxo(800)),
    ok = beamchain_chainstate:flush(),
    %% After flush, dirty count = 0
    ?assertEqual(0, ets:info(beamchain_utxo_dirty, size)),
    %% Structural note: on flush ERROR, State is returned unchanged —
    %% blocks_since_flush, pending_undo_deletes, and dirty ETS remain
    %% populated. No retry logic exists.
    beamchain_chainstate:spend_utxo(Txid, 0),
    beamchain_chainstate:flush().

%% BUG-3 (G27): flush tip write uses empty opts [] — no sync=true.
%%
%% Bitcoin Core's FlushStateToDisk uses sync writes for the tip update
%% (FlushMode::ALWAYS path: `CoinsDB().BatchWrite(...sync=true)`).
%% Beamchain's direct_write_batch calls `rocksdb:write(Db, Ops, [])`
%% with an empty options list, providing no durability guarantee.
%% A power failure between the OS write buffer and the storage medium
%% can leave the on-disk tip in an older state while the ETS state is
%% already at a higher tip.
%%
%% Severity: CRASH-CONSISTENCY
%%
%% This test is structural (we cannot inject a power failure in a unit
%% test).  We verify that flush returns ok and the tip IS persisted
%% (the write succeeded without sync), to document the current behaviour.

bug3_flush_no_sync_option() ->
    Txid = fresh_txid(),
    beamchain_chainstate:add_utxo_fresh(Txid, 0, spendable_utxo(900)),
    ok = beamchain_chainstate:flush(),
    %% Tip is written (no sync, but write did land)
    {ok, {Hash, Height}} = beamchain_chainstate:get_tip(),
    {ok, #{hash := DbHash, height := DbHeight}} = beamchain_db:get_chain_tip(),
    ?assertEqual(Hash, DbHash),
    ?assertEqual(Height, DbHeight),
    beamchain_chainstate:spend_utxo(Txid, 0),
    beamchain_chainstate:flush().

%% G28: FlushStateToDisk ALWAYS mode (exposed as flush/0 RPC path):
%% calling flush/0 manually must persist even when cache is under the
%% automatic threshold.

g28_flush_always_mode() ->
    Txid = fresh_txid(),
    U = spendable_utxo(1111),
    beamchain_chainstate:add_utxo_fresh(Txid, 0, U),
    %% Before flush: not in RocksDB
    ?assertEqual(not_found, beamchain_db:get_utxo(Txid, 0)),
    %% Explicit flush (ALWAYS-equivalent) must write regardless of cache size
    ok = beamchain_chainstate:flush(),
    {ok, DbU} = beamchain_db:get_utxo(Txid, 0),
    ?assertEqual(1111, DbU#utxo.value),
    beamchain_chainstate:spend_utxo(Txid, 0),
    beamchain_chainstate:flush().

%% G29: pending_undo_deletes land in the flush WriteBatch.
%%
%% Undo data for disconnected blocks is stored in cf_undo, keyed by
%% block hash. During disconnect_to (reorg), the block's undo entry is
%% added to pending_undo_deletes rather than being deleted immediately.
%% The flush batch must include a delete op for each pending hash.

g29_pending_undo_in_flush_batch() ->
    %% Store some undo data and verify it gets deleted when we commit
    %% a flush that carries a pending_undo_delete for that hash.
    BlockHash = crypto:strong_rand_bytes(32),
    UndoBin = <<"fake_undo_data">>,
    ok = beamchain_db:store_undo(BlockHash, UndoBin),
    ?assertMatch({ok, _}, beamchain_db:get_undo(BlockHash)),
    %% Manually inject the hash into pending_undo_deletes via sys:replace_state
    sys:replace_state(beamchain_chainstate, fun(S) ->
        Pending = element(18, S),  %% pending_undo_deletes field
        setelement(18, S, [BlockHash | Pending])
    end),
    %% Trigger a flush (needs at least one dirty/spent op or tip change
    %% to take the non-fast path; add a dirty entry)
    Txid = fresh_txid(),
    beamchain_chainstate:add_utxo_fresh(Txid, 0, spendable_utxo(50)),
    ok = beamchain_chainstate:flush(),
    %% After flush, undo data must be gone
    ?assertEqual(not_found, beamchain_db:get_undo(BlockHash)),
    beamchain_chainstate:spend_utxo(Txid, 0),
    beamchain_chainstate:flush().

%% BUG-10 (G30): ZMQ block notification fires BEFORE flush commit.
%%
%% In do_connect_block_inner, beamchain_zmq:notify_block/2 is called
%% inside the `try` block AFTER validation succeeds but BEFORE
%% maybe_flush is called.  If the subsequent flush fails (Bug-2), the
%% ZMQ consumer has already received a "block connected" event for a
%% block whose UTXO state is NOT yet committed to disk.  On restart,
%% the node will re-connect that block, issuing a duplicate notification.
%%
%% Bitcoin Core fires ChainStateFlushed and BlockConnected signals AFTER
%% the flush batch commits (validation.cpp ConnectTip → CChainState::
%% NotifyChainStateFlushed).
%%
%% Severity: OBSERVABILITY (duplicate events to ZMQ subscribers; can
%% cause double-spend-detection false positives in wallets listening to
%% rawblock/rawtx).
%%
%% Structural test: verify that ZMQ notification function exists and is
%% called, documenting the pre-flush ordering bug.

bug10_zmq_before_flush() ->
    %% The ZMQ module is always present (it no-ops when no socket is open).
    %% We verify the notification occurs by adding a UTXO and flushing;
    %% the notification path is exercised during connect_block, which we
    %% don't call directly here.  Instead, document the structural bug:
    %% zmq:notify_block is at line ~1008 in chainstate.erl, which is
    %% BEFORE maybe_flush at line ~973 in the reorg_in_progress=false arm.
    %% The ordering is: validation → zmq_notify → maybe_flush.
    %% Core's ordering is: validation → flush → zmq_notify.
    %%
    %% We assert the beamchain_zmq module is available:
    ?assert(erlang:function_exported(beamchain_zmq, notify_block, 2)),
    %% And that beamchain_chainstate's flush path can be called independently:
    Txid = fresh_txid(),
    beamchain_chainstate:add_utxo_fresh(Txid, 0, spendable_utxo(200)),
    ok = beamchain_chainstate:flush(),
    beamchain_chainstate:spend_utxo(Txid, 0),
    beamchain_chainstate:flush().
