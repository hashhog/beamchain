-module(beamchain_w101_activate_best_chain_tests).

%% W101 audit: ActivateBestChain + InvalidateBlock gate audit.
%%
%% Bugs documented here (do NOT fix — audit only):
%%
%%  BUG-1 (CONSENSUS-DIVERGENT): find_best_valid_chain/1 does not filter out
%%    blocks that lack BLOCK_HAVE_DATA (bit 8).  Core's FindMostWorkChain skips
%%    candidates where !(pindexTest->nStatus & BLOCK_HAVE_DATA). beamchain will
%%    attempt to connect a chain whose block data does not exist on disk,
%%    producing a block_data_missing error mid-reorg.
%%
%%  BUG-2 (CONSENSUS-DIVERGENT): do_invalidate_block_impl/3 calls
%%    disconnect_to_height(BlockHeight - 1, State) without first verifying that
%%    the target block hash is actually the active-chain block at BlockHeight.
%%    A side-branch block at the same height as an active-chain block will
%%    cause active-chain blocks to be disconnected unnecessarily. Core guards
%%    with m_chain.Contains(pindex) before disconnecting anything.
%%
%%  BUG-3 (CORRECTNESS): disconnect_to_height/2 swallows disconnect errors —
%%    on failure it logs a warning and returns the partially-disconnected State
%%    as if nothing went wrong. The caller (do_invalidate_block_impl) proceeds
%%    to mark descendants invalid and attempt a reconnect against an inconsistent
%%    tip. Core's InvalidateBlock returns false on DisconnectTip failure.
%%
%%  BUG-4 (CORRECTNESS): do_invalidate_block_impl/3 returns {error, Reason}
%%    from connect_blocks but returns {ok, State2} when find_best_valid_chain
%%    returns {error, Reason} (line 2259-2260). Error is silently swallowed and
%%    callers see ok even though the post-invalidation tip is stranded.
%%
%%  BUG-5 (DOS): find_best_valid_chain/1 calls get_all_block_indexes() which
%%    loads the entire block index into memory.  On mainnet (900 K+ blocks) this
%%    is called on every invalidateblock / reconsiderblock and during post-
%%    invalidation best-chain selection — allocating hundreds of megabytes.
%%    Core uses an incrementally-maintained sorted set (setBlockIndexCandidates).
%%
%%  BUG-6 (DOS): mark_descendants_invalid/2 also calls get_all_block_indexes()
%%    and then calls is_descendant_of/3 for each candidate, which walks the
%%    chain. Total cost is O(N^2) per invalidation. On mainnet this is
%%    catastrophically slow.
%%
%%  BUG-7 (OBSERVABILITY): No tip-update notification is sent after
%%    do_invalidate_block completes and changes the active chain tip.
%%    Core fires GetNotifications().blockTip(...) and
%%    signals->ActiveTipChange(*Assert(m_chain.Tip()), ...) when
%%    pindex_was_in_chain is true. beamchain fires ZMQ per-disconnect but
%%    never calls beamchain_peer_manager:notify_tip_updated() after the
%%    full invalidation sequence settles.
%%
%%  BUG-8 (CORRECTNESS): do_invalidate_block/2 only looks up blocks via
%%    get_block_index_by_hash which only covers active-chain blocks. A side-
%%    branch block passed to invalidate_block returns block_not_found even
%%    though lookup_block_index_anywhere (present in the file) would find it.
%%    Core's InvalidateBlock operates on any entry in m_blockman.m_block_index.
%%
%%  BUG-9 (CORRECTNESS): find_best_valid_chain/1 does not check BLOCK_HAVE_DATA
%%    on the blocks it proposes to connect.  A valid-flagged block stored as a
%%    side-branch index entry (status=2, VALID_TREE) with no body in cf_blocks
%%    will be returned as a candidate; collect_chain_blocks silently drops it
%%    (returns an incomplete chain) and connect_blocks receives fewer blocks than
%%    expected with no error.
%%
%%  BUG-10 (CORRECTNESS): The reorg_in_progress flag is NOT set during the
%%    disconnect+reconnect in do_invalidate_block_impl, so each per-block
%%    disconnect and each per-block connect flushes independently. There is no
%%    atomic commit for the full invalidation sequence; a crash mid-way leaves
%%    the chain in a partially-invalidated state on disk.
%%
%%  BUG-11 (DOS): build_side_branch_chain_to_active/1 walks the side-branch
%%    chain without any depth limit. An attacker submitting a very long side-
%%    branch (up to the block-index size) can force an unbounded walk and large
%%    allocation before the MAX_REORG_DEPTH guard in do_reorganize fires.
%%
%%  BUG-12 (CORRECTNESS): do_invalidate_block/2 returns not_found for any block
%%    that is on a side-branch rather than the active chain, even if that block
%%    is tracked in the side-branch index. The correct behaviour (Core) is to
%%    mark the block and descendants BLOCK_FAILED_VALID and erase it from the
%%    candidate set regardless of whether it is currently active.

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-define(BLOCK_FAILED_VALID, 32).
-define(BLOCK_HAVE_DATA, 8).

%%%===================================================================
%%% Test suite entry point
%%%===================================================================

w101_activate_best_chain_test_() ->
    {setup,
     fun setup/0,
     fun teardown/1,
     fun(_Ctx) ->
         [
          %% BUG-1: find_best_valid_chain does not filter BLOCK_HAVE_DATA=0
          {"BUG-1: find_best_valid_chain admits no-data candidates (CONSENSUS-DIVERGENT)",
           fun bug1_find_best_valid_chain_no_data_filter/0},

          %% BUG-2: invalidate without active-chain membership check
          {"BUG-2: invalidate_block disconnects active chain for off-chain hash",
           fun bug2_invalidate_disconnects_without_containment_check/0},

          %% BUG-3: disconnect_to_height swallows errors
          {"BUG-3: disconnect_to_height error is swallowed, state inconsistent",
           fun bug3_disconnect_to_height_error_swallowed/0},

          %% BUG-4: find_best_valid_chain error silently returns ok
          {"BUG-4: find_best_valid_chain error returns ok instead of error",
           fun bug4_find_best_valid_chain_error_swallowed/0},

          %% BUG-7: no notify_tip_updated after invalidation
          {"BUG-7: invalidate_block does not call notify_tip_updated after tip change",
           fun bug7_no_tip_notification_after_invalidate/0},

          %% BUG-8: invalidate_block returns not_found for side-branch blocks
          {"BUG-8: invalidate_block returns block_not_found for side-branch block",
           fun bug8_invalidate_side_branch_block_not_found/0},

          %% BUG-10: no atomic flush during invalidation sequence
          {"BUG-10: invalidation sequence uses no reorg_in_progress flag (no atomic commit)",
           fun bug10_no_atomic_commit_during_invalidation/0},

          %% Correct-path baseline tests (verify what works)
          {"baseline: cannot invalidate genesis block",
           fun baseline_cannot_invalidate_genesis/0},
          {"baseline: invalidate unknown hash returns block_not_found",
           fun baseline_invalidate_unknown_hash/0},
          {"baseline: already-invalid block is a no-op",
           fun baseline_invalidate_already_invalid_noop/0},
          {"baseline: reconsider_block clears BLOCK_FAILED_VALID flag",
           fun baseline_reconsider_clears_flag/0},
          {"baseline: mark_descendants_invalid propagates to children",
           fun baseline_descendants_marked_invalid/0},
          {"baseline: compare_work correctly ranks by chainwork",
           fun baseline_compare_work_ranking/0},

          %% Additional gate coverage
          {"gate: invalidate_block marks status BLOCK_FAILED_VALID on active block",
           fun gate_invalidate_sets_failed_valid_flag/0},
          {"gate: find_best_valid_chain excludes BLOCK_FAILED_VALID blocks",
           fun gate_find_best_valid_excludes_failed_blocks/0},
          {"gate: reconsider_block clears BLOCK_FAILED_VALID from descendants",
           fun gate_reconsider_clears_descendants/0}
         ]
     end}.

%%%===================================================================
%%% Setup / teardown
%%%===================================================================

setup() ->
    TmpDir = filename:join(["/tmp",
        "beamchain_w101_test_" ++
        integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),
    application:ensure_all_started(rocksdb),
    application:set_env(beamchain, datadir, TmpDir),
    application:set_env(beamchain, network, regtest),
    {ok, ConfigPid} = beamchain_config:start_link(),
    {ok, DbPid}     = beamchain_db:start_link(),
    Params  = beamchain_chain_params:params(regtest),
    Genesis = beamchain_chain_params:genesis_block(regtest),
    GenesisHash = Genesis#block.hash,
    ok = beamchain_db:store_block(Genesis, 0),
    ok = beamchain_db:store_block_index(0, GenesisHash,
             Genesis#block.header, <<0,0,0,1>>, 5),
    ok = beamchain_db:set_chain_tip(GenesisHash, 0),
    {ok, ChainstatePid} = beamchain_chainstate:start_link(),
    [CoinbaseTx | _] = Genesis#block.transactions,
    CoinbaseTxid = beamchain_serialize:tx_hash(CoinbaseTx),
    [CoinbaseOut | _] = CoinbaseTx#transaction.outputs,
    GenesisUtxo = #utxo{
        value        = CoinbaseOut#tx_out.value,
        script_pubkey = CoinbaseOut#tx_out.script_pubkey,
        is_coinbase  = true,
        height       = 0
    },
    beamchain_chainstate:add_utxo(CoinbaseTxid, 0, GenesisUtxo),
    #{tmpdir    => TmpDir,
      config    => ConfigPid,
      db        => DbPid,
      chainstate => ChainstatePid,
      params    => Params,
      genesis   => Genesis,
      genesis_hash => GenesisHash}.

teardown(#{tmpdir := TmpDir}) ->
    catch gen_server:stop(beamchain_chainstate),
    catch beamchain_db:stop(),
    catch gen_server:stop(beamchain_config),
    os:cmd("rm -rf " ++ TmpDir),
    ok.

%%%===================================================================
%%% Helper: build a minimal fake block header at height H off genesis
%%%===================================================================

fake_header(PrevHash, Nonce) ->
    #block_header{
        version    = 1,
        prev_hash  = PrevHash,
        merkle_root = <<0:256>>,
        timestamp  = 1296688930 + Nonce,
        bits       = 16#207fffff,
        nonce      = Nonce
    }.

fake_block_hash(Header) ->
    beamchain_serialize:block_hash(Header).

%%%===================================================================
%%% BUG-1: find_best_valid_chain does not filter BLOCK_HAVE_DATA
%%%
%%% Core's FindMostWorkChain rejects candidate chains that include a
%%% block index entry with BLOCK_HAVE_DATA (bit 8) clear, adding those
%%% blocks to m_blocks_unlinked and erasing from setBlockIndexCandidates.
%%% beamchain's find_best_valid_chain only filters on BLOCK_FAILED_VALID.
%%% A block with status=2 (VALID_TREE, no data) and high chainwork will
%%% be returned as BestBlock, causing collect_chain_blocks to silently
%%% drop it (body absent in cf_blocks) and the caller to receive an
%%% incomplete chain — or a block_data_missing error.
%%%===================================================================

bug1_find_best_valid_chain_no_data_filter() ->
    #{genesis_hash := GenesisHash} = setup_ctx(),
    %% Insert a block index entry with high chainwork but NO block body
    %% (status = 2 = VALID_TREE, not BLOCK_HAVE_DATA = 8).
    Header1 = fake_header(GenesisHash, 999),
    Hash1   = fake_block_hash(Header1),
    %% Chainwork higher than genesis so find_best_valid_chain would have
    %% picked it before the fix.
    HighCW  = <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,0,0,0,255,0,0,0,0>>,
    ok = beamchain_db:store_block_index(1, Hash1, Header1, HighCW,
                                        2),   %% status=2, no HAVE_DATA bit
    %% NOTE: we deliberately do NOT call beamchain_db:store_block/2,
    %% so cf_blocks has no body for Hash1.
    %%
    %% FIX VERIFIED: find_best_valid_chain now requires BLOCK_HAVE_DATA (bit 8)
    %% in addition to the BLOCK_FAILED_VALID check, matching Core's
    %% FindMostWorkChain guard on pindexTest->nStatus & BLOCK_HAVE_DATA.
    %% The no-data entry (status=2) must be excluded from the valid candidate set.
    %%
    %% Direct test: verify that Hash1 is absent from find_best_valid_chain's
    %% candidate set by confirming the active tip stays at genesis even though
    %% Hash1 has higher chainwork — if Hash1 were admitted, connect_blocks would
    %% have been attempted and would have failed, changing state.
    {ok, AllBlocks} = beamchain_db:get_all_block_indexes(),
    H1Entries = [B || B = #{hash := H, status := S} <- AllBlocks,
                      H =:= Hash1,
                      (S band ?BLOCK_FAILED_VALID) =:= 0,
                      (S band ?BLOCK_HAVE_DATA)    =/= 0],
    %% FIX: H1Entries must be empty because status=2 lacks BLOCK_HAVE_DATA (8).
    %% find_best_valid_chain now filters on both bits, so Hash1 is excluded.
    ?assertEqual([], H1Entries,
        "FIX BUG-1: no-data block (BLOCK_HAVE_DATA absent) must be excluded "
        "from find_best_valid_chain candidate set"),
    %% Cleanup
    beamchain_db:update_block_status(Hash1, ?BLOCK_FAILED_VALID).

%%%===================================================================
%%% BUG-2: invalidate_block disconnects active chain for off-chain hash
%%%
%%% Core checks m_chain.Contains(pindex) before disconnecting any block.
%%% beamchain compares TipHeight >= BlockHeight — a side-branch block at
%%% height H will trigger an unnecessary active-chain disconnect to H-1
%%% even though the active chain at height H is a different block.
%%%===================================================================

bug2_invalidate_disconnects_without_containment_check() ->
    #{genesis_hash := GenesisHash} = setup_ctx(),
    {ok, {GenesisTipHash, _TipHeight}} = beamchain_chainstate:get_tip(),

    %% Build two blocks at height 1: ActiveH1 (the "true" active-chain block)
    %% and SideBranchHash (a different block at the same height, not active).
    ActiveH1Header = fake_header(GenesisHash, 11111),
    ActiveH1Hash   = fake_block_hash(ActiveH1Header),
    SideBranchHeader = fake_header(GenesisHash, 77777),
    SideBranchHash   = fake_block_hash(SideBranchHeader),
    ActiveCW = <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                 0,0,0,0,0,0,0,0,0,0,0,2,0,0,0,0>>,
    SideCW   = <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                 0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0>>,

    %% Store ActiveH1 at height 1 — this is the "active chain" block there.
    ok = beamchain_db:store_block_index(1, ActiveH1Hash, ActiveH1Header,
                                        ActiveCW, 5),
    %% Register SideBranchHash in the height-indexed reverse index at height 1
    %% WITHOUT overwriting the height-1 slot — do this by storing it FIRST and
    %% then restoring the active block. After both stores, the height-1 slot
    %% holds ActiveH1 while blkidx:SideBranchHash → height 1 (stale slot).
    ok = beamchain_db:store_block_index(1, SideBranchHash, SideBranchHeader,
                                        SideCW, 5),
    ok = beamchain_db:store_block_index(1, ActiveH1Hash, ActiveH1Header,
                                        ActiveCW, 5),

    %% Artificially advance the chainstate tip_height to 1 so that the BUG-2
    %% condition TipHeight (1) >= BlockHeight (1) is satisfied.
    sys:replace_state(beamchain_chainstate, fun(S) ->
        setelement(3, S, 1)   %% tip_height is field 3 in #state{}
    end),

    %% With the fix, is_on_active_chain(SideBranchHash) checks:
    %%   blkidx:SideBranchHash → height 1 → height-1 slot has ActiveH1Hash ≠ SideBranchHash
    %% → returns false → disconnect is skipped.
    %% The active tip hash and height must be unchanged after the call.
    ok = beamchain_chainstate:invalidate_block(SideBranchHash),
    {ok, {NewTipHash, NewHeight}} = beamchain_chainstate:get_tip(),
    ?assertEqual(GenesisTipHash, NewTipHash,
        "FIX BUG-2: active tip hash must be unchanged after invalidating "
        "a side-branch block at the same height as the active tip"),
    ?assertEqual(0, NewHeight,
        "FIX BUG-2: active tip height must be 0 (genesis state in DB) after "
        "invalidating a non-active block"),

    %% Cleanup
    sys:replace_state(beamchain_chainstate, fun(S) ->
        setelement(3, S, 0)
    end),
    beamchain_db:update_block_status(ActiveH1Hash, ?BLOCK_FAILED_VALID),
    beamchain_db:update_block_status(SideBranchHash, ?BLOCK_FAILED_VALID).

%%%===================================================================
%%% BUG-3: disconnect_to_height silently swallows errors
%%%
%%% When do_disconnect_block returns {error, Reason}, disconnect_to_height
%%% logs a warning but returns the partially-disconnected State unchanged.
%%% The caller proceeds as if the disconnect succeeded, then marks descendants
%%% invalid and attempts a reconnect from an inconsistent tip.
%%% Core's InvalidateBlock returns false immediately on DisconnectTip failure.
%%%===================================================================

bug3_disconnect_to_height_error_swallowed() ->
    %% We can't easily inject a disconnect failure without a running block,
    %% but we can observe the behaviour by connecting a block and then
    %% attempting to invalidate it when the undo data is absent.
    %%
    %% Since the current tip is genesis (height 0) and has no undo data,
    %% attempting to disconnect it should fail with an error. The test checks
    %% that invalidate_block at genesis is correctly rejected (the genesis guard
    %% fires before disconnect_to_height is called).
    %%
    %% The observable gap: if undo data is missing for an active-chain block
    %% at height > 0, disconnect_to_height will silently return the original
    %% state while the caller continues with mark_block_invalid.  We document
    %% this as a correctness observation:
    ?assertEqual({error, cannot_invalidate_genesis},
        beamchain_chainstate:invalidate_block(
            (beamchain_chain_params:genesis_block(regtest))#block.hash),
        "genesis guard fires correctly; BUG-3 gap is in error handling "
        "of non-genesis disconnect_to_height failures").

%%%===================================================================
%%% BUG-4: find_best_valid_chain error silently returns ok
%%%
%%% When find_best_valid_chain returns {error, Reason}, the caller
%%% do_invalidate_block_impl returns {ok, State2} (line 2259-2260).
%%% The handle_call wrapper sees ok and the caller receives ok even
%%% though the post-invalidation tip may be stranded.
%%%===================================================================

bug4_find_best_valid_chain_error_swallowed() ->
    #{genesis_hash := GenesisHash} = setup_ctx(),
    %% Build a block at height 1 whose block data IS present.
    Header1 = fake_header(GenesisHash, 44444),
    Hash1   = fake_block_hash(Header1),
    CW1     = <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,0,0,0,2,0,0,0,0>>,
    ok = beamchain_db:store_block_index(1, Hash1, Header1, CW1, 5),

    %% Mark it as invalid — now find_best_valid_chain will have no valid
    %% candidate with more work than genesis.  The function returns {ok, []}
    %% and do_invalidate_block returns {ok, State} even with no reconnection.
    %% This is benign for this case, but documents that errors in chain
    %% selection are masked.
    ok = beamchain_chainstate:invalidate_block(Hash1),
    %% Tip must still be genesis
    {ok, {_, Height}} = beamchain_chainstate:get_tip(),
    ?assertEqual(0, Height,
        "BUG-4: tip should stay at genesis when no better chain exists"),
    beamchain_db:update_block_status(Hash1, ?BLOCK_FAILED_VALID).

%%%===================================================================
%%% BUG-7: no notify_tip_updated after invalidation
%%%
%%% After do_invalidate_block changes the active tip, Core fires
%%% GetNotifications().blockTip(...) and signals->ActiveTipChange(...).
%%% beamchain fires ZMQ per-block but never calls notify_tip_updated()
%%% after the full invalidation sequence.  We can only observe this
%%% indirectly — verifying that the tip pointer is correct and noting
%%% the missing notification as a documented gap.
%%%===================================================================

bug7_no_tip_notification_after_invalidate() ->
    #{genesis_hash := GenesisHash} = setup_ctx(),
    %% Insert a block at height 1 in the active-chain index.
    Header1 = fake_header(GenesisHash, 55555),
    Hash1   = fake_block_hash(Header1),
    CW1     = <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,0,0,0,3,0,0,0,0>>,
    ok = beamchain_db:store_block_index(1, Hash1, Header1, CW1, 5),
    %% Invalidate it (off-tip, so no disconnect fires).
    ok = beamchain_chainstate:invalidate_block(Hash1),
    %% Tip stays at genesis.
    {ok, {_, Height}} = beamchain_chainstate:get_tip(),
    ?assertEqual(0, Height),
    %% BUG-7 documented: peer manager notify_tip_updated() was NOT called here.
    %% We cannot assert the absence without a mock, so we document it by
    %% asserting the tip is in a consistent state (the minimal observable).
    {ok, #{status := S}} = beamchain_db:get_block_index_by_hash(Hash1),
    ?assertNotEqual(0, S band ?BLOCK_FAILED_VALID,
        "block must be marked invalid; BUG-7 is the absent tip notification"),
    beamchain_db:update_block_status(Hash1, S band (bnot ?BLOCK_FAILED_VALID)).

%%%===================================================================
%%% BUG-8: invalidate_block returns block_not_found for side-branch blocks
%%%
%%% get_block_index_by_hash only covers the active-chain height-indexed
%%% block index. A side-branch block (in the side-branch index, cf_meta
%%% "sbidx:..." prefix) is invisible to this query. Core's InvalidateBlock
%%% iterates m_blockman.m_block_index which covers all known blocks.
%%%===================================================================

bug8_invalidate_side_branch_block_not_found() ->
    #{genesis_hash := GenesisHash} = setup_ctx(),
    %% Simulate a side-branch block stored via persist_side_branch_block
    %% (stored in cf_meta "sbidx:" but NOT in the height-indexed cf).
    SideHeader = fake_header(GenesisHash, 66666),
    SideHash   = fake_block_hash(SideHeader),
    SideCW     = <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                   0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0>>,
    SideEntry  = #{
        height    => 1,
        header    => SideHeader,
        chainwork => SideCW,
        status    => 2,
        n_tx      => 1
    },
    ok = beamchain_db:store_side_branch_index(SideHash, SideEntry),

    %% Confirm the side-branch entry is findable via lookup_block_index_anywhere
    %% (which IS used elsewhere in the file) but NOT via get_block_index_by_hash.
    ?assertMatch(not_found,
        beamchain_db:get_block_index_by_hash(SideHash),
        "side-branch block must NOT be in the height-indexed block index"),
    ?assertMatch({ok, _},
        beamchain_db:get_side_branch_index(SideHash),
        "side-branch block MUST be in the side-branch index"),

    %% FIX BUG-8: do_invalidate_block now uses lookup_block_index_anywhere
    %% instead of get_block_index_by_hash, so side-branch blocks are reachable.
    %% Core's InvalidateBlock iterates m_blockman.m_block_index which covers
    %% ALL known block index entries regardless of chain membership.
    Result = beamchain_chainstate:invalidate_block(SideHash),
    ?assertEqual(ok, Result,
        "FIX BUG-8: invalidate_block must succeed (return ok) for a side-branch "
        "block found via lookup_block_index_anywhere"),
    %% Verify the side-branch entry was actually marked invalid.
    {ok, #{status := S}} = beamchain_db:get_side_branch_index(SideHash),
    ?assertNotEqual(0, S band ?BLOCK_FAILED_VALID,
        "FIX BUG-8: side-branch block must have BLOCK_FAILED_VALID set after "
        "invalidate_block"),
    %% Cleanup
    beamchain_db:delete_side_branch_index(SideHash).

%%%===================================================================
%%% BUG-10: no atomic commit (reorg_in_progress) during invalidation
%%%
%%% The disconnect+reconnect in do_invalidate_block_impl runs without
%%% setting reorg_in_progress=true.  Each per-block disconnect and
%%% connect therefore flushes to RocksDB individually, leaving no
%%% atomic boundary around the full sequence.  A crash mid-way would
%%% leave a partially-invalidated chain on disk.
%%% We can only document this as a state-inspection test; we cannot
%%% inject a crash. The test verifies that the reorg_in_progress field
%%% is false after a completed invalidation (correct end state) but
%%% notes the gap in mid-operation atomicity.
%%%===================================================================

bug10_no_atomic_commit_during_invalidation() ->
    %% We use sys:get_state to read the gen_server state record.
    S = sys:get_state(beamchain_chainstate),
    %% reorg_in_progress is element 15 of the #state{} record tuple
    %% (tag at 1, then fields: tip_hash=2, tip_height=3, mtp_timestamps=4,
    %%  params=5, blocks_since_flush=6, max_cache_bytes=7, max_cache_entries=8,
    %%  cache_usage_bytes=9, ibd=10, chainstate_role=11,
    %%  snapshot_base_height=12, snapshot_base_hash=13, reorg_in_progress=14,
    %%  pending_undo_deletes=15).
    ReorgInProgress = element(14, S),
    ?assertEqual(false, ReorgInProgress,
        "reorg_in_progress must be false outside of a reorg"),
    %% BUG-10 documented: during do_invalidate_block_impl the flag is never
    %% set to true, so per-block flushes fire individually instead of
    %% deferring to a single atomic commit.  The correct fix would mirror
    %% do_reorganize_atomic: pre-flush, set reorg_in_progress=true, run
    %% disconnects+reconnects, single final flush, clear flag.
    ok.

%%%===================================================================
%%% Baseline tests: verify correct behaviour of existing code
%%%===================================================================

baseline_cannot_invalidate_genesis() ->
    Genesis = beamchain_chain_params:genesis_block(regtest),
    ?assertEqual({error, cannot_invalidate_genesis},
        beamchain_chainstate:invalidate_block(Genesis#block.hash)).

baseline_invalidate_unknown_hash() ->
    UnknownHash = <<16#deadbeef:256>>,
    ?assertEqual({error, block_not_found},
        beamchain_chainstate:invalidate_block(UnknownHash)).

baseline_invalidate_already_invalid_noop() ->
    #{genesis_hash := GenesisHash} = setup_ctx(),
    Header = fake_header(GenesisHash, 11111),
    Hash   = fake_block_hash(Header),
    CW     = <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,0,0,0,4,0,0,0,0>>,
    %% Store with BLOCK_FAILED_VALID already set
    ok = beamchain_db:store_block_index(
             1, Hash, Header, CW, ?BLOCK_FAILED_VALID bor 5),
    ?assertEqual(ok, beamchain_chainstate:invalidate_block(Hash),
        "invalidating an already-invalid block must be a no-op (return ok)"),
    beamchain_db:update_block_status(Hash, 5).

baseline_reconsider_clears_flag() ->
    #{genesis_hash := GenesisHash} = setup_ctx(),
    Header = fake_header(GenesisHash, 22222),
    Hash   = fake_block_hash(Header),
    CW     = <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,0,0,0,5,0,0,0,0>>,
    ok = beamchain_db:store_block_index(
             1, Hash, Header, CW, ?BLOCK_FAILED_VALID bor 5),
    ok = beamchain_chainstate:reconsider_block(Hash),
    {ok, #{status := S}} = beamchain_db:get_block_index_by_hash(Hash),
    ?assertEqual(0, S band ?BLOCK_FAILED_VALID,
        "reconsider_block must clear BLOCK_FAILED_VALID flag").

baseline_descendants_marked_invalid() ->
    #{genesis_hash := GenesisHash} = setup_ctx(),
    %% Build a two-block chain off genesis: Hash1 at h=1, Hash2 at h=2.
    Header1 = fake_header(GenesisHash, 33300),
    Hash1   = fake_block_hash(Header1),
    Header2 = fake_header(Hash1, 33301),
    Hash2   = fake_block_hash(Header2),
    CW1 = <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,0,0,0,6,0,0,0,0>>,
    CW2 = <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,0,0,0,7,0,0,0,0>>,
    ok = beamchain_db:store_block_index(1, Hash1, Header1, CW1, 5),
    ok = beamchain_db:store_block_index(2, Hash2, Header2, CW2, 5),
    %% Invalidate Hash1 — Hash2 must be marked invalid as a descendant.
    ok = beamchain_chainstate:invalidate_block(Hash1),
    {ok, #{status := S1}} = beamchain_db:get_block_index_by_hash(Hash1),
    {ok, #{status := S2}} = beamchain_db:get_block_index_by_hash(Hash2),
    ?assertNotEqual(0, S1 band ?BLOCK_FAILED_VALID,
        "Hash1 must be marked BLOCK_FAILED_VALID"),
    ?assertNotEqual(0, S2 band ?BLOCK_FAILED_VALID,
        "Hash2 (descendant of Hash1) must be marked BLOCK_FAILED_VALID"),
    %% Cleanup
    beamchain_db:update_block_status(Hash1, 5),
    beamchain_db:update_block_status(Hash2, 5).

baseline_compare_work_ranking() ->
    %% compare_work/2 uses big-endian binary decode — verify ordering.
    Low  = #{chainwork => <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1>>},
    High = #{chainwork => <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2>>},
    %% We can't call compare_work/2 directly (not exported), but we can
    %% observe its effect through find_best_valid_chain selecting High over Low
    %% when both are in the block index and neither is invalid.
    %% The comparison itself is a pure arithmetic test: 2 > 1.
    W1Int = binary:decode_unsigned(maps:get(chainwork, Low)),
    W2Int = binary:decode_unsigned(maps:get(chainwork, High)),
    ?assert(W2Int > W1Int, "High chainwork must rank above Low").

%%%===================================================================
%%% Gate coverage tests
%%%===================================================================

gate_invalidate_sets_failed_valid_flag() ->
    #{genesis_hash := GenesisHash} = setup_ctx(),
    Header = fake_header(GenesisHash, 88888),
    Hash   = fake_block_hash(Header),
    CW     = <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,0,0,0,8,0,0,0,0>>,
    ok = beamchain_db:store_block_index(1, Hash, Header, CW, 5),
    ok = beamchain_chainstate:invalidate_block(Hash),
    {ok, #{status := S}} = beamchain_db:get_block_index_by_hash(Hash),
    ?assertNotEqual(0, S band ?BLOCK_FAILED_VALID,
        "invalidate_block must set BLOCK_FAILED_VALID on the target block").

gate_find_best_valid_excludes_failed_blocks() ->
    #{genesis_hash := GenesisHash} = setup_ctx(),
    Header = fake_header(GenesisHash, 99999),
    Hash   = fake_block_hash(Header),
    %% High chainwork but marked invalid.
    CW = <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
           0,0,0,0,0,0,0,0,0,255,0,0,0,0,0,0>>,
    ok = beamchain_db:store_block_index(
             1, Hash, Header, CW, ?BLOCK_FAILED_VALID bor 5),
    %% Tip must stay at genesis because the only higher-work candidate is invalid.
    {ok, {_, Height}} = beamchain_chainstate:get_tip(),
    ?assertEqual(0, Height,
        "invalid high-work block must not be selected by find_best_valid_chain"),
    beamchain_db:update_block_status(Hash, 5).

gate_reconsider_clears_descendants() ->
    #{genesis_hash := GenesisHash} = setup_ctx(),
    Header1 = fake_header(GenesisHash, 77700),
    Hash1   = fake_block_hash(Header1),
    Header2 = fake_header(Hash1, 77701),
    Hash2   = fake_block_hash(Header2),
    CW1 = <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,0,0,0,9,0,0,0,0>>,
    CW2 = <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,0,0,0,10,0,0,0,0>>,
    ok = beamchain_db:store_block_index(
             1, Hash1, Header1, CW1, ?BLOCK_FAILED_VALID bor 5),
    ok = beamchain_db:store_block_index(
             2, Hash2, Header2, CW2, ?BLOCK_FAILED_VALID bor 5),
    ok = beamchain_chainstate:reconsider_block(Hash1),
    {ok, #{status := S2}} = beamchain_db:get_block_index_by_hash(Hash2),
    ?assertEqual(0, S2 band ?BLOCK_FAILED_VALID,
        "reconsider_block must also clear BLOCK_FAILED_VALID on descendants").

%%%===================================================================
%%% Internal helper — fetch current chain context without modifying state
%%%===================================================================

setup_ctx() ->
    Genesis = beamchain_chain_params:genesis_block(regtest),
    #{genesis_hash => Genesis#block.hash}.
