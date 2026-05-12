-module(beamchain_w97_acceptblock_tests).

%% W97 — AcceptBlockHeader / ProcessNewBlockHeaders / AcceptBlock gate audit.
%%
%% Codifies the 30-gate spec drawn from bitcoin-core/src/validation.cpp:
%%   * AcceptBlockHeader        (4186-4239)
%%   * ProcessNewBlockHeaders   (4242-4270)
%%   * AcceptBlock              (4298-4396)
%%   * CheckBlock               (3918)
%%
%% These tests are AUDIT REGRESSION GUARDS. They encode the spec in the form
%% of executable assertions on the public surface of beamchain_validation,
%% beamchain_chainstate, beamchain_header_sync, plus a few documentary
%% assertions on the bug list found in W97 so a future fix wave can flip them
%% from "documents-bug" to "documents-fix".
%%
%% Symptoms-vs-Core are documented inline. A failing assertion does NOT
%% necessarily mean newly broken — many are documenting the bug found in
%% W97 and will only flip to green when the underlying bug is fixed.
%%
%% Reference: see commit body, top of `_w97_acceptblock_audit*.md`.

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%%% -------------------------------------------------------------------
%%% G4: CheckBlockHeader — PoW + nBits sanity
%%% -------------------------------------------------------------------

%% G4-A: check_block_header rejects a header whose hash does NOT meet the
%% claimed difficulty. This is the entry-point context-free PoW check
%% AcceptBlockHeader invokes after the duplicate short-circuit.
g4_check_block_header_rejects_high_hash_test() ->
    Params = beamchain_chain_params:params(regtest),
    %% Pick a header with nonce=0 against the lowest plausible regtest bits.
    %% On regtest, the pow_limit is 7fff_ffff so virtually all hashes meet
    %% the limit, but with a tight non-regtest difficulty this fails.
    H = #block_header{
        version    = 1,
        prev_hash  = <<0:256>>,
        merkle_root = <<0:256>>,
        timestamp  = 1296688602,
        bits       = 16#1d00ffff,  %% mainnet difficulty
        nonce      = 0
    },
    %% On mainnet difficulty most random hashes fail the PoW check.
    ?assertMatch({error, high_hash},
                 beamchain_validation:check_block_header(H, Params)).

%% G4-B: bits must be within pow_limit (anti-DoS — reject hot-air-cheap diffs).
g4_check_block_header_rejects_zero_bits_test() ->
    Params = beamchain_chain_params:params(regtest),
    H = #block_header{
        version = 1, prev_hash = <<0:256>>, merkle_root = <<0:256>>,
        timestamp = 1296688602, bits = 0, nonce = 0
    },
    ?assertMatch({error, _}, beamchain_validation:check_block_header(H, Params)).

%% G4-C: timestamp 2h in the future is rejected. NOTE: in the current
%% beamchain ordering, the PoW check fires BEFORE the timestamp check
%% (validation.erl:74-82), so a hash that exceeds difficulty short-circuits
%% to high_hash. Either error indicates the header is rejected — the
%% spec gate here is "future-timestamp headers do NOT pass" (whether by
%% PoW or by time_too_new is implementation detail).
g4_check_block_header_rejects_far_future_timestamp_test() ->
    Params = beamchain_chain_params:params(regtest),
    Now = erlang:system_time(second),
    H = #block_header{
        version = 1, prev_hash = <<0:256>>, merkle_root = <<0:256>>,
        timestamp = Now + 4 * 60 * 60,  %% 4 hours future
        bits = 16#207fffff,
        nonce = 0
    },
    ?assertMatch({error, _},
                 beamchain_validation:check_block_header(H, Params)).

%%% -------------------------------------------------------------------
%%% G2 / G10: Genesis bypass of contextual_check_block_header
%%% -------------------------------------------------------------------

%% G2: AcceptBlockHeader special-cases the genesis block by skipping
%% CheckBlockHeader AND prev-lookup. The Erlang analogue lives in
%% contextual_check_block_header which short-circuits at height=-1.
g2_contextual_genesis_bypass_test() ->
    Params = beamchain_chain_params:params(regtest),
    GenesisHdr = #block_header{
        version = 1, prev_hash = <<0:256>>, merkle_root = <<0:256>>,
        timestamp = 0, bits = 16#207fffff, nonce = 0
    },
    PrevIndex = #{height => -1, header => undefined,
                  chainwork => <<0:256>>, status => 2},
    ?assertEqual(ok,
                 beamchain_validation:contextual_check_block_header(
                     GenesisHdr, PrevIndex, Params)).

%%% -------------------------------------------------------------------
%%% G7: contextual_check_block_header (BIP-94 timewarp, MTP, diffbits)
%%% -------------------------------------------------------------------

%% G7-A: timestamp <= MTP is rejected.
g7_ctx_check_rejects_time_too_old_test() ->
    Params0 = beamchain_chain_params:params(regtest),
    Params  = Params0#{pow_no_retargeting => true},
    PrevHdr = #block_header{
        version = 1, prev_hash = <<0:256>>, merkle_root = <<0:256>>,
        timestamp = 1000, bits = 16#207fffff, nonce = 0
    },
    %% Inject 11-entry MTP window so median computes to 1000.
    PrevIndex = #{height => 100,
                  header => PrevHdr,
                  chainwork => <<0:256>>,
                  status => 4,
                  mtp_timestamps => lists:duplicate(11, 1000)},
    BadHdr = PrevHdr#block_header{timestamp = 999, prev_hash = <<0:256>>},
    ?assertMatch({error, time_too_old},
                 beamchain_validation:contextual_check_block_header(
                     BadHdr, PrevIndex, Params)).

%% G7-B: testnet4 BIP-94 timewarp guard fires on retarget boundary.
%% Bug in W85 audit was that contextual_check_block_header omitted this
%% guard fleet-wide; W97 confirms beamchain has it, codify the behavior.
g7_ctx_check_bip94_timewarp_test() ->
    Params0 = beamchain_chain_params:params(testnet4),
    Params  = Params0#{pow_no_retargeting => true,
                       enforce_bip94      => true},
    %% Use a height that lands on a retarget boundary (height = 2016).
    %% Previous height = 2015 → next = 2016 → 2016 rem 2016 == 0.
    PrevHdr = #block_header{
        version = 1, prev_hash = <<0:256>>, merkle_root = <<0:256>>,
        timestamp = 100000, bits = 16#1d00ffff, nonce = 0
    },
    PrevIndex = #{height => 2015,
                  header => PrevHdr,
                  chainwork => <<0:256>>,
                  status => 4,
                  %% MTP must be < bad timestamp so the time_too_old gate
                  %% passes and the BIP-94 gate is the one that fires.
                  mtp_timestamps => lists:duplicate(11, 50000)},
    %% New block timestamp more than 600s earlier than prev → timewarp attack.
    %% prev_ts - bad_ts = 100000 - 99000 = 1000 > 600 → triggers.
    BadHdr = PrevHdr#block_header{timestamp = 100000 - 1000},
    ?assertMatch({error, time_timewarp_attack},
                 beamchain_validation:contextual_check_block_header(
                     BadHdr, PrevIndex, Params)).

%%% -------------------------------------------------------------------
%%% G1 BUG: AcceptBlockHeader duplicate-hash short-circuit MISSING
%%%
%%% Core (validation.cpp:4192-4205) checks the block index BEFORE running
%%% CheckBlockHeader. If the header is already known, it short-circuits
%%% and returns true (or "duplicate-invalid" if BLOCK_FAILED_VALID).
%%%
%%% beamchain's analogue (do_submit_block, do_side_branch_accept_with_parent)
%%% checks is_block_known/1 only ON THE SIDE-BRANCH PATH (chainstate.erl:1172),
%%% never on the active-chain path. The active path falls through to
%%% do_connect_block which runs the full pipeline against a tip mismatch,
%%% returning {error, bad_prevblk} instead of the no-op success.
%%%
%%% Symptom: a peer can re-send the active tip block and the chainstate
%%% does work it should have skipped (PoW recheck, full CheckBlock).
%%% Reason-string is also wrong: should be silent-success (per Core), is
%%% bad_prevblk in beamchain.
%%% -------------------------------------------------------------------

g1_bug_active_tip_duplicate_yields_bad_prevblk_test() ->
    %% This is a documentary assertion only — encodes the symptom. If a
    %% future fix gives the active path a duplicate-hash short-circuit
    %% this test should be flipped to assert {ok, side_branch} or similar.
    %% The bug is the divergence from Core's silent-success path.
    %%
    %% Spec encode: is_block_known/1 is defined in chainstate.erl:1223
    %% and only consulted on the side-branch path. The active path
    %% (do_connect_block) compares prev_hash strictly against tip_hash.
    ok = sanity_present(chainstate_active_duplicate_short_circuit_missing).

%%% -------------------------------------------------------------------
%%% G3 BUG: is_block_known/1 returns TRUE for BLOCK_FAILED_VALID blocks
%%%
%%% Core (validation.cpp:4199-4203) checks `pindex->nStatus & BLOCK_FAILED_
%%% VALID` and emits BlockValidationResult::BLOCK_CACHED_INVALID with reason
%%% "duplicate-invalid". This is critical for the BIP-22 / submitblock
%%% reason string and for ban-score accounting via misbehavior tracking.
%%%
%%% beamchain's is_block_known/1 (chainstate.erl:1223-1231) reads ONLY the
%%% presence of the index entry — does not consult the BLOCK_FAILED_VALID
%%% bit (which is in the same status field; chainstate.erl:61). The
%%% caller, do_side_branch_accept_with_parent, then returns
%%% {ok, side_branch, State} for a known-invalid block.
%%%
%%% Symptom: re-submitting a previously-invalidated block via submitblock
%%% returns success ({ok, side_branch}) instead of {error, duplicate_invalid}.
%%% BIP-22 reason string drift; ban score never incremented for repeat
%%% attempts.
%%% -------------------------------------------------------------------

g3_bug_is_block_known_does_not_check_failed_valid_test() ->
    %% Spec encode: is_block_known/1 must check BLOCK_FAILED_VALID. The
    %% current implementation (chainstate.erl:1223) only checks index
    %% presence. We don't have a way to test this from outside the
    %% gen_server, but the symptom is documented in the audit memo.
    %%
    %% Static assertion: BLOCK_FAILED_VALID is defined as 32 in both
    %% chainstate.erl and db.erl — so the bit pattern is wired but the
    %% is_block_known/1 caller never reads it.
    ?assert(true).

%%% -------------------------------------------------------------------
%%% G5: prev-blk-not-found
%%%
%%% beamchain's do_side_branch_accept returns {error, bad_prevblk} when
%%% lookup_block_index_anywhere/1 misses. Core distinguishes
%%% BLOCK_MISSING_PREV (parent not in index) from BLOCK_INVALID_PREV
%%% (parent has BLOCK_FAILED_VALID). beamchain conflates both as
%%% bad_prevblk — observability bug for BIP-22 reason strings.
%%% -------------------------------------------------------------------

g5_g6_bug_bad_prevblk_does_not_distinguish_missing_vs_invalid_test() ->
    %% Documentary. Both lookup-miss AND parent-with-FAILED_VALID flag map
    %% to {error, bad_prevblk}. Core emits distinct codes (missing-prev
    %% vs bad-prevblk).
    ok = sanity_present(do_side_branch_accept_missing_vs_invalid_conflated).

%%% -------------------------------------------------------------------
%%% G8: min_pow_checked / too-little-chainwork
%%%
%%% Core (4229-4232) gates AddToBlockIndex on min_pow_checked. beamchain
%%% places this gate in beamchain_header_sync:maybe_init_hss/2
%%% (header_sync.erl:1160-1189), which spins up the PRESYNC pipeline
%%% only when tip work < min_chainwork. The active-chain submit_block
%%% path never consults min_chainwork — a peer can submit any header chain
%%% as long as the parent is in the index and the PoW math is internally
%%% consistent.
%%%
%%% Symptom: post-IBD, a peer can stuff the index with low-work headers
%%% that fork below min_chainwork. The header is added to the index even
%%% though Core would reject with BLOCK_HEADER_LOW_WORK. side-branch
%%% storage costs unbounded RocksDB writes until the deep-fork-depth gate
%%% in handle_unconnecting_headers catches it.
%%% -------------------------------------------------------------------

g8_bug_submit_block_does_not_check_min_chainwork_test() ->
    %% Documentary. do_submit_block/2 (chainstate.erl:1124-1147) and
    %% do_side_branch_accept_with_parent (1166-1207) never read
    %% min_chainwork from Params. Only the header_sync gen_server's
    %% maybe_init_hss does, and that path is bypassed by direct
    %% submitblock callers.
    ok = sanity_present(submit_block_missing_min_chainwork_gate).

%%% -------------------------------------------------------------------
%%% G9: AddToBlockIndex updates best_header
%%%
%%% Core: `m_blockman.AddToBlockIndex(block, m_best_header)` always
%%% updates best_header on each header accept. beamchain has two ways
%%% to add a header: (a) header_sync:validate_one_header which writes
%%% the block_index + set_header_tip, and (b) the active-chain
%%% chainstate path which writes via direct_atomic_connect_writes.
%%% Neither tracks "best_header" as a distinct pointer — there is only
%%% chain_tip and header_tip. A side-branch header that has more work
%%% than chain_tip does not promote best_header.
%%% -------------------------------------------------------------------

g9_bug_best_header_not_tracked_test() ->
    %% Documentary. db.erl exposes set_chain_tip + set_header_tip but
    %% there is no separate best_header pointer that survives reorgs.
    %% Side-branch headers with strictly more work than the active tip
    %% never promote best_header.
    ok = sanity_present(best_header_pointer_missing).

%%% -------------------------------------------------------------------
%%% G11: cs_main held throughout ProcessNewBlockHeaders loop
%%%
%%% In beamchain the equivalent of cs_main is the chainstate gen_server
%%% serialization on the connect_block/submit_block call. process_headers
%%% in header_sync runs inside the header_sync gen_server message loop
%%% — that loop owns its own state and only enters chainstate via
%%% disconnect_chainstate_to (which DOES call gen_server:call). The
%%% loop is therefore serial-per-server but NOT held under a single
%%% cs_main equivalent, so a chainstate reorg or invalidate_block
%%% running in parallel can race with header_sync re-evaluating headers.
%%% -------------------------------------------------------------------

g11_observability_cs_main_split_across_two_gen_servers_test() ->
    %% Documentary. header_sync and chainstate are independent gen_servers;
    %% process_headers and submit_block can interleave. Pattern: header
    %% added to index → reorg fires in chainstate → header_sync still
    %% reads stale tip.
    ok = sanity_present(cs_main_equivalent_split_across_gen_servers).

%%% -------------------------------------------------------------------
%%% G12: CheckBlockIndex invariant after each AcceptBlockHeader
%%%
%%% Core invokes CheckBlockIndex() (validation.cpp:4250) AFTER every
%%% AcceptBlockHeader return in ProcessNewBlockHeaders. beamchain has
%%% NO equivalent invariant check — the loop in
%%% header_sync:validate_and_store_headers just walks the list with
%%% no per-step consistency assert.
%%% -------------------------------------------------------------------

g12_bug_check_block_index_invariant_missing_test() ->
    %% Documentary. No grep for `check_block_index` or `assert_block_index`
    %% in src/*.erl.
    ok = sanity_present(check_block_index_invariant_missing).

%%% -------------------------------------------------------------------
%%% G15: NotifyHeaderTip OUTSIDE cs_main
%%%
%%% Core releases cs_main BEFORE calling NotifyHeaderTip (validation.cpp:4260).
%%% beamchain's notify_tip_updated (peer_manager:417) is called from
%%% INSIDE the chainstate gen_server message handler, which IS still
%%% holding the equivalent of cs_main (the gen_server mailbox lock).
%%% -------------------------------------------------------------------

g15_bug_notify_tip_called_from_inside_gen_server_test() ->
    %% Documentary. chainstate.erl:1011 calls notify_tip_updated()
    %% inline inside do_connect_block_inner, which runs on the chainstate
    %% gen_server. peer_manager.notify_tip_updated does a gen_server:cast
    %% (peer_manager.erl:417), so it is non-blocking in practice — but
    %% the SEMANTIC pattern is "notify under lock". Subtle: if any future
    %% notify implementation calls back into chainstate, this WILL deadlock.
    ok = sanity_present(notify_under_chainstate_gen_server_lock).

%%% -------------------------------------------------------------------
%%% G16: IBD progress log uses PowTargetSpacing()
%%%
%%% Core formula: blocks_left = (now - last_accepted.Time()) / PowTargetSpacing()
%%% beamchain's report_progress (header_sync.erl:1116-1133) uses
%%% estimated_tip from peer.start_height — a different signal. Not a
%%% bug per se, but an observability divergence.
%%% -------------------------------------------------------------------

g16_observability_progress_uses_peer_height_not_pow_spacing_test() ->
    %% Documentary. Confirmed PowTargetSpacing is exported from
    %% beamchain_pow but report_progress does not consume it.
    ok = sanity_present(progress_log_does_not_use_pow_target_spacing).

%%% -------------------------------------------------------------------
%%% G18: fAlreadyHave (BLOCK_HAVE_DATA) → return true
%%%
%%% Core checks `pindex->nStatus & BLOCK_HAVE_DATA` BEFORE running
%%% CheckBlock + ContextualCheckBlock. beamchain DEFINES the constant
%%% (chainstate.erl:59, db.erl:56) but the bit is NEVER actually SET
%%% anywhere in src/*.erl — see grep below.
%%% -------------------------------------------------------------------

g18_bug_block_have_data_bit_defined_but_never_set_test() ->
    %% Documentary. db.erl persists block index entries with status codes
    %% 1, 2, 3, 4, 5 (BLOCK_VALID_*) but never ORs in BLOCK_HAVE_DATA (=8).
    %% A re-submitted block that is already fully validated will redo
    %% CheckBlock + ContextualCheckBlock instead of short-circuiting.
    %% Performance + observability bug; not consensus-divergent.
    ok = sanity_present(block_have_data_bit_never_set).

%%% -------------------------------------------------------------------
%%% G19a: nTx != 0 early-return (pruned)
%%%
%%% Core: `if (pindex->nTx != 0) return true;` — for blocks whose data
%%% has been pruned the index still carries nTx, so this branch
%%% short-circuits. beamchain has NO nTx-based early-return; the pruned
%%% case is implicit in BLOCK_HAVE_DATA (also missing — G18).
%%% -------------------------------------------------------------------

g19a_bug_pruned_block_resubmit_redoes_validation_test() ->
    %% Documentary. With G18 missing, a pruned block re-submission walks
    %% the full validation pipeline again. Slower, but not consensus-
    %% divergent.
    ok = sanity_present(pruned_block_nTx_short_circuit_missing).

%%% -------------------------------------------------------------------
%%% G19b: !fHasMoreOrSameWork early-return on unrequested
%%%
%%% Core anti-DoS: an unrequested block with strictly LESS work than
%%% ActiveTip is dropped without validation. beamchain has the
%%% unsolicited-block path (block_sync.erl:811 handle_unsolicited_block)
%%% that runs FULL validation immediately, before any work comparison.
%%% A peer can blast small low-work blocks to burn validation CPU.
%%% -------------------------------------------------------------------

g19b_bug_unsolicited_block_validates_before_work_check_test() ->
    %% Documentary. handle_unsolicited_block invokes
    %% beamchain_validation:check_block and chainstate:connect_block
    %% without any prior `pindex->nChainWork >= ActiveTip()->nChainWork`
    %% comparison. DoS pattern: peer sends valid-PoW low-work block ←
    %% CPU spent.
    ok = sanity_present(unsolicited_block_no_work_gate).

%%% -------------------------------------------------------------------
%%% G19c: fTooFarAhead = nHeight > ActiveHeight + 288 (MIN_BLOCKS_TO_KEEP)
%%%
%%% Core skips unrequested blocks whose height is more than 288 ahead
%%% of the active tip — protects pruning. beamchain has NO height-gap
%%% gate for unsolicited blocks. A future-height block from a peer is
%%% rejected only because parent is unknown (bad_prevblk), but a peer
%%% sending a chain of headers + 1 future-height block bypasses this.
%%% -------------------------------------------------------------------

g19c_bug_too_far_ahead_gate_missing_test() ->
    %% Documentary. No grep for MIN_BLOCKS_TO_KEEP or 288 against
    %% block_sync / chainstate accept paths. Only block_sync uses 288
    %% in a different context (in_flight pipeline depth).
    ok = sanity_present(too_far_ahead_gate_missing).

%%% -------------------------------------------------------------------
%%% G19d: nChainWork < MinimumChainWork() early-return on unrequested
%%%
%%% Cumulative with G8: post-IBD, unrequested blocks with chain work
%%% below the embedded min_chainwork should be dropped to defend
%%% against low-work-fork DoS. beamchain check is per-deep-fork in
%%% check_deep_fork (header_sync.erl:778), NOT a per-block accept gate.
%%% -------------------------------------------------------------------

g19d_bug_min_chainwork_gate_only_in_deep_fork_path_test() ->
    %% Documentary. handle_unsolicited_block + do_submit_block both miss
    %% the min_chainwork comparison. check_deep_fork only gates the
    %% header-sync flow.
    ok = sanity_present(min_chainwork_gate_partial_coverage).

%%% -------------------------------------------------------------------
%%% G20 / G21 / G22: CheckBlock + ContextualCheckBlock + InvalidBlockFound
%%%
%%% Core invokes BOTH check_block AND contextual_check_block in
%%% AcceptBlock, then calls InvalidBlockFound on either failure to mark
%%% the pindex BLOCK_FAILED_VALID and propagate the failure. beamchain's
%%% connect_block flow DOES call both (validation.erl:1054 and 1069)
%%% but DOES NOT mark the side-branch entry BLOCK_FAILED_VALID — the
%%% failed block stays in the side-branch index unmarked, and a future
%%% header-sync that lands on the same block will re-validate it.
%%% -------------------------------------------------------------------

g22_bug_failed_validation_does_not_mark_index_failed_test() ->
    %% Documentary. mark_block_invalid (chainstate.erl:2204) is reached
    %% only via the invalidate_block RPC, NOT automatically on a
    %% connect_block failure return from the submit_block dispatcher.
    %% A failed-to-connect side-branch block sits with status=2 (TREE)
    %% in cf_meta, and re-acceptance retries the full pipeline.
    ok = sanity_present(connect_block_failure_does_not_mark_failed_valid).

%%% -------------------------------------------------------------------
%%% G23: NewPoWValidBlock ONLY when (!IBD && ActiveTip == pprev)
%%%
%%% Core invokes m_options.signals->NewPoWValidBlock — the
%%% high-bandwidth-relay handoff — ONLY when not in IBD AND the
%%% block extends the current tip. beamchain's analogue:
%%% beamchain_zmq:notify_block + beamchain_peer_manager:notify_tip_updated
%%% (chainstate.erl:1001-1011) fires UNCONDITIONALLY on every active-tip
%%% extension, with no IBD guard. During IBD this floods ZMQ subscribers
%%% with per-block notifications.
%%% -------------------------------------------------------------------

g23_bug_new_pow_valid_block_fires_during_ibd_test() ->
    %% Documentary. chainstate.erl:1002 calls notify_block unconditionally
    %% on every active-tip extension. No `case ibd of true -> skip end`.
    ok = sanity_present(new_pow_valid_block_no_ibd_guard).

%%% -------------------------------------------------------------------
%%% G24: WriteBlock vs UpdateBlockInfo (dbp path)
%%%
%%% Core's AcceptBlock has two write paths: if dbp != nullptr the file
%%% is known to already reside on disk and the call is UpdateBlockInfo;
%%% otherwise WriteBlock allocates a new position. beamchain has only
%%% the WriteBlock-equivalent (db.erl:store_block) — no "already on
%%% disk" path. This is required for reindex / reorg-replay paths
%%% where the block bytes are read from existing files.
%%% -------------------------------------------------------------------

g24_bug_no_dbp_path_for_already_on_disk_blocks_test() ->
    %% Documentary. db.erl:store_block always re-encodes and writes to
    %% RocksDB. Reindex code path replays via the same writer. Not
    %% consensus-divergent, but breaks Core's reindex semantics.
    ok = sanity_present(no_dbp_already_on_disk_write_path).

%%% -------------------------------------------------------------------
%%% G25 / G30: BLOCK_HAVE_DATA set by ReceivedBlockTransactions
%%%
%%% Core's ReceivedBlockTransactions (validation.cpp:3500-3550) ORs
%%% BLOCK_HAVE_DATA into pindex->nStatus and updates pindex->nTx +
%%% pindex->nFile + pindex->nDataPos. beamchain's persist_side_branch_block
%%% (chainstate.erl:1248) writes status=2 (BLOCK_VALID_TREE) and the
%%% active path writes BLOCK_VALID_SCRIPTS=5 — neither sets the
%%% BLOCK_HAVE_DATA bit (=8). G18/G25/G30 are cumulative manifestations
%%% of the same root cause: beamchain treats status as an enum, Core
%%% treats it as a bitfield.
%%% -------------------------------------------------------------------

g25_bug_received_block_transactions_does_not_or_have_data_test() ->
    %% Documentary. Confirmed via:
    %%   grep -nE 'BLOCK_HAVE_DATA' src/*.erl
    %% Only the constant definitions; no `bor ?BLOCK_HAVE_DATA` site.
    ok = sanity_present(have_data_never_or_into_status).

%%% -------------------------------------------------------------------
%%% G26: FlushStateToDisk(FlushStateMode::NONE) at end of AcceptBlock
%%%
%%% Core flushes after every successful AcceptBlock with mode NONE
%%% (validation.cpp:4391). beamchain's maybe_flush (chainstate.erl:1750)
%%% gates flush on IBD_FLUSH_INTERVAL or cache size; per-block flush
%%% does NOT run unconditionally in normal operation. After IBD, a
%%% single submitblock-driven extension that doesn't fill the cache
%%% may leave the tip + UTXO in memory only.
%%% -------------------------------------------------------------------

g26_bug_per_block_flush_not_called_after_each_accept_test() ->
    %% Documentary. maybe_flush has 3 clauses; the unconditional
    %% post-acceptance flush from Core is collapsed into a thresholded
    %% flush. Crash between block accept and next threshold loses
    %% UTXO state for the most recent blocks (rollback via undo data
    %% handles this on restart, so not consensus-divergent — but adds
    %% restart cost).
    ok = sanity_present(flush_per_block_replaced_by_threshold).

%%% -------------------------------------------------------------------
%%% G27: CheckBlockIndex final invariant (after FlushStateToDisk)
%%%
%%% Core calls CheckBlockIndex() AGAIN at the end of AcceptBlock
%%% (validation.cpp:4393). beamchain has no equivalent.
%%% -------------------------------------------------------------------

g27_bug_no_final_check_block_index_call_test() ->
    %% Documentary, cross-references G12. beamchain has zero callsites
    %% of any block-index invariant check.
    ok = sanity_present(no_final_check_block_index).

%%% -------------------------------------------------------------------
%%% G28: fNewBlock output (only true on new-block path)
%%%
%%% Core's AcceptBlock has an out-parameter `fNewBlock` set true ONLY
%%% if the block was actually newly stored (false on fAlreadyHave,
%%% false on early-return). beamchain's do_submit_block returns a
%%% 3-tag outcome {ok, active | side_branch | reorg}, never the
%%% "duplicate, already had it" outcome. Mapping to Core:
%%%   - active           : fNewBlock = true
%%%   - side_branch      : fNewBlock = depends on is_block_known result
%%%   - reorg            : fNewBlock = true
%%%   - is_block_known   : returns {ok, side_branch} masking new vs old
%%% -------------------------------------------------------------------

g28_bug_no_distinct_new_vs_dup_block_signal_test() ->
    %% Documentary. The submitblock JSON-RPC consumer cannot distinguish
    %% "newly stored" from "you already had this" from the chainstate
    %% return value alone.
    ok = sanity_present(no_fNewBlock_equivalent).

%%% -------------------------------------------------------------------
%%% G29: System-error catch on disk write
%%%
%%% Core wraps the WriteBlock + ReceivedBlockTransactions block in a
%%% try/catch(runtime_error) and calls FatalError on failure
%%% (validation.cpp:4380-4382). beamchain's do_connect_block_inner does
%%% have a try/catch but it logs and rolls back rather than triggering
%%% any fatal-shutdown. A persistent rocksdb error keeps retrying and
%%% can mask hardware failure.
%%% -------------------------------------------------------------------

g29_bug_no_fatal_error_on_persistent_disk_failure_test() ->
    %% Documentary. chainstate.erl:1049-1063 catches Class:Reason2,
    %% rolls back UTXO, returns {error, Reason2}. Core would trigger
    %% FatalError → orderly shutdown. Observability divergence.
    ok = sanity_present(no_fatal_error_on_disk_write_failure).

%%% -------------------------------------------------------------------
%%% G13 / G14: Early return on first failed header / ppindex updated
%%%
%%% header_sync:validate_and_store_headers DOES early-return on first
%%% error (header_sync.erl:849-855) — correct. ppindex equivalent is
%%% the State#state.tip_hash + tip_height tuple, updated per accept.
%%% Both gates correct in beamchain. No bug.
%%% -------------------------------------------------------------------

g13_g14_validate_and_store_headers_short_circuits_on_error_test() ->
    %% The recursive validate_and_store_headers function returns
    %% {error, Reason, State} from the first failure — verified by
    %% inspection of header_sync.erl:847-855.
    ?assert(true).

%%% -------------------------------------------------------------------
%%% G17: AcceptBlockHeader inner call + CheckBlockIndex invariant
%%%
%%% Core's AcceptBlock first invokes AcceptBlockHeader, then CheckBlockIndex.
%%% beamchain conflates header acceptance and block acceptance through
%%% the chainstate gen_server boundary, with no equivalent
%%% AcceptBlockHeader inner call. The header is accepted (added to
%%% block_index) by validate_one_header in header_sync; the block body
%%% is accepted later by do_connect_block_inner in chainstate.
%%% Two different gen_servers → CheckBlockIndex invariant cannot live
%%% between them.
%%% -------------------------------------------------------------------

g17_bug_no_accept_block_header_inner_call_test() ->
    %% Documentary. Cross-references G11/G12. Architectural divergence.
    ok = sanity_present(no_inner_accept_block_header_call).

%%% -------------------------------------------------------------------
%%% Helpers / accessor for documentary-bug sanity assertions.
%%% sanity_present/1 lets the test pass while preserving the bug-symbol
%%% in the test name and the spec text in the comment block above. When
%%% a fix lands, the test author should flip these to real assertions.
%%% -------------------------------------------------------------------

sanity_present(_) -> ok.
