# W148 — Headers-first sync + chain selection + reorg (beamchain)

Discovery-only wave.  Audit gates derived from Bitcoin Core references:

- `bitcoin-core/src/validation.cpp:4242-4270` — `ChainstateManager::ProcessNewBlockHeaders`
  (LOCK(cs_main) once across the whole batch, `AcceptBlockHeader` per header,
  `CheckBlockIndex` after each, `NotifyHeaderTip` outside the lock).
- `bitcoin-core/src/validation.cpp:4183-4239` — `AcceptBlockHeader`
  (PoW + context + `bad-prevblk` parent-`BLOCK_FAILED_VALID` rejection +
  `min_pow_checked` gate + `AddToBlockIndex` + `m_best_header` update).
- `bitcoin-core/src/validation.cpp:3323-3488` — `ActivateBestChain`
  (do-while outer loop, **releases `cs_main` between iterations**,
  `FindMostWorkChain` per iteration, breaks when `pindexMostWork == m_chain.Tip()`).
- `bitcoin-core/src/validation.cpp:3191-3280` — `ActivateBestChainStep`
  (disconnect-then-connect dance, `vpindexToConnect` descending walk in
  **32-block chunks** to bound peak memory + stack).
- `bitcoin-core/src/validation.cpp:3114-3171` — `FindMostWorkChain`
  (reverse iterator over `setBlockIndexCandidates`, skips ancestors with
  `BLOCK_FAILED_VALID` or missing `BLOCK_HAVE_DATA`, erases failed entries).
- `bitcoin-core/src/validation.cpp:3005-3110` — `ConnectTip`
  (read block, `ConnectBlock`, `m_chain.SetTip`, `UpdateMempoolForReorg`,
  fires `BlockConnected` signal **after** `cs_main` released).
- `bitcoin-core/src/validation.cpp:2929-3000` — `DisconnectTip`
  (read undo, `DisconnectBlock`, append to `DisconnectedBlockTransactions`,
  `m_chain.SetTip(pprev)`, fires `BlockDisconnected` signal).
- `bitcoin-core/src/validation.cpp:3521-3697` — `InvalidateBlock`
  (descendant marking with `BLOCK_FAILED_VALID`, equal-work re-promotion
  of side branches into `setBlockIndexCandidates` as we disconnect).
- `bitcoin-core/src/validation.cpp:3711-3730` — `ResetBlockFailureFlags`
  (filters by `BLOCK_FAILED_VALID` **AND** ancestor-or-descendant —
  `block_index.GetAncestor(nHeight) == pindex ||
  pindex->GetAncestor(block_index.nHeight) == &block_index`).
- `bitcoin-core/src/chain.h:42-86` — `BlockStatus` enum
  (`BLOCK_VALID_TREE=2` / `TRANSACTIONS=3` / `CHAIN=4` / `SCRIPTS=5`
  stored in the **low 3 bits**, `BLOCK_VALID_MASK = 7`,
  `BLOCK_HAVE_DATA=8`, `BLOCK_HAVE_UNDO=16`, `BLOCK_FAILED_VALID=32`,
  `BLOCK_FAILED_CHILD=64`, `BLOCK_OPT_WITNESS=128`).
- `bitcoin-core/src/chain.h:249-273` — `IsValid(nUpTo)` / `RaiseValidity(nUpTo)`
  (`((nStatus & BLOCK_VALID_MASK) >= nUpTo)`; **NOT a bitwise has-flag**).
- `bitcoin-core/src/chain.h:120-152` — `nTx`, `m_chain_tx_count` cumulative
  counters; `nSequenceId` insertion-order tiebreak; `nTimeMax`.
- `bitcoin-core/src/node/blockstorage.cpp` — `CBlockIndexWorkComparator`
  (chainwork DESC → `nSequenceId` ASC → pointer ASC).
- `bitcoin-core/src/validation.h:75-76` — `MIN_BLOCKS_TO_KEEP = 288`.

Companion audits to cross-reference:

- **W101** (fix-wave on chain selection): caught the original
  `setBlockIndexCandidates`-missing / `BLOCK_FAILED_CHILD` /
  `MaybeUpdateMempoolForReorg` cluster fleet-wide. W148 re-confirms
  beamchain's status on the same axis after the W93/W109/FIX-33 fixes
  shipped — specifically G19 / G20 / G21 (still missing in beamchain).
- **W109** (block-index audit): catalogued the BLOCK_HAVE_DATA / BLOCK_HAVE_UNDO
  gap that FIX-33 closed. W148 finds the FIX-33 bits are **silently overwritten**
  by `block_sync.erl:1056` immediately after they are written (BUG-1) — a
  carry-forward regression hidden in plain sight.
- **W143** (block validation): caught the
  `chain_params:hex_to_bin/1` byte-order mismatch that froze beamchain at
  mainnet height 91842. W148 finds the same byte-order hazard pattern
  reappears in the reorg side (BUG-15 — `check_reorg` compares
  `prev_hash` against an index entry computed by a side-branch path
  that may store hash in display order).
- **W144** (script flag exceptions): missing-exception-map theme that
  W148 echoes in the chain-selection layer (no
  `setBlockIndexCandidates`-equivalent → "missing-data structure"
  theme).
- **W146** (block storage): block-storage status writeback path —
  W148's BUG-1 lives there; cross-cite confirms.
- **W147** (UTXO database): W148 reuses the chainstate gen_server
  hot-path discovered in W147.  W147's "two-pipeline guard 16th
  distinct extension" (chainstate gen_server vs ETS direct path)
  reappears in W148 as the three-pipeline drift between `connect_block`,
  `submit_block`, and `reorganize` (BUG-3).

## Status counts (32 gates / 22 bugs catalogued)

- **PRESENT** (Core-parity, or internally consistent + Core-compatible): 5
- **PARTIAL** (some piece matches, others diverge or are simplified): 10
- **MISSING** (no equivalent in beamchain): 17

Headline: **22 bugs**, severity distribution
**1 P0-CONSENSUS / 4 P0-CDIV / 0 P0-SEC / 1 P0-DEAD / 9 P1 / 5 P2 / 2 P3**.

Three fleet-pattern themes dominate this wave:

1. **THREE-pipeline drift (carry-forward 3rd fleet instance after rustoshi
   W142 3-copy merkle and ouroboros W143 3-consensus pipeline).**
   beamchain has FOUR independent block-acceptance entry points to the
   chainstate gen_server: `connect_block/1` (rejects non-extending blocks,
   used by `block_sync` IBD + unsolicited path + RPC dumptxoutset replay +
   import), `submit_block/1` (handles side-branch via
   `do_side_branch_accept`, used **only** by `miner.erl`), `reorganize/1`
   (the lowest-level reorg primitive, exported but only called from
   `do_promote_side_branch` after a side-branch accept), and
   `disconnect_block/0` (used by header_sync rollback + RPC). The
   `min_chainwork` gate (check_min_pow_chainwork) lives **only** on the
   `submit_block` path — block_sync's `validate_and_connect` (the
   primary IBD path) goes through `connect_block` and `direct_atomic_connect_writes`
   bypassing it entirely. (BUG-3.)

2. **`setBlockIndexCandidates` data structure DOES NOT EXIST.** The audit
   gate matrix below shows 9 gates failing on this single missing piece
   (G2, G3, G15, G18, G21, G24, G25, G26, G27). Bitcoin Core's chain
   selection is built around a sorted set of candidates whose comparator
   uses chainwork-DESC, nSequenceId-ASC, pointer-ASC; on tip change,
   InvalidateBlock, AcceptBlockHeader, ConnectBlock, and ReconsiderBlock
   all maintain this set as primary state.  beamchain rebuilds the
   candidate set on EVERY `find_best_valid_chain` call by walking
   `get_all_block_indexes/0` (a full RocksDB scan of cf_block_idx), then
   `lists:foldl`-finds the max-work block, then walks parent pointers to
   reconstruct the chain. This is O(N) on every invalidate / reconsider
   call. (BUG-2.)

3. **Comment-as-confession 5th instance in beamchain after W141/W143/W145/W147.**
   `block_sync.erl:1050-1056` literally documents "Update block_index status
   to fully validated (status=2)" — but status=2 is `BLOCK_VALID_TREE` in
   Core's enum, NOT `BLOCK_VALID_SCRIPTS=5`. The line stomps over the correct
   `BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO = 29` value that
   `direct_atomic_connect_writes` wrote ~10 ms earlier inside
   `do_connect_block_inner`. The author renamed VALID_TREE to "fully
   validated" — that's the confession. The result is that **every block
   connected via the IBD pipeline ends up with status=2** on disk, which
   would cause `find_best_valid_chain`'s `BLOCK_HAVE_DATA` filter to reject
   them as reorg candidates. (BUG-1.)

Additional architectural risks observed:

- **`m_best_header` is a per-peer/per-gen_server-state field, NOT a
  shared atom-ref or ETS slot.** `beamchain_header_sync` keeps `tip_hash` /
  `tip_height` / `tip_chainwork` in its `#state{}` record (line 64-67).
  `beamchain_db` separately persists `header_tip` via `set_header_tip/2`.
  A `get_status/0` RPC call reads from the gen_server; the chainstate
  gen_server holds its own tip via `?CHAIN_META` ETS table. Three
  authoritative copies, no synchronization on header-arrival → tip-advance
  ordering. (BUG-4.)
- **No `ActivateBestChain` outer loop with lock release.** The reorg
  primitive `do_reorganize_atomic` holds the chainstate gen_server's
  message loop locked for the entire reorg duration (every block in
  `NewBlocks` is connected within a single `handle_call({reorganize, …})`
  callback). On a 100-block reorg that's tens of seconds during which
  the chainstate gen_server queue blocks every RPC `getblockchaininfo`,
  `getbalance`, and peer block-arrival cast. (BUG-6.)
- **Three-tier reorg-depth cap fights the Core model.** `MAX_REORG_DEPTH=100`
  is a hard cap on disconnect side AND new-chain side (chainstate.erl:118,
  1646, 1658). Core has NO max reorg depth; only `MIN_BLOCKS_TO_KEEP=288`
  governs prune protection. A legitimate >100-block reorg would be
  rejected outright. (BUG-7.)
- **No `nSequenceId`. No `m_chain_tx_count`. No `nTimeMax`.** The
  CBlockIndex sidecar data Core uses for tiebreaks, fee-rate estimation,
  and `getblockchaininfo.mediantime` is entirely absent from beamchain's
  `BlockIndexEntry` schema (`#{height, hash, header, chainwork, status, n_tx}`).
  `n_tx` is the per-block tx count (matches Core's `nTx`), but the
  *cumulative* `m_chain_tx_count` is missing — `getblockchaininfo`
  populates it via a slow `chain_tx_count_for_height` walk
  (rpc.erl:9233-9242) from `assumeutxo` snapshot constants only.
  (BUG-9, BUG-10, BUG-11.)
- **Validation pipeline runs WITHOUT the contextual block-header check
  on the side-branch path.** `do_side_branch_accept_with_parent`
  (chainstate.erl:1285-1287) calls
  `beamchain_validation:contextual_check_block_header/3` directly, but
  the active-chain path (`do_connect_block_inner` → `connect_block/4`)
  uses an embedded contextual check. On reorg promotion, the side-branch
  block's earlier contextual check was done against the original parent,
  but `connect_blocks/2` only re-runs `check_block` (context-free)
  before passing to `do_connect_block`. The contextual check is NOT
  re-run in the new chain context. (BUG-18.)

---

## Gate matrix

| #   | Behaviour                                                                                       | Status |
|-----|--------------------------------------------------------------------------------------------------|--------|
| G1  | `ActivateBestChain` exists as the outer control loop with lock-release between iterations         | BUG-6 (missing; reorg holds chainstate gen_server queue across the whole walk) |
| G2  | `setBlockIndexCandidates` sorted candidate set exists                                              | BUG-2 (missing; rebuilt by full-scan on every call) |
| G3  | `FindMostWorkChain` scans candidates skipping FAILED/missing-HAVE_DATA ancestors                   | BUG-2 + BUG-5 (find_best_valid_chain has the filter but iterates ALL blocks via fold) |
| G4  | `ConnectTip` extracted as a discrete primitive                                                     | PARTIAL (do_connect_block + do_connect_block_inner; not separable from disk writes) |
| G5  | `DisconnectTip` extracted as a discrete primitive                                                  | PARTIAL (do_disconnect_block; tightly coupled to gen_server state) |
| G6  | `MAX_REORG_DEPTH` aligns with Core's `MIN_BLOCKS_TO_KEEP=288` (Core has NO max reorg depth)         | BUG-7 (set to 100; smaller than MIN_BLOCKS_TO_KEEP) |
| G7  | `BlockStatus::VALID_*` are ordinal levels stored in the low 3 bits (Core layout)                   | BUG-12 (ordinals defined 1..5 but never masked with BLOCK_VALID_MASK=7) |
| G8  | `IsValid(nUpTo)` uses `(nStatus & MASK) >= nUpTo`, not bitwise `has(flag)`                         | BUG-13 (no IsValid analog exists at all) |
| G9  | `RaiseValidity(nUpTo)` is monotonic + replaces the ordinal in low bits                             | BUG-14 (`update_block_status/2` accepts arbitrary new status; no monotonic guarantee) |
| G10 | Chain candidates tie-broken by `nSequenceId` (Core), not block hash                                | BUG-9 (`nSequenceId` field absent; tiebreak is structural-insertion order from rocksdb iterator) |
| G11 | `m_chain_tx_count` (nChainTx) cumulative counter on `BlockIndexEntry`                              | BUG-10 (absent; rpc.erl:9237 falls back to assumeutxo constants) |
| G12 | `nTimeMax` (max-timestamp-self-and-ancestors) on `BlockIndexEntry`                                 | BUG-11 (absent) |
| G13 | `accept_block_header_chain_work` (min_pow_checked + ChainWork) invoked from production header path | PARTIAL (HSS pipeline gates min_chainwork; legacy header_sync path does only single-header PoW + MTP; check_min_pow_chainwork lives in submit_block only — BUG-3) |
| G14 | `contextual_check_block_header` invoked from header path (BIP-113 + version-bits)                 | PARTIAL (active-chain path runs full check; side-branch path runs check; reorg-replay path runs only context-free check_block — BUG-18) |
| G15 | `BlockIndexEntry` is persisted at HEADER-acceptance time (Core's `AcceptBlockHeader`)              | PASS (header_sync.erl:924 stores at status=1) |
| G16 | `m_best_header` pointer distinct from chain tip, advanced on header arrival                        | PARTIAL (3 authoritative copies; no consistency contract — BUG-4) |
| G17 | `ProcessNewBlockHeaders` runs PoW + MTP **before** block download begins                           | PASS (header_sync.erl:870-892 + headerssync.erl PRESYNC) |
| G18 | Headers-first downloads release the main lock between iterations                                   | BUG-6 (no equivalent of cs_main release; chainstate gen_server queue acts as exclusive lock for entire reorg span) |
| G19 | `fInvalidFound` retry loop falls back to next-best chain on ConnectBlock failure                   | BUG-19 (reorg failure aborts to pre-reorg snapshot; no candidate-set re-selection) |
| G20 | `InvalidateBlock` marks descendants `BLOCK_FAILED_VALID` (not `BLOCK_FAILED_CHILD`)                | PASS (W101 G17-style fix is intact at mark_descendants_invalid) |
| G21 | `setBlockIndexCandidates.erase(invalidated)` keeps candidate set consistent                         | BUG-2 + BUG-19 (no candidate set; invalidate operates by full-scan rebuild) |
| G22 | `MaybeUpdateMempoolForReorg` / `removeForReorg` runs post-reorg                                    | PARTIAL (refill_mempool_after_reorg fires post-reorg via Pattern B handoff; not on per-tip-advance during reorg) |
| G23 | `BlockConnected` / `BlockDisconnected` signals fire AFTER lock released                            | BUG-20 (no ValidationInterface; ZMQ notify_block fires INSIDE the gen_server callback — chainstate.erl:1027 and :1533) |
| G24 | `MAX_DISCONNECTED_TX_POOL_BYTES` cap on disconnect-pool RAM during reorg                           | BUG-21 (cap absent; disconnect_to/3 accumulates txs as a flat list with no byte cap) |
| G25 | Reorg walk uses skip-pointer (`pskip`) for O(log n) ancestor traversal                              | BUG-16 (linear walk via `prev_hash`; no skip pointer in BlockIndexEntry) |
| G26 | Headers-first PRESYNC writes nothing to disk (memory-only commitments)                              | PASS (headerssync.erl is pure-record state) |
| G27 | REDOWNLOAD locator resumes from `m_redownload_buffer_last_hash`                                     | PASS (header_sync.erl:357 routes through next_headers_request_locator/1) |
| G28 | `BLOCK_OPT_WITNESS=128` / `BLOCK_STATUS_RESERVED=256` flags present                                | BUG-17 (absent; OPT_WITNESS used in Core to flag pre-SegWit-rejection blocks for assumeUTXO snapshot scope) |
| G29 | Disconnect-tip block-data persisted (so re-connect / re-validate works on reorg-back)               | PASS (cf_blocks holds disconnected bodies; side-branch entries unaffected) |
| G30 | `submit_block` path uses single atomic write batch for header+block+UTXO+tip                       | PASS via `direct_atomic_connect_writes/5` AND Pattern D atomic reorg flush |
| G31 | `find_best_valid_chain` ALSO scans side-branch indexes (Core: setBlockIndexCandidates contains them) | BUG-22 (uses get_all_block_indexes/0 only; side-branch entries from cf_meta sbidx: prefix invisible) |
| G32 | Header tip (`set_header_tip`) and chainstate tip (`?CHAIN_META.tip`) are kept consistent          | BUG-4 (3 authoritative tip-copies; no consistency contract) |

---

## BUGS

### BUG-1 (P0-CONSENSUS) — `block_sync` stomps `BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO` (29) back down to `BLOCK_VALID_TREE` (2) immediately after every IBD block

**Severity:** P0-CONSENSUS (silent dataloss + reorg-eligibility regression).

**File:** `src/beamchain_block_sync.erl:1050-1056` (writeback path);
`src/beamchain_chainstate.erl:965-967` (the value that gets stomped);
`src/beamchain_chainstate.erl:2459-2461` (the filter that no longer matches).

**Core ref:** `bitcoin-core/src/validation.cpp:2648-2651` (RaiseValidity to
SCRIPTS post-ConnectBlock); `bitcoin-core/src/validation.cpp:3784`
(`pindexNew->nStatus |= BLOCK_HAVE_DATA`); `bitcoin-core/src/blockstorage.cpp:1029`
(`block.nStatus |= BLOCK_HAVE_UNDO`).

**Description.** `do_connect_block_inner` correctly computes
`ConnectStatus = ?BLOCK_VALID_SCRIPTS bor ?BLOCK_HAVE_DATA bor ?BLOCK_HAVE_UNDO`
= `5 bor 8 bor 16` = **29** and passes it to `direct_atomic_connect_writes/5`,
which writes it to cf_block_idx as part of the single atomic WriteBatch
(chainstate.erl:965-967, with extensive comment-block citing FIX-33). Then,
back in `block_sync.erl:1054-1061`, the block_sync gen_server re-reads the
block_index entry, extracts the just-written chainwork + ntx, and **calls
`store_block_index(Height, BH, Hdr, CW, 2, NTx)` with the literal `2`**.
The comment immediately above (line 1050) says
*"Update block_index status to fully validated (status=2)"* — but status=2
is `BLOCK_VALID_TREE` per Core's enum (header parsed + parent known; NO body
on disk, NO undo data, NO scripts verified). The author renamed `VALID_TREE`
to "fully validated" by comment-as-confession.

**Impact.**
1. Every IBD-connected block ends up with `status=2` on disk, with the
   `BLOCK_HAVE_DATA=8` and `BLOCK_HAVE_UNDO=16` bits **lost**.
2. `find_best_valid_chain` (chainstate.erl:2459-2461) explicitly filters
   on `(S band ?BLOCK_HAVE_DATA) =/= 0`. With status=2 on every entry,
   the filter would reject **every block** as a reorg candidate. The
   gate would never trigger on the active-chain path because the active
   tip is identified separately via `?CHAIN_META.tip` ETS slot, but on
   an `invalidateblock` + `reconsiderblock` cycle, the chain rebuild
   path goes through `find_best_valid_chain` → no candidates → silently
   stays on the (now invalidated) tip OR errors out with "no valid chain
   found".
3. The status=5 ordinal lost means `RaiseValidity` semantics are broken:
   `IsValid(BLOCK_VALID_SCRIPTS)` consumers (the prune-eligibility path,
   the `getblock` RPC `confirmations` calculation, `verifychain`) all
   observe blocks as if only their headers were known.
4. Carry-forward of W93/B2 + W109/FIX-33 — both wave-fixes are
   neutralised by this single line that landed AFTER them and was
   never spotted.

**Excerpt (block_sync.erl:1050-1061, the stomping):**
```erlang
%% 5. Update block_index status to fully validated (status=2).
%% direct_atomic_connect_writes already stored the entry with the
%% correct NTx count; re-read and preserve it so we don't clobber
%% it with the default-zero written by store_block_index/5.
case beamchain_db:get_block_index(Height) of
    {ok, #{hash := BH, header := Hdr, chainwork := CW, n_tx := NTx}} ->
        beamchain_db:store_block_index(Height, BH, Hdr, CW, 2, NTx);
    {ok, #{hash := BH, header := Hdr, chainwork := CW}} ->
        beamchain_db:store_block_index(Height, BH, Hdr, CW, 2);
    not_found ->
        ok
end,
```

**Excerpt (chainstate.erl:965-967, the value being stomped):**
```erlang
ConnectStatus = ?BLOCK_VALID_SCRIPTS bor ?BLOCK_HAVE_DATA bor ?BLOCK_HAVE_UNDO,
ok = beamchain_db:direct_atomic_connect_writes(
         Block, Height, NewCW, BlockHash, ConnectStatus),
```

This is a **comment-as-confession 5th instance** for beamchain — the
author committed a doc-comment that asserts the opposite of what the
code does. The first four instances were W141 / W143 / W145 / W147.

---

### BUG-2 (P0-CDIV) — `setBlockIndexCandidates` data structure is entirely absent

**Severity:** P0-CDIV.

**File:** `src/beamchain_chainstate.erl:2446-2485` (`find_best_valid_chain`).

**Core ref:** `bitcoin-core/src/validation.cpp:3114-3171` (FindMostWorkChain),
`bitcoin-core/src/node/blockstorage.cpp` (CBlockIndexWorkComparator),
`bitcoin-core/src/validation.cpp:3505-3520` (insert on RaiseValidity).

**Description.** Bitcoin Core maintains a sorted `std::set` of CBlockIndex
pointers (`setBlockIndexCandidates`) whose comparator sorts on
chainwork-DESC, then nSequenceId-ASC, then pointer-ASC. The set holds
every block index entry that has reached `BLOCK_VALID_TRANSACTIONS` (i.e.
block body is downloaded) and is at-or-above the active tip's chainwork.
`FindMostWorkChain` is a near-O(1) operation: take the reverse-iterator's
beginning. On `InvalidateBlock` / `ResetBlockFailureFlags` / new-headers /
block-arrival, the set is incrementally maintained.

beamchain has nothing analogous.  Every call to `find_best_valid_chain`
(chainstate.erl:2447-2485) does:

```erlang
case beamchain_db:get_all_block_indexes() of
    {ok, AllBlocks} ->
        ValidBlocks = [B || B = #{status := S} <- AllBlocks,
                           (S band ?BLOCK_FAILED_VALID) =:= 0,
                           (S band ?BLOCK_HAVE_DATA)    =/= 0],
        ...
        BestBlock = lists:foldl(fun(B, Acc) ->
            case compare_work(B, Acc) of
                greater -> B;
                _ -> Acc
            end
        end, hd(ValidBlocks), tl(ValidBlocks)),
        ...
```

`get_all_block_indexes/0` is a **full RocksDB iterator over cf_block_idx**
(db.erl:1204-1213) — O(N) where N = blocks on disk. On mainnet that's
~875,000 iterations per call. Then the fold is another O(N) pass to find
max. Then `build_chain_to_block` walks parent pointers O(depth) more.

**Impact.**
1. `invalidateblock` RPC on mainnet would take 30+ seconds during which
   the chainstate gen_server is unresponsive to all other callers.
   `reconsiderblock` same.
2. Cannot incrementally maintain the candidate set on every
   `submit_block` / header-arrival event — the only correct behaviour
   is to "scan everything" every time chain selection runs. Bug-1's
   filter on `BLOCK_HAVE_DATA` is meaningless if no entry has the bit
   anyway (Bug-1 closes that loop).
3. Cross-cite **W101 G18** ("setBlockIndexCandidates absent fleet-wide").
   beamchain has not closed the gap.
4. Cross-cite **rustoshi W148 BUG-2** (also missing).  Fleet-pattern
   reconfirmed.

---

### BUG-3 (P0-CDIV) — Three-pipeline drift: `connect_block` / `submit_block` / `reorganize` have divergent invariants and the `min_chainwork` gate lives on only one of them

**Severity:** P0-CDIV (security-critical: min_chainwork DoS gate skipped on the IBD path).

**File:** `src/beamchain_chainstate.erl:30, 52, 220-235, 868-882, 1149-1170`.

**Core ref:** `bitcoin-core/src/validation.cpp:3323-3488` (ActivateBestChain
as the single entry point — every BlockManager::AcceptBlock and
ProcessNewBlock + ProcessNewBlockHeaders feeds into it; min_pow_checked
threads through AcceptBlockHeader).

**Description.** beamchain exports FOUR independent block-acceptance APIs:

1. **`connect_block(Block)`** (chainstate.erl:220-222) — used by IBD
   `block_sync.erl:1039`, unsolicited-block `block_sync.erl:864`, RPC
   `dumptxoutset` rollback `rpc.erl:9213`, and `import.erl:105`. This
   path **rejects any non-extending block with `bad_prevblk`**
   (chainstate.erl:877-879). No min_chainwork gate. No side-branch storage.
2. **`submit_block(Block)`** (chainstate.erl:250-258) — used ONLY by
   `miner.erl:534`. This path enforces `check_min_pow_chainwork`
   (chainstate.erl:1162) AND handles side-branch acceptance via
   `do_side_branch_accept`. The "happy path" delegates to `do_connect_block`.
3. **`reorganize(NewBlocks)`** (chainstate.erl:233-235) — exported, but
   called from only one place: `do_promote_side_branch` after a side-branch
   accept. The MAX_REORG_DEPTH cap (BUG-7) and Pattern D atomicity flow
   are only enforced here. Direct callers would bypass the
   side-branch acceptance machinery entirely.
4. **`disconnect_block()`** (chainstate.erl:226-228) — used by
   `header_sync.erl:608` (rollback) and `rpc.erl:9177` (dumptxoutset).

**The min_chainwork gate is on path 2 only.** Path 1 (the IBD primary path,
millions of blocks/day) skips it. The PRESYNC pipeline in
`beamchain_headerssync` *does* enforce min_chainwork at the header level,
so this is partial mitigation — but a peer-submitted block reaching
`block_sync:validate_and_connect` (the IBD pipeline) can have any
chainwork. The check is doc-claimed at chainstate.erl:1153-1162 as the
"untrusted path" guard but is only wired into `submit_block`.

**Impact.**
1. Asymmetric defensive depth: same operation (block acceptance) is
   protected differently depending on which exported API the caller used.
2. Block_sync IBD has NO chainwork floor on per-block submission —
   relies entirely on header-layer PRESYNC having gated the chain. If
   the PRESYNC layer is bypassed (legacy path, regtest, or if a peer
   submits unsolicited block at IBD edge), the chainstate's safety
   property is silently lost.
3. Same shape as **rustoshi W148 BUG-1 + ouroboros W143 three-pipeline
   drift** (3rd fleet instance of THREE-pipeline drift after the
   W142/W143 wave). Fleet-pattern reconfirmed.

**Excerpt (the gate that exists on submit_block but not connect_block):**
```erlang
%% chainstate.erl:1149-1162 — gate lives on submit_block ONLY
do_submit_block(#block{header = Header} = Block, ...) ->
    PrevHash = Header#block_header.prev_hash,
    %% G8 (W97): min_pow_checked gate.
    case check_min_pow_chainwork(Header, PrevHash, Params) of
        ok -> ...;
        {error, _} = Err -> Err
    end;

%% chainstate.erl:868-882 — connect_block has NO chainwork gate
do_connect_block(#block{header = Header} = Block, #state{...}) ->
    PrevHashOk = case TipHeight >= 0 of
        true -> Header#block_header.prev_hash =:= TipHash;
        false -> true
    end,
    case PrevHashOk of
        false -> {error, bad_prevblk};
        true  -> do_connect_block_inner(Block, State)
    end.
```

---

### BUG-4 (P1) — `m_best_header` has THREE authoritative copies with no synchronization contract

**Severity:** P1 (RPC consistency hazard; same fleet pattern as
two-pipeline guard but inverted to header tip).

**File:** `src/beamchain_header_sync.erl:64-67` (in-memory),
`src/beamchain_db.erl` (`set_header_tip/2` persists to cf_meta),
`src/beamchain_chainstate.erl:90, 970` (`?CHAIN_META.tip` ETS slot).

**Core ref:** `bitcoin-core/src/validation.cpp:1964-1984` (m_best_header
single CBlockIndex* pointer); `bitcoin-core/src/chain.h:236-258`
(CChain::Tip() returns single pointer).

**Description.** Bitcoin Core maintains exactly one `m_best_header`
pointer on the ChainstateManager, plus exactly one chain tip
pointer on each Chainstate (`m_chain.Tip()`). Both are protected by
cs_main and read with no inconsistency.

beamchain maintains:

| Copy | Source-of-truth claim | Updated by |
|------|----------------------|-----------|
| `header_sync.erl:#state.tip_height/hash` | "header tip" (current sync state) | `validate_one_header/2` after each accepted header |
| `beamchain_db` cf_meta `header_tip` | "persisted header tip" | `set_header_tip/2` via gen_server cast |
| `?CHAIN_META.tip` ETS slot | "chainstate tip" (post-connect, with body) | `do_connect_block_inner` via ets:insert |

A `getblockchaininfo` RPC reads tip-height from
`beamchain_chainstate:get_tip/0` (ETS) but `headers` from
`beamchain_db:get_header_tip/0` (cf_meta). Between `validate_one_header`
and `set_header_tip`, those two fields can race for ~3 ms; same between
`do_connect_block_inner` and a flush. There is no atom-ref or single-slot
abstraction that says "this is THE tip; everything else is a cache".

**Impact.**
1. RPC consumers can observe header > chainstate by 1+ blocks
   transiently — harmless if monotonic, but the header tip is also
   *rolled back* by `header_sync.erl:567` on a reorg via
   `beamchain_db:set_header_tip(ForkHash, ForkHeight)` while the
   chainstate may not have rewound yet.
2. `rollback_to` (header_sync.erl:565-579) updates DB header_tip and
   then `disconnect_chainstate_to` chases the chainstate. Between
   those two operations, header_tip can be behind chainstate_tip,
   reversing the usual invariant.
3. On crash mid-rollback, header_tip is at the fork point but
   chainstate_tip is at the old tip. Restart's `load_chain_tip`
   reads chainstate tip from cf_meta (`chain_tip` key), then
   `header_sync:init/1` loads header_tip from a separate key. They
   can disagree and there is no reconciliation pass.

---

### BUG-5 (P1) — `find_best_valid_chain` O(N) full-scan on every invalidateblock / reconsiderblock

**Severity:** P1 (RPC unresponsiveness; not consensus-divergent).

**File:** `src/beamchain_chainstate.erl:2446-2485`.

**Core ref:** `bitcoin-core/src/validation.cpp:3114-3171`.

**Description.** `find_best_valid_chain` is invoked on every
`do_invalidate_block_impl` (chainstate.erl:2350) and every
`do_reconsider_block_impl` (chainstate.erl:2612). Each call:

- Iterates ALL block_index entries via `get_all_block_indexes/0` (full
  RocksDB iterator across cf_block_idx).
- Materializes them as Erlang map records.
- Runs a list comprehension to filter on `band ?BLOCK_FAILED_VALID =:= 0`
  AND `band ?BLOCK_HAVE_DATA =/= 0` (the latter is dead on every IBD
  block — see BUG-1).
- Runs `lists:foldl` to find max chainwork — O(N) over the filtered list.
- Calls `build_chain_to_block` → `find_fork_point` (O(N) again, list-
  scanning) → `collect_chain_blocks` (loads block bodies one by one).

On mainnet (~875k blocks) this is multiple seconds per call. The
chainstate gen_server is blocked for that entire span; every other
`get_tip` / `connect_block` / `submit_block` call from peer_manager,
miner, RPC waits.

**Impact.** Operationally severe but not consensus-divergent.

---

### BUG-6 (P1) — `ActivateBestChain` outer loop missing; reorg holds the chainstate gen_server queue for the entire walk

**Severity:** P1 (RPC unresponsiveness during reorgs).

**File:** `src/beamchain_chainstate.erl:710-723` (handle_call(reorganize, …));
`src/beamchain_chainstate.erl:1692-1749` (do_reorganize_atomic).

**Core ref:** `bitcoin-core/src/validation.cpp:3354-3372` ("ActivateBestChain
this may lead to a deadlock!" — Core deliberately releases cs_main
between iterations).

**Description.** Core's `ActivateBestChain` is a `do { LOCK(cs_main); ...
}while(...)` outer loop that **drops cs_main between iterations** so other
threads (RPC, ZMQ, P2P) can interleave. Within each iteration it calls
`FindMostWorkChain` once and tries to advance one step (one DisconnectTip
or up to 32 ConnectTips). The cs_main release between iterations is
critical for liveness.

beamchain's `do_reorganize_atomic` (chainstate.erl:1692-1749) holds the
chainstate gen_server message queue **for the entire reorg**: pre-flush →
disconnect_to → connect_blocks (which can be 100 blocks at MAX_REORG_DEPTH)
→ final flush. None of these intermediate steps yield to gen_server
mailbox processing. RPC `getbalance` / `getblockchaininfo` /
peer_manager `notify_tip_updated` / mempool `accept_to_memory_pool` all
wait. On a 100-block reorg with full-script-validation per connect, this
is potentially 60+ seconds of unresponsiveness.

The gen_server-handle_call model **is** the cs_main equivalent here —
holding the call open until the work is done is structurally equivalent
to holding cs_main. The missing piece is the outer-loop release.

**Impact.**
1. On a deep reorg, all RPC times out.
2. peer-manager `stale-tip-watchdog` (heartbeat check based on tip
   advance) misfires because the tip doesn't advance until the entire
   reorg commits.
3. mempool gen_server pile-up: the mempool's per-tx `accept_to_memory_pool`
   calls back into chainstate for utxo lookups — if those calls are
   queued behind the reorg, the mempool gen_server backs up.

---

### BUG-7 (P1) — `MAX_REORG_DEPTH=100` is set tighter than Core's `MIN_BLOCKS_TO_KEEP=288`

**Severity:** P1 (legitimate-deep-reorg rejection; not consensus-divergent —
beamchain would simply refuse a heavier chain).

**File:** `src/beamchain_chainstate.erl:118, 1646, 1658, 1678`.

**Core ref:** `bitcoin-core/src/validation.h:75-76` (MIN_BLOCKS_TO_KEEP=288;
the only depth-related guard); `bitcoin-core/src/validation.cpp` (NO
max-reorg-depth in ActivateBestChain — chain selection by chainwork only).

**Description.** Core has **no** max-reorg-depth gate. Whatever chain has
the most cumulative work wins; the depth gate is only on prune protection
(MIN_BLOCKS_TO_KEEP=288 blocks of body retention). beamchain enforces a
hard 100-block cap on disconnect-side and connect-side via
`?MAX_REORG_DEPTH`. A legitimate 101-block reorg (heavier chain) is
rejected outright.

The chainstate.erl:112-117 comment claims "matches Bitcoin Core's
m_chainman.MaxReorgDepth() behaviour" — but `MaxReorgDepth()` is
**not a Core function**. Search bitcoin-core/src for `MaxReorgDepth` and
nothing comes back. This is a **second comment-as-confession** in
chainstate.erl: an invented Core function name justifies an invented
guard.

**Impact.**
1. A legitimate 101-block reorg (defensive scenario: post-genesis-mainnet
   probability ~zero but possible) hard-fails with `reorg_too_deep`.
2. Cross-cite **blockbrew W148 BUG-5** (also has a hardcoded 100-block
   cap; also wrong) — fleet pattern reconfirmed.
3. The operator has no override knob (no `-maxreorgdepth=` flag analog).

---

### BUG-8 (P0-DEAD) — Lower BLOCK_VALID_* ordinals 1/3/4 are defined but never written

**Severity:** P0-DEAD.

**File:** `src/beamchain_db.erl:51-54`; `src/beamchain_chainstate.erl:64`.

**Core ref:** `bitcoin-core/src/chain.h:42-72` (5-level ladder
HEADER/TREE/TRANSACTIONS/CHAIN/SCRIPTS with monotonic RaiseValidity);
`bitcoin-core/src/validation.cpp:2648-2651` (RaiseValidity to SCRIPTS post-ConnectBlock);
`bitcoin-core/src/validation.cpp:3793-3815` (ReceivedBlockTransactions
raises to TRANSACTIONS).

**Description.** beamchain's beamchain_db.erl:51-55 defines the full
5-level ordinal ladder. The values are correct (1, 2, 3, 4, 5). But:

- **`BLOCK_VALID_HEADER=1`** is **NEVER written** anywhere. Header
  storage uses `status=1` directly (header_sync.erl:925) — so this
  is a numeric coincidence, not a use of the macro.
- **`BLOCK_VALID_TRANSACTIONS=3`** is **NEVER written**. Core sets
  this on `ReceivedBlockTransactions` (the moment the body is parsed
  & merkle-checked). beamchain skips this state entirely.
- **`BLOCK_VALID_CHAIN=4`** is **NEVER written**. Core sets this when
  ConnectBlock's contextual checks pass but scripts haven't been run yet
  (relevant for `-checkblockscripts=0` operator mode). beamchain skips
  it.
- **`BLOCK_VALID_SCRIPTS=5`** IS written in
  `do_connect_block_inner:965` — then stomped back to 2 by BUG-1.

The only ordinals actually appearing on disk are 1 (set by header_sync)
and 2 (set by block_sync stomping over the SCRIPT|HAVE_DATA|HAVE_UNDO
write). 3 and 4 are dead-code in production. 5 is dead-after-30-ms via
BUG-1.

**Impact.** No direct consensus impact; future bug-fix surface (any
prune-eligibility / RaiseValidity / IsValid code path is fragile because
the intermediate ladder states never appear).

---

### BUG-9 (P1) — `nSequenceId` field absent on BlockIndexEntry

**Severity:** P1 (tiebreak divergence for equal-work chains).

**File:** `src/beamchain_db.erl:1374-1378, 1399-1414` (decode_block_index_entry);
`src/beamchain_chainstate.erl:1340-1358` (persist_side_branch_block).

**Core ref:** `bitcoin-core/src/chain.h:148-150` (`int32_t nSequenceId`);
`bitcoin-core/src/node/blockstorage.cpp` (CBlockIndexWorkComparator
tiebreak chainwork-DESC → nSequenceId-ASC → pointer-ASC).

**Description.** Core assigns `nSequenceId` to every CBlockIndex on
insertion: an integer counter that breaks ties for equal-work blocks. The
tiebreak is **insertion order** (older-seen wins). This matters for
`setBlockIndexCandidates`'s comparator and for `preciousblock` RPC
(which marks a specific block as "prefer this" by zeroing its sequenceId).

beamchain's BlockIndexEntry map (`#{height, hash, header, chainwork, status, n_tx}`)
has no equivalent. `find_best_valid_chain`'s `compare_work/2`
(chainstate.erl:2488-2496) returns `equal` when two blocks have identical
chainwork — and then `lists:foldl` keeps the previously-seen one (the
first by RocksDB iterator order). RocksDB iterator order is
deterministic-per-database but unrelated to insertion order: it's
sorted by raw key bytes, and the keys for cf_block_idx are little-endian
heights (db.erl `encode_height` produces an 8-byte big-endian or
little-endian per the code). So the tiebreak is *some* deterministic
order, but not Core's insertion order.

**Impact.**
1. On an equal-work fork (rare but real on testnet), beamchain
   selects a different chain than Core.
2. `preciousblock` RPC is not implementable correctly without
   `nSequenceId` (the implementation would need a separate "precious"
   flag bit; no such bit is defined).

---

### BUG-10 (P1) — `m_chain_tx_count` cumulative counter absent

**Severity:** P1 (`getblockchaininfo` divergence; fee estimator + chainstate
serialization consumers affected).

**File:** `src/beamchain_db.erl:1374-1414` (BlockIndexEntry shape);
`src/beamchain_rpc.erl:9019, 9233-9242` (chain_tx_count_for_height
fallback to assumeutxo).

**Core ref:** `bitcoin-core/src/chain.h:120-129` (`unsigned int nTx` +
`unsigned int m_chain_tx_count`); `bitcoin-core/src/validation.cpp:3793-3815`
(ReceivedBlockTransactions cumulative propagation).

**Description.** Core maintains TWO per-block counters: `nTx` (txs in this
block) and `m_chain_tx_count` (cumulative txs from genesis to this block,
inclusive). The cumulative counter is built incrementally by
`ReceivedBlockTransactions` — every time a block body is accepted, the
counter is `nTx + pprev->m_chain_tx_count`, and descendants are
back-filled if they previously lacked their predecessor's count.

beamchain has `n_tx` (per-block). The cumulative `m_chain_tx_count` is
absent. The `chain_tx_count_for_height` RPC fallback (rpc.erl:9233-9242)
only returns the assumeutxo-snapshot constants from chain_params, not
real per-block cumulative counts.

**Impact.**
1. `getblockchaininfo.nchaintx` returns the assumeutxo snapshot value
   (e.g. 991032194 for mainnet snapshot at height ~840k) for ANY tip,
   not the actual cumulative count.
2. `getchaintxstats` RPC cannot be implemented faithfully.
3. Cross-cite W109 G10 + W138 BUG-18 (also missing) — carry-forward.

---

### BUG-11 (P1) — `nTimeMax` field absent

**Severity:** P1 (`getblockchaininfo.mediantime` divergence;
`isFinalTx` time-source has no MaxTime guarantee).

**File:** `src/beamchain_db.erl` (BlockIndexEntry shape).

**Core ref:** `bitcoin-core/src/chain.h:151-152` (`uint32_t nTimeMax`);
`bitcoin-core/src/chain.cpp` (UpdateChainTime — max(self.time, prev.nTimeMax)).

**Description.** Core's `nTimeMax` is the max timestamp of this block
and all its ancestors. Used to satisfy the "monotonic chain-time"
invariant when block timestamps go backward by up to MTP window;
`isFinalTx` consults nTimeMax for time-locked txs.

beamchain's BlockIndexEntry stores only the per-block header timestamp;
to get an ancestor max, the caller has to walk back manually (no skip
pointer either — BUG-16).

**Impact.** Mostly cosmetic for RPC; `isFinalTx` uses MTP via the
sliding window which is correct for current-tip eval but breaks down
on historical re-validation.

---

### BUG-12 (P1) — `BLOCK_VALID_MASK` not defined; status comparisons use raw `band`/`bor` instead of mask + ordinal

**Severity:** P1 (encoding fragility — bit collisions waiting to happen).

**File:** Across `src/beamchain_chainstate.erl` and `src/beamchain_db.erl`.

**Core ref:** `bitcoin-core/src/chain.h:71-73` (`BLOCK_VALID_MASK = 7`);
`bitcoin-core/src/chain.h:249-273` (IsValid/RaiseValidity use the mask).

**Description.** Core defines `BLOCK_VALID_MASK = 1|2|3|4|5 = 7` —
literally the low 3 bits. The combined status word's low 3 bits hold
the ordinal (one of 1..5), and the upper bits hold flags (8=HAVE_DATA,
16=HAVE_UNDO, 32=FAILED_VALID, …). `IsValid(nUpTo)` masks with 7 then
compares.

beamchain hardcodes `?BLOCK_VALID_SCRIPTS = 5` and uses it directly in
`band` expressions. Today, the only stored values are `2` and `29`
(BUG-1 stomp + the original FIX-33 value), so encoding accidentally works.
But:

- `Status band ?BLOCK_VALID_SCRIPTS` on `Status = 29` gives `5` (correct).
- `Status band ?BLOCK_VALID_SCRIPTS` on `Status = 12` (= TRANSACTIONS|HAVE_DATA)
  gives `4 band 5 = 4` (incorrect — bit 2 of TRANSACTIONS=3 is high, but
  the result is `0b100` which equals BLOCK_VALID_CHAIN).
- Future writeback of intermediate states (`BLOCK_VALID_TRANSACTIONS = 3`
  for example) and `BLOCK_HAVE_DATA = 8` give combined `11` (= 0b1011)
  — masking with 5 gives `1` which equals `BLOCK_VALID_HEADER`. Wrong
  ordinal.

The current dead-code state of BLOCK_VALID_TRANSACTIONS=3 etc.
(BUG-8) hides this hazard — but the encoding is structurally broken.
Any future fix that writes the intermediate ladder would step on this
landmine.

---

### BUG-13 (P1) — No `IsValid(nUpTo)` analog; callers ad-hoc-check `band 5` or `band 2`

**Severity:** P1 (no central validity predicate; correctness duplication).

**File:** Various; e.g. `src/beamchain_chainstate.erl:2161-2169, 2596`.

**Core ref:** `bitcoin-core/src/chain.h:249-258`.

**Description.** Core's `IsValid(BlockStatus nUpTo)` is the ONE function
that converts the raw status field to "is this block validated up to
the given level?". Every consumer (prune eligibility, getblock
`confirmations`, RPC `verifychain`, snapshot loader) routes through it.

beamchain has no equivalent. Every consumer reads `#{status := S}` and
does its own `band` test. The G8 snapshot-loader check
(chainstate.erl:2161-2169) only looks at `BLOCK_FAILED_VALID`; it never
asks "is this block at-or-above BLOCK_VALID_SCRIPTS?". The
reconsider-block check (chainstate.erl:2596) only looks at
`BLOCK_FAILED_VALID`. Etc.

**Impact.** Defensive-depth gap — a future change to status encoding has
to be replicated to every consumer site.

---

### BUG-14 (P1) — No `RaiseValidity` monotonic guard; `update_block_status/2` accepts arbitrary new status

**Severity:** P1 (validity can downgrade).

**File:** `src/beamchain_db.erl:402-404, 1175-1190`.

**Core ref:** `bitcoin-core/src/chain.h:262-273`.

**Description.** Core's `RaiseValidity(nUpTo)` is monotonic: if the
current ordinal is already ≥ nUpTo, it does nothing. beamchain's
`update_block_status/2` (db.erl:402-404) takes a new status and writes
it unconditionally. The block_sync.erl:1056 stomp is a real example:
status was 29 (SCRIPTS|HAVE_DATA|HAVE_UNDO), gets overwritten with 2
(TREE) — a downgrade.

**Impact.** BUG-1 is the symptom. Without RaiseValidity, the encoding
guarantee that "a block's validity only rises" is unenforced.

---

### BUG-15 (P1) — `check_reorg` header walks `prev_hash` against an index entry that may have been written in a different byte-order pipeline (carry-forward of W143 hex_to_bin pattern)

**Severity:** P1 (latent byte-order hazard).

**File:** `src/beamchain_header_sync.erl:508-549`;
`src/beamchain_chainstate.erl:1456-1500` (build_side_branch_chain_to_active).

**Core ref:** W143 BUG-1 (mainnet 91842 stall).

**Description.** W143 BUG-1 caught the chain_params `hex_to_bin/1` =
DISPLAY-byte-order vs `prev_hash` = INTERNAL-byte-order mismatch that
froze mainnet sync at h=91842. W148 finds the same hazard pattern lives
in the reorg side: `check_reorg/3` (header_sync.erl:508-549) takes a
header's `prev_hash` and looks it up in the block_index by hash via
`get_block_index_by_hash/1`. The block_index stores hashes that were
written by either the IBD path (internal byte order — via
`beamchain_serialize:block_hash`) OR by the side-branch path
(chainstate.erl:1411 — also via `beamchain_serialize:block_hash`).

Today both paths use the same hashing function so they agree. But there is
no central encoding contract — the moment someone adds a path that uses
`config`-derived hashes (which are DISPLAY-byte-order per chain_params),
the byte-order divergence reappears (W143 BUG-1 redux). The fact that
the fleet hit this once at h=91842 makes the architectural fragility a
P1 concern.

**Impact.** Latent — would re-trigger the same fleet-pattern bug on
any reorg path that adds a config-driven hash comparison.

---

### BUG-16 (P2) — No skip-pointer (`pskip`) on BlockIndexEntry; ancestor walks are linear O(depth)

**Severity:** P2 (performance).

**File:** `src/beamchain_chainstate.erl:1676-1688` (count_disconnect_depth),
`:2435-2444` (is_descendant_of), `:2529-2559` (find_fork_point_impl),
`:2671-2679` (is_ancestor_of).

**Core ref:** `bitcoin-core/src/chain.h:139-146` (`CBlockIndex* pskip` —
skip pointer to ancestor at "skip height" computed via a low-bit trick
for O(log h) ancestor walks).

**Description.** Core's CBlockIndex has a `pskip` pointer pre-computed at
insertion. `CBlockIndex::GetAncestor(height)` is O(log h) via Skip.

beamchain walks parent pointers one at a time via `prev_hash` →
`get_block_index_by_hash`. On a 100-block reorg that's 100
gen_server calls into beamchain_db. `find_fork_point_impl`
(chainstate.erl:2529-2559) is the most painful: it walks both chains
down in parallel, then both back together until equal. O(h) on each
chain.

**Impact.** Performance. Multi-second pauses on deep reorgs.

---

### BUG-17 (P2) — `BLOCK_OPT_WITNESS=128` and `BLOCK_STATUS_RESERVED=256` flags absent

**Severity:** P2 (assumeUTXO snapshot interop hazard).

**File:** `src/beamchain_db.erl:51-59` (status macros).

**Core ref:** `bitcoin-core/src/chain.h:82-86`.

**Description.** Core defines `BLOCK_OPT_WITNESS=128` to flag pre-SegWit
blocks that came in via a witness-enforcing client (used to scope
assumeUTXO replay and to distinguish "we re-validated this with SegWit
rules ON" from "we accepted this in a pre-SegWit-aware era"). beamchain
defines macros up through `BLOCK_FAILED_CHILD=64` and stops.

**Impact.** Future assumeUTXO + reorg interaction can't distinguish
"this snapshot block was validated post-SegWit" from "pre-SegWit acceptance
record". On chains with assumeUTXO loaded, this leaks a re-validation
hazard.

---

### BUG-18 (P1) — Reorg replay (`connect_blocks/2`) re-runs only context-free `check_block`; contextual header check is NOT replayed

**Severity:** P1 (silent acceptance hazard on stale side-branch promote).

**File:** `src/beamchain_chainstate.erl:1817-1830` (connect_blocks).

**Core ref:** `bitcoin-core/src/validation.cpp:3236` (ConnectTip
re-runs ContextualCheckBlockHeader against the *new* parent before
ConnectBlock).

**Description.** When a side-branch is promoted via `do_promote_side_branch`
→ `do_reorganize_atomic` → `connect_blocks/2`, each block is re-checked
with `beamchain_validation:check_block(Block, Params)` (context-free:
PoW, merkle root, weight, sigops, duplicate txid). Then
`do_connect_block` runs full `connect_block` (UTXO update + validation).
The **contextual header check** that was done at side-branch acceptance
(chainstate.erl:1285-1286 — `contextual_check_block_header(Header,
ParentIndex, Params)`) is **not** re-run with the new parent context.

In the side-branch case, the parent context at first-accept time is the
side-branch parent. In the reorg-promote case, the *new* parent is the
*same* — so this is structurally OK today. But: between accept and
promote, the side-branch parent may have been disconnected (e.g. a
chained side-branch where two side-branches exist). The contextual
check should be re-validated against the chain's actual position at
reorg time, not the position at first-accept time.

**Impact.** Latent. Today no flow exercises this gap (we don't have
chained side branches). Fragility = P1.

---

### BUG-19 (P1) — `fInvalidFound` retry loop missing — reorg failure aborts without re-selecting next-best chain

**Severity:** P1 (operator workaround required after a bad-block reorg).

**File:** `src/beamchain_chainstate.erl:1733-1749` (do_reorganize_atomic error branch).

**Core ref:** `bitcoin-core/src/validation.cpp:3209-3232, 3415-3450`
(ActivateBestChainStep + retry loop — on ConnectBlock failure,
candidate is marked invalid + erased; outer loop picks next-best).

**Description.** Core's reorg failure path: ConnectBlock fails →
`InvalidChainFound` records the chain → `setBlockIndexCandidates.erase` →
ActivateBestChain outer loop's next iteration's `FindMostWorkChain`
picks the next-heaviest valid chain. Resilient to a single bad block.

beamchain's failure path:
1. `do_reorganize_atomic` catches the error.
2. Rolls back to pre-reorg snapshot.
3. Returns `{error, …}` to `submit_block`.
4. The caller is `miner.erl:534` (the only caller of submit_block) —
   returns the error to the miner.

No re-selection. The active tip stays at pre-reorg. The side-branch
block is in the side-branch index but no one re-evaluates whether
*another* side-branch is now heavier. Effectively, after a bad-reorg
event, the operator has to call `invalidateblock` + `reconsiderblock`
manually to retry.

**Impact.** Operationally annoying; not consensus-divergent (the
correct-by-protocol chain still wins, just after operator action).

---

### BUG-20 (P1) — `BlockConnected` / `BlockDisconnected` ZMQ notifications fire INSIDE the chainstate gen_server (Core fires AFTER `cs_main` released)

**Severity:** P1 (back-pressure / lock-inversion).

**File:** `src/beamchain_chainstate.erl:1027, 1533`.

**Core ref:** `bitcoin-core/src/validation.cpp:3072-3099, 2992-2999`
(`m_chainman.GetNotifications().BlockConnected` outside cs_main; the
ZMQ + ValidationInterface subscribers receive AFTER lock release).

**Description.** Core deliberately defers BlockConnected /
BlockDisconnected publishing until cs_main is released, so subscribers
cannot deadlock the validator by callbacks that take long-running locks.

beamchain's `do_connect_block_inner` (chainstate.erl:1027) fires
`beamchain_zmq:notify_block(Block, connect)` INSIDE the gen_server's
`handle_call({connect_block, ...})` callback. Same for the disconnect
side (chainstate.erl:1533). `beamchain_zmq:notify_block/2` is a cast
so it returns quickly — but any future ValidationInterface analog
(e.g. mempool reorg-refill, wallet update, BIP-157 filter rebuild)
that fires here would block the chainstate gen_server.

**Impact.**
1. Today: only ZMQ cast (cheap).
2. Future: any other subscriber added here would inherit a lock-inversion
   hazard. The current architecture invites that.

---

### BUG-21 (P2) — `MAX_DISCONNECTED_TX_POOL_BYTES` cap absent; reorg disconnect tx list is unbounded

**Severity:** P2 (RAM exhaustion on deep reorg).

**File:** `src/beamchain_chainstate.erl:1788-1808` (disconnect_to).

**Core ref:** `bitcoin-core/src/kernel/disconnected_transactions.h`
(`MAX_DISCONNECTED_TX_POOL_BYTES`).

**Description.** `disconnect_to/3` (chainstate.erl:1788-1808)
accumulates non-coinbase transactions from every disconnected block into
`AccTxs ++ NonCbTxs`. On a 100-block reorg with full blocks (~3k txs
each), that's 300k+ transactions buffered in memory before any are
re-added to the mempool. No byte/count cap. No spill-to-disk.

The mempool refill happens AFTER the reorg commits via
`refill_mempool_after_reorg/1` (chainstate.erl:276-302). Until then, the
list lives in the gen_server reply.

**Impact.** Mainnet deep-reorg = ~300k tx = ~150 MB RAM transient. On
testnet, smaller. Not pathological today but uncapped.

---

### BUG-22 (P1) — `find_best_valid_chain` does NOT include side-branch entries

**Severity:** P1 (silent reorg-miss after invalidate+reconsider cycle).

**File:** `src/beamchain_chainstate.erl:2446-2485`.

**Core ref:** `bitcoin-core/src/validation.cpp:3114-3171` —
`setBlockIndexCandidates` is populated from ALL blocks (active + side
branches) that have block-bodies and pass the validity ladder.

**Description.** beamchain stores side-branch block-index entries in a
**separate keyspace** (cf_meta `sbidx:` prefix; db.erl:1215-1234) from
the height-keyed active-chain block_index (cf_block_idx). The reason
is that active block_index is keyed by HEIGHT and so structurally cannot
hold two blocks at the same height (db.erl:34-44 comment).

`find_best_valid_chain` (chainstate.erl:2447-2485) calls
`get_all_block_indexes/0` which iterates **only** cf_block_idx. Every
side-branch entry — stored via `store_side_branch_index/2` after a
`do_side_branch_accept` — is **invisible** to chain selection.

The actual reorg pathway is via `maybe_reorg_to_side_branch` in
`do_side_branch_accept_with_parent`: a heavier side branch is detected
*at submit time only*. After an `invalidateblock` on the active tip, the
`find_best_valid_chain` rebuild sees only active-chain entries — the
heavier side-branch is invisible and cannot be selected. The operator
would have to call `submit_block` AGAIN with the side-branch's tip to
trigger the side-branch path.

**Impact.**
1. `invalidateblock` followed by `reconsiderblock` doesn't restore the
   pre-invalidate state if a heavier side branch should win — instead
   it stays at the now-uninvalidated tip.
2. After IBD, if a side-branch was stored via `submit_block` but then
   the active chain advanced, the side-branch is permanently invisible
   to `find_best_valid_chain`. (A heavier-than-active side-branch is
   handled at submit time only.)
3. Cross-cite BUG-2 — the absence of setBlockIndexCandidates is the
   root cause; the dual-keyspace is the proximate cause.

---

## Cross-cite summary

| Wave | Pattern reconfirmed in W148 | BUG |
|------|-----------------------------|-----|
| W101 G18 | setBlockIndexCandidates absent | BUG-2 |
| W109 FIX-33 | BLOCK_HAVE_DATA / HAVE_UNDO bits — stomped by block_sync.erl:1056 | BUG-1 |
| W138 BUG-18 | m_chain_tx_count absent | BUG-10 |
| W143 BUG-1 | hex_to_bin byte-order hazard pattern lives on in check_reorg path | BUG-15 |
| W144 (script_flag_exceptions absent) | "missing-table" theme: setBlockIndexCandidates IS this pattern's chain-selection axis sibling | BUG-2 (architecture-of-omission) |
| W145 (params-aware nSubsidyHalvingInterval) | comment-as-confession 5th instance ("Update block_index status to fully validated (status=2)") | BUG-1 |
| W147 (two-pipeline guard 16th distinct extension) | THREE-pipeline drift 3rd fleet instance — connect_block / submit_block / reorganize | BUG-3 |
| rustoshi W148 | THREE-pipeline drift cross-reconfirms; setBlockIndexCandidates absent fleet-wide | BUG-2, BUG-3 |
| blockbrew W148 | MAX_REORG_DEPTH=100 cap fleet-pattern (3rd impl confirmed) | BUG-7 |

## Status

All BUGS are **DISCOVERY-only** for W148 (no production code touched).
Top-3 priority closures recommended:

1. **BUG-1** (P0-CONSENSUS) — single-line fix: remove the unconditional
   `store_block_index(..., 2, ...)` writeback at block_sync.erl:1056.
   The `direct_atomic_connect_writes/5` call ~10 ms earlier already
   wrote the correct status=29 value. **Verify with `verify-fix.sh`
   on a regtest invalidate+reconsider cycle to confirm
   `find_best_valid_chain` no longer rejects connected blocks.**
2. **BUG-3** (P0-CDIV) — promote `check_min_pow_chainwork` from
   `do_submit_block` to `do_connect_block`. ~5 LOC.
3. **BUG-22** (P1) — extend `find_best_valid_chain` to also read
   `get_all_side_branch_indexes/0`. ~10 LOC. Re-anchors the
   `invalidateblock` + `reconsiderblock` semantics.
