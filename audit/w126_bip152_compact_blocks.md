# W126 — BIP-152 Compact Block Relay audit (beamchain)

Discovery-only wave. 30 audit gates. Status counts:

- **PRESENT** (matches Core or is a deliberate, Core-compatible variation): 12
- **PARTIAL** (some sites match, others don't): 4
- **MISSING** (no equivalent in beamchain): 14

Headline: **18 bugs** spread across the BIP-152 hot path. The largest
divergence cluster is the **HB-to (announce) side**: beamchain accepts
`sendcmpct(announce=1)` from peers but never sends `cmpctblock` to them
when we have a new tip (BUG-2, BUG-3, BUG-15). The second cluster is
**pre-validation gates** in the inbound `cmpctblock`/`getblocktxn`/
`blocktxn` handlers (BUG-4, BUG-8, BUG-11, BUG-21).

Two P0-CDIV findings: BUG-1 (sendcmpct version != 2 must be silently
ignored — peer can wedge our HB state with v=999) and BUG-12 (inbound
`getblocktxn` indexes lack the strict-increasing post-decode invariant
that DifferenceFormatter would otherwise enforce; a peer can craft a
wire payload that decodes to a non-monotonic absolute index set and
extract arbitrary tx data from blocks via our `lists:filtermap`
permissive accepter).

Reference: `bitcoin-core/src/net_processing.cpp` (SENDCMPCT 3901,
CMPCTBLOCK 4466, GETBLOCKTXN 4245, BLOCKTXN 4714, NewPoWValidBlock
2103, MaybeSetPeerAsAnnouncingHeaderAndIDs 1272, SendBlockTransactions
2598, ProcessCompactBlockTxns 3441), `bitcoin-core/src/blockencodings.{cpp,h}`
(InitData 59, FillBlock 191, GetShortID 46, FillShortTxIDSelector 35),
`bitcoin-core/src/validation.cpp` (IsBlockMutated 4027). BIP-152.

The audit asserts current divergent behavior in
`test/beamchain_w126_bip152_tests.erl` using the
"`?_assert(true)` marker with prose comment for PARTIAL/MISSING"
convention (W124 beamchain pattern). A follow-up FIX wave will flip
the corresponding markers to real assertions when production code is
brought into parity.

---

## Gate index (1..30)

| #  | Name | Status | Core ref | beamchain ref |
|----|------|--------|----------|---------------|
| 1  | SENDCMPCT version != CMPCTBLOCKS_VERSION (2) silently ignored | MISSING | net_processing.cpp:3907 | beamchain_peer.erl:1514-1519 |
| 2  | SENDCMPCT received post-VERACK still valid (Core: yes) | PRESENT | net_processing.cpp:3901 (no post-verack guard) | beamchain_peer.erl:1253-1254 |
| 3  | Outgoing sendcmpct on handshake (v1+v2) | PRESENT (over-eager — also sends v1) | net_processing.cpp:3864-3870 | beamchain_peer.erl:1630-1653 |
| 4  | sendcmpct v1 should NOT be sent (Core 2024+: v2 only) | BUG | net_processing.cpp:3870 sends only v2 | beamchain_peer.erl:1646-1648 |
| 5  | CMPCTBLOCK header pre-validation (LookupBlockIndex + low-work + ProcessNewBlockHeaders) | MISSING | net_processing.cpp:4483-4513 | beamchain_block_sync.erl:1294-1311 (jumps straight to init_compact_block) |
| 6  | CMPCTBLOCK ignored while LoadingBlocks() | MISSING | net_processing.cpp:4469-4472 | beamchain_block_sync.erl:411-413 |
| 7  | CMPCTBLOCK header punishment via `via_compact_block=true` | MISSING | net_processing.cpp:4505 / 4677 | none |
| 8  | CanDirectFetch() gate before reconstruction | MISSING | net_processing.cpp:4570-4572 | none |
| 9  | MAX_CMPCTBLOCK_DEPTH = 5 guard (post-W112 fix) | PRESENT | net_processing.cpp:138, 2466 | beamchain_block_sync.erl:79, 1116 |
| 10 | MAX_BLOCKTXN_DEPTH = 10 guard | PRESENT | net_processing.cpp:140, 4276 | beamchain_sync.erl:36, 297 |
| 11 | Optimistic reconstruction path (block already in flight) | MISSING | net_processing.cpp:4635-4654 | none |
| 12 | force_processing=true on cmpctblock-derived block | MISSING | net_processing.cpp:4701 | beamchain_block_sync.erl:1376 (regular path) |
| 13 | mapBlockSource attribution for compact-block-derived blocks | MISSING | net_processing.cpp:4690 / 3513 | none |
| 14 | MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3 cap | MISSING | net_processing.h:47 | none |
| 15 | InitData header-IsNull + empty-cmpctblock reject | PRESENT | blockencodings.cpp:62 | beamchain_compact_block.erl:65, 69 |
| 16 | InitData txn-count cap = MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TX_WEIGHT | PRESENT | blockencodings.cpp:64 | beamchain_compact_block.erl:31, 75 |
| 17 | InitData prefilled-tx differential index strict-monotone + uint16 cap | PRESENT | blockencodings.cpp:73-86 | beamchain_compact_block.erl:87-110 |
| 18 | InitData prefilled-tx-is-null reject | PRESENT | blockencodings.cpp:74 | beamchain_compact_block.erl:91 |
| 19 | InitData duplicate-short-id reject (FAILED → re-request block) | PRESENT | blockencodings.cpp:115 | beamchain_compact_block.erl:121-127 |
| 20 | InitData unordered-map bucket-size DoS check (>12 elements per bucket → FAILED) | MISSING | blockencodings.cpp:110-111 | none |
| 21 | mempool-side collision: clear slot AND decrement count (BUG-5 closure) | PRESENT | blockencodings.cpp:129-138 | beamchain_compact_block.erl:296-302 |
| 22 | extra_txn-side collision: compare wtxids before clearing | PRESENT | blockencodings.cpp:163-168 | beamchain_compact_block.erl:329-339 |
| 23 | FillBlock count-mismatch reject | PRESENT | blockencodings.cpp:214 | beamchain_compact_block.erl:206-209 |
| 24 | FillBlock IsBlockMutated check (merkle + witness + 64-byte tx) | PARTIAL (only merkle root) | blockencodings.cpp:219-222, validation.cpp:4027 | beamchain_compact_block.erl:372-376 |
| 25 | GETBLOCKTXN recent-block-hash cache fast path | MISSING | net_processing.cpp:4254-4264 | beamchain_sync.erl:299 (DB only) |
| 26 | GETBLOCKTXN strict-increasing index invariant post-decode | MISSING | net_processing.cpp:4250-4252 | beamchain_p2p_msg.erl:732-739 |
| 27 | GETBLOCKTXN out-of-bounds index → Misbehaving | MISSING | net_processing.cpp:2602-2605 | beamchain_sync.erl:310-319 (silent filter) |
| 28 | NewPoWValidBlock fast-announce CMPCTBLOCK to HB-from peers | MISSING | net_processing.cpp:2103-2152 | beamchain_peer_manager.erl:324-331 (announce_block only routes headers/inv) |
| 29 | wants_cmpct / cmpct_version propagated to peer_manager ETS | MISSING | net_processing.cpp:3911-3912 (CNodeState) | beamchain_peer.erl:1517 (peer_data only) |
| 30 | pending_compact stale entry eviction (timeout sweep) | MISSING | implicit via BlockRequested / RemoveBlockRequest timers | beamchain_block_sync.erl: no eviction |

---

## BUG CATALOGUE

### BUG-1 [P0-CDIV] G1 — sendcmpct accepts any version (Core: silently drop != 2)
**Core**: `net_processing.cpp:3907` — `if (sendcmpct_version != CMPCTBLOCKS_VERSION) return;` (CMPCTBLOCKS_VERSION = 2 per `:199`). Non-v2 sendcmpct messages are dropped without state change.
**beamchain**: `beamchain_peer.erl:1514-1519` — accepts `version => V` for any V, stores on `peer_data{wants_cmpct, cmpct_version}` unconditionally. A peer can send `sendcmpct(true, v=999)` and we'd commit "HB mode at version 999"; our `compute_short_id` always uses v2 wtxid-based encoding so any subsequent cmpctblock from such a peer would silently fail to reconstruct.
**Consensus risk**: P0-CDIV — yes, because (a) we'd advertise HB-from acceptance, (b) the peer would push cmpctblocks expecting v=999 semantics, (c) we'd silently fail reconstruction with "short id collision", (d) the peer's BIP-152 fallback path may correctly send GETDATA/MSG_BLOCK *or* may not, depending on remote implementation. This is a wedge — once HB is set, the inbound block-relay path for that peer is broken.

### BUG-2 [P0-CDIV] G28 — Outbound CMPCTBLOCK fast-announce missing
**Core**: `net_processing.cpp:2103-2152` — `NewPoWValidBlock` is invoked on every PoW-valid new block; for every peer with `m_requested_hb_cmpctblocks=true` it pushes an unsolicited `CMPCTBLOCK` message (the BIP-152 high-bandwidth path).
**beamchain**: `beamchain_peer_manager.erl:324-331` — `announce_block/2` only branches between `headers` and `inv`. There is **no** cmpctblock branch. Even if a peer sent us `sendcmpct(announce=1)` and we accepted, we will never send them a cmpctblock for our new tips.
**Consensus risk**: P0-CDIV — yes, because beamchain holds an asymmetric BIP-152 role: we receive but never serve compact blocks. Any node electing beamchain as HB-from depends on us pushing cmpctblock; we never do. They fall back to inv→getheaders→headers→getdata→block (slow path), but only if their HB-from quorum has other peers. Worst case: beamchain is on a strict BIP-152-only path and the downstream peer never gets tip blocks from us.

### BUG-3 [P0] G29 — wants_cmpct/cmpct_version isolated to peer process state
**Core**: `net_processing.cpp:3911-3912` — `nodestate->m_provides_cmpctblocks = true; nodestate->m_requested_hb_cmpctblocks = sendcmpct_hb;` stored on the manager-global `CNodeState` keyed by NodeId.
**beamchain**: `beamchain_peer.erl:1517` — stored only on `peer_data{}` inside the per-peer gen_server. No path to the `peer_manager` ETS table, so `announce_block/2` cannot read it even if it tried.
**Consensus risk**: P0 — directly enables BUG-2.

### BUG-4 [P0] G5 — No header pre-validation before reconstruction
**Core**: `net_processing.cpp:4483-4513` — looks up prev_block index, checks `prev_block->nChainWork + GetBlockProof(...) < GetAntiDoSWorkThreshold()` (low-work cmpctblock rejection), then `ProcessNewBlockHeaders` to accept the header before any reconstruction work.
**beamchain**: `beamchain_block_sync.erl:1294-1311` — `handle_cmpctblock_received` jumps straight to `init_compact_block`. The block hash is computed from the (untrusted) header. No prev-block lookup, no low-work guard, no header validation.
**Consensus risk**: P0 — a peer can flood compact blocks with garbage headers and tie up reconstruction CPU. The result will eventually fail validation downstream but only after unbounded compact-block state has been allocated.

### BUG-5 [P0] G7 — `via_compact_block=true` distinction missing in punishment
**Core**: `net_processing.cpp:4505, 4677, 4682` — when a header arrives via cmpctblock, the `via_compact_block=true` flag is threaded into `MaybePunishNodeForBlock` and `ProcessHeadersMessage`. BIP-152 §"Pre-Versioning Considerations" permits HB peers to relay before full validation; peers MUST NOT be disconnected for invalid blocks announced via cmpctblock.
**beamchain**: No equivalent — invalid cmpctblock headers would feed through the standard validation path and trigger ban score via the regular invalid-block route. Inbound HB peers risk being banned for headers they're explicitly permitted to push pre-validation.
**Consensus risk**: P0 (interop) — beamchain may ban honest BIP-152 HB peers.

### BUG-6 [P0] G6 — No `LoadingBlocks` gate on inbound cmpctblock/blocktxn
**Core**: `net_processing.cpp:4469-4472` and `:4717-4720` — both CMPCTBLOCK and BLOCKTXN handlers `return` early if `m_chainman.m_blockman.LoadingBlocks()` (i.e., reindexing/importing).
**beamchain**: `beamchain_block_sync.erl:411-413` and `:416-418` — accepted regardless of state. The `cmpctblock` cast has no status guard at all; `blocktxn` is silently dropped if status != syncing (which is the inverse of Core: drop during init, accept after).
**Consensus risk**: P0 — slow disk reads under load during reindex; potential for double-acceptance of blocks already being imported via local datadir.

### BUG-7 [P0] G24 — FillBlock IsBlockMutated check incomplete
**Core**: `blockencodings.cpp:219-222` — after `FillBlock`, calls `IsBlockMutated(block, segwit_active)` which checks (a) `CheckMerkleRoot` (merkle root match), (b) any tx with `GetSerializeSize(TX_NO_WITNESS(tx)) == 64` for non-coinbase blocks (CVE-2019-* class), (c) `CheckWitnessMalleation` for segwit-active blocks. Any positive result → `READ_STATUS_FAILED`.
**beamchain**: `beamchain_compact_block.erl:372-376` — only `verify_merkle_root`. Misses the 64-byte-tx mutation check and the witness malleation check entirely.
**Consensus risk**: P0 — a short-id collision that swaps in a 64-byte non-coinbase tx (or a witness-malleated coinbase commitment) will reconstruct cleanly, pass merkle root, and then be accepted into the chain — only to fail downstream consensus checks (or worse, succeed if the cleanup logic gives up). Core's `IsBlockMutated` is the structural defense.

### BUG-8 [P0] G8 — `CanDirectFetch` gate missing on cmpctblock processing
**Core**: `net_processing.cpp:4570-4572` — refuses to process a cmpctblock for reconstruction unless `CanDirectFetch()` (tip is within 20× PowTargetSpacing of now). During IBD or a long disconnect, cmpctblocks are passed through to the headers-processing branch only.
**beamchain**: None. A peer can push a cmpctblock during IBD and force allocation of pending_compact state for blocks we have no business reconstructing yet.
**Consensus risk**: P0 (DoS).

### BUG-9 [P0] G27 — getblocktxn out-of-bounds index silently filtered
**Core**: `net_processing.cpp:2602-2605` — `if (req.indexes[i] >= block.vtx.size()) { Misbehaving(peer, "getblocktxn with out-of-bounds tx indices"); return; }`.
**beamchain**: `beamchain_sync.erl:310-319` — `lists:filtermap` silently drops out-of-range indices. No misbehavior score; the peer gets a partial blocktxn response with no error indication.
**Consensus risk**: P0 (interop) — the peer's reconstruction will fail with a tx-count mismatch and they'll have to fall back to full block, but they'll never learn the request was malformed. Also no DoS protection against repeated probing.

### BUG-10 [P0] G25 — getblocktxn doesn't check recent-block cache before DB lookup
**Core**: `net_processing.cpp:4254-4264` — locks `m_most_recent_block_mutex`, checks `m_most_recent_block_hash == req.blockhash`, serves from the in-memory cache. Critical hot path for newly-mined-block compact propagation.
**beamchain**: `beamchain_sync.erl:299` — always `beamchain_db:get_block(BlockHash)`. The block we just announced via cmpctblock is read from RocksDB on every getblocktxn round-trip from every HB peer.
**Consensus risk**: P1 (performance, not correctness) — but the parity claim is wrong, so listing here.

### BUG-11 [P0] G20 — InitData missing bucket-size DoS check
**Core**: `blockencodings.cpp:110-111` — when building the shorttxid map, asserts `bucket_size(bucket(shorttxid)) <= 12`. The cap defends against an adversary who picks shorttxids that hash-collide in our std::unordered_map, forcing the bucket walk to dominate reconstruction time (a stronger DoS than the SipHash-key collision protection).
**beamchain**: Uses Erlang `maps:put` — no bucket structure exposed. The equivalent invariant (no shortid space has > 12 entries with the same hash modulo table size) is unenforced. Erlang maps are persistent HAMT, less vulnerable than std::unordered_map, but the asymptotic guarantee still depends on key distribution.
**Consensus risk**: P0 (DoS amplification).

### BUG-12 [P0-CDIV] G26 — getblocktxn differential-index decode lacks post-decode monotonic invariant
**Core**: `net_processing.cpp:4250-4252` — after `DifferenceFormatter` decode, `Assume(req.indexes[i] > req.indexes[i-1])`. The differential encoding guarantees strict-monotone post-decode IF the encoder is honest, but the post-decode `Assume` catches encoder bugs / wire-crafted regressions.
**beamchain**: `beamchain_p2p_msg.erl:732-739` — `decode_diff_indexes` accepts any varint sequence including `diff = -1` (well, varint is unsigned so this can't underflow, but diff=0 between two indexes is unrepresentable per the spec ("the difference from the previous index minus one"), and `Prev + 0 + 1 = Prev + 1`, which is allowed only if Idx > Prev). The decoder is technically correct for spec-compliant peers, but a peer can send varint=0 → Idx = Prev + 0 + 1 = Prev + 1 (legal); the issue is more subtle: a peer can send a sequence where, after decoding, two adjacent indexes collide. Concretely, `[0, 0]` on the wire decodes to `[0, 1]` (fine), but `[]` after the count varint is `count=0`, and we accept count > tx_count silently.
**Consensus risk**: P0-CDIV — corrupted index lists feed straight into the `lists:filtermap`/`element` path in beamchain_sync.erl, returning a partial response with no error and no peer punishment.

### BUG-13 [P1] G11 — Optimistic reconstruction path missing
**Core**: `net_processing.cpp:4635-4654` — when a cmpctblock arrives but the block is already in flight from another peer (and we're at the cap), Core still tries to reconstruct from the cmpctblock and, on success, processes it without removing the existing in-flight entry. Fast path for racing tip blocks.
**beamchain**: `beamchain_block_sync.erl:1294-1311` — if the block hash isn't in `hash_to_height`, falls through to `do_handle_unsolicited_cmpctblock` (good); but doesn't track partial reconstructions for unsolicited cmpctblocks (the docstring at :1316-1320 acknowledges this).
**Consensus risk**: P1 — a tip cmpctblock that needs a getblocktxn round-trip cannot be reconstructed on the unsolicited path. Effectively, beamchain is HB-from for "we have all the txs in mempool" cases only.

### BUG-14 [P1] G12 — `force_processing=true` not set on cmpctblock-derived blocks
**Core**: `net_processing.cpp:4701` — `ProcessBlock(pblock, /*force_processing=*/true, ...)` — bypasses some anti-DoS checks because cmpctblock has its own DoS controls (CanDirectFetch + min chain work + ignored cmpctblocks-with-less-work-than-tip).
**beamchain**: `beamchain_block_sync.erl:1376` — `handle_block_received` follows the normal IBD/requested-block path. Optimistic (unsolicited) cmpctblock reconstructions may be rejected as "block we didn't request".
**Consensus risk**: P1 (correctness, not consensus).

### BUG-15 [P1] G14 — No HB-to outbound cap (Core: 3 per direction)
**Core**: `net_processing.cpp:1272-1329` — `MaybeSetPeerAsAnnouncingHeaderAndIDs` maintains `lNodesAnnouncingHeaderAndIDs` (max size 3); demotes oldest when adding 4th; preserves 1 outbound slot.
**beamchain**: Per BUG-2 we don't have an HB-to set at all. If BUG-2 is fixed naively without the cap, we'd push CMPCTBLOCK to every HB-requesting peer for every tip → bandwidth amplification.
**Consensus risk**: P1 (DoS / cost).

### BUG-16 [P1] G30 — pending_compact has no timeout eviction
**Core**: Equivalent via the `mapBlocksInFlight` request timeout (BlockRequested → RemoveBlockRequest on stall).
**beamchain**: `beamchain_block_sync.erl: state.pending_compact` is a plain map; entries are removed on blocktxn arrival or on full block fallback, but NOT on peer disconnect, NOT on timeout, NOT on tip advancement past the missing block.
**Consensus risk**: P1 (memory growth, slow leak).

### BUG-17 [P1] G3 — sendcmpct v1 is dead bandwidth in 2024+
**Core**: `net_processing.cpp:3870` — sends only v2 (CMPCTBLOCKS_VERSION = 2). The handler at `:3907` rejects all non-v2 received sendcmpct.
**beamchain**: `beamchain_peer.erl:1646-1648` — still sends v1 (announce=false) followed by v2. The v1 message advertises that we'd accept v1-encoded cmpctblocks (txid-based shortids), but our `compute_short_id` only uses wtxid (v2 semantics). Any peer that took us at our v1 advertisement and pushed a v1-cmpctblock will silently fail to reconstruct.
**Consensus risk**: P1 — interop with legacy peers is broken in a specific subtle way: we advertise v1 acceptance but cannot fulfil it.

### BUG-18 [P2] G4 — No misbehavior score for non-v2 sendcmpct
**Core**: Silently drops non-v2 (no misbehavior). Listed for completeness — Core's behavior is "ignore", not "punish".
**beamchain**: Accepts. Per BUG-1 this is a P0-CDIV; the misbehavior side is informational only because Core doesn't punish either.

### BUG-19 [P2] G13 — No `mapBlockSource` for compact-block-derived blocks
**Core**: `net_processing.cpp:4690` and `3513` — records the peer ID that supplied a cmpctblock-reconstructed block; used by `BlockChecked` (`:2196`) to punish the peer if validation fails.
**beamchain**: No equivalent. A peer can push an invalid cmpctblock that we successfully reconstruct, validation fails, and the peer is never attributed / punished.
**Consensus risk**: P2 (no consensus impact, but DoS amplification possible).

---

## Out of scope (will be follow-on waves)

- W126 does not audit erlay (BIP-330) interaction with BIP-152; the erlay handlers in `beamchain_p2p_msg.erl` are pure pass-through to `beamchain_erlay`, not exercised here.
- The Core `MaybeSetPeerAsAnnouncingHeaderAndIDs` dynamic HB-to promotion (based on tip-following recency) is partially audited (BUG-15) but the BIP-152 §"Protocol Flow" tip-follow learning algorithm is deferred to a follow-on wave.
- Transaction compression (`TransactionCompression = DefaultFormatter`) is a no-op in Core today; not audited as a discovery wave but flagged as a future BIP-339-class change.

---

## Summary

| Priority | Count |
|----------|-------|
| P0-CDIV  | 3 (BUG-1, BUG-2, BUG-12) |
| P0       | 8 (BUG-3..11) |
| P1       | 5 (BUG-13..17) |
| P2       | 2 (BUG-18, BUG-19) |
| **Total** | **18** |

Two structural meta-patterns surface in this audit:

1. **Receive-only BIP-152 role** — beamchain accepts BIP-152 cmpctblocks
   correctly enough for IBD-time reconstruction (which is well-covered by
   W112's prior pass), but the HB-to (announce-out) side is entirely
   missing. This is a *dead-helper-at-call-site* pattern: `wants_cmpct`
   and `cmpct_version` are set on `peer_data` and never consulted by
   the announce path. (34-wave streak continues.)

2. **Pre-validation gap on inbound cmpctblock** — beamchain skips Core's
   header pre-validation, `LoadingBlocks` ignore-gate, `CanDirectFetch`
   gate, and `via_compact_block` punishment-distinction. Each is an
   independent DoS / interop gap.

Both clusters are fixable in a single follow-on FIX wave (~3-4 hours
estimated): a new `cmpctblock` arm in `announce_block/2` keyed off
peer_manager-side cmpct flags + a `prevalidate_cmpctblock_header` helper
in front of `init_compact_block` + a `LoadingBlocks` predicate from
`beamchain_block_sync`. The v1-sendcmpct dead-bandwidth issue (BUG-17)
is a one-line removal.
