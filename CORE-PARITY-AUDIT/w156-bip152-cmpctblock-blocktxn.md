# W156 — BIP-152 deep-dive: sendcmpct + cmpctblock + getblocktxn + blocktxn (beamchain)

**Wave:** W156 — `CBlockHeaderAndShortTxIDs`, `PartiallyDownloadedBlock`,
`BlockTransactions`, `BlockTransactionsRequest`, `SendCompactBlock`,
`ProcessCompactBlock`, `ProcessCompactBlockTxns`,
`MaybeRequestCompactBlock`, `MaybeSetPeerAsAnnouncingHeaderAndIDs`,
`MAX_CMPCTBLOCK_DEPTH = 5`, `MAX_BLOCKTXN_DEPTH = 10`,
`MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3`, `CMPCTBLOCKS_VERSION = 2`,
`vExtraTxnForCompact`, short-tx-id SipHash-2-4 (k0/k1 from
SHA256(header||nonce)), prefilledtxn[] with coinbase@0,
DifferenceFormatter (varint diff-minus-1), `MSG_CMPCT_BLOCK = 4`
(BIP-152 getdata type).

**Scope:** discovery only — no production code changes. W126 covered
BIP-152 fundamentals (18 bugs); W156 is the wire-level deep dive
auditing every byte that crosses the socket, every state transition
between `init_compact_block` / `try_reconstruct` / `fill_block`, and
every gate Core enforces between `NetMsgType::CMPCTBLOCK` arrival and
the eventual `ProcessNewBlock` call.

**Bitcoin Core references**
- `bitcoin-core/src/blockencodings.cpp:20-33` — `CBlockHeaderAndShortTxIDs`
  constructor. Coinbase **always** prefilled at index 0. Wire-format
  prefilled.index is `uint16_t` (post-deserialize cap at
  `blockencodings.h:125`, throws `"indexes overflowed 16 bits"`).
- `bitcoin-core/src/blockencodings.cpp:35-50` — `FillShortTxIDSelector`:
  `DataStream stream; stream << header << nonce; CSHA256(stream).Finalize(buf)`.
  `m_hasher = PresaltedSipHasher(buf.GetUint64(0), buf.GetUint64(1))`.
  `GetShortID(wtxid) = m_hasher(wtxid.ToUint256()) & 0xffffffffffffL`.
- `bitcoin-core/src/blockencodings.cpp:59-181` — `PartiallyDownloadedBlock::InitData`.
  Five invariants beamchain must mirror: header-IsNull reject,
  empty-cmpctblock reject, `shorttxids + prefilledtxn > MAX_BLOCK_WEIGHT/MIN_SERIALIZABLE`
  reject, prefilled-index strict-monotone + uint16-cap +
  `lastprefilledindex > shorttxids.size() + i` reject (the **per-prefilled-tx**
  cap, NOT the overall TxnCount cap), bucket-size > 12 hash-collision
  DoS reject.
- `bitcoin-core/src/blockencodings.cpp:191-237` — `FillBlock`. After
  vtx population, runs `IsBlockMutated(block, /*check_witness_root=*/segwit_active)`
  which calls `CheckMerkleRoot` (with `mutated` flag), and
  `CheckWitnessMalleation` for segwit blocks, AND scans for 64-byte
  non-coinbase txs (CVE-2017-12842 class).
- `bitcoin-core/src/blockencodings.h:21-43` — `DifferenceFormatter`
  serializes/deserializes `indexes` as varint-minus-1. POST-decode
  invariant: indexes MUST be strictly increasing (the formatter
  enforces this via `m_shift += n` then `v = I(m_shift++)`).
- `bitcoin-core/src/blockencodings.h:23-69` — `BlockTransactionsRequest`
  uses `VectorFormatter<DifferenceFormatter>` for indexes; `BlockTransactions`
  uses `TX_WITH_WITNESS(Using<VectorFormatter<TransactionCompression>>(txn))`
  — txns are ALWAYS witness-serialized over the wire, regardless of
  whether the underlying tx has witness data. `PrefilledTransaction`
  similarly uses `TX_WITH_WITNESS(Using<TransactionCompression>(obj.tx))`.
- `bitcoin-core/src/net_processing.cpp:138-141` — `MAX_CMPCTBLOCK_DEPTH = 5`,
  `MAX_BLOCKTXN_DEPTH = 10`. Both depth windows are RELATIVE TO TIP and
  count downward.
- `bitcoin-core/src/net_processing.cpp:199` — `CMPCTBLOCKS_VERSION = 2`.
  Receiving sendcmpct with any other version is silently dropped
  (`net_processing.cpp:3907`). Only v2 is honored.
- `bitcoin-core/src/net_processing.cpp:1272-1329` —
  `MaybeSetPeerAsAnnouncingHeaderAndIDs`: maintains `lNodesAnnouncingHeaderAndIDs`
  (max 3 peers), demotes oldest when a 4th peer is selected, sends
  `sendcmpct(high_bandwidth=true)` to promote and `(false)` to demote.
- `bitcoin-core/src/net_processing.cpp:2103-2152` — `NewPoWValidBlock`:
  on every PoW-valid new block, iterates peers and pushes
  unsolicited `CMPCTBLOCK` to every peer with `m_requested_hb_cmpctblocks=true`
  (the HB-from set). This is the BIP-152 high-bandwidth tip-relay path.
- `bitcoin-core/src/net_processing.cpp:4466-4708` — `CMPCTBLOCK` handler.
  Six gates BEFORE init_compact_block: (1) `LoadingBlocks()` return,
  (2) `LookupBlockIndex(prev)` exists check, (3) low-work guard
  (`nChainWork + GetBlockProof < GetAntiDoSWorkThreshold()`),
  (4) `ProcessNewBlockHeaders` accept, (5) `BLOCK_HAVE_DATA` check
  (already-have-block), (6) `CanDirectFetch` recency window. Then
  `MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3` parallel-attempt cap.
  Finally `ProcessNewBlock(force_processing=true, fNewBlock=&new_block)`
  with `mapBlockSource` attribution for peer punishment.
- `bitcoin-core/src/net_processing.cpp:4245-4304` — `GETBLOCKTXN` handler.
  Three-tier serving path: recent-block-cache fast path (`m_most_recent_block`
  / `m_most_recent_compact_block_hash`), block-from-disk if within
  `MAX_BLOCKTXN_DEPTH`, MSG_WITNESS_BLOCK fallback for older. Indexes
  validated by `DifferenceFormatter` (strict-monotone post-decode).
- `bitcoin-core/src/net_processing.cpp:2598-2614` — `SendBlockTransactions`:
  out-of-range index → `Misbehaving(peer, 100, "getblocktxn with out-of-bounds tx indices")`.
- `bitcoin-core/src/net_processing.cpp:4710-4736` — `BLOCKTXN` handler.
  LoadingBlocks return, then `ProcessCompactBlockTxns`.

**Files audited**
- `src/beamchain_compact_block.erl` (376 LOC) — `init_compact_block/1`,
  `try_reconstruct/2`, `fill_block/2`, `get_missing_indices/1`,
  `compute_short_id/3`, `derive_siphash_key/2`. Encapsulates the
  `PartiallyDownloadedBlock` state. `MAX_COMPACT_BLOCK_TXS = 400000`
  (`:31`).
- `src/beamchain_block_sync.erl:36-40, 75-82, 144-150, 202-210,
  405-420, 1108-1118, 1287-1457` — `handle_cmpctblock/2`,
  `handle_blocktxn/2`, `handle_cmpctblock_received/3`,
  `do_handle_cmpctblock/5`, `do_handle_unsolicited_cmpctblock/4`,
  `handle_blocktxn_received/3`, `send_getblocktxn/3`,
  `request_full_block/3`, `pending_compact` map state,
  `is_cmpctblock_too_deep/2`, depth constants
  (`MAX_CMPCTBLOCK_DEPTH = 5`, `MAX_BLOCKTXN_DEPTH = 10`).
- `src/beamchain_sync.erl:33-37, 259-330` — `route_message/4` for
  cmpctblock / blocktxn / getblocktxn dispatch. `MAX_BLOCKTXN_DEPTH = 10`
  redefined (`:36`).
- `src/beamchain_peer.erl:97-101, 1253-1254, 1514-1520, 1630-1653`
  — `wants_cmpct` + `cmpct_version` peer_data fields,
  `dispatch_message(sendcmpct, ...)`, `handle_sendcmpct_msg/2`,
  `send_feature_msgs/1` (sends v1 AND v2 sendcmpct outbound).
- `src/beamchain_peer.erl:97-99` — `command_name`, `command_atom`
  for `sendcmpct`, `cmpctblock`, `getblocktxn`, `blocktxn`.
- `src/beamchain_p2p_msg.erl:250-251, 266-287, 460-461, 483-501,
  696-739` — encode/decode for sendcmpct, cmpctblock, getblocktxn,
  blocktxn; `encode_prefilled_txn` / `decode_prefilled_txns`;
  `encode_diff_indexes` / `decode_diff_indexes`; `decode_short_ids`.
- `src/beamchain_peer_manager.erl:316-342, 1436-1444, 1733-1801` —
  `announce_block/2` (headers-or-inv only, NO cmpctblock branch),
  `handle_peer_message(cmpctblock|blocktxn|getblocktxn, ...)`
  dispatch, `handle_getdata_msg/2` (no MSG_CMPCT_BLOCK = 4 case).
- `src/beamchain_crypto.erl:937-1049` — SipHash-2-4 reference +
  `siphash_uint256/3` optimised path for the BIP-152 hot path.
- `src/beamchain_serialize.erl:141-153, 185-200` — `encode_block_header`,
  `tx_hash`, `wtx_hash` (used by `compute_short_id` for wtxid).
- `include/beamchain_protocol.hrl:115-125` — `MSG_TX = 1`, `MSG_BLOCK = 2`,
  `MSG_FILTERED_BLOCK = 3`, `MSG_CMPCT_BLOCK = 4`, `MSG_WITNESS_TX`,
  `MSG_WITNESS_BLOCK`.

---

## Gate matrix (32 sub-gates / 10 behaviours)

| #  | Behaviour | Sub-gate | Verdict |
|----|-----------|----------|---------|
| 1  | sendcmpct version validation | G1: receiving sendcmpct(v != 2) silently dropped (Core: `:3907`) | **BUG-1 (P0-CDIV, W126-BUG-1 carry-forward, 7+ weeks open)** — `peer.erl:1514-1519` stores any version including 999/0/1 |
| 1  | … | G2: outbound sendcmpct sends ONLY v2 (Core 2024+ default) | **BUG-2 (P1, W126-BUG-17 carry-forward)** — `peer.erl:1646-1651` still sends v1 AND v2; we never speak v1 receive-side so the v1 advert is a lie |
| 1  | … | G3: sendcmpct received post-VERACK no-op (Core: yes) | PASS (`peer.erl:1253-1254` accepts; Core has no guard either) |
| 2  | sendcmpct state propagation | G4: HB-from flag readable by outbound announce logic | **BUG-3 (P0-CDIV, W126-BUG-3 carry-forward)** — `peer.erl:1517` writes only to `peer_data{}`; `peer_manager.erl:316-342` `announce_block/2` cannot read it |
| 3  | NewPoWValidBlock fast-announce | G5: on new tip, push CMPCTBLOCK to HB-from peers (Core: `:2103-2152`) | **BUG-4 (P0-CDIV, W126-BUG-2 carry-forward)** — `peer_manager.erl:324-342` `announce_block/2` only emits `headers`/`inv`; no cmpctblock branch. **`encode_payload(cmpctblock, ...)` exists at `p2p_msg.erl:266` but has ZERO call sites — pure dead-helper, 7+ weeks** |
| 3  | … | G6: HB-to set capped at 3 peers (Core: `MaybeSetPeerAsAnnouncingHeaderAndIDs` `:1272-1329`) | **BUG-5 (P1)** — moot pending BUG-4 but no infrastructure exists; a naive BUG-4 fix would push CMPCTBLOCK to every HB-requesting peer for every new tip |
| 4  | cmpctblock receive pre-gates | G7: `LoadingBlocks()` ignore (Core: `:4469-4472`) | **BUG-6 (P0)** — `block_sync.erl:411-413` dispatches regardless |
| 4  | … | G8: `LookupBlockIndex(prev_hash)` exists check + `MaybeSendGetHeaders` fallback (Core: `:4483-4488`) | **BUG-7 (P0)** — `block_sync.erl:1294-1311` jumps straight to `init_compact_block`. A header that doesn't connect locally still triggers full reconstruction attempt + mempool walk |
| 4  | … | G9: low-work guard `prev->nChainWork + GetBlockProof < GetAntiDoSWorkThreshold()` (Core: `:4490-4493`) | **BUG-8 (P0)** — no equivalent. A peer can flood mempool walks with garbage low-work cmpctblocks |
| 4  | … | G10: `ProcessNewBlockHeaders` BEFORE init_compact_block (Core: `:4503`) | **BUG-9 (P0)** — beamchain reverses the order: reconstruct, then validate header inside `connect_block` |
| 4  | … | G11: `BLOCK_HAVE_DATA` return-early (Core: `:4539-4540`) | PASS — `block_sync.erl:824-827` `has_block` check in `handle_unsolicited_block` (run AFTER reconstruction, so wasteful) |
| 4  | … | G12: `CanDirectFetch()` recency window (Core: `:4570-4572`) | **BUG-10 (P0)** — no equivalent (W126-BUG-8 carry-forward) |
| 4  | … | G13: `MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3` parallel-attempt cap (Core: `:4577, 4624`) | **BUG-11 (P1, W126-BUG-14 carry-forward)** — `block_sync.erl: pending_compact` is unbounded |
| 4  | … | G14: `via_compact_block=true` punishment distinction (Core: `:4505`) | **BUG-12 (P0)** — `block_sync.erl:1404` assigns 100 score for invalid cmpctblock without the HB-relay-before-validation excuse |
| 4  | … | G15: MAX_CMPCTBLOCK_DEPTH = 5 receiver-side guard | PASS — `block_sync.erl:79, 1116-1118` |
| 5  | InitData semantics | G16: header-IsNull reject (Core: `:62`) | PASS — `compact_block.erl:62-65, 263-264` (heuristic via `bits = 0`) |
| 5  | … | G17: empty cmpctblock reject (Core: `:62`) | PASS — `compact_block.erl:69` |
| 5  | … | G18: `shorttxids + prefilled > MAX_BLOCK_WEIGHT/MIN_SERIALIZABLE` reject (Core: `:64`) | PASS — `compact_block.erl:31, 75` (`MAX_COMPACT_BLOCK_TXS = 400000`) |
| 5  | … | G19: post-deserialize uint16 cap on `BlockTxCount()` (Core: `blockencodings.h:125`) | **BUG-13 (P1)** — beamchain enforces only the 400k cap; a cmpctblock with BlockTxCount = 100_000 (over 65535 but under 400_000) passes beamchain but Core throws "indexes overflowed 16 bits" |
| 5  | … | G20: prefilled-index strict-monotone + uint16-cap | PASS — `compact_block.erl:87-110` (W126 fix loop) |
| 5  | … | G21: prefilled-index per-tx cap `lastprefilledindex > shorttxids.size() + i` (Core: `:80-85`) | **BUG-14 (P0)** — `compact_block.erl:103-104` uses `AbsIdx >= TxnCount` (i.e. `shorttxids.size() + prefilled.size()`) instead of the per-i cap. For early prefilled txs (i=0, 1, 2…) Core rejects much earlier than beamchain. A wire-crafted prefilled at abs_idx = `shorttxids.size() + 0` for the first prefilled would fail Core's check but pass beamchain |
| 5  | … | G22: prefilled-tx-is-null reject (Core: `:74`) | PASS — `compact_block.erl:91` |
| 5  | … | G23: **coinbase MUST be at prefilled[0] with abs_idx=0** (BIP-152 §"PrefilledTransaction") | **BUG-15 (P0)** — `compact_block.erl: init_compact_block` does NOT enforce `Prefilled[0].abs_idx == 0`. A peer can send cmpctblock with NO coinbase prefilled (or with first prefilled at abs_idx=5); reconstruction tries mempool lookup for the coinbase slot, which always fails (coinbases aren't in mempool), but the partial state proceeds to getblocktxn round-trip. The merkle root check eventually catches this but only after wire+CPU spend |
| 5  | … | G24: duplicate short-id reject (Core: `:115`) | PASS — `compact_block.erl:121-127` (W126 fix) |
| 5  | … | G25: bucket-size > 12 hash-collision DoS reject (Core: `:110`) | **BUG-16 (P1, W126-BUG-11 carry-forward)** — Erlang maps don't expose buckets; no equivalent |
| 6  | FillBlock | G26: count-mismatch reject (Core: `:214`) | PASS — `compact_block.erl:206-209` (W126 fix) |
| 6  | … | G27: `IsBlockMutated` (CVE-2012-2459 + 64-byte tx + witness malleation) (Core: `:219-222`, `validation.cpp:4027`) | **BUG-17 (P0-CDIV, W126-BUG-7 carry-forward, W143-W156 echo)** — `compact_block.erl:372-376` `verify_merkle_root` only checks merkle equality; misses **all three** mutation classes. A short-id collision that swaps in a 64-byte non-coinbase tx reconstructs cleanly and feeds into chainstate |
| 7  | getblocktxn handler | G28: `LoadingBlocks()` ignore | **BUG-18 (P0)** — `sync.erl:278-326` no equivalent |
| 7  | … | G29: recent-block-cache fast path (Core: `:4254-4264`) | **BUG-19 (P1, W126-BUG-10 carry-forward)** — every getblocktxn reads from RocksDB |
| 7  | … | G30: out-of-bounds index → Misbehaving(100) (Core: `:2602-2614`) | **BUG-20 (P0, W126-BUG-9 carry-forward)** — `sync.erl:310-319` `lists:filtermap` silently drops out-of-range indices |
| 7  | … | G31: MAX_BLOCKTXN_DEPTH = 10 fallback to MSG_WITNESS_BLOCK | PASS — `sync.erl:285-306` |
| 8  | blocktxn handler | G32: `LoadingBlocks()` ignore (Core: `:4717-4720`) | **BUG-21 (P0)** — `block_sync.erl:416-420` gates on `status =:= syncing` (inverted: drops post-IBD) |

---

## BUG-1 (P0-CDIV) — sendcmpct accepts any version (W126-BUG-1, 7-week carry-forward)

**Severity:** P0-CDIV. Core's `CMPCTBLOCKS_VERSION = 2` (net_processing.cpp:199) is the **only** version Core honors. The handler at `net_processing.cpp:3901-3917`:

```cpp
if (msg_type == NetMsgType::SENDCMPCT) {
    bool sendcmpct_hb{false};
    uint64_t sendcmpct_version{0};
    vRecv >> sendcmpct_hb >> sendcmpct_version;
    if (sendcmpct_version != CMPCTBLOCKS_VERSION) return;  // ← silent drop
    ...
    nodestate->m_provides_cmpctblocks = true;
    nodestate->m_requested_hb_cmpctblocks = sendcmpct_hb;
```

beamchain `peer.erl:1514-1520`:

```erlang
handle_sendcmpct_msg(Payload, Data) ->
    case beamchain_p2p_msg:decode_payload(sendcmpct, Payload) of
        {ok, #{announce := Ann, version := V}} ->
            {ok, Data#peer_data{wants_cmpct = Ann, cmpct_version = V}};  % ← any V
        _ ->
            {ok, Data}
    end.
```

A peer can wedge beamchain's HB-from state with `sendcmpct(true, version=0)` or `(true, version=3)` or `(true, version=999)`. The version is recorded on `peer_data{}` and never validated against {2}. Today this is benign-by-accident because the outbound CMPCTBLOCK push doesn't exist (BUG-4), so the wedged state never produces a divergent outcome. **But the moment BUG-4 is fixed without also fixing BUG-1, every peer that sends `sendcmpct(version != 2)` becomes a malformed-cmpctblock loop**: we'd push them v2-encoded cmpctblocks (wtxid-based shortids), they'd interpret as their declared version, reconstruction fails silently, and the BIP-152 fallback path is unreliable across implementations.

**File:** `src/beamchain_peer.erl:1514-1520`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:3907`.

**Impact:** wedge primitive against the HB-from set; carry-forward 7+ weeks since W126.

---

## BUG-2 (P1) — Outbound sendcmpct still sends v1 (W126-BUG-17 carry-forward)

**Severity:** P1. Bitcoin Core's 2024+ behavior at `net_processing.cpp:3870`:

```cpp
MakeAndPushMessage(pfrom, NetMsgType::SENDCMPCT, /*high_bandwidth=*/false, /*version=*/CMPCTBLOCKS_VERSION);
```

— sends ONLY v2. beamchain `peer.erl:1646-1651`:

```erlang
CmpctV1 = beamchain_p2p_msg:encode_payload(sendcmpct,
              #{announce => false, version => 1}),
D2 = do_send_raw(sendcmpct, CmpctV1, D1),
CmpctV2 = beamchain_p2p_msg:encode_payload(sendcmpct,
              #{announce => true, version => 2}),
D3 = do_send_raw(sendcmpct, CmpctV2, D2),
```

— sends BOTH v1 and v2. The v1 advertise tells the peer beamchain
accepts v1-encoded cmpctblocks (txid-based shortids). beamchain's
`compute_short_id` (`compact_block.erl:241-243`) only uses wtxid
(v2 semantics). A peer who took us at our v1 advert and pushed a
v1-cmpctblock would silently fail reconstruction.

**The inline comment is a 12th-instance "comment-as-confession"
fleet pattern**: lines 1642-1645 admit that the v1 advert was added
to "get into any peer's HB-to set", which suggests the v1 advert is
a workaround for some peer misbehavior (likely Core nodes refusing
to honor a v2-only HB request on incompatible code paths). But the
side effect is that a v1-speaking peer would mis-encode.

**File:** `src/beamchain_peer.erl:1646-1651`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:3870`.

**Impact:** subtle interop break with any peer that takes the v1
advert literally; for current mainnet (~all peers Core-derived) this
is dormant. Cross-cite: W126-BUG-17 same finding, not yet fixed.

---

## BUG-3 (P0-CDIV) — `wants_cmpct`/`cmpct_version` isolated to peer_data (W126-BUG-3 carry-forward)

**Severity:** P0-CDIV. Core's `nodestate->m_provides_cmpctblocks` and `m_requested_hb_cmpctblocks` live on the per-NodeId `CNodeState` keyed in a manager-global mutex-protected map (`net_processing.cpp:3911-3912`), making them readable from the `MaybeSetPeerAsAnnouncingHeaderAndIDs` / `NewPoWValidBlock` paths.

beamchain stores wants_cmpct + cmpct_version on the per-peer `peer_data{}` record (`peer.erl:97-101, 1517`). The `peer_manager` ETS table at `peer_manager.erl: ?PEER_TABLE` has columns for `wants_headers`, `info`, etc., but **NO `wants_cmpct` column**. The `announce_block/2` function reads `wants_headers` directly from ETS rows (`peer_manager.erl:326-329`); it cannot reach `peer_data.wants_cmpct` without an inter-process call to every peer's gen_server.

**Concretely**: even if a follow-on FIX wave naively adds a `cmpctblock` branch to `pick_announce_msg/3`, that branch cannot decide which peers are HB-from until `wants_cmpct` is exported into the ETS row. This is a **dead-data-plumbing** pattern (set on one struct, never readable by the consumer that needs it) — 13th distinct beamchain instance per W141-W155 tracking.

**File:** `src/beamchain_peer.erl:1517`; `src/beamchain_peer_manager.erl: peer_entry record` (~`:170` per file index — has wants_headers but NOT wants_cmpct).

**Core ref:** `bitcoin-core/src/net_processing.cpp:3911-3912`,
`bitcoin-core/src/net_processing.cpp:460` (`m_provides_cmpctblocks` in
the Peer struct).

**Impact:** blocks the BUG-4 fix; tip-relay latency stays at the slow
inv→getheaders→headers→getdata→block path forever.

---

## BUG-4 (P0-CDIV) — `announce_block/2` has no cmpctblock branch; `encode_payload(cmpctblock, ...)` is dead-helper (W126-BUG-2 carry-forward, 7+ weeks)

**Severity:** P0-CDIV. Core's `NewPoWValidBlock` (`net_processing.cpp:2103-2152`)
fans the new tip out via three paths:

1. HB-from peers: unsolicited `CMPCTBLOCK` push (the BIP-152 high-bandwidth path);
2. sendheaders peers: `headers` push;
3. legacy peers: `inv(MSG_BLOCK)`.

beamchain's `announce_block/2` (`peer_manager.erl:316-342`):

```erlang
pick_announce_msg(true, Header, _BlockHash) ->
    {headers, #{headers => [Header]}};
pick_announce_msg(false, _Header, BlockHash) ->
    {inv, #{items => [#{type => ?MSG_BLOCK, hash => BlockHash}]}}.
```

— enumerates only the headers / inv paths. **There is no cmpctblock
branch.** The peer-side `encode_payload(cmpctblock, ...)` exists at
`p2p_msg.erl:266-276`; a grep across `src/`, `include/`, `test/` for
any caller other than `decode_payload` returns zero hits.

**Side-effect dependency chain**:
- BUG-1 wedge of HB-from state is currently masked because we never
  push CMPCTBLOCK anyway.
- BUG-3 (state-isolation) blocks BUG-4 fix.
- BUG-5 (no HB-to cap) is moot pending BUG-4 fix.

This is the **encoder-without-callers** archetype (dead-helper, 13th
instance, fleet-wide pattern). The most concerning consequence is
that beamchain advertises `sendcmpct(announce=true, version=2)` to
every peer post-handshake (`peer.erl:1649-1651`), creating an
**asymmetric BIP-152 role**: peers honor the announce request and
elect beamchain as HB-from candidate; beamchain receives but never
serves. From the peer's perspective beamchain looks like a node
with permanently-empty mempool.

**File:** `src/beamchain_peer_manager.erl:324-342`; `src/beamchain_p2p_msg.erl:266-276`
(dead encode_payload).

**Core ref:** `bitcoin-core/src/net_processing.cpp:2103-2152`
(`NewPoWValidBlock`).

**Impact:** receive-only BIP-152 role; tip propagation latency ~1-2
blocks higher than Core peers (W126 ticket noted this as observed
behavior on 2026-04-25 mainnet); 7+ weeks open.

---

## BUG-5 (P1) — No HB-to outbound peer cap; would amplify if BUG-4 naively fixed

**Severity:** P1 (latent — moot until BUG-4 is addressed). Core's
`MaybeSetPeerAsAnnouncingHeaderAndIDs` at
`bitcoin-core/src/net_processing.cpp:1272-1329` maintains
`lNodesAnnouncingHeaderAndIDs` capped at 3 peers; when a 4th is
selected the oldest is demoted via `sendcmpct(high_bandwidth=false)`.
The cap exists because CMPCTBLOCK pushes are uncoordinated bandwidth
amplification: a single new block costs ~12 KB per HB-from peer.
Without the cap, an attacker could `sendcmpct(announce=true)` from
50 IP addresses and force beamchain to send 50 × 12 KB = 600 KB on
every new tip — a 50× amplification of every mined block.

**File:** none — would need to be added alongside BUG-4 fix.

**Core ref:** `bitcoin-core/src/net_processing.cpp:1272-1329`.

**Impact:** latent DoS amplification; bundled with BUG-4 fix.

---

## BUG-6 (P0) — `cmpctblock` handler missing `LoadingBlocks` ignore-gate

**Severity:** P0. Bitcoin Core's CMPCTBLOCK handler at
`net_processing.cpp:4469-4472`:

```cpp
// Ignore cmpctblock received while importing
if (m_chainman.m_blockman.LoadingBlocks()) {
    LogDebug(BCLog::NET, "Unexpected cmpctblock message received from peer %d\n", pfrom.GetId());
    return;
}
```

The rationale is that during reindex / blocks.dat import, the
chainstate is mid-construction and any block reconstruction would
race against the local import path. beamchain `block_sync.erl:411-413`:

```erlang
handle_cast({cmpctblock, Peer, CmpctBlock}, State) ->
    State2 = handle_cmpctblock_received(Peer, CmpctBlock, State),
    {noreply, State2};
```

No status / loading-state guard. Inbound cmpctblocks during a
hypothetical reindex would feed into `connect_block` mid-construction.

**Beamchain doesn't ship `-reindex` today** (`block_sync.erl: no
loading_blocks state`), so this is currently latent — but the lack
of a gate is a structural defect that will surface the day reindex
lands. Cross-cite: W149-BUG-22 (`-reindex` flag rejected with hard
error) means a corrupt chainstate is currently a `rm -rf datadir`
recovery; if reindex is ever added, this gate becomes essential.

**File:** `src/beamchain_block_sync.erl:411-413`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4469-4472`.

**Impact:** latent (no reindex today); P0 the moment reindex lands.
Cross-cite W126-BUG-6 (same finding for the blocktxn handler).

---

## BUG-7 (P0) — cmpctblock processed without parent-block existence check; no `MaybeSendGetHeaders` fallback

**Severity:** P0. Bitcoin Core's CMPCTBLOCK handler runs FIVE
gates between message arrival and `InitData`:

```cpp
LOCK(cs_main);
const CBlockIndex* prev_block = m_chainman.m_blockman.LookupBlockIndex(cmpctblock.header.hashPrevBlock);
if (!prev_block) {
    if (!m_chainman.IsInitialBlockDownload()) {
        MaybeSendGetHeaders(pfrom, GetLocator(m_chainman.m_best_header), peer);
    }
    return;
}
```

(`net_processing.cpp:4483-4488`). The check serves two purposes:
(1) avoid wasting reconstruction CPU on a cmpctblock whose parent
we haven't validated yet, (2) **opportunistically issue
`MaybeSendGetHeaders`** so the peer's chain catches us up.

beamchain `block_sync.erl:1294-1311` `handle_cmpctblock_received`
proceeds directly to `init_compact_block` (which calls
`block_hash(Header)` to derive a key), then to `try_reconstruct`
(which walks the **entire mempool** computing wtxid + short-id for
every entry — see `compact_block.erl:282-311`). For a beamchain node
with a 10k-entry mempool and a peer that pushes a cmpctblock with
random `prev_hash`, every such message costs 10k × (witness-encode
+ SHA-256 + SipHash) operations. A peer can amplify trivially.

**Secondary**: no `MaybeSendGetHeaders` means a peer who tries to
help us catch up via cmpctblock relay gets no headers request in
return; we stay behind even when the peer was acting honestly.

**File:** `src/beamchain_block_sync.erl:1294-1311`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4483-4488`.

**Impact:** mempool-walk DoS amplifier; missing headers-sync nudge.

---

## BUG-8 (P0) — Low-work guard missing on inbound cmpctblock

**Severity:** P0. Core at `net_processing.cpp:4490-4493`:

```cpp
} else if (prev_block->nChainWork + GetBlockProof(cmpctblock.header) < GetAntiDoSWorkThreshold()) {
    // If we get a low-work header in a compact block, we can ignore it.
    LogDebug(BCLog::NET, "Ignoring low-work compact block from peer %d\n", pfrom.GetId());
    return;
}
```

The `GetAntiDoSWorkThreshold` (validation.cpp) computes the minimum
chainwork beneath which a header is considered DoS-grade. beamchain
has no `min_chain_work` derivation for the cmpctblock path; even if
it did, `block_sync.erl:1294-1311` performs no such check. A peer
can craft headers with valid PoW but well below the active tip's
work and force reconstruction work.

**File:** `src/beamchain_block_sync.erl:1294-1311`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4490-4493`,
`bitcoin-core/src/validation.cpp::GetAntiDoSWorkThreshold`.

**Impact:** DoS via low-work cmpctblock flood.

---

## BUG-9 (P0) — `ProcessNewBlockHeaders` not called BEFORE reconstruction

**Severity:** P0. Core at `net_processing.cpp:4503-4514`:

```cpp
const CBlockIndex *pindex = nullptr;
BlockValidationState state;
if (!m_chainman.ProcessNewBlockHeaders({{cmpctblock.header}}, /*min_pow_checked=*/true, state, &pindex)) {
    if (state.IsInvalid()) {
        MaybePunishNodeForBlock(pfrom.GetId(), state, /*via_compact_block=*/true, "invalid header via cmpctblock");
        return;
    }
}
Assert(pindex);
if (received_new_header) {
    LogBlockHeader(*pindex, pfrom, /*via_compact_block=*/true);
}
```

The header is validated and admitted to the block index BEFORE
reconstruction is attempted. This is what allows `mapBlocksInFlight`
tracking, `MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3` enforcement,
`UpdateBlockAvailability` peer-state tracking, and the `via_compact_block=true`
punishment-distinction.

beamchain reverses this order: `init_compact_block` runs first, then
on full reconstruction success `handle_unsolicited_block` calls
`chainstate:connect_block` which internally drives header acceptance.
There's no point in the pipeline where the header is admitted as
"valid but body pending" — beamchain only knows about a block once
it has the FULL body.

**Concrete consequence**: `pending_compact` state is keyed on the
block hash but the header isn't in the block index until reconstruction
+ connect succeed. A second cmpctblock for the same hash from a
different peer cannot find the in-flight entry via the standard
`mapBlocksInFlight` mechanism; beamchain races two reconstruction
attempts in parallel without coordination.

**File:** `src/beamchain_block_sync.erl:1349-1407`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4503-4514`.

**Impact:** unbounded parallel reconstruction (cross-cite BUG-11);
no via_compact_block punishment exception (cross-cite BUG-12);
no header-availability accounting.

---

## BUG-10 (P0) — `CanDirectFetch()` recency gate missing (W126-BUG-8 carry-forward)

**Severity:** P0. Core at `net_processing.cpp:4570-4572`:

```cpp
// If we're not close to tip yet, give up and let parallel block fetch work its magic
if (!already_in_flight && !CanDirectFetch()) {
    return;
}
```

`CanDirectFetch` is defined as "tip within 20× PowTargetSpacing of now"
(~3.3 hours). During IBD or a long disconnect, cmpctblocks are
ignored for reconstruction — the peer's mempool is unlikely to help
us anyway, and the standard parallel block fetch path is preferred.

beamchain has no equivalent. During IBD a peer can push cmpctblocks
for tip blocks; beamchain allocates `pending_compact` state per
arrival and round-trips `getblocktxn` for blocks it has no business
reconstructing.

**File:** `src/beamchain_block_sync.erl:1349-1407`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4570-4572`,
`bitcoin-core/src/net_processing.cpp::CanDirectFetch`.

**Impact:** IBD-time memory growth via `pending_compact` map;
W126-BUG-8 carry-forward.

---

## BUG-11 (P1) — `pending_compact` is unbounded (W126-BUG-14 + BUG-16 carry-forward)

**Severity:** P1. Core's `MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3`
(net_processing.h:47) caps parallel reconstruction attempts for the
same block hash to 3 (BIP-152 §"Protocol Flow" recommends 3 to
maximize the chance one peer's mempool has the missing txs).
Additionally, the `BlockRequested` / `RemoveBlockRequest` stall path
evicts stale entries via the `mapBlocksInFlight` timeout.

beamchain `block_sync.erl: state.pending_compact` (`:146-150`) is a
plain map. Entries are removed:
- on successful `fill_block` (`:1419-1421`);
- on `fill_block` error → request full block (`:1435-1437`);
- ...and that's it. NOT on peer disconnect, NOT on timeout, NOT on
  tip advancement past the missing block.

The unbounded growth is bounded in practice by the fact that we only
add to pending_compact in `do_handle_cmpctblock` (solicited path),
not `do_handle_unsolicited_cmpctblock` (which drops partials per
the comment at `:1316-1320`). So today the leak only fires during
IBD; post-IBD partial unsolicited cmpctblocks are dropped before
allocation. Still a P1 leak primitive — the moment the unsolicited
path tracks partials, the map grows without sweep.

**File:** `src/beamchain_block_sync.erl:146-150, 1322-1347,
1349-1407, 1419-1437`.

**Core ref:** `bitcoin-core/src/net_processing.h:47`,
`bitcoin-core/src/net_processing.cpp:4577, 4624`.

**Impact:** memory leak primitive; carry-forward W126.

---

## BUG-12 (P0) — `via_compact_block=true` punishment-distinction missing

**Severity:** P0. Core's invalid-block punishment path threads a
`via_compact_block` flag (`net_processing.cpp:4505, 4677, 4682`)
into `MaybePunishNodeForBlock`. BIP-152 §"Protocol Flow" requires
that HB peers MAY relay cmpctblocks before they have fully validated
the block — so receiving an invalid block "via_compact_block" does
NOT trigger ban score; the peer is permitted that one round of
optimistic relay.

beamchain `block_sync.erl:1399-1405`:

```erlang
{error, Reason} ->
    logger:warning("block_sync: invalid compact block: ~p", [Reason]),
    %% BUG-9 fix: Core assigns 100 (ban) for READ_STATUS_INVALID
    %% (net_processing.cpp ProcessMessage/cmpctblock path).
    %% A malformed cmpctblock that fails init is READ_STATUS_INVALID.
    beamchain_peer:add_misbehavior(Peer, 100),
    State
```

— assigns 100 score (instant ban) for READ_STATUS_INVALID. Core
distinguishes: READ_STATUS_INVALID at *init* time IS a ban offense
(the cmpctblock wire format is malformed), but `MaybePunishNodeForBlock`
for the BLOCK-validation failures is gated on `via_compact_block`
**not** being true.

beamchain compounds the bug: `handle_unsolicited_block` (called from
the unsolicited cmpctblock path) at `:881-884` assigns 100 score
for any `connect_block` failure. An honest HB peer who relays a
cmpctblock before fully validating gets banned.

**File:** `src/beamchain_block_sync.erl:881-884, 1399-1405`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4505, 4677, 4682`.

**Impact:** beamchain bans honest BIP-152 HB peers for the BIP-152-permitted
pre-validation relay window.

---

## BUG-13 (P1) — Post-deserialize `BlockTxCount() > 65535` cap missing

**Severity:** P1. Bitcoin Core's `CBlockHeaderAndShortTxIDs::SERIALIZE_METHODS`
at `blockencodings.h:121-130`:

```cpp
SERIALIZE_METHODS(CBlockHeaderAndShortTxIDs, obj) {
    READWRITE(obj.header, obj.nonce, ...);
    if (ser_action.ForRead()) {
        if (obj.BlockTxCount() > std::numeric_limits<uint16_t>::max()) {
            throw std::ios_base::failure("indexes overflowed 16 bits");
        }
        obj.FillShortTxIDSelector();
    }
}
```

— hard cap of 65535 (uint16_t max). beamchain enforces only the
larger `MAX_COMPACT_BLOCK_TXS = 400000` (`compact_block.erl:31, 75`).
A cmpctblock with `BlockTxCount() = 100_000` (above 65535, under
400_000) passes beamchain's init but Core throws.

Today's reality: real Bitcoin blocks have ~2-4k transactions max,
so the gap is academic in practice. But a wire-crafted message
exercising the 65k-400k range proves a divergence-to-Core that
could cascade if other implementations also enforce the uint16 cap
(they likely do).

**File:** `src/beamchain_compact_block.erl:31, 75`.

**Core ref:** `bitcoin-core/src/blockencodings.h:125`.

**Impact:** wire-format parity gap; latent until exotic blocks hit
the 65k-400k zone (never on real chain).

---

## BUG-14 (P0) — Prefilled-index per-prefilled-tx cap diverges from Core

**Severity:** P0. Core at `blockencodings.cpp:80-85`:

```cpp
if ((uint32_t)lastprefilledindex > cmpctblock.shorttxids.size() + i) {
    // If we are inserting a tx at an index greater than our full list of shorttxids
    // plus the number of prefilled txn we've inserted, then we have txn for which we
    // have neither a prefilled txn or a shorttxid!
    return READ_STATUS_INVALID;
}
```

The check is a *per-prefilled-tx* invariant: at iteration `i`,
`lastprefilledindex` (the absolute index of the just-decoded prefilled
tx) must be ≤ `shorttxids.size() + i`. The intuition: for every
absolute position `j` from 0..lastprefilledindex, we must have
EITHER a shorttxid covering it (if not yet at i prefilled txs) OR
a prefilled tx at it (at most i of those so far).

beamchain `compact_block.erl:99-104`:

```erlang
%% BUG-4 fix: absolute index must not skip past shorttxids + fills.
%% Core: (uint32_t)lastprefilledindex > cmpctblock.shorttxids.size() + i
%% We compute this check below (would require tracking i separately;
%% we defer to the AbsIdx < TxnCount check as an approximation,
%% supplemented by the >= TxnCount guard already in place).
AbsIdx >= TxnCount andalso throw(invalid_prefilled_index),
```

— the **comment explicitly admits deferring the correct per-i check**
and substituting the looser `AbsIdx >= TxnCount` boundary. This is
a **comment-as-confession** (13th fleet instance) AND a documented
divergence-from-Core that has been carried since W126's BUG-4 closure.

**Concrete divergence**: cmpctblock with `shorttxids.size() = 10`
and 3 prefilled txns whose absolute indexes are `[12, 13, 14]`:
- Core at i=0: `lastprefilledindex = 12 > 10 + 0 = 10` → REJECT.
- beamchain: `TxnCount = 10 + 3 = 13`. Iteration:
  - i=0: AbsIdx=12, `12 >= 13` false → accept.
  - i=1: AbsIdx=13, `13 >= 13` true → throw.
  beamchain accepts the FIRST prefilled at AbsIdx=12 before throwing.

Functional impact: beamchain attempts mempool reconstruction with
a partially-corrupt prefilled set; the resulting block reconstruction
fails at merkle-root verification, but only after a full mempool walk
+ getblocktxn round-trip. Core rejects up-front with READ_STATUS_INVALID.

**File:** `src/beamchain_compact_block.erl:99-110`.

**Core ref:** `bitcoin-core/src/blockencodings.cpp:80-85`.

**Impact:** asymmetric reject behavior (beamchain slower to reject,
allocates state, does mempool walk); divergent wire-protocol
semantics; 7+ weeks since W126 deferred it.

---

## BUG-15 (P0) — Coinbase-at-prefilled[0]-abs-idx-0 invariant unenforced

**Severity:** P0. BIP-152 §"CBlockHeaderAndShortTxIDs":

> A list of "prefilled" transactions of length given by the
> prefilled_txn_length value. ... The first prefilled transaction
> MUST be the coinbase transaction (i.e., its index field MUST be 0
> and its tx field MUST be the coinbase transaction).

Core enforces structurally via `CBlockHeaderAndShortTxIDs` constructor
(`blockencodings.cpp:28`):

```cpp
prefilledtxn[0] = {0, block.vtx[0]};
```

— and on the receive side, the implicit assumption that prefilledtxn[0]
has differential index = 0 (which decodes to absolute index 0) is
threaded through `InitData`'s short-id assignment logic — when
`i + index_offset` lands on the coinbase slot, it must be filled.

beamchain `compact_block.erl:87-110` has NO check that `Prefilled[0].abs_idx == 0`:

```erlang
{TxnAvailable1, _LastIdx} = lists:foldl(
    fun(#{index := DiffIdx, tx := Tx}, {Arr, PrevIdx}) ->
        is_null_tx(Tx) andalso throw(null_prefilled_tx),
        AbsIdx = PrevIdx + DiffIdx + 1,
        AbsIdx > 65535 andalso throw(prefilled_index_overflow),
        AbsIdx >= TxnCount andalso throw(invalid_prefilled_index),
        Arr2 = array:set(AbsIdx, Tx, Arr),
        {Arr2, AbsIdx}
    end,
    {TxnAvailable0, -1},
    Prefilled),
```

A peer can send cmpctblock with:
- empty `Prefilled` (no coinbase prefilled) — `compact_block.erl:69`
  rejects only the case where BOTH short_ids AND prefilled are empty,
  so a peer can send (10 short_ids, 0 prefilled);
- or `Prefilled = [{index=3, tx=non-coinbase-tx}]` (first prefilled
  at AbsIdx=3, no coinbase prefilled).

Reconstruction proceeds. The mempool slot at abs_idx=0 (the coinbase
slot) has no candidate — coinbases aren't in mempool, never. The
slot stays `undefined` after `match_mempool_txns` and
`match_extra_txns`. `get_missing_indices` returns `[0, ...]`. We
issue `getblocktxn(indexes=[0, ...])`. Peer responds with their
coinbase. We `fill_block`, merkle-root verifies, accept.

**Why this is P0**: this opens an attack where a peer can launder
the coinbase via getblocktxn. Worse: the round-trip costs us, and
the peer can stall indefinitely on the getblocktxn response.

**The merkle-root check IS the long-term safety net**, but Core
rejects before reaching it; beamchain doesn't.

**File:** `src/beamchain_compact_block.erl:87-110` (init_compact_block
prefilled loop, no abs_idx-0 check on Prefilled[0]).

**Core ref:** `bitcoin-core/src/blockencodings.cpp:28`; BIP-152
§"CBlockHeaderAndShortTxIDs".

**Impact:** wire-DoS (force getblocktxn round-trip), latency
amplifier, BIP-152 spec violation accepted.

---

## BUG-16 (P1) — Bucket-collision DoS check missing (W126-BUG-11 carry-forward)

**Severity:** P1. Core at `blockencodings.cpp:110-111`:

```cpp
if (shorttxids.bucket_size(shorttxids.bucket(cmpctblock.shorttxids[i])) > 12)
    return READ_STATUS_FAILED;
```

— defends against an adversary who picks shorttxids that hash-collide
in `std::unordered_map`, forcing bucket walks that dominate
reconstruction time. The "12 elements" threshold is derived from the
binomial-distribution math at lines 100-109.

beamchain uses Erlang `maps:put` for the shorttxid → index map
(`compact_block.erl:162-169`). Erlang maps are persistent HAMT —
the bucket-collision attack shape is different (HAMT lookups are
O(log32 N) worst case), so the asymptotic resistance is better,
BUT the explicit DoS-rejection invariant is not enforced. If maps
implementation ever shifts to a hash-bucket variant, the gap reopens.

**File:** `src/beamchain_compact_block.erl:162-169`.

**Core ref:** `bitcoin-core/src/blockencodings.cpp:110-111`.

**Impact:** DoS resistance is implementation-dependent rather than
structurally enforced; carry-forward W126-BUG-11.

---

## BUG-17 (P0-CDIV) — `verify_merkle_root` is not `IsBlockMutated` (W126-BUG-7 + W143-W156 echo)

**Severity:** P0-CDIV. Core's `FillBlock` at `blockencodings.cpp:218-222`:

```cpp
// Check for possible mutations early now that we have a seemingly good block
IsBlockMutatedFn check_mutated{m_check_block_mutated_mock ? m_check_block_mutated_mock : IsBlockMutated};
if (check_mutated(/*block=*/block, /*check_witness_root=*/segwit_active)) {
    return READ_STATUS_FAILED; // Possible Short ID collision
}
```

`IsBlockMutated` (`validation.cpp:4027`) checks **three** mutation classes:
1. **CVE-2012-2459**: `CheckMerkleRoot` with `mutated` flag — detects
   the duplicate-last-pair attack where a block with N transactions
   can be re-presented with the last odd transaction duplicated and
   still produce the same merkle root.
2. **64-byte transaction**: any non-coinbase tx that
   `GetSerializeSize(TX_NO_WITNESS(tx)) == 64` is mutation-vulnerable
   because 64-byte non-coinbase txs can be interpreted as merkle-node
   pairs (CVE-2017-12842 class).
3. **Witness malleation**: `CheckWitnessMalleation` for segwit-active
   blocks — verifies the witness merkle commitment is consistent.

beamchain `compact_block.erl:372-376`:

```erlang
verify_merkle_root(#block{header = Header, transactions = Txs}) ->
    ExpectedRoot = Header#block_header.merkle_root,
    TxHashes = [beamchain_serialize:tx_hash(Tx) || Tx <- Txs],
    ComputedRoot = beamchain_serialize:compute_merkle_root(TxHashes),
    ExpectedRoot =:= ComputedRoot.
```

— ONLY merkle-root equality. **The compute_merkle_root function at
`serialize.erl:215-221` is the very implementation that's vulnerable
to CVE-2012-2459** (it duplicates odd elements rather than tracking
a mutation flag):

```erlang
merkle_pairs([A]) ->
    %% odd element: duplicate it
    [hash256(<<A/binary, A/binary>>)];
```

This is the canonical W143 BUG-1 echo (CVE-2012-2459 mutated-merkle
detection MISSING fleet-wide pattern, 6+ impls). For the cmpctblock
path it compounds: a short-id collision could legitimately produce
a transaction whose `wtxid` ≠ the original (different witness data),
but whose `txid` (non-witness hash) collides with the block's actual
coinbase or another tx. Reconstruction succeeds, `verify_merkle_root`
passes (because the txid still matches what the merkle root expects),
the block is admitted into chainstate, and only THEN does the witness
commitment verification (in `connect_block`) fail.

The 64-byte-tx mutation class is even more concerning: a short-id
collision that swaps in a 64-byte non-coinbase tx would survive
`verify_merkle_root` IF the 64-byte tx happens to hash to the same
txid as the original (vanishingly unlikely but structurally allowed
by beamchain).

**File:** `src/beamchain_compact_block.erl:355-376`;
`src/beamchain_serialize.erl:215-221` (vulnerable merkle helper).

**Core ref:** `bitcoin-core/src/blockencodings.cpp:218-222`,
`bitcoin-core/src/validation.cpp:4027` (`IsBlockMutated`).

**Impact:** chain-split candidate vs Core on adversarial cmpctblock;
W126-BUG-7 + W143 fleet-pattern carry-forward; carry-forward 7+ weeks.

---

## BUG-18 (P0) — `getblocktxn` handler missing `LoadingBlocks` ignore-gate

**Severity:** P0. Bitcoin Core's GETBLOCKTXN handler at
`net_processing.cpp:4245-4252`:

```cpp
if (msg_type == NetMsgType::GETBLOCKTXN) {
    if (m_chainman.m_blockman.LoadingBlocks()) {
        LogDebug(BCLog::NET, "Unexpected getblocktxn message received from peer %d\n", pfrom.GetId());
        return;
    }
    ...
}
```

beamchain `sync.erl:278-326` has no equivalent. During a hypothetical
reindex, a peer's getblocktxn would `beamchain_db:get_block(BlockHash)`
mid-construction; the result may or may not be consistent.

Cross-cite BUG-6 — same gap as the cmpctblock receiver. Together
with W149-BUG-22 (`-reindex` rejected), the gates are latent today
but structurally important.

**File:** `src/beamchain_sync.erl:278-326`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4245-4252`.

**Impact:** latent (no reindex today); P0 if reindex lands.

---

## BUG-19 (P1) — `getblocktxn` reads from RocksDB on every call; no recent-block cache (W126-BUG-10 carry-forward)

**Severity:** P1. Bitcoin Core caches `m_most_recent_block` /
`m_most_recent_compact_block_hash` (`net_processing.cpp:4254-4264`):

```cpp
std::shared_ptr<const CBlock> recent_block;
{
    LOCK(m_most_recent_block_mutex);
    if (m_most_recent_block_hash == req.blockhash) {
        recent_block = m_most_recent_block;
    }
}
if (recent_block) {
    SendBlockTransactions(pfrom, peer, *recent_block, req);
    return;
}
```

The cache is populated by every `NewPoWValidBlock` (the same path
that pushes CMPCTBLOCK). Critical hot path: when we mine or accept
a new tip and push it as CMPCTBLOCK to N HB-from peers, those N
peers may EACH round-trip getblocktxn for missing txs; serving
those N round-trips from the in-memory cache rather than RocksDB
is the difference between ~µs and ~ms per response on a heavily-loaded
node.

beamchain `sync.erl:299` always calls `beamchain_db:get_block(BlockHash)`
which round-trips through the `beamchain_db` gen_server to RocksDB.

Today this is academic — BUG-4 means we never push CMPCTBLOCK
outbound, so we never see the HB-peer getblocktxn fan-in. The
moment BUG-4 is fixed, BUG-19 becomes a measurable latency issue.

**File:** `src/beamchain_sync.erl:299`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4254-4264`.

**Impact:** latency under HB-fan-in load; carry-forward W126.

---

## BUG-20 (P0) — `getblocktxn` out-of-bounds index silently filtered (W126-BUG-9 carry-forward)

**Severity:** P0. Core at `net_processing.cpp:2602-2614` (inside
`SendBlockTransactions`):

```cpp
for (size_t i = 0; i < req.indexes.size(); i++) {
    if (req.indexes[i] >= block.vtx.size()) {
        Misbehaving(peer, 100, "getblocktxn with out-of-bounds tx indices");
        return;
    }
    resp.txn[i] = block.vtx[req.indexes[i]];
}
```

— out-of-bounds index ≥ block.vtx.size() triggers `Misbehaving(100)`
(instant ban) AND returns without sending a response.

beamchain `sync.erl:310-319`:

```erlang
RequestedTxs = lists:filtermap(
    fun(Idx) ->
        ArrIdx = Idx + 1,
        if ArrIdx >= 1, ArrIdx =< tuple_size(TxArray) ->
            {true, element(ArrIdx, TxArray)};
           true ->
            false
        end
    end, Indexes),
```

— `lists:filtermap` SILENTLY drops out-of-range indices. The peer
gets a partial `blocktxn` response with no error; their reconstruction
fails with tx-count mismatch and they fall back to full block. No
misbehavior score, no peer ban for malformed requests.

**Concrete attack**: a peer can probe block structure by sending
getblocktxn with indexes `[0, 999_999_999]` and observing the
response length. If response has 1 tx, they know the block has 1
tx slot but not 999_999_999. Repeated probes leak block structure
without any DoS cost to the attacker.

**File:** `src/beamchain_sync.erl:310-319`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:2602-2614`.

**Impact:** DoS probe primitive; carry-forward W126.

---

## BUG-21 (P0) — `blocktxn` handler drops messages post-IBD (status =/= syncing)

**Severity:** P0. Bitcoin Core's BLOCKTXN handler at
`net_processing.cpp:4710-4736` ignores only `LoadingBlocks()`. Once
the chainstate is stable (post-IBD, no reindex), every blocktxn is
processed.

beamchain `block_sync.erl:415-420`:

```erlang
%% BIP152 blocktxn response
handle_cast({blocktxn, Peer, BlockTxn}, #state{status = syncing} = State) ->
    State2 = handle_blocktxn_received(Peer, BlockTxn, State),
    {noreply, State2};
handle_cast({blocktxn, _Peer, _BlockTxn}, State) ->
    {noreply, State};
```

— accepts blocktxn ONLY when `status =:= syncing`. **Post-IBD
(`status = complete`) every blocktxn is silently dropped.**

Today this is partially masked by another bug: `do_handle_unsolicited_cmpctblock`
drops partial reconstructions WITHOUT sending getblocktxn (`block_sync.erl:1332-1337`,
comment at `:1316-1320` admits deferral), so the unsolicited path
never depends on a blocktxn response.

But the gap exposes a real bug **if a cmpctblock arrives via the
solicited path** (i.e. hash is in `hash_to_height` because we
requested it as part of IBD or watchdog `blast_request`), AND
`status` flips to `complete` between the cmpctblock arrival and
the blocktxn response. The solicited cmpctblock calls
`send_getblocktxn` and adds an entry to `pending_compact`; the peer
sends back blocktxn but it's silently dropped because `status`
moved to `complete` in the interim. `pending_compact` entry stays
forever (cross-cite BUG-11).

The handler logic is **inverted relative to Core**: Core ignores
during loading/reindex; beamchain ignores AFTER IBD. The asymmetry
is a likely transcription error from the cmpctblock path — note that
`handle_cast({cmpctblock, ...})` at `:411-413` correctly accepts
regardless of status, per the comment at `:405-410`.

**File:** `src/beamchain_block_sync.erl:415-420`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4710-4736`.

**Impact:** blocktxn loss + pending_compact entry leak in the
IBD-to-complete transition window; cross-cite BUG-11.

---

## BUG-22 (P0-CDIV) — `getdata(MSG_CMPCT_BLOCK = 4)` returns `notfound`

**Severity:** P0-CDIV. Per BIP-152 §"Protocol Flow", a node that
announced a block via `inv(MSG_BLOCK)` may receive a peer's
`getdata(MSG_CMPCT_BLOCK)` requesting that block as a cmpctblock.
Core handles this in the GETDATA path
(`net_processing.cpp::ProcessGetBlockData`): if the type bit
`MSG_CMPCT_BLOCK = 4` is set AND the requested block is within
`MAX_CMPCTBLOCK_DEPTH = 5` of tip, respond with `cmpctblock`;
otherwise respond with `block`.

beamchain `peer_manager.erl:1733-1801` `handle_getdata_msg`:

```erlang
NotFound = lists:filtermap(fun(#{type := Type, hash := Hash}) ->
    case Type of
        T when T =:= ?MSG_BLOCK; T =:= ?MSG_WITNESS_BLOCK ->
            ... serve block ...;
        T when T =:= ?MSG_TX; T =:= ?MSG_WITNESS_TX ->
            ... serve tx ...;
        _ ->
            {true, #{type => Type, hash => Hash}}   %% ← MSG_CMPCT_BLOCK falls here
    end
end, Items),
```

— `MSG_CMPCT_BLOCK = 4` is neither MSG_BLOCK (=2) nor MSG_WITNESS_BLOCK
(=0x40000002), so it falls through to the catchall `_` clause and is
returned as `notfound`. The peer is forced to re-send `getdata(MSG_BLOCK)`
incurring a full extra round-trip.

This is the **W152 inv-type-filter pattern echo** ("inv-type-filter-rejects-MSG_TX/WTX/CMPCT"
universal pattern, NEW fleet finding from W152 this cycle). The
W152 finding was for INBOUND inv filtering; this is the symmetric
finding on the OUTBOUND getdata response path.

**File:** `src/beamchain_peer_manager.erl:1750-1792`.

**Core ref:** `bitcoin-core/src/net_processing.cpp::ProcessGetBlockData`.

**Impact:** every BIP-152-aware peer that requests our blocks via
MSG_CMPCT_BLOCK gets `notfound`, must retry as MSG_BLOCK → wasted
RTT; peers that have implemented Core's behavior may interpret
`notfound(MSG_CMPCT_BLOCK)` as "this node doesn't have this block at
all" and stop asking us. Cross-impl divergence.

---

## BUG-23 (P1) — `inv(MSG_CMPCT_BLOCK)` from peers silently dropped

**Severity:** P1. beamchain `sync.erl:213-257` `route_message(inv, ...)`:

```erlang
BlockItems = lists:filter(fun(#{type := Type, hash := Hash}) ->
    (Type =:= ?MSG_BLOCK orelse Type =:= ?MSG_WITNESS_BLOCK)
        andalso not beamchain_db:has_block(Hash);
    (_) -> false
end, Items),
```

`MSG_CMPCT_BLOCK = 4` is neither MSG_BLOCK nor MSG_WITNESS_BLOCK,
so peers who advertise tips via `inv(MSG_CMPCT_BLOCK)` get dropped.

In practice Core peers don't typically `inv` cmpctblocks (the BIP-152
HB path is direct CMPCTBLOCK push, not inv); cmpctblock-via-inv is
mainly a non-HB-mode informational announce. So the gap is minor.

Cross-cite BUG-22 (the symmetric outbound finding); together they
form the **inv-type-filter pattern, full duplex**.

**File:** `src/beamchain_sync.erl:213-257`.

**Core ref:** `bitcoin-core/src/net_processing.cpp::ProcessGetData`
(MSG_CMPCT_BLOCK handling in the receive path).

**Impact:** minor tip-discovery latency for peers using cmpctblock-via-inv
(rare).

---

## BUG-24 (P1) — Encoder uses non-witness format for cmpctblock prefilled / blocktxn txns when no witness present

**Severity:** P1 (interop). Core at `blockencodings.h:67-71`:

```cpp
SERIALIZE_METHODS(BlockTransactions, obj) {
    READWRITE(obj.blockhash, TX_WITH_WITNESS(Using<VectorFormatter<TransactionCompression>>(obj.txn)));
}
```

— `TX_WITH_WITNESS` ALWAYS uses witness serialization (with the
marker/flag bytes and an empty-witness `0x00` count for inputs lacking
witness data), regardless of whether any input has actual witness
content. Same at `blockencodings.h:80` for `PrefilledTransaction`.

beamchain `p2p_msg.erl:283-287` (blocktxn encode):

```erlang
encode_payload(blocktxn, #{block_hash := Hash, transactions := Txs}) ->
    Count = beamchain_serialize:encode_varint(length(Txs)),
    TxsBin = << <<(beamchain_serialize:encode_transaction(T))/binary>>
                || T <- Txs >>,
    <<Hash:32/binary, Count/binary, TxsBin/binary>>;
```

And `serialize.erl:276-281`:

```erlang
encode_transaction(Tx) ->
    case has_witness(Tx) of
        true  -> encode_transaction(Tx, witness);
        false -> encode_transaction(Tx, no_witness)
    end.
```

— uses non-witness format when NO input has witness data. For a
pure-legacy P2PKH transaction (common pre-segwit), beamchain
emits the 4-byte version + N inputs + N outputs + locktime form;
Core emits version + 0x00 marker + 0x01 flag + inputs + outputs +
empty witness counts + locktime.

The wire bytes differ. A peer decoding our blocktxn would either:
- Successfully decode our non-witness form (because Bitcoin tx
  parsing handles both with/without segwit) and reconstruct the
  block normally — OK; OR
- Strictly enforce TX_WITH_WITNESS for cmpctblock prefilled/blocktxn
  (per Core's `READWRITE` declaration) and reject.

Today this is dormant because we don't EMIT cmpctblock (BUG-4). The
blocktxn path emits only when a peer sent us getblocktxn (rare in
production because we're a permanent IBD-helper) and the txns are
served as-is from disk. For pre-segwit txs in blocktxn responses,
peers may or may not accept.

**File:** `src/beamchain_p2p_msg.erl:283-287, 700-703`;
`src/beamchain_serialize.erl:276-281`.

**Core ref:** `bitcoin-core/src/blockencodings.h:67-71, 80`.

**Impact:** wire-format parity gap; pre-segwit txn round-trips may
fail with strict-Core peers.

---

## BUG-25 (P2) — `match_mempool_txns` recomputes wtxid per-tx instead of using cached `Entry.wtxid`

**Severity:** P2 (perf). `compact_block.erl:282-311`:

```erlang
match_mempool_txns(ShortIdMap, K0, K1, TxnAvailable) ->
    Txids = beamchain_mempool:get_all_txids(),
    lists:foldl(
        fun(Txid, {Arr, Count}) ->
            case beamchain_mempool:get_tx(Txid) of
                {ok, Tx} ->
                    Wtxid = beamchain_serialize:wtx_hash(Tx),    %% ← recompute per call
                    ShortId = compute_short_id(K0, K1, Wtxid),
                    ...
```

— for each mempool tx: ETS lookup → extract Tx → witness-encode
(serialize.erl:284 onwards) → SHA-256 twice → SipHash. The wtxid is
already stored in `mempool_entry{wtxid}` (`mempool.erl:255-258`)
but `get_tx/1` only returns the bare `Tx`, dropping the cached wtxid.

For a 50k-entry mempool and a single cmpctblock arrival, this costs
50k × (witness-encode + 2×SHA256 + SipHash) ≈ 50k × ~5 µs = ~250 ms
per cmpctblock CPU. Bitcoin Core's equivalent uses the cached wtxid
in `pool->txns_randomized` (`blockencodings.cpp:121`).

Cross-cite BUG-7: combined with the missing pre-validation gates,
a peer can amplify ~250 ms of CPU per unauthenticated cmpctblock
message → mempool-walk DoS amplifier.

**File:** `src/beamchain_compact_block.erl:282-311`;
`src/beamchain_mempool.erl:239-243, 254-259`.

**Core ref:** `bitcoin-core/src/blockencodings.cpp:120-145`.

**Impact:** mempool-scaling perf gap; DoS amplifier per BUG-7.

---

## BUG-26 (P1) — Two parallel `MAX_BLOCKTXN_DEPTH` definitions: `sync.erl:36` and `block_sync.erl:82`

**Severity:** P1 (two-pipeline-guard pattern, 19th distinct fleet
instance). Both modules define `?MAX_BLOCKTXN_DEPTH = 10` independently:

```erlang
%% sync.erl:33-36
%% BIP152 getblocktxn depth limit (Core net_processing.cpp:140/4276).
-define(MAX_BLOCKTXN_DEPTH, 10).
```

```erlang
%% block_sync.erl:80-82
%% Parallel constant for getblocktxn: blocks deeper than MAX_BLOCKTXN_DEPTH
%% below the tip are served as full blocks to bound expensive disk reads.
-define(MAX_BLOCKTXN_DEPTH, 10).
```

The constant is consumed in only one place (sync.erl:297 — the
getblocktxn handler), so the block_sync.erl definition is dead. But
the dual declaration is the classic two-pipeline-guard shape: a
future tuning change to `MAX_BLOCKTXN_DEPTH` in one file (say bumping
to 12 for testing) silently misses the other; if a consumer is later
added in block_sync.erl, the two values can diverge.

Per W126 audit's "module-local constant duplication" finding pattern
shows up across the fleet; this is the 19th distinct beamchain instance.

**File:** `src/beamchain_sync.erl:36`; `src/beamchain_block_sync.erl:82`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:140` (single
`static const int MAX_BLOCKTXN_DEPTH = 10`).

**Impact:** drift risk; cleanup candidate.

---

## Summary

**Bug count:** 26 (BUG-1 through BUG-26).

**Severity distribution:**
- **P0-CDIV:** 5 (BUG-1, BUG-3, BUG-4, BUG-17, BUG-22)
- **P0:** 11 (BUG-6, BUG-7, BUG-8, BUG-9, BUG-10, BUG-12, BUG-14, BUG-15, BUG-18, BUG-20, BUG-21)
- **P1:** 9 (BUG-2, BUG-5, BUG-11, BUG-13, BUG-16, BUG-19, BUG-23, BUG-24, BUG-26)
- **P2:** 1 (BUG-25)

Total: 5 + 11 + 9 + 1 = 26. ✓

**W126 carry-forward (7+ weeks open):**
- BUG-1 ← W126-BUG-1 (sendcmpct version != 2 acceptance)
- BUG-2 ← W126-BUG-17 (v1 outbound dead bandwidth)
- BUG-3 ← W126-BUG-3 (wants_cmpct state isolation)
- BUG-4 ← W126-BUG-2 (no outbound cmpctblock branch)
- BUG-10 ← W126-BUG-8 (no CanDirectFetch gate)
- BUG-11 ← W126-BUG-14 + W126-BUG-16 (no in-flight cap, no pending_compact sweep)
- BUG-12 ← W126-BUG-5 (no via_compact_block punishment distinction)
- BUG-14 ← W126-BUG-4 deferred (prefilled-index per-i cap)
- BUG-16 ← W126-BUG-11 (bucket-size DoS check)
- BUG-17 ← W126-BUG-7 (IsBlockMutated)
- BUG-19 ← W126-BUG-10 (no recent-block cache)
- BUG-20 ← W126-BUG-9 (silent OOB index filter)

12 of the 26 bugs (46%) are W126 carry-forwards — beamchain has not
shipped a BIP-152 FIX wave since W126's discovery audit.

**Fleet patterns confirmed:**
- **dead-helper-at-call-site** (BUG-4, 13th instance) — `encode_payload(cmpctblock, ...)` exists but no caller; `wants_cmpct` set but unread.
- **dead-data plumbing** (BUG-3, 13th distinct beamchain instance) — `wants_cmpct` set on `peer_data{}` never propagated to ETS where consumers can see it.
- **inv-type-filter-rejects-CMPCT** (BUG-22 + BUG-23, **NEW echo from W152** in full duplex) — getdata MSG_CMPCT_BLOCK=4 returns notfound (outbound); inv MSG_CMPCT_BLOCK=4 silently dropped (inbound).
- **comment-as-confession** (BUG-2 line 1642-1645 v1 advert; BUG-14 line 100-103 deferred per-i cap; 13th distinct beamchain instance) — 14th and 15th.
- **two-pipeline-guard** (BUG-26, 19th distinct fleet extension) — `MAX_BLOCKTXN_DEPTH` defined in two modules.
- **wiring-look-but-no-wire** (BUG-4) — outbound sendcmpct sent, wants_cmpct stored, peer_manager dispatch wired, encode_payload exists — the ONE missing piece is the announce_block branch.
- **status-gate inverted from Core** (BUG-21) — blocktxn dropped post-IBD instead of dropped-during-loading.
- **CVE-2012-2459 missing fleet pattern** (BUG-17, 7th distinct beamchain instance per W143-W156 tracking) — `verify_merkle_root` uses the same vulnerable `compute_merkle_root` helper.
- **assume-valid-style scope creep absence** (BUG-12) — beamchain's misbehavior punishment is broader than Core's because the `via_compact_block` distinction is missing.

**Top three findings:**

1. **BUG-4 (P0-CDIV) — `encode_payload(cmpctblock, ...)` is dead-helper, 7+ weeks**. The most visible symptom of beamchain's asymmetric BIP-152 role: every peer is told we want to be HB-from (`sendcmpct(announce=true, v=2)` after handshake), every peer dutifully tracks us as HB-from-candidate, and yet we never push a single CMPCTBLOCK outbound for our entire process lifetime. Tip-propagation latency is therefore Core+1-2 blocks; downstream peers who would have received via CMPCTBLOCK fall back to inv→getheaders→headers→getdata→block (slow path). Compounded by BUG-3 (no ETS surface) and BUG-1 (no version validation), the wedge will get worse the moment BUG-4 is fixed without the other two.

2. **BUG-17 (P0-CDIV) — `verify_merkle_root` is not `IsBlockMutated`, 7+ weeks**. After full block reconstruction, beamchain checks only merkle-root equality using the CVE-2012-2459-vulnerable `compute_merkle_root` (duplicates odd elements, no mutation flag). Three mutation classes go unchecked: (a) CVE-2012-2459 duplicate-pair attack, (b) 64-byte non-coinbase tx mutation primitive (CVE-2017-12842 class), (c) witness merkle malleation. Combined with BUG-15 (no coinbase-at-prefilled[0] check), a peer can in principle corrupt a block via cmpctblock and have beamchain admit it pre-validation while Core rejects. W126-BUG-7 echo, W143-W156 fleet pattern, 6+ impls confirm.

3. **BUG-15 (P0) — Coinbase-at-prefilled[0]-abs-idx-0 invariant unenforced**. BIP-152 mandates the first prefilled tx be the coinbase at absolute index 0. beamchain's `init_compact_block` accepts cmpctblock with empty `Prefilled` OR with `Prefilled[0]` at any abs_idx. Reconstruction proceeds; the slot at abs_idx=0 (coinbase) can't be filled from mempool (coinbases aren't in mempool), so we always round-trip getblocktxn for it. Peer gets a free DoS round-trip primitive. Merkle root would eventually reject, but only after wire+CPU expenditure.

**Architectural meta-finding**: beamchain implements ~60% of Core's
BIP-152 receive-side surface and ~0% of the send-side surface. The
audit reveals **THREE structural gaps** that compound:

- Pre-validation gates (BUG-6, BUG-7, BUG-8, BUG-9, BUG-10) — every
  cmpctblock arrival triggers full mempool walk before any header
  validation.
- Mutation defenses (BUG-15, BUG-17) — `IsBlockMutated` reduced to
  `verify_merkle_root`.
- Send side (BUG-3, BUG-4, BUG-5) — encode exists, transport exists,
  state exists, but the wire is uncrossed.

A FIX wave that addresses the send-side trio alone (BUG-3 + BUG-4 +
BUG-5, ~3-4 hours) would close the W126 "asymmetric role" finding
and probably cut tip-propagation latency by ~1 block average. The
mutation-defense trio (BUG-15 + BUG-17 + W143 fleet IsBlockMutated)
should be bundled with the W143 fleet-wide CVE-2012-2459 sweep.
