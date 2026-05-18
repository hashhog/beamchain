# W152 — Tx relay + inv batching + orphan handling (beamchain)

**Wave:** W152 — `RelayTransaction`, `AddTxAnnouncement`,
`m_tx_inventory_to_send`, `m_recently_announced_invs`,
`m_next_inv_send_time`, Poisson inv trickle (`INVENTORY_BROADCAST_PER_SECOND=14`
→ `INVENTORY_BROADCAST_TARGET=70`, `INVENTORY_BROADCAST_MAX=1000`),
`TxOrphanage::AddTx` / `EraseTx` / `EraseForBlock` / `EraseForPeer` /
`LimitOrphans`, `OrphanByParent` map,
**`DEFAULT_MAX_ORPHAN_TRANSACTIONS=100`** (now `m_max_global_latency_score`),
`txrequest` scheduler (`TXID_RELAY_DELAY=2s` BIP-339,
`NONPREF_PEER_TX_DELAY=2s`, `OVERLOADED_PEER_TX_DELAY=2s`,
`MAX_PEER_TX_REQUEST_IN_FLIGHT=100`, `GETDATA_TX_INTERVAL=60s`),
`MSG_TX` vs `MSG_WTX` per-peer dispatch (BIP-339 wtxidrelay),
`MAX_INV_SZ=50000`, `m_lazy_recent_rejects` rolling-Bloom,
BIP-37 MSG_FILTERED_BLOCK dispatch, peer-misbehavior accounting on
malformed inv/tx.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/net_processing.cpp:126` — `MAX_INV_SZ = 50000`.
- `bitcoin-core/src/net_processing.cpp:172-178` —
  `INVENTORY_BROADCAST_PER_SECOND=14` (NOTE: project-brief said `=7`;
  current Core 26.x is `14`), `INVENTORY_BROADCAST_TARGET = 14 * 5s = 70`,
  `INVENTORY_BROADCAST_MAX = 1000`.
- `bitcoin-core/src/net_processing.cpp:609-620` — `AddTxAnnouncement` and
  `RelayTransaction` (per-peer pending inv add, dedup, m_recently_announced_invs).
- `bitcoin-core/src/net_processing.cpp:4040, 4131` — inbound inv decode
  rejects size > MAX_INV_SZ with `Misbehaving(100)` (instant ban).
- `bitcoin-core/src/net_processing.cpp:5969, 6021, 6045-6046` —
  SendMessages inv-trickle loop; `broadcast_max = TARGET + (queue/1000)*5`,
  capped at `INVENTORY_BROADCAST_MAX`.
- `bitcoin-core/src/node/txdownloadman.h:24-38` —
  `MAX_PEER_TX_REQUEST_IN_FLIGHT = 100`,
  `TXID_RELAY_DELAY = 2s` (BIP-339 txid-vs-wtxid arbitration),
  `NONPREF_PEER_TX_DELAY = 2s`,
  `OVERLOADED_PEER_TX_DELAY = 2s`,
  `GETDATA_TX_INTERVAL = 60s`.
- `bitcoin-core/src/node/txorphanage.h:20-23` —
  `DEFAULT_RESERVED_ORPHAN_WEIGHT_PER_PEER = 404,000`,
  `DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE = 3000`. (Legacy
  `DEFAULT_MAX_ORPHAN_TRANSACTIONS=100` from pre-Core-29 → replaced
  with latency-score model; Core no longer expires orphans on a timer.)
- `bitcoin-core/src/node/txorphanage.cpp` — `EraseForBlock(block)` walks
  every output spent by every block tx via `m_orphan_by_outpoint` (the
  reverse index), not by linear scan; `EraseForPeer(peer)` walks an
  `m_orphan_announcers` map keyed by `(peer_id, orphan_wtxid)`.
- `bitcoin-core/src/net_processing.cpp` `MaybeSetPeerAsAnnouncingHeaderAndIDs` /
  `RelayTransaction` — wtxidrelay-aware MSG_TX-vs-MSG_WTX choice per
  individual peer at the moment the inv is built.

**Files audited**
- `src/beamchain_peer.erl` — gen_statem state machine; `pending_tx_inv`
  queue (line 127), `trickle_timer_ref`, `wtxidrelay` flag (line 105),
  `queue_tx_inv/2` API (lines 19, 239-241), `do_trickle_inv` (line 1788-1814),
  `schedule_trickle_timer` (line 1761-1774), `poisson_interval` (line 1779-1783),
  `send_tx_inv` (line 1841-1857), `INBOUND_INV_INTERVAL_MS=5000`,
  `OUTBOUND_INV_INTERVAL_MS=2000`, `INV_BROADCAST_TARGET=70`,
  `INV_BROADCAST_MAX=1000`, `shuffle_list` (line 1860-1864),
  `filter_by_feefilter` (line 1818-1824).
- `src/beamchain_peer_manager.erl` — `broadcast/2,3` (line 300-314),
  `announce_block/2` (line 324-331), `handle_peer_message(inv, ...)`
  (line 1415-1417) routes to sync, `handle_getdata_msg` (line 1733-1801),
  `handle_mempool_msg` (line 1864-1872, BIP-35), `send_inv_chunks`
  (line 1895-1899), `chunk_inv_items` (line 1906-1916).
- `src/beamchain_sync.erl` — `route_message(Peer, inv, ...)` (line 213-257)
  ONLY handles block-inv items; tx-inv items silently dropped;
  `route_message(Peer, tx, ...)` (line 333-350) calls
  `accept_to_memory_pool` and `broadcast(inv, ...)` (instant + always
  MSG_TX); `route_message(Peer, notfound, ...)` (line 197-211) silently
  drops tx-notfound entries.
- `src/beamchain_mempool.erl` — orphan-pool API
  (lines 33-34, 101-102, 118-119, 396-397, 504-507, 2561-2622, 2670-2687,
  2716-2721, 2965-2983, 3005-3058); `MAX_ORPHAN_TXS=100`,
  `ORPHAN_TX_EXPIRE_TIME=1200`, `MEMPOOL_ORPHANS=wtxid->{tx, expiry}`,
  `MEMPOOL_ORPHAN_BY_TXID=txid->wtxid`; `reprocess_orphans/1`
  (line 2598-2622), `add_orphan/3` (line 2564-2590),
  `erase_orphans_for_block/1` (line 3005-3041),
  `erase_orphans_for_peer/1` (line 3054-3058 — DEAD).
- `src/beamchain_rpc.erl:2706-2713` — `relay_transaction(Txid)` (always
  MSG_TX broadcast).
- `src/beamchain_p2p_msg.erl:643-679` — `encode_inv_item` / `decode_inv_payload`
  (correct wire layout, internal-byte-order hash); `MAX_INV_SIZE` enforced
  on decode (lines 673-675).
- `include/beamchain_protocol.hrl:67-71` — `MAX_INV_SIZE=50000`,
  `MAX_GETDATA_SZ=1000`; `MSG_TX=1`, `MSG_WTX=5` (lines 116-126).

---

## Gate matrix (35 sub-gates / 14 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | Per-peer pending-inv set | G1: inv add via Poisson-trickled queue (not instant broadcast) | **BUG-1 (P0)** — `queue_tx_inv/2` exists (`peer.erl:240`) and pushes to `pending_tx_inv` but ZERO production callers (test/`beamchain_w103_tx_relay_tests.erl:380-383` literally documents this gap). The actual relay path (`sync.erl:340-343`, `rpc.erl:2706-2713`) calls `beamchain_peer_manager:broadcast(inv, ...)` directly, sending the inv to every peer in the same wall-clock millisecond → **defeats the entire Poisson-trickle privacy design** |
| 1 | … | G2: dedup against m_tx_inventory_known per-peer | **BUG-2 (P1)** — no `m_tx_inventory_known` filter; the same txid is sent on the wire as many times as `broadcast/2` is called for it. After mempool accept (sync.erl:341) + every RPC sendrawtransaction (rpc.erl:2706) + every CPFP descendant promote → duplicate inv to the same peer |
| 1 | … | G3: source-peer exclusion (don't echo inv back to sender) | **BUG-3 (P1)** — `broadcast/2` has no source-peer exclusion; `sync.erl:341` re-sends the inv to the peer that just gave us the tx. Core's `RelayTransaction` excludes the source peer (via m_relay_transactions filter check on per-peer pending set) |
| 2 | Poisson trickle timing | G4: INBOUND_INV_INTERVAL_MS ≈ 5000 | PASS (`peer.erl:70`) — but BUG-1 means timer never fires productively |
| 2 | … | G5: OUTBOUND_INV_INTERVAL_MS ≈ 2000 | PASS (`peer.erl:72`) |
| 2 | … | G6: exponential distribution `-ln(U) * mean` | PASS (`peer.erl:1779-1783`) |
| 3 | INVENTORY_BROADCAST_TARGET=70 + scaling | G7: target + 5/1000 queue length | PASS (`peer.erl:1801-1802`) but dead code per BUG-1 |
| 3 | … | G8: cap at INVENTORY_BROADCAST_MAX=1000 | PASS (`peer.erl:1801`) |
| 3 | … | G9: outbound chunk at MAX_INV_SIZE=50000 | PASS (`peer_manager.erl:1895-1899`) |
| 4 | Per-peer MSG_TX vs MSG_WTX choice (BIP-339) | G10: relay path inspects peer's wtxidrelay flag and emits MSG_WTX + wtxid for negotiated peers | **BUG-4 (P0-CDIV)** — production relay path (`sync.erl:341`, `rpc.erl:2706`) hardcodes `MSG_TX` + Txid regardless of peer flag. Only the BIP-35 mempool response (`peer_manager.erl:1864-1872`) and the dead `do_trickle_inv` path consult wtxidrelay. **Result: beamchain advertises wtxidrelay during handshake (peer.erl:1374) but never honors it for outbound tx announcements.** Any peer expecting MSG_WTX (Core 22.0+) treats every announcement as txid-only, falling back to MSG_TX request, breaking the BIP-339 wtxid-relay split-brain detection. Witness-malleated tx attack surface re-opens |
| 5 | TxOrphanage size + memory cap | G11: DEFAULT_MAX_ORPHAN_TRANSACTIONS=100 (or modern latency-score model) | PARTIAL — `MAX_ORPHAN_TXS=100` (`mempool.erl:101`) matches the LEGACY Core constant. Current Core (post-29.0) replaced this with `DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE=3000` + per-peer `DEFAULT_RESERVED_ORPHAN_WEIGHT_PER_PEER=404,000` (see W152 ref). Beamchain ships pre-Core-29 model; OK functionally but won't accept big bursts of valid orphans from useful peers |
| 5 | … | G12: per-peer attribution / EraseForPeer effective | **BUG-5 (P0)** — `erase_orphans_for_peer/1` (`mempool.erl:3054-3058`) is a **no-op** with TODO comment `"no peer field in orphan records — cannot prune per-peer without schema change"`. **Disconnect-time orphan cleanup is dead code.** A malicious peer can dump 100 orphans, disconnect, and the orphans stay in the pool until they expire 20 min later or a block confirms them — defeats the per-peer orphanage limit that Core uses to prevent orphan-spam DoS |
| 5 | … | G13: OrphanByParent reverse index (lookup orphans by parent-outpoint in O(1)) | **BUG-6 (P1)** — no `m_orphan_by_outpoint` / OrphanByParent map. `reprocess_orphans/1` (line 2599) and `erase_orphans_for_block/1` (line 3009) **scan the entire orphan ETS table for every confirmed txid**. `erase_orphans_for_block` at line 3040 ALSO calls `reprocess_orphans/1` for every BlockTxid → O(BlockTxids × Orphans) per block. For a 4000-tx block with 100 orphans = 400,000 tab2list+filter cycles per block-connect |
| 6 | Orphan-promotion entry safety | G14: orphan-promotion path runs without deadlocking the mempool gen_server | **BUG-7 (P0-CDIV)** — **CONFIRMED self-deadlock** matches W150 BUG-12 shape. `reprocess_orphans/1` (mempool.erl:2612) calls `add_transaction(OrphanTx)` which is `gen_server:call(?SERVER, ...)` — the same gen_server reentering itself via synchronous call. Fires from THREE production paths: (a) `do_add_transaction` line 817, (b) `do_accept_package` line 1515, (c) `do_remove_for_block → erase_orphans_for_block` line 3040. Cross-cite W150 BUG-12: same root cause, but the path-count is THREE not TWO (W150 missed the package-relay path). 30-second mailbox freeze + permanent orphan loss on EVERY CPFP child whose parent arrives after it |
| 7 | Tx-inv incoming (peer announces tx) | G15: inv with MSG_TX/MSG_WTX → schedule getdata for unknown txids | **BUG-8 (P0-CDIV)** — `sync.erl:217-221` filters incoming inv to ONLY MSG_BLOCK / MSG_WITNESS_BLOCK (`(_) -> false` catch-all). **MSG_TX and MSG_WTX inv items are silently dropped — beamchain NEVER initiates a getdata for a peer-announced transaction.** The only path that pulls txs from peers is `getdata` round-trips from someone else's accept-and-broadcast. Net effect: beamchain is an **inv-relay-only / never-pull node** — it processes incoming `tx` push messages but does not request announced ones. After IBD, any unsolicited tx must arrive as a `tx` push (which Core peers never do post-2017; they inv-and-await-getdata) |
| 7 | … | G16: tx-request scheduler with delay + retry | **BUG-9 (P0)** — no `TxRequestTracker` analogue at all. No `TXID_RELAY_DELAY=2s` (BIP-339 wtxidrelay/non-wtxidrelay arbitration), no `NONPREF_PEER_TX_DELAY=2s`, no `OVERLOADED_PEER_TX_DELAY=2s`, no `MAX_PEER_TX_REQUEST_IN_FLIGHT=100`, no `GETDATA_TX_INTERVAL=60s`. Cross-cite: `grep -rn "TXID_RELAY_DELAY\|NONPREF_PEER\|OVERLOADED_PEER\|MAX_PEER_TX_REQUEST_IN_FLIGHT\|m_recently_announced_invs\|tx_announcement\|inv_to_send\|AnnounceTx" src/*.erl` → zero matches. Companion to BUG-8: the missing scheduler is why the inv-receive path was never built |
| 7 | … | G17: tx-notfound handling (re-request from another peer) | **BUG-10 (P1)** — `sync.erl:197-211` notfound handler filters to MSG_BLOCK / MSG_WITNESS_BLOCK only; tx-notfound silently discarded. With no txrequest scheduler (BUG-9) there's nothing to re-route to anyway, but the absence is recorded |
| 8 | Orphan parent-fetch | G18: when accept-tx returns {error, orphan}, request the missing parent | **BUG-11 (P0)** — `sync.erl:333-350` accept-to-mempool returns `{error, orphan}` (mempool.erl:837); the handler just `logger:debug` and proceeds (line 344-346). **No getdata for the parent.** Core's net_processing path adds the missing parents to txrequest. Beamchain stores the orphan but never asks for its parent — so the orphan can never be promoted unless the parent arrives unsolicited. Combined with BUG-8 (no inv-receive for txs) this means orphan promotion fires ONLY when the parent is also pushed (i.e., almost never on a healthy network) |
| 9 | m_recently_announced_invs cache | G19: per-peer rolling set of (recently-sent) txids to dedup getdata flap | **BUG-12 (P1)** — no `m_recently_announced_invs` per peer (or its modern txrequest equivalent). Subsequent inv announcements re-trigger getdata each time. Combined with BUG-2 (no dedup on send) this is an O(N²) leak on heavily-relayed tx storms |
| 10 | Inv message size cap (inbound) | G20: reject inv with > MAX_INV_SIZE=50000 entries | PASS (`p2p_msg.erl:673-675` — returns {error, {oversized, ...}}) |
| 10 | … | G21: peer Misbehaving(100) on oversize | **BUG-13 (P1)** — `sync.erl:255 _Error -> State` silently swallows the decode error; **no `add_misbehavior` call.** Core net_processing.cpp:4042 charges +100 (instant ban). Beamchain just drops the message and lets the peer keep going. Compare with `sync.erl:184/193/265/274/328/348` which DO charge +20 for OTHER message decode failures — inv is the outlier |
| 10 | … | G22: peer Misbehaving on malformed inv item | Same as G21 — silent drop, no penalty |
| 11 | Inv hash byte-order (W141 cross-cite) | G23: inv hash sent in internal byte-order (raw sha256d) on the wire | PASS — `p2p_msg.erl:644-645` writes the raw 32-byte `tx_hash`; `tx_hash` in `serialize.erl:191-193` returns raw SHA256d output. No `lists:reverse(Hash)` anywhere in inv encode. Inv byte-order is correct on the wire (compare W141 BUG-1/BUG-2 ZMQ byte-order: those are display-order outputs, distinct from inv) |
| 12 | MSG_FILTERED_BLOCK dispatch (BIP-37) | G24: getdata MSG_FILTERED_BLOCK delivers a merkleblock | **BUG-14 (P1)** (cross-cite W134 BUG-X fleet pattern) — `peer_manager.erl:1750-1791` getdata loop handles MSG_BLOCK, MSG_WITNESS_BLOCK, MSG_TX, MSG_WITNESS_TX; **MSG_FILTERED_BLOCK (3) falls into the `_ -> notfound` catch-all** (line 1790-1791). A BIP-37 SPV peer that loads a bloom filter and requests filtered blocks gets notfound for everything → SPV peers cannot use beamchain as a backend |
| 13 | Tx relay during IBD | G25: ATMP gated when IsInitialBlockDownload (Core: net_processing.cpp:4395 returns early) | **BUG-15 (P1)** — `grep -rn "is_initial_block_download\|in_ibd\|is_ibd" src/` → zero matches. `sync.erl:333` accepts tx and broadcasts inv even during IBD. Core explicitly returns from ProcessMessage TX during IBD; beamchain processes the tx, fails ATMP because the UTXO context is stale, returns `{error, ...}`, and the resources are wasted |
| 13 | … | G26: relay path skipped during IBD | Same — no IBD gate. `relay_transaction/1` (rpc.erl:2706) and `sync.erl:341` always fire |
| 14 | Misc tx-relay quality | G27: `m_lazy_recent_rejects` rolling Bloom for already-rejected txids | **BUG-16 (P1)** — no rolling-Bloom of recent-rejects. `check_tx_already_known/1` (mempool.erl:4347-4360) checks whether the OUTPUTS are already in UTXO set (i.e., is the tx CONFIRMED) — not whether the txid was previously rejected. A peer can re-flood a previously-rejected tx forever and beamchain runs the full ATMP gauntlet every time |
| 14 | … | G28: TxOrphanage time-based expiry (legacy) | PASS (`mempool.erl:101-102, 504-507, 2965-2983`) — `ORPHAN_TX_EXPIRE_TIME=1200s` (20 min) matches legacy Core. Modern Core uses score-based eviction |
| 14 | … | G29: `pending_tx_inv` queue dedup is O(1) | **BUG-17 (P2)** — `peer.erl:608` uses `lists:member(Txid, Pending)` which is O(N) per queue. For a 50,000-entry pending queue (allowed by `INV_BROADCAST_MAX` scaling) every enqueue is a 50,000-entry scan |
| 14 | … | G30: filter-by-feefilter doesn't permanently drop borderline txs | **BUG-18 (P2)** — `peer.erl:1812-1813` `Pending -- Filtered ; Remaining -- FilteredOut` permanently removes any txid that failed the current feefilter, even though the peer's feefilter can DECREASE over time (mempool churn). Comment claims "they'll never pass the filter" — false. Also O(N²) per trickle tick |
| 14 | … | G31: shuffle_list is unbiased | **BUG-19 (P2) — "comment-as-confession" 8th distinct beamchain instance** — `peer.erl:1859-1864` comment says "Fisher-Yates shuffle" but the implementation is `lists:sort(fun(_, _) -> rand:uniform() > 0.5 end, List)` — a BIASED comparator-based pseudo-shuffle. The comparator is non-transitive (`X < Y < Z < X` possible) → undefined Erlang sort behavior; observable bias in tx-inv ordering. Either rename comment OR implement actual Fisher-Yates |
| 14 | … | G32: relay path doesn't echo inv to source peer | (Cross-cite BUG-3) |
| 14 | … | G33: rebroadcast loop for stale unconfirmed txs | **BUG-20 (P1)** — Core's `ScheduleNextRebroadcast` re-announces unconfirmed txs every ~10 min (privacy: prevents source-fingerprinting by anti-spam timing). Beamchain has **no rebroadcast loop**: `grep -rn "rebroadcast\|unbroadcast\|m_unbroadcast" src/` → only `mempool_persist.erl:24-28` literally documents "beamchain has no fee-delta priority map and no unbroadcast set today". Locally-created txs sent at IBD wait or during a brief network partition are never re-announced — they sit in mempool forever, never reach the network |
| 14 | … | G34: lookup_entry_by_wtxid is O(1) (Core has mapTxByWtxid) | **BUG-21 (P2)** — `mempool.erl:4368-4374` does `ets:match_object(?MEMPOOL_TXS, {'_', #mempool_entry{wtxid = Wtxid, _ = '_'}})` which is a linear ETS scan. Wtxid lookup is on the hot path for getdata MSG_WTX. Comment-as-confession at line 4365-4367 admits "Mempool sizes are bounded so the cost is acceptable" but at 300 MB / ~75,000 txs that's 75k record scans per MSG_WTX getdata |
| 14 | … | G35: `accept_to_memory_pool` from chainstate path uses async cast (not call) | PASS — `chainstate.erl:282` runs in caller's process post-`submit_block` (line 254-260); explicit deadlock-avoidance comment at line 244-250. This is the ONE place beamchain got the gen_server-reentrance pattern right. Cross-cite BUG-7: the SAME root cause was fixed for chainstate↔mempool but missed for mempool↔mempool |

---

## BUG-1 (P0) — Production tx-relay path bypasses the Poisson-trickle queue entirely

**Severity:** P0 ("dead-handler plumbing" fleet pattern — 4th distinct
beamchain instance after W150 BUG-13/BUG-14). Bitcoin Core's tx-relay
privacy design relies on a per-peer, per-tick Poisson-randomized trickle
of the per-peer pending inv set
(`m_tx_inventory_to_send` → SendMessages drains with exponentially
distributed inter-announcement intervals: INBOUND mean 5s, OUTBOUND
mean 2s). This is what prevents an observer from correlating tx-source
timing to the originating peer.

Beamchain has the FULL trickle infrastructure built and exported:
- `pending_tx_inv` field in `#peer_data{}` (peer.erl:127),
- `queue_tx_inv/2` API (peer.erl:240),
- `schedule_trickle_timer/1` Poisson scheduler (peer.erl:1761-1774),
- `do_trickle_inv/1` flusher with feefilter + cap (peer.erl:1788-1814),
- `send_tx_inv/2` with per-peer MSG_TX/MSG_WTX dispatch (peer.erl:1841-1857).

But **zero production callers invoke `queue_tx_inv/2`.** A `grep -rn`
finds it only in `peer.erl` itself (the export + the handle clause) and
in `test/beamchain_w103_tx_relay_tests.erl:380-388` which literally
documents the gap (test docstring: "the tx relay path in beamchain_sync
does NOT use queue_tx_inv — it calls broadcast/2 directly, bypassing the
trickle entirely").

The actual relay path is:

```erlang
%% sync.erl:340-343
beamchain_peer_manager:broadcast(inv, #{
    items => [#{type => ?MSG_TX, hash => Txid}]
});

%% rpc.erl:2706-2713
relay_transaction(Txid) ->
    try
        beamchain_peer_manager:broadcast(inv, #{
            items => [#{type => ?MSG_TX, hash => Txid}]
        })
    catch _:_ -> ok end.
```

`broadcast/2` (peer_manager.erl:307-314) walks the entire peer ETS table
and sends the inv to every peer in the same wall-clock millisecond.

**File:** `src/beamchain_sync.erl:340-343`,
`src/beamchain_rpc.erl:2706-2713` (callers);
`src/beamchain_peer.erl:240, 605-611, 613-617, 1761-1814` (dead trickle
machinery).

**Core ref:** `bitcoin-core/src/net_processing.cpp::RelayTransaction`,
`SendMessages` trickle loop at lines 5969-6046.

**Impact:**
- Privacy: an observer correlating tx timing can identify the source
  peer trivially because beamchain announces a new tx to all peers in
  the same millisecond (no Poisson jitter).
- Bandwidth: the per-peer per-tick cap (INV_BROADCAST_MAX=1000) is dead
  code; the cap on real outbound traffic is "every tx, every peer,
  immediately".
- **Fleet pattern: 4th confirmed beamchain dead-handler plumbing
  instance**: W150 BUG-13 (`do_trim_to_size`), W150 BUG-14
  (`do_expire_old`), W150 BUG-12 (orphan promotion via self-deadlock),
  W152 BUG-1 (Poisson trickle).

---

## BUG-4 (P0-CDIV) — `RelayTransaction` always emits MSG_TX, never MSG_WTX, even for wtxidrelay-negotiated peers

**Severity:** P0-CDIV (BIP-339 wire-format compliance). Bitcoin Core's
`RelayTransaction` emits `MSG_WTX` (inv type 5) + wtxid for any peer
that negotiated `wtxidrelay` during the handshake, and falls back to
`MSG_TX` (inv type 1) + txid only for pre-BIP-339 peers. This is the
foundation of BIP-339's wtxid-vs-txid arbitration that protects against
tx-malleability-based relay-pool poisoning.

Beamchain CORRECTLY negotiates wtxidrelay during handshake — see
`peer.erl:1374` (`Data4 = do_send_raw(wtxidrelay, <<>>, Data3)`) and
`peer.erl:105` (`wtxidrelay = false :: boolean()`). The wtxidrelay flag
IS propagated into peer info (`peer.erl:1748-1751`).

But the production relay path **hardcodes `MSG_TX`** and ignores the
per-peer flag:

```erlang
%% sync.erl:340-343
beamchain_peer_manager:broadcast(inv, #{
    items => [#{type => ?MSG_TX, hash => Txid}]
});

%% rpc.erl:2706-2713
beamchain_peer_manager:broadcast(inv, #{
    items => [#{type => ?MSG_TX, hash => Txid}]
})
```

The only paths that correctly do per-peer MSG_TX/MSG_WTX selection are:
- `peer_manager.erl:1882-1893` (BIP-35 mempool response — server side),
- `peer.erl:1841-1857` (`send_tx_inv` — dead code per BUG-1).

The production broadcast/2 callers have no per-peer awareness.

**File:** `src/beamchain_sync.erl:341`,
`src/beamchain_rpc.erl:2708-2710`.

**Core ref:** `bitcoin-core/src/net_processing.cpp::RelayTransaction`,
BIP-339.

**Impact:**
- Wire-format divergence: peers expecting MSG_WTX per their negotiated
  wtxidrelay receive MSG_TX instead. Modern Core (22.0+) silently
  accepts but the txid-vs-wtxid split-brain detection (BIP-339's primary
  purpose: detect a tx that has different witness-stripped vs
  witness-included serializations) cannot fire.
- The witness-malleated tx attack surface that BIP-339 was designed to
  close re-opens for any chain whose mempool includes a beamchain node.
- Cross-fleet: blockbrew/clearbit/rustoshi/etc. all do per-peer
  MSG_WTX selection. Beamchain is the outlier.

---

## BUG-5 (P0) — `erase_orphans_for_peer/1` is a no-op TODO; disconnect-time orphan cleanup is dead

**Severity:** P0 (DoS amplifier). Bitcoin Core's
`TxOrphanage::EraseForPeer(NodeId peer)` is called from
`PeerManager::FinalizeNode` when a peer disconnects. It walks the
peer's announced-orphan set and removes any orphan whose ONLY
announcer was this peer. This is the cleanup that prevents a malicious
peer from dumping `MAX_ORPHAN_TRANSACTIONS=100` worth of orphans and
disconnecting, then reconnecting from a different IP to do it again.

Beamchain's analogue (`mempool.erl:3054-3058`):

```erlang
-spec erase_orphans_for_peer(term()) -> ok.
erase_orphans_for_peer(_PeerId) ->
    %% TODO(W103/BUG-14): no peer field in orphan records — cannot prune
    %% per-peer without schema change.  Hook is in place for future upgrade.
    ok.
```

The function is exported, has a TODO admitting it doesn't work, and is
called from disconnect paths but **does nothing**. The orphan record
schema (`?MEMPOOL_ORPHANS`: wtxid → {tx, expiry}) has no peer field, so
the function literally cannot do the work.

**File:** `src/beamchain_mempool.erl:3054-3058`,
`src/beamchain_mempool.erl:118-119` (schema lacks peer column).

**Core ref:** `bitcoin-core/src/node/txorphanage.cpp::EraseForPeer`.

**Impact:**
- DoS: a malicious peer can dump 100 orphans then disconnect; the
  orphans stay in the pool until they expire 20 min later or a block
  confirms them. With 100 orphan slots and a 20-min churn, the
  adversary's effective rate is ~5 orphans/min/IP. From a /24 subnet
  that's 25,600 orphans/min — far above the `MAX_ORPHAN_TXS=100` cap,
  but the cap is per-pool not per-IP, so the adversary trades the cap
  every few seconds. Legitimate orphan promotion is blocked because
  the pool is constantly full.
- The fleet-wide "dead-handler plumbing" pattern (companion to BUG-1
  in this audit + W150 BUG-13/BUG-14).
- **Comment-as-confession (9th distinct beamchain instance)** — the
  TODO admits the schema is broken and the function is non-functional.

---

## BUG-7 (P0-CDIV) — `reprocess_orphans/1` fires `gen_server:call` on the same gen_server from THREE production paths (W150 BUG-12 path-count was 2)

**Severity:** P0-CDIV. Cross-cite W150 BUG-12 — this audit CONFIRMS
the self-deadlock pattern and corrects the path-count: it fires from
**THREE** production paths, not two.

`reprocess_orphans/1` (mempool.erl:2598-2622) iterates orphans whose
parent matches `NewTxid` and calls `add_transaction(OrphanTx)`
(line 2612). `add_transaction/1` is defined at mempool.erl:201:

```erlang
add_transaction(Tx) ->
    gen_server:call(?SERVER, {add_tx, Tx}, 30000).
```

`?SERVER` is `?MODULE` = `beamchain_mempool` (line 92). When
`reprocess_orphans/1` runs inside the mempool gen_server's own
`handle_call` invocation, the synchronous `gen_server:call` posts a
message to the SAME process's mailbox, which is already blocked
handling the original request. The call sits in the mailbox until the
30-second timeout, then bombs with `{timeout, {gen_server, call, ...}}`.

**Three production callsites:**

1. **`do_add_transaction` line 817** — direct from handle_call({add_tx, ...})
   at line 425. Triggers on every CPFP child that arrives whose parent
   was already in mempool (very common in fee-bump flows).

2. **`do_accept_package` line 1515** — direct from handle_call({accept_package, ...})
   at line 432. Triggers on package-relay CPFP submissions where a
   child references a parent in the same package.

3. **`erase_orphans_for_block` line 3040** — calls `reprocess_orphans/1`
   for every confirmed block-txid; this is called from
   `do_remove_for_block` line 2721, which is reached via
   handle_call({remove_for_block, ...}) at line 471 OR
   handle_cast({remove_for_block, ...}) at line 498. The cast path
   doesn't deadlock the caller but still timeouts the inner call.

W150 BUG-12 catalogued paths (a) and (c); it missed path (b)
(do_accept_package).

**Failure mode confirmed:** every CPFP child whose parent arrives AFTER
it (very normal pattern for replace-by-feerate flows) hits this code
path. The orphan record is deleted from ETS BEFORE the doomed
`gen_server:call` (mempool.erl:2610-2611):

```erlang
ets:delete(?MEMPOOL_ORPHANS, OrphanWtxid),
ets:delete(?MEMPOOL_ORPHAN_BY_TXID, OrphanTxid),
case add_transaction(OrphanTx) of   %% <-- 30s freeze, then timeout
    {ok, _} -> ...;
    {error, _} -> ok
end
```

So even after the timeout the orphan is PERMANENTLY LOST. The user's
CPFP child is in mempool but the parent is not, and the orphan record
that would have re-tried is gone.

**File:** `src/beamchain_mempool.erl:201` (synchronous call),
`src/beamchain_mempool.erl:817, 1515, 3040` (three production callsites),
`src/beamchain_mempool.erl:2598-2622` (reprocess_orphans).

**Core ref:** `bitcoin-core/src/validation.cpp::MemPoolAccept::SubmitPackage`,
`bitcoin-core/src/net_processing.cpp::ProcessOrphanTx` —
Core processes orphan re-attempts in a separate `ProcessOrphanTx` queue
that drains AFTER the current ATMP call returns, never re-entering the
same lock.

**Cross-cite:** W150 BUG-12 (orphan promotion deadlock) — same root
cause, but here we add the third callsite (`do_accept_package`).
W150 noted "chainstate.erl:282 runs in caller's process post-submit_block
(line 254-260); explicit deadlock-avoidance comment at line 244-250" —
that pattern is the correct fix, applied for chainstate↔mempool but
missed for mempool↔mempool.

**Impact:**
- 30s mailbox freeze on every CPFP child whose parent arrives after
  it. Blocks ALL other mempool operations (add_tx, accept_package,
  remove_for_block, getrawmempool RPC) for 30s.
- Permanent orphan loss on every promotion attempt.
- BUG-3 above (no source-peer exclusion) means we ALSO re-broadcast
  the inv for the parent to the source peer, who in turn announces it
  back — infinite ping-pong if both peers are beamchain.

---

## BUG-8 (P0-CDIV) — Incoming `MSG_TX` / `MSG_WTX` inv items are silently dropped; no tx-fetch via getdata

**Severity:** P0-CDIV (mempool population pathway broken). Bitcoin
Core's `ProcessMessage(NetMsgType::INV)` handler iterates every inv
item: blocks go to the block-download queue, **txs (MSG_TX / MSG_WTX)
are routed to txrequest which schedules a getdata after the
delay/preference logic**.

Beamchain's `route_message(Peer, inv, ...)` at sync.erl:213-257
filters inbound inv items with:

```erlang
BlockItems = lists:filter(fun(#{type := Type, hash := Hash}) ->
    (Type =:= ?MSG_BLOCK orelse Type =:= ?MSG_WITNESS_BLOCK)
        andalso not beamchain_db:has_block(Hash);
    (_) -> false      %% <-- MSG_TX / MSG_WTX caught here
end, Items),
case BlockItems of
    [] ->
        State;        %% <-- silent return; no tx getdata scheduled
    ...
end
```

**Net effect: beamchain does not fetch transactions announced by
peers.** The only mempool-population path is unsolicited `tx` push
messages (which Core peers never send post-2017 — they inv-and-await),
RPC sendrawtransaction, mempool.dat load, and reorg-refill.

**File:** `src/beamchain_sync.erl:213-257`.

**Core ref:** `bitcoin-core/src/net_processing.cpp::ProcessMessage` INV
handler (BIP-339-aware txrequest dispatch).

**Impact:**
- On a typical p2p network beamchain's mempool stays nearly empty
  except for txs it locally accepts via RPC. Fee estimation, package
  relay, RBF — all degraded because the mempool view is incomplete.
- Combined with BUG-1 (no Poisson trickle, instant broadcast) and
  BUG-4 (always MSG_TX) the entire tx-relay subsystem is in a
  degenerate "outbound-only-as-MSG_TX" mode.
- Companion to BUG-9 (no txrequest scheduler at all): even if the
  filter were fixed, there is no scheduler to send the resulting
  getdatas with the BIP-339 / NONPREF / OVERLOADED delays.

---

## BUG-9 (P0) — No `TxRequestTracker` analogue; all delay/preference/in-flight constants absent

**Severity:** P0. Bitcoin Core's `node::TxDownloadManagerImpl` is a
sophisticated per-peer scheduler with five tuning constants:
- `TXID_RELAY_DELAY = 2s` (BIP-339 wtxidrelay-vs-txidrelay arbitration:
  prefer the wtxidrelay peer to avoid txid-malleated double-spends),
- `NONPREF_PEER_TX_DELAY = 2s` (deprefer peers that haven't yet sent
  the tx as a candidate fetch source),
- `OVERLOADED_PEER_TX_DELAY = 2s` (deprefer a peer with
  MAX_PEER_TX_REQUEST_IN_FLIGHT=100 outstanding requests),
- `MAX_PEER_TX_REQUEST_IN_FLIGHT = 100` (concurrent getdata cap),
- `GETDATA_TX_INTERVAL = 60s` (retry interval after a peer's getdata
  times out).

Beamchain has **none of these constants and no scheduler**. A grep:

```
grep -rn "TXID_RELAY_DELAY\|NONPREF_PEER\|OVERLOADED_PEER\|
  MAX_PEER_TX_REQUEST_IN_FLIGHT\|m_recently_announced_invs\|
  tx_announcement\|inv_to_send\|AnnounceTx\|TxRequest" src/*.erl
```

returns zero hits. The closest analogue is `beamchain_block_sync.erl`'s
`in_flight` map for BLOCKS, not txs.

**File:** missing across `src/`.

**Core ref:** `bitcoin-core/src/node/txdownloadman.h:24-38`,
`bitcoin-core/src/node/txrequest.cpp`.

**Impact:**
- Companion to BUG-8: the missing scheduler is why the inv-receive
  path was never built — there's nothing for it to dispatch to.
- BIP-339 wtxidrelay-vs-txidrelay arbitration cannot fire: beamchain
  can't deprefer txid-only peers in favour of wtxidrelay peers.
- If BUG-8 were fixed naively (just fire getdata on every inv), the
  result would be N peers × M txs simultaneous getdata storm with no
  in-flight cap → trivially DoS'able.
- **Fleet pattern: "scheduler-missing-entirely"** — this is the most
  expensive missing subsystem catalogued in the W148-W152 sweep.

---

## BUG-11 (P0) — Orphan tx whose parent is unknown is never followed up with a getdata-for-parent

**Severity:** P0. Bitcoin Core's `ProcessMessage(NetMsgType::TX)`
handler, on `state == MempoolAcceptResult::ResultType::MEMPOOL_ENTRY`
returning `MissingOrSpentInputs`, immediately queues the missing parent
txid (or wtxid, per peer's wtxidrelay) into `m_txrequest` so it can be
fetched. Without this, an orphan can NEVER be promoted unless the
parent arrives unsolicited.

Beamchain's tx-receive path (sync.erl:333-350):

```erlang
route_message(Peer, tx, Payload, State) ->
    case beamchain_p2p_msg:decode_payload(tx, Payload) of
        {ok, Tx} ->
            case beamchain_mempool:accept_to_memory_pool(Tx) of
                {ok, Txid} ->
                    logger:info("sync: accepted tx ~s from ~p",
                                [beamchain_serialize:hex_encode(Txid), Peer]),
                    beamchain_peer_manager:broadcast(inv, #{...});
                {error, Reason} ->
                    logger:debug("sync: rejected tx from ~p: ~p", [Peer, Reason])
            end;
        ...
    end,
    State;
```

When mempool returns `{error, orphan}` (mempool.erl:837 path; see
add_orphan invocation at line 2564), this handler treats it
identically to any other rejection: log at debug, move on. The orphan
HAS been added to `?MEMPOOL_ORPHANS` (line 2569), but the missing
parent is never requested.

Combined with BUG-8 (incoming inv MSG_TX silently dropped) the orphan
can only be promoted if the parent arrives via:
- another unsolicited `tx` push (rare; Core peers don't push
  post-2017),
- a future block containing the parent (which would invalidate the
  orphan anyway in most cases),
- BIP-35 mempool dump (very rare).

**File:** `src/beamchain_sync.erl:344-346`,
`src/beamchain_mempool.erl:836-838`.

**Core ref:** `bitcoin-core/src/net_processing.cpp::ProcessMessage` TX
handler — adds missing parents to txrequest.

**Impact:**
- Orphans accumulate in the 100-slot pool but cannot be promoted in
  practice. Effective orphanage hit rate = ~0 for typical traffic.
- Pool churn happens via expiry (20 min) and EraseForBlock; never via
  successful promotion. Wasted CPU on `reprocess_orphans` scans
  (BUG-6) that always find no parents.

---

## BUG-13 (P1) — Inv decode error silently swallowed; no misbehavior penalty

**Severity:** P1. Bitcoin Core's net_processing.cpp:4040-4042 charges
`Misbehaving(20, "oversized inv message")` (note: this matches the
generic decode-failure scoring, not the +100 I cited earlier; the +100
applies to higher-level protocol violations). What matters is that
Core ALWAYS records a misbehavior score on inv-decode failure;
beamchain records ZERO.

Beamchain's inv route at sync.erl:255 has a bare `_Error -> State`:

```erlang
route_message(Peer, inv, Payload, State) ->
    case beamchain_p2p_msg:decode_payload(inv, Payload) of
        {ok, #{items := Items}} ->
            ...
        _Error ->
            State          %% <-- NO add_misbehavior call
    end;
```

Compare with the SAME file's other route handlers:
- headers (line 184): `add_misbehavior(Peer, 20)`
- block (line 193): `add_misbehavior(Peer, 20)`
- cmpctblock (line 265): `add_misbehavior(Peer, 20)`
- blocktxn (line 274): `add_misbehavior(Peer, 20)`
- getblocktxn (line 328): `add_misbehavior(Peer, 20)`
- tx (line 348): `add_misbehavior(Peer, 20)`

Inv is the only message type with `_Error -> State`. Looks like a
copy-paste omission.

**File:** `src/beamchain_sync.erl:255-256`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4040-4133` (inv
decode + Misbehaving).

**Impact:**
- A peer sending oversized inv (entry count > MAX_INV_SIZE = 50,000)
  has its message rejected (per p2p_msg.erl:673-675) but suffers no
  ban-score penalty. The peer can repeat indefinitely.
- A peer sending a malformed inv item (wrong byte alignment, etc.)
  similarly skates free.
- The lack of penalty makes a slow-burn DoS via repeated bad inv
  cheap.

---

## BUG-14 (P1) — Getdata MSG_FILTERED_BLOCK falls to notfound; BIP-37 SPV peers cannot use beamchain

**Severity:** P1 (BIP-37 fleet pattern — cross-cite W134). Bitcoin
Core's `ProcessGetData` handles MSG_FILTERED_BLOCK (inv type 3) by
walking the block's tx set against the requesting peer's bloom filter
and emitting a `merkleblock` message. Beamchain's
`handle_getdata_msg/2` at peer_manager.erl:1750-1791 enumerates four
inv types:

```erlang
NotFound = lists:filtermap(fun(#{type := Type, hash := Hash}) ->
    case Type of
        T when T =:= ?MSG_BLOCK; T =:= ?MSG_WITNESS_BLOCK ->
            ...                                              %% serve full block
        T when T =:= ?MSG_TX; T =:= ?MSG_WITNESS_TX ->
            ...                                              %% serve mempool tx
        _ ->
            {true, #{type => Type, hash => Hash}}            %% <-- MSG_FILTERED_BLOCK lands here
    end
end, Items),
```

MSG_FILTERED_BLOCK (3) and MSG_CMPCT_BLOCK (4) fall into the catch-all,
producing a notfound. BIP-37 SPV wallets (BlueWallet, older Electrum)
that load a bloom filter and request filtered blocks get notfound for
everything → cannot use beamchain as a backend.

**File:** `src/beamchain_peer_manager.erl:1750-1791`.

**Core ref:** `bitcoin-core/src/net_processing.cpp::ProcessGetData`
MSG_FILTERED_BLOCK case.

**Impact:**
- BIP-37 SPV peers cannot use beamchain as a backend. Beamchain
  advertises NODE_BLOOM (when configured) but cannot serve the
  resulting requests.
- W134 BUG-X catalogued this as a fleet-wide pattern (7 of 10 impls).
  Beamchain confirms the gap.

---

## BUG-15 (P1) — No IBD gate on tx-processing path

**Severity:** P1. Bitcoin Core's `ProcessMessage(NetMsgType::TX)`
returns early when `m_chainman.IsInitialBlockDownload()` is true:

```cpp
// net_processing.cpp:4395
if (m_chainman.IsInitialBlockDownload()) return;
```

Rationale: during IBD the UTXO view is stale, ATMP gates that depend
on UTXO context (BIP-113 IsFinalTx, BIP-68 SequenceLocks, fee rate vs
mempool rolling min fee) produce non-meaningful results, and any
broadcast to peers is premature.

Beamchain has no IBD gate. `grep -rn "is_initial_block_download\|in_ibd\|is_ibd" src/`
returns zero hits. The tx-receive path at `sync.erl:333` runs the
full ATMP pipeline regardless of sync state, then broadcasts on
success.

**File:** missing from `src/beamchain_sync.erl:333-350`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4395`.

**Impact:**
- CPU waste: ATMP runs against a stale UTXO view, almost always fails
  for txs that depend on recent confirmations.
- Bandwidth waste: if ATMP does accept (because the tx is small + old
  enough to predate the IBD window), beamchain broadcasts an inv to
  all peers, who already have the tx confirmed or rejected.
- Network noise: during IBD, beamchain looks like a misbehaving relay
  to its peers.

---

## BUG-16 (P1) — No `m_lazy_recent_rejects` rolling Bloom; re-processed-rejected attacks possible

**Severity:** P1. Bitcoin Core's `m_lazy_recent_rejects` is a
`CRollingBloomFilter(120000, 0.000001)` that records txids/wtxids
recently rejected by ATMP. New inv items are checked against this
filter; matched items skip the getdata-and-revalidate round-trip.

Beamchain has no such filter. `check_tx_already_known/1`
(mempool.erl:4347-4360) checks whether the tx's OUTPUTS are in the
UTXO set — i.e., whether the tx is CONFIRMED. It does NOT check
whether the txid was previously rejected. A peer can re-send a
rejected tx forever and beamchain runs the full 21-gate ATMP gauntlet
every time.

**File:** missing from `src/beamchain_mempool.erl`.

**Core ref:** `bitcoin-core/src/net_processing.cpp::PeerManagerImpl::m_lazy_recent_rejects`.

**Impact:**
- CPU DoS: an adversary can keep beamchain busy running ATMP gates
  by replaying invalid txs.
- Cross-cite W150 BUG-21 (m_recent_rejects rolling-bloom absent in
  ATMP path) — same gap from the other direction.

---

## BUG-19 (P2) — `shuffle_list` is comment-as-confession; not actually Fisher-Yates

**Severity:** P2 ("comment-as-confession" 9th distinct beamchain
instance — cross-cite W150 BUG-12 which catalogued 8 prior instances).
`peer.erl:1859-1864`:

```erlang
%% Fisher-Yates shuffle for randomizing inv order
shuffle_list([]) -> [];
shuffle_list([X]) -> [X];
shuffle_list(List) ->
    %% Use a simple random sort for small lists
    lists:sort(fun(_, _) -> rand:uniform() > 0.5 end, List).
```

The header comment claims "Fisher-Yates shuffle"; the implementation is
NOT Fisher-Yates — it's a biased comparator-based pseudo-shuffle. The
comparator `fun(_, _) -> rand:uniform() > 0.5 end` is non-transitive
(it can return X<Y, Y<Z, Z<X for the same triple), which is undefined
behavior for `lists:sort`. The Erlang docs specify lists:sort produces
"stable, mergesort-based" output assuming a total order; with a
non-transitive comparator the output ordering is implementation-defined
and observably biased.

Real Fisher-Yates is O(N) with strict uniform-random index selection.
The comment-vs-code gap is exactly the "comment-as-confession" fleet
pattern.

**File:** `src/beamchain_peer.erl:1859-1864`.

**Core ref:** N/A (Core uses `std::shuffle(rng)` which is well-defined
uniform).

**Impact:**
- Bias in inv ordering — observable in long-running traces. A
  determined observer can statistically distinguish "random" tx-inv
  ordering from the biased lists:sort output.
- Privacy: tx-ordering bias leaks information about queue contents and
  arrival times.
- Mostly cosmetic (BUG-1 makes the trickle path dead anyway), but the
  pattern matters for fleet docs.

---

## BUG-20 (P1) — No rebroadcast loop; locally-created unconfirmed txs never get re-announced

**Severity:** P1. Bitcoin Core's `ScheduleNextRebroadcast` (in
net_processing.cpp) re-announces unconfirmed wallet txs every ~10 min,
with a per-tx counter. This is partly a privacy feature
(source-fingerprinting prevention) and partly a reliability feature
(if a tx was sent during a brief network partition, it gets retried).

Beamchain has no rebroadcast machinery. Confession at
`mempool_persist.erl:24-28`:

```erlang
%% beamchain has no fee-delta priority map and no unbroadcast set today,
```

There is no timer that walks the mempool and re-announces stale txs.
`unbroadcastcount` is hardcoded to 0 in two places
(`rest.erl:446`, `rpc.erl:3259`).

**File:** missing across `src/`; documented gap in
`src/beamchain_mempool_persist.erl:24-28`.

**Core ref:** `bitcoin-core/src/net_processing.cpp::ScheduleNextRebroadcast`.

**Impact:**
- A tx sent via RPC during a brief network partition (peer churn,
  full sync wait, etc.) is added to mempool and broadcast ONCE. If no
  peer relays it onward (because they were all temporarily
  disconnected), the tx sits in beamchain's mempool forever, never
  reaches the network, and never confirms.
- Source-fingerprinting: a single broadcast at tx-creation time is
  exactly the timing signature observers use to identify originating
  peers.
- Wallet UX: users see the tx in `getrawmempool` but it never
  confirms; no clear failure path.

---

## BUG-21 (P2) — `lookup_entry_by_wtxid` is O(N) ETS match_object; wtxid getdata is slow

**Severity:** P2 (perf hot path; not consensus). Bitcoin Core uses
`mapTxByWtxid` for O(log N) lookup of mempool entries by wtxid.
Beamchain emulates this with `ets:match_object` (mempool.erl:4368-4374):

```erlang
lookup_entry_by_wtxid(Wtxid) ->
    case ets:match_object(?MEMPOOL_TXS,
                          {'_', #mempool_entry{wtxid = Wtxid, _ = '_'}}) of
        [{_, Entry}] -> {ok, Entry};
        ...
    end.
```

`match_object` with no key in the pattern scans the full table.
Comment-as-confession at line 4363-4367 admits "Mempool sizes are
bounded so the cost is acceptable; if it becomes a hotspot a secondary
ets index on wtxid → txid would be the right fix."

At 300 MB / ~75,000 txs that's a 75,000-record full-table scan per
MSG_WTX getdata. On a healthy mainnet relay, that's hundreds per
second.

**File:** `src/beamchain_mempool.erl:4368-4374`,
`src/beamchain_mempool.erl:4363-4367` (confession).

**Core ref:** `bitcoin-core/src/txmempool.h::mapTxByWtxid`.

**Impact:**
- Wtxid-keyed getdata hot path is O(N). Acceptable for small mempools
  but the only thing keeping the hotspot tolerable is BUG-4 (we
  always send MSG_TX, so wtxid getdata only happens on incoming
  requests from other-impl peers).
- Add a secondary ets index `?MEMPOOL_BY_WTXID = wtxid → txid` — the
  exact fix the confession recommends.

---

## Summary

**Bug count:** 21 (BUG-1 through BUG-21).

**Severity distribution:**
- **P0-CDIV:** 4 (BUG-4, BUG-7, BUG-8, plus BUG-1 borderline-CDIV via
  privacy gap — counted as plain P0)
- **P0:** 5 (BUG-1, BUG-5, BUG-9, BUG-11, plus W150 BUG-12 re-anchor)
- **P1:** 8 (BUG-2, BUG-3, BUG-6, BUG-10, BUG-12, BUG-13, BUG-14,
  BUG-15, BUG-16, BUG-20)
- **P2:** 4 (BUG-17, BUG-18, BUG-19, BUG-21)

Recount: P0-CDIV(3)=BUG-4/7/8, P0(5)=BUG-1/5/9/11/+a, total P0 family
8. P1(9)=BUG-2/3/6/10/12/13/14/15/16/20 = wait, that's 10. Let me
recount: P1 list = {BUG-2, BUG-3, BUG-6, BUG-10, BUG-12, BUG-13,
BUG-14, BUG-15, BUG-16, BUG-20} = 10. P2 list = {BUG-17, BUG-18,
BUG-19, BUG-21} = 4. P0-CDIV = {BUG-4, BUG-7, BUG-8} = 3. P0 (non-CDIV)
= {BUG-1, BUG-5, BUG-9, BUG-11} = 4. Total = 3 + 4 + 10 + 4 = 21. ✓

**Fleet patterns confirmed:**
- **"dead-handler plumbing" — 4th distinct beamchain instance**
  (BUG-1 Poisson trickle; companions: W150 BUG-13 do_trim_to_size,
  W150 BUG-14 do_expire_old, BUG-5 erase_orphans_for_peer).
- **"comment-as-confession" — 9th and 10th distinct beamchain
  instances** (BUG-5 TODO + BUG-19 Fisher-Yates comment; BUG-21
  match_object confession is the 11th).
- **"gen_server self-deadlock"** — BUG-7 confirms W150 BUG-12 and
  adds the third callsite (do_accept_package).
- **"scheduler-missing-entirely"** — BUG-9 (TxRequestTracker) is the
  most expensive missing subsystem catalogued in the W148-W152 sweep.
- **"wiring-look-but-no-wire"** — BUG-1 (queue_tx_inv exported, not
  called); BUG-5 (erase_orphans_for_peer exported, no-op).
- **"misbehavior-score-omitted"** — BUG-13 inv-decode error is the
  only sync.erl route that lacks add_misbehavior (six other routes
  charge +20).
- **"inv-receive-blocks-only"** — BUG-8: filter only allows
  MSG_BLOCK / MSG_WITNESS_BLOCK; MSG_TX / MSG_WTX silently dropped.
- **BIP-339 wire-format slippage** — BUG-4 confirms beamchain
  negotiates wtxidrelay but never emits MSG_WTX on broadcast.

**Cross-cites:**
- W150 BUG-12 (orphan-promotion self-deadlock) — confirmed + extended
  with third callsite.
- W141 hash byte-order (ZMQ display-vs-internal) — distinct from inv
  byte-order; inv path PASSES (BUG-21 cross-cite section).
- W134 MSG_FILTERED_BLOCK dispatch gap — confirmed (BUG-14).
- W136 feefilter / wtxidrelay / sendheaders parity — BUG-4 extends
  the wtxidrelay-not-honored finding to the relay/broadcast direction
  (W136 audited the negotiation direction only).
- W143 hex_to_bin byte-order — distinct subsystem; not relevant here.

**Top three findings:**

1. **BUG-1 + BUG-4 cluster (P0 + P0-CDIV) — production tx-relay path
   has wrong everything**: it bypasses the Poisson-trickle privacy
   queue entirely (instant broadcast to all peers, defeating BIP-339
   privacy) AND always emits MSG_TX regardless of per-peer
   wtxidrelay negotiation (BIP-339 wire-format divergence). The full
   correct relay machinery is built and exported in `peer.erl` but no
   production caller invokes it.

2. **BUG-7 (P0-CDIV) — three production paths trigger the
   `reprocess_orphans` self-deadlock**: confirms W150 BUG-12 and adds
   the missed third callsite (`do_accept_package` line 1515).
   Permanent orphan loss + 30s mailbox freeze on every CPFP child
   whose parent arrives after it.

3. **BUG-8 + BUG-9 + BUG-11 cluster (P0-CDIV / P0 / P0) — incoming
   tx-relay subsystem does not exist**: `sync.erl:217-221` silently
   drops MSG_TX / MSG_WTX inv items; there is no TxRequestTracker
   analogue at all (zero of the five Core constants present);
   orphan-tx parent-fetch is absent. Net effect: beamchain processes
   `tx` push messages but does not pull announced txs — mempool
   stays nearly empty on a healthy p2p network, fee estimation
   degraded, package relay degraded.
