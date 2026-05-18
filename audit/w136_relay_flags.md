# W136 — BIP-130 sendheaders + BIP-133 feefilter + BIP-339 wtxidrelay audit (beamchain)

Discovery-only wave. 30 audit gates against three closely-related P2P feature
negotiations that govern how a beamchain peer expresses block-announcement
preference (sendheaders / BIP-130), per-peer minimum fee for transaction
relay (feefilter / BIP-133), and witness-txid based inventory hashes
(wtxidrelay / BIP-339).

These three messages are bundled because they are all *single-shot or
periodic feature negotiations* sent during or shortly after the version
handshake, and Core handles them in adjacent net_processing.cpp branches
(SENDHEADERS @ :3896, WTXIDRELAY @ :3921, FEEFILTER @ :5035, plus the
periodic `MaybeSendSendHeaders` / `MaybeSendFeefilter` in `SendMessages`).
A bug in any one of them can corrupt the relay metadata maintained for the
peer — wrong wtxid/txid hash in inv, wrong block-announce path, leak of
non-private mempool fee floor — without affecting consensus, so this is a
P2P-policy audit, not a CDIV one.

Bitcoin Core references:
- `bitcoin-core/src/net_processing.cpp` (peer-state, MaybeSendSendHeaders,
  MaybeSendFeefilter, ProcessMessage SENDHEADERS/WTXIDRELAY/FEEFILTER)
- `bitcoin-core/src/net.h` + `net.cpp` (CNode::GetCommonVersion,
  IsBlockOnlyConn, HasPermission)
- `bitcoin-core/src/policy/fees/block_policy_estimator.{h,cpp}`
  (`FeeFilterRounder` for privacy-quantized broadcasts)
- `bitcoin-core/src/node/protocol_version.h`
  (SENDHEADERS_VERSION=70012, FEEFILTER_VERSION=70013, WTXID_RELAY_VERSION=70016)

BIPs: 130, 133, 339.

Companion audits to cross-reference:
- **W99** — net_processing message dispatch baseline.
- **W103** — tx relay / inv pipeline (where the wtxidrelay flag is consumed
  per-announcement).
- **W110** — bloom filter / NODE_BLOOM gating (filter messages flow through
  the same `m_relay_txs` slot that feefilter and wtxidrelay also depend on).
- **W112** — BIP-152 compact blocks (sendcmpct is the fourth feature
  negotiation message, gated similarly to sendheaders; not covered here).
- **W117** — BIP-155 sendaddrv2 (the other "before VERACK" feature
  negotiation; same fSuccessfullyConnected disconnect pattern as wtxidrelay).

## Status counts (30 gates)

- **PRESENT** (matches Core or internally consistent + Core-compatible): 6
- **PARTIAL** (some piece matches, others diverge or are simplified): 8
- **MISSING** (no equivalent in beamchain): 16

Headline: **22 bugs**, severity distribution **0 CDIV / 4 HIGH / 11 MEDIUM /
7 LOW**. None of these is a consensus issue. Wire-protocol correctness
deviations (HIGH) can break interoperability with strict peers and leak
non-private mempool fee floor; policy deviations (MEDIUM/LOW) affect
bandwidth, privacy, and operator-surface symmetry with Core.

The most consequential:

1. **BUG-1 (HIGH)** — **sendheaders broadcast lacks the BIP-130
   "best-known-block > MinimumChainWork" precondition.** Core's
   `MaybeSendSendHeaders` (net_processing.cpp:5519) gates the
   `sendheaders` send on `state.pindexBestKnownBlock->nChainWork >
   m_chainman.MinimumChainWork()` to avoid telling a peer we want headers
   announcements *before* we've completed initial-headers-sync with
   them — receiving headers announcements for new blocks while still
   syncing the peer's chain corrupts the connect-side state tracking.
   beamchain sends `sendheaders` unconditionally in
   `send_feature_msgs/1` (beamchain_peer.erl:1633) on every
   `ready(enter, …)` transition, **before** any header sync has run with
   the peer. A peer that immediately starts pushing `headers` announces
   for new tips while we're still locator-walking their history can wedge
   our header sync. Mitigated in practice because beamchain's headers
   handler doesn't reject mid-sync header announcements outright, but the
   anti-foot-gun guard is missing.

2. **BUG-2 (HIGH)** — **feefilter `do_send_feefilter` does NOT use a
   `FeeFilterRounder` privacy quantization.** Core's `FeeFilterRounder`
   (block_policy_estimator.h:323, .cpp:1109) builds a log-spaced
   `m_fee_set` from `min_incremental_fee` up to `MAX_FILTER_FEERATE=1e7`
   with `FEE_FILTER_SPACING=1.1`, then for each broadcast it does a
   `lower_bound` lookup + ⅓ probability of rounding down to the
   *next-lower* bucket. The effect is two-fold: (a) the announced filter
   is a quantized log-bucket, not the exact mempool min fee — so an
   observer cannot fingerprint your mempool's exact min-fee, (b) one in
   three sends "blurs" further by stepping to a lower bucket — adding
   privacy. beamchain just clamps to `?DEFAULT_MIN_RELAY_FEE=1000`
   (beamchain_peer.erl:1550) and sends the raw value. Every observer
   that sees more than one feefilter from a beamchain node can detect
   per-second mempool fee-floor changes at sat/kvB granularity — a
   significant fingerprinting and mempool-spy surface vs Core.

3. **BUG-3 (HIGH)** — **wtxidrelay-after-VERACK is NOT a disconnect.**
   Core ProcessMessage SENDADDRV2/WTXIDRELAY/SENDTXRCNCL all
   *disconnect the peer* (`pfrom.fDisconnect = true`) if these
   feature-negotiation messages arrive after `fSuccessfullyConnected`
   (net_processing.cpp:3924, 3946, 3964). beamchain's
   `dispatch_message(wtxidrelay, …)` (beamchain_peer.erl:1261-1266)
   silently ignores wtxidrelay if handshake is complete — *no
   disconnect, no misbehavior score bump.* The same gap appears for
   `sendaddrv2` (beamchain_peer.erl:1255-1260). The companion
   `sendtxrcncl` *does* disconnect (line 1431), so the per-message
   behaviour is inconsistent inside beamchain. A misbehaving peer can
   send wtxidrelay at any time post-VERACK and beamchain will never
   notice; if any future code path branches on the flag, this becomes a
   relay-mode confusion attack vector.

4. **BUG-4 (HIGH)** — **`MaybeSendSendHeaders` semantics absent /
   `m_sent_sendheaders` not modelled.** Core records on the peer
   whether `sendheaders` was already sent (`Peer::m_sent_sendheaders`,
   net_processing.cpp:406) so the post-IBD `SendMessages` tick can
   re-emit the message when we *first* cross MinimumChainWork with that
   peer. beamchain sends `sendheaders` exactly once, in
   `send_feature_msgs/1` on the ready-enter transition, and never
   re-checks. If beamchain is started below MinimumChainWork (cold IBD)
   AND BIP-130 gating were added per BUG-1, the message would never
   be re-emitted post-IBD — peers would think we still want inv-only
   announcements. The two fixes interlock and must land together.

The remaining 18 bugs cover: feefilter to ForceRelay peers (Core skips,
beamchain sends unconditionally), feefilter to block-relay-only outbound
peers (Core skips, beamchain has no concept of such peers in the
feefilter gate), feefilter MAX_MONEY-during-IBD signal (Core sends
MAX_FILTER while IBD to tell peers "don't send tx invs", beamchain just
sends whatever the mempool reports), feefilter randomized Poisson
broadcast vs interval reset on IBD-exit, feefilter "send the current
filter if we sent MAX_FILTER previously" recovery, feefilter received
value not gated on `MoneyRange` (Core rejects > MAX_MONEY,
beamchain accepts any uint64), sendheaders not sent to outbound peers
without txrelay (Core sends to non-NODE NETWORK too because even pruned
peers can announce blocks), `m_provides_cmpctblocks` interaction with
sendheaders, wtxidrelay duplicate-send detection (Core logs ignored dup,
beamchain just no-ops), wtxidrelay version-gate (Core ignores wtxidrelay
from peers with common version < WTXID_RELAY_VERSION, beamchain
unconditionally accepts), wtxidrelay→sendtxrcncl interaction (Core's
`ForgetPeer` cleanup absent), `m_wtxid_relay_peers` global counter
absent (no observable for `getnetinfo`-style stats), feefilter inv-side
filtering inconsistency (beamchain looks up tx fee rate per-inv via a
synchronous mempool gen_server call, Core uses a snapshot), `peer_relay
= true` default during version unmarshal (beamchain defaults peer_relay
to `true` even when relay field is decoded to false — see below),
`build_info/1` doesn't surface peer_fee_filter (so getpeerinfo can't
report it), and feefilter received logged at debug level only with no
metric.

**Not a CDIV**: every bug below affects peer-interop, P2P bandwidth,
privacy, or operator UX. None affects consensus validation of received
blocks. Cluster severity: 4 HIGH / 11 MEDIUM / 7 LOW.

The audit-flip convention applies: every test asserts the current
(divergent) behavior so it **passes today** and will **fail when the
fix lands**, flipping the gate from MISSING/BUG → PRESENT.

---

## Gate index (1..30)

| #  | Name | Status | Core ref | beamchain ref |
|----|------|--------|----------|---------------|
| 1  | sendheaders gated on `nChainWork > MinimumChainWork`                                        | MISSING | net_processing.cpp:5519-5538 | unconditional in send_feature_msgs/1 (beamchain_peer.erl:1633) |
| 2  | `m_sent_sendheaders` per-peer latch + post-IBD re-check                                     | MISSING | net_processing.cpp:405-406, 5519 | one-shot send on ready enter; no latch |
| 3  | sendheaders gated on `GetCommonVersion() >= SENDHEADERS_VERSION` (70012)                    | MISSING | net_processing.cpp:5525   | no version-gate; sent regardless of peer_version |
| 4  | Send sendheaders to non-NODE NETWORK peers (pruned can still announce)                      | PARTIAL | net_processing.cpp:5530-5533 | sent to all, no NODE_NETWORK awareness either way |
| 5  | Peer's `sendheaders` flag selects `headers` vs `inv` block-announce branch                  | PRESENT | net_processing.cpp:m_blocks_for_headers_relay | beamchain_peer_manager.erl:325-342 (announce_block/2) |
| 6  | feefilter periodic broadcast with `AVG_FEEFILTER_BROADCAST_INTERVAL` ≈ 10 min               | PARTIAL | net_processing.cpp:180, 5572 | uses 600000 ms constant + own rng (beamchain_peer.erl:1568) |
| 7  | feefilter `MAX_FEEFILTER_CHANGE_DELAY` ≈ 5 min accelerated bump on >25% change              | PARTIAL | net_processing.cpp:182, 5577 | own significant-change logic but uses 300000 ms (line 1594-1601) |
| 8  | feefilter goes through `FeeFilterRounder.round()` (log buckets + ⅓ blur)                    | MISSING | block_policy_estimator.{h,cpp}:323/1109 | raw value clamped to DEFAULT_MIN_RELAY_FEE only |
| 9  | feefilter skip for `IsBlockOnlyConn()` (block-relay-only outbound)                          | MISSING | net_processing.cpp:5548   | no IsBlockOnlyConn concept in feefilter path |
| 10 | feefilter skip for `HasPermission(NetPermissionFlags::ForceRelay)`                          | MISSING | net_processing.cpp:5545   | no permission system; sent to all peers with V≥70013 + relay |
| 11 | feefilter override to MAX_MONEY during IBD ("don't send invs")                              | MISSING | net_processing.cpp:5552-5555 | no IBD-override; current mempool value used |
| 12 | feefilter recovery: `next_send_feefilter = 0us` after IBD-exit + previous send was MAX     | MISSING | net_processing.cpp:5558-5562 | no IBD recovery branch |
| 13 | feefilter min-relay floor on every send (`std::max(filter, min_relay_feerate)`)             | PARTIAL | net_processing.cpp:5567   | floor applied via clamp in do_send_feefilter but uses DEFAULT_MIN_RELAY_FEE constant, not mempool's min_relay setting |
| 14 | feefilter skip if `m_opts.ignore_incoming_txs` (blocksonly mode)                            | MISSING | net_processing.cpp:5542   | no blocksonly mode in beamchain config |
| 15 | feefilter received: validate `MoneyRange(newFeeFilter)`                                     | MISSING | net_processing.cpp:5038   | beamchain_peer.erl:1522-1528 accepts any uint64 |
| 16 | feefilter received: store in per-peer `m_fee_filter_received` slot                          | PRESENT | net_processing.cpp:5040   | beamchain_peer.erl:1525 (`fee_filter = Fee`) |
| 17 | wtxidrelay rejected (disconnect) after fSuccessfullyConnected (BIP-339)                     | MISSING | net_processing.cpp:3921-3927 | silently ignored if handshake complete (beamchain_peer.erl:1263-1265) |
| 18 | wtxidrelay version-gate (`GetCommonVersion() >= WTXID_RELAY_VERSION`)                       | MISSING | net_processing.cpp:3928   | accepted regardless of peer_version |
| 19 | wtxidrelay duplicate-send logging vs first-send latch                                       | MISSING | net_processing.cpp:3929-3934 | no first-send latch (idempotent set of true→true) |
| 20 | wtxidrelay → `m_wtxid_relay_peers` global counter                                           | MISSING | net_processing.cpp:837, 1688, 3931 | no global counter |
| 21 | wtxidrelay sent unconditionally if `greatest_common_version >= WTXID_RELAY_VERSION`         | PRESENT | net_processing.cpp:3710-3712 | beamchain_peer.erl:1374 sent unconditionally before verack |
| 22 | wtxidrelay flag drives MSG_WTX vs MSG_TX in tx-inv pipeline                                 | PRESENT | net_processing.cpp:4059, 2259 | beamchain_peer.erl:1841 (send_tx_inv) + beamchain_peer_manager.erl:1884 (handle_mempool_msg) |
| 23 | feefilter pre-trickle inv filter: drop tx if `fee < filterrate.GetFee(vsize)`                | PARTIAL | net_processing.cpp:6013, 6071 | beamchain_peer.erl:1822-1836 uses sat/kvB compare; doesn't go via vsize × feerate |
| 24 | feefilter inv filter applied to BIP35 `mempool` response                                    | MISSING | net_processing.cpp:6000-6013 (filterrate branch in fSendTrickle/m_send_mempool) | handle_mempool_msg (beamchain_peer_manager.erl:1864) doesn't consult fee_filter |
| 25 | feefilter `MaybeSendFeefilter` callsite in periodic SendMessages tick                       | PARTIAL | net_processing.cpp:MaybeSendFeefilter | beamchain uses per-peer self-scheduled timer (check_feefilter info msg, line 619) |
| 26 | feefilter sendto observer ordering: send-then-update vs update-then-send                    | PARTIAL | net_processing.cpp:5564-5572 | beamchain do_send_feefilter writes then updates sent_at (line 1548-1557) — ordering matches Core |
| 27 | `peer_relay` default during version unmarshal (BIP-37 `fRelay` field absent = true)         | PRESENT | net_processing.cpp:3688   | beamchain_peer.erl:97 default=true + decode_payload(version) reads the field |
| 28 | Peer's feefilter surfaced via `build_info/1` → getpeerinfo `minfeefilter`                    | MISSING | net.h CNodeStats::m_fee_filter_received | build_info/1 (beamchain_peer.erl:1733) omits fee_filter |
| 29 | feefilter received: log + metric                                                            | MISSING | net_processing.cpp:5042 (LogDebug) | beamchain has neither log nor metric on receive |
| 30 | feefilter ForceRelay permission peers exempt from received filter on outbound tx selection  | MISSING | net_processing.cpp:5544-5545 | no permission system → no exemption |

---

## Detailed findings

### CDIV (0)

None. This is operator/policy surface; consensus is untouched.

### HIGH (4)

**BUG-1 (HIGH)** — **sendheaders broadcast lacks BIP-130 MinimumChainWork gate.**
`beamchain_peer.erl:1630-1653` (`send_feature_msgs/1`) sends `sendheaders`
immediately on entering `ready` state, with no pre-condition. Core's
`PeerManagerImpl::MaybeSendSendHeaders` (net_processing.cpp:5519) wraps the
emit in:
```cpp
if (!peer.m_sent_sendheaders && node.GetCommonVersion() >= SENDHEADERS_VERSION) {
    LOCK(cs_main);
    CNodeState &state = *State(node.GetId());
    if (state.pindexBestKnownBlock != nullptr &&
            state.pindexBestKnownBlock->nChainWork > m_chainman.MinimumChainWork()) {
        MakeAndPushMessage(node, NetMsgType::SENDHEADERS);
        peer.m_sent_sendheaders = true;
    }
}
```
The chain-work pre-condition prevents announcing "send me headers, not invs"
to a peer we have not yet finished header-sync'ing — the docstring at
:5521-5524 is explicit: "Receiving headers announcements for new blocks
while trying to sync their headers chain is problematic, because of the
state tracking done." beamchain skips both the version gate (covered in
BUG-3) AND the chain-work gate. Net effect: every newly-handshaked peer
immediately gets a sendheaders, and any subsequent header announce arrives
mid-sync. Fix: replicate the gate; needs a new `m_sent_sendheaders` field
on `#peer_data{}` and a call from `peer_manager` (or a new periodic tick)
that re-fires after chain-work crosses the threshold (intertwined with
BUG-4).

**BUG-2 (HIGH)** — **No `FeeFilterRounder` privacy quantization.**
Core's `FeeFilterRounder` (block_policy_estimator.h:323) builds a
log-spaced set of fee buckets between `min_incremental_fee` and
`MAX_FILTER_FEERATE = 1e7` with `FEE_FILTER_SPACING = 1.1`; `round()`
returns `lower_bound(currentMinFee)` with ⅓ probability of stepping to
the *next-lower* bucket (block_policy_estimator.cpp:1109-1119). The
returned value is what's broadcast — not the raw mempool min fee. Two
effects: (a) quantization-only privacy (an observer learns the bucket,
not the exact value), (b) one-in-three "stair-step" blur (further
fingerprint resistance). beamchain's `do_send_feefilter`
(beamchain_peer.erl:1547-1557) just takes `max(FeeRate,
DEFAULT_MIN_RELAY_FEE)` and broadcasts that raw value verbatim. An
observer who logs a beamchain node's feefilter announcements across
several mempool fluctuations can reconstruct the exact mempool min-fee
trajectory at sat/kvB resolution — a meaningful fingerprinting signal vs
Core. Fix: port `FeeFilterRounder` (the spacing constant and bucket-set
construction is straightforward) into a `beamchain_fee_filter_rounder`
helper module and apply at both `maybe_send_initial_feefilter/1` and
`do_send_feefilter/2`.

**BUG-3 (HIGH)** — **wtxidrelay/sendaddrv2 after VERACK is NOT a
disconnect.** Core's `ProcessMessage(WTXIDRELAY)` (net_processing.cpp:3921):
```cpp
if (pfrom.fSuccessfullyConnected) {
    LogDebug(BCLog::NET, "wtxidrelay received after verack, %s", pfrom.DisconnectMsg());
    pfrom.fDisconnect = true;
    return;
}
```
beamchain's `dispatch_message(wtxidrelay, …)` (beamchain_peer.erl:1261):
```erlang
dispatch_message(wtxidrelay, _Payload, Data) ->
    case handshake_complete(Data) of
        false -> {ok, Data#peer_data{wtxidrelay = true}};
        true  -> {ok, Data}
    end;
```
…silently no-ops instead of stopping. The same gap applies to
`sendaddrv2` at lines 1255-1260. Note that the companion
`sendtxrcncl` (line 1431) *does* `{stop, protocol_violation}` after
VERACK, so the inconsistency is internal to beamchain — three "before
VERACK" messages, three different reactions. Detection: a misbehaving
peer that wants to confuse our relay-mode tracking can flip our
wtxidrelay flag at any time post-handshake; if any future code path
re-reads the flag (the trickle pipeline does, beamchain_peer.erl:1841),
this is a relay-mode toggle. Fix: replace the `true ->` arm with
`{stop, protocol_violation}` for both wtxidrelay and sendaddrv2 to
match Core + the existing sendtxrcncl pattern.

**BUG-4 (HIGH)** — **No `m_sent_sendheaders` latch / post-IBD re-emit.**
Core models sendheaders dispatch as `peer.m_sent_sendheaders` set on first
successful emit (net_processing.cpp:5535), and the SendMessages tick
re-checks `MaybeSendSendHeaders` on every iteration — so the moment chain
work crosses MinimumChainWork (post-IBD), the message fires (cf.
BUG-1). beamchain has no such latch and no periodic re-check. If BUG-1
were fixed naively (just add the chain-work guard around
`do_send_raw(sendheaders, …)` in `send_feature_msgs/1`), a node that
handshakes a peer DURING IBD would never emit sendheaders to that peer at
all — even after exiting IBD. The fix requires both: (a) the gate, (b) a
new tick (or hook into the periodic_getheaders timer) that re-runs
`MaybeSendSendHeaders` per peer and consults the latch.

### MEDIUM (11)

**BUG-5 (MEDIUM)** — **sendheaders not version-gated.** Core requires
`GetCommonVersion() >= SENDHEADERS_VERSION = 70012`
(net_processing.cpp:5525). beamchain unconditionally sends sendheaders on
ready-enter — a peer that handshaked at version 70011 (rare but possible
with very old nodes) will receive a sendheaders it can't parse and may
disconnect us. Mitigated because our `?PROTOCOL_VERSION` is 70016, and we
use `min(theirs, ours)` for common version implicitly, but the
common-version computation is currently absent (peer_version is the
peer's claimed version, not the common version) — see also BUG-18.

**BUG-6 (MEDIUM)** — **feefilter periodic broadcast uses fixed
`?FEEFILTER_BROADCAST_INTERVAL_MS = 600000`.** Core uses
`AVG_FEEFILTER_BROADCAST_INTERVAL{10min}` as the **mean** of an
exponential distribution (`m_rng.rand_exp_duration`,
net_processing.cpp:5572). beamchain's `feefilter_poisson_interval`
(beamchain_peer.erl:1573) also samples from `-ln(U) * mean`, so the
distribution itself is correct — but the clamp at line 1577
(`max(1000, min(Interval, 1800000))`) introduces a hard floor at 1 s
and ceiling at 30 min that doesn't appear in Core (Core lets the
exponential tail go arbitrarily long). Cosmetic; behavior diverges
only on extreme tails.

**BUG-7 (MEDIUM)** — **feefilter "significant change" math.** Core:
`currentFilter < 3 * peer.m_fee_filter_sent / 4 || currentFilter > 4 *
peer.m_fee_filter_sent / 3` (net_processing.cpp:5577). beamchain:
`CurrentFee * 4 < SentFee * 3 orelse CurrentFee * 3 > SentFee * 4`
(beamchain_peer.erl:1588-1589). Algebraically equivalent (rearranged to
avoid the integer division), so this is just structural divergence — but
worth a forward-regression guard so a future refactor doesn't flip a
strict comparison and silently break the threshold.

**BUG-8 (MEDIUM)** — **feefilter not skipped for block-relay-only outbound
peers.** Core: `if (pto.IsBlockOnlyConn()) return;`
(net_processing.cpp:5548). beamchain has no concept of `IsBlockOnlyConn`
in the feefilter path — `maybe_send_initial_feefilter/1` only gates on
`peer_relay = true`, which is the **peer's** request not to receive tx
relay, not our outbound *direction* setting. Block-relay-only outbound
peers (the 2 anchor connections per `MAX_BLOCK_RELAY_ONLY`) will receive
feefilter announcements unnecessarily; harmless in correctness terms but
1.6× wasted bandwidth across the 10 outbound slots.

**BUG-9 (MEDIUM)** — **feefilter not skipped for ForceRelay permission.**
Core: `if (pto.HasPermission(NetPermissionFlags::ForceRelay)) return;`
(net_processing.cpp:5545). beamchain has no permission system →
ForceRelay-equivalent peers (operator-configured `-whitelist`,
`-forcerelay`) don't exist → no exemption is needed *yet*. If an
operator-permissions surface is added (covered separately under
W124 operator experience), this gate must follow.

**BUG-10 (MEDIUM)** — **feefilter MAX_MONEY-during-IBD signal absent.**
Core: while IBD, `currentFilter = MAX_MONEY` (net_processing.cpp:5552-5555),
forcing all peers to NOT send us tx invs while we're catching up.
beamchain just sends the current mempool min-fee regardless of IBD state.
Effect: during IBD, beamchain receives the normal full firehose of tx invs
from each connected peer, then has to drop them because the mempool isn't
processing tx during sync. Wasted inbound bandwidth (small but
nonzero — 1-2% of total IBD bytes).

**BUG-11 (MEDIUM)** — **No post-IBD feefilter recovery.** Core's
"if (peer.m_fee_filter_sent == MAX_FILTER) { next_send_feefilter = 0us; }"
branch (net_processing.cpp:5557-5562) forces an immediate re-broadcast
after IBD exit, so peers stop suppressing tx invs. Absent in beamchain
because there's no MAX_FILTER signal sent in the first place (BUG-10);
both must be fixed together.

**BUG-12 (MEDIUM)** — **feefilter received value not range-checked.**
Core: `if (MoneyRange(newFeeFilter)) { ... }`
(net_processing.cpp:5038-5043). beamchain accepts any 64-bit unsigned
integer value (beamchain_peer.erl:1522-1528) and stores it verbatim into
`fee_filter`. A peer sending `feefilter` with a value > MAX_MONEY
(2.1×10¹⁵ sat) would inject a nonsensical filter that, when applied via
`filter_by_feefilter` (line 1818), would filter out everything — silently
breaking tx relay to that peer. Effect is minor (only that one peer is
broken), but a strict-MoneyRange gate is a one-liner.

**BUG-13 (MEDIUM)** — **No `m_wtxid_relay_peers` global counter.** Core
maintains `std::atomic<int> m_wtxid_relay_peers{0}` (net_processing.cpp:837)
incremented on wtxidrelay accept (line 3931), decremented on peer DOWN
(line 1688). Surfaced via `getnetinfo`/`getpeerinfo` stats. beamchain
has no such counter. Cosmetic but observable: an operator can't
distinguish "10 peers, 3 wtxidrelay" from "10 peers, 9 wtxidrelay" via
RPC, which masks slow wtxidrelay-adoption rollouts on the network.

**BUG-14 (MEDIUM)** — **feefilter not surfaced via `build_info/1`.**
beamchain_peer.erl:1733-1752 (`build_info/1`) doesn't include
`fee_filter` (the value we received from the peer) in the returned map.
`getpeerinfo` therefore can't report the peer's minfeefilter. Core
exposes this via `CNodeStats::m_fee_filter_received` →
`getpeerinfo.minfeefilter`. Two-line addition; the data is already on
the gen_statem state record.

**BUG-15 (MEDIUM)** — **feefilter filter-by-feerate inv pipeline differs
from Core's vsize×feerate math.** Core does `if (txinfo.fee <
filterrate.GetFee(txinfo.vsize)) continue;` (net_processing.cpp:6013,
6071) — i.e. it compares the *absolute fee* of the tx against the
*minimum fee at the filter rate for that tx's vsize*. beamchain's
`tx_passes_feefilter` (beamchain_peer.erl:1828-1836) compares
`FeeRateKvB >= PeerFeeFilter` directly, which is *arithmetically*
equivalent for the standard sat/kvB units (vsize × sat/kvB / 1000 = abs
fee, and the rate ratio gives back the same inequality), but the
ordering differs: Core's compares totals, beamchain compares rates. The
divergence shows up only with rounding: a tx near the filter boundary
may round one way in Core and the other in beamchain. Sub-1-sat
divergence, but auditable.

### LOW (7)

**BUG-16 (LOW)** — **feefilter MAX_FEEFILTER_CHANGE_DELAY uses ms not
chrono::microseconds.** Style/units mismatch with Core; behaviour
equivalent at the 5-minute scale, but a future port-back to a faster
clock granularity would be confusing.

**BUG-17 (LOW)** — **No log when feefilter sent (only when received in
Core).** Core: `LogDebug(BCLog::NET, "received: feefilter of %s from peer=%d\n",
…)` (net_processing.cpp:5042). beamchain logs neither send nor receive —
operator debugging during fee market spikes is harder.

**BUG-18 (LOW)** — **`peer_version` is the peer's claimed version, not
the common version.** Core's `GetCommonVersion` returns `min(theirs,
ours)` and is the value gated against `SENDHEADERS_VERSION`,
`FEEFILTER_VERSION`, `WTXID_RELAY_VERSION`. beamchain's `peer_version`
field (beamchain_peer.erl:93) is just the value from the inbound version
message. When the peer's version is higher than ours (e.g. a future
peer at version 70017 talking to beamchain at 70016), the version-gated
features should be capped at the lower value. Currently irrelevant
because beamchain's `?PROTOCOL_VERSION = 70016` and the lowest
feature-gate is also 70012 — but if a future protocol version raises any
gate, the bug becomes operative.

**BUG-19 (LOW)** — **feefilter sendto peers with `peer_relay = false`.**
beamchain's `maybe_send_initial_feefilter/1`
(beamchain_peer.erl:1536-1545) gates on `Relay =:= true`, which is
correct *for the initial send*, but the periodic `check_feefilter`
timer (line 619) doesn't re-check `peer_relay`. If a peer changes its
relay preference mid-session via a filterclear or filteradd message
(BIP-37), beamchain will continue sending feefilters. Edge case.

**BUG-20 (LOW)** — **wtxidrelay sent before peer's version is fully
acknowledged.** Core: wtxidrelay is sent at line 3711 *after* the
peer's version is processed and `greatest_common_version` is computed.
beamchain sends wtxidrelay at beamchain_peer.erl:1374 in
`handle_version_msg` — but the check `peer_version V >= 70016` is at
line 1410 in the *sendtxrcncl* path, NOT around the wtxidrelay send.
Net effect: beamchain sends wtxidrelay even when the peer's version is
below 70016, which the peer should ignore — but spec-strict peers may
disconnect. The gate is missing.

**BUG-21 (LOW)** — **wtxidrelay duplicate-receive not logged.** Core
logs `"ignoring duplicate wtxidrelay from peer=%d\n"` on duplicate
(net_processing.cpp:3933). beamchain's set-to-true is idempotent so no
visible bug, but a misbehaving peer hammering the message is silent.

**BUG-22 (LOW)** — **No "after VERACK is protocol violation" comment in
beamchain dispatch.** Core ProcessMessage explicitly documents the
disconnect reason. beamchain just no-ops with no inline doc. Fix
overlaps with BUG-3 — adding the disconnect arm also lets us add the
comment.

---

## Universal patterns (cross-impl candidates)

1. **"feature negotiation flag default-true vs default-false"** —
   beamchain defaults `peer_relay = true` (beamchain_peer.erl:97),
   which matches Core's BIP-37 spec (the `fRelay` field defaults to
   true when absent from older peers). Several other impls have been
   audited to default `relay = false`, which silently breaks tx relay
   with old peers. Pattern: every relay-flag default must match Core.

2. **"after-VERACK message handling: silent-ignore vs disconnect"** —
   beamchain's three "before-VERACK" message handlers (wtxidrelay,
   sendaddrv2, sendtxrcncl) split on this: sendtxrcncl disconnects,
   the other two silently ignore. Core disconnects all three. Pattern:
   when adding new BIP-330-style feature negotiations, treat
   post-VERACK arrival as a hard error fleet-wide. Promotion candidate
   to W### universal pattern.

3. **"FeeFilterRounder as a privacy primitive"** — none of the
   currently-audited impls fully port the log-bucket quantization;
   most just clamp to a min and send the raw value. Pattern: fee-rate
   broadcasts on the gossip layer leak mempool fingerprint and deserve
   a fleet-wide audit gate for `lower_bound + ⅓ blur`. W136 is the
   first wave to surface this for beamchain; if other impls show the
   same gap, the pattern goes universal.

4. **"common version vs peer-claimed version"** — multiple
   feature-version gates (SENDHEADERS_VERSION, FEEFILTER_VERSION,
   WTXID_RELAY_VERSION) compare against `GetCommonVersion()` in Core,
   which is `min(theirs, ours)`. beamchain uses the peer's raw version
   from the version message. Latent for now because beamchain's local
   ?PROTOCOL_VERSION caps everything anyway, but a future protocol
   bump exposes the gap.
