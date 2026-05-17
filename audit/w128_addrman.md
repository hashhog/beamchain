# W128 — AddrMan / connman / peer selection audit (beamchain)

Discovery-only wave. 30 audit gates. Status counts:

- **PRESENT** (matches Core or is internally consistent and Core-compatible): 6
- **PARTIAL** (some semantics match, others don't): 5
- **MISSING** (no equivalent in beamchain): 19

Headline: **19 bugs** spanning the missing collision/test-before-evict
discipline, the absent IsTerrible/GetChance address-quality model, the
collapsed new/tried selection table that ignores Core's
ADDRMAN_BUCKET_SIZE position semantics, the missing
ADDRMAN_NEW_BUCKETS_PER_ADDRESS multiplicity, single-table banning that
ignores subnets/discouragement, the missing feeler connection class,
and the IP-only ban primitive that diverges from Core's
CSubNet-keyed banlist.

Audit asserts current divergent behaviour in
`test/beamchain_w128_addrman_tests.erl` so a follow-up FIX wave will
flip the symbolic assertions PASS → FAIL when production code is
brought into parity (the audit-flip convention used by FIX-65 / FIX-66
/ FIX-67 / W123 / W124 / W125).

EXCLUDES BIP-155 wire format (covered in W117) — this audit covers the
in-memory AddrMan, the connman outbound-selection pipeline, BanMan,
and inbound eviction.

Reference: `bitcoin-core/src/addrman.{cpp,h}`,
`bitcoin-core/src/addrman_impl.h`, `bitcoin-core/src/banman.{cpp,h}`,
`bitcoin-core/src/net.cpp`, `bitcoin-core/src/util/asmap.cpp`,
`bitcoin-core/src/protocol.h`.

---

## Gate index (1..30)

| #  | Name | Status | Core ref | beamchain ref |
|----|------|--------|----------|---------------|
| 1  | Bucket-count constants (NEW=1024, TRIED=256, BUCKET_SIZE=64) | PRESENT | addrman_impl.h:27-33 | beamchain_addrman.erl:47-49 |
| 2  | ADDRMAN_NEW_BUCKETS_PER_ADDRESS (=8) — single addr in up to 8 new buckets | MISSING | addrman.h:27, addrman.cpp:566 | beamchain_addrman.erl:53 (constant defined; never enforced) |
| 3  | Stochastic-test "2^N times harder" when nRefCount > 0 | MISSING | addrman.cpp:569-572 | beamchain_addrman.erl: AddSingle equivalent (`add_to_new`) increments ref but never multi-buckets |
| 4  | AddSingle routability filter (IsRoutable) | PRESENT | addrman.cpp:534 | beamchain_addrman.erl:497-534 (is_routable/2 covers IPv4/IPv6/Tor/I2P/CJDNS) |
| 5  | AddSingle time-penalty + currently_online update (`update_interval` 1h/24h) | MISSING | addrman.cpp:545-553 | beamchain_addrman.erl:551-559 (always overwrites timestamp; no penalty applied) |
| 6  | AddSingle service-flag OR-merge on update | MISSING | addrman.cpp:554 | beamchain_addrman.erl: services updated only on fresh insert |
| 7  | AddSingle "do not update if entry was in tried" early return | PARTIAL | addrman.cpp:561-563 | beamchain_addrman.erl:552-555 (only touches timestamp) |
| 8  | Bucket-position collision resolution (existing-terrible OR refcount asymmetry → overwrite) | MISSING | addrman.cpp:582-602 | beamchain_addrman.erl:589-608 (uses HORIZON_SECS instead of IsTerrible) |
| 9  | IsTerrible model (5 conditions: m_last_try<1min, nTime>now+10min, age>HORIZON, no-success-and-retries, MAX_FAILURES-in-MIN_FAIL) | MISSING | addrman.cpp:49-72 | beamchain_addrman.erl: only HORIZON age is checked; the other 4 conditions are absent |
| 10 | GetChance scoring (last_try<10min ×0.01, 0.66^min(attempts,8)) | MISSING | addrman.cpp:74-87 | beamchain_addrman.erl: Select uses uniform random over buckets, no GetChance weighting |
| 11 | Select_ search loop with chance_factor=1.2× growth | MISSING | addrman.cpp:732-772 | beamchain_addrman.erl:781-809 (uniform random; no chance loop, no chance_factor) |
| 12 | Select_ tried/new 50%-each toggle | PARTIAL | addrman.cpp:719-728 | beamchain_addrman.erl:755-757 (uses 70/30 hard-coded; Core picks 50/50 with rand_bool) |
| 13 | Select_(new_only=true) restriction | PARTIAL | addrman.cpp:715-723 | beamchain_addrman.erl:753-762 (honours new_only flag) |
| 14 | Select_(networks filter) — restrict to set of Network types | MISSING | addrman.cpp:702-714 | beamchain_addrman.erl:do_select_address has no network-filter option |
| 15 | m_tried_collisions set + ADDRMAN_SET_TRIED_COLLISION_SIZE=10 cap | MISSING | addrman.cpp:639-650, addrman.h:39 | beamchain_addrman.erl: Good_ equivalent (`mark_tried`) unconditionally evicts — no collision queue |
| 16 | Good(test_before_evict=true) discipline | MISSING | addrman.cpp:606-659 | beamchain_addrman.erl:641-700 (single mode: unconditional evict via `evict_tried_to_new`) |
| 17 | ResolveCollisions / SelectTriedCollision feeler-driven resolve | MISSING | addrman.cpp:892-981 | beamchain_addrman.erl: not implemented |
| 18 | Attempt() with fCountFailure + m_last_count_attempt < m_last_good gate | MISSING | addrman.cpp:673-691 | beamchain_addrman.erl:731-742 (`mark_failed` always increments attempts; no rate-limit) |
| 19 | m_last_good tracking (initial=1s sentinel) | MISSING | addrman_impl.h:215, addrman.cpp:612 | beamchain_addrman.erl: m_last_good is not tracked |
| 20 | Connected() update with 20-min `update_interval` (avoid leak) | MISSING | addrman.cpp:857-874 | beamchain_addrman.erl: no Connected() entrypoint (mark_tried sets timestamp, also leaks) |
| 21 | GetAddr() filter for IsTerrible + max_pct + random walk with SwapRandom | PARTIAL | addrman.cpp:792-831 | beamchain_addrman.erl:811-843 (collects all, shuffles via `shuffle/1`; no IsTerrible filter, no max_pct) |
| 22 | SetServices() entry-point | MISSING | addrman.cpp:876-890 | beamchain_addrman.erl: not implemented |
| 23 | FEELER connection class + next_feeler ~ exp(FEELER_INTERVAL=2min) | MISSING | net.cpp:2565, 2753-2756, net.h:61 | beamchain_peer_manager.erl: no feeler class at all |
| 24 | EXTRA_BLOCK_RELAY_ONLY + EXTRA_NETWORK_PEER schedule | MISSING | net.cpp:2566-2567, 2729-2767 | beamchain_peer_manager.erl: not implemented |
| 25 | Outbound netgroup-diversity check (one outbound per /16 or ASN) | PRESENT | net.cpp:2664-2691, 2830-2832 | beamchain_peer_manager.erl:1191-1194 (has_netgroup_diversity, asmap-aware) |
| 26 | Anchor connections: 2 block-relay peers persisted across restarts | PRESENT | net.cpp:57, 3496-3497, 3651-3652 | beamchain_peer_manager.erl:98, 1006-1063 |
| 27 | Inbound eviction: 4-stage protection (netgroup, ping, tx-time, block-time) + evict-from-largest-netgroup | PARTIAL | net.cpp:1689-1736, eviction.cpp | beamchain_peer_manager.erl:1243-1353 (4 stages PRESENT, but no protect-by-relevant-services, no prefer_evict flag, no NoBan exemption applied to eviction candidates) |
| 28 | BanMan: subnet-keyed banlist (CSubNet) | MISSING | banman.h:63-99, banman.cpp:118-122 | beamchain_peer_manager.erl:1929-1949 (IP-keyed only via ETS, no subnet support — setban with CIDR is ignored) |
| 29 | BanMan: separate discouragement bloom filter (CRollingBloomFilter, 50k, p=1e-6) | MISSING | banman.h:98, banman.cpp:83-87, 124-128 | beamchain_peer_manager.erl: bans and discouragement collapsed into one ETS table; no bloom filter |
| 30 | BanMan: ban-list periodic dump (DUMP_BANS_INTERVAL=15min) + load-then-dump on startup | PARTIAL | banman.h:22, banman.cpp:17-22, 48-70 | beamchain_peer_manager.erl:1975-2015 (saves on every set_ban call; no periodic dump timer; load-on-startup ok) |

---

## Bug catalogue (19 BUGs)

### BUG-1 (P0-CDIV) — `ADDRMAN_NEW_BUCKETS_PER_ADDRESS` defined but never enforced

`beamchain_addrman.erl:53` defines `?NEW_BUCKETS_PER_ADDRESS` = 8 but
the constant is never referenced anywhere else in the file. Core's
AddSingle (`addrman.cpp:566-572`) limits an entry to at most 8 new
buckets *and* applies a 2^N stochastic test to make each additional
bucket exponentially harder to fill. Beamchain only ever places an
address in **one** new bucket (whichever `get_new_bucket` returns for
the first source). When the same address is received from N different
sources, beamchain updates the timestamp on the existing entry and
re-uses the same bucket, while Core spreads the entry across up to 8
buckets to bias selection toward addresses heard from many distinct
sources.

**Concrete consequence**: eclipse-attack mitigation is weaker than
Core. Frequently-heard addresses get the same selection weight as
once-heard ones, so an attacker can fill bucket slots evenly with
once-heard Sybil addresses without competing against any
high-multiplicity honest entries.

### BUG-2 (P0-CDIV) — `IsTerrible` model absent

Core (`addrman.cpp:49-72`) marks an address terrible when ANY of:

1. `m_last_try` ≤ 1 min ago (don't remove just-tried entries),
2. `nTime > now + 10 min` (future-dated, came in a flying DeLorean),
3. `now - nTime > ADDRMAN_HORIZON` (older than 30 days),
4. `m_last_success == 0` AND `nAttempts ≥ ADDRMAN_RETRIES` (=3 tries
   never succeeded),
5. `now - m_last_success > ADDRMAN_MIN_FAIL` (=7 days) AND
   `nAttempts ≥ ADDRMAN_MAX_FAILURES` (=10).

Beamchain only checks (3) — the HORIZON age cutoff
(`beamchain_addrman.erl:593`). Conditions (1), (2), (4), (5) are
**absent**: an address that has failed 100 times in a row is still
considered fresh by beamchain. Selection oversamples dead addresses,
slowing outbound bring-up after a long offline period.

### BUG-3 (P0-CDIV) — `GetChance` weighting absent

Core (`addrman.cpp:74-87`) applies a per-address chance factor to
Select_:

- `if now - m_last_try < 10min: chance *= 0.01`,
- `chance *= 0.66 ^ min(nAttempts, 8)`.

Beamchain's `select_random_bucket_entry/5` performs uniform random
sampling over buckets with the only filter being the
`MIN_RETRY_INTERVAL = 60` seconds guard. There is no exponential
deprioritisation of failed addresses, and no 0.01 squelch on
just-tried entries. The downstream `chance_factor *= 1.2` retry
boost (`addrman.cpp:771`) is also absent — beamchain doesn't have a
chance-driven search loop at all.

### BUG-4 (P0-CDIV) — `m_tried_collisions` set + test-before-evict missing

Core's `Good_(addr, test_before_evict=true, time)` will NOT immediately
evict the existing tried-bucket occupant. Instead it queues the new
collision into `m_tried_collisions` (capped at
`ADDRMAN_SET_TRIED_COLLISION_SIZE = 10`), and `SelectTriedCollision()`
later returns the collision to the connman so it can feeler-test the
**old** entry. Only if the old entry is unreachable for >40 min
(`ADDRMAN_TEST_WINDOW`) or hasn't connected in 4h (`ADDRMAN_REPLACEMENT`)
does `ResolveCollisions_()` actually evict it.

Beamchain's `do_mark_tried` (`beamchain_addrman.erl:641-700`) does the
opposite: ANY collision in the tried bucket-slot is resolved by
**immediately** evicting the old entry to new
(`evict_tried_to_new/6`). This eliminates the eviction-protection
property that test-before-evict was designed to give — a single
successful connection to a Sybil is sufficient to displace a
well-known honest entry from the tried table.

### BUG-5 (P0-CDIV) — `ResolveCollisions` / `SelectTriedCollision` not implemented

Direct consequence of BUG-4. Because there is no collision queue,
there is no resolve path either. Feeler-driven test-before-evict
cannot exist (also see BUG-13). The two API entrypoints
(`AddrMan::ResolveCollisions`, `AddrMan::SelectTriedCollision`) are
unreachable in beamchain.

### BUG-6 (P0-CDIV) — `Attempt()` rate-limit + `m_last_good` gate absent

Core's `Attempt_(addr, fCountFailure, time)` increments `nAttempts`
**only when** `fCountFailure` is true AND `m_last_count_attempt <
m_last_good` (`addrman.cpp:687-690`). This rate-limits failure
counting so a brief outage doesn't immediately push an address past
`ADDRMAN_MAX_FAILURES`. It also guarantees that a stretch of failures
between two successful connections counts as at most one increment.

Beamchain's `do_mark_failed` (`beamchain_addrman.erl:731-742`)
unconditionally increments `attempts` on every failed connect, with
no rate-limit and no `m_last_good` (which beamchain doesn't track —
see BUG-7). After 10 retries on a temporarily-down peer beamchain
will mark it permanently failed (when BUG-2 is fixed), whereas Core
would only have logged 1-3 increments over the same window.

### BUG-7 (P0-CDIV) — `m_last_good` not tracked

Direct dependency of BUG-6. Core stores `m_last_good` at the
addrman level (initial value = 1s — strictly worse than "never" so
the `<` test in BUG-6 fires on first Attempt;
`addrman_impl.h:215`). Beamchain has no such field. Beyond the
Attempt rate-limit, this also means beamchain can't decide whether
to run the collision-resolve path in BUG-5's window
(`current_time - info_new.m_last_success > ADDRMAN_TEST_WINDOW`).

### BUG-8 (P0-CDIV) — `Connected()` 20-min `update_interval` missing

Core's `Connected_(addr, time)` updates `nTime` **only if** at least
20 minutes have passed since the last update
(`addrman.cpp:857-874`). The 20-min interval is a privacy guard:
publishing a finer-grained `nTime` in subsequent ADDR gossip would
leak the current connection time of every peer, helping topology
mapping.

Beamchain has no `Connected()` entrypoint at all. Successful
connection updates `last_success = Now` (`mark_tried`) and the same
field is used by GetAddr to populate the gossip `timestamp` field
— meaning every restart of a peer announces its current online time
to the network. This is a moderate topology-leak.

### BUG-9 (P0-CDIV) — `Select_(networks)` filter missing

Core supports filtering by network (`addrman.cpp:702-714,
732-754`) so the connman can request "give me a tried peer on Tor"
to drive its `MaybePickPreferredNetwork` extra-outbound logic.
Beamchain's `do_select_address` takes only `new_only` — there is no
way to request a Tor-or-I2P address specifically, so the cross-
network diversity logic (Core net.cpp:2825-2828) cannot work even
if it were ported.

### BUG-10 (P0-CDIV) — Bucket-position collision uses wrong "terrible" criterion

`add_to_new` (`beamchain_addrman.erl:589-608`) decides whether to
evict an existing bucket-slot occupant based on
`(Now - OldTime) > ?HORIZON_SECS` — i.e. only one of IsTerrible's
five conditions. Core's `AddSingle` decides based on
`infoExisting.IsTerrible() || (infoExisting.nRefCount > 1 &&
pinfo->nRefCount == 0)` (`addrman.cpp:584-588`). The second clause
("displaceable iff existing has higher multiplicity") is **not
checked** in beamchain because beamchain doesn't track multiplicity
at all (BUG-1). The first clause is partially checked (only the
HORIZON branch — BUG-2).

### BUG-11 (P0-CDIV) — AddSingle time-penalty + currently-online update intervals missing

Core (`addrman.cpp:545-553`) updates `nTime` with:

```cpp
const bool currently_online{NodeClock::now() - addr.nTime < 24h};
const auto update_interval{currently_online ? 1h : 24h};
if (pinfo->nTime < addr.nTime - update_interval - time_penalty) {
    pinfo->nTime = std::max(NodeSeconds{0s}, addr.nTime - time_penalty);
}
```

Beamchain unconditionally overwrites `timestamp = Now`
(`beamchain_addrman.erl:554`) on every duplicate add, ignoring both
the `time_penalty` argument (which is dropped entirely) and the
update-interval gating. This means:

1. An ADDR-gossiped peer with a stale 7-day-old `nTime` gets its
   freshness reset to "right now" the moment beamchain hears about
   it, defeating the purpose of `nTime` as an "approximate last-time-
   seen-online" hint.
2. The `time_penalty` propagation path (Core: 2-hour penalty for
   forwarded-ADDR vs 0 for self-announce) is dead code: callers can't
   express the distinction.

### BUG-12 (P0-CDIV) — AddSingle service-flag OR-merge missing

Core (`addrman.cpp:554`) OR-merges incoming `addr.nServices` into the
existing entry. Beamchain only writes `services` on initial insert
(`beamchain_addrman.erl:614`); subsequent ADDR messages from peers
that *did* learn newer services bits never propagate them onto
beamchain's entry. NODE_COMPACT_FILTERS, NODE_P2P_V2, etc. learned
later don't take effect for selection that filters on services
(beamchain doesn't filter on services for selection at all — see
BUG-9 and BUG-15 — but the propagation gap is independent).

### BUG-13 (P0-CDIV) — FEELER connection class absent

Core opens 1 FEELER connection per `FEELER_INTERVAL = 2min` (with
exponentially-distributed jitter) to drive the test-before-evict
discipline of BUG-4/BUG-5. The feeler:

1. First calls `SelectTriedCollision()` to test the to-be-evicted
   peer for a queued collision (`net.cpp:2801-2809`);
2. If no collision queued, calls `Select(true, reachable_nets)` to
   get a new-table peer and probe it;
3. Either way, the connection is closed after handshake.

Beamchain only opens OUTBOUND_FULL_RELAY (8) + BLOCK_RELAY (2)
connection types (`beamchain_peer_manager.erl:1099-1108`). There is
no feeler timer, no feeler connect path, no feeler disconnect-on-
verack. Consequence: the only way addresses move new → tried in
beamchain is via outbound dialling, which is itself rate-limited by
the existing FULL_RELAY slot count.

### BUG-14 (P0-CDIV) — Stale-tip extra-outbound logic missing

Core's `GetTryNewOutboundPeer()` + `EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL`
(`net.cpp:2727-2767`) opens an extra outbound peer temporarily when
the tip is stale, and another extra block-relay-only peer
periodically to detect "I'm being eclipsed". Beamchain has stale-tip
detection (`beamchain_peer_manager.erl:2456-2505`) but the response
is **eviction** of a stale outbound, not opening an additional
outbound peer. Core's anti-eclipse safety net (extra peer to confirm
the tip is current) is therefore absent.

### BUG-15 (P0-CDIV) — `MaybePickPreferredNetwork` / per-network outbound floor missing

Core's `EXTRA_NETWORK_PEER_INTERVAL`-driven `MaybePickPreferredNetwork`
(`net.cpp:2757-2767`) ensures at least one outbound peer from each
reachable network (IPv4, IPv6, Tor, I2P, CJDNS), making it harder for
a single-network attacker to monopolise outbound slots. Beamchain has
network-type tracking on peer_entry (`network_type`) and applies it
during stale eviction (`get_protected_networks/1`), but never *opens*
a connection specifically to fill an underrepresented network.
Cross-impl: rustoshi + ouroboros have the same gap, blockbrew does
not.

### BUG-16 (P1-COMPAT) — BanMan: subnet (CSubNet) ban primitive missing

Core's `BanMan::Ban(CSubNet, …)` (`banman.cpp:130-154`) accepts an
arbitrary CIDR subnet as the ban key, and `IsBanned` walks the banlist
checking `sub_net.Match(net_addr)` for each entry
(`banman.cpp:89-102`). Beamchain's banlist is a flat
`{IP, BanExpiry}` ETS table keyed on the host-order tuple
(`beamchain_peer_manager.erl:1936-1949`). The `setban` RPC handler at
`beamchain_rpc.erl:3631+` (per W125 BUG-7) emits -8 for CIDR
arguments because it parses `inet:parse_address` only. Effectively,
`setban 10.0.0.0/8 add` is silently impossible.

### BUG-17 (P1-COMPAT) — BanMan: discouragement bloom filter missing

Core's BanMan stores **two** structures: `m_banned` (subnet-keyed,
hard rejection) and `m_discouraged` (CRollingBloomFilter, 50k entries,
1e-6 false-positive rate; `banman.h:98`). A discouraged peer is
allowed to connect inbound when slots are available but is
preferentially evicted when the inbound table is near capacity
(`banman.cpp:83-87, 124-128, net.cpp:1812-1818`). Beamchain collapses
the two into a single ETS ban table — there is no
"prefer-to-evict-but-still-accept" tier. As a result:

1. Misbehaving peers are immediately full-banned for 24h
   (`handle_misbehaving/4` line 2077-2083) where Core would only
   discourage them.
2. The bloom filter's intentional probabilistic forgetting (banlist
   bound at ~50k entries with rolling decay) is replaced by an
   unbounded ETS table — a long-running node sees the ban-table grow
   without bound until the `cleanup_expired_bans` 60-second sweep
   runs. See also W117 disclose-unbounded-banlist follow-up notice
   referenced in `banman.h:58-62`.

### BUG-18 (P1-COMPAT) — Inbound-eviction missing relevant-services + prefer-evict + NoBan exemption

Core's `AttemptToEvictConnection` (`net.cpp:1689-1736`) builds the
candidate list with **all** of:
`fRelevantServices`, `m_relay_txs`, `fBloomFilter`, `m_is_local`,
`m_noban`, `m_conn_type`, `prefer_evict`
(`net.cpp:1698-1713`).

Beamchain's `select_eviction_victim/1`
(`beamchain_peer_manager.erl:1260-1280`) feeds **only** four fields
(`keyed_netgroup`, `min_ping_time`, `last_tx_time`,
`last_block_time`) into the 4-stage protection. The missing pieces:

1. No protect-by-relevant-services (Core protects up to 8 peers
   whose `fRelevantServices` flag is set in addition to the 4-stage
   stack).
2. No protect-by-NoBan (whitelisted peers can be evicted by
   beamchain).
3. No `prefer_evict` flag (Core's "discourage now, evict on next
   inbound burst" tier — see BUG-17).
4. No `m_is_local` priority handling (localhost peers can be evicted
   by beamchain when they shouldn't).

### BUG-19 (P1-COMPAT) — BanMan periodic dump timer missing

Core dumps the banlist to disk every `DUMP_BANS_INTERVAL = 15min`
(`banman.h:22, banman.cpp:21-22`). Beamchain saves on every
`set_ban` / `handle_misbehaving` call (`save_bans(DataDir)` at
`beamchain_peer_manager.erl:2078, 2082, …`) but has no periodic
dump timer. Consequence: a flurry of misbehaviour events causes
N×JSON writes within a second (each `handle_misbehaving` writes the
whole banlist). Both correctness (eventual-disk-consistency) and
cost (N×fsync) diverge from Core.

---

## Universal patterns observed during this audit

1. **"audit-framework boundary clarity"** — three categories of
   AddrMan parity gap surfaced cleanly:
   (a) constants defined but unenforced (BUG-1: NEW_BUCKETS_PER_ADDRESS),
   (b) APIs missing entirely (BUG-5: ResolveCollisions),
   (c) APIs present but semantically simpler (BUG-10: collision check
   uses HORIZON_SECS instead of IsTerrible). Each shape will require
   a different FIX-wave class.

2. **"banman + addrman are entangled by design"** — Core deliberately
   keeps them separate (banman.h:28-46 explains the
   discouragement/banning distinction). Beamchain's collapse into a
   single ETS table is the root of BUG-16 AND BUG-17 AND BUG-19.
   Any FIX wave that closes one will benefit from closing all three
   together rather than one-by-one.

3. **"feeler-class absent ⇒ collision-resolve absent ⇒
   test-before-evict absent"** chain — BUG-13 ⇒ BUG-5 ⇒ BUG-4. FIX
   wave for BUG-4 must precede or co-land with BUG-13's feeler-class
   addition; otherwise the collision queue can never be drained.
