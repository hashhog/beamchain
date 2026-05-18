# W134 — BIP-37 Bloom filter (legacy SPV) audit (beamchain)

Discovery-only wave. 30 audit gates against Core's legacy bloom-filter SPV
subsystem.

Reference:
- `bitcoin-core/src/common/bloom.{h,cpp}` — `CBloomFilter` (130 LOC), the
  filter constructor + `Hash` + `insert` + `contains` +
  `IsWithinSizeConstraints` + `IsRelevantAndUpdate`.
- `bitcoin-core/src/merkleblock.{h,cpp}` — `CPartialMerkleTree` +
  `CMerkleBlock` (≈230 LOC) used to serve `MSG_FILTERED_BLOCK` getdata
  requests as a header + matched-txid proof tree.
- `bitcoin-core/src/net_processing.cpp:4963-5033` — `FILTERLOAD` /
  `FILTERADD` / `FILTERCLEAR` handlers (with their NODE_BLOOM gate and
  `Misbehaving` calls).
- `bitcoin-core/src/net_processing.cpp:2438-2459` — `MSG_FILTERED_BLOCK`
  getdata branch that builds a `CMerkleBlock` from the peer's filter and
  pushes the matched txns too.
- `bitcoin-core/src/init.cpp:572,1104-1105` — `-peerbloomfilters`
  CLI flag wires `NODE_BLOOM` into `g_local_services`.
- `bitcoin-core/src/net_processing.h:44` — `DEFAULT_PEERBLOOMFILTERS = false`.

BIPs: 37 (filterload/filteradd/filterclear/merkleblock + bloomflags +
NODE_BLOOM), 111 (NODE_BLOOM service bit allocation + disconnect-on-pre-70011).

Companion audits cross-referenced:
- **W110** — first BIP-37 audit on beamchain (18 bugs / 30 gates,
  `13559f4` 2026-04-25). Verdict was "MISSING ENTIRELY (19/30) + PARTIAL
  (11/30) — no `beamchain_bloom.erl`, no MurmurHash3, no codec for
  filter*/merkleblock, no handler in peer_manager." Since then two
  trivial fixes landed (`95ddaea` peerbloomfilters default-false,
  `1bb22fb` NODE_BLOOM advertisement gate). The core subsystem is
  unchanged — every BUG in W110 still applies.
- **W117** — BIP-155 BIP-324 cross-cutting wave. Confirmed
  `beamchain_v2_msg.erl:36-38` registers `filteradd` / `filterclear` /
  `filterload` in the BIP-324 short-id table but no wire codec or
  handler exists; W117 left the gap open as out-of-scope.
- **W116** — Package relay + bloom interaction. None — package relay
  serves listeners on the *unfiltered* relay path, so no interaction
  with the bloom subsystem.
- **W121** — BIP-157 compact-filter index P2P (the modern privacy-preserving
  successor to BIP-37). Demonstrated the *correct* pattern for a P2P
  filter subsystem in beamchain (codec in `beamchain_p2p_msg.erl`,
  handler in `beamchain_peer_manager.erl`, per-peer protocol-violation
  → disconnect gate). W134 measures BIP-37 against the same yardstick;
  BIP-37 sits on the opposite end (still missing entirely).

## Status counts (30 gates)

- **PRESENT** (matches Core or internally consistent + Core-compatible): 0
- **PARTIAL** (some piece matches, others diverge or are simplified): 3
- **MISSING** (no equivalent in beamchain): 27

Headline: **22 bugs**, severity distribution **0 CDIV / 9 HIGH / 9 MEDIUM /
4 LOW**. BIP-37 is **non-consensus**: a missing or buggy bloom filter
cannot fork the chain, only break legacy SPV peers that connect to
beamchain expecting `filterload` / `merkleblock` service. The cluster
nonetheless matters for operator-experience and interop. The most
consequential findings:

1. **BUG-1 (HIGH)** — **No `beamchain_bloom` module.** The entire
   `CBloomFilter` class is absent. `MAX_BLOOM_FILTER_SIZE = 36000`,
   `MAX_HASH_FUNCS = 50`, `LN2SQUARED` (full 52-digit precision), the
   constructor sizing formula `vData.size() = min(-1/LN2SQUARED * N *
   ln(fp), MAX_BLOOM_FILTER_SIZE*8) / 8`, `nHashFuncs =
   min(vData.size()*8/N * LN2, MAX_HASH_FUNCS)`, the
   `nHashNum * 0xFBA4C795 + nTweak` MurmurHash3 schedule, the bit-set
   operations, `insert` / `contains`, `IsWithinSizeConstraints`, and
   `IsRelevantAndUpdate` — all absent. No file under
   `apps/beamchain/src/` or `src/` named `beamchain_bloom*` exists; no
   inline implementation either. Gates G1..G24 and G29 are MISSING
   ENTIRELY because there is no module to host them.

2. **BUG-2 (HIGH)** — **No MurmurHash3 (x86_32) anywhere in the
   codebase.** Core's `hash.cpp:13-65` implements MurmurHash3 with
   seed-based mixing; the standard SMHasher test vectors are:
   `MurmurHash3(seed=0, <<>>) = 0`,
   `MurmurHash3(seed=0, <<0>>) = 0x514E28B7`,
   `MurmurHash3(seed=1, <<0>>) = 0xEA3F7AFF`. beamchain has
   crypto-hash primitives (`beamchain_crypto`) and SipHash for short-id
   compact-blocks, but no MurmurHash3. Without MurmurHash3 the bloom
   filter cannot be implemented at all (G6).

3. **BUG-3 (HIGH)** — **No `filterload` / `filteradd` / `filterclear`
   in the wire codec.** `beamchain_p2p_msg.erl` `command_name/1` (lines
   80-117) and `command_atom/1` (lines 120-157) handle 35 message types
   ranging from `version` to `cfcheckpt`. None of them is
   `filterload`, `filteradd`, `filterclear`, or `merkleblock`. An
   incoming `filterload` message has its 12-byte command name (e.g.
   `<<"filterload\0\0">>`) unpadded and passed through `command_atom`,
   which falls through to the `Other` catch-all and produces the atom
   `filterload` via `binary_to_atom(Other, utf8)`. The message is then
   dispatched to `handle_peer_message(_Pid, filterload, _Payload,
   State)`. There is no such clause; it lands on the `(_Pid, _Command,
   _Payload, State)` catch-all at `beamchain_peer_manager.erl:1500-1501`
   and is silently dropped. Returned: no response, no disconnect, no
   `Misbehaving`, no log line above debug.

4. **BUG-4 (HIGH)** — **No `merkleblock` getdata response.** Core's
   getdata handler at `net_processing.cpp:2438-2459` branches on
   `inv.IsMsgFilteredBlk()` (inv type 3 = `MSG_FILTERED_BLOCK`) and
   constructs a `CMerkleBlock(*pblock, *tx_relay->m_bloom_filter)`,
   sending it followed by the matched txns. beamchain's
   `handle_getdata_msg` (`beamchain_peer_manager.erl:1733-1801`) only
   branches on `MSG_BLOCK` / `MSG_WITNESS_BLOCK` (line 1752) and
   `MSG_TX` / `MSG_WITNESS_TX` (line 1782); `MSG_FILTERED_BLOCK = 3`
   (defined in `beamchain_protocol.hrl:118`) falls into the `_ ->`
   wildcard (line 1790) which adds the request to the `notfound` list.
   Legacy SPV clients see `notfound` and either disconnect or fall back
   to full blocks.

5. **BUG-5 (HIGH)** — **`CMerkleBlock` / `CPartialMerkleTree` not
   reachable from P2P.** beamchain *does* have the partial-merkle-tree
   algorithm implemented as `w47b_traverse_and_build` /
   `w47b_traverse_and_extract` in `beamchain_rpc.erl:8088-8217` (the
   reference at `beamchain_rpc.erl:9384` confirms the comment block
   attributing it to "TraverseAndExtract from src/merkleblock.cpp").
   That code is wired to **only** the `gettxoutproof` /
   `verifytxoutproof` RPC entry points. It is *not* connected to the
   getdata `MSG_FILTERED_BLOCK` path (which doesn't exist; see BUG-4),
   and it is *not* connected to a `filterload`-driven filter (which
   doesn't exist; see BUG-3). This is the classic two-pipeline / dead
   helper pattern: the algorithm exists but for a different consumer.
   Fixing BIP-37 means **either** lifting `w47b_traverse_and_*` into
   a shared module **or** writing a parallel implementation in a new
   `beamchain_merkleblock` module that consumes a `beamchain_bloom`
   filter (which also doesn't exist; see BUG-1).

6. **BUG-6 (HIGH)** — **No per-peer bloom-filter state.**
   `beamchain_peer.erl:82-131` defines `#peer_data{}` with 30+ fields
   (handshake flags, peer info, BIP-339 wtxidrelay, BIP-330 erlay,
   stats, trickle, feefilter, …) but **nothing** equivalent to Core's
   `TxRelay::m_bloom_filter` (`unique_ptr<CBloomFilter>` at
   `net_processing.cpp:297`). Even if BUG-3 were fixed and the
   filterload message reached a handler, there is nowhere to store the
   per-peer filter. By extension, no `m_relay_txs` / `m_bloom_filter_loaded`
   flags exist either (Core sets both on filterload/filterclear, line
   4980-4982 and 5027-5030); beamchain's `peer_relay` exists but never
   transitions through the filterload state-machine.

7. **BUG-7 (HIGH)** — **No NODE_BLOOM disconnect-gate on incoming
   filter messages.** Core's `net_processing.cpp:4964-4968` (and the
   parallel filteradd / filterclear gates at 4989-4992 / 5017-5019)
   disconnects a peer that sends `filterload` while NODE_BLOOM is NOT
   advertised in `peer.m_our_services`. The relevant lines:
   ```
   if (!(peer.m_our_services & NODE_BLOOM)) {
       LogDebug(BCLog::NET, "filterload received despite not offering
                            bloom services, %s", pfrom.DisconnectMsg());
       pfrom.fDisconnect = true;
       return;
   }
   ```
   beamchain has no handler at all; even after the operator runs with
   `-peerbloomfilters=0` (W110's `95ddaea` made that the default) the
   peer that *still* tries to send filterload is silently ignored
   rather than disconnected. From the peer's perspective this looks
   like a node that accepts the filter and then never sends a
   merkleblock — pathological for any peer-rotation logic.

8. **BUG-8 (HIGH)** — **No `IsWithinSizeConstraints` enforcement on
   filterload.** Even if BUG-3 were partially fixed (decode filterload
   into a map and store it somewhere), an oversized filter
   (>36000 bytes) must trigger `Misbehaving(peer, "too-large bloom
   filter")` — Core `net_processing.cpp:4972-4975`. With no handler,
   this DoS check never runs. An attacker who learns that beamchain
   advertises NODE_BLOOM but ignores the filter could still spam
   the recv buffer with 4-MB filterload payloads (the protocol-message
   ceiling) before disconnect. Misbehavior tracking would have
   credited the wrong peer with zero score.

9. **BUG-9 (HIGH)** — **No `MAX_SCRIPT_ELEMENT_SIZE = 520` enforcement
   on filteradd.** Core's filteradd handler at `net_processing.cpp:5000`
   calls `Misbehaving(peer, "bad filteradd message")` if the appended
   data element is larger than `MAX_SCRIPT_ELEMENT_SIZE` (520 bytes —
   defined in `beamchain_protocol.hrl:43` ✓). Again, no handler in
   beamchain means no check; even larger items go unnoticed.

The remaining 13 bugs cover: missing `bloomflags` enum (BUG-10),
missing `0xFBA4C795` constant (BUG-11), missing outpoint serialization
for filter insertion (BUG-12), `IsRelevantAndUpdate` logic absent
(BUG-13 thru BUG-17 — txid match, output pushdata scan, output type
detection for UPDATE_P2PUBKEY_ONLY, outpoint match, scriptSig data
scan), `CMerkleBlock(block, filter)` constructor absent (BUG-18),
post-filter txid pushback for matched txns absent (BUG-19), filterclear
re-enables m_relay_txs to true (BUG-20), `m_bloom_filter_loaded` flag
on Peer (BUG-21) and `m_relays_txs` flag (BUG-22). None affects
consensus.

**Not a CDIV** — every bug below is non-consensus: beamchain validates
incoming blocks identically with or without bloom filters; bloom only
affects what beamchain *serves* to its legacy-SPV peers. The
disposition is: legacy SPV peers see beamchain as a "node that
advertises NODE_NETWORK but ignores filterload" — effectively useless
for BIP-37 wallets and likely to be disconnected by Electrum / older
mobile wallets after a getdata-without-merkleblock-response timeout.

The audit-flip convention applies: every test that asserts a divergent
fact (e.g. "no filterload codec") is written so it **passes today** and
**will fail when the fix lands**, flipping the gate from MISSING/BUG → PRESENT.

---

## Gate index (1..30)

| #  | Name | Status | Core ref | beamchain ref |
|----|------|--------|----------|---------------|
| 1  | `MAX_BLOOM_FILTER_SIZE = 36000`                                          | MISSING | bloom.h:17                              | absent; no beamchain_bloom module |
| 2  | `MAX_HASH_FUNCS = 50`                                                    | MISSING | bloom.h:18                              | absent |
| 3  | `LN2SQUARED = 0.4804530139182014246671025263266649717305529515945455`     | MISSING | bloom.cpp:23                            | absent |
| 4  | Constructor sizing formula `min(-1/LN2SQ * N * ln(fp), MAX*8)/8`         | MISSING | bloom.cpp:32                            | absent |
| 5  | `nHashFuncs = min(vData*8/N * LN2, MAX_HASH_FUNCS)`                      | MISSING | bloom.cpp:38                            | absent |
| 6  | MurmurHash3 (x86_32) primitive                                           | MISSING | hash.cpp:13-65                          | not implemented anywhere |
| 7  | Hash schedule `nHashNum * 0xFBA4C795 + nTweak`                           | MISSING | bloom.cpp:47                            | constant 0xFBA4C795 absent |
| 8  | Bit-index `vData[h>>3] |= 1 << (7 & h)`                                  | MISSING | bloom.cpp:57-58, 77                     | absent |
| 9  | `insert` + `contains` round-trip                                         | MISSING | bloom.cpp:50-81                         | absent |
| 10 | `isFull` / `vData.empty()` CVE-2013-5700 guard                           | MISSING | bloom.cpp:52, 71, 100                   | absent |
| 11 | `BLOOM_UPDATE_NONE = 0`                                                  | MISSING | bloom.h:26                              | absent |
| 12 | `BLOOM_UPDATE_ALL = 1`                                                   | MISSING | bloom.h:27                              | absent |
| 13 | `BLOOM_UPDATE_P2PUBKEY_ONLY = 2`                                         | MISSING | bloom.h:29                              | absent |
| 14 | `BLOOM_UPDATE_MASK = 3`                                                  | MISSING | bloom.h:30                              | absent |
| 15 | `(nFlags & BLOOM_UPDATE_MASK)` selects update mode in IsRelevantAndUpdate | MISSING | bloom.cpp:123,125                       | absent |
| 16 | `IsRelevantAndUpdate` txid match                                         | MISSING | bloom.cpp:102-104                       | absent |
| 17 | Per-output scriptPubKey pushdata scan                                    | MISSING | bloom.cpp:113-134                       | absent |
| 18 | P2PKH/P2SH/P2PK/MULTISIG type detection for UPDATE_P2PUBKEY_ONLY         | MISSING | bloom.cpp:127-131, script/solver        | absent |
| 19 | Outpoint match in IsRelevantAndUpdate (txin.prevout)                     | MISSING | bloom.cpp:144                           | absent |
| 20 | scriptSig data items scan                                                | MISSING | bloom.cpp:149-155                       | absent |
| 21 | UPDATE_ALL inserts outpoint on output pushdata match                     | MISSING | bloom.cpp:123-124                       | absent |
| 22 | UPDATE_P2PUBKEY_ONLY conditional outpoint insert (PUBKEY / MULTISIG)     | MISSING | bloom.cpp:125-131                       | absent |
| 23 | UPDATE_NONE never inserts outpoints                                      | MISSING | bloom.cpp:122,125                       | absent |
| 24 | COutPoint serialization for filter insert (txid(32B,LE) ‖ vout(4B LE))    | MISSING | bloom.cpp:62-67, 83-88                  | absent |
| 25 | `filterload` codec + handler in p2p_msg + peer_manager                   | MISSING | net_processing.cpp:4963-4986            | command_name/atom miss; falls to catch-all |
| 26 | `filteradd` codec + ≤520-byte data guard + Misbehaving on violation      | MISSING | net_processing.cpp:4988-5013            | absent |
| 27 | `filterclear` codec + handler resets m_bloom_filter + m_relay_txs=true   | MISSING | net_processing.cpp:5016-5033            | absent |
| 28 | `merkleblock` codec + CMerkleBlock built from bloom filter at getdata    | MISSING | merkleblock.{h,cpp}, net_processing.cpp:2438-2459 | RPC-side w47b helpers exist but only for gettxoutproof |
| 29 | `IsWithinSizeConstraints` enforced before storing a filterload filter   | MISSING | bloom.cpp:90-93, net_processing.cpp:4972-4975 | absent |
| 30 | NODE_BLOOM=4 service-bit + BIP-111 disconnect-if-not-advertised gate     | PARTIAL | bloom: net_processing.cpp:4964-4968, init.cpp:1104-1105 | NODE_BLOOM constant correct, advertised conditionally, default-false ✓; disconnect gate absent |

PRESENT gates: 0. PARTIAL gates: G30. The 27 MISSING gates each map to
one or more BUG-N below.

Two further sub-PARTIAL observations rolled into BUG-22 / BUG-21:
- `mempool` message has a NODE_BLOOM gate at
  `beamchain_peer_manager.erl:1464-1473` (correct, per BIP-35). This is
  the only point where a NODE_BLOOM check is actually enforced in the
  codebase.
- `beamchain_peer.erl:1289` comment claims "Default-true mirrors Core's
  `-peerbloomfilters` default" — the implementation at line 1291
  reads `node_bloom_enabled/0` (which `95ddaea` made default-false), so
  the implementation is now Core-correct but the comment is stale.
  Treat as BUG-22 (LOW; comment hygiene).

---

## Bug catalogue (22 bugs)

### HIGH (9)

**BUG-1 (HIGH)** — No `beamchain_bloom` module. The entire `CBloomFilter`
class is absent: constants (MAX_BLOOM_FILTER_SIZE, MAX_HASH_FUNCS,
LN2SQUARED), constructor sizing, `nHashFuncs` computation,
`MurmurHash3`-based `Hash`, bit-set/insert/contains,
`IsWithinSizeConstraints`, `IsRelevantAndUpdate`. Fixing this means
introducing `apps/beamchain/src/beamchain_bloom.erl` with the eight
public functions: `new/4` (nElements, fp, tweak, flags),
`new_empty/0` (empty filter), `insert/2`, `insert_outpoint/2`,
`contains/2`, `contains_outpoint/2`, `is_within_size_constraints/1`,
`is_relevant_and_update/2`. All of G1..G10 and G29 hinge on this.
Severity HIGH because the entire subsystem cannot exist without it.

**BUG-2 (HIGH)** — No MurmurHash3 (x86_32) anywhere. Even if BUG-1
were fixed in skeleton, the filter cannot test or insert without
MurmurHash3. Erlang's `crypto` module does not provide MurmurHash3.
Two implementation paths: (a) pure-Erlang implementation modelled on
Core's `hash.cpp:13-65` (≈40 LOC), or (b) NIF binding to the
Core/SMHasher reference. Pure-Erlang is preferred for the same
reason as `beamchain_blockfilter.erl` (BIP-158 GCS): NIF crash isolation
+ deterministic build. Test vectors at the BUG-1 spec line.

**BUG-3 (HIGH)** — No `filterload` / `filteradd` / `filterclear` in
wire codec. `beamchain_p2p_msg.erl` `command_name/1` (lines 80-117)
and `command_atom/1` (lines 120-157) miss all three message names.
Encoding the wire format for filterload:
`varint(|vData|) ‖ vData ‖ nHashFuncs(4B LE) ‖ nTweak(4B LE) ‖ nFlags(1B)`.
filteradd: `varint(|data|) ‖ data`. filterclear: empty payload. None
of these clauses exist in `encode_payload/2` or `decode_payload/2`.
Without them no handler can receive a parsed message.

**BUG-4 (HIGH)** — No `merkleblock` codec or getdata `MSG_FILTERED_BLOCK`
branch. `handle_getdata_msg/2` at `beamchain_peer_manager.erl:1733-1801`
only handles MSG_BLOCK / MSG_WITNESS_BLOCK (line 1752) and
MSG_TX / MSG_WITNESS_TX (line 1782). `MSG_FILTERED_BLOCK = 3` falls
into the catch-all `_ ->` (line 1790) and is reported as `notfound`.
Even if a peer were to install a filter via filterload (also missing —
BUG-3), beamchain would never serve a merkleblock. Wire format:
`80B block-header ‖ uint32(nTransactions) ‖ varint(nHashes) ‖
32B*nHashes ‖ varint(nFlagBytes) ‖ flagBytes`.

**BUG-5 (HIGH)** — `CMerkleBlock` / `CPartialMerkleTree` not reachable
from P2P. `beamchain_rpc.erl:8088-8217` implements `w47b_traverse_and_build`
and `w47b_traverse_and_extract` for `gettxoutproof` / `verifytxoutproof`
(see the comment block at line 9384). The partial-merkle-tree algorithm
is present; nothing wires it to (a) a `beamchain_bloom`-driven match
predicate, or (b) a `merkleblock` codec, or (c) the getdata dispatch.
Two-pipeline / dead-helper pattern: the algorithm exists for a
different consumer.

**BUG-6 (HIGH)** — No per-peer bloom-filter state. `beamchain_peer.erl`
`#peer_data{}` lacks a `bloom_filter` field. Core's
`net_processing.cpp:297` stores the filter as
`std::unique_ptr<CBloomFilter> m_bloom_filter PT_GUARDED_BY(m_bloom_filter_mutex)`
inside `TxRelay`. The companion flags `m_relay_txs` (line 295) and
`m_bloom_filter_loaded` (Peer member) drive whether unfiltered tx
inv goes out. Fix path: add three fields to `#peer_data{}`:
`bloom_filter = undefined | beamchain_bloom:filter()`,
`bloom_filter_loaded = false`, `relay_txs = false`.

**BUG-7 (HIGH)** — No NODE_BLOOM disconnect gate on incoming filter
messages. Core's per-msg gate:
```
if (!(peer.m_our_services & NODE_BLOOM)) {
    pfrom.fDisconnect = true;
    return;
}
```
fires for filterload (`net_processing.cpp:4964-4968`), filteradd
(:4989-4992), filterclear (:5017-5019). beamchain has the NODE_BLOOM
constant correct (`beamchain_protocol.hrl:84`) and conditional service
advertisement (`beamchain_peer.erl:1291`), but no handler to enforce
the gate. An incoming filterload-on-no-NODE_BLOOM peer is silently
dropped, not disconnected. This is BIP-111 §2 violation: BIP-111 says
"a node MUST NOT respond to bloom filtering messages from a peer that
has not asked for them." Silently ignoring is not "MUST NOT respond";
it allows the abuser to keep the slot open.

**BUG-8 (HIGH)** — No `IsWithinSizeConstraints` enforcement on
filterload. Core `net_processing.cpp:4972-4975` calls
`Misbehaving(peer, "too-large bloom filter")` when the inbound filter
exceeds either `MAX_BLOOM_FILTER_SIZE = 36000` bytes of `vData` or
`MAX_HASH_FUNCS = 50` hashes. Without a handler this DoS check is
never run. An attacker can saturate the recv buffer with 4-MB
filterload payloads before disconnect (the protocol-message ceiling
is `MAX_PROTOCOL_MESSAGE_LENGTH = 4000000` from `beamchain_protocol.hrl:65`).

**BUG-9 (HIGH)** — No `MAX_SCRIPT_ELEMENT_SIZE = 520` enforcement on
filteradd. Core `net_processing.cpp:5000` calls
`Misbehaving(peer, "bad filteradd message")` when the appended data
exceeds `MAX_SCRIPT_ELEMENT_SIZE`. beamchain has the constant correct
(`beamchain_protocol.hrl:43` — 520) but no handler invokes it.

### MEDIUM (9)

**BUG-10 (MEDIUM)** — `bloomflags` enum entirely absent. Core's
`bloom.h:24-31`:
```
enum bloomflags { BLOOM_UPDATE_NONE = 0, BLOOM_UPDATE_ALL = 1,
                  BLOOM_UPDATE_P2PUBKEY_ONLY = 2, BLOOM_UPDATE_MASK = 3 };
```
No `?BLOOM_UPDATE_NONE` / `?BLOOM_UPDATE_ALL` /
`?BLOOM_UPDATE_P2PUBKEY_ONLY` / `?BLOOM_UPDATE_MASK` macros in
`beamchain_protocol.hrl`. Without these the filterload handler cannot
decode `nFlags` and the IsRelevantAndUpdate cannot branch on update
mode. Gates G11..G15.

**BUG-11 (MEDIUM)** — `0xFBA4C795` constant absent. Core's hash schedule
multiplies `nHashNum` by `0xFBA4C795` before adding `nTweak`
(`bloom.cpp:46-47` comment: "chosen as it guarantees a reasonable bit
difference between nHashNum values"). The exact constant matters
because BIP-37 SPV clients construct their filter expecting this
specific schedule; any other value mis-matches bits and gives false
negatives on every contained element. Filter would still function
internally but would not interoperate with Core/Electrum/libwally.

**BUG-12 (MEDIUM)** — No `COutPoint` serialization for filter insert.
Core `bloom.cpp:62-67` does
```
DataStream stream{};
stream << outpoint;             // txid(32B,LE) ‖ vout(4B LE)
insert(MakeUCharSpan(stream));
```
beamchain has `beamchain_serialize` helpers for varints / varstrs but
no canonical 36-byte outpoint serialiser exposed as a single function.
This is the canonical form used in BOTH filter insert AND wire
`CTxIn::prevout`; the BIP-37 spec is explicit that outpoint hashing
into the filter uses this 36-byte encoding (gate G24).

**BUG-13 (MEDIUM)** — `IsRelevantAndUpdate` txid match path absent.
Core line 102-104: `if (contains(tx.GetHash().ToUint256())) fFound = true`.
This is the cheap "have we filtered this tx by txid?" check. With no
filter and no `contains`, this is N/A but is the smallest gate
(G16). Severity MEDIUM rather than HIGH because BIP-37 wallets that
care about txid-only matches almost always also send P2PKH script
pushes; the per-output scan (BUG-14) is the dominant gate.

**BUG-14 (MEDIUM)** — `IsRelevantAndUpdate` per-output pushdata scan
absent. Core line 113-134 iterates `txout.scriptPubKey.GetOp(...)` and
for each non-empty `data` push tests `contains(data)`. This is the
core of BIP-37 matching: the SPV wallet inserts its P2PKH script hash
(20B) and the filter matches any output paying to that hash. Skipping
this scan means BIP-37 wallets that filter by address would receive no
merkleblocks. Gate G17. Coupled with BUG-15 / BUG-16.

**BUG-15 (MEDIUM)** — Output-type detection for `UPDATE_P2PUBKEY_ONLY`
absent. Core line 127-131 calls `Solver(txout.scriptPubKey, vSolutions)`
and only inserts the matched `COutPoint` when the solved type is
`PUBKEY` or `MULTISIG`. This is the privacy/efficiency carve-out for
SPV wallets that only care about pay-to-pubkey-and-multisig payments
(very rare in modern blocks; the mode exists primarily for backward
compat). Gate G18. Cannot be implemented without a TxoutType solver
that matches Core's `script/solver.h`.

**BUG-16 (MEDIUM)** — Outpoint match in IsRelevantAndUpdate absent.
Core line 144: `if (contains(txin.prevout)) return true`. This is the
"have we seen the outpoint this tx is *spending*?" check. SPV wallets
add outpoints they own to the filter and rely on this branch to
discover spends. Without it spends are invisible until an output-side
match also occurs. Gate G19.

**BUG-17 (MEDIUM)** — `scriptSig` data scan absent. Core line 149-155
iterates `txin.scriptSig.GetOp(...)` and `contains(data)` on each push.
This matches the redeemScript or signature data the SPV wallet
inserted. Gate G20.

**BUG-18 (MEDIUM)** — `CMerkleBlock(block, filter)` constructor logic
absent. Core `merkleblock.cpp:31-56` walks `block.vtx[]`, calls
`filter->IsRelevantAndUpdate(*block.vtx[i])` for each, builds
`vMatch[i]`, calls `txn = CPartialMerkleTree(vHashes, vMatch)`, and
emits the matched `vMatchedTxn` list so the getdata branch can also
send the txns themselves. beamchain `w47b_traverse_and_build` takes
a *pre-computed* match vector; it has no equivalent to the
"build the match vector from the filter" step. Gate G28 sub-step 1.

### LOW (4)

**BUG-19 (LOW)** — Post-merkleblock matched-txn push absent. Core
`net_processing.cpp:2456-2457` iterates `merkleBlock.vMatchedTxn` and
sends each tx as a separate `NetMsgType::TX` message (`MakeAndPushMessage(pfrom, NetMsgType::TX, TX_NO_WITNESS(*pblock->vtx[tx_idx]))`).
Even if BUG-4..BUG-18 are fixed, omitting this pushback means SPV
peers receive the matched txid but not the tx bytes — they'd have to
re-request via getdata, wasting an RTT. Gate G28 sub-step 2.

**BUG-20 (LOW)** — filterclear must reset `m_relay_txs = true`. Core
`net_processing.cpp:5026-5031` does:
```
{
    LOCK(tx_relay->m_bloom_filter_mutex);
    tx_relay->m_bloom_filter = nullptr;
    tx_relay->m_relay_txs = true;     // ← reset to true, restoring unfiltered relay
}
pfrom.m_bloom_filter_loaded = false;
pfrom.m_relays_txs = true;
```
The semantics of BIP-37 filterclear is: "stop filtering, resume full
tx relay." A naïve implementation would set the filter to undefined
but leave `relay_txs = false` if it had been false on connect. This is
a subtle BIP-37 conformance bug that future implementers commonly
miss. Gate G27 sub-step. Severity LOW because the entire handler is
missing (BUG-3) — when fixed, must include this reset.

**BUG-21 (LOW)** — `m_bloom_filter_loaded` Peer flag absent. Core
tracks `m_bloom_filter_loaded` on `CNode` (separate from the
`m_bloom_filter` unique_ptr inside `TxRelay`) and uses it for inv
suppression — if no filter is loaded, certain optimisation paths skip
the contains() check entirely. beamchain has no such flag; gate G21 /
G22 (UPDATE_ALL / UPDATE_P2PUBKEY_ONLY outpoint inserts) cannot be
implemented without it.

**BUG-22 (LOW)** — `beamchain_peer.erl:1289` stale comment. The line
reads:
```
%% mirrors Core's `-peerbloomfilters` default.
```
The implementation immediately below correctly reads
`node_bloom_enabled/0` which defaults to **false** (`95ddaea`). The
comment is preserved from before that fix and mentions "Default-true"
in earlier context. LOW severity but documents the W110 → W134 lineage:
the comment was inaccurate, the fix landed, the comment never got
updated. Should be a one-line fix when the rest of BIP-37 is added.

---

## Bug count summary

| Severity | Count |
|----------|-------|
| CDIV     | 0     |
| HIGH     | 9     |
| MEDIUM   | 9     |
| LOW      | 4     |
| **Total**| **22**|

## Test count summary

30 EUnit tests in `test/beamchain_w134_bloom_tests.erl`. One test per
gate. All assertions written audit-flip — they pass today and **must
fail when the corresponding fix lands**, prompting a deliberate
update.

## Two-pipeline / dead-helper observations

1. **Partial-merkle-tree algorithm exists but only for RPC.**
   `beamchain_rpc.erl:8088-8217` (`w47b_traverse_and_build` /
   `w47b_traverse_and_extract`) is a complete CPartialMerkleTree port,
   only invoked from `gettxoutproof` / `verifytxoutproof`. The exact
   same algorithm would serve P2P `MSG_FILTERED_BLOCK` if connected
   to a `beamchain_bloom`-derived match predicate. Classic two-pipeline.

2. **`v2_msg.erl` registers BIP-324 short-ids for `filteradd` /
   `filterclear` / `filterload` (lines 36-38) and `merkleblock`
   (line 46) but no wire codec or handler exists.** This is dead
   registry: if a BIP-324-v2 peer sends one of these short-id messages
   the dispatcher will recover the long-form name then fall through
   the same catch-all as a v1 peer would. The registry exists for
   BIP-324 strict-conformance — short-ids are allocated 1..28 in a
   well-known order and beamchain follows that order — but it accomplishes
   nothing functional.

3. **`mempool` message NODE_BLOOM gate is the only NODE_BLOOM gate
   wired.** `beamchain_peer_manager.erl:1464-1473` checks
   `beamchain_config:node_bloom_enabled/0` before responding to a
   `mempool` request and disconnects the peer otherwise (BIP-35
   compliance, per W116/W117). Every other NODE_BLOOM gate
   (filterload / filteradd / filterclear / merkleblock-getdata)
   is missing.

## Universal patterns to flag

1. **"Helper exists for a different consumer"** — same as W121 BUG-15
   (`PrepareBlockFilterRequest` helper) and W120 BUG-7 (RBF cluster
   validator dead-helper). Each time an audit finds a complete
   algorithmic primitive in a module written for *another* consumer
   (here: RPC `gettxoutproof`) that the new audit wants for P2P
   serving. Three audits now; promote to fleet-wide pattern.

2. **"BIP-111 silent-ignore vs disconnect"** — Core's response to a
   protocol-violating filter message is `pfrom.fDisconnect = true`,
   not silent drop. beamchain has the catch-all silent-drop pattern in
   several places (W120, W121, W122). Repeated audit finding:
   silently-dropped is **not** the same as protocol-conformant
   "MUST NOT respond". When wiring the fix, the disconnect side
   matters as much as the drop side.

3. **"Wire codec registered but no handler"** — the
   `beamchain_v2_msg.erl` short-id table mirror of the BIP-324 spec
   contains every message name beamchain might ever serve, including
   ones with no codec or handler (this audit: filteradd / filterclear /
   filterload / merkleblock). Same dead-registry pattern as W117
   BUG-1 / W116 BUG-3. Worth noting as a fleet pattern: short-id
   registries should track what's *actually* implemented, not what's
   spec-defined, so xref / scaffolding tools can flag holes.

4. **"NODE_BLOOM default-false fixed but feature still missing"** —
   `95ddaea` defaulted `peerbloomfilters` to false (Core parity), but
   the feature behind the flag is still ABSENT. Operators flipping
   the flag on get a node that advertises NODE_BLOOM but ignores
   filterload — actively worse than non-advertisement, because peers
   will trust the advertisement and try to use the service. Fleet
   pattern: a config-default fix without the feature is worse than
   either alone. Flag the dependency at fix-time.

## Post-fix verification expectations

When the bloom feature lands (likely a multi-wave campaign across
`beamchain_bloom`, `beamchain_merkleblock`, `beamchain_p2p_msg` codecs,
`beamchain_peer_manager` handlers, and `#peer_data{}` fields), each
of the 30 audit-flip tests in this wave **must fail** — that's how we
know the gate flipped from MISSING/BUG → PRESENT. Re-running W134
EUnit after the fix should yield 30 deliberate failures, NOT 30 passes,
NOT 30 ignored. The methodology is the same as W121 / W120 / W117:
audit-flip means "passing test = bug still present."

Cross-impl reference: blockbrew, ouroboros, and clearbit have full
BIP-37 implementations (their per-impl audits exist in
`CORE-PARITY-AUDIT/`); rustoshi and lunarblock have it partial; hotbuns,
nimrod, haskoin, camlcoin, beamchain are missing. beamchain joins the
"missing" cluster on this re-audit.

## Out of scope

- `CRollingBloomFilter` (Core `bloom.h:108-125` / `bloom.cpp:163-247`) —
  used internally by Core for orphan-handling, addrman, and the
  filterInventoryKnown trickle filter. None of those structures
  exist in beamchain either (W128 confirmed addrman uses a different
  data structure; orphan handling is gen_server based; trickle is
  random-shuffle, not bloom-based). A separate W### would audit
  CRollingBloomFilter independently.
- BIP-157 / BIP-158 compact filters — already audited in W121.
  BIP-37 (this audit) and BIP-158 are *different* SPV/light-client
  protocols with no shared code.
- Wallet-side bloom filter creation (Core `node/interface_ui.cpp`
  `CreateWalletFilter`). beamchain wallet uses native UTXO scanning
  rather than bloom; no equivalent.

## Cumulative discovery cadence

Wave 134 of the beamchain discovery sequence. Streak preserved.
Co-running with 3 other audit waves in parallel (per dispatch brief).

Reference for follow-up fix waves: see W110 audit document
(`test/beamchain_w110_bloom_filter_tests.erl`) for the prior baseline.
W110 found 18 bugs; W134 finds 22 (the difference is finer-grained
splits — BUG-10..14 cover what W110 grouped as BUG-14 "all four
bloomflags absent", and BUG-19..22 are new sub-gates uncovered by
re-reading Core's filterclear and the matched-txn pushback). Strict
superset.
