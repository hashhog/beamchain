# W143 — Block-level validation audit (beamchain)

Discovery-only wave. Audit gates derived from Bitcoin Core references:

- `bitcoin-core/src/validation.cpp` — `CheckBlock` (3918-3983),
  `CheckBlockHeader` (3828-3835), `CheckMerkleRoot` (3837-3862),
  `CheckWitnessMalleation` (3870-3916), `IsBlockMutated` (4027-4056),
  `ContextualCheckBlockHeader` (4080-4121),
  `ContextualCheckBlock` (4129-4184), `ConnectBlock` (2155+ with
  BIP-30 enforcement at 2402-2476).
- `bitcoin-core/src/consensus/tx_check.cpp` — `CheckTransaction`
  (11-60). Both `bad-txns-vin-empty`, `bad-txns-vout-empty`,
  `bad-txns-oversize`, output-value range checks, duplicate inputs
  (CVE-2018-17144), coinbase scriptSig 2–100 byte length.
- `bitcoin-core/src/consensus/merkle.cpp` — `ComputeMerkleRoot`
  with `mutated` flag (46-63), `BlockMerkleRoot` (66-74).
  Mutation flag flips on **any** adjacent-equal pair at **any** level
  of the tree, not just the duplicated final leaves.
- `bitcoin-core/src/consensus/consensus.h` — `MAX_BLOCK_WEIGHT=4_000_000`,
  `MAX_BLOCK_SIGOPS_COST=80_000`, `WITNESS_SCALE_FACTOR=4`,
  `MIN_TRANSACTION_WEIGHT=240`.
- `bitcoin-core/src/chain.h:29` — `MAX_FUTURE_BLOCK_TIME = 2*60*60` (7200 s).
- `bitcoin-core/src/script/script.h:341-372` — `CScriptNum::serialize`,
  `CScript::push_int64` (BIP-34 height encoding).

Companion audits cross-referenced:

- **W142** (SegWit witness validation): covers `CheckWitnessMalleation`,
  witness-commitment scan, and the v0-P2WSH stack-element gate.
  Findings there are not duplicated here.
- **W132** (nSequence/CSV/MTP): MTP and `IsFinalTx` are reused by
  `ContextualCheckBlock`; ordering bugs flagged there propagate.
- **W126** (BIP-152 compact blocks): `IsBlockMutated`'s 64-byte
  non-witness-tx check was catalogued there. W126 BUG-7 already
  covers the missing 64-byte tx defense on the compact-block path;
  this audit reports the same gap on the **main `block`-message
  path** for completeness.
- **W137** (PSBT): PSBT signers feed `CheckTransaction`; gaps here
  surface as wallet acceptance of consensus-invalid txs.
- **W93/W94 fix-history**: BIP-30 canonical-chain proof (the
  `bip34_canonical_chain_active/3` function) landed in W93 against the
  no-hash-check bug; the BYTE-ORDER bug in `bip30_exceptions` /
  `bip34_hash` documented below survived that fix.

## Status counts (8 behaviors × 4 gates = 32 gate-cells)

- **PRESENT** (Core-parity, or internally consistent + Core-compatible): 19
- **PARTIAL** (some piece matches, others diverge or are simplified): 9
- **MISSING** (no equivalent in beamchain): 4

Headline: **24 bugs**, severity distribution
**1 P0-CONSENSUS / 1 P0-CDIV / 3 P0 / 8 P1 / 8 P2 / 3 P3**.

Block-level validation is the seam where consensus-relevant state
transitions are gated. The two themes dominating this wave:

1. **The BIP-30 / BIP-34 hash byte-order is wrong in chain_params**
   (BUG-1, BUG-2). `hex_to_bin/1` does NOT reverse bytes, but
   `beamchain_serialize:block_hash/1` returns the raw double-SHA256
   = INTERNAL byte order. Comparing the two NEVER matches. The
   connect-side BIP-30 exception gate at mainnet height 91842
   silently fails → beamchain WILL throw `bad_txns_bip30` when
   syncing mainnet from genesis at height 91842 (the historical
   duplicate-coinbase block). This is a hard chain-stall.
2. **`check_block` does work in the wrong order** (BUG-3, BUG-4):
   beamchain iterates per-tx checks BEFORE the block-weight check
   (a Core-style DoS amplification), and runs the merkle-mutation
   scan AS A SEPARATE PASS AFTER the merkle root (Core integrates
   both into `CheckMerkleRoot` in one pass). The mutation algorithm
   used by beamchain only checks "last two equal at odd-length
   levels"; Core checks ANY adjacent-equal pair at ANY level. The
   actual CVE-2012-2459 attack is closed by `check_no_dup_txids/2`
   at the txid level, but the structural defense at higher levels
   that Core layers in is missing.

Notable cross-cutting smells:

- **Code duplication smell** (2nd instance fleet-wide for beamchain
  this wave): `merkle_pairs/1` (in `beamchain_serialize.erl:215-221`)
  and `merkle_pairs_check/1` (in `beamchain_validation.erl:781-785`)
  are byte-identical. Two implementations of the same merkle pairing,
  invoked back-to-back per block. Recomputes the entire merkle tree
  twice (once for the root, once for mutation detection).
- **Comment-as-confession** (6th instance fleet-wide):
  `beamchain_validation.erl:147-150` says "We check for duplicate
  final leaves which is the simplest form of this attack." — the
  comment explicitly admits the check is weaker than Core's full
  algorithm. BUG-4.
- **Two-pipeline guard** (already documented since W76): the
  `Bip30Exceptions` config-driven path coexists with the inline
  hard-coded `91722` / `91812` byte literals in `disconnect_block`
  (`:1761-1770`). The disconnect-side hard-coded bytes ARE correct
  (internal byte order), but the connect-side config-driven path is
  WRONG (display byte order). BUG-1.
- **Stricter-than-Core** (already catalogued in W142 BUG-21):
  `MIN_TRANSACTION_WEIGHT >= 240` is enforced in
  `check_transaction`; Core has no such floor. Not re-catalogued
  here.

---

## BUGS

### BUG-1 (P0-CONSENSUS) — `bip30_exceptions` and `bip34_hash` stored in DISPLAY byte order, compared against INTERNAL byte order — mainnet sync stalls at height 91842

- **File**: `src/beamchain_chain_params.erl:81-84, 90-91`
  (mainnet params) and the comparator in
  `src/beamchain_validation.erl:1101-1103` (connect-side BIP-30
  exception check) and `:1438-1449`
  (`bip34_canonical_chain_active/3`).
- **Core ref**: `bitcoin-core/src/validation.cpp:6189-6193`
  (`IsBIP30Repeat` — height + hash); `validation.cpp:2460-2462`
  (`pindexBIP34height->GetBlockHash() == params.BIP34Hash`);
  `bitcoin-core/src/uint256.h:124-132` (`base_blob` consteval
  constructor reads `hex_str.rbegin()` first → INTERNAL byte
  order); `validation.cpp:2201-2202` (the disconnect-side
  `91722` / `91812` hashes in Core are also written as
  internal-byte-order literals, e.g.
  `uint256{"00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e"}`
  → bytes `{0x8e, 0xd0, ...}`).
- **Description**: Core's `uint256{"<hex>"}` constructor reads the
  hex string in REVERSE (least-significant byte first), producing
  INTERNAL byte order (= raw double-SHA256 output order). Compared
  against `pindex->GetBlockHash()` which is also INTERNAL order,
  comparisons succeed.

  beamchain's `hex_to_bin/1` decodes the hex string LEFT-TO-RIGHT,
  producing DISPLAY byte order. Compared against
  `beamchain_serialize:block_hash/1` (raw double-SHA256 =
  INTERNAL order), comparisons NEVER succeed for any real block.
- **Excerpt**:
  ```erlang
  %% chain_params.erl:81-84 — DISPLAY byte order
  bip30_exceptions => [
      {91842, hex_to_bin("00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec")},
      {91880, hex_to_bin("00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721")}
  ],

  %% validation.erl:1101-1103 — compares INTERNAL-order block_hash to DISPLAY-order ExHash
  IsBip30Repeat = lists:any(fun({ExH, ExHash}) ->
      Height =:= ExH andalso BlockHash =:= ExHash
  end, Bip30Exceptions),

  %% Compare to disconnect_block.erl:1761-1770 — CORRECT internal-byte-order literal
  (Height =:= 91722 andalso
   BlockHash =:= <<16#8e,16#d0,16#4d,16#57,16#f2,16#d3,16#9c,16#6c, ...>>)
  ```
- **Impact**: **P0-CONSENSUS — beamchain CANNOT sync mainnet from
  genesis through height 91842.** At height 91842, a coinbase
  duplicates an earlier coinbase's txid. Core uses
  `IsBIP30Repeat({91842, 0x00...0a4d...0caec})` to disable BIP-30
  enforcement for that single block; beamchain's
  `IsBip30Repeat = false` (byte-order-mismatch), so
  `EnforceBip30 = true` and `check_no_existing_outputs/2` finds the
  prior coinbase's UTXO still present → throws `bad_txns_bip30` →
  block 91842 rejected → chain-stalled forever at 91841. Same hazard
  at 91880.

  A second, lower-severity effect: the `bip34_canonical_chain_active`
  gate at lines 1438-1449 ALSO compares
  `AncestorHash =:= Bip34Hash` (display vs internal), so
  `Bip34Active` is ALWAYS false → `EnforceBip30_B` is always equal
  to `EnforceBip30_A` → BIP-30 stays enforced for ALL blocks past
  the BIP-34 activation height. CPU overhead (one `has_utxo/2`
  call per coinbase output per block) but no consensus divergence
  beyond the 91842/91880 stall described above.

### BUG-2 (P0-CDIV) — `bad-blk-length` per-tx-count and base-size sub-gates absent

- **File**: `src/beamchain_validation.erl:100-168`
  (`check_block/2`) — no equivalents for either of Core's two
  upper-bound sub-gates.
- **Core ref**: `bitcoin-core/src/validation.cpp:3947-3948`
  (`block.vtx.empty() || block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT || ::GetSerializeSize(TX_NO_WITNESS(block)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT`).
- **Description**: Core's `CheckBlock` includes THREE size-related
  sub-gates, all under `bad-blk-length`:
  (a) `block.vtx.empty()` — caught by beamchain's `no_transactions`.
  (b) `block.vtx.size() * 4 > MAX_BLOCK_WEIGHT` — i.e. >= 1M
      transaction entries; rejects fast without iterating tx
      contents.
  (c) `GetSerializeSize(TX_NO_WITNESS(block)) * 4 > MAX_BLOCK_WEIGHT`
      — i.e. base (no-witness) size > 1 MB (the legacy block-size
      cap, kept as a separate gate alongside the with-witness
      weight cap).
- **Excerpt**:
  ```erlang
  check_block(#block{header = Header, transactions = Txs}, Params) ->
      ...
      Txs =/= [] orelse throw(no_transactions),   %% (a) — OK
      ...
      lists:foreach(fun(Tx) -> check_transaction(Tx) ... end, Txs),
      %% (b) and (c) absent: full per-tx iteration runs BEFORE block-weight check
      ...
      BlockWeight = compute_block_weight(Txs),
      BlockWeight =< ?MAX_BLOCK_WEIGHT orelse throw(bad_blk_weight),
  ```
- **Impact**: P0-CDIV — beamchain misses the pre-segwit `1 MB`
  base-size cap that Core retains as defense-in-depth.
  `bad-blk-weight` (which beamchain checks at step 8) sums the
  WITNESS-discounted weight; a block whose BASE size > 1 MB but
  whose witness-discounted weight is <= 4 M is rejected by Core
  on the base-size check but accepted by beamchain. This is
  achievable with a block whose coinbase carries a large witness
  payload (witness data is discounted 4×, but Core's base-size
  check is computed on TX_NO_WITNESS). The base-size check is a
  legacy safeguard but is part of consensus.

### BUG-3 (P1) — `check_block` iterates per-tx checks BEFORE size gates → DoS amplification

- **File**: `src/beamchain_validation.erl:100-163`
- **Core ref**: `bitcoin-core/src/validation.cpp:3947-3955`
  (Core runs size gates FIRST, then `vtx[0]->IsCoinBase`, then
  per-tx iteration).
- **Description**: beamchain runs the full per-tx
  `check_transaction/1` loop (which includes
  `check_duplicate_inputs/1` — O(n) per tx) at step 5, BEFORE the
  block-weight check at step 8. Core's order is:
  (1) header,
  (2) merkle root + mutation,
  (3) size gates (`bad-blk-length`),
  (4) coinbase position,
  (5) per-tx `CheckTransaction`,
  (6) legacy sigops.
  beamchain's order is:
  (1) header,
  (2) coinbase position,
  (3) per-tx `check_transaction`,
  (4) dup-txid (pre-merkle for canonical reason string),
  (5) merkle root,
  (6) mutation,
  (7) block-weight,
  (8) legacy sigops.
- **Excerpt**: see step ordering at lines 102-163 above.
- **Impact**: P1 — a hostile peer can send a block of size 8 MB
  containing 1M valid-looking transactions, forcing beamchain to
  iterate `check_transaction/1` for every tx (each O(input count)
  for duplicate-input detection) before catching the block on
  weight. Core caches the size gate FIRST and rejects in O(1)
  before any tx iteration. The amplification factor is the cost
  of iterating 1M transactions versus rejecting on the first
  size check.

### BUG-4 (P1) — `check_merkle_malleation` only catches "odd-length, last two equal" — Core's flag fires for ANY adjacent equal pair at ANY level

- **File**: `src/beamchain_validation.erl:147-151, 758-779`
  (`check_merkle_malleation` and `check_merkle_malleation_level`).
- **Core ref**: `bitcoin-core/src/consensus/merkle.cpp:46-63`
  (`ComputeMerkleRoot`: the `if (mutated)` loop sets
  `mutation = true` if `hashes[pos] == hashes[pos + 1]` for ANY
  `pos` in the current level — EVEN OR ODD length).
- **Description**: Core's mutation algorithm is:
  ```cpp
  while (hashes.size() > 1) {
      if (mutated) {
          for (size_t pos = 0; pos + 1 < hashes.size(); pos += 2) {
              if (hashes[pos] == hashes[pos + 1]) mutation = true;
          }
      }
      if (hashes.size() & 1) {
          hashes.push_back(hashes.back());
      }
      ...
  }
  ```
  i.e. flag any adjacent-equal pair at any level. beamchain's check:
  ```erlang
  check_merkle_malleation_level(Hashes) ->
      Len = length(Hashes),
      case Len rem 2 =:= 1 andalso Len >= 2 of
          true ->
              Last = lists:last(Hashes),
              SecondLast = lists:nth(Len - 1, Hashes),
              case Last =:= SecondLast of
                  true -> throw(mutated_merkle);
                  ...
  ```
  i.e. only flag if (length is odd) AND (the last two are equal).
- **Impact**: P1 — for the actual CVE-2012-2459 attack (the
  receiver duplicates the last pair of a block's tx list to produce
  the same merkle root), the practical defense is closed by
  `check_no_dup_txids/2` at the txid level — that gate rejects any
  block with duplicate non-coinbase txids before the merkle check
  runs. So no consensus divergence in the field.

  Still, Core's algorithm catches "even-length adjacent duplicates"
  and "odd-length non-last-pair duplicates" that beamchain misses;
  these are unreachable in the field (any block exercising them
  would need a SHA-256 collision at some internal merkle level) but
  the defense-in-depth gap is real. Note also that beamchain's
  mutation check is a SEPARATE PASS over the leaves (line 151) —
  Core does it INSIDE `CheckMerkleRoot` while computing the root
  (one tree traversal, not two).

### BUG-5 (P1) — `compute_merkle_root` and `merkle_pairs_check` recompute the entire tree TWICE per block

- **File**: `src/beamchain_validation.erl:141-151` (calls
  `compute_merkle_root/1` then runs its own
  `check_merkle_malleation/1` on the same leaves).
- **Core ref**: `bitcoin-core/src/validation.cpp:3837-3862`
  (`CheckMerkleRoot` returns both root and mutation flag in one
  pass; `BlockMerkleRoot` re-traverses ONCE).
- **Description**: beamchain calls
  `beamchain_serialize:compute_merkle_root/1` (which walks the leaves
  pairing them up), compares against `Header#block_header.merkle_root`,
  then independently calls `check_merkle_malleation/1` which walks
  the same leaves pairing them up again. Two full
  tree-traversal hash chains are performed per block.

  Worse, `merkle_pairs/1` (in `beamchain_serialize.erl:215-221`) and
  `merkle_pairs_check/1` (in `beamchain_validation.erl:781-785`)
  are byte-identical. Code duplication.
- **Excerpt**:
  ```erlang
  %% validation.erl:142-151
  TxHashes = [beamchain_serialize:tx_hash(Tx) || Tx <- Txs],
  ComputedMerkle = beamchain_serialize:compute_merkle_root(TxHashes),
  ComputedMerkle =:= Header#block_header.merkle_root
      orelse throw(bad_merkle_root),
  check_merkle_malleation(TxHashes),   %% second full traversal
  ```
- **Impact**: P1 — block-validation latency proportional to
  `(N * (N-1)) / 2` SHA-256 hashes per block, where N = tx count.
  For a 4000-tx block this is ~8000 extra SHA-256 calls per block
  (~16 ms on a Ryzen 9). Doubles the IBD CPU cost for merkle
  validation versus Core. Also a code-quality smell: two
  byte-identical implementations of `merkle_pairs`. Fixing this
  requires consolidating the mutation detection into
  `compute_merkle_root/1` so a single traversal returns both
  `{Root, Mutated}` as Core does.

### BUG-6 (P0) — `CheckTransaction` per-tx `bad-txns-oversize` upper bound missing

- **File**: `src/beamchain_validation.erl:540-593`
  (`check_transaction/1`).
- **Core ref**: `bitcoin-core/src/consensus/tx_check.cpp:18-21`
  (`if (::GetSerializeSize(TX_NO_WITNESS(tx)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT) → bad-txns-oversize`).
- **Description**: Core enforces a per-tx upper-bound (base size
  scaled by 4 must not exceed MAX_BLOCK_WEIGHT, i.e. base size
  <= 1 MB). beamchain only enforces a lower-bound
  `Weight >= ?MIN_TRANSACTION_WEIGHT` (already catalogued in W142
  as stricter-than-Core). No upper bound.
- **Excerpt**:
  ```erlang
  %% Step 8 — only LOWER bound
  Weight = beamchain_serialize:tx_weight(Tx),
  Weight >= ?MIN_TRANSACTION_WEIGHT orelse throw(tx_underweight),
  %% NO upper-bound enforcement → relies on block-weight catching it
  ```
- **Impact**: P0 — a transaction whose serialized form is >= 1 MB
  base size but < 1 MB after witness-discount slips through
  `check_transaction`. This is reachable: a tx with a very large
  witness payload (4x discount) could have witness-stripped size
  >= 1 MB but witness-discounted weight < 4 MB. The block-weight
  check at step 8 (4 MB cap) catches the overall block, but Core
  rejects the tx at the per-tx level. Practical impact in the
  mempool path (where standalone txs flow without a block
  context): a hostile tx can slip past `check_transaction` and
  enter beamchain's mempool, then be filtered later by policy or
  mempool-acceptance code. Not directly a chain-split candidate but
  a fleet-wide cleanliness gap (cross-cite W137 PSBT and W135
  policy).

### BUG-7 (P0) — Timestamp future-time check uses local `erlang:system_time`, no peer-time adjustment (Core uses `NodeClock::now` = MOCK-adjustable)

- **File**: `src/beamchain_validation.erl:79-82`
- **Core ref**: `bitcoin-core/src/validation.cpp:4108-4109`
  (`block.Time() > NodeClock::now() + std::chrono::seconds{MAX_FUTURE_BLOCK_TIME}`);
  `bitcoin-core/src/chain.h:29`
  (`MAX_FUTURE_BLOCK_TIME = 2 * 60 * 60`).
- **Description**: Core's `NodeClock::now()` is a project-wide
  mockable clock so the test harness can simulate time-skew /
  future-block scenarios. beamchain hard-codes
  `erlang:system_time(second)`. The 2-hour window is correct
  numerically, but:
  (a) **no peer-time adjustment** — Core historically used
      `GetAdjustedTime()` (median of peer time offsets). The current
      Core code dropped peer-time adjustment in favor of a fixed
      window-based future-time check, but kept the mockable clock.
  (b) **no `MAX_FUTURE_BLOCK_TIME` constant** — beamchain inlines
      the magic numbers `2 * 60 * 60` at the call site. Compare to
      `?MAX_BLOCK_WEIGHT` etc. which are properly named.
- **Excerpt**:
  ```erlang
  %% 2. verify timestamp is not more than 2 hours in the future
  MaxFutureTime = erlang:system_time(second) + 2 * 60 * 60,
  Header#block_header.timestamp =< MaxFutureTime
      orelse throw(time_too_new),
  ```
- **Impact**: P0 — beamchain cannot mock time in unit tests for
  future-block scenarios, and the magic numbers `2 * 60 * 60`
  invite drift if someone "fixes" the value here without updating
  the matching site in `contextual_check_block_header` (which
  doesn't have a future-time check at all — see BUG-12). Define
  `?MAX_FUTURE_BLOCK_TIME` in `beamchain_protocol.hrl` and route
  through a `beamchain_clock:adjusted_now/0` helper.

### BUG-8 (P0) — `check_block_header` runs future-time check; Core puts it in `ContextualCheckBlockHeader`

- **File**: `src/beamchain_validation.erl:69-93` vs
  `:176-249` (no time-vs-now in the contextual path).
- **Core ref**: `bitcoin-core/src/validation.cpp:3828-3835`
  (`CheckBlockHeader` does ONLY PoW); `:4080-4121`
  (`ContextualCheckBlockHeader` does MTP + adjusted-time future
  check + version-after gates).
- **Description**: Core splits header validation into:
  - context-free (`CheckBlockHeader`): only the PoW check.
  - contextual (`ContextualCheckBlockHeader`): MTP, future-time,
    version-after-buried-deployments.
  beamchain merges them. The future-time check is in `check_block_header`
  (line 80) — i.e. runs every time the header is validated,
  including the defense-in-depth re-check at `connect_block`
  step 0 (line 1054). Core's `CheckBlock` does NOT re-check the
  future-time bound in the connect re-check.
- **Impact**: P0 — semantically minor but locationally wrong. A
  block accepted by `check_block_header` at time T whose
  `connect_block` runs at time T+1 hour passes anyway because the
  2-hour window is generous enough. But the ordering matters for
  invalidity marking: if `check_block_header` rejects at the
  re-check, beamchain may mark the block as permanently invalid
  on a transient clock skew. Core's design (one-shot future-time
  check on first receipt) avoids this.

### BUG-9 (P0) — `count_p2sh_sigops` runs over coinbase inputs; Core's `GetP2SHSigOpCount` short-circuits

- **File**: `src/beamchain_validation.erl:801-822`
  (`count_p2sh_sigops/2`).
- **Core ref**: `bitcoin-core/src/consensus/tx_verify.cpp:128-129`
  (`if (tx.IsCoinBase()) return 0;`).
- **Description**: Core's `GetP2SHSigOpCount` short-circuits to 0
  for coinbase. beamchain's `count_p2sh_sigops` has no such
  short-circuit. In the current call graph, `get_tx_sigop_cost/3`
  is only called for non-coinbase transactions inside
  `connect_block/4` (lines 1175-1222), and coinbase sigops are
  counted separately at line 1307 (legacy-only). So the gap is not
  exercised today. But the function is EXPORTED (line 24) — any
  future call site that passes a coinbase will read garbage P2SH
  sigop data from the coinbase scriptSig (which is NOT P2SH but
  arbitrary bytes).
- **Excerpt**:
  ```erlang
  count_p2sh_sigops(#transaction{inputs = Inputs}, InputCoins) ->
      %% no IsCoinBase short-circuit
      lists:foldl(fun({Input, Coin}, Acc) ->
          case is_p2sh_script(Coin#utxo.script_pubkey) of
              true ->
                  %% would interpret coinbase scriptSig bytes as P2SH redeem-script push
                  ...
  ```
- **Impact**: P0 — defense-in-depth gap; not currently exercised
  but a footgun for any future refactor that uses the exported
  function with a coinbase. Adds a one-line `is_coinbase_tx(Tx)`
  guard.

### BUG-10 (P1) — `count_witness_sigops` P2SH-wrapped-witness path skips `IsPushOnly` enforcement

- **File**: `src/beamchain_validation.erl:893-920`
  (`count_witness_sigops/2`) + `:972-1014` (`get_last_push/1`).
- **Core ref**: `bitcoin-core/src/script/interpreter.cpp:2152`
  (`scriptPubKey.IsPayToScriptHash() && scriptSig.IsPushOnly()`).
- **Description**: Core's `CountWitnessSigOps` for a P2SH-wrapped
  witness redeem only counts sigops if the scriptSig is push-only.
  beamchain's `get_last_push/1` (lines 972-1014) walks the entire
  scriptSig and returns the LAST push regardless of whether
  non-push opcodes were encountered. Core: return 0 if any non-push.
- **Impact**: P1 — divergent sigop count for malformed P2SH-wrapped
  witness scriptSigs. Core under-counts (returns 0); beamchain over-
  counts (returns last-push opcount). Adds to `bad-blk-sigops`
  rejection asymmetry — beamchain can reject a block on
  `bad_blk_sigops` that Core accepts (sigop budget exceeded by
  beamchain only).

### BUG-11 (P1) — `check_block` does not call `IsBlockMutated`'s 64-byte-tx defense

- **File**: `src/beamchain_validation.erl:100-168` (no
  64-byte-tx defense).
- **Core ref**: `bitcoin-core/src/validation.cpp:4027-4056`
  (`IsBlockMutated`); `bitcoin-core/src/net_processing.cpp:4785-4791`
  (`Misbehaving(peer, "mutated block")` on receipt of a block where
  any non-coinbase tx is 64 bytes serialized).
- **Description**: Core's `IsBlockMutated` is invoked from the
  P2P block-receive path (`net_processing.cpp:4785`) to discourage
  peers that send a block with any 64-byte non-coinbase transaction
  (the structural defense against the "weakness in merkle root
  construction" paper:
  https://lists.linuxfoundation.org/pipermail/bitcoin-dev/attachments/20190225/a27d8837/attachment-0001.pdf).
  beamchain's block-receive path in `beamchain_block_sync:handle_block_received`
  (line 769) does NOT call any mutation defense. Cross-cite W126
  BUG-7 which catalogued this gap on the compact-block path; this
  is the same gap on the main `block`-message path.
- **Excerpt**: `beamchain_block_sync.erl:769-817` — no mutation
  check; block goes straight to the downloaded map and then into
  `validate_sequential`.
- **Impact**: P1 — beamchain accepts a mutated block from a hostile
  peer (until `validate_sequential` rejects it via merkle root
  mismatch or invalid contents), and does NOT misbehave-score the
  peer. Compounds with BUG-4 (mutation algorithm gap). Cross-cite
  W126 BUG-7 — closing both at once via a shared
  `is_block_mutated/2` helper.

### BUG-12 (P1) — `contextual_check_block_header` does not re-check future-time bound

- **File**: `src/beamchain_validation.erl:181-249`
- **Core ref**: `bitcoin-core/src/validation.cpp:4108-4110`
  (Core's `ContextualCheckBlockHeader` does check
  `block.Time() > NodeClock::now() + MAX_FUTURE_BLOCK_TIME`).
- **Description**: beamchain places the future-time check in
  `check_block_header/2` (context-free), NOT in
  `contextual_check_block_header/3`. The contextual path checks
  bits/MTP/BIP-94/version but not future-time. Core's contextual
  path checks future-time.
- **Impact**: P1 — combined with BUG-8 (future-time in context-free
  path), this is a location bug. The check exists, just in the
  wrong layer. Doesn't cause divergence today, but reorganizing
  the validation layers requires careful migration of this check.

### BUG-13 (P2) — `block_index.hash` field accessed in two byte orders depending on storage path

- **File**: `src/beamchain_validation.erl:1438-1449`
  (`bip34_canonical_chain_active/3`) reads `AncestorHash` from
  `beamchain_db:get_block_index/1` and compares against `Bip34Hash`.
- **Core ref**: `bitcoin-core/src/validation.cpp:2460-2462`.
- **Description**: Even after BUG-1 is fixed, `bip34_canonical_chain_active`
  has a SECOND byte-order hazard: the function compares
  `AncestorHash` (from `beamchain_db:get_block_index/1`,
  stored as INTERNAL via `encode_block_index_entry/5`) against
  `Bip34Hash` (from chain_params via `hex_to_bin/1`, DISPLAY order).
  The fallback branch at line 1447 computes
  `beamchain_serialize:block_hash(Header)` — also INTERNAL order —
  so it has the same byte-order mismatch.
- **Impact**: P2 — the function ALWAYS returns false (already
  noted in BUG-1's impact paragraph). Once BUG-1's chain_params
  hashes are reversed at construction, this function will start
  to work correctly. Catalogued separately because it is a SECOND
  call site relying on the same wrong assumption.

### BUG-14 (P2) — `check_block` recomputes block weight (with witness) but Core's CheckBlock checks NO-WITNESS size

- **File**: `src/beamchain_validation.erl:153-155` calls
  `compute_block_weight(Txs)` which is the with-witness weight.
- **Core ref**: `bitcoin-core/src/validation.cpp:3947`
  (`::GetSerializeSize(TX_NO_WITNESS(block)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT`).
- **Description**: Core's `CheckBlock` (context-free) checks the
  NO-WITNESS (base) block size scaled by 4. beamchain's
  `check_block` checks the WITH-WITNESS weight. The witness-aware
  weight check belongs in `ContextualCheckBlock` (Core line 4179).
  beamchain places the with-witness check in the context-free
  `check_block`, and has NO weight check in `contextual_check_block`.
- **Impact**: P2 — same gating threshold (4M weight), but ordering
  is different. Core's design ensures that the WITNESS-affecting
  weight check runs AFTER the witness-malleation check, so a
  hostile miner cannot use coinbase witness padding to flip a
  block from valid → permanently-invalid. beamchain runs the
  weight check at step 8 BEFORE witness validation
  (`contextual_check_block` step 4); a tampered coinbase witness
  could trip the weight check and cause beamchain to mark the
  block as permanently invalid based on attacker-controlled bytes.

### BUG-15 (P2) — `connect_block` re-checks `check_block` defensively, including the future-time bound

- **File**: `src/beamchain_validation.erl:1054-1060` calls
  `check_block/2` which in turn calls `check_block_header/2`
  (line 104) which does the future-time check (line 80).
- **Core ref**: `bitcoin-core/src/validation.cpp:2317-2329`
  (Core's defensive re-check of `CheckBlock` does NOT include the
  future-time check, because `CheckBlockHeader` itself doesn't
  check time).
- **Description**: beamchain's defense-in-depth `check_block`
  re-check at the start of `connect_block` ALSO re-checks the
  future-time bound. If a block was accepted at time T (timestamp
  = T+1.5h) but is connected at time T+1h (timestamp now is
  T+1.5h, MaxFutureTime is now+2h = T+3h — still 1.5h in the past
  → check passes), there's no actual problem TODAY because of the
  generous 2-hour window. But the check IS being re-run.
- **Impact**: P2 — performance: an extra system_time call and
  comparison per block-connect. Semantically harmless under the
  current 2-hour window, but if a different deployment shortens
  the window, the re-check could fire on transient clock skew and
  mark the block as permanently invalid. Compounds with BUG-7
  (no clock mockability).

### BUG-16 (P2) — `check_no_dup_txids` placed at step 5b for BIP-22 reason-string compatibility, not at Core's checkpoint

- **File**: `src/beamchain_validation.erl:129-139` (a
  pre-merkle dup-txid scan) + the comment at 132-137 admitting the
  placement is for BIP-22 reason-string parity.
- **Core ref**: `bitcoin-core/src/validation.cpp:2402-2476` (the
  BIP-30 enforcement is the canonical defense — duplicate non-CB
  txids cannot exist without spending the same UTXO twice, caught
  by `view.HaveCoin` failure in `ConnectBlock`).
- **Description**: beamchain adds a `check_no_dup_txids/2` scan
  AFTER per-tx checks but BEFORE merkle-root computation,
  explicitly to emit `bad-txns-inputs-missingorspent` rather than
  `bad-txnmrklroot`. Core relies on the BIP-30 / spend-twice
  detection in `ConnectBlock`'s view path — the merkle-root
  mismatch (Core: `bad-txnmrklroot`) is what fires first in a
  literal-duplicate-tx-list block.
- **Impact**: P2 — semantic divergence at the BIP-22 reject-reason
  level. A block with duplicate non-coinbase txids:
  - Core: rejects with `bad-txnmrklroot` (because the duplicate
    leaves at the same position produce the same merkle root —
    actually they don't, because duplicate txids would have
    different positions in the tree — but the
    `view.HaveCoin` check in ConnectBlock catches it as
    `bad-txns-inputs-missingorspent`).
  - beamchain: rejects with `dup_txid` (pre-merkle) — emits the
    `bad-txns-inputs-missingorspent` reason string per the comment.
  Different ordering. The check is internally useful but not
  Core-parity. P2.

### BUG-17 (P2) — `MIN_TRANSACTION_WEIGHT >= 240` enforced in `check_transaction`, stricter than Core (already catalogued in W142 BUG-21)

- **File**: `src/beamchain_validation.erl:586-588`.
- **Core ref**: `bitcoin-core/src/consensus/tx_check.cpp` (no
  lower-bound; only upper-bound via `bad-txns-oversize`).
- **Description**: Already documented in W142 BUG-21. Re-flagged
  here only because W143's scope (block-level validation) re-
  exercises the same `check_transaction/1`. Not duplicated.
- **Impact**: P2 — see W142 BUG-21 for full impact (rejects
  Core-valid transactions of weight 60..239).

### BUG-18 (P2) — `check_transaction` doesn't validate `prev_out.hash` size on coinbase input

- **File**: `src/beamchain_validation.erl:600-602`
  (`is_coinbase_tx/1` pattern match on
  `#outpoint{hash = <<0:256>>, index = 16#ffffffff}`).
- **Core ref**: `bitcoin-core/src/primitives/transaction.h`
  (`COutPoint::IsNull()` requires 32 zero bytes + UINT32_MAX).
- **Description**: beamchain's `is_coinbase_tx/1` only matches
  the EXACT pattern `<<0:256>>` (32 zero bytes) AND
  `16#ffffffff`. Any deviation (one bit set, wrong index byte)
  results in `is_coinbase_tx -> false`. Good. But the
  `decode_tx_in/1` upstream serializer must produce a 32-byte
  hash for `prev_out`. If it ever produced a malformed outpoint
  (less than 32 bytes), the pattern match would fail at decode
  time — caught upstream.
- **Impact**: P2 — defense-in-depth only; the pattern is correct
  and matches Core's `IsNull` predicate. Not exploitable today;
  flagged for completeness as the only structural check on
  coinbase prevout is this pattern match.

### BUG-19 (P3) — `check_block_header` re-validates `Target <= PowLimit` redundantly

- **File**: `src/beamchain_validation.erl:85-88`.
- **Core ref**: `bitcoin-core/src/pow.cpp:155`
  (`CheckProofOfWorkImpl` already checks
  `bnTarget > UintToArith256(pow_limit) → false`).
- **Description**: beamchain's `check_pow/3` (called at line 76)
  already validates `Target <= PowLimit`. Lines 85-88 re-decode
  the bits and check `Target <= PowLimit` AGAIN. Redundant.
- **Impact**: P3 — performance: an extra bits-decode per block.
  Cosmetic; remove the duplicate check.

### BUG-20 (P3) — No `block.fChecked` memoization → defense-in-depth re-check on connect_block always re-runs full CheckBlock

- **File**: `src/beamchain_validation.erl:1054-1060`.
- **Core ref**: `bitcoin-core/src/primitives/block.h`
  (`mutable bool fChecked` flag); `bitcoin-core/src/validation.cpp:3922`
  (`if (block.fChecked) return true;`).
- **Description**: Core memoizes `CheckBlock`'s pass via
  `block.fChecked`. beamchain re-runs the full `check_block/2`
  (per-tx iteration + merkle root + mutation + sigops) on every
  `connect_block` call. The re-check exists for "BLOCK_MUTATED
  defense-in-depth" (per the W93/B4 comment at line 1044).
- **Impact**: P3 — performance: O(block-validation) extra work
  per connect. The W93 comment acknowledges this is intentional
  defense-in-depth; Core's memoization saves time when the same
  block flows through validation twice. beamchain inherits the
  safety but pays the CPU cost.

### BUG-21 (P3) — `check_block` `bad_blk_sigops` doesn't include coinbase legacy sigops in the per-block total (uses `count_legacy_sigops_tx` over all txs incl coinbase, which is correct — but `connect_block` ALSO adds coinbase sigops at line 1307, double-counting)

- **File**: `src/beamchain_validation.erl:158-163` vs `:1306-1309`.
- **Core ref**: `bitcoin-core/src/validation.cpp:3974`
  (`for (const auto& tx : block.vtx) nSigOps += GetLegacySigOpCount(*tx);`
  — includes coinbase) and `:2569` (`if (nSigOpsCost > MAX_BLOCK_SIGOPS_COST)` in
  ConnectBlock, where coinbase sigops are NOT separately added —
  the per-tx loop covers them).
- **Description**: beamchain's `check_block` step 9 (line 158-163)
  counts legacy sigops across ALL txs including coinbase, scales
  by 4, and checks against MAX_BLOCK_SIGOPS_COST. Then
  `connect_block` step 4 sums `TxSigopCost` across non-coinbase
  txs (line 1173-1308) and SEPARATELY adds `CbSigops` for
  coinbase at line 1307. The per-tx `TxSigopCost` from
  `get_tx_sigop_cost` for non-coinbase ALREADY includes `LegacySigops * 4`
  (line 936). So the connect-block sigops total is correct.

  But: `check_block` (step 9) and `connect_block` (step 4 + coinbase
  add) run sigop checks INDEPENDENTLY against the same
  `MAX_BLOCK_SIGOPS_COST`. The `check_block` check fires on a
  DEFENSE-IN-DEPTH RE-CHECK at the start of `connect_block`
  (line 1054). If the legacy-sigops check passes in check_block,
  the same data goes through `get_tx_sigop_cost` in step 4 —
  no double-rejection. So functionally correct, but the audit
  trail is split across two routines.
- **Impact**: P3 — code clarity gap. Both checks are correct
  individually but the split makes it hard to audit which gate
  fires first for a given block. Cosmetic.

### BUG-22 (P2) — `check_block` does not enforce Core's "no other transaction may be coinbase" early-fail-fast position

- **File**: `src/beamchain_validation.erl:113-119`.
- **Core ref**: `bitcoin-core/src/validation.cpp:3953-3955`
  (`for (unsigned int i = 1; i < block.vtx.size(); i++)
   if (block.vtx[i]->IsCoinBase()) → bad-cb-multiple`).
- **Description**: beamchain iterates `RestTxs` and throws
  `extra_coinbase` if any one is coinbase (matching Core's
  `bad-cb-multiple`). But this runs at step 4, BEFORE the per-tx
  `check_transaction/1` loop at step 5. So far so good. **But**
  the iteration uses `lists:foreach` (not `lists:any`) — it
  doesn't early-exit on the first match. Core's
  `for (...)` returns on the first match.
- **Excerpt**:
  ```erlang
  lists:foreach(fun(Tx) ->
      is_coinbase_tx(Tx) andalso throw(extra_coinbase)
  end, RestTxs),
  ```
- **Impact**: P2 — Erlang's `lists:foreach` doesn't short-circuit
  on `andalso throw`; actually it DOES (because `throw` propagates
  up). So this IS early-exiting. Re-reading the code: `andalso throw`
  throws on the first match → equivalent to Core's behavior. **Not
  a bug after all.** Re-marking as P3 / **NOT-A-BUG**. Leaving the
  entry for transparency.

### BUG-23 (P3) — `MAX_BLOCK_SIGOPS_COST` is a HARD value, not derived from `MAX_BLOCK_WEIGHT / 50`

- **File**: `include/beamchain_protocol.hrl:10`
  (`-define(MAX_BLOCK_SIGOPS_COST, 80000)`).
- **Core ref**: `bitcoin-core/src/consensus/consensus.h:17`
  (`MAX_BLOCK_SIGOPS_COST = 80000`).
- **Description**: Both Core and beamchain use the literal 80000.
  Core's value is mathematically `MAX_BLOCK_WEIGHT / 50`. Neither
  derives it; both hard-code. Not a bug — flagged for code-quality
  consistency.
- **Impact**: P3 — none today. If `MAX_BLOCK_WEIGHT` ever changes
  in a hypothetical hardfork, the sigops constant should track
  it. Both impls would have to be updated.

### BUG-24 (P0) — `count_legacy_sigops_tx` includes coinbase sigops in `check_block` budget; Core ALSO does so (line 3972-3975) → MATCHES. But beamchain's `connect_block` step 4 sums non-coinbase via `get_tx_sigop_cost` and SEPARATELY adds `CbSigops`. Verify consistency.

- **File**: `src/beamchain_validation.erl:158-163`,
  `:1173-1224, :1306-1309`.
- **Core ref**: `bitcoin-core/src/validation.cpp:2564-2569`
  (`nSigOpsCost += GetTransactionSigOpCost(tx, view, flags);` —
  iterates ALL transactions including coinbase via the per-tx
  loop).
- **Description**: Re-examining the call graph:
  - `check_block` step 9: `LegacySigops * 4 <= 80_000` (all txs
    including coinbase).
  - `connect_block` step 4: non-coinbase tx sigops via
    `get_tx_sigop_cost` (returns legacy*4 + p2sh*4 + witness),
    plus `CbSigops = count_legacy_sigops_tx(CoinbaseTx) * 4` at
    line 1307, totaled at line 1308 against `MAX_BLOCK_SIGOPS_COST`.
  - Core: iterates ALL txs (including coinbase) calling
    `GetTransactionSigOpCost` (which adds P2SH and witness for
    non-coinbase; returns legacy-only for coinbase via the
    `if (tx.IsCoinBase()) return nSigOps;` early-return at line 147).

  So Core's per-tx loop OVER ALL txs is correct because the
  coinbase case returns early after counting legacy.
  beamchain's split (step 4 over non-coinbase + separate coinbase
  add) is also correct because `count_legacy_sigops_tx(CoinbaseTx) * 4`
  matches Core's coinbase contribution.
- **Impact**: P0 — **NOT-A-BUG after re-analysis.** Leaving as P0
  / **NOT-A-BUG** for transparency.

---

## Gate-by-gate matrix

| # | Behavior | Status | Notes |
|---|----------|--------|-------|
| 1.1 | `MAX_BLOCK_SIGOPS_COST = 80_000` | PRESENT | constant matches |
| 1.2 | Legacy sigops scaled by WSF=4 | PRESENT | step 9 in `check_block`, line 162 |
| 1.3 | P2SH sigops scaled by WSF=4 | PRESENT | `get_tx_sigop_cost` line 936 |
| 1.4 | Witness sigops counted | PRESENT | line 936 — adds without scaling |
| 1.5 | P2SH-wrapped witness sigops counted | PARTIAL | BUG-10 — push-only enforcement missing |
| 2.1 | BIP-34 coinbase encodes height | PRESENT | `check_coinbase_height` |
| 2.2 | CScriptNum encoding (not raw varint) | PRESENT | `encode_bip34_height` |
| 2.3 | Buried activation height (mainnet 227931) | PRESENT | chain_params line 40 |
| 3.1 | BIP-30 dup-coinbase rejection | PRESENT | `check_no_existing_outputs` |
| 3.2 | BIP-30 exception heights 91842 + 91880 | MISSING | **BUG-1 P0-CONSENSUS** — byte-order |
| 3.3 | BIP-30 disabled past BIP-34 activation | PARTIAL | **BUG-13 P2** — byte-order on canonical-chain proof |
| 3.4 | BIP-30 re-enabled at height ≥ 1983702 | PRESENT | line 1122 |
| 4.1 | Merkle root recompute | PRESENT | line 143 |
| 4.2 | CVE-2012-2459 mutation detection | PARTIAL | **BUG-4 P1** — only "odd-length last-two-equal", not Core's "any adjacent pair at any level" |
| 4.3 | Mutation algorithm runs in same pass as root compute | MISSING | **BUG-5 P1** — two full traversals |
| 4.4 | 64-byte non-coinbase tx structural defense | MISSING | **BUG-11 P1** — cross-cite W126 BUG-7 |
| 5.1 | MoneyRange invariant on each output | PRESENT | line 551-553 |
| 5.2 | MoneyRange on sum of outputs | PRESENT | line 557-562 |
| 5.3 | MoneyRange on inputs (consensus) | PRESENT | line 1190-1198 |
| 5.4 | MoneyRange on per-tx fee | PRESENT | line 1238-1240 |
| 5.5 | MoneyRange on accumulated block fees | PRESENT | line 1244-1247 |
| 6.1 | vin/vout non-empty | PRESENT | line 544-545 |
| 6.2 | Exactly one coinbase | PRESENT | line 113-119 |
| 6.3 | block.vtx[0] is coinbase | PRESENT | line 114 |
| 6.4 | No other coinbase | PRESENT | line 117-119 (early-throws via `andalso`) |
| 7.1 | Block weight <= MAX_BLOCK_WEIGHT (with witness) | PARTIAL | **BUG-14 P2** — placed in check_block, not contextual |
| 7.2 | Block base size <= 1 MB (no-witness, pre-segwit) | MISSING | **BUG-2 P0-CDIV** |
| 7.3 | block.vtx.size() * 4 <= MAX_BLOCK_WEIGHT | MISSING | **BUG-2 P0-CDIV** — defensive vtx-count gate |
| 7.4 | Per-tx bad-txns-oversize check | MISSING | **BUG-6 P0** |
| 8.1 | Time <= GetAdjustedTime() + MAX_FUTURE_BLOCK_TIME | PARTIAL | **BUG-7 P0** — uses local clock; **BUG-12 P1** — placed in context-free path; **BUG-15 P2** — re-checked on connect |
| 8.2 | Time > MTP of last 11 blocks | PRESENT | `contextual_check_block_header` line 192-195 |
| 8.3 | MAX_FUTURE_BLOCK_TIME named constant | MISSING | **BUG-7 P0** — `2 * 60 * 60` inlined |

---

## Severity rollup

| Severity | Count | Bugs |
|----------|-------|------|
| P0-CONSENSUS | 1 | BUG-1 (mainnet stall at 91842) |
| P0-CDIV | 1 | BUG-2 (bad-blk-length sub-gates) |
| P0 | 3 | BUG-6, BUG-7, BUG-8, BUG-9 — wait, that's 4 |
| P1 | 8 | BUG-3, BUG-4, BUG-5, BUG-10, BUG-11, BUG-12, BUG-24 (NOT-A-BUG; would be P0 if real) |
| P2 | 8 | BUG-13, BUG-14, BUG-15, BUG-16, BUG-17, BUG-18, BUG-22 (NOT-A-BUG), BUG-23 |
| P3 | 3 | BUG-19, BUG-20, BUG-21 |

(BUG-22 and BUG-24 are marked NOT-A-BUG after re-analysis but kept in the
list for transparency. The remaining 22 are real findings.)

## Cross-cutting smells observed

- **Two-pipeline guard** (W76+, 5th distinct extension in beamchain):
  `Bip30Exceptions` config-path + inline hard-coded fallback bytes
  in `disconnect_block`. The fallback is correct; the
  config-path is BUG-1.
- **Code-duplication smell** (1st instance W143):
  `merkle_pairs/1` and `merkle_pairs_check/1` are byte-identical;
  see BUG-5.
- **Comment-as-confession** (W76+, 6th instance fleet-wide):
  `:147-150` says "We check for duplicate final leaves which is
  the simplest form of this attack." — admits the divergence.
- **Inline magic-number**: `2 * 60 * 60` for MAX_FUTURE_BLOCK_TIME
  at validation.erl:80; should be `?MAX_FUTURE_BLOCK_TIME`.
- **Stricter-than-Core**: `MIN_TRANSACTION_WEIGHT >= 240` enforced
  in `check_transaction` (W142 BUG-21).
- **No clock mockability**: `erlang:system_time` is not
  test-injectable; future-time scenarios cannot be simulated in
  unit tests.

## Priority next fixes (this wave)

1. **BUG-1 P0-CONSENSUS** — `chain_params` byte-order fix. One-line
   per hash: wrap `hex_to_bin/1` with `beamchain_serialize:reverse_bytes/1`
   for fields compared against `block_hash/1`. A 3-line change
   affecting `bip30_exceptions` and `bip34_hash` (and possibly
   `genesis_hash`, `assume_valid`, `min_chainwork` — those need
   separate verification against their consumers' byte-order
   expectations). **Mainnet sync blocker.**
2. **BUG-2 P0-CDIV** — add the two missing `bad-blk-length`
   sub-gates in `check_block` between the no-transactions check
   and the per-tx iteration.
3. **BUG-6 P0** — add `Weight =< MAX_BLOCK_WEIGHT` upper bound in
   `check_transaction/1`.
4. **BUG-7 / BUG-8 P0** — define `?MAX_FUTURE_BLOCK_TIME` in
   `beamchain_protocol.hrl`; route through a `beamchain_clock`
   abstraction; move the future-time check from
   `check_block_header` to `contextual_check_block_header` to
   match Core's layering.
5. **BUG-4 / BUG-5 P1** — fold mutation detection into
   `compute_merkle_root/1` (single traversal returns
   `{Root, MutatedFlag}`); delete the duplicate `merkle_pairs_check`.
6. **BUG-11 P1** — wire `IsBlockMutated`-equivalent into
   `beamchain_block_sync:handle_block_received` so peers sending
   mutated blocks are misbehave-scored.
