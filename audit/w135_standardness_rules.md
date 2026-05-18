# W135 — Standardness rules (IsStandardTx) audit (beamchain)

Discovery-only wave. 30 audit gates against Core's mempool standardness
gate: **IsStandardTx** (`bitcoin-core/src/policy/policy.cpp:100-165`,
`policy.h:152-159`), the output classifier **Solver**
(`bitcoin-core/src/script/solver.{cpp,h}`, 228+67 LOC), the dust gate
**GetDustThreshold / IsDust / GetDust**
(`bitcoin-core/src/policy/policy.cpp:27-78`), the input-side standardness
gate **ValidateInputsStandardness**
(`bitcoin-core/src/policy/policy.cpp:214-263`), and the small companion
helpers (`MIN_STANDARD_TX_NONWITNESS_SIZE` gate in
`bitcoin-core/src/validation.cpp:813-814`,
`MAX_OP_RETURN_RELAY` budget arithmetic, `permit_bare_multisig` /
`max_datacarrier_bytes` plumbing). TRUC / `truc_policy.cpp` is referenced
where TRUC topology interacts with the version-3 standardness gate; the
full TRUC topology audit was W120.

`IsWitnessStandard` (`policy.cpp:265-351`) has its own dedicated test file
(`test/beamchain_witness_standard_tests.erl`, 7 gates) and is **not**
re-audited here. W135 covers the non-witness, output-side classifier and
the input-side ValidateInputsStandardness paths.

Companion audits to cross-reference:
- **W120** — RBF + cluster mempool (mempool dynamics). 33 gates, found the
  `validateRbfDiagram` dead-helper that FIX-79 closed.
- **W96** — ATMP gates wave (the 21 PreChecks gates of MemPoolAccept).
  Established the gate-by-gate naming convention that this audit reuses
  (W96 GATE 3 = `check_standard`, GATE 7 = `is_witness_standard`,
  GATE 8 = `validate_inputs_standardness`).
- **W127** — Taproot. Cross-checks the BIP-341 spend semantics that the
  taproot output classifier here treats as "standard on output, may be
  non-standard on input depending on version".
- **W117** — BIP-155 (addrv2). Cross-impl pattern: discovery-only audits
  that document divergence rather than producing fixes immediately.

Reference: `bitcoin-core/src/policy/policy.{cpp,h}`,
`bitcoin-core/src/script/solver.{cpp,h}`,
`bitcoin-core/src/policy/truc_policy.cpp`,
`bitcoin-core/src/consensus/tx_check.cpp`,
`bitcoin-core/src/validation.cpp:780-1190` (PreChecks).

## Status counts (30 gates)

- **PRESENT** (matches Core or internally consistent + Core-compatible): 9
- **PARTIAL** (some piece matches, others diverge or are simplified): 11
- **MISSING** (no equivalent in beamchain): 10

Headline: **22 bugs**, severity distribution **0 CDIV / 4 HIGH / 11 MEDIUM
/ 7 LOW**. Standardness is policy, not consensus: a non-standard tx is
silently dropped at relay/mempool admission but a block containing it is
still validated. No bug here can fork the chain. The most consequential
divergences:

1. **BUG-1 (HIGH)** — **Bare P2PK (`<pubkey> OP_CHECKSIG`) outputs are
   classified `nonstandard`.** Core's `Solver` returns
   `TxoutType::PUBKEY` for `<33-byte-pubkey> OP_CHECKSIG` (33+1+1 = 35
   bytes) and `<65-byte-pubkey> OP_CHECKSIG` (65+1+1 = 67 bytes), and
   `IsStandard` accepts them. beamchain's `classify_output_standard/1`
   (`beamchain_mempool.erl:1659-1669`) has no PUBKEY case — bare-pubkey
   outputs fall through to the catch-all `nonstandard` clause and
   `check_standard` throws `scriptpubkey`. Historical mainnet still has
   many P2PK outputs (genesis coinbase is P2PK; ~2-3% of pre-2012 coins).
   A tx that pays P2PK directly would be rejected from the beamchain
   mempool. The INPUT side (`classify_input_template/1`,
   `beamchain_mempool.erl:4174-4213`) DOES have a `pubkey` arm (line
   4210-4211) — so spending an existing P2PK output is allowed, but
   CREATING a new one is rejected. Asymmetric.

2. **BUG-2 (HIGH)** — **Bare multisig outputs (`OP_M <pk1>..<pkN> OP_N
   OP_CHECKMULTISIG`) are classified `nonstandard`.** Core's `Solver`
   returns `TxoutType::MULTISIG` and `IsStandard` (`policy.cpp:87-95`)
   accepts m-of-n for `n=1..3, m=1..n`. beamchain's output classifier has
   NO multisig case. The INPUT classifier does (`classify_input_template`
   line 4200-4204) — symmetric with BUG-1's asymmetry. Plus there's no
   `permit_bare_multisig` config flag at all
   (`policy.h:52: DEFAULT_PERMIT_BAREMULTISIG{true}`), so beamchain
   *unconditionally* rejects what Core *optionally* accepts.

3. **BUG-3 (HIGH)** — **No `permit_bare_multisig` config.** Core exposes
   `-permitbaremultisig` (default `true`) so operators can disable bare
   multisig relay if they want to reserve mempool space. beamchain neither
   accepts bare multisig (BUG-2) nor lets the operator toggle it.

4. **BUG-4 (HIGH)** — **No `max_datacarrier_bytes` configurability.**
   Core's `IsStandardTx` takes `max_datacarrier_bytes` as an
   `std::optional<unsigned>`; `nullopt` means "OP_RETURN outputs
   forbidden", any value means "global per-tx budget = that many bytes".
   This wires up to `-datacarrier` (boolean) + `-datacarriersize` (the
   numeric budget). beamchain hardcodes the budget at
   `MAX_OP_RETURN_RELAY = 100000` (`beamchain_protocol.hrl:180`); there
   is no way for the operator to disable OP_RETURN relay or shrink the
   per-tx budget. Affects relay-policy customisation.

5. **BUG-5 (MEDIUM)** — **`is_push_only/1` rejects `OP_RESERVED` (0x50).**
   Core's `CScript::IsPushOnly` (`script.cpp:265-280`) explicitly accepts
   OP_RESERVED as push-only because `if (opcode > OP_16) return false;`
   and OP_RESERVED = 0x50 < OP_16 = 0x60. beamchain's
   `beamchain_script.erl:3030-3059` has no clause for 0x50 (only handles
   1..0x4b raw pushes, OP_0=0x00, OP_PUSHDATA1/2/4, OP_1NEGATE=0x4f, and
   OP_1..OP_16). A scriptSig containing OP_RESERVED therefore makes
   `check_standard` throw `scriptsig_not_pushonly` while Core would accept
   it. Also affects the scope of where `scriptpubkey` truncated-OP_RETURN
   tests would reject — OP_RETURN with an OP_RESERVED in the payload is
   currently *non-standard* in beamchain but *standard* in Core (because
   the `IsPushOnly(begin()+1)` check at Solver line 185 also accepts
   OP_RESERVED).

6. **BUG-6 (MEDIUM)** — **No `MAX_DUST_OUTPUTS_PER_TX = 1` gate.** Core
   (`policy.h:95`) allows up to one dust output per transaction (the
   "ephemeral dust" lane) regardless of fee, gated by the
   `GetDust(tx).size() > MAX_DUST_OUTPUTS_PER_TX` check at
   `policy.cpp:159-162`. beamchain has two related but DIFFERENT gates:
   `check_dust` (line 2147-2167) throws on the FIRST dust output unless it
   is a zero-value P2A ephemeral anchor; `pre_check_ephemeral_tx` rejects
   ANY dust output if fee > 0. There is no explicit count-based gate —
   the semantics diverge subtly: a tx with one dust output, fee=0, and
   no P2A is rejected as `ephemeral_anchor_needs_spending` in beamchain
   but PASSES Core's count gate (it is the 1 allowed ephemeral dust output
   per policy, and the package-relay child must spend it).

7. **BUG-7 (MEDIUM)** — **Dust-threshold spend-input-size constants drift
   from Core.** Core's `GetDustThreshold` (`policy.cpp:27-64`) computes
   the spend cost as `32 + 4 + 1 + 107 + 4 = 148` for non-witness and
   `32 + 4 + 1 + (107/4) + 4 = 67` for any witness program. beamchain's
   `spend_input_size/1` table (`beamchain_mempool.erl:2217-2227`) uses
   `p2wpkh=68, p2wsh=68, p2tr=58, p2a=67`. Three drifts: `p2wpkh/p2wsh`
   are off-by-one (68 vs 67), `p2tr` is off by nine (58 vs 67). Result:
   beamchain's P2TR dust threshold is `303 sat` versus Core's `330 sat`
   at default `DUST_RELAY_TX_FEE = 3000`; beamchain admits txs Core
   rejects.

8. **BUG-8 (MEDIUM)** — **Dust output-size formula does not handle large
   scriptPubKey varint.** Core computes `nSize = GetSerializeSize(txout)`
   which uses the full varint encoding of `scriptPubKey.size()`. beamchain
   hardcodes `OutputSize = 8 + 1 + byte_size(SPK)` — the `1` assumes the
   varint is one byte, which only holds for SPK ≤ 252 bytes. Any
   scriptPubKey ≥ 253 bytes (rare but legal: e.g. a witness scriptPubKey
   that pushes large data) would have a 3-byte varint, and beamchain
   would under-count by 2 bytes. The dust threshold would be 0.6% too
   low. Tiny but technically incorrect for non-standard-but-legal SPK
   sizes.

9. **BUG-9 (MEDIUM)** — **`MIN_STANDARD_TX_NONWITNESS_SIZE` reason atom
   collides with `MAX_STANDARD_TX_WEIGHT` reason atom.** Core
   distinguishes `"tx-size"` (the weight cap from
   `policy.cpp:113`) from `"tx-size-small"` (the 65-byte minimum from
   `validation.cpp:814`). beamchain's `check_standard` throws the same
   atom `tx_size` for both gates (`beamchain_mempool.erl:1616, 1622`).
   RPC error reporting via `testmempoolaccept` cannot distinguish them.
   The CVE-2017-12842 reason should be `'tx-size-small'`.

10. **BUG-10 (MEDIUM)** — **Coinbase rejection precedes `IsStandardTx` in
    beamchain.** Core checks `tx.IsCoinBase()` at `validation.cpp:803-804`
    BEFORE the standardness gate runs, returning the
    `TX_CONSENSUS "coinbase"` reason. beamchain runs `check_standard` at
    line 583 of `do_add_transaction` AFTER the W96 GATE 1b coinbase check
    at line 563-564, which is correct ordering. But `check_standard` does
    NOT itself reject coinbase tx (the `is_coinbase_tx` guard is upstream).
    If a caller bypasses `do_add_transaction` and invokes `check_standard`
    directly on a coinbase tx, the coinbase scriptSig (the height push +
    extra-nonce) would fail the `is_push_only` gate but with the wrong
    reason (`scriptsig_not_pushonly` instead of the coinbase-specific
    `bad-txns-coinbase`). Documentation / robustness issue only.

11. **BUG-11 (MEDIUM)** — **No `WITNESS_UNKNOWN` distinction on output
    classifier return.** Core's `Solver` returns `TxoutType::WITNESS_UNKNOWN`
    for any future witness version (v2..v16) with a 2-40-byte program; the
    classifier on the **output side** then treats it as STANDARD (the
    forward-compat goal). beamchain's `classify_output_standard` returns
    the term `{witness, N}` (line 1668) for the same input. `check_standard`
    then matches it via the catch-all `_Known -> Budget` arm (line 1643)
    so it ends up standard. *However*, no test or downstream consumer
    distinguishes `{witness, 2}` from `{witness, 3}` etc.: any future
    soft-fork-driven extension would need to add a specific case to
    `classify_output_standard` for the new version. Core's
    `WITNESS_UNKNOWN` is an explicit token (a non-NONSTANDARD non-known
    catch-all); beamchain's `{witness, N}` is similarly a catch-all but
    carries the version number, which is *more* information than Core
    exposes via `TxoutType`. Documentation gap, not a correctness bug.

12. **BUG-12 (MEDIUM)** — **Witness v0 with size != {20,32} is treated as
    `nonstandard` on the OUTPUT side.** Core's `Solver` for witness v0
    with size 20 returns WITNESS_V0_KEYHASH; with size 32 returns
    WITNESS_V0_SCRIPTHASH; with any OTHER size in [2,40], returns
    `TxoutType::NONSTANDARD` via the fall-through at solver.cpp:177.
    beamchain matches this behavior — but only by happy accident: the
    "future witness" catch-all at `classify_output_standard` line 1666-
    1668 has a guard `WitVer >= 16#51` (i.e. ≥ OP_1) so witness v0 with
    weird length never matches that arm. It falls through to the
    `nonstandard` final clause. Behavior is correct, but the *intent*
    documentation is missing — a maintainer adding witness v0 alternative
    sizes could accidentally widen the standard set.

13. **BUG-13 (MEDIUM)** — **OP_RETURN dust gate uses byte_size of full
    scriptPubKey, not the value-vs-threshold check.** This is correct per
    Core (OP_RETURN outputs are unspendable so dust threshold is 0; they
    are never dust). beamchain's `is_dust_output` early-returns `false`
    for `<<16#6a, _>>` (line 4254-4257). Match with Core — but the
    `dust_threshold` function itself (line 2212-2215) does NOT special-
    case OP_RETURN at all; if it were called directly on an OP_RETURN SPK
    it would return a non-zero positive number. This is benign because
    `is_dust_output` short-circuits first, but the helper is internally
    inconsistent: Core's `GetDustThreshold` returns 0 for any
    `IsUnspendable()` script, which is the canonical guard.

14. **BUG-14 (MEDIUM)** — **No `IsUnspendable` guard on dust threshold.**
    Core's `GetDustThreshold` (`policy.cpp:43-44`) early-returns 0 for
    any `scriptPubKey.IsUnspendable()` (i.e. starts with `OP_RETURN` OR
    is provably-prunable via any other path). beamchain's
    `dust_threshold/1` only checks for the OP_RETURN prefix indirectly
    via `is_dust_output`. A scriptPubKey of `<<0x6a, ...>>` is handled
    correctly by short-circuit, but other unspendable forms (e.g. an
    OP_RESERVED-only script, or any script that always fails like
    `<<0x00>>`) are not. Theoretical, since few non-OP_RETURN unspendable
    forms appear in practice.

15. **BUG-15 (MEDIUM)** — **`classify_input_template` does not enforce
    `permit_bare_multisig` on input side.** This mirrors BUG-3 on the
    output side. The input arm at `beamchain_mempool.erl:4200-4204`
    accepts up to 3-of-3 bare multisig unconditionally. The output side
    rejects all bare multisig. Asymmetry: an existing bare-multisig UTXO
    (mined by someone else, perhaps via a relaxed-relay node) can be
    spent through the beamchain mempool, but creating a new one is
    rejected. Symmetric with BUG-1's P2PK asymmetry.

16. **BUG-16 (LOW)** — **Multisig output cap is policy=3 in Core, but
    consensus-level `MAX_PUBKEYS_PER_MULTISIG` is 20.** Core's
    `Solver/MatchMultisig` accepts up to `MAX_PUBKEYS_PER_MULTISIG = 20`
    keys (`script.h`), but `IsStandard` then caps it at n=1..3.
    beamchain's `classify_input_template` cap is hardcoded to 3 at
    line 4228 (`Acc =< 3`). The CONSTANT is correct but the *source* of
    the constant is not the protocol-wide `MAX_PUBKEYS_PER_MULTISIG`
    define — it's a literal `3`. A future change to "x-of-5 standard
    multisig" would need to find and edit this literal. Cosmetic.

17. **BUG-17 (LOW)** — **Multisig matcher does not validate pubkey
    validity.** Core's `MatchMultisig` collects pubkey pushes and then
    calls `CPubKey::ValidSize(data)` to ensure each is 33 or 65 bytes
    (compressed or uncompressed). beamchain's `classify_multisig_tail`
    (line 4221-4230) accepts 33-byte or 65-byte pushes by matching
    `<<16#21, _:33/binary, ...>>` and `<<16#41, _:65/binary, ...>>` but
    does not check that the bytes actually parse as a valid secp256k1
    point. That's identical to Core's `ValidSize` check (which is also
    size-only, not point-on-curve). PARITY — listed as LOW only because
    the source comment ("crude bare-multisig tail check") suggests the
    author wasn't sure.

18. **BUG-18 (LOW)** — **Witness v1 (Taproot) policy verification asymmetry
    between output and input classifier.** Output side `classify_output_standard`
    accepts ONLY witness v1 with 32-byte program (line 1663). Input side
    `classify_input_template` accepts the same (line 4182-4183), but also
    accepts witness v1 with 2-byte P2A program (line 4184-4185). Wait —
    this matches Core's Solver which separates ANCHOR (v1, 2-byte) from
    WITNESS_V1_TAPROOT (v1, 32-byte). beamchain output classifier line
    1664 also has the P2A case BEFORE the taproot case. The asymmetry is
    actually fine. *Listed as LOW for completeness*: a v1 with size in
    (2,32) is classified WITNESS_UNKNOWN in Core (returning
    `TxoutType::WITNESS_UNKNOWN` which is STANDARD on output side); in
    beamchain it matches the future-witness catch-all at line 1666-1668
    and returns `{witness, 1}`. Same end behavior (admitted), different
    intermediate label.

19. **BUG-19 (LOW)** — **`spend_input_size` of `_unknown` is 148, not 67.**
    Core's `GetDustThreshold` consults `scriptPubKey.IsWitnessProgram` to
    decide between 67 and 148 — for any unknown but witness-program-shaped
    SPK, Core uses 67. beamchain's fallback in `spend_input_size/1` is
    148 (non-witness). For a witness v2-v16 output (which `classify_output`
    returns `unknown`), beamchain would compute the dust threshold as
    `(8 + 1 + spk_size + 148) * 3000 / 1000` — overstating the threshold
    by `(148-67)*3 = 243 sat`. Future-witness outputs would have a stricter
    dust threshold than Core. Forward-incompat for soft-fork lanes.

20. **BUG-20 (LOW)** — **`scriptpubkey` is the catch-all reason atom.**
    Core's `IsStandardTx` distinguishes the per-output failure modes via
    a single `reason="scriptpubkey"` BUT keeps `whichType` in the
    `TxoutType` enum so the caller can re-classify. beamchain throws
    `scriptpubkey` atom from `check_standard` but does not surface the
    failed type. testmempoolaccept's `reject-reason` is therefore less
    helpful than Core's. Cosmetic; alignment with the existing approach
    in W125 RPC parity.

21. **BUG-21 (LOW)** — **`bare-multisig` reason atom not surfaced.**
    Per Core's `policy.cpp:152-154`, when `permit_bare_multisig` is false
    and a multisig output is found, the reason is `"bare-multisig"`.
    beamchain unconditionally rejects bare multisig as `scriptpubkey`
    (via the nonstandard fall-through). The dedicated reason atom does
    not exist. Cosmetic.

22. **BUG-22 (LOW)** — **No DEFAULT_BYTES_PER_SIGOP override path in
    standardness layer.** Not strictly a `IsStandardTx` gate (it's used
    by `GetVirtualTransactionSize` for the vsize calculation), but
    relevant because Core allows `-bytespersigop` to be tuned (default
    20). beamchain hardcodes `?DEFAULT_BYTES_PER_SIGOP = 20` via
    `beamchain_protocol.hrl:160` and the `tx_sigop_vsize` helper does
    not consult any operator override. Standardness-adjacent.

**Not a CDIV**: every bug above affects only the relay/admission policy.
A non-standard tx is dropped from the mempool but a block containing it
is still valid by consensus. The beamchain node would still accept and
relay a *block* containing a P2PK output (BUG-1), a bare multisig (BUG-2),
or a 5-of-7 multisig (BUG-2/3) — it just won't accept the loose tx at
the mempool door. Cluster severity: 4 HIGH / 11 MEDIUM / 7 LOW.

The audit-flip convention applies: every test that asserts a divergent
fact (e.g. "bare P2PK is non-standard in beamchain") is written so it
**passes today** and **will fail when the fix lands**, flipping the gate
from MISSING/BUG → PRESENT.

## What a fix wave would touch

The minimum-viable fix wave for the HIGH bugs:

1. **BUG-1+2+3+15 (output and input multisig+P2PK)** — Add `pubkey` and
   `multisig` arms to `classify_output_standard` mirroring `classify_input_template`.
   Add a `permit_bare_multisig` boolean to the mempool gen_server state
   (default `true`), plumb it through `check_standard`, and have the
   multisig arm short-circuit to `bare-multisig` reason when disabled.
   Symmetrise output and input templates.

2. **BUG-4 (datacarrier configurability)** — Add `max_datacarrier_bytes`
   to the mempool gen_server options; plumb `-datacarrier` (boolean
   on/off) and `-datacarriersize` (numeric vbytes) via
   `beamchain_config`. Replace the literal `?MAX_OP_RETURN_RELAY` in
   `check_standard` with the per-mempool config value, defaulting to
   100000.

3. **BUG-5 (push-only OP_RESERVED)** — Add an `OP_RESERVED` clause to
   `is_push_only/1` in `beamchain_script.erl` matching Core's
   `if (opcode > OP_16) return false;` semantics. One-line fix.

4. **BUG-6 (MAX_DUST_OUTPUTS_PER_TX)** — Add an explicit count-based
   gate in `check_standard` (or PreChecks gate 13c) that allows up to
   `?MAX_DUST_OUTPUTS_PER_TX = 1` dust output per transaction in line
   with `policy.cpp:159-162`. Decouple the ephemeral-anchor path from
   the dust-count path.

5. **BUG-7+8 (dust threshold formula drifts)** — Replace
   `spend_input_size` with a single function that returns 67 for any
   witness-program SPK and 148 otherwise. Replace `OutputSize = 8 + 1 +
   byte_size(SPK)` with a real serialize-size computation that uses
   `beamchain_serialize:encode_varint/1` for the SPK length prefix.

6. **BUG-9 (tx-size-small reason)** — Split the `tx_size` throw in
   `check_standard` into `tx_size` (weight) and `tx_size_small`
   (non-witness 65-byte minimum).

The full close-out of all 22 bugs is a single-impl wave estimated at
60-90 minutes (the output-classifier symmetry work + the config plumbing
is the bulk; the dust-formula tweaks + reason-atom split are quick
follow-ons).

Until then: every test in `beamchain_w135_standardness_tests.erl`
documents the *current* (divergent) behavior, asserts it, and PASSES
today. When the fix lands, those tests FAIL — flipping the gates from
MISSING/BUG → PRESENT.

---

## Gate index (1..30)

| #  | Name | Status | Core ref | beamchain ref |
|----|------|--------|----------|---------------|
| 1  | `TX_MIN_STANDARD_VERSION` / `TX_MAX_STANDARD_VERSION` (1..3)                              | PRESENT | policy.h:152-153                            | `check_standard` line 1613 |
| 2  | `MAX_STANDARD_TX_WEIGHT = 400000` weight gate                                            | PRESENT | policy.h:38, policy.cpp:111-115             | `check_standard` line 1615-1616 |
| 3  | `MIN_STANDARD_TX_NONWITNESS_SIZE = 65` CVE-2017-12842                                    | PARTIAL | validation.cpp:813-814                      | line 1621-1622 (BUG-9 reason atom) |
| 4  | `MAX_STANDARD_SCRIPTSIG_SIZE = 1650` per-input cap                                       | PRESENT | policy.h:62, policy.cpp:127-130             | `check_standard` line 1627 |
| 5  | `IsPushOnly(scriptSig)` per input                                                        | PARTIAL | policy.cpp:131-134, script.cpp:265-280      | line 1628 (BUG-5: OP_RESERVED missing) |
| 6  | Output classifier: `TxoutType::PUBKEY` (bare P2PK)                                       | MISSING | solver.cpp:190-193, MatchPayToPubkey        | `classify_output_standard` has no arm (BUG-1) |
| 7  | Output classifier: `TxoutType::PUBKEYHASH` (P2PKH)                                       | PRESENT | solver.cpp:195-198                          | line 1659 (P2PKH OP_DUP OP_HASH160 ... OP_EQUALVERIFY OP_CHECKSIG) |
| 8  | Output classifier: `TxoutType::SCRIPTHASH` (P2SH)                                        | PRESENT | solver.cpp:147-152                          | line 1660 |
| 9  | Output classifier: `TxoutType::MULTISIG` + n=1..3 + m=1..n                               | MISSING | solver.cpp:200-207 + policy.cpp:87-95       | no arm; bare multisig rejected as `scriptpubkey` (BUG-2/3) |
| 10 | Output classifier: `TxoutType::NULL_DATA` (OP_RETURN + push-only)                        | PRESENT | solver.cpp:185-187                          | line 1654-1658 (W56 fix already applied) |
| 11 | Output classifier: `TxoutType::ANCHOR` (P2A)                                             | PRESENT | solver.cpp:169-171, script.cpp:206-213      | line 1664 |
| 12 | Output classifier: `TxoutType::WITNESS_V0_KEYHASH` (P2WPKH)                              | PRESENT | solver.cpp:157-160                          | line 1661 |
| 13 | Output classifier: `TxoutType::WITNESS_V0_SCRIPTHASH` (P2WSH)                            | PRESENT | solver.cpp:161-164                          | line 1662 |
| 14 | Output classifier: `TxoutType::WITNESS_V1_TAPROOT` (P2TR)                                | PRESENT | solver.cpp:165-168                          | line 1663 |
| 15 | Output classifier: `TxoutType::WITNESS_UNKNOWN` (future witness v2-v16, 2-40 bytes)      | PARTIAL | solver.cpp:172-176                          | line 1666-1668 returns `{witness, N}` (BUG-11/12) |
| 16 | `MAX_OP_RETURN_RELAY = 100000` per-tx datacarrier budget                                 | PARTIAL | policy.h:84, policy.cpp:137,147-151         | line 1635-1647 hardcoded; no config (BUG-4) |
| 17 | `permit_bare_multisig` config (default true)                                             | MISSING | policy.h:52, policy.cpp:152-155             | no gate; bare multisig unconditionally `nonstandard` (BUG-3) |
| 18 | `max_datacarrier_bytes` config (Optional<unsigned>)                                      | MISSING | policy.h:159, validation.cpp:808            | no config; hardcoded 100000 (BUG-4) |
| 19 | `GetDustThreshold` formula (output_size + spend_input_size) * dust_relay_fee / 1000     | PARTIAL | policy.cpp:27-64                            | `dust_threshold/1` line 2212-2215 (BUG-7/8) |
| 20 | `GetDustThreshold` early-return 0 for `IsUnspendable()`                                  | PARTIAL | policy.cpp:43-44                            | `is_dust_output` shortcircuits OP_RETURN only (BUG-13/14) |
| 21 | `IsDust(txout, feerate)` per-output                                                      | PRESENT | policy.cpp:66-69                            | `is_dust_output/1` line 4253-4259 |
| 22 | `GetDust(tx).size() > MAX_DUST_OUTPUTS_PER_TX (=1)` gate                                 | MISSING | policy.h:95, policy.cpp:159-162             | `pre_check_ephemeral_tx` is fee-gated, not count-gated (BUG-6) |
| 23 | `ValidateInputsStandardness` per-input scriptPubKey classifier                           | PRESENT | policy.cpp:226-260                          | `validate_inputs_standardness_loop` line 4130-4164 |
| 24 | `ValidateInputsStandardness` WITNESS_UNKNOWN input reject                                | PRESENT | policy.cpp:234-240                          | `classify_input_template` line 4138 |
| 25 | `ValidateInputsStandardness` P2SH redeem-script sigop cap (MAX_P2SH_SIGOPS=15)           | PRESENT | policy.cpp:241-258, policy.h:42             | line 4144-4161 |
| 26 | `CheckSigopsBIP54` (MAX_TX_LEGACY_SIGOPS=2500 cap on legacy sigops)                      | MISSING | policy.cpp:170-194, policy.h:46             | not implemented anywhere |
| 27 | `MAX_STANDARD_TX_SIGOPS_COST = 16000` global sigops gate                                 | PRESENT | policy.h:44                                 | mempool gate 9 line 631 |
| 28 | `SpendsNonAnchorWitnessProg` (for BIP-431 v3/TRUC interaction)                           | MISSING | policy.cpp:354-388                          | no equivalent; TRUC partial via `check_truc_rules` |
| 29 | `IsStandardTx` reason-string surface (`version`, `tx-size`, `tx-size-small`,             |         |                                             |               |
|    | `scriptsig-size`, `scriptsig-not-pushonly`, `scriptpubkey`, `datacarrier`,                |         |                                             |               |
|    | `bare-multisig`, `dust`)                                                                  | PARTIAL | policy.cpp:100-164                          | atom-based; collisions/missing (BUG-9/20/21) |
| 30 | `MatchMultisig` pubkey size + count validation (33/65-byte pubkeys, n ≤ MAX_PUBKEYS)     | PARTIAL | solver.cpp:85-105                           | `classify_multisig_tail` line 4218-4230 (BUG-16/17) |

## Notes on `IsWitnessStandard` (already audited)

The witness-side standardness rules (`policy.cpp:265-351`) are NOT part
of W135 — they have their own dedicated test file
(`test/beamchain_witness_standard_tests.erl`, 7 gates) and were closed
out as part of the W96 wave. Cross-reference for completeness:

- Gate 1: coinbase exempt — PRESENT
- Gate 2: empty witness skipped — PRESENT
- Gate 3: P2A with witness → reject — PRESENT
- Gate 4: P2SH redeemScript via EvalScript — PRESENT
- Gate 5: non-witness prevScript with non-empty witness → reject — PRESENT
- Gate 6: P2WSH limits (3600 / 100 / 80) — PRESENT
- Gate 7: Taproot limits (no annex, 80-byte stack item cap) — PRESENT

If W135 finds a regression in any of those gates, it would be filed
under W96 errata, not under W135.

## Cross-impl posture

| impl | output classifier | bare P2PK | bare multisig | permit_bare_multisig config | datacarrier config |
|------|-------------------|-----------|---------------|------------------------------|---------------------|
| bitcoin-core | full Solver | yes | yes (n≤3) | yes (`-permitbaremultisig`) | yes (`-datacarrier`, `-datacarriersize`) |
| beamchain | template-based | **no (BUG-1)** | **no (BUG-2)** | **no (BUG-3)** | **no (BUG-4)** |

(Other impls not yet audited at this wave; ouroboros's `policy.py`,
rustoshi's `policy.rs`, and clearbit's `policy.zig` likely have similar
template-classifier shapes — pattern reuse predicted.)
