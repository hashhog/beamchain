# W127 — Taproot / Schnorr / Tapscript audit (beamchain)

Discovery-only wave. 30 audit gates against BIP-340 (Schnorr signatures),
BIP-341 (Taproot key-path + script-path), and BIP-342 (Tapscript opcodes,
OP_CHECKSIGADD, leaf version 0xC0, validation-weight budget).

Reference: `bitcoin-core/src/script/interpreter.cpp` (EvalChecksigTapscript,
ExecuteWitnessScript, VerifyTaprootCommitment, SignatureHashSchnorr,
ComputeTaprootMerkleRoot, ComputeTapleafHash), `bitcoin-core/src/script/script.h`
(VALIDATION_WEIGHT_PER_SIGOP_PASSED, VALIDATION_WEIGHT_OFFSET, IsOpSuccess),
`bitcoin-core/src/script/interpreter.h` (TAPROOT_LEAF_MASK,
TAPROOT_LEAF_TAPSCRIPT, TAPROOT_CONTROL_BASE_SIZE,
TAPROOT_CONTROL_NODE_SIZE, TAPROOT_CONTROL_MAX_NODE_COUNT,
WITNESS_V1_TAPROOT_SIZE, ANNEX_TAG), `bitcoin-core/src/key.cpp` +
`pubkey.cpp` (Schnorr, XOnlyPubKey, CheckTapTweak),
`bitcoin-core/src/test/data/script_assets_test.json` (vector set).

Status counts:

- **PRESENT** (Core-parity / consensus-faithful): 23
- **PARTIAL** (logic exists but a sub-condition diverges or is missing): 4
- **MISSING** (no equivalent in beamchain): 3

Headline: **7 BUGS** in beamchain's BIP-340/341/342 surface.
None are P0-CONSENSUS for the canonical happy paths — W94 / W95 already
closed the highest-impact gates (annex threading, validation-weight
budget, hash_type whitelist, P2SH-wrapped Taproot fall-through). The
remaining BUGS cluster around (a) defensive parsing where Core emits a
different error code than beamchain, (b) test-mode hash hooks that
quietly bypass spec checks, (c) a missing `m_*_init` paranoia gate that
Core asserts and beamchain has no equivalent for, and (d) a
script-assets test-vector corpus that beamchain does not consume at all.

This audit asserts current divergent behaviour in
`test/beamchain_w127_taproot_tests.erl` so a follow-up FIX wave will
flip them PASS → FAIL when the production code is brought into parity
(audit-flip convention used by W94 → 6164c4f, W95 → 4c630f5,
W120 / W121 / W125).

---

## Gate index (1..30)

| #  | Name | Status | Core ref | beamchain ref |
|----|------|--------|----------|---------------|
| 1  | BIP-340 Schnorr `schnorr_verify/3` (NIF) | PRESENT | key.cpp / secp256k1_schnorrsig | beamchain_crypto.erl:202-219 |
| 2  | BIP-340 tagged-hash construction (`SHA256(SHA256(tag) \|\| SHA256(tag) \|\| data)`) | PRESENT | hash.h HASHER_TAPSIGHASH etc. | beamchain_crypto.erl:560-562 |
| 3  | BIP-340 tag-hash cache pre-warmed for `BIP0340/{challenge,aux,nonce}` + 4 Tap tags | PRESENT | (Core re-derives every call; not a parity gap) | beamchain_crypto.erl:710-728 |
| 4  | BIP-340 Schnorr sig-cache lookup before NIF | PRESENT | script/sigcache.h:64-74 | beamchain_crypto.erl:261-276 |
| 5  | BIP-340 batch Schnorr verify | PRESENT (Erlang fallback iterates schnorr_verify/3 on NIF miss) | secp256k1_schnorrsig batch | beamchain_crypto.erl:694-708 |
| 6  | Witness v1 + 32 bytes + non-P2SH gates Taproot path | PRESENT | interpreter.cpp:1947 | beamchain_script.erl:2653-2658 |
| 7  | Witness v1 + 32 + P2SH falls through to upgradable-witness branch | PRESENT (W94 fix) | interpreter.cpp:1947 | beamchain_script.erl:2578-2584 |
| 8  | Witness v1 + non-32-byte program pre-Taproot succeeds (anyone-can-spend) | PRESENT (W94 fix) | interpreter.cpp:1990-1997 | beamchain_script.erl:2684-2696 |
| 9  | Witness v1 + 0x4e73 (P2A) is anyone-can-spend, bypasses DISCOURAGE | PRESENT | script.cpp IsPayToAnchor | beamchain_script.erl:2678-2682 |
| 10 | BIP-341 control-block size: `33 <= len <= 4129`, `(len-33) % 32 == 0` | PRESENT | interpreter.cpp:1968-1970 | beamchain_script.erl:2811-2818 |
| 11 | BIP-341 annex tag = 0x50, stripped when `len(witness) >= 2` and last item starts with 0x50 | PRESENT | interpreter.cpp:1951-1956 | beamchain_script.erl:2745-2754 |
| 12 | BIP-341 annex sighash commit: `SHA256(compact_size(annex_size) \|\| annex)` (NOT tagged) | PRESENT (W94 fix) | interpreter.cpp:1953-1955 | beamchain_script.erl:2738-2742 |
| 13 | BIP-341 TapLeaf hash: `tagged_hash("TapLeaf", leaf_version \|\| compact_size(script_size) \|\| script)` | PRESENT | interpreter.cpp:1872-1874 | beamchain_script.erl:2823-2826 |
| 14 | BIP-341 TapBranch lexicographic ordering when combining nodes | PRESENT | interpreter.cpp ComputeTaprootMerkleRoot | beamchain_script.erl:2941-2949 |
| 15 | BIP-341 TapTweak: `tagged_hash("TapTweak", internal_key \|\| merkle_root)` | PRESENT | key.cpp ComputeTapTweakHash | beamchain_script.erl:2828-2831 |
| 16 | BIP-341 leaf version = `control[0] & 0xFE` (strip parity bit) | PRESENT | interpreter.cpp:1973 | beamchain_script.erl:2821 |
| 17 | BIP-341 leaf version 0xC0 → Tapscript; other even versions → DISCOURAGE / succeed | PRESENT | interpreter.cpp:1978-1988 | beamchain_script.erl:2837-2895 |
| 18 | BIP-341 valid hash_type whitelist `{0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83}` | PRESENT (W95 fix) | interpreter.cpp:1516 | beamchain_script.erl:1817-1822, 2386-2390 |
| 19 | BIP-341 sigmsg `spend_type` byte = `(ext_flag << 1) \| annex_bit` | PRESENT (W94 fix) | interpreter.cpp:1537 | beamchain_script.erl:3457-3462 |
| 20 | BIP-341 sigmsg writes ORIGINAL hash_type (0x00 for DEFAULT, not remapped) | PRESENT | interpreter.cpp:1516-1518 | beamchain_script.erl:3517-3521 |
| 21 | BIP-341 SIGHASH_SINGLE out-of-range → SCHNORR_SIG_HASHTYPE (Core: SignatureHashSchnorr returns false) | PRESENT (W94 fix) | interpreter.cpp:1549-1556 | beamchain_script.erl:2363-2369 + 2783-2788 |
| 22 | BIP-342 OP_CHECKSIGADD opcode (0xBA), tapscript-only, accumulator increment | PRESENT | interpreter.cpp:1740-1747 + script.h | beamchain_script.erl:1996-2095 |
| 23 | BIP-342 OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY disabled in tapscript | PRESENT | interpreter.cpp (no dispatch in TAPSCRIPT) | beamchain_script.erl:1834-1838, 1903-1905 |
| 24 | BIP-342 MINIMALIF always-on in tapscript (consensus, not flag-gated) | PRESENT | interpreter.cpp:494-499 | beamchain_script.erl:1010-1018 |
| 25 | BIP-342 OP_SUCCESS opcode set: 0x50, 0x62, 0x7E-0x81, 0x83-0x86, 0x89, 0x8A, 0x8D, 0x8E, 0x95-0x99, 0xBB-0xFE | PRESENT | script.cpp IsOpSuccess:364-369 | beamchain_script.erl:348-362 |
| 26 | BIP-342 validation-weight budget seed: `GetSerializeSize(witness.stack) + 50` | PRESENT (W94 fix) | interpreter.cpp:1981 + script.h:61-64 | beamchain_script.erl:2848-2856 |
| 27 | BIP-342 validation-weight decrement = 50 per executed sigop with non-empty sig | PRESENT (W94 fix) | interpreter.cpp:362-365 | beamchain_script.erl:1634-1642 |
| 28 | BIP-342 budget gate order: `if(!sig.empty()) decrement` BEFORE pubkey-type branch | PRESENT (W94 fix) | interpreter.cpp:357-385 | beamchain_script.erl:1597-1635 + 2041-2069 |
| 29 | BIP-342 tapscript initial-stack size limit = MAX_STACK_SIZE (1000) | PRESENT (W94 fix) | interpreter.cpp:1854-1855 | beamchain_script.erl:2858-2864 |
| 30 | BIP-342 tapscript initial-stack element size limit = MAX_SCRIPT_ELEMENT_SIZE (520) | PRESENT (W94 fix) | interpreter.cpp:1858-1861 | beamchain_script.erl:2868-2879 |

Total: 23 PRESENT, 4 PARTIAL, 3 MISSING (see bug catalogue below).

---

## Bug catalogue (7 BUGS)

### BUG-1 (P1-CDIV) — `scan_for_op_success/1` silently aborts on malformed push instead of erroring with BAD_OPCODE

`beamchain_script.erl:516-541`. Core's `ExecuteWitnessScript`
(`interpreter.cpp:1837-1851`) iterates via `CScript::GetOp`; when that
fails (e.g. an `OP_PUSHDATA1` declaring length 200 but only 50 bytes
remain), Core returns `SCRIPT_ERR_BAD_OPCODE` **before** reaching any
OP_SUCCESS in the script. Beamchain's `skip_push/2` / `skip_data/2`
return `false` (the script does not contain OP_SUCCESS), and the
caller then falls through to `execute/3`, which encounters the same
malformed push and emits a generic decode error.

**Same behavioural outcome** (the script fails either way) but the
error atom diverges from Core's `bad_opcode`, which matters for any
fixture that pins specific script-error codes. Material to byte-exact
diff against Core's `script_assets_test.json`.

Priority: **P1-CDIV** (correctness divergence, not a consensus split,
because both paths reject).

### BUG-2 (P1-CDIV) — `compute_taproot_sig_hash` test-mode hook bypasses `valid_taproot_hash_type/1` gate

`beamchain_script.erl:2345-2347`:

```erlang
compute_taproot_sig_hash(#script_state{sig_checker = #{compute_taproot_sighash := Fun}},
                         HashType, CodeSepPos) ->
    {ok, Fun(HashType, CodeSepPos)};
```

This map-fun hook is used by some test fixtures (and one or two RPC
test paths). It bypasses both the `valid_taproot_hash_type/1` whitelist
(W95-era defence) and the `sighash_single_in_range/3` check that the
4-arity tuple-form does enforce (lines 2348-2372).

**Concrete risk**: a test that calls into the script evaluator with a
custom hook and an out-of-spec hash_type (e.g. `0x7F`) will get a
silently-produced fake sighash instead of the `SCHNORR_SIG_HASHTYPE`
error a real consensus run would emit. Audit-flippable: the hook
should call `valid_taproot_hash_type/1` and return
`{error, schnorr_sig_hashtype}` on failure, mirroring the 4-arity
clause. The hook is not used in production block validation paths
(see `beamchain_validation.erl:1584` — production uses the tuple
form), so consensus impact is zero; the gap is test-correctness.

Priority: **P1-CDIV** (test parity).

### BUG-3 (P1-CDIV) — `sighash_taproot_for_key_path` test-mode hook bypasses SIGHASH_SINGLE bounds check

`beamchain_script.erl:2779-2782`:

```erlang
sighash_taproot_for_key_path(#{compute_taproot_sighash := Fun}, HashType, _AnnexHash) ->
    %% External sighash hook (used by some test fixtures). It is expected
    %% to handle SIGHASH_SINGLE bounds checking itself.
    {ok, Fun(HashType, 16#ffffffff)};
```

Same "hook bypasses production gate" shape as BUG-2 but specifically
for the **key-path** spend. The comment ("It is expected to handle
SIGHASH_SINGLE bounds checking itself") is the textbook
**comment-as-confession** pattern flagged in W120 BUG-5 / W122
test-comment-as-confession: the hook contract delegates a consensus-
critical bounds check to anonymous test callers. None of the in-tree
test callers I could find actually enforce it.

Priority: **P1-CDIV** (test parity; comment-as-confession).

### BUG-4 (P2) — `verify_taproot_key_path` ignores `_Flags` parameter

`beamchain_script.erl:2757`:

```erlang
verify_taproot_key_path(OutputKey, Sig, AnnexHash, _Flags, SigChecker) ->
```

The `Flags` argument is destructured with a leading underscore and
never used. Core's key-path code path doesn't use flags either at this
gate (the `SCRIPT_VERIFY_TAPROOT` flag was checked one level up in
`VerifyWitnessProgram`, line 1949: `if (!(flags & SCRIPT_VERIFY_TAPROOT)) return set_success(serror);`).
So this is currently correct — but the **dead parameter** is a future-
softfork landmine. If a follow-up adds e.g.
`SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_KEY_VERSION` flag handling
in the key-path code path (analogous to the existing tapscript-path
`SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION` at line 2886),
the `_Flags` underscore will silently hide the regression.

Priority: **P2** (well-engineered helper signature, parameter never
reached). Defensive rename to `Flags`, or add a no-op pattern-match
guard to fail the build if a flag bit is set that this function does
not handle.

### BUG-5 (P1-CDIV) — No `m_validation_weight_left_init` / `m_annex_init` / `m_tapleaf_hash_init` paranoia gates

`beamchain_script.erl` `#script_state{}` record (lines 36-67) tracks
`annex_hash`, `sigops_budget`, and `codesep_pos` but does not carry
the three `*_init` boolean flags that Core uses to **assert** every
tapscript-aware sigmsg / sigops decrement was reached via the right
call path. Core panics (`assert`) when any of these is false at use
time (interpreter.cpp:361, 1533, 1561, 1959, 1977, 1982).

Concrete consequence: if a future refactor (or an exposed-for-testing
entry point such as `eval_tapscript/5` line 2899) skips the
`verify_taproot` → `verify_taproot_script_path` setup chain and
invokes `eval_tapscript` directly with an unseeded budget, the
budget-decrement path will quietly clamp at zero and erroneously
emit `tapscript_sigops_exceeded` instead of crashing the way Core
would.

Audit-flippable: add `validation_weight_left_init`, `annex_init`,
`tapleaf_hash_init` boolean fields to `#script_state{}`, set them
at the `verify_taproot*` entry points, and pattern-match-fail any
tapscript codepath that reads the corresponding value when the init
flag is false.

Priority: **P1-CDIV** (defensive — same gate Core asserts at).

### BUG-6 (P2) — `eval_tapscript/5` (5-arity, no annex) still exported

`beamchain_script.erl:21-23, 2899-2904`:

```erlang
-export([eval_tapscript/5, eval_tapscript/6, ...]).
...
eval_tapscript(Script, Stack, SigopsBudget, Flags, SigChecker) ->
    eval_tapscript(Script, Stack, SigopsBudget, undefined, Flags, SigChecker).
```

Comment says "preserved for callers / tests that don't have an annex
hash (e.g. pre-W94 unit tests)." This is a **well-engineered helper
never wired** (W127 audit-pattern recurrence): the 5-arity version
**always** passes `AnnexHash = undefined`, which means any caller using
it cannot test annex-bearing tapscript paths. The dependent test code
(`beamchain_script_tests.erl:935-1100`) does exactly that and so
silently exercises the wrong sighash.

Priority: **P2** (legacy helper; remove after porting the 5-arity
callers to the 6-arity form with explicit `undefined`, OR document
that the entrypoint is consensus-blind).

### BUG-7 (P0-CDIV) — `script_assets_test.json` corpus is NOT consumed

`bitcoin-core/src/test/data/script_assets_test.json` is the canonical
cross-impl BIP-341/342 vector set (~50k entries covering every
combination of key-path / script-path, annex / no-annex, all
hash_types, valid + invalid sigs, malformed control blocks, all
OP_SUCCESS codes, every BIP-342 sigops-budget edge case).

Beamchain does **not** load or assert against this corpus. The
nearest existing fixture is `beamchain_script_tests.erl` (~1300
lines, hand-rolled unit tests) plus `script_vectors_tests.erl`
(BIP-66 / pre-segwit vectors only).

**Concrete consequence**: this is the same audit gap pattern as W122
("audit framework requires byte-exact not SHA256d-only"). All other
BIP-340/341/342 gates can be PRESENT and the implementation still
diverge byte-exact from Core on an obscure malformation that Core's
own test vectors do exercise. Without `script_assets_test.json`
consumption, the audit-flip safety net is missing exactly where the
W94 audit said it was needed.

Priority: **P0-CDIV** (audit-completeness gap; not a known runtime
divergence but explicitly the only mechanism that catches the
divergences W122 calls out for filter codecs).

---

## Cross-cutting patterns observed

1. **"Comment-as-confession"** (W120 BUG-5 / W122 lineage) shows up
   twice in this audit at BUG-2 and BUG-3, both around test-mode
   hash hooks that explicitly delegate consensus-critical
   bounds-checks to anonymous test callers.

2. **"Well-engineered helper never wired"** (BUG-4 ignored `_Flags`,
   BUG-6 5-arity `eval_tapscript`). These are not bugs that
   manifest today, but they reduce the audit safety net for the
   next softfork.

3. **"Audit-framework byte-exact requires Core vectors"** (BUG-7)
   directly mirrors W122's headline finding for BIP-158: tests that
   hash-equal themselves (SHA256d-of-output checks) cannot detect
   divergence from Core's reference encoder. The same gap applies
   to script_assets_test.json for Taproot/Tapscript.

4. **Parent-takeover protection healthy**: W94 + W95 fixed the seven
   most-consequential consensus bugs in this surface. The remaining
   seven W127 BUGs are CDIV / defensive / corpus-loading — none
   would split the chain on the canonical happy path.

---

## Outcome for future FIX waves

| BUG | Suggested FIX wave shape | Single-impl or fleet? |
|-----|--------------------------|-----------------------|
| BUG-1 | Tighten `scan_for_op_success/1` to emit `bad_opcode` on malformed push | single-impl (beamchain) |
| BUG-2 / BUG-3 | Tighten test-mode hooks: validate hash_type and SIGHASH_SINGLE bounds before delegating to the closure | single-impl (beamchain) |
| BUG-4 | Rename `_Flags` to `Flags` in `verify_taproot_key_path/5`; add a no-op flag guard | trivial single-impl |
| BUG-5 | Add `validation_weight_left_init` / `annex_init` / `tapleaf_hash_init` to `#script_state{}` | single-impl |
| BUG-6 | Either remove `eval_tapscript/5` or document the legacy contract | single-impl |
| BUG-7 | Wire `script_assets_test.json` consumption into the eunit suite (one-off, ~600 LOC fixture loader) | fleet-wide PATTERN if Core JSON parsing is shared, otherwise single-impl |

No P0-CONSENSUS findings.

---

## Cross-references

- W94 (6164c4f) — BIP-341/342 first-pass audit, closed 7 bugs.
- W95 (4c630f5) — BIP-340 + tagged-hash audit, closed 3 bugs.
- W120 — Mempool RBF audit, introduced "comment-as-confession"
  meta-pattern (BUG-5 prose rationalisation for a FullRBF deviation).
- W122 — BIP-158 GCS codec stress, introduced "audit framework
  requires byte-exact not SHA256d-only" meta-pattern. BUG-7 here is
  the direct Taproot/Tapscript analog.
- script_assets_test.json — Bitcoin Core canonical test corpus
  (~50k Taproot/Tapscript vectors). Source of truth for BUG-7.
