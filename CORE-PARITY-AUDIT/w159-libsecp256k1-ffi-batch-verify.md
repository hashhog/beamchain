# W159 — libsecp256k1 FFI wrapping + batch verification (beamchain)

**Wave:** W159 — secp256k1 NIF wrapping & lifecycle: `secp256k1_context_create`,
`SECP256K1_CONTEXT_VERIFY|SIGN` vs `SECP256K1_CONTEXT_NONE`,
`secp256k1_context_randomize` (side-channel blinding seed),
sign-then-verify paranoia (`CKey::Sign` / `CKey::SignCompact` /
`KeyPair::SignSchnorr` post-sign `secp256k1_ecdsa_verify` /
`secp256k1_schnorrsig_verify`), `secp256k1_ec_seckey_verify` scalar-range
gate, batch Schnorr verification (sequential-loop vs cryptographic),
ECDSA recovery (`secp256k1_ecdsa_recover`), Schnorr (`schnorrsig_sign32`
+ `schnorrsig_verify`), XOnly Taproot helpers
(`xonly_pubkey_parse|serialize|tweak_add|from_pubkey`),
ElligatorSwift (BIP-324 `ellswift_create` / `ellswift_xdh`),
constant-time scalar ops, NIF resource lifecycle, dirty-scheduler
selection, secret-buffer cleanse, NULL/error-return discipline,
pure-Erlang `crypto:*` fallback shape vs C FFI.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**

- `bitcoin-core/src/secp256k1/include/secp256k1.h:207-290` — context
  flag definitions: `SECP256K1_CONTEXT_NONE` is the only non-deprecated
  flag; `SECP256K1_CONTEXT_VERIFY` and `SECP256K1_CONTEXT_SIGN` are
  retained for backward-compat but documented as **deprecated**:
  *"These flags are treated equivalent to `SECP256K1_CONTEXT_NONE`"*.
- `bitcoin-core/src/secp256k1/include/secp256k1.h:30-49` — thread-safety
  contract: *"A constructed context can safely be used from multiple
  threads simultaneously, but API calls that take a non-const pointer
  to a context need exclusive access to it. In particular this is the
  case for `secp256k1_context_destroy`, `secp256k1_context_preallocated_destroy`,
  and `secp256k1_context_randomize`."*
- `bitcoin-core/src/secp256k1/include/secp256k1.h:806-841` —
  `secp256k1_context_randomize`: *"It is highly recommended to call
  this function on contexts returned from `secp256k1_context_create`
  ... before using these contexts to call API functions that perform
  computations involving secret keys, e.g., signing and public key
  generation. ... Randomization of the context shields against
  side-channel observations which aim to exploit secret-dependent
  behaviour."*
- `bitcoin-core/src/secp256k1/include/secp256k1.h:685` —
  `secp256k1_ec_seckey_verify`: must be called before any operation
  that takes a seckey to confirm `1 <= seckey < n`.
- `bitcoin-core/src/key.cpp:571-587` — `ECC_Start`: `secp256k1_context_create(SECP256K1_CONTEXT_NONE)`
  + immediate `secp256k1_context_randomize(ctx, vseed.data())` with
  `GetRandBytes(vseed)` (32-byte CSPRNG seed). Asserts on randomize
  failure.
- `bitcoin-core/src/key.cpp:158-160` — `CKey::Check` =
  `secp256k1_ec_seckey_verify(secp256k1_context_static, vch)` before
  consuming the key.
- `bitcoin-core/src/key.cpp:162-168` — `CKey::MakeNewKey` retries
  `GetStrongRandBytes` until `Check()` passes.
- `bitcoin-core/src/key.cpp:209-235` — `CKey::Sign`: after
  `secp256k1_ecdsa_sign` + DER serialize, ALWAYS re-parses the pubkey
  and calls `secp256k1_ecdsa_verify` as a *"sign-then-verify paranoia"*
  step against silent corruption (fault-injection, RAM bitflips, buggy
  signer). `assert(ret)`.
- `bitcoin-core/src/key.cpp:250-271` — `CKey::SignCompact`: same
  paranoia for recoverable sigs — `secp256k1_ecdsa_recover` +
  `secp256k1_ec_pubkey_cmp` after sign.
- `bitcoin-core/src/key.cpp:549-563` — `KeyPair::SignSchnorr`: same
  paranoia for Schnorr — `secp256k1_schnorrsig_verify` after
  `schnorrsig_sign32`; `memory_cleanse(sig.data(), sig.size())` on
  failure.
- `bitcoin-core/src/secp256k1/include/secp256k1_schnorrsig.h:170-184` —
  BIP-340 `schnorrsig_verify` signature: takes `msg`, `msglen` —
  arbitrary-length message is part of the spec (Tapscript uses 32, but
  BIP-322 / sighash-precomputed extensions can use other lengths).
- `bitcoin-core/src/random.cpp` + `bitcoin-core/src/support/cleanse.cpp` —
  `memory_cleanse` (compiler-barrier protected) wipes secret-bearing
  buffers; LockedPool (`bitcoin-core/src/support/lockedpool.cpp`)
  `mlock`s pages backing secret allocations.
- `bitcoin-core/src/secp256k1/CHANGELOG.md` — v0.4.0 (Aug 2023)
  deprecated the SIGN/VERIFY context flags; v0.5.1 (Mar 2024) is the
  current vendored version. **There is NO `secp256k1_batch_verify`
  API in v0.5.1** — true batch Schnorr verification still lives only
  in the upstream `master` branch behind `--enable-experimental` and
  has not been merged into a release. Any "batch" verify wrapper in
  v0.5.1 is necessarily a sequential loop.
- `bitcoin-core/src/script/sigcache.h:42-44` — `m_salted_hasher`:
  startup-random nonce mixed into every cache key so cross-restart
  pre-population attacks fail.

**Files audited**

- `beamchain/c_src/beamchain_crypto_nif.c` (1357 LOC) — the only NIF
  module wrapping libsecp256k1; also embeds a portable + SHA-NI + ARMv8
  SHA-2 SHA-256 implementation.
- `beamchain/c_src/Makefile` (~75 LOC) — builds the NIF, vendors
  libsecp256k1 v0.5.1 via `git clone --depth 1 --branch v0.5.1`,
  enables `MODULE_SCHNORRSIG`, `MODULE_EXTRAKEYS`, `MODULE_RECOVERY`.
- `beamchain/src/beamchain_crypto.erl` (1071 LOC) — Erlang wrapper:
  exports verify/sign/tweak/recover, pure-Erlang fallbacks for SHA-256,
  DER strict + lax decode/encode, low-S enforcement, SipHash-2-4
  (BIP-152), BIP-137 signed-message, BIP-341 TapTweak helpers, tagged
  hash with persistent_term cache.
- `beamchain/src/beamchain_sig_cache.erl` (136 LOC) — gen_server
  wrapping an ETS sig-verify cache; startup nonce + LRU eviction.
- `beamchain/c_src/secp256k1/include/*.h` — confirms vendored API surface.

---

## Gate matrix (27 sub-gates / 8 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | Context lifecycle | G1: process-singleton (one ctx for module lifetime) | PASS (`beamchain_crypto_nif.c:630, 638`) |
| 1 | … | G2: `secp256k1_context_create` flag = `CONTEXT_NONE` (v0.5.1+) | **FAIL — BUG-1** (uses deprecated `VERIFY \| SIGN`) |
| 1 | … | G3: context destroyed on unload | PASS (`beamchain_crypto_nif.c:648-654`) |
| 1 | … | G4: NIF `upgrade` callback registered for hot-code reload | **FAIL — BUG-2** (`ERL_NIF_INIT(... NULL, NULL, unload)`) |
| 2 | Side-channel blinding | G5: `secp256k1_context_randomize` called at load time | **FAIL — BUG-3** (never called fleet-wide for beamchain) |
| 2 | … | G6: re-randomize periodically as defense-in-depth | FAIL — BUG-3 follow-on |
| 3 | Sign-then-verify paranoia | G7: ECDSA sign re-parses pubkey + `secp256k1_ecdsa_verify` post-sign | **FAIL — BUG-4** |
| 3 | … | G8: ECDSA recoverable sign re-runs `secp256k1_ecdsa_recover` + `ec_pubkey_cmp` post-sign | **FAIL — BUG-5** |
| 3 | … | G9: Schnorr sign re-runs `secp256k1_schnorrsig_verify` post-sign | **FAIL — BUG-6** |
| 4 | Scalar-range hygiene | G10: `secp256k1_ec_seckey_verify` called before any secret-key consumer | **FAIL — BUG-7** |
| 4 | … | G11: Erlang-side range gate (1 ≤ k < n) at API boundary | FAIL — BUG-7 follow-on |
| 5 | Batch Schnorr verify | G12: production callers wire `batch_schnorr_verify` for block-validate | **FAIL — BUG-8** (dead helper) |
| 5 | … | G13: `batch_schnorr_verify_nif` uses cryptographic batch (single multi-scalar mult) | **FAIL — BUG-9** (sequential loop falsely named "batch") |
| 5 | … | G14: short-circuit on first failure to limit work attacker can force | FAIL — BUG-9 follow-on |
| 5 | … | G15: `batch_ecdsa_verify` likewise wired into block validation | **FAIL — BUG-10** (dead helper, second instance) |
| 6 | Memory hygiene | G16: secret buffers wiped after use (`memory_cleanse` / `OPENSSL_cleanse` / `explicit_bzero`) | **FAIL — BUG-11** (NIF zero cleanse calls) |
| 6 | … | G17: stack copy of seckey in `seckey_tweak_add_nif` cleansed before return | FAIL — BUG-11 follow-on |
| 6 | … | G18: ElligatorSwift session-secret cleansed on error | FAIL — BUG-11 follow-on |
| 6 | … | G19: LockedPool / `mlock` shields long-lived secret data | **FAIL — BUG-12** (no equivalent in beamchain) |
| 7 | API hygiene / NULL discipline | G20: `enif_alloc` NULL-check in `pubkey_combine_nif` | **FAIL — BUG-13** (no NULL check; will SIGSEGV on OOM) |
| 7 | … | G21: ignored return values from serialise functions documented as `WARN_UNUSED_RESULT` | PARTIAL — `secp256k1_ec_pubkey_serialize` always returns 1, OK; but `secp256k1_ecdsa_signature_serialize_der` can return 0 and is ignored (**BUG-14**) |
| 7 | … | G22: Schnorr `schnorrsig_verify` invoked with hard-coded `msglen=32` | **FAIL — BUG-15** (per BIP-340 `msglen` is arbitrary) |
| 7 | … | G23: `schnorr_verify/3` Erlang guard rejects non-32-byte messages | **FAIL — BUG-16** (BIP-322 surface needs arbitrary msg-len) |
| 8 | Fallback / dispatch | G24: `init()` returns NIF load result so `-on_load` aborts module load on failure | PASS, but contradicted by **BUG-17** (claim "using pure Erlang fallback" is dead-code-but-called) |
| 8 | … | G25: SHA-256 NIF dispatched to normal scheduler (sub-1ms gating) | PARTIAL — see **BUG-18** (no length cap; multi-MB blocks block the scheduler) |
| 8 | … | G26: lax-DER length parser handles `0x82` (2-byte) AND `0x83+` (3+) | **FAIL — BUG-19** (`read_der_length/1` silently returns `{0, Rest}` on `0x83+`) |
| 8 | … | G27: signed-message header byte range matches Core | **FAIL — BUG-20** (stricter than Core: rejects header bytes Core accepts) |

Result: **20 P0/P1/P2 bugs across 8 behaviours** — see per-bug
write-ups below.

---

## Severity bands

| Tier | Count |
|------|-------|
| P0-SEC (security / side-channel / DoS) | 5 (BUG-3, BUG-4, BUG-5, BUG-6, BUG-13) |
| P0-CDIV (cross-impl divergence at API boundary) | 1 (BUG-15) |
| P1 (correctness / hygiene with material impact) | 8 (BUG-1, BUG-7, BUG-8, BUG-9, BUG-10, BUG-11, BUG-12, BUG-14) |
| P2 (cosmetic / surface) | 6 (BUG-2, BUG-16, BUG-17, BUG-18, BUG-19, BUG-20) |

---

## BUG-1 (P1) — `secp256k1_context_create` uses deprecated `VERIFY | SIGN` flags

**Severity:** P1. libsecp256k1 v0.4.0 (Aug 2023) deprecated the
`SECP256K1_CONTEXT_VERIFY` and `SECP256K1_CONTEXT_SIGN` bit flags;
v0.5.1 (the vendored version per `c_src/Makefile:11`) still accepts
them for backward-compat but the header explicitly states they are
*"treated equivalent to `SECP256K1_CONTEXT_NONE`"* and the recommended
form is the single `CONTEXT_NONE` flag (Core uses this — see
`bitcoin-core/src/key.cpp:575`).

beamchain's NIF load callback:

```c
/* beamchain_crypto_nif.c:638 */
ctx = secp256k1_context_create(
    SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
```

**File:** `c_src/beamchain_crypto_nif.c:638-639`.

**Core ref:** `bitcoin-core/src/key.cpp:575`
(`secp256k1_context_create(SECP256K1_CONTEXT_NONE)`).
`bitcoin-core/src/secp256k1/include/secp256k1.h:216-218`
(deprecation comment).

**Impact:** functional behaviour is identical at the secp256k1 layer
(the flags are no-ops on the active code path), but:

- Forward-compat: a future libsecp256k1 release could remove the
  deprecated flag macros entirely; beamchain would then fail to
  compile against a fresh upstream pin.
- Audit signal: the code reads as if the impl knew about a
  verify/sign distinction; that's wrong for v0.5.1+. Pattern smell
  for "library version drift not tracked".

---

## BUG-2 (P2) — NIF `upgrade` callback NULL — hot-code-upgrade silently breaks the secp256k1 context

**Severity:** P2. `ERL_NIF_INIT(MODULE, funcs, load, reload, upgrade, unload)`:
beamchain registers `load` + `unload` and passes `NULL` for both
`reload` and `upgrade`:

```c
/* beamchain_crypto_nif.c:1357 */
ERL_NIF_INIT(beamchain_crypto, nif_funcs, load, NULL, NULL, unload)
```

A NULL `upgrade` slot means hot-code-upgrade of the `beamchain_crypto`
module (e.g., `appup`/`relup` flow, or `l(beamchain_crypto)` in a live
shell) will succeed at the BEAM level but the new module instance
never runs the NIF's `load` again — so the static `ctx` pointer
remains owned by the *old* code's load. After the old code's `unload`
fires (which it eventually does once all references drop), the
`secp256k1_context*` is destroyed but the new code's `ctx` still
points at it (use-after-free) OR was never initialised (NULL deref).

OTP's contract: if `upgrade` is NULL, hot-upgrade attempts can fail
with `{error, {upgrade, ...}}` and leave the system in a partially-
loaded state.

**File:** `c_src/beamchain_crypto_nif.c:1357`.

**Core ref:** N/A (Core is C++, no hot-code-upgrade concept). The
analogue is Core's `ECC_Stop` / `ECC_Start` pair which is invoked
manually at process boundaries.

**Impact:** OTP releases that use `appup` to upgrade `beamchain_crypto`
without a node restart will hit use-after-free or NULL-deref the
first time a signature verification runs in the upgraded code. Mainnet
risk if a hotfix lands via `relup` rather than restart.

**Mitigation:** register `upgrade` that does the same as `load`
(create + randomize a fresh context, atomically swap the static
pointer), and `unload` only when the final code-version is being
purged. See OTP `erts/erl_nif.h` docs.

---

## BUG-3 (P0-SEC) — `secp256k1_context_randomize` is never called — side-channel blinding seed absent

**Severity:** P0-SEC. **Fleet-wide pattern**: see W158 clearbit BUG-2
(cipher-as-scalar), W158 lunarblock BUG-7 (`context_randomize` never
called), W159 rustoshi BUG-4 (same root cause). With beamchain
confirmed here, the **side-channel-blinding-disabled** pattern is now
at minimum **3/10** impls and almost certainly higher.

libsecp256k1's per-context random seed exists specifically to mask
secret-dependent timing/EM/power side-channels in scalar
multiplication. Core does this unconditionally at startup:

```cpp
/* bitcoin-core/src/key.cpp:578-584 */
std::vector<unsigned char, secure_allocator<unsigned char>> vseed(32);
GetRandBytes(vseed);
bool ret = secp256k1_context_randomize(ctx, vseed.data());
assert(ret);
```

beamchain's `load` callback:

```c
/* beamchain_crypto_nif.c:636-646 */
static int load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
    if (!ctx) return -1;

    /* Detect best SHA-256 implementation at load time */
    detect_sha256_implementation();

    return 0;
}
```

There is **no** `secp256k1_context_randomize` call. Grep confirms zero
occurrences across `c_src/` and `src/`. The static `ctx` therefore
performs all signing / pubkey-create / tweak operations with the
library's default seed — every secret-multiplication is run with
predictable blinding.

**File:** `c_src/beamchain_crypto_nif.c:636-646` (load callback,
randomize missing); zero call sites repo-wide.

**Core ref:** `bitcoin-core/src/key.cpp:578-584` (`ECC_Start` calls
`secp256k1_context_randomize` with `GetRandBytes(vseed)`).
`bitcoin-core/src/secp256k1/include/secp256k1.h:806-841` (API contract,
randomize *"highly recommended"*).

**Impact:**
- Side-channel attacks on a host running beamchain that signs
  (wallet daemon, mining payout signer, witness signer at
  `src/beamchain_witness_signer.erl`) are not blinded. An attacker
  with co-tenant access (cloud, shared-tenant CI, malicious local
  binary) can in principle recover secret keys via timing/cache /
  Spectre-style side-channels that the randomize-seed would have
  masked.
- This is the *exact* same root cause as W158 lunarblock BUG-7 and
  W159 rustoshi BUG-4 — adding beamchain makes the side-channel
  pattern **3/10** confirmed (clearbit's BUG-2 is a worse variant
  using the wrong material as a "seed" entirely).
- For witness-signer use (Lightning, BIP-174 cooperative signing),
  every signing operation leaks more side-channel material than a
  randomized context would. A single signing event under
  adversarial timing observation may not be exploitable, but
  long-lived signers (mining payout, channel routing) accumulate
  enough samples to matter.

**Fix sketch:** in `load()`, after `secp256k1_context_create`, call
`enif_priv_data` / `enif_random_bytes` (Erlang VM exposes a CSPRNG via
`crypto:strong_rand_bytes` reachable from C through a callback, or
just `open("/dev/urandom", ...)` directly) and pass 32 bytes to
`secp256k1_context_randomize(ctx, seed32)`. Mirror Core's `assert(ret)`.
Ideally schedule a re-randomize on a timer or per-N-signatures for
defense-in-depth (Core does it only at startup, but the API supports
multiple calls).

---

## BUG-4 (P0-SEC) — ECDSA sign omits post-sign verify (paranoia step)

**Severity:** P0-SEC. Bitcoin Core's `CKey::Sign` re-parses the pubkey
and runs `secp256k1_ecdsa_verify` after every successful sign, with
`assert(ret)`:

```cpp
/* bitcoin-core/src/key.cpp:228-233 */
// Additional verification step to prevent using a potentially corrupted signature
secp256k1_pubkey pk;
ret = secp256k1_ec_pubkey_create(secp256k1_context_sign, &pk, UCharCast(begin()));
assert(ret);
ret = secp256k1_ecdsa_verify(secp256k1_context_static, &sig, hash.begin(), &pk);
assert(ret);
```

This is the canonical defense against fault-injection / RAM-bitflip /
hardware-bug attacks (Rowhammer-on-keys, undervolt-glitch on signing
CPUs, etc.) AND a sanity gate against future libsecp256k1 regressions
in the signing path. Bitcoin Core's commit log notes this was added
after a real-world fault-injection demonstration.

beamchain's NIF `ecdsa_sign_nif`:

```c
/* beamchain_crypto_nif.c:985-1003 */
static ERL_NIF_TERM ecdsa_sign_nif(ErlNifEnv *env, int argc,
                                    const ERL_NIF_TERM argv[])
{
    /* ... parse args ... */
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_sign(ctx, &sig, msg.data, seckey.data, NULL, NULL))
        return make_error(env, "signing_failed");

    unsigned char der[72];
    size_t der_len = 72;
    secp256k1_ecdsa_signature_serialize_der(ctx, der, &der_len, &sig);

    return make_ok_binary(env, der, der_len);
}
```

No post-sign verify. The signature is returned to Erlang as-is.

**File:** `c_src/beamchain_crypto_nif.c:985-1003`.

**Core ref:** `bitcoin-core/src/key.cpp:228-233`.

**Impact:**
- A corrupted signature (caused by a bitflip in the `sig` buffer
  between `ecdsa_sign` write and `serialize_der` read, or a future
  libsecp256k1 signing bug) is silently emitted. The wallet then
  broadcasts an invalid transaction; mempool peers reject it as
  malformed; the user sees "fee paid for nothing".
- Worse: on a mining/payout signer the bad signature ends up in a
  block coinbase or PSBT artifact and bricks downstream tooling.
- This is the SAME shape as Core's W156 IsBlockMutated-post-FillBlock:
  belt-and-braces paranoia where the "extra" step is cheap and
  catches single-bit corruption that would otherwise be undetectable.

**Cost:** one extra `secp256k1_ecdsa_verify` per sign (~70 µs on
modern x86); ECDSA signing is already ~30-40 µs so the paranoia step
roughly doubles signing CPU. Core accepts that cost; beamchain's
omission is a hot-path performance optimization that drops a
defense-in-depth gate.

---

## BUG-5 (P0-SEC) — Recoverable ECDSA sign omits post-sign recovery check (paranoia step)

**Severity:** P0-SEC. Bitcoin Core's `CKey::SignCompact` has the same
paranoia structure, specialised for recoverable sigs: re-runs
`secp256k1_ecdsa_recover` on the just-produced sig and uses
`secp256k1_ec_pubkey_cmp` to confirm the recovered pubkey matches the
signer's pubkey:

```cpp
/* bitcoin-core/src/key.cpp:262-269 */
// Additional verification step to prevent using a potentially corrupted signature
secp256k1_pubkey epk, rpk;
ret = secp256k1_ec_pubkey_create(secp256k1_context_sign, &epk, UCharCast(begin()));
assert(ret);
ret = secp256k1_ecdsa_recover(secp256k1_context_static, &rpk, &rsig, hash.begin());
assert(ret);
ret = secp256k1_ec_pubkey_cmp(secp256k1_context_static, &epk, &rpk);
assert(ret == 0);
```

beamchain's `ecdsa_sign_recoverable_nif`:

```c
/* beamchain_crypto_nif.c:1014-1038 */
static ERL_NIF_TERM ecdsa_sign_recoverable_nif(...)
{
    /* ... parse args ... */
    secp256k1_ecdsa_recoverable_signature rsig;
    if (!secp256k1_ecdsa_sign_recoverable(ctx, &rsig, msg.data, seckey.data,
                                           NULL, NULL))
        return make_error(env, "signing_failed");

    unsigned char compact[64];
    int recid = 0;
    if (!secp256k1_ecdsa_recoverable_signature_serialize_compact(
            ctx, compact, &recid, &rsig))
        return make_error(env, "serialize_failed");

    unsigned char out[65];
    out[0] = (unsigned char)recid;
    memcpy(out + 1, compact, 64);
    return make_ok_binary(env, out, 65);
}
```

No `secp256k1_ecdsa_recover` + `ec_pubkey_cmp` after sign.

**File:** `c_src/beamchain_crypto_nif.c:1014-1038`.

**Core ref:** `bitcoin-core/src/key.cpp:262-269`.

**Impact:** identical to BUG-4 but with WORSE downstream consequences,
because recoverable signatures are used by:

- `signmessage` RPC (beamchain_crypto.erl:421 `sign_message/2`) — a
  corrupted recoverable sig produces a base64 string that
  `verify_message` rejects, but the *recovered pubkey* may map to a
  DIFFERENT address than the signer expects. The user receives a
  signature whose `verifymessage` returns "valid for address X" where
  X is not the signer's address.
- BIP-137 / BIP-322 signed-message verification is wired through
  `verify_message/3` (line 442), so a fault-injection during signing
  could cause the verifier to accept the sig as proving control of
  an address the signer never owned — a silent **identity claim
  forgery** that is undetectable at sign time.

**Cost:** one `ec_pubkey_create` + one `ecdsa_recover` + one
`ec_pubkey_cmp` per sign (~150 µs total) — Core eats it.

---

## BUG-6 (P0-SEC) — Schnorr sign omits post-sign verify (paranoia step)

**Severity:** P0-SEC. Bitcoin Core's `KeyPair::SignSchnorr` includes
the same paranoia, with the additional discipline of cleansing the
signature buffer if verify fails:

```cpp
/* bitcoin-core/src/key.cpp:549-563 */
bool KeyPair::SignSchnorr(const uint256& hash, std::span<unsigned char> sig, ...) const
{
    assert(sig.size() == 64);
    if (!IsValid()) return false;
    auto keypair = reinterpret_cast<const secp256k1_keypair*>(m_keypair->data());
    bool ret = secp256k1_schnorrsig_sign32(secp256k1_context_sign, sig.data(), hash.data(), keypair, aux.data());
    if (ret) {
        // Additional verification step to prevent using a potentially corrupted signature
        secp256k1_xonly_pubkey pubkey_verify;
        ret = secp256k1_keypair_xonly_pub(secp256k1_context_static, &pubkey_verify, nullptr, keypair);
        ret &= secp256k1_schnorrsig_verify(secp256k1_context_static, sig.data(), hash.begin(), 32, &pubkey_verify);
    }
    if (!ret) memory_cleanse(sig.data(), sig.size());
    return ret;
}
```

beamchain's `schnorr_sign_nif`:

```c
/* beamchain_crypto_nif.c:1080-1100 */
static ERL_NIF_TERM schnorr_sign_nif(ErlNifEnv *env, int argc,
                                      const ERL_NIF_TERM argv[])
{
    /* ... parse args ... */
    secp256k1_keypair keypair;
    if (!secp256k1_keypair_create(ctx, &keypair, seckey.data))
        return make_error(env, "invalid_seckey");

    unsigned char sig[64];
    if (!secp256k1_schnorrsig_sign32(ctx, sig, msg.data, &keypair,
                                      aux_rand.data))
        return make_error(env, "signing_failed");

    return make_ok_binary(env, sig, 64);
}
```

No post-sign `schnorrsig_verify`. No `memory_cleanse` on the `keypair`
struct (which contains the secret scalar in libsecp256k1's internal
representation).

**File:** `c_src/beamchain_crypto_nif.c:1080-1100`.

**Core ref:** `bitcoin-core/src/key.cpp:549-563`.

**Impact:** worst-tier among the three sign paranoia bugs (BUG-4, BUG-5,
BUG-6) because:

- Schnorr signatures land in **Taproot witnesses** — a corrupted
  Schnorr sig is a permanent on-chain artifact (the tx pays fees and
  the witness commits to it), so a fault-injected bad Schnorr
  signature in a self-spend can permanently lock funds.
- BIP-341 key-path spends are the dominant modern Taproot usage; a
  silent corruption defeats the entire spend rather than failing
  fast at sign time.

**Cost:** ~90 µs per sign for verify; cheap.

---

## BUG-7 (P1) — `secp256k1_ec_seckey_verify` never called — seckey scalar-range gate absent

**Severity:** P1. libsecp256k1 documents that callers MUST validate
seckey is in `[1, n)` before calling any function that takes a seckey
(`secp256k1.h:685-696`). The functions DO return 0 on out-of-range
input, but the API contract is to fail-fast at the boundary. Core
does this:

```cpp
/* bitcoin-core/src/key.cpp:158-160 */
bool CKey::Check(const unsigned char *vch) {
    return secp256k1_ec_seckey_verify(secp256k1_context_static, vch);
}
```

`MakeNewKey` retries with `GetStrongRandBytes` until `Check()` passes
(`bitcoin-core/src/key.cpp:162-168`).

beamchain accepts any 32-byte binary as a seckey and hands it directly
to the relevant secp256k1 function. The functions that consume it
(`pubkey_create`, `ecdsa_sign`, `keypair_create`, `seckey_tweak_add`,
`ellswift_create`) all return 0 on out-of-range or zero seckey, which
the NIF translates to `{error, invalid_seckey}` / `{error,
signing_failed}` — so the failure is detected, but:

- The error atom is inconsistent across paths (`invalid_seckey` from
  `pubkey_create_nif`, `signing_failed` from `ecdsa_sign_nif`,
  `tweak_failed` from `seckey_tweak_add_nif`) — same underlying
  cause, different error messages, harder to handle in Erlang.
- There is no fast-fail check at the Erlang API boundary
  (`beamchain_crypto:ecdsa_sign/2` etc. just guards `byte_size = 32`).
  A caller iterating over candidate seckeys (BIP-32 derivation,
  brute-force address scan, RNG validation loop) pays the cost of
  building a `keypair` / sig / etc. before learning the seckey was
  bad.

The repository grep confirms zero `secp256k1_ec_seckey_verify` calls
across the entire codebase.

**File:** `c_src/beamchain_crypto_nif.c` (entire file — function
absent); `src/beamchain_crypto.erl:480-487`
(`pubkey_from_privkey/1` accepts any 32-byte binary).

**Core ref:** `bitcoin-core/src/key.cpp:158-160`,
`bitcoin-core/src/secp256k1/include/secp256k1.h:685-696`.

**Impact:**
- Hygiene: API doesn't fail-fast on a bad seckey; downstream layers
  see assorted error atoms for the same root cause.
- Edge case: a seckey == 0 or seckey ≥ n is rejected by the
  consuming function, so consensus is not affected — but BIP-32
  child-key derivation can produce out-of-range scalars (see
  `bitcoin-core/src/key.cpp:296-310`, where `CKey::Derive` checks
  the tweak result). beamchain's `seckey_tweak_add_nif` does check
  the result (returns `tweak_failed`), but Erlang-side BIP-32
  derivation (if any) may not retry-with-different-i; instead it
  propagates `{error, tweak_failed}` up.

---

## BUG-8 (P1) — `batch_schnorr_verify/1` is exported but has ZERO production callers (dead helper / wiring-look-but-no-wire)

**Severity:** P1. **Fleet pattern: wiring-look-but-no-wire**. The
Erlang API:

```erlang
%% beamchain_crypto.erl:697-707
-spec batch_schnorr_verify([{binary(), binary(), binary()}]) -> [boolean()].
batch_schnorr_verify([]) ->
    [];
batch_schnorr_verify(Items) when is_list(Items) ->
    try
        batch_schnorr_verify_nif(Items)
    catch
        error:nif_not_loaded ->
            [schnorr_verify(Msg, Sig, PubKey) || {Msg, Sig, PubKey} <- Items]
    end.
```

is exported on line 44. Grep for production callers:

```
$ grep -rn "batch_schnorr_verify" beamchain/src/
beamchain/src/beamchain_crypto.erl:44:-export([batch_ecdsa_verify/1, batch_schnorr_verify/1]).
beamchain/src/beamchain_crypto.erl:163:batch_schnorr_verify_nif(_Items) ->
beamchain/src/beamchain_crypto.erl:697:-spec batch_schnorr_verify([{binary(), binary(), binary()}]) -> [boolean()].
beamchain/src/beamchain_crypto.erl:698:batch_schnorr_verify([]) ->
beamchain/src/beamchain_crypto.erl:700:batch_schnorr_verify(Items) when is_list(Items) ->
beamchain/src/beamchain_crypto.erl:706:[schnorr_verify(Msg, Sig, PubKey) || {Msg, Sig, PubKey} <- Items]
```

No call sites outside the module itself. The production Schnorr verify
path in `beamchain_script.erl:2249` uses `schnorr_verify_cached/3` — a
one-at-a-time call.

`batch_ecdsa_verify/1` exhibits the identical pattern (see BUG-10).

**File:** `src/beamchain_crypto.erl:44, 697-707`.

**Core ref:** N/A (Core does not yet have batch verification in a
released branch — see BUG-9 — but its `ConnectBlock` and `CheckBlock`
worker pool batches sig-checks via `CCheckQueue` which is the
moral equivalent).

**Impact:**
- 40+ LOC of NIF code + Erlang wrapper is dead in production.
- The advertised performance win ("batch verification amortizes the
  NIF call overhead" — comment at `beamchain_crypto.erl:675-678`)
  never materialises because no caller exists.
- This is the SAME shape as W156 hotbuns BUG-31 BlockTemplateBuilder
  (helper built, no caller). Now also extends to a beamchain
  signature-verification helper: **first beamchain instance of the
  fleet pattern in the crypto layer** specifically.
- Also a **comment-as-confession** instance: the docstring claims
  amortisation that the codebase shape contradicts.

**Fix sketch:** wire `batch_schnorr_verify` into `ConnectBlock` /
block-validation in `src/beamchain_validation.erl` (collect all Schnorr
sig-checks from all Tapscript inputs in a block, single NIF dispatch).
For mempool, accumulate per-batch in `AcceptToMemoryPool`.

---

## BUG-9 (P1) — `batch_schnorr_verify_nif` is NOT a cryptographic batch — it's a sequential loop with a misleading name

**Severity:** P1. The C implementation:

```c
/* beamchain_crypto_nif.c:1253-1308 */
static ERL_NIF_TERM batch_schnorr_verify_nif(ErlNifEnv *env, int argc, ...)
{
    /* ... parse list length ... */
    for (i = 0; i < list_len; i++) {
        /* ... parse tuple ... */
        int valid = 0;
        if (msg.size == 32 && sig.size == 64 && pubkey.size == 32) {
            secp256k1_xonly_pubkey xpk;
            if (secp256k1_xonly_pubkey_parse(ctx, &xpk, pubkey.data)) {
                valid = secp256k1_schnorrsig_verify(ctx, sig.data,
                                                     msg.data, 32, &xpk);
            }
        }
        results[i] = enif_make_atom(env, valid ? "true" : "false");
    }
    /* ... */
}
```

This is `secp256k1_schnorrsig_verify` called once per item — i.e.,
identical CPU cost to N individual `schnorr_verify_nif` calls. The
**only** benefit is one NIF dispatch instead of N (saves ~50 ns per
sig of FFI overhead vs ~90 µs verification cost: ~0.05% speedup).

True cryptographic batch verification fuses N verifications into a
single multi-scalar multiplication: cost ~`(N+2) * scalar_mult` vs
`N * 2 * scalar_mult` for individual verify, i.e., **~2× speedup at
N=8, ~3× at N=32**. libsecp256k1 has this implementation behind
`--enable-experimental` on `master` but it has not been merged into
any release — v0.5.1 (vendored at `c_src/Makefile:11`) has NO
`secp256k1_batch_verify` symbol.

The Erlang docstring at `beamchain_crypto.erl:673-678`:

```
%%% Batch verification (reduces NIF call overhead)
%%%
%%% When verifying multiple signatures (e.g., all inputs in a block),
%%% batch verification amortizes the NIF call overhead by processing
%%% multiple signatures in a single call to C.
```

honestly states "reduces NIF call overhead" — but the function name
`batch_schnorr_verify` invites confusion with cryptographic batch
verification, which it is NOT. A consensus engineer reading the API
sees "batch verify" and assumes the multi-scalar-mult speedup.

Also: no short-circuit on first failure. An attacker who knows N-1
sigs are valid and 1 is invalid forces verification of all N regardless
of order — a DoS amplifier when the verifier could have rejected the
batch as soon as the first fail was detected. Core's `CCheckQueue`
short-circuits via `failed_` flag.

**File:** `c_src/beamchain_crypto_nif.c:1253-1308`;
`src/beamchain_crypto.erl:670-707`.

**Core ref:** N/A in v0.5.1 (API absent). Conceptual: BIP-340 Section
"Batch Verification" + `bitcoin-core/src/checkqueue.h` for the
`CCheckQueue<T>` worker-pool short-circuit pattern.

**Impact:**
- Misleading API name: a caller may believe enabling
  `batch_schnorr_verify` gives them a 2-3× speedup at block validation,
  but it gives ~0%.
- No short-circuit on first failure: an attacker can force N full
  verifications by submitting N-1 valid + 1 invalid Schnorr sigs.
- Combined with BUG-8 (dead helper), the failure is "doubly silent":
  the helper isn't even called by the production validator.

**Fix sketch:** (a) rename to `verify_schnorr_list` or
`schnorr_verify_many` to defuse the false promise; (b) add early-exit
on first `valid == 0`; (c) document the upstream batch-verify API
status with a TODO to swap in once v0.6 lands.

---

## BUG-10 (P1) — `batch_ecdsa_verify/1` is exported but has ZERO production callers (dead helper, 2nd instance)

**Severity:** P1. Identical shape to BUG-8, applied to ECDSA. Grep
confirms zero production call sites:

```
$ grep -rn "batch_ecdsa_verify" beamchain/src/
beamchain/src/beamchain_crypto.erl:44   (export decl)
beamchain/src/beamchain_crypto.erl:160  (nif stub)
beamchain/src/beamchain_crypto.erl:682  (spec)
beamchain/src/beamchain_crypto.erl:685  (impl)
beamchain/src/beamchain_crypto.erl:687  (nif call)
beamchain/src/beamchain_crypto.erl:691  (fallback)
```

Production ECDSA verify in `beamchain_script.erl` flows through the
single-item `ecdsa_verify_cached` path; never the batch one.

Same sequential-loop-with-batch-name issue as BUG-9 also applies
(`batch_ecdsa_verify_nif`, `beamchain_crypto_nif.c:1186-1246`, is
likewise a per-item `secp256k1_ecdsa_verify` loop). Note that **for
ECDSA there is no cryptographic batch verification at all** (BIP-340
batching is Schnorr-specific), so the function name is even less
informative.

**File:** `src/beamchain_crypto.erl:44, 682-692`;
`c_src/beamchain_crypto_nif.c:1186-1246`.

**Core ref:** N/A — Core's per-item ECDSA verify is amortised via
`CCheckQueue` worker pools, not batched cryptographically.

**Impact:** dead helper (~50 LOC NIF + Erlang); maintenance cost only.
Adds to the fleet **wiring-look-but-no-wire** pattern count.

---

## BUG-11 (P1) — No `memory_cleanse` / `explicit_bzero` of secret-bearing buffers in the NIF

**Severity:** P1. Bitcoin Core's `KeyPair::SignSchnorr` calls
`memory_cleanse(sig.data(), sig.size())` on the signature buffer if
verify fails (line 561) and the entire `CKey`/`secure_allocator`
infrastructure wipes secret material on destruction
(`bitcoin-core/src/support/cleanse.cpp`).

beamchain's NIF has zero such calls. Concretely:

1. `seckey_tweak_add_nif` (lines 1107-1124): allocates a stack
   `unsigned char result[32]` and copies the seckey into it via
   `memcpy(result, seckey.data, 32)`. After `make_ok_binary` returns,
   the stack frame is unwound but the 32 secret bytes remain in the
   stack memory until overwritten. A subsequent NIF call (or a
   process scheduler switch) may leave the seckey readable to an
   attacker with `/proc/$pid/mem` access for an arbitrary window.
2. `schnorr_sign_nif` (line 1090): `secp256k1_keypair keypair;` on
   the stack holds the secret scalar in libsecp256k1's internal
   representation. Not cleansed.
3. `ellswift_xdh_nif` (line 1169): `unsigned char output[32]` is the
   BIP-324 ECDH shared secret — the seed for the v2 transport
   session. Returned to Erlang, then the stack copy is left in
   memory.
4. `ecdsa_sign_recoverable_nif`: `secp256k1_ecdsa_recoverable_signature rsig;`
   contains the signature including k (nonce) derivation traces;
   not cleansed.
5. `make_ok_binary` (line 667-674) copies into an Erlang VM binary
   via `enif_make_new_binary`; the VM-owned binary's lifetime is the
   Erlang GC, not under NIF control. There is no equivalent of
   Core's `secure_allocator` for Erlang binaries.

**File:** `c_src/beamchain_crypto_nif.c:1107-1124, 1080-1100, 1157-1178,
1014-1038` (representative; many more sites).

**Core ref:** `bitcoin-core/src/key.cpp:561` (cleanse on Schnorr
verify-fail); `bitcoin-core/src/support/cleanse.cpp` (`memory_cleanse`
implementation); `bitcoin-core/src/support/allocators/secure.h`
(`secure_allocator`).

**Impact:**
- Cold-boot-attack-style: an attacker who reads memory shortly after
  a sign / ECDH operation can recover secret material that should
  have been wiped.
- The risk is moderate (requires same-host access), but Core treats
  it as P0 — beamchain's omission is a hygiene gap.

**Fix sketch:** add `explicit_bzero` (or a portable
`secure_memzero`) just before each return path that handled secret
material. For long-lived secret data (the static `ctx` itself),
nothing to do — libsecp256k1's internal allocations are already
opaque.

---

## BUG-12 (P1) — No equivalent of Bitcoin Core's `LockedPool` / `mlock` for secret allocations

**Severity:** P1. Bitcoin Core's `LockedPool`
(`bitcoin-core/src/support/lockedpool.cpp`) `mlock(2)`s pages backing
secret-bearing allocations so they cannot be swapped to disk —
swap-paged secrets survive far longer than RAM-only secrets and may
end up in fsck-recovered swap dumps, hibernation files, crash dumps.
Core wires `CKey` through `secure_allocator` which routes through
`LockedPool`.

beamchain has no analogue. Erlang `binary()` data is allocated by the
VM's standard allocators (`erl_alloc.c`) which do not `mlock`. The
NIF's stack-local seckey buffers are likewise on the VM's process
stack — not locked.

A `swap` partition on a beamchain host with active signers
(`beamchain_witness_signer`, `beamchain_wallet`) can therefore swap
secret material to disk under memory pressure. After a crash,
`/dev/sdXswap` may contain recoverable seckeys.

**File:** `c_src/beamchain_crypto_nif.c` (zero `mlock` calls);
`src/beamchain_wallet*.erl` (zero VM-level cleanup hooks).

**Core ref:** `bitcoin-core/src/support/lockedpool.cpp`,
`bitcoin-core/src/support/allocators/secure.h`.

**Impact:** secret material may leak via swap. Concrete mitigations
on a maxbox-class host include `swapoff -a` or systemd
`MemoryDenyWriteExecute=` style hardening, but these are operator
controls, not code-level.

---

## BUG-13 (P0-SEC) — `pubkey_combine_nif` ignores `enif_alloc` NULL return — SIGSEGV / OOB write on memory pressure

**Severity:** P0-SEC. Under OOM, `enif_alloc` returns NULL. The
function then dereferences both pointers:

```c
/* beamchain_crypto_nif.c:941-979 */
static ERL_NIF_TERM pubkey_combine_nif(ErlNifEnv *env, int argc, ...)
{
    unsigned int list_len;
    if (!enif_get_list_length(env, argv[0], &list_len) ||
        list_len < 2 || list_len > 1024)
        return enif_make_badarg(env);

    secp256k1_pubkey *pubkeys = enif_alloc(list_len * sizeof(secp256k1_pubkey));
    const secp256k1_pubkey **ptrs = enif_alloc(list_len * sizeof(secp256k1_pubkey *));

    ERL_NIF_TERM head, tail = argv[0];
    for (unsigned int i = 0; i < list_len; i++) {
        enif_get_list_cell(env, tail, &head, &tail);
        ErlNifBinary pk_bin;
        if (!enif_inspect_binary(env, head, &pk_bin) ||
            !secp256k1_ec_pubkey_parse(ctx, &pubkeys[i], pk_bin.data, pk_bin.size)) {
            enif_free(pubkeys);
            enif_free(ptrs);
            return make_error(env, "invalid_pubkey");
        }
        ptrs[i] = &pubkeys[i];
    }
    /* ... */
}
```

If either `enif_alloc` returns NULL, the first `pubkeys[i] = ...` /
`ptrs[i] = ...` writes through a NULL pointer (SIGSEGV). If only the
SECOND allocation fails (high list_len, fragmented heap), the first
loop iteration writes successfully to `pubkeys[0]` but then dereferences
NULL `ptrs[0]` — same SIGSEGV.

Also: if `enif_get_list_cell` returns 0 (truncated list while
`enif_get_list_length` succeeded — racy if the list term were mutated,
but Erlang terms are immutable so unreachable in safe code), the loop
still writes to `pubkeys[i]` despite `head` being undefined.

A NIF SIGSEGV crashes the entire BEAM VM (the Erlang runtime
process), taking down all 60+ supervised processes in the node. This
is a remote DoS amplifier: any RPC path that exposes `pubkey_combine`
(MuSig2 / multisig descriptor expansion in
`beamchain_descriptor.erl`, `beamchain_psbt.erl:620`) can be triggered
remotely with a list of 1024 pubkeys to push the VM into OOM (the
total alloc is `1024 * (sizeof(pubkey) + sizeof(ptr)) = 1024 * 72 =
72 KiB` per call; nontrivial under concurrent flood). On a 32-thread
host running multiple beamchain instances, a flood of `pubkey_combine`
RPCs can starve the allocator.

**File:** `c_src/beamchain_crypto_nif.c:941-979`.

**Core ref:** Core uses C++ `std::vector` which throws `std::bad_alloc`
on allocation failure; the surrounding code catches at the RPC layer.

**Impact:** **remotely-triggerable BEAM VM crash** — full node down,
takes the supervision tree with it. P0-SEC. The cap `list_len > 1024`
limits per-call size but not aggregate concurrency.

**Fix:** check both `pubkeys` and `ptrs` for NULL immediately after
allocation; return `make_error(env, "alloc_failed")` (matching the
pattern used in `batch_ecdsa_verify_nif:1198` and
`batch_schnorr_verify_nif:1264`, which DO check NULL — so this is an
inconsistency within the same file).

---

## BUG-14 (P1) — `secp256k1_ecdsa_signature_serialize_der` return value ignored

**Severity:** P1. The serialiser returns 0 if the output buffer is
too small (per `secp256k1.h` API). beamchain uses a fixed 72-byte
buffer:

```c
/* beamchain_crypto_nif.c:998-1002 */
unsigned char der[72];
size_t der_len = 72;
secp256k1_ecdsa_signature_serialize_der(ctx, der, &der_len, &sig);

return make_ok_binary(env, der, der_len);
```

Canonical low-S DER signatures fit in 71 bytes worst-case (sequence
tag + len byte + 2× (int tag + len byte + 33-byte int) = 1+1+2+33+1+1+33
= 72), so 72 is exactly the canonical worst-case. But:

- If a future libsecp256k1 emits a non-canonical-length DER (highly
  unlikely; the API documents canonical output), the 72-byte buffer
  could be insufficient. The return value `0` would be silently
  ignored and `der_len` would be left at its prior value (which the
  v0.5.1 implementation actually writes the required size to on
  failure — but beamchain doesn't check it).
- The signature returned to Erlang would be garbage (uninitialised
  stack bytes from `der`).

**File:** `c_src/beamchain_crypto_nif.c:1000`.

**Core ref:** Core's `CKey::Sign` calls
`secp256k1_ecdsa_signature_serialize_der(secp256k1_context_static,
vchSig.data(), &nSigLen, &sig);` and then `vchSig.resize(nSigLen);`
(`bitcoin-core/src/key.cpp:226-227`) — Core trusts the size update.
But the surrounding `assert(ret)` at the post-sign verify step would
catch a corrupted output. beamchain has neither the assertion nor the
post-sign verify (BUG-4), so a serializer failure here is
double-silent.

**Impact:** practically unreachable today (canonical DER fits in 72);
becomes reachable if libsecp256k1 changes the encoding policy.
Defense-in-depth gap.

---

## BUG-15 (P0-CDIV) — Schnorr verify NIF hard-codes `msglen=32`; cannot verify BIP-340 arbitrary-length sigs

**Severity:** P0-CDIV. BIP-340 (and the libsecp256k1
`schnorrsig_verify` API at `secp256k1_schnorrsig.h:170-184`) accept
arbitrary-length messages — `msglen` is a parameter. Tapscript always
uses 32-byte sighashes (per BIP-341), so the consensus path is
unaffected, but:

- BIP-322 generic message-signing v2 messages can be arbitrary length
  (the `to_sign` virtual tx commits a tagged-hash of the raw
  message), and verify-message flows that hash externally then pass
  the digest are forced to do their own SHA-256 wrap.
- Anything calling `schnorr_verify` from outside the script
  interpreter (RPC `signmessage` if upgraded to use Schnorr, a
  hypothetical BIP-322-Schnorr verifier) is locked into 32-byte
  messages.

beamchain's NIF:

```c
/* beamchain_crypto_nif.c:779-799 */
static ERL_NIF_TERM schnorr_verify_nif(ErlNifEnv *env, int argc, ...)
{
    /* ... */
    if (msg.size != 32 || sig.size != 64 || pubkey.size != 32)
        return make_error(env, "invalid_size");
    /* ... */
    int result = secp256k1_schnorrsig_verify(ctx, sig.data,
                                              msg.data, 32, &xpk);
    /* ... */
}
```

The `32` literal is the `msglen` arg — not the caller-supplied
`msg.size`. This is intentional but undocumented; the comment block
above the function ("`Msg32, Sig64, XOnlyPubKey32`") names the
expected shape but doesn't say "BIP-340 also supports msglen != 32".

**File:** `c_src/beamchain_crypto_nif.c:789, 796`.

**Core ref:** `bitcoin-core/src/secp256k1/include/secp256k1_schnorrsig.h:170-184`
(API supports arbitrary `msglen`).

**Impact:**
- BIP-322-Schnorr verification path cannot use this NIF directly
  (must pre-hash messages to 32 bytes — duplicating the BIP-340 spec
  rule that `e = int(challenge_hash || ...)` already includes the
  hashing).
- API surface is narrower than upstream. A future feature wave that
  needs arbitrary-length Schnorr verify (signed-message-v2,
  BIP-322 helpers, MuSig2 partial-sig adaptor) needs to expand the
  NIF.

**Fix:** add a `schnorr_verify_msglen_nif(Msg, Sig, PubKey, MsgLen)`
or pass `msg.size` directly to `schnorrsig_verify`.

---

## BUG-16 (P2) — `schnorr_verify/3` Erlang guard forbids non-32-byte messages

**Severity:** P2 (follow-on to BUG-15). The Erlang wrapper:

```erlang
%% beamchain_crypto.erl:202-218
-spec schnorr_verify(Msg :: binary(), Sig :: binary(),
                     PubKey :: binary()) -> boolean().
schnorr_verify(Msg, Sig, PubKey) when byte_size(Msg) =:= 32,
                                       byte_size(Sig) =:= 64,
                                       byte_size(PubKey) =:= 32 ->
    /* ... */
```

The function-head guard rejects any message that isn't exactly 32
bytes with `function_clause` (BadMatch-style crash for a guarded
function). Even if BUG-15's NIF were fixed to accept arbitrary
lengths, the Erlang API would still gate at 32.

**File:** `src/beamchain_crypto.erl:202-218, 261-276, 697-707`
(`schnorr_verify_cached`, `batch_schnorr_verify` likewise gate at 32).

**Core ref:** BIP-340 `Verify(pk, m, sig)` allows arbitrary `|m|`.

**Impact:** API surface defect; same root cause as BUG-15. Callers
must SHA-256 the message themselves before calling, which is
asymmetric with the underlying C library's signature.

---

## BUG-17 (P2) — Comment-as-confession: `init/0` claims "using pure Erlang fallback" on NIF load failure, but the path is dead-code-but-called

**Severity:** P2 (fleet pattern: comment-as-confession). The init
callback:

```erlang
%% beamchain_crypto.erl:71-83
init() ->
    SoName = filename:join(priv_dir(), "beamchain_crypto_nif"),
    Ret = erlang:load_nif(SoName, 0),
    %% Track NIF load status for fallback logic
    case Ret of
        ok ->
            persistent_term:put(?NIF_LOADED, true);
        _ ->
            persistent_term:put(?NIF_LOADED, false),
            logger:warning("beamchain_crypto: NIF not loaded, using pure Erlang fallback")
    end,
    init_tag_hashes(),
    Ret.
```

The function returns `Ret`, which is whatever `erlang:load_nif/2`
returned (`ok` or `{error, _}`). Per OTP semantics, returning
`{error, _}` from `-on_load(init/0)` ABORTS module load — the module
becomes uncallable, no other function (including the "pure Erlang
fallback") can ever execute.

So:
- The `logger:warning` line at line 80 fires once during the abort
  sequence, then the entire `beamchain_crypto` module is removed.
- All `try ... catch error:nif_not_loaded -> ...` branches in
  `sha256/1` (line 538-544), `hash256/1` (line 546-554),
  `ecdsa_verify/3` (line 172-182), `schnorr_verify/3` (line 202-218),
  `batch_ecdsa_verify/1` (line 685-692), `batch_schnorr_verify/1`
  (line 700-707) are unreachable: the module isn't loaded, so
  `nif_not_loaded` errors don't fire from "stub" calls — they fire
  from `load_nif` failing, which aborts module load entirely.

The "pure Erlang fallback" is a fiction. If the NIF doesn't load,
`beamchain_crypto:sha256/1` is undefined and every caller raises
`undef`. The supervision tree restarts everything.

This is the SAME comment-as-confession shape as W153 hotbuns BUG-5
("Bug fixed: was 1 sat/vB (10× too high)" comment confessing a bug
when the new behaviour is also wrong).

**File:** `src/beamchain_crypto.erl:71-83, 538-544, 547-554, 172-182,
202-218, 685-707`.

**Core ref:** N/A.

**Impact:** misleading commentary; an operator reading
`logger:warning("...using pure Erlang fallback")` may believe the
node will degrade gracefully. In reality it will fail to start.

**Fix:** return `ok` unconditionally from `init/0` and gate runtime
behaviour on `persistent_term:get(?NIF_LOADED)` per call — OR remove
the misleading "fallback" comment + log line and document that the
NIF is a hard dependency.

---

## BUG-18 (P2) — SHA-256 NIF runs on the NORMAL scheduler with no size cap; multi-MB inputs block the VM

**Severity:** P2. The NIF dispatch table:

```c
/* beamchain_crypto_nif.c:1314-1320 */
static ErlNifFunc nif_funcs[] = {
    {"sha256_nif",                 1, sha256_nif,
        0},  /* Fast enough for normal scheduler */
    {"double_sha256_nif",          1, double_sha256_nif,
        0},  /* Fast enough for normal scheduler */
    /* ... */
};
```

`sha256_nif` runs on the normal Erlang scheduler (flags = 0). OTP's
contract: a NIF must complete within ~1 ms or it disrupts scheduler
fairness (Erlang preemption is cooperative for NIFs).

The portable SHA-256 implementation processes ~250 MB/s on a typical
core (the SHA-NI variant ~2 GB/s; the ARM-SHA variant ~1.5 GB/s). At
250 MB/s, a 1 MB block takes ~4 ms — already 4× over the budget. A 4
MB block (Bitcoin's serialized-size cap) takes ~16 ms on the portable
path. Even with SHA-NI, a 4 MB block is ~2 ms — still 2× the budget.

The actual workload `hash256` (double-SHA256) doubles the time. A
block-merkle re-hash over a tx-id batch can chain many such calls in
sequence.

**File:** `c_src/beamchain_crypto_nif.c:1314-1320`.

**Core ref:** N/A (Core is C++, no scheduler-fairness contract).

**Impact:**
- Scheduler latency spikes when validating large blocks: other
  processes (P2P, RPC, ZMQ) wait for a ~10-20 ms scheduler tick
  before they run. Aggregate impact: tail-latency on RPC bumps
  during block validation. Not a consensus bug but an operability
  defect — and beamchain's W12 87-min DOWN postmortem flagged
  scheduler/process-management as a chronic source of bugs.
- The dirty-CPU schedulers (used by `ERL_NIF_DIRTY_JOB_CPU_BOUND`)
  exist precisely to take long-running NIFs OFF the normal pool.
  Marking `sha256_nif` as `ERL_NIF_DIRTY_JOB_CPU_BOUND` for inputs
  > N bytes (e.g., 64 KB) would resolve this.

**Fix sketch:** add a length-gated dispatcher (Erlang side):
`sha256/1` checks `byte_size(Data) > 65536` and routes to
`sha256_dirty_nif/1` (registered with `ERL_NIF_DIRTY_JOB_CPU_BOUND`)
in that case.

---

## BUG-19 (P2) — Lax-DER length parser silently truncates 3+ byte length encodings (`0x83+`) to zero

**Severity:** P2. The lax-DER length reader:

```erlang
%% beamchain_crypto.erl:865-875
%% Read a DER length field (handles 1-byte and multi-byte forms)
read_der_length(<<>>) -> {0, <<>>};
read_der_length(<<Len, Rest/binary>>) when Len < 16#80 ->
    {Len, Rest};
read_der_length(<<16#81, Len, Rest/binary>>) ->
    {Len, Rest};
read_der_length(<<16#82, Len:16/big, Rest/binary>>) ->
    {Len, Rest};
read_der_length(<<_, Rest/binary>>) ->
    %% Fallback: treat as zero length
    {0, Rest}.
```

Handles 1-byte (Len < 0x80), `0x81 <byte>` (up to 255), and `0x82
<u16>` (up to 65535). The fallback clause silently returns `{0,
Rest}` for anything else — including `0x80` (indefinite-length form,
which IS a valid BER but not DER), `0x83 <u24>` (up to 2^24-1), or
`0x84 <u32>`.

For Bitcoin signatures the length field never exceeds ~72 bytes so
`0x82` is overkill and `0x83+` is impossible in well-formed input.
BUT Bitcoin Core's lax parser
(`bitcoin-core/src/script/interpreter.cpp::ecdsa_signature_parse_der_lax`)
DOES accept extended-length forms because it is "tolerant of any
length encoding that is well-formed BER" — beamchain's stricter
behaviour means some pre-BIP66 signatures Core accepts, beamchain
rejects.

Pre-BIP66 (block 363725 / July 2015) was when STRICTDER was activated
at consensus. Before that height, "lax" signatures were valid. A full
sync that revalidates pre-BIP66 history (i.e., not using assumevalid)
hits this divergence on any tx whose ScriptSig used `0x83+` length
encoding for its sig.

In practice, no historical Bitcoin tx used `0x83+` (signatures are
always ≤ ~73 bytes), so this is a theoretical divergence today. But
the wrapper's silent truncation also means that on `0x80` (BER
indefinite-length, invalid for DER) the parser succeeds with len=0
where Core fails — that's the wrong direction (we accept what Core
rejects).

**File:** `src/beamchain_crypto.erl:865-875`.

**Core ref:** `bitcoin-core/src/script/interpreter.cpp` (lax parser
handles extended forms);
`bitcoin-core/src/secp256k1/contrib/lax_der_parsing.c` (reference
implementation).

**Impact:** practically unreachable on current chain; theoretical
divergence on craft / historical edge cases.

---

## BUG-20 (P2) — Signed-message header byte range is STRICTER than Bitcoin Core

**Severity:** P2. beamchain's `verify_message`:

```erlang
%% beamchain_crypto.erl:449-451
<<Header:8, RS:64/binary>> when Header >= 27, Header =< 42 ->
    RecId = (Header - 27) band 3,
    Compressed = (Header - 27) >= 4,
```

Bitcoin Core's `CPubKey::RecoverCompact`:

```cpp
/* bitcoin-core/src/pubkey.cpp:300-304 */
bool CPubKey::RecoverCompact(const uint256 &hash, const std::vector<unsigned char>& vchSig) {
    if (vchSig.size() != COMPACT_SIGNATURE_SIZE)
        return false;
    int recid = (vchSig[0] - 27) & 3;
    bool fComp = ((vchSig[0] - 27) & 4) != 0;
    /* ... */
```

Core has NO upper bound on `vchSig[0]` (it's a byte: 0..255). The
mask `(vchSig[0] - 27) & 3` extracts the recid; `(vchSig[0] - 27) &
4` extracts the compressed bit. So Core accepts any header byte that
recovers a valid pubkey for one of the four recids.

beamchain's `Header =< 42` rejects header bytes 43..255 (and rejects
header bytes 0..26 with `Header >= 27`). This is a strict subset of
Core's accepted set: beamchain will reject signatures with header
bytes like 50 or 100 that Core would happily decode (assuming the
sig+hash combo recovers to a valid pubkey).

Concretely: every legitimately-emitted Bitcoin signed message uses
header bytes 27..34 (rec 0-3, compressed 0/1), so the divergence is
not observed in practice. But a fuzzer / cross-impl differential
test that feeds out-of-spec header bytes will diverge: Core
accepts/rejects based on the mathematical recovery, beamchain
rejects based on the byte being out of [27, 42].

Also: `Compressed = (Header - 27) >= 4` is wrong for headers 38..42.
For Header=38: `(38-27) >= 4` → 11 >= 4 → true. But the bit-mask
form `((vchSig[0]-27) & 4) != 0` gives 11 & 4 = 4 ≠ 0 → also true.
For Header=39: `12 >= 4 → true` vs `12 & 4 = 4 → true`. Both agree
on 4..7 and 12..15, disagree on 8..11. Specifically:
- Header=35 (8): beamchain `>= 4 → true` (compressed). Core `8 & 4
  = 0 → false` (uncompressed). **divergence**.

Within the range beamchain accepts (27..42), bytes 35..38 give the
wrong `Compressed` flag relative to Core. This means a signed
message produced with header byte 35 (uncommon but possible from a
fuzzed/malformed signer) is interpreted as compressed by beamchain
but uncompressed by Core — `pubkey_decompress` is called on a
compressed pubkey (no-op) vs not called (returns as-is), and the
`hash160` comparison fails on whichever side disagrees.

**File:** `src/beamchain_crypto.erl:449-451`.

**Core ref:** `bitcoin-core/src/pubkey.cpp:300-304`.

**Impact:** P2 — practical signers never emit out-of-spec header
bytes, so this is a cross-impl differential-fuzz issue rather than
a real-world divergence. But it's clearly wrong on two axes:
- overly-narrow accepted range,
- wrong `Compressed` flag derivation for the upper half of the
  range.

---

## Fleet-pattern cross-cites

- **side-channel-blinding-disabled (3/10 confirmed)** — beamchain
  BUG-3 joins W158 lunarblock BUG-7 (`context_randomize` never called)
  and W159 rustoshi BUG-4 (same root cause). With W158 clearbit
  BUG-2 (cipher-as-scalar) as a worse variant, the pattern is now
  **at minimum 4/10** impls. Outstanding 6 impls (hotbuns, blockbrew,
  ouroboros, camlcoin, haskoin, nimrod) likely candidates; W160+ should
  pin this down.
- **wiring-look-but-no-wire (BUG-8 + BUG-10)** — `batch_schnorr_verify`
  and `batch_ecdsa_verify` are exported, NIF-implemented, documented
  performance-amortising helpers with ZERO production callers. Same
  shape as W156 hotbuns BUG-31 (BlockTemplateBuilder 1000+ LOC dead),
  W153 beamchain BUG-2+3+11 (do_trim_to_size / do_expire_old never
  fire), and many others. **First instance of this pattern in the
  beamchain crypto layer.**
- **comment-as-confession (BUG-17)** — `init/0`'s
  "using pure Erlang fallback" log message + the surrounding `try ...
  catch error:nif_not_loaded -> ...` infrastructure is dead-code-but-
  called. Same shape as W153 hotbuns BUG-5 "Bug fixed: was 1 sat/vB
  (10× too high)". This is beamchain's
  **N-th distinct comment-as-confession instance** (W138-W158 already
  documented multiple).
- **dead-helper-with-misleading-name (BUG-9)** — `batch_schnorr_verify`
  promises cryptographic batch verification (`(N+2)*mul`) but
  delivers a sequential loop (`N*2*mul`). API name and reality
  diverge. Joins the "advertisement-as-lie" pattern noted in W155
  hotbuns 5th instance.
- **API name asymmetric with C library contract (BUG-15, BUG-16)** —
  `schnorr_verify_nif` hard-codes `msglen=32`; the Erlang wrapper
  enforces it with a function-head guard. Underlying C API supports
  arbitrary lengths. Same architectural shape as W156 blockbrew BUG
  "asymmetric encode/decode round-trip".

## New patterns this audit

- **NIF-FFI paranoia-step uniformly absent** (BUG-4, BUG-5, BUG-6
  — three sites, identical structure). Core's
  `CKey::Sign`/`SignCompact`/`KeyPair::SignSchnorr` all close with a
  post-sign verify; beamchain's NIF closes none of them. This is a
  **fleet-pattern candidate**: check rustoshi/camlcoin/clearbit/...
  NIF wrappers for the same gap.
- **Sequential-loop labeled as `batch_*`** (BUG-9, BUG-10) — Two
  functions advertise cryptographic batch verification semantics they
  do not provide. Variation on "advertisement-as-lie".
- **Dead-on-load-failure infrastructure** (BUG-17) — extensive
  fallback-style code that can never run because the load failure
  path takes the module down. **Different shape from
  comment-as-confession**: not just a docstring lie, but ~60 LOC of
  `try ... catch error:nif_not_loaded` that is dead-on-arrival
  because the module wouldn't exist if the NIF didn't load.
  Suggested pattern name: **"defensive-code-against-impossible-state"**.
- **NULL-check inconsistency within one file** (BUG-13) — two
  different `enif_alloc` sites in the same file: one checked, one not.
  Same shape as the audits' frequent "intra-module N-pipeline drift",
  but at the C-NIF granularity rather than the validation-pipeline
  granularity.

## Carry-forward observations

- W158 noted no equivalent of side-channel-blinding in beamchain's
  signing path; this audit confirms it (BUG-3) — beamchain side-
  channel-blinding-disabled stays open.
- No new beamchain-specific carry-forwards from this wave (the
  crypto layer hadn't been a discrete audit target before).

## Notes for next wave

- Repeat for hotbuns / blockbrew / ouroboros / camlcoin / haskoin /
  nimrod: side-channel-blinding-disabled count + paranoia-step
  uniformly-absent count.
- Check whether MuSig2 partial-sig aggregation
  (`beamchain_psbt.erl:620`) routes through a hypothetical batch
  Schnorr verifier — if so, BUG-9 becomes higher priority.
- Audit `beamchain_witness_signer.erl` for additional sign sites
  that bypass the central NIF dispatch (carrying their own ad-hoc
  paranoia or lack thereof).
