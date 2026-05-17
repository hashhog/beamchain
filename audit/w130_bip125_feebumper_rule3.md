# W130 — BIP-125 RBF feebumper Rule 3 / `incrementalRelayFee.GetFee(maxTxSize)` audit (beamchain)

Discovery-only wave. 30 audit gates focused on the **wallet-side** BIP-125
fee-bump path: `bitcoin-core/src/wallet/feebumper.cpp`
(`CreateRateBumpTransaction`, `CheckFeeRate`, `EstimateFeeRate`,
`PreconditionChecks`, `CommitTransaction`) + the policy invariants in
`policy/rbf.{cpp,h}` and `policy/feerate.cpp` that those wallet helpers
must obey.

Companion to **W120** (mempool-side strict Rules 1-5) and **W118** (wallet
bumpfee surface). W120 catalogues the mempool's `do_rbf` / `do_package_rbf`
gates; W118 catalogues that bumpfee + psbtbumpfee were missing pre-FIX-61.
**W130 goes a level deeper than both**: it audits the *integration* between
the wallet's `rpc_bumpfee` and mempool's `do_rbf`, with focus on the
`incrementalRelayFee.GetFee(maxTxSize)` precise invariant that Core lifts
out of `policy/rbf.cpp::PaysForRBF` and re-imposes wallet-side in
`feebumper.cpp::CheckFeeRate` (line 93).

Status counts (30 gates):

- **PRESENT** (matches Core or internally consistent + Core-compatible): 3
- **PARTIAL** (some piece matches, others diverge): 7
- **MISSING** (no equivalent in beamchain): 20

Headline: **22 bugs**, severity distribution **0 CDIV / 3 HIGH / 11
MEDIUM / 8 LOW**. None affects consensus validation of received blocks
(feebumper is wallet-side: wrong selection = wallet UX failure / silent
overpay / under-replacement, not consensus drift). The most consequential:

1. **BUG-1 (HIGH)** — Rule 4 / `PaysForRBF` denominator uses `OldVSize`
   instead of `replacement_vsize`. Core (`policy/rbf.cpp:118`) requires
   `additional_fees >= relay_fee.GetFee(replacement_vsize)`. beamchain
   computes `MinAdditionalFee = (OldVSize * 100 + 999) div 1000` in
   `rpc_bumpfee` at `beamchain_rpc.erl:5750` and treats the result as the
   wallet-side minimum. When the replacement is materially larger than the
   original (added witness for re-signing, or just a different signature
   shape), the bump fee is computed on the wrong size and the replacement
   is rejected by the **mempool's** PaysForRBF on entry — the wallet path
   accepted a feerate the mempool gates won't.
2. **BUG-2 (HIGH)** — `CheckFeeRate.mempoolMinFee` gate (Core
   `feebumper.cpp:67-75`) is **entirely absent**. The bumped tx can be
   computed with a feerate below the rolling mempool min fee, then submit
   to `accept_to_memory_pool` and bounce with `mempool_min_fee_not_met`.
   The wallet returns RPC success → mempool reject; Core would have
   returned `WALLET_ERROR "New fee rate ... is lower than the minimum fee
   rate to get into the mempool"` before doing any work.
3. **BUG-3 (HIGH)** — `-maxtxfee` cap (Core
   `feebumper.cpp:108-114, m_default_max_tx_fee`) is **entirely absent**.
   beamchain has no `m_default_max_tx_fee` concept at all (verified by
   absence of `max_tx_fee` / `maxtxfee` token across
   `beamchain_config.erl`, `beamchain_wallet.erl`, `beamchain_rpc.erl`).
   A misconfigured `fee_rate=10000` (sat/vB) will silently produce a
   1 BTC fee on a 100 kvB tx instead of erroring out.
4. **BUG-4 (HIGH)** — Rule 5 `MAX_REPLACEMENT_CANDIDATES` is documented
   ("Core: MAX_REPLACEMENT_CANDIDATES" at
   `include/beamchain_protocol.hrl:169`) but **gated wrong**.
   beamchain compares `length(AllEvictTxids) =< 100` (total tx count
   inc. descendants), whereas Core (`policy/rbf.cpp:69-75`,
   `GetUniqueClusterCount`) caps the **unique cluster count of the
   directly-conflicting iters**. The cluster count is ≤ the tx count, so
   beamchain over-rejects: a single conflict's chain of 101 descendants
   is rejected by beamchain even though it is **one** cluster and
   Core would accept it.
5. **BUG-5 (MEDIUM)** — Rule 3 (`PaysForRBF.replacement_fees <
   original_fees`) is enforced as `NewFee >= EvictedFeeTotal` (correct),
   but the **wallet-side mirror** in `bumpfee_build_and_finalize`
   computes `MinNewFee = OldFee + OldVSize * IncrSatVB` — Core's
   `CheckFeeRate` line 93 uses `minTotalFee = old_fee +
   incrementalRelayFee.GetFee(maxTxSize)`, where `maxTxSize` is the
   *new* tx's max signed vsize from `CalculateMaximumSignedTxSize`
   (line 289). beamchain has no `CalculateMaximumSignedTxSize` helper;
   re-using `OldVSize` is wrong whenever the new sig is larger or witness
   shape differs.

The remaining 17 bugs (5 MEDIUM + 8 LOW) cover: missing
`combined_bump_fee` integration, missing `EstimateFeeRate` defaults
(W118 BUG-2 fallback), no `original_change_index` option, no `outputs`
array override, no `WALLET_INCREMENTAL_RELAY_FEE` propagation through
`EstimateFeeRate` (only used in rpc_bumpfee's PaysForRBF gate),
`PreconditionChecks` missing `HasWalletSpend` wallet-descendants check,
`replaced_by_txid`/`replaces_txid` map-value tracking absent (Core
`feebumper.cpp:42-44, 371-378`), no `MarkReplaced` wallet-tx
relationship, comment-as-confession at `beamchain_rpc.erl:5637`
("get_descendants includes self" — false: `get_all_descendants` excludes
seed), `WALLET_INCREMENTAL_RELAY_FEE_SATVB=5` integer rounding mismatches
Core's `CFeeRate(WALLET_INCREMENTAL_RELAY_FEE)` 5000 sat/kvB exact
arithmetic, fee-rate option accepted as float but Core only accepts
CAmount-per-kvB (`spend.cpp:bumpfee_helper`), no `original_change_index`
range check at output-vector length, `bumpfee_extract_entry`'s
positional record-pattern destructures `mempool_entry` shape — silent
rot-trap when fields are added (W129-style fixture rot risk), and a
package-RBF interaction gate where the wallet's `rpc_bumpfee` never goes
through the package path (W120 G18-G20 already document the mempool
side; W130 G28 records the wallet-side absence).

Reference: `bitcoin-core/src/wallet/feebumper.cpp` (385 LOC,
`PreconditionChecks` :23-57, `CheckFeeRate` :60-117, `EstimateFeeRate`
:119-144, `CreateRateBumpTransaction` :159-328, `CommitTransaction`
:350-382), `bitcoin-core/src/policy/rbf.{cpp,h}` (`PaysForRBF`,
`GetEntriesForConflicts`, `EntriesAndTxidsDisjoint`,
`MAX_REPLACEMENT_CANDIDATES`, `ImprovesFeerateDiagram`),
`bitcoin-core/src/policy/feerate.cpp` (`CFeeRate::GetFee` ceiling
arithmetic), BIP-125.

The audit-flip convention applies: every test asserts a **divergent fact
that holds today** so the gate passes now, and **flips to FAIL when the
fix lands**.

---

## Gate index (1..30)

| #  | Name | Status | Core ref | beamchain ref |
|----|------|--------|----------|---------------|
| 1  | `MAX_BIP125_RBF_SEQUENCE` constant value (0xFFFFFFFD)        | PRESENT | util/rbf.h                                          | `beamchain_protocol.hrl:168` |
| 2  | `DEFAULT_INCREMENTAL_RELAY_FEE` constant (100 sat/kvB)       | PRESENT | policy/policy.h:48                                  | `beamchain_protocol.hrl:165` |
| 3  | `WALLET_INCREMENTAL_RELAY_FEE` constant (5000 sat/kvB)       | PARTIAL | wallet/wallet.h                                     | `beamchain_rpc.erl:5582` defined as `_SATVB=5` (integer rounding) — see BUG-7 |
| 4  | `PaysForRBF` Rule 3 (replacement_fees ≥ original_fees)       | PRESENT | policy/rbf.cpp:109-112                              | `beamchain_mempool.erl:1982` (mempool side); wallet side BUG-5 |
| 5  | `PaysForRBF` Rule 4: `additional_fees ≥ relay_fee.GetFee(replacement_vsize)` | PARTIAL | policy/rbf.cpp:117-123                              | `beamchain_rpc.erl:5750` uses **OldVSize** not replacement vsize — BUG-1 |
| 6  | `CheckFeeRate.mempoolMinFee` precheck                        | MISSING | wallet/feebumper.cpp:67-75                          | absent in `rpc_bumpfee` — BUG-2 |
| 7  | `m_default_max_tx_fee` / `-maxtxfee` cap                     | MISSING | wallet/feebumper.cpp:108-114                        | no `max_tx_fee` config token — BUG-3 |
| 8  | `MAX_REPLACEMENT_CANDIDATES` is **cluster** count            | MISSING | policy/rbf.cpp:69 / `GetUniqueClusterCount`         | `beamchain_mempool.erl:1962` uses total tx count — BUG-4 |
| 9  | `CheckFeeRate.minTotalFee` = old_fee + incrFee × **maxTxSize** | MISSING | wallet/feebumper.cpp:93                             | `beamchain_rpc.erl:5750` uses OldVSize — BUG-5 |
| 10 | `EstimateFeeRate` default path (no caller fee_rate)          | PARTIAL | wallet/feebumper.cpp:119-144                        | `beamchain_rpc.erl:5752-5755` collapses to `MinNewFee` (no estimator) — BUG-6 |
| 11 | `WALLET_INCREMENTAL_RELAY_FEE` exact 5000 sat/kvB arithmetic | MISSING | wallet/wallet.h + feebumper.cpp:136                 | beamchain `?WALLET_INCREMENTAL_RELAY_FEE_SATVB = 5` rounded — BUG-7 |
| 12 | `CalculateMaximumSignedTxSize` for new tx                    | MISSING | wallet/spend.cpp / feebumper.cpp:289                | absent; `OldVSize` is reused — BUG-8 |
| 13 | `combined_bump_fee` from `chain.calculateCombinedBumpFee`    | MISSING | wallet/feebumper.cpp:83-87                          | absent (W129 BUG-30 carry-forward) |
| 14 | `original_change_index` option                               | MISSING | wallet/feebumper.cpp:181-184                        | not parsed in `rpc_bumpfee` — BUG-10 |
| 15 | `outputs` array override                                     | MISSING | wallet/feebumper.cpp:159-160, 251-263               | not parsed in `rpc_bumpfee` — BUG-11 |
| 16 | `PreconditionChecks.HasWalletSpend` wallet-descendants check | MISSING | wallet/feebumper.cpp:25-28                          | only mempool descendants checked — BUG-12 |
| 17 | `PreconditionChecks.GetTxDepthInMainChain ≠ 0`               | MISSING | wallet/feebumper.cpp:37-40                          | not checked; assumes mempool presence == unconfirmed — BUG-13 |
| 18 | `PreconditionChecks.replaced_by_txid` recursive-bump guard   | MISSING | wallet/feebumper.cpp:42-45                          | no `replaced_by_txid` tracking — BUG-14 |
| 19 | `PreconditionChecks.AllInputsMine` for `require_mine`        | PARTIAL | wallet/feebumper.cpp:47-54                          | `lookup_privkeys_for_inputs` enforces — see BUG-15 |
| 20 | `CreateRateBumpTransaction.findCoins` over UTXO set          | PARTIAL | wallet/feebumper.cpp:191-208                        | `bumpfee_lookup_input_utxos` does similar — see BUG-16 |
| 21 | `CommitTransaction.MarkReplaced` + `mapValue["replaces_txid"]` | MISSING | wallet/feebumper.cpp:370-379                        | absent — BUG-17 |
| 22 | Rule 5 cluster check pre-RBF for **package** RBF             | PARTIAL | validation.cpp ReplacementChecks/PackageRBFChecks   | uses same `length =< 100` gate — BUG-4 carry to package |
| 23 | `ImprovesFeerateDiagram` strict `is_gt` (Core 28+)           | PARTIAL | policy/rbf.cpp:130-139                              | `diagram_dominates` uses `>=` (non-strict) — W120 BUG-12 carry |
| 24 | `find_mempool_conflicts` dedup by txid                       | PRESENT | (helper)                                            | `lists:usort` at `beamchain_mempool.erl:1895` |
| 25 | `EntriesAndTxidsDisjoint` ancestor walk                      | PARTIAL | policy/rbf.cpp:85-98                                | `beamchain_mempool.erl:1944-1948` walks **direct parents only** (W120 BUG-7 carry) |
| 26 | `rpc_bumpfee` re-runs coin selection (`SelectCoins`)         | MISSING | wallet/feebumper.cpp:314 + spend.cpp                | reuses input set; never calls SelectCoins — BUG-21 (W129 BUG-29 carry) |
| 27 | `psbtbumpfee` returns Core wire shape (psbt/origfee/fee/errors) | PARTIAL | wallet/feebumper.cpp:CommitTransaction              | `bumpfee_emit_psbt` returns shape; missing `errors` semantics |
| 28 | Package-RBF wallet path                                      | MISSING | wallet/feebumper.cpp + validation PackageRBFChecks  | `rpc_bumpfee` is single-tx only — BUG-22 |
| 29 | `bumpfee_extract_entry` positional record-pattern hardened   | MISSING | (cosmetic rot guard)                                | `beamchain_rpc.erl:5694-5697` will silently mismatch if `mempool_entry` fields added — BUG-20 |
| 30 | Comment-as-confession at `bumpfee_run` descendants check     | MISSING | (lint)                                              | `beamchain_rpc.erl:5637` claims "get_descendants includes self" — actually excludes (BUG-19) |

---

## Bug catalogue (22 BUGs)

### BUG-1 (HIGH) — Rule 4 / PaysForRBF wallet-side uses `OldVSize` not `replacement_vsize`

Core `policy/rbf.cpp:117-123`:
```cpp
CAmount additional_fees = replacement_fees - original_fees;
if (additional_fees < relay_fee.GetFee(replacement_vsize)) { ... reject }
```
where `replacement_vsize` is the **new** tx's vsize.

beamchain `beamchain_rpc.erl:5743-5750`:
```erlang
NodeIncrSatVB = (beamchain_mempool:incremental_relay_fee_constant() + 999) div 1000,
IncrSatVB = max(?WALLET_INCREMENTAL_RELAY_FEE_SATVB, NodeIncrSatVB),
MinNewFee = OldFee + OldVSize * IncrSatVB,
```
`OldVSize` is the **original** tx's vsize. The replacement is normally
larger (different witness, different change script, possibly different
sig). When `new_vsize > old_vsize`, the wallet computes a target fee that
satisfies its own pseudo-PaysForRBF but the *mempool's* real
`PaysForRBF` (which uses `new_vsize` correctly,
`beamchain_mempool.erl:1991-1994`) rejects with
`rbf_insufficient_additional_fee`. The wallet computes "good", the
mempool says "no" — a classic split-brain.

### BUG-2 (HIGH) — `CheckFeeRate.mempoolMinFee` precheck is missing

Core `wallet/feebumper.cpp:67-75`:
```cpp
CFeeRate minMempoolFeeRate = wallet.chain().mempoolMinFee();
if (newFeerate.GetFeePerK() < minMempoolFeeRate.GetFeePerK()) {
    errors.push_back(... "New fee rate ... is lower than the minimum fee rate ...");
    return feebumper::Result::WALLET_ERROR;
}
```

`rpc_bumpfee` does not query the rolling mempool min fee at all
(no `mempool_min_fee` / `GetMinFee` call in any of the 5 bumpfee_*
helpers). The bumped tx is built, signed, and submitted to
`accept_to_memory_pool` which then rejects with
`mempool_min_fee_not_met`. The user sees "Replacement tx rejected by
mempool" instead of a precondition error, and the wallet has already
done a full re-sign for nothing.

### BUG-3 (HIGH) — `-maxtxfee` (`m_default_max_tx_fee`) cap is missing

Core `wallet/feebumper.cpp:108-114`:
```cpp
const CAmount max_tx_fee = wallet.m_default_max_tx_fee;
if (new_total_fee > max_tx_fee) {
    errors.push_back(... "Specified or calculated fee ... is too high (cannot be higher than -maxtxfee ...");
    return feebumper::Result::WALLET_ERROR;
}
```

The `m_default_max_tx_fee` concept does not exist in beamchain:
no `max_tx_fee`, `m_default_max_tx_fee`, or `maxtxfee` reference in
`beamchain_config.erl`, `beamchain_wallet.erl`, or `beamchain_rpc.erl`.
The closest match is `DEFAULT_MAX_RAW_TX_FEE_RATE = 10000000` at
`beamchain_rpc.erl:2546`, but that is a **sendrawtransaction
fee-rate cap**, not a per-tx absolute fee cap. A user who passes
`fee_rate=10000` (sat/vB) to bumpfee on a 100 kvB tx will produce a
1,000,000,000 sat = **10 BTC** fee, and `rpc_bumpfee` will broadcast it.

### BUG-4 (HIGH) — Rule 5 `MAX_REPLACEMENT_CANDIDATES` is cluster count, not tx count

Core `policy/rbf.cpp:69-75`:
```cpp
auto num_clusters = pool.GetUniqueClusterCount(iters_conflicting);
if (num_clusters > MAX_REPLACEMENT_CANDIDATES) {
    return strprintf("rejecting replacement %s; too many conflicting clusters ...");
}
```

beamchain `beamchain_mempool.erl:1962`:
```erlang
AllEvictTxids = lists:usort(DescendantsAndSelf ++ EphemeralParents),
length(AllEvictTxids) =< ?MAX_RBF_EVICTIONS
    orelse throw(rbf_too_many_evictions),
```
where `?MAX_RBF_EVICTIONS = 100`. The comment in
`beamchain_protocol.hrl:169` says
`%% Core: MAX_REPLACEMENT_CANDIDATES` — but the semantics differ:

- Core caps the **number of distinct clusters** the directly-conflicting
  set intersects (BEFORE descendant expansion).
- beamchain caps the **total evicted txid count** (AFTER descendant
  expansion + ephemeral-parent widening).

A single conflict that has a 101-deep CPFP descendant chain (one
cluster) is rejected by beamchain even though Core would accept it
(one cluster, well within `MAX_REPLACEMENT_CANDIDATES=100`).
Symmetric overlap is conceivable — 101 separate one-tx conflicts (101
clusters) — but beamchain's count would *also* reject that, so the
divergence is one-directional: beamchain is **stricter** than Core,
causing wallet-correctness-preserving overlap but client-incompatible
behavior on `getmempoolentry` follow-up calls.

### BUG-5 (MEDIUM) — `CheckFeeRate.minTotalFee` parity uses wrong size

`CheckFeeRate` line 93:
```cpp
CAmount minTotalFee = old_fee + incrementalRelayFee.GetFee(maxTxSize);
```
where `maxTxSize` is `CalculateMaximumSignedTxSize(CTransaction(temp_mtx),
&wallet, &new_coin_control).vsize` (line 289). That is the **new** tx's
projected max vsize. beamchain's mirror at `beamchain_rpc.erl:5750`
collapses to `OldFee + OldVSize * IncrSatVB`, which is the right shape
but the wrong size argument.

This is the **wallet-side companion** to BUG-1 (which is the mempool
side). Same root cause, different code path. Listed separately because
the wallet-side check is what surfaces the user-facing
"Insufficient total fee" error; BUG-1 is what makes the mempool reject
later.

### BUG-6 (MEDIUM) — No `EstimateFeeRate` default path (no caller fee_rate)

Core `wallet/feebumper.cpp:119-144` builds an estimated feerate by:
```cpp
CFeeRate feerate(old_fee, txSize); feerate += CFeeRate(1);
CFeeRate node_incremental_relay_fee = wallet.chain().relayIncrementalFee();
CFeeRate wallet_incremental_relay_fee = CFeeRate(WALLET_INCREMENTAL_RELAY_FEE);
feerate += std::max(node_incremental_relay_fee, wallet_incremental_relay_fee);
CFeeRate min_feerate(GetMinimumFeeRate(wallet, coin_control, /*feeCalc=*/nullptr));
return std::max(feerate, min_feerate);
```

beamchain `beamchain_rpc.erl:5752-5755` collapses the default path to
`MinNewFee = OldFee + OldVSize * IncrSatVB` (no fee estimator, no
`GetMinimumFeeRate` mempool-floor escalation, no `+ CFeeRate(1)` adjust
for the rounded old fee rate). When the original tx was already
deliberately mined at low feerate, the default bump just barely covers
the increment with no margin and is likely to be re-bumped within
minutes by a competing dRBF.

### BUG-7 (MEDIUM) — `WALLET_INCREMENTAL_RELAY_FEE` is `=5` sat/vB integer

Core `wallet/wallet.h` defines `WALLET_INCREMENTAL_RELAY_FEE = 5000` (in
sat/kvB; `CFeeRate(5000)` does ceiling arithmetic at sat/vB scale).

beamchain `beamchain_rpc.erl:5582`:
```erlang
-define(WALLET_INCREMENTAL_RELAY_FEE_SATVB, 5).
```
The integer collapse to sat/vB drops the ceiling-vs-floor distinction:
a 1234-vbyte tx requires `ceil(1234 * 5000 / 1000) = ceil(6170) = 6170`
sat additional fee under Core, but `1234 * 5 = 6170` sat under
beamchain. **In this specific case the answer matches by accident**
because 5000/1000 = 5 exactly. The divergence appears when someone
configures a non-multiple-of-1000 incremental relay fee (Core's CLI
`-incrementalrelayfee=` is in BTC/kvB; values like 0.00001234 →
1234 sat/kvB are legal). beamchain's
`incremental_relay_fee_constant/0` is hardcoded so the divergence
doesn't surface today, but the *shape* of the constant is wrong and
will break if/when the constant becomes configurable.

### BUG-8 (MEDIUM) — `CalculateMaximumSignedTxSize` not implemented

Core `wallet/spend.cpp` provides `CalculateMaximumSignedTxSize`
(called from `feebumper.cpp:289`) which projects the new tx's **maximum**
signed vsize over all possible signature shapes (taproot vs ECDSA,
high-S vs low-S, varying witness lengths). It uses
`SignatureWeightChecker` to upper-bound the per-input weight.

beamchain has no such helper. `rpc_bumpfee` reuses `OldVSize` as a
single-point estimate of "the new tx will be about this size". When
the original tx was signed with a low-S ECDSA signature (71-72 bytes)
and the bumped tx is re-signed with a 73-byte high-S sig (or vice
versa), the size estimate is off by ~1 byte per input. For a 50-input
tx, that's a 50-byte vsize variance, which at 30 sat/vB is
1500 sat — enough to flip the Rule 4 gate.

### BUG-9 (MEDIUM) — No `combined_bump_fee` integration

Core `wallet/feebumper.cpp:83-87`:
```cpp
const std::optional<CAmount> combined_bump_fee = wallet.chain().calculateCombinedBumpFee(reused_inputs, newFeerate);
if (!combined_bump_fee.has_value()) { ... reject ... }
CAmount new_total_fee = newFeerate.GetFee(maxTxSize) + combined_bump_fee.value();
```

`calculateCombinedBumpFee` is the wallet's mechanism for accounting for
**unconfirmed parents** when the bumped tx uses unconfirmed inputs.
beamchain has no such helper (no `combined_bump_fee` /
`calculateCombinedBumpFee` token in any wallet/RPC file). The
side-effect is documented but not fully understood: when bumping a tx
whose inputs come from unconfirmed parents, the bumped tx's effective
feerate is *lower* than the explicit feerate because part of the fee
also has to pay for the parent cluster's CPFP bump. beamchain bumps
the explicit feerate only, and the actual mempool admission will
silently fail Rule 4 because of the parent cluster's deficit. (W129
BUG-30 carry — re-listed here at wallet integration granularity.)

### BUG-10 (MEDIUM) — No `original_change_index` option

Core `wallet/feebumper.cpp:181-184`:
```cpp
if (original_change_index.has_value() && original_change_index.value() >= wtx.tx->vout.size()) {
    errors.emplace_back(... "Change position is out of range");
    return Result::INVALID_PARAMETER;
}
```

beamchain's `rpc_bumpfee` (`beamchain_rpc.erl:5585+`) does not accept an
`original_change_index` option. The change output is discovered by
walking outputs and checking against `listaddresses` for `change=true`
entries (`bumpfee_change_outputs/3` at line 5816). When the wallet's
HD-derivation path was changed between the original tx and the bumpfee
call (or the change addresses moved between wallets), the change
output is misidentified and the bumpfee succeeds with the **wrong
output** reduced, silently transferring satoshis from a recipient to
the operator. The fix needs a `change_position` integer option and
range-check before discovery.

### BUG-11 (MEDIUM) — No `outputs` array override

Core `wallet/feebumper.cpp:159-160, 251-263`:
```cpp
Result CreateRateBumpTransaction(... const std::vector<CTxOut>& outputs, std::optional<uint32_t> original_change_index)
...
const auto& txouts = outputs.empty() ? wtx.tx->vout : outputs;
```

The `outputs` array lets a caller replace the recipient set entirely
on bumpfee (e.g. to consolidate two recipients into one). beamchain
has no equivalent — `bumpfee_build_and_finalize/12` reuses
`OldTx#transaction.outputs` unconditionally. The user-facing impact:
a stuck tx cannot be re-targeted to a different recipient via bumpfee,
which is one of the documented Core bumpfee uses.

### BUG-12 (MEDIUM) — `PreconditionChecks.HasWalletSpend` missing

Core `wallet/feebumper.cpp:25-28`:
```cpp
if (wallet.HasWalletSpend(wtx.tx)) {
    errors.emplace_back(... "Transaction has descendants in the wallet");
    return feebumper::Result::INVALID_PARAMETER;
}
```

This is **wallet-internal** descendant tracking: it catches descendants
that the wallet has *created* but not yet broadcast (e.g. a chain of
unsigned dRBF candidates). beamchain only checks **mempool**
descendants (`get_descendants` at `beamchain_rpc.erl:5635`); it does
not walk the wallet's outgoing-tx table to find descendants that the
wallet knows about but the mempool doesn't (because they were never
broadcast or were dropped). A wallet that builds A → A' → A'' offline
and then asks to bumpfee A will succeed despite A' and A'' depending
on A's outputs.

### BUG-13 (MEDIUM) — `GetTxDepthInMainChain ≠ 0` precondition missing

Core `wallet/feebumper.cpp:37-40`:
```cpp
if (wallet.GetTxDepthInMainChain(wtx) != 0) {
    errors.emplace_back(... "Transaction has been mined, or is conflicted with a mined transaction");
    return feebumper::Result::WALLET_ERROR;
}
```

beamchain's `rpc_bumpfee` deduces "transaction is unconfirmed" from
"transaction is in mempool" (`get_entry/1` at line 5626 returns
`not_found` for confirmed txs because confirmed txs are removed from
the mempool). This is correct *if* the mempool's confirmed-removal
hook always fires before bumpfee runs, but during reorg windows the
mempool can be inconsistent: a tx that was briefly confirmed and then
reorganized out re-enters the mempool, but the wallet's
`GetTxDepthInMainChain` returns the (now-stale) positive depth.
beamchain has no wallet-side depth check, so the bumpfee would proceed
to re-sign and re-broadcast a tx that the chain ultimately re-confirms.

### BUG-14 (MEDIUM) — `replaced_by_txid` recursive-bump guard missing

Core `wallet/feebumper.cpp:42-45`:
```cpp
if (wtx.mapValue.contains("replaced_by_txid")) {
    errors.push_back(... "Cannot bump transaction ... which was already bumped by transaction ...");
    return feebumper::Result::WALLET_ERROR;
}
```

beamchain has no `replaced_by_txid` map-value tracking
(no `replaced_by` / `replaces_txid` token in any wallet/RPC file). A
user who bumps A → B and then calls `bumpfee A` again will start a
**new** bumpfee chain instead of being redirected to bump B (or
errored). Two separate bump chains then race for confirmation;
whichever wins, the user has signed two redundant transactions and
paid two redundant fees. This is the well-known accidental-double-pay
risk that Core explicitly guards against.

### BUG-15 (LOW) — `PreconditionChecks.AllInputsMine` is enforced by side-effect

Core `wallet/feebumper.cpp:47-54` explicitly walks `wtx.tx->vin` and
calls `AllInputsMine(wallet, *wtx.tx)` to fail-fast on external inputs.
beamchain's `rpc_bumpfee` doesn't have a dedicated check; it relies on
`lookup_privkeys_for_inputs/3` (line 5672) to throw
`{key_not_found, _, _}` if any input is unowned. The semantics are
identical *when the wallet's keystore is the source of truth*, but
Core's `AllInputsMine` walks `wallet.IsMine(prevout.scriptPubKey)`
which is **broader** than "wallet has the private key" (e.g. watch-only
scripts, external signer scripts). beamchain rejects watch-only inputs
even when bumpfee should accept-and-defer-to-external-signer.

### BUG-16 (LOW) — `findCoins` may miss prevout when chainstate AND mempool both lack it

Core `wallet/feebumper.cpp:191-208` calls `wallet.chain().findCoins(coins)`
which queries the union of chainstate + mempool *atomically* under
`cs_main`. beamchain's `bumpfee_lookup_input_utxos` does:
```erlang
case beamchain_chainstate:get_utxo(H, I) of
    {ok, Utxo} -> Utxo;
    not_found ->
        case beamchain_mempool:get_mempool_utxo(H, I) of
            {ok, Utxo} -> Utxo;
            not_found -> throw(... "Could not locate prevout UTXO ...")
        end
end
```
This is two sequential lookups with no shared lock, so a race window
exists where a parent tx is removed from the mempool (e.g. confirmed
in a block) **between** the chainstate and mempool queries: chainstate
miss (parent not yet flushed to UTXO) + mempool miss (parent moved out)
→ spurious "Could not locate prevout" error. Low impact because the
window is microseconds, but the failure mode is wrong (operator sees a
hard error when the right answer is "retry").

### BUG-17 (LOW) — `CommitTransaction.MarkReplaced` not invoked

Core `wallet/feebumper.cpp:370-379`:
```cpp
mapValue["replaces_txid"] = oldWtx.GetHash().ToString();
wallet.CommitTransaction(tx, std::move(mapValue), oldWtx.vOrderForm);
bumped_txid = tx->GetHash();
if (!wallet.MarkReplaced(oldWtx.GetHash(), bumped_txid)) {
    errors.emplace_back(... "Created new bumpfee transaction but could not mark the original transaction as replaced");
}
```

beamchain's `bumpfee_sign_and_submit` (line 5844-5869) submits the
new tx to the mempool but never updates the wallet's record of the
original. The wallet's `gettransaction OldTxid` will not reflect the
replacement, breaking any client that walks the wallet's transaction
history to find "the latest version" of a tx. (This is the wallet-side
half of BUG-14: BUG-14 prevents re-bumping the same original; BUG-17
prevents knowing the bump happened at all.)

### BUG-18 (LOW) — `WALLET_INCREMENTAL_RELAY_FEE` semantic divergence

When Core's `EstimateFeeRate` computes
`std::max(node_incremental_relay_fee, wallet_incremental_relay_fee)`,
the **wallet** value is meant as a *floor*: even if a future Core
release lowers the node's incremental relay fee, the wallet keeps
bumping by at least 5 sat/vB so the bump is future-proof against
network policy changes. beamchain's `rpc_bumpfee` computes
`max(?WALLET_INCREMENTAL_RELAY_FEE_SATVB=5, NodeIncrSatVB=1)` (so 5
wins), but the use of integer sat/vB and the absence of an
`EstimateFeeRate` helper means the value is only consulted on the
PaysForRBF-mirror gate; it is **not** used when the caller provided
`fee_rate=`. A caller who supplies `fee_rate=2` (sat/vB) bypasses the
wallet floor — Core would have rejected with "Insufficient total
fee", beamchain accepts.

### BUG-19 (LOW) — Comment-as-confession at `bumpfee_run` descendants check

`beamchain_rpc.erl:5637`:
```erlang
%% --- precondition 2: descendants in mempool? ---
case beamchain_mempool:get_descendants(Txid) of
    Descs when is_list(Descs) ->
        %% get_descendants includes self; require length =< 1.
        case [D || D <- Descs, D =/= Txid] of
            [] -> ok;
            ...
```

The comment claims `get_descendants` includes self. The actual
implementation (`beamchain_mempool.erl:2535-2541`) calls
`get_all_descendants(Txid)` which seeds with `[Txid]` but only
accumulates `Children` (line 2121), so **the seed is filtered out**.
The list comprehension `[D || D <- Descs, D =/= Txid]` is therefore
redundant — but harmless because the actual descendants set is what
we need. The bug is a **future-rot trap**: anyone refactoring
`get_descendants` to "fix" the (incorrect) comment by including self
will silently break the bumpfee precondition (every tx would suddenly
have at least one self-descendant and bumpfee would always reject).
Comment-as-confession pattern, sibling of W122 blockbrew BUG-1.

### BUG-20 (LOW) — `bumpfee_extract_entry` positional record destructure is rot-prone

`beamchain_rpc.erl:5694-5697`:
```erlang
case Entry of
    {mempool_entry, _Txid, _Wtxid, Tx, Fee, _Size, VSize, _Weight,
     _FeeRate, _TimeAdded, _HeightAdded, _AC, _AS, _AF, _DC, _DS, _DF,
     _SC, _RBF} ->
        {Tx, Fee, VSize};
```

The pattern destructures `mempool_entry` by position with 19 explicit
fields. If a future wave adds a 20th field (e.g. cluster_id, sigop
cache), this pattern silently mismatches and bumpfee falls through
the `_ -> throw(?RPC_MISC_ERROR, "Unexpected mempool_entry shape")`
branch. **No compile error**. The fix is to use record-field access
(`Entry#mempool_entry.tx`, `Entry#mempool_entry.fee`,
`Entry#mempool_entry.vsize`) which is field-name-driven and survives
field additions. Same pattern flagged in the **test-compile gate**
section of `.claude/CLAUDE.md` (rustoshi May 5 2026 wave 48c).

### BUG-21 (LOW) — `rpc_bumpfee` does not re-run coin selection

Carry-forward of W129 BUG-18 (and W129 G29 MISSING). Core's
`CreateRateBumpTransaction` line 314 calls `CreateTransaction` which
runs full `SelectCoins`. beamchain reuses the original input set and
shrinks the change output to absorb the fee delta. When the change
output goes below dust (line 5778-5786), beamchain rejects with
"Insufficient change to absorb fee delta"; Core would have run
`SelectCoins` to bring in additional UTXOs (`m_allow_other_inputs =
true`, line 309 in Core feebumper). Listed here at the **bumpfee
integration boundary** rather than under coin selection — same root
cause as W129 BUG-18, different audit framing.

### BUG-22 (LOW) — `rpc_bumpfee` is single-tx only; no package-RBF wallet path

Core's `validation.cpp::PackageRBFChecks` supports package-RBF
(replacing N → M unconfirmed txs atomically). beamchain has
`do_package_rbf/4` on the **mempool side** (entered when the package
contains txs that conflict with mempool entries) but `rpc_bumpfee`
calls `accept_to_memory_pool/1` (single-tx), not `accept_package/1`.
A wallet that wants to bump a tx **and** its dependent unsigned
follow-up atomically cannot do so via this RPC. This is W120 G18-20
catalogued from the mempool side and W118 BUG-2 closed for single-tx
bumpfee; the package-bumpfee wallet path is **net-new** gap.

---

## Non-bugs / things that are right

- `MAX_BIP125_RBF_SEQUENCE = 0xFFFFFFFD` constant value matches Core
  `util/rbf.h` (G1).
- `DEFAULT_INCREMENTAL_RELAY_FEE = 100` sat/kvB matches Core
  `policy/policy.h:48` (G2).
- `do_rbf` mempool-side Rule 3 enforcement
  (`NewFee >= EvictedFeeTotal`) matches `PaysForRBF` line 109
  (G4 mempool side).
- `lists:usort` on conflict-txids dedups properly (G24).
- The `_ -> throw(rbf_not_signaled)` path correctly skips when
  `mempool_full_rbf=true` (matches Core 28+ default-on semantics
  after `-mempoolfullrbf` was removed and replaced with the
  always-on Core 28 behavior). W120 G16 already documents this; W130
  records that the **wallet-side** path correctly defers to the
  mempool here (no wallet-side override of the fullRBF flag).

---

## Future-fix triage (priority order, not in scope for this wave)

| Order | Bug    | Rough scope                               |
|-------|--------|-------------------------------------------|
| 1     | BUG-1  | `rpc_bumpfee`: track `replacement_vsize`  |
| 2     | BUG-3  | wire `-maxtxfee` config token (+ check)   |
| 3     | BUG-2  | add `mempoolMinFee` precheck              |
| 4     | BUG-4  | mempool: add `GetUniqueClusterCount` helper, gate clusters not txs |
| 5     | BUG-14 | wallet: add `replaced_by_txid` map-value  |
| 6     | BUG-17 | wallet: `MarkReplaced(OldTxid, NewTxid)`  |
| 7     | BUG-10 | `original_change_index` option            |
| 8     | BUG-11 | `outputs` array override                  |
| 9     | BUG-21 | (W129 BUG-18) bumpfee → SelectCoins re-run |
| 10    | BUG-12 | wallet-descendants check                  |
| ...   |        |                                           |

---

Audit-flip convention: every gate test asserts a *divergent fact that
holds today*. Tests **pass now** and **fail when the fix lands**,
flipping the gate from MISSING/BUG to PRESENT.
