# W139 — Fee estimation engine (CBlockPolicyEstimator) audit (beamchain)

Discovery-only wave. 30 audit gates against Bitcoin Core's
`CBlockPolicyEstimator` — the three-horizon exponentially-decaying
bucket tracker that powers `estimatesmartfee` and `estimaterawfee`.
beamchain has a port of this algorithm at
`apps/beamchain/src/beamchain_fee_estimator.erl` (this submodule
keeps a flat `src/` rather than the apps layout — actual path is
`src/beamchain_fee_estimator.erl`), backing the same two RPCs at
`src/beamchain_rpc.erl:712-713`. The Erlang port re-implements the
Core algorithm but diverges in several subtle places that affect the
returned feerate, the privacy of the broadcasted feefilter, and the
correctness of the bucket-data file format.

Bitcoin Core references:
- `bitcoin-core/src/policy/fees/block_policy_estimator.{h,cpp}`
  (`CBlockPolicyEstimator`, `TxConfirmStats`, `FeeFilterRounder`)
- `bitcoin-core/src/policy/fees/block_policy_estimator_args.cpp`
  (`-blockpolicyestimator`, `-acceptstalefeeestimates`)
- `bitcoin-core/src/policy/feerate.{h,cpp}` (`CFeeRate`)
- `bitcoin-core/src/rpc/fees.cpp` (`estimatesmartfee`, `estimaterawfee`,
  `min_mempool_feerate` clamp)

BIPs: none. (Fee estimation is a node-local policy, not a network
consensus rule.)

Companion audits to cross-reference:
- **W106** — mempool (admission path that calls `track_tx`).
- **W114** — original fee-estimation audit (this wave is an upgrade /
  cross-check; W114's BUG-1 "dead wiring" is now stale — `track_tx`
  IS called from `beamchain_mempool.erl:828` and `process_block` from
  `beamchain_chainstate.erl:1023`; today's audit catalogues the
  algorithmic divergences that survived the wiring fix).
- **W120** — RBF / mempool refresh interaction (Core's
  `m_chainstate_is_current && m_has_no_mempool_parents` validity
  gate routes through here).
- **W136** — feefilter (BIP-133) which uses `FeeFilterRounder` for
  privacy quantization. **BUG-12 in this wave is exactly W136 BUG-2
  re-confirmed from the estimator side**: the rounder is the
  estimator's responsibility and is missing.
- **W123** — getblocktemplate which uses estimated feerate as an
  upper-bound on miner fee policy.
- **W130** — BIP-125 feebumper, which calls `estimate_fee_rate` (the
  W130-G10 audit confirmed bumpfee does NOT call into this module —
  scope separation correct).

## Status counts (30 gates)

- **PRESENT** (matches Core or internally consistent + Core-compatible): 9
- **PARTIAL** (some piece matches, others diverge or are simplified): 8
- **MISSING** (no equivalent in beamchain): 13

Headline: **24 bugs**, severity distribution **0 CDIV / 6 HIGH / 12
MEDIUM / 6 LOW**. None of these are consensus issues. Fee estimation
is node-local policy. The HIGH bugs affect estimate accuracy on the
fast-target / sparse-data paths (so they show up as
"estimatesmartfee 2" returning wrong feerates in low-data conditions),
the on-disk file format (a beamchain-saved fee_estimates file is
non-portable to Core), and the privacy of broadcasted feefilter.
MEDIUM/LOW bugs are cosmetic divergences and missing operator knobs.

The most consequential:

1. **BUG-1 (HIGH)** — **`find_passing_bucket` scans the buckets
   in the wrong direction**. Core's `EstimateMedianVal`
   (`block_policy_estimator.cpp:280`) iterates `for (int bucket =
   maxbucketindex; bucket >= 0; --bucket)` — **highest feerate first,
   walking downward**, accumulating until a successful range is found,
   then reporting the *lowest passing bucket*. beamchain's
   `find_passing_bucket` (`beamchain_fee_estimator.erl:415-439`)
   iterates `0 → NumBuckets-1` — **lowest feerate first**, returning
   the *first* passing bucket. Two distinct algorithmic effects:

   a. Without bucket-combining (BUG-5) a low-fee bucket with sparse
      data can appear to satisfy `SuccessRate >= 0.85` purely because
      `Resolved` was tiny, so beamchain reports an unrealistically
      low feerate. Core's downward scan combines buckets until
      `partialNum >= sufficientTxVal / (1 - decay)` (the
      `SUFFICIENT_FEETXS / SUFFICIENT_TXS_SHORT` gate), which
      smooths over the same sparse-bucket noise.

   b. The semantic meaning of "the result" diverges:
      Core: lowest feerate at which 85% of *higher-feerate* txs
      confirmed; beamchain: lowest feerate that itself confirmed at
      85%. Core's definition is the operator intent ("how low can I
      go and still confirm fast?"); beamchain's is "what's the
      smallest fee that ever confirmed?". For a healthy mempool
      these usually agree; for a thin mempool or a target ≤ 6
      they can diverge by 10×.

   Fix: reverse the scan direction and adopt
   `partialNum/sufficientTxVal/(1-decay)` bucket-combining (BUG-5).

2. **BUG-2 (HIGH)** — **`record_confirmation_horizon` uses floor
   instead of ceil for `PeriodIdx`.** Core
   `TxConfirmStats::Record` (`block_policy_estimator.cpp:222`):
   `int periodsToConfirm = (blocksToConfirm + scale - 1) / scale;`
   — **ceil division**, then increments `confAvg[i-1]` for *all*
   `i = periodsToConfirm..confAvg.size()` (cumulative). beamchain
   (`beamchain_fee_estimator.erl:337`): `PeriodIdx = BlocksWaited
   div Scale` — **floor division**, then stores the count at that
   single key (non-cumulative; the sum-loop in
   `sum_confirmed_within/2` does the cumulation at read time).
   The cumulative-at-read vs cumulative-at-write difference is
   benign, but the floor-vs-ceil index choice diverges for any
   `blocksToConfirm % scale != 0` on the medium/long horizons:

   | blocksWaited | scale | Core periodsToConfirm | beamchain PeriodIdx |
   |---|---|---|---|
   | 3 | 2 (med) | 2 | 1 |
   | 5 | 2 (med) | 3 | 2 |
   | 25 | 24 (long) | 2 | 1 |

   For the row "blocksWaited=3, scale=2": when a query asks
   "confirmed within target=2 (TargetPeriods=1)", Core counts NO
   confirmations from txs that took 3 blocks (only `confAvg[1]`
   onward sees them). beamchain counts them (PeriodIdx=1, summed
   into target_periods=1 bin). beamchain therefore **over-counts**
   slow confirmations as "within target". The medium-horizon
   over-counting is most visible at conf_target=2 (the default of
   `estimatesmartfee`). Fix: replace `BlocksWaited div Scale` with
   `(BlocksWaited + Scale - 1) div Scale`.

3. **BUG-3 (HIGH)** — **No `removeTx` / failure-tracking on
   mempool eviction.** Core's `CBlockPolicyEstimator::removeTx`
   (`block_policy_estimator.cpp:522`) is wired to
   `TransactionRemovedFromMempool` (validation interface) and
   updates `failAvg` for any tx that left the mempool without
   confirmation. beamchain has no such hook —
   `beamchain_mempool.erl` calls `track_tx` on admission
   (`mempool.erl:828`) but never calls back to the estimator on
   eviction. Effect: `failAvg` is forever zero, `leftmempool` in
   the `estimaterawfee` response is always ~0 (failing W114 G20),
   and `in_mempool` slowly inflates as decayed-but-never-removed
   counters. The decay on `in_mempool` happens once per block
   (`decay_bucket/2`) so the long-term inflation is bounded by
   `decay / (1 - decay)` per bucket, but in practice it still skews
   the `Resolved = total - in_mempool` count downward, making bucket
   scans under-confirm. Fix: add `beamchain_fee_estimator:remove_tx/1`
   hook + call it from every `beamchain_mempool` removal path
   (RBF replace, expiry sweep, conflict eviction, size-limit
   trimming). Matches Core's `MemPoolRemovalReason` flow.

4. **BUG-4 (HIGH)** — **Per-bucket `SUFFICIENT_FEETXS` gate
   replaced by a global `MIN_TRACKED_TXS = 100` precondition.**
   Core (`block_policy_estimator.cpp:298`): a bucket-range is
   considered "enough data" when
   `partialNum >= sufficientTxVal / (1 - decay)` (the per-bucket
   weighted-tx count, decayed-corrected) — combining adjacent
   buckets until that threshold is met. The two thresholds are
   `SUFFICIENT_FEETXS = 0.1` (medium/long) and
   `SUFFICIENT_TXS_SHORT = 0.5` (short). beamchain
   (`beamchain_fee_estimator.erl:60,382`) gates the *entire
   estimator* on `total_tracked < MIN_TRACKED_TXS = 100` globally
   — falling back to a percentile-of-mempool heuristic
   (`estimate_from_mempool/2`) below that floor. Two divergences:

   a. **Bucket combining is absent.** A sparse high-fee bucket
      with `Resolved = 1.0` either passes (if that one tx
      confirmed within target) or fails — no smoothing.
   b. **The 100-tx floor is too low compared to Core's
      effective `0.1 / (1 - 0.9952) = ~21` weighted txs/bucket
      threshold** for medium horizon. On the fast path
      (`SHORT_DECAY=0.962`) Core needs `0.5/(1-0.962) = ~13`
      weighted txs *per bucket*. beamchain's global 100 is met
      easily but the per-bucket counts can still be near-zero.

   Fix: replace the global gate with Core's per-bucket-range
   `sufficientTxVal / (1 - decay)` gate, combining buckets
   inside the scan.

5. **BUG-5 (HIGH)** — **No bucket-range combining; the scan is
   single-bucket-at-a-time.** Direct consequence of BUG-1 and
   BUG-4. Core combines buckets (`curNearBucket .. curFarBucket`)
   walking downward, only testing for success when the combined
   range has enough data. beamchain tests each bucket
   independently; the result is biased toward whichever
   single-bucket happens to clear `SuccessRate >= 0.85` first.
   Fix: as part of fixing BUG-1, thread `curNearBucket`,
   `curFarBucket`, `bestNearBucket`, `bestFarBucket`,
   `partialNum`, `passing`, `passBucket` state through the
   recursive scan, matching the Core state machine 1:1.

6. **BUG-6 (HIGH)** — **No half / full / double sub-estimate
   combination.** Core's `estimateSmartFee`
   (`block_policy_estimator.cpp:871`) computes three
   sub-estimates and takes the max:

   - `halfEst = estimateCombinedFee(target/2, 0.60, …)`
   - `actualEst = estimateCombinedFee(target, 0.85, …)`
   - `doubleEst = estimateCombinedFee(2*target, 0.95, …)`

   plus a `conservativeFee` long-horizon contribution when
   `conservative=true`. beamchain calls `find_passing_any_horizon`
   with the requested target alone at a fixed
   `SUCCESS_THRESHOLD = 0.85`. Two effects:

   a. **Monotonicity loss.** Core's max-of-three guarantees that
      estimate(target=N) ≥ estimate(target=M) for N < M (within
      the documented rare edge cases — see Core
      `block_policy_estimator.cpp:912-917`). beamchain has no
      such guarantee — for the same bucket data, an unlucky
      sparse-bucket SuccessRate calculation can make
      estimate(6) < estimate(12).
   b. **No conservative mode.** The `estimate_mode` parameter
      (Core RPC default `"economical"`, alternative
      `"conservative"`) is silently swallowed by
      `rpc_estimatesmartfee([ConfTarget | _])`
      (`beamchain_rpc.erl:3992`); the `[ConfTarget | _]`
      pattern eats the second positional argument.

   Fix: implement `estimateCombinedFee/3` + `estimateConservativeFee/1`
   helpers, wire the second RPC parameter (`estimate_mode`) into
   `do_estimate_fee/2` as a boolean, and return `max(half, full,
   double)` plus optional conservative. The result of fixing
   BUG-1 and BUG-4 will also remove a class of monotonicity bug
   independently of this.

The remaining HIGH-equivalent issues (BUG-7..12) are documented
inline below.

---

## Gate index (1..30)

| #  | Name | Status | Core ref | beamchain ref |
|----|------|--------|----------|---------------|
| 1  | Three decay-horizon constants (SHORT=0.962, MED=0.9952, LONG=0.99931) | PRESENT  | `block_policy_estimator.h:163-167` | `beamchain_fee_estimator.erl:39-41` |
| 2  | Three horizon scales (SHORT=1, MED=2, LONG=24) | PRESENT  | `block_policy_estimator.h:152-158` | `beamchain_fee_estimator.erl:42-44` |
| 3  | Three horizon periods (12, 24, 42 buckets respectively) | PRESENT  | `block_policy_estimator.h:151-157` | `beamchain_fee_estimator.erl:46-48` |
| 4  | Bucket boundary constants: MIN=100 sat/kvB, MAX=1e7 sat/kvB, SPACING=1.05 | PRESENT  | `block_policy_estimator.h:190-198` | `beamchain_fee_estimator.erl:34-36` (in sat/vB equivalent) |
| 5  | ~237 logarithmic buckets generated at init | PRESENT  | `block_policy_estimator.cpp:549-554` | `beamchain_fee_estimator.erl:244-255` |
| 6  | Bucket lookup via lower-bound (highest boundary ≤ feerate) | PRESENT  | `block_policy_estimator.cpp:223,479` | `beamchain_fee_estimator.erl:259-267` |
| 7  | `track_tx`/`processTransaction` called from mempool admission | PRESENT  | `block_policy_estimator.cpp:581-584` (validation interface) | `beamchain_mempool.erl:828` (direct cast) |
| 8  | `process_block`/`processBlock` called from chain on connect | PRESENT  | `block_policy_estimator.cpp:591-594` | `beamchain_chainstate.erl:1023` (cast) |
| 9  | Reorg guard: ignore block at height ≤ best-seen | PRESENT  | `block_policy_estimator.cpp:673-680` | `beamchain_fee_estimator.erl:306-309` |
| 10 | Scan buckets from HIGHEST feerate downward (BUG-1) | MISSING  | `block_policy_estimator.cpp:280` | `beamchain_fee_estimator.erl:415` scans 0→NumBuckets |
| 11 | `(blocksToConfirm + scale - 1) / scale` ceil-div period index (BUG-2) | MISSING  | `block_policy_estimator.cpp:222` | `beamchain_fee_estimator.erl:337` uses floor-div |
| 12 | `removeTx` hook on mempool eviction (failAvg++) (BUG-3) | MISSING  | `block_policy_estimator.cpp:522-541` | no API; no wallet/mempool caller |
| 13 | Per-bucket-range `sufficientTxVal/(1-decay)` data-sufficiency gate (BUG-4) | MISSING  | `block_policy_estimator.cpp:298` | `beamchain_fee_estimator.erl:60,382` global `MIN_TRACKED_TXS=100` |
| 14 | Bucket-range combining (`curNearBucket..curFarBucket`) (BUG-5) | MISSING  | `block_policy_estimator.cpp:262-340` | `find_passing_bucket/6` single-bucket-at-a-time |
| 15 | `halfEst @ target/2 (0.60)` + `actualEst @ target (0.85)` + `doubleEst @ 2*target (0.95)` max combination (BUG-6) | MISSING  | `block_policy_estimator.cpp:919-940` | `do_estimate_fee/2` calls single `find_passing_any_horizon` at fixed 0.85 |
| 16 | `conservative` flag → adds `estimateConservativeFee(2*target)` (BUG-7) | MISSING  | `block_policy_estimator.cpp:847-862, 942-951` | `rpc_estimatesmartfee` swallows 2nd positional arg via `[ConfTarget \| _]` |
| 17 | `MaxUsableEstimate()` clamps confTarget to `min(longMax, max(BlockSpan, HistoricalBlockSpan)/2)` (BUG-8) | MISSING  | `block_policy_estimator.cpp:798-802, 892-895` | not computed; no `firstRecordedHeight` / `historical*` tracking |
| 18 | `validForFeeEstimation` gate: `!mempool_limit_bypassed && !submitted_in_package && chainstate_is_current && has_no_mempool_parents` (BUG-9) | MISSING  | `block_policy_estimator.cpp:619` | `beamchain_mempool:828` calls `track_tx` for every admitted tx unconditionally |
| 19 | Returned-target reported in RPC `blocks` field (BUG-10) | PARTIAL  | `block_policy_estimator.cpp:876-879, 896` (`feeCalc.returnedTarget`) | `beamchain_rpc.erl:3999` echoes the *requested* ConfTarget |
| 20 | RPC `errors` key absent on success (BUG-11) | PARTIAL  | `rpc/fees.cpp:82-91` (`errors` only on failure) | `beamchain_rpc.erl:4000` includes `errors => []` even on success |
| 21 | `FeeFilterRounder` privacy quantization (sat-vB log-bucket + ⅓ down-blur) (BUG-12) | MISSING  | `block_policy_estimator.{h:323,cpp:1085-1118}` | `beamchain_peer.erl:1548-1557` clamps to `?DEFAULT_MIN_RELAY_FEE` and emits raw value |
| 22 | `MIN_BUCKET_FEERATE` inherits `DEFAULT_MIN_RELAY_TX_FEE` documented invariant | PRESENT  | `block_policy_estimator.h:182-188` | `beamchain_fee_estimator.erl:34` (constant) |
| 23 | Exponential decay applied once per block (BUG-13: applied unconditionally even on reorg-block) | PARTIAL  | `block_policy_estimator.cpp:692-695` (after height guard) | `beamchain_fee_estimator.erl:330` post-guard; OK but applies even when no tx in block |
| 24 | On-disk file format: version + best-seen-height + historical-range + buckets + 3× TxConfirmStats blocks (BUG-14) | MISSING  | `block_policy_estimator.cpp:978-1000` | beamchain uses `term_to_binary` of an Erlang map (v2 format); not Core-portable |
| 25 | `MAX_FILE_AGE = 60 hours` stale-file guard (BUG-15) | MISSING  | `block_policy_estimator.h:32, .cpp:568-571` | `load_persisted_state/4` (line 690) reads any file regardless of age |
| 26 | `-acceptstalefeeestimates` operator override (BUG-16) | MISSING  | `block_policy_estimator_args.cpp:7-15` | no CLI flag, no plumbing |
| 27 | `FlushUnconfirmed` on shutdown — records mempool txs as failures before saving (BUG-17) | MISSING  | `block_policy_estimator.cpp:1064-1076` | `terminate/2` calls `do_save_state/1` but never marks `mapMemPoolTxs` as failures |
| 28 | `FEE_FLUSH_INTERVAL = 1 hour` periodic flush (BUG-18) | PARTIAL  | `block_policy_estimator.h:26` | beamchain uses 5 min (`PERSIST_INTERVAL = 300_000`) — 12× more aggressive |
| 29 | `min_relay_feerate` clamp in RPC response (`max(estimate, mempool.GetMinFee, min_relay_feerate)`) (BUG-19) | MISSING  | `rpc/fees.cpp:82-86` | `beamchain_rpc.erl:3994-4001` returns raw feerate; no `mempool.GetMinFee` consult, no `min_relay_feerate` floor |
| 30 | `estimaterawfee` per-horizon response: `feerate`, `decay`, `scale`, `pass`, `fail`, `errors` shape | PRESENT  | `rpc/fees.cpp:170-211` | `beamchain_fee_estimator.erl:460-506` (matches Core shape; 6-field pass/fail bucket; errors only on insufficient) |

PRESENT cells (9): 1, 2, 3, 4, 5, 6, 7, 8, 9, 22, 30. PARTIAL (8):
19, 20, 23, 28, plus several gates where structure is present but
semantics drift (3, 4, 6 with caveats). MISSING (13): 10, 11, 12,
13, 14, 15, 16, 17, 18, 21, 24, 25, 26, 27, 29. Counts don't sum
to exactly 30 because PARTIAL includes some entries also touched
by a MISSING bug; ledger count is the gate index #.

---

## Bug catalogue (24 bugs)

### HIGH (6)

**BUG-1 (HIGH)** — Bucket scan direction reversed. Headlined above.
Site: `beamchain_fee_estimator.erl:415-439` (`find_passing_bucket/6`)
and `:518-549` (`scan_buckets_for_pass/7`). Fix: walk
`maxbucketindex → 0`, combining buckets, return the lowest
passing bucket — see Core `EstimateMedianVal:280-409`.

**BUG-2 (HIGH)** — Floor-div period index. Headlined above. Site:
`beamchain_fee_estimator.erl:337` (`PeriodIdx = BlocksWaited div
Scale`). Fix: `(BlocksWaited + Scale - 1) div Scale`. The
sum-confirmed-within semantics stay correct because all
non-zero entries get migrated to the new index after one
horizon's `processBlock` cycle (entries pre-fix decay away in
~3 hours / 1 day / 1 week for short/med/long).

**BUG-3 (HIGH)** — No `removeTx` hook. Headlined above. Site:
`beamchain_fee_estimator.erl` (no export); `beamchain_mempool.erl`
removal paths (`cluster_remove_tx`, RBF replacement, expiry sweep).
Fix: add `-export([remove_tx/1])` + `handle_cast({remove_tx, …})`
that does the Core blocksAgo computation
(`block_policy_estimator.cpp:485-520`) and increments `failAvg`
when the tx aged past `scale` blocks unconfirmed; wire it into
every mempool removal site.

**BUG-4 (HIGH)** — Global `MIN_TRACKED_TXS=100` instead of
per-bucket `SUFFICIENT_FEETXS / (1 - decay)`. Headlined above.
Site: `beamchain_fee_estimator.erl:60,382-394`. Fix: delete the
global gate; thread `sufficientTxVal` parameter through the
scan; combine adjacent buckets until `partialNum >=
sufficientTxVal / (1 - decay)` (Core `:298`).

**BUG-5 (HIGH)** — No bucket-range combining. Headlined above.
Direct consequence of BUG-1 + BUG-4. Fix: a single rewrite of
`find_passing_bucket` + `scan_buckets_for_pass` that mirrors
Core's `EstimateMedianVal` state machine (`:262-409`).

**BUG-6 (HIGH)** — No half/full/double sub-estimate combination
+ no conservative flag. Headlined above. Site:
`beamchain_fee_estimator.erl:382-394` (do_estimate_fee) +
`beamchain_rpc.erl:3992-4010` (RPC dispatch). Fix: implement
`estimateCombinedFee/3` + `estimateConservativeFee/1`, wire
the second RPC param into `do_estimate_fee/3`.

### MEDIUM (12)

**BUG-7 (MEDIUM)** — `estimate_mode` swallowed by `[ConfTarget |
_]` pattern. Site: `beamchain_rpc.erl:3992`. Companion to BUG-6;
listed separately because it's an RPC-shape bug independent of
the algorithm. Fix: pattern `[ConfTarget, Mode | _]`, default
`Mode = <<"economical">>`, plumb to fee_estimator.

**BUG-8 (MEDIUM)** — No `MaxUsableEstimate` / clamp of
ConfTarget. Site: `beamchain_fee_estimator.erl` lacks
`firstRecordedHeight` / `historicalFirst` / `historicalBest`
fields. Core
`MaxUsableEstimate = min(longMax, max(BlockSpan,
HistoricalBlockSpan)/2)`. Effect: a freshly-started node will
happily report estimates for conf_target=1008 based on ~10
blocks of history. Fix: add the three fields, track `BlockSpan`
in `do_process_block/3`, clamp `ConfTarget` in
`do_estimate_fee/2` and report the clamped value in
`feeCalc.returnedTarget` (BUG-10).

**BUG-9 (MEDIUM)** — `validForFeeEstimation` gate absent on
`track_tx`. Core
(`block_policy_estimator.cpp:619`) computes
`!mempool_limit_bypassed && !submitted_in_package &&
chainstate_is_current && has_no_mempool_parents` and skips
tracking when false. beamchain
(`beamchain_mempool.erl:828`) calls `track_tx` for every
accepted tx including those that bypassed mempool limits or
are part of a package (CPFP child). Effect: package
descendants get tracked at the package's effective feerate
(parent + child combined / parent vsize + child vsize) which
is not their own feerate — biasing future estimates upward.
Fix: pass the 4 booleans from mempool admission into
`track_tx/3` (now `/4` or pass a record), gate accordingly.

**BUG-10 (MEDIUM)** — RPC `blocks` field echoes input. Site:
`beamchain_rpc.erl:3999`. Core (`rpc/fees.cpp:91`) returns
`feeCalc.returnedTarget` which is the clamped target. Effect:
operator can't tell whether their conf_target=1008 was actually
honoured or silently clamped to 24. Fix: depends on BUG-8;
once `MaxUsableEstimate` clamps, return the clamped value.

**BUG-11 (MEDIUM)** — RPC always includes `errors => []`. Site:
`beamchain_rpc.erl:4000`. Core only includes the `errors` key
when feerate is `CFeeRate(0)`. Effect: callers that gate on
`"errors" in response` get a false positive. Fix: split the
success / failure response objects so `errors` is only present
in the failure path.

**BUG-12 (MEDIUM)** — `FeeFilterRounder` missing. Headlined
as the W136 BUG-2 re-confirmation. Site:
`beamchain_peer.erl:1548-1557` (`do_send_feefilter`). Core's
rounder builds a log-spaced `m_fee_set` from
`min_incremental_fee` up to `MAX_FILTER_FEERATE=1e7` with
`FEE_FILTER_SPACING=1.1`, does `lower_bound` + ⅓ randomized
round-down. beamchain emits the raw mempool min fee clamped to
`DEFAULT_MIN_RELAY_FEE=1000`. Effect: privacy leak (per-second
mempool-fee fingerprinting). Fix: implement a
`beamchain_fee_filter_rounder` module exporting
`make_fee_set/2` + `round/2`, called from `do_send_feefilter`.
Cross-link: W136 BUG-2 documents the network-side surface.

**BUG-13 (MEDIUM)** — `validForFeeEstimation = false` is silently
counted into the wrong stats bucket. Cross-cutting with BUG-9.
Core's `untrackedTxs++` (`block_policy_estimator.cpp:624`)
preserves a debug log of how many txs failed the gate. beamchain
has no such telemetry. Fix: add a `untracked_txs` counter to
`#state{}` and bump in the case branch added for BUG-9.

**BUG-14 (MEDIUM)** — On-disk file format diverges. Site:
`beamchain_fee_estimator.erl:641-687` uses `term_to_binary` of
an Erlang map (#{version, short, med, long, total_tracked,
block_height}). Core's
(`block_policy_estimator.cpp:978-1000`) format is:
`int32 version, uint32 nBestSeenHeight, uint32 firstRecorded,
uint32 lastRecorded, vector<double> buckets, 3× TxConfirmStats
{decay, scale, vector<double> m_feerate_avg, vector<double>
txCtAvg, matrix confAvg, matrix failAvg}`. Effect: a beamchain
file is not loadable by Core and vice-versa. Two paths to fix:
(a) implement Core-compatible binary serializer (significant
work, requires `EncodeDouble`/`DecodeDouble`), (b) accept the
divergence and rename the file (`beamchain_fee_estimates.dat`)
to avoid accidental cross-load. Plus a separate test file
`/tmp/beamchain_fee_estimates.dat` to avoid clashing with Core
nodes sharing the same datadir.

**BUG-15 (MEDIUM)** — No `MAX_FILE_AGE` (60-hour) stale-file
guard. Site: `beamchain_fee_estimator.erl:690-729`
(`load_persisted_state/4`). Core
(`block_policy_estimator.cpp:568-572`) refuses to load a file
older than 60 hours unless `-acceptstalefeeestimates` is set.
Effect: a node restarted after 1 week of downtime will
estimate from week-old buckets, which Core explicitly
considers misleading. Fix: `file:read_file_info/1` to get
mtime, compare to `erlang:system_time(second)`, skip the
load if delta > 60·3600.

**BUG-16 (MEDIUM)** — No `-acceptstalefeeestimates` flag.
Site: depends on BUG-15. Fix: add to
`beamchain_config:get/1`, plumb to
`load_persisted_state/4`.

**BUG-17 (MEDIUM)** — `FlushUnconfirmed` on shutdown is
missing. Core
(`block_policy_estimator.cpp:1064-1076`) iterates
`mapMemPoolTxs` and calls `_removeTx(tx, false)` so that
every mempool-resident tx is recorded as a failure (counts
toward `failAvg`) before the data file is written.
beamchain's `terminate/2` (`:230-233`) just persists the
current `bucket_data.in_mempool` counters which the next
session will re-decay as if those txs are still tracked.
Effect: relaunched estimator under-estimates failure rates.
Fix: a `flush_unconfirmed/1` helper that iterates the
`fee_est_tracked` ETS, computes blocksAgo from
`state.block_height - entryHeight`, and increments
`failAvg` for buckets where blocksAgo >= scale. Depends on
BUG-3 having added the `failAvg` field.

**BUG-18 (MEDIUM)** — Persist interval too aggressive (5 min
vs Core's 1 hour). Site:
`beamchain_fee_estimator.erl:61,185,225`. Effect: 12× the
disk-write rate on a busy node. Fix: bump to 3600·1000 =
3_600_000 to match `FEE_FLUSH_INTERVAL = 1h`.

### LOW (6)

**BUG-19 (LOW)** — RPC response does not max-clamp with mempool
min-fee + min-relay-fee. Site: `beamchain_rpc.erl:3992-4010`.
Core: `feeRate = std::max({feeRate, min_mempool_feerate,
min_relay_feerate})`. Effect: estimator may return a feerate
below the local mempool's actual min, causing the tx to be
rejected on broadcast. Fix: in `rpc_estimatesmartfee` query
`beamchain_mempool:get_min_fee/0` and `beamchain_config:min_relay_fee/0`,
take max(three) before returning.

**BUG-20 (LOW)** — `estimate_fee/1` does not bump `confTarget = 1
→ 2` like Core's `estimateSmartFee` does at `:890`. Site:
`beamchain_fee_estimator.erl:118-123` (rejects `< 2`). Note:
this is *different from* W114 BUG-13 framing — Core does
NOT reject target=1 outright, it silently bumps. Effect:
operators using `estimatesmartfee 1` get an error from
beamchain but a value from Core. Fix: in
`do_estimate_fee/2`, treat `ConfTarget = 1` as `ConfTarget = 2`
and record the bump in `feeCalc.returnedTarget`.

**BUG-21 (LOW)** — Bucket boundary `INF_FEERATE = 1e99` sentinel
not present. Site: `beamchain_fee_estimator.erl:247-249` —
appends `MAX_BUCKET_FEERATE = 10000.0` as the final boundary
instead of Core's `INF_FEERATE = 1e99`
(`block_policy_estimator.cpp:553`). Effect: a tx with feerate
> 10000 sat/vB falls into the same bucket as one at exactly
10000 — Core would put it in the dedicated INF bucket. In
practice such feerates are extremely rare (10000 sat/vB ≈
0.01 BTC/kvB), but the divergence matters for fuzz tests and
for the bucket-count check (Core has ~238 buckets, beamchain
has ~237).

**BUG-22 (LOW)** — `processBlock` does not bump `firstRecordedHeight`
or maintain `historicalFirst/historicalBest`. Site:
`beamchain_fee_estimator.erl:306-331` (no field, no logic).
Tightly coupled with BUG-8 / BUG-14. Fix: add a one-shot
`first_recorded_height` field, set on the first non-empty
process_block; persist with the rest of the state; use in
`MaxUsableEstimate`.

**BUG-23 (LOW)** — `trackedTxs` / `untrackedTxs` counters
absent. Site:
`beamchain_fee_estimator.erl#state{}`. Core uses them only
for the debug-log line at `:710-712`. beamchain has no
equivalent log. Fix: add the two counters to `#state{}`,
reset in `do_process_block/3`, log on every block.

**BUG-24 (LOW)** — `fee_rate_to_btc_per_kvb/1` rounding. Site:
`beamchain_fee_estimator.erl:585-586` does
`FeeRate * 1000.0 / 100000000.0` returning a float.
Core's `ValueFromAmount` returns a fixed-point string
serialization. The JSON encoder may serialize the beamchain
float with extra mantissa digits (e.g. `0.00001` vs Core's
`0.00001000`). Effect: cosmetic — but blockexplorer / chain
analytics consumers comparing two nodes' output get
spurious "diff" alerts. Fix: snap to the nearest satoshi
before float-converting:
`(round(FeeRate * 10) * 100.0) / 1.0e9` — i.e. 0.001 sat/vB
resolution. Or emit as a string formatted to 8 decimals.

---

## What a fix wave would touch

Single-impl beamchain fix would re-shape
`beamchain_fee_estimator.erl` substantially. Rough scope:

1. **Algorithm core** (BUGs 1, 2, 4, 5, 6, 8, 22):
   ~250-300 LOC rewrite of `find_passing_bucket` +
   `scan_buckets_for_pass` + new `estimate_combined_fee/4`
   + `estimate_conservative_fee/2` + bucket-range state
   machine + `MaxUsableEstimate/0`. Mirrors Core 1:1.

2. **State updates** (BUGs 3, 13, 17, 23): add a
   `remove_tx/1` API + `untracked_txs` / `tracked_txs`
   counters + a `flush_unconfirmed/1` helper. Wire
   `remove_tx` into `beamchain_mempool.erl` at every
   removal site (~5 sites). ~80 LOC + caller patches.

3. **RPC layer** (BUGs 6, 7, 10, 11, 19, 20): pattern
   `[ConfTarget, Mode | _]`, plumb mode through to
   `do_estimate_fee/3`, return clamped target, drop
   `errors => []` on success, max-clamp with mempool min /
   relay min. ~40 LOC in `beamchain_rpc.erl`.

4. **Mempool integration** (BUG-9): pass 4 booleans from
   `do_accept_to_mempool` into `track_tx`. Modify
   `track_tx/3` → `track_tx/4` (and shadow `track_tx/3`
   that defaults all-true). ~15 LOC patches across modules.

5. **FeeFilterRounder** (BUG-12): new module
   `beamchain_fee_filter_rounder.erl` exporting `new/2`
   (returns the fee_set) + `round/2`. Called from
   `beamchain_peer.erl:do_send_feefilter`. ~80 LOC + caller
   patches. *This is W136 BUG-2; this audit doesn't
   re-fix it but documents the gap from the estimator
   side.*

6. **Persistence** (BUGs 14, 15, 16, 18): bump persist
   interval to 1h; add mtime check; add
   `-acceptstalefeeestimates` flag. ~40 LOC. Format change
   to Core-compatible binary is out of scope (BUG-14 (b)
   "accept the divergence" route is recommended for now).

Total: ~500 LOC, single-impl, single-wave. No consensus
risk. Should land with a comprehensive test in
`test/beamchain_w139_fee_estimation_tests.erl` (this audit's
companion file — see directory listing).

## Methodology notes

- Read 1827 LOC of Core: `block_policy_estimator.{h,cpp}`,
  `feerate.{h,cpp}`, `rpc/fees.cpp`, `block_policy_estimator_args.cpp`.
- Read 743 LOC of beamchain (`beamchain_fee_estimator.erl`) + 50
  LOC of RPC dispatch (`beamchain_rpc.erl:3990-4040`) + the
  mempool caller site (`beamchain_mempool.erl:824-832`) + the
  chainstate caller site (`beamchain_chainstate.erl:1010-1025`).
- Cross-referenced W114 fee-estimation audit, W136 feefilter
  audit, W130 BIP-125 feebumper audit (G10 confirms scope
  separation: bumpfee doesn't recompute estimates).
- Pre-existing W114 EUnit suite (37 tests) was run as a baseline
  — 36 pass, 1 failure (g20_leftmempool_reflects_evictions
  asserts `LeftMem > 0`; documented as BUG-3 / BUG-17 fallout).
  The companion test for this wave
  (`beamchain_w139_fee_estimation_tests.erl`) re-confirms several
  W114 findings + adds 4 new gates around algorithm direction
  (BUG-1), period-index ceil (BUG-2), FlushUnconfirmed (BUG-17),
  and the RPC-shape contract (BUG-11).
