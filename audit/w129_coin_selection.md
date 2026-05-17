# W129 — Coin selection deep-dive audit (beamchain)

Discovery-only wave. 30 audit gates focused on the four selection algorithms
(BnB / Knapsack / SRD / CG), their inputs (effective_value, long-term
feerate, cost-of-change, min_viable_change, change_target generation), and
the multi-algorithm orchestration (run all → pick lowest waste).

W113 already audited the surface ("does beamchain have a knapsack? a BnB?")
and catalogued 12 bugs around algorithm presence and OutputGroup. **W129
goes a level deeper**, gating the *specific Core invariants* inside each
algorithm: Murch's bounding-box, the descending sort, the lookahead, the
3×LTFRE gating of CoinGrinder, SRD's CHANGE_LOWER offset, Knapsack's
two-pass stochastic search at 1000 iters, etc. Most of these subgate-level
checks return MISSING because the host algorithms themselves don't exist.
The W113 bug catalogue is **preserved** and W129 adds **18 new bugs** at
sub-gate granularity, focusing on what would be wrong even if a CoinGrinder
were dropped in tomorrow.

Status counts:
- **PRESENT** (matches Core or internally consistent and Core-compatible): 2
- **PARTIAL** (some piece matches, others diverge): 1
- **MISSING** (no equivalent in beamchain): 27

Headline: **18 bugs**, almost all P2/P3 (none is a CDIV — coin selection is
wallet-side, not consensus). The most consequential ones:

1. **BUG-1 (HIGH)** — BnB depth limit 20 vs Core TOTAL_TRIES=100000 with
   bounding-box pruning. This is a *correctness* gap in addition to the
   performance gap W113 BUG-1 documented: beamchain's BnB DOES NOT
   implement Murch's range check (`curr_value > target + cost_of_change` →
   backtrack), so even within 20 depth it can return overshooting "exact
   match" results outside the legal range.
2. **BUG-2 (HIGH)** — BnB declares a match whenever `Diff =< DustLimit=546`.
   Core's range is `[target, target + cost_of_change]` where
   `cost_of_change = change_output_size*effective_feerate +
   change_spend_size*discard_feerate`. At 30 sat/vB, cost_of_change ≈
   3000 sat — much wider than 546. beamchain rejects valid changeless
   solutions that Core would accept, and accepts overshoots that Core
   would reject as "you might as well make change".
3. **BUG-3 (HIGH)** — beamchain never computes effective_value. The cost
   per input is computed *once* on the entry to `bnb_select` from a single
   `FeeRate` argument and applied to every UTXO, but the resulting
   "EffValue" is folded directly into the running accumulator without ever
   being attached to a per-UTXO struct or surfaced. Re-runs (e.g. in
   feebumper) recompute from scratch and may produce different numbers
   because the FeeRate is rounded to integer sat/vB.
4. **BUG-4 (HIGH)** — No fallback ordering between algorithms. Core runs
   BnB → KnapsackSolver → (CoinGrinder if feerate ≥ 3×LTFRE) → SRD and
   picks the *lowest-waste* result among the survivors. beamchain stops at
   the first success: if BnB returns `{ok, _, 0}` with a 545-sat overshoot
   it never checks whether a knapsack pick would have been cheaper.
5. **BUG-5 (HIGH)** — No mixed-output-type re-attempt. Core's
   AttemptSelection runs once per OutputType and only mixes types if no
   single-type solution exists. beamchain has no concept of output type
   in coin selection at all (every UTXO is treated as P2WPKH for sizing).

The remaining 13 bugs cover: SFFO short-circuit absent (Core skips BnB
when subtract_fee_outputs=true), GenerateChangeTarget randomization absent
(W113 BUG-11 documented append-only; W129 documents the *upstream*
absence of the random change target that feeds the change position),
SelectionResult.Merge / preset_inputs path missing, max_tx_weight gating
absent, RecalculateWaste missing, KnapsackSolver's 1000-iteration
two-pass not implemented, KnapsackSolver's lowest_larger fallback
missing, OUTPUT_GROUP_MAX_ENTRIES not honored, no CoinEligibilityFilter
escalation ladder, no FastRandomContext seeded shuffle (Knapsack uses
list:sort then list:reverse — completely deterministic), no
m_subtract_fee_outputs gating of BnB (Core skips it; beamchain runs it
unconditionally), no bump_fee_group_discount, no `safe`/`solvable`/
`from_me` per-COutput tracking (W113 BUG-5 OutputGroup absence in
shallow form; W129 BUG-15 documents the deeper per-COutput attribute
absence that breaks unsafe-input handling).

**NOT a CDIV**: every bug below affects wallet fee efficiency, change
fingerprinting, performance, or operator UX. None affects consensus
validation of received blocks. Cluster severity: 5 HIGH / 8 MEDIUM /
5 LOW.

Reference: `bitcoin-core/src/wallet/coinselection.{h,cpp}` (993+479 LOC),
`bitcoin-core/src/wallet/spend.cpp` (1547 LOC, in particular
`AttemptSelection` :702-727, `ChooseSelectionResult` :729-812,
`SelectCoins` :814-870, `AutomaticCoinSelection` :872-985,
`CreateTransactionInternal` :1058-1255), `bitcoin-core/src/wallet/feebumper.cpp`
(385 LOC, `CreateRateBumpTransaction` :159+).

The audit-flip convention applies: every test that asserts a divergent
fact (e.g. "BnB has a depth-20 cap") is written so it **passes today**
and **will fail when the fix lands**, flipping the gate from MISSING/BUG
to PRESENT.

---

## Gate index (1..30)

| #  | Name | Status | Core ref | beamchain ref |
|----|------|--------|----------|---------------|
| 1  | BnB exists                                                | PARTIAL | coinselection.cpp:93-201 (SelectCoinsBnB)                          | beamchain_wallet.erl:1569-1611 (bnb_select / bnb_search) |
| 2  | BnB sorts descending by effective_value                   | MISSING | coinselection.cpp:114 (descending comparator)                       | only one outer sort by raw `value`, no effective-value sort |
| 3  | BnB bounding box `curr_value ∈ [target, target+cost_of_change]` | MISSING | coinselection.cpp:128 (`curr_value > selection_target + cost_of_change`) | bnb_search uses `Diff =< DustLimit=546` (fixed 546-sat upper bound, no `cost_of_change`) |
| 4  | BnB TOTAL_TRIES = 100000 with lookahead pruning           | MISSING | coinselection.cpp:91, 124 (`curr_value + curr_available_value < selection_target`) | depth-capped at 20 (W113 BUG-1; W129 BUG-1 deeper) |
| 5  | BnB skipped when SFFO active                              | MISSING | spend.cpp:751 (`!m_subtract_fee_outputs`)                           | beamchain has no SFFO concept; BnB always runs |
| 6  | BnB returns SelectionResult, not raw `{ok, list, change}` | MISSING | coinselection.cpp:96, 200 (`SelectionResult` w/ Algo tag, waste, weight) | flat tuple `{ok, [Coin], Change}` |
| 7  | KnapsackSolver exists                                     | PARTIAL | coinselection.cpp:652-747                                           | beamchain_wallet.erl:1614-1636 (knapsack_select / accumulate_coins) |
| 8  | KnapsackSolver does 1000-iter two-pass stochastic search  | MISSING | coinselection.cpp:602-650 (ApproximateBestSubset)                   | accumulate_coins is a single deterministic left-fold |
| 9  | KnapsackSolver tracks `lowest_larger` fallback            | MISSING | coinselection.cpp:659, 678-680, 698-700                              | no concept; accumulate_coins always selects smallest-first |
| 10 | KnapsackSolver uses FastRandomContext for shuffle         | MISSING | coinselection.cpp:665 (`std::shuffle(groups, rng)`)                  | `lists:sort` + `lists:reverse` — fully deterministic |
| 11 | SRD (SelectCoinsSRD) exists                               | MISSING | coinselection.cpp:536-588                                            | absent entirely (W113 BUG-3) |
| 12 | CoinGrinder exists                                        | MISSING | coinselection.cpp:325-525                                            | absent entirely (W113 BUG-4) |
| 13 | CG gated on `effective_feerate > 3 × long_term_feerate`   | MISSING | spend.cpp:769                                                        | no feerate comparison; no long_term_feerate concept |
| 14 | OutputGroup struct                                        | MISSING | coinselection.h:228-270                                              | flat `{Txid, Vout, #utxo{}}` tuples (W113 BUG-5) |
| 15 | OUTPUT_GROUP_MAX_ENTRIES = 100 cap                        | MISSING | spend.cpp:46, 629                                                    | no cap (W113 BUG-10) |
| 16 | `m_avoid_partial_spends` honored                          | MISSING | spend.cpp:889, 1078                                                  | absent |
| 17 | COutput.effective_value caching                           | MISSING | coinselection.h:31-34, 75-89                                         | computed inside loop, never cached |
| 18 | COutput.long_term_fee caching                             | MISSING | coinselection.h:70, coinselection.cpp:761-762                        | absent |
| 19 | COutput.ancestor_bump_fees + ApplyBumpFee                 | MISSING | coinselection.h:73, 108-116                                          | absent |
| 20 | CoinSelectionParams.m_cost_of_change computed             | MISSING | spend.cpp:1174-1175 (`discard_feerate.GetFee(change_spend_size) + change_fee`) | absent; only a 546-sat dust constant |
| 21 | CoinSelectionParams.min_viable_change                     | MISSING | spend.cpp:1184 (`max(change_spend_fee+1, dust)`)                      | absent; flat 546-sat dust threshold (W113 BUG-9) |
| 22 | CoinSelectionParams.m_change_fee                          | MISSING | spend.cpp:1174                                                       | absent |
| 23 | GenerateChangeTarget randomized (50ksat..min(2×pay,1Msat))| MISSING | coinselection.cpp:809-818                                            | absent; change is always residual after target+fee |
| 24 | ChooseSelectionResult runs BnB/Knapsack/CG/SRD then picks min-waste | MISSING | spend.cpp:729-812                                              | first-success BnB→Knapsack chain (W113 BUG-3/BUG-4 expansion) |
| 25 | SelectionResult.RecalculateWaste                          | MISSING | coinselection.cpp:827-853                                            | absent (W113 BUG-2 expansion) |
| 26 | SelectionResult.Merge for preset inputs                   | MISSING | coinselection.cpp:922-934                                            | wcfp_select_coins does ad-hoc list-concat; no merge semantics |
| 27 | CoinEligibilityFilter escalation ladder (1/6→1/1→0/1/2→…) | MISSING | spend.cpp:898-928                                                    | absent; single pass over all UTXOs |
| 28 | max_tx_weight / max_selection_weight gating               | MISSING | spend.cpp:743-748, coinselection.cpp:131, 132 (BnB), 438 (CG), 567 (SRD) | absent (W113 BUG-12 expansion: wrong weight constant, but also no cap) |
| 29 | feebumper.CreateRateBumpTransaction wired to SelectCoins  | MISSING | feebumper.cpp:159-345                                                | beamchain's bumpfee (W118 FIX-61) re-uses inputs directly and does NOT re-run coin selection |
| 30 | mempool / chain.calculateCombinedBumpFee integration      | MISSING | spend.cpp:798, feebumper.cpp:83                                      | no combined-bump-fee call; per-coin bump fee not tracked |

---

## Bug catalogue (18 BUGs)

### BUG-1 (HIGH) — BnB has no `cost_of_change` upper bound, uses fixed 546-sat

`beamchain_wallet.erl:1576-1586`. The match condition is
`Diff >= 0 andalso Diff =< DustLimit` where `DustLimit = 546`. Core's BnB
(`coinselection.cpp:128`) uses
`curr_value > selection_target + cost_of_change` to detect overshoot,
where `cost_of_change` = change_output_size × effective_feerate +
change_spend_size × discard_feerate. At 30 sat/vB effective, 10 sat/vB
discard, P2WPKH change (31-byte output, 68-vbyte spend), this is
31×30 + 68×10 = 930 + 680 = **1610 sat**. beamchain rejects any
overshoot ≥ 547, so it routinely picks an inferior knapsack solution
when a 1000-sat-overshoot changeless tx would be cheaper. At the other
extreme, when effective_feerate is high (e.g. 100 sat/vB), the legal
range is much wider than 546 and beamchain is correct *by accident*.

### BUG-2 (HIGH) — BnB recursion is depth-bounded, not try-bounded

`beamchain_wallet.erl:1587-1590`. `bnb_search/7` aborts when `Depth > 20`
where Depth is the number of UTXOs considered (not the number of
branches explored). Core's TOTAL_TRIES (`coinselection.cpp:91`, value
100000) counts *branches*; the depth-first exploration with lookahead
pruning can examine far more than 20 UTXOs while only visiting <100k
branches. A wallet with 50 UTXOs cannot use BnB at all in beamchain.

### BUG-3 (HIGH) — BnB never sorts by effective_value

`beamchain_wallet.erl:1554-1557`. `select_coins/3` does one outer sort
by raw `Utxo#utxo.value` descending. Core's BnB
(`coinselection.cpp:114`) re-sorts by **descending GetSelectionAmount()**
(= effective_value when no SFFO, raw value when SFFO). The two sort
keys differ when input weights vary: a 100k-sat P2PKH UTXO at 10 sat/vB
has effective_value ≈ 100000 - 1480 = 98520, while a 100k-sat P2WPKH
has effective_value ≈ 100000 - 680 = 99320. Raw-value sort gives the
wrong ordering for BnB's bounding-box logic.

### BUG-4 (HIGH) — First-success short-circuit, never compares waste

`beamchain_wallet.erl:1559-1565`. The orchestrator runs BnB first; if
BnB returns `{ok, _, _}` it returns *unconditionally* without running
Knapsack. Core's `ChooseSelectionResult` (`spend.cpp:729-812`)
collects results from all enabled algorithms (BnB, Knapsack, CG, SRD)
and returns `*std::min_element(results)` by waste. beamchain can pick a
BnB result that wastes more on bump fees than a Knapsack result would.

### BUG-5 (HIGH) — No mixed-output-type re-attempt

`beamchain_wallet.erl:1553+`. Core's `AttemptSelection`
(`spend.cpp:702-727`) runs once per OutputType (Legacy, P2SH-Segwit,
Bech32, Bech32m) and only mixes types if no single-type solution
exists. beamchain has no output-type partition in coin selection;
every UTXO is treated as a generic P2WPKH input. A wallet with 50%
P2PKH and 50% P2WPKH UTXOs will mix them even when one type alone
would have funded the tx (privacy leak).

### BUG-6 (MEDIUM) — `bnb_select` runs unconditionally; no SFFO gate

`beamchain_wallet.erl:1559`. Core skips BnB when SFFO is active
(`spend.cpp:751`: `if (!coin_selection_params.m_subtract_fee_outputs)`)
because changeless input sets cause SFFO-recipient amount drift.
beamchain has no SFFO concept at all (no `subtract_fee_outputs`
argument anywhere in `select_coins`), so this gate is silently
absent. Knock-on: any wallet caller wanting "subtract fee from output"
semantics has to manually pre-adjust the recipient amount, but the
adjustment is done *before* coin selection knows the input set, so
the fee is wrong by a few sat per input.

### BUG-7 (MEDIUM) — Knapsack is a deterministic linear sweep

`beamchain_wallet.erl:1620-1636`. `accumulate_coins/5` walks the
ascending-sorted list once and stops at the first sufficient prefix.
Core's `ApproximateBestSubset` (`coinselection.cpp:602-650`) runs 1000
randomized two-pass iterations to approximate the subset-sum minimum.
The deterministic sweep produces sub-optimal selections (typically
larger input count than necessary) and is *deterministic*, so
fingerprinting is easier (same UTXO set + target + feerate ⇒ same
selection every call, with no randomization mask).

### BUG-8 (MEDIUM) — Knapsack does not consider `lowest_larger`

`beamchain_wallet.erl:1614-1636`. Core's Knapsack (`coinselection.cpp:659,
678-680, 698-700, 715-717`) keeps track of the smallest single UTXO
that is **larger than the target** as a fallback: when the stochastic
search misses, or when the closest approximate is no closer than this
fallback, it picks the lowest_larger. beamchain has no such fallback —
if `accumulate_coins` runs out of UTXOs it returns
`{error, insufficient_funds}` even when a single larger UTXO would
fund the tx by itself. This is impossible to hit in practice because
the outer `bnb_select` already returns `{ok, _, _}` for any single
UTXO that covers target+fee, but the logic is bug-for-bug different.

### BUG-9 (MEDIUM) — Knapsack does not use a RNG-seeded shuffle

`beamchain_wallet.erl:1619-1621`. The list is sorted descending by
value then *reversed* to get smallest-first. Core
(`coinselection.cpp:665`) does `std::shuffle(groups.begin(),
groups.end(), rng)` for the stochastic loop, which is a key part of
why the algorithm is called *stochastic* approximation. beamchain's
Knapsack is fully deterministic; no privacy benefit from randomized
selection ordering.

### BUG-10 (MEDIUM) — No `cost_of_change` parameter exists

`beamchain_wallet.erl` (entire file). Core computes
`m_cost_of_change = m_discard_feerate.GetFee(change_spend_size) +
m_change_fee` at `spend.cpp:1175`. beamchain has no `discard_feerate`,
no `change_spend_size`, no `change_fee` — only a single integer
`FeeRate` (sat/vB). Without this parameter, BnB cannot correctly bound
its search (see BUG-1) and the waste metric (see BUG-12) cannot be
computed.

### BUG-11 (MEDIUM) — No long-term feerate / consolidation feerate

`beamchain_wallet.erl` (entire file). Core's
`wallet.m_consolidate_feerate` (`spend.cpp:1087`) is the feerate
estimate used to predict *future* spend cost of created change. It
drives both the BnB waste calculation and the CoinGrinder gate
(`spend.cpp:769`). beamchain has no second feerate. (W113 BUG-7 noted
this at a higher level; W129 BUG-11 documents that even the SCAFFOLD
to add it is missing — no `consolidate_feerate` config key, no
`-fallbackfee` analogue, etc.)

### BUG-12 (MEDIUM) — No waste metric (`RecalculateWaste`)

Core's `SelectionResult::RecalculateWaste`
(`coinselection.cpp:827-853`) computes `waste = Σ(coin.fee -
coin.long_term_fee) - bump_fee_group_discount + (change_cost OR
excess)`. beamchain never computes this number, so its first-success
short-circuit (BUG-4) has no metric to compare results against even
if a second algorithm were added. (W113 BUG-2 stub; W129 BUG-12
ratifies that the *infrastructure* for the waste metric is absent
end-to-end.)

### BUG-13 (MEDIUM) — `GenerateChangeTarget` randomization absent

`beamchain_wallet.erl:1614-1621`. Core's `GenerateChangeTarget`
(`coinselection.cpp:809-818`) picks a random change target between 50
ksat and min(2×payment, 1 Msat) to make change outputs hard to
distinguish from payments. beamchain's Knapsack uses a fixed
`BaseFee = round(FeeRate * 71)` for "header + 1 output + 1 change";
change is *whatever's left over*, fully deterministic given (UTXO
set, target, feerate). Privacy regression: any analyst can compute
the expected residual and identify the change output with high
confidence.

### BUG-14 (MEDIUM) — `m_subtract_fee_outputs` absent; SFFO unsupported

`beamchain_wallet.erl` (entire file) and `beamchain_rpc.erl:5435+`
(rpc_sendtoaddress). Core's
`CoinSelectionParams.m_subtract_fee_outputs` (`coinselection.h:163`)
controls whether `GetSelectionAmount()` returns raw value or effective
value. beamchain has no such switch; every UTXO is treated as
"effective value" implicitly. Wallet RPCs that should support
`subtractfeefromamount` (sendtoaddress, sendmany,
walletcreatefundedpsbt) silently ignore it.

### BUG-15 (LOW) — COutput `safe` / `solvable` / `from_me` flags absent

Core's `COutput` struct (`coinselection.h:36-68`) carries:
- `safe` (false for unconfirmed inputs received from external wallets)
- `solvable` (false if descriptor doesn't have the keys/scripts)
- `from_me` (true if the wallet sent the parent tx)

These drive `CoinEligibilityFilter` (`coinselection.h:201-225`).
beamchain's `#utxo{}` has `value`, `script_pubkey`, `is_coinbase`,
`height` and that's it — no `safe`, no `solvable`, no `from_me`. So
all UTXOs are treated as if `safe=true, solvable=true, from_me=true`,
which means a malicious sender can spam unconfirmed external UTXOs
into beamchain's UTXO set and they'll be picked for spending.

### BUG-16 (LOW) — `CoinEligibilityFilter` escalation ladder absent

`beamchain_rpc.erl:7559+` (wcfp_select_coins). Core's
`AutomaticCoinSelection` (`spend.cpp:898-928`) walks a 6-step ladder
of progressively-relaxed filters: (1,6,0) → (1,1,0) → (0,1,2) →
(0,1,min(4,maxA/3)) → (0,1,maxA/2) → (0,1,maxA-1, include_partial).
beamchain does a single pass over all UTXOs with no
confs-from-me / confs-from-them distinction at all. The first
selection attempt that succeeds *might* be one that should have been
rejected at the strictest filter level.

### BUG-17 (LOW) — No `m_max_tx_weight` enforcement

Core's `CoinSelectionParams.m_max_tx_weight` (`coinselection.h:176`)
caps tx weight at `MAX_STANDARD_TX_WEIGHT` (400000 wu) by default
and is consulted inside every algorithm (BnB at
`coinselection.cpp:131`, CG at :438, SRD at :567, Knapsack at :668).
beamchain has no weight cap; in principle a 500-input changeless BnB
result could exceed standard-tx weight and be rejected by the
network.

### BUG-18 (LOW) — feebumper does not re-run coin selection

`beamchain_rpc.erl:5570+` (rpc_bumpfee / rpc_psbtbumpfee, W118 FIX-61).
beamchain's bumpfee replaces the change output and re-signs, but does
*not* invoke `select_coins/3` to find additional inputs if the
boosted fee exceeds the original change. Core's
`CreateRateBumpTransaction` (`feebumper.cpp:159+`) constructs a new
`CCoinControl` with all original inputs preselected via
`Select(prevout)`, sets `m_allow_other_inputs=true`, and calls
`CreateTransaction` which goes through full coin selection. beamchain
will fail bumpfee silently with "insufficient funds in change" when
Core would succeed by pulling additional UTXOs.

---

## Universal patterns (W129)

1. **"Audit framework requires per-Murch-invariant tests, not algorithm-presence"** —
   W113 asked "does BnB exist?" and answered "yes (sort of)" — green-light.
   W129 asks "does BnB implement Murch's bounding box?" and answers "no" — bug.
   Pattern to promote fleet-wide: every algorithm presence gate must be
   accompanied by ≥3 specific invariant gates that survive the algorithm
   being present-but-wrong.

2. **"`Diff =< DustLimit` is a Core-bug-look-alike, not a Core impl"** —
   beamchain's BnB tail check looks like Core's "is this within the legal
   range?" but uses the wrong bound (dust vs cost_of_change). Pattern:
   any audit of an algorithm with a numerical match condition must
   compute the Core expected value at a non-degenerate feerate (e.g. 30
   sat/vB) and compare; matching at 1 sat/vB is a false-positive trap.

3. **"`{ok, X, Change}` flat tuples vs Core `SelectionResult` struct"** —
   beamchain's selection return type carries enough for "what to spend"
   but loses *algorithm provenance*, *waste*, *weight*, and
   *completed?*. Pattern: any audit of a Core algorithm with rich return
   metadata must check that the consumer-side type carries equivalent
   fields, not just the "happy-path" subset.

4. **"Deterministic shuffle is a privacy regression"** —
   `lists:sort + lists:reverse` is faster and simpler than
   `std::shuffle(rng)`, but it's a fingerprint vector. Pattern: every
   selection algorithm doc gate must check whether the randomness is
   sourced from a `FastRandomContext` (or equivalent) at the call site
   — *not* whether the function "uses random" in some abstract sense.

5. **"Audit-flip preserves the bug as a test"** —
   We assert `Diff =< 546` as the current match condition. When BUG-1
   is fixed the assertion will start failing, naturally flipping the
   gate from MISSING to PRESENT. Pattern: every divergent value in the
   audit becomes a pin-test against the divergent value, which becomes
   an audit-failure when the fix lands; same pattern as W125 already
   uses for RPC error codes.

6. **"Cluster severity skews to MEDIUM/LOW when domain is wallet"** —
   18 bugs / 0 P0 / 5 HIGH / 8 MEDIUM / 5 LOW. Coin selection bugs
   manifest as fee inefficiency, change fingerprinting, and degraded
   UX — never as block validation drift. Pattern: domain (consensus vs
   policy vs wallet) sets the severity ceiling regardless of bug count.

---

## Out-of-scope (deferred to follow-up waves)

- **Output type partition (P2WPKH / P2TR / P2PKH) in coin selection**:
  Documented as BUG-5 at orchestrator level; sub-bugs around per-type
  effective_value and per-type weight would expand to ~8 more entries
  but they're all rooted in the same missing partition. A separate FIX
  wave would have to add `output_type/1` classification and rerun the
  audit.
- **Reproducible Knapsack with VRF seed for tests**: would require a
  test-only entry that takes a seed. Not in scope here.
- **Bump-fee group discount math**: `SelectionResult.SetBumpFeeDiscount`
  and `bump_fee_group_discount` interactions with shared-ancestor
  inputs. Documented at gate level (G30) but no behavioral test added
  because feebumper W118 FIX-61 is already 4 bugs deep on its own.
- **`OutputGroupTypeMap` per-type vs all_groups dispatch**: requires
  introducing output_type first.

---

## Where things live

- **Coin selection**: `src/beamchain_wallet.erl:1547-1636`
- **RPC sendtoaddress**: `src/beamchain_rpc.erl:5425-5505`
- **wcfp_select_coins + wcfp_append_change**:
  `src/beamchain_rpc.erl:7559-7628`
- **build_transaction**: `src/beamchain_wallet.erl:923-949`
- **bumpfee (W118 FIX-61)**: `src/beamchain_rpc.erl:5549+`
- **payjoin_client select_coins caller**:
  `src/beamchain_payjoin_client.erl:392`
- **W113 prior audit**: `test/beamchain_w113_coin_selection_tests.erl`
  (12 bugs documented).
- **W118 wallet audit (BUG-9 / G30 overlap)**:
  `test/beamchain_w118_wallet_tests.erl:1150-1180`.

Test file landing this audit: `test/beamchain_w129_coin_selection_tests.erl`
(30 EUnit gates; PRESENT/PARTIAL/MISSING/BUG-* status asserted; audit-flip
convention for the 18 divergent values).
