# W145 — Coinbase + subsidy + fees + MAX_MONEY invariants (beamchain)

Discovery-only wave.  Audit gates derived from Bitcoin Core references:

- `bitcoin-core/src/validation.cpp:1839-1850` — `GetBlockSubsidy`
  (initial 50 * COIN, halved every `nSubsidyHalvingInterval`,
  `>= 64` halvings → 0).
- `bitcoin-core/src/validation.cpp:2610-2614` — coinbase-amount gate
  (`blockReward = nFees + GetBlockSubsidy(...)`,
  `block.vtx[0]->GetValueOut() > blockReward` ⇒ `bad-cb-amount`).
- `bitcoin-core/src/consensus/tx_check.cpp` — `CheckTransaction`
  (per-output range, accumulated total, duplicate inputs CVE-2018-17144,
  coinbase scriptSig length 2..100).
- `bitcoin-core/src/consensus/tx_verify.cpp:164-214` — `CheckTxInputs`
  (per-coin MoneyRange + accumulated MoneyRange, coinbase maturity
  `nSpendHeight - coin.nHeight < COINBASE_MATURITY`, `bad-txns-in-belowout`,
  `bad-txns-fee-outofrange`).
- `bitcoin-core/src/consensus/amount.h` — `MAX_MONEY = 21M * COIN`,
  `MoneyRange(v) = (v >= 0 && v <= MAX_MONEY)`.
- `bitcoin-core/src/consensus/consensus.h:19` — `COINBASE_MATURITY = 100`.
- `bitcoin-core/src/kernel/chainparams.cpp` — per-network
  `nSubsidyHalvingInterval` (mainnet/testnet3/testnet4/signet = 210000,
  regtest = 150).

Companion audits to cross-reference:

- **W126** (BIP-152): compact-block reconstruction must recompute fees
  the same way `Consensus::CheckTxInputs` does; gaps here propagate.
- **W129** (Coin selection): wallet fee bumps that round-DOWN at
  fractional sat/vB underpay; the subsidy/fees side of that asymmetry
  is the consensus gate audited here.
- **W139** (Fee estimation): the consensus fee invariant
  (`nValueIn >= value_out`) is the floor underneath every estimator.
- **W142** (SegWit witness validation): catalogued the
  `decode_transaction` / `check_transaction` perimeter at v0/P2WPKH/P2WSH;
  this wave audits the consensus-amount perimeter at the same gate.
  Two pre-existing W142 findings are *cross-cited* here (not re-counted):
  BUG-21 (W142) `MIN_TRANSACTION_WEIGHT >= 240` enforced in
  `check_transaction` (stricter than Core), and BUG-5 (W142) `check_no_dup_txids`
  being O(n log n) via `lists:usort` rather than a single-pass set.

## Status counts (32 gates)

- **PRESENT** (Core-parity, or internally consistent + Core-compatible): 17
- **PARTIAL** (some piece matches, others diverge or are simplified): 9
- **MISSING** (no equivalent in beamchain): 6

Headline: **22 bugs**, severity distribution
**0 P0-CONSENSUS / 0 P0-CDIV / 5 P1 / 9 P2 / 8 P3**.

The subsidy/fees/MAX_MONEY surface is by far the most-audited consensus
gate in Bitcoin (CVE-2010-5139, CVE-2018-17144); the canonical
arithmetic checks are in place in beamchain.  All consensus-critical
gates — `block_subsidy/2` (chain_params:393-399), the per-block
`CbValue =< Subsidy + TotalFees` (validation:1311-1315), per-output
`V =< MAX_MONEY` + accumulated sum (validation:550-562), per-coin and
running-sum input MoneyRange in the connect-block fold (validation:1190-1198),
duplicate-input detection in context-free `check_transaction`
(validation:565), per-tx fee MoneyRange + per-block accumulated-fee
MoneyRange (validation:1238-1247), and BIP-30/BIP-34 wiring — are
present, internally consistent, and Core-compatible.  No
P0-CONSENSUS-class or P0-CDIV finding fired.

Two themes dominate this wave:

1. **Two-pipeline guard 15th distinct extension fleet-wide (1st in
   beamchain on the subsidy axis).**  beamchain has TWO independent
   `subsidy_halving_interval` data sources — `beamchain_chain_params`
   (used by validation + miner) and `beamchain_config`
   (used by RPC + `block_subsidy` in `beamchain_rpc.erl:2156-2164`,
   which has its OWN local copy of `GetBlockSubsidy`).  Both currently
   agree, but a divergent-edit on either side gives an asymmetric
   subsidy view: RPC `getblockstats`/`getmininginfo` would report one
   subsidy while validation/miner uses another.  This is the same
   "two-pipeline" fork the audit framing has been tracking since W76,
   now extended to the per-network monetary policy axis.
2. **Comment-as-confession (5th instance fleet-wide; 1st on the
   subsidy/fees axis).**  `beamchain_miner.erl:1010-1014` explicitly
   reads *"In a real impl, would compute fee from inputs-outputs / For
   generateblock, caller is responsible for valid txs"*.  The
   consequence — `generateblock` (a regtest test-helper RPC) creates a
   coinbase paying ONLY the subsidy, leaving every fee from the
   supplied tx list unclaimed.  Consensus-valid (under-claim is fine)
   but semantically broken: test fixtures and CI corpus reproductions
   that depend on the coinbase capturing fees will silently see fees
   evaporate.

Notable cross-cutting smells:

- **Bignum-safe but inconsistent-with-Core**: Erlang `bsr` is well
  defined for any shift count, including `>= 64`.  beamchain still
  keeps the `Halvings >= 64 -> 0` guard, matching Core's UB-avoidance
  contract (BUG-2 below: the comment header on the guard does not
  explain that the guard is purely a Core-parity artefact, not an
  Erlang correctness requirement).
- **`is_coinbase_tx` is stricter than Core on `index`**: Core matches
  `prevout.hash.IsNull() && n == NULL_INDEX`; beamchain hard-codes
  `index = 16#ffffffff`.  Equivalent today (`NULL_INDEX == 0xffffffff`),
  but the literal couples the matcher to the constant — if Core ever
  redefines `NULL_INDEX` (it won't), beamchain silently diverges.
- **Mempool path: `check_tx_inputs_money_range` accumulated sum check
  upper-bound only** (BUG-3): Core checks both `>= 0` and `<= MAX_MONEY`
  on the running sum; beamchain only checks `<= MAX_MONEY`.  Benign
  given Erlang bignums + per-coin `V >= 0` precondition, but
  inconsistent with Core's defence-in-depth contract.

---

## BUGS

### BUG-1 (P1) — Two-pipeline `subsidy_halving_interval` (chain_params vs config) plus a duplicate `block_subsidy/1` in `beamchain_rpc.erl`

- **File**: `src/beamchain_chain_params.erl:37,118,166,215,258`
  (5 sites) AND `src/beamchain_config.erl:711,737,761,782,805`
  (5 sites) AND `src/beamchain_rpc.erl:2156-2164` (duplicate GetBlockSubsidy).
- **Core ref**: `bitcoin-core/src/validation.cpp:1839-1850`
  (single canonical `GetBlockSubsidy` reads
  `consensusParams.nSubsidyHalvingInterval`).
- **Description**: beamchain has TWO independent in-memory representations
  of per-network params:
  - `beamchain_chain_params:params/1` returns a map; used by
    `beamchain_validation` (connect-block path) and
    `beamchain_miner` (block-template path).
  - `beamchain_config:network_params/1` returns a `#network_params{}`
    record; used by `beamchain_rpc` and most CLI helpers.

  Each one re-declares `subsidy_halving_interval` (chain_params) or
  `subsidy_halving` (config) for every network.  Additionally,
  `beamchain_rpc.erl:2156-2164` defines its own local `block_subsidy/1`
  that re-implements Core's GetBlockSubsidy:
- **Excerpt**:
  ```erlang
  %% src/beamchain_rpc.erl:2156-2164
  block_subsidy(Height) ->
      Params = beamchain_config:network_params(),
      HalvingInterval = Params#network_params.subsidy_halving,
      Halvings = Height div HalvingInterval,
      case Halvings >= 64 of
          true -> 0;
          false -> (50 * 100000000) bsr Halvings  %% 50 BTC in satoshis
      end.
  ```
  vs. the canonical implementation:
  ```erlang
  %% src/beamchain_chain_params.erl:392-399
  block_subsidy(Height, Network) ->
      #{subsidy_halving_interval := Interval} = params(Network),
      Halvings = Height div Interval,
      case Halvings >= 64 of
          true -> 0;
          false -> ?INITIAL_SUBSIDY bsr Halvings
      end.
  ```
- **Impact**: Today both views agree (10 sites all reference
  `?SUBSIDY_HALVING_INTERVAL` or `150` for regtest), but a future
  divergent edit — e.g., adding a new test network or fixing a
  per-network testnet quirk — would split chain_params's
  validation/miner view from config's RPC view.  RPC tools
  (`getblockstats`, `getmininginfo`) would report a different
  subsidy than the one validation actually enforces.
  Two-pipeline guard, same shape as W76+: collapse to a single
  canonical accessor (e.g., have `beamchain_config:network_params/0`
  delegate to `beamchain_chain_params:params/1`).

### BUG-2 (P2) — `Halvings >= 64 -> 0` guard inherits Core's UB-avoidance contract without comment, masking that Erlang `bsr` is well-defined

- **File**: `src/beamchain_chain_params.erl:392-399`,
  `src/beamchain_rpc.erl:2156-2164`.
- **Core ref**: `bitcoin-core/src/validation.cpp:1842-1844` (comment
  "Force block reward to zero when right shift is undefined").
- **Description**: Core's guard exists because C++ `>>=` of a signed
  integer by a count `>= bit-width` is undefined behaviour.  Erlang's
  `bsr` is well-defined for any non-negative shift count (right-shift
  of a positive bignum by a large count returns 0).  beamchain
  *keeps* the guard, which is correct (Core-parity, ensures the
  consensus rule's bit-level behavior matches), but the surrounding
  documentation does not explain that the guard is purely a parity
  artefact, not an Erlang correctness requirement.
- **Excerpt**:
  ```erlang
  block_subsidy(Height, Network) ->
      #{subsidy_halving_interval := Interval} = params(Network),
      Halvings = Height div Interval,
      case Halvings >= 64 of
          true -> 0;
          false -> ?INITIAL_SUBSIDY bsr Halvings   %% well-defined in Erlang
      end.
  ```
- **Impact**: No runtime bug today.  But a future reviewer or
  refactoring agent reading the Erlang code in isolation may "simplify"
  away the guard ("Erlang shift handles 64+ fine, drop the case"),
  silently diverging from Core's bit-exact rule: post-block-13_440_000
  the chain would mint subsidy that Core treats as zero, producing a
  fleet-only consensus split.  Add a one-line comment citing
  validation.cpp:1842-1844.

### BUG-3 (P2) — Mempool `check_tx_inputs_money_range` accumulated sum only checks upper bound

- **File**: `src/beamchain_mempool.erl:4237-4247`.
- **Core ref**: `bitcoin-core/src/consensus/amount.h:27`
  (`MoneyRange(v) = (v >= 0 && v <= MAX_MONEY)`),
  `bitcoin-core/src/consensus/tx_verify.cpp:186-188`.
- **Description**: Core's `MoneyRange` is a TWO-sided check.  Beamchain
  mempool's `check_tx_inputs_money_range` checks per-coin two-sided
  (`V >= 0 andalso V =< ?MAX_MONEY`) but accumulated sum only on
  the upper bound:
- **Excerpt**:
  ```erlang
  check_tx_inputs_money_range(InputCoins, _Txid) ->
      lists:foldl(fun(Coin, Acc) ->
          V = Coin#utxo.value,
          (V >= 0 andalso V =< ?MAX_MONEY)
              orelse throw('bad-txns-inputvalues-outofrange'),
          NewAcc = Acc + V,
          NewAcc =< ?MAX_MONEY                     %% upper bound only
              orelse throw('bad-txns-inputvalues-outofrange'),
          NewAcc
      end, 0, InputCoins),
      ok.
  ```
- **Impact**: Benign in Erlang (per-coin `V >= 0` precondition + bignum
  addition cannot produce negative).  But inconsistent with Core's
  defence-in-depth contract and with beamchain's OWN connect-block path
  (`beamchain_validation.erl:1195`) which DOES check `NewAcc >= 0`.
  Two-pipeline divergence between mempool and connect-block on the
  same invariant — collapse to a single helper.

### BUG-4 (P2) — `is_coinbase_tx/1` couples to literal `0xffffffff` rather than abstracting NULL_INDEX

- **File**: `src/beamchain_validation.erl:600-602`.
- **Core ref**: `bitcoin-core/src/primitives/transaction.h:42`
  (`bool IsNull() const { return (hash.IsNull() && n == NULL_INDEX); }`),
  `bitcoin-core/src/primitives/transaction.h:341-343`
  (`IsCoinBase() = (vin.size() == 1 && vin[0].prevout.IsNull())`).
- **Description**: Core abstracts the prevout-null sentinel into
  `NULL_INDEX = 0xffffffff` (`COutPoint::NULL_INDEX`).  beamchain
  inlines the literal:
- **Excerpt**:
  ```erlang
  is_coinbase_tx(#transaction{inputs = [#tx_in{prev_out =
      #outpoint{hash = <<0:256>>, index = 16#ffffffff}}]}) -> true;
  is_coinbase_tx(_) -> false.
  ```
- **Impact**: Functionally identical to Core today.  The bug is
  abstraction-level: there is no `?NULL_INDEX` macro alongside
  `?COINBASE_MATURITY` / `?MAX_MONEY` in `beamchain_protocol.hrl`,
  so the matcher is brittle to a renaming of the sentinel and harder
  to grep against Core for parity.  Add `-define(NULL_INDEX, 16#ffffffff).`

### BUG-5 (P3) — `is_coinbase_tx/1` rejects multi-input coinbases that Core would also reject, but error path emits `null_input` instead of `bad-cb`

- **File**: `src/beamchain_validation.erl:576-583`.
- **Core ref**: `bitcoin-core/src/consensus/tx_check.cpp:50,55`.
- **Description**: A tx with two inputs where input[0] is null and
  input[1] is non-null:
  - Core path:  `CheckTransaction` sees `IsCoinBase() = false`
    (because `vin.size() != 1`), then runs the non-coinbase loop
    which throws `bad-txns-prevout-null` on input[0].
  - beamchain path: same — `is_coinbase_tx/1` pattern-fails on
    multi-element list, falls through to the non-coinbase null check
    which throws `null_input` on input[0].
  Behaviorally equivalent reject, but the error atom maps to
  `bad-cb` in the BIP-22 reason string code path while Core emits
  `bad-txns-prevout-null` (BIP-22 `prevout-null`).
- **Impact**: Reason-string asymmetry surfaces in `submitblock` RPC
  responses — beamchain reports the WRONG canonical reason for a
  Core-rejectable block, breaking mining pool dashboards that
  pattern-match on the Core string.  Cross-cite W125 (RPC error parity).

### BUG-6 (P1) — `generateblock` RPC creates a coinbase that ignores supplied-tx fees

- **File**: `src/beamchain_miner.erl:1008-1019`.
- **Core ref**: `bitcoin-core/src/rpc/mining.cpp` `generateblock`,
  which calls `BlockAssembler::CreateNewBlock` and tallies
  `nFees` from the txs.
- **Description**: COMMENT-AS-CONFESSION.  The `generateblock`
  helper (regtest-only, used in tests + diff-test corpora)
  zeroes `TotalFees` regardless of what the user-supplied txs
  actually pay:
- **Excerpt**:
  ```erlang
  %% Block subsidy (no fees from provided txs for simplicity)
  Subsidy = beamchain_chain_params:block_subsidy(Height, Network),
  TotalFees = lists:foldl(fun(_Tx, Sum) ->
      %% In a real impl, would compute fee from inputs-outputs
      %% For generateblock, caller is responsible for valid txs
      Sum
  end, 0, Txs),
  CoinbaseValue = Subsidy + TotalFees,
  ```
- **Impact**: Consensus-valid (under-claim is fine, never produces
  `bad-cb-amount`), but semantically broken.  Test fixtures that
  produce a tx-with-fee in regtest and assert that the coinbase
  output VALUE equals `subsidy + fee` will silently fail or
  see fees evaporate from the chain (the inputs-outputs delta
  goes nowhere — it just isn't claimed).  This degrades regression
  detection in the very RPC most often used by the test suite.
  Comment-as-confession 5th instance fleet-wide, 1st on the
  subsidy/fees axis.

### BUG-7 (P2) — `block_subsidy/2` accepts negative Height (`Height div Interval` returns -1 for negative Height)

- **File**: `src/beamchain_chain_params.erl:392-399`.
- **Core ref**: `bitcoin-core/src/validation.cpp:1841`
  (`int halvings = nHeight / consensusParams.nSubsidyHalvingInterval;`
  signed integer division — `-1 / 210000 = 0` in C++, but Erlang
  `(-1) div 210000 = -1`).
- **Description**: The `-spec` says `non_neg_integer()` but at runtime
  Erlang does not enforce specs.  If a caller passes a negative
  height (e.g., a sentinel `-1` during reorg-rewind paths or as a
  default for "no chain yet"), `Halvings = -1`, the `>= 64` guard
  returns false, and `?INITIAL_SUBSIDY bsr (-1)` raises a
  `badarith` exception.  Core returns 50 * COIN at any negative height
  (the C++ truncated division of negative ints by positive yields 0,
  and `>>= 0` is identity).
- **Excerpt**:
  ```erlang
  block_subsidy(Height, Network) ->
      #{subsidy_halving_interval := Interval} = params(Network),
      Halvings = Height div Interval,    %% -1 div 210000 = -1 in Erlang
      case Halvings >= 64 of
          true -> 0;
          false -> ?INITIAL_SUBSIDY bsr Halvings  %% bsr negative ⇒ badarith
      end.
  ```
- **Impact**: A defensive crash rather than a wrong subsidy (better
  than a wrong subsidy!), but unreachable from the consensus path —
  `connect_block` short-circuits height 0, and pre-genesis heights
  can't arise on the validate-block path.  The dialyzer warning is
  the main loss.  Lower severity because the path is unreachable
  in production.  Add a `Height >= 0 orelse error(...)` guard or
  `when Height >= 0` clause head.

### BUG-8 (P3) — `block_subsidy/1` in `beamchain_rpc.erl` uses an undeclared magic literal `(50 * 100000000)` instead of `?INITIAL_SUBSIDY`

- **File**: `src/beamchain_rpc.erl:2163`.
- **Core ref**: `bitcoin-core/src/consensus/amount.h:15`
  (`static constexpr CAmount COIN = 100000000;`),
  `bitcoin-core/src/validation.cpp:1846` (`nSubsidy = 50 * COIN`).
- **Description**: The duplicate `block_subsidy/1` in `beamchain_rpc.erl`
  hand-codes `(50 * 100000000)`:
- **Excerpt**:
  ```erlang
  block_subsidy(Height) ->
      Params = beamchain_config:network_params(),
      HalvingInterval = Params#network_params.subsidy_halving,
      Halvings = Height div HalvingInterval,
      case Halvings >= 64 of
          true -> 0;
          false -> (50 * 100000000) bsr Halvings  %% 50 BTC in satoshis
      end.
  ```
- **Impact**: Style-only.  A hypothetical change to `?INITIAL_SUBSIDY`
  (e.g., regtest variants for some test corpus) would NOT propagate
  to the RPC view, silently diverging from the validation view.
  Fold into BUG-1.

### BUG-9 (P3) — `?MAX_MONEY` comment says "21M BTC in satoshis" without citing Core sanity-check semantics

- **File**: `include/beamchain_protocol.hrl:23`.
- **Core ref**: `bitcoin-core/src/consensus/amount.h:17-26` — the
  long-form comment explicitly states "this constant is *not* the
  total money supply ... but rather a sanity check.  As this sanity
  check is used by consensus-critical validation code, the exact
  value of the MAX_MONEY constant is consensus critical".
- **Description**: beamchain's macro definition is a one-liner with no
  citation:
- **Excerpt**:
  ```erlang
  -define(MAX_MONEY, 2100000000000000).   %% 21M BTC in satoshis
  ```
- **Impact**: Cosmetic — Core's framing matters because a well-meaning
  reader might think "21M BTC * 1e8 = 2.1e15 sat" is the **soft cap
  on actual supply** rather than a **hard input-validation sanity
  check**.  The former is wrong (real supply is lower due to lost
  coins + zero-subsidy halvings); the latter is consensus-critical.
  Add the 4-line citation from amount.h.

### BUG-10 (P2) — `check_duplicate_inputs/1` uses O(n log n) `lists:usort` rather than O(n) set insert (Core uses `std::set::insert`)

- **File**: `src/beamchain_validation.erl:605-610`.
- **Core ref**: `bitcoin-core/src/consensus/tx_check.cpp:41-44`.
- **Description**: Core's check is a single-pass O(n) loop with
  early-out on first duplicate:
  ```cpp
  std::set<COutPoint> vInOutPoints;
  for (const auto& txin : tx.vin) {
      if (!vInOutPoints.insert(txin.prevout).second)
          return state.Invalid(... "bad-txns-inputs-duplicate");
  }
  ```
  beamchain's check is O(n log n) and no early-out:
- **Excerpt**:
  ```erlang
  check_duplicate_inputs(Inputs) ->
      Outpoints = [{H, I} || #tx_in{prev_out = #outpoint{hash = H, index = I}} <- Inputs],
      case length(Outpoints) =:= length(lists:usort(Outpoints)) of
          true -> ok;
          false -> throw(duplicate_inputs)
      end.
  ```
- **Impact**: Performance, not correctness.  A worst-case tx with
  10,000 inputs sees a ~3× slowdown on the duplicate-check pass
  vs. Core's set-insert.  Lower severity because `check_transaction`
  runs early in the validate pipeline and a DoS bound exists from
  block weight.  Single-pass map fold collapses to O(n).

### BUG-11 (P1) — `bad-cb-amount` error atom emitted is `bad_cb_amount`; reason-string mapping to Core's `bad-cb-amount` not verified

- **File**: `src/beamchain_validation.erl:1315`.
- **Core ref**: `bitcoin-core/src/validation.cpp:2612` (state.Invalid(...
  "bad-cb-amount")).
- **Description**: beamchain throws atom `bad_cb_amount` (underscore).
  The BIP-22 / `submitblock` reason-string code path must translate
  this atom to the EXACT Core wire string `bad-cb-amount` (hyphen)
  for parity with mining pool tooling.  No grep-confirmable mapping
  exists in `beamchain_rpc.erl` for this atom.
- **Excerpt**:
  ```erlang
  CbValue =< Subsidy + TotalFees orelse throw(bad_cb_amount),
  ```
- **Impact**: `submitblock` returns the bad-cb-amount reason as an
  internal atom (e.g., `bad_cb_amount` or a generic message) rather
  than the wire string `bad-cb-amount`, breaking pool dashboards.
  Cross-cite W125 (RPC error parity) and the
  `_reorg-via-submitblock-fleet-result` patterns.  Verify the
  reason-string mapping exists; if not, add it.

### BUG-12 (P2) — `bad-txns-fee-outofrange` only checks upper bound (`Fee =< ?MAX_MONEY`); Core's `MoneyRange(txfee_aux)` is two-sided

- **File**: `src/beamchain_validation.erl:1238-1240`,
  `src/beamchain_mempool.erl:649,924`.
- **Core ref**: `bitcoin-core/src/consensus/tx_verify.cpp:202-209`.
- **Description**: Core: `if (!MoneyRange(txfee_aux))` — both
  `txfee_aux >= 0` and `txfee_aux <= MAX_MONEY`.  beamchain
  *connect-block* (validation.erl:1239) has the two-sided check
  (`Fee >= 0 andalso Fee =< ?MAX_MONEY`), but mempool (mempool.erl:649
  AND mempool.erl:924) only has the upper-bound check:
- **Excerpt**:
  ```erlang
  %% validation.erl:1238-1240 — two-sided, GOOD
  Fee = TotalIn - TotalOut,
  (Fee >= 0 andalso Fee =< ?MAX_MONEY)
      orelse throw(fee_outofrange),

  %% mempool.erl:649 — upper-bound only, BAD
  Fee = TotalIn - TotalOut,
  Fee =< ?MAX_MONEY orelse throw('bad-txns-fee-outofrange'),
  ```
- **Impact**: Mempool path: `TotalIn >= TotalOut` already enforces
  `Fee >= 0`, so this is benign today.  But it's TWO-PIPELINE
  divergence between connect-block and mempool on the same invariant
  — a future refactor that drops the prior `TotalIn >= TotalOut`
  check would silently accept negative-fee txs into the mempool
  while connect-block still rejects them.  Add the explicit
  `Fee >= 0` guard for defence-in-depth.

### BUG-13 (P2) — `check_transaction` does not enforce `tx.vin.size() == 1` for coinbase classification (relies on pattern match coincidence)

- **File**: `src/beamchain_validation.erl:600-602`, `:541-593`.
- **Core ref**: `bitcoin-core/src/primitives/transaction.h:341-343`.
- **Description**: Core's `IsCoinBase()` is
  `(vin.size() == 1 && vin[0].prevout.IsNull())`.  Beamchain's
  pattern (line 600) is `[#tx_in{prev_out = #outpoint{...}}]`
  — a one-element list match — which DOES enforce
  `length(inputs) == 1`, but only as a side effect of the pattern.
  Adding a second input to the pattern would silently accept
  multi-input "coinbase" txs.
- **Excerpt**:
  ```erlang
  is_coinbase_tx(#transaction{inputs = [#tx_in{prev_out =
      #outpoint{hash = <<0:256>>, index = 16#ffffffff}}]}) -> true;
  is_coinbase_tx(_) -> false.
  ```
- **Impact**: Today: equivalent to Core.  But the implicit "1-input"
  constraint is documentation-fragile.  Add an explicit
  `length(Inputs) =:= 1 andalso ...` guard or a comment that the
  pattern is the size-1 enforcement.

### BUG-14 (P3) — Coinbase scriptSig length 2..100 check fires in BOTH `check_transaction` and `contextual_check_block`; the second is redundant

- **File**: `src/beamchain_validation.erl:570-575` (check_transaction)
  AND `:341-345` (contextual_check_block).
- **Core ref**: `bitcoin-core/src/consensus/tx_check.cpp:49-50`.
- **Description**: Core checks the coinbase scriptSig length 2..100
  ONCE inside `CheckTransaction`.  beamchain checks it in
  `check_transaction` (line 574) AND in `contextual_check_block`
  (line 344).  The second is defensive — the comment says
  "context-free, but placed here so it fires on the connect_block path
  which does NOT call check_block".  But it DOES call check_block
  (line 1054: `case check_block(Block, Params)` runs the W93/B4
  defence-in-depth re-check), so the second call is redundant.
- **Impact**: Duplicate compute on every coinbase tx in every block
  (negligible perf hit, but a real bookkeeping anomaly that suggests
  the contextual-block invariant was added before W93/B4 landed).
  Defence-in-depth is OK; just note in a comment.

### BUG-15 (P1) — No explicit `bad-cb-length` reason atom; the `bad_coinbase_length` atom is shared with the mempool path

- **File**: `src/beamchain_validation.erl:575,345`,
  `src/beamchain_mempool.erl` (no separate coinbase length atom).
- **Core ref**: `bitcoin-core/src/consensus/tx_check.cpp:50`.
- **Description**: Core emits `bad-cb-length` as a distinct
  consensus-rejection reason.  beamchain emits `bad_coinbase_length`,
  which after underscore→hyphen substitution becomes `bad-coinbase-length`,
  not `bad-cb-length`.  Wire-string asymmetry.
- **Impact**: BIP-22 `submitblock` RPC reports `bad-coinbase-length`
  where Core would report `bad-cb-length`, breaking string-match
  pool tooling.  Cross-cite W125 (RPC error parity).
  Single-character fix (rename atom) plus mapping entry.

### BUG-16 (P3) — Spec says `non_neg_integer()` for `block_subsidy/2` but no runtime guard

- **File**: `src/beamchain_chain_params.erl:392`.
- **Core ref**: N/A (C++ has compile-time signed int).
- **Description**: `-spec block_subsidy(non_neg_integer(), atom()) -> non_neg_integer().`
  is a dialyzer hint, not a runtime check.  See BUG-7 for the
  `badarith` consequence.  Add `Height when Height >= 0` clause head:
- **Impact**: Same as BUG-7; cluster with it.

### BUG-17 (P2) — `check_no_dup_txids/1` uses an O(n) map fold but is invoked on `RestTxs` (excluding coinbase); Core's `bad-txns-duplicate` BIP-22 reason needs uniform mapping

- **File**: `src/beamchain_validation.erl:138-139,744-755`.
- **Core ref**: `bitcoin-core/src/validation.cpp:3854-3856`,
  `bitcoin-core/src/validation.cpp:3845`.
- **Description**: `check_no_dup_txids` excludes the coinbase from
  the duplicate-txid check, citing BIP-34 / height-commitment as the
  reason the coinbase txid is unique.  Correct for BIP-34-active
  heights (mainnet >= 227931, testnet3 >= 21111).  But the BIP-30
  exception pairs (mainnet heights 91842/91880) PRE-DATE BIP-34
  activation and are explicitly grandfathered.  At any height in
  `[1, 91841]` ∪ `[91843, 91879]` ∪ `[91881, 227930]` a duplicate
  COINBASE txid would not be caught by `check_no_dup_txids` (excluded)
  AND would not be caught by BIP-30 (the BIP-30 path checks the UTXO
  set, but the bug in question is two txs with the same txid in
  the SAME block).
- **Impact**: Today: historical (mainnet is past BIP-34 buried at
  227931), and the audit module is a regression-detection layer.  A
  block in `[1, 227930]` with two coinbase-pattern txs sharing a txid
  would not be caught by this gate.  The merkle root check at line
  144 would still catch it (merkle root computed from ALL txs
  including coinbase), so the rejection still happens — but
  via `bad-merkle-root` rather than `bad-txns-duplicate`.  Reason-
  string asymmetry, cross-cite BUG-11 / W125.

### BUG-18 (P3) — `Subsidy + TotalFees` arithmetic in coinbase check is unbounded but bignums make overflow unreachable; comment to clarify

- **File**: `src/beamchain_validation.erl:1311-1315`.
- **Core ref**: `bitcoin-core/src/validation.cpp:2610`
  (`CAmount blockReward = nFees + GetBlockSubsidy(...)`).
- **Description**: Core's `nFees + GetBlockSubsidy(...)` could
  overflow int64 if either were >2^62.  Both are bounded by MAX_MONEY
  (2.1e15 < 2^51), so the sum is bounded by 2*MAX_MONEY < 2^52 — no
  overflow risk.  beamchain inherits the same bounds (per-tx fee
  MoneyRange + accumulated block fee MoneyRange) but the comment at
  line 1311 doesn't cite WHY the sum is safe.
- **Impact**: Documentation only.

### BUG-19 (P3) — Genesis subsidy: `block_subsidy(0, ...)` returns 50 BTC; never reachable on consensus path (genesis short-circuit) — note in comment

- **File**: `src/beamchain_chain_params.erl:392-399`,
  `src/beamchain_validation.erl:1039-1040` (genesis short-circuit).
- **Core ref**: `bitcoin-core/src/validation.cpp:2337-2343`
  (genesis short-circuit; the genesis coinbase output is unspendable
  and never enters the chainstate).
- **Description**: At height 0 the chain-params returns 50 BTC, but
  `connect_block(_Block, 0, ...) -> ok;` short-circuits ALL coinbase
  checks for the genesis block.  This matches Core.  The genesis
  coinbase output (50 BTC paid to satoshi's pubkey) never enters
  the UTXO set in either impl.  Note in a comment that the subsidy
  function returns a value for height 0 that is correct in
  isolation, but is never used by the consensus path.
- **Impact**: Documentation only.  Same for any RPC consumer of
  `block_subsidy(0)` (e.g., `getblockstats`) — they'd report 50 BTC
  for the genesis block which is technically a sanity-value, not the
  actual subsidy enforced.

### BUG-20 (P1) — `?COINBASE_MATURITY = 100` macro shared by both connect-block AND mempool path, but mempool spends a *future* hypothetical block height (TipHeight + 1) — comment-fragile

- **File**: `include/beamchain_protocol.hrl:27`,
  `src/beamchain_validation.erl:1496-1505` (connect-block),
  `src/beamchain_mempool.erl:2290-2299` (mempool).
- **Core ref**: `bitcoin-core/src/consensus/tx_verify.cpp:179`
  (connect-block: `nSpendHeight - coin.nHeight < COINBASE_MATURITY`),
  `bitcoin-core/src/validation.cpp:375`
  (mempool: same check with `mempool_spend_height = ActiveTip()->nHeight + 1`).
- **Description**: Both call-sites use the same `?COINBASE_MATURITY`
  macro but pass a different "spend height" semantic:
  connect-block uses the actual Block Height being connected;
  mempool uses `TipHeight + 1` (the hypothetical NEXT block).  This
  matches Core.  The bug is that **a future refactor that re-uses
  the helper with the wrong height argument would silently produce
  off-by-one** — for example, passing `TipHeight` instead of
  `TipHeight + 1` would let a coinbase be spent one block too early.
- **Excerpt**:
  ```erlang
  %% validation.erl:1496 (connect-block)
  check_coinbase_maturity(InputCoins, Height) -> ...

  %% mempool.erl:2290 (mempool) — passes TipHeight + 1
  check_mempool_coinbase_maturity(InputCoins, NextHeight) ->
      ...
      Confs = NextHeight - Coin#utxo.height,
      Confs >= ?COINBASE_MATURITY ...
  ```
- **Impact**: No bug today (callers pass correct height).  The shared
  macro + similar helper signatures invite a copy-paste mistake.
  Document the semantic difference in a comment header on each helper.

### BUG-21 (P3) — `?INITIAL_SUBSIDY = 5000000000` comment says "50 BTC" but doesn't cite `50 * COIN` form

- **File**: `include/beamchain_protocol.hrl:36`.
- **Core ref**: `bitcoin-core/src/validation.cpp:1846`
  (`CAmount nSubsidy = 50 * COIN;`).
- **Description**: beamchain's macro is `-define(INITIAL_SUBSIDY, 5000000000).
  %% 50 BTC`.  Core hard-codes `50 * COIN` for documentation clarity.
- **Impact**: Cosmetic.  Use `(50 * ?COIN)` for parity readability.

### BUG-22 (P2) — No defence-in-depth check for `Subsidy + TotalFees < 0` (signed-overflow class, CVE-2010-5139 lineage)

- **File**: `src/beamchain_validation.erl:1311-1315`.
- **Core ref**: `bitcoin-core/src/consensus/tx_check.cpp:23-34`
  (the original CVE-2010-5139 fix: per-output `>= 0` and accumulated
  `>= 0`).
- **Description**: After CVE-2010-5139 ("output value of 92,233,720,368.54
  BTC"), Core's defence-in-depth is to check at EVERY layer that values
  are in MoneyRange.  beamchain checks per-output MoneyRange in
  `check_transaction`, per-input MoneyRange in the connect-block fold,
  per-tx-fee MoneyRange, accumulated-fee MoneyRange — but the FINAL
  reward (`Subsidy + TotalFees`) is computed as a bare addition with
  no MoneyRange assertion.  Bignum-safe in Erlang (cannot wrap), but
  Core-parity demands one extra `MoneyRange(blockReward)` check.
- **Excerpt**:
  ```erlang
  %% 5. verify block subsidy
  Subsidy = beamchain_chain_params:block_subsidy(Height, Network),
  CbValue = lists:foldl(fun(#tx_out{value = V}, A) -> A + V end,
                        0, CoinbaseTx#transaction.outputs),
  CbValue =< Subsidy + TotalFees orelse throw(bad_cb_amount),
  ```
- **Impact**: Defence-in-depth gap.  Cannot fire today (`Subsidy <=
  50e8 < 2^33`, `TotalFees <= MAX_MONEY < 2^51`, sum < 2^52).  But the
  CVE-2010-5139 lineage demands that EVERY summation be checked.
  Add `(Subsidy + TotalFees) =< 2 * ?MAX_MONEY orelse throw(...)`
  or fold into the per-block accumulated-fee MoneyRange check.

---

## Gate-by-gate matrix

| Gate | Core ref | beamchain ref | Status | Bug(s) |
|------|----------|---------------|--------|--------|
| `GetBlockSubsidy(0)` = 50 BTC | validation.cpp:1846 | chain_params.erl:398 | PRESENT | — |
| `Halvings = nHeight / interval` | validation.cpp:1841 | chain_params.erl:395 | PRESENT | — |
| `Halvings >= 64 → 0` (UB guard) | validation.cpp:1843 | chain_params.erl:396 | PRESENT | BUG-2 |
| `nSubsidyHalvingInterval` mainnet = 210000 | chainparams.cpp:84 | chain_params.erl:37 | PRESENT | — |
| `nSubsidyHalvingInterval` testnet3 = 210000 | chainparams.cpp:209 | chain_params.erl:118 | PRESENT | — |
| `nSubsidyHalvingInterval` testnet4 = 210000 | chainparams.cpp:310 | chain_params.erl:166 | PRESENT | — |
| `nSubsidyHalvingInterval` signet = 210000 | chainparams.cpp:454 | chain_params.erl:258 | PRESENT | — |
| `nSubsidyHalvingInterval` regtest = 150 | chainparams.cpp:535 | chain_params.erl:215 | PRESENT | — |
| Single canonical halving constant | (n/a in C++ via Consensus::Params) | (two-pipeline) | PARTIAL | BUG-1 |
| Subsidy returns 0 after 64 halvings | validation.cpp:1843 | tests cover 13_440_000 → 0 | PRESENT | — |
| Coinbase = sum(outputs) ≤ subsidy + fees | validation.cpp:2611 | validation.erl:1315 | PRESENT | BUG-22 (DiD) |
| `bad-cb-amount` reason string | validation.cpp:2612 | atom `bad_cb_amount` | PARTIAL | BUG-11 |
| COINBASE_MATURITY = 100 | consensus.h:19 | protocol.hrl:27 | PRESENT | — |
| Coinbase maturity gate (`< 100 → reject`) | tx_verify.cpp:179 | validation.erl:1501 | PRESENT | BUG-20 |
| Coinbase maturity in mempool (TipHeight+1) | validation.cpp:375 | mempool.erl:2294 | PRESENT | BUG-20 |
| MAX_MONEY = 21e6 * 1e8 | amount.h:26 | protocol.hrl:23 | PRESENT | BUG-9 |
| MoneyRange two-sided | amount.h:27 | mixed | PARTIAL | BUG-3, 12 |
| Per-output `nValue >= 0` (CVE-2010-5139) | tx_check.cpp:27 | validation.erl:552 | PRESENT | — |
| Per-output `nValue <= MAX_MONEY` | tx_check.cpp:29 | validation.erl:553 | PRESENT | — |
| Accumulated output MoneyRange | tx_check.cpp:31-33 | validation.erl:557-562 | PRESENT | — |
| Duplicate inputs (CVE-2018-17144) | tx_check.cpp:41-44 | validation.erl:605-610 | PRESENT | BUG-10 |
| Duplicate inputs early (before UTXO lookup) | tx_check.cpp:42 | validation.erl:565 (check_tx) | PRESENT | — |
| Coinbase scriptSig length 2..100 | tx_check.cpp:49 | validation.erl:574 + :344 | PRESENT | BUG-14, 15 |
| Non-coinbase: no null prevout | tx_check.cpp:55 | validation.erl:578-583 | PRESENT | BUG-5 |
| Fee = `nValueIn - value_out >= 0` | tx_verify.cpp:196 | validation.erl:1205 | PRESENT | — |
| `bad-txns-in-belowout` | tx_verify.cpp:197 | validation.erl:1205 | PRESENT | — |
| Per-coin input MoneyRange | tx_verify.cpp:186 | validation.erl:1192 | PRESENT | — |
| Accumulated input MoneyRange | tx_verify.cpp:186 | validation.erl:1195 + mempool:4243 | PARTIAL | BUG-3 |
| Per-tx fee MoneyRange (defence-in-depth) | tx_verify.cpp:203 | validation.erl:1239 + mempool:649,924 | PARTIAL | BUG-12 |
| Accumulated block-fee MoneyRange | validation.cpp:2543-2547 | validation.erl:1246 | PRESENT | — |
| IsCoinBase (`vin.size()==1 && prevout.IsNull()`) | transaction.h:343 | validation.erl:600-602 | PRESENT | BUG-4, 13 |
| Single-callsite `GetBlockSubsidy` (no duplicate) | validation.cpp:1839 | duplicated in rpc.erl:2156 | PARTIAL | BUG-1, 8 |

32 gates audited / 17 PRESENT / 9 PARTIAL / 6 MISSING (the 6 MISSING are
captured under BUG-3 (mempool MoneyRange asymmetric), BUG-11 / 15
(reason-string mapping), BUG-22 (`MoneyRange(blockReward)` defence-in-depth),
BUG-7 / 16 (negative-Height guard), BUG-6 (generateblock fee accounting)).

---

## Fleet-pattern smell

- **Two-pipeline guard (15th distinct extension fleet-wide; 1st on
  subsidy/fees axis)** — BUG-1.  beamchain has TWO independent
  per-network params modules: `beamchain_chain_params` (validation +
  miner) and `beamchain_config` (RPC + CLI).  Each declares
  `subsidy_halving_interval` separately; `beamchain_rpc.erl:2156-2164`
  even re-implements `GetBlockSubsidy` locally with its own
  `(50 * 100000000)` literal instead of `?INITIAL_SUBSIDY`.
- **Comment-as-confession (5th instance fleet-wide; 1st on subsidy/fees
  axis)** — BUG-6.  `beamchain_miner.erl:1010-1014` literally reads
  *"In a real impl, would compute fee from inputs-outputs / For
  generateblock, caller is responsible for valid txs"*.  Consensus-valid
  under-claim but semantically broken for test fixtures.
- **Reason-string asymmetry on consensus-reject path** — BUG-5, 11, 15.
  beamchain emits Erlang atoms (`bad_cb_amount`, `null_input`,
  `bad_coinbase_length`) that, after underscore→hyphen substitution,
  do NOT match the Core wire strings (`bad-cb-amount`,
  `bad-txns-prevout-null`, `bad-cb-length`).  Cross-cite W125.
- **Defence-in-depth gap on the final reward summation** — BUG-22.
  Bignum-safe in Erlang (no overflow possible), so no runtime bug; but
  Core's CVE-2010-5139 contract is that EVERY summation be MoneyRange-
  checked.  The single-extra-check fix is one line.
- **NO P0-CONSENSUS / P0-CDIV finding fired** — the subsidy/fees/
  MAX_MONEY perimeter in beamchain is the most-thoroughly-checked
  consensus surface, and the canonical arithmetic is in place.  The
  22 bugs catalogued here are all either reason-string-asymmetry,
  documentation gaps, two-pipeline divergence, or defence-in-depth
  redundancy.  No chain-split candidate.

---

## Cross-references

- W76 — two-pipeline framing (origin).
- W125 — RPC error parity (`submitblock` reason-string mapping).
- W126 — BIP-152 compact-block fee re-verification.
- W129 — coin selection / wallet fee rounding (input side).
- W139 — fee estimation (the consensus floor under every estimator).
- W142 — SegWit witness validation (BUG-21 stricter-than-Core tx weight,
  BUG-5 O(n log n) `lists:usort` for `check_no_dup_txids`).
- _reorg-via-submitblock-fleet-result — Pattern Y origin of the
  "structurally unreachable path" framing.
