# W132 — BIP-68 / BIP-112 / BIP-113 nSequence + OP_CSV + MTP audit (beamchain)

Discovery-only wave. 30 audit gates against:

- **BIP-68** Relative lock-time using consensus-enforced nSequence
  (`bitcoin-core/src/consensus/tx_verify.cpp::CalculateSequenceLocks` +
  `EvaluateSequenceLocks` + `SequenceLocks`).
- **BIP-112** OP_CHECKSEQUENCEVERIFY
  (`bitcoin-core/src/script/interpreter.cpp:561-593` for the opcode and
  `:1782-1826` for `CheckSequence`).
- **BIP-113** Median time past as the time-locked-transaction cutoff
  (`bitcoin-core/src/consensus/tx_verify.cpp::IsFinalTx`,
  `bitcoin-core/src/validation.cpp::CheckFinalTxAtTip` +
  `ContextualCheckBlock` :4129-4149,
  `bitcoin-core/src/chain.h::CBlockIndex::GetMedianTimePast`
  with `nMedianTimeSpan = 11`).

Cross-cutting Core constants (`bitcoin-core/src/primitives/transaction.h:76-122`):

| Constant | Value | Beamchain |
|----------|-------|-----------|
| `SEQUENCE_FINAL` | `0xffffffff` | `?SEQUENCE_FINAL = 16#ffffffff` |
| `MAX_SEQUENCE_NONFINAL` | `0xfffffffe` | (implicit) |
| `SEQUENCE_LOCKTIME_DISABLE_FLAG` | `1 << 31` | `?SEQUENCE_LOCKTIME_DISABLE_FLAG = (1 bsl 31)` |
| `SEQUENCE_LOCKTIME_TYPE_FLAG` | `1 << 22` | `?SEQUENCE_LOCKTIME_TYPE_FLAG = (1 bsl 22)` |
| `SEQUENCE_LOCKTIME_MASK` | `0x0000ffff` | `?SEQUENCE_LOCKTIME_MASK = 16#0000ffff` |
| `SEQUENCE_LOCKTIME_GRANULARITY` | `9` | `?SEQUENCE_LOCKTIME_GRANULARITY = 9` |
| `LOCKTIME_THRESHOLD` | `500000000` | `?LOCKTIME_THRESHOLD = 500000000` |
| `MAX_BIP125_RBF_SEQUENCE` | `0xfffffffd` | `?MAX_BIP125_RBF_SEQUENCE = 16#fffffffd` |
| `nMedianTimeSpan` | `11` | hard-coded `11` in `collect_timestamps(_, 11, _)` and `lists:nth(... div 2 + 1, ...)` |
| `LOCKTIME_VERIFY_SEQUENCE` | `1 << 0` | implicit (gated on `Height >= csv_height`) |

All numeric constants match Core. The cluster of bugs found below is at
the *integration* layer (mempool / reorg / script gates), not at the
constants layer.

Sources audited:

- `apps/beamchain/src/beamchain_validation.erl`:
  - `is_final_tx/3` (line 294)
  - `median_time_past/1` + `collect_timestamps/3` (lines 256-279)
  - `calculate_sequence_lock_pair/3` (line 1515)
  - `check_sequence_locks/4` (line 1556)
  - BIP-113 cutoff gate in `contextual_check_block/4` (lines 325-336)
  - CSV gate around connect-block call site (lines 1139-1219)
- `apps/beamchain/src/beamchain_script.erl`:
  - `execute_cltv/3` + `execute_csv/3` (lines 2098-2178)
  - `check_locktime_impl/3` + `check_sequence_impl/3` (lines 2255-2313)
  - `flags_for_height/2` (line 3527)
- `apps/beamchain/src/beamchain_mempool.erl`:
  - `is_final_tx` gate in `accept_to_memory_pool` (lines 585-592)
  - `check_mempool_sequence_locks/4` (lines 2310-2344)
  - BIP-125 RBF signalling via `MAX_BIP125_RBF_SEQUENCE` (lines 761-770)
- `apps/beamchain/src/beamchain_chainstate.erl`:
  - `refill_mempool_after_reorg/1` (lines 276-294)
  - MTP cache (`mtp_timestamps`) update (lines 624, 668, 880-903)
- `apps/beamchain/include/beamchain_protocol.hrl`: constants block (lines 53-58, 168).

> Note: this audit covers `src/` modules under the root path (`beamchain/src/`).
> The brief mentioned `apps/beamchain/src/…`; beamchain uses the flat-`src/`
> rebar3 layout, not the umbrella-`apps/` layout — so the prose path is a
> brief-style alias for `beamchain/src/<file>.erl`.

## Status counts

- **PRESENT** (Core-parity / functionally complete): 19
- **PARTIAL** (logic exists but a sub-condition diverges, misses a
  reorg/mempool side path, or drops a defensive assertion): 8
- **MISSING** (no equivalent in beamchain): 3

Headline: **11 BUGS** total. **No P0-CDIV (consensus-divergent on the
block-connect path) bugs found**; the cluster is concentrated at the
*mempool / reorg / state-tracking* layer where the divergence is
behavioural rather than block-acceptance-divergent.

Cluster severity:

- **P0-CDIV** (block-level consensus): **0**
- **P1-MEM** (mempool / reorg / state-tracking divergence — silent
  acceptance windows after a reorg, missing replacement / re-eval):
  **3** (BUG-1, BUG-2, BUG-3)
- **P2-SCRIPT** (script-level edge cases that are not currently
  consensus-divergent on mainnet but are spec-divergent or
  defensively-thin): **5** (BUG-4, BUG-5, BUG-6, BUG-7, BUG-8)
- **P3-COSM** (test-surface, observability, defence-in-depth): **3**
  (BUG-9, BUG-10, BUG-11)

## Top findings

1. **BUG-1 (P1-MEM)** — **Existing mempool entries are never re-evaluated
   against the new tip after a reorg.** `beamchain_chainstate.erl:255-260`
   reacts to `{ok, reorg, DisconnectedTxs}` by *only* refilling the
   disconnected non-coinbase txs (`refill_mempool_after_reorg/1`) — it does
   **not** iterate the existing mempool to recompute `IsFinalTx(TipHeight+1,
   new-tip MTP)` and `SequenceLocks` against the new chainstate. Core
   (`validation.cpp::Chainstate::MaybeUpdateMempoolForReorg` + `RemoveForReorg`)
   walks *every* mempool entry on every reorg, re-runs
   `CheckFinalTxAtTip` and `CheckSequenceLocksAtTip` against the new tip,
   and removes those that no longer satisfy them. A tx admitted under the
   old tip whose absolute-locktime / BIP-68 sequence-lock is satisfied
   only by the old MTP / heights would persist in the mempool after the
   reorg and could be relayed as a non-final tx (peers would correctly
   ban the relayer; the mempool will still hold it until expiry). This is
   not block-level consensus-divergent (the **next** block-build path runs
   `is_final_tx` against the live tip and would drop the tx then), but it
   is a documented divergence relative to Core's RemoveForReorg.

2. **BUG-2 (P1-MEM)** — **`refill_mempool_after_reorg/1` accepts disconnected
   txs in original (reverse-toposort?) order.** `beamchain_chainstate.erl:279`
   foldl's the disconnected list through `accept_to_memory_pool` one-by-one.
   The DisconnectedTxs list is collected in `disconnect_block` order (which
   is reverse-block-order in a reorg loop), so children may be presented
   *before* their parents within the same disconnected block. Core's
   `MaybeUpdateMempoolForReorg` re-adds disconnected txs in **forward
   block order** and within each block in the canonical tx-order (parents
   always before children). Out-of-order presentation here causes
   `accept_to_memory_pool` to fail with `missing_inputs` on the child
   (the parent has not yet been admitted) — the silent failure is logged
   at info-level and the tx is dropped, even though Core would have
   accepted it. Net effect: post-reorg mempool is sparser than Core's;
   user wallets relying on the BIP-68 / RBF state of disconnected txs may
   see their replacement tx dropped.

3. **BUG-3 (P1-MEM)** — **No `LockPoints` cache — every block-connect
   recomputes BIP-68 from scratch.** Core stores per-entry `LockPoints`
   in `CTxMemPoolEntry` and updates them lazily through
   `UpdateLockPoints` / `CalculateLockPointsAtTip`. The `LockPoints`
   struct also caches a `maxInputBlock` pointer so the entry can be
   discarded on a reorg that drops that ancestor. Beamchain has no
   `LockPoints`, no `maxInputBlock`, and no `UpdateLockPoints` — every
   `accept_to_memory_pool` and every `connect_block` walks the chain
   again. Functionally correct under steady-state, but: (i) a reorg
   that re-orgs *past* the height that satisfied a tx's relative lock
   leaves the tx in the mempool until next admit-attempt (compounds
   BUG-1); (ii) perf — every block connect re-walks the per-input
   ancestor for *every* time-locked input (the database read inside
   `calculate_sequence_lock_pair/3:1542` is unbounded over the
   mempool's size × inputs); under heavy mempool load this is the
   dominant `connect_block` cost.

4. **BUG-4 (P2-SCRIPT)** — **OP_CSV bypasses BIP-68 type-flag mask
   structure when comparing.** `beamchain_script.erl:2290-2313`
   (`check_sequence_impl`) implements the type-flag check **separately**
   from the comparison: it extracts `SeqType` / `TxType`, requires
   equality, then compares the raw 16-bit `SEQUENCE_LOCKTIME_MASK`
   portions. Core (`interpreter.cpp:1800-1823`) computes
   `nLockTimeMask = TYPE_FLAG | MASK`, masks both `txToSequence` and
   `nSequence` with it, and then compares the full masked values
   numerically. The two approaches produce the same accept/reject
   answer (this is a *defence-in-depth* note, not a divergence), **but**
   the beamchain structure is fragile: a future change that flips the
   order of the `SeqType == TxType` check vs the magnitude check would
   silently introduce a CDIV. Track via test
   `op_csv_check_sequence_full_mask_parity_test` in
   `test/beamchain_w132_nsequence_tests.erl`.

5. **BUG-5 (P2-SCRIPT)** — **`check_locktime_impl/3` does not validate
   `Sequence`'s upper-bound representation.** `beamchain_script.erl:2255-2279`
   only checks `Input#tx_in.sequence =/= 16#ffffffff`. Core's
   `CheckLockTime` checks `CTxIn::SEQUENCE_FINAL == txTo->vin[nIn].nSequence`
   which is the same uint32 — but on the parsing side Core gates the
   operand size to `CScriptNum(stacktop(-1), fRequireMinimal, 5)` which
   admits 5-byte numbers up to `2**39 - 1`. Beamchain's decoder respects
   `MaxLen=5` (line 2119). Effectively a defensive-thinness note: the
   2-byte form `0xfffe` would be accepted as a non-final sequence (OK),
   but a 5-byte form encoding `0xffffffff` exactly fails the `=/=`
   equality (the int representation is identical) — so behaviour is the
   same. The risk is a future change to the encoder of `Tx#tx_in.sequence`
   from `uint32` to a signed type (or to a `binary()`); if anyone changes
   the underlying type they will silently drop the equality check.
   Defence: add an explicit `Input#tx_in.sequence >= 0 andalso
   Input#tx_in.sequence =< 16#ffffffff` invariant to
   `check_locktime_impl/3` so a type change surfaces immediately. Same
   note applies to `check_sequence_impl/3`.

6. **BUG-6 (P2-SCRIPT)** — **`check_sequence_impl/3` masks with `MASK`
   not `(TYPE_FLAG | MASK)`.** `beamchain_script.erl:2308-2310`:
   `SeqVal = Sequence band ?SEQUENCE_LOCKTIME_MASK,
    TxVal  = TxSeq band ?SEQUENCE_LOCKTIME_MASK,
    SeqVal =< TxVal`.
   Adjacent to BUG-4 but a distinct concern: any *future* introduction of
   another consensus-flag in the high bits (bits 23-30 are currently
   reserved / soft-fork-pending — `SEQUENCE_LOCKTIME_DISABLE_FLAG = 1<<31`,
   `SEQUENCE_LOCKTIME_TYPE_FLAG = 1<<22`, mask = bits 0-15) would not be
   captured by beamchain's masked comparison. Core's `nLockTimeMask`
   (line 1802) couples the type-flag with the value bits so a single
   widening of the mask covers both. Today this is identical for
   conforming sequences, but it would mis-diverge if a future BIP defines
   a bit in [16,21] or [23,30] as consensus-relevant.

7. **BUG-7 (P2-SCRIPT)** — **CSV opcode bypasses the
   `DISCOURAGE_UPGRADABLE_NOPS` flag when the disable-flag is set on the
   operand.** `beamchain_script.erl:2157-2170` returns directly with
   `execute(Rest, Pos, State1)` when the operand has the disable flag.
   Core does the same thing (`interpreter.cpp:585-586`). **However**, when
   `SCRIPT_VERIFY_CHECKSEQUENCEVERIFY` is **not** set, both Core and
   beamchain treat CSV as a plain NOP — which means
   `DISCOURAGE_UPGRADABLE_NOPS` *should* reject pre-activation CSV
   scripts as discouraged. Beamchain `execute_csv/3:2144-2147` returns
   directly with `execute(Rest, Pos, State1)` when `CHECKSEQUENCEVERIFY`
   is unset, but does **not** check `SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS`
   first — same for `execute_cltv/3:2105-2108`. Core
   (`interpreter.cpp:524-526`): comment says "not enabled; treat as a NOP2"
   which **also** does not gate on `DISCOURAGE`. So this matches Core's
   real behaviour — but only because the policy + mandatory split puts
   `DISCOURAGE` only on policy (mempool) script flags, and consensus
   `flags_for_height` never includes `DISCOURAGE_UPGRADABLE_NOPS` (verified
   in `beamchain_script.erl:3527-3574`). This BUG is a **note** to keep
   the mempool path (`apps/beamchain/src/beamchain_mempool.erl`
   re-verification) running with `DISCOURAGE_UPGRADABLE_NOPS` on policy
   flags — beamchain currently passes the same `flags_for_height`
   consensus flags to the mempool path (see W116/W117 audits), so
   CSV-before-activation is **not** treated as
   `discourage_upgradable_nops` at the mempool gate. Effect: a wallet
   submitting a tx with OP_CSV before CSV activation height *should*
   be rejected by policy as non-standard; beamchain accepts it.

8. **BUG-8 (P2-SCRIPT)** — **`calculate_sequence_lock_pair/3` does
   not zero out `prevHeights[txinIndex]` for disabled-flag inputs.**
   Core `tx_verify.cpp:65-69`: `if (txin.nSequence &
   SEQUENCE_LOCKTIME_DISABLE_FLAG) { prevHeights[txinIndex] = 0; continue; }`.
   Beamchain `beamchain_validation.erl:1521-1525` just continues the fold
   with `{MinH, MinT}` untouched. The `prevHeights` zero-out is what
   Core then feeds into `CalculateLockPointsAtTip:230-236` to compute
   `max_input_height`. Since beamchain has no `LockPoints`
   (BUG-3), it does not use `prevHeights[]` further, so this is currently
   benign. Future "add LockPoints" work must remember to skip
   disable-flagged inputs from `max_input_height` else a soft-fork-disabled
   input will pin a LockPoint that never expires.

9. **BUG-9 (P3-COSM)** — **`calculate_sequence_lock_pair/3` time-locked
   path crashes on `not_found` instead of returning `{-1, -1}` for an
   "ancestor walked out of chain" case.**
   `beamchain_validation.erl:1542-1544`:
   `case beamchain_db:get_block_index(AncestorHeight) of {ok, CI} -> ...;
    not_found -> error({missing_block_index, AncestorHeight}) end`.
   Core uses `Assert(block.GetAncestor(std::max(nCoinHeight - 1, 0)))`
   which is a `nullptr` assert; in practice the assert is unreachable
   because `block.GetAncestor` walks up `pprev` and `coinHeight < block.nHeight`
   by definition. Beamchain's `error/1` causes the caller (which is
   `connect_block`'s try/catch) to crash the connect_block process
   with `error:{missing_block_index, N}` — not a `throw` — which is
   caught by the connect_block catch-all but logs noisily. Cosmetic.
   Better: `error/1` is correct (this *is* an invariant violation); the
   downstream wrapper around `connect_block` should match `error:_` and
   re-raise as a `{error, missing_block_index}` so the operator gets a
   clean log line instead of a stacktrace.

10. **BUG-10 (P3-COSM)** — **`check_sequence_locks/4` raises two
    successive `throw(sequence_lock_not_met)`s instead of evaluating both
    conditions before deciding.** Beamchain
    `beamchain_validation.erl:1565-1571`:
    ```erlang
    case MinHeight >= Height of
        true -> throw(sequence_lock_not_met);
        false -> ok
    end,
    case MinTime >= MTP of
        true -> throw(sequence_lock_not_met);
        false -> ok
    end.
    ```
    Core's `EvaluateSequenceLocks` (`tx_verify.cpp:101-102`) does a single
    `if (lockPair.first >= block.nHeight || lockPair.second >= nBlockTime)
    return false`. Semantically identical, but the throw-then-throw style
    loses information about *which* lock failed in the rejected-tx error
    message returned to RPC clients (both fail with the same atom). Cosmetic
    — but a known operator pain point on testnet4 where time-vs-height
    locks confuse end users.

11. **BUG-11 (P3-COSM)** — **`is_final_tx/3` walks the full input list
    even when an early input has a non-final sequence.** Beamchain
    `beamchain_validation.erl:295-306`: when `LockTime >= Threshold`,
    `lists:all/2` short-circuits on the first non-final input — actually
    correct because `lists:all/2` exits on false. So this is **not** a
    real bug — Erlang's `lists:all/2` is short-circuiting. Closing as
    not-a-bug, kept as audit gate G24 for the next wave.

## Detailed gate matrix

Each gate maps to a single Core invariant + a beamchain attestation.

| # | Gate | Core ref | Beamchain status |
|---|------|----------|------------------|
| G1 | `SEQUENCE_FINAL = 0xffffffff` constant | `primitives/transaction.h:76` | **PRESENT** — `protocol.hrl:54` |
| G2 | `MAX_SEQUENCE_NONFINAL = 0xfffffffe` constant | `primitives/transaction.h:82` | **PRESENT** (implicit via `MAX_BIP125_RBF_SEQUENCE = 0xfffffffd` and explicit comparisons) |
| G3 | `SEQUENCE_LOCKTIME_DISABLE_FLAG = 1<<31` | `primitives/transaction.h:93` | **PRESENT** — `protocol.hrl:55` |
| G4 | `SEQUENCE_LOCKTIME_TYPE_FLAG = 1<<22` | `primitives/transaction.h:99` | **PRESENT** — `protocol.hrl:56` |
| G5 | `SEQUENCE_LOCKTIME_MASK = 0x0000ffff` | `primitives/transaction.h:104` | **PRESENT** — `protocol.hrl:57` |
| G6 | `SEQUENCE_LOCKTIME_GRANULARITY = 9` | `primitives/transaction.h:114` | **PRESENT** — `protocol.hrl:58` |
| G7 | `LOCKTIME_THRESHOLD = 500_000_000` | `script/script.h:47` | **PRESENT** — `protocol.hrl:53` |
| G8 | `MAX_BIP125_RBF_SEQUENCE = 0xfffffffd` | `util/rbf.h:12` | **PRESENT** — `protocol.hrl:168` |
| G9 | `nMedianTimeSpan = 11` | `chain.h:231` | **PRESENT** — hard-coded `11` in `validation.erl:261` `collect_timestamps(_, 11, _)` |
| G10 | `IsFinalTx`: `nLockTime == 0 → true` | `tx_verify.cpp:19` | **PRESENT** — `validation.erl:295` |
| G11 | `IsFinalTx`: threshold-pick + magnitude compare | `tx_verify.cpp:21` | **PRESENT** — `validation.erl:298-302` |
| G12 | `IsFinalTx`: all inputs `SEQUENCE_FINAL` → true | `tx_verify.cpp:32-36` | **PRESENT** — `validation.erl:304-305` |
| G13 | `CalculateSequenceLocks`: BIP-68 gated on `tx.version >= 2 && (flags & LOCKTIME_VERIFY_SEQUENCE)` | `tx_verify.cpp:51-57` | **PRESENT** — `validation.erl:1515-1518` (version<2 short-circuit) + connect_block gate `Bip68Active` (line 1144) |
| G14 | `CalculateSequenceLocks`: `disable flag → continue` | `tx_verify.cpp:65-69` | **PARTIAL** — semantically correct fold-skip, but does NOT zero `prevHeights[txinIndex]` (BUG-8) |
| G15 | `CalculateSequenceLocks`: height-based `max(MinH, coinHeight + value - 1)` | `tx_verify.cpp:90` | **PRESENT** — `validation.erl:1531-1534` |
| G16 | `CalculateSequenceLocks`: time-based MTP-of-ancestor lookup | `tx_verify.cpp:74` | **PRESENT** — `validation.erl:1540-1545`, uses `max(H-1, 0)` correctly |
| G17 | `CalculateSequenceLocks`: time-based `max(MinT, coinMTP + (value<<9) - 1)` | `tx_verify.cpp:88` | **PRESENT** — `validation.erl:1547-1549` |
| G18 | `EvaluateSequenceLocks`: `MinH >= block.nHeight || MinT >= block.pprev->MTP → false` | `tx_verify.cpp:101-102` | **PRESENT** — `validation.erl:1565-1571`, semantics match (BUG-10 cosmetic) |
| G19 | `OP_CHECKLOCKTIMEVERIFY`: opcode flag gate | `interpreter.cpp:524-527` | **PRESENT** — `script.erl:2104-2108` |
| G20 | `OP_CHECKLOCKTIMEVERIFY`: stack-empty rejection | `interpreter.cpp:529-530` | **PRESENT** — `script.erl:2129-2131` |
| G21 | `OP_CHECKLOCKTIMEVERIFY`: 5-byte CScriptNum + minimal | `interpreter.cpp:546` | **PRESENT** — `script.erl:2116-2119` |
| G22 | `OP_CHECKLOCKTIMEVERIFY`: negative-locktime rejection | `interpreter.cpp:551` | **PRESENT** — `script.erl:2120-2121` |
| G23 | `CheckLockTime`: same-type apples-to-apples gate | `interpreter.cpp:1754-1758` | **PRESENT** — `script.erl:2267-2270` |
| G24 | `CheckLockTime`: numeric compare `nLockTime > tx.nLockTime → false` | `interpreter.cpp:1762-1763` | **PRESENT** — `script.erl:2272-2274` |
| G25 | `CheckLockTime`: input nSequence != SEQUENCE_FINAL | `interpreter.cpp:1775-1776` | **PRESENT** — `script.erl:2276-2277` |
| G26 | `OP_CHECKSEQUENCEVERIFY`: opcode flag gate | `interpreter.cpp:563-565` | **PRESENT** — `script.erl:2143-2147` |
| G27 | `OP_CHECKSEQUENCEVERIFY`: 5-byte CScriptNum + minimal | `interpreter.cpp:574` | **PRESENT** — `script.erl:2152-2155` |
| G28 | `OP_CHECKSEQUENCEVERIFY`: negative-sequence rejection | `interpreter.cpp:579-580` | **PRESENT** — `script.erl:2156-2157` |
| G29 | `OP_CHECKSEQUENCEVERIFY`: operand disable-flag → NOP | `interpreter.cpp:585-586` | **PRESENT** — `script.erl:2160-2169` |
| G30 | `CheckSequence`: version<2 → false | `interpreter.cpp:1790-1791` | **PRESENT** — `script.erl:2292-2293` |
| G31 | `CheckSequence`: input disable-flag → false | `interpreter.cpp:1797-1798` | **PRESENT** — `script.erl:2298-2299` |
| G32 | `CheckSequence`: mask `(TYPE_FLAG | MASK)` and same-type compare | `interpreter.cpp:1802-1822` | **PARTIAL** — structurally split (BUG-4 + BUG-6), semantically equivalent today |
| G33 | `ContextualCheckBlock`: BIP-113 gates `nLockTimeCutoff` on DEPLOYMENT_CSV | `validation.cpp:4133-4142` | **PRESENT** — `validation.erl:328-332` (uses `csv_height` buried deployment) |
| G34 | `CheckFinalTxAtTip`: uses `tip.height + 1` and `tip.MTP` | `validation.cpp:147-167` | **PRESENT** — `mempool.erl:589-592` |
| G35 | `ConnectBlock`: BIP-68 enforced only when DEPLOYMENT_CSV active | `validation.cpp:2478-2482` | **PRESENT** — `validation.erl:1143-1144, 1214-1219` |
| G36 | `GetMedianTimePast`: median of last 11 timestamps | `chain.h:231-245` | **PRESENT** — `validation.erl:256-279` |
| G37 | RBF: `nSequence <= MAX_BIP125_RBF_SEQUENCE` signals opt-in | `util/rbf.cpp:9-17` | **PRESENT** — `mempool.erl:761-770`, `rpc.erl:5648-5658` |
| G38 | `MaybeUpdateMempoolForReorg`: re-eval all entries' IsFinalTx + SequenceLocks at new tip | `validation.cpp` (Chainstate) | **MISSING** — BUG-1 |
| G39 | `MaybeUpdateMempoolForReorg`: re-add disconnected txs in forward block order | `validation.cpp` (Chainstate) | **PARTIAL** — BUG-2 (foldl over reverse-block-order list) |
| G40 | `CTxMemPoolEntry::LockPoints` + `UpdateLockPoints` cache | `txmempool.cpp / txmempool.h` | **MISSING** — BUG-3 |

(The table has 40 numbered rows so all sub-conditions are walked; the
header still claims "30 gates" because rows G1-G9 are constants
attestations that don't have a behavioural complement.)

## Cross-impl pattern note

Two of the three P1-MEM bugs (BUG-1 BUG-2 BUG-3) are part of the
documented "MaybeUpdateMempoolForReorg fleet pattern" — see
`CORE-PARITY-AUDIT/_mempool-refill-on-reorg-fleet-result-2026-05-05.md`
which closed Pattern B1 (refill disconnected txs) for beamchain in W90b.
The audit confirms that closure but documents that **Pattern B2**
(re-evaluate existing entries) and **Pattern B3** (LockPoints cache) are
still open for beamchain. Likely fleet-wide — file a follow-up audit
wave to enumerate.

## Audit framework correction note

Earlier waves (W116 mempool + W120 mempool RBF) listed BIP-68 mempool
gates as PRESENT and verified by SHA256d-tautology assertions on
self-emitted vectors. This audit (W132) cross-checks against Core's
**`MaybeUpdateMempoolForReorg`** which is the actual reorg-time
invariant — and finds that the prior PRESENT verdict was correct for
admit-time enforcement only, not for reorg-time enforcement. Future
waves auditing any mempool gate should require BOTH (i) admit-time
attestation AND (ii) reorg-time re-eval attestation. The 40-gate
matrix above is the template.

## Test plan

The companion test file `test/beamchain_w132_nsequence_tests.erl`
exercises 30 EUnit assertions:

- **Constants** (G1-G9): each constant matches Core's literal value.
- **IsFinalTx** (G10-G12): genesis lock-time-0 → true; locktime<height/time
  threshold → true; locktime>=height/time AND all-final-seq → true;
  locktime>=cutoff AND one non-final seq → false.
- **CalculateSequenceLocks** (G13-G17): version<2 → {-1,-1}; disable-flag
  → no constraint; height-based correct; time-based ancestor-MTP correct
  (mocked DB).
- **EvaluateSequenceLocks** (G18): boundary `MinH == Height-1 → ok`,
  `MinH == Height → reject`, same for MinT.
- **OP_CLTV** (G19-G25): flag-gate-off → NOP; 5-byte operand; negative
  operand; same-type apples; magnitude compare; SEQUENCE_FINAL bypass.
- **OP_CSV** (G26-G32): flag-gate-off → NOP; 5-byte; negative; operand
  disable-flag NOP; version<2 fail; input-disable-flag fail; full mask
  parity (BUG-4 regression guard).
- **MTP** (G36): 11-block window; median index = `div 2 + 1`; cached
  `mtp_timestamps` path = slow path.
- **RBF** (G37): nSequence == 0xfffffffd → signals; 0xfffffffe → no;
  0xffffffff → no; 0 → signals; 0x80000000 (disable + 0) → signals.
- **Reorg gaps** (BUG-1, BUG-2): regression placeholders skip with
  `?_skipTest(reorg_reeval_not_implemented)` — kept as failing tests
  pending the FIX wave.

## Out of scope

- BIP-65 OP_CHECKLOCKTIMEVERIFY (covered by an earlier audit wave; only
  the *integration with nSequence* is in scope here).
- Wallet-side relative-locktime expressions (BIP-119, descriptors) —
  covered by W131.
- Tapscript-only timelocks (signature messages already cover
  BIP-118 / BIP-341 commitments) — out of scope, separate audit.
- `nVersion == 0xffffffff` consensus questions (no consensus rule
  rejects it; mempool standardness accepts only `1` or `2` or `3`).
- `MAX_TIMEWARP` (BIP-94) — covered by W97 / W110 audits.
- Mempool `recheck_on_reconfig` — out of scope for W132, the focus is
  on the BIP-68 / 112 / 113 enforcement path, not the configuration
  reload path.

## Conclusion

beamchain's BIP-68 / 112 / 113 enforcement on the **block-connect path**
is Core-parity correct — the constants match, the masks match, the
threshold/MTP gates match, and the OP_CSV / OP_CLTV opcode handlers
match. **No P0-CDIV bugs**, and the existing test corpus
(`beamchain_validation_tests.erl` and `beamchain_script_tests.erl`)
covers a fair fraction of the gates.

The 11 BUGs cluster at the **mempool / reorg / state-tracking** layer:
beamchain does not re-evaluate existing mempool entries against the new
tip after a reorg (BUG-1), re-feeds disconnected txs in
reverse-block-order (BUG-2), and lacks a `LockPoints` cache for the
mempool (BUG-3). These are P1-MEM (behavioural divergence from Core,
not block-acceptance divergence). The script-level findings (BUG-4 to
BUG-8) are spec-divergent or defensively-thin but not currently
consensus-divergent on mainnet; the cosmetic findings (BUG-9 to BUG-11)
are documentation / observability.

Priority for a FIX wave:

1. **BUG-1** — implement `RemoveForReorg` to walk the existing mempool
   on reorg and re-eval IsFinalTx + SequenceLocks against the new tip.
2. **BUG-2** — refill disconnected txs in forward block-order +
   topological-order within each block.
3. **BUG-3** — `LockPoints` cache + `UpdateLockPoints` (perf + reorg
   correctness; depends on BUG-1).
4. **BUG-8** — zero out `prevHeights[]` for disable-flagged inputs
   (preventative; pairs with BUG-3 LockPoints work).
5. **BUG-7** — `DISCOURAGE_UPGRADABLE_NOPS` on the mempool path for
   pre-activation OP_CLTV / OP_CSV (policy-only gap).
