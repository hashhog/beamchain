# W153 — Mempool eviction + tx-removed signals + min-relay fee (beamchain)

**Wave:** W153 — `TrimToSize`, `GetMinFee`, `LimitMempoolSize`,
`RemoveStaged`, `removeForBlock`, `removeForReorg`,
`MaybeUpdateMempoolForReorg`, `MemPoolRemovalReason` enum +
fan-out, `DEFAULT_MAX_MEMPOOL_SIZE_MB`,
`DEFAULT_MEMPOOL_EXPIRY_HOURS`, `DEFAULT_MIN_RELAY_TX_FEE`,
`DEFAULT_INCREMENTAL_RELAY_FEE`, rolling-fee decay
(`ROLLING_FEE_HALFLIFE`), `prioritisetransaction` RPC,
ZMQ + REST + fee-estimator fan-out on removal.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/txmempool.cpp:793-826` — `RemoveStaged`,
  `removeUnchecked`, `Expire`.  `RemoveStaged` fires the
  `TransactionRemovedFromMempool` signal with the reason from the
  caller; `removeUnchecked` cascades to fee-estimator + ZMQ + REST
  callbacks via `m_opts.signals->TransactionRemovedFromMempool`.
- `bitcoin-core/src/txmempool.cpp:829-851` — `GetMinFee(sizelimit)`:
  rolling decay using `ROLLING_FEE_HALFLIFE = 12 h = 43,200 s`.
  Halflife scales down (÷2 / ÷4) when mempool is < half / < quarter
  full. Floor: when decayed rate < `incremental_relay_feerate / 2`,
  reset to 0. Always returns `max(decayed, incremental_relay_feerate)`.
- `bitcoin-core/src/txmempool.cpp:853-859` — `trackPackageRemoved`:
  if `rate > rollingMinimumFeeRate`, bump it and clear
  `blockSinceLastRollingFeeBump`.
- `bitcoin-core/src/txmempool.cpp:861-911` — `TrimToSize`: evict worst
  chunk until `DynamicMemoryUsage() <= sizelimit`; bumps rolling fee
  with `evicted_feerate + incremental_relay_feerate` and fires
  `removeUnchecked(_, MemPoolRemovalReason::SIZELIMIT)`.
- `bitcoin-core/src/validation.cpp:264-278` — `LimitMempoolSize`: runs
  `Expire(now - m_opts.expiry)` **and** `TrimToSize(m_opts.max_size_bytes)`
  in one call. Invoked from BlockConnected (line 387),
  AcceptSingleTransaction (line 1397), package accept (line 1731).
- `bitcoin-core/src/validation.cpp:294-388` — `MaybeUpdateMempoolForReorg`:
  builds `filter_final_and_mature` predicate (BIP-113 IsFinalTx, BIP-68
  SequenceLocks, COINBASE_MATURITY) and calls
  `m_mempool->removeForReorg(m_chain, filter_final_and_mature)`. This
  EVICTS existing mempool entries whose context changed after the
  reorg, BEFORE re-adding disconnected block txs.
- `bitcoin-core/src/kernel/mempool_options.h:19-23` —
  `DEFAULT_MAX_MEMPOOL_SIZE_MB = 300` (decimal MB, i.e. 300,000,000
  bytes) and `DEFAULT_MEMPOOL_EXPIRY_HOURS = 336` (14 d).
- `bitcoin-core/src/policy/policy.h:48,70` —
  `DEFAULT_INCREMENTAL_RELAY_FEE = 100` and
  `DEFAULT_MIN_RELAY_TX_FEE = 100` (both in sat/kvB; lowered from 1000
  in PR #24858, May 2022).
- `bitcoin-core/src/kernel/mempool_removal_reason.h:13-20` —
  `enum class MemPoolRemovalReason { EXPIRY, SIZELIMIT, REORG, BLOCK,
  CONFLICT, REPLACED }`.
- `bitcoin-core/src/validationinterface.cpp:211` — fan-out of
  `TransactionRemovedFromMempool(tx, reason, mempool_sequence)` to all
  registered subscribers (ZMQ, REST, fee-estimator, wallet, indexer).
- `bitcoin-core/src/rpc/mempool.cpp:1054-1056` — `getmempoolinfo`:
  `mempoolminfee = max(pool.GetMinFee(), m_opts.min_relay_feerate)`,
  i.e. the **dynamic rolling** floor, not the static one.

**Files audited**
- `src/beamchain_mempool.erl` (4462 lines) — `do_add_transaction`
  (550-841), `do_accept_package` (1044-1521), `do_remove_for_block`
  (2693-2738), `remove_block_conflicts` (2742-2777),
  `do_trim_to_size` (2792-2862), `do_expire_old` (2917-2963),
  `reprocess_orphans` (2598-2622), `get_min_fee` (4396-4442),
  `track_package_removed` (4449-4457), `remove_entry`/`remove_entry_with_zmq`
  (2635-2666), `handle_info(load_persisted)` (509-519).
- `src/beamchain_mempool_persist.erl` — `apply_loaded` (275-299).
- `src/beamchain_chainstate.erl` — `submit_block`/`refill_mempool_after_reorg`
  (251-294), block-connect post-step (994-1024).
- `src/beamchain_miner.erl` — block-accepted post-step (534-549).
- `src/beamchain_rpc.erl` — `rpc_getmempoolinfo` (3235-3261),
  `rpc_getnetworkinfo` (3401-3427), `rpc_sendrawtransaction`
  (2548-2614). No `prioritisetransaction` case.
- `src/beamchain_zmq.erl` — `notify_transaction/3` (82-85),
  `do_notify_tx` (288-328).
- `src/beamchain_fee_estimator.erl` — `track_tx` (105-107).  No
  removed-from-mempool hook.
- `include/beamchain_protocol.hrl` — `DEFAULT_MIN_RELAY_TX_FEE` (161),
  `DEFAULT_INCREMENTAL_RELAY_FEE` (165), `DEFAULT_MEMPOOL_MAX_SIZE`
  (166), `MEMPOOL_EXPIRY_HOURS` (170).

---

## Gate matrix (33 sub-gates / 11 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | `DEFAULT_MAX_MEMPOOL_SIZE_MB` enforcement | G1: constant present | **BUG-1 (P1)** — two constants for the same thing, two files: `?DEFAULT_MAX_MEMPOOL_SIZE = 300 * 1024 * 1024 = 314,572,800` (mempool.erl:98) vs `?DEFAULT_MEMPOOL_MAX_SIZE = 300,000,000` (protocol.hrl:166). 14.5 MiB apart. **Names also reverse word order**: `MAX_MEMPOOL_SIZE` vs `MEMPOOL_MAX_SIZE`. Two-pipeline guard (2nd beamchain mempool constant after W150 BUG-5 `MIN_RELAY_TX_FEE` duplication) |
| 1 | … | G2: TrimToSize fires automatically after successful AcceptToMemoryPool | **BUG-2 (P0-CDIV)** **CARRY-FORWARD W150 BUG-13 STILL OPEN** — `do_add_transaction` line 832 ends with `{ok, Txid, State5}` and never calls `do_trim_to_size`. **Zero non-test callers** of `do_trim_to_size` confirmed by `grep` over `src/`. The 300 MB cap is plumbed-but-not-enforced. Mempool grows past max_size indefinitely. Core ConnectTip/AcceptSingle/AcceptPackage all call `LimitMempoolSize` (validation.cpp:387/1397/1731) |
| 1 | … | G3: TrimToSize fires after package accept | **BUG-2 cross-cite** — `do_accept_package` line 1521 also never calls `do_trim_to_size` |
| 1 | … | G4: TrimToSize fires after BlockConnected (Core LimitMempoolSize in MaybeUpdateMempoolForReorg + post-connect) | **BUG-2 cross-cite** — `do_remove_for_block` line 2735-2738 does NOT call `do_trim_to_size` either. Blocks landing don't trigger size-limit eviction |
| 2 | `DEFAULT_MEMPOOL_EXPIRY_HOURS=336` (14d) | G5: constant present | PASS (`?MEMPOOL_EXPIRY_HOURS=336` protocol.hrl:170) |
| 2 | … | G6: `do_expire_old` fires automatically | **BUG-3 (P0-CDIV)** **CARRY-FORWARD W150 BUG-14 STILL OPEN** — `do_expire_old` only fires from `handle_call(expire_old, …)` (line 479), reached only via the `expire_old/0` RPC (line 335). Zero non-test callers — `grep` over `src/` shows no scheduler, no BlockConnected hook, no periodic timer (compare `expire_orphans` at line 504 which IS scheduled every 60 s). Stale txs (>14 d) persist forever unless operator manually calls RPC. The orphan pool gets its own scheduler but the main mempool doesn't |
| 3 | `DEFAULT_MIN_RELAY_TX_FEE` | G7: Core value `100 sat/kvB` (since PR #24858, May 2022) | **BUG-4 (P0-CDIV)** **CARRY-FORWARD W150 BUG-5 STILL OPEN** — `?DEFAULT_MIN_RELAY_TX_FEE=1000` in protocol.hrl:161 AND `?MIN_RELAY_TX_FEE=1000` in mempool.erl:99 (10× Core's `100`). Defined in TWO places with TWO different names (`DEFAULT_*` vs bare `*`). beamchain rejects every tx below 1.0 sat/vB while Core relays at 0.1 sat/vB |
| 3 | … | G8: applied as `EffectiveMin = max(rolling, static)` | PASS (`do_add_transaction` line 695-697 / `do_add_transaction_dry_run` line 944-946) — but the static floor is 10× too high (BUG-4) |
| 4 | `DEFAULT_INCREMENTAL_RELAY_FEE` | G9: constant value 100 sat/kvB | PASS (`?DEFAULT_INCREMENTAL_RELAY_FEE=100` protocol.hrl:165) |
| 4 | … | G10: used in TrimToSize rolling bump as `evicted_rate + incremental` | PASS (line 2840) |
| 4 | … | G11: surfaced via `getmempoolinfo.incrementalrelayfee` and `getnetworkinfo.incrementalfee` in correct units | **BUG-5 (P1)** — both fields hardcoded to `0.00001` (rpc.erl:3258, 3424). Core emits `100 / 1e8 = 0.000001` BTC/kvB for the same Core value. beamchain reports **10× higher**. Fee-estimator clients (wallets, mempool.space) see incrementalrelayfee=1 sat/vB instead of 0.1 sat/vB. Cross-cite BUG-9 (mempoolminfee unit conversion) |
| 5 | Rolling-fee decay (`GetMinFee`) | G12: `ROLLING_FEE_HALFLIFE = 43,200 s` | PASS (`get_min_fee` line 4421: `BaseHalflife = 43200.0`) |
| 5 | … | G13: halflife ÷2 when mempool < half full; ÷4 when < quarter full | PASS (line 4422-4426) |
| 5 | … | G14: floor: zero out when decayed < `incremental/2` | PASS (line 4431-4434) |
| 5 | … | G15: floor: return `max(decayed, incremental)` | PASS (line 4440) |
| 5 | … | G16: track_package_removed bumps + clears block_since_bump | PASS (line 4450-4456) |
| 5 | … | G17: `getmempoolinfo.mempoolminfee` returns the DYNAMIC rolling floor (Core: `max(pool.GetMinFee(), m_opts.min_relay_feerate)`) | **BUG-6 (P0-CDIV)** — `rpc_getmempoolinfo` line 3256 returns `?DEFAULT_MIN_RELAY_TX_FEE / 100000.0` — i.e. the STATIC floor only, ignoring `State#state.rolling_min_fee` entirely. A node whose mempool is full and has bumped rolling to 50 sat/vB still reports `mempoolminfee=0.01` (the static floor). External fee-estimators and wallets cannot detect mempool congestion. **rolling_min_fee state is dead-data for external observers** |
| 6 | `MemPoolRemovalReason` enum (6 variants) | G18: distinct EXPIRY / SIZELIMIT / REORG / BLOCK / CONFLICT / REPLACED reasons signalled to subscribers | **BUG-7 (P0-CDIV)** — `notify_transaction/3` accepts only `mempool_add | mempool_remove | block` (zmq.erl:83-84). Every removal (TrimToSize, Expire, RBF replacement, block-conflict eviction, reorg) collapses to the single atom `mempool_remove`. ZMQ subscribers (electrs, mempool.space, fulcrum) cannot distinguish replacement from size-limit eviction. Core's enum has 6 reasons because fee-estimator handling for BLOCK (success signal) vs SIZELIMIT (failed-delivery, do NOT penalize) differs |
| 7 | Removal signal fan-out to subscribers | G19: ZMQ `hashtx`/`rawtx` emitted on every removal | **BUG-8 (P0)** — `do_remove_for_block` (line 2705) uses `remove_entry/1` (NO ZMQ) for block-confirmed txs; `remove_block_conflicts` (line 2766) uses `remove_entry_with_zmq` so conflict-evictions DO emit; `do_trim_to_size`/`do_expire_old`/RBF-eviction also emit. Result: block-confirmed mempool txs do NOT fire any ZMQ removal sequence at all. External subscribers cannot reconcile their mempool view — they receive `mempool_add` then later see the tx in a `rawblock` topic but never receive the `mempool_remove` sequence event. Core fires `TransactionRemovedFromMempool(_, BLOCK, _)` for every confirmed tx (txmempool.cpp:272-274 in `removeUnchecked`) |
| 7 | … | G20: fee-estimator informed on removal (so it can drop tracked-tx for SIZELIMIT/REORG/CONFLICT/REPLACED, count BLOCK as confirmed) | **BUG-9 (P0)** — `beamchain_fee_estimator` exports only `track_tx/3` (line 19); no `tx_removed`/`removed_from_mempool` hook. Mempool code never notifies fee estimator on removals. txs evicted by trim/expire/RBF/conflict stay tracked forever; on a much-later block confirming a different tx with the same txid (impossible, but the estimator never garbage-collects), the entry accumulates indefinitely. Core: `CBlockPolicyEstimator::removeTx(hash, MemPoolRemovalReason)` selectively counts BLOCK as success vs everything else as drop-tracking |
| 7 | … | G21: REST `/rest/mempool/contents` reflects removal | N/A — REST endpoint isn't audited here; documented out of scope |
| 7 | … | G22: tx-relay layer informed (no further inv re-broadcast of evicted txs) | **BUG-10 (P1)** — no `mempool_remove` plumbing into `beamchain_peer_manager` or `beamchain_sync`. Inv-set in peer state is not invalidated on eviction; a peer's already-queued `getdata` for an evicted tx returns `notfound`, which generates UNKNOWN-tx log noise. Mild |
| 8 | `BlockConnected` → mempool update | G23: `removeForBlock(block.vtx)` runs | PASS (`do_remove_for_block` via `chainstate.erl:1019` async cast) |
| 8 | … | G24: `LimitMempoolSize` (Expire+TrimToSize) runs immediately AFTER removeForBlock (Core validation.cpp:387 in MaybeUpdateMempoolForReorg) | **BUG-11 (P0-CDIV)** — `do_remove_for_block` (line 2693-2738) ends without calling either `do_expire_old` or `do_trim_to_size`. Core fires both via `LimitMempoolSize` after every block. Compounding fleet-wide pattern with BUG-2 + BUG-3 (the only two paths that would naturally trigger the dead handlers are also broken) |
| 9 | `BlockDisconnected` + reorg → mempool update | G25: `removeForReorg(filter_final_and_mature)` evicts existing mempool entries whose context changed (BIP-113 IsFinalTx + BIP-68 SequenceLocks + COINBASE_MATURITY) | **BUG-12 (P0-CDIV)** — `refill_mempool_after_reorg` (chainstate.erl:276-294) only re-adds the disconnected block's txs (Core's `disconnectpool`). It does NOT walk existing mempool entries and re-check them against the new tip. A mempool tx admitted under tip `T` that becomes non-final under tip `T'` (different BIP-113 MTP) stays in the mempool, would mint a Core-rejected block. Also no COINBASE_MATURITY recheck — a coinbase-spending tx admitted at depth 100 against `T` may be at depth 99 against `T'` |
| 9 | … | G26: `MaybeUpdateMempoolForReorg(disconnectpool, fAddToMempool)` semantics  | PARTIAL — beamchain's `refill_mempool_after_reorg` always sets `fAddToMempool=true` (line 282 always calls `accept_to_memory_pool`). Core distinguishes (validation.cpp:3589) — re-adds only if `disconnected <= 10 && ret` — short-circuits on long reorgs |
| 10 | `prioritisetransaction` RPC | G27: handler dispatched | **BUG-13 (P0-CDIV)** — there is NO `<<"prioritisetransaction">>` case in the RPC dispatch table (rpc.erl line 670-720). `mempool_persist.erl` reads/writes the `mapDeltas` section of mempool.dat (line 178-193 `encode_deltas`/`decode_deltas`) — Core's BIP-22 PrioritiseTransaction map — but the deltas are always `[]` on dump (line 80: `deltas => []`) and the load discards `_FeeDelta` (line 282). **The deltas slot is dead-wire-format plumbing** |
| 10 | … | G28: applied to `GetModifiedFee` for mining + RBF Rule 3 | N/A (handler absent) |
| 10 | … | G29: applied to TrimToSize ordering | N/A (handler absent) |
| 11 | Self-deadlock on gen_server reentry | G30: load_persisted path does NOT call back into the same gen_server | **BUG-14 (P0-CDIV)** **FOURTH self-deadlock site** (W150 BUG-12 / W152 BUG-7 were 2-then-3 paths; W153 finds the 4th). `handle_info(load_persisted, State)` (mempool.erl:509) runs IN the mempool gen_server, calls `beamchain_mempool_persist:load()` → `apply_loaded()` → `accept_to_memory_pool(Tx)` → `gen_server:call(?SERVER, {add_tx, Tx}, 30000)`. EVERY tx in mempool.dat triggers a 30 s self-call timeout. Every restart with a non-empty `mempool.dat` causes the mempool gen_server to **deadlock for `N × 30 s`** seconds where N = tx count. The catch-all `_:_ -> bump(failed, Acc)` (persist.erl:294-296) catches the timeout, so the load fails silently with all txs marked `failed`. **Restart-after-warm-mempool DOES NOT WORK** |
| 11 | … | G31: chainstate↔mempool path uses async cast | PASS (chainstate.erl:1019 `remove_for_block_async`) — comment at chainstate.erl:1002-1005 even documents the deadlock-avoidance |
| 11 | … | G32: orphan-promotion path doesn't reenter | **BUG-15 (P0-CDIV)** **CARRY-FORWARD W150 BUG-12 / W152 BUG-7 STILL OPEN** — `reprocess_orphans/1` at mempool.erl:2612 still calls `add_transaction(OrphanTx)` (synchronous `gen_server:call`). Three production paths confirmed (W152 count): (a) `do_add_transaction` line 817, (b) `do_accept_package` line 1515, (c) `do_remove_for_block → erase_orphans_for_block` line 3040. With BUG-14, **the total self-deadlock site count is now FOUR** |
| 11 | … | G33: refill_mempool_after_reorg avoids reentry | PASS — moved to caller process via `submit_block` outer wrapper (chainstate.erl:251-260). Comment at line 244-250 explicitly documents the deadlock-avoidance |

---

## BUG-1 (P1) — `DEFAULT_MAX_MEMPOOL_SIZE` defined twice with different values + reversed names

**Severity:** P1 ("two-pipeline guard" archetype, 17th-or-so distinct
fleet instance per the W142 counter; specifically the **2nd**
beamchain mempool-constant duplication after W150 BUG-5's
`MIN_RELAY_TX_FEE`).

Two macros for the same logical quantity:

```erlang
% src/beamchain_mempool.erl:98
-define(DEFAULT_MAX_MEMPOOL_SIZE, 300 * 1024 * 1024).  % 300 MB
                                                       % = 314,572,800 (binary MiB)

% include/beamchain_protocol.hrl:166
-define(DEFAULT_MEMPOOL_MAX_SIZE, 300000000). %% 300 MB
                                              % decimal MB
```

The two values are 14.5 MiB apart. Even the macro NAMES reverse word
order (`MAX_MEMPOOL_SIZE` vs `MEMPOOL_MAX_SIZE`). The mempool gen_server
initializes `max_size = ?DEFAULT_MAX_MEMPOOL_SIZE = 314,572,800`
(mempool.erl:413) but `rpc_getmempoolinfo` returns `maxmempool =>
?DEFAULT_MEMPOOL_MAX_SIZE = 300,000,000` (rpc.erl:3255).

**External observer impact:** wallets and external monitors that use
`maxmempool` as the upper bound for `mempoolminfee` extrapolation
see the wrong size. The fill ratio they compute is off by
`(314,572,800 - 300,000,000) / 314,572,800 ≈ 4.6%`. Halflife scaling
in `get_min_fee` (line 4422-4426) compares `TotalBytes` to
`MaxSize div 4` and `MaxSize div 2` where MaxSize = 314,572,800; an
operator looking at `getmempoolinfo.maxmempool=300,000,000` cannot
predict when the ÷2 or ÷4 halflife kicks in because the runtime uses
the LARGER value.

**Core ref:** `bitcoin-core/src/kernel/mempool_options.h:19`
(`DEFAULT_MAX_MEMPOOL_SIZE_MB{300}`) → `max_size_bytes{300 * 1'000'000}`
(line 40). Core uses **decimal** MB (300,000,000 bytes), matching the
RPC value but NOT the mempool.erl macro.

**Impact:** `rpc_getmempoolinfo.maxmempool` is consistent with Core's
decimal MB, but the runtime evictor uses binary MiB — so beamchain
actually accepts ~4.6 % more bytes than its own RPC advertises.

---

## BUG-2 (P0-CDIV) — `do_trim_to_size` STILL has zero non-test callers (CARRY-FORWARD W150 BUG-13)

**Severity:** P0-CDIV ("dead-handler plumbing" fleet pattern; 4th
beamchain instance with W150 BUG-13/14, W152 BUG-1).

This bug was first catalogued in **W150 BUG-13** (April 2026). At W153
audit time (May 18 2026), it is **STILL OPEN**.

`do_trim_to_size/2` is fully implemented (`mempool.erl:2792-2862`) —
~70 LOC of correct cluster-tail-eviction + rolling-fee-bump logic that
mirrors Core's `TrimToSize` (txmempool.cpp:861-911) including the
`incremental_relay_feerate` bump and `trackPackageRemoved` call. The
handler is reachable only via:

```erlang
% src/beamchain_mempool.erl:475-477
handle_call({trim_to_size, MaxBytes}, _From, State) ->
    State2 = do_trim_to_size(MaxBytes, State),
    {reply, ok, State2};
```

…which is reached only via the public API `trim_to_size/1` at line 329-331.

**`grep -rn "trim_to_size" src/` shows zero non-test callers.** Only the
exported API and the test files reference it. `do_add_transaction` line
832 ends with `{ok, Txid, State5}` and never calls `do_trim_to_size`.
`do_accept_package` line 1521 also never calls it. `do_remove_for_block`
line 2735-2738 also never calls it.

**Core requires this on three paths:**
- `validation.cpp:387` — `LimitMempoolSize` in `MaybeUpdateMempoolForReorg`
- `validation.cpp:1397` — after `AcceptSingleTransaction`
- `validation.cpp:1731` — after `AcceptPackage`

**Impact:** the `?DEFAULT_MAX_MEMPOOL_SIZE = 300 MiB` cap is plumbed
but never enforced. A node under a relay storm can balloon the
mempool past 300 MiB / 500 MiB / 1 GiB indefinitely until OOM. Same
storm also bypasses the rolling-fee-bump optimisation
(`trackPackageRemoved` is only called from `do_trim_to_size` per
mempool.erl:2842) — so a congested-mempool node never raises its
relay floor, accepting low-fee txs that Core would reject. Compounding
with BUG-6 (mempoolminfee surfaces static-only): operators looking at
the RPC cannot tell their node is under stress.

**Fleet pattern continuity:** matches W150 BUG-13/14, W152 BUG-1
"wiring-look-but-no-wire" / "dead-handler plumbing".

---

## BUG-3 (P0-CDIV) — `do_expire_old` STILL has zero non-test callers (CARRY-FORWARD W150 BUG-14)

**Severity:** P0-CDIV (companion to BUG-2). First catalogued in
**W150 BUG-14**; STILL OPEN at W153.

`do_expire_old/1` is fully implemented (`mempool.erl:2917-2963`) with
correct Core-parity semantics: collects directly-expired txs by
`time_added < CutoffTime`, expands to include all descendants
(matching Core CalculateDescendants), removes with ZMQ notification.

The handler is only reachable via:

```erlang
% src/beamchain_mempool.erl:479-481
handle_call(expire_old, _From, State) ->
    {Count, State2} = do_expire_old(State),
    {reply, Count, State2};
```

…via API `expire_old/0` at line 334-336.

**`grep -rn "expire_old" src/` shows zero non-test callers.** No scheduler,
no BlockConnected hook, no periodic timer.

Compare the orphan pool which DOES get scheduled (`expire_orphans` at
line 504 fires every 60 s via `erlang:send_after`). The main mempool
expiry is missing the analogous scheduler.

Core invokes `LimitMempoolSize` (which calls `Expire`) after every
block AND after every successful single/package tx accept
(validation.cpp:269 → 387/1397/1731). beamchain has no equivalent.

**Impact:** stale txs (>14 d old) persist forever unless an operator
manually issues the `expire_old` RPC. Combined with BUG-2 (no trim),
the mempool can grow with cumulative-stale entries that never get
removed by either size-limit OR expiry mechanism.

---

## BUG-4 (P0-CDIV) — `DEFAULT_MIN_RELAY_TX_FEE = 1000` (Core: 100); STILL 10× off (CARRY-FORWARD W150 BUG-5)

**Severity:** P0-CDIV. First catalogued **W150 BUG-5**; STILL OPEN.

```erlang
% src/beamchain_mempool.erl:99
-define(MIN_RELAY_TX_FEE, 1000).           % 1000 sat/kvB = 1 sat/vB

% include/beamchain_protocol.hrl:161
-define(DEFAULT_MIN_RELAY_TX_FEE, 1000).     %% sat/kvB
```

Bitcoin Core (`policy/policy.h:70`) sets the constant to `100` as of
PR #24858 (May 2022). beamchain has 1000 in **two files with two
different macro names**. The accept-path (`do_add_transaction` line
695) uses the protocol.hrl macro:

```erlang
StaticMinRelay = ?DEFAULT_MIN_RELAY_TX_FEE / 1000.0,
EffectiveMin = max(RollingMin, StaticMinRelay),
FeeRate >= EffectiveMin orelse throw('mempool min fee not met'),
```

EffectiveMin is therefore at minimum `1.0 sat/vB`. Core's floor is `0.1
sat/vB`. beamchain rejects every tx between 0.1 and 1.0 sat/vB that
Core relays. On the wire, a beamchain node sends `feefilter=1000`
sat/kvB to peers, so peers don't even try to relay those txs to it —
beamchain is effectively isolated from the bottom decile of Core's
relay window.

**Same value, two macros, two files — fleet-pattern "duplicate-constant".**
Note also `mempool.erl:99` calls it `?MIN_RELAY_TX_FEE` (no
DEFAULT_ prefix); the protocol header calls it `?DEFAULT_MIN_RELAY_TX_FEE`.
Comment line 99 (`% 1000 sat/kvB = 1 sat/vB`) explicitly states the
wrong value with the assertion "= 1 sat/vB", treating the bug as a
feature — **comment-as-confession 12th beamchain instance**.

**Core ref:** `bitcoin-core/src/policy/policy.h:70`.

---

## BUG-5 (P1) — `incrementalrelayfee` / `incrementalfee` hardcoded to 10× Core's value

**Severity:** P1.

```erlang
% src/beamchain_rpc.erl:3258 (getmempoolinfo)
<<"incrementalrelayfee">> => 0.00001,
% src/beamchain_rpc.erl:3424 (getnetworkinfo)
<<"incrementalfee">> => 0.00001,
```

Both fields hardcoded to `0.00001` BTC/kvB. With Core's
`DEFAULT_INCREMENTAL_RELAY_FEE = 100 sat/kvB` and `ValueFromAmount`
(divide by 1e8), Core emits `100 / 1e8 = 0.000001` BTC/kvB.

beamchain reports **10× higher** than Core's value. External
fee-estimation tooling that uses this field for RBF Rule 4
(PaysForRBF) minimum-bump calculations will over-estimate the
required bump by 10×.

Even more bizarre: beamchain DOES have the correct constant
(`?DEFAULT_INCREMENTAL_RELAY_FEE=100` in protocol.hrl:165) — it's
used internally for the rolling-fee bump in `do_trim_to_size`
(line 2840) and for RBF Rule 4 (line 1446, 1992) — but the RPC
emitter computes a hardcoded literal instead of reading the constant.
**Constant-correct, RPC-stringly-typed-divergent.**

The right expression would be:
```erlang
<<"incrementalrelayfee">> => beamchain_mempool:incremental_relay_fee_constant() / 100000000.0,
```

Cross-cite BUG-9 (the entire mempool-fee RPC group uses `/100000.0`
where the right divisor is `/1e8`).

---

## BUG-6 (P0-CDIV) — `getmempoolinfo.mempoolminfee` reports STATIC floor, ignores rolling fee

**Severity:** P0-CDIV.

```erlang
% src/beamchain_rpc.erl:3256
<<"mempoolminfee">> => ?DEFAULT_MIN_RELAY_TX_FEE / 100000.0,
```

Core (`rpc/mempool.cpp:1054`):
```cpp
ret.pushKV("mempoolminfee", ValueFromAmount(
    std::max(pool.GetMinFee(), pool.m_opts.min_relay_feerate).GetFeePerK()));
```

Core's value is `max(rolling, static)` — the **dynamic** floor that
reflects current mempool pressure. beamchain returns only the static
floor; the entire `State#state.rolling_min_fee` machinery is invisible
to external observers.

On a node whose mempool is full and has bumped rolling to, say, 50
sat/vB, Core's RPC reports `mempoolminfee ≈ 0.0005` (50/100 of a
satoshi per byte). beamchain reports `mempoolminfee = 0.01` (the
static 1 sat/vB floor — also 10× wrong per BUG-4) regardless of
mempool state.

**rolling_min_fee is dead-data for external observers.** Internal use:
the accept-path DOES consult `get_min_fee/1` (line 694) so rolling fee
DOES gate admission. RPC reporting is the only consumer that's broken,
but it's the consumer that monitoring tools, wallets, and fee-estimators
depend on.

**Cross-cite BUG-4:** even when fixed to surface the rolling floor, the
static fallback value is still 10× too high.

**Impact:** external fee-estimation services (mempool.space, bitcoinerlive,
electrum servers) hosting a beamchain node show a misleadingly low
mempool-min-fee during congestion. Wallets that compute send-fees based
on this field will systematically under-pay during a fee-storm — and
their txs will then bounce off the (correctly-elevated) accept gate,
appearing as silent send-failures.

---

## BUG-7 (P0-CDIV) — `MemPoolRemovalReason` enum collapsed to single `mempool_remove` atom

**Severity:** P0-CDIV.

Core's `MemPoolRemovalReason` (kernel/mempool_removal_reason.h:13-20)
has 6 distinct variants:

```cpp
enum class MemPoolRemovalReason {
    EXPIRY,      // 14-day expiry
    SIZELIMIT,   // TrimToSize eviction
    REORG,       // disconnect-side eviction
    BLOCK,       // confirmed by block
    CONFLICT,    // conflict with in-block tx
    REPLACED,    // RBF replacement
};
```

beamchain's `notify_transaction/3` (zmq.erl:82-85):

```erlang
-spec notify_transaction(#transaction{}, mempool_add | mempool_remove | block,
                          non_neg_integer()) -> ok.
```

Only THREE atoms; every removal path passes `mempool_remove`:
- `remove_entry_with_zmq` (line 2662): always `Reason` from caller; all
  call sites pass literal `mempool_remove`
- `do_trim_to_size` (line 2846) passes `mempool_remove`
- `do_expire_old` (line 2942) passes `mempool_remove`
- `remove_block_conflicts` (line 2766) passes `mempool_remove`
- RBF eviction in `check_mempool_conflicts` similarly

ZMQ subscribers (electrs, mempool.space, fulcrum, nbxplorer) cannot
distinguish:
- a tx that was REPLACED by RBF (subscriber should track the replacement)
- a tx that was EXPIRED (subscriber should drop fee-estimation tracking)
- a tx that was SIZELIMIT-evicted (subscriber should drop tracking AND
  raise its own mempoolminfee snapshot)
- a tx that was CONFLICTed by a block (subscriber should drop)
- a tx confirmed by BLOCK (subscriber should mark confirmed)

The 6-vs-1 fan-out collapse silently breaks downstream observers that
rely on the reason code for state-machine transitions.

**Cross-cite:** Core's fee-estimator dispatches on the reason
(`policy/fees.cpp::removeTx`) — BLOCK counts as confirmation success,
everything else counts as drop-tracking; without the reason discriminator
beamchain's fee estimator cannot make this distinction (BUG-9).

---

## BUG-8 (P0) — Block-confirmed mempool txs do NOT emit ZMQ removal sequence

**Severity:** P0.

`do_remove_for_block` (mempool.erl:2693-2738) is the block-connect
mempool-cleanup path. It uses `remove_entry/1` (line 2705) — the NO-ZMQ
variant:

```erlang
%% 1. remove confirmed transactions and update clusters
{RemovedBytes, RemovedCount, State2} = lists:foldl(
    fun(Txid, {Bytes, Count, St}) ->
        case remove_entry(Txid) of               % <-- no ZMQ
            #mempool_entry{vsize = VSize} ->
                St2 = cluster_remove_tx(Txid, St),
                {Bytes + VSize, Count + 1, St2};
            not_found ->
                {Bytes, Count, St}
        end
    end,
    {0, 0, State0},
    Txids),
```

Then in the SAME function, `remove_block_conflicts` (line 2725 → 2766)
DOES use `remove_entry_with_zmq`. So:
- mempool tx confirmed by block → NO `mempool_remove` ZMQ sequence
- mempool tx conflicting with a block tx → ZMQ `mempool_remove` sequence fires

External subscribers see the asymmetry: they receive `mempool_add` for
tx T, then receive a `rawblock` topic containing T, but **never receive
a `mempool_remove` sequence event for T**. The subscriber's mempool
state cache stays inconsistent until a periodic full-mempool refresh.

Core fires `TransactionRemovedFromMempool(_, BLOCK, _)` for every
confirmed tx in `removeUnchecked` (txmempool.cpp:272-274) — the
BlockConnected hook walks `block.vtx`, calls `removeRecursive →
RemoveStaged → removeUnchecked` for each, and every one of those calls
fires the signal. ZMQ subscribers receive ONE `hashtx`/`sequence` event
per mempool tx confirmed.

**Impact:**
- electrs / fulcrum index-builders see a "leak" — txs that enter the
  mempool then vanish from `getrawmempool` without a removal event
- mempool.space dashboard's "mempool tx count" goes wrong on the
  block-arrival tick
- subscriber-side fee-estimators cannot correlate (tx_admitted_at,
  tx_confirmed_at) → biased fee/confirmation latency model

---

## BUG-9 (P0) — Fee estimator has NO removal hook

**Severity:** P0.

`beamchain_fee_estimator` exports only:

```erlang
% src/beamchain_fee_estimator.erl:19
-export([track_tx/3, process_block/2]).
```

`track_tx/3` is called from `do_add_transaction` (mempool.erl:828) on
every successful accept. `process_block/2` (chainstate.erl:1023) is
called from BlockConnected with the list of confirmed txids — these
become the "success" / "confirmation latency" measurements.

There is no `removed_from_mempool/2`, `tx_removed/1`, or equivalent.
Mempool txs that get evicted by trim / expire / RBF / conflict /
non-block remove stay in the fee estimator's internal `track_tx`
state forever.

Core's `CBlockPolicyEstimator::removeTx(hash, MemPoolRemovalReason)`
(policy/fees.cpp) is reason-aware:
- `BLOCK` → record confirmation; count as success
- `EXPIRY` / `SIZELIMIT` / `REORG` / `CONFLICT` / `REPLACED` → drop
  tracked tx; do NOT count as failure (it never had a chance)

Because beamchain has no equivalent:
- A tx admitted at 1 sat/vB, evicted by TrimToSize, NEVER confirms →
  the entry stays in fee-estimator tracking → eventually `track_tx`
  state size grows unbounded
- If the same txid is later re-tracked (unlikely but possible after a
  reorg → refill), Core's behaviour is to ignore the duplicate;
  beamchain may double-count

**Cross-cite BUG-7:** without the reason discriminator, even an
externally-supplied "tx was removed" signal cannot distinguish
BLOCK-confirm from SIZELIMIT-evict — so retrofitting requires the
enum upgrade as a prerequisite.

**Impact:** fee-estimator state grows; estimate accuracy drifts over a
long-running node; memory leak proportional to historical
non-confirmed-tx volume.

---

## BUG-10 (P1) — Tx-relay layer not informed of mempool evictions

**Severity:** P1.

When `do_trim_to_size` or `do_expire_old` evicts txs from the mempool,
no signal is sent to `beamchain_peer_manager` or `beamchain_sync` to
invalidate any peer's in-flight `getdata` for the evicted txid.

A peer's already-queued `getdata` for an evicted tx hits the mempool
lookup path (`beamchain_mempool:get_tx/1`) which returns `not_found`,
and the request is silently dropped or responded to with `notfound`.
Core fires `TransactionRemovedFromMempool` which `net_processing.cpp`
consumes to drop the tx from `vRecentlyAnnounced`/`m_recent_confirmed_transactions`
and other per-peer tracking structures.

beamchain has no equivalent plumbing. The W152 BUG-1 inv-queue is
unaffected (it's also dead — see W152), but a future fix to W152 BUG-1
will need a removal-hook to invalidate its queue.

**Impact:** mild log noise (`UNKNOWN-tx-requested` events for txids
that were just evicted); no correctness issue today.

---

## BUG-11 (P0-CDIV) — `do_remove_for_block` does NOT trigger `LimitMempoolSize` (Expire + TrimToSize)

**Severity:** P0-CDIV. Compounding with BUG-2 / BUG-3 (their two would-be
firing sites are both broken).

Core's `MaybeUpdateMempoolForReorg` runs `LimitMempoolSize` immediately
after `removeForBlock` (`validation.cpp:387`). `LimitMempoolSize` in
turn runs Expire AND TrimToSize. So every confirmed block, Core:
1. removes confirmed txs from mempool (BLOCK reason)
2. expires any tx >14 days old
3. trims to 300 MB cap

beamchain's `do_remove_for_block` (mempool.erl:2693-2738) does step 1
only. Steps 2 and 3 never fire from the block-connect path.

```erlang
do_remove_for_block(Txids, State) ->
    %% Set blockSinceLastRollingFeeBump = true ...
    Now = erlang:system_time(second),
    State0 = State#state{block_since_bump = true, last_fee_update = Now},
    %% 1. remove confirmed transactions
    %% 1b. clean orphan pool
    %% 2. remove block conflicts
    State3#state{...}.
    %% MISSING step 3: do_expire_old + do_trim_to_size
```

This is the LAST natural trigger point for the dead handlers
(do_trim_to_size, do_expire_old) — without it, the mempool grows
without bound between manual operator interventions.

**Core ref:** `validation.cpp:381-387` (`removeForBlock` → 
`LimitMempoolSize`).

**Impact:** the only mechanism that could rescue BUG-2 + BUG-3 in
practice is also broken. Block arrival is the natural cadence for
size-and-age limiting (Core's choice); beamchain skips it.

---

## BUG-12 (P0-CDIV) — `MaybeUpdateMempoolForReorg` `removeForReorg(filter_final_and_mature)` absent

**Severity:** P0-CDIV.

Core's reorg-side mempool update has TWO phases:
1. `removeForReorg(filter_final_and_mature)` — EVICT existing mempool
   txs that became non-final (BIP-113 IsFinalTx) or whose coinbase
   parent became immature (COINBASE_MATURITY) or whose
   SequenceLock no longer holds (BIP-68) under the new tip.
2. `MaybeUpdateMempoolForReorg(disconnectpool, fAddToMempool=true)` —
   re-feed disconnected block txs.

beamchain has ONLY phase 2 (`refill_mempool_after_reorg` at
chainstate.erl:276-294). Phase 1 is missing.

```erlang
% src/beamchain_chainstate.erl:276-294
refill_mempool_after_reorg([]) -> ok;
refill_mempool_after_reorg(Txs) ->
    %% Re-adds disconnected block's txs only; no existing-mempool filter
    {Added, Skipped} = lists:foldl(
        fun(Tx, {AccAdded, AccSkipped}) ->
            try beamchain_mempool:accept_to_memory_pool(Tx) of
                ...
```

A mempool tx admitted under tip `T` that becomes non-final under tip
`T'` (different BIP-113 MTP, because reorg pulled in a new last-11
window with later timestamps) stays in the mempool, would mint a
Core-rejected block. A mempool tx admitted at depth ≥100 (coinbase
maturity satisfied) against `T` may be at depth 99 against `T'` —
should be evicted but stays.

**Core ref:** `validation.cpp:294-388` (`MaybeUpdateMempoolForReorg`),
specifically the predicate construction at line 334-385 and the
`m_mempool->removeForReorg(m_chain, filter_final_and_mature)` call.

**Impact:**
- post-reorg miner builds blocks containing non-final txs → Core peers
  reject the block → chain split until beamchain catches up to the
  reorg's MTP changes
- post-reorg coinbase-spending tx at depth 99 → block-template
  invalid → BIP-22 `inconclusive` from peers

**Fleet pattern:** this is the same gap as W150-class
`accept-to-memory-pool runs at admission only, not at re-evaluation`.

---

## BUG-13 (P0-CDIV) — `prioritisetransaction` RPC entirely absent; mempool.dat deltas slot is dead-wire-format

**Severity:** P0-CDIV.

beamchain's RPC dispatch table (rpc.erl:670-720) has NO
`prioritisetransaction` case. The method silently returns
`Method not found`.

Meanwhile, `mempool_persist.erl` has full encode/decode for Core's
mempool.dat `mapDeltas` section:

```erlang
% src/beamchain_mempool_persist.erl:178-193
encode_deltas(Deltas) ->
    CountBin = encode_compact_size(length(Deltas)),
    Body = list_to_binary(
             [<<Txid:32/binary, (encode_int64_le(Delta))/binary>>
              || {Txid, Delta} <- Deltas]),
    <<CountBin/binary, Body/binary>>.

decode_deltas(Bin) ->
    {Count, Rest0} = decode_compact_size(Bin),
    decode_n_deltas(Count, Rest0, []).
```

But on dump (`mempool_persist.erl:80`):
```erlang
deltas        => [],   %% empty mapDeltas (no PrioritiseTransaction yet)
```

And on load, the delta is discarded:
```erlang
% src/beamchain_mempool_persist.erl:282
fun({Tx, Time, _FeeDelta}, Acc) ->
    ...
```

So the **wire format slot is correctly plumbed for byte-for-byte Core
parity, but no delta ever enters the slot, and any delta read from a
Core-produced mempool.dat is silently dropped**. This is a "dead-wire-format
plumbing" subspecies of the dead-handler pattern (15th distinct
beamchain instance).

Consequences:
- RBF Rule 3 (newer tx pays MORE absolute fee than evictees including
  PrioritiseTransaction modifiers) silently mis-evaluates because
  `mempool_entry.fee` never includes operator-applied deltas
- mining via getblocktemplate cannot prioritise specific txs
- when restarting after a Core->beamchain migration, all prioritisations
  set on the Core node are silently lost

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::prioritisetransaction`,
`txmempool.cpp::PrioritiseTransaction`,
`bitcoin-core/src/node/mempool_persist.cpp:104-110` (dump deltas).

---

## BUG-14 (P0-CDIV) — `handle_info(load_persisted)` is a FOURTH gen_server self-deadlock site

**Severity:** P0-CDIV. **NEW** — discovered in W153 (W150 BUG-12 found
2 paths, W152 BUG-7 found 3, W153 finds the 4th).

`handle_info(load_persisted, State)` at mempool.erl:509-519 runs inside
the mempool gen_server:

```erlang
handle_info(load_persisted, State) ->
    case beamchain_mempool_persist:load() of
        {ok, Stats} ->
            logger:info("mempool: loaded mempool.dat ~p", [Stats]);
        ...
    end,
    {noreply, State};
```

`beamchain_mempool_persist:load/0` → `apply_loaded/1` (persist.erl:275-299)
→ per-tx `beamchain_mempool:accept_to_memory_pool/1` (line 287) →
`gen_server:call(?SERVER, {add_tx, Tx}, 30000)` (mempool.erl:202).

**The mempool gen_server is calling itself synchronously, from inside
handle_info.** The `gen_server:call` mailbox-queues behind the
in-flight `handle_info`, which is waiting for the call to return —
classic Erlang gen_server self-deadlock. The call times out after 30 s
and crashes (`{timeout, …}` exit). `apply_loaded`'s catch-all
`_:_ -> bump(failed, Acc)` (persist.erl:294-296) swallows the timeout,
and every tx ends up in the `failed` bucket.

For a mempool.dat with N txs, **startup blocks for N × 30 s on the
mempool's main loop**. During this window:
- All `add_transaction` / `accept_to_memory_pool` calls from peers
  time out
- `getrawmempool` / `getmempoolinfo` time out
- `chainstate:remove_for_block_async` (cast) queues up without being
  drained
- Health-check probes from systemd / monitoring fail

The persisted load is corrupted in addition to the freeze: the entire
mempool.dat fails to load (every tx → failed), so the warm-restart
optimisation is fully broken.

**Why it happens:** the init hook at mempool.erl:409 dispatches a
deferred `load_persisted` message specifically to wait until the
supervision tree boots — but the dispatch lands BACK in the mempool's
own message-loop, where it then re-enters via synchronous call. The
right pattern: dispatch to a separate process (similar to chainstate's
`submit_block` wrapper at chainstate.erl:251-260) that runs the load
outside the mempool gen_server, then issues `gen_server:call` to the
mempool from there.

**Cross-cite W152 BUG-7:** the W152 audit catalogued three reentry
paths via `reprocess_orphans`; W153 makes it four with `load_persisted`.

**Fleet pattern continuity:** "gen_server self-deadlock", 4th distinct
beamchain site.

**Impact:**
- mempool.dat warm-restart is BROKEN — every tx is dropped on the
  floor at startup
- node startup wall-clock is N × 30 s longer than expected (for a
  realistic mempool.dat with 50,000 txs, **17 days of blocked startup**
  before the loop drains; in practice the supervisor restart limit
  triggers an OTP-level crash long before)
- the only thing keeping this bug bounded in production is that
  `dump_mempool` is only called from RPC (`savemempool`) and from
  shutdown (`terminate/2` line 524) — operators that don't shut down
  cleanly avoid the load-at-restart entirely

---

## BUG-15 (P0-CDIV) — `reprocess_orphans/1` self-deadlock STILL OPEN (CARRY-FORWARD W150 BUG-12 / W152 BUG-7)

**Severity:** P0-CDIV. First catalogued W150 BUG-12 (2 sites), expanded
W152 BUG-7 (3 sites); STILL OPEN at W153.

`reprocess_orphans/1` (mempool.erl:2598-2622) calls
`add_transaction(OrphanTx)` (line 2612) which dispatches a synchronous
`gen_server:call(?SERVER, {add_tx, Tx}, 30000)` to the SAME mempool
gen_server.

Three production callers (W152 count):
- (a) `do_add_transaction` line 817 — every successful tx-accept calls
      reprocess_orphans → potential self-deadlock for each promoted orphan
- (b) `do_accept_package` line 1515 — same shape
- (c) `do_remove_for_block` → `erase_orphans_for_block` line 3040 —
      every block-connect

With BUG-14 (`load_persisted` direct reentry), beamchain now has FOUR
distinct mempool gen_server self-deadlock sites. The pattern is
fleet-wide-archetypal: every code path that calls into the mempool
from inside the mempool gen_server breaks.

The cumulative-frequency of this bug in the beamchain codebase is now
the single most-frequent fleet-pattern instance (4 sites in one
gen_server, more than the W128 banman 2-bug cluster and the W104
peer-message 3-bug cluster).

**Fix shape:** all four sites need to dispatch via `gen_server:cast` or
via a wrapper process — the same pattern chainstate.erl:251-260 used
for `submit_block`. The W152 audit recommended one-time bulk
refactoring; this is now overdue.

---

## BUG-16 (P1) — Two parallel `remove_for_block` pipelines (sync from miner, async from chainstate)

**Severity:** P1 ("two-pipeline guard" 18th-or-so distinct fleet
instance; 3rd in beamchain mempool after BUG-1 size constant and W150
BUG-5 min-relay-fee constant).

`beamchain_mempool` exports BOTH `remove_for_block/1` (synchronous
gen_server:call) and `remove_for_block_async/1` (asynchronous
gen_server:cast):

```erlang
% src/beamchain_mempool.erl:313-326
-spec remove_for_block([binary()]) -> ok.
remove_for_block(Txids) ->
    gen_server:call(?SERVER, {remove_for_block, Txids}, 30000).

-spec remove_for_block_async([binary()]) -> ok.
remove_for_block_async([]) -> ok;
remove_for_block_async(Txids) ->
    gen_server:cast(?SERVER, {remove_for_block, Txids}).
```

Production consumers diverge:
- `beamchain_chainstate:1019` uses the ASYNC variant after a block
  connects (correctly avoiding the chainstate↔mempool deadlock per
  comment at line 1002-1005)
- `beamchain_miner:542` uses the SYNC variant after submitblock

The miner is on the RPC handler process (not the chainstate
gen_server), so the sync call doesn't deadlock; but the asymmetry
matters:
- after a peer-relayed block: removeForBlock runs ASYNC (delayed),
  next-tx admission may briefly see the just-confirmed txs as still in
  mempool
- after a submitblock RPC: removeForBlock runs SYNC, the response to
  the operator is delayed by the mempool's gen_server queue depth

The miner ALSO passes the coinbase txid in its Txids list (line
540-541: `[beamchain_serialize:tx_hash(Tx) || Tx <- Block#block.transactions]`
— the full vtx including coinbase), while chainstate explicitly skips
the coinbase (line 1013-1015: `[_Coinbase | RegularTxs] -> ...`). So
the miner pipeline tries (harmlessly) to remove the coinbase txid from
the mempool every block — the mempool returns `not_found` and the
counter doesn't budge, but the cluster-update path runs.

**Impact:** subtle inconsistency. Mild perf cost on submitblock path.
No correctness divergence today, but two near-identical pipelines with
slightly different argument shapes is a classic regression-on-future-fix
risk.

---

## BUG-17 (P0) — `do_remove_for_block` does NOT fire `TransactionRemovedFromMempool` for **block-confirmed** txs (companion to BUG-8)

**Severity:** P0.

Already covered partly in BUG-8 — the ZMQ asymmetry. Lifting it to
its own bug because the Core signal `TransactionRemovedFromMempool`
fans out beyond ZMQ:
- fee-estimator (`policy/fees.cpp::removeTx`) — count BLOCK as confirmation
- wallet (`wallet/wallet.cpp::TransactionRemovedFromMempool`) — clear
  pending-by-id, mark confirmed
- REST endpoint subscribers — `/rest/mempool/contents` cache invalidation
- indexer (e.g. txindex) — finalize-by-block
- mining (`getblocktemplate` template cache) — re-template

beamchain emits NONE of these signals on block-confirm because
`remove_entry` is the no-fan-out variant.

The fee-estimator gap is critical because beamchain's
`beamchain_fee_estimator:process_block/2` (chainstate.erl:1023) gets a
flat `ConfirmedTxids` list — it relies on this single hook for
confirmation-latency stats. But that hook is the ONLY confirmation
signal; it's brittle (what if the chainstate→fee_estimator cast is
dropped due to mailbox overflow? Core's fan-out is redundant by design,
beamchain's single hook is not).

**Cross-cite BUG-7 + BUG-8 + BUG-9:** the root cause for all four is
that `notify_transaction` has no `block_confirmed` arm AND the
removal-signal fan-out architecture is missing entirely.

**Impact:** beamchain's fee-estimator works ONLY because of the
chainstate single-hook. Any subscriber outside the chainstate→fee_estimator
direct path is starved of confirmation events. Wallet integrations
break.

---

## BUG-18 (P1) — `do_expire_old` returns DirectlyExpired count but logs/totals use AllExpired count (off-by-descendants in RPC response)

**Severity:** P1.

```erlang
% src/beamchain_mempool.erl:2917-2963
do_expire_old(State) ->
    ...
    DirectlyExpired = lists:filtermap(...),
    AllExpired = lists:usort(lists:flatmap(
        fun(Txid) ->
            [Txid | get_all_descendants(Txid)]
        end,
        DirectlyExpired)),
    %% Remove with ZMQ notification.
    {ExpiredCount, ExpiredBytes, State2} = lists:foldl(...),  % ExpiredCount uses AllExpired
    ...
    {length(DirectlyExpired), State3}.  % <-- returns DirectlyExpired count, NOT ExpiredCount
```

The function returns `length(DirectlyExpired)` (line 2963) — the count
of directly-expired roots. But `ExpiredCount` (line 2940-2951) and the
total-bytes/total-count state updates (line 2960-2962) use
`AllExpired` (roots + descendants).

So:
- RPC client (`expire_old/0` API) sees the directly-expired count
- Internal state correctly removes all (descendants too)
- Log line (line 2955: `expired ~B old txs`) uses `ExpiredCount`
  (i.e. AllExpired)

The RPC and the log disagree on the same operation. An operator
reading the RPC response `{ok, 3}` who then greps the log for
`expired 5 old txs` (root + 2 descendants per root) sees an
inconsistency that takes minutes to resolve.

Core's `Expire` (txmempool.cpp:825) returns `stage.size()` — the FULL
removal count, descendants included.

**Impact:** monitoring contract drift; operator confusion.

---

## BUG-19 (P1) — `mempoolminfee` / `minrelaytxfee` / `relayfee` unit conversion off by 1000× (wrong divisor)

**Severity:** P1 (severity downgraded from P0 because the static value
is also 10× wrong per BUG-4 — combined error is the proximate cause,
not just the unit conversion).

```erlang
% src/beamchain_rpc.erl:3256-3257 (getmempoolinfo)
<<"mempoolminfee">> => ?DEFAULT_MIN_RELAY_TX_FEE / 100000.0,
<<"minrelaytxfee">> => ?DEFAULT_MIN_RELAY_TX_FEE / 100000.0,

% src/beamchain_rpc.erl:3423 (getnetworkinfo)
<<"relayfee">> => ?DEFAULT_MIN_RELAY_TX_FEE / 100000.0,
```

`?DEFAULT_MIN_RELAY_TX_FEE = 1000` in **sat/kvB** (per protocol.hrl:161
comment).

Core's `ValueFromAmount` (rpcvalues.cpp) divides by COIN = 1e8 to
convert from satoshis to BTC. The value units are sat/kvB, so the
correct BTC/kvB conversion divides by 1e8: `1000 / 1e8 = 0.00001`.

beamchain divides by `100000` (1e5): `1000 / 1e5 = 0.01`.

**Result: 1000× too large**, reporting 0.01 BTC/kvB instead of
0.00001 BTC/kvB. With Core's correct constant of 100 sat/kvB and
correct conversion, the right value is `0.000001`. beamchain's
combined `1000 / 1e5 = 0.01` is 10,000× larger than Core's correct
`0.000001`.

**Impact:** monitoring + RPC-client wallet integration:
- bitcoin-cli / bitcoinjs / electrum / nbxplorer parsing this field
  see beamchain's relayfee as 10,000 sat/vB instead of 0.1 sat/vB
- automatic fee-bumping wallets will refuse to send any tx (the
  reported floor exceeds reasonable absolute fees)
- mempool.space "min relay fee" displayed as 10,000 sat/vB

This is the most operator-visible RPC bug in the audited set.

**Cross-cite BUG-5 + BUG-6.**

---

## BUG-20 (P1) — `mempool.erl:99` comment line is a confession: "1000 sat/kvB = 1 sat/vB"

**Severity:** P1 ("comment-as-confession" fleet pattern, 12th distinct
beamchain instance).

```erlang
% src/beamchain_mempool.erl:99
-define(MIN_RELAY_TX_FEE, 1000).           % 1000 sat/kvB = 1 sat/vB
```

The comment frames the value as a deliberate choice ("= 1 sat/vB") —
asserting the WRONG value as a positive feature. Core's value is 100
sat/kvB = 0.1 sat/vB, and has been since PR #24858 (May 2022 — almost
four years before this audit).

This is the 12th "comment-as-confession" beamchain instance:
- W125 — 4 instances catalogued
- W138 — 1 more
- W140 — 2 more
- W142 — 1 more
- W144 BUG-12 lunarblock (separate impl, but pattern crystallizes
  across fleet)
- W149 hotbuns BUG-8 comment "Skip undo data generation during
  assume-valid IBD for performance"
- W150 BUG-5 "the constant cited inline wrongly"
- W153 here — 12th beamchain instance, naming-time-machine
  ("the value-was-1000 from 2017") cited as design intent

**Impact:** future maintainers reading the macro see the comment and
assume the value is correct. Until the comment is updated, the bug
is effectively "self-documenting as a feature".

---

## BUG-21 (P0-CDIV) — `apply_loaded` is best-effort but the catch-all hides BUG-14's 30 s self-deadlock as `failed`

**Severity:** P0-CDIV (companion to BUG-14).

```erlang
% src/beamchain_mempool_persist.erl:282-297
fun({Tx, Time, _FeeDelta}, Acc) ->
    case Time =< Cutoff of
        true ->
            bump(expired, Acc);
        false ->
            try beamchain_mempool:accept_to_memory_pool(Tx) of
                {ok, _Txid} ->
                    bump(accepted, Acc);
                {error, already_in_mempool} ->
                    bump(already, Acc);
                {error, _Other} ->
                    bump(failed, Acc)
            catch
                _:_ ->
                    bump(failed, Acc)
            end
    end
end,
```

The `catch _:_` swallows the `{timeout, {gen_server, call, ...}}` exit
that BUG-14 induces. So when `load_persisted` self-deadlocks:
- The mempool gen_server is frozen for 30 s per tx (BUG-14)
- After the timeout, `apply_loaded` continues and tries the NEXT tx
- Each tx triggers another 30 s timeout
- Final result: `{ok, #{accepted=>0, expired=>0, failed=>N, already=>0, total=>N}}`
- Log emits `mempool: loaded mempool.dat #{accepted=>0, failed=>50000, ...}`

An operator looking at the load summary sees ALL txs failed and assumes
mempool.dat was corrupted. **They will likely `rm mempool.dat` to
"recover"**, losing the warm-restart state entirely.

The catch-all should at least distinguish exit-timeout from
{error, _} so the log shows the actual class of failure. Better: log
each failure reason at debug level.

**Impact:** silent broken-by-design warm restart; operator-driven data
loss from a misleading symptom signature.

---

## BUG-22 (P1) — Rolling-fee state (`rolling_min_fee`, `block_since_bump`, `last_fee_update`) never persisted across restart

**Severity:** P1.

The `#state{}` record (mempool.erl:166-182) carries three rolling-fee
fields:
- `rolling_min_fee :: float()`
- `block_since_bump :: boolean()`
- `last_fee_update :: integer()`

These are initialised to `0.0 / false / now()` on every restart
(mempool.erl:419-421) and the persist module
(`beamchain_mempool_persist`) writes only the `mapDeltas` slot — not
rolling-fee state.

Core's mempool.dat does NOT persist rolling-fee state either (the
state is in-memory CTxMemPool member), but Core's mempool size is
typically bounded by the actual mempool population on restart — once
TrimToSize fires post-restart, the rolling fee re-converges within
minutes.

beamchain's BUG-2 (TrimToSize never auto-fires) compounds this:
restart → mempool floor resets to incremental_relay floor → no trim
→ rolling-fee never re-converges. The bumped-floor protection from
the pre-restart congestion event is lost.

**Impact:** restart during sustained congestion drops the relay floor
back to the incremental-relay minimum, accepting low-fee txs that the
pre-restart node was correctly rejecting. The fee-storm can flood the
restarted node's mempool faster than it would have without restart.

---

## Summary

**Bug count:** 22 (BUG-1 through BUG-22).

**Severity distribution:**
- **P0-CDIV:** 11 (BUG-2, BUG-3, BUG-4, BUG-6, BUG-7, BUG-11, BUG-12, BUG-13, BUG-14, BUG-15, BUG-21)
- **P0:** 3 (BUG-8, BUG-9, BUG-17)
- **P1:** 8 (BUG-1, BUG-5, BUG-10, BUG-16, BUG-18, BUG-19, BUG-20, BUG-22)
- **P2:** 0
- Total: 11 + 3 + 8 = 22. ✓

**Carry-forward bugs STILL OPEN from prior waves:**
- W150 BUG-13 → W153 BUG-2 (`do_trim_to_size` zero non-test callers)
- W150 BUG-14 → W153 BUG-3 (`do_expire_old` zero non-test callers)
- W150 BUG-5 → W153 BUG-4 (`DEFAULT_MIN_RELAY_TX_FEE` 10× Core)
- W150 BUG-12 / W152 BUG-7 → W153 BUG-15 (`reprocess_orphans` self-deadlock,
  3 sites; W153 BUG-14 makes it 4 with `load_persisted`)
- W150 BUG-11 (inverted predicate in `remove_block_conflicts`) — STILL
  PRESENT at mempool.erl:2755-2759 (cross-cite without re-cataloguing
  here; reaches same wrong conclusion)

**Fleet patterns confirmed:**
- **"dead-handler plumbing"** (BUG-2, BUG-3, BUG-13) —
  `do_trim_to_size`, `do_expire_old`, prioritisetransaction RPC + its
  wire-format slot all plumbed-but-not-wired. 4th-5th-6th beamchain
  instance.
- **"gen_server self-deadlock"** (BUG-14, BUG-15) — beamchain now has
  FOUR distinct mempool self-call sites (load_persisted +
  reprocess_orphans×3). Single most-frequent fleet-pattern instance
  in beamchain.
- **"two-pipeline guard"** (BUG-1, BUG-16) — 17th-and-18th distinct
  fleet instance: `DEFAULT_MAX_MEMPOOL_SIZE` defined twice with
  different values; `remove_for_block` exists as both sync and async
  with different consumers passing different argument shapes.
- **"dead-data plumbing"** (BUG-6 rolling_min_fee not in RPC, BUG-13
  deltas slot in mempool.dat) — internal state correctly computed,
  external observers blind to it.
- **"comment-as-confession"** (BUG-20) — 12th distinct beamchain
  instance; `MIN_RELAY_TX_FEE` constant cites wrong value as
  intentional.
- **"unit-conversion-off"** (BUG-19) — fee fields divided by 1e5
  instead of 1e8; combined with BUG-4 / BUG-5 hardcoded values, RPC
  reports are 10,000× off from Core in absolute units.
- **"enum collapsed to single atom"** (BUG-7) — Core's 6-variant
  MemPoolRemovalReason flattened to single `mempool_remove` atom in
  ZMQ + fee-estimator + REST fan-out paths.
- **"reason-aware signal missing"** (BUG-7 + BUG-9 + BUG-17) — the
  removed-from-mempool fan-out architecture is essentially absent;
  fee-estimator has no removal hook at all (BUG-9), wallet/REST/indexer
  hooks would also be missing if they existed.
- **"defense-in-depth gap during reorg"** (BUG-12) — Core's
  `removeForReorg(filter_final_and_mature)` phase entirely missing;
  only the disconnectpool re-feed is implemented.
- **"silent-failure-masked-by-broad-catch"** (BUG-21) — `apply_loaded`'s
  `catch _:_` hides BUG-14's deadlock symptom as a generic `failed`
  count; operator data-loss risk via "rm mempool.dat to recover".

**Top three findings:**

1. **BUG-14 (P0-CDIV `load_persisted` 4th self-deadlock site)** —
   `handle_info(load_persisted)` runs inside the mempool gen_server
   and calls `accept_to_memory_pool` → `gen_server:call(?SERVER, ...)`,
   self-deadlocking with 30 s timeout per tx. mempool.dat warm-restart
   is fully broken — every tx ends in the `failed` bucket. Combined
   with BUG-21 (broad catch masks the symptom), operators who don't
   shut down cleanly silently lose all warm-restart state. Combined
   with BUG-15 (reprocess_orphans, 3 sites), beamchain mempool now has
   FOUR distinct gen_server self-deadlock sites — the single
   most-frequent fleet-pattern instance in beamchain.

2. **BUG-2 + BUG-3 + BUG-11 cluster (size-limit and expiry never fire
   in production)** — `do_trim_to_size` and `do_expire_old` are
   correctly implemented (~70 + ~50 LOC) but reachable only from RPC.
   The natural trigger sites (post-accept, post-package-accept,
   post-block-connect) all fail to call them. Core's `LimitMempoolSize`
   fires from all three; beamchain fires from none. Result: mempool
   grows past 300 MB / 14-day-old-tx cap indefinitely until OOM. STILL
   OPEN from W150 (April 2026, ~6 weeks).

3. **BUG-7 + BUG-8 + BUG-9 + BUG-17 cluster (removed-from-mempool
   signal fan-out is broken in every dimension)** — the
   `MemPoolRemovalReason` enum is collapsed to a single
   `mempool_remove` atom; block-confirmed mempool txs don't emit ZMQ
   sequence events at all (`do_remove_for_block` uses
   `remove_entry/1` not `remove_entry_with_zmq/3`); the fee-estimator
   has NO removal hook (only `track_tx`/`process_block`). External
   ZMQ subscribers (electrs, mempool.space, fulcrum, nbxplorer) cannot
   reconcile their mempool view; wallets get no removal-confirmation
   events; fee-estimator state leaks indefinitely. This is a
   fan-out-architecture bug, not a single line — a full Core-parity
   refactor would touch zmq.erl + fee_estimator.erl + at least 6
   mempool.erl call sites + a new optional REST hook.
