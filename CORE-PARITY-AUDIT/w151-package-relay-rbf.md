# W151 — Package relay + BIP-125 RBF rules 2-5 (beamchain)

**Wave:** W151 — `MemPoolAccept::AcceptPackage`,
`MemPoolAccept::AcceptMultipleTransactionsInternal`,
`MemPoolAccept::AcceptSubPackage`, `MemPoolAccept::SubmitPackage`,
`MemPoolAccept::PackageRBFChecks`, `MemPoolAccept::ReplacementChecks`,
`IsWellFormedPackage`, `IsTopoSortedPackage`, `IsConsistentPackage`,
`IsChildWithParents`, `IsChildWithParentsTree`,
`PackageMempoolChecks`, `PackageTRUCChecks`,
`GetEntriesForConflicts` (Rule 5), `EntriesAndTxidsDisjoint`,
`PaysForRBF` (Rules 3+4), `ImprovesFeerateDiagram`, `IsRBFOptIn`,
`SignalsOptInRBF`, BIP-125 rules 2 (no-new-unconfirmed), 3 (more-fee),
4 (per-relay-bandwidth), 5 (≤MAX_REPLACEMENT_CANDIDATES distinct
clusters), `submitpackage` RPC, `testmempoolaccept` RPC,
`MAX_PACKAGE_COUNT=25`, `MAX_PACKAGE_WEIGHT=404000`,
`MAX_REPLACEMENT_CANDIDATES=100`, `EXTRA_DESCENDANT_TX_SIZE_LIMIT`,
`m_subpackage.m_rbf`, `m_subpackage.m_changeset`.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**

- `bitcoin-core/src/validation.cpp` —
  `MemPoolAccept::AcceptPackage` (~1622-1771),
  `MemPoolAccept::AcceptMultipleTransactionsInternal` (~1432-1564),
  `MemPoolAccept::AcceptSubPackage` (~1596-1620),
  `MemPoolAccept::SubmitPackage`,
  `MemPoolAccept::PackageMempoolChecks`,
  `MemPoolAccept::PackageRBFChecks` (~1037-1133),
  `MemPoolAccept::ReplacementChecks` (~984-1035) — single-tx RBF Rules 3+4+5
  but Rule 2 (HasNoNewUnconfirmedParents) has been REMOVED from
  single-tx path; cluster diagram-domination replaces it.
- `bitcoin-core/src/policy/packages.cpp` —
  `IsTopoSortedPackage` (~17-50), `IsConsistentPackage` (52-77) (also
  rejects empty-input txs as inconsistent), `IsWellFormedPackage`
  (~79-117) (in this order: MAX_PACKAGE_COUNT → MAX_PACKAGE_WEIGHT →
  duplicate-txid → topo-sort → consistency), `IsChildWithParents`
  (~119-134), `IsChildWithParentsTree` (~136-149) (extra "no parent
  spends another parent" check), `GetPackageHash`.
- `bitcoin-core/src/policy/packages.h` —
  `MAX_PACKAGE_COUNT=25`, `MAX_PACKAGE_WEIGHT=404000`.
- `bitcoin-core/src/policy/rbf.cpp` —
  `IsRBFOptIn` (~24-50), `IsRBFOptInEmptyMempool` (52-56),
  `GetEntriesForConflicts` (58-83) — Rule 5 bound is on
  `GetUniqueClusterCount(iters_conflicting)`, NOT on total evicted tx
  count. `EntriesAndTxidsDisjoint` (85-98), `PaysForRBF` (100-125)
  (Rule 3 = `replacement_fees >= original_fees`, Rule 4 =
  `additional_fees >= relay_fee.GetFee(replacement_vsize)`),
  `ImprovesFeerateDiagram` (127-140) (cluster chunk-diagram dominance,
  replaces per-conflict feerate gate).
- `bitcoin-core/src/policy/rbf.h:26` —
  `MAX_REPLACEMENT_CANDIDATES{100}` — bound on DISTINCT CLUSTERS,
  not raw evicted txs.
- `bitcoin-core/src/util/rbf.cpp:9-17` —
  `SignalsOptInRBF(tx)` = `any input has nSequence <=
  MAX_BIP125_RBF_SEQUENCE (0xfffffffd)`.
- `bitcoin-core/src/util/rbf.h:12` — `MAX_BIP125_RBF_SEQUENCE=0xfffffffd`.
- `bitcoin-core/src/policy/policy.h:70` —
  `DEFAULT_MIN_RELAY_TX_FEE{100}` (sat/kvB; NOT 1000).
- `bitcoin-core/src/policy/policy.h:48` —
  `DEFAULT_INCREMENTAL_RELAY_FEE{100}` (sat/kvB).
- `bitcoin-core/src/policy/policy.h:76-78` —
  `DEFAULT_ANCESTOR_LIMIT=25`, `DEFAULT_DESCENDANT_LIMIT=25`.
- `bitcoin-core/src/rpc/mempool.cpp::submitpackage` (~1302-1513) —
  - `IsChildWithParentsTree` is REQUIRED for multi-tx packages (1395).
  - `IsUnspendable || !HasValidOps` + `value > max_burn_amount` is
    UNCONDITIONAL (1387), no zero-gate.
  - per-tx result map includes `effective-feerate`,
    `effective-includes`, `other-wtxid` fields.
  - `replaced-transactions` populated from each
    `MempoolAcceptResult::m_replaced_transactions`.
  - `package_msg = package_result.m_state.ToString()` on PCKG_POLICY /
    PCKG_TX failure (returns Core-canonical string, NOT erlang term).
- `bitcoin-core/src/txmempool.cpp:388-403` — `removeConflicts(tx)`:
  iterate INPUTS of the confirmed tx, look up `mapNextTx[txin.prevout]`
  to find the mempool spender of THAT exact outpoint, evict via
  `removeRecursive(it->second, MemPoolRemovalReason::CONFLICT)`.
  CRUCIAL: does NOT iterate over mempool tx inputs vs confirmed txid
  set — that pattern evicts CPFP-children rather than double-spends.
- `bitcoin-core/src/node/transaction.h:28` —
  `DEFAULT_MAX_RAW_TX_FEE_RATE{COIN / 10}` = 0.1 BTC/kvB.
- `bitcoin-core/src/kernel/mempool_entry.h` —
  `CTxMemPoolEntry::GetTxSize()` returns sigop-adjusted vsize via
  `GetVirtualTransactionSize(nTxWeight, sigOpCost, nBytesPerSigOp)`.

**Files audited**

- `src/beamchain_mempool.erl` (4462 LOC) — single-tx ATMP gates
  (`do_add_transaction`, ~516-839), single-tx dry-run
  (`do_add_transaction_dry_run`, ~857-992), package acceptance
  (`do_accept_package`, ~1042-1069), package structural checks
  (`validate_package_structure`, 1071-1105), package topo-sort
  (`is_topo_sorted`/`is_topo_sorted_loop`, 1107-1128), package
  consistency (`is_consistent_package`, 1131-1136), package shape
  (`is_child_with_parents`, 1138-1157), individual-then-CPFP loop
  (`try_individual_accept`, 1159-1194), package CPFP evaluation
  (`evaluate_package_cpfp`, 1196-1230), package RBF
  (`do_package_rbf`, 1397-1463), package commit
  (`accept_package_txs`, 1465-1521), single-tx RBF (`do_rbf`,
  1908-2017), cluster diagram dominance check
  (`check_cluster_rbf_diagram`, 2036-2106), block-removal
  (`do_remove_for_block`, 2693-2738), conflict-removal
  (`remove_block_conflicts`, 2742-2787), orphan reprocess
  (`reprocess_orphans`, 2598-2622), `find_orphaned_ephemeral_parents`
  (2670-2687), TRUC sibling eviction (`do_truc_sibling_eviction`,
  3245-3273), TRUC package rules (`check_truc_package_rules`,
  3280-3294), policy constants (lines 98-109).
- `src/beamchain_rpc.erl` (9513 LOC) — `rpc_submitpackage` (2874-3032),
  `rpc_testmempoolaccept` (2778-2872), `rpc_sendrawtransaction`
  (2548-2614), `check_max_fee_rate` (2673-2690),
  `compute_tx_input_value` (2693-2703), `relay_transaction`
  (2706-2713), `build_pkg_tx_result` (3039-3067),
  `ds_is_unspendable` (4158-4159), `decode_package_tx` (3023-3032).
- `src/beamchain_peer_manager.erl` — `broadcast(inv, ...)`
  (300-314), MSG_TX vs MSG_WTX picking
  (`inv_items_from_pairs`/`peer_uses_wtxid`, 1874-1893).
- `src/beamchain_config.erl:170-189` — `mempool_full_rbf` (env +
  config; defaults true).
- `include/beamchain_protocol.hrl` —
  `?MAX_PACKAGE_COUNT=25` (197), `?MAX_PACKAGE_WEIGHT=404000` (198),
  `?MAX_BIP125_RBF_SEQUENCE=0xfffffffd` (168),
  `?MAX_RBF_EVICTIONS=100` (169),
  `?DEFAULT_INCREMENTAL_RELAY_FEE=100` (165),
  `?DEFAULT_MIN_RELAY_TX_FEE=1000` (161) — **10× Core's 100**.

---

## Gate matrix (33 sub-gates / 14 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | Package count bound | G1: > MAX_PACKAGE_COUNT (25) → reject | PASS (`mempool.erl:1072`, hyphen-vs-underscore string aside) |
| 2 | Package weight bound | G2: > MAX_PACKAGE_WEIGHT (404000) for multi-tx → reject | PASS (`mempool.erl:1076-1081`) |
| 3 | Package duplicates | G3: duplicate txid → reject | PASS (`mempool.erl:1087-1089`) |
| 4 | Package topo-sort | G4: parent appears after child → reject | PASS (`mempool.erl:1109-1128`) but **BUG-1** below — self-spending edge case diverges |
| 5 | Package consistency | G5: two txs spend same outpoint → reject | PASS (`mempool.erl:1131-1136`) but **BUG-2** below — empty-input case diverges from Core |
| 6 | Package shape | G6: multi-tx → child-with-parents | PASS (`mempool.erl:1138-1157`) |
| 6 | … | G7: multi-tx → child-with-parents **TREE** (no parent spends another) | **BUG-3 (P0-CDIV)** — `is_child_with_parents_tree` does not exist anywhere; submitpackage admits packages where parents chain among themselves, then runs into orphan-or-conflict-recovery |
| 7 | submitpackage RPC | G8: count range [1, MAX_PACKAGE_COUNT] | PASS (`rpc.erl:2909-2914`) |
| 7 | … | G9: per-tx maxfeerate gate uses sigop-adjusted vsize | **BUG-4 (P1)** — `check_max_fee_rate` uses `tx_vsize` (raw), not `tx_sigop_vsize`; high-sigop txs slip past the maxfeerate limit (cross-cite W144) |
| 7 | … | G10: per-tx maxfeerate looks up package-internal parent outputs | **BUG-5 (P1)** — `compute_tx_input_value` consults UTXO + mempool only; package-internal parents missing → TotalIn=0 → fee 0 → maxfeerate trivially passes |
| 7 | … | G11: maxburnamount unspendable+HasValidOps check unconditional | **BUG-6 (P1)** — `case MaxBurnSat > 0 of` skips check when arg is 0 (default); Core checks always with default 0 → any burn rejected. Also missing `HasValidOps` check |
| 7 | … | G12: per-tx result map includes effective-feerate / effective-includes / other-wtxid | **BUG-7 (P1)** — `build_pkg_tx_result` emits only `txid`+`vsize`+`fees.base`; missing Core's `fees.effective-feerate`, `fees.effective-includes`, `other-wtxid` (`rpc.erl:3039-3067`) |
| 7 | … | G13: package_msg failure string == Core's canonical string | **BUG-8 (P0-DIV)** — `io_lib:format("~p", [Reason])` prints Erlang atoms (`rbf_not_signaled`, `package_fee_too_low`, `{tx_failed, _, _}`) instead of Core wire-format ("insufficient fee, rejecting replacement…", "package-not-sorted", etc.) — breaks electrs / fulcrum / mempool.space / nbxplorer / any client parsing the package_msg string |
| 7 | … | G14: replaced-transactions populated | **BUG-9 (P1)** — submitpackage emits `<<"replaced-transactions">> => []` ALWAYS (`rpc.erl:2993`) — never populated, comment acknowledges ("beamchain's package validator does not yet emit a per-package replaced-tx list") |
| 8 | Per-tx accept loop atomicity | G15: AcceptPackage is all-or-nothing (no partial-accept stickiness) | **BUG-10 (P0-CDIV)** — `do_accept_package` calls `try_individual_accept` then `evaluate_package_cpfp`; if CPFP throws after some txs were individually accepted into ETS, gen_server returns `{error, ...}` with the ORIGINAL State — but ETS still holds the partial accepts (State<->ETS divergence). Mempool count/bytes accounting is now silently wrong |
| 9 | Package-RBF preconditions | G16: package size MUST be exactly 2 (1 parent + 1 child) | **BUG-11 (P0-CDIV)** — `do_package_rbf` accepts ANY package size (`mempool.erl:1397-1463`). Core (validation.cpp:1051): `if (workspaces.size() != 2 || !Assume(IsChildWithParents(txns)))` → fail with "package must be 1-parent-1-child" |
| 9 | … | G17: package RBF requires "new transaction cannot have mempool ancestors" | **BUG-12 (P0-CDIV)** — `do_package_rbf` does not enforce this gate. Core (validation.cpp:1063-1067): rejects with "package RBF failed: new transaction cannot have mempool ancestors" |
| 9 | … | G18: package-rbf uses package-feerate diagram dominance via ImprovesFeerateDiagram | PARTIAL — `check_cluster_rbf_diagram` (single-tx path) builds a single-point new diagram; package path does not call diagram dominance at all (`mempool.erl:1397-1463` has no `check_cluster_rbf_diagram` call). Cross-cite **BUG-13** |
| 10 | Rule 5 (≤ MAX_REPLACEMENT_CANDIDATES distinct clusters) | G19: bound is on DISTINCT CLUSTERS of direct conflicts | **BUG-14 (P0-CDIV)** — `do_rbf` line 1962 and `do_package_rbf` line 1428 enforce `length(AllEvictTxids) =< 100` (total txs including descendants). Core bounds DISTINCT CLUSTERS of `iters_conflicting` via `GetUniqueClusterCount` (rbf.cpp:69). Rule 5 limit is therefore **wrong axis** — beamchain rejects valid replacements with 1 cluster + 101 descendants; admits invalid replacements with 200 clusters × 0 descendants |
| 11 | Rule 3 (PaysForRBF — more abs. fees) | G20: replacement_fees ≥ original_fees | PASS (`mempool.erl:1442, 1982`) — but reject-string atom is `rbf_insufficient_fee` not the Core wire-format |
| 12 | Rule 4 (PaysForRBF — covers own relay bandwidth) | G21: additional_fees ≥ incremental_relay × replacement_vsize | PASS structurally (`mempool.erl:1446-1448, 1992-1994`); but **BUG-15** below — uses Erlang-side incremental fee that is ALSO 10× too low relative to a constant DEFAULT_MIN_RELAY_TX_FEE that is 10× too high — interactions cancel imperfectly |
| 13 | Rule 2 (no new unconfirmed) | G22: replacement may add new unconfirmed input | **BUG-16 (P1)** — Core REMOVED this gate for single-tx RBF (cluster diagram-domination replaces it). beamchain still enforces it as a hard reject (`mempool.erl:1937-1938`) → over-rejects valid single-tx replacements that pull in new in-mempool ancestors; throws `rbf_new_unconfirmed_inputs` (also wrong wire string) |
| 14 | Cluster Rule 5 (BIP-125 signaling) | G23: `IsRBFOptIn` — any conflicting tx signals via `nSequence ≤ MAX_BIP125_RBF_SEQUENCE` (or inherits from ancestor) | PASS (`mempool.erl:761-770, 1265-1273`) |
| 14 | … | G24: full-RBF default ON (Core 28.0+ removed the option entirely) | PARTIAL — beamchain defaults true but still honors `BEAMCHAIN_FULLRBF=0` / `mempoolfullrbf=0` → can downgrade to BIP-125 signaling enforcement. Core 28.0+ hardcoded ON; the no-signaling-required path is no longer optional |
| 15 | RBF dry-run idempotence | G25: testmempoolaccept must NOT mutate the mempool | **BUG-17 (P0-CDIV)** — `do_add_transaction_dry_run` (line 915) calls `check_mempool_conflicts` → `do_rbf` → `remove_entry` on real ETS. Dry-run for a replacement actually EVICTS the conflicts permanently. Same path via package dry-run (`dry_run_individual_accept` line 1028 → `do_add_transaction_dry_run`). FIX-54/W116 BUG-1 fixed the case where dry-run inserted into ETS; the converse mutation (eviction) was not fixed |
| 16 | Block-conflict removal | G26: removeConflicts iterates BLOCK-tx inputs and looks up mempool spenders of THAT outpoint | **BUG-18 (P0-CDIV)** — `remove_block_conflicts` (`mempool.erl:2742-2787`) iterates MEMPOOL-tx inputs and checks `prev_out.hash ∈ ConfSet`. This evicts every mempool tx referencing a confirmed parent txid — exactly the legitimate CPFP-children that should now be mineable from UTXO. Same shape as **W150 BUG-11**. Exact CVE-class: post-block-confirmation mempool wipeout for CPFP/RBF flows |
| 17 | Orphan reprocess self-deadlock | G27: reprocess_orphans called from inside handle_call must not call back into gen_server | **BUG-19 (P0-CDIV)** — `reprocess_orphans/1` (line 2598) calls `add_transaction(OrphanTx)` (line 2612), which is `gen_server:call(?SERVER, {add_tx, Tx}, 30000)` (line 202). Called from `do_add_transaction` (line 817), `accept_package_txs` (line 1515), and `do_remove_for_block` → `erase_orphans_for_block` → `reprocess_orphans` (line 3040). All three sites are inside `handle_call`. Self-deadlock — gen_server is busy in this call, so the call-from-self waits up to 30 s then crashes the caller. **Exact W150 BUG-12 pattern** |
| 18 | Sigops-vsize parity in package | G28: package vsize is sigop-adjusted (`tx_sigop_vsize`) | PASS (`mempool.erl:1258`) — beamchain uses sigop-adjusted vsize in the package fee-rate denominator |
| 19 | Package fee gate matches Core | G29: package fee >= max(rolling_min_fee, min_relay_fee) | **BUG-20 (P0-CDIV)** — `evaluate_package_cpfp:1209-1210`: `PackageFeeRate >= 1.0 sat/vB`. Hardcoded constant. Ignores BOTH `RollingMin` (line 695 has it for single-tx path) AND `DEFAULT_MIN_RELAY_TX_FEE` (which beamchain has wrong anyway). When the mempool is full, package CPFP bypasses the rolling-fee DoS defence entirely |
| 20 | TRUC sibling eviction fee delta | G30: sibling-eviction must cover sibling_fee + incremental_relay × new_vsize | **BUG-21 (P1)** — `do_truc_sibling_eviction` (line 3252): `MinFee = SiblingFee + NewVSize` = sibling_fee + 1 sat/vB × new_vsize. Hardcodes 1 sat/vB; should be 0.1 sat/vB per `DEFAULT_INCREMENTAL_RELAY_FEE`. Also `tx_vsize` (raw, not sigop-adjusted) |
| 21 | DEFAULT_MIN_RELAY_TX_FEE constant | G31: equals Core's 100 sat/kvB | **BUG-22 (P0-CDIV)** — `?DEFAULT_MIN_RELAY_TX_FEE = 1000` (protocol.hrl:161) AND `?MIN_RELAY_TX_FEE = 1000` (mempool.erl:99) — TWO copies, BOTH 10× Core. Direct impact: every "min fee" gate (single-tx mempool gate, RBF Rule 4 incremental, package CPFP fee gate when finally fixed) is 10× too high. Direct **W150 BUG-5** cross-cite; not yet fixed |
| 22 | submitpackage relay uses MSG_WTX for BIP-339 peers | G32: per-peer MSG_TX vs MSG_WTX choice | **BUG-23 (P1)** — `relay_transaction` (`rpc.erl:2706-2713`) sends to ALL peers as `MSG_TX` regardless of `wtxidrelay` advertisement. peer_manager has `inv_items_from_pairs` that DOES pick MSG_WTX for wtxidrelay peers (line 1882-1890), but the submitpackage / sendrawtransaction relay path bypasses it. Wtxidrelay peers may discard MSG_TX inv (some Core deployments do) and the wtxid-based reject cache misses |
| 23 | Same-txid-different-witness in package | G33: detect and emit `other-wtxid` per Core | **BUG-24 (P1)** — `try_individual_accept` (mempool.erl:1167-1193) only deduplicates by txid; a package tx that hits a same-txid-different-witness mempool entry is silently `[Txid \| AcceptedAcc]` instead of producing `MempoolTxDifferentWitness` and emitting `other-wtxid` in the RPC reply |

---

## BUG-1 (P1) — Topo-sort allows self-spending input

**Severity:** P1. beamchain explicitly excludes self-input from the
later-set check (`H =/= Txid andalso sets:is_element(H, LaterTxids)`,
mempool.erl:1119-1120). Core's `IsTopoSortedPackage` (packages.cpp:29)
does NOT exclude self — it deletes `Txid` from `later_txids` AFTER the
input scan (line 35), so an input with `prevout.hash == own_txid` is
detected as parent-after-child.

**File:** `src/beamchain_mempool.erl:1116-1128`.

**Core ref:** `bitcoin-core/src/policy/packages.cpp:19-41`.

**Excerpt (beamchain, divergence)**
```erlang
SpendsFuture = lists:any(fun(#tx_in{prev_out = #outpoint{hash = H}}) ->
    H =/= Txid andalso sets:is_element(H, LaterTxids)   %% <-- explicit self-skip
end, Tx#transaction.inputs),
```

**Impact:** a malformed tx whose input references its own txid (would
never validate downstream, but the topo-sort phase admits the package
into the heavier pipeline). Minor by itself; symptomatic of a "tighten
the gate but harden the wrong direction" bug.

---

## BUG-2 (P1) — `is_consistent_package` admits empty-input txs

**Severity:** P1. Core (`packages.cpp:57-62`) explicitly rejects any
tx with `vin.empty()` as INCONSISTENT (with an explanatory comment:
"duplicate empty transactions are also not consistent with one
another"). beamchain's `is_consistent_package` (mempool.erl:1131-1136)
only checks that no two inputs match — txs with zero inputs slip
through with a `lists:flatmap` over empty inputs producing no outpoints,
trivially `lists:usort` matching `length`.

**File:** `src/beamchain_mempool.erl:1131-1136`.

**Core ref:** `bitcoin-core/src/policy/packages.cpp:57-62`.

**Impact:** a 0-input tx in a package passes the consistency gate
(rejected downstream at coinbase detection, but the consistency
diagnostic is silently lost; Core surfaces it explicitly).

---

## BUG-3 (P0-CDIV) — `IsChildWithParentsTree` not enforced for multi-tx submitpackage

**Severity:** P0-CDIV. Core's `submitpackage` (rpc/mempool.cpp:1395)
calls `IsChildWithParentsTree` — child-with-parents PLUS the extra
constraint that none of the parents has an input spending another
parent (packages.cpp:136-149). beamchain only enforces
`is_child_with_parents` (mempool.erl:1100); the
parents-don't-depend-on-each-other tree property is never checked.

**File:** `src/beamchain_mempool.erl:1100, 1138-1157` (no
`is_child_with_parents_tree` exists anywhere).

**Core ref:** `bitcoin-core/src/policy/packages.cpp:136-149` (the tree
check); `bitcoin-core/src/rpc/mempool.cpp:1395-1397` (the call site,
throws `"package topology disallowed. not child-with-parents or
parents depend on each other."`).

**Impact:** beamchain admits packages with non-tree shape into the
mempool acceptance path. These packages then fail later in subtler
ways (orphan-then-eviction, ancestry-limit miscount, RBF cluster math
gone wrong). The Core-canonical reject string never appears. RPC
clients depending on `package_msg` to distinguish topology failures
from fee failures get wrong diagnostic.

---

## BUG-4 (P1) — submitpackage / sendrawtransaction maxfeerate uses raw vsize, not sigop-adjusted

**Severity:** P1. Core (rpc/mempool.cpp:1367-1372) calls
`ParseFeeRate(maxfeerate)` and then implicitly compares against
`CFeeRate(ws.m_modified_fees, ws.m_vsize)` where `ws.m_vsize` is
sigop-adjusted via `GetVirtualTransactionSize(nTxWeight, sigOpCost,
nBytesPerSigOp)`. beamchain's `check_max_fee_rate` (rpc.erl:2673-2690)
calls `beamchain_serialize:tx_vsize/1` — the raw (weight-only) vsize.

**File:** `src/beamchain_rpc.erl:2684`.

**Core ref:** `bitcoin-core/src/policy/policy.cpp::GetVirtualTransactionSize`
(sigop-adjusted vsize); `bitcoin-core/src/rpc/mempool.cpp:1367-1372`
(maxfeerate parse + per-tx check).

**Impact:** for high-sigop txs (e.g., raw P2SH multisig with many
sigops), the effective vsize is `sigop_cost × DEFAULT_BYTES_PER_SIGOP
/ 4`; using the raw vsize understates the denominator → fee_rate
appears higher → maxfeerate trips on txs Core would admit, OR (more
commonly) the maxfeerate barrier is bypassed for txs Core would
reject. Direct W144 cross-cite (STANDARD-flag accounting axis).

---

## BUG-5 (P1) — submitpackage maxfeerate ignores package-internal parents

**Severity:** P1. `check_max_fee_rate` calls
`compute_tx_input_value(Tx)` (rpc.erl:2693-2703) which looks up
inputs only in the **UTXO set + current mempool**. Package-internal
parents (the parent txs in the same submitpackage call) are not yet
in either; their outputs are not visible. The function returns
`Acc = 0` for unknown inputs, so `TotalIn = 0` for a package child
that fully depends on package parents → `Fee = -TotalOut` (or 0 if
clamped) → the maxfeerate check is bypassed.

**File:** `src/beamchain_rpc.erl:2693-2703`.

**Core ref:** Core uses `m_viewmempool.PackageAddTransaction(ws.m_ptx)`
during the per-workspace loop (validation.cpp:1476) so that subsequent
package txs can see the staged outputs of earlier package txs. The
client_maxfeerate per-tx check (validation.cpp:1458) runs AFTER
PreChecks has populated all the package-internal inputs.

**Impact:** clients passing `maxfeerate=0.01 BTC/kvB` expect every tx
in the package to be ≤ that rate; package-internal children evade the
gate entirely. Anti-fat-finger protection is silently disabled for
package CPFP.

---

## BUG-6 (P1) — `maxburnamount` skipped when arg is 0 (Core checks unconditionally with default 0)

**Severity:** P1. Core's submitpackage burn check
(`rpc/mempool.cpp:1387`):
```cpp
if ((out.scriptPubKey.IsUnspendable() || !out.scriptPubKey.HasValidOps())
     && out.nValue > max_burn_amount) { throw ... }
```
The check is UNCONDITIONAL; `max_burn_amount` defaults to
`DEFAULT_MAX_BURN_AMOUNT = 0` (mempool.cpp:1322 calls it). With
default args, ANY unspendable output with value > 0 is rejected.
beamchain (`rpc.erl:2939-2954`):
```erlang
case MaxBurnSat > 0 of
    true -> ... actual check ...
    false -> ok                          %% <-- skipped at default args
end,
```
So beamchain's default behavior is "no burn check at all"; Core's
default behavior is "reject any burn > 0". Additionally beamchain
only tests `ds_is_unspendable` (OP_RETURN prefix); the
`HasValidOps()` half — which rejects scripts with truncated pushes
or invalid opcodes — is missing entirely.

**File:** `src/beamchain_rpc.erl:2939-2954`, `4157-4159`
(`ds_is_unspendable`).

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp:1387-1390`.

**Impact:** anti-fat-finger burn protection is OFF by default in
beamchain; submitpackage admits arbitrary OP_RETURN-burn amounts.
Operators relying on the BIP-125-era safety default are silently
unprotected. Scripts with `HasValidOps()=false` (truncated pushes)
are NOT classified as unspendable, but Core treats them as such for
the burn gate.

---

## BUG-7 (P1) — `tx-results` map omits `effective-feerate`, `effective-includes`, `other-wtxid`

**Severity:** P1. Core's submitpackage emits per-VALID-tx:
```json
{ "txid": "...",
  "vsize": 165,
  "fees": {
      "base": 0.0001,
      "effective-feerate": 0.0005,
      "effective-includes": ["wtxid1", "wtxid2", ...] } }
```
plus `"other-wtxid"` when the wtxid mismatches a same-txid mempool
entry. beamchain's `build_pkg_tx_result` (rpc.erl:3039-3067) only
emits `txid`, `vsize`, `fees.base` — three fields out of seven.

**File:** `src/beamchain_rpc.erl:3039-3067`.

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp:1483-1503`.

**Impact:** RPC clients (bitcoind-compat tools, hardware-wallet
integrations, fee-bumping scripts) cannot detect package CPFP feerate
from beamchain's response; they have to recompute it client-side from
fee/vsize, but without effective-includes they cannot tell which
sibling txs were folded into the package-feerate calculation.

---

## BUG-8 (P0-DIV) — `package_msg` returns Erlang term-print instead of Core wire string

**Severity:** P0-DIV (wire-format divergence). `rpc.erl:2962-2966`:
```erlang
{error, Reason} ->
    ReasonBin = iolist_to_binary(io_lib:format("~p", [Reason])),
    {ReasonBin, sets:new()}
```
`Reason` is an atom thrown by the mempool (e.g.,
`rbf_not_signaled`, `package_fee_too_low`,
`rbf_too_many_evictions`, `{tx_failed, <<...>>, 'mempool min fee not met'}`).
`io_lib:format("~p")` produces strings like
`<<"rbf_not_signaled">>`, `<<"{tx_failed,<<...>>,'mempool min fee not met'}">>`.

Core's canonical wire strings:
- `"insufficient fee, rejecting replacement <hash>; ..."`
- `"too many potential replacements"`
- `"package-too-many-transactions"` (hyphen, not underscore)
- `"package-too-large"`
- `"package-contains-duplicates"`
- `"package-not-sorted"`
- `"package-not-child-with-parents"`
- `"replacement-adds-unconfirmed"`
- `"bip125-replacement-disallowed"`
- `"replacement-failed"`

**File:** `src/beamchain_rpc.erl:2962-2966`, `3062-3066`; reject-string
atoms thrown all over `src/beamchain_mempool.erl:1072-2047`.

**Core ref:** `bitcoin-core/src/policy/rbf.cpp:71-122`,
`bitcoin-core/src/policy/packages.cpp:84-114`,
`bitcoin-core/src/validation.cpp:839, 974, 1000, 1014, 1031, 1065,
1085, 1101, 1110, 1116, 1123`.

**Impact:** every RPC client that switch/case-es on `package_msg` to
distinguish Rule 3 vs Rule 5 vs structural failures sees mismatched
strings. electrs / fulcrum / mempool.space / nbxplorer / RBF
tracker / wallet fee-bumpers all break for package errors. The
wire-format gap is the equivalent of W141 BUG-1 (ZMQ hash byte-order)
applied to mempool reject reasons.

---

## BUG-9 (P1) — `replaced-transactions` always empty

**Severity:** P1. beamchain emits `<<"replaced-transactions">> => []`
unconditionally (`rpc.erl:2993`), with an in-code admission comment:
"beamchain's package validator does not yet emit a per-package
replaced-tx list. Empty array keeps the field shape parity with
Core." Core's array is populated from `tx_result.m_replaced_transactions`
on each VALID per-tx result (rpc/mempool.cpp:1500-1502).

**File:** `src/beamchain_rpc.erl:2986-2994`.

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp:1500-1510`.

**Impact:** package-RBF clients cannot tell which mempool txs were
evicted by their replacement; fee-bumping wallets that need to
double-spend-cancel the original txs get no signal. The mempool DID
evict them (line 1458-1460), the RPC just refuses to report it.

---

## BUG-10 (P0-CDIV) — submitpackage NOT atomic: partial accepts persist on CPFP failure

**Severity:** P0-CDIV. `do_accept_package` (mempool.erl:1046-1069)
calls `try_individual_accept` (each tx hits `do_add_transaction` →
**inserts into ETS and threads State**), then on remaining deferred
txs calls `evaluate_package_cpfp`. If CPFP throws (e.g.,
`package_fee_too_low`, sigops, TRUC violation), `do_accept_package`
catches and returns `{error, Reason}`.

Back in `handle_call({accept_package, ...}, _From, State)` (line
432-438):
```erlang
{error, Reason} -> {reply, {error, Reason}, State}        %% <-- ORIGINAL State
```
The reply uses the original State, but the individually-accepted txs
are PHYSICALLY IN ETS (insert_entry was called for them). State now
reports `total_count = N` while ETS holds `N + k` entries. Mempool
size accounting silently drifts. Subsequent trim_to_size /
GetMinFee math is wrong. AcceptPackage is supposed to be
all-or-nothing per Core (PackageMempoolAcceptResult atomicity); this
implementation leaks partial state.

**File:** `src/beamchain_mempool.erl:432-438, 1046-1069, 1162-1194`.

**Core ref:** `bitcoin-core/src/validation.cpp:1432-1564`
(`AcceptMultipleTransactionsInternal` uses a single changeset; on
failure, the changeset is discarded — nothing reaches the mempool
unless every tx passed).

**Impact:** observable: the rejected package leaves txs in mempool
that don't appear in `getmempoolinfo.size` (because State.total_count
wasn't bumped). They will appear in `getrawmempool`. Long-term:
the mempool grows in ETS but the count diverges; trim-to-size
under-counts and may not trigger when it should. Operator visible.

---

## BUG-11 (P0-CDIV) — Package RBF accepts any package size (Core: only 2-tx)

**Severity:** P0-CDIV. Core's `PackageRBFChecks` (validation.cpp:1051):
```cpp
if (workspaces.size() != 2 || !Assume(IsChildWithParents(txns))) {
    return package_state.Invalid(PackageValidationResult::PCKG_POLICY,
        "package RBF failed: package must be 1-parent-1-child");
}
```
Package RBF in Core 28+ is restricted to exactly a 1-parent + 1-child
shape. beamchain's `do_package_rbf` (mempool.erl:1397-1463) operates
on any package size (`DeferredTxs`, `ConflictTxids`, no count gate).

**File:** `src/beamchain_mempool.erl:1397-1463`.

**Core ref:** `bitcoin-core/src/validation.cpp:1037-1067`.

**Impact:** beamchain allows 3-tx, 4-tx, etc. package replacements
that Core would reject. The cluster math underlying ImprovesFeerateDiagram
assumes 2-tx topology; running it with larger packages may produce
either false-positives (admit unimprovements) or unbounded cluster
work.

---

## BUG-12 (P0-CDIV) — Package RBF skips "new transaction cannot have mempool ancestors"

**Severity:** P0-CDIV. Core (validation.cpp:1063-1067):
```cpp
for (const auto& ws : workspaces) {
    if (!ws.m_parents.empty()) {
        return package_state.Invalid(PackageValidationResult::PCKG_POLICY,
            "package RBF failed: new transaction cannot have mempool ancestors");
    }
}
```
beamchain's `do_package_rbf` performs no such gate. The Core invariant
is that package-RBF can only replace direct conflicts of a fresh
package (no in-mempool parents), to avoid combinatorial cluster
expansion. beamchain accepts package-RBF for txs whose parents are
already in mempool, which can result in CCoinsViewMemPool
inconsistency in Core terminology (line 1057-1062 explains the design
constraint).

**File:** `src/beamchain_mempool.erl:1397-1463` (gate is absent).

**Core ref:** `bitcoin-core/src/validation.cpp:1056-1067`.

**Impact:** beamchain accepts package replacements that Core rejects.
The cluster-merge logic during `accept_package_txs` may misclassify
clusters when ancestors of package txs already exist in another
cluster — this is the exact path Core's check prevents.

---

## BUG-13 (P1) — Package RBF does NOT call ImprovesFeerateDiagram dominance

**Severity:** P1. Core's `PackageRBFChecks` (validation.cpp:1120):
```cpp
if (const auto err_tup{ImprovesFeerateDiagram(*m_subpackage.m_changeset)}) {
    Assume(err_tup->first == DiagramCheckError::FAILURE);
    return package_state.Invalid(PackageValidationResult::PCKG_POLICY,
                                 "package RBF failed: " + err_tup.value().second, "");
}
```
beamchain's `do_package_rbf` runs Rules 3+4 plus a per-conflict
fee-rate comparison (line 1450-1455 `PackageFeeRate > E#mempool_entry.fee_rate`),
but **does not run cluster-diagram dominance** for the package path.
The single-tx path has `check_cluster_rbf_diagram` (line 2036-2106),
but it's only invoked from `do_rbf`, not from `do_package_rbf`.

**File:** `src/beamchain_mempool.erl:1397-1463` (no
`check_cluster_rbf_diagram` call in package path).

**Core ref:** `bitcoin-core/src/validation.cpp:1119-1124`,
`bitcoin-core/src/policy/rbf.cpp:127-140` (ImprovesFeerateDiagram).

**Impact:** package RBF admits replacements that DON'T strictly
improve mempool quality; under load this enables fee-grinding pinning
attacks. The per-conflict fee-rate check is the OLD pre-cluster-mempool
gate; Core deprecated it precisely because it's too permissive.

---

## BUG-14 (P0-CDIV) — Rule 5 limit applied on TOTAL EVICTED TXS, not DISTINCT CLUSTERS

**Severity:** P0-CDIV. Core's `GetEntriesForConflicts`
(rbf.cpp:69-75):
```cpp
auto num_clusters = pool.GetUniqueClusterCount(iters_conflicting);
if (num_clusters > MAX_REPLACEMENT_CANDIDATES) {  // 100
    return strprintf("rejecting replacement %s; too many conflicting clusters (%u > %d)", ...);
}
```
The bound is on UNIQUE CLUSTERS of the DIRECT CONFLICTS. The
descendants (`all_conflicts` includes descendants of `iters_conflicting`)
are NOT counted toward the 100 limit. beamchain (`mempool.erl:1962`,
`1428`):
```erlang
AllEvictTxids = lists:usort(DescendantsAndSelf ++ EphemeralParents),
length(AllEvictTxids) =< ?MAX_RBF_EVICTIONS  %% 100
    orelse throw(rbf_too_many_evictions),
```
The bound is on TOTAL EVICTED TXS including descendants.

**File:** `src/beamchain_mempool.erl:1962-1963, 1428-1429`.
`include/beamchain_protocol.hrl:169`.

**Core ref:** `bitcoin-core/src/policy/rbf.cpp:64-83`,
`bitcoin-core/src/policy/rbf.h:24-26`.

**Impact:**
- **Over-rejection**: replacing one tx with 1 cluster + 101 descendants
  hits beamchain's 100 limit but is valid for Core (1 < 100 clusters).
- **Under-rejection**: a tx conflicting with 200 isolated direct
  conflicts (zero descendants) PASSES beamchain (200 ≤ 100 only if
  descendants tallied) — actually fails beamchain too; but a
  craftable case where 99 direct conflicts each have 0 descendants
  passes both… the AXIS is wrong. The intent of the 100 limit is to
  bound cluster-resort work, which is per-cluster, not per-tx.

The Core canonical reject string is `"too many potential replacements"`
or `"rejecting replacement <hash>; too many conflicting clusters (N > 100)"`;
beamchain emits `rbf_too_many_evictions` (BUG-8 cross-cite).

---

## BUG-15 (P1) — RBF Rule 4 incremental-relay-feerate is the right CONSTANT but operates on a different MIN_RELAY axis

**Severity:** P1. Beamchain has `?DEFAULT_INCREMENTAL_RELAY_FEE = 100`
(correct), but `?DEFAULT_MIN_RELAY_TX_FEE = 1000` (10× too high — see
BUG-22). Rule 4 in beamchain (line 1992):
```erlang
MinAdditionalFee = (NewVSize * ?DEFAULT_INCREMENTAL_RELAY_FEE + 999) div 1000,
(NewFee - EvictedFeeTotal) >= MinAdditionalFee
    orelse throw(rbf_insufficient_additional_fee),
```
This is structurally correct (Core: `additional_fees >=
relay_fee.GetFee(replacement_vsize)` where `relay_fee =
incremental_relay_feerate = 100 sat/kvB`).

BUT the single-tx mempool gate uses `?DEFAULT_MIN_RELAY_TX_FEE = 1000`
which means any sub-1-sat/vB tx is rejected before RBF even runs.
When BUG-22 is fixed (lower to 100 sat/kvB = 0.1 sat/vB), the
existing Rule 4 implementation will start admitting RBFs that Core
admits — but the per-conflict feerate gate (BUG-13 territory) is too
strict for some valid cases.

**File:** `src/beamchain_mempool.erl:1992-1994, 1446-1448`.

**Core ref:** `bitcoin-core/src/policy/rbf.cpp:114-123`,
`bitcoin-core/src/policy/policy.h:48`.

**Impact:** subtler — depends on the BUG-22 fix to surface. Documented
here so the constant-update fix touches both sites.

---

## BUG-16 (P1) — Single-tx RBF still enforces removed Rule 2 (HasNoNewUnconfirmedParents)

**Severity:** P1. Bitcoin Core removed BIP-125 Rule 2 from the
single-tx RBF path; the cluster-mempool feerate-diagram dominance
check replaced it. Modern Core single-tx RBF allows the replacement
to spend new in-mempool ancestors as long as the chunk-aware feerate
strictly improves.

beamchain still enforces it (`mempool.erl:1929-1938`):
```erlang
%% 2. new tx must not add new unconfirmed parents (Rule 2)
%% Core: validation.cpp HasNoNewUnconfirmedParents check.
NewParents = get_parent_txids(NewTx),
OldParents = lists:usort(lists:flatmap(fun(E) ->
    get_parent_txids(E#mempool_entry.tx)
end, ConflictEntries)),
NewUnconfirmed = NewParents -- OldParents -- ConflictTxids,
NewUnconfirmed =:= [] orelse throw(rbf_new_unconfirmed_inputs),
```

Comment references "Core: validation.cpp HasNoNewUnconfirmedParents
check" — that function no longer exists in the single-tx path.

**File:** `src/beamchain_mempool.erl:1929-1938`.

**Core ref:** Removed circa Bitcoin Core 28.x; package RBF
(validation.cpp:1064) still enforces it (no mempool ancestors), but
that's a stricter PACKAGE rule, not the single-tx Rule 2.

**Impact:** beamchain over-rejects valid single-tx RBF replacements
that incorporate new unconfirmed parents. CPFP-then-bump flows are
broken in beamchain when the bumper would pull in a new parent.

---

## BUG-17 (P0-CDIV) — testmempoolaccept dry-run EVICTS conflicting mempool entries

**Severity:** P0-CDIV. `do_add_transaction_dry_run` (mempool.erl:857-992)
runs all 21 gates without inserting the new tx. **But Gate 10**
(line 915):
```erlang
{ok, RbfEvictedTxids, _RbfEvictedVBytes} =
    check_mempool_conflicts(Tx, InputCoins, TxSigopCost),
```
`check_mempool_conflicts` (line 1884-1892) calls `do_rbf` on conflict,
and `do_rbf` (line 2006-2013) **calls `remove_entry` for every
conflicting tx**:
```erlang
EvictedVBytes = lists:foldl(fun(EvictTxid, Acc) ->
    case remove_entry(EvictTxid) of      %% <-- REAL ETS delete
        #mempool_entry{vsize = VS} -> Acc + VS;
        not_found -> Acc
    end
end, 0, AllEvictTxids),
```

`remove_entry` deletes from `?MEMPOOL_TXS`, `?MEMPOOL_BY_FEE`,
`?MEMPOOL_OUTPOINTS`, `?MEMPOOL_EPHEMERAL`. ETS is shared across all
gen_server calls — the State reply that "discards" the dry-run is
purely cosmetic; the eviction is permanent.

Same path triggers via package dry-run (`dry_run_individual_accept`
line 1028 → `do_add_transaction_dry_run`).

**File:** `src/beamchain_mempool.erl:915, 1884-1892, 2006-2013`.

**Core ref:** Core's `MemPoolAccept::AcceptSingleTransaction` with
`m_test_accept=true` (validation.cpp:1388 returns early without
running `SubmitPackage`/`Finalize`; the changeset is discarded);
nothing is ever evicted in dry-run.

**Impact:** invoking `testmempoolaccept` on a candidate RBF tx
DESTROYS the original in mempool. This is the exact failure-mode
that FIX-54/W116 BUG-1 fixed for the OPPOSITE direction
(`accept_to_memory_pool` then `remove_for_block` was real insert →
real remove). The eviction side of the same problem was not fixed —
the FIX-54 commit added a dry-run-specific gate path but routed the
RBF conflict check through the production `check_mempool_conflicts`
→ `do_rbf` → `remove_entry` chain.

W116 partial-fix completeness regression. The W116 commit
documentation referenced this exact failure mode for accept-side; the
remove-side via RBF was missed.

---

## BUG-18 (P0-CDIV) — `remove_block_conflicts` evicts CPFP children instead of double-spends

**Severity:** P0-CDIV. Direct W150 BUG-11 cross-cite. `remove_block_conflicts`
(mempool.erl:2742-2787):
```erlang
ConfSet = sets:from_list(ConfirmedTxids),
AllEntries = ets:tab2list(?MEMPOOL_TXS),
lists:foldl(fun({Txid, Entry}, {Bytes, Count, St}) ->
    case sets:is_element(Txid, ConfSet) of
        true -> {Bytes, Count, St};
        false ->
            HasConflict = lists:any(
                fun(#tx_in{prev_out = #outpoint{hash = H}}) ->
                    sets:is_element(H, ConfSet)        %% <-- WRONG: H is the FUNDING txid
                end,
                (Entry#mempool_entry.tx)#transaction.inputs),
            case HasConflict of
                true ->
                    %% remove this tx and its descendants
                    ...evict...
```

The predicate fires when a mempool tx's input references a confirmed
block tx's hash. That means the mempool tx is the CONFIRMED tx's
CHILD (spending its outputs from the new UTXO). Such children should
remain in mempool (now mineable). They should NOT be evicted.

Correct check (Core, txmempool.cpp:388-403): iterate over the
**inputs of the confirmed tx**, look up `mapNextTx[txin.prevout]`
to find any mempool tx spending the SAME OUTPOINT (i.e., a
double-spend); evict only that.

**File:** `src/beamchain_mempool.erl:2742-2787` (inverted predicate);
`2754-2758` (the wrong scan).

**Core ref:** `bitcoin-core/src/txmempool.cpp:388-403`
(`removeConflicts(tx)`).

**Impact:** every CPFP child whose parent confirmed in the latest
block gets nuked from the mempool. RBF + CPFP fee-bumping flows are
broken at block-connect time. Anyone-can-spend / payjoin /
lightning-channel-bump txs get evicted. The error is silent (just a
debug log "removed N txs for block").

This is the SAME PATTERN as W150 BUG-11 — the inverted-predicate
class. Two distinct beamchain `remove_*` functions exhibit the same
bug; the previous wave caught one (in some other function), this one
catches `remove_block_conflicts`. The code-duplication smell from
W143 BUG-3 (byte-identical `merkle_pairs` / `merkle_pairs_check`)
recurs here as semantically-similar functions with the same
inverted check.

---

## BUG-19 (P0-CDIV) — `reprocess_orphans` self-deadlocks gen_server (W150 BUG-12 SAME PATTERN)

**Severity:** P0-CDIV. Direct W150 BUG-12 cross-cite — present in
THREE call sites and not fixed despite W150 catching it.

`reprocess_orphans/1` (mempool.erl:2598-2622):
```erlang
reprocess_orphans(NewTxid) ->
    Orphans = ets:tab2list(?MEMPOOL_ORPHANS),
    lists:foreach(fun({OrphanWtxid, OrphanTx, _Expiry}) ->
        ...
        case add_transaction(OrphanTx) of           %% <-- gen_server:call to SELF
            {ok, _} -> ... ;
            {error, _} -> ok
        end;
        ...
    end, Orphans).
```

`add_transaction/1` (line 200-202):
```erlang
add_transaction(Tx) ->
    gen_server:call(?SERVER, {add_tx, Tx}, 30000).
```

Three callers, ALL inside `handle_call`:
1. `do_add_transaction` line 817 (single-tx accept path)
2. `accept_package_txs` line 1515 (package accept path)
3. `do_remove_for_block` → `erase_orphans_for_block` → `reprocess_orphans`
   line 3040 (block-confirmation path)

In all three: the gen_server is currently executing `handle_call`;
the inner `gen_server:call(?SERVER, {add_tx, ...}, 30000)` is a call
to the SAME PROCESS that's already blocked. Erlang's gen_server
serializes handle_call, so the inner call queues until handle_call
returns. handle_call won't return until the inner call returns.
Deadlock → 30s timeout → caller crashes with `{timeout, ...}` → if
called via RPC, the RPC dies; if called via block-connect, the
chainstate-mempool handshake breaks.

W150 documented this as BUG-12; not fixed in this submodule.

**File:** `src/beamchain_mempool.erl:817, 1515, 3040, 2598-2622, 200-202`.

**Core ref:** Core uses `LOCK(m_pool.cs)` (a single mutex held for
the duration of the operation), and re-enters the mempool re-add
logic without round-tripping through the message bus. beamchain's
gen_server-as-bus pattern is fundamentally incompatible with
re-entry — fix is to refactor `reprocess_orphans` to take the gen_server
State directly and call `do_add_transaction(OrphanTx, State)` rather
than the gen_server:call public API.

**Impact:** every orphan promotion path is a latent 30-second freeze.
RPC senders see timeouts; block-connect mempool reconciliation may
silently drop orphans on every block. The W150 BUG-12 fix proposal
("refactor to thread State directly") applies verbatim.

---

## BUG-20 (P0-CDIV) — Package CPFP fee gate hardcoded 1 sat/vB; ignores rolling-min-fee

**Severity:** P0-CDIV. `evaluate_package_cpfp` (mempool.erl:1206-1210):
```erlang
PackageFeeRate = TotalFee / max(1, TotalVSize),
%% Check against minimum relay fee (1 sat/vB)
PackageFeeRate >= 1.0 orelse throw(package_fee_too_low),
```

Two divergences from Core (validation.cpp:1507-1512):
```cpp
if (args.m_package_feerates &&
    !CheckFeeRate(m_subpackage.m_total_vsize, m_subpackage.m_total_modified_fees, placeholder_state)) {
    package_state.Invalid(PackageValidationResult::PCKG_TX, "transaction failed");
    ...
}
```
where `CheckFeeRate` compares against `max(GetMinFee(), min_relay_feerate)` —
the rolling minimum fee (which grows under mempool pressure) AND the
static min-relay floor. beamchain:
1. Hardcodes 1.0 sat/vB instead of reading
   `?DEFAULT_MIN_RELAY_TX_FEE / 1000.0` (which would be 0.1 if BUG-22
   is fixed).
2. Ignores `RollingMin` entirely — the single-tx path on the same
   value gets it (`mempool.erl:694-697`), but the package path skips it.

**File:** `src/beamchain_mempool.erl:1206-1210`.

**Core ref:** `bitcoin-core/src/validation.cpp:1507-1512`,
`bitcoin-core/src/validation.cpp::CheckFeeRate`.

**Impact:**
- under-priced packages bypass the static min-relay gate (because 1.0
  sat/vB is the hardcoded floor; when min-relay should be 0.1, the
  gate over-rejects).
- under-load packages bypass the rolling fee defence entirely —
  beamchain's anti-DoS rolling-fee bump is rendered ineffective for
  the package path. Memory exhaustion vector: spam under-priced
  packages that pass the gate, then trim_to_size has to evict them
  later (extra work).

---

## BUG-21 (P1) — TRUC sibling-eviction fee delta uses raw vsize and 1 sat/vB

**Severity:** P1. `do_truc_sibling_eviction` (mempool.erl:3245-3273):
```erlang
SiblingFee = SiblingEntry#mempool_entry.fee,
NewVSize = beamchain_serialize:tx_vsize(NewTx),         %% raw, not sigop-adjusted
MinFee = SiblingFee + NewVSize,                          %% 1 sat/vB * new_vsize
case NewFee >= MinFee of
```

Core's `incremental_relay_feerate.GetFee(vsize)` for sibling-eviction
in TRUC path is `DEFAULT_INCREMENTAL_RELAY_FEE * vsize / 1000` =
`100 * vsize / 1000` = `0.1 sat/vB * vsize` (10× lower than 1 sat/vB).
And vsize MUST be sigop-adjusted (cross-cite BUG-4).

**File:** `src/beamchain_mempool.erl:3251-3253`.

**Core ref:** `bitcoin-core/src/policy/truc_policy.cpp::SingleTRUCChecks`
(uses `m_pool.m_opts.incremental_relay_feerate.GetFee(...)` and Core's
`m_vsize` is sigop-adjusted).

**Impact:** beamchain rejects TRUC sibling-eviction replacements that
Core admits (over-rejection by 10× on the incremental fee axis).
High-sigop replacement txs see additional rejection bias via the raw
vsize.

---

## BUG-22 (P0-CDIV) — `DEFAULT_MIN_RELAY_TX_FEE` and `MIN_RELAY_TX_FEE` are both 10× Core's value

**Severity:** P0-CDIV. Direct W150 BUG-5 cross-cite — UNFIXED.

Beamchain defines the constant in **two places**:
- `include/beamchain_protocol.hrl:161` — `?DEFAULT_MIN_RELAY_TX_FEE = 1000`
- `src/beamchain_mempool.erl:99` — `?MIN_RELAY_TX_FEE = 1000`
  (file-local define, same value, dead — but two-pipeline-guard pattern)

Core (`policy.h:70`): `DEFAULT_MIN_RELAY_TX_FEE = 100` sat/kvB =
0.1 sat/vB.

**File:** `include/beamchain_protocol.hrl:161`,
`src/beamchain_mempool.erl:99`.

**Core ref:** `bitcoin-core/src/policy/policy.h:69-70`.

**Impact:** every gate that consults this constant rejects txs at
10× the Core threshold:
- Single-tx mempool gate (mempool.erl:695-697) requires ≥ 1.0 sat/vB.
- Package CPFP fee gate (BUG-20) hardcodes the same 1.0 sat/vB floor.
- RBF Rule 4 incremental floor (PaysForRBF) uses
  DEFAULT_INCREMENTAL_RELAY_FEE which is correct (100), so Rule 4 is
  spared — BUT the static-min-relay floor used elsewhere isn't.

beamchain over-rejects all sub-1-sat/vB txs that Core would admit.
On testnet/regtest this breaks fee-floor testing. On mainnet during
low-fee periods, beamchain refuses txs that propagate through the
rest of the network.

Plus the two-pipeline-guard fleet pattern: changing one constant
doesn't change the other (if a future fix touches protocol.hrl, the
mempool.erl-local define still says 1000).

---

## BUG-23 (P1) — submitpackage / sendrawtransaction relay sends MSG_TX to wtxidrelay peers

**Severity:** P1. `relay_transaction` (rpc.erl:2706-2713):
```erlang
relay_transaction(Txid) ->
    try
        beamchain_peer_manager:broadcast(inv, #{
            items => [#{type => ?MSG_TX, hash => Txid}]      %% <-- hardcoded MSG_TX
        })
    catch _:_ -> ok end.
```

The peer_manager has `inv_items_from_pairs` / `peer_uses_wtxid`
(peer_manager.erl:1874-1893) that picks MSG_WTX (5) for BIP-339
wtxidrelay peers. But the submitpackage / sendrawtransaction relay
path bypasses it — every peer gets MSG_TX (1) regardless of
advertisement.

**File:** `src/beamchain_rpc.erl:2706-2713`,
`src/beamchain_peer_manager.erl:1874-1893` (good code, not called).

**Core ref:** `bitcoin-core/src/net_processing.cpp::RelayTransaction`
+ per-peer `m_wtxid_relay` check.

**Impact:** wtxidrelay-advertising peers may discard MSG_TX inv
(implementation-dependent); even if accepted, the wtxid-based reject
cache misses → if the tx is later re-announced via MSG_WTX from
another peer, beamchain re-validates instead of cache-hitting reject.
Plus: a witness-replaced version of the tx (same txid, different
wtxid) cannot be distinguished — beamchain's own peers don't see
the wtxid.

NOTE: this is the "dead-helper-at-call-site" pattern from W141 —
the correct primitive exists, is exported, but the call site uses a
direct MSG_TX literal instead.

---

## BUG-24 (P1) — Package validator silently accepts same-txid-different-witness duplicates

**Severity:** P1. `try_individual_accept` (mempool.erl:1167-1194):
```erlang
case ets:member(?MEMPOOL_TXS, Txid) of
    true ->
        %% Already in mempool, treat as accepted
        try_individual_accept(Rest, State, [Txid | AcceptedAcc], DeferredAcc);
    false ->
        case do_add_transaction(Tx, State) of ...
```

The dedupe key is txid. If the package tx has the SAME txid but
DIFFERENT witness as an existing mempool entry (a valid scenario
in Core 28+), beamchain silently treats it as accepted (adds the
ORIGINAL mempool entry's txid to AcceptedAcc) and skips the new tx.

Core (validation.cpp:1676-1686): emits `MempoolTxDifferentWitness`
result, surfaces `other-wtxid` in the RPC reply so the caller can
look up the mempool's preferred witness:
```cpp
} else if (m_pool.exists(txid)) {
    const auto& entry{*Assert(m_pool.GetEntry(txid))};
    results_final.emplace(wtxid, MempoolAcceptResult::MempoolTxDifferentWitness(
        entry.GetTx().GetWitnessHash()));
}
```

**File:** `src/beamchain_mempool.erl:1167-1194`,
`src/beamchain_rpc.erl:3039-3067` (`build_pkg_tx_result` lacks
`other-wtxid` field — cross-cite BUG-7).

**Core ref:** `bitcoin-core/src/validation.cpp:1676-1686`,
`bitcoin-core/src/rpc/mempool.cpp:1477-1478` (`other-wtxid` emission).

**Impact:** wallets cannot detect that the submitted witness was
not the one that won the mempool race (the alternative version is
in mempool); they cannot adjust their next sign+send. PSBT v2
finalization paths get wrong signal.

---

## Summary

24 bugs across 14 behaviour groups; 9 P0-CDIV, 14 P1, 1 P0-DIV.

### Top findings (by impact)

1. **BUG-18 (P0-CDIV) — `remove_block_conflicts` evicts CPFP children
   on every block-connect** (W150 BUG-11 same-pattern; inverted
   predicate; nukes mempool-resident CPFP / RBF / lightning-bump txs
   at confirmation time, silently).

2. **BUG-17 (P0-CDIV) — `testmempoolaccept` (and package dry-run)
   PERMANENTLY EVICTS conflicting mempool txs** when probing a
   replacement (FIX-54/W116 partial-fix regression on the eviction
   side; dry-run is supposed to be read-only).

3. **BUG-19 (P0-CDIV) — `reprocess_orphans` self-deadlocks gen_server**
   in THREE call sites (W150 BUG-12 SAME pattern unfixed since
   prior wave; 30s freeze + permanent orphan loss on every block
   and every accepted tx with a child orphan).

### Secondary high-impact

4. **BUG-22 (P0-CDIV) — `DEFAULT_MIN_RELAY_TX_FEE = 1000`** (10× Core;
   W150 BUG-5 unfixed; two copies in two files = two-pipeline-guard
   pattern).

5. **BUG-14 (P0-CDIV) — Rule 5 limit on wrong axis** (counts evicted
   txs, not distinct clusters; both over- and under-rejects relative
   to Core).

6. **BUG-10 (P0-CDIV) — submitpackage NOT atomic** (partial accepts
   persist after CPFP failure → State<->ETS divergence; mempool size
   accounting silently drifts).

7. **BUG-3 / BUG-11 / BUG-12 / BUG-20 cluster** — package-RBF gate
   coverage is non-Core: missing tree-shape check (BUG-3), missing
   2-tx restriction (BUG-11), missing no-mempool-ancestors gate
   (BUG-12), missing rolling-min-fee gate on the package-fee path
   (BUG-20).

8. **BUG-8 (P0-DIV) — reject strings are Erlang atom prints**, not
   Core wire-format strings ("rbf_not_signaled" vs Core's "BIP125-replacement-disallowed");
   wire-divergence breaks every RPC client parsing `package_msg`.

### Fleet pattern cross-cites

- **W150 BUG-11 inverted-predicate** → BUG-18 (`remove_block_conflicts`
  evicts CPFP children).
- **W150 BUG-12 gen_server self-deadlock** → BUG-19 (still present
  at three call sites despite W150 catching it).
- **W150 BUG-5 DEFAULT_MIN_RELAY_TX_FEE 10×** → BUG-22 (still
  1000 in both `protocol.hrl` and `mempool.erl`).
- **W144 STANDARD-flag mux gap** → BUG-4 (maxfeerate uses raw vsize
  not sigop-adjusted; same axis as the W144 STANDARD flags missing
  three discourage bits).
- **W116/FIX-54 partial-fix regression** → BUG-17 (dry-run insert
  was fixed; dry-run eviction was missed).
- **W141 dead-helper-at-call-site** → BUG-23 (`relay_transaction`
  hardcodes MSG_TX, ignoring the peer_manager's per-peer MSG_WTX
  pick).
- **W143 code-duplication smell** → BUG-22 (TWO copies of
  DEFAULT_MIN_RELAY_TX_FEE, both 10× wrong; two-pipeline-guard).
- **comment-as-confession** → 4 instances:
  - `mempool.erl:1989` "DEFAULT_INCREMENTAL_RELAY_FEE = 100 sat/kvB
    (NOT 1000 = MIN_RELAY_TX_FEE)" (BUG-22 cross-cite — the comment
    knows MIN_RELAY_TX_FEE is wrong).
  - `mempool.erl:2690` "Internal: block removal (stub)" (block-removal
    is the critical path that BUG-18 silently corrupts).
  - `rpc.erl:2886-2988` "beamchain's package validator does not yet
    emit a per-package replaced-tx list" (BUG-9 confession).
  - `mempool.erl:1996-2000` "Core does NOT require the replacement's
    fee-rate to exceed each individual conflict's fee-rate; Rules 3+4
    above are the only fee gates. A per-conflict fee-rate check was
    present in earlier beamchain code and has been removed as a
    non-Core policy gate" — yet `do_package_rbf:1452-1455` STILL
    enforces a per-conflict feerate check the comment claims was
    removed. Single-tx path was cleaned; package path was missed
    (single-vs-package divergence with confession trail).

### NEW patterns discovered this wave

- **"single-tx path correct, package path missed"** (BUG-13 cluster
  diagram dominance call; BUG-20 rolling-min-fee gate; the
  comment-as-confession entry at line 1996-2000 documents the
  per-conflict fee-rate check removal applied to single-tx but not
  package). 3 instances across this wave — distinct from
  two-pipeline-guard because both pipelines exist in the same module
  but with different feature coverage.
- **"dry-run mutates ETS via shared gate code"** (BUG-17 same-pattern
  to W116 BUG-1; the inverse direction). Lesson: dry-run safety
  requires either a parallel ETS namespace (overkill) or per-call
  rollback (gen_server can't easily do this with bare ETS); the
  pragmatic fix is for dry-run-specific gate code to switch on a
  thread-local "dry_run=true" before calling mutating helpers, OR to
  refactor `check_mempool_conflicts` to take a `Mutate :: boolean()`
  flag.
- **"wrong-axis bound"** (BUG-14 Rule 5 evicted-tx count vs distinct
  cluster count). Distinct from "wrong magnitude" (BUG-22 10×).
- **"correct call site, wrong primitive at call site"** (BUG-23 —
  MSG_TX literal instead of routing through
  `inv_items_from_pairs`). Distinct from W141's
  "dead-helper-at-call-site" (helper exists, exported, called, but
  no-op): here helper exists, exported, NOT called.
