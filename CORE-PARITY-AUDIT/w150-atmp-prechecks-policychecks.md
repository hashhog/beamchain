# W150 — AcceptToMemoryPool + PreChecks + PolicyScriptChecks + ConsensusScriptChecks (beamchain)

**Wave:** W150 — `MemPoolAccept::AcceptSingleTransaction`,
`MemPoolAccept::PreChecks`, `MemPoolAccept::PolicyScriptChecks`,
`MemPoolAccept::ConsensusScriptChecks`, `IsStandardTx`, `IsWitnessStandard`,
`AreInputsStandard`, `removeForBlock` / `removeConflicts`, dust /
`PreCheckEphemeralTx`, BIP-125 RBF rules 1-5, `LimitMempoolSize` /
`TrimToSize` / `Expire`, `-acceptnonstdtxn`, `-minrelaytxfee` /
`-incrementalrelayfee` / `-maxmempool` / `-datacarriersize`, reject
codes / BIP-22 reason strings, `STANDARD_SCRIPT_VERIFY_FLAGS` at
PolicyScriptChecks, peer-misbehavior accounting on TX_INVALID,
`m_recent_rejects` rolling-Bloom.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/validation.cpp` —
  `MemPoolAccept::AcceptSingleTransaction` (~600-700),
  `MemPoolAccept::PreChecks` (~700-980),
  `MemPoolAccept::PolicyScriptChecks` (~1100-1160),
  `MemPoolAccept::ConsensusScriptChecks` (~1160-1200),
  `MemPoolAccept::Finalize`, `CheckFinalTxAtTip`,
  `CheckSequenceLocksAtTip`, `CheckFeeRate`, `LimitMempoolSize`,
  `bad-txns-too-many-sigops` reject path (line 942).
- `bitcoin-core/src/policy/policy.cpp` — `IsStandardTx` (~150-200),
  `AreInputsStandard` (~205-262) — emits four distinct reject strings,
  `IsWitnessStandard` (~265-352), `GetDustThreshold`, `IsDust`.
- `bitcoin-core/src/policy/policy.h` —
  `DEFAULT_INCREMENTAL_RELAY_FEE=100`,
  **`DEFAULT_MIN_RELAY_TX_FEE=100`** (NOT 1000 — Core changed this
  before 28.0; the comment-style refs in beamchain still say 1000),
  `MAX_STANDARD_TX_WEIGHT=400000`,
  `MAX_STANDARD_P2WSH_STACK_ITEMS=100`,
  `MAX_STANDARD_P2WSH_STACK_ITEM_SIZE=80`,
  `MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE=80`,
  `MAX_STANDARD_TX_SIGOPS_COST = MAX_BLOCK_SIGOPS_COST/5 = 16000`,
  `MIN_STANDARD_TX_NONWITNESS_SIZE=65`,
  `STANDARD_SCRIPT_VERIFY_FLAGS` (17 distinct bits),
  `MANDATORY_SCRIPT_VERIFY_FLAGS` (7 distinct bits, NO NULLFAIL).
- `bitcoin-core/src/policy/ephemeral_policy.cpp:23-31` —
  `PreCheckEphemeralTx`: rejects dust outputs unless **BOTH** base and
  **modified** fee are 0 (`(base_fee != 0 || mod_fee != 0)`).
- `bitcoin-core/src/policy/rbf.cpp` — `EntriesAndTxidsDisjoint`,
  `HasNoNewUnconfirmedParents`, `PaysForRBF`,
  `PaysMoreThanConflicts`.
- `bitcoin-core/src/txmempool.cpp` — `CTxMemPool::removeForBlock`,
  `CTxMemPool::removeConflicts` (iterates the **inputs of the
  confirmed tx** to find mempool spenders via `mapNextTx`, NOT the
  outpoint hashes of the mempool tx vs the txid set of the block),
  `Expire`, `TrimToSize`, `GetMinFee`, `trackPackageRemoved`.
- `bitcoin-core/src/consensus/tx_check.cpp:44` — duplicate-input
  reject string is `"bad-txns-inputs-duplicate"` (NOT
  `"bad-txns-duplicate"`).
- `bitcoin-core/src/net_processing.cpp` — `MaybePunishNodeForTx`
  (Misbehaving on `TX_RESULT_TYPE::TX_INVALID`),
  `m_recent_rejects` rolling Bloom (120k entries).
- `bitcoin-core/src/rpc/mempool.cpp` —
  `sendrawtransaction` `maxfeerate` uses `GetVirtualTransactionSize`
  (sigop-adjusted), `testmempoolaccept` emits the canonical
  reject-token string, `submitpackage` reports
  `replaced-transactions` and treats `maxburnamount = 0` as "any
  unspendable output > 0 is rejected".
- `bitcoin-core/src/script/interpreter.h` —
  `STANDARD_SCRIPT_VERIFY_FLAGS` adds
  `DISCOURAGE_UPGRADABLE_TAPROOT_VERSION`,
  `DISCOURAGE_OP_SUCCESS`,
  `DISCOURAGE_UPGRADABLE_PUBKEYTYPE` on top of beamchain's set.

**Files audited**
- `src/beamchain_mempool.erl` — `accept_to_memory_pool/1`,
  `add_transaction/1`, `do_add_transaction/2` (gates 1..21),
  `do_add_transaction_dry_run/2`, `check_standard/1`,
  `classify_output_standard/1`, `is_witness_standard/2`,
  `validate_inputs_standardness/2`, `validate_inputs_standardness_loop/3`,
  `check_mempool_conflicts/3`, `do_rbf/3`,
  `check_cluster_rbf_diagram/3`, `find_mempool_conflicts/1`,
  `check_dust/2`, `check_p2a_policy/1`, `find_ephemeral_anchor/2`,
  `pre_check_ephemeral_tx/2`, `is_dust_output/1`,
  `dust_threshold/1`, `verify_scripts/2`, `all_standard_flags/0`,
  `consensus_script_flags/0`, `consensus_script_checks/2`,
  `check_mempool_coinbase_maturity/2`,
  `check_mempool_sequence_locks/4`, `compute_ancestors/3`,
  `check_descendant_limits/2`, `check_cluster_limits/2`,
  `lookup_inputs/1`, `check_tx_inputs_money_range/2`,
  `check_tx_already_known/1`, `lookup_entry_by_wtxid/1`,
  `get_min_fee/1`, `track_package_removed/2`, `do_trim_to_size/2`,
  `do_expire_old/1`, `do_remove_for_block/2`,
  `remove_block_conflicts/2`, `reprocess_orphans/1`,
  `add_orphan/3`, `do_expire_orphans/0`,
  `do_accept_package/2`, `do_accept_package_dry_run/2`,
  `try_individual_accept/2`, `evaluate_package_cpfp/3`.
- `src/beamchain_validation.erl` — `check_transaction/1`,
  `check_duplicate_inputs/1`, `count_sigops_accurate/1`,
  `get_p2sh_redeem_script/1`, `is_final_tx/3`,
  `calculate_sequence_lock_pair/3`, `median_time_past/1`,
  `count_legacy_sigops_tx/1`.
- `src/beamchain_rpc.erl` — `rpc_sendrawtransaction/1`,
  `rpc_testmempoolaccept/1`, `rpc_submitpackage/1`,
  `check_max_fee_rate/2`, `compute_tx_input_value/1`,
  `format_mempool_error/2`, `bip22_result/1`, `relay_transaction/1`,
  `decode_package_tx/1`, `build_pkg_tx_result/4`,
  `ds_is_unspendable/1`.
- `src/beamchain_chainstate.erl` — `submit_block/1`,
  `refill_mempool_after_reorg/1`, `remove_for_block_async` callout
  (line 1019), get_tip/get_mtp/get_utxo callbacks used by mempool.
- `src/beamchain_sync.erl` — `route_message(_, tx, _, _)` (line 332)
  — peer-misbehavior accounting on tx-accept reject.
- `src/beamchain_config.erl` — `mempool_full_rbf/0` (the ONLY policy
  knob exposed — no `-acceptnonstdtxn`, `-minrelaytxfee`,
  `-incrementalrelayfee`, `-maxmempool`, `-datacarriersize`,
  `-permitbaremultisig`, `-bytespersigop`).
- `src/beamchain_mempool_persist.erl` — `apply_loaded/1` (re-feeds
  mempool.dat through `accept_to_memory_pool/1`).
- `include/beamchain_protocol.hrl` — `?DEFAULT_MIN_RELAY_TX_FEE=1000`,
  `?DEFAULT_INCREMENTAL_RELAY_FEE=100`, `?COINBASE_MATURITY=100`,
  `?MAX_BIP125_RBF_SEQUENCE=0xfffffffd`,
  `?MAX_STANDARD_TX_WEIGHT=400000`,
  `?MIN_STANDARD_TX_NONWITNESS_SIZE=65`,
  `?MAX_STANDARD_TX_SIGOPS_COST=16000`,
  `?MAX_RBF_EVICTIONS=100`, `?MEMPOOL_EXPIRY_HOURS=336`,
  `?MAX_PACKAGE_COUNT=25`, `?MAX_PACKAGE_WEIGHT=404000`.

---

## Gate matrix (35 sub-gates / 12 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | Public entry point | G1: `accept_to_memory_pool/1` → `add_transaction/1` → `gen_server:call({add_tx, Tx}, 30000)` | PASS (mempool.erl:196-202) |
| 1 | … | G2: `accept_to_memory_pool_dry_run/1` (testmempoolaccept path) does not write ETS | PASS (mempool.erl:216-219, dry-run handler 443-449) |
| 2 | CheckTransaction (context-free) | G3: vin / vout non-empty, MoneyRange, duplicate-inputs, coinbase shape, weight >= 240 | PASS (validation.erl:540-590); **BUG-1 (P1)** reject token `duplicate_inputs` maps to `"bad-txns-duplicate"` (rpc.erl:3781) — Core: `"bad-txns-inputs-duplicate"` (consensus/tx_check.cpp:44) |
| 3 | IsStandardTx | G4: version 1/2/3 only | PASS (mempool.erl:1613) |
| 3 | … | G5: weight <= MAX_STANDARD_TX_WEIGHT (400000) | PASS (mempool.erl:1616) |
| 3 | … | G6: non-witness size >= MIN_STANDARD_TX_NONWITNESS_SIZE (65) | PASS (mempool.erl:1621-1622) |
| 3 | … | G7: scriptSig push-only AND ≤ MAX_STANDARD_SCRIPTSIG_SIZE (1650) | PASS (mempool.erl:1626-1629); **BUG-2 (P1)** reject tokens `scriptsig_size` / `scriptsig_not_pushonly` are atom-style (Core: `"scriptsig-size"` / `"scriptsig-not-pushonly"`) |
| 3 | … | G8: output scriptPubKey standard; OP_RETURN budget (MAX_OP_RETURN_RELAY=100000) | PASS (mempool.erl:1635-1646) |
| 4 | IsWitnessStandard | G9: coinbase skip / empty-witness skip | PASS (mempool.erl:1693-1713) |
| 4 | … | G10: P2A + any witness → reject | PASS (mempool.erl:1717-1720) |
| 4 | … | G11: P2SH redeem-script extraction via EvalScript(SCRIPT_VERIFY_NONE) | PASS (mempool.erl:1727-1737) |
| 4 | … | G12: P2WSH stack ≤ 100, item ≤ 80, script ≤ 3600 | PASS (mempool.erl:1760-1776) |
| 4 | … | G13: Taproot annex reject, control-block leaf-version dispatch, tapscript item ≤ 80 | PASS (mempool.erl:1789-1848) |
| 5 | AreInputsStandard | G14: nonstandard / witness_unknown classifier | PASS (mempool.erl:4135-4143) |
| 5 | … | G15: P2SH redeem-script sigops cap (MAX_P2SH_SIGOPS=15) | PARTIAL — **BUG-3 (P1)** silent fall-through when `get_p2sh_redeem_script(SS)` returns `_NoRedeem` (mempool.erl:4158-4160), Core emits `"input %u P2SH redeemscript missing"` |
| 5 | … | G16: P2SH "scriptsig malformed" reject on EvalScript failure | **BUG-4 (P1)** — `get_p2sh_redeem_script/1` parses scriptSig byte-by-byte without an EvalScript-equivalent failure-flag; malformed scriptSig silently returns `error` and falls through to silent-pass at line 4159 |
| 6 | Per-input MoneyRange | G17: per-coin + running-sum check | PASS (mempool.erl:4232-4248) |
| 7 | Sigops cap (16000) | G18: STANDARD_SCRIPT_VERIFY_FLAGS used for counting | PASS (mempool.erl:629-632) |
| 8 | RBF (BIP-125) | G19: full-rbf signaling override | PASS (mempool.erl:1919-1921) |
| 8 | … | G20: Rule 2 (no new unconfirmed parents) | PASS (mempool.erl:1933-1938) |
| 8 | … | G21: Rule 5 (≤ 100 evictions) | PASS (mempool.erl:1962-1963) |
| 8 | … | G22: Rule 3 (NewFee >= EvictedFeeTotal) | PASS (mempool.erl:1973-1982) |
| 8 | … | G23: Rule 4 (PaysForRBF — incremental relay over new vsize) | PASS (mempool.erl:1991-1994); uses `?DEFAULT_INCREMENTAL_RELAY_FEE=100` per Core |
| 9 | Fee gates | G24: `EffectiveMin = max(rolling_min, DEFAULT_MIN_RELAY_TX_FEE/1000)` | **BUG-5 (P0-CDIV)** — `?DEFAULT_MIN_RELAY_TX_FEE=1000` (mempool.erl:99, protocol.hrl:161) but Core's current value is **100** (policy.h:70). beamchain rejects all txs below 1.0 sat/vB even when peers Core-side relay them at 0.1 sat/vB |
| 9 | … | G25: `pre_check_ephemeral_tx` uses both base_fee AND modified_fee | **BUG-6 (P1)** — mempool.erl:4272-4283 only sees `Fee` (base), Core ephemeral_policy.cpp:23-31 requires `(base_fee != 0 || mod_fee != 0)`; no prioritisetransaction tracking |
| 9 | … | G26: `maxfeerate` parameter of sendrawtransaction uses GetVirtualTransactionSize (sigop-adjusted) | **BUG-7 (P1)** — rpc.erl:2684 uses `beamchain_serialize:tx_vsize(Tx)` (raw vsize, not sigop-adjusted); a sigop-heavy tx may falsely trigger the fat-finger gate |
| 10 | PolicyScriptChecks | G27: `all_standard_flags()` matches Core STANDARD_SCRIPT_VERIFY_FLAGS | **BUG-8 (P0-CDIV)** — mempool.erl:2267-2284 OMITS `SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION`, `SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS`, `SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE`. All three flags are defined in `beamchain_protocol.hrl:151-153` AND consulted by `beamchain_script.erl:508 / 1613 / 2886` — **dead-flag plumbing** (W144 fleet pattern, 9-of-10 carry-forward) |
| 10 | … | G28: script_verify_failed throw carries enough info to distinguish MANDATORY vs NON-MANDATORY | **BUG-9 (P0-CDIV)** — mempool.erl:2261 emits `{script_verify_failed, Idx}` discarding the script-error type. format_mempool_error (rpc.erl:2768-2770) renders ALL script failures as `"mandatory-script-verify-flag-failed"` — Core distinguishes `non-mandatory-script-verify-flag-failed` for STANDARD-only flag violations; misclassification leaks into peer-misbehavior gates |
| 11 | ConsensusScriptChecks | G29: re-verify with `currentBlockScriptVerifyFlags` | PARTIAL — **BUG-10 (P1)** mempool.erl:4292-4301 hardcodes the consensus flag set as `P2SH | DERSIG | NULLDUMMY | CLTV | CSV | WITNESS | NULLFAIL | TAPROOT` (8 flags). Core's `GetBlockScriptFlags(tip)` is context-derived; if a future soft-fork lands, beamchain's policy-time consensus check silently bypasses it. Also: NULLFAIL is STANDARD-only in Core (`policy.h:125` adds it; `MANDATORY` set at policy.h:105-111 does NOT) — beamchain's inclusion of NULLFAIL here is benign but a parity-set deviation |
| 12 | removeForBlock | G30: confirmed-tx removal from mempool | PASS (mempool.erl:2693-2738) |
| 12 | … | G31: removeConflicts — evict mempool spenders of outpoints just confirmed by the block | **BUG-11 (P0-CDIV)** — `remove_block_conflicts/2` (mempool.erl:2742-2777) tests whether each mempool tx's input `prev_out.hash` is in `sets:from_list(ConfirmedTxids)`. This is the WRONG predicate: it evicts legitimate CPFP children whose parent just confirmed (a child's input hash IS the parent's txid) AND misses real double-spend conflicts (where the new block's tx spends an outpoint that some mempool tx also spends, via a different spender). Core: `removeConflicts(tx)` iterates `tx.vin` and walks `mapNextTx[outpoint]` to find the mempool spender |
| 12 | … | G32: orphan-promotion path runs without deadlocking the mempool gen_server | **BUG-12 (P0-CDIV)** — `reprocess_orphans/1` (mempool.erl:2612) calls `add_transaction(OrphanTx)` which is `gen_server:call(?SERVER, ...)`. This is the SAME gen_server reentering itself via synchronous call. The orphan-promotion call sits in the gen_server mailbox until the 30s timeout expires; the just-deleted orphan record is then permanently lost. Fires from `do_add_transaction` (line 817) AND from `do_remove_for_block` → `erase_orphans_for_block` (line 3040). 30s freeze + orphan loss on every CPFP child whose parent arrives after it |
| 13 | LimitMempoolSize | G33: `do_trim_to_size(max_size)` invoked after successful accept | **BUG-13 (P1)** — `do_trim_to_size/2` exists (mempool.erl:2792-2862) but is reachable ONLY via the `trim_to_size/1` RPC; `do_add_transaction` (line 832) never calls it. **Zero non-test callers in the production tree** (`grep` confirms). The 300 MB `?DEFAULT_MAX_MEMPOOL_SIZE` cap is plumbed-but-not-enforced. Mempool grows past max_size indefinitely |
| 13 | … | G34: `do_expire_old(MEMPOOL_EXPIRY_HOURS=336)` invoked automatically (Core: from `LimitMempoolSize` post-`removeForBlock`) | **BUG-14 (P1)** — `expire_old/0` has zero non-test callers (same grep). The 14-day expiry only fires when an operator manually calls the RPC. Companion to BUG-13: trim + expire are both dead-handler plumbing |
| 14 | testmempoolaccept | G35: `reject-reason` field uses canonical Core token strings | **BUG-15 (P1)** — `iolist_to_binary(io_lib:format("~p", [Reason]))` (rpc.erl:2824, 2848) renders Erlang term notation: `'bad-witness-nonstandard'` (with quotes), `{'bad-txns-too-many-sigops',16012}` (tuple syntax). Tools that grep for `"bad-witness-nonstandard"` won't match. Same problem in `submitpackage` `package_msg` (rpc.erl:2964) and `format_mempool_error` fallback (rpc.erl:2774-2776) |

---

## BUG-1 (P1) — Duplicate-inputs reject token is `bad-txns-duplicate` (Core: `bad-txns-inputs-duplicate`)

**Severity:** P1 (wire-format parity slippage — affects BIP-22
`getblocktemplate` proposals AND every RPC consumer that compares
reject-reason strings to Core's tokens). Bitcoin Core's
`CheckTransaction` returns the canonical string
`"bad-txns-inputs-duplicate"` for a tx that lists the same outpoint
twice in its inputs (`consensus/tx_check.cpp:44`).

beamchain's `check_transaction/1` (`validation.erl:565-609`) throws
the atom `duplicate_inputs`. `bip22_result/1` then maps it to the
string `"bad-txns-duplicate"` (`rpc.erl:3781`) — missing the
`-inputs-` token segment. There is exactly ONE place in Core's
codebase that uses the shorter `bad-txns-duplicate` string:
`validation.cpp:3856`, which is the BIP-30 block-level check
("duplicate transaction by txid"). beamchain conflates BIP-30
duplicate-tx with CheckTransaction duplicate-input. Two distinct
classes of reject collapsed into one token — operators monitoring
BIP-22 proposals cannot distinguish them.

**File:** `src/beamchain_validation.erl:609` (throw `duplicate_inputs`);
`src/beamchain_rpc.erl:3781` (map to wire token).

**Core ref:** `bitcoin-core/src/consensus/tx_check.cpp:44`.

**Excerpt (beamchain, wrong token)**
```erlang
bip22_result(duplicate_inputs)          -> <<"bad-txns-duplicate">>;
```

**Impact:** wire-format break — tools that grep the BIP-22 proposal
JSON or RPC `reject_reason` for `bad-txns-inputs-duplicate` see
nothing on beamchain; conversely tools matching the
shorter`bad-txns-duplicate` see BOTH BIP-30 duplicate-tx AND
duplicate-input failures. One-line fix.

---

## BUG-2 (P1) — Many standardness reject atoms are not Core's canonical kebab-case tokens

**Severity:** P1 (wire-format parity, "reject-string slippage" fleet
pattern — W125 + W145 companion). beamchain's `check_standard/1`
throws Erlang atoms in snake_case (`scriptsig_size`,
`scriptsig_not_pushonly`, `scriptpubkey`, `datacarrier`, `version`,
`tx_size`, `dust`, `non_final`). `format_mempool_error/2` partially
maps these to Core tokens but most fall through to the
`~p`-formatted fallback at `rpc.erl:2774-2776`, producing e.g.
`"scriptsig_size"` (with underscore) instead of Core's
`"scriptsig-size"`, and `"tx_size"` instead of `"tx-size"` (which
Core emits with the variant `"tx-size-small"` for the
`MIN_STANDARD_TX_NONWITNESS_SIZE` violation, distinguishing it from
the `MAX_STANDARD_TX_WEIGHT` overrun).

Concrete divergences:
| beamchain atom | Wire token emitted | Core canonical |
|----------------|--------------------|----------------|
| `scriptsig_size` | `"scriptsig_size"` | `"scriptsig-size"` |
| `scriptsig_not_pushonly` | `"scriptsig_not_pushonly"` | `"scriptsig-not-pushonly"` |
| `scriptpubkey` | `"scriptpubkey"` | `"scriptpubkey"` (match — but Core also has `"bare-multisig"`, beamchain has no equivalent) |
| `tx_size` (both > MAX and < MIN_NONWITNESS) | `"tx_size"` | `"tx-size"` / `"tx-size-small"` (Core distinguishes) |
| `version` | `"version"` | `"version"` (match by accident) |
| `datacarrier` | `"datacarrier"` | `"datacarrier"` (match) |
| `dust` | `"dust"` | `"dust"` (match) |
| `non_final` | `"non_final"` | `"non-final"` |

**File:** `src/beamchain_mempool.erl:1613-1646` (throw sites);
`src/beamchain_rpc.erl:2774-2776` (fall-through formatter).

**Core ref:** `bitcoin-core/src/policy/policy.cpp:174-200` (`IsStandardTx`
state.Invalid calls).

**Impact:** wire-format break for every external monitoring tool;
mempool reject metrics aggregated against Core-token taxonomies miss
beamchain reject categories.

---

## BUG-3 (P1) — `AreInputsStandard` silently passes when P2SH redeem-script extraction fails

**Severity:** P1. Bitcoin Core's `AreInputsStandard`
(`policy/policy.cpp:241-258`) for a P2SH-classified input has FOUR
distinct outcomes:
1. EvalScript fails on scriptSig → reject `"p2sh scriptsig malformed
   (input N: error)"`.
2. EvalScript stack empty → reject `"input N P2SH redeemscript
   missing"`.
3. Redeem script sigops > MAX_P2SH_SIGOPS (15) → reject
   `"p2sh redeemscript sigops exceed limit"`.
4. Sigops ≤ 15 → continue.

beamchain's `validate_inputs_standardness_loop/3` for the `scripthash`
case collapses outcomes 1 and 2 into a silent fall-through at
`mempool.erl:4158-4160`:

```erlang
case beamchain_validation:get_p2sh_redeem_script(SS) of
    {ok, RedeemScript} ->
        N = beamchain_validation:count_sigops_accurate(RedeemScript),
        if N > ?MAX_P2SH_SIGOPS -> {error, 'bad-txns-nonstandard-inputs'};
           true -> validate_inputs_standardness_loop(Rest, Idx + 1, Tx)
        end;
    _NoRedeem ->
        %% No identifiable redeem script — Core treats as 0 sigops.
        validate_inputs_standardness_loop(Rest, Idx + 1, Tx)
end;
```

The inline comment "Core treats as 0 sigops" is **wrong** —
Core REJECTS with `"input N P2SH redeemscript missing"`. The
silent pass moves the failure downstream to `verify_scripts`
(`mempool.erl:2248`), which fails with a different reject token
(`script_verify_failed`) → re-categorized as
`mandatory-script-verify-flag-failed` (BUG-9 below) → peer
misbehavior accounting goes wrong.

**File:** `src/beamchain_mempool.erl:4158-4160`.

**Core ref:** `bitcoin-core/src/policy/policy.cpp:249-251`.

**Impact:** cross-impl divergence on AreInputsStandard reject
classification; combined with BUG-9, a malformed-P2SH peer is
mis-classified as a MANDATORY-rule violator and unfairly banned.

---

## BUG-4 (P1) — `get_p2sh_redeem_script/1` lacks the EvalScript "malformed scriptsig" gate

**Severity:** P1 (companion to BUG-3). Core uses `EvalScript(stack,
scriptSig, SCRIPT_VERIFY_NONE, BaseSignatureChecker(),
SigVersion::BASE, &serror)` (`policy/policy.cpp:245`) and emits a
distinct `"p2sh scriptsig malformed (input N: %s)"` reject string
that includes the `ScriptErrorString(serror)` — useful for debugging
which exact opcode caused the failure.

beamchain's `get_p2sh_redeem_script/1` (`validation.erl:838-885`)
is a hand-rolled byte-by-byte push-only parser. It returns `error`
for any unparseable byte sequence but the caller at
`mempool.erl:4158` ignores this distinction (lumping it into the
silent fall-through). There is no analogue of `ScriptErrorString`
plumbed back to the reject reason.

**File:** `src/beamchain_validation.erl:838-885` (no caller-visible
error distinction); `src/beamchain_mempool.erl:4158-4160` (caller
drops the error).

**Core ref:** `bitcoin-core/src/policy/policy.cpp:245-248`.

**Impact:** debuggability + wire-format slippage; consumers of
beamchain testmempoolaccept who expect Core's `"p2sh scriptsig
malformed"` token to identify scriptSig-corruption attacks get the
wrong category.

---

## BUG-5 (P0-CDIV) — `DEFAULT_MIN_RELAY_TX_FEE = 1000` (Core: 100); beamchain refuses Core-relayable txs at 0.1-0.99 sat/vB

**Severity:** P0-CDIV (cross-impl relay divergence; mempool/network
behavior split). Bitcoin Core's policy/policy.h:70 currently sets
`DEFAULT_MIN_RELAY_TX_FEE{100}` (100 sat/kvB = 0.1 sat/vB). The
value changed from 1000 (1.0 sat/vB) sometime before the 28.0
release. beamchain has it hardcoded as 1000 in
`beamchain_protocol.hrl:161` AND in the local `?MIN_RELAY_TX_FEE`
constant at `mempool.erl:99`, with inline comments at
`mempool.erl:692-693` that **explicitly cite the wrong value**:

```erlang
%%   effective_min = max(rolling_min_fee_sat_per_vb,
%%                       DEFAULT_MIN_RELAY_TX_FEE / 1000)
%% DEFAULT_MIN_RELAY_TX_FEE = 1000 sat/kvB = 1.0 sat/vB.    <-- WRONG
StaticMinRelay = ?DEFAULT_MIN_RELAY_TX_FEE / 1000.0,
EffectiveMin = max(RollingMin, StaticMinRelay),
FeeRate >= EffectiveMin orelse throw('mempool min fee not met'),
```

Same value at line 944 (dry-run path). And the
`getmempoolinfo` RPC (rpc.erl:3256-3257) advertises
`mempoolminfee=0.00001000 BTC/kvB = 1 sat/vB` — also wrong (Core
advertises 0.00000100 = 0.1 sat/vB by default).

Consequences:
- Every tx between 0.1 sat/vB and 0.99 sat/vB that a Core peer
  relays gets **rejected by beamchain with `mempool min fee not met`**.
- BIP-133 `feefilter` advertised to peers is 10× Core's value; peers
  receive a higher floor → reduced tx-flow into beamchain's
  mempool.
- Cross-cite W141 finding (nimrod `mempoolminfee 1000× divisor`): same
  shape of magnitude error in the inverse direction. Fleet pattern
  of fee-unit confusion.

**File:** `include/beamchain_protocol.hrl:161`,
`src/beamchain_mempool.erl:99, 692-695, 944-946`,
`src/beamchain_rpc.erl:3256-3257, 3423`.

**Core ref:** `bitcoin-core/src/policy/policy.h:70` (current value
100, with kernel/mempool_options.h:44 propagating it).

**Excerpt (beamchain, 10× over-rejection)**
```erlang
-define(DEFAULT_MIN_RELAY_TX_FEE, 1000).     %% sat/kvB (Core DEFAULT_MIN_RELAY_TX_FEE)
                                              %% ^^^ comment misstates the Core value
```

**Impact:** mempool/network divergence — beamchain's mempool will
chronically miss txs that Core mempools accept; the
`feefilter` advertised to peers is wrong; `getmempoolinfo`
returns a wrong `relayfee`/`mempoolminfee` to wallets, which then
attach unnecessarily high fees to outgoing txs. One-line fix:
change the constant from 1000 to 100 and update the comments.

---

## BUG-6 (P1) — `pre_check_ephemeral_tx` ignores prioritisetransaction-modified fee

**Severity:** P1. Core's `PreCheckEphemeralTx`
(`policy/ephemeral_policy.cpp:23-31`) uses the disjunction:

```cpp
if ((base_fee != 0 || mod_fee != 0) && !GetDust(tx, dust_relay_rate).empty()) {
    return state.Invalid(TxValidationResult::TX_NOT_STANDARD, "dust", "tx with dust output must be 0-fee");
}
```

beamchain's `pre_check_ephemeral_tx/2` only sees the base `Fee` (the
result of `TotalIn - TotalOut`). There is no `mempool_entry` field
for `modified_fee` — `prioritisetransaction` is not even implemented
(grep: `prioritisetransaction` returns 0 hits in beamchain_rpc.erl
and beamchain_mempool.erl). So a hypothetical
prioritisetransaction-bumped zero-base-fee tx with a dust output
would be erroneously admitted as "ephemeral" even when its modified
fee is positive (a miner-incentivized scenario Core prevents).

This is a fleet pattern of `prioritisetransaction never wired` (also
seen in lunarblock W125 and clearbit W127 audits).

**File:** `src/beamchain_mempool.erl:4272-4283`.

**Core ref:** `bitcoin-core/src/policy/ephemeral_policy.cpp:23-31`.

**Impact:** ephemeral-anchor policy semantics drift if/when
prioritisetransaction is implemented; no test exposure today but
the gate is structurally wrong.

---

## BUG-7 (P1) — `check_max_fee_rate` uses raw vsize instead of sigop-adjusted vsize

**Severity:** P1. Core's `sendrawtransaction` computes
`virtual_size = GetVirtualTransactionSize(*tx)` where
`GetVirtualTransactionSize` is sigop-adjusted
(`max(weight, sigOpCost * DEFAULT_BYTES_PER_SIGOP) / 4`,
`policy/policy.cpp::GetVirtualTransactionSize`). beamchain's
`check_max_fee_rate/2` (`rpc.erl:2684`) uses
`beamchain_serialize:tx_vsize(Tx)` — the raw `weight / 4` form,
NOT sigop-adjusted.

A heavy-sigop tx (e.g., a P2SH multisig with many CHECKMULTISIG
opcodes) has a small raw vsize but a large sigop-adjusted vsize.
beamchain divides `Fee / raw_vsize` → much HIGHER fee-rate than
Core's `Fee / sigop_adjusted_vsize`. The fat-finger gate fires
spuriously on such txs (rejects with "Fee rate exceeds maximum").

Inversely: the same code is used in `submitpackage`'s per-tx fee-
rate check (`rpc.erl:2929`), so submitpackage with sigop-heavy
inputs may falsely trigger.

Same vsize-confusion also surfaces in W129 (camlcoin coin selection
68-vB-per-input hardcode) and W144 (multiple impls).

**File:** `src/beamchain_rpc.erl:2684, 2929`.

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::sendrawtransaction`
(uses `GetVirtualTransactionSize`).

**Impact:** spurious "Fee rate exceeds maximum" rejection for sigop-
heavy txs; cross-impl divergence on the fat-finger threshold.

---

## BUG-8 (P0-CDIV) — `all_standard_flags()` omits 3 STANDARD-side script flags; defined-and-consulted-but-never-emitted

**Severity:** P0-CDIV ("dead-flag plumbing" fleet pattern, W144
9-of-10 carry-forward — beamchain is the **10th** confirmed
instance). Core's STANDARD_SCRIPT_VERIFY_FLAGS
(`policy/policy.h:119-132`) is the disjunction of MANDATORY (7
flags) AND 10 additional standard flags. beamchain's
`all_standard_flags()` (`mempool.erl:2267-2284`) sets:
- P2SH, STRICTENC, DERSIG, LOW_S, NULLDUMMY, MINIMALDATA,
  DISCOURAGE_UPGRADABLE_NOPS, CLEANSTACK, CHECKLOCKTIMEVERIFY,
  CHECKSEQUENCEVERIFY, WITNESS,
  DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, MINIMALIF, NULLFAIL,
  WITNESS_PUBKEYTYPE, CONST_SCRIPTCODE, TAPROOT.

**Missing vs Core STANDARD_SCRIPT_VERIFY_FLAGS:**
- `SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION` (bit 18)
- `SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS` (bit 19)
- `SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE` (bit 20)

All three flag bits ARE defined in
`include/beamchain_protocol.hrl:151-153` AND consulted by the
script interpreter at:
- `beamchain_script.erl:508` (`SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS`)
- `beamchain_script.erl:1613, 1730, 2054`
  (`SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE`)
- `beamchain_script.erl:2886`
  (`SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION`)

The interpreter-side gates **exist** and **execute**, but the
PolicyScriptChecks mempool gate **never sets the flag bit**, so the
gates **never fire at policy time**. Classic "dead-flag plumbing":
the defensive code exists, the operator looks at the script.erl
gates and assumes the policy is enforced, but the upstream mux
never emits the bit. A tapscript with future leaf-version 0xc1 or
OP_SUCCESS opcode 0xd0..0xfe is **admitted into the beamchain
mempool**, then ALSO accepted via PolicyScriptChecks (no
DISCOURAGE_OP_SUCCESS to reject it as nonstandard), then relayed to
peers. Operationally consistent with the mainnet OP_SUCCESS
fingerprint risk.

This is the W144 fleet pattern (9 of 10 impls confirm missing or
incomplete script_flag_exceptions / STANDARD flag mux):
beamchain's W144 audit also flagged `all_standard_flags()` as
incomplete; this W150 finding closes the loop on which **specific
production path** is affected (PolicyScriptChecks gate, sendraw-
and-testmempoolaccept entry points).

**File:** `src/beamchain_mempool.erl:2267-2284`
(`all_standard_flags()` definition);
`include/beamchain_protocol.hrl:151-153` (flag bits defined);
`src/beamchain_script.erl:508, 1613, 1730, 2054, 2886` (handlers
that consult the flags but are never reached).

**Core ref:** `bitcoin-core/src/policy/policy.h:119-132`.

**Excerpt (beamchain, missing 3 flags)**
```erlang
all_standard_flags() ->
    ?SCRIPT_VERIFY_P2SH bor
    ?SCRIPT_VERIFY_STRICTENC bor
    ?SCRIPT_VERIFY_DERSIG bor
    %% ... 14 flags total ...
    ?SCRIPT_VERIFY_CONST_SCRIPTCODE bor
    ?SCRIPT_VERIFY_TAPROOT.
%%   MISSING: SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
%%   MISSING: SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS,
%%   MISSING: SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE.
```

**Impact:** beamchain mempool relays nonstandard tapscript variants
(OP_SUCCESS, future-leaf-version, future-pubkey-type) that Core
mempools reject. Cross-impl mempool divergence → divergent fee
estimation → divergent block templates → potential reorg-loss for
miners relying on beamchain templates. Mainnet-relevant once
operators upgrade Core past the relevant soft-forks.

---

## BUG-9 (P0-CDIV) — `script_verify_failed` throw discards the script-error type → all failures become `mandatory-script-verify-flag-failed`

**Severity:** P0-CDIV (peer-misbehavior misclassification). Core's
`MemPoolAccept::PolicyScriptChecks`
(`validation.cpp::PolicyScriptChecks`) runs the script-eval pass
with `STANDARD_SCRIPT_VERIFY_FLAGS`. On failure, it inspects the
specific `ScriptError` and decides:
- if the failure bit is one of `MANDATORY_SCRIPT_VERIFY_FLAGS`,
  reject with `"mandatory-script-verify-flag-failed (<err>)"` →
  `TxValidationResult::TX_CONSENSUS` → peer misbehavior +100;
- if the failure bit is STANDARD-only, reject with
  `"non-mandatory-script-verify-flag-failed (<err>)"` →
  `TxValidationResult::TX_NOT_STANDARD` → **no peer misbehavior**.

beamchain's `verify_scripts/2` (`mempool.erl:2248-2265`) throws
`{script_verify_failed, Idx}` — discarding the script-error type
entirely. `format_mempool_error/2` (`rpc.erl:2768-2770`) then
renders ALL such failures as
`"mandatory-script-verify-flag-failed (input N)"` regardless of
whether the failure was a mandatory or standard-only flag.

Consequences:
1. **Operator-visible reject reason lies.** A tx that fails
   `LOW_S` (a STANDARD-only check; never mandatory) is reported
   to the operator as `mandatory-script-verify-flag-failed`.
2. **Peer misbehavior accounting goes wrong.** Although beamchain's
   sync layer (`beamchain_sync.erl:344-345`) currently does NOT
   increase peer misbehavior on any ATMP rejection (BUG-16 below),
   any future addition that maps `mandatory-script-verify-flag-
   failed` → ban will over-fire on STANDARD-only failures.
3. **Wire-format break with Core's `testmempoolaccept` and
   `sendrawtransaction` reject-reason strings.** Tools parsing
   the standard Core distinction see only the mandatory variant.

Additionally, the verify call is at line 2258 inside `verify_scripts`
which uses `all_standard_flags()` — a script that fails ONLY a flag
that's in the STANDARD-but-not-MANDATORY subset
(e.g. CLEANSTACK, MINIMALIF, NULLFAIL, MINIMALDATA, STRICTENC,
LOW_S, WITNESS_PUBKEYTYPE, CONST_SCRIPTCODE) is INCORRECTLY
classified as mandatory.

**File:** `src/beamchain_mempool.erl:2258-2262`;
`src/beamchain_rpc.erl:2768-2770`.

**Core ref:** `bitcoin-core/src/validation.cpp::PolicyScriptChecks`,
`bitcoin-core/src/script/script_error.h::ScriptErrorString`.

**Excerpt (beamchain, type discarded)**
```erlang
case beamchain_script:verify_script(
        ScriptSig, ScriptPubKey, Witness, Flags, SigChecker) of
    true -> ok;
    false -> throw({script_verify_failed, Idx})    %% No error code!
end,
```

**Impact:** peer-misbehavior accounting misclassification + wire-
format break. Combined with BUG-3/BUG-4 (P2SH malformed-scriptSig
silently passes the AreInputsStandard gate but then fails
verify_scripts), an honest peer who sends a malformed P2SH tx
becomes a candidate for being banned as a MANDATORY violator.

---

## BUG-10 (P1) — `consensus_script_flags()` is hardcoded, not derived from `GetBlockScriptFlags(tip)`

**Severity:** P1 (architectural — future soft-fork upgrade hazard).
Core's `MemPoolAccept::ConsensusScriptChecks`
(`validation.cpp:1158-1189`) computes
`currentBlockScriptVerifyFlags = GetBlockScriptFlags(active_chain.Tip())`
on every accept; the flag set is tip-derived and changes when a
soft-fork activates.

beamchain's `consensus_script_flags()` (`mempool.erl:4292-4301`)
returns a **hardcoded constant**:

```erlang
consensus_script_flags() ->
    ?SCRIPT_VERIFY_P2SH bor
    ?SCRIPT_VERIFY_DERSIG bor
    ?SCRIPT_VERIFY_NULLDUMMY bor
    ?SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY bor
    ?SCRIPT_VERIFY_CHECKSEQUENCEVERIFY bor
    ?SCRIPT_VERIFY_WITNESS bor
    ?SCRIPT_VERIFY_NULLFAIL bor                  %% NB: not in Core MANDATORY
    ?SCRIPT_VERIFY_TAPROOT.
```

Two distinct sub-issues:
- (a) `NULLFAIL` is **STANDARD-only in Core** (`policy.h:125`
  adds it; `MANDATORY` set at `policy.h:105-111` does NOT
  include it). beamchain's inclusion here is defensive at policy
  time but creates a fork-set divergence: a NULLFAIL-violating tx
  that PolicyScriptChecks already rejected can't reach
  ConsensusScriptChecks, but the inline comment at
  `mempool.erl:4291` says NULLFAIL was "made mandatory in 0.18.0" —
  which is **false** (it remains policy-only).
- (b) Future soft-fork: when a new SCRIPT_VERIFY bit becomes
  mandatory on the active chain, beamchain's policy-time consensus
  check **silently bypasses it**. The block-validation path
  (separate code) may enforce it via `GetBlockScriptFlags`, but
  the mempool would admit non-conformant txs that would then fail
  to mine into a block (orphan-prone if a beamchain miner uses
  them in a template).

**File:** `src/beamchain_mempool.erl:4286-4301`.

**Core ref:** `bitcoin-core/src/validation.cpp:1158-1189`
(`ConsensusScriptChecks`), `bitcoin-core/src/validation.cpp::
GetBlockScriptFlags`.

**Impact:** soft-fork upgrade hazard; current-tip semantics are
correct on mainnet but the wire-up to tip-derived flag computation
is missing. Cross-cite W144 fleet pattern (no
`script_flag_exceptions` table).

---

## BUG-11 (P0-CDIV) — `remove_block_conflicts` uses the wrong predicate; evicts legitimate CPFP children and misses real double-spends

**Severity:** P0-CDIV (mempool-management correctness — affects every
block-connection event). Bitcoin Core's `removeConflicts(tx)`
(`txmempool.cpp:removeConflicts`) iterates the **inputs of the
confirmed tx** and looks up each outpoint in `mapNextTx` (which maps
`outpoint → spender-iter`); any mempool tx that spends a matching
outpoint with a different txid is evicted recursively:

```cpp
for (const CTxIn &txin : tx.vin) {                            // confirmed tx's inputs
    auto it = mapNextTx.find(txin.prevout);                   // outpoint lookup
    if (it != mapNextTx.end()) {
        const CTransaction &txConflict = it->second->GetTx(); // mempool spender
        if (Assume(txConflict.GetHash() != tx.GetHash())) {
            removeRecursive(it->second, MemPoolRemovalReason::CONFLICT);
        }
    }
}
```

beamchain's `remove_block_conflicts/2` (`mempool.erl:2742-2777`)
inverts the predicate:

```erlang
ConfSet = sets:from_list(ConfirmedTxids),           %% set of CONFIRMED TXIDS
AllEntries = ets:tab2list(?MEMPOOL_TXS),
lists:foldl(fun({Txid, Entry}, {Bytes, Count, St}) ->
    %% for each MEMPOOL tx, check if any of its INPUT'S OUTPOINT.HASH
    %% is in the confirmed-txids set:
    HasConflict = lists:any(
        fun(#tx_in{prev_out = #outpoint{hash = H}}) ->
            sets:is_element(H, ConfSet)                 %% WRONG predicate
        end,
        (Entry#mempool_entry.tx)#transaction.inputs),
    ...
```

This is **the wrong predicate two ways**:

**Wrong direction A — false positives, evicts legitimate CPFP
children.** `prev_out.hash` is the **txid of the PARENT** (the tx
whose output is being spent). If `H` is in `ConfSet`, that means
"my parent was just confirmed in this block" — which is the
**normal, expected state** for a CPFP child whose parent was just
mined. The child IS still valid: its parent's output is now in the
UTXO set. beamchain evicts it as a "conflict". **Every CPFP child
gets erased from the mempool every time its parent confirms.**

**Wrong direction B — false negatives, misses real double-spend
conflicts.** A real conflict arises when `txM` (in mempool) spends
outpoint `(parent, vout)`, and the block contains `txB` (NOT
`parent`!) that ALSO spends `(parent, vout)` via a different
spender. To detect this, the predicate should walk **`txB.vin`**
(the confirmed tx's inputs) and look up `(parent, vout)` in
`?MEMPOOL_OUTPOINTS` (outpoint → mempool spender). beamchain's
predicate doesn't even consider `?MEMPOOL_OUTPOINTS`.

Combined, this means: every block confirms one or more parent txs,
beamchain immediately evicts every child of those parents (so they
must be re-broadcast and re-validated by the network), AND it never
catches a real reorg-induced double-spend.

**File:** `src/beamchain_mempool.erl:2742-2777`.

**Core ref:** `bitcoin-core/src/txmempool.cpp::removeConflicts`.

**Excerpt (beamchain, inverted predicate)**
```erlang
%% Build set of outpoints spent by confirmed txs
%% For each confirmed txid, its outputs are now in the UTXO set,
%% and any mempool tx spending the same inputs as a confirmed tx
%% is now invalid.
ConfSet = sets:from_list(ConfirmedTxids),                  %% txid set
...
HasConflict = lists:any(
    fun(#tx_in{prev_out = #outpoint{hash = H}}) ->         %% mempool tx's input
        sets:is_element(H, ConfSet)                         %% input.hash ∈ confirmed_txids
    end,
    (Entry#mempool_entry.tx)#transaction.inputs),
```

The inline comment confuses **outpoint** (parent_txid, vout) with
**input.hash** (parent_txid only). It describes the correct Core
behavior but implements the wrong check.

**Impact:**
- **CPFP child loss on every block confirmation.** A typical
  block contains ~3000 confirming txs; if ~5% have a CPFP child
  in the mempool, beamchain evicts ~150 valid mempool txs per
  block, requiring re-broadcast. Bandwidth waste + fee-estimation
  drift.
- **Reorg-induced double-spend miss.** A reorg where the new tip's
  block-N replaces a different tx-B at the same height (both
  spending the same outpoint with different spenders) doesn't
  trigger eviction of the mempool spender of the SAME outpoint;
  the orphaned spender lingers and may be re-mined in a later
  block, double-spending against the now-canonical chain.
- **Fleet pattern:** "comment-as-confession" — the comment
  describes Core's algorithm; the code implements the inverse.
  9th distinct beamchain comment-as-confession instance.

---

## BUG-12 (P0-CDIV) — `reprocess_orphans/1` calls `add_transaction/1` on the same gen_server; 30-second self-deadlock on every CPFP child

**Severity:** P0-CDIV (correctness — orphan promotion is broken).
`reprocess_orphans/1` (`mempool.erl:2598-2622`) is the function that
promotes orphans whose missing parent has just been seen. It's
called from two sites that BOTH run inside the mempool gen_server's
own process:
1. `do_add_transaction/2` → line 817 (after admitting a tx that
   may be a parent of orphans).
2. `do_remove_for_block/2` → `erase_orphans_for_block/1` → line 3040
   (after a block confirms a parent).

Inside `reprocess_orphans/1`, when an orphan is found whose missing
parent was the just-arrived/just-confirmed tx, the orphan is removed
from the orphan ETS tables and **re-submitted** via:

```erlang
case add_transaction(OrphanTx) of
    {ok, _} ->
        logger:debug("mempool: promoted orphan wtxid=~s", ...);
    {error, _} -> ok
end;
```

But `add_transaction/1` is:

```erlang
add_transaction(Tx) ->
    gen_server:call(?SERVER, {add_tx, Tx}, 30000).
```

The **caller IS the gen_server itself**. `gen_server:call` performs
a synchronous monitor + receive, but the request sits in its own
mailbox until the current `handle_call` returns — which it cannot
do because it's waiting on this call. The OTP runtime does not
detect self-call; it waits for the timeout. After 30 seconds:

- The current `handle_call({add_tx, ...})` is **still blocked**
  on this self-call (the receive hasn't returned yet — but the
  mailbox processing is also blocked because the gen_server is
  inside handle_call).
- Eventually the call returns `{'EXIT', timeout}` (via the monitor
  death from the gen_server's own demonitor or from gen_server's
  internal timeout); the orphan-promotion code logs nothing,
  silently consumes the timeout, and continues.
- The orphan record was already deleted at lines 2610-2611 BEFORE
  the doomed re-submission. It is **lost forever**.

The bug also affects `do_remove_for_block` (line 3040). Every block
that confirms a parent of a mempool orphan freezes the mempool
gen_server for 30 seconds AND loses the orphan.

There is a separate clue confirming this concern: `submit_block/1`
in `beamchain_chainstate.erl:243-260` documents the symmetric
deadlock and uses `refill_mempool_after_reorg/1` from OUTSIDE the
gen_server precisely to avoid it. beamchain knows the pattern;
it's just not applied to `reprocess_orphans`. **Plumb-gate-then-flip
2× in same wave** companion (W141 nimrod pattern).

**File:** `src/beamchain_mempool.erl:2598-2622, 817, 3040`.

**Core ref:** `bitcoin-core/src/txorphanage.cpp::PromoteOrphans` runs
synchronously inside the ATMP critical section; the equivalent in
beamchain would be to call `do_add_transaction/2` directly (passing
State through) instead of going through the gen_server boundary.

**Excerpt (beamchain, self-deadlock)**
```erlang
reprocess_orphans(NewTxid) ->
    Orphans = ets:tab2list(?MEMPOOL_ORPHANS),
    lists:foreach(fun({OrphanWtxid, OrphanTx, _Expiry}) ->
        HasParent = lists:any(...),
        case HasParent of
            true ->
                OrphanTxid = beamchain_serialize:tx_hash(OrphanTx),
                ets:delete(?MEMPOOL_ORPHANS, OrphanWtxid),                  %% delete first
                ets:delete(?MEMPOOL_ORPHAN_BY_TXID, OrphanTxid),
                case add_transaction(OrphanTx) of                            %% gen_server:call(self())
                    {ok, _} -> logger:debug(...);
                    {error, _} -> ok                                         %% 30s timeout silently ignored
                end;
            false -> ok
        end
    end, Orphans).
```

**Impact:**
- **Orphan promotion is functionally dead.** Every CPFP child
  whose parent arrives after it is lost after a 30-second
  mempool freeze.
- **Mempool gen_server availability collapses** during the freeze:
  every other RPC call (`sendrawtransaction`, `getrawmempool`,
  `getmempoolentry`, `testmempoolaccept`) queues up; new tx-relay
  from peers is silently dropped after the 30s gen_server:call
  timeout in the sync layer.
- **Block confirmation freezes the mempool for 30s** per
  block-promoting orphan. On a busy mainnet, this is a guaranteed
  10-minute window each block.
- **Cross-cite W93/B3 (chainstate ↔ mempool deadlock).** The same
  pattern was fixed there with `remove_for_block_async` (cast
  instead of call). The fix for this would be: route the orphan
  back through `do_add_transaction/2` IN-PROCESS (the function
  takes State as argument, so threading is straightforward); or
  use `gen_server:cast` and accept that the orphan is best-effort.

---

## BUG-13 (P1) — `do_trim_to_size(max_size)` is never called after `do_add_transaction`; `?DEFAULT_MAX_MEMPOOL_SIZE` is not enforced

**Severity:** P1. Bitcoin Core invokes `LimitMempoolSize(pool, ...)`
at the END of every successful `AcceptToMemoryPool` (validation.cpp
line ~1390-1395 inside `Finalize`), which calls
`pool.TrimToSize(maxMemPoolSize)`. This is what guarantees that the
mempool never exceeds `-maxmempool` MB (default 300 MB).

beamchain's `do_trim_to_size/2` (`mempool.erl:2792-2862`) is fully
implemented — cluster-aware eviction with rolling-fee bumping. But
a grep over `src/` confirms it has **zero non-test callers**:

```
$ grep -rn "trim_to_size\|expire_old" /home/work/hashhog/beamchain/src/
src/beamchain_mempool.erl:37:-export([trim_to_size/1, expire_old/0]).
src/beamchain_mempool.erl:329-336: (the API definitions)
src/beamchain_mempool.erl:475:    handle_call({trim_to_size, MaxBytes}, ...)
src/beamchain_mempool.erl:479:    handle_call(expire_old, ...)
```

No production code path ever calls `beamchain_mempool:trim_to_size/1`.
After `do_add_transaction` commits at line 822 (state.total_bytes
incremented), there is no `do_trim_to_size(State.max_size, State)`
call. The mempool **grows past 300 MB unbounded** until either:
- the operator manually calls a hypothetical RPC to invoke
  `trim_to_size`, or
- the gen_server runs out of memory and crashes.

**File:** `src/beamchain_mempool.erl:812-815` (state-totals update
after add) — should be followed by `do_trim_to_size(max_size,
State)`; `src/beamchain_mempool.erl:329-336, 475-477` (the API
exists but has no production caller).

**Core ref:** `bitcoin-core/src/validation.cpp::Finalize` (calls
`LimitMempoolSize` → `m_pool.TrimToSize`).

**Impact:** mempool size limit is **fully unenforced** in production.
Under a sustained tx-flood (or even normal load over many days),
beamchain's mempool grows without bound. Memory pressure eventually
causes BEAM emulator to OOM-kill the entire node.

---

## BUG-14 (P1) — `do_expire_old(MEMPOOL_EXPIRY_HOURS=336)` is never called automatically

**Severity:** P1 (companion to BUG-13). Core's
`CTxMemPool::Expire(time)` is invoked from `LimitMempoolSize` after
every block-connection event AND after every successful
`AcceptToMemoryPool`. It removes any tx older than 14 days.

beamchain's `do_expire_old/1` (`mempool.erl:2917-2963`) is fully
implemented but the same grep above shows it has zero non-test
callers in production. The `expire_orphans` timer fires every
60 seconds (mempool.erl:403) but it expires **orphan-pool**
entries, NOT mempool entries.

A tx admitted to the mempool and never confirmed (e.g., a low-fee
tx during a fee spike) stays in the mempool **forever** — Core
would have expired it after 14 days.

Combined with BUG-13: there is no path that ever removes a
mempool entry except (a) block-confirmation removal,
(b) RBF eviction, (c) external operator RPC. The mempool is
effectively a write-only structure plus the two narrow removal
paths.

**File:** `src/beamchain_mempool.erl:334-336, 479-481` (API and
handler exist; no automatic invocation); compare to the
`expire_orphans` timer wiring at line 403.

**Core ref:** `bitcoin-core/src/validation.cpp::LimitMempoolSize`
(calls `m_pool.Expire`).

**Impact:** unbounded growth of stale txs; cross-cite BUG-13. The
14-day Core expiry contract is plumbed-but-not-enforced.

---

## BUG-15 (P1) — testmempoolaccept and submitpackage emit Erlang-term reject reasons (`~p`), not canonical Core tokens

**Severity:** P1 (wire-format parity — affects every external
consumer of testmempoolaccept and submitpackage). The
`testmempoolaccept` reply schema is documented per Core's
rpc/mempool.cpp. The `reject-reason` field is expected to carry a
canonical short string like `"dust"`, `"bad-witness-nonstandard"`,
`"insufficient fee, rejecting replacement"`.

beamchain renders the field via `io_lib:format("~p", [Reason])`:
- `'bad-witness-nonstandard'` becomes the binary
  `<<"bad-witness-nonstandard">>` (with single quotes around the
  atom — `~p` quotes atoms with non-alphanumeric chars).
- `{'bad-txns-too-many-sigops', 16012}` becomes
  `<<"{'bad-txns-too-many-sigops',16012}">>` (tuple syntax leaked).
- `script_verify_failed` (atom without special chars) becomes
  `<<"script_verify_failed">>` (no quotes, no Core token mapping).

The same fall-through fires in:
- `rpc_testmempoolaccept` single-tx path (`rpc.erl:2823-2824`).
- `rpc_testmempoolaccept` multi-tx path (`rpc.erl:2847-2848`).
- `rpc_submitpackage` `package_msg` field (`rpc.erl:2963-2965`).
- `format_mempool_error` fall-through (`rpc.erl:2774-2776`).

This is the W125/W145 "reject-string wire-parity slippage" fleet
pattern (lunarblock W145 9-token sweep). beamchain's mempool has
~30 distinct reject atoms; only ~15 have explicit mappings in
`format_mempool_error`. Every other one leaks Erlang term syntax.

**File:** `src/beamchain_rpc.erl:2774-2776, 2823-2824, 2847-2848,
2963-2965`.

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::testmempoolaccept`
(emits `state.GetRejectReason()` as a plain string).

**Impact:** wire-format break; tools parsing the `reject-reason`
field against Core's taxonomy see beamchain-specific strings with
quote characters and tuple braces. `electrum`, `mempool.space`,
`btcd`-compat tools all break on these fields.

---

## BUG-16 (P0-SEC) — No peer-misbehavior accounting on ATMP rejection; malicious peers spam invalid-script txs without consequence

**Severity:** P0-SEC. Core's `MaybePunishNodeForTx`
(`net_processing.cpp`) increments peer misbehavior based on the
`TxValidationResult`:
- `TX_INVALID` (consensus violation) → +100 (immediate ban).
- `TX_NOT_STANDARD` → no ban, but the tx contributes to the
  `m_recent_rejects` filter (so the peer can't re-broadcast the
  same garbage cheaply).

beamchain's tx-relay path (`beamchain_sync.erl:332-350`) only
punishes for **decoder failure** (line 348). A peer that sends a
syntactically valid tx that fails ATMP for any reason — invalid
signature, MoneyRange violation, bad-witness-merkle, anything —
is logged at debug level and otherwise ignored:

```erlang
route_message(Peer, tx, Payload, State) ->
    case beamchain_p2p_msg:decode_payload(tx, Payload) of
        {ok, Tx} ->
            case beamchain_mempool:accept_to_memory_pool(Tx) of
                {ok, Txid} -> ...broadcast...;
                {error, Reason} ->
                    logger:debug("sync: rejected tx from ~p: ~p", [Peer, Reason])
                    %% MISSING: beamchain_peer:add_misbehavior(Peer, ...);
            end;
        _Error ->
            beamchain_peer:add_misbehavior(Peer, 20)
    end,
    State;
```

A malicious peer can repeatedly send invalid-script txs (each
fails the full 21-gate pipeline at PolicyScriptChecks/
ConsensusScriptChecks, but the decoder pass succeeds), forcing
beamchain to expend full ECDSA-validation CPU on every one,
without any rate-limiting feedback. There is no `m_recent_rejects`
filter either (BUG-17 below).

**File:** `src/beamchain_sync.erl:332-350`.

**Core ref:** `bitcoin-core/src/net_processing.cpp::MaybePunishNodeForTx`.

**Impact:**
- **CPU-exhaustion DoS primitive.** A single peer can saturate
  ECDSA-validation cores by repeatedly sending invalid-sig txs.
- **No rate-limiting feedback.** beamchain doesn't track which
  peer fed which bad tx; cannot disconnect repeat offenders.
- Defense-in-depth gap that matches W128 "8-of-10 banman fleet-
  wide CVE" pattern.

---

## BUG-17 (P1) — No `m_recent_rejects` rolling-Bloom; every duplicate bad tx re-runs all 21 gates

**Severity:** P1 (CPU/bandwidth waste; companion to BUG-16). Core
maintains `m_recent_rejects` — a 120k-entry rolling Bloom filter of
recently-rejected txids (and a secondary `m_recent_rejects_reconsiderable`
for txs that may become valid after a parent arrives). On tx-relay,
Core checks the filter BEFORE running PreChecks; a match short-
circuits to "already rejected, no work to do".

beamchain has no equivalent. Every duplicate from any peer reruns
all 21 gates (cheap up to the script gates, then expensive).
Combined with BUG-16 (no misbehavior accounting), this means:
**a peer can re-broadcast the same invalid tx every second** and
beamchain re-pays the full CPU cost each time.

**File:** entire `src/beamchain_mempool.erl` — grep for
`recent_rejects`, `RejectsFilter`, `recentlyRejected` returns 0 hits.

**Core ref:** `bitcoin-core/src/net_processing.cpp::m_recent_rejects`
(declared in `PeerManagerImpl`, initialized 120k entries).

**Impact:** CPU-amplification DoS surface; bandwidth waste.

---

## BUG-18 (P1) — `submitpackage` `maxburnamount = 0` is treated as "no limit" (Core: "reject any unspendable output > 0")

**Severity:** P1. Core's `submitpackage` (and `sendrawtransaction`)
parses `maxburnamount` as:

```cpp
const CAmount max_burn_amount = request.params[2].isNull() ? 0 : AmountFromValue(request.params[2]);
```

Then later: `if (out.scriptPubKey.IsUnspendable() && out.nValue > max_burn_amount) throw MAX_BURN_EXCEEDED;`.

So `max_burn = 0` means "any unspendable output > 0 sat is rejected"
(zero-value OP_RETURN passes). beamchain inverts the contract at
`rpc.erl:2939-2954`:

```erlang
case MaxBurnSat > 0 of
    true -> ... burn-amount check ...;
    false -> ok               %% MaxBurnSat == 0 → skip the check entirely
end,
```

When operator passes `maxburnamount=0` (or omits the arg),
beamchain accepts a package with any-value OP_RETURN outputs.
Core rejects them.

**File:** `src/beamchain_rpc.erl:2939-2954`.

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::submitpackage` (and
the `max_burn_amount` parse a few hundred lines down for
`sendrawtransaction`).

**Impact:** operator running beamchain with `maxburnamount=0` (the
sensible default) gets the opposite behavior from Core. A burn-
prevention guard is silently disabled.

---

## BUG-19 (P1) — `submitpackage` always reports empty `replaced-transactions`; RBF replacements via package are invisible

**Severity:** P1 (comment-as-confession; consumer-API contract
break). Core's `submitpackage` response includes a
`replaced-transactions` array listing every txid evicted via RBF
during package acceptance. beamchain hardcodes an empty list
with an inline confession:

```erlang
{ok, #{
    <<"package_msg">> => PackageMsg,
    <<"tx-results">> => TxResultMap,
    %% beamchain's package validator does not yet emit
    %% a per-package replaced-tx list. Empty array keeps
    %% the field shape parity with Core.
    <<"replaced-transactions">> => []
}}
```

Operators monitoring RBF activity via `submitpackage` (a recommended
ancestor-aware RBF entry point) see zero replacements every time.
Wallets that drive submitpackage in a `try replacement → check
replaced-transactions` loop are misinformed.

**File:** `src/beamchain_rpc.erl:2987-2994` (response builder);
`src/beamchain_mempool.erl:1466+` (`accept_package_txs` does
internally produce eviction lists but they're discarded at the
RPC boundary).

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::submitpackage`
return-shape (specifically the `replaced-transactions` field).

**Impact:** consumer-API contract break; 10th distinct beamchain
comment-as-confession instance (cross-cite W141 series).

---

## BUG-20 (P1) — `ds_is_unspendable/1` only matches OP_RETURN prefix; Core's `IsUnspendable` also catches scripts > MAX_SCRIPT_SIZE

**Severity:** P1. Bitcoin Core's `CScript::IsUnspendable()`
(`script/script.h`) returns true when EITHER:
- the script starts with OP_RETURN (`0x6a`), OR
- the script length > `MAX_SCRIPT_SIZE` (10000 bytes).

beamchain's `ds_is_unspendable/1` (`rpc.erl:4157-4159`) only checks
the OP_RETURN prefix:

```erlang
ds_is_unspendable(<<16#6a, _/binary>>) -> true;
ds_is_unspendable(_)                   -> false.
```

An attacker submitting a package whose outputs have a 10001-byte
scriptPubKey that does NOT start with OP_RETURN sneaks past the
`maxburnamount` check (`rpc.erl:2944`) even though those outputs
are unspendable per Core. The `maxburnamount` gate becomes
permissive on script-bloat unspendables.

**File:** `src/beamchain_rpc.erl:4157-4159`.

**Core ref:** `bitcoin-core/src/script/script.h::IsUnspendable`.

**Impact:** burn-amount-limit bypass for script-bloat unspendable
outputs (rare in practice, but a parity gap).

---

## BUG-21 (P1) — `mempool_full_rbf` defaults to TRUE (Core: also TRUE, but no operator override per-tx)

**Severity:** P1 — wait, let me re-check. Core 28.0+ defaults
`-mempoolfullrbf` to `true`. beamchain matches (config.erl:181).
However, beamchain only checks the **global** flag; it does not
support per-tx opt-OUT signaling via `nSequence < 0xfffffffe`.
Actually Core ALSO doesn't support per-tx opt-out — full-rbf
overrides the BIP-125 signaling entirely. So this is parity.
**Re-classifying: NOT A BUG. Dropping this entry from the count.**

---

## BUG-22 (P1) — Mempool max_size constant is not derived from `-maxmempool` operator flag

**Severity:** P1 (operator-knob absence; companion to BUG-13). Core
exposes `-maxmempool=<MB>` (default 300). beamchain hardcodes
`?DEFAULT_MAX_MEMPOOL_SIZE = 300 * 1024 * 1024` at
`mempool.erl:98` and uses it at `mempool.erl:413` (state init);
there is no `beamchain_config` knob, no env var, no CLI flag.

Combined with BUG-13 (no trim invocation), the constant is doubly
inert — but the operator-knob is still missing, so even when BUG-13
is fixed there's no way to tune the limit without recompiling.

`getmempoolinfo` advertises `maxmempool = 300000000` per
`rpc.erl:3255` — operators see the value but can't change it.

**File:** `src/beamchain_mempool.erl:98, 413`;
`src/beamchain_rpc.erl:3255`.

**Core ref:** `bitcoin-core/src/kernel/mempool_options.h::DEFAULT_MAX_MEMPOOL_SIZE_MB`
(parsed from `-maxmempool` by `bitcoind`).

**Impact:** operator cannot tune mempool size without recompiling.
Fleet pattern of "no operator-knob" (cross-cite W138 BUG-4
clearbit, W148 BUG-6 blockbrew).

---

## BUG-23 (P1) — `MIN_RELAY_TX_FEE` and `DEFAULT_MIN_RELAY_TX_FEE` are two separate constants both set to 1000

**Severity:** P1 (cleanup; reduces blast radius of fixing BUG-5).
beamchain defines:
- `?MIN_RELAY_TX_FEE = 1000` (mempool.erl:99, module-local)
- `?DEFAULT_MIN_RELAY_TX_FEE = 1000` (protocol.hrl:161, global)

Both are used in scattered places. `?MIN_RELAY_TX_FEE` is referenced
only in the mempool.erl header comment and is otherwise dead.
`?DEFAULT_MIN_RELAY_TX_FEE` is the production constant (mempool.erl
fee gate, rpc.erl info reporting). When fixing BUG-5, both need to
change, and a future contributor may update one but not the other.

**File:** `src/beamchain_mempool.erl:99`,
`include/beamchain_protocol.hrl:161`.

**Impact:** maintenance hazard; cleanup candidate.

---

## BUG-24 (P1) — `lookup_entry_by_wtxid` uses ETS linear scan; O(N) per accept

**Severity:** P1 (perf). beamchain has only one ETS index
(`?MEMPOOL_TXS` keyed by txid). The wtxid duplicate check
(BIP-339) requires a wtxid lookup, performed via
`ets:match_object(?MEMPOOL_TXS, {'_', #mempool_entry{wtxid = Wtxid, _ = '_'}})`
(`mempool.erl:4368-4374`). `ets:match_object` on a set table
with a partial-key pattern is **O(table size)**.

Every `do_add_transaction` invokes `lookup_entry_by_wtxid(Wtxid)`
at line 568 — that's one O(N) scan per tx-accept. At 30k mempool
txs, that's 30k entries scanned per arrival. Compounded with
peer-flood, the gen_server CPU becomes bottlenecked on this scan
even before reaching the script-verify gates.

Inline comment confirms the issue:

```erlang
%% Beamchain stores entries keyed by txid in ?MEMPOOL_TXS but also stamps each
%% entry with its wtxid.  Core has two separate indices (mapTx + mapTxByWtxid);
%% we emulate the wtxid index with a linear scan.  Mempool sizes are bounded
%% so the cost is acceptable; if it becomes a hotspot a secondary ets index
%% on wtxid → txid would be the right fix.
```

Comment-as-confession (11th distinct beamchain instance).

**File:** `src/beamchain_mempool.erl:4368-4374`.

**Core ref:** `bitcoin-core/src/txmempool.h::mapTxByWtxid` (explicit
secondary index keyed by wtxid).

**Impact:** O(N) per-tx-accept overhead; 30k mempool → ~30k entry
scans per accept; degrades to seconds-per-tx at large mempool
size. Aggregates with BUG-13 (no trim) for catastrophic compounding.

---

## Summary

**Bug count:** 22 (BUG-1 through BUG-24, with BUG-21 retracted).

**Severity distribution:**
- **P0-CDIV:** 5 (BUG-5, BUG-8, BUG-9, BUG-11, BUG-12)
- **P0-SEC:** 1 (BUG-16)
- **P1:** 16 (BUG-1, BUG-2, BUG-3, BUG-4, BUG-6, BUG-7, BUG-10,
  BUG-13, BUG-14, BUG-15, BUG-17, BUG-18, BUG-19, BUG-20, BUG-22,
  BUG-23, BUG-24)
- **P2:** 0

(Recount: 5 + 1 + 17 = 23. Re-checking P1: BUG-1, BUG-2, BUG-3,
BUG-4, BUG-6, BUG-7, BUG-10, BUG-13, BUG-14, BUG-15, BUG-17,
BUG-18, BUG-19, BUG-20, BUG-22, BUG-23, BUG-24 = 17. Total =
5 + 1 + 17 = 23.)

Final: **23 bugs** (5 P0-CDIV, 1 P0-SEC, 17 P1).

**Fleet patterns confirmed:**
- **"dead-flag plumbing"** (BUG-8) — `all_standard_flags()` omits
  3 STANDARD bits; the script interpreter has handlers for all 3
  but the mempool mux never sets them. 10th distinct fleet
  instance of W144's STANDARD_SCRIPT_VERIFY_FLAGS-incomplete
  pattern (9-of-10 → now 10-of-10).
- **"comment-as-confession"** (BUG-5 line 692-693 "wrong constant
  value cited inline"; BUG-11 line 2742-2744 "describes Core
  correctly, implements inverse"; BUG-19 line 2990-2992 "does not
  yet emit"; BUG-24 line 4365-4367 "if it becomes a hotspot...")
  — 4 distinct instances in this audit; 8th-11th distinct
  beamchain instances overall.
- **"dead-handler plumbing"** (BUG-13, BUG-14) — `do_trim_to_size`
  and `do_expire_old` exist, are tested, are exported via the
  gen_server API, but have zero non-test callers. Same shape as
  W138 "30-of-30 gates buggy" archetype where the function exists
  but the call site is missing.
- **"reject-string wire-parity slippage"** (BUG-1, BUG-2, BUG-15)
  — W125/W145 pattern, 12th-14th distinct beamchain instances.
- **"no operator-knob exists"** (BUG-22) — `-maxmempool` absent;
  W138/W148 fleet pattern.
- **"two-pipeline guard"** does NOT extend in this audit (mempool
  has only one accept path; the dry-run path is structurally
  parallel by design).
- **"plumb-gate-then-flip"** (BUG-12) — beamchain ALREADY KNOWS
  about the self-deadlock pattern (cited inline at
  `chainstate.erl:243-246`) and uses `_async` cast to avoid it
  for `remove_for_block`, but the SAME pattern in
  `reprocess_orphans` still uses synchronous self-call. The
  defensive infrastructure is present; only one entry point uses
  it. Matches W141 nimrod "plumb-gate-then-flip 2× in same wave".
- **"inverted-predicate cluster"** (BUG-11) — first beamchain
  instance of a predicate that describes Core's algorithm
  correctly in the comment but implements its inverse in code.
- **"30-second self-deadlock"** (BUG-12) — first beamchain
  instance; pairs with the W93/B3 fix that already exists for the
  chainstate↔mempool direction.

**Top three findings:**

1. **BUG-12 (P0-CDIV reprocess_orphans self-deadlock)** —
   `add_transaction/1` is `gen_server:call(SELF)` from inside the
   mempool gen_server's own `handle_call`. Every CPFP child whose
   parent arrives after it triggers a 30-second mempool freeze AND
   permanently loses the orphan record. Fires from two distinct
   sites (tx-accept and block-confirm). Catastrophic effect on
   orphan promotion AND on mempool availability during the freeze
   window.

2. **BUG-11 (P0-CDIV removeConflicts wrong predicate)** —
   `remove_block_conflicts/2` tests `prev_out.hash in
   confirmed_txids` instead of `(prev_out.hash, prev_out.index)
   spent_by_confirmed_input`. This evicts EVERY legitimate CPFP
   child from the mempool when its parent confirms AND misses
   every real reorg-induced double-spend conflict. Fires on every
   block-connection event. ~150 mempool losses per typical block.

3. **BUG-5 (P0-CDIV DEFAULT_MIN_RELAY_TX_FEE off by 10×)** —
   beamchain hardcodes 1000 sat/kvB (1.0 sat/vB); Core's current
   value is 100 sat/kvB (0.1 sat/vB). All txs in [0.1, 0.99]
   sat/vB are silently rejected with `"mempool min fee not met"`,
   diverging from every other mempool on the network. Companion
   to W141 nimrod `mempoolminfee 1000× divisor` (same shape of
   fee-unit confusion).

**Honorable mentions:**
- **BUG-8 (P0-CDIV all_standard_flags missing 3 bits)** — first
  beamchain instance of the W144 fleet-wide STANDARD-flag mux gap;
  closes the 9-of-10 → 10-of-10 fleet pattern.
- **BUG-13 + BUG-14 (P1 dead-handler plumbing for trim + expire)**
  — mempool has no automatic size cap and no automatic 14-day
  expiry; can only be triggered by external RPC. Compounds with
  BUG-24 (O(N) wtxid scan) for catastrophic large-mempool perf.
- **BUG-16 (P0-SEC no peer misbehavior on tx-reject)** — every ATMP
  reject path silently logs at debug level; malicious peers can
  spam invalid-sig txs without rate-limiting. CPU-exhaustion DoS
  primitive.

**Carry-forward catches:**
- W143/W149 hex_to_bin DISPLAY-vs-INTERNAL byte-order: **not
  triggered in W150** — mempool path uses txids/wtxids as binary
  hashes throughout; no DISPLAY-vs-INTERNAL conflation surfaces
  at policy boundaries.
- W140 BUG-3 pattern-match short-circuit on validation: **not
  triggered in W150** — the catch-all in `do_add_transaction`'s
  outer try (line 833-840) is `throw:Reason -> {error, Reason}`,
  which is the correct shape (no `_:_` swallow).
- W141 BUG-3 list_to_atom atom-table DoS: **not triggered in
  W150** mempool path (the only `list_to_atom` in beamchain is in
  `beamchain_zmq.erl:209`, unrelated to mempool).
- W141 BUG-4 chumak:stop OTP-callback no-op: **not triggered in
  W150** (mempool gen_server's terminate/2 is well-formed).
