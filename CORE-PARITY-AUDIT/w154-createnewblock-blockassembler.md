# W154 — CreateNewBlock + BlockAssembler + block template construction (beamchain)

**Wave:** W154 — `BlockAssembler::CreateNewBlock`, `addChunks`,
`TestChunkBlockLimits`, `TestChunkTransactions`, `AddToBlock`,
`resetBlock`, `ApplyArgsManOptions`, `ClampOptions`, `GetMinimumTime`
(BIP-94), `UpdateTime`, `RegenerateCommitments`,
`AddMerkleRootAndCoinbase`, `GenerateCoinbaseCommitment` (BIP-141 OP_RETURN
`0xaa21a9ed`), `BlockMerkleRoot` / `BlockWitnessMerkleRoot`,
`CoinbaseTx::block_reward_remaining`, BlockTemplate request handling,
package-feerate (chunk) selection, BIP-9/BIP-34/BIP-141 wiring in the
template.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/node/miner.cpp` — `BlockAssembler::CreateNewBlock`
  (line 122–237), `addChunks` (279–334), `TestChunkBlockLimits` (239–248),
  `TestChunkTransactions` (252–260), `AddToBlock` (262–277), `resetBlock`
  (111–120), `ClampOptions` (79–88), `ApplyArgsManOptions` (98–109),
  `GetMinimumTime` (36–47, BIP-94 timewarp `MAX_TIMEWARP = 600`),
  `UpdateTime` (49–65), `RegenerateCommitments` (67–77),
  `AddMerkleRootAndCoinbase` (336–351).
- `bitcoin-core/src/node/miner.h` — `BlockAssembler::Options` (81–88),
  `CBlockTemplate` (42–57), `nBlockMaxWeight = DEFAULT_BLOCK_MAX_WEIGHT`
  (line 83).
- `bitcoin-core/src/policy/policy.h` — `DEFAULT_BLOCK_MAX_WEIGHT = MAX_BLOCK_WEIGHT`
  (25), `DEFAULT_BLOCK_RESERVED_WEIGHT = 8000` (27),
  `MINIMUM_BLOCK_RESERVED_WEIGHT = 2000` (34),
  `DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS = 400` (29),
  `MAX_STANDARD_TX_SIGOPS_COST = MAX_BLOCK_SIGOPS_COST / 5` (44).
- `bitcoin-core/src/consensus/consensus.h` — `MAX_BLOCK_WEIGHT = 4000000`
  (12), `WITNESS_SCALE_FACTOR = 4` (16), `MAX_BLOCK_SIGOPS_COST = 80000`
  (17), `MAX_TIMEWARP = 600` (35).
- `bitcoin-core/src/consensus/tx_verify.cpp` — `GetTransactionSigOpCost`
  (line 143–164) — legacy×4 + P2SH×4 + witness sigops.
- `bitcoin-core/src/validation.cpp` — `GenerateCoinbaseCommitment`
  (3997–4019) sets the `OP_RETURN 0x24 0xaa21a9ed <32-byte>` output
  unconditionally when no commitment is present, regardless of whether any
  tx has a witness; `CheckWitnessMalleation` (3870–3899).
- `bitcoin-core/src/consensus/merkle.cpp` — `BlockMerkleRoot` (66–73),
  `BlockWitnessMerkleRoot` (76–84), `ComputeMerkleRoot` (46–) — does
  NOT detect mutated/duplicate-leaf pairs (CVE-2012-2459 mitigation
  is left to `IsBlockMutated` / `CheckMerkleRoot`).
- `bitcoin-core/src/rpc/mining.cpp` — `getblocktemplate` request handling
  (730–852, mode="proposal" at 730–752, `rules` enforcement at 854–857),
  `longpollid` (783–845), `getmininginfo`, `submitblock`,
  `generatetoaddress`, `generateblock` (305–415; uses
  `RegenerateCommitments` to re-sync commitments after the caller
  appends txs), `submitheader`, `prioritisetransaction`.
- `bitcoin-core/src/script/script.h` — `CScript::push_int64` (433–442):
  `n in {1..16}` pushes `OP_1..OP_16` (single byte 0x51..0x60), NOT
  a length-prefixed push.

**Files audited**
- `src/beamchain_miner.erl` — `start_link`, `create_block_template/{1,2}`,
  `submit_block/1`, `generate_blocks/3`, `generate_block_with_txs/3`,
  `encode_coinbase_height/1`, `build_gbt_rules_and_vbavailable/2`,
  `do_create_template/3` (183–352), `do_submit_block/1` (512–578),
  `select_transactions/2` (601–628), `ancestor_fee_rate/1` (633–644),
  `greedy_select/11` (666–746), `resolve_parents/2` (749–773),
  `estimate_sigops/1` (777–784), `topological_sort/1` (791–812),
  `build_coinbase/5` (845–894), `witness_commitment_output/2` (898–914),
  `le_minimal/1` (927–943), `do_generate_blocks/4` (950–962),
  `do_generate_one_block/3` (965–990), `do_generate_block_with_txs/4`
  (993–1075), `build_coinbase_for_txs/5` (1078–1117),
  `witness_commitment_for_txs/2` (1120–1126), `mine_block/4` /
  `mine_block_loop/5` (1131–1149), `compute_minimum_time/3` (430–441).
- `src/beamchain_serialize.erl` — `compute_merkle_root/1` (206–213),
  `merkle_pairs/1` (215–221) — NO CVE-2012-2459 dup-pair detection;
  `compute_witness_commitment/2` (223–227), `block_hash/1` (185–189),
  `wtx_hash/1` (195–200) (hash256 returns natural/internal byte order).
- `src/beamchain_chain_params.erl` — `block_subsidy/2` (393–399) is
  params-aware (closes W145 BUG-1 class for beamchain at the chainparams
  level); `bip30_exceptions` list (81–84) stores hashes via
  `hex_to_bin/1` (line 574–581, DISPLAY-order bytes); cf.
  `display_hex_to_bin/1` (592–595) which reverses to INTERNAL order
  (W143 BUG-1 byte-order class — flagged on `validation.erl` connect
  path; miner side does not consult `bip30_exceptions` directly).
- `src/beamchain_validation.erl` — `check_block/2` (100–168) — counts
  only `count_legacy_sigops_tx` × WITNESS_SCALE_FACTOR (no P2SH /
  witness sigops at the CHECK_BLOCK gate); `is_final_tx/3` (294–306);
  `get_tx_sigop_cost/3` (924–940) — the cost-correct helper exists,
  but `select_transactions` does NOT use it (uses `estimate_sigops/1`).
- `src/beamchain_versionbits.erl` — `compute_block_version/2` (657–668)
  — version bits seeded with `VERSIONBITS_TOP_BITS = 0x20000000`, OR
  each STARTED/LOCKED_IN deployment bit; deployment state computation.
- `src/beamchain_rpc.erl` — `rpc_getblocktemplate/1` (3720–3739),
  `bip22_result/1` (3748–3808), `rpc_submitblock/1` (3810–3834),
  `rpc_generatetoaddress/3` (3843–3873), `rpc_generateblock/3`
  (3880–3916), `rpc_generate/1` (3918–nn), `parse_generate_transactions/2`
  (3945–nn).
- `src/beamchain_mempool.erl` — `get_sorted_by_fee/0` (298–309, ETS),
  `get_info/0` (294–295, gen_server:call), `compute_ancestors/3`
  (2351–2365), `ancestor_size` / `ancestor_fee` fields on
  `#mempool_entry{}` (139–140).
- `src/beamchain_chainstate.erl` — `get_tip/0` (192–197, ETS),
  `get_mtp/0` (200–202, gen_server:call), `submit_block/1` (251–260,
  gen_server:call), `is_synced/0` (205–207).
- `include/beamchain_protocol.hrl` — `MAX_BLOCK_WEIGHT = 4000000` (9),
  `MAX_BLOCK_SIGOPS_COST = 80000` (10), `WITNESS_SCALE_FACTOR = 4` (11),
  `MAX_BLOCK_SERIALIZED_SIZE = 4000000` (12),
  `DIFFICULTY_ADJUSTMENT_INTERVAL = 2016` (30).

---

## Gate matrix (32 sub-gates / 14 behaviours)

Legend: PASS = parity with Core; PARTIAL = wired but deviates;
**BUG-N** = open finding.

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | MAX_BLOCK_WEIGHT constant | G1: defined and = 4_000_000 | PASS (`protocol.hrl:9`) |
| 1 | … | G2: enforced in `select_transactions` | PASS (`miner.erl:615`; `>= MaxW` check at 728) |
| 2 | WITNESS_SCALE_FACTOR constant | G3: defined and = 4 | PASS (`protocol.hrl:11`) |
| 2 | … | G4: used in sigops accounting | PASS (`miner.erl:784`) |
| 3 | DEFAULT_BLOCK_MAX_WEIGHT | G5: defined and = MAX_BLOCK_WEIGHT | **BUG-1 (P1)** — beamchain has no `DEFAULT_BLOCK_MAX_WEIGHT` analogue, no `-blockmaxweight` operator knob; pool can't shrink template |
| 3 | … | G6: `-blockmaxweight` CLI exposed | **BUG-1 cross-cite** |
| 4 | DEFAULT_BLOCK_RESERVED_WEIGHT | G7: defined and = 8000 | PASS (`miner.erl:36`, W87 fix landed) |
| 4 | … | G8: `-blockreservedweight` CLI exposed + clamped `[MINIMUM=2000, MAX_BLOCK_WEIGHT]` | **BUG-2 (P1)** — constant hard-coded; no operator knob; no `MINIMUM_BLOCK_RESERVED_WEIGHT=2000` floor anywhere |
| 5 | DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS | G9: = 400 and subtracted from sigop budget | PASS (`miner.erl:42, 619`) |
| 5 | … | G10: operator-knob | **BUG-2 cross-cite** |
| 6 | addPackageTxs / addChunks (ancestor-feerate selection) | G11: sort by ancestor fee/weight ratio (CPFP-aware) | PARTIAL — `ancestor_fee_rate/1` (`miner.erl:633-644`) computes ancestor_fee / (ancestor_size × WITNESS_SCALE_FACTOR), with the off-by-1-to-3 noted at line 637-639 ("vsize*4 is a reasonable upper bound") |
| 6 | … | G12: chunk-feerate (multi-tx package) selection | **BUG-3 (P0-CDIV)** — beamchain's `greedy_select` always picks ONE entry at a time, then `resolve_parents` pulls in its unselected mempool parents transitively; Core's `addChunks` pulls in a pre-clustered "chunk" via `m_mempool->GetBlockBuilderChunk(selected_transactions)` (a package of txs that should be evaluated together). beamchain's single-entry-then-pull-parents diverges from chunk-based selection in the package-fee-rate behaviour; a child whose ancestor-fee-rate exceeds blockMinFeeRate but whose OWN fee rate is below it gets evaluated only after the parent is in (so it's selected based on its own fee), not as a chunk |
| 6 | … | G13: skip already-selected via "Seen" set | PASS (`miner.erl:678`) |
| 6 | … | G14: MAX_CONSECUTIVE_FAILURES early-exit | PASS (`miner.erl:47, 668-672`) |
| 6 | … | G15: blockMinFeeRate gate (`DEFAULT_BLOCK_MIN_TX_FEE = 1 sat/kvB`) | PASS (`miner.erl:53, 689`) |
| 6 | … | G16: IsFinalTx per chunk before adding | PASS (`miner.erl:698-705`) |
| 7 | GenerateCoinbaseCommitment | G17: OP_RETURN 0xaa21a9ed (39 bytes) | PASS (`miner.erl:912-913`) |
| 7 | … | G18: commitment over witness merkle root + witness reserved value (32-zero nonce by default) | PASS (`miner.erl:898-914`, `serialize.erl:223-227`) |
| 7 | … | G19: commitment is added unconditionally when SegWit is active (Core's `GenerateCoinbaseCommitment` adds even for legacy-only blocks) | **BUG-4 (P1)** — beamchain gates on `HasWitnessTx` (`miner.erl:329, 873-880`); a legacy-only block under SegWit-active context does NOT get a commitment. Cross-cite: Core's `validation.cpp:3997` adds unconditionally regardless of witness presence (when `commitpos == NO_WITNESS_COMMITMENT`) |
| 8 | BlockMerkleRoot + BlockWitnessMerkleRoot | G20: merkle root computed from natural-order txid leaves | PASS (`miner.erl:248-249`, `serialize.erl:206-221`) |
| 8 | … | G21: witness merkle root uses 32-zero coinbase wtxid | PASS (`miner.erl:900`) |
| 8 | … | G22: CVE-2012-2459 mutated-merkle dup-pair detection at the miner level | **BUG-5 (P1)** — `serialize.erl:215-221`'s `merkle_pairs` blindly duplicates an unpaired entry without checking whether the prior pair matched (no fanout-collision detection in the miner; the `check_merkle_malleation` exists in validation.erl:151 but is NOT run during template construction). A pool that mutates the tx list and resubmits could trigger malleation off-path. Fleet pattern: W142+W143 6+ impls confirmed missing CVE-2012-2459 |
| 9 | mintime / GetMinimumTime / BIP-94 | G23: mintime = MTP + 1 in non-boundary heights | PASS (`miner.erl:312`) |
| 9 | … | G24: mintime = max(MTP+1, prev_block_time - MAX_TIMEWARP) at difficulty-adjustment boundaries (BIP-94) | **BUG-6 (P0-CDIV)** — `miner.erl:312` emits `<<"mintime">> => MTP + 1` unconditionally; the BIP-94 boundary check (`compute_minimum_time/3` at line 432-441) IS computed for the local `Timestamp` field at line 253, but the GBT-exposed `mintime` field is the raw `MTP + 1`. A pool that respects the GBT `mintime` will mine at `MTP+1` which can VIOLATE BIP-94 at the 2016-block boundary (rejected by Core peers as `time-timewarp-attack` when boundary minimum < `prev_block_time - 600`). Core `rpc/mining.cpp:1004` emits `GetMinimumTime(pindexPrev, DifficultyAdjustmentInterval())`. |
| 10 | nVersion / BIP-9 version-rolling | G25: `compute_block_version` ORs STARTED/LOCKED_IN bits onto `0x20000000` | PASS (`versionbits.erl:657-668`, miner uses it at `miner.erl:222`) |
| 11 | coinbase scriptSig length 2..100 | G26: enforced at template construction | PASS — height + 8-byte extra nonce = 9..14 bytes for realistic heights; floor 2 satisfied because extra nonce always ≥ 8 bytes; checked at `validation.erl:344` for connect-block but template builder doesn't repeat it |
| 12 | coinbase BIP-34 height encoding | G27: encode as `OP_1..OP_16` for h∈{1..16} (Core's `CScript() << nHeight`) | **BUG-7 (P2)** — `miner.erl:920-921` emits `<<1, Height:8>>` (2-byte push) for h∈{1..16}; Core's `CScript::push_int64` (script.h:433-442) emits `OP_1..OP_16` (single byte 0x51..0x60). Both decode to the same CScriptNum value via `CScriptNum(scriptSig, false, 5)`, but block fingerprint differs; non-canonical encoding for heights ≤ 16 |
| 12 | … | G28: encode as minimal LE for h ≥ 17 with explicit sign byte | PASS (`miner.erl:927-938`) |
| 13 | sigops budget (block + per-tx) | G29: `MAX_BLOCK_SIGOPS_COST = 80_000` enforced | PASS (`miner.erl:619`, `protocol.hrl:10`) |
| 13 | … | G30: `GetTransactionSigOpCost(tx, view, flags)` = legacy×4 + P2SH×4 + witness sigops | **BUG-8 (P0-CDIV)** — miner's `estimate_sigops/1` (`miner.erl:777-784`) ONLY counts legacy sigops in `script_sig` + `script_pubkey` and multiplies by WITNESS_SCALE_FACTOR. Does NOT add P2SH redeemScript sigops (requires the input coin's prevout scriptPubKey) and does NOT add witness sigops. A P2SH-heavy / segwit-heavy mempool can produce templates that, when filled, violate `MAX_BLOCK_SIGOPS_COST`; submit fails or peer relay rejects. The cost-correct helper `get_tx_sigop_cost/3` EXISTS at `validation.erl:924-940` and is used by `connect_block` — but the miner's selection path uses the wrong helper. Two-pipeline drift inside this impl |
| 14 | generateblock pays subsidy+fees | G31: coinbase value = subsidy + sum(tx_fees) | PARTIAL — `do_generate_block_with_txs` at `miner.erl:1010-1014` ALWAYS sets `TotalFees = 0` (loop body returns the accumulator unchanged) with comment `"In a real impl, would compute fee from inputs-outputs / For generateblock, caller is responsible for valid txs"`. Carry-forward from **W145 BUG-6 — STILL OPEN**. Note: Core's `generateblock` ALSO uses `use_mempool=false` and the coinbase pays only subsidy, then appends txs; `RegenerateCommitments` re-merkles but does NOT bump coinbase value. So behaviour matches Core (miner forfeits the fees). Severity downgraded to P2 (comment-as-confession; behaviour is parity) |
| 14 | … | G32: `RegenerateCommitments` helper exists to re-sync witness commitment + merkle root after caller-side tx mutation | **BUG-9 (P1)** — beamchain has no `regenerate_commitments` / `update_witness_commitment` helper. Pool software using BIP-23 proposal mode or appending txs to a returned template cannot resync the commitment without rebuilding the whole template. Core: `node/miner.cpp:67-77` |

---

## BUG-1 (P1) — `DEFAULT_BLOCK_MAX_WEIGHT` and `-blockmaxweight` operator knob absent

**Severity:** P1. Bitcoin Core's `BlockAssembler::Options.nBlockMaxWeight`
defaults to `DEFAULT_BLOCK_MAX_WEIGHT = MAX_BLOCK_WEIGHT = 4_000_000`
(`policy/policy.h:25`) and is overridable via `-blockmaxweight=N`
(`miner.cpp:101`). Pools commonly cap templates well below 4 MWU to
reduce orphan risk and to leave room for compact-block propagation.

beamchain hard-codes `MaxWeight = ?MAX_BLOCK_WEIGHT - ?DEFAULT_BLOCK_RESERVED_WEIGHT`
(`miner.erl:615`). There is no `?DEFAULT_BLOCK_MAX_WEIGHT` constant,
no config-file knob in `beamchain_config.erl`, and no CLI flag wired
through `do_create_template/3`'s second-arg `Opts` map (the `Opts`
parameter is accepted but ignored; only the public `coinbasescript`
field of the GBT request is consulted).

**File:** `src/beamchain_miner.erl:90-91, 183-184, 615`.

**Core ref:** `bitcoin-core/src/node/miner.h:83`,
`bitcoin-core/src/node/miner.cpp:101`,
`bitcoin-core/src/policy/policy.h:25`.

**Impact:** operators cannot tune template size for orphan-risk
management; mining-pool deployments that rely on `-blockmaxweight=3500000`
(a common conservative cap) cannot use beamchain as a back-end.
Cross-impl divergence: every other hashhog impl exposes a block-max-weight
knob.

---

## BUG-2 (P1) — `-blockreservedweight`, `-blockmintxfee`, `MINIMUM_BLOCK_RESERVED_WEIGHT` operator-knobs absent

**Severity:** P1. Core (`miner.cpp:101-108`) wires three CLI flags:
- `-blockmaxweight=N` (covered in BUG-1)
- `-blockmintxfee=<amount>` (parses to `blockMinFeeRate`)
- `-blockreservedweight=N` (clamped via `ClampOptions` to
  `[MINIMUM_BLOCK_RESERVED_WEIGHT=2000, MAX_BLOCK_WEIGHT]`)

beamchain hard-codes all three:
- `?DEFAULT_BLOCK_RESERVED_WEIGHT = 8000` (`miner.erl:36`)
- `?DEFAULT_BLOCK_MIN_TX_FEE_SAT_KVBYTE = 1` (`miner.erl:53`)
- `?DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS = 400` (`miner.erl:42`)

There is no `MINIMUM_BLOCK_RESERVED_WEIGHT = 2000` floor anywhere in
the codebase. If a future operator-knob landed without the floor, a
user could pass `-blockreservedweight=0` and produce a block whose
header + tx-count varint + coinbase wouldn't fit. Cross-cite Core's
`policy.h:34`.

**File:** `src/beamchain_miner.erl:36, 42, 53`;
`src/beamchain_config.erl` (no flags).

**Core ref:** `bitcoin-core/src/node/miner.cpp:79-88, 98-109`;
`bitcoin-core/src/policy/policy.h:25-34`.

**Impact:** mining-pool ergonomics (cannot set per-deployment fee
floors or coinbase-script sigop budgets via config); silent absence of
the 2000-WU floor means future plumbing must reproduce the safety
check rather than rely on a shared constant.

---

## BUG-3 (P0-CDIV) — Single-tx-then-pull-parents diverges from chunk-feerate selection; child-with-low-own-fee gets in based on own fee, not package fee

**Severity:** P0-CDIV (divergence in block contents; mining-quality
regression that can produce templates a competing miner would beat).
Bitcoin Core's `addChunks` (`miner.cpp:279-334`) consumes "chunks" via
`m_mempool->GetBlockBuilderChunk(selected_transactions)` where each
chunk is a topologically-ordered package of txs that the cluster-mempool
has pre-computed should be evaluated together at the chunk's package
fee rate. The chunk's `chunk_feerate` is the package fee rate, applied
to the entire group when checking against `blockMinFeeRate` and against
`TestChunkBlockLimits`.

beamchain's `greedy_select/11` (`miner.erl:666-746`) iterates one
mempool entry at a time, runs `resolve_parents/2` (`miner.erl:749-773`)
to pull in any unselected mempool parents transitively, and then
checks the COMBINED weight + sigops against the block limits. But:

1. The `blockMinFeeRate` check at line 689 is against the **selected
   entry's OWN fee rate** (`FeeRateSatKvb = Entry.fee * 1000 / VSize`),
   NOT the ancestor-fee-rate. So a tx whose own fee is below 1
   sat/kvB but whose ancestor-fee-rate (parent-CPFP-pull) is much
   higher will be SKIPPED at line 690-694 even though Core would
   evaluate it as part of the parent's chunk and admit it.

2. Conversely, a child tx whose own fee rate is high but whose
   parent's fee rate is low will appear early in the
   `ancestor_fee_rate/1`-sorted list (`miner.erl:608-610`); when
   selected, `resolve_parents` pulls in the low-fee parent for free.
   The parent's individual fee-rate check is never run because it's
   admitted as a dependency, not as a primary candidate. Core's
   chunk-feerate model would compute the package fee rate as
   `(child.fee + parent.fee) / (child.weight + parent.weight)` and
   compare THAT against `blockMinFeeRate` — same outcome here, but
   reached differently.

The end-state divergence: for mempools with chains-of-three or
deeper, where the middle tx has very low fee, beamchain's child-pulls-grandparent
path will admit the parent regardless of fee floor; Core's chunk
selection groups by cluster ID and either admits or skips the whole
cluster atomically.

**File:** `src/beamchain_miner.erl:601-628, 666-746, 749-773`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:279-334` (chunk-based
`addChunks`), `bitcoin-core/src/policy/policy.h::FeePerWeight`.

**Impact:** block templates have different tx ordering / inclusion vs
Core for non-trivial mempool topologies. A pool running beamchain will
produce templates with slightly different fee-extraction; the absolute
delta is small at typical mempool depths, but at >100 ktx mempool
fingerprints diverge enough to be observable via comparing
`getblocktemplate` against `bitcoind`'s on the same mempool.

---

## BUG-4 (P1) — Witness commitment gated on `HasWitnessTx`; Core adds unconditionally when SegWit is active

**Severity:** P1. Bitcoin Core's `BlockAssembler::CreateNewBlock`
calls `m_chainstate.m_chainman.GenerateCoinbaseCommitment(*pblock,
pindexPrev)` UNCONDITIONALLY at `miner.cpp:200`. The commitment is
the SHA256d of `witness_root || 32-zero-nonce`. For a legacy-only block
(no witness txs), the witness merkle root is computed from `[32-zero
coinbase-wtxid]` only, which produces a deterministic non-zero
commitment value. Core adds the commitment output anyway, which keeps
the block structure consistent.

beamchain's `build_coinbase/5` (`miner.erl:845-894`) gates on
`HasWitnessTx`:

```erlang
witness = case HasWitnessTx of
    true -> [<<0:256>>];   %% witness nonce: 32 zero bytes
    false -> []
end,
...
Outputs = case HasWitnessTx of
    true -> [PayoutOutput, CommitOutput];
    false -> [PayoutOutput]
end,
```

A SegWit-active mainnet block containing ONLY legacy txs (e.g., a
miner that filters witness txs from its mempool, or an empty block
post-tip) will have NO witness commitment and NO coinbase witness
nonce on beamchain, while Core would still emit both. Per
`CheckWitnessMalleation` (`validation.cpp:3870-3899`), the absence of
a commitment is tolerated post-activation (the function only validates
the existing commitment if present), so this is not consensus-breaking
— but block-fingerprint divergence affects compact-block reconstruction
and miner-attribution scrapers.

**File:** `src/beamchain_miner.erl:329-345, 860-864, 873-880,
1088-1092, 1099-1105`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:200`,
`bitcoin-core/src/validation.cpp:3997-4019`.

**Impact:** block-fingerprint divergence between beamchain and Core for
legacy-only blocks in SegWit-active networks. Compact-block (BIP-152)
shortid reconstruction is robust to coinbase variation, so no relay
break, but cross-impl block diff tools (consensus-diff harness) will
flag the difference.

---

## BUG-5 (P1) — `compute_merkle_root` has no CVE-2012-2459 mutated-pair detection at the miner level

**Severity:** P1 (fleet pattern, 7th distinct hashhog instance per
W142+W143 tracking — 6+ of 10 impls confirmed missing this). Bitcoin
Core's `ComputeMerkleRoot` (`consensus/merkle.cpp:46-`) takes a
`mutated*` out-parameter and sets it true when ANY level of the merkle
tree has an unpaired entry whose duplication would produce a hash
collision (`if (i + 1 == hashes.size()) ... mutated`). The check
guards CVE-2012-2459: a duplicate-pair forgery produces the same root
as a non-duplicated tree, enabling a transaction-malleability
side-channel.

beamchain's `merkle_pairs/1` (`serialize.erl:215-221`) blindly
duplicates the odd entry without any mutation detection:

```erlang
merkle_pairs([A]) ->
    %% odd element: duplicate it
    [hash256(<<A/binary, A/binary>>)];
```

`compute_merkle_root/1` returns only the root — no mutation flag, no
caller-visible signal. The `check_merkle_malleation/1` helper at
`validation.erl:151` does run during `check_block`, but the miner's
template-construction path at `miner.erl:248-249` does NOT call it.

Pools that mutate the tx list and resubmit a template via `submit_block`
would have the mutation caught at submit time (via `check_block` →
`check_merkle_malleation`), so this is a defense-in-depth gap rather
than a consensus break. But miners running custom code paths that
bypass `check_block` (e.g., direct chainstate `connect_block` from
generated blocks) could feed mutated trees into the chainstate.

**File:** `src/beamchain_serialize.erl:215-221`;
`src/beamchain_miner.erl:248-249` (no malleation check at template build).

**Core ref:** `bitcoin-core/src/consensus/merkle.cpp:46-` (`mutated*`
out-param), `bitcoin-core/src/validation.cpp::IsBlockMutated`.

**Impact:** defense-in-depth gap; cross-cite fleet pattern.

---

## BUG-6 (P0-CDIV) — GBT `mintime` field emitted as raw `MTP+1`; BIP-94 timewarp not applied to the exposed value

**Severity:** P0-CDIV. Bitcoin Core's `getblocktemplate`
(`rpc/mining.cpp:1004`) emits:

```cpp
result.pushKV("mintime", GetMinimumTime(pindexPrev, consensusParams.DifficultyAdjustmentInterval()));
```

`GetMinimumTime` (`miner.cpp:36-47`) returns
`max(MTP+1, [boundary] prev_block_time - MAX_TIMEWARP)`. The RPC
documentation explicitly states "Adjusted for the proposed BIP94
timewarp rule" (`rpc/mining.cpp:687`).

beamchain's template at `miner.erl:312` emits:

```erlang
<<"mintime">> => MTP + 1,
```

The BIP-94 boundary check IS computed at `miner.erl:202` as
`MinTime = compute_minimum_time(MTP, PrevBlockTime, Height)`, and IS
used at line 253 for the in-memory `Timestamp` field set on
`_header`. But the GBT-exposed `mintime` key remains the raw MTP+1.

Failure mode: a mining pool that respects the GBT `mintime` will mine
at `MTP+1` at a difficulty-adjustment boundary. If
`prev_block_time - MAX_TIMEWARP > MTP+1` at that height, the produced
block has `nTime < prev_block_time - MAX_TIMEWARP` and is rejected by
Core peers (`time-timewarp-attack`, `consensus/consensus.h:35`).

Note: in practice `MTP <= prev_block_time` (MTP is the median of the
last 11 block timestamps including the previous), so `MTP+1` is
typically close to `prev_block_time`. The 600-second window means the
miner-pool would have to be reasonably out-of-sync to actually fall
foul, but a miner that submits a `mintime` template back to Core for
proposal validation will get rejected.

**Two-pipeline guard:** the SAME impl computes BIP-94-correct MinTime
internally (line 202, 253) and emits the BIP-94-incorrect MinTime
externally (line 312). 16th distinct fleet instance of the two-pipeline
guard pattern.

**File:** `src/beamchain_miner.erl:202, 253, 312`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1004,
bitcoin-core/src/node/miner.cpp:36-47`,
`bitcoin-core/src/consensus/consensus.h:35`.

**Impact:** mining-pool BIP-94 compliance: pools that respect the
template's `mintime` (most do) will produce invalid blocks at
difficulty-adjustment boundaries when wall-clock is close to the
timewarp ceiling. The actual block produced internally by
`do_generate_blocks_loop` uses the correct value, so regtest
generation is fine — but external pools driven by GBT are at risk.

---

## BUG-7 (P2) — BIP-34 height encoding for h ∈ {1..16} uses 2-byte length-prefixed push, not OP_1..OP_16

**Severity:** P2 (non-canonical encoding; CScriptNum decoding agrees,
so consensus is unaffected). Bitcoin Core's `CScript() << nHeight`
(`script.h:433-442`) handles `n ∈ {-1, 1..16}` by emitting a single
byte `OP_1..OP_16` (`0x51..0x60`). beamchain's `encode_coinbase_height`
(`miner.erl:920-921`):

```erlang
encode_coinbase_height(Height) when Height >= 1, Height =< 16 ->
    <<1, Height:8>>;
```

This emits `0x01 0xHH` (2 bytes: push 1 byte, value Height), not
`OP_HH` (1 byte: 0x51..0x60). The BIP-34 verifier reads the value via
`CScriptNum(scriptSig, /*fRequireMinimal=*/false, /*nMaxNumSize=*/5)`
which decodes both forms to the same number — so consensus passes —
but the block fingerprint differs from Core's.

Regtest impact: tests that hard-code the BIP-34 scriptSig prefix for
heights 1..16 (e.g., comparison against a Core-produced block) will
fail with byte-level mismatch.

**File:** `src/beamchain_miner.erl:918-925`.

**Core ref:** `bitcoin-core/src/script/script.h:433-442`.

**Impact:** block-fingerprint divergence at heights 1..16; non-canonical
encoding. Pre-BIP-34 mainnet heights (227,835 and below) don't enforce
height encoding at all, so this only matters on regtest / signet where
miners may start at h ≤ 16.

---

## BUG-8 (P0-CDIV) — `estimate_sigops/1` undercounts: legacy-only ×4, missing P2SH and witness sigops; two-pipeline drift with `get_tx_sigop_cost/3`

**Severity:** P0-CDIV. Bitcoin Core's `GetTransactionSigOpCost(tx,
inputs, flags)` (`consensus/tx_verify.cpp:143-164`) computes:

```cpp
nSigOps  = GetLegacySigOpCount(tx) * WITNESS_SCALE_FACTOR;
if (!IsCoinBase()) {
    if (flags & SCRIPT_VERIFY_P2SH)
        nSigOps += GetP2SHSigOpCount(tx, inputs) * WITNESS_SCALE_FACTOR;
    for each input:
        nSigOps += CountWitnessSigOps(...);
}
```

beamchain's miner-side `estimate_sigops/1` (`miner.erl:777-784`):

```erlang
estimate_sigops(#transaction{inputs = Inputs, outputs = Outputs}) ->
    InSigops  = lists:foldl(fun(#tx_in{script_sig = S}, Acc) ->
        Acc + beamchain_validation:count_legacy_sigops(S)
    end, 0, Inputs),
    OutSigops = lists:foldl(fun(#tx_out{script_pubkey = S}, Acc) ->
        Acc + beamchain_validation:count_legacy_sigops(S)
    end, 0, Outputs),
    (InSigops + OutSigops) * ?WITNESS_SCALE_FACTOR.
```

This counts only the legacy sigops in `script_sig` and `script_pubkey`
(no P2SH redeemScript walk, no witness sigops). It is then multiplied
by `WITNESS_SCALE_FACTOR=4` to match Core's "cost" units.

**Result:** the miner's per-tx sigop estimate is a strict LOWER BOUND
on the consensus cost. For a P2SH-multisig spend, the actual sigop
count comes from CHECKMULTISIG within the redeemScript (pushed in
script_sig); `count_legacy_sigops(S)` would count just the push opcode,
not the redeemScript contents. For P2WSH witness scripts, the actual
sigops live in the witness stack, which `estimate_sigops` doesn't touch.

**Concrete failure mode:** a mempool full of P2SH-multisig spends. The
miner's `select_transactions` greedy fills the block to
`MAX_BLOCK_SIGOPS_COST - 400 = 79,600` "estimated" sigops. The actual
consensus sigop count (computed by `check_block` via
`count_legacy_sigops_tx`, line 158-163 — STILL underbounded — and by
`connect_block` via `get_tx_sigop_cost`, line 1222) could exceed
`MAX_BLOCK_SIGOPS_COST`. submit then fails with `bad-blk-sigops`,
and Core peers also reject.

**Two-pipeline drift:** the cost-correct helper `get_tx_sigop_cost/3`
EXISTS at `validation.erl:924-940` (used by connect_block at line 1222).
The miner has access to UTXOs via `beamchain_chainstate`, so it
COULD invoke `get_tx_sigop_cost(Tx, InputCoins, Flags)` per entry —
but uses `estimate_sigops` instead. Same impl, two divergent sigop
pipelines. 17th distinct fleet instance of the two-pipeline guard.

Cross-cite: `validation.erl:158-163`'s `check_block` ALSO uses the
legacy-only `count_legacy_sigops_tx` (no P2SH/witness). That means a
beamchain miner could PRODUCE an over-sigop block, locally pass
`check_block`, fail `connect_block`'s `get_tx_sigop_cost` check, and
end up in an inconsistent state. This is a P0 because the same gap
exists at `check_block` (where it's a consensus check, not just a
miner estimate).

**File:** `src/beamchain_miner.erl:777-784`;
`src/beamchain_validation.erl:158-163` (cross-cite);
`src/beamchain_validation.erl:924-940` (cost-correct helper present
but not used by miner).

**Core ref:** `bitcoin-core/src/consensus/tx_verify.cpp:112-164`.

**Impact:** miner produces over-sigop templates for P2SH-/segwit-heavy
mempools; submit/relay rejects; pool wastes effort on invalid
templates.

---

## BUG-9 (P1) — `RegenerateCommitments` analogue absent; pools cannot resync after caller-side tx mutation

**Severity:** P1. Bitcoin Core's `RegenerateCommitments(CBlock&,
ChainstateManager&)` (`node/miner.cpp:67-77`) is the canonical helper
for "I mutated the tx list after `CreateNewBlock`, please re-sync the
witness commitment and merkle root." It is called from
`generateblock` (`rpc/mining.cpp:390`), from `MaybeRegenerateCommitments`
in the kernel mining interface, and from BIP-23 proposal-mode
validation.

beamchain has no such helper. The only paths that produce a block
post-mutation are:
- `do_generate_block_with_txs` (`miner.erl:993-1075`) — builds the
  coinbase OVER the supplied Txs, so commitments are correct.
- `do_submit_block` (`miner.erl:512-578`) — accepts whole pre-built
  blocks; no mutation API.

A pool that wants to: (a) call `getblocktemplate`, (b) prepend its
own coinbase variant, (c) recompute merkle root + witness commitment,
(d) submit via `submitblock` — must reimplement the commitment math
from scratch. Core gives them `RegenerateCommitments`. beamchain
gives them nothing.

**File:** `src/beamchain_miner.erl` (no helper);
`src/beamchain_serialize.erl:223-227` (`compute_witness_commitment`
exists but operates on wtxids, not on a block struct).

**Core ref:** `bitcoin-core/src/node/miner.cpp:67-77`.

**Impact:** mining-pool integration friction; pools must vendor the
commitment-computation code themselves to do proposal-mode validation.

---

## BUG-10 (P1) — `mintime` field uses MTP+1 inside template but `_header` uses BIP-94-correct min; subtle clock-driven divergence

**Severity:** P1 ("two-pipeline guard" subtype — adjacent values in
the SAME data structure use different min-time computations).
`miner.erl:319` emits `<<"curtime">> => Timestamp` where `Timestamp =
max(MinTime, Now)` (line 253) and `MinTime` is BIP-94-correct.
`miner.erl:312` emits `<<"mintime">> => MTP + 1` (BIP-94-incorrect,
per BUG-6).

The `_header` field at line 323 carries a struct with `timestamp =
Timestamp` (line 260) — so the BIP-94-correct value. A pool that
mines off the `_header` directly is safe; a pool that uses the
public BIP-22 `mintime` is at risk. Same template, two min-time
values.

**File:** `src/beamchain_miner.erl:202, 253, 260, 312, 319, 323`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:994-1004` (mintime +
curtime both derive from `GetMinimumTime`).

**Impact:** subset of BUG-6; recorded separately because the
within-structure inconsistency is a code-smell beyond the
external-API gap.

---

## BUG-11 (P2) — `submit_block/1` returns `{error, inconclusive}` for valid side-branch acceptance; semantic mismatch with `{ok, _}`

**Severity:** P2 (semantic confusion, not a behaviour bug). `do_submit_block`
at `miner.erl:551-564`:

```erlang
{ok, side_branch} ->
    %% Block stored as side-branch — no tip flip,
    %% no mempool churn, no broadcast.  Surface as
    %% BIP-22 "inconclusive" via the rpc_submitblock
    %% layer.
    BlockHash = beamchain_serialize:block_hash(Header),
    logger:info("miner: stored block ~s "
                "as side-branch (inconclusive)",
                [short_hex(BlockHash)]),
    {error, inconclusive};
```

This returns `{error, inconclusive}` to the caller, even though a
side-branch acceptance is BIP-22 success (BIP-22 result strings
include `"inconclusive"` as a non-rejection outcome — see
`rpc/mining.cpp::SubmitBlock`). Callers that pattern-match `{ok, _}`
treat this as failure.

The RPC layer at `beamchain_rpc.erl:3820-3830` correctly maps the
`{error, inconclusive}` to BIP-22 `<<"inconclusive">>` via
`bip22_result/1`, so the end-user RPC response is correct. But any
Erlang caller of `beamchain_miner:submit_block/1` would mishandle the
result.

**File:** `src/beamchain_miner.erl:551-564`;
`src/beamchain_utxo_repair.erl:234` (caller — `case ... of ok -> ...`).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp::SubmitBlock` —
BIP-22 success codes include "inconclusive" as a non-error result.

**Impact:** internal API semantic confusion; `utxo_repair`'s submit
path would treat side-branch acceptance as a failure to retry. Worth
flagging as `{ok, side_branch}` or `{ok, inconclusive}` instead.

---

## BUG-12 (P1) — `tip_hash`, `template`, `_coinbase_tx`, `_total_weight`, `_total_sigops` are dead-data plumbing

**Severity:** P1 (dead-data plumbing fleet pattern; 5 instances in one
module).

1. `#state{template, tip_hash}` (`miner.erl:72-73`) — `template` is
   set in `do_create_template` (line 347) and invalidated on submit
   (140, 150, 161), but NEVER read. There's no template-cache lookup
   on subsequent `create_template` requests (every call rebuilds from
   scratch). `tip_hash` is also set but only used (line 347) as the
   value passed back into State — never compared. If the intent was
   "fast-path: serve cached template when tip hasn't changed",
   that logic is missing.

2. `<<"_coinbase_tx">>`, `<<"_total_weight">>`, `<<"_total_sigops">>`
   (`miner.erl:324-327`) — set into the template map, but a grep over
   `src/` shows the only readers of internal `_*` fields are
   `<<"_header">>` and `<<"_all_txs">>` (at `miner.erl:968-969`,
   inside `do_generate_one_block`). The other three are write-only.

**File:** `src/beamchain_miner.erl:72-73, 139-143, 150, 161, 324-327, 347, 968-969`.

**Impact:** code-hygiene; `template` field is the only one that
suggests an intended (but unimplemented) longpoll/template-cache
optimisation. Either implement the cache or remove the dead state.

---

## BUG-13 (P1) — `do_generate_block_with_txs` does NOT call `IsFinalTx` or check duplicate-txid on supplied txs

**Severity:** P1. `do_generate_block_with_txs` (`miner.erl:993-1075`)
accepts a tx list from the caller, builds the coinbase that includes
the witness commitment over those txs, computes merkle root, mines,
and submits. It does NOT iterate the txs to check `IsFinalTx(Tx,
Height, LockTimeCutoff)`, does NOT check for duplicate txids, does
NOT verify sigops.

The downstream `do_submit_block` runs `check_block` which DOES check
duplicates, sigops, and (via `contextual_check_block`) IsFinalTx. So
the block is rejected at submit time. But the miner wastes effort
mining a doomed block first.

Core's `generateblock` does the same prebuild then `TestBlockValidity`
(`rpc/mining.cpp:392`) BEFORE mining, so the rejection happens
synchronously without burning the mine loop. beamchain mines first
then rejects.

**File:** `src/beamchain_miner.erl:993-1075` (no validity check
between block assembly and `mine_block`).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:392` (TestBlockValidity
before GenerateBlock).

**Impact:** regtest performance / clarity; a malformed `generateblock`
RPC call wastes a mining loop before erroring out.

---

## BUG-14 (P1) — `select_transactions`'s `ancestor_fee_rate` denominator approximates `ancestor_weight` as `ancestor_size × 4` with admitted off-by-1-to-3 error

**Severity:** P1 (acknowledged simplification; ranking jitter at the
sort boundary). `ancestor_fee_rate/1` (`miner.erl:633-644`):

```erlang
ancestor_fee_rate(Entry) ->
    AncFee = Entry#mempool_entry.ancestor_fee,
    AncWeight = Entry#mempool_entry.ancestor_size * ?WITNESS_SCALE_FACTOR,
    case AncWeight of
        0 -> Entry.fee / max(1, Entry.weight);
        _ -> AncFee / AncWeight
    end.
```

`ancestor_size` is the vsize sum; multiplying by 4 gives approximately
the weight sum, off by 0..3 per tx because `vsize = ceil(weight/4)`.
For an ancestor set of N txs, the rounding error compounds to up to
`3*N` WU. For sorting purposes this is usually negligible, but
borderline entries can flip order vs Core. Comment at line 637-639
already admits this.

The fix is to track `ancestor_weight` separately in `#mempool_entry{}`
(currently only `ancestor_size` exists, see `mempool.erl:139`).

**File:** `src/beamchain_miner.erl:633-644`;
`src/beamchain_mempool.erl:139` (no `ancestor_weight` field).

**Core ref:** `bitcoin-core/src/policy/feerate.h::FeePerWeight` (uses
exact weight).

**Impact:** marginal block-quality ranking jitter; same-cluster txs
may be sorted slightly differently than Core. Acknowledged in source.

---

## BUG-15 (P1) — `getblocktemplate` accepts non-standard `coinbasescript` request field; pools using BIP-23 `coinbase/payload` won't work

**Severity:** P1. `rpc_getblocktemplate` at `beamchain_rpc.erl:3722-3726`:

```erlang
rpc_getblocktemplate([TemplateRequest]) when is_map(TemplateRequest) ->
    DefaultScript = <<16#51>>,
    CoinbaseScript = maps:get(<<"coinbasescript">>, TemplateRequest,
                               DefaultScript),
```

`coinbasescript` is a NON-STANDARD BIP-22 field. Core's `getblocktemplate`
does NOT accept a coinbase script from the request; it always builds a
dummy / placeholder coinbase whose scriptPubKey the miner is expected
to replace post-template (the BIP-22 `transactions[0]` slot is reserved
for "the miner's coinbase" with `<<"data">>` being a hex of the dummy).

The default `<<16#51>>` (OP_TRUE) is the regtest mining script. On
mainnet, pool software that does NOT pass `coinbasescript` will get
OP_TRUE coinbases — funds permanently locked in an anyone-can-spend
script. A pool integrator unaware of this beamchain-specific behaviour
risks losing the block reward.

Core mining-pool software does not know to set `coinbasescript`; it
expects the BIP-22 contract where the miner constructs their own
coinbase. beamchain's design forces pools to pre-supply the coinbase
script via a non-standard knob.

**File:** `src/beamchain_rpc.erl:3722-3727`;
`src/beamchain_miner.erl:90-91` (API takes `CoinbaseScriptPubKey`
as a required argument).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:730-879` (no
`coinbasescript` field).

**Impact:** mining-pool integration; default OP_TRUE on mainnet =
anyone-can-spend coinbase = pool loses block reward. Cross-impl
divergence in BIP-22 wire-protocol.

---

## BUG-16 (P1) — No `TestBlockValidity` post-template construction

**Severity:** P1. Bitcoin Core's `BlockAssembler::CreateNewBlock` ends
with (at `miner.cpp:223-228`):

```cpp
if (m_options.test_block_validity) {
    if (BlockValidationState state{TestBlockValidity(m_chainstate, *pblock, /*check_pow=*/false, /*check_merkle_root=*/false)}; !state.IsValid()) {
        throw std::runtime_error(strprintf("TestBlockValidity failed: %s", state.ToString()));
    }
}
```

This is the post-template sanity check that catches bad-cb-amount,
bad-blk-sigops, dup-input, BIP-30, and other consensus issues BEFORE
the template is returned to the pool. Default `test_block_validity =
true`.

beamchain's `do_create_template/3` does NOT call any equivalent. The
template is returned without validation. If `estimate_sigops` undercounts
(BUG-8) and the actual block would violate `MAX_BLOCK_SIGOPS_COST`, the
pool only finds out on `submitblock`.

**File:** `src/beamchain_miner.erl:128-134, 183-352` (no `check_block`
call before returning the template).

**Core ref:** `bitcoin-core/src/node/miner.cpp:223-228`.

**Impact:** pools get malformed templates from beamchain that fail at
submit time; debugging tools harder; cross-cite BUG-8 (sigops undercount
+ no post-validity check = silent over-sigop templates).

---

## BUG-17 (P1) — No `MAX_FUTURE_BLOCK_TIME = 2h` clamp on emitted `curtime`

**Severity:** P1 (clock-drift defense). Bitcoin Core's `UpdateTime`
sets `pblock->nTime = max(GetMinimumTime(...), TicksSinceEpoch(NodeClock::now()))`;
`CheckBlockHeader` later rejects blocks with `timestamp > Now + 2h`
(`MAX_FUTURE_BLOCK_TIME`, `chain.h:29`). The miner does not preemptively
clamp.

beamchain similarly sets `Timestamp = max(MinTime, Now)` (`miner.erl:253`).
A miner with a 3-hour-fast clock would emit a template with
`curtime = Now > true_now + 2h`, which propagates through the
template to the produced block, gets caught at `check_block_header`
(`validation.erl:80-82`).

This is parity with Core (both clamp at validation time, not at
miner output). But neither emits a warning to the pool that its
own clock might be off. Worth noting.

**File:** `src/beamchain_miner.erl:253`.

**Core ref:** `bitcoin-core/src/chain.h:29`.

**Impact:** none on its own (validation catches it); flagged for
completeness against the wave checklist.

---

## BUG-18 (P1) — `do_generate_one_block` is regtest-only but lacks `network == regtest` guard at internal entry point

**Severity:** P1 (defensive). `do_generate_one_block` and
`do_generate_block_with_txs` are gated on `State.network == regtest`
at the gen_server `handle_call` boundary (`miner.erl:147-165`). The
RPC layer also gates at `beamchain_rpc.erl:3848, 3886` etc. But the
internal `do_*` helpers themselves don't check. A future code path
that calls them directly (e.g., a maintenance tool that grew into the
miner module) could mine on mainnet.

Defense-in-depth would have the `do_generate_*` helpers themselves
assert regtest.

**File:** `src/beamchain_miner.erl:950-990, 993-1075`.

**Impact:** future-proofing only; current call graph is regtest-safe.

---

## BUG-19 (P2) — `mine_block_loop` does NOT increment extra-nonce on nonce exhaustion; regtest-only impact

**Severity:** P2. `mine_block_loop` (`miner.erl:1131-1149`) iterates
the header nonce 0..0xFFFFFFFF and returns `nonce_exhausted` when
exhausted. Real-world miners roll the coinbase extra-nonce (the 8-byte
field at `miner.erl:850, 1081`) when the header nonce space is
exhausted, then re-hash the merkle root and continue. beamchain's
internal mine_block doesn't do this — it just fails.

This affects only regtest where `pow_limit` is near-maximum; nonce=0
typically succeeds. On a real network with real difficulty, the
internal `generate*` RPCs are not used (Core also limits them to
regtest), so this is a regtest-only ergonomics issue.

**File:** `src/beamchain_miner.erl:1131-1149`.

**Impact:** regtest only; theoretical, would never trigger in practice
on regtest.

---

## BUG-20 (P1) — Per-tx `sigops` field in `transactions[]` GBT entries reports `estimate_sigops` (undercount per BUG-8)

**Severity:** P1 (cross-cite BUG-8 to the BIP-22 wire surface).
`format_tx_entries/4` (`miner.erl:457-486`) emits per-tx fields
including `<<"sigops">> => estimate_sigops(Tx)` (line 480). Pool
software relying on the per-tx `sigops` field for its own packing
math gets the same undercount as the miner's internal estimate. Pool
that builds its own template (e.g., by transaction filtering or
prioritisation) may pack until the SUM of reported per-tx sigops hits
`sigoplimit=80000`, end up overflowing the real consensus sigop cost,
and produce an invalid block.

**File:** `src/beamchain_miner.erl:480`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp::getblocktemplate`
emits `tx.GetSigOpCost()` (the cost-correct value via
`GetTransactionSigOpCost`).

**Impact:** subset of BUG-8 surfaced at the BIP-22 wire boundary;
pool integrators see the undercount.

---

## BUG-21 (P1) — `longpollid` uses `tip_hex + mempool_size`; not invalidated on prioritisation / package-feerate change

**Severity:** P1 (longpoll under-invalidation). `do_create_template`
at `miner.erl:289-292`:

```erlang
MempoolInfo = beamchain_mempool:get_info(),
MempoolCount = maps:get(size, MempoolInfo, 0),
LongPollId = <<(hash_to_hex(TipHash))/binary,
               (integer_to_binary(MempoolCount))/binary>>,
```

Bitcoin Core's longpollid is `tip.GetHex() + ToString(nTransactionsUpdatedLast)`,
where `nTransactionsUpdatedLast` increments on every mempool add/remove
AND on RBF / prioritisation. beamchain uses raw `mempool.size`, which
only changes on net add/remove. A prioritisation event (e.g.,
`prioritisetransaction` adjusting fees, if it were implemented) would
NOT change the longpollid.

Currently `prioritisetransaction` is NOT implemented (W123 G-class),
so the actual divergence in practice is zero. But the longpollid
shape diverges from Core's, and the cross-impl long-poll cycle has
different sensitivity.

**File:** `src/beamchain_miner.erl:289-292`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp::getblocktemplate`
(`longpollid` construction).

**Impact:** longpoll under-invalidation; benign today, brittle
against future `prioritisetransaction` addition.

---

## BUG-22 (P1) — `do_create_template` re-runs full mempool selection on every call; no template caching despite `template` state field

**Severity:** P1 (cross-cite BUG-12). The miner state holds
`#state{template, tip_hash}` ostensibly for caching, but
`do_create_template` always re-runs `select_transactions`, recomputes
the coinbase, recomputes the merkle root, etc., on every
`create_template` call. There is no fast path that returns the
existing `State#state.template` when:
- `TipHash == State#state.tip_hash` (no new tip), AND
- mempool unchanged since last build, AND
- elapsed time < some threshold.

Core's `getblocktemplate` does the same expensive rebuild per call by
default, but its `BlockAssembler` lifetime is per-request and the
mining-interface `waitNext` API caches transparently. beamchain has
no analogue.

**File:** `src/beamchain_miner.erl:128-134, 183-352`.

**Impact:** O(mempool-size) per `getblocktemplate` call; pools that
poll at 1 Hz on a 100k-tx mempool burn O(100k) sorts per second.
Cross-cite BUG-12 (dead-data plumbing — the `template` field is set
but never read on fast-path).

---

## BUG-23 (P2) — `do_generate_blocks_loop` holds the miner gen_server hostage for `N * 60s` synchronous mining

**Severity:** P2 (responsiveness). `generate_blocks` at `miner.erl:103-104`
calls `gen_server:call(?SERVER, {generate_blocks, ...}, NumBlocks *
60000 + 30000)`. Inside the handle_call, `do_generate_blocks_loop`
runs N iterations of `do_generate_one_block`, each of which calls
`do_create_template` (which calls `chainstate:get_mtp` blocking
gen_server:call) and then `do_submit_block` (which calls
`chainstate:submit_block` blocking gen_server:call). The miner gen_server
is blocked for the duration; concurrent `getblocktemplate`,
`submitblock`, or other API calls queue up and may time out.

For regtest with N=1 (typical test invocation), this is fine. For
batch generation of e.g. 200 blocks (for testing CSV / coinbase
maturity), all other miner-API calls block for the full duration.

**File:** `src/beamchain_miner.erl:103-104, 145-154, 950-962`.

**Impact:** regtest test ergonomics; concurrent test cases that share
the same miner process serialise.

---

## Summary

**Bug count:** 23 (BUG-1 through BUG-23).

**Severity distribution:**
- **P0-CDIV:** 3 (BUG-3, BUG-6, BUG-8) — note BUG-20 is a cross-cite
  of BUG-8 surfaced at the BIP-22 wire boundary, recorded as P1.
- **P1:** 16 (BUG-1, BUG-2, BUG-4, BUG-5, BUG-9, BUG-10, BUG-12,
  BUG-13, BUG-14, BUG-15, BUG-16, BUG-17, BUG-18, BUG-20, BUG-21,
  BUG-22)
- **P2:** 4 (BUG-7, BUG-11, BUG-19, BUG-23)
- Total: 3 + 16 + 4 = **23** ✓

**Carry-forwards verified open:**
- **W145 BUG-6** "generateblock confession 'would compute fee from
  inputs-outputs'": confession line 1011 STILL PRESENT at
  `miner.erl:1010-1014`. Note: behaviour is actually parity with Core
  (Core's generateblock also uses `use_mempool=false` and the coinbase
  pays only subsidy). Severity downgraded — the COMMENT is misleading
  but the BEHAVIOUR matches Core. Recorded in gate G31 + downgraded.
- **W143 BUG-1** mainnet sync stall at h=91842 (hex_to_bin
  DISPLAY-vs-INTERNAL): does NOT touch miner-side code path directly.
  The miner does not consult `bip30_exceptions` during template
  construction (it relies on `chainstate:submit_block` to run the BIP-30
  check). The byte-order class issue is still active in
  `validation.erl:1101-1104` per W143 — but the miner-side audit
  does not surface a separate occurrence. Listed as cross-cite only.
- **W145 BUG-1** P1 two-pipeline `subsidy_halving_interval` 15th
  distinct guard: `block_subsidy/2` at `chain_params.erl:393-399`
  is now properly params-aware (`Interval = maps:get(subsidy_halving_interval, params(Network))`).
  CLOSED at the chainparams level for beamchain. Re-confirmed: the
  miner's `Subsidy = beamchain_chain_params:block_subsidy(Height, Network)`
  at `miner.erl:230, 1009` calls into the correct helper. Not a new
  finding here.
- **W150 BUG-12** gen_server self-deadlock (4 sites): the miner does
  NOT introduce a fifth site. All blocking calls within
  `do_create_template` / `do_submit_block` are to DIFFERENT
  gen_servers (chainstate, mempool, peer_manager). No miner→miner
  self-call.
- **W152 BUG-1+4** production tx-relay (queue_tx_inv dead, MSG_TX
  hardcoded): does not intersect miner surface. No new finding.

**Fleet patterns confirmed:**
- "**two-pipeline guard**" — 17th distinct fleet instance (BUG-8
  miner-side `estimate_sigops` vs validation-side `get_tx_sigop_cost`)
  AND 16th instance (BUG-6 + BUG-10 internal BIP-94-correct `MinTime`
  vs external BIP-94-incorrect `mintime` GBT field).
- "**dead-data plumbing**" — 5 instances in one module (BUG-12:
  `template`, `tip_hash` state fields; `_coinbase_tx`, `_total_weight`,
  `_total_sigops` template fields).
- "**comment-as-confession**" — `miner.erl:1011` "In a real impl,
  would compute fee from inputs-outputs / For generateblock, caller
  is responsible for valid txs" (W145 BUG-6 STILL OPEN at the
  COMMENT level; behaviour matches Core). 12th+ distinct fleet
  instance. Cross-cite BUG-14 line 637-639 "This is a simplification
  - for truly accurate results we'd track ancestor_weight separately".
- "**operator-knob absence**" — BUG-1, BUG-2 — `-blockmaxweight`,
  `-blockmintxfee`, `-blockreservedweight` all hard-coded as defines;
  no config wire-through. Symmetric to W149 BUG-5 (`-assumevalid`),
  W148 (`-maxorphantx`), etc.
- "**already-exports-the-primitive-just-not-called**" — BUG-8 cross-cite:
  `get_tx_sigop_cost/3` exists and is exported at `validation.erl:27`,
  but the miner's selection path uses `estimate_sigops/1` instead.
  Same pattern as W141 "dead-helper-at-call-site" / W138 cluster.
- "**CVE-2012-2459 mutated-merkle absence**" — BUG-5; W142+W143 6+
  impls confirmed missing this; beamchain has the check at
  `validation.erl:151` but NOT at miner-side template construction
  (`merkle_pairs` blindly duplicates without flagging mutation).
- "**non-canonical encoding for h ≤ 16**" — BUG-7; first beamchain
  instance; cross-fleet new variant of "asymmetric defensive depth"
  (functional encoding works, but block-fingerprint diverges from
  Core's canonical form).
- "**caller-side dummy-coinbase contract divergence**" — BUG-15;
  beamchain accepts non-standard `coinbasescript` request field with
  OP_TRUE default. Pool integration risk that funds get locked to
  anyone-can-spend on mainnet.

**Top three findings:**

1. **BUG-8 (P0-CDIV `estimate_sigops` undercount + two-pipeline drift)**
   — miner's `estimate_sigops/1` counts ONLY legacy sigops×4, missing
   P2SH redeemScript sigops and witness sigops. Same impl has a
   cost-correct `get_tx_sigop_cost/3` helper (used by connect_block)
   that the miner could call but doesn't. For P2SH-/segwit-heavy
   mempools, the miner produces over-sigop templates that fail at
   submit/relay. Cross-cite BUG-20 (per-tx GBT field reports the
   undercount). 17th distinct two-pipeline guard. Same gap exists at
   `check_block` (line 158-163), which is itself a consensus check
   — making this potentially P0-CONS as a follow-up audit.

2. **BUG-6 (P0-CDIV `mintime` BIP-94 incorrect in GBT)** — template
   emits `<<"mintime">> => MTP + 1` regardless of difficulty-adjustment
   boundaries; the BIP-94 `prev_block_time - MAX_TIMEWARP` clause IS
   computed for the internal `_header` field but NOT for the
   GBT-exposed `mintime`. Pools that respect GBT `mintime` will
   produce blocks rejected as `time-timewarp-attack` at every 2016th
   block boundary. Cross-cite BUG-10 (same impl, two adjacent fields
   use different min-time computations).

3. **BUG-15 (P1 + funds-loss risk on mainnet)** — `rpc_getblocktemplate`
   accepts non-standard `coinbasescript` request field and defaults
   to OP_TRUE when missing. Pool software written against Core's
   BIP-22 (which has no such field) will get OP_TRUE coinbases on
   mainnet → anyone-can-spend block reward. Mining-pool-integration
   risk. Cross-impl wire-protocol divergence.

**Methodology note:** every gate was re-checked against the present
source (`master @ 2be6279`) — prior W123 / W108 fix-pass results were
not relied on. Of the 32 sub-gates, 14 PASS, 4 PARTIAL, 11 BUG, 3 N/A
(boundary cases gated on absent features).
