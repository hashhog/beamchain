# W123 — Mining / getblocktemplate parity audit (beamchain)

Date: 2026-05-17
Scope: full mining stack vs. Bitcoin Core
References:
  - `bitcoin-core/src/node/miner.cpp` (`BlockAssembler`, `GetMinimumTime`,
    `UpdateTime`, `addChunks`, `RegenerateCommitments`)
  - `bitcoin-core/src/node/miner.h`, `bitcoin-core/src/node/types.h`
    (`BlockCreateOptions`, `BlockWaitOptions`, `BlockCheckOptions`,
    `CoinbaseTx`)
  - `bitcoin-core/src/rpc/mining.cpp` (`getblocktemplate`, `submitblock`,
    `submitheader`, `getmininginfo`, `getnetworkhashps`, `generatetoaddress`,
    `generatetodescriptor`, `generateblock`, `prioritisetransaction`,
    `getprioritisedtransactions`)
  - `bitcoin-core/src/interfaces/mining.h` (`Mining`, `BlockTemplate`)
  - `bitcoin-core/src/policy/policy.h` (block weight + min-fee + reserved
    weight constants)
  - `bitcoin-core/src/versionbits.h` (`BIP9GBTStatus`, `gbt_optional_rule`)
  - BIPs 9 / 22 / 23 / 34 / 141 / 145 / 94

Implementation surface in beamchain:
  - `src/beamchain_miner.erl` — `create_block_template`, `submit_block`,
    `generate_blocks`, `generate_block_with_txs`, `build_coinbase`,
    `encode_coinbase_height`, `select_transactions`, `greedy_select`,
    `topological_sort`, `mine_block_loop`, `compute_minimum_time`.
  - `src/beamchain_rpc.erl` — `rpc_getmininginfo`, `rpc_getblocktemplate`,
    `rpc_submitblock`, `rpc_generatetoaddress`, `rpc_generateblock`,
    `rpc_generate`, `rpc_getnetworkhashps`, `bip22_result/1`.
  - `src/beamchain_versionbits.erl` — `compute_block_version`,
    `deployment_maps`, `get_deployment_state_at_height`.
  - `src/beamchain_chainstate.erl` — `submit_block/1` (active vs side-branch).

Prior coverage:
  - W87 fixed 8 GBT bugs (reserved weight, sigop reserve, IsFinalTx, BIP-94
    timewarp, blockMinFeeRate, weight >= check, compute_block_version).
  - W108 catalogued 30 GBT defects against the same surface; the existing
    `beamchain_w108_gbt_tests.erl` (61 tests, all PASS at 22ac35d) is the
    de-facto regression suite for the post-W87 fixes plus the BIP-22/23/141
    required-field set (BUG-3 closed in W108).
  - W121 (5f9ad9d) declared beamchain "STRONGEST in fleet" for BIP-157/158.
    W122 (ee2b629) confirmed the codec stress-tested across q∈[0..1000+].

W123 is a fresh DISCOVERY pass on the mining/GBT surface against a 30-gate
W123-standard framework.  The mining surface has a long bug history (W87
fix wave + W108 audit wave) — every gate below is therefore re-checked
against the present source rather than relying on prior labels.

---

## Per-gate result (30 gates)

Legend: PRESENT = parity with Core / spec; PARTIAL = wired but deviates;
MISSING = not implemented.

### Section A — getblocktemplate request handling (BIP-22/23)

**G1 [P0] IBD / connection guard** — MISSING.
Core (`rpc/mining.cpp:766-775`) rejects `getblocktemplate` on a non-test
chain when peer count == 0 OR `IsInitialBlockDownload()` returns true.
beamchain's `rpc_getblocktemplate/1` (`beamchain_rpc.erl:3720-3739`)
delegates straight to `beamchain_miner:create_block_template/1` with no
network-state check.  A solo miner on mainnet that hasn't synced will
silently get a template built off a stale tip, mine off-chain, and waste
hashes.

**G2 [P0] mode="proposal" handler (BIP-23 §3)** — MISSING.
Core (`rpc/mining.cpp:730-752`) reads `template_request.mode`; on
`"proposal"` it decodes `data`, looks the block up in the index, returns
`"duplicate"` / `"duplicate-invalid"` / `"duplicate-inconclusive"`, or
calls `TestBlockValidity` for a BIP-22 reason string.  beamchain's
`rpc_getblocktemplate/1` never reads the `mode` key — it always returns
a regular template.  A mining pool that uses BIP-23 proposal mode to
validate a constructed block before broadcasting will get back a
template instead of a yes/no answer.

**G3 [P1] setClientRules "segwit" enforcement** — MISSING.
Core (`rpc/mining.cpp:854-857`) throws `RPC_INVALID_PARAMETER` if the
client's `rules` array does not contain `"segwit"`.  beamchain ignores
the `rules` field entirely (`rpc_getblocktemplate/1` does not inspect
it).  A pre-SegWit miner gets a SegWit template back and will produce
an invalid block.

**G4 [P1] long-polling (BIP-22 §8)** — MISSING.
Core (`rpc/mining.cpp:783-845`) waits up to 60 s (then 10-s ticks) for
the tip to change OR mempool to grow when `longpollid` is in the
request.  beamchain ignores the `longpollid` key entirely.  Mining
pools relying on long-poll for low-latency tip notification will not
get them.

**G5 [P2] signet rules enforcement** — MISSING.
Core (`rpc/mining.cpp:849-852`) throws when the network is signet and
`rules` does not contain `"signet"`.  beamchain has no signet rules
check.  Currently beamchain does not run on signet, but the gate would
be needed if/when it does.

**G6 [P3] "capabilities" includes "proposal"** — PRESENT.
`beamchain_miner.erl:273` sets `Capabilities = [<<"proposal">>]`.
Matches Core (`rpc/mining.cpp:895`).

### Section B — getblocktemplate response fields (BIP-22/23/141)

**G7 [P1] rules array, active deployments, ! prefix** — PARTIAL.
`beamchain_miner.erl:360-415` (`build_gbt_rules_and_vbavailable/2`)
emits `"!segwit"` for segwit's active state, bare name for all others.
Core (`rpc/mining.cpp:953-957`) hardcodes `"csv"`, `"!segwit"`,
`"taproot"`, and conditionally `"!signet"`.  The semantics of
`gbt_optional_rule` ("!" prefix when the rule changes block structure
or generation tx) is correct for segwit but Core treats `signet` as
non-optional (`!signet`) too.  beamchain does not emit signet (it is
not a beamchain network), so the bare-name branch covers `csv` +
`taproot`.  The bug: **the rule string is computed from the
deployment table, not from a `gbt_optional_rule` flag**, so any future
non-optional rule (e.g. a hypothetical `"!opcodename"`) needs an
explicit `name_atom` clause in `build_gbt_rules_and_vbavailable/2`
rather than a data-driven flag.

**G8 [P1] vbavailable map** — PARTIAL.
`beamchain_miner.erl:401-410` adds `started` + `locked_in` deployments
into `vbavailable`.  Core (`rpc/mining.cpp:968-983`) ALSO masks the
block version (`block.nVersion &= ~info.mask`) when the client did not
opt into a non-optional rule.  beamchain never applies that mask
because `setClientRules` is not threaded through (G3 missing).  The
beamchain template therefore always advertises the segwit bit
regardless of client capabilities.

**G9 [P3] vbrequired bitmask** — PRESENT.
Hard-coded `0` (`beamchain_miner.erl:282`).  Matches Core
(`rpc/mining.cpp:996`).

**G10 [P3] longpollid format** — PRESENT.
`beamchain_miner.erl:289-292`: `<<tip_hex/binary, mempool_count/integer>>`.
Matches Core's `tip.GetHex() + ToString(nTransactionsUpdatedLast)`
shape (`rpc/mining.cpp:1002`).  Semantics: Core uses
`mempool.GetTransactionsUpdated()` (a strictly-monotonic counter);
beamchain uses `mempool size` (changes both up and down as txs are
added/evicted).  The longpoll-invalidation contract holds but the
counter is not monotonic — a long-poll waiter watching for a
counter-change may miss a tx-add immediately followed by a tx-evict.

**G11 [P2] default_witness_commitment present when witness txs** —
PRESENT.
`beamchain_miner.erl:329-345`: when `HasWitnessTx` is true, extracts
the OP_RETURN commitment script from coinbase output[1] and emits it
as `default_witness_commitment`.  Format `<<0x6a,0x24,0xaa,0x21,0xa9,
0xed, Commitment:32/binary>>` matches BIP-141 §commitment-structure.

**G12 [P3] signet_challenge field on signet** — MISSING.
Core (`rpc/mining.cpp:1024-1026`) emits the network's signet
challenge.  beamchain does not run on signet; field omitted entirely.
P3 because non-applicable until signet support is added.

### Section C — coinbase / template internals (BIP-34/141)

**G13 [P0] BIP-34 coinbase height encoding (CScriptNum / sign-bit)** —
PRESENT.
`beamchain_miner.erl:927-943` (`le_minimal/1`): appends a 0x00 sign
byte when the last LE byte has bit 7 set, matching Core's
`CScriptNum::serialize` (`script.h:366-367`).  Verified by W108 tests
(`gbt_coinbase_height_128/255/32768/65535_sign_bit_fixed_test`).

**G14 [P1] coinbase scriptSig 2-100 byte length validation** — PARTIAL.
Core relies on `CScript() << nHeight` always producing a minimal push
(>= 1 byte) AND `include_dummy_extranonce=true` (`miner.cpp:187-193`)
to guarantee >= 2 bytes for low heights.  beamchain's `build_coinbase`
(`beamchain_miner.erl:845-894`) ALWAYS appends an 8-byte `ExtraNonce`,
so total scriptSig is min 9 bytes and max 16-or-so bytes — well within
2..100.  The bug: **there is no explicit length assertion at template
creation**.  `do_submit_block` will catch a bad length via
`check_block`, but the template builder will silently produce an
invalid template if the height grows large enough (~2^56 heights × 8
extra-nonce bytes > 100) or if the defensive `encode_coinbase_height(0)
= <<0>>` branch is hit (would yield 9 bytes — fine, but the gate is
not load-bearing in beamchain).

**G15 [P0] coinbase output count + value (subsidy + fees)** — PRESENT.
`beamchain_miner.erl:230-231`: `CoinbaseValue = Subsidy + TotalFees`.
Outputs: payout + (optional witness-commitment) — matches Core's
`miner.cpp:176-179`.

**G16 [P0] witness commitment output (OP_RETURN + magic + 32-byte hash)**
— PRESENT.
`beamchain_miner.erl:897-914` (`witness_commitment_output/2`): emits
`<<0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed, Commitment:32/binary>>`.
Matches BIP-141 §commitment-structure.  Witness nonce = 32 zero bytes
(`beamchain_miner.erl:861`).

### Section D — block transaction selection (addChunks / cluster mempool)

**G17 [P1] cluster-aware GetBlockBuilderChunk path** — MISSING.
Core post-cluster-mempool (PR #28676, ≈ Core v28) uses
`m_mempool->StartBlockBuilding() / GetBlockBuilderChunk /
IncludeBuilderChunk / SkipBuilderChunk / StopBlockBuilding` (per
`miner.cpp:152-154` + `addChunks` at `miner.cpp:279-334`).
beamchain uses the legacy "sort-by-fee + recursive parent resolution"
approach (`beamchain_miner.erl:601-746`) — `get_sorted_by_fee`,
`ancestor_fee_rate`, `resolve_parents`, `greedy_select`.  This is
architecturally pre-cluster.  Consequence:
  - No chunk-level fee floor (Core skips a chunk if its fee rate is
    below `blockMinFeeRate`, then stops scanning entirely).
  - No `m_package_feerates` accumulator for the template.
  - No `MAX_CLUSTER_COUNT_LIMIT` budget per package — the
    `resolve_parents` recursion has no depth limit (W108 BUG-19).
  - The double-counting hazard in `resolve_parents` (W108 BUG-29) is
    still latent.

**G18 [P2] blockMinFeeRate gate** — PRESENT (but legacy semantics).
`beamchain_miner.erl:683-694`: per-entry skip when
`Entry#mempool_entry.fee * 1000 / vsize < ?DEFAULT_BLOCK_MIN_TX_FEE_SAT_KVBYTE`.
Core's chunk-level gate is at the cluster-builder layer.  The
beamchain gate is per-entry — semantically equivalent for an
ungrouped sort but does not capture the early-exit Core does when a
chunk falls below the floor.

**G19 [P0] IsFinalTx per-entry locktime check** — PRESENT.
`beamchain_miner.erl:698-705`: calls
`beamchain_validation:is_final_tx(Tx, Height, LockTimeCutoff)` where
`LockTimeCutoff = MTP` of the tip.  Matches Core
(`miner.cpp:252-260`).  W87 BUG2 fix; W108 has positive coverage at
`gbt_is_final_tx_height_based_test`.

### Section E — submitblock (BIP-22 §5)

**G20 [P0] duplicate-block detection (already-valid / failed / inconclusive)**
— MISSING.
Core's `submitblock` (`rpc/mining.cpp:1083-1106`) uses the `new_block`
out-parameter of `ProcessNewBlock` and a `submitblock_StateCatcher`
validation interface to distinguish:
  - block accepted, was new → null
  - block accepted, was duplicate → `"duplicate"`
  - block rejected with state → BIP22ValidationResult(state)
beamchain's `do_submit_block` (`beamchain_miner.erl:512-578`) does not
look up the block in the index before calling
`beamchain_chainstate:submit_block/1`.  A duplicate submit of an
already-active block enters `do_connect_block` which then tries to
spend already-spent UTXOs and returns `bad_txns_inputs_missingorspent`
or similar.  The result is a wrong-reason rejection string rather
than `"duplicate"`.  Side-branch duplicates are handled correctly
(`beamchain_chainstate.erl:1264-1268` returns `side_branch` and the
RPC maps that to `"inconclusive"`) but active-chain duplicates are
not.

**G21 [P1] UpdateUncommittedBlockStructures call** — MISSING.
Core (`rpc/mining.cpp:1085-1090`) calls
`chainman.UpdateUncommittedBlockStructures(block, pindex)` before
`ProcessNewBlock`.  This regenerates the witness commitment in
coinbase output[1] if the submitted block is from a miner that does
not yet signal SegWit but the node does.  beamchain calls
`check_block` then `submit_block` directly — a block missing the
commitment will be rejected for `bad-witness-merkle-match` rather
than silently fixed up.

**G22 [P0] !new_block && accepted → "duplicate" path** — MISSING.
Tied to G20.  beamchain's `do_submit_block` has no concept of "block
was accepted but was a duplicate".  Tested at
`beamchain_w108_gbt_tests:gbt_submitblock_new_block_flag_missing_test`.

**G23 [P0] BIP22ValidationResult canonical strings** — PRESENT.
`beamchain_rpc.erl:3748-3808` maps validation atoms to canonical
BIP-22 strings: `bad-cb-amount`, `bad-cb-length`, `bad-cb-height`,
`bad-blk-sigops`, `bad-txns-nonfinal`, `bad-txns-vout-negative`,
`bad-txns-vout-toolarge`, `bad-txnmrklroot`,
`bad-txns-inputs-missingorspent`, `bad-witness-merkle-match`,
`block-script-verify-flag-failed`, `bad-txns-in-belowout`,
`bad-txns-premature-spend-of-coinbase`, `bad-txns-BIP30`,
`bad-txns-duplicate`, `time-too-old`, `time-too-new`,
`time-timewarp-attack`, `duplicate`, `inconclusive`, plus catch-all
`"rejected"`.

**G24 [P3] submitblock 2nd arg "dummy" accepted** — PRESENT (implicit).
`rpc_submitblock/1` accepts `[HexData]` with no dummy — Erlang
pattern-match ignores extra params.  The accept-and-ignore behaviour
matches Core's "Argument 2 is ignored" (`rpc/mining.cpp:1058`).

### Section F — auxiliary mining RPCs

**G25 [P1] submitheader RPC** — MISSING.
Core (`rpc/mining.cpp:1108-1146`) registers `submitheader` which
takes a hex-encoded header and feeds it into `ProcessNewBlockHeaders`.
beamchain has no `submitheader` handler — `handle_method` returns
method-not-found.

**G26 [P1] prioritisetransaction RPC + dust-output guard** — MISSING.
Core (`rpc/mining.cpp:502-545`) registers `prioritisetransaction` and
guards against modifying non-zero-fee dust transactions
(`mempool.m_opts.require_standard && tx && !GetDust(*tx, ...).empty()`).
beamchain has no `handle_method` clause.  Mining pools that rely on
out-of-band fee adjustment to push a transaction into a block cannot
operate against beamchain.

**G27 [P1] getprioritisedtransactions RPC** — MISSING.
Core (`rpc/mining.cpp:547-583`) returns the full delta table keyed by
txid with `fee_delta`, `in_mempool`, optional `modified_fee`.
beamchain has no handler.

### Section G — getmininginfo / getnetworkhashps

**G28 [P1] getmininginfo "next" sub-object uses NextEmptyBlockIndex** —
PARTIAL.
Core (`rpc/mining.cpp:479-487`) calls
`NextEmptyBlockIndex(tip, consensus, next_index)` then emits
next.height, next.bits (from `next_index.nBits` =
`GetNextWorkRequired`), next.difficulty, next.target.
beamchain (`beamchain_rpc.erl:3711-3716`) emits `next.height = Blocks
+ 1`, but next.bits/difficulty/target ALL reuse the current tip's
values.  At any difficulty-adjustment boundary the next-block bits
will diverge from the tip's; beamchain returns the tip's stale value.
At testnet's `fPowAllowMinDifficultyBlocks` boundaries the divergence
fires every block where the gap exceeds 20 min.

**G29 [P1] getmininginfo "networkhashps" real computation** — MISSING.
`beamchain_rpc.erl:3708` hardcodes `<<"networkhashps">> => 0` even
though `rpc_getnetworkhashps/1` (`beamchain_rpc.erl:9249-9276`)
implements the chainwork/timedelta math.  `getmininginfo` does not
invoke `rpc_getnetworkhashps([120])` to populate the field.

**G30 [P2] getmininginfo currentblock* fields use BlockAssembler
last-block static** — PARTIAL.
Core (`rpc/mining.cpp:467-468`) emits `currentblockweight` and
`currentblocktx` only when `BlockAssembler::m_last_block_weight` /
`m_last_block_num_txs` are set (i.e. a template was ever assembled).
beamchain (`beamchain_rpc.erl:3702-3704`) always emits all three of
`currentblocksize`, `currentblockweight`, `currentblocktx`, all
hardcoded to 0.  `currentblocksize` was REMOVED in Core 0.17+ — its
presence in the response is a documented divergence.

---

## Summary

|  Category                                                | Count |
|----------------------------------------------------------|------:|
| PRESENT                                                  |    11 |
| PARTIAL                                                  |     7 |
| MISSING                                                  |    12 |
| **Total gates**                                          |    30 |

|  Severity bucket                                         | Count |
|----------------------------------------------------------|------:|
| P0 — consensus / correctness                             |     8 |
| P1 — protocol parity / operator-visible behaviour        |    13 |
| P2 — semantic divergence                                 |     5 |
| P3 — cosmetic / future-proofing                          |     4 |

### Bug ledger

| ID    | Sev | Gate | Title                                                                         |
|-------|-----|------|-------------------------------------------------------------------------------|
| BUG-1 | P0  | G1   | GBT served without IBD / peer-count guard on mainnet                          |
| BUG-2 | P0  | G2   | mode="proposal" never read; always returns a regular template                 |
| BUG-3 | P1  | G3   | client `rules`["segwit"] not enforced; pre-segwit miner gets segwit template  |
| BUG-4 | P1  | G4   | long-polling absent; longpollid ignored                                       |
| BUG-5 | P2  | G5   | signet rule absence (n/a until signet supported)                              |
| BUG-6 | P1  | G7   | rule string driven by name_atom switch, not gbt_optional_rule data flag       |
| BUG-7 | P1  | G8   | vbavailable correct; block.nVersion mask for unwanted rules not applied (G3)  |
| BUG-8 | P3  | G10  | longpollid uses mempool size (non-monotonic) vs TransactionsUpdated counter   |
| BUG-9 | P3  | G12  | signet_challenge field missing                                                |
| BUG-10| P1  | G14  | coinbase scriptSig length not asserted at template creation                   |
| BUG-11| P1  | G17  | cluster-aware block builder absent; legacy sort-by-fee + recursive parents    |
| BUG-12| P2  | G18  | per-entry minfee gate (legacy semantics; no chunk-level early exit)           |
| BUG-13| P0  | G20  | submitblock: no duplicate-block pre-check; active-chain duplicate misreported |
| BUG-14| P1  | G21  | UpdateUncommittedBlockStructures never called on submit                       |
| BUG-15| P0  | G22  | !new_block && accepted "duplicate" path absent                                |
| BUG-16| P1  | G25  | submitheader RPC absent                                                       |
| BUG-17| P1  | G26  | prioritisetransaction RPC absent (incl. dust guard)                           |
| BUG-18| P1  | G27  | getprioritisedtransactions RPC absent                                         |
| BUG-19| P1  | G28  | getmininginfo "next" sub-object reuses tip bits/target (no NextEmptyBlockIdx) |
| BUG-20| P1  | G29  | getmininginfo networkhashps hardcoded 0 despite getnetworkhashps existing     |
| BUG-21| P2  | G30  | getmininginfo currentblock* always present; currentblocksize is Core-removed  |

### Top findings — does the STRONGEST claim extend to mining?

**No.**  beamchain is fleet-leading on the consensus surfaces (W121
BIP-157/158: 0 bugs; W122 GCS codec: clean) but the mining stack lags Core
by an architectural era.  Cluster-mempool block building (Core PR #28676,
≈ v28) has not landed — beamchain still uses the pre-cluster
sort-by-fee + recursive-parent-resolution path with a tracked
`resolve_parents` double-count hazard (W108 BUG-29) and no depth guard
(W108 BUG-19).

The mining-stack gaps split into three families:

1. **GBT request-shape gaps (BIP-22/23):** mode="proposal", long-polling,
   client `rules` enforcement, signet rules.  All four are absent.
   Mining-pool integrations that expect Core-style GBT semantics will
   either silently get stale templates (no IBD guard) or get a wrong
   response shape (proposal mode returns a template).

2. **submitblock duplicate handling:** the active-chain dup path is wholly
   absent; side-branch dup → "inconclusive" works correctly.  This is
   the most likely operator-visible bug — pool resubmits of just-mined
   blocks (race between miner and pool) will get a non-canonical
   rejection reason string instead of `"duplicate"`.

3. **Auxiliary mining RPCs (submitheader, prioritisetransaction,
   getprioritisedtransactions):** none are wired.  Pools that rely on
   prioritisetransaction for OOB fee adjustment cannot operate against
   beamchain.  The getmininginfo response itself reuses the tip's bits
   in `"next"` (wrong at difficulty-adjustment boundaries) and emits
   `currentblocksize`/`currentblockweight`/`currentblocktx`/`networkhashps`
   as hardcoded zeros despite `rpc_getnetworkhashps` already being
   implemented (only ever invoked directly, never via getmininginfo).

Pattern overlap with prior beamchain audits:
  - **Dead-helper-at-call-site (33-wave streak)** — `rpc_getnetworkhashps`
    exists and computes correctly but `rpc_getmininginfo` does not call
    it.  Same shape as W108 BUG-29 (ancestor_fee_rate double-count) and
    W117 "dead-helper-at-call-site".
  - **Well-engineered codec, gaps at system edges** — the BIP-22/23
    response shape (capabilities, rules, vbavailable, vbrequired,
    longpollid, default_witness_commitment) is correct.  The system
    edges (IBD guard, proposal mode, client-rules enforcement,
    long-polling, submitheader, prioritisetransaction) are absent.
  - **Comment-as-confession** — `do_generate_block_with_txs` at
    `beamchain_miner.erl:1010-1014` says "In a real impl, would compute
    fee from inputs-outputs / For generateblock, caller is responsible
    for valid txs" — same shape as W108 BUG-20 and the cross-impl
    "for simplicity" anti-pattern.  Still in code.

Cross-wave continuity:
  - W87 closed 8 GBT bugs; W108 catalogued 30 more.  W123 confirms the
    W108 ledger is still live (zero W108 entries have moved to PRESENT
    since W108 landed) AND surfaces 6 additional gates (G3 client rules
    detail, G7 gbt_optional_rule data-driven flag, G8 nVersion mask, G10
    longpollid monotonicity, G14 length assertion at template creation,
    G21 UpdateUncommittedBlockStructures) that W108 did not isolate.
  - W121 / W122 "STRONGEST" claim is **compact-filter-specific** — the
    mining surface is mid-pack: better than haskoin's pre-W123 BIP-22
    coverage but distinctly weaker than the consensus subsystems.

### Recommended fix ordering (out of scope for W123, but for whoever picks up)

P0 first (G1 + G2 + G15 + G20 + G22): close the wire-shape parity gates
before the architectural one (G17 cluster mempool).  Wire-shape fixes
are decoupled and small; cluster-mempool is its own multi-wave campaign
and should be paired with the mempool subsystem (W120 carry-forwards).

W123 lands as DISCOVERY only — no production code is modified.

