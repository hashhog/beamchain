# W133 — Index databases (txindex + coinstatsindex) audit (beamchain)

Discovery-only wave. 30 audit gates against Core's optional index databases:
**txindex** (`bitcoin-core/src/index/txindex.{h,cpp}`, 121 LOC) and
**coinstatsindex** (`bitcoin-core/src/index/coinstatsindex.{h,cpp}`, 403 LOC),
both built on the shared `BaseIndex` framework (`bitcoin-core/src/index/base.{h,cpp}`,
505 LOC) plus the on-disk layout helpers (`disktxpos.h`, `db_key.h`).

Excludes BIP-158 blockfilterindex (already audited in **W121**) and
txospenderindex (Core-internal, not exposed via RPC).

Companion audits to cross-reference:
- **W121** — Compact filter index P2P + storage (BIP-157/158). 30 gates, 0 bugs.
  Demonstrated that a properly-structured optional index in beamchain is
  feasible. W133 covers the *transaction* and *UTXO-stats* indexes which
  share most of the same scaffolding (`BaseIndex` lifecycle, locator
  persistence, reorg handling, prune lock interaction) but in beamchain
  follow a *very different* design — see headline finding #1.
- **W101** — `ActivateBestChain` / chainstate orchestration. Provides the
  baseline for how beamchain wires per-block work into the connect/disconnect
  flow.
- **W102** — assumeUTXO. Uses MuHash3072 from the same kernel module that
  coinstatsindex consumes.
- **W124** — Operator experience. `-txindex=1` / `-coinstatsindex=1` CLI flags
  cross the operator surface; this audit zooms into the *implementation*
  details behind those flags.

Reference: `bitcoin-core/src/index/base.{h,cpp}`, `txindex.{h,cpp}`,
`coinstatsindex.{h,cpp}`, `disktxpos.h`, `db_key.h`, plus
`bitcoin-core/src/kernel/coinstats.{h,cpp}` (the underlying ComputeUTXOStats
+ ApplyCoinHash routines that coinstatsindex deltas in-place).

## Status counts (30 gates)

- **PRESENT** (matches Core or internally consistent + Core-compatible): 3
- **PARTIAL** (some piece matches, others diverge or are simplified): 5
- **MISSING** (no equivalent in beamchain): 22

Headline: **24 bugs**, severity distribution **0 CDIV / 6 HIGH / 11 MEDIUM /
7 LOW**. Index correctness is operator-surface, not consensus: a wrong txindex
answer cannot fork the chain, only break `-txindex` users' RPC calls and SPV
wallet glue. A wrong coinstatsindex answer cannot fork the chain either, but
*can* corrupt analytics tooling and the `verifychain` cross-check. None is a
CDIV. The most consequential:

1. **BUG-1 (HIGH)** — **No `BaseIndex` abstraction.** Core unifies txindex,
   coinstatsindex, blockfilterindex, and txospenderindex under a single
   `BaseIndex` class that owns: `m_synced` flag, `m_best_block_index`,
   background sync thread, `BlockUntilSyncedToCurrentChain`, `Commit`
   (locator persistence), `Rewind` (per-block disconnect), `BlockConnected` /
   `ChainStateFlushed` validation-interface callbacks, prune lock
   integration via `SetBestBlockIndex`, and per-instance `IndexSummary`.
   beamchain has *no* shared base. blockfilter_index has a bespoke gen_server
   with its own remove_block + tip tracking; tx_index is an inline write
   into a RocksDB column family with no gen_server, no locator, no synced
   flag, no separate sync thread, no prune lock. coinstatsindex *does not
   exist*. This is the structural root from which the next 23 bugs descend.

2. **BUG-2 (HIGH)** — **No coinstatsindex at all.** Core's coinstatsindex
   maintains a *per-height* delta of the UTXO-set MuHash + accountant
   scalars (`m_transaction_output_count`, `m_total_amount`, per-coinbase /
   non-coinbase split, BIP30 unspendables, unclaimed rewards…) so that
   `gettxoutsetinfo height=N` is O(1). beamchain implements
   `gettxoutsetinfo` by *flushing the chainstate then folding the entire
   UTXO column family per call* (`beamchain_rpc.erl:3192` → `flush()` +
   `fold_utxos`). On a non-trivial chainstate (mainnet ≈ 170M outputs at
   tip), one call takes minutes and *cannot* answer historical heights at
   all — `compute_utxo_set_stats` only computes against the current tip.
   `gettxoutsetinfo blockhash=<HASH>` is not supported in any verbosity.

3. **BUG-3 (HIGH)** — **txindex stores logical position only, not disk
   position.** Core's `CDiskTxPos` is `{nFile, nPos, nTxOffset}` (`disktxpos.h`:14):
   the .dat file number, byte offset of the block, and the byte offset of
   the transaction *within* the block after the header. `FindTx` opens the
   block file, seeks past the header, seeks an additional `nTxOffset`, and
   reads exactly one tx. beamchain stores `{BlockHash, Height, Position}`
   where `Position` is the *index* of the tx in the block's `vtx` list
   (`beamchain_block_sync.erl:1135-1139`). `get_tx_location` →
   `get_block(BlockHash)` → `lists:nth(Pos+1, Txs)` *loads the entire block*
   on every txindex lookup and then walks the tx list O(Position). This is
   ~600x slower per call than Core's design for a 4000-tx block.

4. **BUG-4 (HIGH)** — **No `remove_tx_index` on disconnect / reorg.**
   Core's `BaseIndex::Rewind` iterates from `current_tip` back to the fork
   point and calls `CustomRemove(block_info)` for each disconnected block,
   which for `BaseIndex`-derived indexes erases the per-tx rows.
   beamchain's `do_disconnect_block` (chainstate.erl:1506-1564) reverts
   UTXOs, rolls back the cfheader chain (`beamchain_blockfilter_index:remove_block`),
   and clears mempool — but **never touches the `tx_index` column family**.
   The Pattern-C1 partial-fix in CORE-PARITY-AUDIT/_txindex-revert-on-reorg-fleet-result-2026-05-05.md
   filters at read time via `confirmations(BlockHeight, BlockHash)` →
   `is_block_in_active_chain`, but: (a) `get_tx_location` itself returns a
   stale `block_hash` that the RPC may forward, (b) iteration tools that
   probe the column family directly see ghosts, (c) two different tx with
   colliding txid (BIP30 historical or the Duff'12 BIP30-exception blocks)
   on different forks corrupt the index because the WRITE on the new
   branch silently overwrites the WRITE on the stale branch — the read-time
   gate fixes neither stale reads from index iteration nor write-side
   ordering.

5. **BUG-5 (HIGH)** — **No locator persisted; `m_synced` not modelled.**
   Core writes a `CBlockLocator` (exponentially-spaced ancestor hashes
   starting at the index's best block, see `BaseIndex::DB::WriteBestBlock`
   in `base.h:75`) so that on restart the index knows: (a) where it
   stopped, (b) whether the stop point is on the active chain or a stale
   fork that needs rewinding. beamchain's `tx_index` column family has no
   self-describing metadata — restart cannot distinguish "we caught up to
   tip" from "we crashed mid-block and the tip we last indexed is now
   orphaned". On crash recovery beamchain *re-stores* every tx in every
   block under `connect_block`, which masks the missing locator but
   wastes one full re-write per restart.

6. **BUG-6 (HIGH)** — **Genesis-block coinbase is indexed in beamchain.**
   Core explicitly skips genesis txns in `TxIndex::CustomAppend`
   (`txindex.cpp:77`: "Exclude genesis block transaction because outputs
   are not spendable"). beamchain `store_tx_index` is called from the
   block-connect path without a height-zero exception, so the mainnet
   genesis coinbase txid (the 4a5e1e4… one) is queryable via
   `getrawtransaction` *and* shows confirmations + height 0 (Core returns
   `-5 No such mempool or blockchain transaction`). Two-line semantic
   divergence from Core.

The remaining 18 bugs cover: no background sync thread (foreground only),
no `BlockUntilSyncedToCurrentChain` RPC handshake, no `getindexinfo` RPC
(missing tool), no per-index prune lock so `-prune=N` can delete blocks
the index still needs, no per-block-locator commit cadence (Core writes
every 30s via `SYNC_LOCATOR_WRITE_INTERVAL`), no `CustomCommit` /
`CustomInit` separation (so checksum-style verification of the on-disk
muhash is impossible to even attempt), no obfuscate-key on the index DB
(Core uses `f_obfuscate` so on-disk bytes don't trigger antivirus false
positives on coinbase strings), no `assumeUTXO` interaction (which Core
flagged as: when a snapshot is loaded, only the background "IBD" chainstate
indexes, then *reinitialize* after background catches up), no
"old indexes/coinstats path" cleanup (Core warns about the pre-v30 path),
no `connect_undo_data` flag awareness, no `DBHeightKey` big-endian
ordering for ranged scans, no BIP30-unspendable accounting in
total_unspendables_bip30, etc.

**Not a CDIV**: every bug below affects index correctness, performance,
or operator UX. None affects consensus validation of received blocks
(beamchain rejects/accepts blocks via `beamchain_chainstate:connect_block`
+ `beamchain_validation` *before* the inline tx_index write happens, so a
tx_index bug cannot taint the active chain). Cluster severity: 6 HIGH /
11 MEDIUM / 7 LOW.

The audit-flip convention applies: every test that asserts a divergent
fact (e.g. "beamchain stores logical position, not disk position") is
written so it **passes today** and **will fail when the fix lands**,
flipping the gate from MISSING/BUG → PRESENT.

---

## Gate index (1..30)

| #  | Name | Status | Core ref | beamchain ref |
|----|------|--------|----------|---------------|
| 1  | `BaseIndex` shared abstraction (m_synced / m_best_block_index / sync thread)             | MISSING | base.{h,cpp}                                | no shared base; tx_index is inline, blockfilter_index is bespoke |
| 2  | coinstatsindex exists                                                                    | MISSING | coinstatsindex.{h,cpp}                      | absent; gettxoutsetinfo walks full UTXO CF on every call |
| 3  | txindex stores `CDiskTxPos {nFile,nPos,nTxOffset}`                                       | MISSING | disktxpos.h:14                              | stores {BlockHash, Height, Position-in-vtx} |
| 4  | `Rewind` / `CustomRemove` deletes per-tx rows on disconnect                              | MISSING | base.cpp:290-326 (Rewind), txindex.cpp      | do_disconnect_block never touches tx_index; read-time filter only |
| 5  | Block locator persisted via `WriteBestBlock`                                             | MISSING | base.h:75, base.cpp:90-93                   | no locator; restart re-writes via full reindex |
| 6  | Genesis coinbase excluded                                                                | MISSING | txindex.cpp:77 (`if (block.height == 0) return true`) | store_tx_index has no height-zero exception |
| 7  | Background sync thread (`m_thread_sync` + `Sync()`)                                      | MISSING | base.cpp:201-268, base.h:93                 | foreground only; tx_index built inline during connect |
| 8  | `BlockUntilSyncedToCurrentChain` semantics                                               | MISSING | base.cpp:424-446                            | no equivalent; callers cannot wait for index catch-up |
| 9  | `getindexinfo` RPC                                                                       | MISSING | rpc/blockchain.cpp::getindexinfo            | not implemented; cannot probe txindex status from RPC |
| 10 | Per-index `IndexSummary` (synced/best_block_height/best_block_hash)                      | MISSING | base.h:30-35                                | no summary struct; getindexinfo would have nothing to read |
| 11 | Prune lock via `SetBestBlockIndex` / `UpdatePruneLock`                                   | MISSING | base.cpp:487-504                            | tx_index never holds a prune lock; `-prune` can wipe blocks it still needs |
| 12 | `AllowPrune()` per index (txindex=false, coinstatsindex=true)                            | MISSING | txindex.h:34, coinstatsindex.h:52           | no AllowPrune hook anywhere |
| 13 | `CustomInit` consistency check (read DB_MUHASH vs in-memory hash)                        | MISSING | coinstatsindex.cpp:262-306                  | coinstatsindex absent → no init-time corruption probe |
| 14 | `CustomCommit` batches DB_MUHASH with DB_BEST_BLOCK atomically                            | MISSING | coinstatsindex.cpp:308-314, base.cpp:270-288| no equivalent atomic-batch concept |
| 15 | `RevertBlock` recomputes MuHash on reorg                                                 | MISSING | coinstatsindex.cpp:326-403                  | no per-block muhash → no per-block revert |
| 16 | `DBHeightKey` big-endian for ordered scans                                               | MISSING | db_key.h:32-53                              | tx_index keyed by raw txid; no height-keyed alternate path |
| 17 | `DBHashKey` fork-fallback on reorg                                                       | MISSING | db_key.h:55-69, coinstatsindex.cpp:222-225 | no copy-height-to-hash on reorg; no hash-index path |
| 18 | `LookUpOne` height-first then hash-fallback lookup                                       | MISSING | db_key.h:95-113                             | no equivalent; tx_index has only txid key |
| 19 | `BIP30Unspendable` coinbase carve-out in coinstatsindex                                  | MISSING | coinstatsindex.cpp:128-132                  | coinstatsindex absent |
| 20 | Per-coinbase / non-coinbase amount split                                                 | MISSING | coinstatsindex.cpp:147-151                  | gettxoutsetinfo returns only `total_amount` aggregate |
| 21 | Unclaimed rewards accountant                                                             | MISSING | coinstatsindex.cpp:181-188                  | not computed; only spent prevout vs new outputs is unknown |
| 22 | `m_total_subsidy` accumulator                                                            | MISSING | coinstatsindex.cpp:110-111                  | not computed |
| 23 | `SYNC_LOCATOR_WRITE_INTERVAL = 30s` cadence                                              | MISSING | base.cpp:50, base.cpp:254-259               | no cadence; tx_index writes per-tx inline |
| 24 | `f_obfuscate` on index DB                                                                | MISSING | base.h:67-68, base.cpp:68-76                | tx_index CF inherits parent DB obfuscation only |
| 25 | Old `indexes/coinstats` path warning                                                     | N/A     | coinstatsindex.cpp:97-101                   | coinstatsindex absent; nothing to warn about |
| 26 | `txindex_enabled` default                                                                | PARTIAL | DEFAULT_TXINDEX{false} (txindex.h:19)       | beamchain defaults to **true** (`beamchain_config.erl:111-117`) |
| 27 | tx_index column family in same DB as chainstate                                          | PARTIAL | Core gives each index its own DB folder      | beamchain uses CFs of the main RocksDB; ok for I/O but no per-index wipe |
| 28 | `FindTx` reads block header + seeks `nTxOffset`                                          | PARTIAL | txindex.cpp:93-120                          | get_tx_location returns location → caller must reload block + walk vtx |
| 29 | atomic_connect_writes batches tx_index with block + idx in one WriteBatch                | PRESENT | (not a Core concept; beamchain extension)   | beamchain_db.erl:629-655 — *better* than Core, but no rollback symmetry |
| 30 | tx_index CF created on first start (with create_missing_column_families=true)            | PRESENT | (not directly in Core; analogous to LoadBlockIndexDB) | beamchain_db.erl:700-711 |

The "audit-flip" cells are gates 1..28 (24 of them marked MISSING /
PARTIAL); each maps to one or more BUG-N in the next section. The two
PRESENT gates (29, 30) are present-but-shallow: 29 is the atomic
WriteBatch coalescing that's *better* than Core (Core writes via two
separate batch ops), but the rollback symmetry (the matching unwind on
disconnect) is BUG-4. 30 just confirms the CF exists.

---

## Bug catalogue (24 bugs)

### HIGH (6)

**BUG-1 (HIGH)** — No `BaseIndex` shared abstraction. Each prospective
index (tx_index, blockfilter_index, future coinstatsindex) needs its own
private gen_server, locator handling, sync thread, prune-lock integration,
and validation-interface registration. The blockfilter_index implementation
re-derived all of this; the tx_index implementation skipped most of it
(inline writes, no locator, no synced flag, no remove). A coinstatsindex
implementation will re-derive the same scaffolding for the third time,
or skip it for the second time. Fixing this means introducing a
`beamchain_base_index` behaviour with `init/append/commit/remove`
callbacks (analogous to `gen_server` or `gen_statem`'s callback contract)
and refactoring blockfilter_index + tx_index + new coinstatsindex onto it.

**BUG-2 (HIGH)** — No coinstatsindex. `gettxoutsetinfo` re-walks the
chainstate column family on every call (`beamchain_rpc.erl:3192-3213`).
For mainnet at tip (~170M UTXOs as of 2026-05-15), the walk fold takes
multiple minutes wall-clock and is unavailable for historical queries
(`gettxoutsetinfo hash_serialized_3 <blockhash>` returns InvalidParams in
beamchain because the 2nd positional arg is unsupported). Operator
monitoring tools that periodically diff `gettxoutsetinfo` against another
implementation will time out.

**BUG-3 (HIGH)** — txindex stores logical position only. The value
`<BlockHash:32/binary, Height:64/big, Position:32/big>`
(`beamchain_db.erl:991`) lacks the disk position info that lets Core's
`FindTx` seek to one tx without loading the full block. Pathological
case: a 4000-tx block with the target tx at position 3999. Core reads
block header (80 bytes) + 80-byte file seek + ~600-byte tx. beamchain
reads the entire block (~3.99MB), then walks 3999 entries of an Erlang
list (the `lists:nth(Pos+1, Txs)` at `beamchain_rest.erl:816`). Two
orders of magnitude slower per call.

**BUG-4 (HIGH)** — No `remove_tx_index` on disconnect / reorg. The
Pattern-C1 partial fix (read-time active-chain filter via
`confirmations(BlockHeight, BlockHash)` at `beamchain_rpc.erl:4722-4728`)
is a hack: it filters *some* RPC code paths but not (a) the get_tx_location
return value itself (`block_hash` field is stale), (b) any direct
iteration over the tx_index CF, (c) BIP30-replay write races where
the new branch's coinbase has the same txid as a disconnected branch's
tx (Duff'12 historical pair: blocks 91842 and 91880 both had coinbase
txids that collided with older coinbases). On a reorg through those
heights, the order of CustomAppend vs CustomRemove matters for which
position+blockhash survive — and beamchain's lack of CustomRemove means
the *original* (stale) entry stays, even after the new branch's same-txid
write is committed.

**BUG-5 (HIGH)** — No locator persisted. The tx_index CF has no
self-describing "I'm caught up to block X" marker. Cold-start cannot
distinguish "all blocks are indexed" from "blocks N+1..tip are missing"
without iterating the index. In practice beamchain side-steps this by
re-writing on every connect, but the cost is one full re-index of every
block on every cold start. A locator + sync thread would let the index
catch up incrementally without re-touching already-indexed rows.

**BUG-6 (HIGH)** — Genesis-block coinbase indexed. `store_tx_index` is
called from `connect_block` with no height-zero check; the mainnet
genesis coinbase txid `4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b`
ends up in the index with `Height=0, Position=0`. `getrawtransaction
<genesis-txid>` returns it (with `confirmations = tip+1`); Core returns
`-5 No such mempool or blockchain transaction`. This is a two-line
divergence in `beamchain_block_sync.erl:1131-1142` (add a guard
`Height =/= 0`).

### MEDIUM (11)

**BUG-7 (MEDIUM)** — No background sync thread. Core's `BaseIndex::Sync()`
runs in its own `m_thread_sync` with interrupt support; this means an
operator can `-txindex=1` on an already-synced node and the index catches
up *in the background* while the node continues to serve RPC + relay
traffic. beamchain has no such thread — `store_tx_index` runs in the
block-connect critical path (gen_server:call to beamchain_db).
Operationally this means: (a) you cannot turn on `-txindex=1` post-hoc
without manually replaying blocks via reindex, (b) the index-build
cannot proceed in parallel with IBD or block-connect.

**BUG-8 (MEDIUM)** — No `BlockUntilSyncedToCurrentChain` handshake.
Several RPCs in Core (`gettxout`, `getrawtransaction` when the txindex
is the only lookup path) call `BlockUntilSyncedToCurrentChain` before
querying the index, to avoid returning false "not-found" answers
during a fresh index build. beamchain RPCs that consult `tx_index` have
no such gate — during cold-start they will return `No such transaction`
for txns that *are* on-chain but not yet re-written by the foreground
block-connect path.

**BUG-9 (MEDIUM)** — No `getindexinfo` RPC. Core exposes
`getindexinfo ( "index_name" )` returning a JSON object keyed by index
name with `synced` (bool) and `best_block_height` (int). beamchain has
no such RPC, so monitoring scripts cannot probe txindex status — they
have to fall back to "does `getrawtransaction <known-historical-txid>`
return successfully?" which is brittle.

**BUG-10 (MEDIUM)** — No per-index `IndexSummary` struct. Even if a
`getindexinfo` RPC were added today, there is nothing to populate it
from: no `m_synced`, no `m_best_block_index`, no summary record. The
fix here is *blocked* on BUG-1 + BUG-5.

**BUG-11 (MEDIUM)** — No prune lock interaction. Core's `SetBestBlockIndex`
calls `m_blockman.UpdatePruneLock(GetName(), prune_lock)` so that the
pruner respects "this index still needs blocks ≥ Height-N". beamchain's
prune logic in `beamchain_db.erl:prune_block_files` honours
`?REORG_SAFETY_BLOCKS = 288` and nothing else — a `-prune=550` operator
with `-txindex=1` will have the pruner delete blocks that the txindex
read path then cannot find. This produces a silent corruption of the
txindex query path (the row still exists in the CF, but
`beamchain_db:get_block(BlockHash)` → `not_found` → caller surfaces
"not-found" to the RPC client).

**BUG-12 (MEDIUM)** — No `AllowPrune()` per-index policy. Core distinguishes
txindex (must NOT be pruneable; AllowPrune=false) from coinstatsindex
(can be pruneable; AllowPrune=true). beamchain has no per-index policy
because there's no per-index module — the only indexes are tx_index
(inline) and blockfilter_index (which has no prune lock either, separate
bug noted but out of W133 scope).

**BUG-13 (MEDIUM)** — No `CustomInit` consistency check. Core's
`CoinStatsIndex::CustomInit` reads `DB_MUHASH` from the index DB and
compares against the rolling in-memory MuHash; if they diverge, the
index is declared corrupt and the node refuses to start. beamchain has
no analogue, but also no MuHash to check — both sides of the gap are
absent.

**BUG-14 (MEDIUM)** — No `CustomCommit` atomic batching. Core writes
`DB_MUHASH` and `DB_BEST_BLOCK` together in a single batch
(`coinstatsindex.cpp:308-314`, called from `BaseIndex::Commit` at
`base.cpp:270-288`) so that on unclean shutdown the on-disk state is
always consistent: either both updated (post-commit) or neither updated
(pre-commit). beamchain has no Commit lifecycle at all for tx_index, so
this question is moot until a coinstatsindex is added.

**BUG-15 (MEDIUM)** — No `connect_undo_data` / `disconnect_undo_data`
flag. Core's `CustomOptions` lets each index opt into receiving block
undo data (which encodes the spent prevouts as `Coin` structs).
coinstatsindex requires it to subtract spent-output amounts from MuHash.
beamchain's block-connect path *does* compute and store undo data
(`beamchain_db:store_undo`), but there's no index-side hook to consume
it; coinstatsindex (if added) would have to re-fetch undo data from the
DB on every block, which is wasteful.

**BUG-16 (MEDIUM)** — No `SYNC_LOCATOR_WRITE_INTERVAL = 30s` cadence.
Core's sync thread commits the locator every 30s during background sync
(`base.cpp:50, 254-259`). On crash, the index is at most 30s of work
behind. beamchain has no locator at all (BUG-5), so the question of
cadence is moot — but if BUG-5 is fixed, an arbitrary cadence choice
should match Core's 30s default for parity with `-reindex` recovery
times.

**BUG-17 (MEDIUM)** — No `DBHeightKey` big-endian ordering. Core's
`db_key.h:39` writes height as 32-bit big-endian so that LevelDB's
lexicographic iteration produces height-ordered scan results. beamchain's
tx_index CF is keyed by raw txid, which makes height-range scans
impossible — `getrawtransaction` is the only access pattern supported.
Tools like "find all txns between height H1 and H2" would need a separate
secondary index.

**BUG-18 (MEDIUM)** — No `assumeUTXO` interaction. Core's `BaseIndex`
checks the chainstate role (`role.validated`) and only indexes the
background ("IBD") chainstate when a UTXO snapshot is loaded; when the
background catches up, the index is reinitialized. beamchain's
`tx_index` is unaware of W102 assumeUTXO state; if assumeUTXO is loaded,
the foreground block-connect path would index *the snapshot's tip's
descendants only*, missing every tx in the snapshot's ancestry.

### LOW (7)

**BUG-19 (LOW)** — txindex enabled by default. Core defaults to
`DEFAULT_TXINDEX{false}` (`txindex.h:19`); beamchain defaults to
`txindex=1` (`beamchain_config.erl:111-117`, returns true unless the
config or env explicitly disables). For new operators this means
~30-40GB of extra disk usage at mainnet tip that they did not opt into.

**BUG-20 (LOW)** — No `f_obfuscate` on the index DB. Core's
`BaseIndex::DB` ctor accepts an `f_obfuscate` flag (`base.h:67`, passed
through to `CDBWrapper`). When set, each on-disk byte is XOR'd with a
per-DB key so that arbitrary script bytes don't trigger antivirus false
positives (the genesis coinbase contains the Times newspaper headline
in cleartext). beamchain inherits the main RocksDB obfuscation if any
but has no per-CF obfuscation flag.

**BUG-21 (LOW)** — tx_index CF shares the main RocksDB. Core gives
each index its own `indexes/<name>/` LevelDB folder. beamchain
co-locates tx_index in the main RocksDB instance as a column family.
Performance-wise this is fine (and arguably better — shared write
amplification). Operationally it's a regression: there's no way to
`rm -rf indexes/txindex/` to wipe the index and rebuild without
nuking the entire chainstate.

**BUG-22 (LOW)** — `FindTx`-equivalent loads the full block. See BUG-3
for the performance impact. Filed separately because the architectural
fix differs from BUG-3's storage-layout fix: even with logical positions,
caching the most-recent-N decoded blocks would amortize the load cost
for hot txns.

**BUG-23 (LOW)** — No "old indexes/coinstats path" cleanup warning.
Core's `CoinStatsIndex` ctor checks for the pre-v30 `indexes/coinstats`
path and logs a warning to the operator (`coinstatsindex.cpp:97-101`).
beamchain has no coinstatsindex at all so there's nothing to warn
about, but if/when one is added with a different layout from v0, the
same migration courtesy should apply.

**BUG-24 (LOW)** — No `dataflow optimization` reuse between index and
block-connect. Core's `BaseIndex::ProcessBlock` already has the
decoded `CBlock` + `CBlockUndo` in hand; it passes them via
`interfaces::BlockInfo` to `CustomAppend` so the index doesn't re-decode.
beamchain's `store_tx_index` in `beamchain_block_sync.erl:1131` *does*
share the already-decoded block, so this gate is actually PARTIAL —
the integration is correct, but the *future* coinstatsindex would
need to re-fetch undo data because there's no shared `BlockInfo`
analogue.

---

## What a fix wave would touch

The minimum-viable fix wave (call it FIX-86 hypothetically) for the
HIGH bugs:

1. Add `beamchain_base_index` behaviour with `init/0`, `custom_append/1`,
   `custom_remove/1`, `custom_commit/0`, `custom_init/1` callbacks.
2. Move tx_index off the main RocksDB into `indexes/txindex/` and add a
   `remove_tx_index/1` operation called from `do_disconnect_block`.
3. Add genesis carve-out: `Height =/= 0 orelse Pos > 0` in
   `store_tx_index`.
4. Add a locator + `m_synced` flag persistance in a `meta:` row of the
   index DB; wire a background sync thread for cold-start catch-up.
5. Implement coinstatsindex as a new `beamchain_coinstatsindex` module
   under the new `beamchain_base_index` behaviour, with per-height
   MuHash deltas + `DBHeightKey` + `DBHashKey` fork fallback.
6. Wire `getindexinfo` RPC to read the synced + best-block fields.

The full close-out of all 24 bugs is a multi-wave effort. W121 brought
blockfilter_index to Core-parity in a single wave (4 weeks of audit-fix
work); W133 + future coinstatsindex would likely require 2-3 waves of
similar magnitude given the abstraction work (BUG-1) blocks parallel
progress on the other bugs.

Until then: every test in `beamchain_w133_index_tests.erl` documents the
*current* (divergent) behavior, asserts it, and PASSES today. When the
fix lands, those tests FAIL — flipping the gates from MISSING → PRESENT.
