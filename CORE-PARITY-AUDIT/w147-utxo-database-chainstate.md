# W147 — UTXO database / chainstate (CCoinsView + CCoinsViewCache + CCoinsViewDB) (beamchain)

Discovery-only wave.  Audit gates derived from Bitcoin Core references:

- `bitcoin-core/src/coins.h:27-90` — `Coin` (out + 1-bit coinbase + 31-bit
  height, `Serialize` = `VARINT((height<<1)|coinbase) || TxOutCompression(out)`).
- `bitcoin-core/src/coins.h:108-209` — `CCoinsCacheEntry` 4-state machine
  (DIRTY / FRESH / clean / spent) + doubly-linked dirty-list invariant.
- `bitcoin-core/src/coins.cpp:89-130` — `AddCoin` (FRESH iff parent did not
  have an unspent entry; `possible_overwrite` for coinbase / BIP-30).
- `bitcoin-core/src/coins.cpp:153-175` — `SpendCoin` (FRESH-shortcut: erase
  from cache without flushing the deletion to parent).
- `bitcoin-core/src/coins.cpp:208-289` — `BatchWrite` + `Flush` (DIRTY-only
  promotion; cache-erase-after-write semantics).
- `bitcoin-core/src/coins.cpp:310-323` — `Uncache` (evict a single clean
  entry — Core's per-op cache trimmer used by `AcceptToMemoryPool`).
- `bitcoin-core/src/txdb.cpp:23-49` — `DB_COIN='C'` + `CoinEntry`
  `key = 'C' || outpoint.hash || VARINT(outpoint.n)`.
- `bitcoin-core/src/txdb.cpp:100-164` — `CCoinsViewDB::BatchWrite`
  (HEAD_BLOCKS two-phase commit marker for interrupted-flush recovery).
- `bitcoin-core/src/validation.cpp:4778-4838` — `ReplayBlocks`
  (CONSUMES `GetHeadBlocks()` on startup to replay an interrupted flush).
- `bitcoin-core/src/validation.cpp:2704-2860` — `FlushStateToDisk` 4-mode
  matrix (NONE / IF_NEEDED / PERIODIC / FORCE_FLUSH / FORCE_SYNC).
- `bitcoin-core/src/compressor.cpp:55-83` — `CompressScript`
  (P2PKH/P2SH/P2PK as 1-byte tag + 20/32 byte payload).
- `bitcoin-core/src/compressor.cpp:149-166` — `CompressAmount`
  (mantissa+exponent encoding; 1-byte for round sat values).
- `bitcoin-core/src/kernel/coinstats.cpp:45-51` — `TxOutSer`
  (outpoint || uint32((height<<1)|coinbase) || CTxOut — UTXO-set commitment
  per-coin serialization).

Companion audits to cross-reference:

- **W138** (assumeUTXO) — overlaps on `populate_utxo_cache_from_snapshot` +
  `load_snapshot` (see BUG-3 / BUG-7 / BUG-15 below; W138 caught the
  `assumeutxo regtest entry placeholder zero hashes` and `loadtxoutset byte
  order disagrees with dump` but did not exercise the chainstate-level
  FRESH-flag-on-snapshot-load consensus hazard).
- **W107** (chain-tip + flush atomicity) — Pattern D groundwork
  (`pending_undo_deletes` + single-batch reorg commit). W147 confirms the
  Pattern D guarantee but uncovers a parallel gap in the SNAPSHOT path:
  the BaseHash tip is set in ETS only, never persisted by `do_flush` after
  `do_load_snapshot_parse` returns (BUG-15).
- **W145** (subsidy + fees + MAX_MONEY) — `validation:1190-1198` MoneyRange
  check fires on per-coin retrieval. W147 audits the load + cache layer that
  feeds that check.

## Status counts (40 gates)

- **PRESENT** (Core-parity, or internally consistent + Core-compatible): 11
- **PARTIAL** (some piece matches, others diverge or are simplified): 12
- **MISSING** (no equivalent in beamchain): 17

Headline: **26 bugs**, severity distribution
**0 P0-CONSENSUS / 3 P0-CDIV / 0 P0-SEC / 8 P1 / 11 P2 / 4 P3**.

The chainstate gate is dominated by **storage-format divergence** and
**crash-consistency missing-replay**: beamchain commits its on-disk
chainstate-CF in a per-Coin layout that is *byte-incompatible* with Core
(no `'C'` key-prefix, vout as 4-byte big-endian rather than VARINT, no
`obfuscate_key` XOR, no `CompressAmount` / `CompressScript`, no
`VARINT((height<<1)|coinbase)` — flat 8 LE + 4 LE + 1 byte instead).
Independently, beamchain *writes* the `HEAD_BLOCKS` two-phase commit
marker on flush but never *consumes* it at init (no `ReplayBlocks`
equivalent). A power-cycle mid-flush leaves a chainstate whose
UTXO set lags one block behind the persisted chain_tip with no
recovery path other than full reindex.

Two fleet-pattern themes dominate this wave:

1. **Two-pipeline guard 16th distinct extension fleet-wide (3rd in
   beamchain — after W145 subsidy axis and W141 ZMQ socket-per-topic
   axis; now first on the UTXO-set storage axis).**  beamchain exposes
   `beamchain_db:store_utxo/3` + `spend_utxo/2` + `has_utxo/2` via
   `gen_server` (per-call serialized writes through the
   `beamchain_db` process) AND a parallel `beamchain_chainstate`
   path that goes ETS → batched `direct_write_batch/1` (bypasses
   gen_server). Validation uses the chainstate path; the `beamchain_db`
   single-coin path is **DEAD CODE in production** — grep confirms
   only `test/beamchain_db_tests.erl` calls it (lines 176/186/188/197/
   202/841-845/883-884). A divergent edit on either side gives an
   asymmetric UTXO view: an operator running a debug helper through
   `beamchain_db:store_utxo` would write *non-atomically* with the
   chainstate ETS cache, leaving the cache out of sync with the CF.
2. **Dead-helper-at-call-site (5th instance fleet-wide; 1st on the
   chainstate axis).**  `beamchain_chainstate.erl:141` declares a
   `cache_usage_bytes` state field; `:640` initializes it to 0; **no
   other line in the codebase ever reads or writes it** (`grep -n
   cache_usage_bytes` returns exactly those two lines). The
   `maybe_flush` decision uses `cache_memory_usage/0` instead, which
   walks ETS at every call. The state field is pure dead weight,
   mirroring W138's "field exists, never assigned" archetype and W141's
   "function exists + exported + called but no-op" pattern.

Notable cross-cutting smells:

- **No `obfuscate_key`** — Core's `chainstate/` CF is XOR-obfuscated with
  an 8-byte random key written under `'\x0e' + "obfuscate_key"` to dodge
  AV false-positives on script bytes. beamchain stores raw bytes. The
  `beamchain_mempool_persist.erl` module has the right primitive
  ("`XOR-obfuscated by an 8-byte key`") but never extends it to the
  chainstate CF (BUG-2).
- **Comment-as-confession via 294-line REPAIR module**
  (`beamchain_utxo_repair.erl`) — production code that fetches missing
  UTXOs from a running Bitcoin Core RPC endpoint and back-fills them
  into our chainstate. The mere existence of this module is the
  strongest possible confession that the validation pipeline has been
  losing UTXOs at runtime (BUG-21). 4th instance of the comment-as-
  confession fleet pattern in beamchain after W141/W145/W138.
- **No `dbcache` configuration option** — Core exposes `-dbcache=<n>`
  (default 450 MiB) as a single knob that tunes the UTXO-cache
  flush threshold AND the RocksDB block_cache_size. beamchain hardcodes
  256 MiB block_cache + a fixed 450 MiB UTXO cache + 4 GiB IBD cache
  with no per-deployment override.

---

## BUGS

### BUG-1 (P0-CDIV) — Chainstate CF on-disk format byte-incompatible with Core

- **File**: `src/beamchain_db.erl:1326-1334` (encode_outpoint + encode_utxo)
  AND `src/beamchain_db.erl:266` (fold_utxos_loop key match).
- **Core ref**: `bitcoin-core/src/txdb.cpp:23-49` (`DB_COIN='C'` +
  `CoinEntry`); `bitcoin-core/src/coins.h:63-78` (`Coin::Serialize`).
- **Description**: beamchain's chainstate column family layout is
  unrelated to Bitcoin Core's. There are four independent divergences:
  - **(a) no `'C'` key prefix.** Core writes `key = 'C' || hash || VARINT(n)`.
    beamchain writes `key = hash || vout:32/big`. Reading a Core
    `chainstate/` CF with beamchain's parser would silently consume one
    byte of every hash; vice versa.
  - **(b) vout encoded as 4-byte big-endian uint32, not VARINT.** Core's
    VARINT compresses small vouts (every coinbase + most txs) to 1 byte;
    beamchain spends 4 bytes per coin (often 3 bytes of zero).
  - **(c) no `obfuscate_key` XOR.** Core XORs every value with a random
    8-byte key looped to length, stored at `'\x0e' + "obfuscate_key"`.
    beamchain stores raw bytes (BUG-2 traces this to its own line).
  - **(d) value layout is `value:64/little || height:32/little ||
    coinbase:8 || script` instead of `VARINT((height<<1)|coinbase) ||
    VARINT(CompressAmount(value)) || ScriptCompression(scriptPubKey)`.**
    On a typical mainnet UTXO set (~190 M coins), Core averages ~48 bytes
    per Coin while beamchain averages ~75-90 bytes — every UTXO is
    1.5-1.9× bigger on disk.
- **Excerpt**:
  ```erlang
  encode_outpoint(Txid, Vout) ->
      <<Txid:32/binary, Vout:32/big>>.

  encode_utxo(#utxo{value = Value, script_pubkey = Script,
                    is_coinbase = IsCoinbase, height = Height}) ->
      CoinbaseFlag = case IsCoinbase of true -> 1; false -> 0 end,
      <<Value:64/little, Height:32/little, CoinbaseFlag:8, Script/binary>>.
  ```
- **Impact**: (1) Disk size 1.5-1.9× Core for the same UTXO set — on a
  mainnet node that's tens of GiB unnecessary. (2) Snapshot interop
  with `bitcoind` impossible: a Core `chainstate/` directory cannot be
  hot-swapped into beamchain or vice versa. (3) Snapshot-axis fork-in-
  the-road: `beamchain_snapshot.erl` correctly serializes coins with
  `VARINT(code) || VARINT(CompressAmount(value)) || ScriptCompression(...)`
  for the `dumptxoutset` output, but the live chainstate CF stores the
  flat-binary form. The two encodings disagree, and the snapshot writer
  decompresses-from-flat on every coin (a hidden O(N) cost). NOT
  consensus-divergent at the protocol layer (decoding is reversible
  for any pure beamchain → beamchain operation), but a byte-level
  divergence relative to Core that classifies as P0-CDIV per the audit
  framing convention ("compatibility-divergent: nodes built from this
  codebase cannot read the canonical reference format").

### BUG-2 (P0-CDIV) — `obfuscate_key` mechanism absent on chainstate CF

- **File**: `src/beamchain_db.erl:680-708` (open path) — chainstate CF
  created without obfuscate-key initialization.
- **Core ref**: `bitcoin-core/src/dbwrapper.cpp` (`OBFUSCATE_KEY_KEY` =
  `'\x0e' + "obfuscate_key"`, XOR-encode/decode on every read+write).
- **Description**: Core stores the chainstate's leveldb values XOR'd with
  a random 8-byte key looped to length, stored at the well-known key
  `'\x0e' + "obfuscate_key"`. The mechanism is meant to dodge anti-virus
  false-positive scans on script bytes (legitimate UTXOs contain
  byte sequences that look like x86 shellcode patterns or trigger AV
  signature matching).  beamchain stores raw bytes, with no obfuscation
  on the chainstate CF or any other CF.
- **Excerpt**:
  ```erlang
  ChainstateCFOpts = [
      {bloom_filter_policy, 10},
      {optimize_filters_for_hits, true}
  ],
  CFDescriptors = [
      {?CF_DEFAULT, CFOpts},
      ...
      {?CF_CHAINSTATE, ChainstateCFOpts},
      ...
  ],
  case rocksdb:open(DbPath, DbOpts, CFDescriptors) of
      ...
  ```
- **Impact**: AV false-positives on operator machines that mount the
  data directory (common on Windows / corporate Linux deployments).
  Note: `beamchain_mempool_persist.erl:7-8,263` mentions the obfuscation
  pattern as "mirrors Core which seeds via FastRandomContext" — that
  proves beamchain has the primitive on hand for mempool persistence
  but did not generalize it to the chainstate CF. **Dead-helper-at-call-
  site fleet pattern variant**: primitive exists in another module, never
  cross-applied.

### BUG-3 (P0-CDIV) — `populate_utxo_cache_from_snapshot` marks EVERY snapshot coin as DIRTY+FRESH without first wiping the on-disk chainstate CF

- **File**: `src/beamchain_chainstate.erl:2233-2252` (populate path) +
  `:594-619` (init path) + `:2192-2230` (do_load_snapshot_parse path).
- **Core ref**: `bitcoin-core/src/coins.h:150-163` (FRESH invariant) +
  `bitcoin-core/src/validation.cpp:5588-5883` (ActivateSnapshot /
  PopulateAndValidateSnapshot, which constructs a SEPARATE chainstate
  with an empty backing view).
- **Description**: Core's `assumeutxo` snapshot loader creates a
  brand-new `CCoinsViewDB` for the snapshot in a dedicated
  `chainstate_snapshot/` subdir (separate column family), so the
  snapshot chainstate's "parent" backing view is provably empty.
  Only then is it safe to mark every coin FRESH — the FRESH-shortcut
  optimization (`SpendCoin` on a FRESH cache entry erases without
  scheduling a parent delete) relies on the parent's emptiness as an
  invariant.  beamchain's `populate_utxo_cache_from_snapshot/1`:
  1. Clears the ETS caches (`UTXO_CACHE`, `UTXO_DIRTY`, `UTXO_FRESH`,
     `UTXO_SPENT`) but **NOT** the RocksDB chainstate CF.
  2. Re-inserts each snapshot coin into ETS marked DIRTY + FRESH.
  Because the on-disk chainstate CF was NOT wiped, the snapshot coins
  marked FRESH could collide with pre-existing on-disk entries from a
  prior (truncated) IBD attempt.  If one of those pre-existing entries
  is spent before the next flush, the FRESH-shortcut path
  (`spend_utxo/2:524-528`) deletes from ETS-only and **skips the
  RocksDB delete**.  The stale on-disk entry becomes a ghost that
  resurrects on next cache miss → double-spend / consensus split when
  the same coin is "spent" twice (once via the FRESH-shortcut, once
  via a subsequent block that legitimately spends the resurrected
  ghost).
- **Excerpt**:
  ```erlang
  populate_utxo_cache_from_snapshot(Coins) ->
      %% Clear existing cache entries
      ets:delete_all_objects(?UTXO_CACHE),
      ets:delete_all_objects(?UTXO_DIRTY),
      ets:delete_all_objects(?UTXO_FRESH),
      ets:delete_all_objects(?UTXO_SPENT),

      %% Insert all coins from snapshot
      lists:foreach(fun({Txid, Vout, Utxo}) ->
          Key = {Txid, Vout},
          ets:insert(?UTXO_CACHE, {Key, Utxo}),
          %% Mark as DIRTY so they get flushed to RocksDB
          ets:insert(?UTXO_DIRTY, {Key}),
          %% Mark as FRESH since they don't exist in RocksDB yet
          ets:insert(?UTXO_FRESH, {Key})
      end, Coins),
      ...
  ```
- **Impact**: P0-CDIV on the assumeutxo path. The bug only fires when
  `do_load_snapshot` is invoked on a node that previously ran partial
  IBD (any node that has been running and got partway before the
  operator decided to use assumeUTXO to skip ahead). For a fresh
  install with an empty chainstate CF, the issue is dormant. The
  symptom is silent UTXO-set divergence from Core at the next reorg
  affecting any of the colliding txids.

### BUG-4 (P1) — `direct_atomic_connect_writes` writes block data + index + tx_index to RocksDB BEFORE the corresponding UTXO state lands; a crash in the gap produces an inconsistent chainstate

- **File**: `src/beamchain_chainstate.erl:966-993` (do_connect_block_inner)
  AND `src/beamchain_db.erl:627-655` (direct_atomic_connect_writes).
- **Core ref**: `bitcoin-core/src/validation.cpp:2704-2860`
  (FlushStateToDisk; block data, undo data, and chainstate ALL flushed
  in a single atomic batch through `FlushChainstateBlockFile` +
  `BatchWrite`).
- **Description**: beamchain's connect-block sequence is:
  1. `beamchain_validation:connect_block` updates ETS UTXO cache.
  2. `direct_atomic_connect_writes` writes block + block_index +
     tx_index entries to RocksDB (in ONE WriteBatch, with the success-
     state-mask `BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO`).
  3. ETS `?CHAIN_META` is updated.
  4. `maybe_flush` may or may not trigger — IBD interval = 5000 blocks,
     so for 4999/5000 blocks no flush happens.
  Between steps 2 and the next flush, the block + index entries exist
  on disk but the UTXO mutations exist only in ETS. A crash in this
  window leaves a chainstate where `block_index` claims height N is
  fully validated (BLOCK_VALID_SCRIPTS set) and the block body is
  written, but the UTXO set on disk still reflects height N-1 (or
  earlier, depending on flush cadence).  On restart, `load_chain_tip`
  returns height N from the meta CF (only written on flush), so the
  in-memory tip is N-1; but the block_index says height N is also
  valid + has data + has undo.
- **Excerpt** (`beamchain_chainstate.erl:965-981`):
  ```erlang
  ConnectStatus = ?BLOCK_VALID_SCRIPTS bor ?BLOCK_HAVE_DATA bor ?BLOCK_HAVE_UNDO,
  ok = beamchain_db:direct_atomic_connect_writes(
           Block, Height, NewCW, BlockHash, ConnectStatus),
  ets:insert(?CHAIN_META, {tip, BlockHash, Height}),
  NewMTP = update_mtp_connect(...),
  BlocksSinceFlush = State#state.blocks_since_flush + 1,
  State2 = State#state{
      tip_hash = BlockHash,
      tip_height = Height,
      ...
  },
  ```
- **Impact**: Crash-recovery hazard. Core handles this via the
  `HEAD_BLOCKS` two-phase commit + `ReplayBlocks` on startup. beamchain
  writes the marker (BUG-5 covers that) but never replays it, so the
  inconsistency is unrecoverable without a manual reindex.

### BUG-5 (P0-CDIV) — `HEAD_BLOCKS` two-phase commit marker is WRITTEN on every flush but NEVER CONSUMED at startup; no `ReplayBlocks` equivalent

- **File**: `src/beamchain_chainstate.erl:1902-1907` (writes the marker)
  AND `src/beamchain_chainstate.erl:1919` (CLEARS the marker on success)
  AND `src/beamchain_chainstate.erl:566-666` (init_chainstate — no
  HEAD_BLOCKS read).
- **Core ref**: `bitcoin-core/src/txdb.cpp:100-164`
  (`CCoinsViewDB::BatchWrite` writes `DB_HEAD_BLOCKS` BEFORE the data,
  CLEARS it AFTER); `bitcoin-core/src/validation.cpp:4778-4838`
  (`ReplayBlocks` consumes `GetHeadBlocks()` on startup, fails-fast
  with "you will need to restart with -reindex-chainstate" if heads
  size != 2 + replays the partial commit if exactly 2).
- **Description**: beamchain's flush path:
  ```erlang
  AllOps = Ops ++ UndoDeleteOps ++ [
      {put, meta, <<"chain_tip">>, TipValue},
      {put, meta, <<"utxo_flush_height">>, <<TipHeight:64/big>>},
      {put, meta, <<"HEAD_BLOCKS">>, Marker}
  ],
  case beamchain_db:direct_write_batch(AllOps) of
      ok ->
          ets:delete_all_objects(?UTXO_DIRTY),
          ets:delete_all_objects(?UTXO_FRESH),
          ets:delete_all_objects(?UTXO_SPENT),
          %% Clear crash recovery marker (best-effort, not critical)
          beamchain_db:put_meta(<<"HEAD_BLOCKS">>, <<>>),
          ...
  ```
  Notice the marker is written THEN cleared in TWO separate writes (the
  bulk batch + a second `put_meta`). That's a regression of Core's
  invariant: Core writes the marker in the FIRST sub-batch and clears
  it in the LAST sub-batch of the SAME atomic flush (txdb.cpp:128-159).
  Worse, beamchain's `init_chainstate/2` never calls
  `get_meta(<<"HEAD_BLOCKS">>)`. There is no equivalent of `ReplayBlocks`.
  So:
  - Operator-friendly path: marker is silently cleared after a clean
    flush. No harm.
  - Crash path: marker is left present with `{from_block, to_block}`
    binary. Beamchain restarts, ignores the marker, loads
    `chain_tip` which already pointed to `to_block` (because the meta
    CF includes the tip in the same batch). The UTXO mutations may or
    may not have committed depending on RocksDB's WAL state.
- **Excerpt**: see Description.
- **Impact**: Core-grade two-phase commit protocol is silently broken.
  The marker is dead-write — never read. Reindex-from-scratch is the
  only recovery path after a power-cycle mid-flush, even though the
  scaffolding for a 1-batch replay is 90% present.

### BUG-6 (P1) — `direct_write_batch/1` and `direct_atomic_connect_writes/5` use empty WriteOptions `[]` (no `{sync, true}`); UTXO mutations are buffered in OS page cache

- **File**: `src/beamchain_db.erl:614,655,1028,1057` (all 4 production
  RocksDB write sites use `[]` options).
- **Core ref**: `bitcoin-core/src/validation.cpp:2820-2850`
  (`FlushStateToDisk` with `SYNC_NEEDED` / `FORCE_SYNC` passes `fsync=true`
  to `LevelDB::Write` for the chainstate flush).
- **Description**: All chainstate flushes go through `rocksdb:write(Db,
  Ops, [])`. With empty options, RocksDB defaults to async writes — the
  WriteBatch is durable to the WAL on disk only after the OS page-cache
  flushes (typically up to 30 s on Linux's default `dirty_expire_centisecs`).
  A power-cycle within that window can lose acknowledged flushes. Only
  the chainstate WIPE path uses `{sync, true}` (`:364`):
  ```erlang
  case rocksdb:delete_range(Db, CF, BeginKey, EndKey, [{sync, true}]) of
  ```
  Inversion: the path most operators will rarely run synchronously
  is sync-safe, but the every-5000-blocks production flush is not.
- **Excerpt**:
  ```erlang
  direct_write_batch(Ops) ->
      Db = persistent_term:get(beamchain_db_handle),
      WriteActions = lists:map(fun(Op) -> resolve_direct_batch_op(Op) end, Ops),
      rocksdb:write(Db, WriteActions, []).   %% NO {sync, true}
  ```
- **Impact**: Compounds with BUG-5. Crash within ~30 s of a successful
  do_flush can lose the entire flush despite the gen_server having logged
  "flushed at height N" — and there is no HEAD_BLOCKS replay to detect
  the inconsistency on next start.

### BUG-7 (P1) — `do_load_snapshot_parse` returns without flushing the loaded snapshot; restart-before-next-block loses the entire snapshot

- **File**: `src/beamchain_chainstate.erl:2204-2221` (do_load_snapshot_parse
  return path).
- **Core ref**: `bitcoin-core/src/validation.cpp:5879-5895`
  (`ActivateSnapshot` calls `m_chainman.MaybeRebalanceCaches()` →
  `Chainstate::FlushStateToDisk(FORCE_FLUSH)` before returning).
- **Description**: After `populate_utxo_cache_from_snapshot/1` puts
  hundreds of millions of coins into ETS marked DIRTY+FRESH, the
  load_snapshot handle_call returns the new State directly. The next
  flush trigger is either (a) ibd-tick reaches 5000 connect_blocks
  (`?IBD_FLUSH_INTERVAL`), or (b) cache exceeds the 8 M entry high-water
  mark, or (c) `flush/0` is called by some other path, or (d) terminate
  runs on a clean shutdown. None of those is guaranteed within the next
  N minutes. A crash in the gap = full snapshot lost; on restart, the
  ETS tables are empty, `load_chain_tip` returns whatever pre-snapshot
  tip was persisted (or `undefined`), and the snapshot data on the file
  system was never imported.
- **Excerpt**: see Read of `do_load_snapshot_parse/6`.
- **Impact**: Operator UX hazard. The `loadtxoutset` RPC returns
  `{"coins_loaded": N, "tip_height": N, "base_height": N}` indicating
  success, but a Ctrl-C / SIGTERM before the next 5000 blocks of headers
  catch up silently discards the entire load. Compounds with BUG-3 if
  the operator's prior chainstate CF was non-empty.

### BUG-8 (P0-CDIV) — `init_chainstate/2` proceeds when the snapshot's `base_hash` is not in the chain_params assumeutxo whitelist (logs warning, then uses height=0)

- **File**: `src/beamchain_chainstate.erl:599-605` (init_chainstate
  snapshot branch).
- **Core ref**: `bitcoin-core/src/validation.cpp:5616-5621`
  (`ActivateSnapshot`: if base_blockhash not in
  `m_chainman.GetParams().AssumeutxoForBlockhash(...)`, return
  `error{"unknown snapshot base"}`).
- **Description**: Core rejects any snapshot whose `base_blockhash` is
  not pre-listed in the network's hard-coded assumeutxo data. beamchain's
  RPC entry path (`do_load_snapshot_inner:2142-2150`) DOES enforce this
  whitelist with `get_assumeutxo_by_hash → not_found → unknown_snapshot_base`.
  But the `init_chainstate(snapshot, SnapshotData)` constructor path is
  separately reachable (`start_link(snapshot, SnapshotData)`) and DOES
  NOT enforce the whitelist — `not_found` falls through to:
  ```erlang
  not_found ->
      logger:warning("chainstate: unknown snapshot base hash"),
      {BaseHash, 0, 0, BaseHash}
  ```
  with height = 0. So a programmatic loader that bypasses the RPC entry
  silently accepts an unknown snapshot and pretends the tip is height 0
  — which then enables the entire FRESH-shortcut machinery (BUG-3) plus
  the missing-wipe hazard, all keyed off an attacker-supplied
  `base_hash`.
- **Excerpt**: see Read of `init_chainstate/2`.
- **Impact**: P0-CDIV. The two-pipeline guard for the assumeUTXO load is
  asymmetric: the RPC pipeline rejects unknown hashes, the
  `start_link(snapshot, ...)` pipeline accepts them with height=0.

### BUG-9 (P1) — `fold_utxos/2` (the cursor analog) iterates the live CF without snapshot semantics; concurrent flushes can produce inconsistent fold results

- **File**: `src/beamchain_db.erl:245-258` (fold_utxos).
- **Core ref**: `bitcoin-core/src/txdb.cpp:194-211` (CCoinsViewDB::Cursor:
  pins `GetBestBlock()` at cursor creation; ensures the iterator
  represents a consistent snapshot of the UTXO set at one block).
- **Description**: Core's `Cursor` API binds a `GetBestBlock` hash AT
  creation time and uses LevelDB's snapshot-iteration semantics so the
  walk is consistent. beamchain's `fold_utxos/2` opens the iterator with
  `rocksdb:iterator(Db, CF, [])` — no `{snapshot, true}` option, no
  `read_snapshot` capture — and never associates the walk with a chain
  tip.  Any concurrent `direct_write_batch` from the chainstate
  gen_server inserts/deletes mid-iteration; the walker sees a mishmash
  of pre-flush and post-flush coins. This breaks consumers like
  `compute_utxo_hash` and `gettxoutsetinfo` that rely on
  point-in-time consistency for the hash to be meaningful.
- **Excerpt**:
  ```erlang
  fold_utxos(Fun, Acc0) when is_function(Fun, 2) ->
      Db = persistent_term:get(beamchain_db_handle),
      CF = persistent_term:get(beamchain_cf_chainstate),
      case rocksdb:iterator(Db, CF, []) of    %% no snapshot option
          {ok, Iter} ->
              try
                  fold_utxos_loop(rocksdb:iterator_move(Iter, first), Iter,
                                  Fun, Acc0)
              ...
  ```
- **Impact**: P1 race. `compute_utxo_hash_from_list/1` (mostly called
  on demand from RPC `gettxoutsetinfo`) is the highest-impact consumer.
  A flush mid-walk produces a hash that no Core node would compute.
  Mitigated by `collect_all_utxos/0:856-866` calling `flush/0` first —
  but only the OPENING flush is synchronized; further flushes mid-walk
  are not blocked.

### BUG-10 (P1) — No `Uncache` equivalent for single-coin eviction; mempool-validation cache misses inflate the cache for the entire IBD/normal cycle

- **File**: `src/beamchain_chainstate.erl:73-77` (exports).
- **Core ref**: `bitcoin-core/src/coins.cpp:310-323` (`CCoinsViewCache::Uncache`,
  called in `AcceptToMemoryPool` on a transaction that failed mempool
  validation to evict the speculatively-pulled prevouts).
- **Description**: Core's `Uncache` evicts a clean (non-DIRTY) entry
  from the cache. It's called specifically when `AcceptToMemoryPool`
  pulls a UTXO from disk to validate a tx, the tx then fails (e.g.
  bad script, missing inputs, conflicting RBF), and we want to drop the
  speculative coin to keep the cache bounded. Without it, every failed
  mempool insertion leaves a memory footprint until the next bulk
  `maybe_evict_cache` (high-water = 8 M entries; on a quiet testnet4
  this can take days).
- **Excerpt**: N/A — function does not exist.
- **Impact**: Memory bloat on a node receiving lots of invalid txs (a
  natural DoS / churn vector). Core's defense-in-depth missing here.

### BUG-11 (P1) — No `FlushStateMode::PERIODIC` (time-based flush); flush only fires on block-count threshold or memory pressure

- **File**: `src/beamchain_chainstate.erl:1842-1859` (maybe_flush).
- **Core ref**: `bitcoin-core/src/validation.cpp:2768`
  (`fPeriodicWrite = mode == FlushStateMode::PERIODIC && nNow >= m_next_write`)
  + `2704-2750` (`m_next_write` set to `now + DATABASE_WRITE_INTERVAL` =
  60 min on every successful flush).
- **Description**: Core flushes at three trigger axes: (a) cache
  pressure (LARGE/CRITICAL), (b) block count, (c) **time elapsed since
  last flush** (default 1 hour). beamchain has (a) and (b) but no (c).
  Symptom: a node sitting at the tip on testnet4 (no new blocks for
  hours) with a small but non-zero dirty UTXO set (from
  mempool-evicted-by-block transactions) will never flush. A crash
  drops those mutations on restart and the chainstate replays the same
  blocks again from the last-flushed tip. On mainnet this is rarer
  (blocks every 10 min); on regtest / quiet testnet4 / IBD-completed-
  but-no-blocks, the gap can be hours.
- **Excerpt**:
  ```erlang
  maybe_flush(#state{ibd = true, blocks_since_flush = N} = State)
    when N >= ?IBD_FLUSH_INTERVAL ->                       %% (b)
      do_flush(State);
  maybe_flush(#state{ibd = false, max_cache_bytes = MaxBytes,
                      max_cache_entries = MaxEntries} = State) ->
      CacheEntries = ets:info(?UTXO_CACHE, size),
      CacheBytes = cache_memory_usage(),
      case CacheEntries > MaxEntries orelse CacheBytes > MaxBytes of  %% (a)
          true ->
              ...do_flush(State);
          false ->
              State
      end;
  maybe_flush(State) ->
      State.
  %% no time-based branch
  ```
- **Impact**: Wider crash-recovery gap, especially relevant on
  testnet4 or post-IBD nodes that aren't writing for hours.

### BUG-12 (P0-CDIV) — `cache_memory_usage/0` ignores the per-Coin script size; cache size estimate diverges from Core's `DynamicMemoryUsage`

- **File**: `src/beamchain_chainstate.erl:2074-2083`.
- **Core ref**: `bitcoin-core/src/coins.h:87-89` (`Coin::DynamicMemoryUsage`
  returns `memusage::DynamicUsage(out.scriptPubKey)`) + `coins.cpp:59-61`
  (`CCoinsViewCache::DynamicMemoryUsage` = unordered_map overhead +
  `cachedCoinsUsage`).
- **Description**: beamchain's accounting uses ETS table memory only:
  ```erlang
  cache_memory_usage() ->
      WordSize = erlang:system_info(wordsize),
      CacheMem = ets:info(?UTXO_CACHE, memory) * WordSize,
      DirtyMem = ets:info(?UTXO_DIRTY, memory) * WordSize,
      FreshMem = ets:info(?UTXO_FRESH, memory) * WordSize,
      SpentMem = ets:info(?UTXO_SPENT, memory) * WordSize,
      CacheMem + DirtyMem + FreshMem + SpentMem.
  ```
  `ets:info(_, memory)` returns the table-overhead estimate but does
  NOT include the *heap-allocated payload* of each `#utxo{}` record
  (specifically the `script_pubkey` binary, which for OP_RETURN /
  inscriptions can be 1-83 KiB per coin).  Core explicitly tracks
  `cachedCoinsUsage = sum_over_coins(out.scriptPubKey.alloc())` and
  uses it in the cache-size-state machine.  beamchain's estimate
  systematically *under*-counts on inscription-heavy testnets and
  signets where the per-coin script payload dominates the ETS
  overhead.
- **Excerpt**: see Description.
- **Impact**: The `max_cache_bytes` ceiling (4 GiB IBD, 450 MiB post-IBD)
  is computed against a misleading number, so the real cache memory
  on, say, an inscription-heavy testnet block can be 5-10× the
  reported size. Risk of OOM on memory-constrained nodes.

### BUG-13 (P1) — `wipe_chainstate/0` is non-atomic across ETS + RocksDB + meta-tip writes; crash mid-wipe leaves a partially-wiped state with stale UTXOs

- **File**: `src/beamchain_chainstate.erl:729-756` (wipe_chainstate
  handle_call) + `src/beamchain_db.erl:354-379` (clear_chainstate_cf).
- **Core ref**: N/A — Core's equivalent (-reindex-chainstate) does this
  via a single `LevelDB::Erase` of the entire `chainstate/` dir under a
  lock, then exits and requires a manual restart.
- **Description**: The wipe sequence is:
  1. `ets:delete_all_objects(?UTXO_CACHE)` (×4 for cache/dirty/fresh/spent)
  2. `ets:delete_all_objects(?CHAIN_META)`
  3. `beamchain_db:clear_chainstate_cf()` (sync delete-range, sync=true)
  4. `beamchain_db:put_meta(<<"chain_tip">>, <<>>)`
  5. `beamchain_db:put_meta(<<"utxo_flush_height">>, <<>>)`
  Steps 1-2 are O(1) ETS ops, step 3 is potentially minutes on a multi-
  GiB chainstate, steps 4-5 are independent `put_meta` gen_server calls.
  A crash:
  - After step 2 / before step 3 → ETS empty but DB still has 100% of
    the old UTXOs. Restart re-loads the chain_tip pointer (still old);
    UTXOs are still on disk; ETS is empty; first connect_block tries
    to BIP30-check `has_utxo` and gets the old data. Confusing but not
    fatal.
  - After step 3 / before step 4 → ETS empty, DB chainstate empty, but
    `chain_tip` in meta CF still points at some old tip. Restart sees
    the tip but `has_utxo` returns `not_found` for everything →
    `missing_inputs` on every spend → chain stalls.
- **Excerpt**: see Read of `handle_call(wipe_chainstate, ...)`.
- **Impact**: Manual recovery only. Wipe is a rare path
  (operator-invoked) but the operator's expectation is that "wipe"
  leaves a consistent reindex-ready state — and it doesn't.

### BUG-14 (P1) — `do_flush` writes `HEAD_BLOCKS` and then clears it in a SEPARATE `put_meta` call (not in the same atomic batch)

- **File**: `src/beamchain_chainstate.erl:1900-1924`.
- **Core ref**: `bitcoin-core/src/txdb.cpp:128-159` (HEAD_BLOCKS
  written by `batch.Write` in the FIRST sub-batch, ERASED by
  `batch.Erase` in the LAST sub-batch, both inside the SAME
  `m_db->WriteBatch(batch)` atomic commit).
- **Description**: beamchain interleaves the marker write inside the
  bulk WriteBatch (good) but the marker clear is done OUTSIDE the
  WriteBatch via `beamchain_db:put_meta(<<"HEAD_BLOCKS">>, <<>>)`
  (single put through the gen_server). A crash between the WriteBatch
  return and the put_meta leaves a `HEAD_BLOCKS` marker on disk pointing
  to the now-committed `(NewTip, OldTip)` — exactly the case Core's
  protocol expects to TRIGGER a replay. Since beamchain never replays
  (BUG-5), the orphaned marker is dead weight, but it would actively
  mislead any future replay code.
- **Excerpt**:
  ```erlang
  AllOps = Ops ++ UndoDeleteOps ++ [
      {put, meta, <<"chain_tip">>, TipValue},
      {put, meta, <<"utxo_flush_height">>, <<TipHeight:64/big>>},
      {put, meta, <<"HEAD_BLOCKS">>, Marker}        %% IN batch
  ],
  case beamchain_db:direct_write_batch(AllOps) of
      ok ->
          ets:delete_all_objects(?UTXO_DIRTY),
          ets:delete_all_objects(?UTXO_FRESH),
          ets:delete_all_objects(?UTXO_SPENT),
          %% Clear crash recovery marker (best-effort, not critical)
          beamchain_db:put_meta(<<"HEAD_BLOCKS">>, <<>>),    %% OUT of batch
  ```
  The comment "best-effort, not critical" is itself an instance of
  the **comment-as-confession fleet pattern** (the marker is supposed
  to be one of the most safety-critical writes in the codebase).
- **Impact**: Stale marker persisted on crash; would be benign today
  but malicious to any future ReplayBlocks.

### BUG-15 (P2) — `verify_flush_sample/0` logs but does not signal corruption; "FLUSH VERIFICATION FAILED" is a debug breadcrumb at best

- **File**: `src/beamchain_chainstate.erl:1972-2014`.
- **Core ref**: N/A — Core does not have a sampled flush-verification
  pass; it relies on LevelDB's WriteBatch durability contract +
  `HEAD_BLOCKS` replay.
- **Description**: After every flush, beamchain reads 10 entries from
  ETS and checks they exist in RocksDB via `beamchain_db:has_utxo`.
  On mismatch it logs `chainstate: FLUSH VERIFICATION FAILED: K/10
  entries NOT in RocksDB after flush!` and continues. The flushing
  state is NOT marked corrupt, the gen_server does NOT crash, no
  notification is sent. An operator who is not watching logs will
  miss the failure. Worse: a sample size of 10 vs a cache size of
  millions means the test catches `~0%` of partial-flush bugs.
- **Excerpt**:
  ```erlang
  NewFailures = case InDb of
      true -> Failures;
      false ->
          logger:error("chainstate: MISSING from RocksDB after flush: "
                       "~s:~B", [..., Vout]),
          Failures + 1
  end,
  ...
  verify_flush_entries('$end_of_table', _Remaining, Checked, Failures, _Total) ->
      case Failures > 0 of
          true ->
              logger:error("chainstate: FLUSH VERIFICATION FAILED: ..."),
          false -> ok
      end;
  ```
- **Impact**: Diagnostic only; gives false confidence that the verifier
  catches anything meaningful.

### BUG-16 (P2) — `beamchain_db:store_utxo/3` and `spend_utxo/2` are DEAD CODE in production (called only from `test/`)

- **File**: `src/beamchain_db.erl:25,200-207,873-900` (declarations +
  gen_server handlers).
- **Core ref**: N/A — Core doesn't have this two-pipeline split.
- **Description**: The `beamchain_db` gen_server exposes per-coin
  `store_utxo/3`, `spend_utxo/2`, `has_utxo/2` (and indirectly
  `get_utxo/2`). Grep for callers in `src/`:
  ```
  $ grep -rn 'beamchain_db:store_utxo\|beamchain_db:spend_utxo' src/
  (no results)
  ```
  All production sites go through `beamchain_chainstate:add_utxo` /
  `spend_utxo` → ETS → batched `direct_write_batch` on flush. The
  `beamchain_db` per-coin path is only invoked from `test/beamchain_db_tests.erl`
  (12 lines). This is the **fleet-pattern two-pipeline guard 16th
  distinct extension**: storage-axis split between the through-gen_server
  per-coin path (dead) and the direct-write-batch path (live).
- **Excerpt**:
  ```erlang
  -export([get_utxo/2, store_utxo/3, spend_utxo/2, has_utxo/2]).
  ...
  handle_call({store_utxo, Txid, Vout, Utxo}, _From, ...) ->
      Key = encode_outpoint(Txid, Vout),
      Value = encode_utxo(Utxo),
      Result = rocksdb:put(Db, CF, Key, Value, []),
      {reply, Result, State};
  ```
- **Impact**: Maintenance hazard. The gen_server path has subtly
  different concurrency semantics (serialized through the gen_server
  vs concurrent ETS writes on the production path) and ANY future
  code that accidentally calls through it will write non-atomically
  with the chainstate ETS cache. The dead path also has no FRESH-flag
  tracking, no IsUnspendable filter (BUG-17), and an asymmetric
  spend_utxo that reads-then-deletes in two non-batched ops
  (`:889-900`).

### BUG-17 (P2) — `beamchain_db:store_utxo/3` does NOT apply the IsUnspendable filter; OP_RETURN coins persisted through the dead-path land on disk

- **File**: `src/beamchain_db.erl:873-878` (handle_call(store_utxo)).
- **Core ref**: `bitcoin-core/src/coins.cpp:91`
  (`if (coin.out.scriptPubKey.IsUnspendable()) return;` — drops
  unspendable outputs before they enter the chainstate).
- **Description**: The chainstate path (`add_utxo/3:421-428`) filters
  unspendable outputs via `is_unspendable_script(SPK)`. The dead-path
  `beamchain_db:store_utxo/3` does not — every byte sequence is
  persisted directly. Even though this path is dead (BUG-16), its
  presence is the kind of trap that catches future maintainers.
- **Excerpt**:
  ```erlang
  handle_call({store_utxo, Txid, Vout, Utxo}, _From,
              #state{db_handle = Db, cf_chainstate = CF} = State) ->
      Key = encode_outpoint(Txid, Vout),
      Value = encode_utxo(Utxo),
      Result = rocksdb:put(Db, CF, Key, Value, []),
      {reply, Result, State};
  ```
- **Impact**: Latent. Becomes active any time a future call site uses
  the dead path. The `scrub_unspendable/0` operator helper exists
  (BUG-21 cross-cite) precisely because earlier versions of beamchain
  did persist unspendable coins.

### BUG-18 (P2) — `cache_usage_bytes` state field is declared and initialized but NEVER ASSIGNED ANYWHERE in the codebase

- **File**: `src/beamchain_chainstate.erl:141,640` (only two references).
- **Core ref**: N/A — Core uses `cachedCoinsUsage` which is mutated on
  every AddCoin / SpendCoin / FetchCoinFromBase (coins.cpp:73,117,157,
  252,256,264,313).
- **Description**:
  ```
  $ grep -n cache_usage_bytes src/beamchain_chainstate.erl
  141:    cache_usage_bytes :: non_neg_integer(),
  640:        cache_usage_bytes = 0,
  ```
  The field is in the `#state{}` record, initialized to `0` in
  `init_chainstate/2`, and **never read or written again** in the
  entire file. The `maybe_flush` decision uses `cache_memory_usage/0`
  (which walks ETS at every call) instead.  This is the
  **dead-helper-at-call-site fleet pattern, 5th instance** — a field
  added with intent but plumbing never completed.
- **Excerpt**: see Description (the entire usage surface).
- **Impact**: Dead weight in the record. Removing it would simplify
  the state.

### BUG-19 (P2) — `add_utxo/3` BIP-30 path does a per-coin RocksDB lookup; cold path is O(num_outputs × log(N)) instead of O(num_outputs)

- **File**: `src/beamchain_chainstate.erl:430-462`.
- **Core ref**: `bitcoin-core/src/coins.cpp:89-130` (`AddCoin` takes a
  `possible_overwrite` flag from the CALLER, who knows whether the
  outpoint can collide; no per-coin DB lookup).
- **Description**: beamchain inverts Core's contract. Instead of
  letting the caller pass `possible_overwrite` (true only for coinbase
  outputs / BIP-30 exceptions), `add_utxo/3` always does a
  `has_utxo(Txid, Vout)` check that may hit RocksDB:
  ```erlang
  AlreadyInDb = case ets:member(?UTXO_CACHE, Key) of
      true ->
          not ets:member(?UTXO_FRESH, Key);
      false ->
          case ets:member(?UTXO_SPENT, Key) of
              true -> true;
              false -> beamchain_db:has_utxo(Txid, Vout)
          end
  end,
  ```
  The DB hit is the slow path. On IBD cold-cache, this is
  ~hundreds of microseconds per output, summing to seconds per block.
  The fast-path equivalent (`add_utxo_fresh/3:471-482`) IS provided
  and IS used by `connect_block` (`validation:1272,1327`) — so the
  slow path fires only in the disconnect/rollback path
  (`validation:1398,1850`).  Lookup is not consensus-incorrect, just
  slow under load.
- **Excerpt**: see Description.
- **Impact**: Per-rollback latency. On a deep reorg, every undo entry
  triggers the cold-cache lookup.

### BUG-20 (P2) — ETS `?UTXO_DIRTY` / `?UTXO_FRESH` / `?UTXO_SPENT` writes are not atomic against `?UTXO_CACHE` writes; a race window between the two inserts

- **File**: `src/beamchain_chainstate.erl:449-461` (do_add_utxo) +
  `:476-481` (add_utxo_fresh) + `:519-535` (spend_utxo).
- **Core ref**: `bitcoin-core/src/coins.cpp:120-122` (a single
  `CCoinsCacheEntry::SetDirty` mutates the cache entry + the
  linked-list flags atomically per coin).
- **Description**: Each insert in beamchain is split:
  ```erlang
  ets:insert(?UTXO_CACHE, {Key, Utxo}),
  ets:insert(?UTXO_DIRTY, {Key}),
  case AlreadyInDb of
      true ->
          ets:delete(?UTXO_FRESH, Key);
      false ->
          ets:insert(?UTXO_FRESH, {Key})
  end,
  ets:delete(?UTXO_SPENT, Key),
  ```
  Between any two of those ops, a concurrent reader sees a partial
  state. The chainstate gen_server is the only flush-trigger, so a
  reader from another process (e.g. a parallel script-verify worker)
  could see `?UTXO_CACHE` populated but `?UTXO_DIRTY` missing. The
  cache will eventually catch up at the next ETS op, but a flush that
  fires in that exact window would skip the new entry.
- **Excerpt**: see Description.
- **Impact**: Low likelihood (the chainstate gen_server is the
  serialized writer for connect_block), but exists in the disconnect
  + reorg paths where validation and chainstate cooperatively mutate
  the tables. No known reproducer.

### BUG-21 (P1) — `beamchain_utxo_repair.erl` exists as production code that fetches missing UTXOs from a running Bitcoin Core RPC instance — the strongest comment-as-confession in the codebase

- **File**: `src/beamchain_utxo_repair.erl` (entire 294-LOC module).
- **Core ref**: N/A — Core does not have a "fetch from another node's
  RPC" repair tool. If chainstate gets corrupted, the answer is
  `-reindex-chainstate`.
- **Description**: Module header:
  ```erlang
  %% @doc Check all input UTXOs for a block and report missing ones.
  %% Uses Bitcoin Core RPC to fetch the creating transaction's output details
  %% and adds missing UTXOs to the chainstate.
  %%
  %% Usage from remote shell:
  %%   beamchain_utxo_repair:repair_for_block(399870).
  %%   beamchain_utxo_repair:repair_range(399870, 412438).
  ```
  Hardcoded `?CORE_RPC_URL` and `?CORE_COOKIE_PATH` literally pointing
  at `/data/nvme1/hashhog-mainnet/bitcoin-core/.cookie`. The module is
  invoked from a remote shell (so not part of CI), and `repair_range/2`
  is wired to auto-submit blocks after repair: the loop runs until the
  tip reaches the requested height. The mere existence of this code is
  unambiguous confession that beamchain's chainstate has been
  losing UTXOs at runtime (the height range 399870..412438 corresponds
  to a known production incident).  This is the **comment-as-
  confession fleet pattern, 5th instance** — the post-mortem
  remediation tool that is still checked into source.
- **Excerpt**:
  ```erlang
  -define(CORE_RPC_URL, "http://127.0.0.1:8332/").
  -define(CORE_COOKIE_PATH, "/data/nvme1/hashhog-mainnet/bitcoin-core/.cookie").
  ```
- **Impact**: P1 because this code can be invoked from a remote shell
  on any beamchain mainnet node; it would silently insert untrusted
  UTXOs into our chainstate without any consensus check beyond what
  Core's `getblock 2` returns (which is itself trusted by the
  remote-shell operator). On a misconfigured deployment, an attacker
  controlling the BEAM cookie + cookie file could direct beamchain to
  ingest UTXOs from an attacker-controlled RPC endpoint.

### BUG-22 (P2) — No `-dbcache` configuration option; cache limits are hardcoded

- **File**: `src/beamchain_chainstate.erl:97-110` + `src/beamchain_db.erl:681-691`.
- **Core ref**: `bitcoin-core/src/init.cpp` (`-dbcache=<n>` default 450,
  feeds `m_total_cache` which fans out to leveldb block cache + UTXO
  cache + leveldb write buffers).
- **Description**: beamchain hardcodes:
  - `?DEFAULT_MAX_CACHE_MB = 450`  (matches Core default — good)
  - `?IBD_MAX_CACHE_MB = 4096`     (no Core equivalent; benefit
    questionable on low-memory deployments)
  - `?DEFAULT_MAX_CACHE_ENTRIES = 10_000_000`
  - `?EVICT_HIGH_WATER = 8_000_000`
  - `?EVICT_LOW_WATER = 6_000_000`
  - RocksDB `block_cache_size = 256 MB` (separate from UTXO cache)
  - RocksDB `write_buffer_size = 64 MB`, `max_write_buffer_number = 3`
  - RocksDB `max_open_files = 256` (Core default is 1024)
  None of these is operator-tunable.  `grep -i dbcache
  beamchain_config.erl` returns no hits.
- **Excerpt**: see Read of `init/1` / `init_chainstate/2`.
- **Impact**: Tuning hazard. A 16 GiB-RAM testnet node cannot shrink
  cache; a 128 GiB beefy node cannot grow cache beyond 4 GiB IBD.

### BUG-23 (P3) — `?IBD_FLUSH_INTERVAL = 5000` blocks is 10× Core's effective flush cadence on time-or-size axis

- **File**: `src/beamchain_chainstate.erl:99`.
- **Core ref**: Core's effective flush cadence is the *minimum* of
  (1 hour, ~450 MiB cache fill), which in practice during IBD is
  cache-fill-driven; 450 MiB / ~75 B per coin ~ 6 M coins ~ 500-1000
  blocks worth of mutations.
- **Description**: 5000-block flush means we keep up to 5000 blocks
  of dirty mutations in ETS before persisting. On a crash, ALL 5000
  blocks need to be re-validated. Core's choice is ~500-1000 blocks
  worth via the size threshold. 5000 is non-standard.
- **Excerpt**:
  ```erlang
  -define(IBD_FLUSH_INTERVAL, 5000).
  ```
- **Impact**: Larger crash-recovery window during IBD.

### BUG-24 (P3) — `compute_utxo_hash` materializes the entire UTXO set as a single in-memory list before SHA256

- **File**: `src/beamchain_chainstate.erl:2265-2270` +
  `src/beamchain_snapshot.erl:828-839`.
- **Core ref**: `bitcoin-core/src/kernel/coinstats.cpp:96-111`
  (`ApplyStats` is incremental — accumulates into the `HashWriter` /
  `MuHash3072` as the cursor walks).
- **Description**: beamchain reads the entire chainstate CF into a
  list via `ets:tab2list(?UTXO_CACHE)` then passes it to
  `compute_utxo_hash_from_list/1` which sorts and concatenates all
  per-coin `tx_out_ser` bins via `iolist_to_binary` → single SHA256d.
  On mainnet ~190 M coins × ~80 B average serialization → 15 GB
  in-memory binary just to hash. This is fine on a 128 GiB workstation
  but unworkable on the 16 GiB nodes the project officially supports.
- **Excerpt**:
  ```erlang
  do_compute_utxo_hash() ->
      AllEntries = ets:tab2list(?UTXO_CACHE),
      Coins = [{Txid, Vout, Utxo} || {{Txid, Vout}, Utxo} <- AllEntries],
      beamchain_snapshot:compute_utxo_hash_from_list(Coins).
  ```
  `compute_utxo_hash_from_list/1` builds a sorted list, then
  `iolist_to_binary(AllBins)`, then `beamchain_crypto:hash256(...)`.
- **Impact**: Memory bloat on `gettxoutsetinfo`. Core streams.

### BUG-25 (P3) — `BatchWrite` analog has no `simulate_crash_ratio` test hook

- **File**: `src/beamchain_chainstate.erl:1893-1937` (do_flush).
- **Core ref**: `bitcoin-core/src/txdb.cpp:147-154` (BatchWrite
  optionally `_Exit(0)` mid-batch when `simulate_crash_ratio` fires —
  CI exercises HEAD_BLOCKS replay).
- **Description**: Core lets CI inject a mid-flush crash via
  `-test=simulate_crash_ratio=N` so the HEAD_BLOCKS replay path can
  be exercised. beamchain has no such hook (and no replay code to
  test, per BUG-5). The absence is consistent with the missing
  replay path but blocks any future safety hardening.
- **Excerpt**: N/A.
- **Impact**: No crash-replay CI coverage.

### BUG-26 (P3) — `verify_flush_sample` "random" entries are not random; it walks `ets:first` + `ets:next` with deterministic spacing

- **File**: `src/beamchain_chainstate.erl:1972-2014`.
- **Core ref**: N/A.
- **Description**: The "sample" walks `ets:first` then `ets:next` 10
  times with `Skip = max(1, Total div 10)` between steps. ETS `set`
  ordering is hash-bucket-driven (not deterministic across versions
  but deterministic within a single ETS instance), so the sample is
  always the same 10 entries — colocated by hash bucket of the
  outpoint binary. A flush bug that affects entries from a different
  bucket range would never be sampled.
- **Excerpt**: see BUG-15 excerpt.
- **Impact**: Even weaker than BUG-15 suggests.

---

## Cross-cutting observations / fleet patterns

- **16th distinct extension of the two-pipeline guard** (storage axis):
  per-coin `beamchain_db:store_utxo` gen_server path vs the ETS-cache
  + `direct_write_batch` chainstate path (BUG-16).
- **5th instance of dead-helper-at-call-site**: `cache_usage_bytes`
  (BUG-18) — field declared, initialized to 0, never read or written.
- **5th instance of comment-as-confession**: `beamchain_utxo_repair.erl`
  (BUG-21) — a 294-LOC module that exists precisely to back-fill UTXOs
  the validation pipeline lost.
- **Snapshot-axis fork-in-the-road encoding**: `beamchain_snapshot.erl`
  correctly uses Core's `VARINT(code) || VARINT(CompressAmount(value))
  || ScriptCompression(...)` for `dumptxoutset`, but the live
  chainstate CF stores the same coin with a flat
  `value:64/LE || height:32/LE || coinbase:8 || raw_script` format
  (BUG-1). Two encodings, one source of truth, asymmetric round-trip.
- **HEAD_BLOCKS scaffolding-without-replay**: BUG-5 mirrors W138's
  "MaybeValidateSnapshot tautological + zero callers" — the marker is
  written but the consumer doesn't exist; the protocol is one-sided
  scaffolding.
- **Defense-in-depth absent on the durability axis**: no `{sync, true}`
  on flush (BUG-6), no time-based PERIODIC mode (BUG-11), no per-coin
  Uncache (BUG-10), no replay (BUG-5), no operator dbcache knob (BUG-22)
  — beamchain inherits Core's UTXO-cache architecture in shape but
  none of the safety nets.
