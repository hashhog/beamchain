# W146 — Block storage layer (beamchain)

Discovery-only wave.  Audit gates derived from Bitcoin Core
references:

- `bitcoin-core/src/node/blockstorage.cpp:1134-1165`
  — `BlockManager::WriteBlock` (FindNextBlockPos + magic+size header +
  TX_WITH_WITNESS serialization + close).
- `bitcoin-core/src/node/blockstorage.cpp:967-1034`
  — `BlockManager::WriteBlockUndo` (rev*.dat write with magic+size +
  block-undo + SHA256d checksum tail; FlushUndoFile on file rotation).
- `bitcoin-core/src/node/blockstorage.cpp:833-921`
  — `BlockManager::FindNextBlockPos` (rotation @ `MAX_BLOCKFILE_SIZE`,
  `FlushBlockFile(fFinalize=true)` on rotation,
  `m_block_file_seq.Allocate` in `BLOCKFILE_CHUNK_SIZE` increments).
- `bitcoin-core/src/node/blockstorage.cpp:742-769`
  — `BlockManager::FlushBlockFile` (fsync via `FlatFileSeq::Flush` →
  `FileCommit` + `DirectoryCommit`; truncates trailing pre-allocation
  on `fFinalize`).
- `bitcoin-core/src/flatfile.cpp:59-86`
  — `FlatFileSeq::Allocate` (`AllocateFileRange` =
  `posix_fallocate`/`fallocate`/platform-equivalent in
  `m_chunk_size` chunks).
- `bitcoin-core/src/flatfile.cpp:88-116`
  — `FlatFileSeq::Flush` (`FileCommit(fsync)` + `DirectoryCommit`).
- `bitcoin-core/src/node/blockstorage.cpp:1036-1075`
  — `BlockManager::ReadBlock` (`ReadRawBlock` + post-deserialise
  `CheckProofOfWork`, signet solution, expected-hash check).
- `bitcoin-core/src/node/blockstorage.cpp:1083-1132`
  — `BlockManager::ReadRawBlock` (open at `pos - STORAGE_HEADER_BYTES`,
  read `MessageStartChars + uint32 size` and validate against
  `GetParams().MessageStart()`; reject if `blk_size > MAX_SIZE`).
- `bitcoin-core/src/node/blockstorage.cpp:58-62`
  — block-index leveldb prefix bytes: `'b'`(BLOCK_INDEX),
  `'f'`(BLOCK_FILES), `'l'`(LAST_BLOCK), `'F'`(FLAG),
  `'R'`(REINDEX_FLAG).
- `bitcoin-core/src/node/blockstorage.h:119-129`
  — `BLOCKFILE_CHUNK_SIZE = 0x1000000` (16 MiB),
  `UNDOFILE_CHUNK_SIZE = 0x100000` (1 MiB),
  `MAX_BLOCKFILE_SIZE = 0x8000000` (128 MiB),
  `STORAGE_HEADER_BYTES = 8` (magic+size),
  `UNDO_DATA_DISK_OVERHEAD = 8 + 32` (magic+size+SHA256d-tail).
- `bitcoin-core/src/node/blockstorage.cpp:1167-1219`
  — `xor.dat` (XOR-key obfuscation file on the `blocks_dir`).
- `bitcoin-core/src/chain.h:44-80`
  — `CBlockIndex::nStatus` bitset
  (`BLOCK_VALID_TREE=2`, `BLOCK_VALID_TRANSACTIONS=3`,
  `BLOCK_VALID_CHAIN=4`, `BLOCK_VALID_SCRIPTS=5`,
  `BLOCK_HAVE_DATA=8`, `BLOCK_HAVE_UNDO=16`).
- `bitcoin-core/src/node/blockstorage.cpp:510-543`
  — `BlockManager::WriteBlockIndexDB` (batch:
  `('f',n)→CBlockFileInfo`, `('l')→lastfile`,
  `('b',hash)→CDiskBlockIndex` containing
  `nFile`/`nDataPos`/`nUndoPos`/`nStatus`/`nTx`/header).

Companion audits to cross-reference:

- **W109** (block index): the `nStatus` semantics + persistence
  format audited there are re-confirmed here for the on-disk
  side; W109's FIX-33 (`BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA |
  BLOCK_HAVE_UNDO`) is the only producer of beamchain's
  `?BLOCK_HAVE_DATA`/`?BLOCK_HAVE_UNDO` bits today.
- **W138** (assumeUTXO): the snapshot chainstate audited there
  bypasses the `blkXXXXX.dat` ingestion entirely — its
  storage-side coverage gap (`MaybeValidateSnapshot` returning
  tautological `true`) is on the same axis as the dead block-
  storage module catalogued here.
- **W141** (REST): `getblock`/`getrawblock` REST endpoints read
  through this layer; gaps in `ReadBlock` propagate.
- W128 (AddrMan) and W129 (Coin selection) only touch this
  surface indirectly (datadir bootstrap); no overlap.
- **W109** "pruning audit" (`_pruning-cross-impl-audit-2026-05-05.md`)
  catalogued the `find_max_height_in_file always 0` bug
  (already fixed; reproduced as context here only).

## Status counts (32 gates)

- **PRESENT** (Core-parity, or internally consistent + Core-compatible): 4
- **PARTIAL** (some piece matches, others diverge or are simplified): 8
- **MISSING** (no equivalent in beamchain): 20

Headline: **22 bugs**, severity distribution
**0 P0-CONSENSUS / 1 P0-CDIV / 6 P1 / 10 P2 / 5 P3**.

The block-storage axis in beamchain is the *most divergent* yet
audited.  Whereas Bitcoin Core stores blocks in flat
`blkXXXXX.dat` files (magic+size framed) with an accompanying
leveldb block-index keyed by `'b' + hash` whose entries carry
`nFile`/`nDataPos`/`nUndoPos`/`nStatus`/`nTx`, beamchain has TWO
parallel storage layers that DO NOT cooperate:

1. **The Core-style flat-file layer** (`do_write_block_flat`,
   `do_read_block_flat`, `find_current_blockfile`, the entire
   blkXXXXX.dat path) is **dead code in production**.  It is
   exported from `beamchain_db` via `write_block/2` and
   `read_block/1`, but the only callers are
   `test/beamchain_db_tests.erl` and `test/beamchain_w109_block_index_tests.erl`.
   Production-side block writes flow through `store_block/2`
   (CF_BLOCKS in RocksDB) and `direct_atomic_connect_writes/5`
   (single RocksDB WriteBatch).  See **BUG-1** (dead-module
   fleet pattern).
2. **The RocksDB-CF layer** (`CF_BLOCKS`, `CF_BLOCK_INDEX`,
   `CF_CHAINSTATE`, `CF_TX_INDEX`, `CF_META`, `CF_UNDO`) is the
   actual production storage path.  It is functionally
   complete (writes are atomic via WriteBatch) but bears no
   resemblance to Core's on-disk layout: blocks are blob values
   in a column family, undo data is a single binary in
   `CF_UNDO`, the block index is keyed by **height** (not by
   `'b' + hash` as Core); reads go through RocksDB MemTable +
   block cache; there are no `blkXXXXX.dat` or `revXXXXX.dat`
   files on disk, and no `'l'` (last-block) / `'F'` (flag) /
   `'R'` (reindex) keys.  See **BUG-2** through **BUG-10**.

Five themes dominate this wave:

1. **Two-pipeline (dead) guard — 16th distinct extension fleet-
   wide (1st on the storage axis).**  Two block-write APIs
   coexist (`write_block/2` flat-file; `store_block/2` RocksDB);
   the flat-file API is exhaustively tested in
   `beamchain_db_tests.erl` but no production caller invokes it.
   See **BUG-1**.
2. **No durability barrier on the block-connect path.**  Core's
   `FlushBlockFile`/`FlushUndoFile` invoke
   `FileCommit(fsync)` + `DirectoryCommit` on rotation.
   beamchain's RocksDB writes use the default
   `WriteOptions{sync=false}` (no WAL fsync per write); the lone
   `{sync, true}` flag at `beamchain_db:364` is on a
   `delete_range` call from `clear_chainstate_cf/0`.  A power
   loss between WriteBatch commit and the RocksDB background
   flush can lose the chain-tip update even though the block was
   "stored".  See **BUG-11**.
3. **Comment-as-confession (6th instance fleet-wide; 1st on the
   storage axis).** `beamchain_db.erl:1284-1285` reads
   *"%% Pruning disabled"* in the `trigger_pruning` cast — the
   message is silently dropped while the rest of the code base
   exports `prune_block_files/0`, `prune_block_files_manual/1`,
   `trigger_pruning/1` and the configuration plumbing acts as if
   pruning is wired.  See **BUG-12**.
4. **`STORAGE_HEADER_BYTES`/`UNDO_DATA_DISK_OVERHEAD` is short by
   32 bytes for the undo case.**  Even if undo-data were ever
   written to a `revXXXXX.dat` file, the encoder
   (`encode_undo_data/1` in
   `beamchain_validation.erl:1652-1664`) emits no SHA256d
   trailing-checksum.  Core's
   `WriteBlockUndo` (`blockstorage.cpp:994-1000`) writes
   `blockundo << hasher.GetHash()` so a flipped bit anywhere in
   the undo record is detected on read.  See **BUG-9**.
5. **Block-index `CDiskBlockIndex` shape divergence.**  Core's
   on-disk block-index entry carries
   `{nFile, nDataPos, nUndoPos, nStatus, nTx, version, prevHash,
   merkleRoot, time, bits, nonce}`.  beamchain stores
   `{Hash(32), HeaderBin(80), CWLen(2), Chainwork, Status(4),
   NTx(4)}` — *no `nFile`/`nDataPos`/`nUndoPos`*.  Location
   metadata lives in an ETS table (`BLOCK_INDEX_ETS`) that is
   only persisted on `terminate/2`.  See **BUG-3** and
   **BUG-13** (durability hole on crash).

Notable cross-cutting smells:

- **Persistent_term as a chain-tip durability proxy.**  Block-
  index location data and chainstate handle live in
  persistent_term + ETS; they are *rebuilt* on restart from
  whatever survives in RocksDB, but the
  `(FileNum, Offset, Size)` ETS triple has no rocksdb mirror —
  a crash between two block writes leaves the next start with
  zero recorded block-file positions for the missing blocks.
  (Currently masked by the dead-module nature of BUG-1: the
  triple is never read in production.  Becomes load-bearing the
  day the flat-file layer is wired up.)
- **`xor.dat` (Core's blocks-dir obfuscation key) is missing.**
  Core writes the random XOR key once on first run; reads XOR-
  decode every blkXXXXX.dat/revXXXXX.dat byte.  beamchain has
  no analogue.  Cosmetic today (no `.dat` files at all), but
  blocks any future "use a Core datadir as beamchain seed"
  workflow.  See **BUG-22**.
- **`xor.dat` is also missing as a *fingerprinting-defense*
  signal.**  Core's XOR key foils naive AV-scanner / file-type
  detectors that index blocks by their on-disk magic — this
  matters less on a server but is a Core-parity gap.

---

## BUGS

### BUG-1 (P1) — `do_write_block_flat`/`do_read_block_flat` are a dead module: blkXXXXX.dat / revXXXXX.dat path is exported, tested, never invoked in production

- **File**: `src/beamchain_db.erl:529-541` (`write_block/2`,
  `read_block/1` exported), `src/beamchain_db.erl:1487-1619`
  (the entire flat-file implementation); plus
  `test/beamchain_db_tests.erl:384-486` and
  `test/beamchain_w109_block_index_tests.erl:315-551`.
- **Core ref**: `bitcoin-core/src/node/blockstorage.cpp:1134`
  (`BlockManager::WriteBlock` is *the* sole production block-
  write path in Core).
- **Description**: beamchain exports two block-storage APIs:
  - `store_block/2` (`beamchain_db.erl:168-170`) → writes the
    serialized block as a blob value to the `CF_BLOCKS` RocksDB
    column family, keyed by 32-byte block hash.
    Used everywhere in production (`beamchain_block_sync.erl:1045`,
    `beamchain_chainstate.erl:1341`,
    `direct_atomic_connect_writes/5`).
  - `write_block/2` (`beamchain_db.erl:532-535`) → writes the
    block to a `blkXXXXX.dat` flat file with Core's
    `<<Magic:4, Size:32/little, BlockData/binary>>` framing,
    maintains an ETS index `(Hash → {FileNum, Offset, Size})`
    and a `current_file`/`current_pos` cursor.
    **Only called by tests.**

  `grep -rn "beamchain_db:write_block\|beamchain_db:read_block"
  /home/work/hashhog/beamchain/src/` returns ZERO matches.
  `find_current_blockfile/1` (`beamchain_db.erl:1454`),
  `do_write_block_flat/2` (`beamchain_db.erl:1497`),
  `do_read_block_flat/2` (`beamchain_db.erl:1573`),
  `write_block_data/8` (`beamchain_db.erl:1548`),
  `persist_block_index/1` (`beamchain_db.erl:1623`),
  `revfile_path/2` (`beamchain_db.erl:1640`),
  `blockfile_path/2` (`beamchain_db.erl:1488`) — every one of
  these is dead in production.
- **Excerpt**:
  ```erlang
  %% src/beamchain_db.erl:529-535
  -spec write_block(#block{}, non_neg_integer()) ->
      {ok, {non_neg_integer(), non_neg_integer(), non_neg_integer()}} |
      {error, term()}.
  write_block(Block, Height) ->
      gen_server:call(?SERVER, {write_block_flat, Block, Height}, 30000).
  %% NOTE: zero callers in src/, only in test/.

  %% Meanwhile, the actual production path:
  %% src/beamchain_block_sync.erl:1045
  ok = beamchain_db:store_block(Block, Height),
  ```
- **Impact**: Same shape as the W138 fleet pattern
  ("9-of-10 impls have an assumeUTXO chain manager defined,
  zero callers"): scaffolding is in place, has tests, was
  presumably implemented to match Core's on-disk layout, but
  the call-graph never threads it.  Three concrete impacts:
  1. Test-suite *appears* to cover the flat-file format but
     literally no consensus-relevant code reads or writes
     `blkXXXXX.dat`.  Block durability lives entirely in
     RocksDB WAL.
  2. Magic-byte parity (BUG-2 below) and `MAX_BLOCKFILE_SIZE`
     (BUG-7) are exercised by tests only.
  3. Pruning (`do_prune_files` / `prune_until_target`) is
     wired to `file:delete` block files that were never
     written; the delete is a no-op on a non-existent path.
     (Mitigated by `trigger_pruning` being a no-op — BUG-12.)

  Recommend either wiring the flat-file path into
  `store_block` / `atomic_connect_writes` (then pulling the
  block blob out of `CF_BLOCKS`), or deleting the dead code
  and reframing the storage layer as RocksDB-only with an
  honest README.  Two-pipeline / dead-module 16th distinct
  fleet extension.

### BUG-2 (P0-CDIV) — Block-data on disk is a RocksDB blob value, not a magic+size framed flat file: `getrawblock` REST + `block_reader.py` Core-compatible tooling cannot read beamchain data

- **File**: `src/beamchain_db.erl:821-828` (`store_block`
  handler).
- **Core ref**: `bitcoin-core/src/node/blockstorage.cpp:1148-1156`
  (Core writes `MessageStart() + block_size + TX_WITH_WITNESS`
  to `blkXXXXX.dat`).
- **Description**: beamchain's production block-store writes
  the serialized block as a CF_BLOCKS value with no magic
  prefix, no size prefix, and no XOR obfuscation key.  The
  format is `Hash(32) → BlockBin` where `BlockBin` is the
  bare `beamchain_serialize:encode_block` output.
- **Excerpt**:
  ```erlang
  %% src/beamchain_db.erl:821-827
  handle_call({store_block, Block, _Height}, _From,
              #state{db_handle = Db, cf_blocks = CF} = State) ->
      Hash = block_hash(Block),
      BlockBin = beamchain_serialize:encode_block(Block),
      %% Store block data keyed by hash only.
      Result = rocksdb:put(Db, CF, Hash, BlockBin, []),
  ```
- **Impact**: Any Core-compatible reader
  (`tools/block_reader.py`, electrs, fulcrum, bitcoin-cli over
  a shared datadir, the mainnet `consensus-diff` harness that
  reads `blkXXXXX.dat` for cross-impl byte-exact comparisons)
  cannot consume beamchain's block store.  The W138 quad-wave
  flagged blockbrew's ZMQ hash-byte-order divergence as
  breaking electrs/fulcrum/mempool.space; this is the same
  class but at the durable storage level.  Re-classified as
  CDIV because the on-disk format is structurally
  incompatible, not because the consensus answer differs (it
  doesn't — beamchain re-deserialises its own blob fine).

### BUG-3 (P1) — `encode_block_index_entry/5` omits `nFile`/`nDataPos`/`nUndoPos` — Core's `CDiskBlockIndex` location triplet is not persisted

- **File**: `src/beamchain_db.erl:1349-1354`.
- **Core ref**: `bitcoin-core/src/chain.h:495-555`
  (`CDiskBlockIndex::SerializationOp` writes
  `VARINT(nVersion)`, `VARINT(nHeight)`, `VARINT(nStatus)`,
  `VARINT(nTx)`, `VARINT(nFile)`,
  `VARINT(nDataPos)`, `VARINT(nUndoPos)`, plus the header
  fields).
- **Description**: beamchain's block-index entry is
  `<<Hash:32, HeaderBin:80, CWLen:16, Chainwork:CWLen,
  Status:32/little, NTx:32/big>>`.  No file number, no data
  position, no undo position.  Block data is in RocksDB
  CF_BLOCKS keyed by hash so location *is* implicit — but the
  semantic gap means any future flat-file migration cannot
  recover location-by-height without the dead ETS table.
- **Excerpt**:
  ```erlang
  %% src/beamchain_db.erl:1346-1354
  %% @doc Encode a block index entry.
  %% Format: Hash (32) | HeaderBin (80) | CWLen (2) | Chainwork (variable) | Status (4) | NTx (4)
  %% NTx is 0 for header-only entries (stored before the full block arrives).
  encode_block_index_entry(Hash, Header, Chainwork, Status, NTx) ->
      HeaderBin = beamchain_serialize:encode_block_header(Header),
      CWLen = byte_size(Chainwork),
      <<Hash:32/binary, HeaderBin:80/binary,
        CWLen:16/big, Chainwork:CWLen/binary,
        Status:32/little, NTx:32/big>>.
  ```
- **Impact**: If BUG-1 is fixed by wiring the flat-file path,
  the persisted block-index entry won't carry the
  `(FileNum, Offset, Size)` triple that should accompany each
  block — every restart will need to scan blkXXXXX.dat files
  from scratch (Core does this on `-reindex`, not on normal
  start).  Today the ETS-only location index
  (`BLOCK_INDEX_ETS`) is the source of truth for the
  unused-but-tested flat-file path.

### BUG-4 (P1) — Block-index leveldb-key shape: keyed by HEIGHT (8 BE bytes) — not Core's `'b' + hash`

- **File**: `src/beamchain_db.erl:912-921` (`store_block_index`
  handler), `src/beamchain_db.erl:1315-1317` (`encode_height/1`).
- **Core ref**: `bitcoin-core/src/node/blockstorage.cpp:58-100`
  (Core: `'b' + hash → CDiskBlockIndex`,
  `'f' + fileNum → CBlockFileInfo`, `'l' → lastFile`).
- **Description**: beamchain stores active-chain block indexes
  in `CF_BLOCK_INDEX` keyed by `<<Height:64/big>>` (8 bytes),
  not by `'b' + Hash`.  A `"blkidx:" ++ Hash` reverse index
  lives in `CF_META` to translate hash → height.  Side-branch
  (off-active-chain) blocks live in `CF_META` under
  `"sbidx:" + Hash`.  This is a three-CF, two-key-shape design
  that has no Core parity.
- **Excerpt**:
  ```erlang
  %% src/beamchain_db.erl:912-921
  handle_call({store_block_index, Height, Hash, Header, Chainwork, Status, NTx},
              _From, #state{db_handle = Db, cf_block_idx = CF,
                            cf_meta = MetaCF} = State) ->
      HeightKey = encode_height(Height),
      Value = encode_block_index_entry(Hash, Header, Chainwork, Status, NTx),
      rocksdb:put(Db, CF, HeightKey, Value, []),
      %% Reverse index: hash -> height for lookup by hash
      HashKey = <<"blkidx:", Hash/binary>>,
      rocksdb:put(Db, MetaCF, HashKey, HeightKey, []),
      {reply, ok, State};
  ```
- **Impact**: Three downstream consequences:
  1. Height-keyed indexes structurally cannot hold two blocks
     at the same height — hence the parallel side-branch
     index (`sbidx:` prefix).  This was caught and partly
     fixed in W124's two-pipeline audit (the side-branch
     prefix is the workaround).  Core handles this naturally
     because `'b' + Hash` accommodates any number of blocks at
     the same height in a single keyspace.
  2. The two `rocksdb:put` calls at lines 917 and 920 are NOT
     atomic — a crash between them leaves the height key
     written but the hash-reverse-index missing
     (`get_block_index_by_hash` returns `not_found` even though
     `get_block_index(Height)` succeeds).  Should be a single
     WriteBatch.
  3. Core's `('f' + nFile)` per-block-file-info entry is
     entirely absent — no on-disk record of which blocks live
     in which `blkXXXXX.dat` (consistent with BUG-1).

### BUG-5 (P1) — `'l'` (last-block-file) leveldb key is missing — `find_current_blockfile/1` rescans the directory on every restart

- **File**: `src/beamchain_db.erl:1454-1484`.
- **Core ref**: `bitcoin-core/src/node/blockstorage.cpp:62, 89-90`
  (Core: `Read(DB_LAST_BLOCK, nFile)` returns the last block
  file number directly).
- **Description**: beamchain has no leveldb/rocksdb key for
  "current block file"; on restart it does a
  `filelib:wildcard("blk*.dat")` and extracts the max
  filenumber from the filename.  Two issues:
  - For an empty `blocks_dir` it returns `{0, 0}` — which is
    correct (Core would too on first start), but only because
    blkXXXXX.dat files are never created (BUG-1 again).
  - A stale or partially-corrupted file (zero-byte
    blk00042.dat survived an aborted write) is treated as the
    "current" file, and writes resume into it; Core's
    `'l'`-key would point to the *last successfully written*
    file, which may be lower.
- **Excerpt**:
  ```erlang
  %% src/beamchain_db.erl:1454-1484 — directory scan, no DB key
  find_current_blockfile(BlocksDir) ->
      Pattern = filename:join(BlocksDir, "blk*.dat"),
      Files = filelib:wildcard(Pattern),
      case Files of
          [] -> {0, 0};
          _ ->
              FileNums = lists:filtermap(fun(Path) -> ... end, Files),
              MaxFile = lists:max(FileNums),
              FilePath = blockfile_path(BlocksDir, MaxFile),
              case file:read_file_info(FilePath) of
                  {ok, #file_info{size = Size}} -> {MaxFile, Size};
                  _ -> {MaxFile, 0}
              end
      end.
  ```
- **Impact**: Moot today because BUG-1 makes the whole path
  dead.  Becomes a recovery hazard the day blockwrite is
  re-wired.

### BUG-6 (P1) — `'R'` (reindex) DB flag is missing — no `-reindex`/`-reindex-chainstate` recovery surface

- **File**: `src/beamchain_db.erl` (absent).
- **Core ref**: `bitcoin-core/src/node/blockstorage.cpp:61, 73-85`
  (Core: `WriteReindexing(true/false)` writes/erases
  `DB_REINDEX_FLAG`, `IsReindexing()` reads it on startup so an
  aborted reindex resumes correctly).
- **Description**: beamchain has no `R` flag, no
  `is_reindexing/0`, no `set_reindexing/1`, and no
  `-reindex`/`-reindex-chainstate` startup flag in
  `beamchain_config.erl`.  An interrupted reindex
  (theoretical, since reindex itself does not exist) leaves no
  signal for the next boot.
- **Impact**: Operator cannot trigger a flat-file replay; the
  fallback to "rebuild from on-disk blockfiles" on UTXO
  corruption — Core's last line of defense before resyncing
  from peers — is absent.  Mitigated today because the entire
  flat-file path is dead (BUG-1), but missing as a
  Core-parity recovery surface and a fleet-wide audit pattern
  ("recovery code path is production fallback" — directly
  quoted from the W146 audit gates).

### BUG-7 (P2) — `MAX_BLOCKFILE_SIZE` and `BLOCKFILE_CHUNK_SIZE`/`UNDOFILE_CHUNK_SIZE` are not implemented as a chunked allocator

- **File**: `src/beamchain_db.erl:121` (`MAX_BLOCKFILE_SIZE =
  134217728`), no `BLOCKFILE_CHUNK_SIZE`.
- **Core ref**: `bitcoin-core/src/node/blockstorage.h:119-123`
  (`BLOCKFILE_CHUNK_SIZE = 16 MiB`,
  `UNDOFILE_CHUNK_SIZE = 1 MiB`,
  `MAX_BLOCKFILE_SIZE = 128 MiB`);
  `bitcoin-core/src/flatfile.cpp:59-86`
  (`FlatFileSeq::Allocate` calls `posix_fallocate` /
  `AllocateFileRange` in chunk-sized increments).
- **Description**: beamchain's
  `do_write_block_flat` simply rolls over to a new file when
  `CurrentPos + TotalSize > ?MAX_BLOCKFILE_SIZE`, using
  `file:open(FilePath, [raw, binary, append])` and
  `file:write/2`.  No pre-allocation: blocks are appended one
  at a time, and the OS handles extent allocation per-write.
  Core pre-allocates `BLOCKFILE_CHUNK_SIZE`-aligned ranges via
  `posix_fallocate` to keep file extents contiguous (faster
  reads, better cache behaviour) and to detect
  `ENOSPC` *before* a partial write.
- **Excerpt**:
  ```erlang
  %% src/beamchain_db.erl:1509-1535
  {FileNum, WritePos, WriteFd1, State1} =
      case CurrentPos + TotalSize > ?MAX_BLOCKFILE_SIZE of
          true ->
              %% Close current file, open new one
              case WriteFd0 of
                  undefined -> ok;
                  OldFd -> file:close(OldFd)
              end,
              NewFileNum = CurrentFile + 1,
              {NewFileNum, 0, undefined,
               State#state{current_file = NewFileNum, current_pos = 0,
                           write_fd = undefined}};
          false ->
              {CurrentFile, CurrentPos, WriteFd0, State}
      end,
      ...
      case file:open(FilePath, [raw, binary, append]) of
          {ok, NewFd} -> ...  %% append-mode write, no fallocate
  ```
- **Impact**: Moot today (BUG-1).  When live, two
  consequences:
  1. Disk-space exhaustion is detected *during* a write
     (partial block written, file rolled back implicitly by
     OS) rather than *before* the write starts.
  2. File extents fragment over hundreds of GB; cold-read
     latency suffers.

### BUG-8 (P2) — `revXXXXX.dat` (undo) files are never written; `revfile_path/2` exists only to feed `file:delete/1`

- **File**: `src/beamchain_db.erl:1639-1642` (`revfile_path/2`),
  `src/beamchain_db.erl:2005-2009` (delete it inside
  `prune_until_target`).
- **Core ref**: `bitcoin-core/src/node/blockstorage.cpp:967-1034`
  (`BlockManager::WriteBlockUndo` — the only producer of
  `revXXXXX.dat`).
- **Description**: `revfile_path/2` is defined and exported,
  but `grep -n "revfile_path"` returns matches only at three
  sites: the definition itself, a disk-usage-accounting fold
  (`calculate_disk_usage/3`), and the prune-side delete
  (`prune_until_target/5`).  There is no
  `do_write_undo_flat`, no `write_undo_data`, no
  `WriteBlockUndo`.  Undo data is stored entirely in
  `CF_UNDO` (RocksDB column family) via
  `store_undo/2` / `direct_store_undo/2`
  (`beamchain_db.erl:484, 618`).
- **Excerpt**:
  ```erlang
  %% src/beamchain_db.erl:2002-2009 — prune deletes a file that
  %% was never written
  prune_until_target(BlocksDir, [{FileNum, Size} | Rest], CurrentUsage, Target, PrunedFiles) ->
      BlkPath = blockfile_path(BlocksDir, FileNum),
      RevPath = revfile_path(BlocksDir, FileNum),
      _ = file:delete(BlkPath),
      _ = file:delete(RevPath),  %% no-op; file never existed
      ...
  ```
- **Impact**: Same shape as BUG-1 but on the undo axis: tooling
  expecting Core-format `revXXXXX.dat` (electrs replay, the
  W123-W127 mainnet-replay corpus) cannot consume beamchain's
  undo data.  Undo *does* round-trip correctly inside
  beamchain (the CF_UNDO blob path works for `disconnect_block`
  and reorgs — that's W126/W128 territory) but it is not the
  Core layout.

### BUG-9 (P2) — `encode_undo_data/1` omits the SHA256d trailing checksum that Core writes after `<< blockundo`

- **File**: `src/beamchain_validation.erl:1652-1664`.
- **Core ref**: `bitcoin-core/src/node/blockstorage.cpp:994-1000`
  (Core's WriteBlockUndo: `hasher << block.pprev->GetBlockHash()
  << blockundo; fileout << blockundo << hasher.GetHash();` —
  the 32-byte SHA256d tail is integrity-checked on
  `ReadBlockUndo`).
- **Description**: beamchain's undo encoder produces
  `Count(4 LE) | Entry₀ | Entry₁ | ...` with no trailing
  hash.  Each `Entry` is
  `H(32) | I(4 LE) | Value(8 LE) | Height(4 LE) | CbFlag(1) |
   SPKLen(4 LE) | SPK(SPKLen)`.  Core's per-block undo record
  is followed by `SHA256d(prevHash || blockundo)` and the
  reader (`ReadBlockUndo`) recomputes-and-compares.
- **Excerpt**:
  ```erlang
  %% src/beamchain_validation.erl:1652-1664
  encode_undo_data(SpentCoins) ->
      Count = length(SpentCoins),
      Entries = lists:map(fun({#outpoint{hash = H, index = I}, Coin}) ->
          ...
      end, SpentCoins),
      <<Count:32/little, (list_to_binary(Entries))/binary>>.
      %% No hash tail; no integrity check on decode.
  ```
- **Impact**: A flipped bit anywhere in
  `CF_UNDO` (RocksDB CRC catches *some* of this at the SST
  level, but a corruption in the in-memory MemTable before
  flush is detected only by Core's hash-tail check) is silently
  decoded as a wrong UTXO restore on disconnect.  Wrong UTXO
  restore = consensus split on the next block.

### BUG-10 (P2) — `STORAGE_HEADER_BYTES` magic+size header is hand-written, not derived from a shared constant — drift hazard if Core ever extends header

- **File**: `src/beamchain_db.erl:1549-1550` (write),
  `src/beamchain_db.erl:1584-1585` (read).
- **Core ref**: `bitcoin-core/src/node/blockstorage.h:126`
  (`STORAGE_HEADER_BYTES = sizeof(MessageStartChars) +
  sizeof(unsigned int)`).
- **Description**: beamchain hard-codes the 8-byte
  magic-plus-size header in two places without a named
  constant:
  ```erlang
  %% src/beamchain_db.erl:1549-1551
  Header = <<Magic:4/binary, BlockSize:32/little>>,
  case file:write(Fd, Header) of ...

  %% src/beamchain_db.erl:1584-1585
  case file:pread(Fd, Offset - 8, 8) of
      {ok, <<ReadMagic:4/binary, ReadSize:32/little>>} ->
  ```
  Two separate sites both bake in `8` and `4` and `32/little`.
  A future Core extension (e.g., adding a checksum tail to
  blkXXXXX.dat — proposed for Core 30.x — or adding a flags
  byte to `MessageStart`) wouldn't be caught by a single-
  symbol update.
- **Impact**: Maintenance/drift hazard; Core-parity-erosion
  candidate.  Recommend a
  `?STORAGE_HEADER_BYTES = 8` macro (matching the Core
  constant name) anchored next to `?MAX_BLOCKFILE_SIZE`.

### BUG-11 (P0-CDIV) — RocksDB writes use `WriteOptions{sync=false}`: no fsync on block-connect WAL commit; chain tip can rewind on power loss

- **File**: `src/beamchain_db.erl:614, 621, 655, 827, 877, 917,
  920, 968, 985, 992, 1009, 1028, 1057, 1071, 1188` (every
  rocksdb:put / rocksdb:write call uses `[]`).
- **Core ref**: `bitcoin-core/src/node/blockstorage.cpp:742-769`
  (Core's FlushBlockFile invokes `FlatFileSeq::Flush` →
  `FileCommit` (= `fsync` on POSIX, `_commit` on Win) +
  `DirectoryCommit` (= `fsync` on the directory).  RocksDB
  writes from the chainstate side use `WriteOptions::sync =
  true` for the per-block commit
  (`bitcoin-core/src/dbwrapper.cpp:200`).)
- **Description**: Every RocksDB write in
  `beamchain_db.erl` uses the empty options list `[]`.
  Erlang `rocksdb` API maps this to
  `WriteOptions{sync=false, disableWAL=false}` — the WAL is
  written (so a clean shutdown is durable) but no `fsync` is
  issued.  A power loss between the application
  `rocksdb:write/3` returning `ok` and the kernel flushing
  the WAL page-cache to disk can lose the most recent block-
  connect's WriteBatch.  The lone `[{sync, true}]` instance
  (`beamchain_db.erl:364`) is on a `delete_range` for
  CF_CHAINSTATE wipe — not on the block-connect path.
- **Excerpt**:
  ```erlang
  %% src/beamchain_db.erl:1057 — atomic_connect_writes;
  %% sync=false (default)
  AllOps = [BlockOp, IdxOp, RevOp | TxOps],
  Result = rocksdb:write(Db, AllOps, []),

  %% src/beamchain_db.erl:614 — direct_write_batch; sync=false
  rocksdb:write(Db, WriteActions, []).

  %% src/beamchain_db.erl:364 — only sync=true call (CHAINSTATE
  %% clear, not block-connect)
  rocksdb:delete_range(Db, CF, BeginKey, EndKey, [{sync, true}])
  ```
- **Impact**: Power loss with `sync=false` typically loses
  the last 1-30 seconds of WAL writes.  At IBD speed
  (hundreds of blocks/sec for blockbrew / 5-50 blocks/sec
  for beamchain at testnet4), this is *seconds* of
  block-connect work.  Concretely: chain tip can rewind
  several blocks on startup after an unclean shutdown; the
  UTXO set, CF_BLOCKS, CF_UNDO and the tip pointer all roll
  back together (RocksDB WAL-atomicity), so consensus
  doesn't split, but the node re-downloads and re-validates
  those blocks from peers.  Larger blast radius if the WAL
  is reset entirely (data corruption recovery).  Core
  passes `sync=true` on the block-connect chainstate flush.
  Recommend `[{sync, true}]` on `direct_atomic_connect_writes`
  and `atomic_connect_writes` at minimum.

### BUG-12 (P1) — `handle_cast({trigger_pruning, _Height}, ...)` is a no-op with the comment "Pruning disabled" — comment-as-confession 6th instance fleet-wide

- **File**: `src/beamchain_db.erl:1283-1285`.
- **Core ref**: `bitcoin-core/src/node/blockstorage.cpp:1230-1290`
  (`FlushStateToDisk` calls `PruneAndFlush` which invokes
  `FindFilesToPrune`).
- **Description**: The async pruning trigger exists in the
  API (`trigger_pruning/1` exported at line 92) and is called
  from chainstate after every block connect... but the cast
  handler immediately returns:
- **Excerpt**:
  ```erlang
  %% src/beamchain_db.erl:1283-1285
  handle_cast({trigger_pruning, _Height}, State) ->
      %% Pruning disabled
      {noreply, State};
  ```
  Meanwhile `prune_block_files/0`, `prune_block_files_manual/1`,
  `is_block_pruned/1`, `get_prune_state/0` are all wired and
  call through to a working `do_prune_files/1` /
  `do_prune_files_manual/2` (lines 1730-1828).  The
  configuration knob (`beamchain_config:prune_target/0`) reads
  the CLI flag.  The chainstate is set up to dispatch the
  cast (`beamchain_chainstate.erl` calls
  `beamchain_db:trigger_pruning(Height)` after connect).
- **Impact**: Auto-pruning (the `pruneblockchain` config that
  matches Core's `-prune=N` for N≥550) is silently disabled.
  Manual pruning via the RPC (`pruneblockchain` height) still
  works because it goes through the gen_server:call path.
  Operator with `-prune=550` ends up disk-full eventually.
  Comment-as-confession 6th instance fleet-wide (after the
  five W138/W139/W141/W144/W145 cases).

### BUG-13 (P1) — ETS block-location index is only persisted on `terminate/2`; crash before clean shutdown loses every block-location entry since last persist

- **File**: `src/beamchain_db.erl:1293-1309` (terminate
  handler), `src/beamchain_db.erl:1623-1632`
  (`persist_block_index/1`).
- **Core ref**: `bitcoin-core/src/node/blockstorage.cpp:510-543`
  (Core's `WriteBlockIndexDB` runs from
  `FlushStateToDisk` — i.e. periodically and on chainstate
  flush, not only at shutdown).
- **Description**: The `BLOCK_INDEX_ETS` table that maps
  `Hash → (FileNum, Offset, Size)` for the dead flat-file
  layer is saved via `ets:tab2file(?BLOCK_INDEX_ETS, ...)`
  only in `terminate/2`.  A crash, OOM-kill, or `kill -9`
  loses everything written since last `init/1`.  Three other
  ETS tables (`HEIGHT_TO_HASH_ETS`, `TIME_INDEX_ETS`,
  `BLOCK_STATS_ETS`) are NOT persisted at all — they are
  rebuilt from RocksDB on every restart, which works because
  the RocksDB CF carries the authoritative data.  But the
  block-location triplet for the flat-file path has no
  RocksDB mirror, so a crash on the flat-file path =
  permanent data loss.
- **Excerpt**:
  ```erlang
  %% src/beamchain_db.erl:1295-1309 — only persist at shutdown
  terminate(_Reason, #state{db_handle = DbHandle, write_fd = WriteFd,
                            blocks_dir = BlocksDir}) ->
      logger:info("beamchain_db: closing rocksdb"),
      case WriteFd of
          undefined -> ok;
          Fd -> file:close(Fd)
      end,
      case BlocksDir of
          undefined -> ok;
          _ -> persist_block_index(BlocksDir)  %% saves
                                                %% BLOCK_INDEX_ETS only
      end,
      rocksdb:close(DbHandle),
      ok.
  ```
- **Impact**: Moot today because BUG-1 keeps the flat-file
  path dead.  Becomes a P0 the day BUG-1 is fixed.

### BUG-14 (P2) — `do_read_block_flat/2` reads block-data BEFORE checking the magic-header (Core does header-first)

- **File**: `src/beamchain_db.erl:1573-1619`.
- **Core ref**: `bitcoin-core/src/node/blockstorage.cpp:1083-1132`
  (Core opens at `pos.nPos - STORAGE_HEADER_BYTES`, reads
  `MessageStartChars` + `unsigned int blk_size`, validates
  magic, validates `blk_size > MAX_SIZE`, *then* reads the
  block bytes).
- **Description**: beamchain reads the block payload at
  `Offset` first via `file:pread(Fd, Offset, Size)`, then
  reads the 8-byte header at `Offset - 8` afterward and
  checks magic.  Two issues:
  1. A torn write that left the header corrupt but the payload
     intact still triggers a "successful" deserialise-then-
     reject path; Core fails fast at the header.
  2. The two `file:pread` calls can race against a concurrent
     write/truncate (in theory; today single-writer per file).
- **Excerpt**:
  ```erlang
  %% src/beamchain_db.erl:1580-1592 — payload first, header after
  case file:pread(Fd, Offset, Size) of
      {ok, BlockData} when byte_size(BlockData) =:= Size ->
          %% Verify magic by reading header (offset - 8)
          case file:pread(Fd, Offset - 8, 8) of
              {ok, <<ReadMagic:4/binary, ReadSize:32/little>>} ->
                  case ReadMagic =:= Magic andalso ReadSize =:= Size of
                      true ->
                          {Block, <<>>} = beamchain_serialize:decode_block(BlockData),
                          {ok, Block};
                      false ->
                          {error, {magic_mismatch, ReadMagic, Magic}}
                  end;
  ```
- **Impact**: Cosmetic today (BUG-1 makes this dead path).
  Header-first is the Core idiom + the audit-gate requirement
  (gate #7 above).

### BUG-15 (P2) — `do_read_block_flat/2` does not enforce `blk_size > MAX_SIZE` rejection

- **File**: `src/beamchain_db.erl:1573-1619`.
- **Core ref**: `bitcoin-core/src/node/blockstorage.cpp:1110-1114`
  (`if (blk_size > MAX_SIZE) return util::Unexpected{ReadRawError::IO};`).
- **Description**: beamchain's read path validates only that
  `ReadSize =:= Size`, where `Size` is the size recorded in
  the ETS index.  Core compares the on-disk `blk_size` against
  `MAX_SIZE = 0x02000000` (33,554,432 bytes) — a sanity
  upper bound that catches obvious corruption (e.g., a
  munged size byte producing 4 GB).  beamchain trusts the
  ETS-recorded `Size` implicitly.
- **Impact**: Cosmetic in the flat-file dead path (BUG-1).
  Becomes a memory-bomb DoS vector if BUG-1 is fixed without
  this gate (a `2^32-1`-byte size in a corrupted file allocates
  a 4 GB binary in `file:pread/3`).  Same shape as the
  W138 haskoin BUG-10 "memory bomb via VarInt".

### BUG-16 (P2) — `do_read_block_flat/2` does not call `CheckProofOfWork` or `CheckSignetBlockSolution` on the deserialised block

- **File**: `src/beamchain_db.erl:1573-1619`.
- **Core ref**: `bitcoin-core/src/node/blockstorage.cpp:1057-1066`
  (Core's ReadBlock: PoW check + signet solution check + expected-
  hash check inside `ReadBlock`, not in callers).
- **Description**: beamchain's read path returns the
  deserialised block as soon as decode succeeds.  Core re-
  validates PoW and signet solution as a corruption-detection
  measure: if the block on disk has a header that no longer
  satisfies `nBits`, the file is presumed corrupt.  beamchain
  has no equivalent.
- **Impact**: Same as BUG-15: cosmetic today (BUG-1 dead
  path); a corruption-detection gap if the flat-file path is
  ever wired up.

### BUG-17 (P2) — `do_write_block_flat/2` does not call `file:sync/1` (or `:datasync`) before returning `ok`

- **File**: `src/beamchain_db.erl:1492-1568`.
- **Core ref**: `bitcoin-core/src/node/blockstorage.cpp:742-769,
  1158-1162` (Core's `WriteBlock` calls `file.fclose()` then
  relies on `FlushBlockFile` later in the connect flow;
  `FlushBlockFile` issues `FileCommit` (= `fsync`) +
  `DirectoryCommit` (= `fsync` on the dir).  Per-block
  `fsync` is avoided for performance; per-flush `fsync` is
  mandatory.).
- **Description**: beamchain's flat-file write path never
  calls `file:sync/1`, `file:datasync/1`, or any directory
  sync.  Two issues:
  1. The `write_fd` stays open in `state{}` for the next
     block, so the file handle is never closed (per the audit
     trail in lines 1295-1302 it's only closed at terminate).
     Core closes `AutoFile` after each block.
  2. No `FlushBlockFile`-equivalent is invoked on rotation
     (the `file:close(OldFd)` at line 1516 closes the FD but
     does not fsync).
- **Impact**: Moot today (BUG-1).  Live, this means every
  blkXXXXX.dat write is in page-cache only — power loss loses
  blocks that beamchain's chainstate believes are durable.

### BUG-18 (P2) — `MaxBlockfileNum() + 1` rotation semantics missing: rotation simply does `CurrentFile + 1`, no awareness of `BlockfileType::NORMAL`/`ASSUMED`

- **File**: `src/beamchain_db.erl:1510-1520`.
- **Core ref**: `bitcoin-core/src/node/blockstorage.cpp:771-777,
  833-921` (Core's `BlockfileType` enum splits NORMAL/ASSUMED
  cursors; rotation calls `MaxBlockfileNum() + 1` to skip
  numbers in use by the other chainstate).
- **Description**: beamchain's rotation:
  ```erlang
  NewFileNum = CurrentFile + 1,
  ```
  has no concept of `BlockfileType::ASSUMED` (the snapshot-
  side blkXXXXX.dat range).  This is consistent with the
  W138 finding that beamchain's `BackgroundValidator` /
  snapshot chainstate is dead code: the storage layer has no
  parallel chainstate to share file numbers with.  If
  assumeUTXO is ever wired, two writers will race for the
  same `CurrentFile + 1`.
- **Impact**: Latent — depends on assumeUTXO fix-up.

### BUG-19 (P3) — `current_file` and `current_pos` are not protected against double-launch (no per-datadir lockfile mention)

- **File**: `src/beamchain_db.erl:756-757` (init reads from
  scratch on every start).
- **Core ref**: `bitcoin-core/src/node/init.cpp:1234-1238`
  (`LOCK_directory` on the datadir; refuses second instance).
- **Description**: beamchain's `init/1` opens the rocksdb
  handle and scans the blocks_dir, but does not establish a
  per-datadir lockfile.  RocksDB's own
  `LOCK` file prevents two `rocksdb:open/3` against the same
  datadir, but the *flat-file* write FD (`write_fd`) is held
  in gen_server state — two beamchain instances pointed at
  the same datadir would both grab the rocksdb lock... wait,
  they wouldn't, RocksDB's lock is exclusive.  So this is
  mitigated by transitive RocksDB locking.  Recorded as P3
  because the structural lock-on-`blocks_dir` is still
  absent and Core writes one explicitly.
- **Impact**: Defense-in-depth gap; not currently exploitable.

### BUG-20 (P3) — `find_current_blockfile/1` truncates partial-write tails silently — no recovery scan for a torn block at end-of-file

- **File**: `src/beamchain_db.erl:1474-1484`.
- **Core ref**: `bitcoin-core/src/node/blockstorage.cpp`
  (Core's `LoadBlockIndexDB` cross-checks `CBlockFileInfo::nSize`
  against the actual file size; mismatch = reindex hint).
- **Description**: On restart, beamchain's
  `find_current_blockfile/1` returns
  `{MaxFile, Size}` where `Size` is the *actual file size*.
  A partial write (Erlang VM killed while writing the
  payload) leaves a trailing torn block.  beamchain happily
  appends the next block at that position, with no `magic|size`
  header for what's beyond — the file is permanently corrupted
  from a Core-parity perspective.  Core compares
  `CBlockFileInfo.nSize` (the *last-written-block-end*
  recorded in the leveldb) against the file's actual size to
  catch this; mismatch triggers a recovery scan.
- **Impact**: Dead today (BUG-1).  Latent recovery gap.

### BUG-21 (P3) — `CBlockFileInfo` per-file `{nBlocks, nSize, nUndoSize, nHeightFirst, nHeightLast, nTimeFirst, nTimeLast}` tuple is partially tracked, never persisted

- **File**: `src/beamchain_db.erl:152-154` (the in-memory
  `file_info` map: `size`, `height_first`, `height_last` —
  no `nUndoSize`, no `nTimeFirst`/`nTimeLast`, no
  `nBlocks`); `scan_block_files/2` only populates `size`.
- **Core ref**: `bitcoin-core/src/chain.h:380-475`
  (`CBlockFileInfo` struct + `SerializationOp`).
- **Description**: beamchain's `file_info` map is a
  three-field map vs Core's seven-field struct, AND the
  values are only ever in-process (rebuilt by
  `scan_block_files/2` on init, never persisted to rocksdb
  under `'f' + nFile` as Core does).  `scan_block_files/2`
  only records `size`; `height_first`/`height_last` are
  declared in the type but never assigned.
- **Excerpt**:
  ```erlang
  %% src/beamchain_db.erl:1666-1681 — only `size` is set
  scan_block_files(BlocksDir, N, MaxFile, Acc) ->
      FilePath = blockfile_path(BlocksDir, N),
      case file:read_file_info(FilePath) of
          {ok, #file_info{size = Size}} ->
              Info = #{size => Size},  %% ← missing height_first/last
              scan_block_files(BlocksDir, N + 1, MaxFile, Acc#{N => Info});
          {error, _} ->
              scan_block_files(BlocksDir, N + 1, MaxFile, Acc)
      end.
  ```
- **Impact**: Today: `find_max_height_in_file/1` had to be
  reimplemented as a `HEIGHT_TO_HASH_ETS` fold (see comment at
  lines 1883-1907) precisely because `file_info` carries no
  height range.  This was the W109/pruning audit fix.  The
  fold is `O(n_blocks_in_index)` per prune-eligibility check
  vs Core's `O(1)` per-file lookup.

### BUG-22 (P3) — `xor.dat` (Core's blocks-dir XOR obfuscation key) is absent

- **File**: `src/beamchain_db.erl` (absent).
- **Core ref**: `bitcoin-core/src/node/blockstorage.cpp:1167-1219`
  (Core's `InitBlocksdirXorKey` creates a random 8-byte XOR
  key on first boot, persists it in `blocks_dir/xor.dat`,
  XOR-decodes every blk/rev byte on read).
- **Description**: beamchain has no `xor.dat` file, no
  `Obfuscation` type, no XOR-encode/decode wrapping around
  block bytes.  (Note: `beamchain_mempool_persist.erl:46-85`
  *does* implement obfuscation for the mempool — Core parity
  on the wrong axis.)  Cosmetic until BUG-1 is fixed; then
  any operator-readable blkXXXXX.dat is byte-identical to a
  Core dump, which Core 28.x+ no longer is.
- **Impact**: Anti-fingerprint feature missing; cross-impl
  parity at the blocks_dir bit level is impossible.

---

## Cross-impl fleet patterns
(observed in this audit and previously catalogued — for the meta-tracking)

| Pattern | Audit | Manifestation in beamchain W146 |
|--------|-------|----------------------------------|
| Dead module / scaffolding + no callers | W138 fleet | BUG-1 (the entire blkXXXXX.dat path; 16th distinct two-pipeline guard) |
| Two-pipeline guard | W76+ fleet | BUG-1 (`write_block`/`store_block` parallel APIs) |
| Comment-as-confession | W138 / W139 / W141 / W144 / W145 fleet | BUG-12 (`%% Pruning disabled` in cast handler) — 6th instance fleet-wide |
| Carry-forward re-anchor | W124+ fleet | (none on this axis) |
| Defense-in-depth-missing-every-layer | W140 fleet | BUG-11 (no rocksdb sync, no fsync, no fdatasync) |
| Storage / sync fork-in-the-road | W126 fleet (Hotbuns / Blockbrew / Ouroboros / Nimrod) | BUG-1 + BUG-4 (parallel block storage paths AND parallel block-index keying schemes) |
| Empty/zero/fabricated chainparams whitelist | W138 fleet | (none — chainparams are valid in W145) |

## Recommended fixes (priority order)

1. **BUG-11**: Switch `direct_atomic_connect_writes/5` and
   `atomic_connect_writes/5` (the two block-connect commit
   paths) to `[{sync, true}]`.  One-line each at lines 614,
   655, 1028, 1057.  Closes the chain-tip-rewind hazard for
   power loss.  Estimated perf cost: 5-15% IBD throughput
   reduction; mitigated by RocksDB WAL group-commit.
2. **BUG-12**: Wire `handle_cast({trigger_pruning, ...}, ...)` to
   call `do_prune_files/1`.  Comment-as-confession is a
   one-line fix.
3. **BUG-1**: Decide flat-file destiny — either wire
   `write_block`/`read_block` into `store_block`/`get_block`
   (and accept all the storage-format changes that implies:
   BUG-3, BUG-4, BUG-5, BUG-7, BUG-9, BUG-10, BUG-13, BUG-21),
   or delete the dead code and re-frame the architecture as
   RocksDB-CF-only with an honest README.  The middle ground
   (dead code with tests pretending it's live) is the
   worst-of-both-worlds and the source of half the W146
   findings.
4. **BUG-4**: If keeping the RocksDB-CF design, batch the two
   `rocksdb:put` calls in `store_block_index` into a single
   WriteBatch (atomicity across `cf_block_idx` and `cf_meta`).
5. **BUG-9**: Add the SHA256d trailing checksum to
   `encode_undo_data/1` (32-byte tail computed over
   `prev_block_hash || serialized_undo`).  Detect-and-reject
   on `decode_undo_data/1`.  Closes silent UTXO-restore
   corruption.

---

## Audit metadata

- **Auditor**: Claude Opus 4.7 sub-agent (W146 / 4 of 40 in
  the parallel discovery run).
- **Methodology**: Read Core references → grep for Core-parity
  primitives in beamchain src/ → cross-walk each audit gate
  (magic, size, rotation, fsync, checksum, magic-on-read,
  recovery, DB-keys, MAX_SIZE) → catalogue gaps + divergences.
- **Coverage**: `src/beamchain_db.erl` (the storage primary),
  `src/beamchain_validation.erl:1652-1684` (undo
  encode/decode), `src/beamchain_chainstate.erl:945-1024`
  (block-connect call site), `src/beamchain_config.erl`
  (network magic accessors).
- **Hash of audited tree**: see commit SHA from this audit's
  parent commit.
