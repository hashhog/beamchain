# W138 — assumeUTXO snapshots (loadtxoutset / dumptxoutset) audit (beamchain)

Discovery-only wave. 30 audit gates against Core's assumeUTXO surface:

- `bitcoin-core/src/node/utxo_snapshot.{h,cpp}` (the `SnapshotMetadata`
  on-disk format, `WriteSnapshotBaseBlockhash` / `ReadSnapshotBaseBlockhash`
  persistence, `FindAssumeutxoChainstateDir` discovery, and the magic
  bytes constant `{'u','t','x','o',0xff}`).
- `bitcoin-core/src/validation.cpp` — `ChainstateManager::ActivateSnapshot`
  (5588-5728), `PopulateAndValidateSnapshot` (5754-5954),
  `MaybeValidateSnapshot` (5967-6077), `LoadAssumeutxoChainstate`
  (6151-6168) and the supporting `Chainstate::SnapshotBase`,
  `m_from_snapshot_blockhash`, `m_target_blockhash`, `m_target_utxohash`
  and `m_assumeutxo` Assumeutxo-state machine.
- `bitcoin-core/src/rpc/blockchain.cpp` — `dumptxoutset` (3074-3231),
  `PrepareUTXOSnapshot` (3233-3269), `WriteUTXOSnapshot` (3271-3348),
  `loadtxoutset` (3368-3447), `getchainstates` (3462), and the
  background-validation cs_main + `TemporaryRollback` machinery
  (3061-3066).
- `bitcoin-core/src/kernel/chainparams.h` — `AssumeutxoData` /
  `AssumeutxoHash` shape and the four mainnet + two testnet4 entries
  used as the strict-content-hash whitelist.

No BIPs apply; assumeUTXO is a Core-specific operator feature documented
in `doc/design/assumeutxo.md` (referenced from `loadtxoutset` help text).

Companion audits to cross-reference:

- **W102** (predecessor) — covered 12 of these gates and landed
  `do_load_snapshot` G6/G7/G8/G9 plus `load_snapshot_validated`
  G1..G5 (`beamchain_chainstate.erl:2119-2230` +
  `beamchain_snapshot.erl:346-457`). W138 picks up where W102 stopped:
  the **post-load machinery** — `m_assumeutxo` state transitions, the
  background-vs-snapshot dual chainstate, `MaybeValidateSnapshot`
  auto-trigger, `WriteSnapshotBaseBlockhash` persistence,
  `FindAssumeutxoChainstateDir` reattach-on-restart, network-services
  downgrade to `NODE_NETWORK_LIMITED`, `getchainstates` exposure,
  Core-shape `dumptxoutset` / `loadtxoutset` JSON, and the
  cleanup-bad-snapshot leveldb-delete dance — none of which W102
  catalogued.
- **W101** — `ActivateBestChain`. The natural call-out point for the
  W138 G12 / G19 / G22 `MaybeValidateSnapshot` insertion lives in
  `do_connect_block_inner` (the equivalent of Core's
  `ActivateBestChainStep` → `ConnectTip` → `MaybeValidateSnapshot`).
- **W133** — Index databases. Both `dumptxoutset rollback`'s
  `TemporaryRollback` (validation invalidate + reconsider) and the
  snapshot-leveldb-suffix dance touch the same index plumbing.
- **W128/W104** — `NODE_NETWORK_LIMITED` advertising. Core's
  `loadtxoutset` calls `RemoveLocalServices(NODE_NETWORK)` +
  `AddLocalServices(NODE_NETWORK_LIMITED)` after a successful load
  (rpc/blockchain.cpp:3432-3435). beamchain has the constant
  (`beamchain_peer.erl:1313`) but no plumbing.

Reference: `bitcoin-core/src/{node,validation,rpc,kernel}/...` files
listed above plus `doc/design/assumeutxo.md` (linked from Core's
`loadtxoutset` help text).

## Status counts (30 gates)

- **PRESENT** (Core-parity, or internally consistent + Core-compatible): 11
- **PARTIAL** (some piece matches, others diverge or are simplified): 8
- **MISSING** (no equivalent in beamchain): 11

Headline: **23 bugs**, severity distribution
**1 CDIV / 5 HIGH / 11 MEDIUM / 6 LOW**.

Most assumeUTXO correctness is operator-experience-facing (snapshot
mis-load → operator restarts), but two pieces escalate higher:

1. **BUG-1 (CDIV)** — **Regtest assumeutxo entry has placeholder zero
   hashes.** `beamchain_chain_params:regtest_assumeutxo/0`
   (`beamchain_chain_params.erl:560-568`) ships height 110 with
   `block_hash => <<0:256>>` and `utxo_hash => <<0:256>>`. Any
   regtest snapshot loaded through this code path will fail the
   strict content-hash gate (`verify_snapshot/2` →
   `compute_utxo_hash_from_list` vs `<<0:256>>`) with the verbatim
   Core wording — which is the correct refusal — **but** the
   `get_assumeutxo_by_hash` lookup will match ANY snapshot whose
   metadata happens to carry `<<0:256>>` as its base hash, because the
   reverse lookup is keyed by `block_hash`. Two consequences:
   (a) an attacker can construct a `<<0:256>>`-metadata snapshot
   that will be **routed past** the `unknown_snapshot_base` rejection
   and into `load_snapshot_validated` / `verify_snapshot`, opening a
   wider per-coin parse surface to a malicious file; and
   (b) regtest's smoke harness cannot actually round-trip a snapshot
   (every dump→load fails on the strict-hash mismatch). The W102 test
   `regtest_placeholder_test/0` already documents (a); W138 elevates
   to **CDIV** because the same `get_assumeutxo_by_hash` is the
   *only* gate between an untrusted snapshot file and the validated
   parse path — a hash collision on a placeholder zero key is a
   structural defect, not a regtest-only convenience oversight.

2. **BUG-2 (HIGH)** — **`MaybeValidateSnapshot` equivalent is never
   auto-triggered.** Core invokes `MaybeValidateSnapshot` from
   `ActivateBestChain` (validation.cpp:3104) on every
   `ConnectTip`, so the moment the background chainstate reaches the
   snapshot block, snapshot validation, `m_assumeutxo = VALIDATED`,
   and the IBD-chainstate teardown all happen automatically.
   `beamchain_chainstate_sup:merge_chainstates/0`
   (`beamchain_chainstate_sup.erl:94-111`) exists and contains the
   verify-then-stop logic, but it is **never called** from
   `do_connect_block_inner` (`beamchain_chainstate.erl:884-1065`) —
   confirmed by grep: no `merge_chainstates` reference outside the
   sup module itself. Background validation will therefore run to
   the snapshot height and then sit idle; the snapshot chainstate
   never transitions to "validated" and the background chainstate is
   never reaped. Operationally this looks like "background sync
   completed but the node is still in the limited-services /
   snapshot-unvalidated state forever" — the user sees normal block
   relay but `getchainstates` (when added per BUG-13) would never
   show `validated=true`.

3. **BUG-3 (HIGH)** — **No `WriteSnapshotBaseBlockhash` /
   `ReadSnapshotBaseBlockhash` persistence at all.** Core persists
   the snapshot base blockhash to a `base_blockhash` file inside the
   snapshot-suffixed chaindir (`node/utxo_snapshot.cpp:22-46`) and
   reads it back during init via `LoadAssumeutxoChainstate`
   (`validation.cpp:6151-6168`), so a node restart in the middle of
   background validation correctly reattaches the snapshot chainstate
   and continues. beamchain has no `base_blockhash` file: the
   `snapshot_base_height` / `snapshot_base_hash` fields in
   `#state{}` (`beamchain_chainstate.erl:147-149`) live only in
   memory and are reset on `init_chainstate(main, _)` to the
   `load_chain_tip()` result, which knows nothing about whether the
   tip was reached via snapshot or normal IBD. Net effect: a node
   restarted between `loadtxoutset` and full background validation
   loses the dual-chainstate state machine. The persisted chainstate
   tables (`UTXO_CACHE`, etc.) are reused as a single combined
   chainstate, blurring the snapshot-vs-validated distinction the way
   `getchainstates` would normally report it.

4. **BUG-4 (HIGH)** — **`dumptxoutset` and `loadtxoutset` JSON
   response shapes do not match Core.** Three divergences:
   - **`loadtxoutset`** (`beamchain_rpc.erl:8780-8785`) returns
     `base_blockhash`, `coins_loaded`, `base_height`, `message`.
     Core (`rpc/blockchain.cpp:3439-3444`) returns
     `coins_loaded`, **`tip_hash`** (different key name),
     `base_height`, **`path`** (different field; beamchain omits).
     The custom `message` field has no Core analog and will be
     rejected by Core-shape clients.
   - **`dumptxoutset`** (`beamchain_rpc.erl:9008-9020`) returns
     `coins_written`, `base_hash`, `base_height`, `path`,
     `txoutset_hash`, `nchaintx`. The keys MATCH Core
     (`rpc/blockchain.cpp:3341-3346`) — but the **hex encoding** is
     `display_hex_encode(reverse_bytes(BaseHash))` for `base_hash`
     and `reverse_bytes(UtxoHash)` for `txoutset_hash`, matching
     `uint256::ToString` byte-reversal order. That part is correct.
   - **`loadtxoutset` `base_blockhash`** is `hex_encode(BaseHash)`
     in `beamchain_rpc.erl:8781` — i.e. *internal byte order*, NOT
     `uint256::ToString` order. A test client comparing against
     `dumptxoutset.base_hash` will see two different hex strings
     for the same blockhash (one reversed, one not). This is the
     load-vs-dump asymmetry.

5. **BUG-5 (HIGH)** — **`getchainstates` RPC is not implemented.**
   Core's `getchainstates` (`rpc/blockchain.cpp:3462-3522`) is the
   sole RPC surface that distinguishes "snapshot loaded, background
   chainstate validating" from "fully validated". It returns
   `headers` plus one or two `chainstates` entries (ordered by
   work), each with `snapshot_blockhash` (only when from snapshot)
   and `validated` boolean (`m_assumeutxo == Assumeutxo::VALIDATED`).
   beamchain has no handler — see the dispatch grep:
   `beamchain_rpc.erl:767-770` has `loadtxoutset` + `dumptxoutset`
   but no `getchainstates` clause; `beamchain_rpc.erl:900-902` lists
   them in the help text without a `getchainstates` entry. Operators
   running the full assumeUTXO workflow have no way to query the
   actual validation state.

---

## Gate index (1..30)

| #  | Name | Status | Core ref | beamchain ref |
|----|------|--------|----------|---------------|
| 1  | `SNAPSHOT_MAGIC_BYTES = "utxo"+0xff` 5-byte constant | PRESENT  | utxo_snapshot.h:28 | beamchain_snapshot.erl:69 (?SNAPSHOT_MAGIC) |
| 2  | `SnapshotMetadata::VERSION = 2` uint16-LE + supported-set check | PRESENT  | utxo_snapshot.h:39 + Unserialize:81-86 | beamchain_snapshot.erl:70 (?SNAPSHOT_VERSION) + parse_metadata/1:304-311 |
| 3  | `pchMessageStart` 4-byte equality (per-network) on load | PRESENT  | utxo_snapshot.h:88-101 + validation.cpp:5605 | parse_snapshot_validated/3:351-353 |
| 4  | Fixed 51-byte metadata header layout (5 magic + 2 ver + 4 magic + 32 hash + 8 count) | PRESENT  | utxo_snapshot.h:Serialize:64-70 + Unserialize:74-105 | beamchain_snapshot.erl:71 (?METADATA_SIZE) + serialize_metadata/3:288-296 + parse_metadata/1:300-303 |
| 5  | Per-coin height > base_height refusal (Core G2) | PRESENT  | validation.cpp:5814-5818 | parse_coin_validated/2:426-428 (W102 G2) |
| 6  | Per-coin vout >= UINT32_MAX refusal (Core G3) | PRESENT  | validation.cpp:5815 (`std::numeric_limits<uint32_t>::max()`) | parse_txid_coin_entries_validated/5:404-406 (W102 G3) |
| 7  | Per-coin `MoneyRange(value)` refusal (Core G4) | PRESENT  | validation.cpp:5820-5822 | parse_coin_validated/2:434-436 (W102 G4) |
| 8  | Trailing-bytes-after-last-coin refusal (Core G5) | PRESENT  | validation.cpp:5872-5882 (`out_of_coins` exception probe) | parse_snapshot_validated/3:358-365 (W102 G5) |
| 9  | "Can't activate snapshot-based chainstate more than once" guard (Core G6) | PARTIAL  | validation.cpp:5600-5601 (checks `m_from_snapshot_blockhash`) | do_load_snapshot/2:2124-2127 (W102 G6) — checks `chainstate_role =:= snapshot` not blockhash, so a previous run that crashed mid-load and left a `snapshot_base_height` set in some not-flushed way would still be allowed |
| 10 | Mempool-non-empty refusal (Core G7) | PARTIAL  | validation.cpp:5626-5628 | do_load_snapshot/2:2129-2133 — checks `beamchain_mempool:get_info()` `size` but the mempool gen_server may not be running at all (regtest test harness), in which case `maps:get(size, MempoolInfo, 0)` returns the default 0 and the gate silently passes |
| 11 | BLOCK_FAILED_VALID refusal on base block (Core G8) | PRESENT  | validation.cpp:5617-5619 (status & BLOCK_FAILED_VALID) | do_load_snapshot_with_height/6:2160-2172 (W102 G8) |
| 12 | Snapshot chainwork > active chainwork refusal (Core G9 — outer check) | PARTIAL  | validation.cpp:5703-5708 (uses `CBlockIndexWorkComparator`) | do_load_snapshot_with_height/6:2174-2184 — uses `active_tip_chainwork(tip_hash)` and compares strict-greater; matches Core direction. **BUT** allows `SnapCWInt =:= 0` to bypass (line 2182) "if chainwork unknown, permit anyway" — Core has no such exception, so a snapshot at a block that was inserted via `addbloomtoindex` (or any path that left `chainwork = <<0:256>>` in the block-index entry) silently sidesteps the gate |
| 13 | Snapshot chainwork > active chainwork — inner check inside `PopulateAndValidateSnapshot` | MISSING  | validation.cpp:5787-5788 | beamchain does the check once in `do_load_snapshot_with_height` BEFORE coin parsing, never again at the equivalent of `PopulateAndValidateSnapshot`. Core does it TWICE (the comment at 5784-5786 explicitly says "duplicate check"). A long-running parse that races with a fast IBD chainstate (testnet only) could see the active tip surpass the snapshot mid-load and would no longer be useful — Core catches this; beamchain doesn't |
| 14 | Headers-chain ancestor check (snapshot base must be on `m_best_header`) | MISSING  | validation.cpp:5622-5624 (`m_best_header->GetAncestor(...) != snapshot_start_block`) | do_load_snapshot_with_height looks up the base by `get_block_index_by_hash` but does not verify the block is on the *headers* best-chain. A snapshot whose base is a stale-fork header still resident in the index will be loaded (and then the chainwork check above is the only remaining filter) |
| 15 | `m_from_snapshot_blockhash` persisted in the chainstate ID (Core's restart-survival ID) | MISSING  | validation.cpp:1872-1886 + Chainstate ctor at validation.h:589 | beamchain `chainstate_role` is in-memory only; `snapshot_base_hash` is in the gen_server `#state{}` but not serialized. After process restart, the role is read from `init_chainstate(main \| background \| snapshot, _)` arg, which the supervisor selects via its child-spec — no on-disk hint |
| 16 | `WriteSnapshotBaseBlockhash` (persist `base_blockhash` file in chaindir) | MISSING  | node/utxo_snapshot.cpp:22-46 | no `base_blockhash` file written. Headline BUG-3 |
| 17 | `ReadSnapshotBaseBlockhash` / `LoadAssumeutxoChainstate` (re-attach snapshot on init) | MISSING  | node/utxo_snapshot.cpp:48-81 + validation.cpp:6151-6168 | `init_chainstate(main, _)` calls `load_chain_tip()` and assumes the role from the supervisor child-spec arg; no re-attach-on-init logic |
| 18 | `FindAssumeutxoChainstateDir` (discover `_snapshot`-suffixed chaindir) | MISSING  | node/utxo_snapshot.cpp:83-92 | beamchain has a single chainstate dir (RocksDB CF), no `_snapshot` suffix scheme; the "two chainstates" model is supervisor-spawned twin gen_servers reusing the same ETS tables (`beamchain_chainstate.erl:584-586` literally states "Snapshot and background chainstates reuse the main ETS tables") — this is a fundamental architecture divergence from Core |
| 19 | `MaybeValidateSnapshot` auto-trigger from connect-block | MISSING  | validation.cpp:3104 (called from `ActivateBestChain`) | `do_connect_block_inner` (`beamchain_chainstate.erl:884-1065`) has no `merge_chainstates` call. Headline BUG-2 |
| 20 | Bad-snapshot cleanup: delete leveldb dir on failed load (Core's `DeleteCoinsDBFromDisk`) | MISSING  | validation.cpp:5677-5694 (`cleanup_bad_snapshot` closure) | beamchain `do_load_snapshot_parse` returns `{error, ...}` and unwinds without deleting any DB state — but because beamchain *reuses the main ETS tables*, a partially-loaded snapshot leaves UTXOs in `?UTXO_CACHE` that will be flushed on next checkpoint. Cleanup is structurally missing (and architecturally awkward to add) |
| 21 | `NODE_NETWORK` removal + `NODE_NETWORK_LIMITED` advertisement on successful load | MISSING  | rpc/blockchain.cpp:3432-3435 | `?NODE_NETWORK_LIMITED` constant defined (`beamchain_peer.erl:1310-1313`) and used in the prune-mode path, but the `loadtxoutset`-success branch does not call any equivalent of `RemoveLocalServices` / `AddLocalServices` — the just-loaded node will continue advertising itself as a full-history node despite serving only ~288 blocks of history |
| 22 | `m_assumeutxo` Assumeutxo enum state machine (UNVALIDATED → VALIDATED → INVALID) | MISSING  | validation.h:630 + transitions at validation.cpp:6010, 6072 | beamchain has a `chainstate_role` field (`main \| snapshot \| background`) that is set once at init and never transitions on `MaybeValidateSnapshot`-equivalent completion (which would need to mutate `snapshot` → `main` and stop the background gen_server) |
| 23 | `dumptxoutset` `path` already-exists refusal with Core wording | PRESENT  | rpc/blockchain.cpp:3139-3143 | rpc_dumptxoutset/1:8854-8860 — refuses with the verbatim "`<path>` already exists. If you are sure this is what you want, move it out of the way first." message |
| 24 | `dumptxoutset` write to `<path>.incomplete` + atomic rename | PRESENT  | rpc/blockchain.cpp:3134-3137 + 3223-3225 | write_snapshot_atomic/3:9031-9050 (fsync before rename — beamchain explicitly fsyncs which Core does too via `AutoFile::fclose`) |
| 25 | `dumptxoutset` `type=rollback`/named option `rollback=<height\|hash>` parsing + `TemporaryRollback` | PARTIAL  | rpc/blockchain.cpp:3115-3130 + 3157 (`TemporaryRollback` invalidate→reconsider) | resolve_dump_target/5:8894-8990 parses the three modes correctly. The actual rollback dance (`do_dump_with_rollback`) walks blocks back-and-forward by `disconnect_block`/`connect_block` rather than using `InvalidateBlock`/`ReconsiderBlock` — semantics are similar but Core's path also temporarily disables network activity (`NetworkDisable`) which beamchain mirrors via `network_disable_during_dump` (`beamchain_mempool.erl:3811-3818` mempool gate) — partial because the gate is on inbound mempool submissions only, not P2P outbound or `setnetworkactive` |
| 26 | `dumptxoutset` `txoutset_hash` matches `m_assumeutxo_data.hash_serialized` for the dumped height | PARTIAL  | rpc/blockchain.cpp:3211 + 3345 (uses `PrepareUTXOSnapshot`'s `HASH_SERIALIZED` stats) | do_dump_at_tip/4:8997 (`compute_utxo_hash` does the SHA256d-via-`tx_out_ser` walk). Implementation should be byte-equal to Core but **no canary test** wires up a regtest dump→assumeutxo-table lookup→hash-equality assertion (the regtest entry's `utxo_hash` is `<<0:256>>`, BUG-1, which makes such a test trivially fail anyway) |
| 27 | `loadtxoutset` JSON response shape (Core keys: `coins_loaded`, `tip_hash`, `base_height`, `path`) | MISSING  | rpc/blockchain.cpp:3439-3444 | rpc_loadtxoutset/1:8780-8785 uses `base_blockhash` (not `tip_hash`), omits `path`, and adds a non-Core `message` field. Headline BUG-4 |
| 28 | `loadtxoutset` `base_blockhash` rendered in `uint256::ToString` (reverse-of-internal) byte order | MISSING  | rpc/blockchain.cpp:3441 (`tip->GetBlockHash().ToString()`) | rpc_loadtxoutset/1:8781 emits `hex_encode(BaseHash)` which is internal-order hex, while `dumptxoutset` correctly reverse-encodes (line 9011-9012). The dump and load disagree about byte order |
| 29 | `getchainstates` RPC (per-chainstate `validated` + `snapshot_blockhash`) | MISSING  | rpc/blockchain.cpp:3462-3522 | No `getchainstates` handler in `beamchain_rpc.erl`. Headline BUG-5 |
| 30 | `getblockchaininfo`'s `verificationprogress` accounts for snapshot-vs-real-tip | MISSING  | rpc/blockchain.cpp:GuessVerificationProgress + 1485 (uses `m_best_header`) | rpc_getblockchaininfo/0:972-1043 computes `verificationprogress` against the active tip without distinguishing snapshot vs validated background; a snapshot at height 840k on mainnet will jump straight to 100% even though background validation is at height 30k. No `background_validation` sub-object exposed |

The "audit-flip" cells (status != PRESENT) are gates 9, 10, 12 plus
13..22 and 25..30 — **19 gates** marked PARTIAL or MISSING. Each maps
to one or more BUG-N in the next section. The 11 PRESENT gates
(1, 2, 3, 4, 5, 6, 7, 8, 11, 23, 24) confirm that:

- the **on-disk wire format** (magic, version, network magic, 51-byte
  header, per-coin VARINT/CompactSize encodings, MoneyRange + UINT32_MAX
  + base-height gates) is Core-parity, and
- the **per-file mechanics** (`<path>.incomplete` atomic rename,
  already-exists refusal, BLOCK_FAILED_VALID base check) are also
  correct.

What is **missing** is the **state machine after a load succeeds**:
persistence to disk, restart-survival, `MaybeValidateSnapshot`
auto-trigger, `Assumeutxo::VALIDATED` transition, services-downgrade,
and the matching `getchainstates` / `getblockchaininfo` reporting.

---

## Bug catalogue (23 bugs)

### CDIV (1)

**BUG-1 (CDIV)** — Regtest assumeutxo entry has placeholder
`<<0:256>>` block_hash + utxo_hash. Headlined above. The
`get_assumeutxo_by_hash` reverse lookup in
`beamchain_chain_params.erl:459-471` matches by `block_hash`; with
the regtest entry's placeholder, any snapshot whose metadata header
declares `<<0:256>>` as base hash bypasses the
`unknown_snapshot_base` rejection and proceeds into per-coin parse.
Fix: either populate the regtest entry with real (compute-at-startup
or hardcoded-after-mining) hashes for height 110, or rip the regtest
entry out and add a strict refusal "assumeutxo not supported on
regtest" until real values are computed. Note: this is **above**
HIGH because the same lookup is the *only* gate on the file's
identity — every per-coin check happens AFTER this point.

### HIGH (5)

**BUG-2 (HIGH)** — `MaybeValidateSnapshot` equivalent never
auto-triggered. Headlined above. Fix: add a
`maybe_validate_snapshot(State)` call in
`do_connect_block_inner` (just after the `ets:insert(?CHAIN_META,
{tip, BlockHash, Height})` at `beamchain_chainstate.erl:970`), which:
- checks `chainstate_role =:= background`,
- checks `Height =:= snapshot_base_height`,
- calls `beamchain_chainstate_sup:merge_chainstates/0`,
- if `merge_chainstates` returns `ok`, mutate the *snapshot*
  gen_server's `chainstate_role` from `snapshot` → `main` (the
  Core equivalent of `Assumeutxo::VALIDATED`).
The merge function itself already does the SHA256d check — the
missing piece is the trigger.

**BUG-3 (HIGH)** — No `WriteSnapshotBaseBlockhash` /
`ReadSnapshotBaseBlockhash` persistence. Headlined above. Fix:
- add `beamchain_snapshot:write_base_blockhash(ChainDir, Hash)`
  + `read_base_blockhash(ChainDir)` mirroring Core's two helpers
  (`node/utxo_snapshot.cpp:22-46` + `48-81`);
- call write in `do_load_snapshot_parse` after a successful load,
  using the per-network chaindir + a `base_blockhash` filename;
- call read in `init_chainstate(main, _)`, and if a value is
  returned, branch into the snapshot-attach init path instead of
  `load_chain_tip`.
Implementation note: beamchain's RocksDB-CF model doesn't have a
"chainstate dir" per se — the equivalent is the datadir. We can
either (a) write `base_blockhash` directly under datadir or (b)
write it as a special RocksDB CF entry. (a) is closer to Core; (b)
is more idiomatic.

**BUG-4 (HIGH)** — `loadtxoutset` JSON shape (G27 + G28). Headlined
above. Fix: rename `base_blockhash` → `tip_hash`, add `path`
field, drop `message`, and reverse-encode the hash hex with
`reverse_bytes` before `hex_encode`. Three-line change in
`rpc_loadtxoutset/1` at `beamchain_rpc.erl:8780-8785`. Forward-test
should compare against Core's `loadtxoutset` JSON byte-for-byte.

**BUG-5 (HIGH)** — `getchainstates` RPC not implemented. Headlined
above. Fix: add handler in `beamchain_rpc.erl`:
- one entry per running chainstate (`chainstate_sup:which_children`),
- per-entry fields: `blocks`, `bestblockhash` (display order),
  `bits`, `target`, `difficulty`, `verificationprogress`,
  `snapshot_blockhash` (only when role=snapshot), `validated`
  (boolean: `chainstate_role =/= snapshot \|\| snapshot_validated`),
  `coins_db_cache_bytes`, `coins_tip_cache_bytes`.
- top-level `headers` from the headers-sync state.
Then expose in `getblockchaininfo` as a `background_validation`
sub-object (Core has this since v23 — see W128/W104 audit).

**BUG-6 (HIGH)** — `m_assumeutxo` state machine is missing entirely
(G22). Without an explicit UNVALIDATED → VALIDATED → INVALID
state machine, the rest of the system has no way to know whether
the chainstate is trusted. Three downstream blast radii:
- `getchainstates` (BUG-5) needs the bit.
- `MaybeValidateSnapshot` (BUG-2) auto-trigger needs to mutate it.
- `verifychain` / `reconsiderblock` / `BLOCK_VALID_SCRIPTS` raise
  paths don't currently care about snapshot state, but they should
  because the snapshot block has no real script-validation evidence
  — Core papers over this via `BLOCK_OPT_WITNESS` flag-faking at
  `validation.cpp:5934-5937`, which beamchain does not do.

### MEDIUM (11)

**BUG-7 (MEDIUM)** — Snapshot-role double-load guard checks role
instead of `from_snapshot_blockhash` (G9). The current check at
`do_load_snapshot/2:2125` is:
```erlang
case State#state.chainstate_role of
    snapshot -> {error, snapshot_already_active};
    _ -> ...
```
But the gen_server can be the *main* chainstate that previously
loaded a snapshot (the role transitions back to `main` after
background validation completes — once BUG-2 is fixed). At that
point, a second `loadtxoutset` call would pass the role check and
silently overwrite the validated UTXO set. Fix: also gate on
`snapshot_base_hash =/= undefined`.

**BUG-8 (MEDIUM)** — Mempool-non-empty guard fails open when
mempool is down (G10). `beamchain_mempool:get_info()` is a
`gen_server:call` that will time out or `noproc`-crash if the
mempool gen_server isn't running (regtest test harnesses do start
without one). The pattern at `do_load_snapshot/2:2130`
(`maps:get(size, MempoolInfo, 0)`) yields the default 0 in that
case, which silently passes the gate. Fix: catch the
`noproc`/timeout in a `try/catch` and refuse rather than allow.

**BUG-9 (MEDIUM)** — Chainwork "zero is OK" exception in G12
`do_load_snapshot_with_height/6:2182`. The clause:
```erlang
case SnapCWInt =:= 0 orelse SnapCWInt > ActiveTipCWInt of
```
The `=:= 0` arm means "if chainwork unknown, permit anyway", which
Core never does. A bug in upstream `direct_atomic_connect_writes`
(or any caller of `beamchain_db`) that mis-encodes chainwork
silently lets a junk-snapshot through. Fix: drop the `=:= 0`
allowance entirely. Cross-reference W109 atomic-connect-writes
hardening.

**BUG-10 (MEDIUM)** — Inner chainwork check inside the populate
path is missing (G13). Core does the chainwork comparison twice —
once in `ActivateSnapshot` (5703-5708) and again in
`PopulateAndValidateSnapshot` (5787-5788). beamchain only does the
outer one. Race window: between
`do_load_snapshot_with_height`'s check and the end of
`do_load_snapshot_parse`'s coin parsing (which can take many
minutes on mainnet), the active chainstate may have caught up past
the snapshot. Fix: re-check chainwork inside
`do_load_snapshot_parse` after `populate_utxo_cache_from_snapshot`,
before `ets:insert(?CHAIN_META, ...)`.

**BUG-11 (MEDIUM)** — Headers-chain ancestor check missing (G14).
`do_load_snapshot_with_height` looks up the base by
`get_block_index_by_hash`, but does not verify the result is on
the best-headers chain. A stale-fork header still resident in the
block-index DB will pass. Fix: add a
`is_on_headers_best_chain(BaseHash, BaseHeight)` helper (walks back
from `header_sync:best_header()` and checks the
`GetAncestor(height) == base` predicate) and gate the load on it,
matching Core's `m_best_header->GetAncestor(...) !=
snapshot_start_block` refusal text "A forked headers-chain with
more work than the chain with the snapshot base block header
exists. Please proceed to sync without AssumeUtxo."

**BUG-12 (MEDIUM)** — Bad-snapshot cleanup is structurally missing
(G20). Core's `cleanup_bad_snapshot` closure in
`validation.cpp:5677-5694` deletes the snapshot leveldb dir on
failure. beamchain's `do_load_snapshot_parse` returns `{error,
...}` without rolling back the ETS-table mutations that
`populate_utxo_cache_from_snapshot` may have already started.
Specifically: `populate_utxo_cache_from_snapshot/1:2233-2252` calls
`ets:delete_all_objects(?UTXO_CACHE)` BEFORE inserting any new
coins, which means **a failed load destroys the previous UTXO set
without replacement** — far worse than Core (which destroys only
the snapshot's leveldb dir). Fix: snapshot the ETS tables before
the destructive call, restore on error.

**BUG-13 (MEDIUM)** — `getblockchaininfo` `verificationprogress`
does not distinguish snapshot vs background (G30). Core
(`rpc/blockchain.cpp` GuessVerificationProgress) uses
`m_best_header` plus the per-chainstate tip to compute the
*background* progress, which is meaningful during snapshot sync.
beamchain reports the snapshot chainstate's progress (= ~1.0
immediately after `loadtxoutset` on mainnet) and the operator has
no signal whether background is at 30k or 800k. Cross-link with
BUG-5 (`getchainstates`) and BUG-6 (`m_assumeutxo` state).

**BUG-14 (MEDIUM)** — No `NODE_NETWORK` → `NODE_NETWORK_LIMITED`
downgrade on successful load (G21). Core unconditionally drops
`NODE_NETWORK` and adds `NODE_NETWORK_LIMITED` after
`ActivateSnapshot` returns successfully
(`rpc/blockchain.cpp:3432-3435`). beamchain continues advertising
`NODE_NETWORK`, falsely claiming to serve full block history when
in fact it has only the most recent ~288 blocks of UTXO-set-derived
data. Effect: well-meaning SPV peers that connect for historical
block-data requests will hit silent timeouts. Fix: in
`do_load_snapshot_parse`, on the success branch, call
`beamchain_peer_manager:remove_local_services(?NODE_NETWORK)`
+ `add_local_services(?NODE_NETWORK_LIMITED)` (or whatever the
internal services-mask manipulation API is — verify against
`beamchain_peer.erl`).

**BUG-15 (MEDIUM)** — No `m_from_snapshot_blockhash`-equivalent
persistence (G15). beamchain stores `snapshot_base_hash` in the
gen_server `#state{}` only, so a crash between `loadtxoutset` and
background-validation completion **loses** the snapshot-attach
information; on restart the supervisor spawns a fresh `main`
chainstate with no awareness of the prior snapshot. Cross-link
with BUG-3 (which fixes the on-disk piece).

**BUG-16 (MEDIUM)** — No `LoadAssumeutxoChainstate`-equivalent
re-attach on init (G17). Even if BUG-3 lands a `base_blockhash`
file, the init code path (`init_chainstate(main, _)`) needs to
*notice* the file and route through a snapshot-attach branch
rather than the IBD-resume `load_chain_tip()` branch. Two-impl
fix: BUG-3 writes; BUG-16 reads.

**BUG-17 (MEDIUM)** — Snapshot-suffixed chaindir scheme is absent
(G18). Core's two-chainstate model uses two leveldb dirs (`chainstate`
+ `chainstate_snapshot`); beamchain runs two gen_servers against
**the same ETS tables and the same RocksDB CF**, which means
"background validation" can never produce a side-by-side
comparison of UTXO sets. Fix: either (a) introduce a snapshot CF
suffix, or (b) accept this as an architectural divergence and
document that beamchain's "background validation" is a re-walk
not a side-by-side validation. (a) is much more work.

### LOW (6)

**BUG-18 (LOW)** — `loadtxoutset` `message` field has no Core
analog. Helper for human operators but not in Core's JSON contract.
Fix: drop in the BUG-4 cleanup. (Aliased into BUG-4 for fix scope.)

**BUG-19 (LOW)** — `dumptxoutset rollback` semantics are correct
but the *network-disable* gate is mempool-only, not P2P-outbound
(G25). The gate at `beamchain_mempool.erl:3811-3818` prevents
inbound mempool submissions during a rollback dump but does not
mute the peer-message loop. Core's `NetworkDisable` is broader
(disables outbound block requests too). Effect on a long
rollback: the node will respond to inbound `getheaders` with stale
data. Fix: extend the gate to the peer-manager loop.

**BUG-20 (LOW)** — No regtest snapshot canary test (G26). The
regtest assumeutxo entry's `utxo_hash` is `<<0:256>>` (BUG-1), so
even if a smoke test dumped and immediately re-loaded a regtest
snapshot, the strict-content-hash check would correctly fail. Fix
in two parts: (a) fix BUG-1 by computing real regtest hashes; (b)
add a `test_dump_load_roundtrip` test in
`beamchain_w138_assumeutxo_tests` that exercises the full
round-trip on regtest.

**BUG-21 (LOW)** — `dumptxoutset` `path` for **relative** input
paths is missing the `datadir` prefix. Core
(`rpc/blockchain.cpp:3133`) joins with
`args.GetDataDirNet()`; beamchain `rpc_dumptxoutset` accepts the
binary path as-is (`PathStr = binary_to_list(Path)`). Effect:
relative paths are interpreted against the cwd of the gen_server
process (typically the release root), not the network datadir.
Fix: prefix relative paths with
`beamchain_config:datadir()`.

**BUG-22 (LOW)** — `dumptxoutset` `latest` mode does not pin the
tip across the call (G24-adjacent). Core's `PrepareUTXOSnapshot`
takes the cs_main lock for the cursor-creation window, then
releases it. beamchain `do_dump_at_tip` calls `flush()` then
`serialize_snapshot` against a **new** cache snapshot — between
those two calls the tip can advance (a block can be connected by
the network loop). The `base_hash` returned will be the tip
*before* the flush; the `coins_written` will reflect the cache
*after* a possible advance. Two slightly inconsistent halves of
the response. Fix: take the chainstate gen_server's "tip lock"
(or use `gen_server:call(chainstate, dump_at_tip)`) for the
duration.

**BUG-23 (LOW)** — `dumptxoutset` does not refuse mid-IBD. Core
permits dumping at any time (the snapshot just won't be
loadable against another node's chain until the dump-source
catches up); beamchain inherits the same permissiveness. But
because beamchain's chainwork "zero-OK" exception (BUG-9) means
the IBD chainstate's chainwork may be 0 mid-load, dumping during
this window can produce a snapshot whose subsequent self-load
silently bypasses the chainwork check. Indirect via BUG-9; the
defensive guard would be: refuse `dumptxoutset` while IBD is
active. Fix: check `beamchain_chainstate:is_synced/0` in
`rpc_dumptxoutset`.

---

## What a fix wave would touch

Suggested partition into 3-4 fix waves of ascending scope:

- **Wave A (~3 hours, single-impl)** — Cosmetic + RPC-shape:
  BUG-4, BUG-18, BUG-21, BUG-5 + BUG-13 (`getchainstates` +
  `getblockchaininfo.background_validation`). All in
  `beamchain_rpc.erl`. Net effect: assumeUTXO RPCs report Core-shape.
- **Wave B (~6 hours, single-impl)** — Per-coin gate hardening:
  BUG-7, BUG-8, BUG-9, BUG-10, BUG-11, BUG-12 (cleanup-on-failure
  ETS rollback). All in `beamchain_chainstate.erl`. Net effect: the
  load gate matches Core's defensive posture.
- **Wave C (~8 hours, single-impl)** — Persistence + restart-survival:
  BUG-3, BUG-15, BUG-16. New `beamchain_snapshot:write_base_blockhash`
  + `read_base_blockhash` helpers, modify `init_chainstate(main, _)`
  to route through the snapshot-attach branch.
- **Wave D (~8 hours, single-impl)** — State machine + auto-validate:
  BUG-2, BUG-6, BUG-14, BUG-22. New `m_assumeutxo` enum equivalent
  + `MaybeValidateSnapshot` hook in `do_connect_block_inner` +
  services-downgrade on load.
- **Wave E (parking lot)** — Architectural: BUG-17 (snapshot-suffix
  CF scheme), BUG-1 (regtest hashes). BUG-17 is enough work to
  deserve a dedicated decision. BUG-1 requires either real
  hash-from-running-mining or a refusal stance — design call.
