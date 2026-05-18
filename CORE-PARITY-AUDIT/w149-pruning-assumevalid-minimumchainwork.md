# W149 — Pruning + assumevalid + minimumchainwork (beamchain)

**Wave:** W149 — `FindFilesToPrune` / `FindFilesToPruneManual` /
`UnlinkPrunedFiles` / `FlushBlockFile`, `MIN_BLOCKS_TO_KEEP=288`,
`-prune=N` CLI sentinel + 550 MiB floor, `BLOCK_ASSUMED_VALID` /
`fScriptChecks` gate, `defaultAssumeValid`, `nMinimumChainWork`,
`UpdateIBDStatus`, `MinimumConnectedChainWork`, `pruneblockchain` RPC,
`NODE_NETWORK_LIMITED` service-bit semantics.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/node/blockstorage.cpp` —
  `FindFilesToPrune`, `FindFilesToPruneManual`, `UnlinkPrunedFiles`,
  `FlushBlockFile`, `PruneOneBlockFile`,
  `MIN_BLOCKS_TO_KEEP=288`.
- `bitcoin-core/src/node/blockmanager_args.cpp:31` —
  `"Prune configured below the minimum of %d MiB. Please use a higher
  number."` — hard-error on `-prune` in `(2..MIN_DISK_SPACE_FOR_BLOCK_FILES)`.
- `bitcoin-core/src/init.cpp:522-524` — `-prune=<n>` arg
  (`0`=off, `1`=manual-RPC-only, `>=550`=auto-target in MiB).
- `bitcoin-core/src/init.cpp:1947-1952` —
  `g_local_services = NODE_NETWORK_LIMITED | NODE_WITNESS` by default;
  add `NODE_NETWORK` only in non-prune mode after historical-data
  check.
- `bitcoin-core/src/validation.cpp:2280-2310` —
  `BLOCK_ASSUMED_VALID` bit + `fScriptChecks` skip gate in
  `ConnectBlock`. `fScriptChecks` ONLY skips script verification —
  every other gate (BIP-30, sigops, coinbase amount, MoneyRange)
  still runs.
- `bitcoin-core/src/validation.cpp:1940-1942, 3283-3291` —
  `IsInitialBlockDownload` exit gate: `IsTipRecent(max_tip_age)
  AND chainwork >= MinimumChainWork()` (BOTH; one-way latch).
- `bitcoin-core/src/kernel/chainparams.h` /
  `kernel/chainparams.cpp` — `defaultAssumeValid`, `nMinimumChainWork`,
  `m_assumeutxo_data`.
- `bitcoin-core/src/node/chainstate.cpp` — `LoadChainstate`
  minimum-chain-work gate.
- `bitcoin-core/src/net_processing.cpp` —
  `MinimumConnectedChainWork`, NODE_NETWORK_LIMITED peer
  discrimination, MIN_BLOCKS_TO_KEEP horizon for `getdata` serve.
- `bitcoin-core/src/rpc/blockchain.cpp::pruneblockchain` —
  height OR unix-timestamp param; clamps to `tip - 288`.
- `bitcoin-core/src/uint256.h` —
  `base_blob(string_view)` reverses display-hex into internal-byte
  storage; comparing `block.GetHash()` (which is SHA-256d → internal
  order) to a `uint256{"<display-hex>"}` literal is the canonical
  pattern. beamchain's `hex_to_bin` does NOT reverse, so the
  equivalent comparison silently fails (see BUG-1).

**Files audited**
- `src/beamchain_chain_params.erl` — `params/1` map (assume_valid,
  min_chainwork, bip30_exceptions, bip34_hash, assumeutxo),
  `hex_to_bin/1`, `display_hex_to_bin/1`.
- `src/beamchain_config.erl` — `prune_enabled/0`,
  `prune_target/0`, `prune_manual_mode/0`, `prune_target_raw/0`,
  `network_params/1` (older `#network_params{}` record path).
- `src/beamchain_db.erl` — `prune_block_files/0`,
  `prune_block_files_manual/1`, `is_block_pruned/1`,
  `trigger_pruning/1`, `get_prune_state/0`,
  `do_prune_files/1`, `do_prune_files_manual/2`,
  `find_prunable_files/5`, `find_max_height_in_file/1`,
  `compute_prune_height/2`, `find_first_unpruned_height/2`,
  `check_block_pruned/2`, `mark_blocks_pruned/1`,
  `MIN_PRUNE_TARGET_MB=550`, `REORG_SAFETY_BLOCKS=288`,
  `BLOCK_HAVE_DATA=8`, `BLOCK_HAVE_UNDO=16`.
- `src/beamchain_validation.erl` —
  `skip_scripts/3`, `skip_scripts_eval/6`,
  `check_chainwork_and_time/4`, BIP-30 exception comparison at
  `validate_block_full` (line 1101-1103), BIP-34 canonical-chain
  check `bip34_canonical_chain_active/3`.
- `src/beamchain_block_sync.erl` — `assume_valid` /
  `assume_valid_height` state, `lookup_assume_valid_height/1`,
  `is_too_far_ahead/2`, `MIN_BLOCKS_TO_KEEP` import path.
- `src/beamchain_chainstate.erl` — `maybe_check_ibd/1`
  (IBD exit), `check_min_pow_chainwork/3`, prune trigger after
  `do_connect_block` (line 1060-1070), `BLOCK_HAVE_DATA` /
  `BLOCK_HAVE_UNDO` set after connect (line 965).
- `src/beamchain_header_sync.erl` — `min_chainwork` /
  `tip_chainwork` interplay, `maybe_init_hss/2` (HSS gate).
- `src/beamchain_headerssync.erl` — `minimum_required_work`
  + PRESYNC/REDOWNLOAD pipeline.
- `src/beamchain_peer.erl` — `do_send_version/1` (NODE_NETWORK +
  NODE_NETWORK_LIMITED service-bit advertisement, line 1290-1315).
- `src/beamchain_peer_manager.erl` — BIP-159 horizon at
  `handle_getdata_msg/2` (line 1733-1801).
- `src/beamchain_rpc.erl` — `rpc_pruneblockchain/1`,
  `do_pruneblockchain/1`, `build_prune_fields/0`
  (getblockchaininfo `pruned`/`pruneheight`/`automatic_pruning`/
  `prune_target_size`).
- `src/beamchain_import.erl` — bulk-import path runs
  through `connect_block` (and thus `skip_scripts`).
- `config/sys.config`, `rebar.config`, `config.example.toml`.

---

## Gate matrix (32 sub-gates / 8 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | `-prune=N` CLI semantics | G1: `0`=off / `1`=manual / `>=550`=auto MiB | PARTIAL — recognised in `prune_target_raw/0` (config.erl:152-169) but **no CLI flag**; only ETS / env (`BEAMCHAIN_PRUNE`) routes exist. **BUG-12 (P2)** |
| 1 | … | G2: `-prune` in `(2..549)` rejected at startup | **BUG-2 (P1)** silently snapped to 550 instead of erroring with `"Prune configured below the minimum of %d MiB"` (config.erl:145) |
| 1 | … | G3: `-prune` incompatible with `-txindex` | **BUG-3 (P0-SEC)** no incompatibility check — operator can run both, creating UTXO-set / tx-index drift after the first prune sweep |
| 1 | … | G4: `-reindex` operator knob | **BUG-13 (P1)** absent — no `-reindex` path; corrupted UTXO requires manual `rm -rf` of data dir |
| 2 | `FindFilesToPrune` (auto) | G5: `MIN_BLOCKS_TO_KEEP=288` honored | PASS (`db.erl:131` `REORG_SAFETY_BLOCKS=288`, used at `do_prune_files` line 1742+1755) |
| 2 | … | G6: never prune the current write file | PASS (`find_prunable_files/5` line 1855-1857 `FileNum >= CurrentFile -> Acc`) |
| 2 | … | G7: per-file max-height tracked | PASS (`find_max_height_in_file/1`; W124 prior-wave fix already applied — comment 1886-1892 records the prior bug-fix) |
| 2 | … | G8: `FlushBlockFile` fsync before delete | **BUG-9 (P1)** no `file:sync/1` call in `do_prune_files` or anywhere in `beamchain_db.erl` — pruning a file race-vulnerable to crash leaving partially-written undo data on disk |
| 2 | … | G9: clear `BLOCK_HAVE_DATA`/`BLOCK_HAVE_UNDO` from pindex on prune | **BUG-5 (P0-CDIV)** `mark_blocks_pruned/1` (db.erl:2024-2038) tombstones ETS only; never updates the persisted `block_index` `Status` field — the block_index entry still reports `BLOCK_HAVE_DATA (=8)` set after the file is gone |
| 3 | `pruneblockchain` RPC | G10: heights and unix-timestamps both accepted | PASS (`rpc.erl:1645-1654`; `>= 1e9` heuristic matches Core) |
| 3 | … | G11: clamp to `tip - 288` for reorg safety | PASS (`db.erl:1812` `SafeUpper = ChainHeight - REORG_SAFETY_BLOCKS`) |
| 3 | … | G12: error when prune mode is off | PASS (`rpc.erl:1637-1640`) |
| 3 | … | G13: returns height of last block pruned | PARTIAL (returns `effective_height` which is the clamped target, not the actual highest pruned height — Core returns the latter; **BUG-8 (P2)**) |
| 4 | `getblockchaininfo` prune fields | G14: `pruned` boolean | PASS (`rpc.erl:1051-1054`) |
| 4 | … | G15: `pruneheight` (lowest height with data on disk) | **BUG-7 (P1)** `find_first_unpruned_height/2` returns `0` when the entire chain is pruned (db.erl:1969) — Core returns `highest_pruned + 1`. Operators reading 0 will think no prune has occurred |
| 4 | … | G16: `automatic_pruning` only when not manual | PASS (`rpc.erl:1155, 1063`) |
| 4 | … | G17: `prune_target_size` only in auto mode | PASS (`rpc.erl:1067-1070`) |
| 5 | `assumevalid` semantics | G18: skip only script verification | PASS (validation.erl:1228 — `SkipScripts` only gates the deferred `ScriptJobs` accumulator; BIP-30, sigops, coinbase, MoneyRange all still run) |
| 5 | … | G19: 6-condition guard (Core v28 ancestor-check) | PARTIAL — beamchain implements all 6 conditions (validation.erl:1902-2014) **but condition 6 uses a raw `timestamp` delta instead of Core's `GetBlockProofEquivalentTime` chainwork-equivalent** (**BUG-10 (P1)**) |
| 5 | … | G20: fail-closed when `BlockEntry = not_found` | **BUG-6 (P1)** validation.erl:2004-2010 falls back to `BlockTimestamp = 0` — guaranteeing `TimeDelta > POW_TARGET_TIMESPAN` if HdrTimestamp is anywhere past 1970+2 weeks. Comment ("the only case that matters for IBD speed") inverts the safety polarity |
| 5 | … | G21: `defaultAssumeValid` per-network | PASS (chain_params.erl:52, 178; mainnet+testnet4 only) |
| 6 | `MinimumChainWork` | G22: configured per-network | PASS (chain_params.erl:48; mainnet only — all others `<<0:256>>`) |
| 6 | … | G23: IBD exit gated on `chainwork >= MinimumChainWork` | **BUG-4 (P0-CDIV)** `maybe_check_ibd/1` (chainstate.erl:1102-1126) exits IBD on `tip_timestamp within 24h` ONLY; min_chainwork is NEVER consulted. A peer feeding fake near-recent timestamps with low chainwork would exit beamchain's IBD prematurely. Same shape as W148 BUG-13 (blockbrew) |
| 6 | … | G24: `LoadChainstate` startup min-chainwork gate | **BUG-11 (P1)** absent — beamchain's `init_chainstate/2` (chainstate.erl:566-647) loads the persisted tip without any chainwork verification |
| 6 | … | G25: PRESYNC/REDOWNLOAD anti-DoS pipeline | PASS (`beamchain_headerssync` is a full implementation of Core's `HeadersSyncState`) |
| 7 | BIP-30 byte-order pipeline | G26: connect-side BIP-30 exception hash comparison | **BUG-1 (P0-CONS, mainnet sync stall at h=91842)** — connect-side compares `BlockHash` (internal byte order from SHA-256d) to `Bip30Exceptions` (DISPLAY byte order from `hex_to_bin` in chain_params.erl:82-84). Comparison ALWAYS false → BIP-30 stays enforced at h=91842/91880 → `bad-txns-BIP30` → hard chain-stall at h=91841 |
| 7 | … | G27: disconnect-side BIP-30 exception | PASS (validation.erl:1761-1770 hardcodes the two pairs in INTERNAL byte order as binary literals — works in isolation, but constitutes a **two-pipeline guard** with G26) |
| 7 | … | G28: `bip34_hash` canonical-chain proof | **BUG-14 (P0-CONS)** chain_params.erl:91 stores `bip34_hash` via `hex_to_bin` (DISPLAY byte order); validation.erl:1437-1440 comment claims "internal byte order" and compares directly to `AncestorHash` (returned by `get_block_index/1` which is internal). Two-pipeline guard #2 in the same file — comment-as-confession exactly inverts the truth. The h=227,931 BIP-34→BIP-30 transition will incorrectly KEEP BIP-30 enforcement enabled |
| 8 | NODE_NETWORK / NODE_NETWORK_LIMITED | G29: NODE_NETWORK_LIMITED set when pruned | PASS (peer.erl:1306-1315) |
| 8 | … | G30: NODE_NETWORK CLEARED when prune-manual or auto-prune | **BUG-15 (P1)** peer.erl:1290 unconditionally sets `BaseServices = ?NODE_NETWORK bor ?NODE_WITNESS`; advertising NODE_NETWORK while running pruned violates Core init.cpp:1947-1952 (Core only sets NODE_NETWORK on top of NODE_NETWORK_LIMITED in **non-prune** mode) |
| 8 | … | G31: BIP-159 horizon `tip - 288` on getdata serve | PASS (peer_manager.erl:1744-1745); but uses hard-coded `288` literal instead of `?MIN_BLOCKS_TO_KEEP` — minor consistency smell |
| 8 | … | G32: `check_block_pruned` distinguishes "pruned" vs "never stored" | **BUG-16 (P2)** `check_block_pruned/2` returns `false` for "block not in index" (db.erl:1712-1714). Callers can't distinguish "pruned" from "never seen" — RPC handlers will report "not_found" for both |

---

## BUG-1 (P0-CONS, mainnet sync stall at h=91842) — BIP-30 exception list stored in DISPLAY byte order, compared to INTERNAL-order hash

**Severity:** P0-CONS — mainnet sync hard-stalls at h=91841 with
`bad-txns-BIP30`. Same shape as W143 BUG-1 (and same root cause as
W143's stall at h=91842) but on a different code path. W143 covered
the chain_params byte-order of internal definitions; this BUG covers
the BIP-30-exception comparison pipeline at connect-time, which W143
did not explicitly enumerate.

**Files:**
- `src/beamchain_chain_params.erl:81-84` — exception list constructor
- `src/beamchain_validation.erl:1095-1103` — comparison site

**Core ref:** `bitcoin-core/src/validation.cpp:6189-6192`
(`IsBIP30Repeat`) — uses `uint256{"<display-hex>"}` which REVERSES
the display string into internal byte order; comparison against
`block_index.GetBlockHash()` (also internal order) works.

**beamchain (broken)**:
```erlang
%% chain_params.erl:81-84
bip30_exceptions => [
    {91842, hex_to_bin("00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec")},
    {91880, hex_to_bin("00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721")}
]
```

`hex_to_bin/1` (chain_params.erl:574-585) emits `<<00,00,00,00,00,0a,4d,0a,...>>`
in DISPLAY order. The comparison:

```erlang
%% validation.erl:1095-1103
BlockHash = beamchain_serialize:block_hash(Header),   %% INTERNAL order (SHA-256d output)
Bip30Exceptions = maps:get(bip30_exceptions, Params, []),
IsBip30Repeat = lists:any(fun({ExH, ExHash}) ->
    Height =:= ExH andalso BlockHash =:= ExHash       %% NEVER true
end, Bip30Exceptions),
EnforceBip30_A = not IsBip30Repeat,                   %% ALWAYS true
```

Therefore at h=91842 the BIP-30 exception fails to fire,
`EnforceBip30` stays true, and the duplicate coinbase txids
(91722/91812 originals overwrote at 91842/91880) trigger
`bad-txns-BIP30` → block rejected → chain stalls one block earlier
at h=91841. The mainnet sync cannot complete.

**Witness for asymmetry:** validation.erl:1761-1770 (disconnect-side
BIP-30 path) hardcodes the SAME two block hashes in **INTERNAL** byte
order as raw binary literals. They work in isolation. So beamchain
has TWO BIP-30 exception pipelines that DISAGREE on byte-order
convention — classic two-pipeline-guard, comment-as-confession
("Note: beamchain uses BIP-30 exceptions from Params for connect_block;
for the two historically hard-coded mainnet exceptions Core uses the
exact hashes below").

**Fix (single line in chain_params.erl)**: replace `hex_to_bin/1`
with `display_hex_to_bin/1` (already defined and used for assumeutxo
block_hash — see chain_params.erl:592-595).

---

## BUG-14 (P0-CONS) — `bip34_hash` stored in DISPLAY byte order; comment claims INTERNAL

**Severity:** P0-CONS. Companion bug to BUG-1 — same byte-order
pipeline split, different field. The `bip34_canonical_chain_active/3`
helper compares `AncestorHash` (returned by `get_block_index/1`,
INTERNAL order) to `Bip34Hash` (loaded from chain_params, **DISPLAY
order** via `hex_to_bin`). Comparison ALWAYS false → BIP-30 stays
forcibly enabled across the entire post-BIP34 window for blocks where
the canonical-proof should disable it.

**Files:**
- `src/beamchain_chain_params.erl:90-91` — `hex_to_bin(...)` storage
- `src/beamchain_validation.erl:1429-1455` —
  `bip34_canonical_chain_active/3` comparison

**Core ref:** `bitcoin-core/src/validation.cpp:2460-2462` —
`pindexBIP34height->GetBlockHash() == params.BIP34Hash`. Core's
`BIP34Hash` is constructed with `uint256{"<display-hex>"}` which
reverses to internal — so the comparison against `GetBlockHash()`
(internal) works.

**Excerpt (the comment-as-confession)**:
```erlang
%% validation.erl:1433-1440
bip34_canonical_chain_active(_Height, Bip34Height, Bip34Hash) ->
    %% At or past BIP34Height: walk the active chain to BIP34Height and
    %% check the recorded hash.  The block_index table stores hashes in
    %% internal byte order; Bip34Hash is also in internal byte order in
    %% chain_params (see params(mainnet) → bip34_hash).
    case beamchain_db:get_block_index(Bip34Height) of
        {ok, #{hash := AncestorHash}} ->
            AncestorHash =:= Bip34Hash;       %% always false on mainnet
```

The comment "is also in internal byte order in chain_params" is
**factually false** — chain_params.erl:90-91 stores it via
`hex_to_bin/1` which is DISPLAY order. The comment is a 5th-instance
"comment-as-confession" (cross-cite W144 BUG-12 lunarblock).

**Impact:** mainnet at h >= 227,931 enters the BIP-34 canonical-chain
fall-through. `bip34_canonical_chain_active/3` returns false → BIP-30
stays enforced. Mainnet does not block-stall here (BIP-30 enforcement
post-BIP34 is just expensive overhead — the duplicate-coinbase
checks all pass), but the operator pays a measurable per-block cost
during sync that Core's optimization eliminates. Pure consensus-
adjacent correctness gap; not a chain-split candidate by itself,
unless a malicious peer can craft a block whose coinbase tx
collides with a historical txid — which is what the BIP-34 height
+ canonical-hash gate is designed to short-circuit.

**Fix:** `bip34_hash => display_hex_to_bin(...)` in chain_params.erl:90.

---

## BUG-2 (P1) — `-prune` in `(2..549)` silently snapped to 550 instead of error

**Severity:** P1 (consensus-adjacent operator surprise).

**File:** `src/beamchain_config.erl:140-147`

**Core ref:** `bitcoin-core/src/node/blockmanager_args.cpp:31` —
returns `util::Error{"Prune configured below the minimum of %d MiB.
Please use a higher number."}` and refuses to start.

**Excerpt (beamchain — silent coercion):**
```erlang
prune_target() ->
    case prune_target_raw() of
        0 -> 0;
        1 -> 0;                       %% manual-only mode: no auto target
        N when N < 550 -> 550;        %% snap small auto values to 550 floor
        N -> N
    end.
```

Operator who runs `-prune=100` expecting a 100 MiB target gets 5.5×
that disk usage with no warning. Core hard-rejects.

**Fix:** match Core: error at startup. Erlang doesn't have Core's
`InitError` but `error/1` with a clear reason atom would be the
parity move.

---

## BUG-3 (P0-SEC) — No `-prune` / `-txindex` incompatibility check

**Severity:** P0-SEC. Core errors at startup with
`"Prune mode is incompatible with -txindex."` (init.cpp; phrased in
the `-prune=<n>` help). beamchain has both `txindex_enabled/0` and
`prune_enabled/0` independently true-able with no cross-check.

**File:** `src/beamchain_config.erl` (no helper),
`src/beamchain_db.erl:init/1` (does not validate).

**Core ref:** `bitcoin-core/src/init.cpp` AppInitParameterInteraction.

**Excerpt:** _absent_ — no `prune_enabled() andalso txindex_enabled() →
error()` clause exists anywhere.

**Impact:**
- After the first prune sweep, `tx_index` entries point at deleted
  blk*.dat offsets. `gettransaction` / `getrawtransaction` returns
  garbage or crashes (`{error, block_pruned}` in some paths,
  uncontrolled exception in others).
- Operator believes their tx index is intact; debugging the symptom
  back to "prune ate the file behind the index" is hours of
  forensics.

**Fix:** add a startup gate; either the prune helpers refuse to
report enabled when txindex is on, or the supervisor refuses to
start.

---

## BUG-4 (P0-CDIV) — IBD exit gated on tip-timestamp alone; `min_chainwork` ignored

**Severity:** P0-CDIV. Bitcoin Core's `IsInitialBlockDownload`
(validation.cpp:1940-1942, 3283-3291) latches `m_cached_is_ibd=false`
when BOTH:
- the chain tip is within `DEFAULT_MAX_TIP_AGE` (24h) of wall-clock, AND
- the chain has accumulated chainwork `>= MinimumChainWork()`.

beamchain's `maybe_check_ibd/1` checks ONLY the first.

**File:** `src/beamchain_chainstate.erl:1102-1126`

**Core ref:** `bitcoin-core/src/validation.cpp:1940-1942, 3283-3291`

**Excerpt (beamchain — half the gate):**
```erlang
maybe_check_ibd(#state{ibd = true, mtp_timestamps = Ts} = State) ->
    Latest = lists:last(Ts),
    Now = erlang:system_time(second),
    case (Now - Latest) < 86400 of
        true ->
            logger:info("chainstate: leaving IBD at height ~B, ..."),
            ...
            State2#state{ibd = false, ...};
        false -> State
    end;
```

There is NO consultation of `maps:get(min_chainwork, Params, _)`
anywhere in `maybe_check_ibd`.

**Impact:**
- A peer that constructs a chain with recent timestamps but low
  cumulative chainwork (e.g., a regtest-easy difficulty chain with
  `time = now()` on every header) would exit beamchain's IBD with
  zero proof-of-work past min_chainwork.
- Once IBD exits, `is_synced=true` propagates to mempool acceptance,
  RPC responses (`initialblockdownload=false`, `verificationprogress
  =1.0`), and skip-scripts gating decisions — all on a low-work
  fake chain.
- Cross-cite: same exact bug shape as W148 BUG-13 (blockbrew uses
  `==` equality, beamchain skips the gate entirely).

**Fix:** add `case is_chainwork_past_minimum(State) of true -> ...;
false -> State end` clause inside the 24h-recent branch.

---

## BUG-5 (P0-CDIV) — Pruning never clears `BLOCK_HAVE_DATA` / `BLOCK_HAVE_UNDO` from block_index

**Severity:** P0-CDIV. Bitcoin Core's `UnlinkPrunedFiles` /
`PruneOneBlockFile` (blockstorage.cpp) explicitly does
`pindex->nStatus &= ~(BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO)` for every
block in the file before unlinking. `FindMostWorkChain` filters
candidates on `BLOCK_HAVE_DATA`: a candidate with the bit set is
assumed available on disk.

beamchain's `mark_blocks_pruned/1` (db.erl:2024-2038) ONLY tombstones
the `BLOCK_INDEX_ETS` entry with a 4-tuple `{Hash, {FileNum, Offset,
Size, pruned}}`. It NEVER touches the persistent `block_index`
column-family entry, which still encodes `Status = BLOCK_VALID_SCRIPTS
| BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO` (set at chainstate.erl:965).

**File:** `src/beamchain_db.erl:2024-2038`

**Core ref:**
`bitcoin-core/src/node/blockstorage.cpp::PruneOneBlockFile` —
walks all `BlockMap` entries with `nFile == fileNumber` and clears
the HAVE_DATA/HAVE_UNDO bits.

**Excerpt:**
```erlang
mark_blocks_pruned(FileNums) ->
    FileNumSet = sets:from_list(FileNums),
    ets:foldl(fun({Hash, {FileNum, Offset, Size}}, _Acc) ->
        case sets:is_element(FileNum, FileNumSet) of
            true ->
                ets:insert(?BLOCK_INDEX_ETS, {Hash, {FileNum, Offset, Size, pruned}});
            false -> ok
        end;
    (_, Acc) -> Acc
    end, ok, ?BLOCK_INDEX_ETS),
    ok.
```

Nothing touches the RocksDB `block_index` column family.

**Impact:**
- A future reorg evaluation (`FindMostWorkChain`-equivalent in
  chainstate.erl) inspects `block_index` `Status` field, sees
  `BLOCK_HAVE_DATA` set, picks the pruned block as a reorg
  candidate, calls `disconnect_block` → file read → `enoent`.
- On restart, `BLOCK_INDEX_ETS` is rebuilt from RocksDB (via
  `persist_block_index` / `ets:file2tab`). If the on-disk dump
  predates the prune sweep, the tombstone is lost and every pruned
  block re-appears "available".

**Fix:** in `do_prune_files`, after `mark_blocks_pruned`, walk the
pruned heights and call `beamchain_db:update_block_status/2` to
clear bits 8 and 16 from the persisted Status.

---

## BUG-6 (P1) — `check_chainwork_and_time` fails-open when `BlockEntry = not_found`

**Severity:** P1. The 6-condition skip_scripts evaluator
(validation.erl:1939-2014) has a "block not yet in index" fallback
that sets `BlockTimestamp = 0`. With `HdrTimestamp` always ≥ 1971
(headers persisted from a real chain), `TimeDelta = HdrTimestamp -
0 > POW_TARGET_TIMESPAN (=1,209,600s)` is essentially always true.

**File:** `src/beamchain_validation.erl:2003-2013`

**Core ref:** `bitcoin-core/src/validation.cpp` — Core uses
`GetBlockProofEquivalentTime(pindexBestHeader, pindex, pindexBestHeader,
consensusParams)`. The block being connected MUST have a `pindex` in
the index (because Core requires headers-first), so the
"BlockEntry = not_found" case never arises.

**Excerpt (beamchain):**
```erlang
BlockTimestamp = case BlockEntry of
    {ok, #{header := BH}} -> BH#block_header.timestamp;
    not_found ->
        %% Block not yet in index (fresh IBD connecting a new block).
        %% Use 0 so the time-delta check passes when the header tip
        %% is well ahead — the only case that matters for IBD speed.
        0
end,
```

The comment is the polarity-inversion confession: "Use 0 so the
time-delta check passes" — but a `0` fallback means "pretend the
block is from 1970", which guarantees passing the 2-week threshold
for any modern HdrTimestamp. The safety condition has been turned
into an unconditional pass.

**Impact:** A block whose `BlockEntry` lookup misses (which CAN
happen at the boundary of `connect_block` if the index entry is
written after script verification — see code at chainstate.erl:944-
969 where status update happens AFTER ConnectBlock returns) will
skip scripts even if the header tip is fresh and barely past
min_chainwork.

**Fix:** flip the polarity — `not_found -> return false` (fail
closed, force scripts to verify when context is unavailable).

---

## BUG-7 (P1) — `pruneheight=0` reported when chain is fully pruned

**Severity:** P1 (wire-format / operator-confusion).

**File:** `src/beamchain_db.erl:1946-1990` (`compute_prune_height/2`,
`find_first_unpruned_height/2`)

**Core ref:** `bitcoin-core/src/rpc/blockchain.cpp::getblockchaininfo`
— surfaces `pruneheight` as the first height with body data still
on disk; when all is pruned it reports `tip - 1` semantics
(highest_pruned + 1), not 0.

**Excerpt:**
```erlang
find_first_unpruned_height([], _PrunedFiles) ->
    0;  %% all heights pruned — wrong, Core returns highest_pruned + 1
```

**Impact:**
- Operator parses `pruneheight=0` and concludes "no pruning has
  occurred" — exactly the opposite of the reality.
- Light-wallet UIs and external monitoring tools (mempool.space,
  Fulcrum) that consult pruneheight to decide what blocks to
  re-fetch will mis-route.

---

## BUG-8 (P2) — `pruneblockchain` RPC returns clamped target, not actual highest pruned

**Severity:** P2 (wire-format slip).

**File:** `src/beamchain_rpc.erl:1655-1657`, `src/beamchain_db.erl:1813,
1822-1842`

**Core ref:** `bitcoin-core/src/rpc/blockchain.cpp::pruneblockchain` —
returns "Height of the last block pruned" (string in the help text,
integer in the JSON).

**Excerpt:**
```erlang
%% rpc.erl:1655-1657
case beamchain_db:prune_block_files_manual(Height) of
    {ok, #{effective_height := Eff}} ->
        {ok, Eff};                  %% returns target, not actual high
```

`EffectiveHeight = min(TargetHeight, SafeUpper)` is the height
beamchain TRIED to prune up to, not the height of the actual highest
pruned block (which could be lower if some files in the range
straddle into the safety window).

---

## BUG-9 (P1) — No `FlushBlockFile` / fsync before pruning

**Severity:** P1 (crash-safety).

**File:** `src/beamchain_db.erl` (no fsync anywhere in the prune
or `do_write_block_flat` paths).

**Core ref:**
`bitcoin-core/src/node/blockstorage.cpp::FlushBlockFile` — fsyncs
the previous blk*.dat / rev*.dat before opening the next, and
explicitly before a prune sweep.

**Impact:** A power-cut during a prune sweep that has already
unlinked file N but not yet written the updated `pruned_files` set
to RocksDB leaves the on-disk file count out of sync with the
metadata. On restart, `scan_block_files` will not know file N is
gone; any block in file N+1 that referenced an undo block in file N
(during a future reorg) will silently corrupt the UTXO set.

---

## BUG-10 (P1) — Condition 6 uses raw timestamp delta, not chainwork-equivalent time

**Severity:** P1 (consensus-adjacent; weakens assume-valid safety
margin).

**File:** `src/beamchain_validation.erl:1995-2013`

**Core ref:** `bitcoin-core/src/validation.cpp` uses
`GetBlockProofEquivalentTime(pindexBestHeader, pindex,
pindexBestHeader, consensusParams)` which computes
`(work_diff) / (work_per_second_at_target_difficulty)` — a
chainwork-derived time delta robust against header-timestamp
manipulation.

**Excerpt:**
```erlang
%% validation.erl:2012-2013
TimeDelta = HdrTimestamp - BlockTimestamp,
TimeDelta > ?POW_TARGET_TIMESPAN
```

Raw header timestamps can be manipulated up to ~7200 seconds in the
future per BIP-113 / network adjusted time. An attacker crafting
the assumed-valid chain could place timestamps to push `TimeDelta`
artificially past the 2-week threshold without actually accumulating
the equivalent chainwork.

---

## BUG-11 (P1) — No `LoadChainstate` startup min-chainwork gate

**Severity:** P1 (defense-in-depth).

**File:** `src/beamchain_chainstate.erl:566-647` (`init_chainstate/2`).

**Core ref:** `bitcoin-core/src/node/chainstate.cpp::LoadChainstate`
— refuses to start if the persisted chainstate's tip chainwork is
below `nMinimumChainWork` (catches a poisoned-on-disk attack).

**Excerpt (beamchain):** _no equivalent_ — `load_chain_tip/0` reads
the tip hash + height without consulting chainwork.

**Impact:** an attacker with filesystem access to swap RocksDB
contents could poison beamchain's persisted tip to a low-work chain;
startup loads it without complaint. Defense-in-depth only.

---

## BUG-12 (P2) — No `-prune` CLI flag

**Severity:** P2 (ergonomics). Operator must use `BEAMCHAIN_PRUNE=N`
env var or set `prune=N` in `beamchain.conf`; there is no
`beamchain --prune=N` CLI path.

**File:** `src/beamchain_cli.erl` (does not parse `--prune`).

**Core ref:** `bitcoin-core/src/init.cpp:522-524`
(`argsman.AddArg("-prune=<n>", ...)`).

---

## BUG-13 (P1) — No `-reindex` operator knob

**Severity:** P1.

**File:** `src/beamchain_cli.erl` and supervisor tree — neither has
a `reindex` entry point.

**Core ref:** `bitcoin-core/src/init.cpp:525-526` —
`-reindex` / `-reindex-chainstate` flags.

**Impact:** when UTXO corruption is suspected, the only recovery is
`rm -rf` of the entire data dir + resync from genesis (which on
mainnet is days). Core can rebuild from existing blk*.dat in hours.

---

## BUG-15 (P1) — `NODE_NETWORK` advertised unconditionally even when pruning

**Severity:** P1 (peer-discrimination / interop). Core defaults
`g_local_services = NODE_NETWORK_LIMITED | NODE_WITNESS` and adds
NODE_NETWORK only in **non-prune** mode (init.cpp:1947-1952).
beamchain unconditionally sets NODE_NETWORK in `BaseServices` and
only ADDS NODE_NETWORK_LIMITED if prune is on.

**File:** `src/beamchain_peer.erl:1290-1315`

**Core ref:** `bitcoin-core/src/init.cpp:863, 1947-1952`

**Excerpt:**
```erlang
BaseServices = ?NODE_NETWORK bor ?NODE_WITNESS,
...
Services = case beamchain_config:prune_enabled() of
    true  -> Services1 bor ?NODE_NETWORK_LIMITED;
    false -> Services1
end,
```

When `prune_enabled() = true`, beamchain advertises
`NODE_NETWORK | NODE_WITNESS | NODE_NETWORK_LIMITED` simultaneously.
Peers parse NODE_NETWORK as "will serve any historical block" and
will request blocks below the keep-288 window → beamchain replies
`notfound` → wasted round-trips and possible peer demotion.

The comment at peer.erl:1310-1311 even confesses the wrong rationale
("Core advertises NODE_NETWORK alongside NODE_NETWORK_LIMITED in
the auto-prune case") — Core does the OPPOSITE.

**Fix:**
```erlang
BaseServices = ?NODE_WITNESS,
...
Services = case beamchain_config:prune_enabled() of
    true  -> Services1 bor ?NODE_NETWORK_LIMITED;
    false -> Services1 bor ?NODE_NETWORK
end,
```

---

## BUG-16 (P2) — `check_block_pruned` cannot distinguish "pruned" from "never stored"

**Severity:** P2. `check_block_pruned/2` returns `false` for both
"this block was never in the index" AND "this block was in the
index, not pruned". The downstream `{error, block_pruned}` vs
`not_found` distinction collapses to `not_found` in the
"never seen" case.

**File:** `src/beamchain_db.erl:1704-1715`

**Excerpt:**
```erlang
check_block_pruned(Hash, #state{pruned_files = PrunedFiles}) ->
    case ets:lookup(?BLOCK_INDEX_ETS, Hash) of
        ...
        [] ->
            %% Block not in index - could be pruned or never stored
            false                          %% wrong: lossy aggregation
    end.
```

The comment names the ambiguity but the code commits the loss.

Also note **dead code at line 1711**: `true orelse sets:is_element(FileNum, PrunedFiles)` — `true orelse X` short-circuits to `true`, so the `sets:is_element` call is never executed. Either intentionally always-true (and the call is dead clutter) or a typo for `andalso` (and the function returns wrong values for tombstoned-but-not-pruned blocks — but that combination is impossible by construction). Either way: dead code.

---

## Fleet-pattern smells

- **Comment-as-confession (3×)**:
  - validation.erl:1437-1440 explicitly claims `Bip34Hash` is in
    internal byte order; chain_params.erl:91 stores it in display
    order (**BUG-14**). Comment perfectly inverts the truth.
  - validation.erl:2006-2009 ("the only case that matters for IBD
    speed") explains the polarity-inverted fallback in BUG-6.
  - peer.erl:1310-1311 ("Core advertises NODE_NETWORK alongside
    NODE_NETWORK_LIMITED in the auto-prune case") — Core does the
    opposite (BUG-15).
- **Two-pipeline guard (3×)**:
  - BIP-30 exception comparison: chain_params-driven path
    (DISPLAY order, BROKEN) vs hardcoded inline literals in
    validation.erl:1761-1770 (INTERNAL order, works). One file,
    two callers, opposite conventions (**BUG-1**).
  - `beamchain_chain_params:params/1` (map-based, has assume_valid,
    min_chainwork, bip30_exceptions) vs `beamchain_config:
    network_params/1` (`#network_params{}` record, missing all
    three — config.erl:684-713 mainnet). Two parallel chain-params
    APIs that diverge in completeness; new fields land in one and
    not the other.
  - `?BLOCK_HAVE_DATA = 8`, `?BLOCK_FAILED_VALID = 32` defined
    independently in both `beamchain_db.erl:51-59` and
    `beamchain_chainstate.erl:64-67`. No shared `.hrl`. Drift
    waiting to happen.
- **Comment-as-confession 4th instance** (subtler): config.erl:138
  "Returns 0 if pruning is disabled or in manual-only mode (manual
  mode has no automatic target — only the RPC handler triggers
  prunes)" — but the code at line 144 (`1 -> 0`) hides the fact
  that the gen_server is initialized with a sentinel byte of 1
  (db.erl:773 `true -> 1`), creating an opaque magic-number path.
- **Hardcoded constants that should be params-aware**:
  - `peer_manager.erl:1745` uses literal `288` instead of
    `?MIN_BLOCKS_TO_KEEP`. Both have the same value today, but a
    future `-fastprune` style override would diverge.
  - `chainstate.erl:1109` uses literal `86400` instead of a
    `?DEFAULT_MAX_TIP_AGE` macro.
- **`list_to_atom` on operator input (1×)** — config.erl:674
  `K = list_to_atom(string:trim(Key))`. Same W140 pattern. Local
  config-file only (no network-reachable surface), so DoS risk
  is bounded, but the anti-pattern is present.
- **Code-duplication smell**:
  - `?BLOCK_VALID_*` ladder defined in db.erl:51-55 but NOT in
    chainstate.erl (which uses `?BLOCK_VALID_SCRIPTS = 5` only). A
    future change to add `?BLOCK_VALID_HEADER` semantics in
    chainstate would silently disagree with db.erl's encoding.
- **Comment-as-confession 5th instance** (db.erl:1712-1714):
  ```erlang
  [] ->
      %% Block not in index - could be pruned or never stored
      false
  ```
  Comment names the ambiguity, code commits the lossy aggregation
  (**BUG-16**).
- **Dead-helper-at-call-site**: `?BLOCK_FAILED_CHILD = 64` defined
  at db.erl:59 with comment "unused in Core" — defined here, never
  consulted anywhere in beamchain either. Just dead clutter.
- **Dead-data BIP9-style plumbing**: `chain_params:params/1`
  defines `min_chainwork` for mainnet only; the `chainstate.erl::
  maybe_check_ibd/1` path (line 1102-1126) **does not consult it
  at all** (**BUG-4**). Field defined → field read only in
  `check_min_pow_chainwork` and `skip_scripts_eval` but never on
  the IBD-exit hot path that the operator-facing
  `getblockchaininfo.initialblockdownload` actually depends on.

---

## Summary

16 bugs catalogued across 8 behaviours / 32 sub-gates.

- **P0-CONS** (chain-split / mainnet-stall): 2 — BUG-1, BUG-14
- **P0-CDIV** (consensus divergence): 2 — BUG-4, BUG-5
- **P0-SEC** (security): 1 — BUG-3
- **P1** (correctness / safety margin / interop): 8 — BUG-2, BUG-6,
  BUG-7, BUG-9, BUG-10, BUG-11, BUG-13, BUG-15
- **P2** (operability / wire-format): 3 — BUG-8, BUG-12, BUG-16

**Top findings:**
1. **BUG-1 (P0-CONS, mainnet sync stall at h=91842)** — `bip30_exceptions`
   stored in DISPLAY byte order, compared to INTERNAL-order
   `BlockHash`. Single-line `hex_to_bin → display_hex_to_bin` fix in
   `chain_params.erl:82-84`. Companion to W143 BUG-1; W143 was the
   header path, this is the connect-side BIP-30 path. The disconnect-
   side path at validation.erl:1761-1770 works because it inlines
   INTERNAL-order literals — clean two-pipeline-guard divergence.
2. **BUG-14 (P0-CONS)** — `bip34_hash` stored in DISPLAY byte order;
   the inline comment claims INTERNAL. Companion to BUG-1 in the same
   chain_params file. BIP-34 canonical-chain proof always fails →
   BIP-30 over-enforced post-h=227,931 (perf, not split, but
   confidence-eroding).
3. **BUG-4 (P0-CDIV)** — `maybe_check_ibd/1` exits IBD on tip-
   timestamp alone, NEVER consulting `min_chainwork`. A peer feeding
   low-work but timely headers can flip beamchain out of IBD on a
   fake chain. Same shape as W148 BUG-13 (blockbrew); this is the
   beamchain instance of the FLEET-WIDE "IBD-exit-missing-chainwork-
   half" pattern.
4. **BUG-5 (P0-CDIV)** — pruning never clears `BLOCK_HAVE_DATA`
   from the persisted `block_index`; `FindMostWorkChain` -equivalent
   reorg evaluation will pick pruned blocks as reorg candidates,
   then crash on file read.
5. **BUG-15 (P1, interop)** — beamchain in prune mode advertises
   NODE_NETWORK alongside NODE_NETWORK_LIMITED — Core does the
   opposite. Peers will request historical blocks beamchain cannot
   serve, wasting round-trips.

**Two-pipeline guard density**: 3 distinct instances in a single
audit (BIP-30 byte-order, two chain_params modules, duplicated
BLOCK_VALID/HAVE_DATA defines in two files). High-density indicates
the codebase's architectural seams cluster around chain-params and
storage boundaries.

**Carry-forward / cross-cite:** BUG-1 is the W143-style mainnet
sync stall but on the CONNECT-side BIP-30 path (W143 documented
disconnect-side). Both bugs originate from the same root cause:
beamchain's `hex_to_bin/1` is asymmetric with Core's
`uint256{"<hex>"}` (which reverses), but the codebase has BOTH a
DISPLAY-order helper (`hex_to_bin`) AND an INTERNAL-order helper
(`display_hex_to_bin`). The wrong one was chosen in
chain_params.erl:82-84 and 90-91.

**Cross-cite to W148:** BUG-4 (beamchain IBD exit missing
min_chainwork half) is the same shape as W148 BUG-13 (blockbrew IBD
exit using `==` equality with assume_valid_height). Both nodes are
candidates for a fleet-wide IBD-exit-correctness sweep.
