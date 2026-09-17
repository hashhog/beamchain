# beamchain proof bundle

A skeptical Bitcoin engineer should be able to check this node without
trusting a narrative. This directory is that check: every claim below
names a file in this directory, and `bash proof/verify.sh` re-checks
those files (and re-runs the in-repo controls).

It claims **only what the included files show.**

## How to check

From the beamchain repository root:

```
bash proof/verify.sh
```

That is the control. It exits 0 only if every claim in `claims.json`
matches a file here, the lineage log is a from-genesis AV=0 run (not a
snapshot boot), and the in-repo T1 RPC-parity eunit is green.

Re-running the heavy instruments (from-genesis IBD, full R2 corpus, live
R5 probe) needs the commands in `r4/`, `r1/command.txt`, `r2/command.txt`,
`r5/command.txt`. Those take days / hours / a running node. The files
here are the captured results of those commands.

## What each file proves

### Provenance — `provenance.txt`

The parent commit this bundle was assembled on, the sha256 of
`_build/default/bin/beamchain` built from this tree (`rebar3 escriptize`),
and the toolchain (Erlang/OTP 27 / rebar3 3.24.0).

**beamchain has no relocatable deploy pin.** The RocksDB NIF is not
loadable from a copied escript archive, so `deploy/beamchain/` is unused.
The running unit's argv[0] is `_build/default/bin/beamchain` (escript).
That path identity is the closure this node can make.

**Byte-identity of the live process vs this file is UNPROVEN.** The live
unit started 2026-09-17T11:20:42Z on commit `d46a9e3` (operator deploy).
The on-disk escript was rebuilt at 12:28Z from `8a40a06` (T3 wallet, not
deployed). `/proc/<pid>/exe` is the BEAM VM, not the escript, so the
running zip cannot be re-hashed. `verify.sh` records the path and the
on-disk sha256; a mismatch is a NOTE, not a FAIL — same class as a
non-bit-stable rebuild.

**Does not prove** bit-exact reproducible builds across toolchains — see
`scripts/reproducible-escript.sh`.

### R4 from-genesis lineage — `r4/`

TRUST-ANCHOR rule, applied without weakening: a reproduction of C(H)
counts only if the chainstate at H descends from a genesis→H validation
with scripts on (`assumevalid=0`) executed by this node's own validation
code. **Snapshot-booted lineages do not count.**

| file | what it proves | what it does not prove |
|---|---|---|
| `r4/C958794.json` | The commitment: height 958794, bestblock `000000000000000000015eaadd989e4f09ff75b643a128dc7bdf6070431d7d0e`, `hash_serialized_3` `29692050559b8f064a03af9cd605040e71d1d978fa22947c079cc7e5546e7af0`, 166,180,925 coins. `snapshot_booted=false`. | That this tree's binary is the one that built the set. The capture is of a genesis-rig process. |
| `r4/capture.md` | The capture receipt: MATCH at 2026-08-25T04:29:27Z, tip frozen at 958794, no rollback. | Ratification ceremony. The TRUST-ANCHOR ledger row is 2026-08-25T03:49:53Z (40 minutes earlier than the watcher MATCH); both hashes are the same. |
| `r4/capture-watch-excerpt.txt` | The watcher log: FROZEN ON ANCHOR → `*** MATCH ***` the same hash. | The UTXO scan transcript (gettxoutsetinfo JSON was not persisted beyond the receipt). |
| `r4/capture-state-marker.txt` | Idempotency marker written on MATCH, containing the same hash. | Anything about later tips. |
| `r4/genesis-unit.service` | The launch command: `--noassumevalid`, `--connect=127.0.0.1:28620` (capped blk-replay), datadir `/home/work/genesis-ibd/beamchain`, no loadtxoutset. | That a stranger can re-run it without that datadir and the capped feeder. |
| `r4/lineage.log.gz` | The lineage receipt: start at height -1, `connected genesis block`, header_sync at height 0, IBD from 1 with `verifying scripts`, no `loadtxoutset`/`loading snapshot` lines, chainstate at 958794. Uncompressed sha256 is `r4/lineage.log.sha256`; gzip sha256 is `r4/lineage.log.gz.sha256`. | Blocks after 958794. The log is append-only across restarts of the same datadir. `sync: snapshot body gap detected` is IBD catch-up wording (headers ahead of chainstate), not a snapshot boot. One `assumeutxo =>` hit is a crash dump of the hardcoded campaign table, not `loadtxoutset`. |
| `r4/lineage-excerpt.txt` | The load-bearing lines of that log, plus Bitcoin's genesis hash from `beamchain_chain_params.erl`. | Completeness — the gzip is the receipt. The log itself never prints the genesis hash as hex; the excerpt cites the in-repo params and the `connected genesis block` line. |
| `r4/av0-250000-ledger.txt` and `r4/av0-250000-ledger.jsonl` | A **separate** AV=0 genesis→250,000 replay: 11 checkpoints, each hash == Core, 6,802,755 txouts at 250,000, `utxo_hash=dd8e8cfd…649c`, `overall=ALL-PASS`. | C(958794). This run records txouts and a UTXO hash at 250,000, not the C(958794) commitment. |

### R1 interpreter — `r1/`

Core's script/tx/sighash vectors through beamchain's own `verify_script` /
decode+checktx / `sighash_legacy/4`.

| file | what it proves | what it does not prove |
|---|---|---|
| `r1/results.json` | script 1222/1222 (in-repo), tx_valid 121/121, tx_invalid 93/93, sighash 500/500, 0 divergences. | Reason-string parity. Phase B's script arm reports 1217/1217 decided + 5 pre-run assemble errors on the same JSON; see the note in results.json. |
| `r1/script.txt`, `r1/tx.txt`, `r1/sighash.txt` | The raw harness summaries that `results.json` was taken from. | A stranger's re-run — that is `r1/command.txt`. |

### R2 validator — `r2/`

Adversarial corpus, accept/reject vs live `bitcoind`.

| file | what it proves | what it does not prove |
|---|---|---|
| `r2/results.json` | 367 PASS / 3 FAIL / 0 ERR of the nightly 370-entry sweep (99.2%). All three FAILs are reject-vs-reject with a different reason string. `consensus_splits_accept_vs_reject: 0`. | Error-code / reject-token identity with Core. The three named entries still differ on *why* they reject. |
| `r2/nightly-report-excerpt.txt` | The nightly report row those numbers were copied from. | A clean classifier: the 10-impl report has an accounting gap on split counts; the three beamchain FAIL logs were read directly. |

### R5 operator RPC — `r5/`

| file | what it proves | what it does not prove |
|---|---|---|
| `r5/live-20260917T112139Z.json` | Live lane 2026-09-17T11:21Z: T1 45/46, T2 40/41, **zero FAIL rows**. The two live-lane non-passes are SKIP-REGTEST (`stop`, `getblockfilter`). | The pin running that probe is this commit. It is `d46a9e3`. |
| `r5/regtest-20260917T122831Z.json` | Regtest lane: T1 1/1, T2 1/1, T3 16/16, 18 methods scored, 0 FAIL. | Wallet behaviour outside the 16-method T3 subset. |
| `r5/t1-after.txt` | In-repo T1 parity eunit: 10 tests, 0 failures (`rebar3 eunit --module=beamchain_t1_rpc_parity_tests`). `verify.sh` re-runs this. | A live `r5_probe.py` of this commit. T3 landed in `8a40a06` and is not the live pin. |
| `r5/scorecard.json` | The numbers above in one place, each pointing at the artifact. | Anything not in those artifacts. |

## What is NOT proven here

- **Tip parity is not consensus evidence.** The live node matching Core's
  tip proves serialization, PoW, headers-first sync and UTXO bookkeeping
  on the assumevalid-skipped prefix. R1/R2/R4 are the consensus proof.
- **Blocks after 958794** have no from-genesis UTXO-hash capture.
- **Snapshot-boot / assumeUTXO activation** is a declared carve-out
  (boot-smoke), not a passing gate. It is also not a substitute for the
  lineage above.
- **Byte-identity of the running escript vs `_build/default/bin/beamchain`.**
  See provenance. Path identity holds; the live zip cannot be re-hashed
  because `/proc/<pid>/exe` is `beam.smp` and the on-disk file was
  overwritten after launch.
- **Bitcoin Core fullblocktests, stale-block replay, BIP90 asserts,
  bitcoinfuzz.** Not in this bundle.
- **Fund custody.** Do not send money to this node. See `SECURITY.md`.
- **That a stranger can replay the genesis IBD** without the datadir, the
  capped feeder, and the original binary. They can check the log and the
  capture hash; they cannot cheaply reproduce them.

## TRUST-ANCHOR, applied

A snapshot-booted range (`range-runner.sh` CLOSED rows) is **not** in
this bundle as R4 evidence. Those boots start from a Core-format UTXO
snapshot; counting them as from-genesis would be circular. The R4 files
above are the genesis-rig log + the frozen-at-958794 capture.
`verify.sh` fails the bundle if the lineage log contains `loadtxoutset`
or `loading snapshot`.
