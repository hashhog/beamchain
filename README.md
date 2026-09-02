# beamchain

A Bitcoin full node implementation in Erlang/OTP.

## Status — v1.0.0

**Label: "Validated — reproduced Core's UTXO set from genesis with all scripts
verified"** (`receipts/RELEASE-v1.0-SCORECARD.md`, §What each label means). That
label means one specific thing: beamchain connected every mainnet block from block 0
to height 958,794 with its assumevalid gate off, serialized its entire UTXO set,
and produced the byte string
`29692050559b8f064a03af9cd605040e71d1d978fa22947c079cc7e5546e7af0` over
166,180,925 coins — the same value Bitcoin Core's `dumptxoutset` produced at that
height. A single wrong coin anywhere in fifteen years changes that hash — the *capture* is unfakeable. **The lineage under it is not checkable from a clone:** what the ledger row records is height, hash and coin count; that the chain beneath was built from genesis with assumevalid off rests on the row's `lineage receipt` column, and four of the five rows point at logs under `/home/work/genesis-ibd/logs/` — outside any repository and uncommitted — while blockbrew's says only `--commit` (`receipts/TRUST-ANCHOR.md:141-145`). The git
tag `v0.1.0-rc1` (`receipts/RELEASE-v1.0-FREEZE.md`) marks the same bar: `rc` in this
project certifies that reproduction and nothing else
(`receipts/beta1-tag-drafts-2026-08-20.md:23-27`). Neither label certifies wallet
or fund-custody readiness — see `SECURITY.md`.

**Operator RPC parity: 60 of Bitcoin Core's 85** — arithmetically the highest of
the ten *in this run*; two probe runs ten minutes apart disagreed by ±2 on other
nodes with no deploy between them, so treat the ranking as run-scoped, not as a
standing property
implementations, and still 25 short of Core. From the 103-method R5 operator
probe run 2026-09-01
(`tools/diff-test-artifacts/r5-probe/20260901T182642Z.json`): beamchain 60 PASS /
25 FAIL, Bitcoin Core 85 PASS on the same probe, 18 methods unmeasured
(`SKIP-REGTEST`) for every node including Core.

**Known gaps in this repo** (`receipts/UNIT-BASELINE-v1.0.md`, 2026-09-01):
beamchain is the only node whose unit suite was already green when the v1.0
baseline was taken — 2808 tests, 0 failures, 0 carried gaps; 8 suites are
*cancelled* (they abort rather than assert), which the baseline counts as
neither pass nor failure. One closed item worth recording: until `8622118`,
verbose `getblockheader` fell back to Bitcoin Core's own RPC on
127.0.0.1:8332 for `nTx` when the local index held 0
(`receipts/beamchain-r3-proxy-survivor-2026-08-23.md`). It was measured dormant
— zero such connections observed across eight sampled heights — and the fallback
was removed on 2026-08-27 in `8622118`, which is an ancestor of this repository's
HEAD. **Two** beamchain stateful-prover shims did not launch in the 2026-09-01 nightly:
`checkheader_prove_beamchain.py` and `bip30_prove_beamchain.py`
(`consensus-diff-artifacts/diffguard-20260901T083001Z.log:110,123`). An earlier
draft of the release scorecard said three and named two; the scorecard is now
corrected to two, and this line no longer passes the error through.

**Fleet-wide comparison:** `receipts/RELEASE-v1.0-SCORECARD.md` in the hashhog
meta-repo, which is **not public** — see the note below.

> **The cited paths are NOT publicly readable — do not treat them as evidence.**
> Paths beginning `receipts/`, `tools/`, `docs/` and `CORE-PARITY-AUDIT/` refer to
> the hashhog meta-repo, which is a **private** repository, not to this one. They
> are provenance for the maintainers. From outside, any claim resting only on such
> a path is **unverified**, and you should read it as such.
>
> Two of those paths are unreadable even with the meta-repo in hand: the R5 probe
> JSON is gitignored (`.gitignore:60  tools/diff-test-artifacts/`) and so are the
> nightly `diffguard-*.log` files (`.gitignore:43  *.log`). Regenerate the probe
> JSON with `python3 tools/r5_probe.py` against a running fleet.
>
> **What you can check from this repository alone:** build it, run its own test
> suite, and reproduce its behaviour against Bitcoin Core yourself. That is the
> evidence this repo actually ships.

## Quick Start

### Docker

```bash
docker build -t beamchain .
docker run -v beamchain-data:/data -p 48348:48348 -p 48338:48338 beamchain
```

### From Source

Toolchain: Erlang/OTP 27 + rebar3 3.24 (the tested/CI version; no manifest pins OTP).
System deps: C compiler, `cmake`, `git` and a C++ toolchain + `libsnappy`/`liblz4`/`libzstd` dev headers —
`c_src/Makefile` clones and builds libsecp256k1 `v0.5.1`, and `rebar.config` builds erlang-rocksdb `9.10.0-emqx-2` from git (network required).

```bash
rebar3 compile
rebar3 escriptize
./beamchain start --network=testnet4
./beamchain --help
```

Note: `rebar.config` states escript mode is unsupported (the RocksDB NIF cannot load from an escript archive);
the deployed path is `rebar3 as prod release` then `_build/prod/rel/beamchain/bin/beamchain daemon`.

**Two committed sources disagree about which artifact ships.** The meta-repo's
`CLAUDE.md` lists beamchain's binary as `_build/default/bin/beamchain (escript)` and
relies on `build-all.sh`'s `rebar3 escriptize` step as its rot protection, while this
file and `rebar.config` name the prod release. The project's own notes record the cost
of that ambiguity: "beamchain's differential measures the prod release while mainnet
runs the escript, so a real fix measured as no-change"
(`CORE-PARITY-AUDIT/_loop-ledger.md:16025-16026`). Confirm which artifact you are
running before drawing conclusions from either.

## Features

- Full block and transaction validation (SegWit v0, Taproot key/script path, BIP68 sequence locks, accurate sigop counting)
- Script interpreter (all opcodes, legacy sighash with FindAndDelete/OP_CODESEPARATOR, BIP143, BIP341, MINIMALIF, NULLFAIL)
- Header-first sync with anti-DoS (PoW validation, unconnecting limits, deep fork protection)
- Block download with compact block relay (BIP-152, SipHash-2-4)
- UTXO set with write-back cache (FRESH flag optimization, undo data for reorgs)
- Cluster mempool (union-find clustering, linearization, fee-rate diagram RBF, full RBF)
- Package acceptance (CPFP within packages, package RBF, v3/TRUC policy, ephemeral anchors)
- BIP-324 v2 encrypted transport (ElligatorSwift, ChaCha20-Poly1305)
- BIP-330 Erlay transaction reconciliation (sendtxrcncl handshake, set reconciliation)
- BIP-133 feefilter (filter tx relay by peer minimum fee rate)
- BIP-155 ADDRv2 (TorV3, I2P, CJDNS address support)
- BIP-9 versionbits soft fork deployment tracking
- Eclipse attack protections (bucket-based addrman, netgroup limits, anchor connections)
- Stale peer eviction (tip timeout, headers timeout, ping timeout, network protection)
- Inventory trickling (Poisson-timed tx relay for privacy)
- Peer misbehavior scoring and banning with pre-handshake rejection
- HD wallet (BIP-32/44/84, BnB+Knapsack coin selection, encrypted storage)
- Multi-wallet support (createwallet, loadwallet, unloadwallet)
- PSBT (BIP-174 with createpsbt, decodepsbt, combinepsbt, finalizepsbt RPCs)
- Output descriptors (BIP380-386: pkh, wpkh, sh, wsh, multi, tr, addr, raw)
- Miniscript policy compiler (type checking, script compilation, satisfaction)
- assumeUTXO snapshot-based sync (loadtxoutset RPC, background validation)
- Block pruning (delete old blk/rev files, keep 288 blocks for reorg safety)
- Flat file block storage (blk*.dat files, Bitcoin Core compatible format)
- Fee estimation (bucketed tracking, confirmation time analysis)
- Block template construction (CPFP-aware tx selection, witness commitment)
- REST API (block, tx, headers, chaininfo, mempool, UTXO endpoints; JSON/binary/hex)
- ZMQ pub/sub notifications (hashblock, hashtx, rawblock, rawtx, sequence topics)
- Tor SOCKS5 proxy and I2P SAM 3.1 support
- NIF-accelerated SHA256/double-SHA256 (SHA-NI, ARM crypto extensions)
- Batch signature verification (amortized NIF call overhead)
- Regtest block generation (generate, generatetoaddress, generateblock RPCs)
- Chain management (invalidateblock, reconsiderblock RPCs)

## Configuration

### CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--network=NET` | `mainnet` | Network: mainnet, testnet, testnet4, regtest, signet |
| `--datadir=DIR` | `~/.beamchain` | Data directory |
| `--rpc-port=PORT` | per-network | RPC server port |
| `--p2p-port=PORT` | per-network | P2P listen port |
| `--debug` | off | Enable debug logging |
| `--reset` | off | Reset chain data before sync |
| `--limit=N` | none | Limit sync to N blocks |
| `--import-file=PATH` | stdin | File to import blocks from |
| `--import-utxo=PATH` | none | Bitcoin Core UTXO snapshot file (`utxo.dat` from `dumptxoutset`); alias `--load-snapshot` |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `BEAMCHAIN_NETWORK` | Override network selection |
| `BEAMCHAIN_DATADIR` | Override data directory |
| `BEAMCHAIN_TXINDEX` | Enable/disable transaction index (`1`/`0`) |
| `BEAMCHAIN_PRUNE` | Prune target in MB (0=disabled, min 550) |

### Commands

| Command | Description |
|---------|-------------|
| `start` | Start the node and block until Ctrl-C |
| `sync` | Start node and show sync progress display |
| `import` | Import blocks from stdin or file (bypasses P2P) |
| `import-utxo` | Import a Bitcoin Core UTXO snapshot (assumeutxo) |
| `status` | Show node status via RPC |
| `stop` | Stop a running node via RPC |
| `getbalance` | Get balance for an address |

## RPC API

JSON-RPC modelled on Bitcoin Core's, with batch request support. Not behaviourally compatible: on the 2026-09-01 operator probe beamchain answers 60 of the 103 probed methods correctly against Core's 85 — the highest of the ten implementations, and still 25 short (`tools/diff-test-artifacts/r5-probe/20260901T182642Z.json`).

| Category | Methods |
|----------|---------|
| Blockchain | `getblockchaininfo`, `getblock`, `getblockhash`, `getblockheader`, `getblockcount`, `getbestblockhash`, `getchaintips`, `getdifficulty`, `getblockstats`, `getchaintxstats`, `gettxout`, `gettxoutsetinfo` |
| Transactions | `getrawtransaction`, `sendrawtransaction`, `decoderawtransaction`, `createrawtransaction`, `decodescript` |
| Mempool | `getmempoolinfo`, `getrawmempool`, `getmempoolentry`, `getmempoolancestors` |
| Mining | `getblocktemplate`, `submitblock`, `getmininginfo`, `generate`, `generatetoaddress`, `generateblock` |
| Network | `getpeerinfo`, `getnetworkinfo`, `getconnectioncount`, `listbanned` |
| Wallet | `createwallet`, `loadwallet`, `unloadwallet`, `listwallets`, `getnewaddress`, `getrawchangeaddress`, `getbalance`, `sendtoaddress`, `listunspent`, `listtransactions`, `listaddresses`, `getwalletinfo`, `dumpprivkey` |
| Wallet Security | `encryptwallet`, `walletpassphrase`, `walletlock` |
| Descriptors | `getdescriptorinfo`, `deriveaddresses` |
| PSBT | `createpsbt`, `decodepsbt`, `combinepsbt`, `finalizepsbt` |
| Util | `validateaddress`, `estimatesmartfee` |
| Chain Mgmt | `invalidateblock`, `reconsiderblock` |
| assumeUTXO | `loadtxoutset`, `dumptxoutset` |
| Control | `stop`, `help` |

REST API available with endpoints for blocks, transactions, headers, chain info, mempool, and UTXOs.

## Monitoring

No dedicated Prometheus exporter. Monitor via RPC calls to `getblockchaininfo`, `getpeerinfo`, `getmempoolinfo`, and `getnetworkinfo`.

## Architecture

beamchain uses OTP supervision trees to structure the node as a collection of supervised processes. The top-level application supervisor manages child supervisors for the chainstate, wallet subsystem, and peer connections. Each peer runs as an independent `gen_statem` process, allowing the node to handle connection failures in isolation without affecting overall operation. The peer manager coordinates connection pooling, DNS discovery, and eclipse attack mitigations through bucketed address management.

Performance-critical cryptographic operations are implemented as NIFs (Native Implemented Functions) in C, binding to libsecp256k1 for ECDSA/Schnorr verification and providing hardware-accelerated SHA256 via SHA-NI or ARM crypto extensions. Batch signature verification amortizes NIF call overhead across multiple transactions within a block. The signature cache uses ETS (Erlang Term Storage) tables for lock-free concurrent reads during parallel validation.

The storage layer uses RocksDB via Erlang NIF bindings for the block index, UTXO set, and chain state, with column families separating different data types. Flat file block storage follows Bitcoin Core's blk*.dat format for compatibility. The UTXO cache implements the same FRESH flag optimization as Bitcoin Core's CCoinsViewCache, minimizing unnecessary writes during batch flush operations.

The mempool uses cluster-based linearization for optimal fee-rate ordering, with union-find data structures for efficient cluster management. Package acceptance supports CPFP fee-bumping within child-with-parents topologies, and v3/TRUC policy enforcement restricts transaction topology for Lightning anchor outputs. The Erlang process model naturally maps to the event-driven nature of mempool updates, with each transaction acceptance running as an isolated operation.

## License

MIT
