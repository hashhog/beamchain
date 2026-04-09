# beamchain

A Bitcoin full node implementation in Erlang/OTP.

## Quick Start

### Docker

```bash
docker build -t beamchain .
docker run -v beamchain-data:/data -p 48348:48348 -p 48338:48338 beamchain
```

### From Source

```bash
rebar3 compile
rebar3 escriptize
./beamchain start --network=testnet4
./beamchain --help
```

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
| `--import-utxo=PATH` | none | HDOG snapshot file for UTXO import |

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
| `import-utxo` | Import UTXO snapshot from HDOG file |
| `status` | Show node status via RPC |
| `stop` | Stop a running node via RPC |
| `getbalance` | Get balance for an address |

## RPC API

Bitcoin Core-compatible JSON-RPC with batch request support.

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
