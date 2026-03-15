# beamchain

Bitcoin full node implementation in Erlang/OTP.

Syncs the blockchain, validates blocks and transactions with full consensus rule enforcement including SegWit and Taproot, connects to the P2P network, and maintains a UTXO set backed by RocksDB.

## Prerequisites

- **Erlang/OTP 26+**
- **rebar3**
- **C compiler** (gcc or clang) for the secp256k1 NIF
- **CMake** for building RocksDB

On Fedora / RHEL:

```bash
sudo dnf install erlang rebar3 gcc gcc-c++ cmake snappy-devel
```

On Ubuntu / Debian:

```bash
sudo apt install erlang rebar3 gcc g++ cmake libsnappy-dev
```

## Build

```bash
git clone https://github.com/hashhog/beamchain.git
cd beamchain
rebar3 compile
```

## Usage

Start syncing testnet4 with a live progress display:

```bash
BEAMCHAIN_NETWORK=testnet4 ./beamchain sync
```

```
beamchain sync - testnet4
data: ~/.beamchain/testnet4

  ⠹ Headers [████████████░░░░░░░░░░░░░]  48%  60.2K / 125.2K  3 peers
  ⠹ Blocks  [██████░░░░░░░░░░░░░░░░░░░]  22%  27.8K / 125.2K  42.1 blk/s  ETA 38m 30s  3 peers
```

Start the node as a background service:

```bash
BEAMCHAIN_NETWORK=testnet4 ./beamchain start
```

Query a running node:

```bash
./beamchain status --network=testnet4
./beamchain getbalance <address> --network=testnet4
./beamchain stop --network=testnet4
```

### All options

```
  --network=<net>   mainnet, testnet, testnet4, regtest, signet (default: mainnet)
  --datadir=<dir>   data directory (default: ~/.beamchain)
  --rpc-port=<n>    RPC port override
  --p2p-port=<n>    P2P port override
  --debug           enable debug logging
  --reset           wipe chain data before sync
  --limit=<n>       limit sync to n blocks
```

### Alternative: run directly with erl

If you prefer the Erlang shell or need more control:

```bash
BEAMCHAIN_NETWORK=testnet4 erl -pa _build/default/lib/*/ebin -sname beamchain -eval \
  "logger:set_primary_config(level, info), application:ensure_all_started(beamchain)."
```

## JSON-RPC

The node exposes a Bitcoin Core-compatible JSON-RPC interface (default ports: mainnet 8332, testnet4 48332).

```bash
curl -s -X POST http://127.0.0.1:48332/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"1.0","method":"getblockchaininfo","params":[]}' | python3 -m json.tool
```

## Networks

| Network    | P2P Port | RPC Port | Data Directory             |
|------------|----------|----------|----------------------------|
| `mainnet`  | 8333     | 8332     | `~/.beamchain/`            |
| `testnet`  | 18333    | 18332    | `~/.beamchain/testnet/`    |
| `testnet4` | 48333    | 48332    | `~/.beamchain/testnet4/`   |
| `signet`   | 38333    | 38332    | `~/.beamchain/signet/`     |
| `regtest`  | 18444    | 18443    | `~/.beamchain/regtest/`    |

## Architecture

```
beamchain_sup                    top-level supervisor
├── beamchain_config             network parameters and runtime config
└── beamchain_node_sup           node supervisor
    ├── beamchain_db             RocksDB storage (blocks, UTXO index, metadata)
    ├── beamchain_sig_cache      signature verification cache
    ├── beamchain_chainstate     UTXO set and chain tip management
    ├── beamchain_mempool        unconfirmed transaction pool
    ├── beamchain_fee_estimator  fee rate estimation
    ├── beamchain_addrman        peer address manager
    ├── beamchain_peer_manager   P2P connection management
    ├── beamchain_header_sync    header-first sync
    ├── beamchain_block_sync     block download and validation
    ├── beamchain_sync           sync coordinator
    ├── beamchain_miner          block template and mining
    ├── beamchain_wallet         key management and signing
    └── beamchain_rpc            JSON-RPC server (cowboy)
```

Key modules outside the supervision tree:

- `beamchain_script` — full Script interpreter (P2PKH, P2SH, P2WPKH, P2WSH, P2TR)
- `beamchain_validation` — block and transaction consensus validation
- `beamchain_serialize` — transaction serialization/deserialization (legacy + segwit)
- `beamchain_crypto` — secp256k1 NIF bindings (ECDSA, Schnorr, SHA256, HASH160)
- `beamchain_pow` — proof-of-work validation and difficulty adjustment
- `beamchain_p2p_msg` — Bitcoin P2P protocol message encoding/decoding

## Consensus

Full validation of all consensus rules through the current block height:

- **Script verification** — all opcodes, including `OP_CHECKSIG`, `OP_CHECKMULTISIG`, `OP_CHECKLOCKTIMEVERIFY`, `OP_CHECKSEQUENCEVERIFY`
- **SegWit** — witness v0 (P2WPKH, P2WSH), witness v1 (Taproot key path and script path)
- **Soft fork activation** — P2SH, DERSIG, CLTV, CSV, SegWit, NULLDUMMY, NULLFAIL, Taproot
- **Difficulty adjustment** — retarget every 2016 blocks, BIP94 rules for testnet4
- **Coinbase maturity**, **block subsidy halving**, **transaction locktime**

## Tests

```bash
rebar3 eunit
```

## License

MIT
