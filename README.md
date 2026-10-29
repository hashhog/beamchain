# beamchain

A Bitcoin full node written from scratch in Erlang/OTP. One of the ten [hashhog](https://github.com/hashhog) nodes.

> **Experimental.** hashhog nodes are independent re-implementations of Bitcoin Core for research and testing. Do not use them with real funds.

## Status

| Area | State |
|---|---|
| Mainnet validation | Validated mainnet from genesis to height 958,794 with assumevalid off and matched Bitcoin Core's `gettxoutsetinfo` `hash_serialized_3` there (`29692050…6e7af0`, 166,180,925 coins). How to reproduce: [docs/status.md](docs/status.md#utxo-set-hash-at-height-958794). |
| Regtest vs Core v31.1 | `test/bc3_core_regtest.sh` mines and spends on Core v31.1, feeds the blocks to beamchain and compares tip, `gettxoutsetinfo` and `scantxoutset`: 141 of 141 fields match. See [docs/status.md](docs/status.md#regtest-comparison-with-core-v311). |
| RPC | 140 JSON-RPC methods modelled on Core's, plus optional REST, ZMQ and a Prometheus endpoint. Method list in [docs/rpc.md](docs/rpc.md). |
| P2P | Headers-first sync, parallel block download, compact blocks (BIP-152), BIP-324 v2 transport, addrv2, Erlay, SOCKS5/Tor/I2P. |
| Wallet | HD wallet (BIP-32/39/44/49/84/86), descriptors, PSBT, multi-wallet. Not audited. |
| Known limitations | Ten unit tests fail on `master`; no Docker image that builds from source; `status`/`stop` need the network subdirectory as `--datadir`. See [docs/status.md](docs/status.md#known-limitations). |

Last updated: 2026-10-17.

## Quick start

Needs Erlang/OTP 27 and rebar3 3.24 (other versions are untested), a C/C++ toolchain,
CMake and git. The build downloads and compiles libsecp256k1 and RocksDB, so it needs
network access and takes a few minutes. On Debian 13 (other systems: [docs/building.md](docs/building.md)):

```bash
sudo apt-get install -y erlang rebar3 build-essential cmake git libsnappy-dev liblz4-dev libzstd-dev
git clone https://github.com/hashhog/beamchain.git
cd beamchain
rebar3 escriptize
./_build/default/bin/beamchain --version
```

Start a regtest node in a throwaway data directory and make an RPC call:

```bash
export DATADIR=$(mktemp -d)
./_build/default/bin/beamchain start --network=regtest --datadir="$DATADIR" > "$DATADIR/node.log" 2>&1 &
sleep 10
curl -s --user "$(cat "$DATADIR/regtest/.cookie")" -d '{"method":"getblockchaininfo","params":[]}' http://127.0.0.1:18443/
./_build/default/bin/beamchain stop --network=regtest --datadir="$DATADIR/regtest"
```

More detail, including the reproducible-build check, is in [docs/building.md](docs/building.md).

## Running

```bash
./_build/default/bin/beamchain start --network=mainnet  --datadir="$HOME/.beamchain"
./_build/default/bin/beamchain start --network=testnet4 --datadir="$HOME/.beamchain"
./_build/default/bin/beamchain start --network=signet   --datadir="$HOME/.beamchain"
./_build/default/bin/beamchain start --network=regtest  --datadir="$HOME/.beamchain"
```

Mainnet uses the data directory itself; every other network gets a subdirectory
(`$DATADIR/testnet4`, `$DATADIR/regtest`, ...). `--network=testnet` is testnet3.

| Network | P2P port | RPC port |
|---|---|---|
| mainnet | 8333 | 8332 |
| testnet4 | 48333 | 48332 |
| testnet3 | 18333 | 18332 |
| signet | 38333 | 38332 |
| regtest | 18444 | 18443 |

RPC binds `127.0.0.1` unless you pass `--rpcbind=<addr>` (or set `rpcbind=` in the
config file). The P2P listener binds all interfaces (`0.0.0.0`). RPC requires the cookie
or `rpcuser`/`rpcpassword`; if you set `--rpcbind=0.0.0.0`, firewall the RPC port. A Prometheus endpoint listens on port 9332; if that port is busy the node
retries for about 30 seconds, then carries on without metrics.

A mainnet node keeps every block unless you set `prune=<MiB>` (550 or more) in the
config file: plan for at least 1 TB of fast disk without pruning. The UTXO cache
defaults to 4096 MiB (`--dbcache=<MiB>`); give the machine 16 GB of RAM.
`--noassumevalid` checks every script from genesis instead of trusting the built-in
assume-valid block.

All flags, config-file keys, environment variables, the data directory layout and
logging are in [docs/running.md](docs/running.md).

## RPC

beamchain aims to match Bitcoin Core's JSON-RPC interface: same method names,
parameters and result shapes, with batch requests and `/wallet/<name>` endpoints. It
accepts HTTP Basic auth with the `.cookie` file written to the network data directory
at startup, or `rpcuser`/`rpcpassword` from the config file:

```bash
curl -s --user "$(cat "$DATADIR/regtest/.cookie")" \
  -d '{"jsonrpc":"1.0","id":1,"method":"getblockcount","params":[]}' http://127.0.0.1:18443/
```

The method list, REST endpoints and known differences from Core are in
[docs/rpc.md](docs/rpc.md).

## Development

```bash
rebar3 eunit
```

This runs every module in `test/` (about 5,300 tests; see
[docs/status.md](docs/status.md#test-suite) for the current result).

```
src/beamchain_cli.erl          entry point, command-line flags, start/stop
src/beamchain_config.erl       network parameters, config file, environment variables
src/beamchain_validation.erl   block and transaction validation
src/beamchain_script.erl       script interpreter and sighash
src/beamchain_chainstate.erl   UTXO cache, connect/disconnect, reorgs
src/beamchain_db.erl           RocksDB storage and blk/rev files
src/beamchain_peer*.erl        peers, peer manager; *_sync.erl for headers and blocks
src/beamchain_mempool.erl      mempool, packages, RBF
src/beamchain_rpc.erl          JSON-RPC (also _rest, _zmq, _metrics)
src/beamchain_wallet.erl       wallet, with _descriptor, _psbt, _miniscript
c_src/                         C NIF for secp256k1 and SHA-256
test/                          EUnit suites and test vectors (test/data/)
```

The full map is in [docs/architecture.md](docs/architecture.md). See
[CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
