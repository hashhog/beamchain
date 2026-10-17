# Running beamchain

The node is one program, `_build/default/bin/beamchain` (built by `rebar3 escriptize`),
with a command and options:

```bash
./_build/default/bin/beamchain <command> [options]
./_build/default/bin/beamchain --help
```

## Commands

| Command | What it does |
|---|---|
| `start` | Start the node in the foreground. Stops on Ctrl-C, SIGTERM or the `stop` RPC. |
| `sync` | Start the node and draw a progress display in the terminal. |
| `import` | Read blocks from `--import-file` (or stdin) and connect them, without P2P. Each record is a 4-byte little-endian height, a 4-byte little-endian size, then the raw block. |
| `import-utxo` | Load a UTXO snapshot written by Bitcoin Core's `dumptxoutset` (`--import-utxo=<file>`), then exit. |
| `status` | Ask a running node for its height, peers, mempool size and uptime over RPC. |
| `stop` | Ask a running node to shut down over RPC. |
| `getbalance [address]` | Ask a running node for a balance over RPC. |

`status`, `stop` and `getbalance` read the `.cookie` file from `--datadir` as given,
without adding the network subdirectory. For any network other than mainnet pass the
subdirectory yourself, for example `--network=regtest --datadir="$DATADIR/regtest"`.

## Options

Every option accepts `--name=value` and `--name value`.

| Option | Default | Meaning |
|---|---|---|
| `--network=<net>` | `mainnet` | `mainnet`, `testnet` (testnet3), `testnet4`, `signet` or `regtest`. |
| `--datadir=<dir>` | `~/.beamchain` | Base data directory. Networks other than mainnet use `<dir>/<network>`. |
| `--conf=<file>` | `<network datadir>/beamchain.conf` | Config file (see below). |
| `--rpc-port=<n>` | per network | JSON-RPC port. |
| `--p2p-port=<n>` | per network | P2P listen port. |
| `--connect=<ip:port>` | none | Connect only to this peer; repeatable. Turns off DNS seeds and automatic outbound connections. |
| `--nodnsseed`, `--dnsseed=0` | seeds on | Do not resolve DNS seeds. |
| `--nofixedseeds`, `--fixedseeds=0` | on | Do not fall back to the built-in seed list. |
| `--externalip=<ip>[:port]` | none | Address to advertise to peers; repeatable. Implies `--discover=0` unless that is given. |
| `--discover[=0\|1]`, `--nodiscover` | 1 | Learn our public address from what outbound peers report. |
| `--noassumevalid`, `--assumevalid=0` | assumevalid on | Verify scripts in every block, including those below the built-in assume-valid block. |
| `--txindex[=0\|1]` | 0 | Keep a transaction index (for `getrawtransaction` without a block hash). |
| `--coinstatsindex[=0\|1]` | 0 | Keep per-height UTXO-set statistics (for `gettxoutsetinfo` at past heights). |
| `--cfilter=<0\|1>`, `--blockfilterindex[=basic]` | 0 | Build BIP-158 basic block filters and serve BIP-157. |
| `--dbcache=<MiB>` | 4096 | UTXO cache budget. Performance only. |
| `--par=<n>` | 0 | Script-check threads: 0 = one per core, negative = leave that many cores free; at most 32. |
| `--rpc-tls-cert=<file>`, `--rpc-tls-key=<file>` | unset | Serve RPC over HTTPS. Both or neither; one alone is a startup error. |
| `--listenonion=<0\|1>` | 0 | Publish a Tor v3 onion service through the Tor control port. |
| `--torcontrol=<host:port>` | `127.0.0.1:9051` | Tor control port. |
| `--torpassword=<pw>` | none | Tor control-port password. |
| `--import-file=<file>` | stdin | Block file for `import`. |
| `--import-utxo=<file>`, `--load-snapshot=<file>` | none | Snapshot file for `import-utxo`. |
| `--limit=<n>` | none | Accepted, but currently has no effect. |
| `--reset` | off | Delete `chaindata/` (block index and UTXO set) before starting; block files are kept. |
| `--pid=<file>` | `<network datadir>/beamchain.pid` | PID file. |
| `--daemon` | off | Detach into the background after starting. |
| `--printtoconsole[=0\|1]` | off | Also write log lines to the terminal. |
| `--debug[=<cats>]` | off | Debug logging, for all modules or for `net,rpc,mempool,validation,sync,db,zmq,wallet,miner`. |
| `-h`, `--help` / `-v`, `--version` | | Help or version. |

An unknown option prints the help and exits with status 1.

## Config file

`beamchain.conf` in the network data directory (or `--conf=<file>`) holds `key=value`
lines. Lines starting with `#` or `;` are comments; `[section]` lines are ignored.
Values are taken literally, so write `prune=550`, not `prune = "550"`. The network and
the data directory cannot be set here; use the options or environment variables.

| Key | Default | Meaning |
|---|---|---|
| `rpcport`, `p2pport` | per network | Same as `--rpc-port` / `--p2p-port` (the options win). The `status` and `stop` commands do not read this file, so pass `--rpc-port` to them as well. |
| `rpcuser`, `rpcpassword` | unset | RPC credentials, accepted in addition to the cookie. |
| `rpctlscert`, `rpctlskey` | unset | Same as `--rpc-tls-cert` / `--rpc-tls-key`. |
| `prune` | 0 | 0 = keep all blocks, 1 = prune only via `pruneblockchain`, 550 or more = target size in MiB. |
| `txindex`, `coinstatsindex`, `blockfilterindex`, `txospenderindex` | 0 | Indexes (`1` = on). |
| `dbcache` | 4096 | Same as `--dbcache`. |
| `par` | 0 | Same as `--par`. |
| `mempoolfullrbf` | 1 | Full replace-by-fee in the mempool. |
| `peerbloomfilters` | 0 | Advertise NODE_BLOOM and answer BIP-35 `mempool` requests. |
| `txreconciliation` | 0 | Erlay (BIP-330) transaction reconciliation. |
| `rest` | 0 | Start the REST server (see [rpc.md](rpc.md#rest)). |
| `zmqpubhashblock`, `zmqpubhashtx`, `zmqpubrawblock`, `zmqpubrawtx`, `zmqpubsequence` | unset | ZMQ publisher endpoints, e.g. `tcp://127.0.0.1:28332`. |
| `proxy`, `onion` | unset | SOCKS5 proxy (`host:port`, default port 9050) for all / onion connections. |
| `i2psam` | unset | I2P SAM bridge (`host:port`, default port 7656). |
| `listenonion`, `torcontrol`, `torpassword` | | Same as the options above. |
| `asmap` | unset | ASMap file for peer bucketing. |

## Environment variables

Each variable overrides the matching config-file key. The command-line options above
set these variables, so an option wins over an inherited variable.

| Variable | Same as |
|---|---|
| `BEAMCHAIN_NETWORK`, `BEAMCHAIN_DATADIR`, `BEAMCHAIN_CONF` | `--network`, `--datadir`, `--conf` |
| `BEAMCHAIN_RPC_PORT`, `BEAMCHAIN_P2P_PORT` | `--rpc-port`, `--p2p-port` |
| `BEAMCHAIN_REST`, `BEAMCHAIN_REST_PORT` | `rest`; REST port (default RPC port + 10) |
| `BEAMCHAIN_TXINDEX`, `BEAMCHAIN_COINSTATSINDEX`, `BEAMCHAIN_BLOCKFILTERINDEX`, `BEAMCHAIN_TXOSPENDERINDEX` | index keys |
| `BEAMCHAIN_PRUNE`, `BEAMCHAIN_DBCACHE`, `BEAMCHAIN_PAR` | `prune`, `dbcache`, `par` |
| `BEAMCHAIN_ASSUMEVALID=0` | `--noassumevalid` |
| `BEAMCHAIN_FULLRBF`, `BEAMCHAIN_PEERBLOOMFILTERS`, `BEAMCHAIN_TXRECONCILIATION` | matching keys |
| `BEAMCHAIN_ZMQPUBHASHBLOCK` (and the other four `ZMQPUB*`) | ZMQ keys |
| `BEAMCHAIN_PROXY`, `BEAMCHAIN_ONION`, `BEAMCHAIN_I2PSAM`, `BEAMCHAIN_ASMAP` | matching keys |
| `BEAMCHAIN_LISTENONION`, `BEAMCHAIN_TORCONTROL`, `BEAMCHAIN_TORPASSWORD` | Tor options |
| `BEAMCHAIN_RPC_TLS_CERT`, `BEAMCHAIN_RPC_TLS_KEY` | TLS options |
| `BEAMCHAIN_BIP324_V2_OUTBOUND=0` | Use v1 transport for outbound connections (v2 is the default). |

## Networks and ports

| Network | P2P | RPC | REST (if enabled) |
|---|---|---|---|
| mainnet | 8333 | 8332 | 8342 |
| testnet4 | 48333 | 48332 | 48342 |
| testnet3 (`testnet`) | 18333 | 18332 | 18342 |
| signet | 38333 | 38332 | 38342 |
| regtest | 18444 | 18443 | 18453 |

The Prometheus endpoint is on port 9332 for every network. Every listener binds all
interfaces. Run beside another node on the same machine with `--rpc-port` and
`--p2p-port`. If port 9332 is busy, startup retries for about 30 seconds and then
continues without metrics. To move or turn off the metrics endpoint, set the OTP
application variable through `ERL_FLAGS`:

```bash
ERL_FLAGS="-beamchain metrics_port 19332" ./_build/default/bin/beamchain start --network=regtest --datadir="$DATADIR"
ERL_FLAGS="-beamchain metrics_port 0"     ./_build/default/bin/beamchain start --network=regtest --datadir="$DATADIR"
```

## Data directory

```
<datadir>/                 mainnet; other networks use <datadir>/<network>/
  beamchain.conf           optional config file
  .cookie                  RPC cookie, written at startup
  beamchain.log            log (rotated at 10 MB, 3 files kept)
  beamchain.pid            PID file
  blocks/                  blk*.dat and rev*.dat, Bitcoin Core's format
  chaindata/               RocksDB: block index, UTXO set, chain state
  indexes/                 optional indexes (block filters, ...)
  peers.dets               address manager
  addrman_secret, netgroup_secret
  <network>/wallet/        wallets (regtest: <datadir>/regtest/regtest/wallet)
```

## Resources

Mainnet without pruning needs about as much disk as Bitcoin Core's blocks directory
plus the UTXO set: plan for at least 1 TB of SSD. The default `--dbcache=4096` plus
RocksDB and the Erlang VM need well over 4 GB; 16 GB of RAM is a comfortable minimum
for initial sync. `--dbcache` and `--par` trade memory and cores for speed and do not
change validation results.

## Logging and monitoring

The node logs at `info` level to `beamchain.log` in the network data directory. That
file is opened once startup has finished; messages from startup itself, and OTP's own
reports, go to standard output, so redirect it to a file as in the examples.
`--printtoconsole` copies the `beamchain.log` lines to standard output too. `--debug`
lowers the level to `debug`.

For monitoring use the RPC (`getblockchaininfo`, `getpeerinfo`, `getmempoolinfo`), the
unauthenticated `GET /health` on the RPC port, or the Prometheus endpoint:

```bash
curl -s http://127.0.0.1:18443/health
curl -s http://127.0.0.1:9332/metrics | head -3
```
