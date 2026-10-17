# RPC

beamchain serves JSON-RPC over HTTP on the RPC port (see [running.md](running.md)). It
aims to match Bitcoin Core: the same method names, positional parameters, result
shapes and error codes. Requests can be single objects or batches (a JSON array).
Wallet methods can be sent to `/wallet/<name>` to pick a wallet when several are loaded.

## Authentication

Every request except `GET /health` needs HTTP Basic auth. At startup the node writes a
cookie, `__cookie__:<random hex>`, to `.cookie` in the network data directory and
keeps it across restarts. You can also set `rpcuser` and `rpcpassword` in the config
file. A request without valid credentials gets HTTP 401.

```bash
COOKIE="$(cat "$DATADIR/regtest/.cookie")"
curl -s --user "$COOKIE" -d '{"jsonrpc":"1.0","id":1,"method":"getblockcount","params":[]}' http://127.0.0.1:18443/
curl -s --user "$COOKIE" -d '[{"method":"getblockcount","id":1},{"method":"uptime","id":2}]' http://127.0.0.1:18443/
curl -s http://127.0.0.1:18443/health
```

Any JSON-RPC client that speaks to Core works, for example
`bitcoin-cli -regtest -rpcport=18443 -rpccookiefile="$DATADIR/regtest/.cookie" getblockcount`.

To serve RPC over HTTPS, pass `--rpc-tls-cert` and `--rpc-tls-key`.

## Methods

The node dispatches 140 methods (`handle_method/3` in `src/beamchain_rpc.erl`).
They are grouped below the way Core's `help` groups them. 121 of them have the same
name in Core v31.1.

| Group | Methods |
|---|---|
| Blockchain | `dumptxoutset`, `getbestblockhash`, `getblock`, `getblockchaininfo`, `getblockcount`, `getblockfilter`, `getblockfrompeer`, `getblockhash`, `getblockheader`, `getblockstats`, `getchainstates`, `getchaintips`, `getchaintxstats`, `getdeploymentinfo`, `getdifficulty`, `getmempoolancestors`, `getmempooldescendants`, `getmempoolentry`, `getmempoolinfo`, `getrawmempool`, `gettxout`, `gettxoutproof`, `gettxoutsetinfo`, `gettxspendingprevout`, `importmempool`, `loadtxoutset`, `preciousblock`, `pruneblockchain`, `savemempool`, `scanblocks`, `scantxoutset`, `verifychain`, `verifytxoutproof`, `waitforblock`, `waitforblockheight`, `waitfornewblock` |
| Control | `getmemoryinfo`, `getrpcinfo`, `help`, `logging`, `stop`, `uptime` |
| Mining | `getblocktemplate`, `getmininginfo`, `getnetworkhashps`, `getprioritisedtransactions`, `prioritisetransaction`, `submitblock`, `submitheader` |
| Generating (hidden in Core) | `generateblock`, `generatetoaddress`, and `generate` (removed from Core in 0.19) |
| Network | `addnode`, `clearbanned`, `disconnectnode`, `getaddednodeinfo`, `getaddrmaninfo`, `getconnectioncount`, `getnettotals`, `getnetworkinfo`, `getnodeaddresses`, `getpeerinfo`, `listbanned`, `ping`, `setban`, `setnetworkactive` |
| Raw transactions | `analyzepsbt`, `combinepsbt`, `combinerawtransaction`, `converttopsbt`, `createpsbt`, `createrawtransaction`, `decodepsbt`, `decoderawtransaction`, `decodescript`, `descriptorprocesspsbt`, `finalizepsbt`, `fundrawtransaction`, `getrawtransaction`, `joinpsbts`, `sendrawtransaction`, `signrawtransactionwithkey`, `submitpackage`, `testmempoolaccept`, `utxoupdatepsbt` |
| Util | `createmultisig`, `deriveaddresses`, `estimatesmartfee`, `getdescriptorinfo`, `getindexinfo`, `signmessagewithprivkey`, `validateaddress`, `verifymessage` |
| Wallet | `backupwallet`, `bumpfee`, `createwallet`, `encryptwallet`, `getaddressinfo`, `getbalance`, `getbalances`, `getnewaddress`, `getrawchangeaddress`, `gettransaction`, `getwalletinfo`, `importdescriptors`, `listdescriptors`, `listlockunspent`, `listtransactions`, `listunspent`, `listwallets`, `loadwallet`, `lockunspent`, `psbtbumpfee`, `rescanblockchain`, `restorewallet`, `send`, `sendtoaddress`, `signmessage`, `signrawtransactionwithwallet`, `unloadwallet`, `walletcreatefundedpsbt`, `walletlock`, `walletpassphrase`, `walletprocesspsbt` |
| Hidden or test-only in Core | `addpeeraddress`, `estimaterawfee`, `getorphantxs`, `invalidateblock`, `reconsiderblock` |

### Not in Core v31.1

| Method | What it does |
|---|---|
| `getsyncstate` | Header and block sync progress. |
| `flushchainstate` | Write the UTXO cache to disk now. |
| `scrubunspendable` | Remove unspendable outputs (OP_RETURN or over 10,000 bytes) that older versions wrote to the UTXO set. |
| `dumpmempool`, `loadmempool` | Write and read `mempool.dat` (Core has `savemempool` and `importmempool`, which beamchain also has). |
| `dumpprivkey`, `importprivkey` | Single-key export and import. Core dropped these with legacy wallets. |
| `listaddresses` | Addresses the wallet has handed out. |
| `getwalletmnemonic` | The wallet's BIP-39 mnemonic. |
| `getpayjoinrequest`, `sendpayjoinrequest` | BIP-78 PayJoin receiver and sender. |

### In Core v31.1 but not in beamchain

`abandontransaction`, `abortprivatebroadcast`, `abortrescan`, `createwalletdescriptor`,
`enumeratesigners`, `getaddressesbylabel`, `getdescriptoractivity`, `gethdkeys`,
`getmempoolcluster`, `getprivatebroadcastinfo`, `getreceivedbyaddress`,
`getreceivedbylabel`, `getzmqnotifications`, `importprunedfunds`, `keypoolrefill`,
`listaddressgroupings`, `listlabels`, `listreceivedbyaddress`, `listreceivedbylabel`,
`listsinceblock`, `listwalletdir`, `migratewallet`, `removeprunedfunds`, `sendall`,
`sendmany`, `setlabel`, `setwalletflag`, `simulaterawtransaction`,
`walletdisplayaddress`, `walletpassphrasechange`. These answer with error -32601
(method not found).

## Known differences

- Having a method with Core's name does not mean every parameter and every error path
  matches. `test/bc3_core_regtest.sh` compares the UTXO-set RPCs (`gettxoutsetinfo`,
  `scantxoutset`) against Core v31.1 directly; see [status.md](status.md).
- There are no label methods (`setlabel`, `listlabels`, ...) and no external-signer support.
- PayJoin covers the basic BIP-78 merge. The output-substitution rules and the
  anti-fingerprinting heuristics are not implemented (`test/beamchain_w119_payjoin_tests.erl`
  prints these as `SKIP-MISSING-ENTIRELY`).

## REST

With `rest=1` in the config file (or `BEAMCHAIN_REST=1`), a read-only REST server
listens on the RPC port plus 10 (18453 on regtest), without authentication. It follows
Core's `rest.cpp`; every path ends in `.json`, `.bin` or `.hex`:

| Path | Returns |
|---|---|
| `/rest/block/<hash>`, `/rest/block/notxdetails/<hash>` | Block |
| `/rest/tx/<txid>` | Transaction (needs `txindex` for transactions not in the mempool) |
| `/rest/headers/<count>/<hash>`, `/rest/headers/<hash>?count=<n>` | Headers |
| `/rest/blockhashbyheight/<height>` | Block hash |
| `/rest/chaininfo` | Same as `getblockchaininfo` |
| `/rest/mempool/info`, `/rest/mempool/contents` | Mempool |
| `/rest/getutxos[/checkmempool]/<txid>-<n>/...` | UTXO lookup |
| `/rest/blockfilter/basic/<hash>`, `/rest/blockfilterheaders/basic/<count>/<hash>` | BIP-157 filters (needs the filter index) |

```bash
curl -s http://127.0.0.1:18453/rest/chaininfo.json
```

## ZMQ

Set any of `zmqpubhashblock`, `zmqpubhashtx`, `zmqpubrawblock`, `zmqpubrawtx`,
`zmqpubsequence` to an endpoint such as `tcp://127.0.0.1:28332`. The messages use
Core's topics and framing (topic, body, 4-byte little-endian sequence number).
