# W141 — ZMQ + REST + Notification scripts audit (beamchain)

Discovery-only wave. 30 audit gates across three bundled subsystems:

- **ZMQ** notification publisher (`bitcoin-core/src/zmq/`):
  - `zmqnotificationinterface.{h,cpp}` (213 LOC) — kernel-notification
    fan-out wiring (UpdatedBlockTip / BlockConnected / BlockDisconnected
    / TransactionAddedToMempool / TransactionRemovedFromMempool).
  - `zmqpublishnotifier.{h,cpp}` (293 LOC) — per-topic notifier
    subclasses (hashblock / hashtx / rawblock / rawtx / sequence) and
    the multipart `[topic, body, LE32(nSequence)]` wire format.
  - `zmqabstractnotifier.{h,cpp}` — base class + `DEFAULT_ZMQ_SNDHWM=1000`
    + per-topic `-zmqpub*hwm=N` knob.
- **REST** HTTP server (`bitcoin-core/src/rest.cpp` 1178 LOC):
  - `/rest/tx`, `/rest/block`, `/rest/block/notxdetails`,
    `/rest/blockpart`, `/rest/blockfilter`, `/rest/blockfilterheaders`,
    `/rest/chaininfo`, `/rest/mempool/{info,contents}`, `/rest/headers`,
    `/rest/getutxos`, `/rest/deploymentinfo`, `/rest/blockhashbyheight`,
    `/rest/spenttxouts`.
  - `MAX_GETUTXOS_OUTPOINTS = 15`, `MAX_REST_HEADERS_RESULTS = 2000`,
    `DEFAULT_REST_ENABLE = false`, `RESTERR` JSON / hex / bin formats.
- **Notification scripts** (`bitcoin-core/src/init.cpp` +
  `bitcoin-core/src/common/system.cpp`):
  - `-blocknotify=<cmd>` — Run `system(cmd)` after best-block change,
    `%s` → block hash, gated on `SynchronizationState::POST_INIT`
    (i.e. NOT during IBD).
  - `-walletnotify=<cmd>` — Wallet-side: `%s` → txid, `%w` → wallet
    name, `%b` → block hash (or "unconfirmed"), `%h` → block height
    (or -1).
  - `-alertnotify=<cmd>` — Run when an alert (`UpdateNotifyChain`,
    `KernelNotifications::warningSet`) fires; `%s` → alert text.
  - `-startupnotify=<cmd>` — fired on successful startup.
  - `-shutdownnotify=<cmd>` — fired during graceful shutdown sequence
    (joined synchronously before VM exit).
  - All five wired via `runCommand(strCommand)` →
    `::system(strCommand.c_str())` in `common/system.cpp:50-61`, with
    `ShellEscape()` (`'arg'` quoting, single-quote escape via
    `'"'"'`).

References: `bitcoin-core/doc/zmq.md`, `bitcoin-core/doc/REST-interface.md`,
`bitcoin-core/contrib/zmq/zmq_sub.py`.

Companion audits to cross-reference:

- **W124** (operator experience): G28 already established that beamchain
  has no `-shutdownnotify` / `-startupnotify` / `-alertnotify` /
  `-walletnotify` hooks. W141 zooms into the *kernel notification*
  fan-out (ZMQ + REST) and explicitly catalogues the missing
  external-command notify hooks as a single LOW-class subsystem.
- **W125** (RPC error parity): the REST error wire format (Core uses
  `RESTERR` → plain HTTP-status + text body) is materially the same
  in beamchain (`reply_error` at `beamchain_rest.erl:887-893`), but
  W125 didn't audit the *REST surface*, only the JSON-RPC envelope.
- **W117** / **W118** / **W121**: the BIP-157 REST endpoints
  (`/rest/blockfilter`, `/rest/blockfilterheaders`) were partially
  cross-audited there; this wave revisits them through the REST lens.
- **W133** (index databases): the REST `/rest/blockfilter*` routes
  depend on `beamchain_blockfilter_index` being enabled
  (`blockfilterindex=1`), which is default-off; W133 catalogued the
  index storage layer, W141 catalogues the REST surface.

## Status counts (30 gates)

- **PRESENT** (Core-parity, or internally consistent + Core-compatible): 6
- **PARTIAL** (some piece matches, others diverge or are simplified): 9
- **MISSING** (no equivalent in beamchain): 15

Headline: **24 bugs**, severity distribution
**0 CDIV / 4 HIGH / 12 MEDIUM / 8 LOW**.

ZMQ/REST/notify is an *external observer* surface — wrong answers
cannot fork the chain, but downstream block explorers, electrum
servers, Lightning hubs, and operator monitoring all depend on these
wire formats matching Core byte-for-byte. The most consequential:

1. **BUG-1 (HIGH)** — **`hashtx` / `rawtx` not republished on block
   disconnect.** `beamchain_zmq:do_notify_block/3` (`src/beamchain_zmq.erl:260-267`)
   only iterates `lists:foldl(do_notify_tx_for_block, ...)` over
   `Txs` when `Action =:= connect`; the `disconnect` clause goes
   straight to `State4` with no per-tx publish. Core
   (`zmqnotificationinterface.cpp:198-211`) publishes
   `NotifyTransaction(*tx)` for every tx in the disconnected block
   BEFORE firing `NotifyBlockDisconnect`. Subscribers using the
   `hashtx` / `rawtx` topics to track mempool churn during a reorg
   miss the "your tx is back in the mempool" signal, which is what
   `NotifyTransaction` represents for disconnected blocks (Core
   treats the disconnected block as if every tx was readmitted to
   the mempool — see kernel/mempool_persist.cpp:`AddToMempool` from
   `MaybeResurrectMempool`). Effect: a reorg that ejects N
   transactions from a block silently drops the `hashtx`/`rawtx`
   notifications for those N transactions, breaking electrs-style
   live mempool consumers.

2. **BUG-2 (HIGH)** — **`hashblock` / `rawblock` fire from
   per-block-connect path, NOT from `UpdatedBlockTip`.** Core
   (`zmqnotificationinterface.cpp:151-159`) fires `NotifyBlock` from
   `UpdatedBlockTip(pindexNew, pindexFork, fInitialDownload)` only
   when `!fInitialDownload && pindexNew != pindexFork` — i.e.
   ONCE per active-chain advance (NOT once per block-connected
   during IBD, NOT during a pure-disconnect run). beamchain's
   `beamchain_chainstate.erl:1027` fires `notify_block(Block,
   connect)` from `do_connect_block_inner` for EVERY block
   connect, including all 850k+ blocks during IBD on mainnet. This
   floods the `hashblock` and `rawblock` ZMQ topics during sync,
   which is the exact problem Core's `UpdatedBlockTip` gate
   prevents. Three downstream consequences: (a) any subscriber to
   `rawblock` receives ~400 GB of mainnet blocks during a fresh
   sync (Core sends nothing during IBD); (b) the ZMQ `SNDHWM=1000`
   default fills almost instantly and ZMQ silently drops most of
   them; (c) sequence-number gaps appear to subscribers (because
   dropped messages still increment the per-topic counter, but the
   subscriber never sees them).

3. **BUG-3 (HIGH)** — **`list_to_atom/1` on operator-controlled
   protocol string (atom-table DoS).** `beamchain_zmq.erl:209` does
   `Protocol = list_to_atom(ProtoStr)` on the URL-prefix of every
   `zmqpub*` endpoint. Erlang's atom table is global and never
   garbage-collected; a misconfigured operator (or a config-file
   typo where the protocol-prefix is non-tcp like `tcp4`, `unix`,
   `epgm`, `pgm`, `vmci`, etc., each typed as a fresh atom)
   permanently leaks an atom per startup. The atom limit defaults
   to 1,048,576 (`+t` flag); this isn't immediately exploitable —
   the operator owns the config file — but it's a footgun that
   should be `list_to_existing_atom/1` followed by a known-good
   whitelist (`tcp` is the only protocol chumak's `chumak_socket:75`
   even supports, all others return `{error, {unsupported_protocol,
   Protocol}}`). Mirrors `bitcoin-core/src/zmq/zmqnotificationinterface.cpp:62`
   which only special-cases the literal string `ADDR_PREFIX_UNIX`
   (`unix:`) and otherwise passes the address straight to
   `zmq_bind()` without any atom-style allocation.

4. **BUG-4 (HIGH)** — **`chumak:stop(Socket)` is a no-op — sockets
   leak.** `beamchain_zmq.erl:159, 180, 194, 198` calls
   `chumak:stop(Socket)` to clean up sockets on terminate / bind
   failure / setup error. But `chumak:stop/1` is the OTP
   application-stop callback (`chumak.erl:36-37`), it discards its
   argument and unconditionally returns `ok`. There is no public
   socket-close API in chumak 1.4.0 (the only path to terminate a
   socket is to crash its supervisor). Effect: every `terminate/2`
   on `beamchain_zmq` leaks all bound ports + accept loops; every
   bind-failure path during `setup_sockets` likewise leaks all the
   sockets created before the failing one. Over many restarts on
   maxbox this exhausts the BEAM listening-socket descriptor table.
   Cross-references rebar3 xref ignores `chumak:stop/1` in
   `rebar.config:82`, which silenced the only signal that would
   have caught this at compile-time.

The remaining 20 bugs cover MEDIUM/LOW scope:

- **BUG-5 (MED)**: no `mempool_sequence` query parameter on
  `/rest/mempool/contents.json`. Core's `rest_mempool` accepts
  `?mempool_sequence=true` (and rejects `verbose=true&mempool_sequence=true`
  with HTTP 400 since the verbose form already exposes per-entry
  state). beamchain ignores the param entirely
  (`beamchain_rest.erl:454-466`) — every subscriber gets the verbose
  flag's snapshot, with no atomic-across-restart sequence guarantee.
- **BUG-6 (MED)**: no `/rest/deploymentinfo` endpoint. Core registers
  both `/rest/deploymentinfo/` and `/rest/deploymentinfo` prefixes
  (`rest.cpp:1155-1156`) for deployment status queries. beamchain
  doesn't route this at all (`route_request/2`); falls through to
  HTTP 404 "Endpoint not found".
- **BUG-7 (MED)**: no `/rest/spenttxouts` endpoint. Core's newer
  REST surface (`rest.cpp:1158`) exposes the spent-utxo lookup for
  any tx; beamchain has no route.
- **BUG-8 (MED)**: no `/rest/blockpart/` endpoint. Core's
  `rest_block_part` (`rest.cpp:481-486`) returns just the txid list
  + a small header summary; beamchain only has `/rest/block` and
  `/rest/block/notxdetails`.
- **BUG-9 (MED)**: no `-blocknotify` external-command hook. Core's
  `init.cpp:2009-2018` wires `block_notify` to
  `uiInterface.NotifyBlockTip_connect` and runs
  `std::thread(runCommand, cmd)` (detached) on each new active tip,
  with `%s` placeholder substitution. beamchain has no equivalent —
  every operator running `bitcoind -blocknotify="...mail..."` for
  fork / reorg / new-block alerting cannot port that config.
- **BUG-10 (MED)**: no `-walletnotify` external-command hook. Core
  fires this on every wallet-tx state change with
  `%s/%w/%b/%h` placeholder substitution; beamchain has no wallet
  notify wiring at all (W118 G24 also notes this).
- **BUG-11 (MED)**: no `-alertnotify` external-command hook (W124
  G28 cross-confirms). Core fires this on warnings via
  `KernelNotifications::warningSet`; beamchain logs the warning but
  has no external-command callout.
- **BUG-12 (MED)**: no `-startupnotify` / `-shutdownnotify`
  external-command hook (W124 G28 cross-confirms). Core wires both
  via `runCommand`; `-shutdownnotify` even joins the thread
  synchronously before VM exit (`init.cpp:255-265`).
- **BUG-13 (MED)**: ZMQ `sequence` topic body order divergence
  for mempool removal. Core's
  `CZMQPublishSequenceNotifier::NotifyTransactionRemoval`
  (`zmqpublishnotifier.cpp:288`) passes `'R'` + the mempool
  sequence to `SendSequenceMsg`; the body shape is
  `<hash:32><label:1><sequence:LE64>`. beamchain
  (`beamchain_zmq.erl:323`) builds
  `<TxidDisplay/binary, Label:8, MempoolSeq:64/little>`. This is
  byte-identical to Core EXCEPT the `MempoolSeq` source: beamchain
  fetches the *mempool gen_server's own* `zmq_seq` counter
  (`beamchain_mempool.erl:820, 2658`), which increments
  per-call-to-zmq, NOT per-mempool-mutation. Core's
  `uint64_t mempool_sequence` is the `m_sequence_number` tracked
  on every `addUnchecked`, `removeUnchecked`, and
  `removeForBlock`, including for-block removals that DON'T fire
  ZMQ. Effect: beamchain's sequence numbers stay dense (no gaps
  for block-confirmed removals), but a subscriber comparing
  beamchain's `sequence` topic against `mempool_sequence` from
  `getmempoolentry` JSON-RPC sees inconsistent counters.
- **BUG-14 (MED)**: no per-topic `-zmqpub*hwm=N` knob (Core
  `zmqnotificationinterface.cpp:69` calls
  `gArgs.GetIntArg(arg + "hwm", DEFAULT_ZMQ_SNDHWM)` for each topic).
  beamchain has no `outbound_message_high_water_mark` setting at
  all; chumak's default is unlimited (no SNDHWM equivalent), so
  beamchain's `notify_block` cast can grow unboundedly during
  back-pressure where Core would have dropped messages once the
  HWM filled.
- **BUG-15 (MED)**: no socket reuse for same-address topics. Core
  (`zmqpublishnotifier.cpp:99-159`) keeps a `mapPublishNotifiers`
  multimap keyed by address — if `-zmqpubhashblock=tcp://*:28332`
  and `-zmqpubrawblock=tcp://*:28332` both exist, ONE socket is
  bound and both topics multiplex over it. beamchain
  (`setup_sockets/2`) creates one chumak PUB socket per topic;
  configuring all five topics on the same port fails with `eaddrinuse`
  on the second one. This silently breaks the published Core
  config recipe in `bitcoin-core/doc/zmq.md`:
  `-zmqpubhashtx=tcp://127.0.0.1:28332`
  `-zmqpubhashblock=tcp://127.0.0.1:28332` (same port).
- **BUG-16 (MED)**: REST endpoint accepts `GET` only — but
  `cowboy_req:method/1` returns the method case-sensitive
  (`beamchain_rest.erl:124`), and `GET` is the only accepted
  method. Core's libevent dispatcher (`httpserver.cpp:438`)
  accepts both `GET` and `HEAD` for the REST surface (a HEAD
  request returns the body-headers but no body, useful for
  monitoring liveness without paying the full block download
  cost). beamchain returns `405 Method Not Allowed` on a HEAD
  request that Core would accept.
- **BUG-17 (LOW)**: `Access-Control-Allow-Origin: *` (wildcard
  CORS) on every reply (`beamchain_rest.erl:882, 891`). Core does
  NOT set any `Access-Control-Allow-Origin` header on the REST
  surface (`httpserver.cpp` writes only `Content-Type`). The
  wildcard origin is a defense-in-depth concern: combined with a
  browser-side same-origin XSRF on a node operator's localhost,
  it permits any web page to scrape the REST surface (block
  hashes, mempool contents, getutxos with `checkmempool`) of a
  node bound to `0.0.0.0:48342`. The mitigation in production is
  the REST `enable_default = false` opt-in (BUG-19 below), but
  W141 still catalogues this divergence: Core's deliberate
  no-CORS design is one of the reasons `-rest=0` defaults to OFF.
- **BUG-18 (LOW)**: no `?count=N` validation on `/rest/headers`
  beyond the `MAX_REST_HEADERS_RESULTS=2000` clamp. Core also
  rejects `count <= 0` with HTTP 400; beamchain silently coerces
  `0` and `-1` to the default `5` (`parse_count` /
  `query_count`). Minor — subscribers ignore the count and
  resubmit — but Core's strict-rejection error surface is
  Core-parity-divergent.
- **BUG-19 (LOW)**: REST gates filter routes on
  `blockfilterindex_enabled()` and returns `400 Bad Request`
  with the body `Index is not enabled for filtertype <name>`.
  Core (`rest.cpp:647`) returns the same body but the
  cross-impl test suite expects exact-byte-match on this string.
  beamchain's exact text is
  `"Index is not enabled for filtertype basic"` which matches Core
  — PRESENT — but the `blockfilterheaders` route (line 598)
  emits the SAME error using a `<<"Index is not enabled for
  filtertype ", FilterType/binary>>` template that includes a
  trailing whitespace if the operator passes
  `/rest/blockfilterheaders/basic /5/<hash>.json`. Core
  pre-trims by splitting on `/`; beamchain's `parse_path` keeps
  the trailing space in the FilterType segment. Edge-case only.
- **BUG-20 (LOW)**: `chaininfo` JSON missing fields versus Core.
  beamchain's `rest_chaininfo` (`beamchain_rest.erl:402-427`)
  emits 13 keys (`chain`, `blocks`, `headers`, `bestblockhash`,
  `difficulty`, `time`, `mediantime`, `verificationprogress`,
  `initialblockdownload`, `chainwork`, `size_on_disk`, `pruned`).
  Core's `getblockchaininfo` (which is what `/rest/chaininfo`
  proxies) returns those plus `warnings` (array since v26),
  `pruneheight` (only when pruned), `automatic_pruning` (only
  when pruned), `prune_target_size` (only when pruned),
  `softforks` / `signet_challenge` (network-conditional). The
  missing `warnings` array is the most consequential for
  operators monitoring activation-warning state.
- **BUG-21 (LOW)**: `rest_chaininfo` returns the WRONG body shape
  for chaininfo with a non-JSON suffix (e.g. `/rest/chaininfo.bin`).
  Core returns HTTP 404 with body
  `"output format not found (available: json)"`. beamchain returns
  HTTP 400 with body `"Only JSON format supported for chaininfo"`.
  Different HTTP status (400 vs 404) + different body text.
  Subscribers / monitors that branch on status code see
  divergent behavior.
- **BUG-22 (LOW)**: `mempool/info` and `mempool/contents` return
  the same wrong-status divergence: HTTP 400 + custom body where
  Core returns HTTP 404 + the literal text
  `"output format not found (available: json)"`.
- **BUG-23 (LOW)**: REST `bestblockhash` chaininfo field uses
  `hash_to_hex(Hash)` (which calls `reverse_bytes` →
  `hex_encode`). The display order is correct. But the REST
  `getutxos` binary response (`encode_utxos_binary` line 1099)
  also reverses the bytes for the `chaintipHash` field
  (`beamchain_serialize:reverse_bytes(ChainHash)`), whereas
  Core's `rest_getutxos` binary path serializes the internal
  hash directly (no byte-reverse). Effect: beamchain's
  binary-format getutxos response has the chaintip hash in
  display order, Core has it in internal order. Subscribers
  reading the binary stream get a byte-reversed prefix.
- **BUG-24 (LOW)**: REST listener port is `RPC_PORT + 10` by
  default (`beamchain_rest.erl:1326-1335`, "Using +10 instead
  of +1 to avoid collision with P2P port"). Core's REST runs on
  the same port as RPC (`httpserver.cpp` registers both
  prefixes). This is a deliberate divergence — beamchain has
  separate listeners for RPC and REST — but it means the
  operator config `rpcport=NNNN` only addresses RPC, not REST,
  and the documented `-rest` opt-in toggles a *different
  port*. Documented but the doc lives only in the comment at
  `rest_port/1`.

## Gate matrix (30 gates)

### ZMQ subsystem (10 gates)

- **G01** PRESENT — Five ZMQ topics (hashblock / hashtx / rawblock /
  rawtx / sequence) defined as binary literals
  (`beamchain_zmq.erl:37-41`). Topic *names* match Core's MSG_*
  constants (`zmqpublishnotifier.cpp:33-37`).
- **G02** PRESENT — Multipart message shape `[topic, body,
  sequence_le32]` (`publish_message/3` line 331-345). Matches
  Core's `zmq_send_multipart(psocket, command, strlen(command),
  data, size, msgseq, 4, nullptr)` at
  `zmqpublishnotifier.cpp:200`.
- **G03** PRESENT — Per-topic 32-bit-wrapping sequence counter
  (`State#state.sequences`, line 343 increments with
  `band 16#ffffffff`). Matches Core's `nSequence++` with
  `WriteLE32(msgseq, nSequence)` at line 199.
- **G04** PRESENT — `sequence` topic body for blockconnect is
  `<hash:32><label:1>` (no LE64 sequence trailer). Matches Core's
  `SendSequenceMsg(*this, hash, 'C')` with `sequence = {}` at
  line 271. Same for `'D'` (line 275).
- **G05** PRESENT — `sequence` topic body for mempool-add/remove
  is `<hash:32><label:1><mempool_seq:LE64>`. Beamchain shape
  matches Core (lines 281-293).
- **G06** PARTIAL/BUG-1 — `hashtx` / `rawtx` NOT republished on
  block disconnect. Catalogued above.
- **G07** PARTIAL/BUG-2 — `hashblock` / `rawblock` fire from
  per-block-connect path, NOT from `UpdatedBlockTip`. Catalogued
  above.
- **G08** MISSING/BUG-14 — No per-topic SNDHWM knob
  (`-zmqpubhashblockhwm=N`).
- **G09** MISSING/BUG-15 — No socket reuse for same-address
  topics — second-bind on the same port fails with `eaddrinuse`.
- **G10** MISSING/BUG-3 — `list_to_atom/1` on operator-controlled
  protocol string (atom-table DoS footgun); plus BUG-4
  `chumak:stop/1` is a no-op so socket cleanup leaks every restart.

### REST subsystem (12 gates)

- **G11** PRESENT — `-rest=0` default (BUG-19 catalogues exact
  body-text parity for the blockfilter disabled-error). Both
  Core and beamchain default the REST listener to OFF, matching
  `DEFAULT_REST_ENABLE = false`.
- **G12** PRESENT — `MAX_GETUTXOS_OUTPOINTS = 15` and
  `MAX_REST_HEADERS_RESULTS = 2000` constants match Core
  (`rest.cpp:44-45`).
- **G13** PRESENT — `/rest/block/<hash>.<json|bin|hex>` route
  shape matches Core's `rest_block_extended`.
- **G14** PRESENT — `/rest/blockhashbyheight/<height>.<format>`
  route matches Core.
- **G15** PRESENT — `/rest/blockfilter/<filtertype>/<hash>.<format>`
  + `/rest/blockfilterheaders/<filtertype>/[<count>/]<hash>.<format>`
  routes match Core (with the deprecated-path form ALSO
  accepted). Wire-format `encode_blockfilter_wire/3` matches
  Core's `BlockFilter::Serialize` byte-for-byte (covered by
  `beamchain_rest_tests.erl:572-614`, exercised by W121).
- **G16** PARTIAL/BUG-5 — `/rest/mempool/contents.json` ignores
  `?mempool_sequence=true` query parameter.
- **G17** PARTIAL/BUG-16 — Only `GET` accepted; Core also accepts
  `HEAD`.
- **G18** PARTIAL/BUG-17 — Wildcard `Access-Control-Allow-Origin: *`
  on every reply; Core sets no CORS header.
- **G19** PARTIAL/BUG-23 — `getutxos` binary `chaintipHash`
  byte-reversed (display order) where Core sends internal order.
- **G20** MISSING/BUG-6 — No `/rest/deploymentinfo` route.
- **G21** MISSING/BUG-7 — No `/rest/spenttxouts` route.
- **G22** MISSING/BUG-8 — No `/rest/blockpart` route.

### Notify-scripts subsystem (8 gates)

- **G23** PRESENT (W124 G28 cross-confirmed null gate) — beamchain
  CLI does NOT advertise `-blocknotify` etc.; the absence is
  consistent across `beamchain_cli.erl --help` and
  `beamchain_config.erl` (no parse rules for these names).
- **G24** MISSING/BUG-9 — `-blocknotify=<cmd>` not wired.
- **G25** MISSING/BUG-10 — `-walletnotify=<cmd>` not wired.
- **G26** MISSING/BUG-11 — `-alertnotify=<cmd>` not wired.
- **G27** MISSING/BUG-12 — `-startupnotify=<cmd>` /
  `-shutdownnotify=<cmd>` not wired.
- **G28** PARTIAL/BUG-20 — `/rest/chaininfo.json` missing
  `warnings` array.
- **G29** PARTIAL/BUG-21+BUG-22 — `/rest/chaininfo.bin`,
  `/rest/mempool/info.bin`, `/rest/mempool/contents.bin` return
  HTTP 400 where Core returns 404 with different body text.
- **G30** PARTIAL/BUG-13 — `sequence` topic mempool seq counter
  source diverges from Core (beamchain uses mempool gen_server's
  zmq_seq, Core uses `m_sequence_number`).

## Status table

| # | Subsystem | Gate | Status | Bug | Severity |
|---|-----------|------|--------|-----|----------|
| G01 | ZMQ | Five topic names | PRESENT | — | — |
| G02 | ZMQ | Multipart message shape | PRESENT | — | — |
| G03 | ZMQ | LE32 per-topic counter | PRESENT | — | — |
| G04 | ZMQ | sequence body block C/D | PRESENT | — | — |
| G05 | ZMQ | sequence body mempool A/R | PRESENT | — | — |
| G06 | ZMQ | hashtx/rawtx on disconnect | PARTIAL | BUG-1 | HIGH |
| G07 | ZMQ | hashblock/rawblock IBD gate | PARTIAL | BUG-2 | HIGH |
| G08 | ZMQ | Per-topic SNDHWM | MISSING | BUG-14 | MED |
| G09 | ZMQ | Socket reuse same-address | MISSING | BUG-15 | MED |
| G10 | ZMQ | atom DoS + stop leak | PARTIAL | BUG-3+BUG-4 | HIGH |
| G11 | REST | -rest=0 default | PRESENT | — | — |
| G12 | REST | MAX_GETUTXOS + MAX_REST_HEADERS | PRESENT | — | — |
| G13 | REST | /rest/block/<h>.<f> | PRESENT | — | — |
| G14 | REST | /rest/blockhashbyheight | PRESENT | — | — |
| G15 | REST | /rest/blockfilter[headers] | PRESENT | — | — |
| G16 | REST | ?mempool_sequence | PARTIAL | BUG-5 | MED |
| G17 | REST | HEAD method | PARTIAL | BUG-16 | MED |
| G18 | REST | CORS wildcard | PARTIAL | BUG-17 | LOW |
| G19 | REST | getutxos chaintipHash order | PARTIAL | BUG-23 | LOW |
| G20 | REST | /rest/deploymentinfo | MISSING | BUG-6 | MED |
| G21 | REST | /rest/spenttxouts | MISSING | BUG-7 | MED |
| G22 | REST | /rest/blockpart | MISSING | BUG-8 | MED |
| G23 | NOT | CLI null gate | PRESENT | — | — |
| G24 | NOT | -blocknotify | MISSING | BUG-9 | MED |
| G25 | NOT | -walletnotify | MISSING | BUG-10 | MED |
| G26 | NOT | -alertnotify | MISSING | BUG-11 | MED |
| G27 | NOT | -startup/shutdownnotify | MISSING | BUG-12 | MED |
| G28 | REST | chaininfo warnings array | PARTIAL | BUG-20 | LOW |
| G29 | REST | non-JSON format HTTP status | PARTIAL | BUG-21+22 | LOW |
| G30 | ZMQ | mempool seq counter source | PARTIAL | BUG-13 | MED |

## Universal patterns surfaced

1. **"audit-flip" convention** continues — every PARTIAL/MISSING gate
   is encoded as an EUnit assertion that pins the *current divergent
   behavior*; a future FIX wave that brings beamchain into parity
   will flip the assertion and force an update. Same convention as
   W94/95/120/121/125/127/130/131/132/133/135/137.
2. **`list_to_atom/1` on operator string** (BUG-3) is the latest
   instance of the atom-table-DoS pattern. Cross-references:
   - `beamchain_zmq.erl:209` (this audit)
   - W125 catalogued the JSON-RPC method-name atomization (different
     atom-table dimension; user input vs operator input).
3. **Dead-helper-at-call-site** (BUG-4: `chumak:stop/1` is the
   application stop callback, not a socket-close API). Same shape
   as the W120 / W121 / W137 dead-helper findings: a function
   exists, IS exported, IS called — but its actual implementation
   does nothing useful. xref+dialyzer can't catch this class
   because the call-site type-signature matches (atom → atom).
4. **External-command notify hooks fleet-wide absence** — W124 G28
   surfaced 4 of the 5 (`-shutdownnotify` / `-startupnotify` /
   `-alertnotify` / `-walletnotify`); W141 G24 adds the 5th
   (`-blocknotify`). Cross-impl pattern: every impl in the fleet
   that grew from "Bitcoin Core RPC parity first, operator wiring
   later" hasn't yet wired the external-command notify hooks.
   Bookkeeping: `bitcoin-core/src/init.cpp` has FIVE distinct
   `runCommand` callsites for these.
5. **Notify-from-block-connect-vs-tip-update** (BUG-2) — Core
   distinguishes "block validated and connected" from "active tip
   advanced", and routes the user-facing `hashblock`/`rawblock`
   topics to the *latter*. Per-block-connect notifications during
   IBD pollute the topic and cause SNDHWM drops. This is the same
   class as the W117/W120 BIP-157 P2P serving status — "fire from
   the right event" is a recurring discovery-wave finding.

## Shell-injection / external-command audit

This wave specifically checks for shell-injection-style issues in any
external-command pipeline:

- `beamchain_cli.erl:969` — `os:cmd(lists:flatten(FullCmd))` (the
  daemon-launch helper). FullCmd is built from `beamchain_cli`-internal
  variables (release path, datadir, node name), not from operator
  config; this is internal use. Not a CVE class — no operator-controlled
  string flows here.
- `beamchain_cli.erl:1221` — `os:cmd("rm -rf " ++ DbDir)`. DbDir
  comes from the `reset` CLI command's argument parsing; operator
  controls DbDir but only via the local CLI shell, which already
  has the same privilege as the operator. No CVE class.
- W141 also confirms beamchain is NOT vulnerable to the `bitcoind`
  shell-injection class because the five Core `runCommand` callsites
  are simply not wired (BUG-9/-10/-11/-12). If beamchain ADDS
  external-command hooks in a future FIX wave, BUG-9..-12 fixes
  MUST use ShellEscape-equivalent quoting matching Core's
  `common/system.cpp:41-46` (replace `'` with `'\"'\"'`,
  wrap in single quotes).

## Test artefact

`beamchain/test/beamchain_w141_zmq_rest_notify_tests.erl` — 30 EUnit
test functions (one per gate). Tests are organized by subsystem and
follow the "audit-flip" convention. Each PARTIAL/MISSING test
explicitly asserts the *current divergent behavior* so that a future
FIX wave bringing beamchain into Core parity will fail the test and
force an update.

## Out of scope

- ZMQ CURVE / AUTH (chumak supports CURVE, Core supports it via
  `-zmqpubhashblockcurvepublickey` etc.; neither end uses it in the
  fleet today). Catalogued for a future W### wave dedicated to
  ZMQ-CURVE rotation + AUTH.
- REST IP-allowlist (`-rpcallowip` on the REST port). Core
  `httpserver.cpp:316-329` gates REST behind the same allowlist as
  RPC; beamchain has no allowlist mechanism on either listener
  (the only port-binding is `{port, P}, {reuseaddr, true}`).
- ZMQ `pubzmqsequence` retransmit-on-resync (Core does NOT
  retransmit dropped messages — that's a deliberate "use REST or
  RPC to catch up after a gap" design choice).
- Cross-impl: rustoshi / blockbrew / ouroboros / lunarblock /
  haskoin / clearbit / hotbuns / nimrod / camlcoin ZMQ surfaces
  are NOT compared here; W141 is single-impl audit per the brief.
