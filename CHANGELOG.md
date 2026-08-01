# Changelog

All notable changes to beamchain are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-07-31

First stable release of beamchain, a Bitcoin full node implementation in
Erlang/OTP.

### Highlights

- Full block and transaction validation: SegWit v0, Taproot key/script path
  (BIP340-342), BIP68 sequence locks, accurate sigop counting, MINIMALIF and
  NULLFAIL consensus flags, unconditional P2SH/WITNESS/TAPROOT script-flag
  deployment matching Bitcoin Core.
- Header-first sync with anti-DoS protections, block download with compact
  block relay (BIP-152), and work-based fork following at any depth.
- Cluster mempool: union-find clustering, linearization, fee-rate diagram
  RBF, full RBF (BIP-125), package acceptance (CPFP, package RBF, v3/TRUC,
  ephemeral anchors).
- P2P: BIP-324 v2 encrypted transport, BIP-330 Erlay, BIP-133 feefilter,
  BIP-155 ADDRv2 (TorV3/I2P/CJDNS), eclipse-attack protections, stale peer
  eviction, misbehavior scoring and banning.
- Wallet: HD (BIP-32/44/84), multi-wallet, BnB+Knapsack coin selection,
  encrypted storage, PSBT (BIP-174), output descriptors (BIP380-386),
  Miniscript policy compiler.
- assumeUTXO snapshot-based sync (loadtxoutset/dumptxoutset) with six
  mainnet snapshot heights (481823, 840000, 880000, 910000, 935000, 944183)
  and Core-parity regtest entries.
- Block pruning, flat-file block storage (Bitcoin Core compatible), fee
  estimation, block template construction, REST API, ZMQ notifications,
  Tor SOCKS5 proxy and I2P SAM support, NIF-accelerated SHA256 (SHA-NI,
  ARM crypto extensions), batch signature verification.
- Regtest block generation (generate/generatetoaddress/generateblock) and
  chain management RPCs (invalidateblock, reconsiderblock, preciousblock).

### Recent notable fixes (since 0.1.0)

- consensus: unconditional P2SH|WITNESS|TAPROOT script flags; MTP from
  hash-linked parent walk; difficulty-retarget hash-linked ancestry;
  tapscript CHECKSIG unknown-pubkey semantics (BIP342); MAX_STACK_SIZE
  after small-integer pushes; accurate OP_0 multisig sigop count.
- sync: un-wedged header sync (announced-headers ingestion, height refresh,
  probe rotation); dropped redundant per-tx tx-index write pass.
- chainstate: eliminated O(n^2) undo bookkeeping in the connect_block hot
  path; detached cached scriptPubKeys from the peer socket buffer.
- policy: feefilter tracks Core v31 min-relay default (1000 -> 100 sat/kvB);
  accept bare P2PK/multisig outputs and generalized ephemeral dust.
- p2p: BIP-152 short-id collision re-requests the full block instead of
  banning; gate non-negotiation messages until verack; tx-relay ingest via
  getdata on inv.
- rpc: Core-exact BIP-22 reject tokens on submitblock; Core bare reject
  tokens on mempool RPC paths; -8/-5 error-code sweep across block RPCs;
  added preciousblock, getnettotals, submitheader; getpeerinfo/getmempoolentry
  response-shape parity.

### Build / packaging

- escript packaging is unsupported (rocksdb NIF cannot load from an escript
  zip); use `rebar3 as prod release` — see README.
- `config/sys.config` no longer hardcodes a machine-specific datadir; the
  node falls back to `~/.beamchain` (override with `BEAMCHAIN_DATADIR` or
  `--datadir`).

[1.0.0]: https://github.com/hashhog/beamchain/releases/tag/v1.0.0
