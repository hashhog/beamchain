# Architecture

beamchain is an OTP application. Each long-lived part of the node is a supervised
process (`gen_server` or `gen_statem`), so a crash in one peer or one RPC handler is
contained and restarted by its supervisor. Hot paths that Erlang is slow at
(secp256k1 signatures, SHA-256) are C NIFs. Storage is RocksDB through the
`erlang-rocksdb` NIF, plus Bitcoin Core's `blk*.dat`/`rev*.dat` flat files.

All source is in `src/`, one module per file.

## Process tree

`beamchain_app` starts `beamchain_sup`, which starts `beamchain_config` and then
`beamchain_node_sup`. The node supervisor starts, in order:

1. Storage and chain state: `beamchain_db`, `beamchain_sig_cache`,
   `beamchain_tip_notifier`, `beamchain_chainstate_sup` (which runs `beamchain_chainstate`).
2. Mempool and fees: `beamchain_mempool`, `beamchain_fee_estimator`, `beamchain_erlay`.
3. Networking: `beamchain_addrman`, `beamchain_peer_manager`, `beamchain_header_sync`,
   `beamchain_block_sync`, `beamchain_sync`, `beamchain_tx_ingest`, `beamchain_serve_limiter`.
4. Services: `beamchain_miner`, `beamchain_wallet_sup`, `beamchain_rpc`,
   `beamchain_metrics`, and when enabled `beamchain_rest`, `beamchain_zmq`, the
   optional indexes and `beamchain_torcontrol`.

## Parts and where they live

| Part | Modules |
|---|---|
| Entry point, CLI | `beamchain_cli` (escript `main/1`, flags, `start`/`stop`/`import`), `beamchain_app`, `beamchain_sup`, `beamchain_node_sup` |
| Configuration | `beamchain_config` (networks, config file, environment), `beamchain_chain_params` (consensus parameters, checkpoints, assume-valid, assumeutxo) |
| Serialization | `beamchain_serialize`, `beamchain_p2p_msg`, `beamchain_address` |
| Consensus | `beamchain_validation` (block and transaction checks, ConnectBlock), `beamchain_pow`, `beamchain_versionbits`, `beamchain_script` (interpreter, sighash, taproot), `beamchain_script_check_queue` (parallel script checks), `beamchain_crypto` + `c_src/` (NIF) |
| Chain state | `beamchain_chainstate` (UTXO cache in ETS with Core's FRESH/DIRTY flags, connect/disconnect, reorgs, flush), `beamchain_db` (RocksDB column families, block files, undo data, pruning), `beamchain_fatal` (abort latch) |
| AssumeUTXO | `beamchain_snapshot` (load/dump Core-format snapshots), `beamchain_bg_validation` (background chainstate), `beamchain_muhash` |
| Indexes | `beamchain_blockfilter`, `beamchain_blockfilter_index` (BIP-157/158), `beamchain_coinstatsindex`, `beamchain_txospenderindex` |
| P2P | `beamchain_peer` (one `gen_statem` per connection), `beamchain_peer_manager`, `beamchain_addrman`, `beamchain_asmap`, `beamchain_localaddr`, `beamchain_listener`, `beamchain_proxy` (SOCKS5, I2P SAM), `beamchain_torcontrol` |
| Transport | `beamchain_transport_v2`, `beamchain_v2_msg` (BIP-324) |
| Sync | `beamchain_headerssync` (anti-DoS headers presync), `beamchain_header_sync`, `beamchain_block_sync` (parallel download), `beamchain_sync`, `beamchain_compact_block` (BIP-152), `beamchain_import` |
| Relay | `beamchain_tx_ingest`, `beamchain_erlay`, `beamchain_minisketch` (BIP-330), `beamchain_serve_limiter` |
| Mempool | `beamchain_mempool` (policy, packages, RBF, TRUC, cluster linearization), `beamchain_mempool_chunks`, `beamchain_mempool_persist` (`mempool.dat`), `beamchain_fee_estimator` |
| Mining | `beamchain_miner` (block templates, `generate*`) |
| RPC and APIs | `beamchain_rpc` (JSON-RPC over Cowboy), `beamchain_core_arity` (Core's argument-count table), `beamchain_rest`, `beamchain_zmq`, `beamchain_metrics`, `beamchain_tip_notifier` (`waitfor*`) |
| Wallet | `beamchain_wallet`, `beamchain_wallet_sup`, `beamchain_descriptor`, `beamchain_miniscript`, `beamchain_psbt`, `beamchain_witness_signer`, `beamchain_bip39`, `beamchain_bip21`, `beamchain_payjoin*` (BIP-78) |
| Test support | `beamchain_fault` (fault-injection hooks used by the crash tests), `beamchain_utxo_repair` |

## Other directories

| Path | Contents |
|---|---|
| `include/` | Shared records and constants (`beamchain.hrl`, `beamchain_protocol.hrl`) |
| `c_src/` | The crypto NIF; its Makefile fetches and builds libsecp256k1 |
| `priv/` | Built NIF (`beamchain_crypto_nif.so`) and data files |
| `config/` | `sys.config` and `vm.args` for `rebar3 as prod release` |
| `test/` | EUnit modules (`*_tests.erl`), vectors in `test/data/`, `bc3_core_regtest.sh` |
| `scripts/` | `reproducible-escript.sh`, `smoke-beamchain.sh` (release cold-boot test), `reset_chainstate.escript`, git hooks |
| `tools/` | `gen_core_arity_erl.py`, which regenerates `beamchain_core_arity` from Core's sources |
| `proof/` | Captured results behind the status table, with `proof/verify.sh` (see [status.md](status.md)) |
