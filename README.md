# beamchain

A Bitcoin full node in Erlang/OTP.

## What is it?

Maybe you've wondered what it takes to validate a Bitcoin transaction from scratch.
beamchain is a from-scratch Bitcoin full node written in Erlang that does exactly that.
It syncs the blockchain, validates blocks with full consensus rules (including SegWit
and Taproot), and maintains a UTXO set backed by RocksDB.

## Current status

- [x] P2P networking and peer management
- [x] Header-first sync with full validation
- [x] Block download and storage (RocksDB)
- [x] Script interpreter (all opcodes)
- [x] Legacy sighash (FindAndDelete, OP_CODESEPARATOR)
- [x] SegWit v0 (P2WPKH, P2WSH) with BIP143 sighash
- [x] Taproot (key path and script path) with BIP341 sighash
- [x] UTXO set management and chainstate
- [x] Mempool with fee-based ordering
- [x] JSON-RPC interface
- [ ] Wallet (HD keys, signing)
- [ ] Compact block relay (BIP152)

## Quick start

```bash
# Build
rebar3 compile

# Sync testnet4
BEAMCHAIN_NETWORK=testnet4 ./beamchain sync

# Or run directly with erl
BEAMCHAIN_NETWORK=testnet4 erl -pa _build/default/lib/*/ebin \
  -eval "application:ensure_all_started(beamchain)."
```

## Project structure

```
src/
├── beamchain_script.erl       Script interpreter (~2800 lines)
├── beamchain_validation.erl   Block/tx consensus rules
├── beamchain_serialize.erl    Tx encoding (legacy + segwit)
├── beamchain_crypto.erl       secp256k1 NIF bindings
├── beamchain_p2p_msg.erl      P2P message encoding
├── beamchain_peer.erl         Connection handling
├── beamchain_block_sync.erl   Block download
├── beamchain_chainstate.erl   UTXO management
├── beamchain_mempool.erl      Transaction pool
├── beamchain_db.erl           RocksDB wrapper
└── beamchain_rpc.erl          JSON-RPC server

c_src/
└── beamchain_crypto_nif.c     libsecp256k1 bindings

test/
└── beamchain_script_tests.erl Script and sighash tests
```

## Running tests

```bash
rebar3 eunit
```
