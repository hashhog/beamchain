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
- [x] Header sync anti-DoS (PoW validation, unconnecting limits, deep fork protection)
- [x] Block download and storage (RocksDB)
- [x] Flat file block storage (blk*.dat files, Bitcoin Core compatible format)
- [x] Script interpreter (all opcodes)
- [x] Legacy sighash (FindAndDelete, OP_CODESEPARATOR)
- [x] SegWit v0 (P2WPKH, P2WSH) with BIP143 sighash
- [x] Taproot (key path and script path) with BIP341 sighash
- [x] MINIMALIF enforcement for witness scripts
- [x] Accurate sigop counting (legacy, P2SH, witness)
- [x] UTXO set management and chainstate with write-back cache
- [x] UTXO cache FRESH flag optimization (like Bitcoin Core's CCoinsViewCache)
- [x] Undo data for block disconnection (reorg support)
- [x] Mempool with fee-based ordering and ancestor/descendant limits
- [x] Full RBF (Replace-by-Fee) transaction replacement
- [x] Package acceptance (CPFP within packages, package RBF)
- [x] v3/TRUC policy (BIP431 topologically restricted transactions)
- [x] BIP68 relative lock-time (sequence locks)
- [x] JSON-RPC interface (core RPCs including getblock, gettxoutsetinfo, getblockstats)
- [x] Block statistics RPCs (getblockstats, getchaintxstats)
- [x] Batch JSON-RPC support (parallel request processing)
- [x] Block template construction (getblocktemplate)
- [x] Witness commitment (BIP141)
- [x] CPFP-aware tx selection (ancestor fee rate)
- [x] Difficulty adjustment algorithm (retarget every 2016 blocks)
- [x] BIP9 versionbits soft fork deployment tracking
- [x] Checkpoint enforcement (reject forks below checkpoints, skip scripts during IBD)
- [x] Peer misbehavior scoring and banning
- [x] Pre-handshake connection rejection (ban/limit checks before handshake)
- [x] Inv trickling (privacy-preserving tx relay with Poisson delays)
- [x] BIP133 feefilter (filter tx relay by peer's minimum fee rate)
- [x] Eclipse attack protections (bucket-based addrman, netgroup limits, anchor connections)
- [x] Stale peer eviction (tip timeout, headers timeout, ping timeout, network protection)
- [x] Block pruning (delete old blk/rev files, keep 288 blocks for reorg safety)
- [x] HD wallet (BIP32/44/84 key derivation)
- [x] Wallet UTXO tracking and balance
- [x] Coin selection (Branch-and-Bound, knapsack)
- [x] Transaction signing (P2PKH, P2WPKH, P2TR)
- [x] PSBT support (BIP 174 with createpsbt, decodepsbt, combinepsbt, finalizepsbt RPCs)
- [x] Wallet RPC methods (getnewaddress, getbalance, sendtoaddress)
- [x] Keypool with 1000-address lookahead
- [x] Coinbase maturity enforcement (100-block rule)
- [x] Wallet encryption (AES-256-CBC with PBKDF2 key derivation)
- [x] Compact block relay (BIP152 with SipHash-2-4)
- [x] BIP324 v2 encrypted transport (ElligatorSwift, ChaCha20-Poly1305)
- [x] BIP155 ADDRv2 messages (TorV3, I2P, CJDNS address support)
- [x] Output descriptors (BIP380-386: pkh, wpkh, sh, wsh, multi, tr, addr, raw)
- [x] Miniscript policy compiler (type checking, script compilation, satisfaction)

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
├── beamchain_peer_manager.erl Peer lifecycle, banning, eclipse protections
├── beamchain_addrman.erl      Address manager with bucket-based storage
├── beamchain_header_sync.erl  Header-first sync with anti-DoS
├── beamchain_block_sync.erl   Block download and compact block relay
├── beamchain_compact_block.erl BIP152 compact block reconstruction
├── beamchain_chainstate.erl   UTXO management
├── beamchain_mempool.erl      Transaction pool
├── beamchain_miner.erl        Block template construction
├── beamchain_pow.erl          Proof of work and difficulty
├── beamchain_versionbits.erl  BIP9 deployment tracking
├── beamchain_chain_params.erl Network parameters and checkpoints
├── beamchain_db.erl           RocksDB wrapper, flat file storage, block indexes
├── beamchain_rpc.erl          JSON-RPC server
├── beamchain_wallet.erl       HD wallet, coin selection
├── beamchain_psbt.erl         BIP 174 PSBT serialization and signing
├── beamchain_descriptor.erl   Output descriptors (BIP380-386)
├── beamchain_miniscript.erl   Miniscript policy compiler
└── beamchain_transport_v2.erl BIP324 v2 encrypted transport

c_src/
└── beamchain_crypto_nif.c     libsecp256k1 bindings

test/
├── beamchain_script_tests.erl         Script and sighash tests
├── beamchain_chainstate_tests.erl     Undo data and disconnect tests
├── beamchain_miner_tests.erl          Block template and witness tests
├── beamchain_mempool_tests.erl        Mempool and limit tests
├── beamchain_peer_tests.erl           Inv trickling and relay tests
├── beamchain_peer_manager_tests.erl   Misbehavior, banning, and stale eviction tests
├── beamchain_addrman_tests.erl        Bucket assignment and netgroup tests
├── beamchain_pow_tests.erl            PoW and difficulty adjustment tests
├── beamchain_versionbits_tests.erl    BIP9 state machine tests
├── beamchain_validation_tests.erl     Consensus rule tests
├── beamchain_rpc_tests.erl            RPC tests (core blockchain and transaction RPCs)
├── beamchain_wallet_tests.erl         HD wallet and coin selection tests
├── beamchain_psbt_tests.erl           BIP 174 PSBT tests
├── beamchain_block_sync_tests.erl     Block sync and compact block tests
├── beamchain_descriptor_tests.erl     Output descriptor tests
├── beamchain_miniscript_tests.erl     Miniscript parsing, compilation, satisfaction
└── beamchain_transport_v2_tests.erl   BIP324 v2 transport tests
```

## Running tests

```bash
rebar3 eunit
```
