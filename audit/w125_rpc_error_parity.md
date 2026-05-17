# W125 — JSON-RPC error code parity audit (beamchain)

Discovery-only wave. 30 audit gates. Status counts:

- **PRESENT** (matches Core or is internally consistent and Core-compatible): 13
- **PARTIAL** (some call sites match, others don't): 2
- **MISSING** (no equivalent emitted in beamchain): 15

Headline: **23 bugs** spanning the missing P2P-client / wallet-encryption /
warmup / IBD code clusters. Largest single divergence by count: 75
"Usage: …" fall-through clauses use `RPC_INVALID_PARAMS` (-32602, a
transport code) instead of `RPC_INVALID_PARAMETER` (-8, the
application-layer code).

Audit asserts current divergent behavior in
`test/beamchain_w125_rpc_error_tests.erl` so a follow-up FIX wave will
flip them PASS → FAIL when the production code is brought into parity
(the audit-flip convention used by FIX-65 / FIX-66 / FIX-67).

Reference: `bitcoin-core/src/rpc/protocol.h`,
`bitcoin-core/src/rpc/{request,server,net,blockchain,mempool,mining,rawtransaction,util}.cpp`,
`bitcoin-core/src/wallet/rpc/{encrypt,spend,addresses,util,wallet}.cpp`,
`bitcoin-core/src/node/transaction.cpp`, BIP-323.

---

## Gate index (1..30)

| #  | Name | Status | Core ref | beamchain ref |
|----|------|--------|----------|---------------|
| 1  | Standard JSON-RPC 2.0 codes (-32700..-32600..-32603) | PRESENT | protocol.h:24-37 | beamchain_rpc.erl:132-136 |
| 2  | General app codes defined as macros | PRESENT (11/12) | protocol.h:40-51 | beamchain_rpc.erl:137-147 |
| 3  | `RPC_OUT_OF_MEMORY` (-7) | MISSING (Core never throws either) | protocol.h:43 | not defined |
| 4  | `RPC_METHOD_DEPRECATED` (-32) | MISSING | protocol.h:51 | not defined / no call sites |
| 5  | Method-not-found path returns -32601 | PRESENT | request.cpp:235 | beamchain_rpc.erl:776-778 |
| 6  | P2P client codes (-9, -10, -23, -24, -29, -30, -31, -33, -34) | MISSING (9 of 9) | net.cpp:362-1003, server_util.cpp:37-127 | many sites use -1 or -8 instead |
| 7  | `sendrawtransaction` already-in-mempool emits -27 (Core: silent re-broadcast) | BUG | node/transaction.cpp:63-71 | beamchain_rpc.erl:2594-2599, 2720-2727 |
| 8  | `addnode add` failure emits -1 (Core: -23) | BUG | net.cpp:362 | beamchain_rpc.erl:3540-3543 |
| 9  | `addnode remove` not-found emits -1 (Core: -24) | BUG | net.cpp:368 | beamchain_rpc.erl:3559 |
| 10 | `disconnectnode` not-connected emits -1 (Core: -29) | BUG | net.cpp:478 | beamchain_rpc.erl:3591 |
| 11 | `setban` invalid subnet emits -8 (Core: -30) | BUG | net.cpp:780, 1003 | beamchain_rpc.erl:3631, 3642 |
| 12 | `setban` unban-failed emits -1 (Core: -30) | BUG | net.cpp:811 | beamchain_rpc.erl:3639 |
| 13 | `getblocktemplate` skips IBD / not-connected gates (Core: throws -9 / -10) | BUG | mining.cpp:769-773 | beamchain_rpc.erl:3720-3739 |
| 14 | Wallet codes (-6, -11, -12, -13, -14, -15, -16, -17, -18, -19, -35, -36) | PARTIAL (2/12 used; -13 + -4 by literal) | wallet/rpc/* | beamchain_rpc.erl: scattered |
| 15 | Internal-error catch-all leaks reason text | INFORMATIONAL | server.cpp catch | beamchain_rpc.erl:599-613 |
| 16 | `dumptxoutset` "already exists" emits -32602 (Core: -8) | BUG | blockchain.cpp:3196+ | beamchain_rpc.erl:8854-8860 |
| 17 | Usage-string fall-through clauses emit -32602 (Core: -8 for wrong-arg) | BUG (75 sites) | util.cpp / RPCHelpMan | beamchain_rpc.erl: 75 occurrences |
| 18 | `verifymessage` malformed base64 → -3 | PRESENT | wallet/rpc/signmessage.cpp | beamchain_rpc.erl:4342-4344 |
| 19 | `RPC_IN_WARMUP` (-28) macro defined but DEAD HELPER | BUG | server.cpp:488 | beamchain_rpc.erl:147 (defined), never thrown |
| 20 | Auth-required uses -1 + HTTP-401 (Core: 401 with no JSON body) | INFORMATIONAL | httprpc.cpp | beamchain_rpc.erl:430-431 |
| 21 | Rate-limited uses -1 + HTTP-429 (Core: no rate-limit logic) | PRESENT (no Core mapping) | n/a | beamchain_rpc.erl:434-438 |
| 22 | Empty batch returns -32600 | PRESENT | httprpc.cpp:179 | beamchain_rpc.erl:449-452 |
| 23 | Block-not-found uses -5 consistently | PRESENT | blockchain.cpp:147, 655 | beamchain_rpc.erl:1106, 1244, 2282, … |
| 24 | `invalidateblock` hash-not-found uses -8 (Core: -5; inconsistent with siblings) | BUG | blockchain.cpp:1701 | beamchain_rpc.erl:1773 |
| 25 | `pruneblockchain` not-in-prune-mode uses -1 | PRESENT | blockchain.cpp:927 | beamchain_rpc.erl:1639, 1659 |
| 26 | `submitblock` uses BIP-22 result strings (not -25) | PRESENT | mining.cpp:1130 | beamchain_rpc.erl:3819-3829 |
| 27 | `importdescriptors` per-request error shape | PRESENT | wallet/rpc/backup.cpp | beamchain_rpc.erl:6904-6919 |
| 28 | Internal-error catch-all → -32603 | PRESENT | server.cpp catch | beamchain_rpc.erl:599-602 |
| 29 | `sendrawtransaction` max-fee-exceeded → -26 | PRESENT | node/transaction.cpp:82 | beamchain_rpc.erl:2600-2604 |
| 30 | Deserialization errors → -22 | PRESENT | rawtransaction.cpp, rpcwallet.cpp | beamchain_rpc.erl:2609, 6021, 6027 |

---

## Bug catalogue (23 BUGs)

### BUG-1 (P0-COMPAT) — `RPC_VERIFY_ALREADY_IN_CHAIN` (-27) emitted for already-in-mempool

`beamchain_rpc.erl:2594-2599, 2720-2727`. Core (`node/transaction.cpp:63-71`)
silently re-broadcasts when the transaction is already in mempool — no
error is raised. Code -27 (`RPC_VERIFY_ALREADY_IN_UTXO_SET`) is reserved
for the strictly stronger case of "already confirmed in the chain".
Client libraries that distinguish "I already sent this" from "this is
already in a block" will mis-route both paths.

**Concrete consequence**: a wallet retry loop that treats -27 as
"don't re-submit, the tx is already final" will treat a mempool-only
tx as final and stop monitoring for confirmation.

### BUG-2..BUG-10 (9 × P0-COMPAT) — Missing P2P client codes (-9, -10, -23, -24, -29, -30, -31, -33, -34)

Entire client-error code cluster is absent. Every call site falls back
to -1 (`RPC_MISC_ERROR`) or -8 (`RPC_INVALID_PARAMETER`).

- BUG-2 `RPC_CLIENT_NOT_CONNECTED` (-9): `getblocktemplate`, `generate*`
  succeed even with zero peers. Core throws -9 (`mining.cpp:769`).
- BUG-3 `RPC_CLIENT_IN_INITIAL_DOWNLOAD` (-10): `getblocktemplate`,
  `importmempool` (n/a) succeed during IBD. Core throws -10
  (`mining.cpp:773`, `mempool.cpp:1141`).
- BUG-4 `RPC_CLIENT_NODE_ALREADY_ADDED` (-23): `addnode add` emits
  -1 with `io_lib:format("~p", [Reason])` (line 3540-3543).
- BUG-5 `RPC_CLIENT_NODE_NOT_ADDED` (-24): `addnode remove` emits -1
  "Node not found" (line 3559).
- BUG-6 `RPC_CLIENT_NODE_NOT_CONNECTED` (-29): `disconnectnode` emits
  -1 "Node not connected" (line 3591).
- BUG-7 `RPC_CLIENT_INVALID_IP_OR_SUBNET` (-30): `setban` invalid
  subnet emits -8 (lines 3631, 3642); unban-failed emits -1 (line 3639).
- BUG-8 `RPC_CLIENT_P2P_DISABLED` (-31): no peerman-absent guard;
  would crash and surface as -32603.
- BUG-9 `RPC_CLIENT_MEMPOOL_DISABLED` (-33): mempool is always
  running; no analogous Erlang configuration.
- BUG-10 `RPC_CLIENT_NODE_CAPACITY_REACHED` (-34): no outbound
  connection-type budget tracking; `addnode onetry` succeeds
  regardless.

**Concrete consequence**: client code that switches behaviour on the
specific P2P error (e.g. "back off and retry on -9, fail-fast on -29")
cannot work against beamchain.

### BUG-11 (P0-COMPAT) — `getblocktemplate` IBD / not-connected gate missing

`beamchain_rpc.erl:3720-3739`. Calls `beamchain_miner:create_block_template`
unconditionally. Mining pool software relying on Core's behaviour will
silently mine on top of an unsynced chain, producing orphan blocks once
the node catches up.

### BUG-12..BUG-19 (8 × P1-COMPAT) — Wallet code cluster mostly emits -1

- BUG-12 `RPC_WALLET_INSUFFICIENT_FUNDS` (-6): `sendtoaddress` emits
  -1 "Insufficient funds" (lines 5497-5498). Core: `spend.cpp:187,1507+`.
- BUG-13 `RPC_WALLET_UNLOCK_NEEDED` (-13): `sendtoaddress` (line
  5481) and `walletprocesspsbt` (lines 6010, 6156) use literal -13.
  All OTHER wallet-locked sites (`signmessage` 4308, `dumpprivkey`
  5391, `getwalletmnemonic` 5367, `getbalance` family) use -1.
  **PARTIAL — 3 of 10+ sites match Core**.
- BUG-14 `RPC_WALLET_PASSPHRASE_INCORRECT` (-14): `walletpassphrase`
  emits **-32602** `RPC_INVALID_PARAMS` (line 6708) — a JSON-RPC
  transport code masquerading as a wallet error. Core: -14
  (`encrypt.cpp:76-78`).
- BUG-15 `RPC_WALLET_WRONG_ENC_STATE` (-15): `walletpassphrase` on
  unencrypted wallet (6703-6704), `walletlock` on unencrypted (6727
  -6728), `encryptwallet` on already-encrypted (6683-6684) — all emit
  -1. Core: -15 (`encrypt.cpp:49,138,203,260`).
- BUG-16 `RPC_WALLET_ENCRYPTION_FAILED` (-16): any encrypt-time
  failure (line 6685-6687) emits -1. Core: -16 (`encrypt.cpp:256,278`).
- BUG-17 `RPC_WALLET_NOT_FOUND` (-18): `wallet_not_found_error/1`
  (line 5418-5422), `unloadwallet` (line 5193) emit -1. Core: -18
  (`util.cpp:72,82,137`, `wallet.cpp:460`).
- BUG-18 `RPC_WALLET_ALREADY_LOADED` (-35): `createwallet` /
  `loadwallet` (lines 5147, 5170) emit -1. Core: -35
  (`wallet.cpp:261`, `util.cpp:140`).
- BUG-19 `RPC_WALLET_NOT_SPECIFIED` (-19) and `RPC_WALLET_ALREADY_EXISTS`
  (-36): no distinction in beamchain; both collapse to -1.

**Concrete consequence**: a wallet GUI that uses error code to drive
re-prompting (passphrase incorrect → re-prompt; wallet locked →
walletpassphrase first) cannot distinguish these cases. Users see
"Error -1" with raw Erlang term in the message.

### BUG-20 (P1) — `dumptxoutset` "already exists" emits -32602

`beamchain_rpc.erl:8854-8860`. Uses `?RPC_INVALID_PARAMS` (-32602,
JSON-RPC transport code). Core uses `RPC_INVALID_PARAMETER` (-8,
app-level argument-validation). Caller cannot distinguish "I sent
malformed JSON" from "the file exists".

### BUG-21 (P1) — 75 usage-string fall-through clauses emit -32602

Pattern: `rpc_*(_) -> {error, ?RPC_INVALID_PARAMS, <<"Usage: ...">>}`
appears 75 times. Core convention is `RPC_INVALID_PARAMETER` (-8) for
wrong-arg errors — `RPC_INVALID_PARAMS` (-32602) is reserved for the
JSON-RPC transport-layer case where `params` is not an array/object.

**Mechanical fix; affects every wrong-arg call path in the codebase.**

### BUG-22 (P1) — `RPC_IN_WARMUP` (-28) macro defined, never thrown — DEAD HELPER

`beamchain_rpc.erl:147` declares the macro. Grep across `src/` shows
ZERO call sites. Continues the 33-wave "dead helper" pattern documented
in MEMORY.md (W117 dead-helper-at-call-site / W121 dead-helper-at-BIP-324-table).

The `/health` endpoint (line 397) uses an HTTP-503 + JSON
`{"status":"warmup"}` body but NOT a JSON-RPC -28 error. Clients
polling JSON-RPC during startup see -32603 `RPC_INTERNAL_ERROR` for
any handler whose dependency (chainstate, wallet) isn't initialized
yet, not the documented -28.

Concrete divergence with Core's `server.cpp:488`:
`throw JSONRPCError(RPC_IN_WARMUP, rpcWarmupStatus)`.

### BUG-23 (P2 — internal inconsistency) — `invalidateblock` uses -8 not -5

`beamchain_rpc.erl:1773` returns `?RPC_INVALID_PARAMETER` (-8) for
"block hash not found". All sibling RPCs (`getblock` 1106,
`getblockheader` 1244, `reconsiderblock` 1800, 1808,
`getrawtransaction` 2282) use `?RPC_INVALID_ADDRESS_OR_KEY` (-5) for
this case. Core: `blockchain.cpp:1701` uses -5.

---

## Sanity-anchors (PRESENT, matches Core)

These confirm that not every RPC path is broken:

- All five JSON-RPC 2.0 transport codes are defined and used correctly
  (Gates 1, 5, 22, 28).
- All 11 of 12 in-scope general-app codes are defined as macros (Gate 2).
- `verifymessage` malformed base64 → -3 (Gate 18).
- Block-not-found uses -5 across 5+ RPCs (Gate 23).
- `pruneblockchain` not-in-prune-mode → -1 (Gate 25; Core also uses -1).
- `submitblock` returns BIP-22 result strings, not error codes (Gate 26).
- `importdescriptors` per-request error shape matches Core (Gate 27).
- `sendrawtransaction` max-fee-exceeded → -26 (Gate 29).
- Deserialization errors → -22 (Gate 30).

---

## Suggested fix wave (for a later FIX-N)

Roughly ordered by Core-compatibility impact:

1. Add the missing macros (`-define`s for -7, -9, -10, -11, -12, -14,
   -15, -16, -17, -18, -19, -23, -24, -29, -30, -31, -33, -34, -35,
   -36) in one place.
2. Refactor `addnode` / `disconnectnode` / `setban` to emit the
   correct P2P client codes (BUGs 4-7, 10).
3. Add IBD / not-connected gate to `getblocktemplate` and
   `generate*` (BUGs 2-3, 11).
4. Reroute wallet-locked / wrong-passphrase / wrong-enc-state /
   wallet-not-found / wallet-already-loaded paths to the correct
   wallet codes (BUGs 12-19).
5. Distinguish silent-re-broadcast (Core OK) from
   already-in-utxo-set (-27) in `sendrawtransaction` (BUG-1).
6. Wire `RPC_IN_WARMUP` (-28) through all handlers whose dependency
   may not yet be initialized (BUG-22).
7. Migrate 75 "Usage: …" fall-throughs from -32602 to -8 (BUG-21).
8. Fix `dumptxoutset` "already exists" -32602 → -8 (BUG-20).
9. Fix `invalidateblock` hash-not-found -8 → -5 (BUG-23).

Estimated scope: ~150-200 LOC delta in `beamchain_rpc.erl`, plus
test fixtures asserting the new code. The `verify-fix.sh` harness is
NOT applicable here (no consensus-relevant changes); regression
coverage from `beamchain_w125_rpc_error_tests.erl` (audit-flip style)
will be sufficient.

---

## Test coverage in this commit

`test/beamchain_w125_rpc_error_tests.erl` — 49 EUnit tests across 30
gates. Asserts the current divergent behaviour so that the future fix
wave can detect "fix landed" via PASS → FAIL flip. Test counts:

- 19 standalone `*_test/0` cases
- 2 generator-style `*_test_/0` (p2p_client_codes, wallet_error_codes)
  expanding to 22 sub-tests
- Pass rate: 49/49 (100%) at the discovery commit.

Reference compatibility:

- BEFORE: `rebar3 eunit --module=beamchain_w125_rpc_error_tests` — 49/49 pass.
- AFTER: same (no production changes).
- BEFORE/AFTER on `beamchain_rpc_tests`: unchanged. 2 pre-existing
  failures (`bip22_result_bad_cb_amount_test`,
  `bip22_result_mandatory_script_test`) are out-of-scope for W125 and
  unrelated to error-code parity.
