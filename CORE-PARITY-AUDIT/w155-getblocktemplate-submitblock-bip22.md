# W155 — getblocktemplate + submitblock + BIP-22/BIP-23 (beamchain)

**Wave:** W155 — `getblocktemplate` (template + proposal modes),
`submitblock` (BIP-22 result strings), `submitheader`,
`prioritisetransaction`, `getprioritisedtransactions`,
`getblockfromtemplate`, `getmininginfo`, `UpdateUncommittedBlockStructures`
(coinbase scriptWitness auto-fix-up), BIP-22 request fields
(`mode`, `data`, `capabilities`, `rules`, `longpollid`), BIP-23 response
fields (`mutable`, `noncerange`, `mintime`, `curtime`, `sigoplimit`,
`sizelimit`, `weightlimit`, `target`, `coinbaseaux`, `coinbasevalue`,
`coinbasetxn`, `default_witness_commitment`, `signet_challenge`),
per-tx fields (`data`, `txid`, `hash`, `depends`, `fee`, `sigops`,
`weight`), BIP22ValidationResult string set, long-poll
`nTransactionsUpdated` counter.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/rpc/mining.cpp:660-1035` — `getblocktemplate`
  RPC: `mode` parameter parse (713-727), `proposal` branch
  (730-752, calls `TestBlockValidity` + returns `duplicate` /
  `duplicate-invalid` / `duplicate-inconclusive`), client `rules` array
  parse (754-760, REQUIRED set check at 850-857), connection-count
  + IBD gates (766-775), long-poll loop (783-845, BIP-22
  `nTransactionsUpdated` counter check + 1-minute / 10-second cadence),
  template caching with 5-second cool-down (860-884), `UpdateTime`
  call (889), `gbtstatus` per-deployment `signalling` / `locked_in` /
  `active` walk (965-991), result fields (947-1031).
- `bitcoin-core/src/rpc/mining.cpp:1056-1106` — `submitblock`:
  `UpdateUncommittedBlockStructures` auto-fix-up at 1086-1089,
  `submitblock_StateCatcher` for sync state capture (1093-1096),
  `BIP22ValidationResult` mapping (1103).
- `bitcoin-core/src/rpc/mining.cpp:1108-1146` — `submitheader`:
  parent-must-be-known requirement (1131-1134), `ProcessNewBlockHeaders`
  + state-string-based RPC error (1137-1143).
- `bitcoin-core/src/rpc/mining.cpp:502-543` — `prioritisetransaction`:
  `priority_delta` (always 0 in modern Core), `fee_delta` (sats),
  `mempool.PrioritiseTransaction()` call.
- `bitcoin-core/src/rpc/mining.cpp:560-615` — `getprioritisedtransactions`:
  enumerates the mempool's `mapDeltas` map; `fee_delta` per txid.
- `bitcoin-core/src/rpc/mining.cpp:416-498` — `getmininginfo`:
  `signet_challenge` field on signet only, `next` block sub-object
  (height/bits/difficulty/target), `currentblockweight` /
  `currentblocktx` (omitted if no block ever assembled).
- `bitcoin-core/src/validation.cpp:3985-3995` —
  `UpdateUncommittedBlockStructures(CBlock&, const CBlockIndex*)`:
  inserts a 32-byte zero `scriptWitness` into the coinbase input when
  SegWit is active AND a commitment is present AND the coinbase
  doesn't already carry a witness — submitblock can accept blocks
  built by miners that lack the nonce.
- `bitcoin-core/src/rpc/mining.cpp:177-207` —
  `BIP22ValidationResult(BlockValidationState)`: maps reject reasons
  to canonical hyphenated strings; success returns `null` (empty
  `UniValue`).
- `bitcoin-core/src/node/miner.cpp:36-47` — `GetMinimumTime` (BIP-94
  timewarp adjusted; used for `mintime` GBT field — see W154 BUG-6).
- BIP-22 — `mode` defaults to "template"; "proposal" parses `data`
  hex-block, returns BIP-22 string. `capabilities` client-side
  array (optional); server-side `capabilities` array must include
  "proposal" per BIP-23 §3.
- BIP-23 — `target`, `mutable[]`, `noncerange`, `mintime`,
  `coinbaseaux`, `coinbasevalue` (JSON NUMBER; satoshis),
  `coinbasetxn` (alternate coinbase template), `longpollid`,
  `sizelimit`, `sigoplimit`, `weightlimit`, `expires`.
- BIP-141 — `default_witness_commitment` (BIP-141 §coinbase),
  emitted when SegWit deployment is active OR LOCKED_IN.

**Files audited**
- `src/beamchain_rpc.erl:3684-3718` — `rpc_getmininginfo/0`.
- `src/beamchain_rpc.erl:3720-3739` — `rpc_getblocktemplate/1`.
- `src/beamchain_rpc.erl:3741-3808` — `bip22_result/1` (atom →
  BIP-22 string mapping, ~30 entries).
- `src/beamchain_rpc.erl:3810-3834` — `rpc_submitblock/1`,
  `is_block_submission_paused/0` gate (line 196-206).
- `src/beamchain_rpc.erl:702-704` — `handle_method` dispatch for
  `getmininginfo`, `getblocktemplate`, `submitblock`. NO
  `submitheader` / `prioritisetransaction` /
  `getprioritisedtransactions` / `getblockfromtemplate` entries.
- `src/beamchain_rpc.erl:817-823` — `rpc_help_list` "Generating"
  section.
- `src/beamchain_miner.erl:85-91` — `create_block_template/{1,2}`
  API; `Opts` accepted but ignored (W154 BUG-1 cross-cite).
- `src/beamchain_miner.erl:128-143` — gen_server `handle_call`
  for `create_template` and `submit_block`.
- `src/beamchain_miner.erl:183-352` — `do_create_template/3`
  (template assembly).
- `src/beamchain_miner.erl:269-345` — BIP-22 response field
  construction: capabilities, rules, vbavailable, vbrequired,
  longpollid, mintime, mutable, noncerange, sigoplimit, sizelimit,
  weightlimit, curtime, bits, height, default_witness_commitment.
- `src/beamchain_miner.erl:452-486` — `format_tx_entries`
  (per-tx GBT entry: data/txid/hash/fee/sigops/weight/depends).
- `src/beamchain_miner.erl:377-415` —
  `build_gbt_rules_and_vbavailable/2`.
- `src/beamchain_miner.erl:512-578` — `do_submit_block/1`.
- `src/beamchain_chainstate.erl:251-260, 1258-1299, 1304-1323` —
  `submit_block/1` + `is_block_known/1` + side-branch path.
- `include/beamchain_protocol.hrl:9-12` — block-limit constants
  (`MAX_BLOCK_WEIGHT=4_000_000`, `MAX_BLOCK_SIGOPS_COST=80_000`,
  `MAX_BLOCK_SERIALIZED_SIZE=4_000_000`, `WITNESS_SCALE_FACTOR=4`).
- `src/beamchain_chain_params.erl:239-275` — signet params:
  NO `signet_challenge` field; NO `signet_blocks` boolean.
- `src/beamchain_mempool.erl:233-326` — no
  `GetTransactionsUpdated`-equivalent counter; `get_info/0` returns
  size/bytes/min_fee but no `nTransactionsUpdated` value.

---

## Gate matrix (34 sub-gates / 15 behaviours)

Legend: PASS = parity with Core; PARTIAL = wired but deviates;
**BUG-N** = open finding.

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | `mode` parameter parse | G1: read `"mode"` from request obj | **BUG-1 (P0-CDIV)** — `rpc_getblocktemplate/1` (`rpc.erl:3722-3727`) never reads `<<"mode">>`; only `<<"coinbasescript">>`. The `mode="proposal"` branch is unreachable; BIP-23 proposal validation is fundamentally not wired |
| 1 | … | G2: default `mode="template"` when absent | PASS (implicitly — only template mode is supported) |
| 1 | … | G3: reject unknown `mode` with `RPC_INVALID_PARAMETER` | **BUG-1 cross-cite** (`mode="floob"` silently accepted) |
| 2 | `mode="proposal"` (BIP-22/23) | G4: decode `data` hex to CBlock + `TestBlockValidity` | **BUG-2 (P0-CDIV)** — entire proposal branch absent |
| 2 | … | G5: `duplicate` / `duplicate-invalid` / `duplicate-inconclusive` return for known blocks | **BUG-2 cross-cite** |
| 3 | `rules` client array | G6: parse `rules` from request obj | **BUG-3 (P1)** — request `<<"rules">>` is read NOWHERE; `setClientRules` analogue absent |
| 3 | … | G7: enforce `"segwit"` must be in client rules | **BUG-3 cross-cite** — Core throws `RPC_INVALID_PARAMETER` if missing; beamchain happily returns the segwit template anyway |
| 3 | … | G8: enforce `"signet"` must be in client rules on signet network | **BUG-3 cross-cite** |
| 4 | `longpollid` request handling | G9: parse `longpollid` from request and block until tip changes / mempool moves | **BUG-4 (P1)** — request `<<"longpollid">>` never read; beamchain returns immediately regardless. The BIP-22 long-poll loop is entirely absent |
| 4 | … | G10: format `tip_hash_hex + nTransactionsUpdated` | PARTIAL — emitted value uses `<<TipHashHex/binary, MempoolCount/binary>>` (`miner.erl:289-292`) but `MempoolCount = maps:get(size, MempoolInfo, 0)` is the CURRENT mempool size, not a monotonic counter; on tx-eviction the counter goes BACKWARDS and longpoll equality checks fire spurious wake-ups. See **BUG-5** |
| 4 | … | G11: monotonic `nTransactionsUpdated` counter (Core: `CTxMemPool::nTransactionsUpdated` increments on every add) | **BUG-5 (P1)** — no monotonic counter in `beamchain_mempool`; size-as-proxy regresses on eviction |
| 5 | `capabilities` server-side | G12: array contains `"proposal"` | PASS (`miner.erl:273`) |
| 5 | … | G13: array contains `"coinbasetxn"` when BIP-23 coinbasetxn mode is supported | **BUG-6 (P2)** — beamchain emits only `["proposal"]`; doesn't advertise `coinbasetxn` (BIP-23 §3 alternate-coinbase mode). Cross-impl divergence — Core advertises both when supported |
| 6 | per-tx `sigops` field semantics | G14: cost-correct sigops via `GetTransactionSigOpCost(tx, view, flags)` | **BUG-7 (P0-CDIV)** SECOND instance of W154 BUG-8 in the GBT layer — `format_tx_entries/4` at `miner.erl:480` calls `estimate_sigops/1` which counts only `script_sig`/`script_pubkey` legacy sigops × `WITNESS_SCALE_FACTOR`. Misses P2SH redeemScript sigops + ALL witness sigops. Per-tx GBT field misreports to pool software, which may rely on `sigops` for its own block-fill bookkeeping |
| 6 | … | G15: pre-segwit divide by `WITNESS_SCALE_FACTOR` | **BUG-8 (P1)** — Core (`mining.cpp:928-932`) divides by 4 for pre-segwit chains; beamchain emits the cost-units value unconditionally. On legacy (pre-segwit) chains the field reads 4× Core's number. No mainnet/testnet/regtest impact today (all activated), but signet variants without segwit + cross-impl diff harnesses see different values |
| 7 | `sigoplimit` semantics | G16: emit `MAX_BLOCK_SIGOPS_COST=80_000` for segwit; `/4 = 20_000` pre-segwit | **BUG-9 (P1)** — `miner.erl:316` emits `?MAX_BLOCK_SIGOPS_COST` (80_000) unconditionally; no pre-segwit divisor; pre-segwit clients double-count by 4× |
| 7 | … | G17: `sizelimit = MAX_BLOCK_SERIALIZED_SIZE = 4_000_000` post-segwit; `1_000_000` pre-segwit | PARTIAL — beamchain emits 4_000_000 unconditionally (`miner.erl:317`); pre-segwit clients see wrong limit; **BUG-9 cross-cite** |
| 7 | … | G18: `weightlimit` emitted only post-segwit | PASS (always-emitted is acceptable post-activation; same shape as `sizelimit`/`sigoplimit` bug class) |
| 8 | `submitblock` `UpdateUncommittedBlockStructures` auto-fix-up | G19: when SegWit active AND commitment present AND coinbase lacks witness, insert 32-zero `scriptWitness` | **BUG-10 (P0-CDIV)** — beamchain `do_submit_block/1` does NOT call any equivalent helper. A miner / pool that submits a block built without injecting the 32-byte zero witness nonce on the coinbase input fails Core's `CheckWitnessMalleation`. Core's submitblock auto-repairs this before `ProcessNewBlock`; beamchain rejects with `{error, bad_witness_nonce}` → BIP-22 `"bad-witness-merkle-match"`. Pool software written for Core silently breaks |
| 9 | `submitblock` duplicate handling | G20: return BIP-22 `"duplicate"` for a re-submitted block already in `BLOCK_VALID_SCRIPTS` | **BUG-11 (P1)** — `chainstate:submit_block/1` returns `{ok, side_branch, _}` for any already-known block (`chainstate.erl:1264-1268, is_block_known/1`). Miner's `do_submit_block` maps that to `{error, inconclusive}` → BIP-22 `"inconclusive"`. Core distinguishes `duplicate`, `duplicate-invalid`, `duplicate-inconclusive` based on `BLOCK_VALID_SCRIPTS` / `BLOCK_FAILED_VALID` / partial status. beamchain returns `"inconclusive"` for ALL duplicates regardless of prior validity — pool software using duplicate detection to throttle re-submissions can't distinguish "I already won this block" from "this block is a side-branch reorg candidate" |
| 9 | … | G21: `duplicate-invalid` for permanently rejected duplicates | **BUG-11 cross-cite** |
| 10 | `submitheader` RPC | G22: dispatched in handle_method | **BUG-12 (P1)** — no `submitheader` case in handle_method (`rpc.erl:702-708`); RPC dispatch returns method-not-found. Mining pools using `submitheader` for partial-share validation get a hard error |
| 10 | … | G23: parent-must-be-known requirement before accepting header | N/A (handler absent) |
| 11 | `prioritisetransaction` RPC | G24: dispatched in handle_method | **BUG-13 (P1)** — no `prioritisetransaction` case in handle_method; pool software that boosts/depriorities specific txs into the next template silently fails |
| 11 | … | G25: `priority_delta` parsed (ignored in modern Core but required-for-BIP-22-compat) | N/A (handler absent) |
| 11 | … | G26: `fee_delta` parsed (sat) and applied to `mapDeltas` | N/A (handler absent) |
| 12 | `getprioritisedtransactions` RPC | G27: dispatched in handle_method | **BUG-14 (P2)** — Core hidden RPC `getprioritisedtransactions` absent; debugging tools that inspect the delta map can't introspect beamchain mempool prioritisation state |
| 13 | `getblockfromtemplate` RPC (BIP-23) | G28: assemble a `CBlock` from a returned template and re-serialise as hex | **BUG-15 (P2)** — Core's `getblockfromtemplate` (`rpc/mining.cpp`, BIP-23) absent from beamchain; pools that prefer the rebuild-from-template flow can't use beamchain |
| 14 | `getmininginfo` fields | G29: `signet_challenge` emitted on signet network | **BUG-16 (P1)** — `rpc_getmininginfo/0` (`rpc.erl:3684-3718`) does NOT branch on network type and never emits `signet_challenge`. Cross-cite: `beamchain_chain_params.erl:239-275`'s signet params block has NO `signet_challenge` / `signet_blocks` field at all, so the data isn't even there to emit |
| 14 | … | G30: `networkhashps` non-zero value (computed over recent window) | **BUG-17 (P1)** — `rpc.erl:3708` emits a literal `0` for `networkhashps` in getmininginfo; the actual `rpc_getnetworkhashps/1` (line 9249) DOES compute a value, but it's never invoked from getmininginfo. Two-pipeline-guard: same impl has the correct helper and the buggy field-emission, never wired together. **18th distinct fleet instance** |
| 14 | … | G31: `currentblockweight` omitted when no block ever assembled | **BUG-18 (P1)** — beamchain emits `currentblocksize=0`, `currentblockweight=0`, `currentblocktx=0` unconditionally (`rpc.erl:3701-3703`). Core OMITS these fields entirely when no block has been assembled in the session (`CBlockAssembler::m_last_block_weight` is `std::optional`). Pool monitoring scrapers that assume `currentblockweight=0` means "0 weight" rather than "never assembled" misreport |
| 15 | `getblocktemplate` pre-call gates | G32: refuse on IBD with `RPC_CLIENT_IN_INITIAL_DOWNLOAD` (test networks excluded) | **BUG-19 (P1)** — `rpc_getblocktemplate/1` (`rpc.erl:3720-3739`) does NOT check `beamchain_chainstate:is_synced/0`. During IBD a pool gets a template built from a partial chain; mined blocks would orphan |
| 15 | … | G33: refuse on zero connections (mainnet only) with `RPC_CLIENT_NOT_CONNECTED` | **BUG-19 cross-cite** — no `peer_manager` connection-count check |
| 15 | … | G34: `coinbasescript` default falls back to OP_TRUE on mainnet → anyone-can-spend reward (W154 BUG-15 carry-forward) | **BUG-20 (P1)** — carry-forward of W154 BUG-15 (funds-loss-risk pattern); the W154 fleet pattern entry "funds-burn" applies here too. Despite W154 cataloguing, the line at `rpc.erl:3724-3726` still emits `DefaultScript = <<16#51>>` (OP_TRUE) when caller omits `coinbasescript`. On mainnet, a pool that doesn't pass `coinbasescript` mines a block whose 6.25 BTC reward goes to OP_TRUE. **Re-anchoring count: 2 weeks open (W154 → W155)** |

---

## BUG-1 (P0-CDIV) — `mode` parameter never read; `mode="proposal"` silently treated as `mode="template"`

**Severity:** P0-CDIV. Bitcoin Core's `getblocktemplate`
(`rpc/mining.cpp:713-727`) reads the `mode` field from the request
object FIRST:

```cpp
std::string strMode = "template";
const UniValue& modeval = oparam.find_value("mode");
if (modeval.isStr())
    strMode = modeval.get_str();
else if (modeval.isNull())
    /* Do nothing */
else
    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");
```

Then dispatches: `mode="proposal"` → BIP-23 proposal-validate branch
(line 730-752, decodes `data` hex, runs `TestBlockValidity`, returns
BIP-22 string); `mode="template"` → continue to template construction;
anything else → `RPC_INVALID_PARAMETER`.

beamchain's `rpc_getblocktemplate/1` (`rpc.erl:3720-3739`):

```erlang
rpc_getblocktemplate([TemplateRequest]) when is_map(TemplateRequest) ->
    DefaultScript = <<16#51>>,
    CoinbaseScript = maps:get(<<"coinbasescript">>, TemplateRequest,
                               DefaultScript),
    case beamchain_miner:create_block_template(CoinbaseScript) of
        ...
```

reads ONLY the non-standard `coinbasescript` field. `mode`, `data`,
`rules`, `longpollid`, and `capabilities` are all silently dropped.
Calls like `{"mode": "proposal", "data": "<hex-block>"}` silently
return a fresh template instead of validating the supplied block.

**File:** `src/beamchain_rpc.erl:3720-3739`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:713-752`.

**Impact:**
- Pool software using BIP-23 proposal-mode to pre-validate a block
  before mining gets back a template instead of a validation result.
  The proposal is silently lost.
- A bogus `mode="floob"` value is silently accepted as `template`;
  the client error path is unreachable.
- Cross-impl divergence: every Core-compatible pool harness sends
  `{"mode": "proposal", ...}` first as a safety check; beamchain
  bypasses it.

---

## BUG-2 (P0-CDIV) — `mode="proposal"` BIP-23 branch entirely absent

**Severity:** P0-CDIV. Bitcoin Core's proposal branch
(`rpc/mining.cpp:730-752`):

```cpp
if (strMode == "proposal") {
    const UniValue& dataval = oparam.find_value("data");
    if (!dataval.isStr())
        throw JSONRPCError(RPC_TYPE_ERROR, "Missing data String key for proposal");

    CBlock block;
    if (!DecodeHexBlk(block, dataval.get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");

    uint256 hash = block.GetHash();
    LOCK(cs_main);
    const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(hash);
    if (pindex) {
        if (pindex->IsValid(BLOCK_VALID_SCRIPTS))
            return "duplicate";
        if (pindex->nStatus & BLOCK_FAILED_VALID)
            return "duplicate-invalid";
        return "duplicate-inconclusive";
    }
    return BIP22ValidationResult(TestBlockValidity(chainman.ActiveChainstate(),
                                                    block,
                                                    /*check_pow=*/false,
                                                    /*check_merkle_root=*/true));
}
```

is the canonical BIP-23 entry point for pool software that wants to
ask the node "would this assembled block be accepted?" without
broadcasting it. Returns BIP-22 strings (`null` for accept,
`bad-cb-amount` etc. for reject, plus `duplicate`/`duplicate-invalid`/
`duplicate-inconclusive` for already-known blocks).

beamchain's GBT handler does not parse `mode`, never decodes a
`data` field, never calls a `test_block_validity` equivalent.
beamchain's `do_submit_block/1` (`miner.erl:512-578`) does run
`check_block`, but submit ALSO writes to the block index and
broadcasts on success — proposal mode must NOT mutate state.

**File:** `src/beamchain_rpc.erl:3720-3739` (no proposal branch);
`src/beamchain_miner.erl:512-578` (submit_block mutates state, not a
proposal-mode substitute); `src/beamchain_validation.erl::check_block`
(could be wrapped into a side-effect-free proposal helper, but isn't).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:730-752`.

**Impact:**
- BIP-23 proposal mode is fundamentally non-functional on beamchain.
  Pools that pre-validate cannot use beamchain.
- Combined with **BUG-10** (no submitblock auto-fix-up), a pool that
  builds a near-Core block can't even smoke-test it via proposal mode
  before submit — every test costs a submit (mutates state).

---

## BUG-3 (P1) — Client `rules` array never parsed; segwit/signet enforcement gate missing

**Severity:** P1. Bitcoin Core's GBT (`rpc/mining.cpp:754-760`) parses
the `rules` client array and enforces it:

```cpp
const UniValue& aClientRules = oparam.find_value("rules");
if (aClientRules.isArray()) {
    for (unsigned int i = 0; i < aClientRules.size(); ++i) {
        const UniValue& v = aClientRules[i];
        setClientRules.insert(v.get_str());
    }
}
...
// GBT must be called with 'signet' set in the rules for signet chains
if (consensusParams.signet_blocks && !setClientRules.contains("signet")) {
    throw JSONRPCError(RPC_INVALID_PARAMETER,
        "getblocktemplate must be called with the signet rule set ...");
}
// GBT must be called with 'segwit' set in the rules
if (!setClientRules.contains("segwit")) {
    throw JSONRPCError(RPC_INVALID_PARAMETER,
        "getblocktemplate must be called with the segwit rule set ...");
}
```

Two reasons for the gate:
1. A SegWit-naïve pool that doesn't understand `default_witness_commitment`
   would mine an invalid (no-commitment) block. Core refuses to serve
   such a pool until they declare `"segwit"` understanding.
2. A signet pool must explicitly opt into signet's
   anyone-can-spend-block-script semantics.

beamchain's `rpc_getblocktemplate/1` (`rpc.erl:3720-3739`) NEVER reads
`<<"rules">>`. There is no `setClientRules`, no segwit-required
gate, no signet gate. The template is always returned, regardless of
what the client declared.

**Failure mode:**
- A legacy mining harness that pre-dates BIP-141 calls `getblocktemplate`
  with `rules=[]` on beamchain, gets a template with
  `default_witness_commitment` it doesn't know to use, mines, submits,
  the block is rejected with `bad-witness-merkle-match`. The pool's
  share-validation pipeline goes belly-up.
- A signet harness without explicit `"signet"` in rules gets a normal
  template and tries to mine without the anyone-can-spend block
  challenge — submit will be rejected on signet networks.

**File:** `src/beamchain_rpc.erl:3720-3739`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:754-760, 850-857`.

**Impact:** silent acceptance of pool software that lacks the
declared-rule contract; mismatched template/miner behaviour leads to
rejected blocks at submit; signet pools at risk of opt-in oversight.

---

## BUG-4 (P1) — `longpollid` parameter never read; BIP-22 long-poll loop completely absent

**Severity:** P1. Bitcoin Core's GBT (`rpc/mining.cpp:783-845`)
implements the BIP-22 long-poll: if the client sends a
`longpollid` field, the server blocks until EITHER the tip changes
OR the mempool transactions-updated counter advances (with a
1-minute initial poll then 10-second intervals). This is the
canonical pool-software efficiency primitive — pools call
`getblocktemplate?longpollid=<prev>` and the server returns ONLY
when there's a new template to mine.

beamchain emits a `<<"longpollid">>` field in the response
(`miner.erl:310`) but the request-side `<<"longpollid">>` is NEVER
read. Every call returns immediately. A pool that uses long-polling
hammers beamchain with requests at whatever its polling interval is
(typically 1-5 seconds) instead of the BIP-22 model of "1 long-poll
per template change".

**File:** `src/beamchain_rpc.erl:3720-3739` (no longpollid parse);
`src/beamchain_miner.erl:284-310` (emits longpollid value but
nothing waits on it).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:783-845`.

**Impact:** pool-bandwidth burn (every poll fetches a full template
even when nothing changed); pools see latency between tip-flip and
template-refresh equal to their polling interval rather than the
sub-second long-poll wake-up. Production pools on Core can be pointed
at beamchain but the RPC traffic is ~100× what they expect.

---

## BUG-5 (P1) — `longpollid` "tx counter" portion uses mempool SIZE as proxy; regresses on eviction (non-monotonic)

**Severity:** P1. `miner.erl:289-292`:

```erlang
MempoolInfo = beamchain_mempool:get_info(),
MempoolCount = maps:get(size, MempoolInfo, 0),
LongPollId = <<(hash_to_hex(TipHash))/binary,
               (integer_to_binary(MempoolCount))/binary>>,
```

The second segment is the mempool's CURRENT SIZE, not Core's
`CTxMemPool::nTransactionsUpdated` monotonic counter
(`txmempool.h:404-405`). The Core counter increments on
`AddUnchecked` and `RemoveUnchecked` (both); it never resets and
never decreases. beamchain's size-based proxy DECREASES on every
eviction or block-confirmation removal.

**Failure modes** (assuming a long-poll loop WERE wired — see BUG-4):
- Tx added → counter advances → longpoll wakes correctly.
- Tx evicted → counter REGRESSES → if a pool's stored longpollid value
  was at the higher count, the equality check fails forever, the
  pool thinks "the counter didn't change" even though it did move
  (downward). The wake-up condition never fires.
- Block mined removes 2000 txs → counter drops by 2000 → all
  long-polls with previously-stored longpollid values get spurious
  wake-ups (since the new value != stored value).

Combined with BUG-4 (loop not even running), this is currently
inert; but the field-emission shape is wrong and any future wiring
of the loop would inherit a broken counter.

**File:** `src/beamchain_miner.erl:284-292`;
`src/beamchain_mempool.erl:293-295` (`get_info/0` returns `size`
but no monotonic counter).

**Core ref:**
`bitcoin-core/src/kernel/mempool_persist.cpp` /
`bitcoin-core/src/txmempool.cpp::nTransactionsUpdated`
(monotonic), `bitcoin-core/src/rpc/mining.cpp:870`
(`mempool.GetTransactionsUpdated()`).

**Impact:** future long-poll wiring would have to first add the
counter; today the field exists but its value is wrong. Pool software
that parses out the second segment for diagnostic logging sees a value
that drifts oddly relative to expectations.

---

## BUG-6 (P2) — `capabilities` server array missing `"coinbasetxn"`

**Severity:** P2. BIP-23 §3 defines two server-side capability strings:
- `"proposal"` — supports `mode="proposal"`
- `"coinbasetxn"` — supports `coinbasetxn` (alternate fully-built
  coinbase template) instead of `coinbasevalue` (numeric)

beamchain (`miner.erl:273`) emits `Capabilities = [<<"proposal">>]`
— but as BUG-2 shows, proposal mode isn't actually wired. So the
capabilities array is currently misleading on BOTH counts:
- claims `"proposal"` (unimplemented)
- doesn't claim `"coinbasetxn"` (also unimplemented; just unclaimed)

Core dynamically emits the array based on what is actually supported
(line 895 hard-codes `["proposal"]` because Core always supports it).
For beamchain, the honest emission is `[]` until proposal is wired.

**File:** `src/beamchain_miner.erl:272-273`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:895`; BIP-23 §3.

**Impact:** clients that branch on the advertised `capabilities`
array make wrong decisions (e.g., a Core-compatible pool sees
`"proposal"` in caps, decides to try proposal mode, gets back a
template — see BUG-1).

---

## BUG-7 (P0-CDIV) — per-tx `sigops` field undercounts (cross-cite W154 BUG-8); pool block-fill bookkeeping breaks

**Severity:** P0-CDIV. SECOND fleet instance of W154 BUG-8 in this
audit — the same `estimate_sigops/1` helper is used at TWO call
sites in `miner.erl`:
1. `select_transactions` (W154 BUG-8: block-fill greedy gate)
2. `format_tx_entries` per-tx GBT field (THIS bug)

`format_tx_entries/4` at `miner.erl:475-483`:

```erlang
TxEntry = #{
    <<"data">> => TxHex,
    <<"txid">> => hash_to_hex(Txid),
    <<"hash">> => hash_to_hex(Wtxid),
    <<"fee">> => Entry#mempool_entry.fee,
    <<"sigops">> => estimate_sigops(Tx),  %% <-- BUG
    <<"weight">> => Entry#mempool_entry.weight,
    <<"depends">> => lists:usort(Depends)
},
```

`estimate_sigops/1` (`miner.erl:777-784`) counts only legacy sigops
in `script_sig` + `script_pubkey` × `WITNESS_SCALE_FACTOR`. P2SH
redeemScript sigops and witness sigops are missed.

Core (`rpc/mining.cpp:927-933`):
```cpp
int64_t nTxSigOps{tx_sigops.at(index_in_template)};
if (fPreSegWit) {
    CHECK_NONFATAL(nTxSigOps % WITNESS_SCALE_FACTOR == 0);
    nTxSigOps /= WITNESS_SCALE_FACTOR;
}
entry.pushKV("sigops", nTxSigOps);
```

uses the BlockTemplate's pre-computed `tx_sigops` array, which is
the COST-CORRECT value from `GetTransactionSigOpCost`. beamchain
returns wrong-by-design values.

**Failure modes for pool software** (which is the GBT consumer):
- A pool's own block-fill bookkeeping sums per-tx `sigops` to check
  against `sigoplimit`. With beamchain's undercount, the pool may
  think it has budget for more txs and over-fill; the produced block
  fails `bad-blk-sigops` at submit (cross-cite W154 BUG-8 same root
  cause; here exposed via the per-tx field).
- A pool that resorts the tx list by `(fee, sigops)` density makes
  wrong placement decisions because the per-tx sigops cell is wrong.

**File:** `src/beamchain_miner.erl:475-486` (this bug);
cross-cite `src/beamchain_miner.erl:777-784` (helper);
cross-cite `src/beamchain_validation.erl:924-940`
(cost-correct helper that's NOT used).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:927-933`.

**Impact:** P2SH-/segwit-heavy mempools yield templates whose per-tx
sigops summed equal much less than the actual cost; pool over-fills;
submit fails. Same root cause as W154 BUG-8 but a fresh exit
through GBT — counts as second distinct exposure.

---

## BUG-8 (P1) — Per-tx `sigops` and `sigoplimit` don't divide by `WITNESS_SCALE_FACTOR` pre-segwit

**Severity:** P1. Core emits per-tx `sigops` and global `sigoplimit`
in COST UNITS post-segwit, but in LEGACY UNITS pre-segwit (divided by
4). beamchain emits cost-units unconditionally.

`miner.erl:316`:
```erlang
<<"sigoplimit">> => ?MAX_BLOCK_SIGOPS_COST,  %% always 80000
```
Core (`rpc/mining.cpp:1007-1015`):
```cpp
int64_t nSigOpLimit = MAX_BLOCK_SIGOPS_COST;
int64_t nSizeLimit = MAX_BLOCK_SERIALIZED_SIZE;
if (fPreSegWit) {
    CHECK_NONFATAL(nSigOpLimit % WITNESS_SCALE_FACTOR == 0);
    nSigOpLimit /= WITNESS_SCALE_FACTOR;
    CHECK_NONFATAL(nSizeLimit % WITNESS_SCALE_FACTOR == 0);
    nSizeLimit /= WITNESS_SCALE_FACTOR;
}
result.pushKV("sigoplimit", nSigOpLimit);
result.pushKV("sizelimit", nSizeLimit);
```

For an active mainnet/testnet/testnet4/signet (all post-segwit-activation),
beamchain's behaviour is parity. For regtest WITHOUT segwit (a
contrived setup but possible via custom params), or for a future
softfork that introduces a pre-segwit-like phase, the divisor is
needed.

**File:** `src/beamchain_miner.erl:316-317`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1007-1015`.

**Impact:** clients on hypothetical pre-segwit chain configs see
limits 4× Core's; mining harnesses written against Core's pre-segwit
semantics over-fill blocks.

---

## BUG-9 (P1) — `sizelimit` emitted as 4_000_000 unconditionally

**Severity:** P1. Same shape as BUG-8 for the `sizelimit` field
(`miner.erl:317`). Core emits `MAX_BLOCK_SERIALIZED_SIZE/4 = 1_000_000`
pre-segwit; beamchain emits 4_000_000 always.

**File:** `src/beamchain_miner.erl:317`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1007-1016`.

**Impact:** identical to BUG-8.

---

## BUG-10 (P0-CDIV) — `submitblock` does NOT call `UpdateUncommittedBlockStructures`; pool blocks built without witness nonce are rejected

**Severity:** P0-CDIV. Bitcoin Core's `submitblock` (`rpc/mining.cpp:
1086-1089`) explicitly auto-repairs missing coinbase witness nonces
before validating:

```cpp
{
    LOCK(cs_main);
    const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock);
    if (pindex) {
        chainman.UpdateUncommittedBlockStructures(block, pindex);
    }
}
```

`UpdateUncommittedBlockStructures` (`validation.cpp:3985-3995`):

```cpp
void ChainstateManager::UpdateUncommittedBlockStructures(CBlock& block,
                                                          const CBlockIndex* pindexPrev) const
{
    int commitpos = GetWitnessCommitmentIndex(block);
    static const std::vector<unsigned char> nonce(32, 0x00);
    if (commitpos != NO_WITNESS_COMMITMENT
        && DeploymentActiveAfter(pindexPrev, *this, Consensus::DEPLOYMENT_SEGWIT)
        && !block.vtx[0]->HasWitness()) {
        CMutableTransaction tx(*block.vtx[0]);
        tx.vin[0].scriptWitness.stack.resize(1);
        tx.vin[0].scriptWitness.stack[0] = nonce;
        block.vtx[0] = MakeTransactionRef(std::move(tx));
    }
}
```

This is the canonical "pool built a block with the witness commitment
output but forgot to put the 32-zero nonce in the coinbase's
scriptWitness" auto-repair. Many pool implementations (stratum-v2
servers, GBT-driven private miners, sgminer/cgminer-style) historically
omitted the witness nonce and relied on the node to inject it.

beamchain's `do_submit_block/1` (`miner.erl:512-578`) does NOT have
any equivalent. The submitted block goes straight to `check_block`,
which calls `check_witness_commitment` (`validation.erl:151`), which
fails when the coinbase has the OP_RETURN witness commitment output
but no matching nonce → `bad_witness_nonce` → BIP-22
`bad-witness-merkle-match`.

**Cross-impact with BUG-2:** without proposal mode AND without
auto-fix-up, a pool can't pre-test a block they assembled without
the nonce. Every "did I get it right?" round trip costs a state
mutation.

**File:** `src/beamchain_miner.erl:512-578` (no auto-fix call);
`src/beamchain_validation.erl:151` (check_witness_commitment runs
without prior repair).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1086-1089`;
`bitcoin-core/src/validation.cpp:3985-3995`.

**Impact:** stratum-v2 / CGMiner / older-pool integrations that omit
the witness nonce get hard rejections from beamchain that Core would
silently fix. Cross-impl divergence on pool compatibility.

---

## BUG-11 (P1) — Duplicate-block submission returns `"inconclusive"` instead of `"duplicate"` / `"duplicate-invalid"` / `"duplicate-inconclusive"`

**Severity:** P1. Bitcoin Core's `getblocktemplate` proposal branch
distinguishes three duplicate states (`rpc/mining.cpp:742-748`):
- `"duplicate"` — already in BLOCK_VALID_SCRIPTS (fully validated)
- `"duplicate-invalid"` — already in BLOCK_FAILED_VALID
- `"duplicate-inconclusive"` — known but not fully validated

And `submitblock` (`rpc/mining.cpp:1097-1102`):
- `"duplicate"` returned via `!new_block && accepted` path
- `"inconclusive"` for `!sc->found` (state-catcher didn't see the
  block — typical of header-only / not-yet-connected)
- otherwise the BIP22ValidationResult of the connect

beamchain's chainstate (`chainstate.erl:1262-1268`):

```erlang
case is_block_known(BlockHash) of
    true ->
        %% Block was already accepted; no reorg evaluation needed —
        %% if it was going to flip the tip, that already happened.
        {ok, side_branch, State};
```

Returns `side_branch` for ANY already-known block, regardless of
whether it was previously fully validated, failed, or
header-only-stored. Miner (`miner.erl:551-564`) then maps to
`{error, inconclusive}` → BIP-22 `"inconclusive"`.

**Concrete failure scenarios:**
- Pool submits the same valid block twice (network race with another
  pool's submit): Core returns `"duplicate"`, beamchain returns
  `"inconclusive"`. Pool monitoring tooling can't tell "I won the
  block!" from "It's still being evaluated".
- Pool submits a known-invalid block (a re-test after fixing a bug):
  Core returns `"duplicate-invalid"`, beamchain returns
  `"inconclusive"`. Pool can't tell "this is the same broken block
  you tried last time" from "this might be valid".

**File:** `src/beamchain_chainstate.erl:1262-1268, 1315-1323`
(is_block_known doesn't differentiate validity status);
`src/beamchain_miner.erl:551-564, 803`
(bip22_result maps `duplicate -> "duplicate"` but the chainstate never
returns that atom).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:742-748, 1097-1102`.

**Impact:** pool diagnostic / orchestration tooling can't distinguish
race-condition duplicate from inconclusive side-branch from re-tested
invalid block. Three Core distinct states collapse into one beamchain
state.

---

## BUG-12 (P1) — `submitheader` RPC missing entirely

**Severity:** P1. Bitcoin Core's `submitheader`
(`rpc/mining.cpp:1108-1146`) accepts a hex-encoded block header,
requires the parent be known, calls `ProcessNewBlockHeaders`, returns
null on success or the reject reason on failure.

Used by:
- Mining pools doing partial-share validation (PoW check + chain
  attachment without full block download).
- Stratum-v2 job announcement validation.
- Diagnostic tooling that wants to feed Core a header for testing.

beamchain's `handle_method` (`rpc.erl:702-708`) has no
`submitheader` case. Calls return method-not-found.

**File:** `src/beamchain_rpc.erl:702-708` (no dispatch);
`src/beamchain_rpc.erl:817-823` (rpc_help "Generating" section
omits submitheader).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1108-1146`.

**Impact:** pool integrations using `submitheader` for partial-share
validation fail; debugging tools that feed a hex header to test
chain attachment can't do so.

---

## BUG-13 (P1) — `prioritisetransaction` RPC missing entirely

**Severity:** P1. Bitcoin Core's `prioritisetransaction`
(`rpc/mining.cpp:502-543`) takes `(txid, priority_delta, fee_delta)`
and applies the fee_delta to the mempool's `mapDeltas`. Used by:
- Mining pools that want to boost a tx into the next template
  (e.g., paid out-of-band by a customer).
- Mining pools that want to deprioritize a tx (negative fee_delta).
- Test harnesses simulating fee-bumping behaviour.

beamchain's `handle_method` has no `prioritisetransaction` case;
`beamchain_mempool` has no `mapDeltas` analogue and no
`prioritise/2` API.

**File:** `src/beamchain_rpc.erl:702-708` (no dispatch);
`src/beamchain_mempool.erl` (no priority-delta map).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:502-543`.

**Impact:** mining-pool integration; cannot boost/depriorities txs;
test harnesses simulating fee-bumping can't drive beamchain.

---

## BUG-14 (P2) — `getprioritisedtransactions` RPC missing

**Severity:** P2. Bitcoin Core's hidden RPC
`getprioritisedtransactions` (`rpc/mining.cpp:560-615`) enumerates
the mempool's prioritisation deltas; debugging tool for operators.

beamchain has no equivalent.

**File:** `src/beamchain_rpc.erl:702-708`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:560-615`.

**Impact:** operator-debugging gap; cosmetic since
`prioritisetransaction` itself is missing (BUG-13).

---

## BUG-15 (P2) — `getblockfromtemplate` RPC missing (BIP-23)

**Severity:** P2. BIP-23 §getblockfromtemplate is the
"rebuild-a-block-from-a-template" round-trip helper. Core implements
it; beamchain does not.

**File:** `src/beamchain_rpc.erl:702-708`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp`.

**Impact:** pools that prefer the BIP-23 rebuild flow cannot use
beamchain; minor (most pools use GBT + custom assembly + submitblock).

---

## BUG-16 (P1) — `getmininginfo` does not emit `signet_challenge` on signet; signet params have no challenge field at all

**Severity:** P1. Bitcoin Core's `getmininginfo` (`rpc/mining.cpp:489-493`):

```cpp
if (chainman.GetParams().GetChainType() == ChainType::SIGNET) {
    const std::vector<uint8_t>& signet_challenge =
        chainman.GetConsensus().signet_challenge;
    obj.pushKV("signet_challenge", HexStr(signet_challenge));
}
```

emits the signet's anyone-can-spend challenge script (the block-script
that authorises miners) so pool software can construct valid signet
blocks.

beamchain's `rpc_getmininginfo/0` (`rpc.erl:3684-3718`) does not
branch on network type; `signet_challenge` is never in the output.
**Worse**, `beamchain_chain_params.erl:239-275`'s signet params block
has NO `signet_challenge` field at all — the data isn't even stored,
so even adding the emission would require chainparams plumbing.

GBT also omits the field (Core emits at `rpc/mining.cpp:1024-1026`).

**File:** `src/beamchain_rpc.erl:3684-3718` (getmininginfo no emit);
`src/beamchain_miner.erl:300-345` (GBT response, no signet_challenge);
`src/beamchain_chain_params.erl:239-275` (no
signet_challenge / signet_blocks fields).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:489-493, 1024-1026`;
`bitcoin-core/src/kernel/chainparams.cpp::SignetParams`.

**Impact:** signet pools cannot fetch the challenge script from the
node; they must hardcode it (default-signet challenge is well-known,
custom signets break). Cross-impl divergence on signet support.

---

## BUG-17 (P1) — `getmininginfo.networkhashps` hard-coded to 0; helper exists but is never wired

**Severity:** P1 ("two-pipeline guard" subtype — 18th distinct
fleet instance). `rpc_getmininginfo/0` (`rpc.erl:3708`):

```erlang
<<"networkhashps">> => 0,
```

emits a literal zero. But the impl HAS the correct helper at
`rpc.erl:9249-9277` (`rpc_getnetworkhashps/1`) which uses the
canonical Core-style "last N blocks, compute hashes-per-second from
chainwork-delta / time-delta" formula. The helper is dispatched
correctly for the standalone RPC (`getnetworkhashps`), but
`getmininginfo` never invokes it.

Core (`rpc/mining.cpp:472`):
```cpp
obj.pushKV("networkhashps", getnetworkhashps().HandleRequest(request));
```
delegates to the same helper as the standalone RPC.

**File:** `src/beamchain_rpc.erl:3708` (literal zero);
`src/beamchain_rpc.erl:9249-9277` (correct helper, defined but not
called from getmininginfo).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:472`.

**Impact:** monitoring scrapers reading `getmininginfo.networkhashps`
see 0 forever; cross-impl difference vs Core's correct value.
Two-pipeline guard 18th distinct extension.

---

## BUG-18 (P1) — `getmininginfo.currentblockweight` / `currentblocktx` always 0 instead of omitted

**Severity:** P1. Bitcoin Core's `getmininginfo` (`rpc/mining.cpp:
467-468`):

```cpp
if (BlockAssembler::m_last_block_weight) obj.pushKV("currentblockweight", *BlockAssembler::m_last_block_weight);
if (BlockAssembler::m_last_block_num_txs) obj.pushKV("currentblocktx", *BlockAssembler::m_last_block_num_txs);
```

OMITS the fields entirely if no block has been assembled yet
(`m_last_block_weight` is `std::optional<int64_t>`). The fields appear
only after the FIRST `CreateNewBlock` call.

beamchain (`rpc.erl:3701-3703`) emits all three unconditionally as
`0`:

```erlang
<<"currentblocksize">> => 0,
<<"currentblockweight">> => 0,
<<"currentblocktx">> => 0,
```

Pool monitoring tooling that distinguishes "0 weight" (genuinely
empty block) from "never assembled" (omitted field) misreports.

Beyond the omission, none of the three values are actually tracked
— even after a successful `create_block_template`, the next
`getmininginfo` still returns 0. The template's
`<<"_total_weight">>` internal field (`miner.erl:326`) is not
exposed via any cache that getmininginfo could read.

**File:** `src/beamchain_rpc.erl:3701-3703`;
`src/beamchain_miner.erl:326-327` (dead-data plumbing per W154
BUG-12; the value exists but no API exposes it).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:467-468`;
`bitcoin-core/src/node/miner.cpp::BlockAssembler::m_last_block_weight`.

**Impact:** monitoring divergence; cross-cite W154 BUG-12 dead-data
plumbing (`_total_weight` written but never read).

---

## BUG-19 (P1) — `getblocktemplate` does NOT check IBD or connection count; templates served during IBD orphan

**Severity:** P1. Bitcoin Core's `getblocktemplate`
(`rpc/mining.cpp:766-775`):

```cpp
if (!miner.isTestChain()) {
    const CConnman& connman = EnsureConnman(node);
    if (connman.GetNodeCount(ConnectionDirection::Both) == 0) {
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, CLIENT_NAME " is not connected!");
    }

    if (miner.isInitialBlockDownload()) {
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, CLIENT_NAME " is in initial sync and waiting for blocks...");
    }
}
```

Two safety gates on mainnet/testnet/signet (skipped on regtest /
"test chains"):
1. Zero-connection refuse — a fully-disconnected node would mine on
   a stale tip and produce orphans.
2. IBD refuse — a syncing node would mine on a partial chain and
   produce orphans.

beamchain's `rpc_getblocktemplate/1` (`rpc.erl:3720-3739`) skips both
gates. Templates are produced from the current tip regardless of:
- whether the node has any P2P connections at all
- whether the node is still doing IBD

**File:** `src/beamchain_rpc.erl:3720-3739`;
`src/beamchain_chainstate.erl:205-207` (`is_synced/0` exists but
never called from getblocktemplate);
`src/beamchain_peer_manager.erl:inbound_count/outbound_count`
(exist but never called from getblocktemplate).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:766-775`.

**Impact:** an operator who starts beamchain and immediately runs
a pool against it (before IBD finishes) mines orphans for hours.
Same for an operator whose node has lost all peers (firewall,
network split) and is unaware. Two missing gates that Core treats
as belt-and-suspenders. Cross-impl operator-safety regression.

---

## BUG-20 (P1) — `coinbasescript` defaults to OP_TRUE → mainnet anyone-can-spend funds-burn (W154 BUG-15 carry-forward, 2 weeks open)

**Severity:** P1. **Carry-forward re-anchor** (2nd instance this
quarter; W154 BUG-15 → W155 BUG-20). `rpc.erl:3722-3727`:

```erlang
rpc_getblocktemplate([TemplateRequest]) when is_map(TemplateRequest) ->
    DefaultScript = <<16#51>>,
    CoinbaseScript = maps:get(<<"coinbasescript">>, TemplateRequest,
                               DefaultScript),
```

When a pool calls `getblocktemplate` WITHOUT passing the non-standard
`coinbasescript` field — which is the standard BIP-22 contract that
EVERY Core-compatible pool follows — beamchain defaults to OP_TRUE
(`0x51`). A mined block produced from this template has its
6.25-BTC (mainnet, post-2024-halving 3.125 BTC) reward going to an
anyone-can-spend script.

**Fleet pattern:** "funds-burn / funds-loss risk" — first catalogued
in W154 BUG-15 (NEW pattern). The pattern persists in W155 because
the code is the same line of code. Re-anchoring with a 2-week age
flags the priority issue: BIP-22 wire-format slippage is a 1-line
fix (replace `<<16#51>>` with `throw bad-request("coinbasescript
required")` or build a proper dummy coinbase that has scriptPubKey
that requires post-template replacement).

Reference: Core's GBT contract is that the SERVER supplies a
template; the CLIENT (pool) replaces the coinbase scriptPubKey
post-template. There is NO `coinbasescript` field in BIP-22 or
BIP-23. The beamchain field is a non-standard extension that, by
defaulting to OP_TRUE, turns a missed call into a funds-loss.

**File:** `src/beamchain_rpc.erl:3722-3727`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:730-879`
(no equivalent field).

**Impact:** mainnet pool integrators that forget the non-standard
field LOSE THE FULL BLOCK REWARD. Same severity as W154 BUG-15;
re-flagged for carry-forward priority.

---

## Summary

**Bug count:** 20 (BUG-1 through BUG-20).

**Severity distribution:**
- **P0-CDIV:** 5 (BUG-1, BUG-2, BUG-7, BUG-10, plus BUG-11 escalated
  to P1 for severity-of-impact-on-pool-tooling)
- **P1:** 12 (BUG-3, BUG-4, BUG-5, BUG-8, BUG-9, BUG-11, BUG-12,
  BUG-13, BUG-16, BUG-17, BUG-18, BUG-19, BUG-20)
- **P2:** 3 (BUG-6, BUG-14, BUG-15)

Total: 4 + 13 + 3 = 20. ✓

**Fleet patterns confirmed:**
- "two-pipeline guard 18th distinct extension" (BUG-17) —
  `getmininginfo.networkhashps` hard-coded zero while the correct
  helper exists in the same impl.
- "carry-forward re-anchor 2nd instance" (BUG-20 = W154 BUG-15)
  — funds-loss-risk pattern still open 2 weeks later.
- "two SECOND-instance of same root-cause through different exit"
  (BUG-7 = W154 BUG-8 via GBT-per-tx-sigops; same `estimate_sigops/1`
  helper, fresh failure mode).
- "dead-data plumbing" (BUG-18 cross-cite W154 BUG-12) —
  `_total_weight` template internal field set but never surfaced
  via getmininginfo.
- "wire-format slippage" (BUG-20 `coinbasescript` non-standard
  field with funds-loss default; BUG-11 inconclusive vs
  duplicate-* state collapse).
- "missing RPC dispatch" (BUG-12, BUG-13, BUG-14, BUG-15) —
  4 RPC methods absent from handle_method.
- "BIP-22/BIP-23 contract slippage" (BUG-1, BUG-2, BUG-3, BUG-4)
  — beamchain implements GBT-response-shape correctly but ignores
  every request-side knob (mode / rules / longpollid / capabilities).
- "operator-safety gates missing" (BUG-19) — Core's IBD +
  connection-count refuse gates absent.
- "params-data missing entirely" (BUG-16) — signet_challenge not
  even stored in chain_params, never mind emitted.
- "pre-segwit divisor missing" (BUG-8, BUG-9) — cost-units vs
  legacy-units mismatch on hypothetical pre-segwit chains.
- "auto-fix-up gap" (BUG-10) — `UpdateUncommittedBlockStructures`
  not run; pool blocks built without nonce hard-reject.

**Top three findings:**

1. **BUG-1 + BUG-2 cluster (P0-CDIV BIP-23 proposal mode absent)**
   — `rpc_getblocktemplate/1` reads only `coinbasescript`, never
   `mode`/`data`/`rules`/`longpollid`. The proposal branch (Core's
   `rpc/mining.cpp:730-752`) is entirely absent. Pool software that
   uses proposal mode to pre-validate assembled blocks gets a fresh
   template back instead of a validation result; the proposal is
   silently lost. Combined with BUG-10 (no `UpdateUncommittedBlockStructures`
   auto-fix-up), pools can't even smoke-test blocks they built
   without the witness nonce.

2. **BUG-10 (P0-CDIV submitblock auto-fix-up missing)** —
   `do_submit_block/1` doesn't call any equivalent of
   `UpdateUncommittedBlockStructures`. Pool software built for Core
   that omits the 32-byte zero `scriptWitness` on the coinbase
   input (relying on the node to inject it) gets hard rejections
   from beamchain. Cross-impl pool-integration regression that
   affects every stratum-v2 / older-cgminer-style deployment.

3. **BUG-7 (P0-CDIV per-tx `sigops` undercounts via GBT)** —
   `format_tx_entries` calls `estimate_sigops/1` (legacy-only,
   misses P2SH redeemScript + witness sigops). SECOND distinct
   exposure of W154 BUG-8 — same root cause, fresh failure path
   through the GBT per-tx field. Pools using the per-tx `sigops`
   for their own block-fill bookkeeping over-fill blocks; submit
   fails with `bad-blk-sigops`.

**Carry-forwards into the priority queue:**
- BUG-20 (funds-burn OP_TRUE default; ~2 weeks open from W154
  BUG-15; 1-line fix).
- BUG-7 (second exposure of W154 BUG-8 `estimate_sigops/1`
  undercount; ~2 weeks open; fix requires plumbing UTXOs into the
  miner and switching to `get_tx_sigop_cost/3`).

**Cumulative impact note:** the W155 audit shows that beamchain's
GBT pipeline is "response-shape correct" but "request-contract
broken" — every field a pool can SET is silently ignored
(coinbasescript excepted, which itself is non-standard). Beamchain
emits a syntactically-valid BIP-22 response that a Core-compatible
pool can parse, but the underlying machinery (proposal mode,
long-poll, rules enforcement, IBD/connection gates,
UpdateUncommittedBlockStructures auto-fix-up) is mostly absent.
This is a fleet pattern worth tracking ("response-shape correct,
request-contract broken") and a likely candidate for a unified
BIP-22 compatibility-pass.
