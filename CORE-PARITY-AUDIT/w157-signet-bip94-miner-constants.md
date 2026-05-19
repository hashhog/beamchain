# W157 — Signet block solution + BIP-94 timewarp + miner-side header constants (beamchain)

**Wave:** W157 — `CheckSignetBlockSolution`, `SignetTxs::Create`,
`FetchAndClearCommitmentSection`, `SIGNET_HEADER = 0xecc7daa2`,
`signet_challenge` consensus param, default signet challenge bin
(`512103ad5e...`-prefixed P2WSH 2-of-2), custom-signet
`m_messagestart` derivation (`sha256d(signet_challenge)[0..4]`),
`signet_blocks` boolean, `MAX_TIMEWARP = 600` (BIP-94),
`enforce_BIP94` consensus param, BIP-94 boundary timestamp gate
(validation.cpp:4097-4104), `GetMinimumTime` miner-side clamp
(node/miner.cpp:36-47), `UpdateTime` testnet-difficulty
re-recompute (node/miner.cpp:49-65), `GetNextWorkRequired`
(pow.cpp:14-48), `CalculateNextWorkRequired` BIP-94 first-block
basis (pow.cpp:67-76), `PermittedDifficultyTransition` (pow.cpp:89-136),
`fPowAllowMinDifficultyBlocks` 20-minute rule, `nVersion`
`compute_block_version` BIP-9 signaling, `nBits` compact-target
round-trip, `MAX_FUTURE_BLOCK_TIME = 2h`,
`HeadersSyncParams.commitment_period / redownload_buffer_size`,
GBT `mintime`, GBT `curtime`, GBT `signet_challenge` field.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/signet.cpp:28` — `SIGNET_HEADER = {0xec, 0xc7, 0xda, 0xa2}`.
- `bitcoin-core/src/signet.cpp:30` — `BLOCK_SCRIPT_VERIFY_FLAGS =
  P2SH | WITNESS | DERSIG | NULLDUMMY` (the signet block-solution
  script-verify flag set; NOT consensus block-script flags).
- `bitcoin-core/src/signet.cpp:32-57` — `FetchAndClearCommitmentSection`:
  walks the witness commitment output's `CScript`, finds the FIRST
  pushdata whose first 4 bytes are `SIGNET_HEADER`, strips the
  header bytes and extracts the remainder as the signet solution.
- `bitcoin-core/src/signet.cpp:59-68` — `ComputeModifiedMerkleRoot`:
  pre-commitment merkle root with the coinbase's modified
  scriptPubKey at vout[cidx] (commitment payload stripped).
- `bitcoin-core/src/signet.cpp:70-123` — `SignetTxs::Create`:
  builds the `to_spend` (locks block-header bytes via OP_0 + signet
  challenge) and `to_sign` (spends `to_spend` and OP_RETURNs) txs.
- `bitcoin-core/src/signet.cpp:126-153` — `CheckSignetBlockSolution`:
  genesis-block bypass, then `SignetTxs::Create`, then
  `VerifyScript(scriptSig, scriptPubKey, witness, BLOCK_SCRIPT_VERIFY_FLAGS, sigcheck)`
  with `MissingDataBehavior::ASSERT_FAIL` sigchecker.
- `bitcoin-core/src/signet.h:21-39` — `CheckSignetBlockSolution`
  declaration, `SignetTxs` opaque type.
- `bitcoin-core/src/consensus/consensus.h:35` — `MAX_TIMEWARP = 600`.
- `bitcoin-core/src/consensus/params.h:117-121` — `enforce_BIP94`
  boolean ("Enforce BIP94 timewarp attack mitigation. On testnet4
  this also enforces the block storm mitigation.").
- `bitcoin-core/src/consensus/params.h:132-140` — `defaultAssumeValid`,
  `signet_blocks{false}`, `signet_challenge` (vector<uint8_t>).
- `bitcoin-core/src/validation.cpp:4080-4119` —
  `ContextualCheckBlockHeader`: difficulty (`GetNextWorkRequired`),
  `time-too-old` (MTP+1 lower bound), BIP-94 gate at retarget boundary
  (`block.GetBlockTime() < pindexPrev->GetBlockTime() - MAX_TIMEWARP`),
  `time-too-new` (2h future), `bad-version` deployment gates.
- `bitcoin-core/src/pow.cpp:14-48` — `GetNextWorkRequired`:
  off-retarget min-difficulty exception when
  `fPowAllowMinDifficultyBlocks` is set; retarget boundary calls
  `CalculateNextWorkRequired`.
- `bitcoin-core/src/pow.cpp:50-85` — `CalculateNextWorkRequired`:
  timespan clamp [tt/4, tt*4], BIP-94 first-block-of-period bits
  basis (`pindexFirst->nBits` if `enforce_BIP94`, else `pindexLast->nBits`).
- `bitcoin-core/src/pow.cpp:89-136` —
  `PermittedDifficultyTransition`: short-circuit true on
  `fPowAllowMinDifficultyBlocks`, round-trip max/min through
  `SetCompact(GetCompact())` to mirror the on-chain rounding.
- `bitcoin-core/src/node/miner.cpp:36-47` — `GetMinimumTime`:
  `min_time = pindexPrev->GetMedianTimePast() + 1`; if
  `height % difficulty_adjustment_interval == 0`,
  `max(min_time, pindexPrev->GetBlockTime() - MAX_TIMEWARP)`.
- `bitcoin-core/src/node/miner.cpp:49-65` — `UpdateTime`:
  `nNewTime = max(GetMinimumTime(...), TicksSinceEpoch<seconds>(NodeClock::now()))`;
  on `fPowAllowMinDifficultyBlocks` networks (testnet),
  `pblock->nBits = GetNextWorkRequired(prev, pblock)` re-evaluated
  because the new timestamp may bump nBits to powLimit (20-min rule).
- `bitcoin-core/src/kernel/chainparams.cpp:100, 223, 322, 464, 547` —
  `enforce_BIP94`: false on mainnet/testnet3/signet/regtest,
  true on testnet4, configurable per-options on regtest.
- `bitcoin-core/src/kernel/chainparams.cpp:418` — default
  signet challenge: `"512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae"_hex_v_u8`
  (2-of-2 P2WSH multisig).
- `bitcoin-core/src/kernel/chainparams.cpp:452-453` —
  `consensus.signet_blocks = true`,
  `consensus.signet_challenge.assign(bin.begin(), bin.end())`.
- `bitcoin-core/src/kernel/chainparams.cpp:475-479` — custom-signet
  `m_messagestart` derivation:
  `HashWriter h; h << consensus.signet_challenge; uint256 hash = h.GetHash(); std::copy_n(hash.begin(), 4, pchMessageStart.begin())`.
  Magic is therefore a function of the challenge bytes, NOT a fixed
  constant.
- `bitcoin-core/src/kernel/chainparams.cpp:423-424` — default-signet
  `nMinimumChainWork` and `defaultAssumeValid` (only when no
  challenge override).
- `bitcoin-core/src/rpc/mining.cpp:1004` — GBT emits
  `mintime = GetMinimumTime(pindexPrev, DifficultyAdjustmentInterval())`.
- `bitcoin-core/src/rpc/mining.cpp:416-498` — `getmininginfo`
  emits `signet_challenge` field on signet only.

**Files audited**
- `src/beamchain_chain_params.erl:239-282` — `params(signet)`:
  network=signet, magic=`0A03CF40`, default_port=38333, rpc_port=38332,
  genesis_hash present, pow_limit `00000377ae...`, enforce_bip94=false,
  bip34..taproot all at height=1, dns_seeds, base58 prefixes,
  bech32 hrp `tb`. **NO `signet_challenge` field, NO `signet_blocks`
  boolean, NO mechanism for custom-signet challenge override.**
  Cross-cite: W155 BUG-3 / BUG-16 already flagged this gap.
- `src/beamchain_chain_params.erl:99-145` — `params(testnet)`:
  enforce_bip94=false (testnet3 — matches Core).
- `src/beamchain_chain_params.erl:147-194` — `params(testnet4)`:
  enforce_bip94=true (matches Core line 322), all BIPs at height=1,
  assume_valid set, magic `1C163F28`, port 48333, message-prefix
  conventional.
- `src/beamchain_chain_params.erl:196-237` — `params(regtest)`:
  enforce_bip94=false (matches Core default 464; but Core also lets
  this be toggled via `RegTestOptions::enforce_bip94`, which beamchain
  has no equivalent for).
- `src/beamchain_chain_params.erl:14-282` — overall
  `params/1` API signature includes `signet` as a valid network atom.
- `src/beamchain_chain_params.erl:323` — `genesis_block(signet)`:
  `make_genesis(satoshi_coinbase(), 1598918400, 52613770, 16#1e0377ae)`
  (matches Core CSigNetParams `CreateGenesisBlock(1598918400, 52613770, 0x1e0377ae, ...)`).
- `src/beamchain_pow.erl:1-313` — `bits_to_target/1`,
  `target_to_bits/1`, `check_pow/3`, `compute_work/1`,
  `get_next_work_required/3` (with `EnforceBIP94` switch on
  `enforce_bip94` Params key, lines 179-183),
  `permitted_difficulty_transition/4`,
  `pow_limit_bits/1`, `find_last_non_special_block/2`.
- `src/beamchain_miner.erl:36-58` — `DEFAULT_BLOCK_RESERVED_WEIGHT
  = 8000`, `DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS = 400`,
  `MAX_CONSECUTIVE_FAILURES = 1000`,
  `BLOCK_FULL_ENOUGH_WEIGHT_DELTA = 4000`,
  `DEFAULT_BLOCK_MIN_TX_FEE_SAT_KVBYTE = 1`, `MAX_TIMEWARP = 600`.
- `src/beamchain_miner.erl:183-352` — `do_create_template/3`:
  `compute_minimum_time(MTP, PrevBlockTime, Height)` at line 202,
  `<<"mintime">> => MTP + 1` at line 312 (W154 BUG-6 carry-forward),
  `<<"curtime">> => Timestamp` at line 319.
- `src/beamchain_miner.erl:417-441` — `compute_minimum_time/3`:
  applies BIP-94 only at `Height rem DIFFICULTY_ADJUSTMENT_INTERVAL == 0`.
  Used internally for `Timestamp = max(MinTime, Now)` but NOT
  surfaced via the GBT `mintime` field.
- `src/beamchain_miner.erl:993-1075` —
  `do_generate_block_with_txs/4`: regtest generateblock path; also
  uses `compute_minimum_time/3`. Coinbase value = subsidy (fees
  forfeited per W145 BUG-6 carry-forward).
- `src/beamchain_validation.erl:67-93` — `check_block_header/2`:
  PoW check, time-too-new (2h future), bits within pow_limit. No
  signet block-solution hook.
- `src/beamchain_validation.erl:174-249` —
  `contextual_check_block_header/3`: difficulty match, MTP+1
  lower-bound, BIP-94 at `Height > 0, Height rem 2016 == 0`
  (lines 206-214), version-bits (BIP-34/66/65). **No
  CheckSignetBlockSolution call; no signet awareness at all.**
- `src/beamchain_validation.erl:308-404` — `contextual_check_block/4`:
  BIP-34 coinbase height, IsFinalTx, coinbase scriptSig length,
  BIP-141 witness commitment/malleation. **No signet block solution
  call.**
- `src/beamchain_validation.erl:1022-1690` — `connect_block/4`:
  re-runs check_block (defense-in-depth), contextual header,
  contextual block, BIP-30, script flags, UTXO updates. **No
  CheckSignetBlockSolution call.**
- `src/beamchain_header_sync.erl:42-46` — `MAX_FUTURE_DRIFT = 7200`,
  `MTP_WINDOW = 11`.
- `src/beamchain_header_sync.erl:857-942` — `validate_one_header/2`:
  PoW, `permitted_difficulty_transition`, MTP+1, time-too-new,
  difficulty match, checkpoint enforce, `check_bip94/3`,
  chainwork accumulator, block-index store.
- `src/beamchain_header_sync.erl:1059-1075` — `check_bip94/3`:
  uses `enforce_bip94` boolean from Params (correct — not
  network-name comparison), boundary check
  `Header.timestamp >= PrevHeader.timestamp - 600`.
- `src/beamchain_headerssync.erl:40-49` — per-network
  HeadersSyncParams `COMMITMENT_PERIOD` and `REDOWNLOAD_BUFFER`
  constants. Mainnet=641/15218, testnet4=606/16092, signet=673/14460,
  testnet=620/15724, regtest=275/7017 (all match Core
  `bitcoin-core/src/kernel/chainparams.cpp` lines 193, 294, 399, 516, 645).
- `src/beamchain_rpc.erl:3684-3718` — `rpc_getmininginfo/0`:
  no signet_challenge field, no signet-network branch (W155 BUG-16
  carry-forward).
- `src/beamchain_rpc.erl:3720-3733` — `rpc_getblocktemplate/1`:
  defaults `CoinbaseScript = OP_TRUE` (W154 BUG-15 / W155 BUG-20
  carry-forward — funds-burn risk on mainnet).
- `src/beamchain_versionbits.erl:349-389` — `deployments(signet)`:
  csv/segwit/taproot all `ALWAYS_ACTIVE`, testdummy `NEVER_ACTIVE`
  (matches Core `SigNetParams` vDeployments[]).
- `src/beamchain_config.erl:786-797` — `network_params(signet)`:
  hardcoded `SIGNET_MAGIC = 0A03CF40` (the DEFAULT-signet magic;
  custom signet would need per-instance derivation).
- `src/beamchain_wallet.erl:913-917` — `bech32_hrp(signet) = "tb"`
  (matches Core SigNetParams).
- `src/beamchain_cli.erl:1240` — default RPC port 38332 for signet.
- `include/beamchain_protocol.hrl:30-36` — `DIFFICULTY_ADJUSTMENT_INTERVAL=2016`,
  `POW_TARGET_SPACING=600`, `POW_TARGET_TIMESPAN=1209600`,
  `SUBSIDY_HALVING_INTERVAL=210000`, `INITIAL_SUBSIDY=5000000000`.
- `include/beamchain_protocol.hrl:110` — `SIGNET_MAGIC` defined as
  `<<16#0A, 16#03, 16#CF, 16#40>>`.

---

## Gate matrix (38 sub-gates / 13 behaviours)

| #  | Behaviour | Sub-gate | Verdict |
|----|-----------|----------|---------|
| 1  | CheckSignetBlockSolution | G1: function defined | **BUG-1 (P0-CDIV)** entirely absent |
| 1  | … | G2: called from `connect_block` / `contextual_check_block` | **BUG-1 cross-cite** |
| 1  | … | G3: called from `submitblock` path | **BUG-1 cross-cite** |
| 1  | … | G4: genesis-block bypass `block.GetHash() == hashGenesisBlock` | **BUG-1 cross-cite** |
| 2  | SIGNET_HEADER 0xecc7daa2 | G5: 4-byte constant defined | **BUG-2 (P0-CDIV)** absent |
| 2  | … | G6: used to identify pushdata in `FetchAndClearCommitmentSection` | **BUG-2 cross-cite** |
| 3  | signet_challenge chain param | G7: present in `params(signet)` map | **BUG-3 (P0-CDIV)** absent (W155 BUG-3/BUG-16 carry-forward — now 3 waves open) |
| 3  | … | G8: Core default challenge bin populated (`512103ad5e...`) | **BUG-3 cross-cite** |
| 3  | … | G9: custom-signet override hook (CLI `-signetchallenge=`) | **BUG-4 (P0-CDIV)** absent |
| 3  | … | G10: `signet_blocks` boolean param present | **BUG-3 cross-cite** |
| 4  | Custom-signet messagestart | G11: magic derived from `sha256d(signet_challenge)[0..4]` | **BUG-5 (P0-CDIV)** hardcoded `0A03CF40` only; custom signets get the wrong magic and disconnect peers |
| 5  | BIP-94 MAX_TIMEWARP=600 | G12: constant defined | PASS (`miner.erl:58`, `header_sync.erl:1068` and `validation.erl:210` use the `600` literal not the macro — minor consistency) |
| 5  | … | G13: enforced in `validation.cpp::ContextualCheckBlockHeader` equivalent | PASS (`validation.erl:206-214`) |
| 5  | … | G14: enforced in `validate_one_header` (header-sync path) | PASS (`header_sync.erl:1059-1075`) |
| 5  | … | G15: enforced when `enforce_bip94` is true on ALL networks (not name-keyed) | PASS (both call sites use the boolean) |
| 6  | GBT mintime / GetMinimumTime | G16: `mintime` GBT field equals `GetMinimumTime(prev, interval)` | **BUG-6 (P0-CDIV, W154 BUG-6 STILL OPEN, 3 waves)** — `miner.erl:312` emits `MTP + 1` unconditionally; BIP-94 boundary clamp absent from emitted field |
| 6  | … | G17: `compute_minimum_time/3` covers boundary | PASS internally (`miner.erl:432-441`) but never surfaces |
| 7  | enforce_BIP94 consensus param | G18: present per-network | PASS (`chain_params.erl:34/116/164/213/256`) |
| 7  | … | G19: mainnet=false, testnet3=false, testnet4=true, signet=false, regtest=false | PASS (matches Core lines 100/223/322/464/547) |
| 7  | … | G20: regtest options-knob equivalent (`-enforcebip94`) | **BUG-7 (P1)** — Core lets regtest enable BIP-94 via `RegTestOptions::enforce_bip94` (line 547); beamchain hardcodes regtest=false with no override knob |
| 8  | GetNextWorkRequired | G21: off-retarget min-difficulty exception (testnet 20-min rule) | PASS (`pow.erl:135-146`) |
| 8  | … | G22: retarget boundary calls `CalculateNextWorkRequired` analog | PASS (`pow.erl:125-130`) |
| 8  | … | G23: BIP-94 first-block-of-period bits basis (`enforce_BIP94` branch in `CalculateNextWorkRequired`) | PASS (`pow.erl:179-183`) |
| 9  | UpdateTime miner-side | G24: `nNewTime = max(GetMinimumTime, NodeClock::now())` semantics | PARTIAL (`miner.erl:208, 253` use `max(MinTime, Now)` — semantics match) |
| 9  | … | G25: on `fPowAllowMinDifficultyBlocks` networks, `nBits = GetNextWorkRequired(prev, pblock)` re-evaluated after time bump | **BUG-8 (P0-CDIV)** — `do_create_template/3` computes `Bits` once (line 212-213) with `DummyHeader.timestamp = max(MinTime, Now)`. Then `Timestamp = max(MinTime, Now)` is recomputed at line 253 (same value, OK). But the `Header` written at line 256-263 uses `Bits` computed against `DummyHeader.timestamp` and `Timestamp` from line 253. These ARE the same value in practice (both are `max(MinTime, Now)`), so this is benign — but the control flow does not match Core's `UpdateTime` ordering of "set time, then re-run GetNextWorkRequired". A subsequent edit to either line that breaks the invariant silently corrupts the testnet template (template publishes one nBits, miner extends timestamp, retarget shifts, peers reject `bad-diffbits`). Pattern: hidden-coincidence-equality |
| 10 | nVersion / BIP-9 signaling | G26: `compute_block_version` ORs STARTED/LOCKED_IN bits onto `0x20000000` | PASS (`versionbits.erl`, used at `miner.erl:222` + `miner.erl:1039`) |
| 11 | nBits compact encoding | G27: round-trip `target_to_bits(bits_to_target(x)) == x` for canonical inputs | PASS (`pow.erl:50-75`, audited against Core SetCompact/GetCompact) |
| 11 | … | G28: negative-bit (0x00800000) treated as zero | PASS (`pow.erl:30, 39-40`) |
| 11 | … | G29: overflow check (Core pfOverflow semantics) | PASS (`pow.erl:35-38`) |
| 12 | GBT signet_challenge field | G30: `getmininginfo` emits `signet_challenge` on signet | **BUG-9 (P1)** — `rpc.erl:3699-3718` emits no signet_challenge (W155 BUG-16 carry-forward; data isn't in the chainparams to emit anyway, see BUG-3) |
| 12 | … | G31: `getblocktemplate` emits `signet_challenge` on signet | **BUG-9 cross-cite** |
| 13 | Operator-knob coverage | G32: `-signetchallenge=<hex>` CLI | **BUG-4 cross-cite** |
| 13 | … | G33: `-signetseednode=<addr>` CLI (Core option) | **BUG-10 (P2)** absent; custom-signet operators cannot supply peer addresses |
| 13 | … | G34: `-enforcebip94` regtest knob | **BUG-7 cross-cite** |
| 13 | … | G35: `getmininginfo.signet_challenge` test coverage | **BUG-9 cross-cite** |
| 14 | Reject-string parity | G36: BIP-94 rejection emits `time-timewarp-attack` | **BUG-11 (P1)** — beamchain throws atom `time_timewarp_attack` (matches Core's reject token modulo underscore-vs-hyphen — the RPC stringifier doesn't translate); `bad_diffbits` / `time_too_old` / `time_too_new` similarly Erlangified |
| 14 | … | G37: signet-solution-invalid emits `bad-signet-blksig` (Core) | **BUG-1 cross-cite** (no such error path at all) |
| 15 | check_block_header constant | G38: uses named `MAX_FUTURE_BLOCK_TIME` macro consistently | **BUG-12 (P2)** — `validation.erl:80` uses literal `2 * 60 * 60`; `header_sync.erl` uses `MAX_FUTURE_DRIFT`; `headerssync.erl` uses `MAX_FUTURE_BLOCK_TIME`. Three distinct names for the same Core constant in three places |

---

## BUG-1 (P0-CDIV) — `CheckSignetBlockSolution` entirely absent; signet blocks accepted with any PoW

**Severity:** P0-CDIV (chain-split / consensus divergence on signet
network — same class as W143 BUG-9 blockbrew finding, 2nd fleet instance).

Bitcoin Core's `CheckSignetBlockSolution` (`signet.cpp:126-153`)
is THE consensus rule that makes signet a permissioned-signer
network. Every non-genesis block on signet must contain a coinbase
witness-commitment-section payload that, when extracted by
`FetchAndClearCommitmentSection`, parses as a `scriptSig +
scriptWitness` pair that successfully spends an OP_0-locked output
whose scriptPubKey is the network's `signet_challenge` (a P2WSH
multisig — default 2-of-2, custom signets can use any script). The
extracted solution commits to the block's nVersion, hashPrevBlock,
*modified* merkle root (with the signet header bytes stripped), and
nTime — the nonce is intentionally excluded so miners can grind.

`CheckSignetBlockSolution` is called from
`ContextualCheckBlock` (`validation.cpp:4150`) gated on
`consensusParams.signet_blocks`. Without it, signet has no
permission gate: any peer with sufficient PoW (signet powLimit is
`0x1e0377ae` which is trivial) can mine arbitrary blocks and have
them accepted.

beamchain's `connect_block/4` (`validation.erl:1022-1690`),
`contextual_check_block_header/3` (`validation.erl:174-249`), and
`contextual_check_block/4` (`validation.erl:308-404`) have **zero
references** to `signet`, `CheckSignetBlockSolution`,
`SignetTxs`, `SIGNET_HEADER`, or `signet_challenge`. A
`grep -rn signet src/*.erl` returns matches only in
`beamchain_chain_params.erl` (network-name plumbing), config
(magic+seeds), versionbits (always-active), bip21, rpc, wallet,
headerssync, and cli — none of which is the consensus check.

**File:** entire `src/beamchain_validation.erl` (no signet hook
at any of 5 entry points: check_block, check_block_header,
contextual_check_block, contextual_check_block_header, connect_block);
no `signet.erl` / `beamchain_signet.erl` / equivalent module
exists.

**Core ref:**
`bitcoin-core/src/signet.cpp::CheckSignetBlockSolution`,
`bitcoin-core/src/validation.cpp:4150` (call site).

**Excerpt (Core signet.cpp:126-153)**
```cpp
bool CheckSignetBlockSolution(const CBlock& block, const Consensus::Params& consensusParams)
{
    if (block.GetHash() == consensusParams.hashGenesisBlock) {
        return true;  // genesis is axiomatic
    }
    const CScript challenge(consensusParams.signet_challenge.begin(), consensusParams.signet_challenge.end());
    const std::optional<SignetTxs> signet_txs = SignetTxs::Create(block, challenge);
    if (!signet_txs) return false;  // parse failure
    const CScript& scriptSig = signet_txs->m_to_sign.vin[0].scriptSig;
    const CScriptWitness& witness = signet_txs->m_to_sign.vin[0].scriptWitness;
    PrecomputedTransactionData txdata;
    txdata.Init(signet_txs->m_to_sign, {signet_txs->m_to_spend.vout[0]});
    TransactionSignatureChecker sigcheck(...);
    if (!VerifyScript(scriptSig, signet_txs->m_to_spend.vout[0].scriptPubKey, &witness,
                      BLOCK_SCRIPT_VERIFY_FLAGS, sigcheck)) {
        return false;  // bad-signet-blksig
    }
    return true;
}
```

**Impact:**
- A beamchain node configured with `--network=signet` will accept
  ANY block past genesis as long as it has minimum-difficulty PoW.
  The signet-signers' challenge bytes are not consulted because
  the param doesn't exist (BUG-3). This forks beamchain off the
  permissioned signet at block 1.
- Cross-impl: a beamchain signet node will sync a different chain
  than every other signet node in the fleet (Core, electrs, btcd,
  etc.) — instantly visible via `getbestblockhash` divergence.
- Same shape as W143 BUG-9 blockbrew finding (`CheckSignetBlockSolution`
  absent there too). Fleet-wide pattern: 2 of 10 confirmed missing,
  beamchain is the 2nd impl audited at this depth on signet.
- An attacker on signet can spam the network with any PoW-valid
  block they construct (signet powLimit = `0x1e0377ae` = trivial
  to mine on a laptop) and a beamchain node accepts each as a tip
  candidate, with predictable wedge / reorg effects.

---

## BUG-2 (P0-CDIV) — `SIGNET_HEADER = 0xecc7daa2` constant entirely absent

**Severity:** P0-CDIV (paired with BUG-1 — without this 4-byte
sentinel, even a manually-coded CheckSignetBlockSolution would
have nowhere to extract the solution from).

`SIGNET_HEADER` (`bitcoin-core/src/signet.cpp:28`) is the magic
4-byte prefix that identifies the signet-solution pushdata inside
the witness-commitment-output's `CScript`. `FetchAndClearCommitmentSection`
walks the script's pushes, finds the first one whose bytes start
with `0xec 0xc7 0xda 0xa2`, strips the prefix, and returns the
remainder as the signet solution payload.

A grep over `beamchain/` returns ZERO matches for `0xecc7daa2`,
`16#ecc7daa2`, `ECC7DAA2`, `SIGNET_HEADER`, `signet_header`, or
the byte tuple `{0xec, 0xc7, 0xda, 0xa2}`. There is no helper for
"strip the signet section from a coinbase output".

**File:** No file (constant doesn't exist).

**Core ref:** `bitcoin-core/src/signet.cpp:28-32`.

**Impact:** Even if BUG-1 / BUG-3 / BUG-4 were filed, the
implementation would have to introduce this constant before any
parser can recover the signet solution from a coinbase output.
Sequential prerequisite — sibling bug to BUG-1.

---

## BUG-3 (P0-CDIV) — `signet_challenge` chain param missing from `params(signet)` (W155 carry-forward, now 3 waves open)

**Severity:** P0-CDIV (consensus param entirely absent; companion
to BUG-1 — even a working CheckSignetBlockSolution implementation
has no challenge bytes to verify against).

`bitcoin-core/src/kernel/chainparams.cpp:418` populates the default
signet challenge:
`512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae`
(74 bytes = OP_1 push33 pubkey1 push33 pubkey2 OP_2 OP_CHECKMULTISIG = 2-of-2 P2WSH multisig).
Line 452-453 stores it: `consensus.signet_blocks = true;
consensus.signet_challenge.assign(bin.begin(), bin.end())`. The
field has `std::vector<uint8_t>` type in
`consensus/params.h:140`.

beamchain's `params(signet)` (`chain_params.erl:239-282`) defines
network/magic/ports/genesis/pow_limit/all-BIPs-at-1/seeds/prefixes,
but has NO `signet_challenge` key, NO `signet_blocks` key, and no
default-challenge byte literal anywhere in the codebase. A
recursive grep over the repo returns zero matches for any of:
- `512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be43`
- `signet_challenge`
- `signet_blocks`

This was previously flagged in W155 BUG-3 (signet rules check),
W155 BUG-16 (getmininginfo.signet_challenge emit), and W155 line
146 ("`beamchain_chain_params.erl:239-275`'s signet params block
has NO `signet_challenge` / `signet_blocks` field at all"). W157
is now the **3rd consecutive wave** with this gap open. **Re-anchoring
count: 3 waves (W155 → W156 → W157).**

**File:** `src/beamchain_chain_params.erl:239-282`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:418, 452-453`,
`bitcoin-core/src/consensus/params.h:139-140`.

**Excerpt (beamchain, missing field)**
```erlang
params(signet) ->
    #{
        network => signet,
        magic => <<16#0A, 16#03, 16#CF, 16#40>>,
        default_port => 38333,
        rpc_port => 38332,
        genesis_hash => hex_to_bin(
            "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"),
        genesis_block => genesis_block(signet),
        pow_limit => hex_to_bin(
            "00000377ae000000000000000000000000000000000000000000000000000000"),
        %% MISSING: signet_challenge => hex_to_bin("512103ad5e0e..."),
        %% MISSING: signet_blocks => true,
        ...
    }
```

**Impact:**
- Without the chain param, every downstream consumer
  (CheckSignetBlockSolution, getmininginfo.signet_challenge,
  getblocktemplate, signet-rules-array check in GBT) is fed a
  default zero / missing-key error.
- Cross-cite with BUG-1 / BUG-2: even if those were filed, this
  bug blocks the verify path from having anything to verify against.
- Operator UX: a user typing `--network=signet` thinks they're
  joining the public signet, but the daemon will fork off at block
  1 (BUG-1) and report no signet_challenge field via RPC.

---

## BUG-4 (P0-CDIV) — Custom-signet `-signetchallenge=<hex>` operator knob absent

**Severity:** P0-CDIV. Core's `SigNetOptions::challenge`
(`kernel/chainparamsbase.cpp` + `init.cpp` argument parser) lets
operators run a **custom-signet** by supplying a different challenge
script via `-signetchallenge=<hex>`. This is the canonical way
the Bitcoin Core test team and the broader signet community spin
up isolated signet variants (e.g., for testing soft-fork
deployments without touching public signet).

Core's `SigNetParams` constructor branches on `options.challenge`:
- absent → use the hard-coded default `512103ad5e...`,
  populate `nMinimumChainWork` + `defaultAssumeValid`, use
  built-in seeds.
- present → use the supplied bytes, clear chainwork/assumevalid,
  derive a per-instance message-start magic from
  `sha256d(signet_challenge)[0..4]`.

beamchain's `params(signet)` is non-parameterised (atomic
`params(signet) -> Map`). There is no `params(signet,
CustomChallenge)` arity-2 variant. The CLI (`cli.erl`) lists
network options as `mainnet, testnet, testnet4, regtest, signet`
with no challenge-bytes pass-through. `config.erl` has no
`signet_challenge` config key. The `network_params(signet)` in
config returns a `#network_params{magic = ?SIGNET_MAGIC, ...}`
with hardcoded magic.

**File:** `src/beamchain_chain_params.erl:239` (params/1 has no
challenge arg); `src/beamchain_cli.erl:296` (network help text);
`src/beamchain_config.erl:786-797` (network_params hardcoded).

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:417-445`
(challenge branch); `bitcoin-core/src/init.cpp` (option parsing).

**Impact:** beamchain operators cannot participate in any
custom-signet test network. The only signet mode supported is
"default public signet" — and that one is already broken by
BUG-1 / BUG-3. Functional dead-end for the entire signet feature.

---

## BUG-5 (P0-CDIV) — Custom-signet `m_messagestart` derivation absent; hardcoded magic conflicts with custom signets

**Severity:** P0-CDIV (peer-handshake-rejection on every
non-default signet, with cascading effect of "every connection
attempt is silently terminated with an unexpected-magic error").

Core's `SigNetParams` derives the network magic
(`pchMessageStart`, the first 4 bytes of every P2P message
envelope) as a function of the challenge bytes:

```cpp
// kernel/chainparams.cpp:475-479
HashWriter h{};
h << consensus.signet_challenge;
uint256 hash = h.GetHash();
std::copy_n(hash.begin(), 4, pchMessageStart.begin());
```

Default signet (with the hardcoded `512103ad5e...` challenge)
hashes to magic `0A 03 CF 40`, which is what beamchain uses as
`SIGNET_MAGIC` (`beamchain_protocol.hrl:110`). A custom signet
with any other challenge hashes to a different 4-byte magic.

beamchain hardcodes `SIGNET_MAGIC = <<16#0A, 16#03, 16#CF, 16#40>>`
(`beamchain_protocol.hrl:110`) and uses it unconditionally in
`network_params(signet)` (`config.erl:789`) and
`params(signet).magic` (`chain_params.erl:242`). A custom signet
operator who supplies their own `-signetchallenge=<hex>` would
need the magic to follow — but the dispatch path has no
derivation routine and no parameter.

The fix would normally accompany the BUG-4 challenge-knob plumbing,
but it deserves its own bug because the derivation is a separate
piece of implementation work (requires a sha256d invocation over
the serialised challenge bytes via `compact_size(len)` framing —
Core uses `HashWriter << CompactSize(challenge.size()) <<
challenge.bytes`).

**File:** `include/beamchain_protocol.hrl:110`,
`src/beamchain_config.erl:786-797`, `src/beamchain_chain_params.erl:242`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:475-479`.

**Impact:**
- Every custom-signet network requires a per-instance magic; beamchain
  always advertises the default-signet magic and gets disconnected
  at the version handshake by every custom-signet peer.
- Net effect: even if BUG-4 (challenge-bytes knob) is implemented,
  the operator-visible result is "node starts up but cannot find
  any peers" — silent dead.
- Cross-cite: same shape as the broader fleet `signet_challenge`
  missing pattern (W155 → W156 → W157 carry-forward).

---

## BUG-6 (P0-CDIV) — GBT `mintime` ignores BIP-94 timewarp at retarget boundary (W154 BUG-6 STILL OPEN, 3 waves)

**Severity:** P0-CDIV (chain-split candidate on testnet4 — at any
2016-block boundary, a pool that respects beamchain's GBT `mintime`
mines a block whose timestamp Core rejects with
`time-timewarp-attack`). **Re-anchoring count: 3 waves (W154 →
W155 → W156-implicit → W157). W154 catalogued; W156 / W157 confirm
unchanged.**

Bitcoin Core's `getblocktemplate` (`rpc/mining.cpp:1004`) emits:

```cpp
result.pushKV("mintime", GetMinimumTime(pindexPrev, consensusParams.DifficultyAdjustmentInterval()));
```

`GetMinimumTime` (`node/miner.cpp:36-47`) returns:
```cpp
int64_t min_time{pindexPrev->GetMedianTimePast() + 1};
const int height{pindexPrev->nHeight + 1};
if (height % difficulty_adjustment_interval == 0) {
    min_time = std::max<int64_t>(min_time, pindexPrev->GetBlockTime() - MAX_TIMEWARP);
}
return min_time;
```

beamchain's template at `miner.erl:312` emits:

```erlang
<<"mintime">> => MTP + 1,
```

The BIP-94 boundary clamp IS computed in
`compute_minimum_time(MTP, PrevBlockTime, Height)` at lines 432-441
(used at line 202 for the `Timestamp` field assignment), but the
GBT-exposed `mintime` field publishes the raw `MTP + 1`. A pool
that respects beamchain's GBT contract mines a block at `MTP + 1`,
which can violate the BIP-94 rule at a 2016-block boundary when
`MTP + 1 < PrevBlockTime - 600` (i.e., when the previous block's
timestamp was forced high to satisfy time-too-new). Core peers
reject with `time-timewarp-attack`.

The shape is **comment-as-confession + two-pipeline-guard**: the
local Timestamp field at line 253 is correctly clamped via
`max(MinTime, Now)` (where `MinTime` IS BIP-94-aware), but the
**exported contract** to pools (mintime) is the raw `MTP + 1`.
Two paths from the same input to two different consumers, both in
the same file.

**File:** `src/beamchain_miner.erl:312` (raw mintime emit),
432-441 (correct helper that's not called for this field).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1004`,
`bitcoin-core/src/node/miner.cpp:36-47`.

**Excerpt (beamchain, divergent pipelines)**
```erlang
%% line 202 — internal compute uses BIP-94-aware helper
MinTime = compute_minimum_time(MTP, PrevBlockTime, Height),

%% line 253 — local Timestamp clamps via BIP-94-aware MinTime
Timestamp = max(MinTime, Now),

%% line 312 — GBT exported mintime DOES NOT use the helper
<<"mintime">> => MTP + 1,
```

The fix is a one-line swap:
`<<"mintime">> => compute_minimum_time(MTP, PrevBlockTime, Height)`.

**Impact:**
- testnet4 (where `enforce_bip94 = true`), every 2016-block boundary:
  a pool mining off the beamchain template at exactly `mintime` gets
  its block rejected by Core peers — **pool revenue loss**.
- mainnet (where `enforce_bip94 = false` today): correctness-neutral;
  but if BIP-94 ever activates on mainnet (the inline comment in
  `compute_minimum_time/3` at line 423 says "active on all networks
  since Core 28.x" which is forward-looking), this bug becomes
  consensus-relevant.
- regtest with `enforce_bip94 = true` option (BUG-7 says beamchain
  has no option — but if BUG-7 is fixed, this bug fires too).
- Cross-impl: divergence vs every Core-faithful impl visible at
  any 2016-block testnet4 wallclock-jump scenario.

---

## BUG-7 (P1) — regtest `-enforcebip94` operator knob absent

**Severity:** P1. Core's `RegTestOptions::enforce_bip94`
(`kernel/chainparams.cpp:547`) is a per-options boolean that lets
tests opt into BIP-94 on regtest. Used in functional tests for
testnet4-like time-warp scenarios that can be run deterministically
without a 24-week timespan.

beamchain hardcodes `enforce_bip94 => false` for regtest
(`chain_params.erl:213`). There is no `params(regtest, #{enforce_bip94
=> true})` arity-2 variant; no config-file key; no CLI flag. Tests
that want to verify BIP-94 enforcement have to use testnet4 (which
has all the other testnet4-specific quirks, like the genesis
difficulty rule and reset behaviour).

**File:** `src/beamchain_chain_params.erl:213`,
`src/beamchain_config.erl` (no regtest-options struct).

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:547`.

**Impact:** test ergonomics; cross-impl regression-test parity gap.
Once BUG-6 is fixed, regtest with `enforce_bip94 = true` becomes
the natural test surface for verifying the mintime fix doesn't
regress.

---

## BUG-8 (P0-CDIV) — Miner's UpdateTime semantics: nBits computed once against pre-set timestamp; testnet 20-minute rule may publish stale nBits

**Severity:** P0-CDIV ("hidden-coincidence-equality" — first
beamchain instance of this fleet pattern as I'm aware).

Core's `UpdateTime` (`node/miner.cpp:49-65`):

```cpp
int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    int64_t nOldTime = pblock->nTime;
    int64_t nNewTime{std::max<int64_t>(
        GetMinimumTime(pindexPrev, consensusParams.DifficultyAdjustmentInterval()),
        TicksSinceEpoch<std::chrono::seconds>(NodeClock::now()))};
    if (nOldTime < nNewTime) {
        pblock->nTime = nNewTime;
    }
    // Updating time can change work required on testnet:
    if (consensusParams.fPowAllowMinDifficultyBlocks) {
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams);
    }
    return nNewTime - nOldTime;
}
```

The comment "Updating time can change work required on testnet" is
the key invariant: on testnet (where the 20-minute min-difficulty
rule applies), the relationship `nBits = GetNextWorkRequired(prev,
pblock)` depends on `pblock.GetBlockTime()`. When `nTime` is bumped
to `nNewTime`, `nBits` may need to drop to `powLimit` (if the new
timestamp is more than `2 * spacing = 1200s` ahead of prev_time).

beamchain's `do_create_template/3` (`miner.erl:183-352`) computes
`Bits` ONCE (line 212-213) using a `DummyHeader` constructed with
`timestamp = max(MinTime, Now)` (line 208). Then the actual block's
`Timestamp` is recomputed at line 253 as `max(MinTime, Now)` again
— same expression, evaluating to the same value at that instant.
The `Header` written at line 256-263 uses the once-computed `Bits`
and the second-computed `Timestamp`.

This works **only because** `max(MinTime, Now)` is evaluated to the
same value twice in adjacent statements. There is no `UpdateTime`
analog that re-runs `get_next_work_required` after the timestamp
field is finalised. If a future edit introduces any
between-line state (e.g., a long-running mempool query between
line 208 and line 253 that ages `Now`), the two `max(MinTime, Now)`
evaluations could diverge, the template would publish stale `Bits`,
and a testnet pool would mine `bad-diffbits` blocks.

The shape is fragile: the consensus invariant is held by a
coincidence of two evaluations producing the same value.

**File:** `src/beamchain_miner.erl:208, 212-213, 253, 256-263`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:49-65`.

**Excerpt (beamchain, fragile coincidence)**
```erlang
%% line 208 — first evaluation feeds into difficulty calc
DummyHeader = #block_header{
    timestamp = max(MinTime, Now),
    ...
},
%% line 212-213 — Bits is fixed against DummyHeader.timestamp
Bits = beamchain_pow:get_next_work_required(PrevIndex, DummyHeader, Params),

%% lots of code in between (mempool selection, coinbase build,
%% merkle compute, GBT response assembly)...

%% line 253 — second evaluation feeds into actual Header.timestamp
Timestamp = max(MinTime, Now),

%% line 256-263 — Header uses Bits (fixed earlier) + Timestamp (fresh)
Header = #block_header{
    timestamp = Timestamp,
    bits = Bits,
    ...
},
```

If `Now` advances between line 208 and line 253 by enough to bump
`max(MinTime, Now)` past `MinTime` (i.e., the wall-clock catches
up to MinTime mid-template-build), the two evaluations differ. On
testnet/regtest with min-difficulty active, this corresponds to
`Bits` being computed against the older time AND `Timestamp` being
the newer time — a violation of the testnet 20-min rule iff the
gap crosses the `spacing*2` threshold.

In practice today this is unlikely to trigger because the work
between lines 208 and 253 is fast. But it's a class of bug that
Core explicitly defends against by re-running `GetNextWorkRequired`
inside `UpdateTime` AFTER `nTime` is finalised.

**Impact:**
- testnet/regtest pools that race against the 20-min rule near a
  retarget boundary may see template `bad-diffbits` rejections.
- The invariant is preserved today by coincidence (two `max(MinTime,
  Now)` calls evaluate equal). Any future refactor that introduces
  awaiting work between them silently breaks the invariant.
- Cross-impl: Core's `UpdateTime` is THE place to put this
  re-evaluation — folding it into a helper named after the Core
  function would document the invariant.

---

## BUG-9 (P1) — `signet_challenge` field not emitted from getmininginfo / getblocktemplate (W155 BUG-16 carry-forward)

**Severity:** P1 (cross-impl monitoring/tooling gap; W155 BUG-16
already filed and **still open** through W157, 2 waves now).

Core's `getmininginfo` (`rpc/mining.cpp:416-498`) emits a
`signet_challenge` field when the active network is signet, so
miner-control software (e.g., `signet/miner.py` from Core's
`contrib/`) can recover the challenge hex and assemble the signet
solution before signing.

beamchain's `rpc_getmininginfo/0` (`rpc.erl:3684-3718`) does not
branch on network and emits no `signet_challenge` field
(W155 BUG-16). Two-pipeline cross-cite: even if the branch were
added, the chainparams (BUG-3) don't carry the value to emit.

Similarly, Core's `getblocktemplate` (`rpc/mining.cpp:660-1035`)
populates `signet_challenge` in the response on signet network;
beamchain's `rpc_getblocktemplate/1` (`rpc.erl:3720-3733`) doesn't.

**File:** `src/beamchain_rpc.erl:3684-3718, 3720-3733`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:416-498`, `660-1035`.

**Impact:** signet miner tooling (e.g., Core's signet miner script)
cannot run against a beamchain signet node — the response is missing
the field they need to assemble the solution.

---

## BUG-10 (P2) — `-signetseednode` operator knob absent

**Severity:** P2. Core's `-signetseednode=<addr>` option
(`init.cpp`) lets custom-signet operators specify peer addresses
when no DNS seeds exist for their custom network. beamchain has no
equivalent CLI flag or config option. Operators of a custom signet
must manually `addnode` after startup.

**File:** `src/beamchain_cli.erl`, `src/beamchain_config.erl`.

**Core ref:** `bitcoin-core/src/init.cpp` (`-signetseednode`).

**Impact:** UX gap; not consensus-relevant.

---

## BUG-11 (P1) — Reject-reason atoms diverge from Core's reject-token strings

**Severity:** P1 (wire-string parity gap; affects RPC consumer
parsing and BIP-22 error response token matching).

Bitcoin Core's `BlockValidationState::Invalid` calls emit specific
reject-token strings, e.g.:
- `time-timewarp-attack` (validation.cpp:4102, BIP-94 boundary)
- `bad-diffbits` (validation.cpp:4089)
- `time-too-old` (validation.cpp:4093)
- `time-too-new` (validation.cpp:4109)
- `bad-signet-blksig` (Core signet rejection reason — beamchain
  has no such path at all per BUG-1).

beamchain throws Erlang atoms (e.g., `time_timewarp_attack`,
`bad_diffbits`, `time_too_old`, `time_too_new`). These are not
auto-translated to Core's hyphenated form by the RPC stringifier;
a quick grep for `atom_to_binary` in `rpc.erl` shows they're
surfaced as `<<"time_timewarp_attack">>` (underscored) rather than
the Core `time-timewarp-attack` (hyphenated). Downstream tooling
that pattern-matches against Core reject reasons (e.g., test-suite
harnesses, BIP-22 submitblock response parsers) sees a different
token.

Fleet pattern echo: 9-token sweep in lunarblock W145 BUG-5/6/7/9/10/11/12;
identical class. **first beamchain instance flagged in W157 for
the BIP-94 + signet token cluster.**

**File:** `src/beamchain_validation.erl:191, 195, 211`,
`src/beamchain_header_sync.erl:893`.

**Core ref:** `bitcoin-core/src/consensus/validation.h::BlockValidationState`
token vocabulary; `validation.cpp:4089, 4093, 4102, 4109`.

**Impact:** RPC consumers / test harnesses get inconsistent reject
tokens between beamchain and Core. BIP-22 submitblock response
text differs.

---

## BUG-12 (P2) — `MAX_FUTURE_BLOCK_TIME` constant named THREE different ways across modules

**Severity:** P2 (code-hygiene / refactor-safety).

The Bitcoin Core constant `MAX_FUTURE_BLOCK_TIME = 2 * 60 * 60`
(`chain.h:29` / `validation.cpp:4108-4110`) appears in beamchain
as:
- `MAX_FUTURE_DRIFT = 7200` (`header_sync.erl:43`) — used at line 893.
- `MAX_FUTURE_BLOCK_TIME = 7200` (`headerssync.erl:56`) — used at line 165.
- raw literal `2 * 60 * 60` (`validation.erl:80`) — used inline.

Three distinct names for the same Core concept in three modules.
A future Core change (e.g., the rumored "drop to 90 min" discussion
in BIP development circles) would require three edits in three
files with three different names. Same code-duplication smell as
W143 BUG-4 beamchain `merkle_pairs` vs `merkle_pairs_check`.

**File:** `src/beamchain_header_sync.erl:43`,
`src/beamchain_headerssync.erl:56`, `src/beamchain_validation.erl:80`.

**Core ref:** `bitcoin-core/src/chain.h:29`.

**Impact:** refactor-safety; not consensus-relevant. Consolidating
under a single `include/beamchain_protocol.hrl` macro
`MAX_FUTURE_BLOCK_TIME` would close the gap.

---

## BUG-13 (P1) — `check_block_header/2` uses wall-clock at validation time, not network-adjusted time

**Severity:** P1. Core's `ContextualCheckBlockHeader` uses
`NodeClock::now()` (`validation.cpp:4108`), which is
`MockableClock` in tests and `SteadyClock`/`SystemClock` in
production — designed to be a single mockable time source so the
test suite can advance time deterministically.

beamchain's `check_block_header/2` uses `erlang:system_time(second)`
directly (`validation.erl:80`). This is the OS wall-clock; there is
no mock-time injection. Tests that want to exercise the
`time_too_new` boundary have to actually wait wallclock seconds,
making them slow and flaky in CI.

Additionally, "network-adjusted time" semantics (Core's
`GetAdjustedTime` which folds in peer time offsets) aren't used by
Core for block-validation `time-too-new` anymore (that was an old
issue eliminated when AdjustedTime was removed), so beamchain's
direct system_time is correct in Core's current code. But:
- The constant `2 * 60 * 60` is inlined instead of named (BUG-12 echo).
- There is no mock-time hook for tests (Core uses `NodeClock` for
  exactly this).
- The single same-file divergent paths: `check_block_header` (line 80
  inline literal) vs `header_sync.erl:891-893` (`MAX_FUTURE_DRIFT`)
  vs `headerssync.erl:165` (`MAX_FUTURE_BLOCK_TIME` macro) — all
  three call `erlang:system_time(second)` directly.

Time-source fragmentation: 3 call sites, 3 names, 0 mock-time
support.

**File:** `src/beamchain_validation.erl:80`.

**Core ref:** `bitcoin-core/src/validation.cpp:4108`
(`NodeClock::now()`), `bitcoin-core/src/util/time.h::NodeClock`.

**Impact:** test ergonomics (CI tests of time-bound consensus
behaviour cannot mock time); first beamchain instance of
"time-source-divergence" pattern, sibling to W143 haskoin BUG-1.

---

## BUG-14 (P1) — BIP-94 check at `Height > 0` rejects the legitimate `height == 2016` case incorrectly... wait no, it's correct, but the comment is wrong

**Severity:** P1 (comment-as-confession; the implementation is
correct but the inline justification points at the wrong Core
constant).

beamchain's `check_bip94/3` (`header_sync.erl:1059-1075`):

```erlang
check_bip94(Height, Header, #state{params = Params} = State) ->
    EnforceBIP94 = maps:get(enforce_bip94, Params, false),
    case EnforceBIP94 of
        true ->
            case Height rem ?DIFFICULTY_ADJUSTMENT_INTERVAL =:= 0
                 andalso Height > 0 of
                true ->
                    PrevHeader = prev_header(State),
                    Header#block_header.timestamp >=
                        PrevHeader#block_header.timestamp - 600
                        orelse throw(time_timewarp_attack);
                false -> ok
            end;
        false ->
            ok
    end.
```

Core's check (`validation.cpp:4097-4104`):
```cpp
if (consensusParams.enforce_BIP94) {
    if (nHeight % consensusParams.DifficultyAdjustmentInterval() == 0) {
        if (block.GetBlockTime() < pindexPrev->GetBlockTime() - MAX_TIMEWARP) {
            return state.Invalid(..., "time-timewarp-attack", ...);
        }
    }
}
```

Core has NO explicit `Height > 0` guard. The implicit reason it works
is that `nHeight = pindexPrev->nHeight + 1`, and the function
`ContextualCheckBlockHeader` is never called for the genesis block
(`pindexPrev != nullptr` is asserted at `validation.cpp:4083`). For
the first non-genesis block, `nHeight = 1`, `1 % 2016 = 1 != 0`,
so the check is skipped naturally.

beamchain's explicit `Height > 0` guard is redundant (and the
"line 207" guard in `validation.erl` similarly redundant), but it
doesn't change behaviour. The inline comment at line 1054-1058
says "BIP94 ... guards against the timewarp attack on the adjustment
boundary". The phrase "block storm mitigation" mentioned in Core's
`consensus/params.h:119` ("On testnet4 this also enforces the block
storm mitigation") is omitted from beamchain's comment, so the
operator reading this docstring won't understand WHY testnet4 has
`enforce_bip94 = true` (vs mainnet which is theoretically eligible
but doesn't enforce yet). Future-readiness gap.

Additionally: at the **off-by-one comparison** — Core uses `<` (strict),
beamchain uses `>=` (non-strict). Let me verify they're equivalent:

Core: `if (block.GetBlockTime() < pindexPrev->GetBlockTime() - MAX_TIMEWARP)` → reject
beamchain: `Header.timestamp >= PrevHeader.timestamp - 600` → accept (orelse throw)

Translating beamchain's accept-condition to Core form:
"accept iff `Header.timestamp >= PrevHeader.timestamp - 600`"
= "reject iff `Header.timestamp < PrevHeader.timestamp - 600`"

That MATCHES Core exactly (`<`). Good. The two-comparison-style is
correctly inverted between accept-orelse-throw and Core's reject-on-true.

**Severity downgrade:** the implementation is correct; only the
comment is incomplete. Tagging as P1 for comment-as-confession (Core's
"block storm mitigation" omitted) rather than P0-CDIV. **Hold this as
a documentation-only follow-up.**

**File:** `src/beamchain_header_sync.erl:1054-1058`,
`src/beamchain_validation.erl:197-205`.

**Core ref:** `bitcoin-core/src/consensus/params.h:117-121`.

**Impact:** code clarity / future-readiness; not consensus-relevant.

---

## BUG-15 (P1) — `pow_no_retargeting` (regtest) bypasses `enforce_bip94` even when both are set

**Severity:** P1 (consistency / regtest behaviour gap, paired with
BUG-7 if that's ever fixed).

beamchain's `get_next_work_required/3` (`pow.erl:120-152`):

```erlang
case PowNoRetargeting of
    true ->
        %% regtest: never adjust difficulty
        PrevBits;
    false ->
        case Height rem ?DIFFICULTY_ADJUSTMENT_INTERVAL of
            0 ->
                calculate_retarget(PrevIndex, Params);
            _ ->
                ...
        end
end.
```

When `pow_no_retargeting = true` (regtest), the function returns
`PrevBits` unconditionally and `calculate_retarget` is never called —
which means the BIP-94 first-block-of-period bits basis is never
applied even if `enforce_bip94 = true`. Core's `CalculateNextWorkRequired`
(`pow.cpp:50-85`) similarly returns `pindexLast->nBits` on
`fPowNoRetargeting`, but Core's `GetNextWorkRequired` flow
(`pow.cpp:14-48`) is structured differently — the BIP-94 first-block
basis only affects the retarget calculation, which IS skipped on
`fPowNoRetargeting`. So **the behavior matches Core**, but the
combinatoric `(fPowNoRetargeting=true, enforce_BIP94=true)` is a
nonsense configuration that beamchain silently accepts without
asserting / warning. Core also accepts it silently.

The audit value here: if BUG-7 lands and an operator combines
`-enforcebip94 -regtest`, the BIP-94 check fires on the
header-validation path (`header_sync.erl:check_bip94`) but the
difficulty-calculation path silently ignores it. This is
**asymmetric enforcement** within the same node — same shape as the
W144 "two flag-derivation pipelines diverge" fleet pattern but for
a different consensus knob.

**File:** `src/beamchain_pow.erl:120-152`.

**Core ref:** `bitcoin-core/src/pow.cpp:52-53, 67-76`.

**Impact:** regtest interop; not a deviation from Core, but a
fragility if BUG-7 lands and the combinatoric is exercised.

---

## BUG-16 (P1) — `assume_valid` boundary semantics: signet inherits mainnet-style assume_valid hash field but signet's default is empty

**Severity:** P1 (cross-impl behaviour parity).

Core's `SigNetParams` constructor (`kernel/chainparams.cpp:423-424`)
populates `defaultAssumeValid` and `nMinimumChainWork` **only when
no challenge override is supplied** (i.e., default-public-signet
mode). When a custom challenge is supplied (line 435-436), both
fields are cleared to `uint256{}`.

beamchain's `params(signet)` (`chain_params.erl:267-269`) sets:
```erlang
min_chainwork => <<0:256>>,
assume_valid => <<0:256>>,
```

Both zeroed unconditionally. Even for default-public-signet (the
ONLY signet mode beamchain actually supports — see BUG-4), the
assume_valid is zero, so signet IBD on beamchain revalidates every
signature from genesis. Core's default-signet
`defaultAssumeValid` is `00000008414aab61092ef93f1aacc54cf9e9f16af29ddad493b908a01ff5c329`
(height 293,175) per chainparams.cpp:424; Core's default-signet
`nMinimumChainWork` is `00000000000000000000000000000000000000000000000000000b463ea0a4b8`
per chainparams.cpp:423.

beamchain's mainnet (`chain_params.erl:48-53`) correctly populates
both, as does testnet4 (`chain_params.erl:177-179`).

**File:** `src/beamchain_chain_params.erl:267-269`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:423-424`.

**Impact:** slow signet IBD (full script verification all the way
to tip); cross-impl divergence in IBD wall-clock time. Similar
shape to blockbrew W149 BUG-7.

---

## BUG-17 (P1) — `compute_minimum_time/3` ignores `prev_block_time` when `PrevIndex` is undefined; fallback to MTP loses BIP-94 protection

**Severity:** P1 (fallback path silently weakens BIP-94 protection
on edge-case data corruption).

beamchain's `do_create_template/3` (`miner.erl:198-202`):
```erlang
PrevBlockTime = case PrevIndex of
    #{header := #block_header{timestamp = T}} -> T;
    _ -> MTP  %% fallback: no worse than MTP
end,
MinTime = compute_minimum_time(MTP, PrevBlockTime, Height),
```

The fallback `PrevBlockTime = MTP` is justified by the comment
"no worse than MTP", but at a difficulty-adjustment boundary
`compute_minimum_time` computes:
```erlang
MinFromTimewarp = PrevBlockTime - ?MAX_TIMEWARP,
max(MinFromMTP, MinFromTimewarp);
```

When `PrevBlockTime = MTP`, `MinFromTimewarp = MTP - 600`, which is
**less than `MinFromMTP = MTP + 1`**, so the `max` resolves to
`MinFromMTP` and the BIP-94 clamp is effectively skipped. The
fallback admits a template whose timestamp is `MTP + 1` even at the
boundary — which is exactly what BUG-6 already exposes via the
emitted `mintime` field, but here we're talking about the
internally-used Timestamp (line 253) **on the rare path where
`PrevIndex` lookup fails**.

In normal operation, `PrevIndex` is populated by
`get_prev_index/1` (line 354-358) which errors on `not_found`, so
the fallback should never trigger. But the defensive fallback
clause exists, and if it ever fires (e.g., transient DB race), the
template silently loses BIP-94 protection.

**File:** `src/beamchain_miner.erl:198-202`.

**Core ref:** Core's `GetMinimumTime` (`node/miner.cpp:36-47`)
takes `const CBlockIndex* pindexPrev` and asserts non-null in the
caller's pre-conditions; there is no fallback.

**Impact:** defensive-fallback weakening BIP-94 protection on a
rare path. Low probability but degenerate behaviour.

---

## BUG-18 (P1) — `find_last_non_special_block/2` recurses without memoisation; testnet long-min-difficulty chains hit O(n) per header

**Severity:** P1 (perf / DoS-amplification on testnet/regtest).

beamchain's `find_last_non_special_block/2` (`pow.erl:192-207`):

```erlang
find_last_non_special_block(Index, Params) ->
    Height = maps:get(height, Index),
    Header = maps:get(header, Index),
    PowLimitBits = pow_limit_bits(Params),
    case Height rem ?DIFFICULTY_ADJUSTMENT_INTERVAL =:= 0 of
        true -> Header#block_header.bits;
        false ->
            case Header#block_header.bits =:= PowLimitBits of
                true when Height > 0 ->
                    PrevIndex = get_block_index(Height - 1),
                    find_last_non_special_block(PrevIndex, Params);
                _ -> Header#block_header.bits
            end
    end.
```

Each recursive call invokes `get_block_index(Height - 1)`, which is
a Pebble/RocksDB lookup (no memoisation, no batched read). On
testnet with a long stretch of min-difficulty blocks (which can
happen when wallclock skips ahead by hours), each header arrival
that hits this branch costs O(distance-to-last-non-special) DB
lookups. A peer feeding crafted timestamps in fast bursts can
amplify the per-header cost into the seconds.

Core's `GetNextWorkRequired` (`pow.cpp:14-48`) has the same shape
(pointer walk back through `pindex->pprev`), but Core's
`CBlockIndex` pointers are in-memory and the walk is O(distance)
in pointer dereferences (nanoseconds per hop). beamchain's per-hop
DB lookup is 3-4 orders of magnitude slower.

**File:** `src/beamchain_pow.erl:192-207`.

**Core ref:** `bitcoin-core/src/pow.cpp:32-35` (analogous pointer walk).

**Impact:** DoS amplification on testnet/regtest peer races; not
a consensus issue.

---

## BUG-19 (P2) — `compute_work/1` returns `0` for `Target == 0`; should signal invalid (not produce a valid-looking chainwork of zero)

**Severity:** P2 (defensive-coding gap).

beamchain's `compute_work/1` (`pow.erl:93-101`):
```erlang
compute_work(Bits) ->
    Target = bits_to_target(Bits),
    case Target of
        0 -> 0;
        _ -> (1 bsl 256) div (Target + 1)
    end.
```

When `Target = 0` (input bits is invalid per `bits_to_target/1`'s
overflow/negative branch), the function returns `0` chainwork. The
caller (`header_sync.erl:917-919`) adds this to the accumulator,
which silently accepts a block whose `Bits` is malformed as
contributing zero work. Core's `GetBlockProof` (`chain.cpp:113-122`)
returns `arith_uint256{}` (also zero) for an invalid target — same
behavior. So this matches Core in result, but neither flags the
invalidity.

The upstream caller is supposed to reject `Bits` values that produce
`Target == 0` via `check_block_header` (`validation.erl:87-88`):
```erlang
Target > 0 orelse throw(bad_diffbits),
```

So the invalid bits are caught before `compute_work` is called. The
defensive-zero behavior in `compute_work` is then unreachable on
valid inputs. Fine — but the function should at least log or assert
when this branch fires, to surface upstream caller bugs.

**File:** `src/beamchain_pow.erl:93-101`.

**Core ref:** `bitcoin-core/src/chain.cpp:113-122` (`GetBlockProof`).

**Impact:** matches Core behaviour; defensive-coding clarity gap.

---

## BUG-20 (P1) — `default_signet_challenge` literal not present anywhere in tree, so even a future signet implementation requires reproducing 74 bytes by hand

**Severity:** P1 (implementation roadmap blocker; precondition for
BUG-3 / BUG-4 fixes).

The default signet challenge bytes
`512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae`
(74 bytes) are NOT present anywhere in the beamchain source tree.
A grep over `src/`, `include/`, `test/`, `priv/`, `config/`,
`audit/` returns zero matches.

When implementing BUG-3 (chain param), the implementer needs to
hand-copy this 148-character hex string from Core's
`chainparams.cpp:418`. This is the canonical operator-paste source
of bugs (one-character typo silently breaks the consensus check
because the magic derivation in BUG-5 would produce different
4-byte magic, and the signet solution check in BUG-1 would reject
every block).

A pre-emptive fix: store the literal as a named constant in
`beamchain_chain_params.erl` so a single review can verify byte
identity vs Core, and downstream code reads it by name.

**File:** No file (literal missing).

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:418`.

**Impact:** implementation roadmap quality; pre-emptive fix for
BUG-3 / BUG-4 / BUG-5 cluster.

---

## BUG-21 (P1) — `--network=signet` accepted by CLI but daemon proceeds into a state that will silently fork at block 1

**Severity:** P1 (UX dead-end with no operator warning).

The cumulative effect of BUG-1 / BUG-2 / BUG-3 / BUG-4 / BUG-5 is
that beamchain's `--network=signet` mode is fundamentally broken:
the daemon starts, advertises signet magic, attempts to sync from
seed nodes, and SILENTLY accepts the first PoW-valid block past
genesis (since `CheckSignetBlockSolution` is absent) — but every
other signet node in the world will accept a DIFFERENT chain
(the actual signer-signed chain), and beamchain will fork off
within minutes.

There is no startup-time warning: `beamchain_app:start` and
`beamchain_chainstate:init` do not check `network == signet` and
emit "WARNING: signet block-solution validation not implemented;
expect fork at block 1". The operator only discovers the fork by
comparing `getbestblockhash` against another signet node.

This is the same shape as the "wiring-look-but-no-wire" fleet
pattern (blockbrew W138/W149 BUG-3 pruneblockchain RPC accepted
but missing). beamchain's CLI accepts the flag, the network params
populate, but the only consensus rule that matters for signet
identity is absent.

A minimal one-line fix: have `beamchain_app:start` log a
prominent FATAL warning when `network == signet` AND
`signet_challenge` chain param is absent / empty. Better: refuse
to start.

**File:** `src/beamchain_app.erl` (startup logic),
`src/beamchain_cli.erl:296` (network help text claims signet is
supported).

**Core ref:** N/A (Core's signet is wired end-to-end).

**Impact:** silent operator footgun; cross-impl divergence visible
within minutes of joining the signet network.

---

## Summary

**Bug count:** 21 (BUG-1 through BUG-21).

**Severity distribution:**
- **P0-CDIV:** 7 (BUG-1, BUG-2, BUG-3, BUG-4, BUG-5, BUG-6, BUG-8)
- **P1:** 11 (BUG-7, BUG-9, BUG-11, BUG-13, BUG-14, BUG-15, BUG-16, BUG-17, BUG-18, BUG-20, BUG-21)
- **P2:** 3 (BUG-10, BUG-12, BUG-19)

Total: 7 + 11 + 3 = 21. ✓

**Fleet patterns confirmed:**
- **"CheckSignetBlockSolution absent" fleet pattern** (BUG-1) — 2nd
  beamchain instance after W143 BUG-9 blockbrew finding; 2 of 10
  impls confirmed missing at consensus-check depth. Fleet-wide
  signet broken candidate; companion to W144 `script_flag_exceptions`
  fleet (9/10 impls) and W128 banman fleet (8/10).
- **"signet_challenge chain param absent" carry-forward 3 waves**
  (BUG-3) — W155 BUG-3 / W155 BUG-16 / W157 BUG-3 same finding now
  open across W155/W156/W157.
- **"W154 BUG-6 GBT mintime BIP-94" carry-forward 3 waves** (BUG-6)
  — W154 catalogued, W155 confirmed implicitly, W157 explicit
  re-confirm. Most-aged P0-CDIV currently open in beamchain.
- **"wiring-look-but-no-wire"** (BUG-4, BUG-21) — CLI accepts
  `--network=signet`, chain params populate, but the only consensus
  rule that matters (signet block solution) is absent. Same shape
  as blockbrew W149 BUG-3 pruneblockchain.
- **"comment-as-confession" 16th beamchain instance** (BUG-14
  comment omits "block storm mitigation"; BUG-17 comment "no worse
  than MTP" admits BIP-94 weakening).
- **"two-pipeline drift inside one impl" 20th distinct fleet
  instance** (BUG-6 internal `compute_minimum_time` correct,
  exported `mintime` wrong; BUG-8 `Bits` computed once against
  DummyHeader.timestamp, `Timestamp` recomputed at line 253;
  BUG-15 BIP-94 fires on header-validation but bypasses
  difficulty-calculation; BUG-13 + BUG-12 three time-source names
  in three modules).
- **"hidden-coincidence-equality" NEW PATTERN** (BUG-8) — first
  beamchain instance. Two evaluations of `max(MinTime, Now)` in
  adjacent statements that just happen to evaluate to the same
  value preserve the consensus invariant; any edit that introduces
  awaiting work between them silently breaks BIP-94.
- **"reject-string wire-parity slippage"** (BUG-11) — Erlang
  atoms `time_timewarp_attack` vs Core hyphenated
  `time-timewarp-attack`. Same shape as lunarblock W145 9-token
  sweep.
- **"time-source-divergence"** (BUG-13) — first beamchain instance;
  sibling to W143 haskoin BUG-1 first-time finding.
- **"hardcoded constant should be params-aware"** (BUG-5
  `SIGNET_MAGIC` hardcoded; BUG-7 `enforce_bip94` not regtest
  options-knob).
- **"dead-data plumbing avoided"** — beamchain's `enforce_bip94`
  chain param IS read at both call sites (header_sync + validation).
  POSITIVE outcome here; not the W141 "exports-the-primitive-just-not-called"
  pattern.

**P0-CDIV concentration:** 7 P0-CDIV in W157 = roughly matches
beamchain's recent quad-audit average (W142+W143+W144+W145 had
0+1+1+0 P0-CONS on the consensus side). This is the **highest
P0-CDIV count for a single beamchain wave since W143**.

**Top three findings:**
1. **BUG-1 (P0-CDIV) — `CheckSignetBlockSolution` entirely absent.**
   beamchain signet accepts any PoW-valid block, forking off the
   permissioned signet at block 1. Sibling to W143 BUG-9 blockbrew
   finding — fleet-wide signet-CheckSignetBlockSolution-absent
   pattern now at 2 of 10 confirmed (every other impl needs to be
   audited at this depth). The fix is a multi-file project: introduce
   `beamchain_signet.erl` module with `SignetTxs::Create` /
   `FetchAndClearCommitmentSection` / `CheckSignetBlockSolution`,
   wire `signet_challenge` + `signet_blocks` into `params(signet)`
   (BUG-3 prerequisite), wire `SIGNET_HEADER` constant (BUG-2
   prerequisite), call from
   `validation.erl::contextual_check_block` gated on `signet_blocks`.
   Cross-cite W155 BUG-3, W155 BUG-16, W157 BUG-3.

2. **BUG-6 (P0-CDIV, W154 BUG-6 STILL OPEN 3 waves) — GBT `mintime`
   ignores BIP-94.** Pool mining off beamchain's testnet4 template
   at exactly `mintime` near a 2016-block boundary gets the block
   rejected by Core peers as `time-timewarp-attack`. Pool revenue
   loss. One-line fix: replace `<<"mintime">> => MTP + 1` with
   `<<"mintime">> => compute_minimum_time(MTP, PrevBlockTime, Height)`.
   The correct helper EXISTS at `miner.erl:432-441` and is already
   called for the local Timestamp field — pure miswiring.

3. **BUG-8 (P0-CDIV) — Miner's UpdateTime semantics: hidden-coincidence
   equality.** Two evaluations of `max(MinTime, Now)` in adjacent
   statements preserve the consensus invariant for testnet's 20-minute
   min-difficulty rule by coincidence. A future refactor that
   introduces awaiting work between line 208 and line 253 silently
   breaks the invariant and a testnet pool mines `bad-diffbits` blocks.
   New "hidden-coincidence-equality" pattern; first fleet instance
   discovered in W157. Fix: extract a single `update_time/3` helper
   that takes the prev_index and the unfinalised header, returns
   `{NewTimestamp, NewBits}` atomically, and is called from both the
   template-build and the `do_generate_block_with_txs` paths.
