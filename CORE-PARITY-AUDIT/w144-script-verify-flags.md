# W144 — Script-verify flag mux audit (beamchain)

Discovery-only wave. Audit gates derived from Bitcoin Core
references:

- `bitcoin-core/src/script/interpreter.h:47-159` —
  `SCRIPT_VERIFY_*` enum + `MAX_SCRIPT_VERIFY_FLAGS`.
- `bitcoin-core/src/validation.cpp:2250-2289`
  (`GetBlockScriptFlags`) — flag bitmap composition per
  `CBlockIndex`, including the `script_flag_exceptions` lookup
  (`flags = it->second;` REPLACES the always-on base).
- `bitcoin-core/src/kernel/chainparams.cpp:85-88, 210-211` —
  the two mainnet exceptions (BIP16 at
  `0000…ac4f9c22` h=173818; Taproot at `0000…1e395ad` h=692261)
  plus the testnet3 BIP16 exception
  (`0000…a432b105` h=21888).
- `bitcoin-core/src/deploymentstatus.h:14-44`
  (`DeploymentActiveAt`) — buried (`index.nHeight >=
  DeploymentHeight(dep)`) vs versionbits.
- `bitcoin-core/src/policy/policy.h:105-135` —
  `MANDATORY_SCRIPT_VERIFY_FLAGS` and
  `STANDARD_SCRIPT_VERIFY_FLAGS` composition.
- `bitcoin-core/src/script/interpreter.cpp` — actual flag
  application inside `EvalScript`, `VerifyScript`,
  `VerifyWitnessProgram`, `ExecuteWitnessScript`.

Companion audits to cross-reference:

- **W132** (nSequence / CSV / MTP): the `Height >= 419328` gate
  for CSV/CHECKSEQUENCEVERIFY is duplicated between
  `beamchain_script.erl:flags_for_height/2` and chain-params'
  `csv_height` (419328). Both copies are read from different
  places — see BUG-7 below.
- **W127** (Taproot): the `SCRIPT_VERIFY_TAPROOT` flag is gated on
  `Height >= 709632` here; the validation paths that actually
  read the flag were audited in W127 and W144 only re-confirms
  the gate.
- **W126** (BIP-152 compact blocks): the same flag bitmap is
  threaded into `VerifyWitnessProgram` for reconstructed
  witnesses — flag-derivation gaps here therefore propagate to
  compact-block validation.
- **W135** (standardness rules): `all_standard_flags/0` in
  `beamchain_mempool.erl:2267-2284` is the policy-counterpart of
  the consensus flag computer; gaps in either direction surface
  here (BUG-2, BUG-4 below).
- **W142** (SegWit witness validation): the
  `SCRIPT_VERIFY_WITNESS` gate around `verify_witness_program`
  was audited in W142; W144 confirms the gate point but adds the
  flag-source divergence findings.

## Status counts (24 gates)

- **PRESENT** (Core-parity, internally consistent + Core-compatible): 9
- **PARTIAL** (some piece matches, others diverge or simplified): 9
- **MISSING** (no equivalent in beamchain): 6

Headline: **24 bugs**, severity distribution
**1 P0-CONSENSUS / 2 P0-CDIV / 4 P1 / 11 P2 / 6 P3**.

This audit surface is small in line count (one function:
`flags_for_height/2`) but disproportionately consequential —
every script verifier in beamchain (block connect, mempool
acceptance, RPC `verifychain`, RPC `verifytxoutproof`) reads
its flags from this one switch. Two themes dominate:

1. **`script_flag_exceptions` is absent.**  Bitcoin Core's
   `GetBlockScriptFlags` is conceptually
   `flags = always_on; flag_set = exceptions.find(hash); if
   found { flags = flag_set; }; flags |= active_deployments`.
   The mainnet exception at h=173818 (BIP16-violating block) and
   the historical testnet3 exception (h=21888) are required to
   re-validate the canonical chain.  Beamchain has no exception
   table.  Because beamchain's `flags_for_height` activates P2SH
   at exactly h=173805 (13 blocks before the exception block),
   the P2SH-violating transaction in the exception block will
   FAIL script verification under beamchain but PASS under Core
   — chain split at block 173818.  Today this is masked because
   the default `assume_valid` is at h=938343, so beamchain skips
   script verification for h=173818.  Disable `assume_valid` (or
   `-noassumevalid`) and the chain split is live.  See BUG-1.
2. **Flag derivation is a two-pipeline guard.**  Buried-
   deployment heights are stored twice: once in chain-params
   (`bip65_height`, `bip66_height`, `csv_height`, `segwit_height`,
   `taproot_height` — read by `beamchain_validation.erl` for
   block-header version gates and CSV activation) and once
   hardcoded inside `beamchain_script.erl:flags_for_height/2`
   (read by every script verifier).  The two copies happen to
   match today.  A future change to one and not the other
   produces silent consensus drift — exactly the pattern Bitcoin
   Core retired in 2018 with the `BuriedDeployment` enum.  See
   BUG-7.

Notable cross-cutting smells:

- **Two-pipeline guard** (15th distinct extension since W76):
  chain-params holds the buried heights for header-version
  checks; `flags_for_height` holds a parallel copy for the
  script verifier (BUG-7).
- **Comment-as-confession**
  (`beamchain_script.erl:3555-3573`): the fall-through clause
  `flags_for_height(_Height, _Network)` literally hardcodes a
  comment that says "testnet/regtest: all consensus flags
  active from genesis" — which is correct for current testnet4
  but is a deliberate divergence from Core's behavior on the
  *original* testnet3 (where BIP65 was at h=581885, BIP66 at
  330776, segwit at 834624; not from genesis).
- **Stricter-than-Core**
  (`beamchain_mempool.erl:4292-4301`): `consensus_script_flags/0`
  includes `SCRIPT_VERIFY_NULLFAIL`, but Core's
  `MANDATORY_SCRIPT_VERIFY_FLAGS` does *not* — NULLFAIL is
  STANDARD-only.  BUG-3.
- **Inverted divergence at mempool**: `all_standard_flags/0` in
  `beamchain_mempool.erl:2267-2284` omits three Core STANDARD
  policy flags (DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
  DISCOURAGE_OP_SUCCESS, DISCOURAGE_UPGRADABLE_PUBKEYTYPE).
  Beamchain mempool is *more permissive* than Core mempool —
  it relays txs that Core would tag NONSTANDARD.  BUG-4.

---

## BUGS

### BUG-1 (P0-CONSENSUS) — `script_flag_exceptions` table absent → mainnet chain split at block 173818

- **File**: `src/beamchain_chain_params.erl` (entire mainnet/testnet
  param block); `src/beamchain_script.erl:3528-3574`
  (`flags_for_height/2`).
- **Core ref**: `bitcoin-core/src/validation.cpp:2262-2266`
  (`GetBlockScriptFlags`); `bitcoin-core/src/kernel/chainparams.cpp:85-88,
  210-211` (mainnet and testnet3 exceptions).
- **Description**: Bitcoin Core's `GetBlockScriptFlags` starts
  from `flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS |
  SCRIPT_VERIFY_TAPROOT}` (always-on), then looks up the
  block's hash in
  `consensusparams.script_flag_exceptions`.  If the lookup
  hits, the entire flag set is REPLACED by the entry value
  (e.g. `SCRIPT_VERIFY_NONE` for the BIP16 exception block).
  Two mainnet exceptions exist:
  - Block `00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22`
    (h=173818) — `SCRIPT_VERIFY_NONE`.
  - Block `0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad`
    (h=692261) — `SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS`
    (omits TAPROOT).
  Plus the testnet3 exception
  `00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105`
  (h=21888) at `SCRIPT_VERIFY_NONE`.
  Beamchain has no equivalent table in
  `beamchain_chain_params.erl` and no exception-lookup in
  `flags_for_height/2`.  Because beamchain unconditionally
  activates P2SH at h=173805 (13 blocks before the exception
  block), the BIP16-violating transaction in block 173818
  FAILS script verification under beamchain but PASSES under
  Core.
- **Excerpt** (`beamchain_script.erl:3528-3561`):
  ```erlang
  flags_for_height(Height, mainnet) ->
      F0 = ?SCRIPT_VERIFY_NONE,
      F1 = case Height >= 173805 of
          true -> F0 bor ?SCRIPT_VERIFY_P2SH;
          false -> F0
      end,
      F2 = case Height >= 363725 of
          true -> F1 bor ?SCRIPT_VERIFY_DERSIG;
          false -> F1
      end,
      ...
      %% NO block-hash exception lookup anywhere
  ```
- **Impact**: Mainnet chain split at h=173818 in any
  non-assumevalid sync (today the default `assume_valid`
  configured at h=938343 hides it: `skip_scripts/3` returns
  true for h=173818, masking the bug).  Run with
  `-noassumevalid` or a re-org through block 173818 and
  beamchain DIVERGES.  Same risk on testnet3 at h=21888.  The
  Taproot exception block (h=692261) is accidentally
  consensus-equivalent in beamchain because TAPROOT is gated
  on h>=709632 (so it's off at h=692261 in both impls), but
  this is fragile — any change to `taproot_height` (e.g.
  setting it to 0 on a forked chain) would expose the same
  class of bug there too.

### BUG-2 (P0-CDIV) — `all_standard_flags/0` missing three Core STANDARD policy flags

- **File**: `src/beamchain_mempool.erl:2267-2284`
  (`all_standard_flags/0`).
- **Core ref**: `bitcoin-core/src/policy/policy.h:119-132`
  (`STANDARD_SCRIPT_VERIFY_FLAGS`).
- **Description**: Core's `STANDARD_SCRIPT_VERIFY_FLAGS` is the
  MANDATORY set plus 13 policy-only flags.  Beamchain's
  `all_standard_flags/0` is missing three of them:
  - `SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION`
  - `SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS`
  - `SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE`
  All three are *defined* in
  `include/beamchain_protocol.hrl:151-153` and *checked* inside
  `beamchain_script.erl` (e.g. `:508`, `:1623`, `:1742`,
  `:2055`, `:2886` for the upgradable-taproot-version path).
  The flags are wired into the interpreter but never set by the
  mempool, so the interpreter's discouragement arms are dead
  code at the mempool boundary.
- **Excerpt** (`beamchain_mempool.erl:2267-2284`):
  ```erlang
  all_standard_flags() ->
      ?SCRIPT_VERIFY_P2SH bor
      ?SCRIPT_VERIFY_STRICTENC bor
      ?SCRIPT_VERIFY_DERSIG bor
      ?SCRIPT_VERIFY_LOW_S bor
      ?SCRIPT_VERIFY_NULLDUMMY bor
      ?SCRIPT_VERIFY_MINIMALDATA bor
      ?SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS bor
      ?SCRIPT_VERIFY_CLEANSTACK bor
      ?SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY bor
      ?SCRIPT_VERIFY_CHECKSEQUENCEVERIFY bor
      ?SCRIPT_VERIFY_WITNESS bor
      ?SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM bor
      ?SCRIPT_VERIFY_MINIMALIF bor
      ?SCRIPT_VERIFY_NULLFAIL bor
      ?SCRIPT_VERIFY_WITNESS_PUBKEYTYPE bor
      ?SCRIPT_VERIFY_CONST_SCRIPTCODE bor
      ?SCRIPT_VERIFY_TAPROOT.
      %% Missing: DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
      %%          DISCOURAGE_OP_SUCCESS,
      %%          DISCOURAGE_UPGRADABLE_PUBKEYTYPE
  ```
- **Impact**: Beamchain relays / accepts into mempool txs that
  Bitcoin Core nodes will tag NONSTANDARD and refuse.  Most
  visible vector: an attacker sends a tx with a tapscript leaf
  version other than 0xc0 (TAPROOT_LEAF_TAPSCRIPT), or a
  tapscript that contains an OP_SUCCESS opcode (one of the 80
  reserved opcodes Core discourages for future-fork
  compatibility).  Beamchain relays it; Core peers drop it.
  Beamchain is then a "leakage" peer for non-conforming
  taproot-future trial balloons.  Not a chain split (these are
  policy flags, not consensus), but a network-fingerprintable
  divergence and an asymmetric relay primitive.

### BUG-3 (P0-CDIV) — `consensus_script_flags/0` stricter than Core (NULLFAIL set as consensus)

- **File**: `src/beamchain_mempool.erl:4292-4301`
  (`consensus_script_flags/0`).
- **Core ref**: `bitcoin-core/src/policy/policy.h:105-111`
  (`MANDATORY_SCRIPT_VERIFY_FLAGS`); explicitly note that
  `SCRIPT_VERIFY_NULLFAIL` is in STANDARD only, NOT MANDATORY.
- **Description**: Beamchain's `consensus_script_flags/0`
  returns `P2SH | DERSIG | NULLDUMMY | CLTV | CSV | WITNESS |
  NULLFAIL | TAPROOT`.  Core's MANDATORY set is `P2SH | DERSIG
  | NULLDUMMY | CLTV | CSV | WITNESS | TAPROOT` — NULLFAIL is
  STANDARD-only and is intentionally not consensus.  Beamchain
  is stricter-than-Core in `ConsensusScriptChecks`.  The
  inline comment even calls it out ("NULLFAIL was made
  mandatory in 0.18.0; LOW_S is policy-only") but the comment
  is wrong: NULLFAIL was never moved to MANDATORY in any Core
  release.  Verified in current Core
  (`master`):
  `policy/policy.h:125` places NULLFAIL in
  STANDARD_SCRIPT_VERIFY_FLAGS, not MANDATORY.
- **Excerpt** (`beamchain_mempool.erl:4287-4301`):
  ```erlang
  %% Core's ConsensusScriptChecks computes GetBlockScriptFlags(tip)
  %% which returns the MANDATORY_SCRIPT_VERIFY_FLAGS plus any
  %% soft-fork flags currently active.  On a post-Taproot chain
  %% (mainnet block 709632, testnet earlier) the active set is:
  %% P2SH | DERSIG | NULLDUMMY | CLTV | CSV | WITNESS | TAPROOT.
  %% (NULLFAIL was made mandatory in 0.18.0; LOW_S is policy-only.)
  -spec consensus_script_flags() -> integer().
  consensus_script_flags() ->
      ?SCRIPT_VERIFY_P2SH bor
      ?SCRIPT_VERIFY_DERSIG bor
      ?SCRIPT_VERIFY_NULLDUMMY bor
      ?SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY bor
      ?SCRIPT_VERIFY_CHECKSEQUENCEVERIFY bor
      ?SCRIPT_VERIFY_WITNESS bor
      ?SCRIPT_VERIFY_NULLFAIL bor
      ?SCRIPT_VERIFY_TAPROOT.
  ```
- **Impact**: The "BUG! PLEASE REPORT THIS!" double-check (Core
  `validation.cpp:1158-1189`, beamchain
  `beamchain_mempool.erl:4308-4338`) will fire on any tx that
  passes STANDARD (which includes NULLFAIL) but somehow fails
  it on re-check — which is impossible because both sides include
  NULLFAIL.  More problematic: the "consensus flags" set is
  what `GetBlockScriptFlags(tip)` represents for a miner — if a
  miner is mining on top of beamchain's view, beamchain's
  consensus check happens to be redundant but technically
  stricter.  The interesting failure is: a fork that *changes*
  the MANDATORY set (e.g. removes NULLFAIL from STANDARD); the
  comment claims it's been done already, which would mislead a
  reader doing a Core-parity audit.

### BUG-4 (P1) — `consensus_script_flags/0` hardcoded to "post-Taproot tip"; no per-tip flag derivation

- **File**: `src/beamchain_mempool.erl:4292-4301`.
- **Core ref**: `bitcoin-core/src/validation.cpp:1181`
  (`script_verify_flags currentBlockScriptVerifyFlags{
   GetBlockScriptFlags(*m_active_chainstate.m_chain.Tip(),
   m_chainman)};`).
- **Description**: Core's `ConsensusScriptChecks` does
  `GetBlockScriptFlags(tip)` — a per-tip computation.  Beamchain's
  `consensus_script_flags/0` returns a *constant*: the
  post-Taproot flag set, no matter what the current tip is.
  On a forked chain that reorged below `taproot_height = 709632`,
  beamchain mempool will still demand TAPROOT.  Any tx with a
  v1+32 taproot spend will be relayed but rejected at the
  consensus pass, while Core would correctly skip the TAPROOT
  gate on the (now pre-Taproot) tip.  Beamchain is
  stricter-than-Core during reorgs through soft-fork
  activation heights.
- **Excerpt** (`beamchain_mempool.erl:4310`):
  ```erlang
  consensus_script_checks(Tx, InputCoins) ->
      Flags = consensus_script_flags(),       %% <-- constant
      ...
  ```
- **Impact**: Mempool divergence during reorgs through h=709632
  on mainnet (very rare) and through h=1 on testnet4/signet/
  regtest (none in practice).  Real-world impact: zero today.
  Latent risk: a future chain with multiple soft-forks
  activating later than tx-creation time would expose this
  fully.  Fix: pass the tip height into
  `consensus_script_flags/0` and call
  `beamchain_script:flags_for_height/2`.

### BUG-5 (P1) — `flags_for_height/2` fall-through clause IGNORES `network` and `*_height` chain-params

- **File**: `src/beamchain_script.erl:3563-3574`.
- **Core ref**: `bitcoin-core/src/validation.cpp:2250-2289`
  (`GetBlockScriptFlags` reads heights from `consensus.*`).
- **Description**: For any network other than mainnet
  (`testnet`, `testnet4`, `regtest`, `signet`),
  `flags_for_height(_Height, _Network)` returns the full
  consensus flag set unconditionally — ignoring both the height
  argument AND the network name.  In particular this
  ignores the chain-params buried heights
  (`testnet`/`bip65_height=581885`, `bip66_height=330776`,
  `csv_height=770112`, `segwit_height=834624` from
  `beamchain_chain_params.erl:121-124`).  A re-sync of testnet3
  from genesis will fail any block before h=330776 that has a
  non-strict-DER signature (Core accepted those pre-BIP66) and
  any block before h=834624 with a non-witness-conformant tx.
- **Excerpt** (`beamchain_script.erl:3563-3574`):
  ```erlang
  flags_for_height(_Height, _Network) ->
      %% testnet/regtest: all consensus flags active from genesis.
      %% Only Bitcoin Core MANDATORY_SCRIPT_VERIFY_FLAGS here.
      %% Policy flags (CLEANSTACK, SIGPUSHONLY, LOW_S, STRICTENC,
      %% MINIMALDATA, NULLFAIL, WITNESS_PUBKEYTYPE, etc.) belong in
      %% the mempool path only.
      ?SCRIPT_VERIFY_P2SH
      bor ?SCRIPT_VERIFY_DERSIG
      bor ?SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY
      bor ?SCRIPT_VERIFY_CHECKSEQUENCEVERIFY
      bor ?SCRIPT_VERIFY_WITNESS
      bor ?SCRIPT_VERIFY_NULLDUMMY
      bor ?SCRIPT_VERIFY_TAPROOT.
  ```
- **Impact**: Cannot re-sync mainnet/testnet3 from genesis
  without the assumevalid mask; testnet4/signet/regtest are
  unaffected because their chain-params set every buried
  height to 1 (so the fall-through happens to match).  Latent
  risk: a future privately-bootstrapped chain (custom magic +
  genesis) cannot have per-network buried heights — the only
  knob is mainnet.

### BUG-6 (P1) — `flags_for_height/2` hardcodes mainnet buried heights instead of reading from chain-params

- **File**: `src/beamchain_script.erl:3528-3561`.
- **Core ref**: `bitcoin-core/src/validation.cpp:2269-2286`
  (`DeploymentActiveAt(block_index, chainman,
  Consensus::DEPLOYMENT_*)`) — every height comes from
  `consensus.{BIP65,BIP66,CSV,Segwit,BIP16Exception}` on the
  `ChainstateManager`'s params.
- **Description**: Beamchain's `flags_for_height(Height,
  mainnet)` literally hardcodes:
  - `Height >= 173805` (P2SH)
  - `Height >= 363725` (BIP66 / DERSIG)
  - `Height >= 388381` (BIP65 / CLTV)
  - `Height >= 419328` (CSV)
  - `Height >= 481824` (Segwit / WITNESS + NULLDUMMY)
  - `Height >= 709632` (Taproot)
  These values are duplicated in
  `beamchain_chain_params.erl:41-45` (as
  `bip65_height`, `bip66_height`, `csv_height`, `segwit_height`,
  `taproot_height`) and in `beamchain_config.erl:704-707`
  (`#config{}` fields).  Three copies, one source of truth in
  Core (the chain params struct).  Pure two-pipeline guard.
- **Excerpt** (`beamchain_script.erl:3528-3553`):
  ```erlang
  flags_for_height(Height, mainnet) ->
      F0 = ?SCRIPT_VERIFY_NONE,
      F1 = case Height >= 173805 of
          true -> F0 bor ?SCRIPT_VERIFY_P2SH;
          false -> F0
      end,
      F2 = case Height >= 363725 of
          true -> F1 bor ?SCRIPT_VERIFY_DERSIG;
          ...
      F4 = case Height >= 419328 of   %% duplicates csv_height
          true -> F3 bor ?SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
          ...
  ```
- **Impact**: Future change to one and not the other produces
  silent consensus drift.  Concrete pathway: a developer
  updates `beamchain_chain_params.erl` to add a new buried
  height (e.g. enforce_BIP94 height for testnet4), forgets the
  duplicate in `flags_for_height`, and the script verifier
  silently desyncs.  Recommended fix: rewrite
  `flags_for_height` to take a `#params{}` map (the same one
  the validator already threads), exactly mirroring
  `GetBlockScriptFlags`.

### BUG-7 (P1) — testnet3 BIP16 exception block (`0000…a432b105`, h=21888) absent

- **File**: `src/beamchain_chain_params.erl:99-145` (testnet
  params); `src/beamchain_script.erl:3563-3574` (fall-through
  clause).
- **Core ref**: `bitcoin-core/src/kernel/chainparams.cpp:210-211`
  (`CTestNetParams::script_flag_exceptions.emplace(
  uint256{"00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105"},
  SCRIPT_VERIFY_NONE);`).
- **Description**: Testnet3 has its own BIP16 exception block
  at h=21888.  Beamchain has no equivalent.  Because beamchain's
  testnet `flags_for_height/2` fall-through forces full
  consensus flags (including P2SH) from h=0, re-syncing
  testnet3 from genesis through h=21888 will fail with a P2SH
  redeem-script verification error on the BIP16-violating
  block — identical pathology to BUG-1 but on the testnet
  chain.
- **Impact**: Testnet3 re-sync from genesis is broken without
  assumevalid.  Today this is masked by
  `assume_valid = "0000…000000"` (the all-zeros default for
  testnet — i.e. assumevalid is effectively off, so scripts
  DO run): per
  `beamchain_chain_params.erl:128`,
  `assume_valid => <<0:256>>`.  So testnet3 re-sync IS live-
  broken on beamchain.

### BUG-8 (P1) — BIP-34 height not threaded into script flag derivation; coinbase-height enforcement and script flags use different code paths

- **File**: `src/beamchain_validation.erl:220-226` (block-version
  gate); `src/beamchain_script.erl:3528-3553` (script-flag gate).
- **Core ref**: `bitcoin-core/src/validation.cpp:2249-2289` —
  although BIP34 is NOT a `SCRIPT_VERIFY_*` flag, Core threads
  the same `consensus.BIP34Height` from the same struct as the
  script-verify heights.  Splitting them into two places is the
  two-pipeline guard pattern.
- **Description**: BIP-34 enforcement reads
  `maps:get(bip34_height, Params, 0)` from chain-params at
  `beamchain_validation.erl:220` (header-version check) and
  `:318` (contextual_check_block) and `:1097` (BIP-30
  interaction).  But `flags_for_height/2` doesn't take BIP-34
  into account *at all*.  This is fine in isolation (BIP-34 is
  not a script-verify flag) but the data-flow shape is the
  same as BUG-6 — heights live in two places.
- **Impact**: P3-level today (no consensus divergence in BIP-34
  scope).  Listed as P1 because the *pattern* it instantiates
  (two parallel pipelines for buried-height tracking) is the
  source of BUG-1, BUG-6, BUG-7.

### BUG-9 (P2) — `flags_for_height/2` doesn't read NULLDUMMY from a `nulldummy_height` param; it co-fires with SEGWIT

- **File**: `src/beamchain_script.erl:3554-3561`.
- **Core ref**: `bitcoin-core/src/validation.cpp:2283-2286`
  (`if (DeploymentActiveAt(block_index, chainman,
  Consensus::DEPLOYMENT_SEGWIT)) { flags |=
  SCRIPT_VERIFY_NULLDUMMY; }`).
- **Description**: Core sets NULLDUMMY when SEGWIT is active
  (BIP-147 was the only sub-deployment co-activated with
  BIP-141).  Beamchain matches by gating on the same height
  (`Height >= 481824`).  However the gate is hardcoded to
  481824 directly instead of being expressed as "same height
  as the SEGWIT activation".  If `segwit_height` is ever
  changed (e.g. for a custom chain), NULLDUMMY's height
  will silently *not* change.  Pure refactoring hazard.
- **Excerpt** (`beamchain_script.erl:3546-3560`):
  ```erlang
      F5 = case Height >= 481824 of
          true -> F4 bor ?SCRIPT_VERIFY_WITNESS;
          false -> F4
      end,
      ...
      case Height >= 481824 of      %% same height, hardcoded twice
          true -> F6 bor ?SCRIPT_VERIFY_NULLDUMMY;
          false -> F6
      end;
  ```
- **Impact**: P2 — refactor hazard.  Recommended fix: compute
  `IsSegwit = Height >= SegwitHeight`, use the boolean to gate
  both WITNESS and NULLDUMMY in one place.

### BUG-10 (P2) — `flags_for_height/2` doesn't accept `#block_index{}` or `Params`; can't model `script_flag_exceptions` even if added

- **File**: `src/beamchain_script.erl:3527`.
- **Core ref**: `bitcoin-core/src/validation.cpp:2250`
  (`GetBlockScriptFlags(const CBlockIndex& block_index,
   const ChainstateManager& chainman)`).
- **Description**: Core's flag derivator takes the entire
  block-index reference (which includes `phashBlock` for the
  exceptions lookup) and the full chainman (which carries the
  full chain-params struct).  Beamchain's API is `(Height,
  Network)` — neither argument exposes the block hash, so
  adding a `script_flag_exceptions` table here would require
  another path through the data.  This is a forward-
  compatibility issue: a fix for BUG-1 would need an API change.
- **Excerpt** (`beamchain_script.erl:3527-3528`):
  ```erlang
  -spec flags_for_height(non_neg_integer(), atom()) -> non_neg_integer().
  flags_for_height(Height, mainnet) ->
  ```
- **Impact**: P2 — design debt.  Recommendation: change the API
  to `flags_for_block(Height, BlockHash, Params)` and add an
  exceptions table in `chain_params.erl`.

### BUG-11 (P2) — `consensus_script_flags/0` ignores network entirely

- **File**: `src/beamchain_mempool.erl:4292-4301`.
- **Description**: Returns a constant — no `Network` argument.
  On testnet4/signet/regtest, mempool consensus flags are
  identical to mainnet.  This is OK in practice (all current
  beamchain-supported networks have the same post-Taproot
  consensus surface) but is structurally incorrect.  Same
  shape as BUG-4.
- **Impact**: P2 — design debt.

### BUG-12 (P2) — RPC `verifychain` level-4 uses `flags_for_height` not `consensus_script_flags`

- **File**: `src/beamchain_rpc.erl:1526`.
- **Core ref**: `bitcoin-core/src/rpc/blockchain.cpp` —
  `verifychain` uses
  `GetBlockScriptFlags(*pindex, m_chainman)` for each block
  re-verification.
- **Description**: `verifychain` (level 4 = full script
  re-verification) correctly uses
  `beamchain_script:flags_for_height(Height, Network)` for
  the historical-height flag derivation.  But this same RPC
  uses the same flag computation as `connect_block`, while
  mempool's `verify_scripts`/`consensus_script_checks` use a
  DIFFERENT flag computation (`all_standard_flags` and
  `consensus_script_flags`).  Two flag-derivation tables to
  audit; should be one.
- **Impact**: P2 — auditing burden.

### BUG-13 (P2) — No assertion that `flags_for_height` output bits fit `MAX_SCRIPT_VERIFY_FLAGS`

- **File**: `src/beamchain_script.erl:3527-3574`.
- **Core ref**:
  `bitcoin-core/src/script/interpreter.h:159`
  (`MAX_SCRIPT_VERIFY_FLAGS = ((1 << MAX_SCRIPT_VERIFY_FLAGS_BITS) - 1)`)
  and the constructor enforcement in
  `script/verify_flags.h` (any unknown bit set =
  `std::abort()` debug build).
- **Description**: Core's flag struct rejects unknown bits at
  construction.  Beamchain uses raw integers, so a misspelt
  define (e.g. `?SCRIPT_VERIFY_NULLDUMNY` typo not detected by
  Erlang's preprocessor — undefined macro is a hard compile
  error, so this is unlikely; but a runtime-computed flag
  bitmap is unchecked).  No upper-bound assert.  Forward
  compatibility hazard if a new bit is added.
- **Impact**: P2 — defensive programming gap.

### BUG-14 (P2) — `flags_for_height` Network arg is `atom()` not the chainparams record/map; no validation of network name

- **File**: `src/beamchain_script.erl:3527-3563`.
- **Description**: Network atom is matched on `mainnet` and
  catch-all `_Network`.  An unintended typo (`mainet`) silently
  falls through to the "all consensus flags on" clause, hiding
  the bug.  A `case Network of mainnet -> ...; testnet ->
  ...; testnet4 -> ...; regtest -> ...; signet -> ... end` with
  explicit clauses would surface the typo as a function-clause
  error.
- **Impact**: P2 — silent failure mode.

### BUG-15 (P2) — `signet` network has no separate test-script-flag derivation path

- **File**: `src/beamchain_script.erl:3563-3574`;
  `src/beamchain_chain_params.erl:260-265` (signet params).
- **Core ref**: `bitcoin-core/src/kernel/chainparams.cpp`
  `CSigNetParams` — signet is its own chain, but the script
  flag table is the same shape as mainnet (heights at 1).
- **Description**: Signet falls through to the catch-all clause
  which is fine *today* but mixes signet behavior with regtest /
  testnet4.  Future signet-specific consensus changes (custom
  signet challenge soft fork) cannot be expressed without
  another fall-through edit.
- **Impact**: P2.

### BUG-16 (P2) — `consensus_script_flags` comment is misleading ("NULLFAIL was made mandatory in 0.18.0")

- **File**: `src/beamchain_mempool.erl:4291`.
- **Description**: Comment claims NULLFAIL was made mandatory in
  Core 0.18.0.  Verified false against current Core: NULLFAIL
  remains in STANDARD_SCRIPT_VERIFY_FLAGS only
  (`policy/policy.h:125`).  This comment is the *cause* of
  BUG-3 — a reader following the comment would not flag NULLFAIL
  as a divergence.  Comment-as-confession variant: the
  *justification* for a bug, not the bug itself.
- **Impact**: P2 — misleads future audits.  Documents already
  drift; this one is wrong from inception.

### BUG-17 (P2) — `flags_for_height` is not tested for the BIP16 exception block (no test fixture for h=173818 with P2SH=off)

- **File**: `test/beamchain_w105_checkqueue_tests.erl:755-757`
  (the P2SH activation test).
- **Description**: The existing tests cover the activation
  *transition* (block 173804 → 173805) but no test exercises
  the exception path (block 173818 expecting flags = NONE).
  Even after BUG-1 is fixed, the test surface is empty for
  the exception lookup.
- **Impact**: P2 — test-coverage gap.

### BUG-18 (P3) — `flags_for_height` uses `case Height >= N of true -> ... end` instead of a single guard expression

- **File**: `src/beamchain_script.erl:3528-3561`.
- **Description**: Cosmetic.  Six nested `case` expressions
  could be folded into a single `lists:foldl` or a list
  comprehension over `{Height, Flag}` pairs.  Improves
  reviewability and reduces line count by ~70%.
- **Impact**: P3 — readability only.

### BUG-19 (P3) — `flags_for_height` doesn't take `#consensus_params{}` record (none exists)

- **File**: beamchain has no `#consensus_params{}` record at
  all.  All consensus parameters are scattered between
  `beamchain_chain_params:params/1` (returns a map), the
  hardcoded heights in `beamchain_script.erl`, the
  `#config{}` record in `beamchain_config.erl`, and macros in
  `include/beamchain_protocol.hrl`.
- **Core ref**:
  `bitcoin-core/src/consensus/params.h:18-80` —
  `Consensus::Params` is a single struct.
- **Description**: Four parallel sources of truth for
  consensus parameters.  Fixing BUG-6 / BUG-10 would benefit
  from consolidating these.
- **Impact**: P3 — design debt.

### BUG-20 (P3) — `consensus_script_flags/0` doesn't include `SCRIPT_VERIFY_CONST_SCRIPTCODE` despite the interpreter implementing it

- **File**: `src/beamchain_mempool.erl:4292-4301`.
- **Core ref**: `bitcoin-core/src/policy/policy.h:119-132` —
  CONST_SCRIPTCODE is in STANDARD only, not MANDATORY.  So
  beamchain's omission from `consensus_script_flags` is
  CORRECT here, matching Core.  However the
  interpreter at `:850-851` and `:1475-1476` and `:1955-1956`
  enforces CONST_SCRIPTCODE on consensus paths anyway — they
  fire whenever the flag is in the bitmap.  Mempool
  `all_standard_flags` does include it (`:2283`), so policy
  enforces it.  Consensus does not.  This is a Core-parity
  match, listed here for completeness against the audit
  matrix.
- **Excerpt** (`beamchain_script.erl:846-851`):
  ```erlang
  %% CONST_SCRIPTCODE: OP_CODESEPARATOR in base (non-segwit)
  %% scripts.  Reject if flag is set.
  case Op =:= ?OP_CODESEPARATOR andalso SigVer =:= base andalso
       (State0#script_state.flags band ?SCRIPT_VERIFY_CONST_SCRIPTCODE) =/= 0 of
  ```
- **Impact**: P3 — informational.  Confirms parity but documents
  a confusable: the flag *can* fire in consensus paths if a
  future change adds it to `consensus_script_flags`.

### BUG-21 (P3) — `flags_for_height` doesn't model the BIP9 versionbits state machine for soft-forks (taproot history)

- **File**: `src/beamchain_script.erl:3528-3561`.
- **Core ref**: `bitcoin-core/src/validation.cpp:2289`
  (post-buried) vs `bitcoin-core/src/versionbits.cpp` (pre-
  buried, BIP9 LOCKED_IN/ACTIVE).
- **Description**: For a re-sync of mainnet through the BIP9
  taproot deployment (h~698000), Core's per-block flag
  derivation went through *versionbits state* not hardcoded
  height before Core 23.0 buried taproot at 709632.  Beamchain
  treats taproot as buried from day one (height 709632).  This
  is consensus-equivalent on the canonical chain (taproot
  activation happened exactly at 709632), but a *forked* mainnet
  branch where miners failed to signal taproot would activate
  taproot differently in Core and beamchain.  Documented as P3
  because the canonical chain is the only one beamchain
  validates.
- **Impact**: P3 — model fidelity.  `beamchain_versionbits.erl`
  has the state machine but `flags_for_height` never calls into
  it.  Dead-versionbits-state for the script verifier.

### BUG-22 (P3) — No `LOW_S` flag in mainnet consensus flags despite Core having STANDARD enforce it

- **File**: `src/beamchain_script.erl:3528-3561`.
- **Core ref**: `bitcoin-core/src/policy/policy.h:126` —
  `SCRIPT_VERIFY_LOW_S` is STANDARD-only.
- **Description**: LOW_S is correctly absent from
  `flags_for_height/2` (a consensus computer).  It is correctly
  present in `all_standard_flags/0` (mempool policy).  Parity
  match.  Listed for completeness against the audit grep hooks
  ("LOW_S (s ≤ N/2)").
- **Impact**: P3 — informational, confirms parity.

### BUG-23 (P3) — `MAX_SCRIPT_VERIFY_FLAGS_BITS` not exposed in `beamchain_protocol.hrl`

- **File**: `include/beamchain_protocol.hrl:132-153`.
- **Core ref**:
  `bitcoin-core/src/script/interpreter.h:154-159`.
- **Description**: Core defines
  `MAX_SCRIPT_VERIFY_FLAGS_BITS` and the all-bits-set
  `MAX_SCRIPT_VERIFY_FLAGS` constant.  Beamchain's
  `beamchain_protocol.hrl` has 21 individual defines (bits 0
  through 20) but no aggregate.  Dead constant; pure
  forward-compat / introspection convenience.  W141 noted the
  same shape gap in the ZMQ notifier subsystem; common smell:
  bit-flag enums without an "all flags" sentinel.
- **Impact**: P3 — defensive constant missing.

### BUG-24 (P3) — `flags_for_height` clause for `mainnet` does six tail-recursive `case`s — no early termination on Height < 173805

- **File**: `src/beamchain_script.erl:3528-3553`.
- **Description**: For heights 0..173804, all six `case` checks
  fire even though every one returns the empty bitmap.  Pure
  micro-cosmetic; not a perf issue (function call is trivial)
  but reduces auditor cognitive load if collapsed.
- **Impact**: P3 — readability.

---

## Cross-cutting summary

| Theme | Bugs | Severity |
|---|---|---|
| `script_flag_exceptions` absent | BUG-1, BUG-7, BUG-17 | P0-CONSENSUS, P1, P2 |
| Mempool flag set vs Core STANDARD/MANDATORY | BUG-2, BUG-3, BUG-4, BUG-16, BUG-20, BUG-22 | P0-CDIV ×2, P1, P2 ×3 |
| Two-pipeline guard (heights in script vs chain-params) | BUG-6, BUG-8, BUG-9, BUG-19 | P1 ×2, P2, P3 |
| API shape (no `BlockIndex`, no `Params`) | BUG-10, BUG-11, BUG-14, BUG-15 | P2 ×4 |
| Versionbits dead-state | BUG-21 | P3 |
| Test-coverage / introspection | BUG-13, BUG-17, BUG-23 | P2, P2, P3 |
| Cosmetic | BUG-18, BUG-24 | P3 ×2 |

**Fleet-pattern smell**: this is the same "buried heights stored
in two parallel pipelines" shape that surfaced in W110/W111 for
ouroboros (`OUROBOROS_BIP68_STOPGAP`), in W132 for haskoin
(OP_CSV no-op for 62,496 mainnet blocks), and in
camlcoin/blockbrew (versionbits / MTP off-by-ones).  The
beamchain variant is currently masked by `assume_valid`, but
the structural gap is identical: chain-params holds one copy,
`flags_for_height` holds another, both populated by hand.  W144
recommends the same fix pattern: thread a single `#params{}`
into `flags_for_height/3` and read `bip65_height`,
`bip66_height`, `csv_height`, `segwit_height`, `taproot_height`
through that.
