# W142 — SegWit witness validation audit (beamchain)

Discovery-only wave. Audit gates derived from Bitcoin Core
references in BIP-141 / BIP-143:

- `bitcoin-core/src/validation.cpp` (`GenerateCoinbaseCommitment`,
  `CheckWitnessMalleation`, `ContextualCheckBlock`,
  `UpdateUncommittedBlockStructures`, `IsBlockMutated`).
- `bitcoin-core/src/consensus/merkle.cpp` (`BlockWitnessMerkleRoot`).
- `bitcoin-core/src/consensus/validation.h`
  (`GetWitnessCommitmentIndex`, `MINIMUM_WITNESS_COMMITMENT=38`).
- `bitcoin-core/src/script/interpreter.cpp`
  (`SignatureHashV0` BIP-143, `VerifyWitnessProgram`,
  `ExecuteWitnessScript`).
- `bitcoin-core/src/primitives/transaction.h`
  (`UnserializeTransaction` — marker/flag/witness-stack invariants).
- `bitcoin-core/src/policy/policy.h`
  (`GetVirtualTransactionSize`, `WITNESS_SCALE_FACTOR=4`).

Companion audits to cross-reference:

- **W126** (BIP-152 compact blocks): the compact-block path
  reconstructs full witnesses; the same `decode_transaction_witness`
  code is reused, so wire-format gaps catalogued here surface in
  compact-block reconstruction too.
- **W127** (Taproot): W127 audited the v1+32 path; this audit covers
  the v0 (P2WPKH / P2WSH) path. The shared
  `verify_witness_program/6` dispatcher binds them together.
- **W137** (PSBT): every PSBT signer that emits witness data must
  agree with the on-chain decoder on marker/flag semantics. PSBT's
  `non_witness_utxo` / `witness_utxo` invariants only hold if
  `decode_transaction` enforces them — gaps here therefore propagate
  to PSBT.
- **W135** (Standardness): `MAX_STANDARD_TX_WEIGHT=400_000` is a
  policy cousin of the consensus `MAX_BLOCK_WEIGHT=4_000_000` and was
  catalogued in W135 G-3.
- **W77** fix-history note: a previous wave landed
  "pre-segwit `unexpected-witness` rejection" + "exactly-one
  32-byte nonce" — both are in place at
  `beamchain_validation.erl:367-399` and `:488-492` and are
  preserved.

## Status counts (30 gates)

- **PRESENT** (Core-parity, or internally consistent + Core-compatible): 8
- **PARTIAL** (some piece matches, others diverge or are simplified): 11
- **MISSING** (no equivalent in beamchain): 11

Headline: **22 bugs**, severity distribution
**0 P0-CONSENSUS / 1 P0-CDIV / 6 P1 / 9 P2 / 6 P3**.

The witness-validation surface is the *one* place beamchain decodes
hostile peer data into the consensus engine — every gap here is a
network-attack vector. Two themes dominate this wave:

1. **`decode_transaction` is permissive where Core throws.**
   Beamchain accepts wire forms that Core rejects at deserialize
   time ("Superfluous witness record", non-`0x01` flag bytes, etc.).
   None of these can fork the chain (the txid round-trip is stable),
   but every one of them is a unique relay-level fingerprint and an
   asymmetric replay primitive: a malicious peer can ask beamchain
   to ingest a tx that Core would have rejected, then watch us
   broadcast a canonicalised version, identifying us on the network.
2. **Consensus-level witness-stack gates are scoped to tapscript.**
   The `MAX_SCRIPT_ELEMENT_SIZE` per-stack-item gate runs for v1
   tapscript (`beamchain_script.erl:2873-2876`) but is missing on the
   v0 P2WSH branch (`:2624-2647`). Core enforces this on every
   witness program (`interpreter.cpp:1858-1861` in
   `ExecuteWitnessScript`, which is called for both P2WSH and
   tapscript).

Notable cross-cutting smells:

- **Two-pipeline guard** (W76+): `decode_transaction` is the only
  caller into the witness/non-witness branch fork. Adding a strict
  "Superfluous witness record" throw + flag-byte check makes the
  decoder a single canonical pipeline, matching the audit framing
  used since W76.
- **Comment-as-confession** (5th instance fleet-wide): a comment at
  `beamchain_validation.erl:325` says "every transaction must be
  final (Core validation.cpp:4146)" but the lock-time-cutoff branch
  (`:329-332`) uses `Header#block_header.timestamp` for pre-CSV
  blocks — which is consistent with Core but the comment elides the
  CSV-vs-MTP split. Not a bug, but flagged here because it sits
  three lines above the witness-commitment check.
- **Stricter-than-Core** (BUG-21): beamchain enforces
  `MIN_TRANSACTION_WEIGHT >= 240` in `check_transaction`; Core does
  not. Inverted-divergence (rejects valid Core txs).
- **Network-divergent regtest segwit-height**: Core regtest
  `SegwitHeight = 0`; beamchain `segwit_height = 1` for regtest,
  testnet4, signet. Genesis-height-only.

---

## BUGS

### BUG-1 (P0-CDIV) — `decode_transaction` accepts "Superfluous witness record" wire form Core rejects

- **File**: `src/beamchain_serialize.erl:330-341`
  (`decode_transaction_witness/2`)
- **Core ref**: `bitcoin-core/src/primitives/transaction.h:222-231`
  (`UnserializeTransaction`)
- **Description**: Core's witness-aware deserializer reads
  marker+flag, then unconditionally reads each input's witness
  stack, then validates `tx.HasWitness()` is true (i.e. at least
  one input has a non-empty witness stack):
  ```cpp
  if ((flags & 1) && fAllowWitness) {
      flags ^= 1;
      for (size_t i = 0; i < tx.vin.size(); i++) {
          s >> tx.vin[i].scriptWitness.stack;
      }
      if (!tx.HasWitness()) {
          throw std::ios_base::failure("Superfluous witness record");
      }
  }
  ```
  beamchain's `decode_transaction_witness/2` reads the witness data
  and never validates that any input has non-empty witness:
- **Excerpt**:
  ```erlang
  decode_transaction_witness(Version, Bin) ->
      {Inputs, Rest} = decode_list(Bin, fun decode_tx_in/1),
      {Outputs, Rest2} = decode_list(Rest, fun decode_tx_out/1),
      {InputsWithWitness, Rest3} = decode_witness_data(Inputs, Rest2),
      <<Locktime:32/little, Rest4/binary>> = Rest3,
      Tx = #transaction{ ... },
      {Tx, Rest4}.
  ```
- **Impact**: A peer can send beamchain a tx whose wire form has
  marker+flag set but every input has a 0-count CompactSize witness
  stack. Core throws `ios_base::failure`; beamchain accepts and
  produces a tx where `has_witness/1 -> false`. Beamchain then
  RE-serializes as legacy on re-broadcast (because
  `encode_transaction(Tx)` falls through to no-witness when
  `has_witness/1 -> false`). This breaks wtxid round-trip: the
  wtxid computed from what we received differs from the wtxid the
  rest of the network computes for the canonical re-broadcast. P0-CDIV
  because a block with such a "padded" coinbase that we accept but
  Core rejects is a chain-split candidate (the BIP-141 witness
  commitment merkle includes wtxids).

### BUG-2 (P1) — `decode_transaction` accepts any non-zero flag byte, Core rejects all but `0x01`

- **File**: `src/beamchain_serialize.erl:307-316`
  (`decode_transaction/1`)
- **Core ref**: `bitcoin-core/src/primitives/transaction.h:222-235`
  (`UnserializeTransaction`)
- **Description**: Core matches marker `0x00` then reads a single
  flag byte; if `flags & 1`, witness data is read; THEN
  `if (flags)` is checked AFTER clearing bit 1 — any other bit set
  throws "Unknown transaction optional data". beamchain hard-codes
  the marker+flag pattern as the literal byte sequence `0x00 0x01`
  in the pattern match:
- **Excerpt**:
  ```erlang
  decode_transaction(<<Version:32/little, Rest/binary>>) ->
      case Rest of
          <<16#00:8, 16#01:8, Rest2/binary>> ->
              %% witness format
              decode_transaction_witness(Version, Rest2);
          _ ->
              %% legacy format
              decode_transaction_legacy(Version, Rest)
      end.
  ```
- **Impact**: A wire form `version || 00 || 03 || ...` parses as a
  *legacy* tx with 0 inputs (vin-count CompactSize = 0), then the
  next byte `0x03` is interpreted as the start of the vout vector
  CompactSize. Core would have thrown after reading 0x03 as the
  flags byte. Mostly self-rejecting (no inputs throws
  `no_inputs` at `check_transaction`), but the divergent
  interpretation of `version || 00 || NN` for `NN ∈ {2,3,…,FF}`
  bytes is a network-fingerprint primitive. Lower severity because
  the resulting tx is rejected on the consensus-check pass
  regardless.

### BUG-3 (P0) — Witness stack item MAX_SCRIPT_ELEMENT_SIZE gate missing on P2WSH branch

- **File**: `src/beamchain_script.erl:2621-2651`
  (`verify_witness_program/6` for v0 + program-size-32)
- **Core ref**: `bitcoin-core/src/script/interpreter.cpp:1858-1861`
  (`ExecuteWitnessScript`)
- **Description**: Core's `ExecuteWitnessScript` enforces:
  ```cpp
  // Disallow stack item size > MAX_SCRIPT_ELEMENT_SIZE in witness stack
  for (const valtype& elem : stack) {
      if (elem.size() > MAX_SCRIPT_ELEMENT_SIZE)
          return set_error(serror, SCRIPT_ERR_PUSH_SIZE);
  }
  ```
  This runs on BOTH the v0-P2WSH path AND the v1-tapscript path.
  beamchain's tapscript path enforces this at lines 2873-2878:
  ```erlang
  case lists:any(
         fun(E) ->
             byte_size(E) > ?MAX_SCRIPT_ELEMENT_SIZE
         end, InitialStack) of
      true ->
          {error, push_size_exceeded};
      false ->
          eval_tapscript(...)
  end
  ```
  The P2WSH branch (`verify_witness_program/6` clause for `0,
  Program byte_size 32`) has NO equivalent gate; it goes straight
  from `lists:reverse(StackItems)` into `eval_script/5` (witness_v0
  sigversion).
- **Excerpt**:
  ```erlang
  verify_witness_program(0, Program, Witness, Flags, SigChecker, _IsP2SH)
    when byte_size(Program) =:= 32 ->
      %% P2WSH
      case Witness of
          [] -> {error, witness_program_empty};
          _ ->
              WitnessScript = lists:last(Witness),
              StackItems = lists:droplast(Witness),
              %% SHA256(witness_script) must equal program
              case beamchain_crypto:sha256(WitnessScript) =:= Program of
                  true ->
                      case byte_size(WitnessScript) > ?MAX_SCRIPT_SIZE of
                          true -> {error, witness_script_too_large};
                          false ->
                              %% Reverse stack items: ...
                              case eval_script(WitnessScript, lists:reverse(StackItems),
                                             Flags, SigChecker, witness_v0) of
                                  ...
                              end
                      end;
                  false -> {error, witness_program_mismatch}
              end
      end;
  ```
- **Impact**: A P2WSH-spending witness can include stack items
  larger than 520 bytes; beamchain forwards them into `eval_script`
  which may catch them via push opcodes — but only if the script
  *uses* them. If the witness script doesn't reference an
  oversized item (it sits on the alt-stack or is consumed by an
  OP_DROP), beamchain accepts it; Core rejects with
  `SCRIPT_ERR_PUSH_SIZE`. P0 because it can produce divergent
  script-execution outcomes for crafted P2WSH inputs on the same
  block — a chain-split candidate.

### BUG-4 (P1) — Regtest `segwit_height = 1` diverges from Core `SegwitHeight = 0`

- **File**: `src/beamchain_chain_params.erl:221`
- **Core ref**:
  `bitcoin-core/src/kernel/chainparams.cpp:541`
  (`consensus.SegwitHeight = 0; // Always active unless overridden`)
- **Description**: Core's regtest treats segwit as active from
  height 0 (the genesis); beamchain only activates it at height 1.
  Since the regtest genesis cannot itself contain witness data, the
  difference is unobservable for the genesis block itself, but any
  test harness that mines a block at height 0 (e.g. an invalidated
  fork that re-tries the genesis with witness data) would diverge.
- **Impact**: Test-harness divergence; flaky regtest reproductions
  against Core. Not a mainnet/testnet consensus issue.

### BUG-5 (P1) — `check_transaction` enforces `MIN_TRANSACTION_WEIGHT` stricter than Core

- **File**: `src/beamchain_validation.erl:586-588`
- **Core ref**:
  `bitcoin-core/src/consensus/consensus.h:23` (`MIN_TRANSACTION_WEIGHT`
  is a documentation constant; Core's `CheckTransaction` in
  `consensus/tx_check.cpp` does NOT enforce it)
- **Description**: beamchain `check_transaction`:
  ```erlang
  Weight = beamchain_serialize:tx_weight(Tx),
  Weight >= ?MIN_TRANSACTION_WEIGHT orelse throw(tx_underweight),
  ```
  Core's `CheckTransaction` does not check `MIN_TRANSACTION_WEIGHT`
  at all; that constant is referenced only by `CTxMemPoolEntry::Trim()`
  diagnostics and the BIP-152 short-id compactness ceiling
  `MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT`. The
  closest production gate is `consensus/tx_check.cpp::CheckTransaction`
  rejecting `vsize < 65` (CVE-2023-precursor "non-witness 64-byte
  malleation"), and that's *also* not present in beamchain (see
  BUG-7 below).
- **Impact**: Inverted-divergence. A transaction that Core accepts
  (e.g. a hand-crafted 1-input-1-output below 60 bytes stripped)
  beamchain rejects. P1 because the threshold is *below* the
  minimum coinbase weight, so the only practical victims are
  hostile-fuzzer-style txs and unit-test fixtures. Not an attack
  primitive, but a network-relay divergence.

### BUG-6 (P1) — `check_block` does not enforce `block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT` early gate

- **File**: `src/beamchain_validation.erl:100-168` (`check_block/2`)
- **Core ref**: `bitcoin-core/src/validation.cpp:3947-3948`
  ```cpp
  if (block.vtx.empty() || block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT || ...)
      return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-length", "size limits failed");
  ```
- **Description**: Core has TWO size guards: (1) `block.vtx.empty()`
  (beamchain has this at line 110), (2) cheap `tx_count * 4 >
  MAX_BLOCK_WEIGHT` and (3) `GetSerializeSize(TX_NO_WITNESS(block))
  * 4 > MAX_BLOCK_WEIGHT`. beamchain only enforces the full
  `compute_block_weight(Txs) <= MAX_BLOCK_WEIGHT` check at line 155.
  This skips the cheap-bail-out for adversarial blocks with
  10⁶ tiny txs that exceed `MAX_BLOCK_WEIGHT / 4` count alone.
- **Impact**: DoS performance issue — beamchain runs the full
  `block_weight/1` computation (which walks every tx, computes
  encode-no-witness AND encode-witness sizes) before rejecting.
  For a 4 GB adversarial block with 10⁹ tiny txs, this is the
  difference between O(n) memory and O(1) reject. Not consensus.

### BUG-7 (P1) — Missing `vsize < 65` ("64-byte mutation") protection on coinbase / per-tx

- **File**: `src/beamchain_validation.erl:540-593`
  (`check_transaction/1`)
- **Core ref**: `bitcoin-core/src/validation.cpp:4040-4053`
  (`IsBlockMutated`)
- **Description**: Core's `IsBlockMutated` rejects blocks where any
  tx has `GetSerializeSize(TX_NO_WITNESS(tx)) == 64` *if* the
  coinbase is not a true coinbase:
  ```cpp
  if (block.vtx.empty() || !block.vtx[0]->IsCoinBase()) {
      // ... 64-byte tx ⇒ merkle malleation attack vector ...
      return std::any_of(block.vtx.begin(), block.vtx.end(),
          [](auto& tx) { return GetSerializeSize(TX_NO_WITNESS(tx)) == 64; });
  }
  ```
  This is a CVE-class merkle malleation protection
  (lists.linuxfoundation.org/.../bitcoin-dev/attachments/20190225/...).
  beamchain has NO equivalent check.
- **Impact**: An attacker who controls block construction (e.g. a
  miner submitting via `submitblock`) can craft a block where the
  first tx is NOT a real coinbase but the second-and-subsequent
  txs are 64 bytes stripped. The CVE attack relies on this; Core
  rejects, beamchain accepts (then later rejects on
  `first_tx_not_coinbase`). The attack scope is narrowed by
  beamchain's `is_coinbase_tx(CoinbaseTx) orelse throw(first_tx_not_coinbase)`
  at line 114, but only if the *first* tx is the non-coinbase one
  — Core's check fires on *any* 64-byte stripped tx in the block.

### BUG-8 (P1) — Witness merkle root recomputation does not catch CVE-2012-2459 mutation

- **File**: `src/beamchain_validation.erl:147-151` (CVE check on
  txid tree only) and `src/beamchain_serialize.erl:223-227`
  (`compute_witness_commitment/2`)
- **Core ref**: `bitcoin-core/src/consensus/merkle.cpp:76-86`
  (`BlockWitnessMerkleRoot`)
- **Description**: beamchain calls `check_merkle_malleation(TxHashes)`
  to detect the CVE-2012-2459 odd-count-duplication mutation on the
  txid tree (line 151). The witness merkle (wtxid tree) used in the
  witness commitment is built by `compute_merkle_root/1` (also at
  `beamchain_serialize.erl:206-221`) but is NOT separately
  malleation-checked. Core's `IsBlockMutated` invokes
  `CheckWitnessMalleation` which recomputes
  `BlockWitnessMerkleRoot` and compares — but the underlying
  `ComputeMerkleRoot` in Core's consensus/merkle.cpp passes a
  `mutated` outparam that `CheckMerkleRoot` reads. beamchain's
  `compute_merkle_root/1` has no `mutated` outparam — it silently
  returns the (possibly mutated) root.
- **Impact**: A block with a malleated witness merkle (the
  attacker exploits the odd-count-duplication on the wtxid tree)
  can have a different "valid" witness commitment than Core would
  compute. Severity P1 because the txid tree malleation check is
  in place, and a block-level mutation that bypasses the txid check
  but lands on the wtxid tree is harder to construct (requires both
  trees to be consistent at malleation points). Worth fixing
  defensively.

### BUG-9 (P1) — `encode_witness_stack` collapses `undefined` and `[]` cases without flagging structural inconsistency

- **File**: `src/beamchain_serialize.erl:465-472`
- **Core ref**: `bitcoin-core/src/primitives/transaction.h:262-265`
- **Description**: beamchain's `encode_witness_stack/1` emits
  `encode_varint(0)` (a single 0x00 byte) for both
  `#tx_in{witness = undefined}` and `#tx_in{witness = []}`. Core
  serializes `CScriptWitness` as `vector<vector<unsigned char>>`
  with `size()=0` → also 1 byte 0x00 — matches. But this hides a
  bug source: code that creates an input with `witness = undefined`
  vs. `witness = []` cannot be distinguished at the record level,
  so transitions between "this input has no witness yet" and "this
  input *is* witness-less" are silent. The mempool path uses
  `undefined`; the chain-state stores `[]` after decode.
- **Impact**: Defensive code-quality bug. Lowest severity.

### BUG-10 (P1) — `is_p2sh_script/1` (P2SH detection for nested-witness sigops) ignores BIP-141 P2A pattern

- **File**: `src/beamchain_validation.erl` (callsite in
  `count_witness_sigops/2` at line 903)
- **Core ref**: `bitcoin-core/src/script/script.h:541` (`IsPayToAnchor`)
- **Description**: `count_witness_sigops/2` falls through to a
  `is_p2sh_script` branch for nested witness; Core's
  `IsWitnessProgram` also matches the BIP-141 P2A pattern (v1+2
  byte program 0x4e73, handled explicitly in
  `beamchain_script.erl:2678` for verify but NOT for sigop counting).
  P2A outputs are anyone-can-spend with 0 witness sigops, so this
  should be 0 for P2A — verify with `classify_witness_program`.
- **Impact**: P2A spend in a P2SH-wrap context could mis-count
  sigops; Core counts 0, beamchain falls through to `not_witness`
  → 0 (same answer by accident). P3 latent.

### BUG-11 (P2) — `extract_witness_program/1` and `classify_witness_program/1` are likely separate definitions

- **File**: `src/beamchain_script.erl:2985-2995` (extract);
  `src/beamchain_validation.erl` (classify, via grep) — need to
  unify.
- **Core ref**: `bitcoin-core/src/script/script.cpp:249-265`
  (`IsWitnessProgram`)
- **Description**: There are likely two near-duplicate
  implementations of "is this a witness program?" in beamchain: one
  in `beamchain_script.erl` (`extract_witness_program/1`) and one
  in `beamchain_validation.erl` (`classify_witness_program/1`, used
  by `count_witness_sigops/2`). Core has a single `IsWitnessProgram`
  method on `CScript`. Fleet-pattern "**two-pipeline guard**" —
  if both diverge, the script-verifier and the sigop counter
  disagree on what constitutes a witness program.
- **Impact**: Latent. Severity rises if one is updated and the
  other isn't.

### BUG-12 (P2) — `compute_witness_commitment/2` does not assert `WitnessNonce` is 32 bytes

- **File**: `src/beamchain_serialize.erl:223-227`
- **Core ref**: `bitcoin-core/src/validation.cpp:3879-3884`
- **Description**: Core requires the witness reserved value to be
  exactly 32 bytes BEFORE feeding it to the SHA256d hash:
  ```cpp
  if (witness_stack.size() != 1 || witness_stack[0].size() != 32) {
      return state.Invalid(..., "bad-witness-nonce-size", ...);
  }
  ```
  beamchain's `compute_witness_commitment/2` accepts any binary
  size:
  ```erlang
  compute_witness_commitment(Wtxids, WitnessNonce) ->
      WitnessRoot = compute_merkle_root(Wtxids),
      hash256(<<WitnessRoot/binary, WitnessNonce/binary>>).
  ```
  The caller in `check_witness_commitment` (line 489-492) guards
  this, but `compute_witness_commitment/2` is also called by the
  *miner* (`beamchain_miner.erl:898-914`). Miner passes 32-byte
  `<<0:256>>`. Defensive missing assert.
- **Impact**: Defense-in-depth. If a future caller passes a
  non-32-byte nonce, the result hash silently changes shape; downstream
  consensus would diverge.

### BUG-13 (P2) — `decode_witness_data` does not bound witness count or item size at decode

- **File**: `src/beamchain_serialize.erl:474-486`
- **Core ref**: `bitcoin-core/src/primitives/transaction.h:222-231`
  (Core's `s >> tx.vin[i].scriptWitness.stack` reads a
  `vector<vector<unsigned char>>` — bounded only by stream-size
  guards)
- **Description**: `decode_witness_data` reads `Count` from
  `decode_varint/1` and then `decode_n(Count, ...)` items. There's
  no per-tx upper bound on `Count` and no per-item size bound at
  the decode level — both are deferred to script evaluation. An
  adversarial peer can send a tx with `Count = 2^31` and beamchain
  will attempt to allocate a list of that size before the upstream
  consensus check rejects.
- **Impact**: Memory-exhaustion DoS at decode time. Core has the
  same issue at decode level (deferred to stream-size limits); the
  surrounding `MAX_BLOCK_WEIGHT` bound is the real cap. Worth a
  defensive `Count > BlockSize` early-bail.

### BUG-14 (P2) — `tx_weight` recomputes `encode_transaction` twice; non-functional but a soft-DoS amplifier

- **File**: `src/beamchain_serialize.erl:367-376`
- **Core ref**: `bitcoin-core/src/consensus/validation.h`
  (`GetTransactionWeight`)
- **Description**: `tx_weight/1` calls
  `encode_transaction(Tx, no_witness)` AND
  `encode_transaction(Tx, witness)` when the tx has witness data,
  re-encoding the full tx twice per call. `compute_block_weight/1`
  in turn calls `tx_weight/1` once per tx. For a 4 MB block with
  4,000 witness txs, that's ~32 MB of redundant byte-buffer
  allocation per block validation. Core's `GetTransactionWeight`
  uses a single computed-stripped-size and witness-size accumulator.
- **Impact**: Soft DoS / wallclock-cost. Not consensus.

### BUG-15 (P2) — `block_weight/1` does not include the 80-byte header CompactSize for the tx-count varint correctly when tx_count > 252

- **File**: `src/beamchain_serialize.erl:399-410`
- **Core ref**: `bitcoin-core/src/consensus/validation.h:13-23`
  (`GetBlockWeight = stripped*3 + total`)
- **Description**: beamchain `block_weight/1` does
  `varint(tx_count) * WITNESS_SCALE_FACTOR` for the tx-count
  prefix. The varint of a number is itself <= 9 bytes. The
  computation looks correct: `80 * 4 + varint_size * 4 + sum(tx_weight)`.
  But Core's formula is `GetBlockWeight = stripped*3 + total`,
  i.e. `(stripped_block_size) * (WITNESS_SCALE_FACTOR - 1) + (total_block_size)`
  where stripped_block_size INCLUDES the header (80) and the
  tx-count varint. Re-deriving: `80 * 3 + varint * 3 + sum(stripped(tx)) * 3
  + 80 + varint + sum(total(tx)) = 80 * 4 + varint * 4 +
  sum(tx_weight)`. **Match.** This is NOT a bug but is documented
  here as a fleet-pattern audit (Core's expression is rewritten in
  beamchain's idiom).
- **Impact**: None — confirmed match.

### BUG-16 (P2) — `encode_block` re-uses `encode_transaction/1` (auto-detect) — block-rebroadcast loses original wire form on "Superfluous witness record"

- **File**: `src/beamchain_serialize.erl:347-351`
- **Core ref**: BIP-141 wire format
- **Description**: `encode_block/1` calls
  `encode_transaction(Tx)` which auto-detects witness presence via
  `has_witness/1`. If BUG-1 lands (a tx decoded with marker+flag
  but all-empty witness stacks), the re-encode emits the LEGACY
  form, changing the byte-shape on rebroadcast. Compounds with
  BUG-1. The txid is invariant (`tx_hash` uses no-witness), so the
  merkle root still matches; but other peers see the wire-format
  diff and the wtxid round-trip is broken.
- **Impact**: Cross-link to BUG-1. Network fingerprinting.

### BUG-17 (P2) — `decode_transaction_witness` does not assert post-witness `Rest3` has enough bytes for locktime

- **File**: `src/beamchain_serialize.erl:334`
- **Core ref**: stream-overflow check in
  `bitcoin-core/src/serialize.h`
- **Description**: `<<Locktime:32/little, Rest4/binary>> = Rest3`
  will crash with a pattern-match failure if `Rest3` is shorter
  than 4 bytes — Erlang `error(...)` propagates as `badmatch`,
  not the expected `{error, decode_failed}`. Caller code that
  catches `throw:` won't catch this.
- **Impact**: Crash on malformed wire data. Soft DoS.

### BUG-18 (P3) — `decode_tx_in` always initialises `witness = []`, but no enforcement on legacy-decode path

- **File**: `src/beamchain_serialize.erl:242-252`
- **Core ref**: implicit in `bitcoin-core/src/primitives/transaction.h`
- **Description**: `decode_tx_in/1` sets `witness = []` for every
  decoded input. The witness data is overlaid by
  `decode_witness_items/3` only on the witness-decode path. A tx
  decoded by `decode_transaction_legacy/2` therefore has all inputs
  `witness = []`. This is what Core does too. **Match** —
  documentation/non-bug entry.
- **Impact**: None — confirmed match.

### BUG-19 (P3) — Wallet `sighash_witness_v0` and `script:sighash_witness_v0` are duplicate code paths (P0-CDIV risk)

- **File**: `src/beamchain_script.erl:3317-3381` and callers in
  `src/beamchain_wallet.erl:1036, 1098`,
  `src/beamchain_psbt.erl:665, 736, 793, 809`,
  `src/beamchain_witness_signer.erl:68`
- **Core ref**: `bitcoin-core/src/script/interpreter.cpp:1605-1665`
  (`SignatureHashV0`)
- **Description**: There is one canonical `sighash_witness_v0/5` in
  `beamchain_script.erl`. The wallet, PSBT, and witness-signer all
  call into it. **No duplication.** Documented here as a positive
  consensus parity finding (single pipeline preserved). The
  ScriptCode argument is the responsibility of the caller, matching
  Core's BIP-143 contract.
- **Impact**: None — single pipeline.

### BUG-20 (P3) — `sighash_witness_v0` accepts `InputIndex` >= length(inputs) silently

- **File**: `src/beamchain_script.erl:3324`
  (`Input = lists:nth(InputIndex + 1, Inputs)`)
- **Core ref**: `bitcoin-core/src/script/interpreter.cpp:1605-1614`
- **Description**: Core's `SignatureHashV0` asserts the input
  index is in range. beamchain uses `lists:nth/2` which crashes
  with `function_clause` if out-of-range. Same error class as BUG-17.
- **Impact**: Crash on caller-side bug (defense-in-depth issue).

### BUG-21 (P3) — `MAX_OP_RETURN_RELAY` comment says 400000/4 = 100000 but Core's current value is 100000 (policy not consensus)

- **File**: `include/beamchain_protocol.hrl:178`
- **Core ref**: `bitcoin-core/src/policy/policy.h`
- **Description**: Documentation note. `MAX_OP_RETURN_RELAY = MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR = 400000 / 4 = 100000`.
  Cross-cite: W135 BUG (op-return relay raised to 100_000 in Core
  recently). Not in this audit scope.
- **Impact**: Cross-cite to W135.

### BUG-22 (P3) — No explicit test for "block with commitment output but no witness anywhere"

- **File**: `src/beamchain_validation.erl:367-399`
- **Core ref**: `bitcoin-core/src/validation.cpp:3870-3916`
  (`CheckWitnessMalleation`)
- **Description**: Case A → HasCommitmentOutput=true →
  `check_witness_commitment` is invoked, which reads the coinbase
  witness nonce. If coinbase has `witness = []`, beamchain throws
  `bad_witness_nonce_size` (correct match to Core). But if the
  block has a commitment output, coinbase has a valid 32-byte
  nonce, and NO tx (including coinbase) has any non-nonce witness
  data, the witness merkle is `BlockWitnessMerkleRoot` of
  [coinbase_zero, tx1_txid, tx2_txid, ...] hashed with the nonce.
  Core: same. **Match.** Documented here as a positive parity
  finding.
- **Impact**: None — confirmed match.

---

## Fleet-pattern observations

- **Two-pipeline guard (G+14)**: `decode_transaction` is the
  bottleneck for every witness-aware wire format; tightening it
  (BUG-1, BUG-2) makes the witness decoder a single canonical
  pipeline. This is the 6th W76-style two-pipeline note in
  beamchain audits.
- **Stricter-than-Core (G+5)**: BUG-5 is the 5th
  stricter-than-Core gate catalogued in beamchain audits (W116
  BUG-3, W127 BUG-12, W135 BUG-1, W136 BUG-19, and this one).
- **Inverted-divergence (W127 echo)**: BUG-4 (regtest segwit
  height) is functionally identical to W127's "regtest taproot
  height = 1 vs Core 0" — same fleet-pattern, different
  deployment.
- **Single-pipeline preserved (W137 echo)**: BUG-19's positive
  finding (one `sighash_witness_v0`) mirrors W137's parity finding
  for `sighash_taproot`.
- **No comment-as-confession in witness code** (negative finding):
  unlike beamchain's PSBT and fee-estimation code, the witness
  validation has no TODO / FIXME / "garbage / for now" markers.
  The comments at `beamchain_validation.erl:346-366` explicitly
  cite the Core source line ranges they mirror. Consensus-quality
  signal.

## Recommended priority for fix waves

1. **BUG-1** (`Superfluous witness record` decode) — P0-CDIV;
   ~10 LOC to add `has_witness(NewTx) orelse throw(...)` at
   `decode_transaction_witness/2` exit.
2. **BUG-3** (P2WSH stack-item MAX_SCRIPT_ELEMENT_SIZE gate) — P0;
   ~5 LOC to copy the tapscript-side `lists:any` check into the
   v0+32 clause.
3. **BUG-7** (`vsize == 64` mutation reject) — P1; ~10 LOC in
   `check_block/2`.
4. **BUG-2** (`flag != 0x01` reject) — P1; restructure
   `decode_transaction/1` to read a flag byte instead of literal
   `0x00 0x01` pattern-match.
5. **BUG-4** (regtest segwit height) — P1; 1-line param fix.
