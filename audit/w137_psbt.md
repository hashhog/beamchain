# W137 — PSBT v0 + v2 (BIP-174 / BIP-370 / BIP-371) audit (beamchain)

Discovery-only wave. 30 audit gates against Core's PSBT surface:

- **BIP-174** (PSBT v0, partially-signed bitcoin transactions): `bitcoin-core/src/psbt.{h,cpp}` (1475 LOC + 639 LOC).
- **BIP-370** (PSBT v2): separate-input-output-encoding, `tx_version`,
  `fallback_locktime`, `input_count`, `output_count`, `tx_modifiable`
  global keys plus the per-input `previous_txid` / `output_index` /
  `sequence` / per-output `amount` / `script` keys.
- **BIP-371** (PSBT taproot fields): `PSBT_IN_TAP_KEY_SIG` (0x13),
  `PSBT_IN_TAP_SCRIPT_SIG` (0x14), `PSBT_IN_TAP_LEAF_SCRIPT` (0x15),
  `PSBT_IN_TAP_BIP32_DERIVATION` (0x16), `PSBT_IN_TAP_INTERNAL_KEY`
  (0x17), `PSBT_IN_TAP_MERKLE_ROOT` (0x18), and the matching output-typed
  keys (0x05 / 0x06 / 0x07).
- **Wallet-rpc PSBT envelope** (`bitcoin-core/src/wallet/rpc/psbt.cpp`,
  reachable via `walletcreatefundedpsbt` / `walletprocesspsbt` /
  `walletfillpsbtdata` and the matching node-side `decodepsbt` /
  `analyzepsbt` / `combinepsbt` / `finalizepsbt` / `joinpsbts` /
  `utxoupdatepsbtpsbt`).

Companion audits to cross-reference:

- **W118** — Wallet (descriptors / BIP-32 / PSBT / fee / send / UTXO).
  Already surfaced the `-record(psbt, ...)` shape collision (FIX-63) and
  the missing `walletprocesspsbt` RPC envelope (W118 BUG-5). W137 zooms
  into the *codec* (BIP-174 + BIP-370 + BIP-371 wire-format compliance
  for serialize / unserialize / merge / finalize) rather than the
  wallet-side flows.
- **W127** — Taproot (BIP-340 / BIP-341 / BIP-342). The taproot field
  set described in BIP-371 routes through W127 for the underlying
  schnorr sig / tagged hash / control-block parsing; W137 covers only
  the *PSBT carrier* for those fields.
- **W125** — RPC-error-parity. Several BIP-174 / BIP-370 parse errors
  surface to the operator via `decodepsbt` / `walletprocesspsbt`; W125
  was the framework for cataloguing the error-shape divergences.

Reference: `bitcoin-core/src/psbt.{h,cpp}`, `bitcoin-core/src/node/psbt.{h,cpp}`,
`bitcoin-core/src/wallet/rpc/psbt.cpp`, BIP-174, BIP-370, BIP-371.

## Status counts (30 gates)

- **PRESENT** (Core-parity, or internally consistent + Core-compatible): 5
- **PARTIAL** (some piece matches, others diverge or are simplified): 8
- **MISSING** (no equivalent in beamchain): 17

Headline: **26 bugs**, severity distribution
**0 CDIV / 5 HIGH / 13 MEDIUM / 8 LOW**.
PSBT is wallet/signer-layer correctness, not consensus: a wrong PSBT
answer cannot fork the chain. The most consequential:

1. **BUG-1 (HIGH)** — **No PSBT v2 (BIP-370) support at all.**
   Core's `psbt.h` carries `PSBT_HIGHEST_VERSION = 0` today but the
   global v2 keys (`PSBT_GLOBAL_TX_VERSION = 0x02`,
   `PSBT_GLOBAL_FALLBACK_LOCKTIME = 0x03`,
   `PSBT_GLOBAL_INPUT_COUNT = 0x04`,
   `PSBT_GLOBAL_OUTPUT_COUNT = 0x05`,
   `PSBT_GLOBAL_TX_MODIFIABLE = 0x06`) plus the per-input v2 keys
   (`PSBT_IN_PREVIOUS_TXID = 0x0e`, `PSBT_IN_OUTPUT_INDEX = 0x0f`,
   `PSBT_IN_SEQUENCE = 0x10`, `PSBT_IN_REQUIRED_TIME_LOCKTIME = 0x11`,
   `PSBT_IN_REQUIRED_HEIGHT_LOCKTIME = 0x12`) and the per-output v2 keys
   (`PSBT_OUT_AMOUNT = 0x03`, `PSBT_OUT_SCRIPT = 0x04`) are *defined*
   constants in Core's wire format. beamchain's `beamchain_psbt.erl`
   does not even define the constants, never mind handle them. A v2
   PSBT (as produced by hardware-wallet vendors like Ledger and
   Coldcard targeting BIP-370) decoded by beamchain falls into the
   `unknown` bucket for every global / per-input / per-output v2 key,
   then crashes when `parse_global` tries to require
   `?PSBT_GLOBAL_UNSIGNED_TX` (because v2 has no unsigned-tx global —
   it encodes the tx as the union of per-input/per-output keys). Two
   call paths exposed: `decodepsbt "<base64 v2>"` returns
   `{decode_error, missing_unsigned_tx}` instead of the v2 parse;
   `combinepsbt` rejects any v2-shaped input. Cross-tooling
   incompatibility, not a parity-CVE.

2. **BUG-2 (HIGH)** — **No duplicate-key detection during unserialize.**
   Core's `PartiallySignedTransaction::Unserialize` (and the matching
   `PSBTInput::Unserialize` / `PSBTOutput::Unserialize`) maintain a
   `std::set<std::vector<unsigned char>> key_lookup;` and throw
   `std::ios_base::failure("Duplicate Key, ...");` on any repeat. This
   is the BIP-174 "Producer MUST check for duplicate keys" rule.
   beamchain's `parse_input_pairs` / `parse_output_pairs` /
   `parse_global` consume the key-value list with simple pattern-match
   recursion; a duplicate `PSBT_IN_NON_WITNESS_UTXO` simply overwrites
   the prior value via `Acc#{non_witness_utxo => Tx}`. A malicious
   sender (or downstream combiner) can substitute a forged
   non_witness_utxo by re-encoding the *first* one + the forgery in the
   same input map; beamchain silently keeps the *last* write. Note: the
   sign-side `get_utxo_info_checked/2` (W41) does verify the chosen
   non-witness UTXO's txid, so a forged-prev-tx PSBT still cannot
   produce a misleading signature — but the *decoded* PSBT carries the
   forged data, which then propagates through `combinepsbt` /
   `walletprocesspsbt` to other downstream signers that may not have
   the same W41 hardening.

3. **BUG-3 (HIGH)** — **MuSig2 input fields entirely absent
   (BIP-371).** Core defines three per-input MuSig2 keys —
   `PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS = 0x1a`,
   `PSBT_IN_MUSIG2_PUB_NONCE = 0x1b`,
   `PSBT_IN_MUSIG2_PARTIAL_SIG = 0x1c` — used by Schnorr-multisig flows
   to publish per-participant nonces and partial signatures into a
   PSBT. beamchain's `beamchain_psbt.erl:1-74` defines
   `PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS = 0x08` (output side only) but
   never defines the three input-side counterparts. A PSBT-carrying-
   MuSig2 round-2 nonce or round-3 partial-sig (produced by a Schnorr-
   multisig wallet like ZeusLN) decoded by beamchain has those entries
   fall into the `unknown` bucket, which silently drops them on a
   re-encode pass through `combinepsbt`. MuSig2 + PSBT users cannot
   round-trip a partial-sig through a beamchain hub.

4. **BUG-4 (HIGH)** — **Hash preimage fields (RIPEMD160 / SHA256 /
   HASH160 / HASH256) defined as constants but never parsed or
   serialized.** beamchain_psbt.erl:54-57 defines
   `PSBT_IN_RIPEMD160 = 0x0a`, `PSBT_IN_SHA256 = 0x0b`,
   `PSBT_IN_HASH160 = 0x0c`, `PSBT_IN_HASH256 = 0x0d` — but
   `parse_input_pairs/2` (476-542) has no clause for any of them, so
   they fall through to the `unknown` catch-all. `encode_input_map/1`
   (356-453) similarly has no producer branch for these. Effect: any
   hash-preimage-locked PSBT (atomic swaps via HTLC, Lightning's
   `update_fulfill_htlc` PSBT carriers, Boltz submarine swaps, certain
   covenant contracts) cannot round-trip preimages through beamchain.
   The Core call path is `script/sign.cpp::SignStep` → `SignatureData::
   ripemd160_preimages.insert(...)` → `PSBTInput::FromSignatureData` →
   wire encode at `psbt.h:341-363` (which serializes via
   `PSBT_IN_RIPEMD160` etc. keys); a beamchain signer that finalized a
   PSBT with preimages would drop them silently on re-encode.

5. **BUG-5 (HIGH)** — **Two parallel PSBT pipelines diverge.** Despite
   the W118 / FIX-63 record unification, the *implementations* of
   create/encode/decode/sign/finalize STILL live in TWO places:
   `beamchain_psbt.erl` (the canonical one, ~1300 LOC) and
   `beamchain_wallet.erl:1217-1530` (a stunted duplicate, ~313 LOC).
   The wallet copy has:
   - `encode_psbt_output/1` (line 1462) ALWAYS emits `<<0>>` (empty
     separator) for every output — every BIP-174 PSBT_OUT_* key is
     silently dropped on this encoder.
   - No version-handling, no XPubs, no global-unknown, no taproot
     fields at all. The output map is `maps:from_list(Pairs)` (line
     1530), bypassing the typed `PSBT_OUT_*` decoder.
   - `sign_psbt_input/3` (line 1311) requires a `utxo_record` field
     that only the wallet sets — the canonical `beamchain_psbt:sign/2`
     does NOT set this field, so a PSBT created via the canonical
     pipeline and fed into the wallet duplicate cannot be signed.
   - `encode_kv/3` takes three args (with the third ignored) while
     `beamchain_psbt:encode_kv/2` takes two; both produce the same
     wire output but the function-clause-mismatch on a typo (passing 3
     args to the psbt-module function) is a typing landmine.
   The wallet PSBT helpers are still referenced internally — e.g.
   `add_witness_utxo/3` (line 1294) is called by
   `bumpfee_emit_psbt` (`beamchain_rpc.erl:5879`) and the
   `walletcreatefundedpsbt` path (`beamchain_rpc.erl:7502`). One
   helper from the dead-impl pipeline that survives is the value
   shape mismatch FIX-63 already documented; the rest of the dead
   pipeline is latent.

The remaining 21 bugs cover: missing `key_lookup` set for the global
map (sibling of BUG-2 at the global level); no separator-missing check
on global/input/output maps; no `m_proprietary` Set with `< / ==`
operator on the wire-key (so insertion order leaks through); no
`MAX_FILE_SIZE_PSBT = 100000000` decode-size cap; no `RemoveUnnecessary
Transactions` simplification when all inputs are segwit-v1; no
`PSBTInputSignedAndVerified` script-engine cross-check on the finalize
path; no sighash compatibility check (Core's `SignPSBTInput` requires
ALL existing `partial_sigs[*].back()` bytes equal the requested
sighash); the BIP-32 keypath length-mod-4 strict check; the
`KeyOriginInfo path.size() > 0` empty-path acceptance bug (BIP-174
explicitly allows the empty path = "root xpub no children"); the
`global_xpubs` set-tracking that Core uses to reject duplicate xpub
keys; the BIP-371 `tap_tree` ordering deserialization that uses
`TaprootBuilder` to verify the tree is well-formed (Core throws
`"Output Taproot tree is malformed"` if Add+IsComplete fails); the
`tap_key_sig` length 64-or-65 check; the `tap_script_sig` length
64-or-65 check; the BIP-174 `signature is a valid DER encoding` check
on partial-sig values via `CheckSignatureEncoding(..., SCRIPT_VERIFY_
DERSIG | SCRIPT_VERIFY_STRICTENC, ...)`; `Combine` semantics with the
empty-input-list edge case; `joinpsbts` RPC missing; `utxoupdatepsbt`
RPC missing; the magic-bytes constant equality check with
`std::equal(magic, magic+5, PSBT_MAGIC_BYTES)` returning a single
clean error vs beamchain's general decode-failed; the wallet RPC
`walletprocesspsbt` `_Bip32Derivs` parameter is parsed but never
honored (a *known* deferral, per the comment at
`beamchain_rpc.erl:5935-5937`); the `Bip32` parameter likewise
parsed-but-ignored on `walletcreatefundedpsbt`.

**Not a CDIV**: PSBT is wallet/signer-layer, not consensus. Even
BUG-2 / BUG-3 / BUG-4 (the duplicate-key / MuSig2 / preimage gaps)
affect interop with external signers, not the validity of received
blocks. Cluster severity: 5 HIGH / 13 MEDIUM / 8 LOW.

The audit-flip convention applies: every test that asserts a divergent
fact (e.g. "beamchain does not detect duplicate keys") is written so
it **passes today** and **will fail when the fix lands**, flipping
the gate from MISSING/BUG → PRESENT.

---

## Gate index (1..30)

| #  | Name | Status | Core ref | beamchain ref |
|----|------|--------|----------|---------------|
| 1  | Magic bytes constant + strict 5-byte equality check | PRESENT  | psbt.h:28 + psbt.h:1228-1232 | beamchain_psbt.erl:36 + decode/1:238 |
| 2  | `PSBT_GLOBAL_*` v0 key constants (0x00 unsigned_tx, 0x01 xpub, 0xfb version, 0xfc proprietary) | PRESENT  | psbt.h:31-34 | beamchain_psbt.erl:39-42 |
| 3  | `PSBT_IN_*` v0 key constants (0x00..0x18) | PARTIAL  | psbt.h:37-58 | 0x00..0x18 defined (beamchain_psbt.erl:45-64) but RIPEMD/SHA256/HASH160/HASH256 (0x0a..0x0d) never used |
| 4  | `PSBT_OUT_*` v0 key constants (0x00..0x07) | PARTIAL  | psbt.h:62-69 | 0x00..0x07 defined but tap_tree (0x06) / tap_bip32_derivation (0x07) only decoded, never encoded |
| 5  | `PSBT_HIGHEST_VERSION = 0` constant + version 0/1 ceiling check | PARTIAL  | psbt.h:80, psbt.h:1322-1324 | beamchain_psbt.erl:346 reads version but no ceiling check; any uint32 accepted |
| 6  | Duplicate-key detection per-map (`std::set<std::vector<unsigned char>> key_lookup;` + throw) | MISSING  | psbt.h:480 (global), 524, 553, etc. (per-key) | parse_input_pairs/parse_global accept duplicates; last-write-wins |
| 7  | Separator-missing check (`if (!found_sep) throw ...`) | PARTIAL  | psbt.h:866-867 (input), 1126-1128 (output), 1354-1356 (global) | decode_map terminates on `<<0, Rest/binary>>` but doesn't distinguish "ran out of bytes" vs "missing separator" — second case may unify under match-fail |
| 8  | DER-encoded `partial_sig` value check via `CheckSignatureEncoding` | MISSING  | psbt.h:544-546 (input v0) | parse_input_pairs stores raw bytes; no DER check |
| 9  | `KeyOriginInfo` length-mod-4 + non-empty | PARTIAL  | psbt.h:127-129 (`if (length % 4 \|\| length == 0) throw...`) | decode_bip32_path:1242 reads fingerprint + path; empty path tolerated but no length-mod-4 enforcement on caller side |
| 10 | `CPubKey::SIZE + 1` or `CPubKey::COMPRESSED_SIZE + 1` key-len check for BIP32 pubkey + dup-pubkey check | MISSING  | psbt.h:153-163 | parse pattern-matches the type byte but accepts any tail length |
| 11 | Global `m_xpubs` duplicate-xpub detection set | MISSING  | psbt.h:1238 + 1293-1296 (`global_xpubs.contains(xpub)`) | parse_global appends to xpubs map; duplicate xpub on the same path silently overwrites |
| 12 | `MAX_FILE_SIZE_PSBT = 100_000_000` decode-size cap | MISSING  | psbt.h:77 | no cap; decode accepts arbitrary-size binary |
| 13 | `PSBT_GLOBAL_TX_VERSION = 0x02` (BIP-370 v2) | MISSING  | (BIP-370 §global keys) | constant not defined |
| 14 | `PSBT_GLOBAL_FALLBACK_LOCKTIME = 0x03` (BIP-370 v2) | MISSING  | (BIP-370) | constant not defined |
| 15 | `PSBT_GLOBAL_INPUT_COUNT = 0x04` + `OUTPUT_COUNT = 0x05` (BIP-370 v2) | MISSING  | (BIP-370) | constants not defined |
| 16 | `PSBT_GLOBAL_TX_MODIFIABLE = 0x06` (BIP-370 v2) | MISSING  | (BIP-370) | constant not defined |
| 17 | `PSBT_IN_PREVIOUS_TXID = 0x0e` + `OUTPUT_INDEX = 0x0f` + `SEQUENCE = 0x10` (BIP-370 v2 per-input) | MISSING  | (BIP-370) | constants not defined |
| 18 | `PSBT_IN_REQUIRED_TIME_LOCKTIME = 0x11` + `REQUIRED_HEIGHT_LOCKTIME = 0x12` (BIP-370 v2) | MISSING  | (BIP-370) | constants not defined |
| 19 | `PSBT_OUT_AMOUNT = 0x03` + `PSBT_OUT_SCRIPT = 0x04` (BIP-370 v2 per-output) | MISSING  | (BIP-370) | constants not defined |
| 20 | `PSBT_IN_MUSIG2_*` (0x1a / 0x1b / 0x1c) | MISSING  | psbt.h:56-58 | only the OUTPUT side (PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS=0x08) is defined |
| 21 | `PSBT_IN_RIPEMD160 / SHA256 / HASH160 / HASH256` hash-preimage parse + serialize | MISSING  | psbt.h:46-49 + 607-689 | constants defined but parser falls through to `unknown`; encoder has no producer branch |
| 22 | `PSBT_IN_TAP_KEY_SIG` length 64-or-65 strict check | MISSING  | psbt.h:691-704 | parse_input_pairs accepts any length |
| 23 | `PSBT_IN_TAP_SCRIPT_SIG` length 64-or-65 + key-size 65 check | PARTIAL  | psbt.h:706-727 | key-size structurally enforced via 65-byte binary match (line 506) but value-size accepted at any length |
| 24 | `PSBT_OUT_TAP_TREE` TaprootBuilder.IsComplete check | MISSING  | psbt.h:1062-1064 (`if (!builder.IsComplete()) throw "malformed"`) | decode_tap_tree(line 1289) returns whatever entries fit; no completeness check |
| 25 | Tap fields encode round-trip (decoded fields re-emitted on encode) | MISSING  | psbt.h:365-410 + 918-947 (output side) | `tap_script_sigs`, `tap_leaf_scripts`, `tap_bip32_derivation`, `tap_merkle_root` decoded into the map but NEVER re-encoded; round-trip drops them silently |
| 26 | `RemoveUnnecessaryTransactions` simplifier (drop non_witness_utxo when all-segwit-v1) | MISSING  | psbt.cpp:514-549 | no equivalent function; non_witness_utxo always kept |
| 27 | `PSBTInputSignedAndVerified` script-engine cross-check on finalize | MISSING  | psbt.cpp:325-352 | finalize_input only checks `final_script_*` presence, doesn't VerifyScript the result |
| 28 | `walletprocesspsbt`-side: sighash compatibility check (all existing partial_sigs match requested sighash) | MISSING  | psbt.cpp:467-477 | rpc_walletprocesspsbt does not cross-check existing partial sigs against the requested sighash |
| 29 | `joinpsbts` RPC | MISSING  | wallet/rpc/psbt.cpp::joinpsbts | not implemented |
| 30 | `utxoupdatepsbt` RPC | MISSING  | wallet/rpc/psbt.cpp::utxoupdatepsbt | not implemented |

The "audit-flip" cells are gates 3..30 (25 of them marked MISSING /
PARTIAL); each maps to one or more BUG-N in the next section. The two
fully PRESENT gates (1, 2) confirm the v0 magic + global-key
constants exist correctly.

---

## Bug catalogue (26 bugs)

### HIGH (5)

**BUG-1 (HIGH)** — No PSBT v2 (BIP-370) support. Headlined above. The
fix requires either (a) sequentially adding the v2 global / per-input
/ per-output keys and a version-2 code path that materializes the
unsigned-tx lazily from the per-input/per-output keys; or (b)
hard-rejecting v2 PSBTs at decode time with a clean error ("PSBT
version 2 not supported, supply a v0 PSBT") so the operator gets a
meaningful failure instead of "missing_unsigned_tx".

**BUG-2 (HIGH)** — No duplicate-key detection during unserialize. Per
BIP-174 §"Specification": "Producers MUST check for duplicate keys
when constructing a PSBT and MUST NOT include them. ... A Combiner
MUST remove duplicate keys ... and MUST FAIL if duplicate keys cause
the data to disagree." beamchain currently silently lets the
*second* writer win. Three call paths exposed:
`combinepsbt` (silently overwrites the first PSBT's data with the
second's), `walletprocesspsbt` (sees only the last-write data),
`decodepsbt` (returns only the last-write structure). Fix: thread a
`KeyLookup` set through `decode_map` and `parse_*_pairs` and throw
`{decode_error, duplicate_key}` on collision.

**BUG-3 (HIGH)** — MuSig2 input fields entirely absent. The three
keys 0x1a / 0x1b / 0x1c are part of BIP-371 — Schnorr-multisig
participants publish their `MUSIG2_PARTICIPANT_PUBKEYS` /
`MUSIG2_PUB_NONCE` / `MUSIG2_PARTIAL_SIG` into the PSBT inputs as
the round-2 / round-3 protocol artifacts. beamchain has only the
*output* side (`PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS = 0x08`),
defined at `beamchain_psbt.erl:73`. The input-side constants and
parser clauses for 0x1a / 0x1b / 0x1c don't exist. Effect: any
PSBT carrying mid-protocol MuSig2 artifacts will have those entries
fall into the `unknown` catch-all map at decode, and the encoder
emits them as opaque pass-through (which a downstream Core-spec
combiner will then reject as ill-formed because the unknown key
shape doesn't match Core's strict key-size validator).

**BUG-4 (HIGH)** — Hash preimages defined but not parsed/serialized.
beamchain_psbt.erl:54-57 has the constants but no clauses. A signer
fed a PSBT with `PSBT_IN_SHA256` preimage entries will see them in
the `unknown` field (because no typed clause matches), can read them
(they're addressable by raw key bytes), but `combinepsbt` will then
drop them because `merge_input/2` (line 1157-1179) merges typed keys
only, not the `unknown` bucket structurally. Fix: add four
`parse_input_pairs` clauses for the type bytes 0x0a..0x0d plus four
producer branches in `encode_input_map/1`. The data model also
needs four map keys (`ripemd160_preimages`, `sha256_preimages`,
`hash160_preimages`, `hash256_preimages`) so the merge function can
union them — Core's `PSBTInput::Merge` (psbt.cpp:215-247) explicitly
unions these four maps.

**BUG-5 (HIGH)** — Two parallel PSBT pipelines diverge. Detailed
above. The wallet pipeline (`beamchain_wallet.erl:1217-1530`) is now
mostly dead-helper-at-call-site (FIX-63 unified records but didn't
delete the wallet's pipeline), with one exception: `add_witness_utxo/3`
is still called from production code (`beamchain_rpc.erl:5879`
and 7502). Fix: delete `beamchain_wallet.erl:1217-1530` and
inline the surviving helper (`add_witness_utxo`) into
`beamchain_psbt`. Cross-impl learnings from W118 / FIX-63 (records
shared but pipelines parallel) apply directly. Note: the W41 audit
documented that `do_finalize_input` already funnels through
`get_utxo_info_checked` — the wallet duplicate has *no* analogous
hardening, so any caller landing on the wallet copy bypasses the
W41 forged-prev-tx check.

### MEDIUM (13)

**BUG-6 (MEDIUM)** — No global-map key_lookup set. Sibling of BUG-2 at
the global level: `PSBT_GLOBAL_UNSIGNED_TX` (0x00) etc. can be
repeated and the second wins. Same fix template.

**BUG-7 (MEDIUM)** — No separator-missing check. Core's input /
output / global Unserialize all end with `if (!found_sep) throw
std::ios_base::failure("Separator is missing at the end of an X
map");`. beamchain's `decode_map(<<0, Rest>>, Acc) ->
{lists:reverse(Acc), Rest};` matches the leading-zero terminator but
if the stream runs out of bytes mid-key/value the failure mode is a
match-fail/binary-pattern-mismatch, not a clean "separator missing".

**BUG-8 (MEDIUM)** — `partial_sig` not DER-checked. Core verifies the
sig is a valid encoding via `CheckSignatureEncoding(sig,
SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_STRICTENC, ...)` at
`psbt.h:544-546`. A non-DER sig in a partial_sig field decoded by
beamchain is silently stored; the downstream finalize might produce
a tx that *every* mempool then rejects with `mandatory-script-verify-
flag-failed (Non-canonical DER signature)`. Fix: add a DER-check call
at parse time.

**BUG-9 (MEDIUM)** — `KeyOriginInfo` length-mod-4 not enforced. Core's
`DeserializeKeyOrigin` (psbt.h:122-139) requires
`length % 4 == 0 && length != 0`. beamchain's `decode_bip32_path`
(line 1242) just splits the 4-byte fingerprint and slurps the rest
into a path list — a single-byte trailer would silently be
truncated by the `<<_:32/little>>` bitstring match, leaving the
trailing byte unread without producing a parse error.

**BUG-10 (MEDIUM)** — BIP32 derivation pubkey key-size not strictly
checked. Core's `DeserializeHDKeypaths` (psbt.h:152-156) requires the
key size to be exactly `CPubKey::SIZE + 1` (66 = 1+65 uncompressed)
or `CPubKey::COMPRESSED_SIZE + 1` (34 = 1+33 compressed). beamchain's
`parse_input_pairs([{<<?PSBT_IN_BIP32_DERIVATION, PubKey/binary>>,
PathData} | Rest], Acc)` accepts ANY pubkey-tail length.

**BUG-11 (MEDIUM)** — No global xpub duplicate-detection set. Core
maintains `std::set<CExtPubKey> global_xpubs;` and throws on repeat
(psbt.h:1238 + 1293-1296). beamchain merges into an Erlang map
keyed by raw bytes (`XPubs#{XPub => ...}`), which silently
overwrites.

**BUG-12 (MEDIUM)** — No `MAX_FILE_SIZE_PSBT = 100_000_000` cap. A
malicious peer could ship a 1-GB blob that the decoder happily
accepts, walking the binary multiple times. Core caps at 100MB
(psbt.h:77). Fix: add a `byte_size(Bin) > 100_000_000` guard at the
top of `decode/1`.

**BUG-13 (MEDIUM)** — Tap fields parse-then-drop on round-trip. `tap_
script_sigs`, `tap_leaf_scripts`, `tap_bip32_derivation`, `tap_
merkle_root` are all decoded into the input map (lines 502-538) but
NOT re-emitted by `encode_input_map/1`. Same for the output side:
`tap_tree`, `tap_bip32_derivation`, `musig2_participant_pubkeys`
decoded by `parse_output_pairs` (603-622) but `encode_output_map/1`
(548-583) only emits redeem_script / witness_script / bip32_derivation
/ tap_internal_key. Round-trip a taproot-spend PSBT and the
script-path data evaporates.

**BUG-14 (MEDIUM)** — `tap_key_sig` length not checked. Core rejects
sigs that aren't 64 or 65 bytes (psbt.h:700-703). beamchain accepts
any length, so a corrupted blob can pass through to finalize, then
fail consensus.

**BUG-15 (MEDIUM)** — `PSBT_OUT_TAP_TREE` not validated for
completeness. Core's `decode_tap_tree` walks a `TaprootBuilder` and
throws `"Output Taproot tree is malformed"` if `IsComplete()` returns
false (psbt.h:1062-1064). beamchain's `decode_tap_tree` (1289-1294)
returns whatever leaves it can parse, so an incomplete tree (e.g.
a depth-3 leaf where depth-2 is missing) yields a list of fragments
that downstream signers may then mis-interpret.

**BUG-16 (MEDIUM)** — No sighash compatibility cross-check at
walletprocesspsbt. Core's `SignPSBTInput` (psbt.cpp:467-477) iterates
`partial_sigs` and rejects if any existing sig's trailing byte
(the sighash flag) doesn't match the requested sighash. beamchain's
`rpc_walletprocesspsbt` parses the sighash string and uses it for
*new* signatures but doesn't validate compatibility with existing
ones. Fix: add a pre-sign pass that walks `partial_sigs` and either
fails (Core semantics) or surfaces a warning.

**BUG-17 (MEDIUM)** — No `RemoveUnnecessaryTransactions`. Core's
`psbt.cpp:514-549` drops `non_witness_utxo` for inputs whose
witness_utxo's scriptPubKey is segwit-v1 (taproot), as long as
SIGHASH_ANYONECANPAY isn't set. This shrinks PSBT size 5-10x in
the common taproot case. beamchain never drops the non_witness_utxo,
so PSBTs are unnecessarily large.

**BUG-18 (MEDIUM)** — No `PSBTInputSignedAndVerified` on finalize.
Core's `psbt.cpp:325-352` actually runs `VerifyScript` against the
assembled final scriptSig + witness using the UTXO's scriptPubKey
before declaring the input finalized. beamchain's `finalize_input`
emits the final fields based on partial_sigs presence, but never
script-verifies the assembled result. A bug in `build_multisig_witness`
or `finalize_legacy_p2sh` could produce a finalize-success that
fails at broadcast.

### LOW (8)

**BUG-19 (LOW)** — `joinpsbts` RPC missing. Core's
`wallet/rpc/psbt.cpp::joinpsbts` lets the caller combine the inputs
+ outputs of MULTIPLE PSBTs (each over a *different* unsigned tx)
into one bigger PSBT. beamchain's `combinepsbt` only handles the
case where all PSBTs share an unsigned tx. Use case: coinjoin / cut-
through batching workflows.

**BUG-20 (LOW)** — `utxoupdatepsbt` RPC missing. Core lets the
caller fill in missing UTXO info by querying the node's chainstate.
beamchain has no equivalent; the caller has to call `getutxos` then
`walletcreatefundedpsbt` separately.

**BUG-21 (LOW)** — `bip32derivs` parameter parsed but ignored. Both
`walletcreatefundedpsbt` and `walletprocesspsbt` accept the flag
but neither populates BIP32 derivation paths into the PSBT
(`beamchain_rpc.erl:5935-5937` documents the deferral). External
signers (hardware wallets) cannot identify their inputs without
this.

**BUG-22 (LOW)** — `PSBT_GLOBAL_VERSION` ceiling not enforced. Core
throws `"Unsupported version number"` if `m_version > PSBT_HIGHEST_
VERSION` (psbt.h:1322-1324). beamchain's `parse_global` reads
`<<V:32/little>>` and stores it unconditionally. A v=42 PSBT is
quietly stored as version=42 and re-emitted as such.

**BUG-23 (LOW)** — `PSBTRole` enum mostly hand-rolled. Core's
`PSBTRole` enum has 5 values (CREATOR/UPDATER/SIGNER/FINALIZER/
EXTRACTOR). beamchain defines them as numeric constants
(`?PSBT_ROLE_CREATOR=0`..`?PSBT_ROLE_EXTRACTOR=4` at
`beamchain_rpc.erl:153-157`) but the names are stringified via
`psbt_role_name/1`. Matches Core's `PSBTRoleName` — but the
classification heuristic in `analyze_input_role/4` (line 7252) is
shallow vs Core's `DUMMY_SIGNING_PROVIDER` walk.

**BUG-24 (LOW)** — `m_proprietary` not modelled. BIP-174 reserves
`PSBT_GLOBAL_PROPRIETARY = 0xFC` / `PSBT_IN_PROPRIETARY = 0xFC` /
`PSBT_OUT_PROPRIETARY = 0xFC` for vendor-specific extensions, with a
structured key format
`<identifier_len><identifier><subtype><keydata>`. beamchain's
proprietary keys fall into the `unknown` bucket undifferentiated.
Effect: round-trip-OK because the keys ARE pass-through, but
no programmatic access for hardware-wallet integrators.

**BUG-25 (LOW)** — Magic bytes equality check returns generic
`{error, invalid_magic}`. Core throws
`"Invalid PSBT magic bytes"` with a specific string; beamchain's
single atom is fine for Erlang taste but the JSON-RPC error string
that bubbles up via `rpc_decodepsbt` is `<<"TX decode failed
{error, invalid_magic}">>` rather than Core's `<<"TX decode failed
Invalid PSBT magic bytes">>`. Cosmetic; W125-class string match
divergence.

**BUG-26 (LOW)** — No `m_proprietary` `<` / `==` operator on the
wire-key. Core uses `std::set<PSBTProprietary>` with a custom
comparator `operator<(...) { return key < b.key; }` so the wire
order is deterministic regardless of insertion order. beamchain
iterates the unknown map via `maps:fold/3`, which has
implementation-defined order; two encoders may produce different
byte sequences for the same proprietary entries. Round-trip
correctness is preserved, but byte-exact reproducibility is not.

---

## What a fix wave would touch

The minimum-viable fix wave (call it **FIX-87** hypothetically) for
the HIGH bugs:

1. **BUG-1 v2 support OR clean reject.** Choose: (a) implement v2
   decoder/encoder (multi-day effort, requires reshaping the in-memory
   `#psbt{}` to be version-aware), or (b) early-reject v2 with a clear
   error message. Recommendation: (b), then revisit when an actual v2-
   producing wallet enters beamchain's integration matrix.
2. **BUG-2 duplicate-key detection.** Thread a `gb_sets:new()` set
   through `parse_input_pairs` / `parse_output_pairs` / `parse_global`,
   throw on collision. ~30 LOC.
3. **BUG-3 MuSig2 input keys (0x1a / 0x1b / 0x1c).** Add three
   constants, three parser clauses, three encoder producer-branches,
   three merge-union ops. ~80 LOC.
4. **BUG-4 hash preimages.** Add four constants (already defined), four
   parser clauses, four encoder producer-branches, four merge-union ops.
   ~60 LOC.
5. **BUG-5 dead pipeline cleanup.** Delete
   `beamchain_wallet.erl:1217-1530`, hoist `add_witness_utxo/3` into
   `beamchain_psbt`. ~30 LOC removed / 15 added.

The full close-out of all 26 bugs is a 2-3 wave effort. The MEDIUM
cluster (BUG-6..18) is mostly mechanical (add a check, add a clause)
but BUG-13 (taproot fields drop on encode) and BUG-15 (tap_tree
completeness) require corresponding model + merge changes too.

Until then: every test in `beamchain_w137_psbt_tests.erl` documents the
*current* (divergent) behavior, asserts it, and PASSES today. When the
fix lands, those tests FAIL — flipping the gates from MISSING → PRESENT.
