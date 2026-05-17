# W131 — Output Descriptors + Miniscript audit (beamchain)

Discovery-only wave. 30 audit gates against BIP-380 (Output Descriptors,
checksum + grammar), BIP-381/382/383/384 (`sh()`, `wsh()`, `pkh()`/`combo()`,
`multi()`/`sortedmulti()`), BIP-385 (`raw()`, `addr()`), BIP-386 (`tr()` /
`rawtr()`), and the Miniscript type-system / compilation / satisfaction
machinery (Core's `script/miniscript.{h,cpp}`).

Reference: `bitcoin-core/src/script/descriptor.cpp` (3006 LOC), the
`PubkeyProvider` hierarchy + per-descriptor classes (`PKDescriptor`,
`PKHDescriptor`, `WPKHDescriptor`, `ComboDescriptor`, `MultisigDescriptor`,
`MultiADescriptor`, `SHDescriptor`, `WSHDescriptor`, `TRDescriptor`,
`MiniscriptDescriptor`, `RawTRDescriptor`, `AddressDescriptor`,
`RawDescriptor`, `MuSigPubkeyProvider`), `bitcoin-core/src/script/miniscript.{h,cpp}`
(2707 + 432 LOC, with `Fragment` enum, `Type` bitmap, `Node`,
`ParseContext`, `DecodeContext`, `ComputeType`, `SatInfo`, `StackSize`,
witness production), and the test corpora
`bitcoin-core/src/test/descriptor_tests.cpp`, `miniscript_tests.cpp`,
and `data/descriptor_tests_external.json`.

BIPs: 380 (checksum + grammar), 381 (sh, pkh, multi), 382 (wsh),
383 (sortedmulti), 384 (combo), 385 (raw/addr), 386 (tr/rawtr).

## Status counts

- **PRESENT** (Core-parity / functionally complete for the BIP-380 happy path): 7
- **PARTIAL** (logic exists but a sub-condition diverges, misses limits, or
  drops a side requirement): 12
- **MISSING** (no equivalent in beamchain): 11

Headline: **23 BUGS**. **None are P0-CDIV** — descriptors are a wallet-side
notation; nothing here changes consensus validation of received blocks.
Cluster severity:
- **HIGH** (correctness / interoperability with externally-produced
  descriptors): 8
- **MEDIUM** (missing-functionality, divergent error surface, malleability
  / soundness): 9
- **LOW** (cosmetic, format, perf): 6

The most consequential ones are summarized below; the full 1:1 mapping to the
30 audit gates follows.

### Top findings

1. **BUG-1 (HIGH)** — **`build_taproot_merkle` ignores leaf depths**.
   `beamchain_descriptor.erl:1092-1133` builds the TapTree merkle root by
   simply pairing leaves left-to-right and re-hashing levels, completely
   discarding the `Depth` field that `parse_tr_tree`/`parse_tr_branch`
   carefully populated. Core uses `TaprootBuilder::Add(depth, script, leaf_ver)`
   which builds the tree from a depth-first pre-order encoding
   (`descriptor.cpp:1462-1466`). The two algorithms produce **different
   output keys** for any `tr(KEY, {a,{b,c}})`-shape tree. beamchain's
   single-leaf case is correct (`leaf_hash/1` line 1102), but any non-trivial
   tree is wrong. Wallets using beamchain to derive addresses from
   `tr(internal_key, {...})` descriptors will pay to addresses that nobody
   else can interpret.

2. **BUG-2 (HIGH)** — **`tr()` script tree never gets `leaf_version=0xC0`
   prefix in compute except for single-leaf path; `pair_hashes/1` sorts
   raw hashes lexicographically rather than using BIP-341's
   `TapBranch(min(a,b) ++ max(a,b))` over the pre-hashed leaf hashes**.
   This is the second half of BUG-1 — even if depths were honored, the
   branch ordering used by Core (`compare_lt` of the byte arrays *after*
   computing tagged leaf hashes) is structurally the same here but the
   call site at `pair_hashes/1` lines 1124-1133 only hashes if even number
   of items, and odd-count leaves get *carried up unhashed* (`pair_hashes([H])
   -> [H]` line 1125), where Core's TaprootBuilder *pairs single nodes with
   themselves at the same depth* via the recursive merge. Trees with
   non-power-of-two leaf counts produce divergent output keys.

3. **BUG-3 (HIGH)** — **No `MiniscriptContext` (P2WSH vs Tapscript)**.
   `beamchain_miniscript.erl` treats every miniscript identically.
   Core (`miniscript.h:251-264`) parameterizes the entire compiler/type-checker
   on a `MiniscriptContext` enum. Consequences in beamchain:
   - `multi(...)` (P2WSH-only per BIP-381) and `multi_a(...)` (Tapscript-only)
     both compile and parse from any expression context. `parse_func("multi", ...)`
     at line 953 and `("multi_a", ...)` at line 954 do not check or record
     context.
   - The `MAX_PUBKEYS_PER_MULTI_A=999` limit (`script.h:37`) is not enforced.
     `MAX_PUBKEYS_PER_MULTISIG=20` for legacy `multi` is also not enforced
     in miniscript (it IS enforced in `beamchain_script.erl:1922` for
     consensus, but not at the miniscript parse layer).
   - Witness items in Tapscript context are 65 bytes max
     (`MAX_TAPMINISCRIPT_STACK_ELEM_SIZE`), and the BIP-340 signature is
     64+1 bytes (vs 72 for ECDSA in P2WSH). `witness_size/1` line 1577
     hardcodes 73 (ECDSA sig length) for `pk_k`.

4. **BUG-4 (HIGH)** — **`pk_k`/`pk_h` accept only 33-byte compressed pubkeys**.
   `beamchain_miniscript.erl:1006-1013` rejects anything other than length-66
   hex (33 raw bytes). Under Tapscript miniscript, keys are x-only (32
   bytes = 64 hex chars). Core's `ParseKey` (line 1813-1819) defers to
   `ctx.FromString(expr)` which accepts both lengths based on
   `MiniscriptContext`. Combined with BUG-3 this means **beamchain cannot
   produce or validate any tapminiscript at all**.

5. **BUG-5 (HIGH)** — **No `musig(...)` key expression**.
   BIP-388 + Core's `MuSigPubkeyProvider` (`descriptor.cpp:596-797`) parses
   `musig(K1,K2,...)/p` and `musig(K1,...)` (TR-context only) and produces
   an aggregated x-only pubkey. beamchain has no equivalent. Wallets that
   import a `tr(musig(...))` descriptor from Core will get a parse error.

6. **BUG-6 (HIGH)** — **No multipath descriptor support (`<0;1>`)**.
   BIP-389. Core's parser (`descriptor.cpp:2073-2089` for multi-path inside
   `musig`, plus the broader multipath logic in `PubkeyProvider`) emits
   *multiple* descriptors from one multipath string. beamchain's
   `parse_xkey_path/3` (line 725-756) does not recognize the `<a;b>` literal
   at all and will reject every multipath descriptor as `invalid_path_element`.

7. **BUG-7 (HIGH)** — **`wsh()` does not accept miniscript expressions**.
   `validate_wsh_inner/2` at lines 455-462 only accepts `desc_multi`,
   `desc_pk`, `desc_pkh`. Core (`descriptor.cpp:2447-...`, the
   `MiniscriptDescriptor` path) accepts arbitrary miniscript as the inner
   of `wsh()`. Any descriptor of the form `wsh(thresh(2,pk(K1),...,pk(K3)))`
   — the standard timelock-vault pattern — fails to parse. `beamchain_miniscript`
   and `beamchain_descriptor` are wired up as two independent modules with
   **no bridge between them**.

8. **BUG-8 (HIGH)** — **`MaxScriptSize` (3600 bytes for P2WSH;
   ~399000 for Tapscript) not enforced on compiled scripts**. Core enforces
   this *during parsing* (`miniscript.h:1869`, `if (script_size > max_size)
   return {};`). beamchain's `script_size/1` just returns `byte_size(compile(AST))`
   *after* compilation. A miniscript expression that exceeds 3600 bytes
   will compile silently and produce an unspendable `wsh()` output if used.

9. **BUG-9 (MEDIUM)** — **`MAX_OPS_PER_SCRIPT=201` not enforced in
   miniscript at parse time**. Core's `IsValidTopLevel()` (`miniscript.h:1571`)
   includes `*ops <= MAX_OPS_PER_SCRIPT`. beamchain's `validate_type/1` only
   checks the top-level type is `B`. A miniscript with > 201 non-push opcodes
   will pass type-check + compile in beamchain and be rejected by the
   interpreter at spend time.

10. **BUG-10 (MEDIUM)** — **`thresh(K, X1, ..., Xn)` doesn't require `n >= K`
    enforcement uniformity**. `parse_thresh_subs/3` (line 1085-1098) checks
    `length(Subs) >= K` after collecting all subs and rejects if not. The
    `compute_type({thresh, K, Subs})` clause at line 600 uses a guard
    `length(Subs) >= K`. But the function-head guard `K >= 1` allows `K=0`-shape
    bugs slip past — Core's `thresh` allows K=0 and requires K<=n
    (`miniscript.h:2401-2412`). In beamchain, K=0 fails the guard
    silently producing `function_clause`. The user-visible error is opaque.

11. **BUG-11 (MEDIUM)** — **`or_b`/`or_d`/`or_c` malleability tracking is
    subtly wrong**. The `m` (nonmalleable) property of `or_b` requires that
    BOTH subs are also `e` (`miniscript.h::ComputeType` for OR_B). beamchain
    line 479 has `m => prop(Tx, m) andalso prop(Ty, m) andalso prop(Tx, e)
    andalso prop(Ty, e)` — correct. But `and_v` line 414-435 doesn't track
    `m` correctly: `m => prop(Tx, m) andalso prop(Ty, m)` (line 429) is
    Core-aligned, but it omits the *subset relations* with `s`/`u`/`f`
    that Core's `ComputeType` derives from `SanitizeType` post-processing
    (`miniscript.h:303`). beamchain has no `SanitizeType` analog — a
    handful of derived properties (e.g. `u` for or_b, `n` of an n-arg `and_v`)
    will be reported incorrectly through `get_properties/1`.

12. **BUG-12 (MEDIUM)** — **Witness-size accounting wrong for `multi` under
    `wsh()`**. `witness_size({multi, K, _Keys}) -> {1 + K * 73, 1 + K}` at
    line 1690-1692 returns `1 + K` for the dissatisfaction case, but
    `CHECKMULTISIG` needs `1 + N` empty stack elements to dissatisfy
    (CHECKMULTISIG semantics: pop K+1 sigs+dummy, *then* N pubkeys). Core's
    `CalcStackSize` for MULTI: dissatisfy = `OneArg() + (N) * Zero` which is
    1+N. This causes fee-bump RPCs that estimate maximum tx weight from a
    `wsh(multi(2-of-3))` descriptor to **underestimate weight by 2 bytes per
    dissatisfaction**, producing a transaction below its true min-feerate.

13. **BUG-13 (MEDIUM)** — **`derive_bip32_pubkey_path/3` throws
    `hardened_derivation_requires_private_key`** (line 914) as a *raw throw*
    rather than returning `{error, _}`. The caller `derive/2` wraps it in
    `try`/`catch` for path errors only (`expand/3` lines 134-145), not for
    derive errors at the top-level. A `tr([fp/86'/0'/0']xpub.../<0;1>/*)`
    descriptor — which is the canonical Sparrow/Specter output — will crash
    the calling process at hardened derivation rather than report
    `cannot_derive_hardened_from_xpub`.

14. **BUG-14 (MEDIUM)** — **`addr(...)` descriptor doesn't validate the
    address**. `parse_func("addr", Rest)` (line 395-401) reads everything up
    to `)` and stuffs it into `#desc_addr{}` without calling
    `beamchain_address:address_to_script/2` to confirm the address even parses.
    Only when `derive/3` is called (line 1052) does the address get decoded.
    The user-visible error surface is `{derive_failed, 0, bad_address}` at
    derivation time rather than `{error, bad_address}` at parse time. Core
    validates eagerly (`AddressDescriptor` ctor takes a `CTxDestination`,
    not a string).

15. **BUG-15 (MEDIUM)** — **`is_solvable/1` returns `true` for `rawtr()`
    but Core says `false`**. `beamchain_descriptor.erl:208-210` matches
    only `desc_addr` and `desc_raw` as `false`, so `desc_rawtr` falls
    through to `true`. Per BIP-386 + Core (`RawTRDescriptor::IsSolvable`)
    `rawtr()` is **not solvable** — the wallet has only the *tweaked* output
    key, not any of the inputs to construct a script-path proof. The
    comment in beamchain at line 211 *acknowledges* this (`%% Note:
    desc_rawtr is solvable (issolvable=true per BIP-386)`) but the comment
    is **factually wrong** about BIP-386 and Core. **"test-comment-as-confession"
    pattern** (per W122).

16. **BUG-16 (MEDIUM)** — **No `combo(...)` script enumeration**.
    `script_from_desc(#desc_combo{}, ...)` line 1058-1072 returns *one*
    script (P2WPKH for compressed, P2PKH for uncompressed). Core
    (`ComboDescriptor::MakeScripts` lines 1248-1265) returns up to **4**
    scripts: `P2PK`, `P2PKH`, plus `P2WPKH` and `P2SH-P2WPKH` for compressed
    keys. Wallets that watch a `combo(K)` descriptor via beamchain will miss
    payments to the P2PK and P2PKH addresses of the same key (P2PK
    especially is a real edge case for ancient outputs).

17. **BUG-17 (LOW)** — **`sortedmulti(...)` sorts after `get_pubkey`**. The
    sort at `script_from_desc(#desc_multi{..., sorted=true}, ...)` line
    1004-1007 uses `lists:sort/1` on the pubkey binaries. BIP-67 ordering is
    lexicographic over the **raw bytes**, which Erlang `lists:sort/1`
    happens to do correctly for `<<>>` binaries, so this is incidentally
    right; it's flagged LOW because there's no test pinning the comparison
    against BIP-67 vectors and a future refactor could trivially break it.

18. **BUG-18 (LOW)** — **`add_checksum/1` doesn't strip existing checksum
    delimiter validation**. Line 156-164: if a descriptor already has a
    checksum, the function strips and recomputes silently. Core's
    `GetDescriptorChecksum` returns the existing checksum if present —
    callers must explicitly opt into replacement. The beamchain behavior
    is "always overwrite", which loses fidelity if the existing checksum
    was deliberately malformed for testing.

19. **BUG-19 (LOW)** — **`derive_bip32_pubkey_path/3` clobbers chain code
    on path return**. Line 901: `_ = FinalChain,` after `derive_bip32_*_path`
    means the chain code is discarded when returning to `derive_bip32_path/2`,
    so the returned `#const_key{}` has lost the parent chain code. This is
    irreversible for any caller that wanted to *continue* deriving from the
    returned key. Core's `BIP32PubkeyProvider::GetPubKey` keeps the
    `CExtPubKey` intact (returns the derived pubkey *and* the chain code).
    LOW because the public API only exposes the pubkey today, but it
    forecloses on multi-step derivation.

20. **BUG-20 (LOW)** — **`format_descriptor/1` for `tr()` with tree drops
    depth information**. `format_tree/1` line 1353-1359 emits leaves
    comma-separated within a single `{...}` regardless of their actual tree
    structure. A descriptor parsed from `tr(K, {a,{b,c}})` round-trips to
    `tr(K, {a,b,c})` — and *that* string parses back to a different tree
    (different output key per BUG-1). format-then-parse is not
    round-trip-stable for any non-trivial tapscript tree.

21. **BUG-21 (LOW)** — **`older(0)`/`older(2^31..2^32)` not rejected at
    parse time**. `parse_func("older", Rest)` and `parse_func("after", Rest)`
    feed into `parse_single_num/3` (line 1038-1044) which accepts `N >= 1`
    but not the upper bound. The `compute_type({older, N})` guard at line
    231 enforces `N < 16#80000000` but only at type-check time. A `older(0)`
    fails type-check, but the error message is opaque. Core rejects at
    parse with a specific error string.

22. **BUG-22 (LOW)** — **`encode_xpub/3`/`encode_xprv/3` hardcode
    depth=0, fingerprint=0, child=0 in the output bytes** (line 1238,
    1247). This is correct *only* for an actual master key. Any non-master
    key that round-trips through encode→decode will lose its depth and
    parent fingerprint, which breaks BIP-32 fingerprint matching for
    co-signers. The function is *only* used by `format_key/1` for ranged
    descriptors (line 1331-1334), so the failure mode is: a descriptor
    parsed from a non-master xpub re-formats to *a* xpub with the same key
    material but wrong metadata.

23. **BUG-23 (LOW)** — **`base58_char_val/2` does linear scan for every
    decoded character**. Line 1226-1230 calls `string:chr(Alphabet, C)` for
    each input character (O(N×58)). Negligible at descriptor sizes today
    but matches the same pattern flagged in W128 for `addrman` (linear
    scan instead of pre-built ETS index). LOW; cosmetic-perf.

## Audit gate matrix

The 30 audit gates below map 1-to-1 to test functions in
`test/beamchain_w131_descriptors_tests.erl`. Each is one of PRESENT (P),
PARTIAL (Pa), or MISSING (M).

| #   | Gate                                                          | Status | Bug(s)        |
|-----|---------------------------------------------------------------|--------|---------------|
| G1  | BIP-380 checksum polymod algorithm + INPUT_CHARSET            | P      | —             |
| G2  | BIP-380 checksum 8-char output via CHECKSUM_CHARSET           | P      | —             |
| G3  | `add_checksum/1` round-trip equivalence to `verify_checksum/1`| Pa     | BUG-18        |
| G4  | `pk(KEY)` parse + scriptPubKey emit                           | P      | —             |
| G5  | `pkh(KEY)` parse + scriptPubKey emit                          | P      | —             |
| G6  | `wpkh(KEY)` parse + scriptPubKey emit                         | P      | —             |
| G7  | `sh(wpkh(KEY))` nesting validation                            | P      | —             |
| G8  | `sh(multi(K, keys))` BIP-381 multisig redeemScript            | Pa     | BUG-17 (lat.) |
| G9  | `wsh(multi(K, keys))` BIP-382 witness script                  | Pa     | BUG-7 (latent)|
| G10 | `wsh(MINISCRIPT)` accepts arbitrary miniscript inner          | M      | BUG-7         |
| G11 | `multi(K, keys)` enforces MAX_PUBKEYS_PER_MULTISIG=20         | M      | BUG-3         |
| G12 | `sortedmulti(K, keys)` BIP-67 byte-lex sort before script     | Pa     | BUG-17        |
| G13 | `multi_a(K, keys)` Tapscript-only, x-only keys                | M      | BUG-3, BUG-4  |
| G14 | `sortedmulti_a(K, keys)` BIP-67 sort + Tapscript-only         | M      | BUG-3         |
| G15 | `tr(internal_key)` key-path-only BIP-341 tweak                | P      | —             |
| G16 | `tr(internal_key, TREE)` honors `m_depths` for merkle build   | M      | BUG-1, BUG-2  |
| G17 | `tr()` tree round-trip via `format_descriptor/1`              | Pa     | BUG-20        |
| G18 | `rawtr(KEY)` BIP-386 no-tweak P2TR emission                   | P      | BUG-15 (sep.) |
| G19 | `combo(KEY)` enumerates P2PK + P2PKH + (P2WPKH + P2SH-P2WPKH) | Pa     | BUG-16        |
| G20 | `addr(ADDRESS)` eager validation at parse time                | Pa     | BUG-14        |
| G21 | `raw(HEX)` byte-for-byte preserve                             | P      | —             |
| G22 | BIP-32 derivation: xpub `/n/m/*` unhardened public-path       | Pa     | BUG-13, BUG-19|
| G23 | BIP-32 derivation: xprv hardened path                         | P      | —             |
| G24 | BIP-389 multipath `<0;1>` expansion                           | M      | BUG-6         |
| G25 | `musig(K1,...)` aggregate (BIP-388)                           | M      | BUG-5         |
| G26 | Miniscript type-check: `B`/`V`/`K`/`W` invariants + property  | Pa     | BUG-11        |
| G27 | Miniscript `MiniscriptContext` (P2WSH vs Tapscript) plumbing  | M      | BUG-3         |
| G28 | Miniscript MaxScriptSize 3600 (P2WSH) enforced at parse       | M      | BUG-8         |
| G29 | Miniscript MAX_OPS_PER_SCRIPT=201 enforced                    | M      | BUG-9         |
| G30 | Witness-size accounting (`max_witness_size/1`) matches Core   | Pa     | BUG-12        |

Status totals: **P=7, Pa=12, M=11**. Bugs: 23 unique (some gates flag two).

## Universal patterns observed

1. **"Test-comment-as-confession"** (per W122 catalogue). BUG-15:
   `beamchain_descriptor.erl:211` carries a comment claiming
   `desc_rawtr` is solvable per BIP-386, which is the *opposite* of what
   BIP-386 says. The comment was added at module-creation time and never
   verified. This is the same pattern flagged in blockbrew's
   `TestBIP158Vectors` opt-out and is now the 3rd documented occurrence
   in beamchain (W120 FullRBF, W125 RPC error, W131 rawtr).

2. **"Two-module bridge missing"**. BUGs 7, 10, 13. beamchain has
   `beamchain_descriptor` and `beamchain_miniscript` as two top-level
   modules, but **no call sites** connect them — `validate_wsh_inner/2`
   in descriptor.erl line 455-462 enumerates four specific inner types and
   never delegates to `beamchain_miniscript:from_string/1`. Same shape as
   W123 mining/GBT where `beamchain_miner` and `beamchain_mempool` had
   independent fee logic that disagreed.

3. **"Throw without catch"**. BUG-13.
   `derive_bip32_pubkey_path/3:914` raises a raw `throw/1` to signal a
   semantic error (hardened path from xpub), but the caller chain only
   catches `throw:{derive_error, _, _}` (line 142) and `throw:odd_hex_length`
   (line 1421). The bare hardened-derivation throw escapes to the calling
   process. Same shape as the W124 operator-experience review of
   `beamchain_p2p` where an internal `throw(bad_msg)` killed the listener
   process.

4. **"Hardcoded constant trumping a guard"**. BUGs 3, 4. The miniscript
   parser uses literal `length(HexStr) =:= 66` (33-byte compressed pubkey
   check, lines 1006-1010 and 1110-1117) instead of dispatching on a
   `MiniscriptContext`. Same compaction pattern as W125 where RPC error
   codes were hardcoded constants rather than derived from a dispatch table.

5. **"Format-then-parse not round-trip-stable"**. BUGs 17, 20, 22. Three
   separate cases where `format_descriptor/format_tree/encode_xpub` lose
   information that `parse_descriptor/parse_tr_tree/decode_xkey` cannot
   reconstruct. Suggests that beamchain's descriptor module has never had
   a round-trip property test — every existing test in
   `test/beamchain_descriptor_tests.erl` checks parse-only or
   checksum-only, never `format(parse(S)) == S` on a non-trivial S. Future
   work: add a QuickCheck-style round-trip property as a discovery wave.

## Operational impact

- **NO CDIV.** Descriptors are wallet-side notation; the consensus
  validation pipeline (`beamchain_validation`, `beamchain_chainstate`,
  `beamchain_script`) does not consult any descriptor module during block
  acceptance. The only path from descriptors to consensus is the wallet
  *producing transactions to broadcast*, where a wrong scriptPubKey
  produces an unspendable output (the user's loss, not the network's).
- **BUG-1, BUG-2 are user-funds-loss bugs.** Any wallet that uses
  beamchain to derive an address from a `tr(K, {a,{b,c}})` descriptor will
  pay to a different address than the one Sparrow/Specter/Core would
  derive from the same descriptor string. Funds sent to the beamchain
  address are recoverable *only* by beamchain (other wallets cannot find
  the input scripts). This is high-severity but **not a network-consensus
  bug** — the resulting txids are perfectly valid Bitcoin transactions,
  they just spend to a different P2TR address than the user intended.
- **BUG-7 is the biggest functional gap.** No miniscript-in-wsh means
  beamchain can't import any of the rich descriptor strings produced by
  modern multi-sig coordinators (Sparrow, Specter, Liana, AnchorWatch).
  The fix is mechanical (route `validate_wsh_inner/2`'s fall-through to
  `beamchain_miniscript:from_string/1`) but introduces ~1500 LOC of new
  test surface.

## Out of scope (not graded in W131)

- BIP-322 generic signed-message verification (separate W).
- Miniscript "policy" language (the higher-level expression-tree
  representation that compiles to miniscript). Core has `compile_policy.cpp`;
  beamchain has nothing.
- Hardware-signer integration via descriptor URIs (BIP-380 §"private origin").
- PSBT-level descriptor consumption (covered partly in W118 PSBT audit).

## Reference

- BIP-380 — Output Script Descriptors: https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki
- BIP-381 — sh, pkh, multi
- BIP-382 — wsh
- BIP-383 — sortedmulti
- BIP-384 — combo
- BIP-385 — raw, addr
- BIP-386 — tr, rawtr
- BIP-388 — multi-key in tr (musig)
- BIP-389 — multipath descriptors
- Miniscript spec: https://bitcoin.sipa.be/miniscript/
- Core test corpora:
  - `bitcoin-core/src/test/descriptor_tests.cpp`
  - `bitcoin-core/src/test/data/descriptor_tests_external.json`
  - `bitcoin-core/src/test/miniscript_tests.cpp`
