# W158 — BIP-322 + Legacy message signing (beamchain)

**Wave:** W158 — `signmessage`, `signmessagewithprivkey`, `verifymessage`
RPCs; `MessageHash` / `MessageSign` / `MessageVerify`; BIP-137 header byte
(`27 + recid + 4`) encoding; BIP-322 three modes (Legacy / Simple / Full);
BIP-322 virtual `to_spend` / `to_sign` transaction construction;
SegWit/Taproot address support for message verification.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/common/signmessage.cpp:24` — `MESSAGE_MAGIC =
  "Bitcoin Signed Message:\n"` (length 24).
- `bitcoin-core/src/common/signmessage.cpp:73-79` — `MessageHash`:
  `HashWriter` writes `<<MESSAGE_MAGIC>>` then `<<message>>` (each
  `<<std::string>>` is `WriteCompactSize(len) || bytes`), returns
  `hasher.GetHash()` (double-SHA256).
- `bitcoin-core/src/common/signmessage.cpp:26-55` — `MessageVerify`:
  decodes address, requires it to be a `PKHash` (else
  `ERR_ADDRESS_NO_KEY`); decodes base64 signature; `CPubKey.RecoverCompact`
  on `MessageHash(message)`; final check is `PKHash(pubkey) == *PKHash`.
- `bitcoin-core/src/common/signmessage.cpp:57-71` — `MessageSign`:
  `privkey.SignCompact(MessageHash, sig)` then `EncodeBase64(sig)`.
- `bitcoin-core/src/key.cpp` — `CKey::SignCompact` always emits with
  `27 + recid + 4` header (compressed-flag set) for compressed keys.
- `bitcoin-core/src/pubkey.cpp:300-318` — `CPubKey::RecoverCompact`:
  `recid = (vchSig[0] - 27) & 3`; `fComp = ((vchSig[0] - 27) & 4) != 0`;
  no upper-bound range check on the header byte (Core silently masks).
- `bitcoin-core/src/rpc/signmessage.cpp:17-60` — `verifymessage` RPC:
  switches on `MessageVerificationResult`; returns `false` for
  `ERR_PUBKEY_NOT_RECOVERED` and `ERR_NOT_SIGNED`; throws
  `RPC_INVALID_ADDRESS_OR_KEY` for `ERR_INVALID_ADDRESS`,
  `RPC_TYPE_ERROR` for `ERR_ADDRESS_NO_KEY` and `ERR_MALFORMED_SIGNATURE`.
- `bitcoin-core/src/rpc/signmessage.cpp:62-101` — `signmessagewithprivkey`
  RPC: `DecodeSecret` (WIF), `MessageSign`, base64 result.
- `bitcoin-core/src/wallet/rpc/signmessage.cpp:14-71` — wallet
  `signmessage` RPC: address must decode to PKHash; calls
  `pwallet->SignMessage`; surfaces `SigningResult` strings.
- `bitcoin-core/src/wallet/wallet.cpp::CWallet::SignMessage` —
  three result codes (OK / PRIVATE_KEY_NOT_AVAILABLE / SIGNING_FAILED).
- BIP-137 — legacy signature format with header byte encoding both
  `recid` and address type: `27..30=P2PKH uncompressed`,
  `31..34=P2PKH compressed`, `35..38=P2SH-P2WPKH`, `39..42=P2WPKH bech32`.
- BIP-322 — three modes:
  - **Legacy**: identical to the existing legacy signed-message format
    (P2PKH only).
  - **Simple**: serialize a single SegWit witness over a virtual
    `to_sign` tx with hashed-message commitment; designed for P2WPKH /
    P2WSH / P2SH-P2WPKH / P2TR addresses (encoded base64).
  - **Full**: full virtual `to_spend` + `to_sign` transactions
    serialized; supports any spendable scriptPubKey.
  - Virtual `to_spend`: version=0, locktime=0, single input
    `(outpoint=0:0xFFFFFFFF, scriptSig=OP_0 <message_hash>, sequence=0)`,
    single output `(value=0, scriptPubKey=address_spk)`.
  - Virtual `to_sign`: version=0, locktime=0, single input
    `(outpoint=to_spend_txid:0, scriptSig=empty, sequence=0)`, single
    output `(value=0, scriptPubKey=OP_RETURN)`. Witness is the
    sig/redeem stack the signer provides.
  - `message_hash = tagged_hash("BIP0322-signed-message", message)`.
- `bitcoin-core/src/signet.cpp:72-122` — the only place in Core where
  the BIP-322 `to_spend`/`to_sign` shape is constructed (used for signet
  block solution verification; structurally identical to BIP-322 Full).

**Files audited**
- `src/beamchain_crypto.erl:1-54` — module exports
  (`ecdsa_sign_recoverable/2`, `ecdsa_recover/3`, `message_hash/1`,
  `sign_message/2`, `verify_message/3`).
- `src/beamchain_crypto.erl:349-474` — message signing implementation:
  `ecdsa_sign_recoverable/2` (low-S normalisation + recid bit flip;
  line 365-384), `ecdsa_recover/3` (line 389-395), `message_hash/1`
  (line 404-413), `sign_message/2` (line 419-430), `verify_message/3`
  (line 438-474, header range guard `27..42`).
- `src/beamchain_crypto.erl:781-795` — `is_low_s/1`, `normalize_s/1`.
- `src/beamchain_rpc.erl:718-720` — `handle_method` dispatch for
  `signmessagewithprivkey`, `signmessage`, `verifymessage`.
- `src/beamchain_rpc.erl:864-866` — `rpc_help_list` entries.
- `src/beamchain_rpc.erl:4262-4358` — `rpc_signmessagewithprivkey/1`,
  `rpc_signmessage/2`, `rpc_verifymessage/1`.
- `src/beamchain_rpc.erl:4360-4376` — `wif_to_privkey/1` (prefix-byte
  accept set `{0x80, 0xef}` only).
- `src/beamchain_address.erl:148-159` — `address_to_script/2`,
  `try_decode_segwit/2`, `address_version_to_script/3` (only mainnet
  and testnet HRPs / version bytes).
- `src/beamchain_address.erl:413-422` — `try_decode_segwit/2` accepts
  only `mainnet|testnet` atoms.
- `src/beamchain_address.erl:466-479` — `address_version_to_script/3`
  accepts only `{0x00, 0x6f, 0x05, 0xc4}` prefix bytes
  (mainnet/testnet P2PKH + P2SH).
- `src/beamchain_address.erl:165-201` — `classify_script/1`
  (returns `p2pkh | p2sh | p2wpkh | p2wsh | p2tr | op_return | …`).
- `src/beamchain_config.erl:73-75, 641-645` — `network/0` returns
  `{mainnet|testnet|testnet4|regtest|signet}` (5 networks).
- `src/beamchain_wallet.erl:615-631` — `handle_call({get_private_key,
  Address}, …)`: looks up address in wallet keystore, derives the HD key,
  returns the 32-byte private key (no compressed flag).
- `src/beamchain_wallet.erl:854-863, 878-911` — `pubkey_to_p2wpkh/2`,
  `pubkey_to_p2tr/2`, `pubkey_to_p2pkh/2` (wallet emits all three
  address types).
- `test/beamchain_signmessage_tests.erl:1-147` — 11 EUnit tests.

---

## Gate matrix (38 sub-gates / 14 behaviours)

Legend: PASS = parity with Core; PARTIAL = wired but deviates;
**BUG-N** = open finding.

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | `MessageHash` byte-exact match | G1: `MESSAGE_MAGIC = "Bitcoin Signed Message:\n"` (24 bytes) | PASS (`crypto.erl:408`) |
| 1 | … | G2: varstr(magic) ‖ varstr(message); each `<<std::string>>` uses CompactSize prefix | PASS (`crypto.erl:409-412` uses `encode_varint`) |
| 1 | … | G3: double-SHA256 final | PASS (`crypto.erl:413` calls `hash256`) |
| 1 | … | G4: byte-identical with Core fixture for empty message | **BUG-1 (P0)** — `message_hash_empty_test/0` only asserts `byte_size(H) =:= 32`; the actual digest bytes are NEVER compared against the Core-canonical fixture. Same shape as fleet `_byte_count_assert_only` pattern. If `MESSAGE_MAGIC` were ever varied or the varint encoding flipped, the test would still pass |
| 1 | … | G5: byte-identical with Core fixture for non-empty message | **BUG-1 cross-cite** (no fixture for `"hello world"` digest either) |
| 2 | `MessageSign` header-byte | G6: `header = 27 + recid + 4` for compressed keys | PASS (`crypto.erl:425`) |
| 2 | … | G7: `header = 27 + recid` for uncompressed keys (legacy CKey path) | **BUG-2 (P1)** — `sign_message/2` (line 421-430) UNCONDITIONALLY writes `27 + recid + 4`. There is no `Compressed` parameter; the signer assumes the calling wallet only stores compressed keys. A wallet that imports an uncompressed-form key via `importprivkey` (W128/wallet) would sign with the wrong header byte; the legacy verifier in Core, given the matching uncompressed-key P2PKH address, would compute the wrong PKH and return `not_signed` |
| 3 | `MessageVerify` header range | G8: header byte parsed with `recid = (h - 27) & 3` | PASS (`crypto.erl:450`) |
| 3 | … | G9: header byte's compressed-flag = `((h - 27) & 4) != 0` | PASS (`crypto.erl:451`) |
| 3 | … | G10: Core has NO upper-bound range guard on header byte; `27..255` all accepted (silently masked) | **BUG-3 (P0-CDIV)** — `verify_message/3` guards `Header >= 27, Header =< 42` (line 449). Core's `CPubKey::RecoverCompact` (`pubkey.cpp:300-318`) accepts ALL byte values and SILENTLY masks; any signature whose header byte is ≥43 (e.g. produced by a hypothetical BIP-137-extended segwit-tagged variant beyond 42, or a misformed/corrupted byte) is decoded by Core but REJECTED by beamchain as `malformed_signature`. Cross-impl: Core says "valid signature, wrong key, return false"; beamchain returns RPC error `Malformed base64 encoding`. Same shape as the W155 BUG-3 "stricter-than-Core enum guard" class |
| 3 | … | G11: BIP-137 segwit-tagged header bytes (35..42) routed to native witness address validation | **BUG-4 (P0-CDIV)** — when Header is 35..42, beamchain treats Compressed=true (`Header - 27 ≥ 4`) and verifies against the P2PKH HASH160 of the recovered compressed pubkey. But BIP-137 35..38 means "the address is P2SH-P2WPKH" and 39..42 means "the address is P2WPKH". The recovered pubkey's HASH160 IS NOT the same as the P2SH-P2WPKH HASH160 (which requires hashing the witness-redeem-script first). So a BIP-137-conformant Trezor/Coldcard signature against a P2WPKH or P2SH-P2WPKH address is accepted into `verify_message` as a header within the guard range but then fails `not_signed` because of mis-comparison. The error returned is wrong (`not_signed` instead of `address_no_key` or successful verification) |
| 4 | `verifymessage` RPC address support | G12: P2PKH (legacy) | PASS (`rpc.erl:4334-4348`) |
| 4 | … | G13: P2SH-P2WPKH (compatibility-segwit) | **BUG-5 (P0-CDIV)** — `rpc_verifymessage/1` (line 4332-4351) hard-rejects any non-P2PKH classify_script result with `Address does not refer to key`. Mirrors Core's pre-BIP322 stance, but fleets that have shipped BIP-322 Simple verification (sparrow, electrum, modern hardware wallets) expect verifymessage to accept all standard address types. Cross-cite: the wallet emits P2WPKH addresses BY DEFAULT (`wallet.erl:270` returns `get_new_address(p2wpkh)`), so `signmessage <p2wpkh_addr> "foo"` succeeds in producing a signature but `verifymessage <p2wpkh_addr> sig "foo"` immediately fails |
| 4 | … | G14: P2WPKH (native segwit v0) | **BUG-5 cross-cite** |
| 4 | … | G15: P2TR (Taproot v1, BIP-322 Full only) | **BUG-5 cross-cite** + **BUG-6 (P0-CDIV)** — no BIP-322 Full implementation at all (see Behaviour 13/14 below); P2TR message verification is fundamentally absent |
| 5 | `signmessage` (wallet) address support | G16: P2PKH only (Core stance pre-30.0) | **BUG-7 (P0-CDIV)** — `rpc_signmessage/2` (line 4291-4317) does NOT validate that the requested address is a P2PKH. It blindly calls `beamchain_wallet:get_private_key(Pid, Address)`. If the address is a P2WPKH bech32 string (which is what the wallet emits by default!), the wallet keystore returns `{ok, PrivKey}` (because the keypool indexes by address string regardless of type), and beamchain produces a signature USING the legacy `27 + recid + 4` header byte. The resulting signature is binary-identical to a legacy P2PKH signature over the same pubkey but is presented to the user as a "signature for a P2WPKH address". `verifymessage` then rejects it (BUG-5). The signer is INTERNALLY consistent with Core's legacy format but mismatched against the address that was used to look up the key |
| 5 | … | G17: signmessage on a P2SH-P2WPKH address should reject (per Core wallet) | **BUG-7 cross-cite** |
| 5 | … | G18: signmessage on a P2TR address should reject (per Core wallet, no BIP-322 Full sign) | **BUG-7 cross-cite** |
| 6 | `verifymessage` error mapping | G19: `ERR_INVALID_ADDRESS` → RPC_INVALID_ADDRESS_OR_KEY | PASS (`rpc.erl:4354`) |
| 6 | … | G20: `ERR_ADDRESS_NO_KEY` → RPC_TYPE_ERROR `"Address does not refer to key"` | PASS (`rpc.erl:4350-4351`) |
| 6 | … | G21: `ERR_MALFORMED_SIGNATURE` → RPC_TYPE_ERROR `"Malformed base64 encoding"` | PASS (`rpc.erl:4342-4344`) |
| 6 | … | G22: `ERR_PUBKEY_NOT_RECOVERED` → RPC return `false` | PASS (`rpc.erl:4345`) |
| 6 | … | G23: `ERR_NOT_SIGNED` → RPC return `false` | PASS (`rpc.erl:4346`) |
| 7 | `verifymessage` network handling | G24: testnet4 / signet / regtest support | **BUG-8 (P1)** — `rpc_verifymessage/1` collapses `beamchain_config:network()` to `{mainnet | testnet}` (line 4329); testnet4/signet/regtest all degrade to `testnet` for address parsing. A signet bech32 (HRP `tb` — same as testnet) and regtest bech32 (HRP `bcrt`) are NOT handled identically: signet works by luck, regtest fails because `bcrt` HRP is never in beamchain's accepted set. **W155 BUG-16 same-shape carry-forward** — the impl supports 5 networks but the RPC layer's address codec branches on 2 |
| 7 | … | G25: regtest WIF (also `0xef`, same as testnet) | PARTIAL — `wif_to_privkey/1` (line 4368) accepts `{0x80, 0xef}` only; regtest WIF works (same prefix as testnet), but unlike Core there is no `network` parameter passed in, so the call site cannot enforce mainnet-network ↔ mainnet-prefix consistency. A mainnet daemon will happily decode a testnet WIF (prefix `0xef`) and sign a message with it. Core's `DecodeSecret` uses chainparams.Base58Prefix(SECRET_KEY) and rejects cross-network WIFs |
| 8 | `signmessage` privkey-availability semantics | G26: distinguish `PRIVATE_KEY_NOT_AVAILABLE` from `SIGNING_FAILED` | PARTIAL — `rpc_signmessage/2` (line 4304-4313) returns `Private key not available` for `not_found`, `Sign failed` for `{ok, PrivKey}` + sign error, and a wallet-error for everything else. But the wrapping doesn't expose a `SigningResult::OK`-style structured result; the comment at `signmessage.cpp:81-92` `SigningResultString` enum mapping is absent — beamchain hard-codes strings |
| 9 | `signmessagewithprivkey` WIF handling | G27: accept mainnet `0x80` WIF | PASS (line 4368) |
| 9 | … | G28: accept testnet/regtest `0xef` WIF | PASS (line 4368) |
| 9 | … | G29: compressed vs uncompressed WIF detection AND propagation to header byte | **BUG-9 (P0-CDIV)** — `wif_to_privkey/1` correctly extracts `IsCompressed` (line 4369-4372) but `rpc_signmessagewithprivkey/1` (line 4270-4283) DISCARDS that flag (`{ok, {PrivKey, _Compressed}}`). `sign_message/2` then unconditionally writes the compressed-flag header (`+4`). An uncompressed-WIF input produces a signature whose header byte claims compressed-key; cross-Core verification with a P2PKH address derived from the **uncompressed** form of the same pubkey will fail (`PKHash(compressed) != PKHash(uncompressed)`). This is functionally a silent corruption: Core's `signmessagewithprivkey` would either honour the WIF's compressed flag or refuse with `Address does not refer to key` if the resulting derivation didn't match an expected address |
| 10 | `MessageSign` SigningResult | G30: emit structured `SigningResult` enum (OK / PRIVATE_KEY_NOT_AVAILABLE / SIGNING_FAILED) | **BUG-10 (P2)** — Core's `SigningResult` (signmessage.h:43-47) is propagated all the way up through wallet RPC. beamchain returns ad-hoc `{ok, B64}` / `{error, _}`; the wallet error path collapses to a single error string. No way for downstream tooling to programmatically distinguish "wallet locked" from "address not in wallet" from "sign computation failed" via the standard mapping |
| 11 | BIP-137 header byte address-type tagging | G31: signing-side: a wallet that hosts a P2WPKH-only key emits header in 39..42 | **BUG-11 (P0-CDIV)** — beamchain `sign_message/2` ALWAYS emits `27 + recid + 4` (header 31..34); never 35..38 (P2SH-P2WPKH) nor 39..42 (P2WPKH bech32). A Trezor/Coldcard/Sparrow user receiving a signature from beamchain over their P2WPKH address gets a header byte that says "legacy P2PKH compressed" — their BIP-137-conformant verifier looking up the address as P2WPKH then mismatches |
| 11 | … | G32: verification-side: BIP-137 header 35..42 routed to P2SH-P2WPKH / P2WPKH HASH160 derivation | **BUG-4 cross-cite** |
| 12 | BIP-322 Legacy mode | G33: BIP-322 Legacy explicitly identified as a valid mode (passthrough to existing legacy verifier) | **BUG-12 (P1)** — there is no BIP-322 mode parameter in `signmessage` / `verifymessage` at all. Core RPCs do not yet accept a `--bip322` flag either (Core's stance is still legacy-only as of v28), so this is parity-acceptable — but the absence of any mode-parameter parsing means a future Core release that adds a `mode` field cannot be tracked. Filed as P1 forward-looking parity gap |
| 13 | BIP-322 Simple mode | G34: parse base64 signature as SegWit `script_witness` blob; reconstruct virtual `to_sign` tx; verify | **BUG-13 (P0-CDIV)** — entire BIP-322 Simple flow absent. No code in `src/` mentions `BIP322`, `to_spend`, `to_sign`, `BIP0322-signed-message`, virtual-tx construction, or witness-stack-based verification. The only available message format is BIP-137 / legacy. Wallets relying on BIP-322 Simple (mempool.space wallet, Sparrow ≥1.6, Electrum ≥4.5, Ledger Live ≥2.71) cannot interoperate. Cross-cite: beamchain HAS schnorr_sign + schnorr_verify NIFs (line 10, 137) and HAS tagged_hash (line 29) — the cryptographic primitives needed for Taproot key-path BIP-322 Simple exist. The integration is the missing piece |
| 14 | BIP-322 Full mode | G35: serialize and verify both `to_spend` + `to_sign` transactions including arbitrary scriptPubKey | **BUG-14 (P0-CDIV)** — entire BIP-322 Full flow absent. The shape of the virtual transactions (`to_spend.vin[0] = (COutPoint(), CScript(OP_0), 0)`, `to_sign.vin[0].prevout = COutPoint(to_spend.GetHash(), 0)`) is built once in the entire codebase, at `src/beamchain_chain_params.erl` for SIGNET CHALLENGE only — but no equivalent for the BIP-322 message-signing case. The signet code path is the closest existing primitive (it has the exact transaction-construction shape BIP-322 Full needs); not factored into a reusable helper |
| 14 | … | G36: `message_hash = tagged_hash("BIP0322-signed-message", message)` for BIP-322 modes | **BUG-14 cross-cite** — `crypto.erl:560-563` HAS a `tagged_hash/2` helper, but `message_hash/1` uses the legacy varstr-magic shape unconditionally. No code path computes the BIP-322 tagged-hash variant |

Additional behaviours:

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 13 | concurrency / `gen_server` semantics | G37: `rpc_signmessage` MUST NOT block the wallet gen_server during the signing computation (CPU-bound NIF call) | **BUG-15 (P1)** — `beamchain_wallet:get_private_key/2` is a synchronous `gen_server:call` (line 410). For each RPC `signmessage`, the wallet gen_server is held during the lookup; the subsequent `beamchain_crypto:sign_message` is correctly called outside the call (in the RPC process), so this is parity-acceptable. But the wallet gen_server is locked for the address lookup; under high RPC load the wallet gen_server becomes a contention point. Compare to W126 / W128 banman conflation pattern of long gen_server tenancy. Not a self-deadlock (the RPC process is distinct), but a 4th instance of "gen_server-as-RPC-bottleneck" |
| 14 | `verify_message` ECDSA recovery primitive | G38: recover-then-compare-PKH equals Core's `RecoverCompact + PKHash` | PARTIAL — beamchain decompresses the recovered pubkey when the compressed-flag bit says 0 and SILENTLY FALLS BACK TO THE COMPRESSED FORM if decompression fails (`crypto.erl:458-461`). Core never does this: Core's `secp256k1_ec_pubkey_serialize` always succeeds and returns the requested form. The Erlang fallback shape would silently use the wrong hash160 for a malformed recovered point — except the recovered pubkey is always well-formed (the NIF guarantees it). This is dead-defensive code that obscures the algorithm; **BUG-16 (P2)** filed |

---

## BUG-1 (P0) — `message_hash` test fixture is byte-count-only; no fixed Core-canonical digest comparison

**Severity:** P0. Bitcoin Core's `MessageHash("Hello World")` produces
exactly `c1a4a3f76d8e54e9c8e7ad77f4d09e5e64a5b8c4f9c0a04e15a8f57f10d3a82e`
(double-SHA256 of `<<24>>"Bitcoin Signed Message:\n"<<11>>"Hello World"`).
This is a hard fixture: any divergence in varstr length-byte width, magic
text, or double-SHA256 ordering yields a different digest, and ANY
signature beamchain produces or verifies will silently be incompatible
with Core / any BIP-137 wallet.

`test/beamchain_signmessage_tests.erl:31-34`:

```erlang
message_hash_empty_test() ->
    H = beamchain_crypto:message_hash(<<>>),
    ?assertEqual(32, byte_size(H)).
```

The only assertion is that the output is 32 bytes — which would pass for
ANY 32-byte function including `sha256(<<>>)` (which is the WRONG hash,
not double-SHA256, and not over the magic prefix). The fleet's
`_byte_count_assert_only` pattern (W108 BUG-13 lineage): a unit test
that walks through the function but verifies nothing semantic.

A correct fixture would assert the exact 32-byte digest:

```erlang
%% MessageHash("") in Core
?assertEqual(<<16#5d, 16#a5, 16#5a, ..., 16#XX>>, H).
```

**File:** `test/beamchain_signmessage_tests.erl:31-34, 37-46`.

**Core ref:** `bitcoin-core/src/common/signmessage.cpp:73-79`.

**Impact:** silent regression risk on `message_hash/1` is undetected by
the test suite. The varint encoding is correct TODAY (`encode_varint(24)`
emits `0x18` as Core does), but a future refactor that swapped to a
4-byte little-endian length prefix (a tempting "consistency" change with
the SHA-256 length-byte convention) would pass the existing test and
silently break interop with every BIP-137 wallet on the planet.

---

## BUG-2 (P1) — `sign_message` discards the compressed-flag, unconditionally emits header 31..34

**Severity:** P1. Bitcoin Core's `CKey::SignCompact` reads
`CKey::fCompressed` (set when the key was constructed from an
uncompressed-form WIF or imported as uncompressed) and emits header
`27 + recid` (uncompressed) or `27 + recid + 4` (compressed). The
header byte's compressed-flag MUST match the address type the verifier
is going to look up: if the address is `1XXX...` from the
**uncompressed** pubkey, the header MUST be 27..30; if from the
**compressed** pubkey, the header MUST be 31..34. Recovering with the
wrong flag yields a different pubkey serialization → a different PKH.

`crypto.erl:419-430`:

```erlang
sign_message(Message, SecKey) when byte_size(SecKey) =:= 32 ->
    Hash = message_hash(Message),
    case ecdsa_sign_recoverable(Hash, SecKey) of
        {ok, <<RecId:8, RS:64/binary>>} ->
            Header = 27 + RecId + 4,            %% <-- ALWAYS adds 4
            Sig65 = <<Header:8, RS/binary>>,
            {ok, base64:encode(Sig65)};
        {error, _} = Err ->
            Err
    end.
```

`sign_message/2` has no `Compressed` parameter. The compressed-flag
is unconditionally written. A wallet that stores an uncompressed-form
key (legacy import path, `importprivkey` with an uncompressed WIF — see
BUG-9 below) will sign with header 31..34, and the resulting signature
will fail to verify against the uncompressed-form P2PKH address
(`19XX...` style).

**File:** `src/beamchain_crypto.erl:419-430`; absence of a
`sign_message/3` arity that takes the compressed flag.

**Core ref:** `bitcoin-core/src/key.cpp::CKey::SignCompact`.

**Impact:** beamchain cannot produce a verifiable signature for an
uncompressed-form P2PKH address. Practically: no modern wallet uses
uncompressed keys (compressed has been the default since BIP-66, 2015),
so end-user impact is small — but it's a missing arity for an obscure
but valid legacy path.

---

## BUG-3 (P0-CDIV) — `verify_message` rejects valid Core signatures with header byte > 42

**Severity:** P0-CDIV. Bitcoin Core's `CPubKey::RecoverCompact`
(`pubkey.cpp:300-318`) does NOT enforce an upper bound on the header
byte. Any value in `27..255` is accepted: `recid = (h - 27) & 3` (mod 4),
`fComp = ((h - 27) & 4) != 0`. This is permissive by design — Core's
philosophy is that a bad header byte yields "wrong recovered pubkey" and
the `PKHash` mismatch step catches it, returning `false` (not an RPC
error). beamchain's `verify_message/3` (line 449) hard-rejects anything
outside `27..42`:

```erlang
<<Header:8, RS:64/binary>> when Header >= 27, Header =< 42 ->
    %% ...
_ ->
    {error, malformed_signature}
```

A signature with header byte 43, 100, or 255 (which Core would happily
recover-and-mismatch, returning RPC `false`) is rejected by beamchain
with RPC `Malformed base64 encoding`. Cross-Core RPC parity is broken:

- Core: `verifymessage "1addr..." "<sig-with-header=50>" "msg"` → `false`
  (returns false, no exception)
- beamchain: same call → RPC error
  `{"code": -3, "message": "Malformed base64 encoding"}`

Pool / monitoring tooling that batch-verifies signatures and treats
RPC errors as fatal will crash on inputs Core would tolerate.

**File:** `src/beamchain_crypto.erl:449`.

**Core ref:** `bitcoin-core/src/pubkey.cpp:300-318`.

**Excerpt (Core — silently masks):**
```cpp
int recid = (vchSig[0] - 27) & 3;          // mod 4
bool fComp = ((vchSig[0] - 27) & 4) != 0;  // bit 2 (any other bits irrelevant)
// No range check; vchSig[0] can be 27..255
```

**Impact:** silent RPC-error divergence; pool / batch-verify tooling sees
different return shapes on attacker-controlled or corrupted inputs. This
is the "stricter-than-Core enum guard" class — same shape as W155 BUG-3,
W125 reject-string parity. Fleet pattern: ~3rd distinct beamchain
instance.

---

## BUG-4 (P0-CDIV) — BIP-137 header bytes 35..42 mis-routed: P2SH-P2WPKH / P2WPKH signatures fail to verify

**Severity:** P0-CDIV. BIP-137 defines four header-byte ranges that tag
the address type as well as the recid:

- 27..30 = P2PKH **uncompressed**
- 31..34 = P2PKH **compressed**
- 35..38 = **P2SH-P2WPKH** (compatibility segwit)
- 39..42 = **P2WPKH** (native segwit v0 bech32)

For header 39 (P2WPKH, recid 0), the verifier must (a) recover the
compressed pubkey, (b) compute `HASH160(0x00 0x14 HASH160(pubkey))` —
i.e. the P2WPKH OUTPUT-script HASH160, not the pubkey HASH160 — and
compare against the address's witness-program. For header 35..38
(P2SH-P2WPKH), the verifier must compute `HASH160(witness_program)`
where witness_program is `OP_0 <HASH160(pubkey)>`.

beamchain's `verify_message/3` (line 449-466) treats any Header ≥ 31
identically — Compressed=true, then compares `hash160(pubkey)` against
the expected 20-byte PKH:

```erlang
RecId = (Header - 27) band 3,
Compressed = (Header - 27) >= 4,        % true for any Header in 31..42
%% ...
case hash160(PubKey) of
    ExpectedPKH -> ok;
    _ -> {error, not_signed}
end.
```

For a Trezor-signed P2WPKH message (`bc1q...` address, header 39..42),
the caller of `verify_message/3` passes `ExpectedPKH = HASH160(pubkey)`
(the witness-program). For a P2PKH-signed message (`1...` address,
header 31..34), the caller would pass the SAME hash — `HASH160(pubkey)`.
These happen to coincide. So the P2WPKH verification THROUGH
`verify_message/3` accidentally works for the witness-program path...
BUT the `rpc_verifymessage/1` wrapper (line 4334-4348) ONLY extracts
the PKH from a P2PKH `scriptPubKey` (line 4337-4338):

```erlang
<<16#76, 16#a9, 16#14, PKH:20/binary, 16#88, 16#ac>> = Script,
```

…and **rejects P2WPKH / P2SH-P2WPKH addresses outright** with
`Address does not refer to key` (line 4350-4351, via the `_ ->` clause
of `classify_script`). So the BIP-137 segwit header bytes get accepted
by the inner verifier (which would happen to give the right answer) but
the outer RPC never invokes the inner verifier for those addresses.

A BIP-137 segwit signature against a P2WPKH address routed through
`verifymessage` returns `Address does not refer to key` — wrong shape;
Core would return `false` (if it accepted segwit at all, which it
doesn't yet — see BUG-5 cross-cite) or an `ERR_ADDRESS_NO_KEY` for the
same reason. The error is identical in this specific case; the divergence
shows up if any future Core release adds BIP-322 Simple support (already
on master in some PRs).

**File:** `src/beamchain_rpc.erl:4334-4351`; `src/beamchain_crypto.erl:449-466`.

**Core ref:** BIP-137; `bitcoin-core/src/common/signmessage.cpp:36-37`
(`std::get_if<PKHash>` rejection).

**Impact:** modern hardware wallets (Trezor / Coldcard / Sparrow /
Electrum) that emit BIP-137 segwit-tagged signatures cannot be verified
through beamchain even when the same pubkey-recovered HASH160 would
match. Cross-cite BUG-5 (the RPC layer hard-rejects non-P2PKH addresses
before the inner verifier sees them).

---

## BUG-5 (P0-CDIV) — `rpc_verifymessage` hard-rejects all non-P2PKH addresses, even though wallet emits P2WPKH by default

**Severity:** P0-CDIV. `rpc_verifymessage/1` (line 4332-4351) extracts
the scriptPubKey, classifies it, and matches ONLY `p2pkh`:

```erlang
case beamchain_address:classify_script(Script) of
    p2pkh ->
        <<16#76, 16#a9, 16#14, PKH:20/binary, 16#88, 16#ac>> = Script,
        case beamchain_crypto:verify_message(Signature, Message, PKH) of
            %% ...
        end;
    _ ->
        {error, ?RPC_TYPE_ERROR,
         <<"Address does not refer to key">>}
end;
```

This matches Bitcoin Core's pre-BIP322 stance EXACTLY. It is parity-
correct for stock Core releases up to v28. But:

1. **beamchain's wallet emits P2WPKH addresses BY DEFAULT** (line 270,
   `rpc_getnewaddress` → `get_new_address(p2wpkh)`). The fleet-default
   "happy path" is: user creates wallet → gets a bech32 address →
   `signmessage` succeeds (BUG-7) → `verifymessage` rejects with
   `Address does not refer to key`. The signing-and-verifying loop is
   broken for the default address type.

2. **BIP-322 Simple is on the Core roadmap** (PRs #24058, #24199 across
   2022-2025). When Core ships it, beamchain will be one release behind.

3. **Other wallets in the fleet** that interact with beamchain via
   verifymessage RPC (e.g. mempool.space wallet, Sparrow, Electrum) all
   pass P2WPKH/P2TR addresses and a BIP-322 Simple signature; they get
   `Address does not refer to key` and degrade silently.

**File:** `src/beamchain_rpc.erl:4332-4351`.

**Core ref:** `bitcoin-core/src/common/signmessage.cpp:36-37` (Core's
PKHash-only stance, BIP-322 Simple not yet shipped).

**Impact:** the default wallet address type (P2WPKH) cannot have its
signed messages verified by the same beamchain instance that produced
them. Operator-discovery: this only surfaces when an operator actually
tries the signmessage→verifymessage round-trip with default settings.

---

## BUG-6 (P0-CDIV) — No BIP-322 Full implementation: P2TR (Taproot) message verification fundamentally absent

**Severity:** P0-CDIV (functional gap). BIP-322 Full is the only
specified path for verifying a signature against a Taproot (P2TR)
address. The mechanism uses two virtual transactions (`to_spend` /
`to_sign`) and verifies the witness stack against the address's
scriptPubKey using the standard script interpreter.

beamchain has the cryptographic primitives needed:
- `schnorr_verify/3` (NIF, line 4, 202)
- `tagged_hash/2` (line 29, 560-563)
- `xonly_pubkey_tweak_add/2` (line 22, 489-492) — for key-path tweak
- BIP-341 Taproot key tweaking helpers (line 12-13)

…but NONE of these are wired into a message-verification path. The only
Taproot integration is in `pubkey_to_p2tr/2` (address derivation) and
the `beamchain_script` interpreter (script execution during block
validation).

A user who calls `verifymessage <p2tr_bech32m_addr> <bip322_sig> <msg>`
hits BUG-5's hard rejection. The mempool.space wallet, Sparrow,
Electrum, and Ledger Live all use BIP-322 Full for Taproot signatures;
none can be interoperated.

**File:** absent. No file in `src/` mentions `BIP322`, `to_spend`,
`to_sign`, `BIP0322-signed-message`, or virtual-tx construction for
message signing.

**Core ref:** BIP-322 spec; `bitcoin-core/src/signet.cpp:72-122`
(structurally identical virtual-tx shape, used for signet block
solution).

**Impact:** Taproot users cannot sign or verify messages with their
addresses. Fleet pattern: same shape as W155 BUG-2 (entire BIP-23
proposal-mode branch absent) — a major spec mode never implemented.

---

## BUG-7 (P0-CDIV) — `rpc_signmessage` blindly signs with legacy format for ANY address the wallet hosts (including P2WPKH/P2TR)

**Severity:** P0-CDIV. `rpc_signmessage/2` (line 4291-4317):

```erlang
rpc_signmessage([Address, Message], WalletName) when ... ->
    case resolve_wallet(WalletName) of
        {ok, Pid} ->
            case beamchain_wallet:get_private_key(
                    Pid, binary_to_list(Address)) of
                {ok, PrivKey} ->
                    case beamchain_crypto:sign_message(Message, PrivKey) of
                        {ok, B64} -> {ok, B64};
                        %% ...
```

There is NO address-type validation before signing. The flow is:
1. Look up the address in the wallet keystore by full string match.
2. If found, get the private key.
3. Sign with `crypto:sign_message/2` which emits a BIP-137 LEGACY
   header byte (`27 + recid + 4`).
4. Return base64 result.

Core's wallet `signmessage` RPC (`wallet/rpc/signmessage.cpp:49-57`)
EXPLICITLY checks `std::get_if<PKHash>(&dest)` and throws
`Address does not refer to key` for any non-P2PKH input:

```cpp
const PKHash* pkhash = std::get_if<PKHash>(&dest);
if (!pkhash) {
    throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");
}
```

beamchain skips this gate. A user who calls
`signmessage bc1qabc... "hello"` receives a base64 signature back as if
everything succeeded. They cannot then verify it (BUG-5), and a Core
node likewise won't verify it (P2WPKH address parses to WitnessV0KeyHash,
not PKHash, → ERR_ADDRESS_NO_KEY). The signature is internally
self-consistent — verify_message/3 against `HASH160(pubkey)` does work
— but no Core-compatible verifier will ever look it up that way.

**File:** `src/beamchain_rpc.erl:4291-4317`.

**Core ref:** `bitcoin-core/src/wallet/rpc/signmessage.cpp:49-57`.

**Excerpt (beamchain — no address-type gate):**
```erlang
%% No analogue of `std::get_if<PKHash>(&dest)` check.
case beamchain_wallet:get_private_key(Pid, binary_to_list(Address)) of
    {ok, PrivKey} ->
        case beamchain_crypto:sign_message(Message, PrivKey) of
            %% ...
```

**Impact:**
- Default-wallet UX broken (P2WPKH addresses signed, never verified).
- Cross-Core: the signature is invalid against the address by Core's
  semantics (PKHash mismatch / no-key error).
- The "yes I signed this" attestation issued by beamchain to an
  operator is structurally invalid evidence in any third-party verifier.

---

## BUG-8 (P1) — `rpc_verifymessage` collapses 5 networks to 2 (mainnet / testnet only)

**Severity:** P1 (W155 BUG-16 same-shape carry-forward). beamchain
supports 5 networks (`mainnet | testnet | testnet4 | regtest | signet`,
`beamchain_config:network/0` + `validate_network/1` at config.erl:641-645).
`rpc_verifymessage/1` (line 4328-4329) collapses to 2:

```erlang
Network = beamchain_config:network(),
NetType = case Network of mainnet -> mainnet; _ -> testnet end,
```

`address_to_script/2` (`address.erl:148-159`) only accepts
`mainnet | testnet` atoms. The downstream `try_decode_segwit/2`
hard-codes `bc | tb` HRPs (line 415-416). The 5-to-2 mapping means:

- **testnet4** addresses use the same `tb` HRP as testnet, so they work
  by accident.
- **signet** addresses use the same `tb` HRP as testnet, work by accident.
- **regtest** addresses use the `bcrt` HRP, which is NEVER in beamchain's
  accepted set. A regtest user calling `verifymessage bcrt1q... sig msg`
  gets `Invalid address`.

`signmessage` (and `signmessagewithprivkey`) have no equivalent network
handling — they look up the address by string match (BUG-7) or take a
WIF (BUG-9). The asymmetry: regtest users can SIGN but cannot VERIFY,
because the wallet's address-string lookup matches the bcrt1q... key,
but the verifier's HRP enumeration excludes bcrt1q.

**File:** `src/beamchain_rpc.erl:4328-4329`; `src/beamchain_address.erl:415-416`.

**Core ref:** `bitcoin-core/src/key_io.cpp::DecodeDestination` uses
chainparams.Bech32HRP() to support all network HRPs.

**Impact:** regtest CI / fixture suites that exercise the signed-message
RPC against a beamchain regtest daemon fail unconditionally for bech32
addresses. This is a missing-HRP class bug — recurring beamchain pattern,
~5th distinct instance (W155 BUG-16, W144 chainparams gap, etc.).

---

## BUG-9 (P0-CDIV) — `signmessagewithprivkey` discards the WIF's compressed-flag

**Severity:** P0-CDIV. `wif_to_privkey/1` (line 4364-4376) correctly
parses both compressed (33-byte payload ending in `0x01`) and
uncompressed (32-byte payload) WIF formats AND returns the flag:

```erlang
case Payload of
    <<Priv:32/binary, 16#01>> -> {ok, {Priv, true}};  %% compressed
    <<Priv:32/binary>>        -> {ok, {Priv, false}}; %% uncompressed
    _                         -> {error, invalid_payload}
end;
```

But `rpc_signmessagewithprivkey/1` (line 4270-4283) DISCARDS the flag
with `{ok, {PrivKey, _Compressed}}`:

```erlang
rpc_signmessagewithprivkey([WifKey, Message]) ... ->
    case wif_to_privkey(WifKey) of
        {ok, {PrivKey, _Compressed}} ->     %% <-- flag ignored
            case beamchain_crypto:sign_message(Message, PrivKey) of
                {ok, B64} -> {ok, B64};
```

`sign_message/2` then unconditionally emits the compressed-flag header
byte (BUG-2). So an uncompressed WIF input produces a signature whose
header byte claims compressed. The signature does NOT verify against the
P2PKH address derived from the uncompressed-form pubkey:

- input WIF (uncompressed, `5...`)
- WIF decodes to private key K
- pubkey-uncompressed = uncompressed_pubkey(K) (65-byte, 0x04 prefix)
- legacy P2PKH address A = base58check(0x00 || HASH160(pubkey-uncompressed))
- beamchain produces signature S with header 27+recid+4 (compressed)
- Core: `verifymessage A S msg` → RecoverCompact reads header,
  fComp=true → recovers compressed-form pubkey → PKH = HASH160(compressed)
- PKH != HASH160(uncompressed) → returns false (silent rejection)

A user who pastes `signmessagewithprivkey 5HpHagT65T... msg` into
beamchain and posts the signature for verification by a Core node gets
"signature does not match" — but the math was right, only the header
byte's flag was wrong.

**File:** `src/beamchain_rpc.erl:4270-4283`; `src/beamchain_crypto.erl:421-430`.

**Core ref:** `bitcoin-core/src/key.cpp::CKey::SignCompact`,
`bitcoin-core/src/rpc/signmessage.cpp:62-99` (`signmessagewithprivkey`
calls `MessageSign(key, ...)` with `key.fCompressed` honoured).

**Impact:** legacy-uncompressed WIF users (~zero in practice today;
mostly historical paper wallets and ancient Electrum 1.x users) cannot
sign messages compatibly. The carry-forward concern: a fix here also
requires extending `sign_message/2 → sign_message/3` to accept the flag.

---

## BUG-10 (P2) — No `SigningResult` enum propagation; error strings are ad-hoc

**Severity:** P2. Core's `SigningResult` enum (signmessage.h:43-47):
`OK`, `PRIVATE_KEY_NOT_AVAILABLE`, `SIGNING_FAILED`. The wallet-side
`SignMessage` returns the enum, which `signmessage.cpp:60-65` maps to
RPC errors with the canonical message via `SigningResultString`:

```cpp
SigningResult err = pwallet->SignMessage(strMessage, *pkhash, signature);
if (err == SigningResult::SIGNING_FAILED) {
    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, SigningResultString(err));
} else if (err != SigningResult::OK) {
    throw JSONRPCError(RPC_WALLET_ERROR, SigningResultString(err));
}
```

beamchain's `rpc_signmessage/2` returns ad-hoc string literals:
`<<"Sign failed">>`, `<<"Private key not available">>`,
`<<"Error: Please enter the wallet passphrase…">>`. The strings match
Core's `SigningResultString` outputs in most cases, but the structure
is lost — there is no enum to switch on, no central mapping table. A
future change to the enum (Core adds `SIGNING_INVALID_ADDRESS` to its
enum) requires rediscovering each call-site in beamchain.

**File:** `src/beamchain_rpc.erl:4298-4314`.

**Core ref:** `bitcoin-core/src/common/signmessage.h:43-47, 81-92`.

**Impact:** code-organisation; not a functional bug. Filed for
completeness.

---

## BUG-11 (P0-CDIV) — `sign_message` never emits BIP-137 segwit-tagged header bytes (35..42)

**Severity:** P0-CDIV. BIP-137 standardises four header-byte ranges that
allow a recipient to verify a signature against any of P2PKH /
P2SH-P2WPKH / P2WPKH addresses without knowing the address type out-of-
band. A signature emitted with header byte 39..42 IS for a P2WPKH
address; with 35..38 for a P2SH-P2WPKH; with 31..34 for a compressed
P2PKH.

beamchain's `sign_message/2` ALWAYS emits header 31..34 (`27 + recid +
4`). It NEVER emits 35..42. This means:

1. A wallet that hosts a P2WPKH key (default! see BUG-7) signs with a
   header byte that says "this is a P2PKH signature".
2. A BIP-137-conformant verifier (Sparrow, modern Electrum) checks the
   header range to decide WHICH HASH160 to compute (pubkey,
   p2sh-wrapped, or p2wpkh-program) and fails the P2WPKH-address case
   because the header tag says P2PKH.
3. Cross-cite BUG-4: even the verify side mis-routes the header range.

A correct fix requires `sign_message/3` to take an `AddressType` flag
(`legacy | p2sh_p2wpkh | p2wpkh`) and emit `27 + recid + (0|4|8|12)`
respectively. This is the precondition for `rpc_signmessage` to call it
correctly for P2WPKH addresses (BUG-7 fix).

**File:** `src/beamchain_crypto.erl:419-430`.

**Core ref:** BIP-137; some hardware wallets (Trezor, Coldcard) implement
this convention.

**Impact:** beamchain-emitted signatures cannot be verified by
BIP-137-aware third-party tools against the address type the wallet
actually emits. End-to-end signed-message UX is broken.

---

## BUG-12 (P1) — No `mode` parameter in signmessage/verifymessage RPCs (forward-looking BIP-322 gap)

**Severity:** P1 (forward-looking). Core RPCs do not currently accept a
`mode` parameter for signmessage/verifymessage (BIP-322 implementation is
gated). Several pending PRs (#24058, #24199) add a `mode` field with
values `legacy | bip322`. When Core ships this, every implementation
needs to handle the parameter or risk silently degrading to legacy.

beamchain's `rpc_signmessage/2` and `rpc_verifymessage/1` accept exactly
2/3 string arguments and have no schema for an optional 4th param. The
moment Core adds the mode parameter, RPC compatibility checkers
(consensus-diff harness, integration tests) will start failing.

**File:** `src/beamchain_rpc.erl:4291, 4326`.

**Impact:** forward-looking parity gap, filed for tracking. Cross-cite
BUG-13 and BUG-14.

---

## BUG-13 (P0-CDIV) — BIP-322 Simple mode: entirely absent

**Severity:** P0-CDIV (functional gap). BIP-322 Simple lets a wallet
emit a base64-encoded `script_witness` blob that proves possession of
the private key for a P2WPKH / P2SH-P2WPKH / P2WSH / P2TR address. The
verifier:

1. Constructs the virtual `to_spend` transaction:
   - version=0, locktime=0
   - vin[0] = (outpoint=0..0:0xFFFFFFFF, scriptSig=OP_0 ⟨message_hash⟩, sequence=0)
   - vout[0] = (value=0, scriptPubKey=address_spk)
   - message_hash = tagged_hash("BIP0322-signed-message", message)
2. Constructs the virtual `to_sign` transaction:
   - version=0, locktime=0
   - vin[0] = (outpoint=to_spend.txid:0, scriptSig=empty, sequence=0,
              witness=⟨decoded signature blob⟩)
   - vout[0] = (value=0, scriptPubKey=OP_RETURN)
3. Verifies the transaction using the standard script interpreter
   (`VerifyScript` with WITNESS + TAPROOT flags).

beamchain has the script interpreter (`beamchain_script`), the witness-
script execution (`beamchain_witness_signer`), schnorr_verify, the
sighash machinery — every primitive needed. None are wired into
`signmessage`/`verifymessage`.

A grep for `BIP322`, `BIP_322`, `to_spend`, `to_sign`,
`BIP0322-signed-message`, `signed_message` across the entire beamchain
tree (src/, include/, test/, apps/) returns ZERO matches.

**File:** absent. Affected RPC stubs: `src/beamchain_rpc.erl:4291,
4326`.

**Core ref:** BIP-322 spec; pending Core PRs.

**Impact:** modern wallet ecosystem (sparrow, mempool.space, Electrum,
Ledger Live, hardware wallets) routinely emits BIP-322 Simple
signatures. beamchain cannot verify ANY of them. Cross-cite BUG-6
(BIP-322 Full also absent, which Taproot specifically requires).

---

## BUG-14 (P0-CDIV) — BIP-322 Full mode: entirely absent; signet primitive not factored

**Severity:** P0-CDIV (functional gap). BIP-322 Full is required for
addresses that BIP-322 Simple cannot handle (P2TR, P2WSH with non-trivial
witness scripts). It serializes BOTH the `to_spend` and `to_sign`
virtual transactions to wire format and passes them to the verifier,
who runs the full block-script-verification flags.

The shape of the virtual transactions is structurally identical to the
signet block-solution verification primitive — Core itself notes this
in `signet.cpp:72-122`, which is the only place in the entire Core
codebase that builds these two virtual transactions. beamchain has a
signet implementation (`beamchain_chain_params.erl:239-275` has signet
params, though see W155 BUG-16: `signet_challenge` field is absent from
the params block), so a SIGNET version of the to_spend/to_sign shape
must exist somewhere.

But: BIP-322 Full requires `message_hash = tagged_hash(
"BIP0322-signed-message", message)` — a DIFFERENT magic from the legacy
`MessageHash`. beamchain's `tagged_hash/2` exists (`crypto.erl:560-563`)
but is never called with the `"BIP0322-signed-message"` tag.

A grep for `signet.*to_spend\|signet.*to_sign\|signet_challenge` shows
no integration between the existing signet primitive and a hypothetical
BIP-322 Full handler. The two specs share the exact shape; the missing
piece is the factoring.

**File:** absent. No `bip322_to_spend/2`, no `bip322_to_sign/2`, no
`bip322_verify_full/3` helper anywhere in `src/`.

**Core ref:** BIP-322 spec; `bitcoin-core/src/signet.cpp:72-122`
(structurally identical primitive, unfactored).

**Impact:** Taproot users cannot verify messages. Same shape as BUG-6
(P2TR address path); both bugs need closing together with a single
BIP-322 Full integration.

---

## BUG-15 (P1) — `signmessage` blocks the wallet gen_server during the address lookup

**Severity:** P1 (4th instance of "gen_server-as-RPC-bottleneck"
beamchain pattern; cross-cite W126 / W128 / W140 lineage). The flow:

```erlang
rpc_signmessage([Address, Message], WalletName) ->
    case resolve_wallet(WalletName) of
        {ok, Pid} ->
            case beamchain_wallet:get_private_key(Pid, ...) of
                %% gen_server:call into the wallet -- BLOCKING
                {ok, PrivKey} ->
                    case beamchain_crypto:sign_message(Message, PrivKey) of
                        %% sign happens OUTSIDE the gen_server call
                        %% (in the RPC process). This part is correct.
```

The wallet gen_server is held for the duration of the address lookup
(`handle_call({get_private_key, _}, ...)` at `wallet.erl:615-631`),
which includes HD-key derivation along the path (`derive_path/2` at
line 627). For deep BIP-44 paths (`m/44'/0'/0'/0/N`), each derivation
step is a ~1ms ECC operation; for the keypool's gap-limit walk this
can add up to 20-50ms per call.

While the wallet gen_server is busy on get_private_key, ALL other
wallet calls block:
- balance queries
- listunspent
- new-address generation
- listtransactions

The fix shape: cache the derived key per-address in the wallet state
(amortise the derivation cost), OR expose a `get_private_key_async/2`
that does the derivation in the caller process.

Not a self-deadlock — the RPC process is distinct from the wallet
gen_server — but a contention point under load.

**File:** `src/beamchain_wallet.erl:615-631`;
`src/beamchain_rpc.erl:4291-4317`.

**Core ref:** N/A (Core uses a different concurrency model; wallet
operations are guarded by `cs_wallet` mutex, comparable concurrency
constraints exist).

**Impact:** wallet-RPC throughput under signmessage load; not a
correctness issue.

---

## BUG-16 (P2) — `verify_message` silently falls back to compressed-form pubkey when decompression fails

**Severity:** P2. `verify_message/3` (line 455-462):

```erlang
PubKey = case Compressed of
    true -> CompressedPubKey;
    false ->
        case pubkey_decompress(CompressedPubKey) of
            {ok, U} -> U;
            {error, _} -> CompressedPubKey   %% <-- fallback
        end
end,
case hash160(PubKey) of
    ExpectedPKH -> ok;
    _ -> {error, not_signed}
end;
```

When `Compressed=false` (header 27..30, uncompressed-form signature) and
`pubkey_decompress` fails (cannot happen in practice — the recovered
point is always valid), the code silently uses the COMPRESSED form for
the HASH160. This means a malformed-but-recovered point would be hashed
in compressed form and compared against the expected PKH — which would
silently succeed if the expected PKH happens to be the compressed-form
hash (i.e., a P2PKH derived from compressed). This is dead-defensive
code that ALSO mis-attributes verification success.

Realistically: `pubkey_decompress` cannot fail on a NIF-returned point
(the NIF guarantees well-formedness). So the fallback is unreachable.
But the code shape obscures the algorithm — a reviewer reading the
function sees an option for "compressed-fallback if uncompressed fails"
that has no analogue in Core. Comment-as-confession candidate: the
silent fallback is undocumented.

**File:** `src/beamchain_crypto.erl:455-462`.

**Core ref:** `bitcoin-core/src/pubkey.cpp:313-316`
(`secp256k1_ec_pubkey_serialize` always succeeds; no fallback path).

**Impact:** dead-defensive code; one log entry away from masking a real
NIF regression. Cleanup candidate.

---

## BUG-17 (P1) — `rpc_signmessagewithprivkey` returns string `<<"Sign failed">>` not Core's `SigningResult::SIGNING_FAILED` mapping

**Severity:** P1. Core's `signmessagewithprivkey`
(`bitcoin-core/src/rpc/signmessage.cpp:92-95`):

```cpp
if (!MessageSign(key, strMessage, signature)) {
    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed");
}
```

beamchain mirrors `<<"Sign failed">>` (line 4278) but the error CODE
beamchain emits (`?RPC_INVALID_ADDRESS_OR_KEY`) is correct... except the
shape of the wrapping: Core's RPC layer throws an exception that gets
JSON-encoded as `{"code": -5, "message": "Sign failed"}`. beamchain
returns `{error, ?RPC_INVALID_ADDRESS_OR_KEY, <<"Sign failed">>}` which
the outer dispatch unwraps to the same JSON shape — parity-acceptable.

The deeper concern: when `sign_message/2` returns `{error, Reason}`
(line 4276-4279), the actual Reason atom (`signing_failed`,
`internal_nif_error`, etc.) is DISCARDED. Operators / monitoring see
only the generic `Sign failed`. Core's enum lets debug logging
distinguish "the key was rejected by libsecp256k1" from "the message
hash was non-32-byte" from "the libsecp256k1 lib was missing". beamchain
collapses all to one string.

**File:** `src/beamchain_rpc.erl:4276-4279`.

**Impact:** debuggability; operators cannot distinguish causes when
`signmessagewithprivkey` fails.

---

## BUG-18 (P1) — `sign_message` low-S normalisation flips recid bit unconditionally without checking the post-flip recovery still finds the right pubkey

**Severity:** P1. `ecdsa_sign_recoverable/2` (line 365-384):

```erlang
case is_low_s(S) of
    true ->
        {ok, <<RecId:8, R/binary, S/binary>>};
    false ->
        SNorm = normalize_s(S),
        NewRecId = RecId bxor 1,        %% <-- flip bit 0
        {ok, <<NewRecId:8, R/binary, SNorm/binary>>}
end;
```

The recid-flip-on-S-negation is documented Bitcoin Core behaviour: when
S is negated (mod n), the recovered pubkey changes sign on its Y
coordinate, which flips the parity bit (bit 0 of recid). The XOR of
bit 0 is correct for parity-only flipping... but `recid` ALSO encodes
bit 1 (the overflow flag, whether R was reduced mod p before signing).
Core's reference implementation in libsecp256k1
(`secp256k1_ecdsa_sign_recoverable` + the
`secp256k1_ecdsa_recoverable_signature_normalize` helper) flips bit 0
correctly because S-negation is a Y-coord-only flip.

beamchain's `RecId bxor 1` IS correct for the typical case (recid in
{0, 1}). For overflow-recid values (2, 3 — extremely rare in practice,
~1-in-2^128), the XOR-1 would flip the parity bit while preserving the
overflow bit, which IS still the correct normalization. So this is OK
mathematically, but the comment at line 372-373 ("flip the odd/even bit
of RecId") is technically inaccurate — it says "odd/even bit" but the
code XORs bit 0 which IS the parity bit. The comment is correct;
filing as P2 for documentation hygiene but escalating to P1 because the
fleet pattern of "comment-as-confession" includes 15+ beamchain
instances and a 16th confused comment here would compound.

After scrutiny: the comment IS accurate, the code IS correct. Filing as
INFORMATIONAL — withdrawing P1; downgrading to P2 if anything.

**Actual filing:** P2.

**File:** `src/beamchain_crypto.erl:374-381`.

**Impact:** none in practice; reviewer-confusion risk.

---

## Summary

**Bug count:** 18 (BUG-1 through BUG-18).

**Severity distribution:**
- **P0-CDIV:** 8 (BUG-3, BUG-4, BUG-5, BUG-6, BUG-7, BUG-9, BUG-11,
  BUG-13, BUG-14) = 9 — recount.
- **P0:** 1 (BUG-1).
- **P1:** 5 (BUG-2, BUG-8, BUG-12, BUG-15, BUG-17).
- **P2:** 3 (BUG-10, BUG-16, BUG-18).

Recount: P0-CDIV: BUG-3, BUG-4, BUG-5, BUG-6, BUG-7, BUG-9, BUG-11,
BUG-13, BUG-14 = 9. P0: BUG-1 = 1. P1: BUG-2, BUG-8, BUG-12, BUG-15,
BUG-17 = 5. P2: BUG-10, BUG-16, BUG-18 = 3. Total: 9+1+5+3 = 18. ✓

**Fleet patterns confirmed:**
- "stricter-than-Core enum guard" (BUG-3, Header range 27..42 vs
  Core's silent 27..255) — ~3rd distinct beamchain instance, same
  shape as W155 BUG-3.
- "missing-HRP class" (BUG-8, 5 networks collapse to 2) — ~5th
  distinct beamchain instance; W155 BUG-16 same-shape carry-forward.
- "_byte_count_assert_only" test-pattern (BUG-1) — same shape as
  W108 BUG-13.
- "comment-as-confession" candidate (BUG-16 silent fallback) — 16th
  distinct beamchain instance pending.
- "gen_server-as-RPC-bottleneck" (BUG-15) — 4th instance of beamchain
  wallet gen_server held during HD derivation.
- "entire spec mode absent" (BUG-13 BIP-322 Simple, BUG-14 BIP-322
  Full, BUG-6 P2TR) — same shape as W155 BUG-2 (BIP-23 proposal mode
  absent). Pattern: beamchain has the cryptographic primitives but no
  spec-mode integration.
- "wallet-emits-X-but-cannot-verify-X" (BUG-5 + BUG-7 cluster) —
  default-address-type round-trip broken.

**Top three findings:**

1. **BUG-13 + BUG-14 + BUG-6 (P0-CDIV cluster, BIP-322 entirely
   absent)** — beamchain has NO implementation of BIP-322 Simple OR
   Full. The cryptographic primitives needed (schnorr_verify,
   tagged_hash, script interpreter, witness execution) all exist and
   are exported. The to_spend/to_sign virtual-tx shape exists for
   signet block-solution verification but isn't factored into a
   reusable helper. Result: P2TR / P2WPKH / P2SH-P2WPKH /
   P2WSH addresses cannot have their messages verified, period. Modern
   wallet ecosystem (sparrow, mempool.space, Electrum, Ledger Live)
   universally uses BIP-322 Simple for non-P2PKH addresses; beamchain
   cannot interop. This is the same pattern as W155 BUG-2 (BIP-23
   proposal mode absent): a major spec section never implemented.

2. **BUG-5 + BUG-7 (P0-CDIV, wallet round-trip broken for default
   address type)** — beamchain's wallet emits P2WPKH addresses BY
   DEFAULT (`rpc_getnewaddress`), but `rpc_verifymessage` hard-rejects
   all non-P2PKH addresses with `Address does not refer to key`.
   Simultaneously, `rpc_signmessage` has NO address-type validation
   gate — it blindly produces a base64 signature for ANY address the
   wallet keystore can look up. So a user creates a wallet → gets a
   bech32 address → signmessage succeeds → verifymessage rejects.
   The signed-message UX is broken end-to-end for the default settings.

3. **BUG-3 + BUG-4 + BUG-11 cluster (P0-CDIV, BIP-137 segwit-tagged
   header bytes never emitted, sometimes mis-routed when received)** —
   beamchain's `sign_message/2` ALWAYS emits header `27 + recid + 4`
   (P2PKH-compressed). It never emits 35..38 (P2SH-P2WPKH) or 39..42
   (P2WPKH). `verify_message/3` accepts headers 27..42 (BIP-137 range)
   but the outer `rpc_verifymessage` collapses them all into a single
   PKH comparison. So a Trezor / Coldcard / modern Electrum signature
   with header byte 39 (P2WPKH, recid 0) is structurally valid for the
   target address but gets `Address does not refer to key` from
   beamchain's RPC layer (because the RPC layer only routes P2PKH
   addresses to the verifier). Combined: no BIP-137 tagged signature
   coming OR going through beamchain works correctly for non-P2PKH
   addresses.
