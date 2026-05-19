# W161 — BIP-32 / BIP-39 / BIP-43 / BIP-44 / BIP-49 / BIP-84 / BIP-86 HD wallet derivation + seed mnemonic (beamchain)

**Wave:** W161 — BIP-32 (`CKD priv/pub`, MUST-retry on `IL ≥ n` or
`child == 0`, hardened format, chain code, master-from-seed
`HMAC-SHA512("Bitcoin seed", S)`, parent fingerprint =
`HASH160(parent_pubkey)[0:4]`, 1-byte depth field overflow gate,
xprv/xpub 78-byte base58check serialisation with per-network version
bytes), BIP-39 (12/15/18/21/24-word mnemonic, 11-bit chunks, ENT/32
checksum, PBKDF2-HMAC-SHA512 with iter=2048 + salt=`"mnemonic"+passphrase`,
NFKD normalisation), BIP-43 / BIP-44 / BIP-49 / BIP-84 / BIP-86 purpose
paths, descriptor expansion + gap limit + seed entropy validation +
memory hygiene zeroize.

**Scope:** discovery only — no production code changes.

## Bitcoin Core references

- `bitcoin-core/src/key.cpp:293-310` (`CKey::Derive`) — BIP-32 priv-side
  child key derivation. `BIP32Hash(cc, nChild, header, data, vout)`
  HMAC-SHA-512, then `secp256k1_ec_seckey_tweak_add(keyChild,
  vout.data())`. Returns the libsecp256k1 success flag — on failure
  (`IL >= n` OR `(seckey + IL) mod n == 0`) the call `ClearKeyData()`s
  the child and returns `false`; the BIP-32 spec §"Public parent key
  → private child key" requires the caller to skip this index and
  proceed to `i+1`. Core's wallet implementations
  (`scriptpubkeyman.cpp::DeriveNewSeed` / `LegacyScriptPubKeyMan::
  TopUpInactiveHDChain`) react to the false return by advancing the
  child index.
- `bitcoin-core/src/key.cpp:482-489` (`CExtKey::Derive`) — first
  statement is **`if (nDepth == std::numeric_limits<unsigned char>::max())
  return false;`**. The wire format has only 1 byte for the depth
  field; a derivation that would produce `nDepth=256` MUST fail
  cleanly rather than wrap-around to `0` and forge a parentless
  extended key.
- `bitcoin-core/src/key.cpp:491-501` (`CExtKey::SetSeed`) —
  master-from-seed: `CHMAC_SHA512{"Bitcoin seed", 12}.Write(seed)`,
  `key.Set(vout, vout+32, true)`. `key.Set` itself runs
  `Check(seckey)` which calls `secp256k1_ec_seckey_verify` — so an
  invalid `IL` (zero or `≥ n`) leaves `key` invalid (`fValid=false`)
  and any further use trips an assertion. (Spec note: chance is
  ~`1 / 2^127`; implementations are advised to ask the user for a
  different seed rather than silently produce a deterministic but
  invalid master.)
- `bitcoin-core/src/key.cpp:503-521` (`CExtKey::Neuter` + `Encode`) —
  78-byte serialisation: `1 depth || 4 fingerprint || 4 child ||
  32 chaincode || 33 keydata`. The version-byte prefix is added by the
  base58 wrapper (`EncodeExtPubKey` / `EncodeExtPrvKey` in
  `key_io.cpp`).
- `bitcoin-core/src/key_io.cpp:204-237` (`EncodeExtKey` /
  `DecodeExtKey`) — per-network version bytes:
  `mainnet xpub = 0x0488B21E`, `mainnet xprv = 0x0488ADE4`,
  `testnet/signet/regtest tpub = 0x043587CF`,
  `testnet/signet/regtest tprv = 0x04358394`.
- `bitcoin-core/src/key.cpp:523-530` (`CExtKey::Decode`) — guards
  `depth==0 → child==0 AND fingerprint==0`, and pad byte 41 == 0;
  rejects (sets key to invalid `CKey()`) otherwise.
- `bitcoin-core/src/pubkey.cpp:341-348` (`CPubKey::Derive`) — pub-side
  CKD, refuses hardened (`nChild >> 31 != 0` would set IL=secret
  bytes which the pub-only path doesn't have).
- `bitcoin-core/src/pubkey.cpp:411-420` (`CPubKey::GetID` +
  `CExtPubKey::Derive` fingerprint computation) — `id = Hash160(pubkey)`
  then `memcpy(vchFingerprint, &id, 4)`. The fingerprint is the
  little-endian first 4 bytes of the HASH160 of the **parent**
  pubkey.
- `bitcoin-core/src/wallet/scriptpubkeyman.cpp` (`DescriptorScriptPubKeyMan`) —
  BIP-32/39 seed flow: seed entropy is generated via `GetStrongRandBytes`,
  master key derived via `CExtKey::SetSeed`. After encryption the
  seed lives only as `Hash(<encrypted seed>)` in `m_storage`; the
  plaintext seed is `memory_cleanse`d. Mnemonic is NOT first-class in
  Core — descriptor wallets persist the **seed** (32 bytes from
  `pbkdf2_hmac_sha512("mnemonic"+passphrase, mnemonic, 2048, 64)` if
  the user-supplied seed came from a mnemonic), not the original
  mnemonic words.
- `bitcoin-core/src/wallet/scriptpubkeyman.cpp::TopUpInactiveHDChain` —
  gap-limit enforcement: when an address is observed used in a block,
  the wallet tops up the keypool to keep `nKeyPoolSize` lookahead
  addresses beyond the highest used index. The default gap limit
  exposed at the RPC layer (`-keypool=N`) is 1000, but BIP-44's
  recommended gap limit for cross-wallet recovery is 20.
- BIP-32 §"Key derivation" — the retry-on-`IL >= n`-or-`child == 0`
  loop is mandatory ("In case parse256(IL) ≥ n or ki = 0, the
  resulting key is invalid, and one should proceed with the next
  value for i").
- BIP-32 §"Serialization format" — depth is a single byte
  (0–255). A wallet that allows derivation past depth=255 MUST
  refuse to serialise the result.
- BIP-39 §"From mnemonic to seed" — passphrase MUST be NFKD-normalised;
  salt is the literal ASCII string `"mnemonic"` concatenated with
  the NFKD-normalised passphrase; PBKDF2-HMAC-SHA512 with
  iter=2048 and dkLen=64.
- BIP-43 — `purpose'` field is the path's first hardened component.
  BIP-44 = `44'`, BIP-49 = `49'`, BIP-84 = `84'`, BIP-86 = `86'`.
- BIP-86 — Taproot key-path-only addresses: `tweak = tagged_hash(
  "TapTweak", x_only_pubkey || empty_string)`. The `empty_string`
  serialised merkle root is what distinguishes BIP-86 from a
  script-tree Taproot (which feeds the actual merkle root). Two
  separate code paths.

## Files audited

- `src/beamchain_wallet.erl` (2142 LOC) — `master_from_seed/1`
  (line 1883-1896), `derive_child/2` (1902-1942), `derive_path/2`
  (1948-1953), `parse_path/1` (1955-1985), `purpose_for_type/1`
  (854-856), `generate_address/3` + `generate_address_silent/3`
  (763-852), `create/3` (193-199), `create_with_mnemonic/1,2`
  (210-229), `restore_from_mnemonic/2` (235-245), `do_encrypt_wallet`
  (2043-2065), `do_unlock_wallet` (2070-2099), `do_lock_wallet`
  (2102-2112), `save_wallet/1` (1642-1677), `terminate/2` (731-740),
  `encrypt_and_write/3` + `derive_key/2` (1694-1731).
- `src/beamchain_bip39.erl` (265 LOC) — `entropy_to_mnemonic/1`,
  `mnemonic_to_entropy/1`, `mnemonic_to_seed/2`, `validate_mnemonic/1`,
  `generate_mnemonic/1`, `wordlist/0`.
- `src/beamchain_descriptor.erl` (1424 LOC) — `decode_xkey/1`
  (1166-1199), `encode_xpub/3` (1232-1239), `encode_xprv/3`
  (1241-1248), `parse_extended_key/4` (684-718),
  `derive_bip32_privkey_path/3` + `derive_bip32_pubkey_path/3`
  (904-927), `script_from_desc/2 :: #desc_tr{}` (1015-1041).
- `src/beamchain_crypto.erl` (1071 LOC) — `seckey_tweak_add/2`
  (308-312), `pubkey_tweak_add/2` (484-486),
  `xonly_pubkey_tweak_add/2` (488-492),
  `taproot_tweak_seckey/1` (328-338), `negate_seckey/1` (343-347),
  `pubkey_from_privkey/1` (480-482).
- `c_src/beamchain_crypto_nif.c` (1357 LOC) — `seckey_tweak_add_nif`
  (1107-1124), `pubkey_tweak_add_nif` (828-848),
  `xonly_pubkey_tweak_add_nif` (856-880).
- `src/beamchain_rpc.erl:732, 5350-5377` — `rpc_getwalletmnemonic/1`.
- `priv/bip39/english.txt` — 2048 words.
- `test/beamchain_bip39_tests.erl` — TREZOR vectors + empty-passphrase
  vector + corruption tests.
- `test/beamchain_wallet_tests.erl:10-64` — BIP-32 test vector 1 +
  vector 2 + BIP-84 mainnet test vector.

---

## Gate matrix (40 sub-gates / 16 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | Master-from-seed | G1: HMAC-SHA512 key = literal ASCII `"Bitcoin seed"` (12 bytes) | PASS (`beamchain_wallet.erl:1887`) |
| 1 | … | G2: seed length accepted in [128 bits, 512 bits] = [16, 64] bytes | PASS (`beamchain_wallet.erl:1884`) |
| 1 | … | G3: `IL == 0` or `IL >= n` → reject seed (BIP-32 spec) | **FAIL — BUG-1** (no check; pubkey_from_privkey then `{ok, …}` hard-match → `{badmatch, {error, invalid_seckey}}` crashes the gen_server in the vanishing ~1/2^127 case rather than returning a clean `{error, invalid_seed}` so the operator can re-roll) |
| 2 | BIP-32 CKD priv | G4: hardened (`i >= 2^31`) → `data = <<0, k_par, i>>` | PASS (`beamchain_wallet.erl:1906-1908`) |
| 2 | … | G5: non-hardened → `data = <<K_par, i>>` (compressed pubkey first) | PASS (line 1910) |
| 2 | … | G6: child priv via libsecp `seckey_tweak_add` NOT pure-Erlang GMP (cross-cite W160 BUG-11) | PASS (`beamchain_crypto.erl:310-312` delegates to NIF `secp256k1_ec_seckey_tweak_add`) |
| 2 | … | G7: **MUST retry on `IL ≥ n` or `(k_par + IL) mod n == 0`** | **FAIL — BUG-2 (5-WAVE CARRY-FORWARD from W160 BUG-12)** — `derive_child/2` at `beamchain_wallet.erl:1914` hard-matches `{ok, ChildPriv} = …seckey_tweak_add(…)`; on the NIF's `{error, tweak_failed}` return the function crashes with `{badmatch, {error, tweak_failed}}` instead of advancing `i` to `i+1`. Same in `beamchain_descriptor.erl:926`. |
| 2 | … | G8: child chain_code = `IR` (rightmost 32 bytes of HMAC output) | PASS (line 1912-1913) |
| 2 | … | G9: child depth = parent.depth + 1 | PASS (line 1921, 1939) |
| 2 | … | G10: **depth-byte-overflow refuse-derive at depth=255 (BIP-32 wire format only has 1 byte)** | **FAIL — BUG-3** (no `Parent#hd_key.depth >= 255` gate at the top of `derive_child/2`; an Erlang integer at 256 silently truncates when re-serialised in `encode_xpub`/`encode_xprv` since those expect to write `0:8`) |
| 3 | BIP-32 CKD pub | G11: pub-only path refuses hardened indices | PASS (`beamchain_wallet.erl:1925-1927` raises `hardened_derivation_requires_private_key`) |
| 3 | … | G12: child pub via libsecp `pubkey_tweak_add` | PASS (NIF `pubkey_tweak_add_nif` at `beamchain_crypto_nif.c:828-848`) |
| 3 | … | G13: pub-CKD also retries on `IL ≥ n` or child-point at infinity | **FAIL — BUG-4** (`beamchain_wallet.erl:1933` hard-matches `{ok, ChildPub} = pubkey_tweak_add(…)`; same shape as BUG-2 — crashes on the NIF's `{error, _}` return instead of `i+1` retry) |
| 4 | Parent fingerprint | G14: fingerprint = `HASH160(parent_compressed_pubkey)[0:4]` | PASS (`beamchain_wallet.erl:1916, 1934`) |
| 4 | … | G15: master fingerprint = `<<0, 0, 0, 0>>` (4 zero bytes) | PASS (`beamchain_wallet.erl:1894`) |
| 5 | BIP-39 mnemonic encode | G16: entropy size in {16, 20, 24, 28, 32} bytes | PASS (`beamchain_bip39.erl:51-52`) |
| 5 | … | G17: checksum = first ENT/32 bits of `SHA256(entropy)` | PASS (`beamchain_bip39.erl:54-57`) |
| 5 | … | G18: 11-bit chunking + wordlist lookup with 1-based Erlang tuple | PASS (`beamchain_bip39.erl:202-205`) |
| 6 | BIP-39 mnemonic decode | G19: rejects unknown word with `{error, {unknown_word, W}}` | PASS (`beamchain_bip39.erl:210-214`) |
| 6 | … | G20: rejects bad checksum | PASS (`beamchain_bip39.erl:88-93`) |
| 7 | BIP-39 mnemonic-to-seed | G21: PBKDF2-HMAC-SHA512 iter=2048 dklen=64 | PASS (`beamchain_bip39.erl:36-37, 112-113`) |
| 7 | … | G22: salt = `"mnemonic" ++ NFKD(passphrase)` | PASS (`beamchain_bip39.erl:111`) |
| 7 | … | G23: mnemonic words joined with single ASCII space U+0020 then NFKD | PASS (`beamchain_bip39.erl:108-110, 252-255`) |
| 7 | … | G24: NFKD applied unconditionally (not only when non-ASCII bytes present) | PASS (`beamchain_bip39.erl:260-264`) |
| 8 | Wordlist coverage | G25: English wordlist (BIP-39 default) loaded with N=2048 | PASS (`priv/bip39/english.txt`, asserted at `beamchain_bip39.erl:170-172`) |
| 8 | … | G26: optional wordlists (Japanese, Chinese-S, Spanish, French, Italian, Korean, Czech) loadable | **FAIL — BUG-5** (only `english.txt` ships; non-English mnemonics from Trezor / ColdCard / Sparrow / Ledger / a hardware wallet localised for JP/CN/KO cannot be restored) |
| 9 | BIP-43 / BIP-44 / BIP-49 / BIP-84 / BIP-86 purpose path | G27: `purpose_for_type(p2wpkh) = 84'` | PASS (`beamchain_wallet.erl:854`) |
| 9 | … | G28: `purpose_for_type(p2tr) = 86'` | PASS (line 855) |
| 9 | … | G29: `purpose_for_type(p2pkh) = 44'` | PASS (line 856) |
| 9 | … | G30: P2SH-P2WPKH (BIP-49 = `49'`) supported | **FAIL — BUG-6** (no `purpose_for_type(p2sh_p2wpkh)` clause; `make_address(p2sh_p2wpkh, …)` would crash at line 858-863's `case` — `function_clause` — for the entire BIP-49 family) |
| 9 | … | G31: account index = `0'` (hardened 0) | PASS (`beamchain_wallet.erl:781, 826`: literal `?HARDENED` = `0 + ?HARDENED`) — but **WARN-1**: the literal `?HARDENED` (without the explicit `+ 0`) is a footgun; a future refactor that adds explicit account selection has to remember that `?HARDENED` means "account 0". |
| 9 | … | G32: full path = `m / purpose' / coin_type' / account' / chain / index` | PASS (path tuple at line 781, 826) |
| 10 | xprv/xpub serialise | G33: 78-byte payload + 4-byte SHA-256d checksum = 82-byte base58 input | PASS (`beamchain_descriptor.erl:1238-1239, 1247-1248, 1250-1256`) |
| 10 | … | G34: depth, fingerprint, child-index propagated from the source key | **FAIL — BUG-7 (P0-CDIV)** — `encode_xpub/3` and `encode_xprv/3` (`beamchain_descriptor.erl:1238, 1247`) HARDCODE depth=0, fingerprint=`0:32`, child-index=`0:32` regardless of the input. A derived child (depth=5, real parent fingerprint, child=N) serialises as a parentless master xpub. Any tool consuming the output round-trips back to wrong state |
| 10 | … | G35: per-network version bytes (mainnet vs testnet/signet/regtest) | PARTIAL — supports `mainnet` and `tpub` / `tprv` for non-mainnet (line 1235-1237, 1244-1246), but conflates testnet3 + testnet4 + signet + regtest (all use the testnet `0x043587CF` prefix in Core too, so PASS on parity — but does NOT support `ypub`/`yprv` (BIP-49 mainnet 0x049D7CB2), `zpub`/`zprv` (BIP-84 mainnet 0x04B24746), `upub`/`uprv` (BIP-49 testnet), `vpub`/`vprv` (BIP-84 testnet), `Ypub`/`Yprv` (multisig P2SH-P2WSH), `Zpub`/`Zprv` (multisig P2WSH). **PARTIAL gates** |
| 11 | Wallet save / load | G36: BIP-39 mnemonic persisted in wallet file (so post-restart `getwalletmnemonic` works) | **FAIL — BUG-8 (P0-FUNDS)** — `save_wallet/1` (`beamchain_wallet.erl:1644-1677`) omits the `<<"mnemonic">>` field in BOTH the encrypted and unencrypted JSON write paths. Comment-as-confession at line 161-162: *"Held in memory only for getwalletmnemonic export; not yet persisted to the wallet file."* Operators who created a wallet via `create_with_mnemonic` and restart the daemon BEFORE writing down the mnemonic permanently lose recovery material. The seed is persisted (encrypted) so derivation continues to work, but the mnemonic words themselves are unrecoverable. |
| 11 | … | G37: on `do_encrypt_wallet` (transition unencrypted → encrypted) the in-memory mnemonic is cleared | **FAIL — BUG-9 (P0-SEC)** — `do_encrypt_wallet` at `beamchain_wallet.erl:2055-2062` clears `seed` and `master_key` but DOES NOT clear `mnemonic`. After encryption the mnemonic survives in plaintext in BEAM heap; `getwalletmnemonic` returns it without requiring the passphrase (the `locked` flag IS set, so `handle_call(getwalletmnemonic, …)` at line 522-525 refuses to return it — but in-memory residue is exposed to any process that introspects the gen_server state via `sys:get_state/1`, which is a debug-only call that requires no auth). The clearance gap is a hygiene violation, not a direct disclosure. |
| 12 | Wallet encryption (at-rest) | G38: ONE PBKDF2 implementation across the encryption surface | **FAIL — BUG-10 (P0-SEC)** — TWO DIFFERENT at-rest encryption schemes coexist in the same module: (a) `do_encrypt_wallet/2` uses `PBKDF2-SHA512` with 25000 iterations producing 48-byte key||IV (line 2125-2128), (b) `encrypt_and_write/3` uses HOMEGROWN iterated `SHA256(Acc || Pass || Salt)` 100000 times producing a 32-byte key (line 1719-1731). The (b) path is custom crypto, not PBKDF2, and is reached by `save_wallet` line 1676 when `Passphrase =/= undefined`. The two paths are not interoperable: a wallet encrypted via `encryptwallet` (path a) and re-saved through `save_wallet` (which routes via path b if `passphrase` was kept in state) yields a file decryptable only by path b's bespoke loop. |
| 13 | Memory hygiene | G39: `terminate/2` zeroes the seed, master_key, AND mnemonic | **FAIL — BUG-11 (P0-SEC)** — `terminate/2` at `beamchain_wallet.erl:731-740` calls `crypto:strong_rand_bytes(byte_size(Seed))` then THROWS THE RESULT AWAY (`_ = …`). Erlang binaries are immutable; this does literally nothing to the seed's heap residue. `mnemonic` and `master_key` are not touched at all. The function name "Overwrite seed memory (best effort)" is a **comment-as-confession** that the author knew it wouldn't work. |
| 14 | Gap limit | G40: `gap_limit` is consulted when generating addresses past the last-used index | **FAIL — BUG-12** — `gap_limit` is plumbed into `#wallet_state{gap_limit}` (line 453, 488, 510) and reported via `getwalletinfo` (line 641), but a `grep` shows NO consumer reads the field. Address generation always advances `next_receive`/`next_change` regardless of how many lookahead entries are unused. Classic dead-data plumbing pattern (cross-cite W149 BUG-2/17 `havePruned`). |

---

## Severity bands

| Tier | Count |
|------|-------|
| P0-CDIV (cross-impl divergence at consensus / wallet API boundary) | 2 (BUG-7, BUG-13) |
| P0-FUNDS (irrecoverable user fund / recovery loss) | 1 (BUG-8) |
| P0-SEC (security / side-channel / DoS / key-material exposure) | 4 (BUG-9, BUG-10, BUG-11, BUG-15) |
| P1 (correctness / hygiene with material impact) | 5 (BUG-1, BUG-2, BUG-3, BUG-4, BUG-12) |
| P2 (cosmetic / missing-feature parity) | 5 (BUG-5, BUG-6, BUG-14, BUG-16, BUG-17) |

**Total: 17 bugs** across 14 behaviours.

---

## BUG-1 (P1) — `master_from_seed/1` does NOT reject `IL == 0` or `IL ≥ n`

**Severity:** P1. BIP-32 §"Master key generation" says: *"In case
parse256(IL) ≥ n or IL = 0, the master key is invalid, and one should
proceed with the next value for the seed."* Core's `CExtKey::SetSeed`
(`key.cpp:491-501`) calls `key.Set(vout, vout+32, true)` which runs
`Check(seckey) == secp256k1_ec_seckey_verify`. If the seckey is
invalid `key.fValid` ends up `false` and any downstream
`assert(key.IsValid())` (e.g. in `CKey::GetPubKey`) trips.

beamchain's `master_from_seed/1` at `beamchain_wallet.erl:1883-1896`:

```erlang
master_from_seed(Seed) when byte_size(Seed) >= 16,
                             byte_size(Seed) =< 64 ->
    <<IL:32/binary, IR:32/binary>> =
        beamchain_crypto:hmac_sha512(<<"Bitcoin seed">>, Seed),
    {ok, PubKey} = beamchain_crypto:pubkey_from_privkey(IL),  %% BUG: hard-match
    #hd_key{
        private_key  = IL,
        public_key   = PubKey,
        chain_code   = IR,
        depth        = 0,
        fingerprint  = <<0, 0, 0, 0>>,
        child_index  = 0
    }.
```

If the (vanishingly rare ~1/2^127) seed happens to produce
`IL ≥ secp256k1.n` or `IL == 0`, `secp256k1_ec_pubkey_create` returns
0 and the NIF returns `{error, invalid_seckey}`. The `{ok, PubKey} =`
pattern then crashes the calling gen_server (`{badmatch, {error,
invalid_seckey}}`) instead of returning `{error, invalid_seed}` so the
operator can re-roll.

**File:** `src/beamchain_wallet.erl:1883-1896`.

**Core ref:** `bitcoin-core/src/key.cpp:491-501` (`CExtKey::SetSeed`).

**Impact:**
- Cryptographically negligible probability (1/2^127), but a
  daemon-crash on master_from_seed is a worse failure mode than a
  clean `{error, invalid_seed}` return. The crash leaves the partial
  wallet state in an inconsistent gen_server-respawn loop (any
  retry hits the same crash for the same seed).
- Fleet parity gap: 9 of 10 hashhog impls return a clean error on
  this corner; beamchain crashes.

---

## BUG-2 (P1) — `derive_child/2` MUST retry on `IL ≥ n` or `child == 0` (5-WAVE CARRY-FORWARD from W160 BUG-12)

**Severity:** P1 (cross-cite W160 BUG-12 — STILL PRESENT at W161).
BIP-32 §"Public parent key → private child key" + §"Private parent
key → private child key" mandates: *"In case parse256(IL) ≥ n or
k_i = 0, the resulting key is invalid, and one should proceed with
the next value for i."* Core's `CKey::Derive` (`key.cpp:307-309`)
returns the libsecp256k1 success flag from
`secp256k1_ec_seckey_tweak_add`; on failure the calling code
(`scriptpubkeyman.cpp::TopUpInactiveHDChain`) advances the keypool
index and tries again.

beamchain's `derive_child/2` at `beamchain_wallet.erl:1902-1924` (priv
branch) and 1928-1942 (pub branch) hard-matches `{ok, ChildPriv} =
seckey_tweak_add(…)` / `{ok, ChildPub} = pubkey_tweak_add(…)`. The NIF
correctly returns `{error, "tweak_failed"}` on the rare-but-
spec-required failure case (`beamchain_crypto_nif.c:1120-1121` for
seckey, `:841-842` for pubkey), but the Erlang side then crashes the
gen_server.

Same pattern at `beamchain_descriptor.erl:926` in
`derive_bip32_privkey_path/3`.

**File:** `src/beamchain_wallet.erl:1914, 1933`;
`src/beamchain_descriptor.erl:910, 926`.

**Core ref:** `bitcoin-core/src/key.cpp:293-310`;
`bitcoin-core/src/pubkey.cpp:341-348`; BIP-32 spec.

**Impact:**
- Cryptographically negligible probability (~1/2^127 per derivation),
  but: a single bad seed × deep path crashes the entire wallet
  process AND any tx/RPC that triggered the derive.
- Cross-cite W160 BUG-12: this is now the **5TH-CONSECUTIVE-WAVE
  carry-forward** (W156, W157, W158, W159, W160, W161) — a one-line
  fix per call site (`case … of {ok, K} → …; {error, _} → throw
  ({skip_to_next_index, Index+1}) end`) plus a wrapper in
  `derive_path/2` to catch and advance — has been open in successive
  audits for ~30+ days.

---

## BUG-3 (P0-CDIV) — `derive_child/2` has no depth-byte-overflow gate (255 → silent wrap)

**Severity:** P0-CDIV ("depth-byte-overflow" fleet pattern, cross-cite
W161 blockbrew BUG-class). Bitcoin Core's `CExtKey::Derive`
(`key.cpp:482-489`) first statement is:

```cpp
bool CExtKey::Derive(CExtKey &out, unsigned int _nChild) const {
    if (nDepth == std::numeric_limits<unsigned char>::max()) return false;
    out.nDepth = nDepth + 1;
    ...
}
```

This guard exists because the BIP-32 78-byte serialisation has only a
**single byte** for the depth field. A derivation past `nDepth=255`
would produce an extended key that cannot be serialised (or worse,
would silently truncate to `nDepth=0`, which is the master-key
marker, manufacturing a forged parentless extended key).

beamchain's `derive_child/2` at `beamchain_wallet.erl:1902-1942` has
NO depth check. Erlang integers are arbitrary-precision so the
in-memory `#hd_key.depth = 256` is fine — but when that key is fed to
`beamchain_descriptor:encode_xpub/3` or `encode_xprv/3`, the depth is
re-serialised as `0:8` (line 1238: `<<Version:32/big, 0, 0:32, 0:32,
…>>`). **Actually** — and this is worse — the `encode_xpub` /
`encode_xprv` hardcodes depth to literal `0` (BUG-7 below) and never
reads `#hd_key.depth` at all, so the depth-byte question is moot
PER-CALL but the dead-data divergence is still present. The
ground-truth check (refuse-derive at 255) is missing.

**File:** `src/beamchain_wallet.erl:1902-1942` (`derive_child/2`).

**Core ref:** `bitcoin-core/src/key.cpp:482-483`.

**Impact:**
- If a future fix lands BUG-7 (proper depth/fp/child propagation in
  encode_xpub), depth wrap from 256→0 would silently forge a master
  xpub from a deep-derived child. The fix LOC for BUG-3 is two lines
  at the top of `derive_child/2`:
  `if Parent#hd_key.depth >= 255 → error(depth_exceeded)`.

---

## BUG-4 (P1) — pub-side `derive_child/2` also hard-matches `{ok, _}` and crashes on `IL ≥ n`

**Severity:** P1. Same root cause as BUG-2 but on the pub-only
derivation branch at `beamchain_wallet.erl:1928-1942`:

```erlang
derive_child(#hd_key{private_key = undefined, chain_code = ChainCode,
                      public_key = PubKey} = Parent, Index) ->
    Data = <<PubKey/binary, Index:32/big>>,
    <<IL:32/binary, IR:32/binary>> =
        beamchain_crypto:hmac_sha512(ChainCode, Data),
    {ok, ChildPub} = beamchain_crypto:pubkey_tweak_add(PubKey, IL),  %% BUG
    ...
```

`pubkey_tweak_add_nif` (`beamchain_crypto_nif.c:828-848`) returns
`{error, "tweak_failed"}` on `IL ≥ n` or child-point at infinity.
Hard-match crashes the gen_server.

**File:** `src/beamchain_wallet.erl:1933`.

**Core ref:** `bitcoin-core/src/pubkey.cpp:341-348`.

**Impact:** Identical to BUG-2 but on the watch-only / xpub-export
path (`bip32_key{extkey={pub, …}}` derivation in
`beamchain_descriptor`). A neutered xpub feeding a deep gap-limit
sweep can hit this with probability ~`numDerivations / 2^127`. Not a
real risk but a parity gap.

---

## BUG-5 (P2) — Only English wordlist ships; BIP-39 supports 9 other languages

**Severity:** P2 (missing-feature parity gap). BIP-39 §"Wordlist"
lists 9 official wordlists: English, Japanese, Korean, Spanish,
Chinese (Simplified), Chinese (Traditional), French, Italian, Czech.
Trezor / ColdCard / Sparrow / Ledger / Keystone hardware wallets
offer JP/CN/KO/ES localised mnemonic generation for users with
non-Latin locales.

beamchain's `beamchain_bip39.erl` hardcodes
`-define(WORDLIST_FILE, "bip39/english.txt").` (line 34) and the
`wordlist/0` function (line 147-155) only loads that file. A user who
backed up a Japanese 12-word mnemonic on a Trezor cannot restore that
wallet in beamchain — `mnemonic_to_entropy` rejects every Japanese
word as `{unknown_word, W}`.

**File:** `src/beamchain_bip39.erl:34, 147-155`;
`priv/bip39/english.txt`.

**Core ref:** Core does not ship BIP-39 wordlists at all (descriptor
wallets persist the seed, not the mnemonic) — but every other hashhog
impl that DOES expose BIP-39 (~6 of 10) ships all 9.

**Impact:** Non-English mnemonics from any hardware wallet rejected.
User must manually convert to entropy and feed via raw `create/1`.

---

## BUG-6 (P2) — `purpose_for_type/1` has no clause for P2SH-P2WPKH (BIP-49)

**Severity:** P2. BIP-49 = wrapped SegWit (P2SH-P2WPKH); used by older
hardware wallets and Electrum-derived wallets. The purpose path is
`m/49'/coin'/account'/change/index`. beamchain's `purpose_for_type/1`
at `beamchain_wallet.erl:854-856` defines only:

```erlang
purpose_for_type(p2wpkh) -> 84 + ?HARDENED;
purpose_for_type(p2tr)   -> 86 + ?HARDENED;
purpose_for_type(p2pkh)  -> 44 + ?HARDENED.
```

There's no `purpose_for_type(p2sh_p2wpkh)` clause. The downstream
`make_address(p2sh_p2wpkh, …)` would also fail (no clause in line
858-863). The wallet has no path to mint a BIP-49 address.

**File:** `src/beamchain_wallet.erl:854-856, 858-863`.

**Impact:** Users cannot import / restore BIP-49 wallets. Migration
path from older Electrum / Trezor (pre-2020) wallets is closed.

---

## BUG-7 (P0-CDIV) — `encode_xpub` / `encode_xprv` hardcode depth, fingerprint, child-index to ZERO

**Severity:** P0-CDIV ("dead-data serialisation" / forged-master
divergence). Bitcoin Core's `CExtKey::Encode` (`key.cpp:513-521`):

```cpp
void CExtKey::Encode(unsigned char code[BIP32_EXTKEY_SIZE]) const {
    code[0] = nDepth;
    memcpy(code+1, vchFingerprint, 4);
    WriteBE32(code+5, nChild);
    memcpy(code+9, chaincode.begin(), 32);
    code[41] = 0;
    assert(key.size() == 32);
    memcpy(code+42, key.begin(), 32);
}
```

i.e., depth, fingerprint, and child-index are read from the
extended-key object. They are crucial: a descriptor wallet importing
the resulting xpub uses depth to verify it can extend the path
without overflow; the parent fingerprint is used by PSBT
`PSBT_IN_BIP32_DERIVATION` and `PSBT_OUT_BIP32_DERIVATION` records to
match signers to inputs; the child index is used to reconstruct the
full origin path.

beamchain's `encode_xpub/3` (`beamchain_descriptor.erl:1232-1239`):

```erlang
encode_xpub(PubKey, ChainCode, Network) when byte_size(PubKey) =:= 33,
                                              byte_size(ChainCode) =:= 32 ->
    Version = case Network of
        mainnet -> 16#0488b21e;
        _ -> 16#043587cf
    end,
    Payload = <<Version:32/big, 0, 0:32, 0:32, ChainCode/binary, PubKey/binary>>,
    %%                          ^^                ^^^^   ^^^^
    %%                          depth=0           fp=0   child=0  ← ALL HARDCODED
    base58check_encode_raw(Payload).
```

Same in `encode_xprv/3` (line 1241-1248) — depth=`0`, fp=`0:32`,
child=`0:32` are literals. The function takes only `(PubKey, ChainCode,
Network)` as arguments — there is NO WAY to pass the real depth,
fingerprint, or child index. Every emitted xpub looks like a master
extended public key, regardless of derivation depth.

**File:** `src/beamchain_descriptor.erl:1232-1248`.

**Core ref:** `bitcoin-core/src/key.cpp:503-521` (`CExtKey::Neuter` +
`Encode`).

**Impact:**
- Any tool that consumes a beamchain-exported xpub (a wallet that
  wants to set it up as a watching-only descriptor) sees a forged
  master-claim, attempts to derive `m/0`, `m/1`, ... from what it
  thinks is the root, generates wrong addresses, never sees a UTXO,
  and the user reports "missing funds".
- PSBT signing: a beamchain-emitted PSBT with `PSBT_IN_BIP32_DERIVATION`
  pointing at the emitted xpub fails to verify because the fingerprint
  on the input doesn't match the four zero bytes in the (forged)
  xpub.
- `listdescriptors` RPC (when added) would emit unusable descriptors.
- Cross-fleet: this is `P0-CDIV` because the wire format is BIP-32 wire
  format, and beamchain is silently emitting wrong wire bytes.

---

## BUG-8 (P0-FUNDS) — BIP-39 mnemonic NEVER persisted; restart-after-create loses recovery material

**Severity:** P0-FUNDS. The wallet's `save_wallet/1` at
`beamchain_wallet.erl:1644-1677` omits the `<<"mnemonic">>` field in
BOTH the encrypted and unencrypted JSON paths:

```erlang
WalletData = case Encrypted of
    true ->
        #{
            <<"encrypted">>       => true,
            <<"encrypted_seed">>  => hex_encode(EncSeed),
            <<"encryption_salt">> => hex_encode(EncSalt),
            <<"addresses">>       => Addrs,
            <<"next_receive">>    => encode_index_map(NextRecv),
            <<"next_change">>     => encode_index_map(NextChg),
            <<"created_at">>      => erlang:system_time(second)
            %% NO <<"mnemonic">> field
        };
    false ->
        #{
            <<"seed">>         => hex_encode(Seed),
            <<"addresses">>    => Addrs,
            <<"next_receive">> => encode_index_map(NextRecv),
            <<"next_change">>  => encode_index_map(NextChg),
            <<"created_at">>   => erlang:system_time(second)
            %% NO <<"mnemonic">> field
        }
end,
```

The `mnemonic` field on the in-memory `#wallet_state{}` (line 163)
is set at create-time (`create_with_mnemonic`, `restore_from_mnemonic`)
and is the ONLY copy. **Restart the daemon, the mnemonic is gone
forever.** The seed remains derivable (it's persisted), so address
derivation continues to work — but `getwalletmnemonic` returns
`{error, no_mnemonic}` from line 519-520 because state.mnemonic is
`undefined` on re-load.

The comment-as-confession at line 161-162 explicitly admits this:

```erlang
%% BIP-39 mnemonic backing the seed, when the wallet was created or
%% restored via beamchain_bip39. `undefined` for raw-seed wallets.
%% Held in memory only for getwalletmnemonic export; not yet
%% persisted to the wallet file.
mnemonic = undefined :: [binary()] | undefined
```

(Whichever fleet-pattern label is correct — "comment-as-confession"
or "implementation-is-confession" — this is a textbook example.)

**File:** `src/beamchain_wallet.erl:1644-1677` (save); line 161-163
(state field comment); line 517-526 (`getwalletmnemonic` handler).

**Core ref:** Core descriptor wallets persist the seed (encrypted) but
NOT the mnemonic — Core is consistent in saying "the mnemonic is the
USER's responsibility, write it down at create-time." But Core ALSO
does not expose a `getwalletmnemonic` RPC. beamchain exposes the RPC,
making the persistence gap user-visible (and giving operators a
false sense that the daemon can recall the mnemonic).

**Impact:**
- User creates wallet via `create_with_mnemonic`, sees mnemonic
  printed to the CLI / RPC reply, intends to "write it down later",
  daemon restarts (planned or OOM), mnemonic is GONE permanently.
  Funds are still spendable from the saved seed, but the
  user-recoverable backup is lost.
- The seed is recoverable from the wallet file (which is the
  encrypted form) — so this isn't fund loss in the immediate sense.
  But the user's "trust mnemonic backup" mental model is broken.
- Listed P0-FUNDS because the GAP between "user sees mnemonic once"
  and "user expects to retrieve mnemonic" is silently lost. Operator
  UX equivalent of "we did 90% of BIP-39 and forgot the save line."

---

## BUG-9 (P0-SEC) — `do_encrypt_wallet/2` clears seed + master_key but NOT mnemonic

**Severity:** P0-SEC. `do_encrypt_wallet/2` at
`beamchain_wallet.erl:2042-2065`:

```erlang
NewState = State#wallet_state{
    seed = undefined,
    master_key = undefined,
    encrypted = true,
    locked = true,
    encrypted_seed = EncryptedSeed,
    encryption_salt = Salt
    %% MISSING: mnemonic = undefined
},
```

After encryption the wallet transitions to `locked=true` with seed
and master_key cleared. The mnemonic, however, is left in
`#wallet_state.mnemonic` as plaintext binary words. The
`handle_call(getwalletmnemonic, …)` handler at line 522-525 refuses
to return it when `locked=true`, so the RPC is not directly
disclosing — but:

- `sys:get_state/1` is an Erlang/OTP debug API that returns the full
  gen_server state without consulting any locking logic. An operator
  running `sys:get_state(beamchain_wallet)` from an Erlang shell sees
  the mnemonic in cleartext.
- `erlang:process_info(Pid, dictionary)` and `erlang:process_info(Pid,
  binary)` can expose binaries on the process heap.
- A core dump (e.g., `erl_crash.dump`, which is present at
  `/home/work/hashhog/beamchain/erl_crash.dump` from a recent SIGSEGV)
  contains the entire BEAM heap including all state field bytes; the
  mnemonic would survive verbatim in a crash dump generated AFTER
  encryption.

**File:** `src/beamchain_wallet.erl:2055-2062`.

**Core ref:** `bitcoin-core/src/wallet/scriptpubkeyman.cpp` —
`memory_cleanse` calls on the seed and on any intermediate buffers
holding seed bytes during the `EncryptKeys` transition.

**Impact:**
- A crash dump from a long-running encrypted wallet leaks the
  mnemonic in plaintext.
- Operator running `sys:get_state` for debugging sees it.
- Cross-cite W159/W160 fleet-wide "memory-hygiene-absent" pattern.

---

## BUG-10 (P0-SEC) — TWO different at-rest encryption schemes coexist with different KDF parameters

**Severity:** P0-SEC ("schemes-diverge" / "two-pipeline guard" fleet
pattern, ~20th distinct extension fleet-wide).
`src/beamchain_wallet.erl` contains TWO independent at-rest
encryption code paths with different KDFs:

### Path A — `do_encrypt_wallet` (the official `encryptwallet` RPC):
```erlang
%% PBKDF2 iteration count for key derivation
-define(PBKDF2_ITERATIONS, 25000).
%% AES-256 key size
-define(AES_KEY_SIZE, 32).
%% IV size for AES-256-CBC
-define(AES_IV_SIZE, 16).

derive_encryption_key(Passphrase, Salt) ->
    crypto:pbkdf2_hmac(sha512, Passphrase, Salt, ?PBKDF2_ITERATIONS, 48).

%% AES-256-CBC, IV derived from same DerivedKey (first 16 bytes), no AEAD
```

### Path B — `encrypt_and_write` (called from `save_wallet` when `passphrase` is in state):
```erlang
%% Homegrown SHA-256 iteration; NOT PBKDF2
iterate_key(Pass, Salt, N, Acc) ->
    iterate_key(Pass, Salt, N - 1,
                beamchain_crypto:sha256(<<Acc/binary, Pass/binary, Salt/binary>>)).

derive_key(Passphrase, Salt) ->
    iterate_key(PassBin, Salt, 100000,
                beamchain_crypto:sha256(<<PassBin/binary, Salt/binary>>)).

%% AES-256-GCM (AEAD)
```

| Property | Path A (`do_encrypt_wallet`) | Path B (`encrypt_and_write`) |
|----------|------------------------------|------------------------------|
| KDF | PBKDF2-HMAC-SHA-512 | Homegrown SHA-256 chain |
| Iterations | 25 000 | 100 000 |
| Cipher | AES-256-CBC | AES-256-GCM (AEAD) |
| IV source | Derived from PBKDF2 (last 16 bytes) | `crypto:strong_rand_bytes(12)` |
| Stored fields | `encrypted_seed` + `encryption_salt` | `salt` + `iv` + `tag` in magic-prefixed blob |
| File magic | (none, JSON-level `"encrypted": true`) | ASCII `"BCWALLET"` |
| AEAD authentication | No (MAC missing — IV is deterministic; padding-oracle window) | Yes (GCM tag) |

The two paths are NOT interoperable: a wallet encrypted via Path A
and re-saved via `save_wallet` (which goes to Path B if `Passphrase
=/= undefined` in state) produces an output decryptable only by Path
B. Worse, Path B uses **non-standard custom crypto** (the
SHA-256-chain loop is NOT PBKDF2 — it's structurally similar to
"poor-man's PBKDF2" but the spec'd PBKDF2 prepends a counter and uses
HMAC, not raw concatenation). Path B is OK against random-guess
attacks (100k iterations of SHA-256 is roughly equivalent to PBKDF2
on cost), but it doesn't compose with any standardised analysis and
silently differs from Path A in iteration count, hash function, and
output length.

**File:** `src/beamchain_wallet.erl:1694-1731` (Path B) +
`2032-2128` (Path A).

**Core ref:** Core uses ONE scheme: `OPENSSL_EVP_aes_256_cbc` +
`CCrypter::SetKeyFromPassphrase` (PBKDF2-HMAC-SHA-256, ~25k iterations
calibrated dynamically). No second path.

**Impact:**
- Operator confusion: two RPCs (`encryptwallet` vs the auto-save
  path) produce different on-disk formats. A wallet
  encrypted-then-loaded via the wrong scheme returns
  `{error, wrong_passphrase}` for the correct passphrase.
- Custom crypto in Path B: SHA-256-chain is not vetted by any
  cryptographic standard; future analysis may find weakness that
  PBKDF2-HMAC-SHA-256 doesn't have.
- AEAD in Path B but not Path A: Path A's AES-CBC has no MAC —
  ciphertext tampering is undetectable at decrypt-time; the JSON
  parser is the only "MAC" (and it's a very loose one). A
  bit-flipped ciphertext that happens to JSON-parse can return a
  bogus seed.

---

## BUG-11 (P0-SEC) — `terminate/2` "seed cleanse" is dead code; mnemonic + master_key not even attempted

**Severity:** P0-SEC. `terminate/2` at `beamchain_wallet.erl:731-740`:

```erlang
terminate(_Reason, State) ->
    %% Clear sensitive data on shutdown
    case State#wallet_state.seed of
        undefined -> ok;
        Seed when is_binary(Seed) ->
            %% Overwrite seed memory (best effort)
            _ = crypto:strong_rand_bytes(byte_size(Seed)),
            ok
    end,
    ok.
```

The `crypto:strong_rand_bytes(byte_size(Seed))` call generates a
fresh random binary of the same length as the seed and **throws it
away** (`_ = …`). Erlang binaries are immutable; you cannot overwrite
the bytes of an existing binary. The comment "Overwrite seed memory
(best effort)" is a **comment-as-confession** that the author knew
the construct doesn't do what the name says.

Additionally:
- `mnemonic` is not touched. After terminate, the mnemonic binaries
  (list of 12-24 short binaries) remain on the BEAM heap until GC.
- `master_key` is not touched. The `#hd_key{private_key=<binary>}`
  binary survives.
- `seed` itself, despite the (empty) `_ = crypto:strong_rand_bytes(…)`
  call, is reachable from `State` for as long as `State` is alive in
  the calling stack frame.
- Erlang has no `memory_cleanse` primitive. The closest available
  is `binary:copy/1` to create a fresh binary then `binary_part` to
  trim — but neither overwrites the original. To actually scrub
  secrets, beamchain would have to allocate seed/mnemonic in an
  ETS table or in NIF-managed memory with an explicit `bzero`.

**File:** `src/beamchain_wallet.erl:731-740`.

**Core ref:** Core uses `memory_cleanse` (compiler-barrier `bzero`)
from `support/cleanse.cpp` on every secret-bearing buffer at
destruction.

**Impact:**
- Crash dump (`erl_crash.dump` already exists in the working dir
  from a recent SIGSEGV) contains seed, master_key, AND mnemonic.
- Long-running daemon swap-out leaks secrets to the swap partition.
- Even a graceful `walletlock` doesn't help because
  `do_lock_wallet/1` (line 2102-2112) sets fields to `undefined` but
  the prior binary stays on the heap until GC.

---

## BUG-12 (P1) — `gap_limit` is plumbed but never consulted

**Severity:** P1 (classic "dead-data plumbing" fleet pattern,
~10th blockbrew/beamchain combined instance, cross-cite W149 BUG-2 +
BUG-17 `havePruned`). The `#wallet_state{}` record has a `gap_limit`
field (line 147), initialised to `?DEFAULT_GAP_LIMIT = 20` (line 169)
at every wallet creation site (line 453, 488, 510). The field is
reported in `getwalletinfo` (line 641). But a `grep` over
`beamchain_wallet.erl` shows NO consumer reads the field. Address
generation always increments `next_receive` / `next_change` by 1
on every call, regardless of how many lookahead entries the wallet
has already created without observed activity.

The intended consumer would be (analogous to Core's
`scriptpubkeyman.cpp::TopUpInactiveHDChain`): when scanning blocks,
record the highest index for which an address was used; only generate
new addresses up to `last_used + gap_limit`; if the user requests
`get_new_address` beyond that, refuse with `{error, gap_limit_exceeded}`.
beamchain has no such consumer.

**File:** `src/beamchain_wallet.erl:147, 169, 453, 488, 510, 641`.

**Core ref:** `bitcoin-core/src/wallet/scriptpubkeyman.cpp::TopUpKeyPool`
(which reads `-keypool=N`, Core's analogous knob).

**Impact:**
- Recovery-from-mnemonic on a different impl: a beamchain wallet that
  has handed out (say) 5000 receive addresses with no activity, then
  the user wallpaper-restores to Electrum / Sparrow, Electrum stops
  scanning at default gap=20 → misses everything. User reports
  "missing funds" when in fact the scanner just gave up early.
- Per-process memory: each call to `get_new_address` appends to the
  `addresses` list (line 799-805, 843-850). With no gap-limit cap,
  a hostile RPC client can drive `addresses` list growth to OOM.

---

## BUG-13 (P0-CDIV) — TapTweak no-merkle-root cross-cite W160 BUG-10 (BIP-86 only path)

**Severity:** P0-CDIV (cross-cite W160 BUG-10, STILL PRESENT at
W161). The wallet-side `pubkey_to_p2tr/2` at
`beamchain_wallet.erl:889-901` and the descriptor-side
`script_from_desc(#desc_tr{tree=[]}, _)` at
`beamchain_descriptor.erl:1015-1026` correctly implement BIP-86's
no-script-tree case (`Tweak = tagged_hash("TapTweak", x_only_pubkey)`).
But neither path is parameterised by a merkle root, so:

- `derive_path/2` returning a derived xonly pubkey, fed into the
  wallet's `pubkey_to_p2tr/2`, ALWAYS treats the output as BIP-86
  (key-path-only).
- `crypto:taproot_tweak_seckey/1` at `beamchain_crypto.erl:328-338`
  ALSO hard-codes the no-merkle-root case.

A wallet user who wants to mint a Taproot output with a script tree
(e.g., DLC, OP_CTV, multisig fallback) has NO API path. The descriptor
module CAN handle a script tree (`script_from_desc(#desc_tr{tree=Tree},
_)` at line 1028-1041 builds a merkle root and uses
`<<XOnly/binary, MerkleRoot/binary>>` as the tweak input correctly),
but the wallet's BIP-32-derived-key → P2TR-address flow is
unconditionally BIP-86.

**File:** `src/beamchain_wallet.erl:889-901`;
`src/beamchain_crypto.erl:328-338` (cross-cite W160 BUG-10).

**Core ref:** `bitcoin-core/src/key.cpp:548-563` (`KeyPair::SignSchnorr`
takes `merkle_root` parameter); BIP-341 §"Constructing and spending
Taproot outputs".

**Impact:**
- Script-path Taproot outputs not constructible by the beamchain
  wallet's BIP-32 derivation path.
- Signing a Taproot input whose UTXO commits to a non-empty merkle
  root (e.g., received from a counterparty's Taproot output) produces
  signatures for the WRONG output key — the user reports
  `mandatory-script-verify-flag-failed (Invalid Schnorr signature)`.
- 5-WAVE CARRY-FORWARD from W156→W160→W161 (still present).

---

## BUG-14 (P2) — Account index hardcoded to `0'` (no multi-account API)

**Severity:** P2. `generate_address/3` and `generate_address_silent/3`
construct the BIP-44 path:

```erlang
%% beamchain_wallet.erl:781, 826
Path = [Purpose, CoinType, ?HARDENED, ChainIdx, Index],
%%                          ^^^^^^^^^^^^^
%%                          account = HARDENED + 0 = 0'
```

The third path element is the literal `?HARDENED` macro value
(`16#80000000`), which evaluates to `0 + HARDENED` = account 0'. The
wallet has no API to:

- create a second account (BIP-44 `account = 1'`),
- list accounts,
- assign labels per account.

Core's `getnewaddress account` parameter (deprecated since 0.18 but
still recognised) is unimplemented.

**File:** `src/beamchain_wallet.erl:781, 826`.

**Impact:** Single-account wallet by construction. Multi-account
workflows (exchange hot/cold split, business unit segregation) are
impossible without manual `derive_path/2` calls outside the keypool
flow.

---

## BUG-15 (P0-SEC) — Encrypted-wallet IV is derived from the same PBKDF2 output as the AES key

**Severity:** P0-SEC. `do_encrypt_wallet/2` at line 2050:

```erlang
DerivedKey = derive_encryption_key(Passphrase, Salt),
%% DerivedKey is 48 bytes (PBKDF2-HMAC-SHA-512 output)
<<Key:?AES_KEY_SIZE/binary, IV:?AES_IV_SIZE/binary>> = DerivedKey,
%% Key = first 32 bytes, IV = last 16 bytes
```

The IV is deterministic per `(passphrase, salt)`. If the user
encrypts the same plaintext seed twice with the same passphrase (the
salt is fresh per call, so different salt → different IV in practice
— but the design contract is that IV must be FRESH PER ENCRYPTION,
not derived from the same KDF as the key).

Worse, the construction allows a single oracle:
- AES-256-CBC produces 32 bytes of ciphertext (seed=32 bytes + PKCS#7
  padding to 48 bytes = 3 AES blocks).
- An attacker who can submit ANY ciphertext + arbitrary salt to the
  decryption path (via a tampered wallet file) gets back the
  decrypted PKCS#7-padded plaintext. If the attacker can observe
  whether the unpad succeeded or failed, they have a padding oracle
  (PKCS#7 + CBC + no MAC = textbook padding-oracle attack — Vaudenay
  2002).

The right construction is either:
- AES-GCM with random nonce (Path B uses this; Path A doesn't), OR
- AES-CBC + HMAC-SHA-256 over ciphertext+IV (encrypt-then-MAC).

Path A has neither.

**File:** `src/beamchain_wallet.erl:2050-2053`.

**Core ref:** Bitcoin Core uses random IV per encryption
(`CCrypter::Encrypt` generates a fresh random IV) and does NOT use
PBKDF2-derived IVs.

**Impact:**
- Padding-oracle attack on the encrypted-wallet path if an attacker
  can call `do_unlock_wallet` repeatedly with crafted ciphertext and
  observe success/failure timing. With ~256 oracle queries per byte,
  full 32-byte seed recovery in <8000 queries.
- IV-from-key construction is broken-by-design even if the oracle
  side-channel were fixed.

---

## BUG-16 (P2) — `parse_path/1` doesn't validate index < 2^31 (allows hardened-by-overflow)

**Severity:** P2. `parse_component/1` at `beamchain_wallet.erl:1975-1985`:

```erlang
parse_component(Str) ->
    case lists:last(Str) of
        $' -> N = list_to_integer(lists:droplast(Str)), N + ?HARDENED;
        $h -> N = list_to_integer(lists:droplast(Str)), N + ?HARDENED;
        _  -> list_to_integer(Str)
    end.
```

There is no upper-bound check that `N < 2^31` for hardened form (the
`N + HARDENED` then becomes ≥ 2^32, requiring two ones-bits in the
top byte — BIP-32 child index is a 32-bit unsigned int). For
non-hardened form (`_` branch) there's no check that `N < 2^31`
either; a parsed value like `3000000000` is silently >= 2^31, which
in Core's parse would be treated as a hardened index `829032704'`.

A user typing `"m/84'/0'/0'/0/2147483648"` (= 2^31, the lowest
hardened index value) gets a non-hardened tag in the parser then a
HARDENED-bit-set integer index at derivation time, but the path tag
says `format_path` (line 865-872) would render it back as `0/0'`
which would mislead the user.

**File:** `src/beamchain_wallet.erl:1955-1985`.

**Core ref:** `bitcoin-core/src/util/strencodings.cpp::ParseInt32`
returns false on overflow.

**Impact:** Parser silently accepts ambiguous integer-overflow paths.
Wallet UX bug, not a fund-loss bug.

---

## BUG-17 (P2) — `decode_xkey/1` doesn't verify the BIP-32 reserved padding byte (priv-key `code[41] == 0`)

**Severity:** P2 (extra-byte-not-checked / spec-strictness gap).
Bitcoin Core's `CExtKey::Decode` (`key.cpp:529`):

```cpp
if ((nDepth == 0 && (nChild != 0 || ReadLE32(vchFingerprint) != 0))
    || code[41] != 0)
    key = CKey();   // mark invalid
```

The check `code[41] != 0` enforces that the byte BEFORE the 32-byte
private key (the "1-byte 0x00 + 32-byte privkey" wire format) is
literally zero. beamchain's `decode_xkey/1` at
`beamchain_descriptor.erl:1166-1199`:

```erlang
<<Version:4/binary, Depth:8, Fingerprint:4/binary,
  ChildIndex:32/big, ChainCode:32/binary, KeyData:33/binary>> = Data,
case Version of
    ...
    <<16#04, 16#88, 16#ad, 16#e4>> -> %% xprv
        <<0, PrivKey:32/binary>> = KeyData,
        {ok, priv, PrivKey, ChainCode, Depth, Fingerprint, ChildIndex};
    ...
end.
```

This pattern-matches `<<0, PrivKey:32/binary>> = KeyData` for the
priv branch — which IS the spec-required check on byte 41 (the leading
zero of the 33-byte priv data). PASS for that. BUT the
master-key-as-non-root check (`if depth=0 AND (child≠0 OR fp≠0)`)
is absent — a forged xpub with depth=0, fp=`<<1,2,3,4>>`, child=5
parses as if it were the legitimate parentless master, with
deceptive non-zero metadata that any consumer trusts.

**File:** `src/beamchain_descriptor.erl:1178-1190`.

**Core ref:** `bitcoin-core/src/key.cpp:528-529`.

**Impact:** Forged-master-xpub via depth=0+nonzero-fp not rejected.
Cross-cite BUG-7 (forged-master output via encode_xpub).

---

## Summary

**Bug count:** 17 (BUG-1 through BUG-17).

**Severity distribution:**
- **P0-CDIV** (cross-impl wire-format divergence): 2 (BUG-7, BUG-13)
- **P0-FUNDS** (irrecoverable user backup loss): 1 (BUG-8)
- **P0-SEC** (key-material exposure / KDF mis-construction): 4 (BUG-9, BUG-10, BUG-11, BUG-15)
- **P1** (correctness with material impact): 5 (BUG-1, BUG-2, BUG-3, BUG-4, BUG-12)
- **P2** (missing-feature parity / cosmetic): 5 (BUG-5, BUG-6, BUG-14, BUG-16, BUG-17)

**Fleet patterns confirmed:**

- **"5-WAVE CARRY-FORWARD sign-then-verify-paranoia"** family
  (W156→W157→W158→W159→W160→W161): BUG-2 + BUG-4 are the W161
  instance of the BIP-32 retry-on-`IL≥n` gap. Same shape; same
  fix LOC; same wave-count counter as W160 BUG-12. **6-WAVE
  CARRY-FORWARD now** if we count W161 as a new wave.
- **"BIP-32 private-GMP asymmetry"** (haskoin+blockbrew+beamchain
  origin from W160 BUG-11): beamchain at W161 PASSES the GMP-vs-NIF
  side for BIP-32 priv-side scalar tweak (`secp256k1_ec_seckey_tweak_add`
  is used, not pure Erlang). This is improvement vs the taproot-tweak
  case from W160 BUG-11 where `negate_seckey` uses pure-Erlang GMP.
  BIP-32 priv path is clean.
- **"TapTweak no-merkle-root BIP-86-only"** (camlcoin+blockbrew+
  beamchain 3-fleet from W160): BUG-13 extends to W161; still
  unfixed.
- **"comment-as-confession"** (4 distinct W161 beamchain instances):
  BUG-8 (state field comment "not yet persisted to the wallet file"),
  BUG-11 (terminate comment "Overwrite seed memory (best effort)"),
  W160-cross-cite BUG-12 stale, also the bip39-doc preamble admits
  "we do not yet persist". **15th-18th** distinct beamchain
  comment-as-confession instances across all waves.
- **"dead-data plumbing"** (~12th distinct fleet instance, this is
  the 10th-or-so beamchain instance): BUG-12 `gap_limit` plumbed
  through every state-creation site, exported via `getwalletinfo`,
  never read.
- **"two-pipeline guard ~20th distinct extension"** (BUG-10): two
  different at-rest encryption schemes with DIFFERENT KDF
  (PBKDF2 vs homegrown), DIFFERENT cipher mode (CBC vs GCM),
  DIFFERENT IV source (derived vs random), DIFFERENT file format
  ("BCWALLET" magic vs JSON), DIFFERENT iteration count (25k vs
  100k). The two paths produce incompatible on-disk outputs. **First
  fleet instance where the two pipelines are within the SAME MODULE**
  (`beamchain_wallet.erl`).
- **"hardcoded zero in serialiser"** (BUG-7): `encode_xpub/3` /
  `encode_xprv/3` hardcode depth=0, fingerprint=0, child=0. First
  fleet instance of this shape on BIP-32 wire format. The shape is
  analogous to the W128 banman-state-not-persisted pattern but the
  blast radius is larger (PSBT signing breaks; cross-impl wallet
  setup breaks).
- **"persistence-shape-skews-recovery"** (BUG-8): wallet persists
  the *seed* (which makes derivation work post-restart) but NOT the
  *mnemonic* (which makes user-recovery fail post-restart). The
  inconsistency makes the bug latent: the daemon WORKS after
  restart, but a CRITICAL operator capability is silently degraded.
- **"new pattern this wave: KDF-and-MAC-asymmetric"** (BUG-15): Path
  A uses AES-CBC (no MAC) + PBKDF2; Path B uses AES-GCM (AEAD) +
  homegrown KDF. The two are roughly equivalent in cost but the
  on-the-wire format and security properties differ. Combining BUG-10
  + BUG-15 yields: the "official" `encryptwallet` RPC path is more
  vulnerable than the legacy auto-save path because it lacks the
  AEAD that the legacy path got "by accident".
- **"new pattern this wave: serialise-discards-state"** (BUG-7):
  `encode_xpub` / `encode_xprv` take only `(Key, ChainCode, Network)`
  — there are NO parameters for depth, fingerprint, or child index.
  The information necessary to produce a valid BIP-32 wire-format
  serialisation is ABSENT from the API signature. The serialiser
  cannot produce correct output even given correct input. Most
  severe form of "wiring-look-but-no-wire" yet observed.
- **"5-language-wordlist-only" missing-feature parity** (BUG-5):
  Only English wordlist; 8 others (Japanese, Korean, Spanish,
  Chinese-S, Chinese-T, French, Italian, Czech) missing. Cross-wallet
  restore from any non-Latin hardware wallet fails. Symmetric to
  W139 `defaultAssumeValid` per-network parameter gap.

**Top three findings:**

1. **BUG-7 (P0-CDIV `encode_xpub`/`encode_xprv` hardcode depth=0,
   fp=0, child=0)** — every BIP-32 extended key emitted by beamchain
   is silently a FORGED MASTER. Tools consuming it (descriptor
   wallets, PSBT signers, hardware-wallet setup flows) construct
   wrong addresses, never see UTXOs, and the user reports "missing
   funds". The serialiser API signature `(Key, ChainCode, Network)`
   is missing the very parameters needed to be correct — this is
   the most-severe form of "wiring-look-but-no-wire" pattern yet
   observed.
2. **BUG-8 (P0-FUNDS mnemonic NEVER persisted; restart-after-create
   loses recovery)** — `save_wallet/1` omits `<<"mnemonic">>` in both
   encrypted and unencrypted JSON paths. Seed IS persisted, so the
   daemon works post-restart, but `getwalletmnemonic` returns
   `{error, no_mnemonic}` permanently. The state-field comment-as-
   confession at line 161-162 admits the gap. Operators who trusted
   the RPC to recall the mnemonic after restart lose backup
   material silently.
3. **BUG-10 (P0-SEC two divergent at-rest encryption schemes in the
   same module)** — `do_encrypt_wallet` (PBKDF2-25k + AES-CBC + no
   MAC + IV-from-key) and `encrypt_and_write` (homegrown
   SHA-256-100k + AES-GCM + random IV) coexist, are NOT
   interoperable, and the Path A scheme is fundamentally weaker
   (no MAC → padding oracle, deterministic IV → IV-reuse on
   collision). The bug cluster combined with BUG-9 (mnemonic not
   cleared on encrypt) and BUG-11 (terminate-cleanse is dead code)
   means: crash dump + wallet file together can leak both
   mnemonic and seed in plaintext on any well-resourced attacker
   path.
