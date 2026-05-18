-module(beamchain_w137_psbt_tests).

%%% -------------------------------------------------------------------
%%% W137 — PSBT v0 (BIP-174) + v2 (BIP-370) + Taproot fields (BIP-371)
%%% audit (DISCOVERY-ONLY).
%%%
%%% Cross-references beamchain's PSBT surface against Bitcoin Core's
%%% `psbt.h`, `psbt.cpp`, `node/psbt.cpp`, `wallet/rpc/psbt.cpp`, and
%%% BIPs 174 / 370 / 371. These tests are NOT meant to all pass as
%%% PASS-meaning-correct: gates marked PRESENT assert Core-parity
%%% invariants (and DO pass); gates marked PARTIAL or MISSING assert
%%% the *current divergent behavior* using the "audit-flip" convention
%%% — when a later FIX wave brings the implementation into parity,
%%% these tests will FAIL and force an update. This is the same
%%% convention used by W94/95/120/121/125/127/130/131/132/133.
%%%
%%% NO PRODUCTION CODE CHANGES IN THIS COMMIT. This is a discovery
%%% wave; the production code stays exactly as-is.
%%%
%%% Reference BIPs: 174 (PSBT v0), 370 (PSBT v2), 371 (PSBT taproot).
%%% Reference Core source:
%%%   src/psbt.h — constants, types, Serialize/Unserialize templates.
%%%   src/psbt.cpp — Merge/Combine/Finalize/Sign helpers,
%%%                  RemoveUnnecessaryTransactions, DecodeBase64PSBT.
%%%   src/node/psbt.cpp — AnalyzePSBT (the analyzepsbt RPC backend).
%%%   src/wallet/rpc/psbt.cpp — walletcreatefundedpsbt /
%%%                              walletprocesspsbt / joinpsbts /
%%%                              utxoupdatepsbt.
%%% -------------------------------------------------------------------

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").
-include("beamchain_psbt.hrl").

%%% ===================================================================
%%% Constants (Core cross-reference)
%%% ===================================================================
%%% PRESENT: PSBT magic = <<0x70, 0x73, 0x62, 0x74, 0xff>> ("psbt"+0xff)
%%% PRESENT: PSBT_GLOBAL_UNSIGNED_TX == 0x00
%%% PRESENT: PSBT_GLOBAL_XPUB == 0x01
%%% PRESENT: PSBT_GLOBAL_VERSION == 0xFB
%%% PRESENT: PSBT_GLOBAL_PROPRIETARY == 0xFC
%%% PRESENT: PSBT_HIGHEST_VERSION == 0
%%% PRESENT: MAX_FILE_SIZE_PSBT == 100_000_000

%%% ===================================================================
%%% Test fixtures
%%% ===================================================================

%% Minimal unsigned tx (1 input, 1 P2WPKH output).
sample_unsigned_tx() ->
    #transaction{
        version = 2,
        inputs = [
            #tx_in{
                prev_out = #outpoint{
                    hash = <<1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
                             17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32>>,
                    index = 0
                },
                script_sig = <<>>,
                sequence = 16#fffffffd,
                witness = []
            }
        ],
        outputs = [
            #tx_out{
                value = 100000,
                script_pubkey = <<16#00, 20,
                    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20>>
            }
        ],
        locktime = 0
    }.

%% Encode a key-value pair using beamchain's wire format.
encode_kv(Key, Value) ->
    KeyLen = beamchain_serialize:encode_varint(byte_size(Key)),
    ValLen = beamchain_serialize:encode_varint(byte_size(Value)),
    <<KeyLen/binary, Key/binary, ValLen/binary, Value/binary>>.

%% Build a PSBT binary by hand (so we can craft hostile inputs).
build_handcrafted_psbt(GlobalKVs, InputKVs, OutputKVs) ->
    Magic = <<16#70, 16#73, 16#62, 16#74, 16#ff>>,
    GlobalBin = iolist_to_binary([ encode_kv(K, V) || {K, V} <- GlobalKVs ]
                                  ++ [<<0>>]),
    InputBin  = iolist_to_binary([ encode_kv(K, V) || {K, V} <- InputKVs ]
                                  ++ [<<0>>]),
    OutputBin = iolist_to_binary([ encode_kv(K, V) || {K, V} <- OutputKVs ]
                                  ++ [<<0>>]),
    iolist_to_binary([Magic, GlobalBin, InputBin, OutputBin]).

%% Encode the minimal unsigned tx and return its no-witness bytes.
unsigned_tx_bytes() ->
    Tx = sample_unsigned_tx(),
    beamchain_serialize:encode_transaction(Tx, no_witness).

%%% ===================================================================
%%% Gate 1 — Magic bytes present + strictly checked.
%%% PRESENT: beamchain_psbt.erl:36 (-define) + decode/1:238 head match.
%%% ===================================================================

gate01_magic_bytes_present_test() ->
    %% Round-trip encode of a freshly-created PSBT begins with magic.
    Tx = sample_unsigned_tx(),
    {ok, Psbt} = beamchain_psbt:create(Tx),
    Enc = beamchain_psbt:encode(Psbt),
    <<16#70, 16#73, 16#62, 16#74, 16#ff, _/binary>> = Enc,
    ok.

gate01_magic_bytes_strictly_checked_test() ->
    %% Any non-magic prefix is rejected with `{error, invalid_magic}`.
    %% Wrong byte at position 4 (0xfe instead of 0xff).
    ?assertMatch({error, invalid_magic},
                 beamchain_psbt:decode(<<16#70, 16#73, 16#62, 16#74, 16#fe>>)),
    %% Truncated magic.
    ?assertMatch({error, invalid_magic},
                 beamchain_psbt:decode(<<16#70, 16#73, 16#62, 16#74>>)).

%%% ===================================================================
%%% Gate 2 — PSBT_GLOBAL_* v0 key constants exist.
%%% PRESENT: beamchain_psbt.erl:39-42 (constants 0x00 / 0x01 / 0xfb / 0xfc).
%%% ===================================================================

gate02_global_constants_present_test() ->
    %% We assert by behavioral round-trip: a PSBT created with no XPubs
    %% and version=0 emits only the UNSIGNED_TX key (0x00) — no version
    %% byte (per `encode_global`).
    Tx = sample_unsigned_tx(),
    {ok, Psbt} = beamchain_psbt:create(Tx),
    Enc = beamchain_psbt:encode(Psbt),
    %% Strip magic, verify first compact-size byte is `key-len=1` and
    %% the key byte is the unsigned-tx type 0x00.
    <<_Magic:5/binary, 1, 16#00, _/binary>> = Enc,
    ok.

%%% ===================================================================
%%% Gate 3 — All v0 input-key constants 0x00..0x18 defined.
%%% PARTIAL: beamchain_psbt.erl:45-64 defines 0x00..0x18 but 0x0a..0x0d
%%% (RIPEMD/SHA256/HASH160/HASH256) constants are defined and never
%%% used — see BUG-4.
%%% ===================================================================

gate03_hash_preimage_constants_defined_but_unused_test() ->
    %% The constants 0x0a..0x0d exist (we use the literal bytes here
    %% because the -define is internal to beamchain_psbt). They are
    %% NEVER referenced by parse_input_pairs/encode_input_map, so a
    %% PSBT carrying a preimage key falls into the `unknown` bucket.
    %% Build a PSBT with PSBT_IN_SHA256 entry; verify it decodes
    %% under `unknown`.
    TxBin = unsigned_tx_bytes(),
    %% PSBT_IN_SHA256 (0x0b) keyed by a 32-byte zero hash + 1-byte type.
    SHA256Key = <<16#0b, 0:256>>,
    SHA256Val = <<"the-secret-preimage">>,
    Blob = build_handcrafted_psbt(
             [{<<16#00>>, TxBin}],
             [{SHA256Key, SHA256Val}],
             []),
    {ok, Decoded} = beamchain_psbt:decode(Blob),
    InputMap = beamchain_psbt:get_input(Decoded, 0),
    %% AUDIT-FLIP: today the preimage lands in `unknown`. When the fix
    %% wave lands, this assert will FAIL because beamchain_psbt will
    %% surface a typed `sha256_preimages` key. Bug BUG-4.
    Unknown = maps:get(unknown, InputMap, #{}),
    ?assertEqual(SHA256Val, maps:get(SHA256Key, Unknown)),
    %% And the typed key does NOT exist today.
    ?assertEqual(undefined, maps:get(sha256_preimages, InputMap, undefined)).

%%% ===================================================================
%%% Gate 4 — All v0 output-key constants 0x00..0x07 defined.
%%% PARTIAL: tap_tree (0x06) / tap_bip32_derivation (0x07) decoded but
%%% never re-encoded — see BUG-13.
%%% ===================================================================

gate04_tap_tree_drops_on_reencode_test() ->
    %% Construct a PSBT with an output-side PSBT_OUT_TAP_TREE entry,
    %% decode it, then re-encode and decode again. The tap_tree map
    %% disappears between the two decodes.
    TxBin = unsigned_tx_bytes(),
    %% Tap tree value: depth=0, leaf_ver=0xc0, script=<<0x51>> (OP_1).
    Script = <<16#51>>,
    ScriptLen = beamchain_serialize:encode_varint(byte_size(Script)),
    TapTreeVal = <<0, 16#c0, ScriptLen/binary, Script/binary>>,
    Blob = build_handcrafted_psbt(
             [{<<16#00>>, TxBin}],
             [],
             [{<<16#06>>, TapTreeVal}]),
    {ok, Dec1} = beamchain_psbt:decode(Blob),
    Out1 = beamchain_psbt:get_output(Dec1, 0),
    %% First decode: tap_tree present.
    ?assertMatch([{0, 16#c0, _}], maps:get(tap_tree, Out1)),
    %% Re-encode and re-decode.
    Re = beamchain_psbt:encode(Dec1),
    {ok, Dec2} = beamchain_psbt:decode(Re),
    Out2 = beamchain_psbt:get_output(Dec2, 0),
    %% AUDIT-FLIP: tap_tree is lost on re-encode today. When the fix
    %% lands, this assert will FAIL — tap_tree must round-trip. BUG-13.
    ?assertEqual(undefined, maps:get(tap_tree, Out2, undefined)).

%%% ===================================================================
%%% Gate 5 — PSBT_HIGHEST_VERSION ceiling check on parse.
%%% PARTIAL: version field read but no ceiling check — BUG-22.
%%% ===================================================================

gate05_version_ceiling_not_enforced_test() ->
    TxBin = unsigned_tx_bytes(),
    %% Pretend to be PSBT v=42 (well above PSBT_HIGHEST_VERSION = 0).
    Blob = build_handcrafted_psbt(
             [{<<16#00>>, TxBin}, {<<16#fb>>, <<42:32/little>>}],
             [], []),
    %% AUDIT-FLIP: today decode succeeds and reports version=42.
    %% When the fix lands, decode will reject. BUG-22.
    {ok, Dec} = beamchain_psbt:decode(Blob),
    ?assertEqual(42, beamchain_psbt:get_version(Dec)).

%%% ===================================================================
%%% Gate 6 — Duplicate-key detection per BIP-174.
%%% MISSING: parse_input_pairs/parse_global accept duplicates — BUG-2.
%%% ===================================================================

gate06_duplicate_input_key_silently_accepted_test() ->
    %% Build a PSBT with TWO PSBT_IN_SIGHASH_TYPE entries — Core throws.
    TxBin = unsigned_tx_bytes(),
    Blob = build_handcrafted_psbt(
             [{<<16#00>>, TxBin}],
             [{<<16#03>>, <<1:32/little>>},   %% SIGHASH_ALL
              {<<16#03>>, <<2:32/little>>}],  %% SIGHASH_NONE (overwrites)
             []),
    %% AUDIT-FLIP: today decode succeeds and the second entry wins.
    %% When the fix lands, decode will return {error, duplicate_key}.
    %% BUG-2.
    {ok, Dec} = beamchain_psbt:decode(Blob),
    InputMap = beamchain_psbt:get_input(Dec, 0),
    ?assertEqual(2, maps:get(sighash_type, InputMap)).

gate06_duplicate_global_key_silently_accepted_test() ->
    TxBin1 = unsigned_tx_bytes(),
    %% Same key (PSBT_GLOBAL_UNSIGNED_TX = 0x00) twice. Core throws
    %% "Duplicate Key, unsigned tx already provided".
    Blob = build_handcrafted_psbt(
             [{<<16#00>>, TxBin1}, {<<16#00>>, TxBin1}],
             [],
             []),
    %% AUDIT-FLIP: today silently accepted. BUG-6.
    Result = beamchain_psbt:decode(Blob),
    ?assertMatch({ok, _}, Result).

%%% ===================================================================
%%% Gate 7 — Separator-missing check.
%%% PARTIAL: terminator matched via <<0,Rest>> but missing-separator
%%% manifests as binary-pattern-mismatch, not clean error — BUG-7.
%%% ===================================================================

gate07_no_clean_separator_missing_error_test() ->
    %% Construct a PSBT where the global map's terminator byte is
    %% truncated. The error surfaced is generic, not the specific
    %% "Separator is missing at the end of the global map" Core emits.
    TxBin = unsigned_tx_bytes(),
    KvLen = beamchain_serialize:encode_varint(1),
    TxBinLen = beamchain_serialize:encode_varint(byte_size(TxBin)),
    %% Build without the trailing 0x00 separator.
    Truncated = <<16#70, 16#73, 16#62, 16#74, 16#ff,
                   KvLen/binary, 16#00,
                   TxBinLen/binary, TxBin/binary>>,
    %% AUDIT-FLIP: today returns generic error or crashes. BUG-7.
    %% (Function returns {error, _} — the SHAPE of the error is what's
    %% wrong, not that it errors.)
    Result = beamchain_psbt:decode(Truncated),
    ?assertMatch({error, _}, Result),
    %% Specifically the error reason does NOT contain
    %% "separator_missing" today.
    {error, Reason} = Result,
    %% iolib_to_binary safely stringifies whatever the reason is.
    Bin = iolist_to_binary(io_lib:format("~p", [Reason])),
    ?assertNot(binary:match(Bin, <<"separator">>) =/= nomatch).

%%% ===================================================================
%%% Gate 8 — partial_sig DER-encoding check.
%%% MISSING: parse_input_pairs stores raw bytes — BUG-8.
%%% ===================================================================

gate08_partial_sig_not_der_checked_test() ->
    %% Inject a non-DER partial signature. Core throws "Signature is
    %% not a valid encoding". beamchain stores it raw.
    TxBin = unsigned_tx_bytes(),
    PubKey = <<2, 0:248, 1>>,  %% 33-byte compressed pubkey shape
    %% Garbage non-DER signature (Core's CheckSignatureEncoding would
    %% reject this — too short, no 0x30 header).
    BadSig = <<"this-is-not-DER-encoded">>,
    PartialSigKey = <<16#02, PubKey/binary>>,
    Blob = build_handcrafted_psbt(
             [{<<16#00>>, TxBin}],
             [{PartialSigKey, BadSig}],
             []),
    %% AUDIT-FLIP: today decode succeeds with the malformed sig stored.
    %% BUG-8. When the fix lands, this should return a parse error.
    {ok, Dec} = beamchain_psbt:decode(Blob),
    InputMap = beamchain_psbt:get_input(Dec, 0),
    PartialSigs = maps:get(partial_sigs, InputMap, #{}),
    ?assertEqual(BadSig, maps:get(PubKey, PartialSigs)).

%%% ===================================================================
%%% Gate 9 — KeyOriginInfo length-mod-4 enforced.
%%% PARTIAL: decode_bip32_path slurps everything beyond the 4-byte
%%% fingerprint into a `<<_:32/little>>` list; trailing bytes that
%%% don't fit the 4-byte stride are silently lost. BUG-9.
%%% ===================================================================

gate09_bip32_path_length_not_strict_test() ->
    %% Trailing 3 bytes (5-byte total beyond fingerprint): the
    %% bitstring comprehension <<_:32/little>> consumes one full
    %% 4-byte index and silently drops the trailing 1 byte without
    %% raising. Core throws "Invalid length for HD key path".
    TxBin = unsigned_tx_bytes(),
    PubKey = <<2, 1:248, 0>>,
    %% Fingerprint (4 bytes) + 4-byte index + dangling 1 byte = 9 bytes.
    PathBlob = <<1,2,3,4, 5,6,7,8, 9>>,
    Bip32Key = <<16#06, PubKey/binary>>,
    Blob = build_handcrafted_psbt(
             [{<<16#00>>, TxBin}],
             [{Bip32Key, PathBlob}],
             []),
    %% AUDIT-FLIP: today decode succeeds with the trailing byte lost.
    %% BUG-9. When the fix lands, this returns a parse error.
    Result = beamchain_psbt:decode(Blob),
    ?assertMatch({ok, _}, Result).

%%% ===================================================================
%%% Gate 10 — BIP32 pubkey key-size strictly checked (33 or 65).
%%% MISSING: beamchain accepts ANY tail length — BUG-10.
%%% ===================================================================

gate10_bip32_pubkey_size_not_checked_test() ->
    TxBin = unsigned_tx_bytes(),
    %% 20-byte "pubkey" — definitely not a valid CPubKey size.
    BadPubKey = <<1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20>>,
    Bip32Key = <<16#06, BadPubKey/binary>>,
    Path = <<1,2,3,4, 1,0,0,0>>,
    Blob = build_handcrafted_psbt(
             [{<<16#00>>, TxBin}],
             [{Bip32Key, Path}],
             []),
    %% AUDIT-FLIP: today accepted; should be rejected. BUG-10.
    Result = beamchain_psbt:decode(Blob),
    ?assertMatch({ok, _}, Result).

%%% ===================================================================
%%% Gate 11 — Global m_xpubs duplicate-detection set.
%%% MISSING: silently overwrites in the xpubs map — BUG-11.
%%% ===================================================================

gate11_global_xpub_duplicate_silently_overwritten_test() ->
    TxBin = unsigned_tx_bytes(),
    %% A 78-byte ext-pubkey (`BIP32_EXTKEY_WITH_VERSION_SIZE = 78`)
    %% prefixed with the type byte. beamchain's parse_global pattern-
    %% matches the GLOBAL_XPUB key as `<<?PSBT_GLOBAL_XPUB, XPub/binary>>`
    %% (variadic XPub tail), so the byte count is only a documentation
    %% nicety here — what matters is that the SAME XPub key, repeated,
    %% silently overwrites in the xpubs map.
    XPub = <<0:78/integer-unit:8>>,  %% 78 bytes of zero — wire-shape stand-in.
    78 = byte_size(XPub),
    XPubKey = <<16#01, XPub/binary>>,
    %% Paths must be size_mod_4 == 0 to round-trip through decode_bip32_path.
    Path1 = <<1,2,3,4, 1:32/little>>,
    Path2 = <<5,6,7,8, 2:32/little>>,
    Blob = build_handcrafted_psbt(
             [{<<16#00>>, TxBin},
              {XPubKey, Path1},
              {XPubKey, Path2}],
             [],
             []),
    %% AUDIT-FLIP: today accepted (second overwrites first). BUG-11.
    Result = beamchain_psbt:decode(Blob),
    ?assertMatch({ok, _}, Result).

%%% ===================================================================
%%% Gate 12 — MAX_FILE_SIZE_PSBT (100MB) cap.
%%% MISSING: no decode-size guard — BUG-12.
%%% ===================================================================

gate12_no_max_file_size_guard_test() ->
    %% beamchain_psbt:decode does NOT have a size guard at entry. We
    %% don't actually craft 100MB here (too slow), but we observe the
    %% absence of the constant in the module.
    %% AUDIT-FLIP: when the fix lands, beamchain_psbt will export a
    %% size-cap constant or apply the check at decode/1.
    Exports = beamchain_psbt:module_info(exports),
    %% No max-size-related export today.
    ?assertNot(lists:member({max_file_size, 0}, Exports)),
    ?assertNot(lists:member({max_psbt_size, 0}, Exports)).

%%% ===================================================================
%%% Gate 13..19 — BIP-370 (PSBT v2) GLOBAL + per-input + per-output
%%% key constants. All MISSING — BUG-1.
%%% ===================================================================

gate13_no_bip370_tx_version_constant_test() ->
    %% PSBT_GLOBAL_TX_VERSION = 0x02 (BIP-370). When beamchain
    %% encounters it, it falls into the global `unknown` map.
    TxBin = unsigned_tx_bytes(),
    %% Build a v0 PSBT that also has a stray BIP-370 v2 global key.
    Blob = build_handcrafted_psbt(
             [{<<16#00>>, TxBin},
              {<<16#02>>, <<2:32/little>>}],   %% PSBT_GLOBAL_TX_VERSION
             [], []),
    %% AUDIT-FLIP: today the v2 key falls into `global_unknown`. BUG-1.
    {ok, Dec} = beamchain_psbt:decode(Blob),
    %% Hand-walk via element/2 since there is no public getter for
    %% global_unknown. #psbt{} layout: {psbt, unsigned_tx, xpubs,
    %% version, global_unknown, inputs, outputs}.
    GlobalUnknown = element(5, Dec),
    ?assertEqual(<<2:32/little>>,
                 maps:get(<<16#02>>, GlobalUnknown)).

gate14_no_bip370_fallback_locktime_test() ->
    TxBin = unsigned_tx_bytes(),
    Blob = build_handcrafted_psbt(
             [{<<16#00>>, TxBin},
              {<<16#03>>, <<500000:32/little>>}],  %% FALLBACK_LOCKTIME
             [], []),
    {ok, Dec} = beamchain_psbt:decode(Blob),
    GlobalUnknown = element(5, Dec),
    ?assertEqual(<<500000:32/little>>,
                 maps:get(<<16#03>>, GlobalUnknown)).

gate15_no_bip370_input_output_count_test() ->
    TxBin = unsigned_tx_bytes(),
    Blob = build_handcrafted_psbt(
             [{<<16#00>>, TxBin},
              {<<16#04>>, <<1>>},  %% PSBT_GLOBAL_INPUT_COUNT (compact size 1)
              {<<16#05>>, <<1>>}], %% PSBT_GLOBAL_OUTPUT_COUNT (compact size 1)
             [], []),
    {ok, Dec} = beamchain_psbt:decode(Blob),
    GlobalUnknown = element(5, Dec),
    ?assertEqual(<<1>>, maps:get(<<16#04>>, GlobalUnknown)),
    ?assertEqual(<<1>>, maps:get(<<16#05>>, GlobalUnknown)).

gate16_no_bip370_tx_modifiable_test() ->
    TxBin = unsigned_tx_bytes(),
    Blob = build_handcrafted_psbt(
             [{<<16#00>>, TxBin},
              {<<16#06>>, <<7>>}],  %% PSBT_GLOBAL_TX_MODIFIABLE = 0x07
             [], []),
    {ok, Dec} = beamchain_psbt:decode(Blob),
    GlobalUnknown = element(5, Dec),
    ?assertEqual(<<7>>, maps:get(<<16#06>>, GlobalUnknown)).

gate17_no_bip370_per_input_v2_keys_test() ->
    %% PSBT_IN_PREVIOUS_TXID (0x0e), OUTPUT_INDEX (0x0f), SEQUENCE (0x10).
    %% All v2-only. beamchain has no clauses; they land in `unknown`.
    TxBin = unsigned_tx_bytes(),
    PrevTxid = <<0:256>>,
    Blob = build_handcrafted_psbt(
             [{<<16#00>>, TxBin}],
             [{<<16#0e>>, PrevTxid},          %% PREVIOUS_TXID
              {<<16#0f>>, <<0:32/little>>},   %% OUTPUT_INDEX
              {<<16#10>>, <<16#fffffffd:32/little>>}], %% SEQUENCE
             []),
    {ok, Dec} = beamchain_psbt:decode(Blob),
    InputMap = beamchain_psbt:get_input(Dec, 0),
    Unknown = maps:get(unknown, InputMap, #{}),
    ?assertEqual(PrevTxid, maps:get(<<16#0e>>, Unknown)),
    ?assertEqual(<<0:32/little>>, maps:get(<<16#0f>>, Unknown)),
    ?assertEqual(<<16#fffffffd:32/little>>, maps:get(<<16#10>>, Unknown)).

gate18_no_bip370_required_locktimes_test() ->
    %% PSBT_IN_REQUIRED_TIME_LOCKTIME (0x11), REQUIRED_HEIGHT_LOCKTIME (0x12).
    TxBin = unsigned_tx_bytes(),
    Blob = build_handcrafted_psbt(
             [{<<16#00>>, TxBin}],
             [{<<16#11>>, <<1700000000:32/little>>},  %% time locktime
              {<<16#12>>, <<800000:32/little>>}],     %% height locktime
             []),
    {ok, Dec} = beamchain_psbt:decode(Blob),
    InputMap = beamchain_psbt:get_input(Dec, 0),
    Unknown = maps:get(unknown, InputMap, #{}),
    ?assertEqual(<<1700000000:32/little>>, maps:get(<<16#11>>, Unknown)),
    ?assertEqual(<<800000:32/little>>, maps:get(<<16#12>>, Unknown)).

gate19_no_bip370_output_v2_keys_test() ->
    %% PSBT_OUT_AMOUNT (0x03), PSBT_OUT_SCRIPT (0x04).
    TxBin = unsigned_tx_bytes(),
    Blob = build_handcrafted_psbt(
             [{<<16#00>>, TxBin}],
             [],
             [{<<16#03>>, <<100000:64/little>>},
              {<<16#04>>, <<16#51>>}]),
    {ok, Dec} = beamchain_psbt:decode(Blob),
    OutputMap = beamchain_psbt:get_output(Dec, 0),
    Unknown = maps:get(unknown, OutputMap, #{}),
    ?assertEqual(<<100000:64/little>>, maps:get(<<16#03>>, Unknown)),
    ?assertEqual(<<16#51>>, maps:get(<<16#04>>, Unknown)).

%%% ===================================================================
%%% Gate 20 — PSBT_IN_MUSIG2_* (BIP-371): 0x1a / 0x1b / 0x1c.
%%% MISSING: input-side MuSig2 constants entirely absent — BUG-3.
%%% ===================================================================

gate20_no_input_musig2_constants_test() ->
    %% beamchain_psbt.erl defines PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS
    %% (0x08 output side) but no PSBT_IN_MUSIG2_* equivalents.
    %% A round-trip with an input-side MuSig2 key falls into `unknown`.
    TxBin = unsigned_tx_bytes(),
    %% PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS (0x1a) keyed by 33-byte agg pubkey.
    AggPub = <<2, 0:248, 1>>,
    PartPub = <<2, 0:248, 2>>,
    Blob = build_handcrafted_psbt(
             [{<<16#00>>, TxBin}],
             [{<<16#1a, AggPub/binary>>, PartPub}],
             []),
    {ok, Dec} = beamchain_psbt:decode(Blob),
    InputMap = beamchain_psbt:get_input(Dec, 0),
    Unknown = maps:get(unknown, InputMap, #{}),
    ?assertEqual(PartPub,
                 maps:get(<<16#1a, AggPub/binary>>, Unknown)),
    ?assertEqual(undefined, maps:get(musig2_participant_pubkeys,
                                     InputMap, undefined)).

%%% ===================================================================
%%% Gate 21 — PSBT_IN_RIPEMD160/SHA256/HASH160/HASH256 preimages.
%%% MISSING: defined as constants but no parser/encoder — BUG-4.
%%% (gate03 already exercises sha256; here we additionally verify the
%%% other three are equally unhandled and that NONE of them have
%%% encoder branches.)
%%% ===================================================================

gate21_no_ripemd160_preimage_clause_test() ->
    %% Build a PSBT with PSBT_IN_RIPEMD160 (0x0a).
    TxBin = unsigned_tx_bytes(),
    RIPEMD160Key = <<16#0a, 0:160>>,  %% type + 20-byte hash
    Blob = build_handcrafted_psbt(
             [{<<16#00>>, TxBin}],
             [{RIPEMD160Key, <<"preimage-ripemd160">>}],
             []),
    {ok, Dec} = beamchain_psbt:decode(Blob),
    InputMap = beamchain_psbt:get_input(Dec, 0),
    Unknown = maps:get(unknown, InputMap, #{}),
    ?assertEqual(<<"preimage-ripemd160">>,
                 maps:get(RIPEMD160Key, Unknown)).

gate21_no_hash160_or_hash256_preimage_clause_test() ->
    TxBin = unsigned_tx_bytes(),
    Hash160Key = <<16#0c, 0:160>>,
    Hash256Key = <<16#0d, 0:256>>,
    Blob = build_handcrafted_psbt(
             [{<<16#00>>, TxBin}],
             [{Hash160Key, <<"preimage-hash160">>},
              {Hash256Key, <<"preimage-hash256">>}],
             []),
    {ok, Dec} = beamchain_psbt:decode(Blob),
    InputMap = beamchain_psbt:get_input(Dec, 0),
    Unknown = maps:get(unknown, InputMap, #{}),
    ?assertEqual(<<"preimage-hash160">>,
                 maps:get(Hash160Key, Unknown)),
    ?assertEqual(<<"preimage-hash256">>,
                 maps:get(Hash256Key, Unknown)).

%%% ===================================================================
%%% Gate 22 — PSBT_IN_TAP_KEY_SIG length 64-or-65 check.
%%% MISSING: parse accepts ANY size — BUG-14.
%%% ===================================================================

gate22_tap_key_sig_length_not_checked_test() ->
    TxBin = unsigned_tx_bytes(),
    %% A 17-byte "signature" — wildly wrong; Core throws.
    BadSig = <<"way-too-short-sig">>,
    Blob = build_handcrafted_psbt(
             [{<<16#00>>, TxBin}],
             [{<<16#13>>, BadSig}],
             []),
    %% AUDIT-FLIP: today accepted. BUG-14.
    {ok, Dec} = beamchain_psbt:decode(Blob),
    InputMap = beamchain_psbt:get_input(Dec, 0),
    ?assertEqual(BadSig, maps:get(tap_key_sig, InputMap)).

%%% ===================================================================
%%% Gate 23 — PSBT_IN_TAP_SCRIPT_SIG: key-size strict; value-size not.
%%% PARTIAL: parser pattern-matches key as <<0x14, XOnly:32, LeafHash:32>>
%%% (which enforces the 65-byte key size structurally), but the sig
%%% value is accepted at any length — BUG-23.
%%% ===================================================================

gate23_tap_script_sig_value_size_not_checked_test() ->
    TxBin = unsigned_tx_bytes(),
    XOnly = <<0:256>>,
    LeafHash = <<1:256>>,
    BadSig = <<"short">>,  %% 5 bytes, not 64 or 65.
    Blob = build_handcrafted_psbt(
             [{<<16#00>>, TxBin}],
             [{<<16#14, XOnly/binary, LeafHash/binary>>, BadSig}],
             []),
    {ok, Dec} = beamchain_psbt:decode(Blob),
    InputMap = beamchain_psbt:get_input(Dec, 0),
    Sigs = maps:get(tap_script_sigs, InputMap, #{}),
    %% AUDIT-FLIP: accepted today; would be rejected post-fix. BUG-23.
    ?assertEqual(BadSig, maps:get({XOnly, LeafHash}, Sigs)).

%%% ===================================================================
%%% Gate 24 — PSBT_OUT_TAP_TREE TaprootBuilder.IsComplete check.
%%% MISSING: decode_tap_tree returns fragments without validation — BUG-15.
%%% ===================================================================

gate24_tap_tree_incomplete_silently_accepted_test() ->
    %% An incomplete tap tree: one leaf at depth 2 with no sibling. Core
    %% throws "Output Taproot tree is malformed".
    TxBin = unsigned_tx_bytes(),
    Script = <<16#51>>,
    SL = beamchain_serialize:encode_varint(byte_size(Script)),
    %% Single leaf at depth=2 — incomplete tree (needs another leaf
    %% at depth 2 to merkle-up).
    TapTreeVal = <<2, 16#c0, SL/binary, Script/binary>>,
    Blob = build_handcrafted_psbt(
             [{<<16#00>>, TxBin}],
             [],
             [{<<16#06>>, TapTreeVal}]),
    %% AUDIT-FLIP: today accepted. BUG-15.
    {ok, Dec} = beamchain_psbt:decode(Blob),
    Out = beamchain_psbt:get_output(Dec, 0),
    ?assertMatch([{2, 16#c0, _}], maps:get(tap_tree, Out)).

%%% ===================================================================
%%% Gate 25 — Tap fields round-trip on encode (decoded → encoded).
%%% MISSING: tap_script_sigs / tap_leaf_scripts / tap_bip32_derivation
%%% / tap_merkle_root decoded but never re-emitted — BUG-13 (covered
%%% partially by gate04; this is the input-side mirror).
%%% ===================================================================

gate25_input_tap_fields_drop_on_reencode_test() ->
    TxBin = unsigned_tx_bytes(),
    %% PSBT_IN_TAP_MERKLE_ROOT (0x18) is a 32-byte field.
    MerkleRoot = <<7:256>>,
    Blob = build_handcrafted_psbt(
             [{<<16#00>>, TxBin}],
             [{<<16#18>>, MerkleRoot}],
             []),
    {ok, Dec1} = beamchain_psbt:decode(Blob),
    In1 = beamchain_psbt:get_input(Dec1, 0),
    %% Decoded the first time: tap_merkle_root present.
    ?assertEqual(MerkleRoot, maps:get(tap_merkle_root, In1)),
    %% Re-encode and re-decode.
    Re = beamchain_psbt:encode(Dec1),
    {ok, Dec2} = beamchain_psbt:decode(Re),
    In2 = beamchain_psbt:get_input(Dec2, 0),
    %% AUDIT-FLIP: tap_merkle_root is lost on the re-encode pass. BUG-13.
    ?assertEqual(undefined,
                 maps:get(tap_merkle_root, In2, undefined)).

%%% ===================================================================
%%% Gate 26 — RemoveUnnecessaryTransactions simplifier on all-segwit-v1.
%%% MISSING: no equivalent function in beamchain_psbt — BUG-17.
%%% ===================================================================

gate26_no_remove_unnecessary_transactions_test() ->
    Exports = beamchain_psbt:module_info(exports),
    %% AUDIT-FLIP: no such export today. BUG-17.
    ?assertNot(lists:member({remove_unnecessary_transactions, 1}, Exports)),
    ?assertNot(lists:member({remove_unnecessary_txs, 1}, Exports)),
    ?assertNot(lists:member({strip_non_witness_utxos, 1}, Exports)).

%%% ===================================================================
%%% Gate 27 — PSBTInputSignedAndVerified script-engine cross-check.
%%% MISSING: finalize_input emits final fields without VerifyScript — BUG-18.
%%% ===================================================================

gate27_finalize_does_not_verify_script_test() ->
    %% finalize/1 produces final_script_sig / final_script_witness based
    %% on partial_sigs presence; it does NOT script-verify the assembled
    %% spend against the UTXO's scriptPubKey. We assert this via the
    %% absence of an export.
    Exports = beamchain_psbt:module_info(exports),
    ?assertNot(lists:member({input_signed_and_verified, 2}, Exports)),
    ?assertNot(lists:member({verify_finalized_input, 2}, Exports)).

%%% ===================================================================
%%% Gate 28 — Sighash compatibility cross-check at walletprocesspsbt.
%%% MISSING: no validation that pre-existing partial_sigs match
%%% requested sighash — BUG-16.
%%% ===================================================================

gate28_walletprocesspsbt_no_sighash_compat_check_test() ->
    %% beamchain_rpc:parse_sighash_string/1 exists, but no helper
    %% validates pre-existing partial_sigs trailing-byte matches the
    %% requested sighash.
    Exports = beamchain_rpc:module_info(exports),
    %% Two arms that, if present, would do the check; neither exists today.
    ?assertNot(lists:member({validate_psbt_sighash_compat, 2}, Exports)),
    ?assertNot(lists:member({check_partial_sig_sighashes, 2}, Exports)).

%%% ===================================================================
%%% Gate 29 — joinpsbts RPC.
%%% MISSING: not implemented — BUG-19.
%%% ===================================================================

gate29_joinpsbts_not_implemented_test() ->
    %% No rpc_joinpsbts export today.
    Exports = beamchain_rpc:module_info(exports),
    ?assertNot(lists:member({rpc_joinpsbts, 1}, Exports)),
    ?assertNot(lists:member({rpc_joinpsbts, 2}, Exports)).

%%% ===================================================================
%%% Gate 30 — utxoupdatepsbt RPC.
%%% MISSING: not implemented — BUG-20.
%%% ===================================================================

gate30_utxoupdatepsbt_not_implemented_test() ->
    Exports = beamchain_rpc:module_info(exports),
    ?assertNot(lists:member({rpc_utxoupdatepsbt, 1}, Exports)),
    ?assertNot(lists:member({rpc_utxoupdatepsbt, 2}, Exports)).

%%% ===================================================================
%%% Supplementary: cross-pipeline coverage (BUG-5 dead-impl in wallet)
%%% Not an audit gate itself — checks that the wallet duplicate is
%%% still around and still has its known bug (empty output map encode).
%%% ===================================================================

walletmodule_encode_psbt_output_still_stub_test() ->
    %% beamchain_wallet:encode_psbt_output/1 is dead-impl that always
    %% emits the empty-map separator byte regardless of input. BUG-5.
    Exports = beamchain_wallet:module_info(exports),
    %% These wallet-local helpers are NOT exported (they're called
    %% internally by encode_psbt/1), but the encode_psbt export
    %% itself MUST still exist for the dead-impl pipeline to be live.
    ?assert(lists:member({encode_psbt, 1}, Exports)),
    ?assert(lists:member({decode_psbt, 1}, Exports)),
    ?assert(lists:member({sign_psbt, 2}, Exports)),
    ?assert(lists:member({finalize_psbt, 1}, Exports)),
    ?assert(lists:member({create_psbt, 2}, Exports)),
    %% The encoder is reachable + structurally returns the magic + a
    %% global tx-only map + the (broken) empty output map. Call it.
    Psbt = beamchain_wallet:create_psbt(
             [{<<0:256>>, 0}],
             [{<<16#51>>, 1000}]),
    Enc = beamchain_wallet:encode_psbt(Psbt),
    %% AUDIT-FLIP: the *wallet pipeline* encoder is broken-by-design —
    %% the output map is always emitted as a single 0x00 separator
    %% byte, dropping every PSBT_OUT_* key. When the wallet
    %% pipeline is deleted (or fixed), this test stops being
    %% meaningful — by then the canonical beamchain_psbt:encode/1 is
    %% the only encoder. BUG-5.
    %% At least the magic must be the prefix.
    <<16#70, 16#73, 16#62, 16#74, 16#ff, _/binary>> = Enc.
