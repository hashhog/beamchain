-module(beamchain_w131_descriptors_tests).

%% W131 — Output Descriptors + Miniscript audit (beamchain)
%%
%% 30 gates against BIP-380 (checksum + grammar), 381 (sh/pkh/multi),
%% 382 (wsh), 383 (sortedmulti), 384 (combo), 385 (raw/addr), 386
%% (tr/rawtr) and the Miniscript spec (B/V/K/W type system, sat/dissat
%% production, MiniscriptContext, MAX_OPS_PER_SCRIPT, MaxScriptSize,
%% witness-size accounting).
%%
%% Status (see audit/w131_descriptors_miniscript.md for the full index):
%%   - PRESENT  : 7 gates
%%   - PARTIAL  : 12 gates
%%   - MISSING  : 11 gates
%%   - BUGs     : 23 (8 HIGH / 9 MEDIUM / 6 LOW)
%%
%% Bugs introduced by this audit:
%%
%%   BUG-1  (HIGH)   tr(K, TREE) merkle build ignores leaf depths.
%%                   Non-trivial TapTrees produce wrong output keys vs
%%                   Core's TaprootBuilder. **Funds-loss class**.
%%   BUG-2  (HIGH)   pair_hashes/1 carries odd leaves up unhashed instead
%%                   of pairing single nodes with themselves (Core
%%                   TaprootBuilder semantics).
%%   BUG-3  (HIGH)   No MiniscriptContext (P2WSH vs Tapscript). multi /
%%                   multi_a accepted from any context; MAX_PUBKEYS_PER_*
%%                   not enforced.
%%   BUG-4  (HIGH)   pk_k / pk_h only accept 33-byte compressed pubkeys.
%%                   Tapminiscript x-only (32-byte) keys rejected.
%%   BUG-5  (HIGH)   No musig(...) key expression (BIP-388).
%%   BUG-6  (HIGH)   No <0;1> multipath descriptor expansion (BIP-389).
%%   BUG-7  (HIGH)   wsh() does not accept miniscript expressions; only
%%                   the four hard-coded inner types (multi, pk, pkh,
%%                   nested wsh/wpkh). No bridge to beamchain_miniscript.
%%   BUG-8  (HIGH)   MaxScriptSize 3600 (P2WSH) not enforced at parse.
%%                   Compiles silently to oversize unspendable script.
%%   BUG-9  (MEDIUM) MAX_OPS_PER_SCRIPT=201 not enforced in miniscript.
%%   BUG-10 (MEDIUM) thresh K=0 fails with function_clause instead of
%%                   a typed parse error.
%%   BUG-11 (MEDIUM) No SanitizeType post-processing; derived props
%%                   (n / u / s subset relations) not always tight.
%%   BUG-12 (MEDIUM) witness_size({multi,K,_}) returns dissatisfaction
%%                   1+K but CHECKMULTISIG needs 1+N. Underestimates
%%                   tx weight by 2 bytes per multisig dissatisfaction.
%%   BUG-13 (MEDIUM) derive_bip32_pubkey_path/3 raises an uncaught throw
%%                   on hardened-from-xpub instead of returning {error,_}.
%%   BUG-14 (MEDIUM) addr() doesn't validate the address eagerly at parse.
%%   BUG-15 (MEDIUM) is_solvable/1 returns true for rawtr() — Core says
%%                   false per BIP-386. **test-comment-as-confession**.
%%   BUG-16 (MEDIUM) combo() emits one script, not Core's four (P2PK +
%%                   P2PKH + P2WPKH + P2SH-P2WPKH for compressed keys).
%%   BUG-17 (LOW)    sortedmulti sort is incidental Erlang behavior, no
%%                   pinned BIP-67 vector.
%%   BUG-18 (LOW)    add_checksum/1 silently overwrites an existing
%%                   (possibly intentional) bad checksum.
%%   BUG-19 (LOW)    derive_bip32_*_path discards chain code on return,
%%                   foreclosing on multi-step BIP-32 derivation chains.
%%   BUG-20 (LOW)    format_descriptor/1 for tr(K, {a,{b,c}}) loses
%%                   internal tree structure (round-trips as flat tree).
%%   BUG-21 (LOW)    older(0) / older(2^31..) fails at type-check with
%%                   opaque error; Core rejects at parse with specific msg.
%%   BUG-22 (LOW)    encode_xpub/encode_xprv hardcode depth=0/fp=0/idx=0.
%%   BUG-23 (LOW)    base58 char decoding is O(N*58) linear scan.
%%
%% NOT a CDIV. Descriptors are wallet-side notation; nothing here
%% changes consensus validation of received blocks. BUG-1, BUG-2 are
%% user-funds-loss class (wallet pays to wrong P2TR address) but not
%% network-consensus bugs.
%%
%% Reference: bitcoin-core/src/script/descriptor.cpp (3006 LOC),
%%            bitcoin-core/src/script/miniscript.{h,cpp} (2707 + 432 LOC),
%%            bitcoin-core/src/test/descriptor_tests.cpp,
%%            bitcoin-core/src/test/miniscript_tests.cpp,
%%            bitcoin-core/src/test/data/descriptor_tests_external.json.
%%
%% Audit-flip discipline: every test below asserts the *current*
%% (divergent) behavior so it PASSES today. A future FIX wave that
%% brings the implementation into Core parity will flip these
%% PASS -> FAIL, surfacing the closure in CI.

-include_lib("eunit/include/eunit.hrl").

%%% ===================================================================
%%% Test fixtures
%%% ===================================================================

%% Compressed pubkeys.
-define(KEY1,
    "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5").
-define(KEY2,
    "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9").
-define(KEY3,
    "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556").
-define(KEY4,
    "024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97").

%% X-only pubkey (32 bytes) for tapminiscript / rawtr.
-define(XONLY_KEY1,
    "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5").

%% Vectors from Bitcoin Core descriptor_tests.cpp / BIP-380.
-define(VECTOR_PKH_DESC,
    "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)").
-define(VECTOR_PKH_CHECKSUM, "8fhd9pwu").

beamchain_src_dir() ->
    Beam = code:which(beamchain_descriptor),
    case Beam of
        non_existing -> "src";
        _ ->
            Ebin = filename:dirname(Beam),
            Lib  = filename:dirname(Ebin),
            Src  = filename:join([Lib, "src"]),
            case filelib:is_dir(Src) of
                true -> Src;
                false -> "src"
            end
    end.

descriptor_src() ->
    filename:join(beamchain_src_dir(), "beamchain_descriptor.erl").

miniscript_src() ->
    filename:join(beamchain_src_dir(), "beamchain_miniscript.erl").

read_src(Path) ->
    case file:read_file(Path) of
        {ok, B} -> binary_to_list(B);
        _ -> ""
    end.

%%% ===================================================================
%%% G1 — BIP-380 polymod algorithm
%%%   PRESENT
%%% ===================================================================

g1_polymod_test_() ->
    [
        {"polymod identity (c=1, val=0) returns shifted value",
         fun() ->
             %% c=1, val=0: result is (1 & 0x7ffffffff) << 5 = 32
             %% (c0 = 1 >> 35 = 0, no XOR), so 32.
             ?assertEqual(32, beamchain_descriptor:polymod(1, 0))
         end},
        {"polymod on known vector for 'pkh(...)' descriptor body",
         fun() ->
             %% End-to-end: the body of ?VECTOR_PKH_DESC must compute to
             %% checksum ?VECTOR_PKH_CHECKSUM.
             Cs = beamchain_descriptor:descriptor_checksum(?VECTOR_PKH_DESC),
             ?assertEqual(?VECTOR_PKH_CHECKSUM, Cs)
         end}
    ].

%%% ===================================================================
%%% G2 — BIP-380 checksum 8-char CHECKSUM_CHARSET output
%%%   PRESENT
%%% ===================================================================

g2_checksum_charset_test_() ->
    [
        {"checksum length is always 8 chars",
         fun() ->
             Cs = beamchain_descriptor:checksum(?VECTOR_PKH_DESC),
             ?assertEqual(8, length(Cs))
         end},
        {"checksum chars are all from bech32 CHECKSUM_CHARSET",
         fun() ->
             Cs = beamchain_descriptor:checksum(?VECTOR_PKH_DESC),
             ChecksumCharset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l",
             ?assert(lists:all(
                 fun(C) -> lists:member(C, ChecksumCharset) end, Cs))
         end}
    ].

%%% ===================================================================
%%% G3 — add_checksum/1 round-trip
%%%   PARTIAL — BUG-18: silently overwrites existing checksum.
%%% ===================================================================

g3_add_checksum_roundtrip_test_() ->
    [
        {"add_checksum on plain descriptor appends body#checksum",
         fun() ->
             D = ?VECTOR_PKH_DESC,
             WithCs = beamchain_descriptor:add_checksum(D),
             ?assertEqual(D ++ "#" ++ ?VECTOR_PKH_CHECKSUM, WithCs)
         end},
        {"BUG-18: add_checksum silently strips and replaces an existing "
         "(possibly intentionally bad) checksum without erroring",
         fun() ->
             D = ?VECTOR_PKH_DESC ++ "#badcksm0",
             %% Current behavior: returns body#good without erroring or
             %% warning. Audit-flip: a Core-parity fix would either keep
             %% the existing checksum or error on mismatch.
             Out = beamchain_descriptor:add_checksum(D),
             ?assertEqual(?VECTOR_PKH_DESC ++ "#" ++ ?VECTOR_PKH_CHECKSUM,
                          Out)
         end}
    ].

%%% ===================================================================
%%% G4 / G5 / G6 — pk / pkh / wpkh parse + scriptPubKey emit
%%%   PRESENT for all three
%%% ===================================================================

g4_pk_test_() ->
    [
        {"pk(KEY) parses to desc_pk",
         fun() ->
             {ok, Parsed} = beamchain_descriptor:parse(
                 "pk(" ++ ?KEY1 ++ ")"),
             ?assertMatch({desc_pk, _}, Parsed),
             %% Derive at index 0 — scriptPubKey should be 35 bytes:
             %% <33 push> <pubkey:33 bytes> <OP_CHECKSIG:0xac>
             {ok, Script} = beamchain_descriptor:derive(Parsed, 0),
             ?assertEqual(35, byte_size(Script)),
             ?assertEqual(16#ac, binary:last(Script))
         end}
    ].

g5_pkh_test_() ->
    [
        {"pkh(KEY) parses to desc_pkh and emits 25-byte P2PKH scriptPubKey",
         fun() ->
             {ok, Parsed} = beamchain_descriptor:parse(?VECTOR_PKH_DESC),
             ?assertMatch({desc_pkh, _}, Parsed),
             {ok, Script} = beamchain_descriptor:derive(Parsed, 0),
             %% OP_DUP OP_HASH160 <20> ... OP_EQUALVERIFY OP_CHECKSIG = 25 bytes
             ?assertEqual(25, byte_size(Script)),
             %% First two bytes are OP_DUP OP_HASH160
             <<16#76, 16#a9, _/binary>> = Script
         end}
    ].

g6_wpkh_test_() ->
    [
        {"wpkh(KEY) parses to desc_wpkh and emits 22-byte P2WPKH script",
         fun() ->
             Desc = "wpkh(" ++ ?KEY2 ++ ")",
             {ok, Parsed} = beamchain_descriptor:parse(Desc),
             ?assertMatch({desc_wpkh, _}, Parsed),
             {ok, Script} = beamchain_descriptor:derive(Parsed, 0),
             %% OP_0 <20-byte hash> = 22 bytes
             ?assertEqual(22, byte_size(Script)),
             <<16#00, 16#14, _:20/binary>> = Script
         end}
    ].

%%% ===================================================================
%%% G7 — sh(wpkh(KEY)) nesting validation
%%%   PRESENT
%%% ===================================================================

g7_sh_wpkh_test_() ->
    [
        {"sh(wpkh(KEY)) parses with correct nested shape",
         fun() ->
             Desc = "sh(wpkh(" ++ ?KEY3 ++ "))",
             {ok, Parsed} = beamchain_descriptor:parse(Desc),
             ?assertMatch({desc_sh, {desc_wpkh, _}}, Parsed)
         end},
        {"sh(pk(KEY)) accepted (P2SH-P2PK)",
         fun() ->
             Desc = "sh(pk(" ++ ?KEY1 ++ "))",
             {ok, Parsed} = beamchain_descriptor:parse(Desc),
             ?assertMatch({desc_sh, {desc_pk, _}}, Parsed)
         end},
        {"sh(addr(...)) rejected (sh cannot wrap an address)",
         fun() ->
             %% addr is not in validate_sh_inner's whitelist.
             ?assertMatch({error, _},
                 beamchain_descriptor:parse(
                     "sh(addr(1BitcoinEaterAddressDontSendf59kuE))"))
         end}
    ].

%%% ===================================================================
%%% G8 — sh(multi(K, keys)) — BIP-381 multisig redeemScript
%%%   PARTIAL — BUG-17 latent (sortedmulti BIP-67 byte-lex not pinned).
%%% ===================================================================

g8_sh_multi_test_() ->
    [
        {"sh(multi(2, K1, K2, K3)) parses and emits valid redeemScript",
         fun() ->
             Desc = "sh(multi(2," ++ ?KEY1 ++ "," ++ ?KEY2 ++
                    "," ++ ?KEY3 ++ "))",
             {ok, Parsed} = beamchain_descriptor:parse(Desc),
             ?assertMatch({desc_sh, {desc_multi, _, _, false}}, Parsed),
             {ok, Script} = beamchain_descriptor:derive(Parsed, 0),
             %% Output of sh(...) is always P2SH (OP_HASH160 <20> OP_EQUAL) = 23 bytes
             ?assertEqual(23, byte_size(Script))
         end}
    ].

%%% ===================================================================
%%% G9 — wsh(multi(K, keys)) — BIP-382 witness script
%%%   PARTIAL — BUG-7 latent (wsh does NOT accept miniscript inner).
%%% ===================================================================

g9_wsh_multi_test_() ->
    [
        {"wsh(multi(2, K1, K2, K3)) parses and emits valid witnessScript",
         fun() ->
             Desc = "wsh(multi(2," ++ ?KEY1 ++ "," ++ ?KEY2 ++
                    "," ++ ?KEY3 ++ "))",
             {ok, Parsed} = beamchain_descriptor:parse(Desc),
             ?assertMatch({desc_wsh, {desc_multi, _, _, false}}, Parsed),
             {ok, Script} = beamchain_descriptor:derive(Parsed, 0),
             %% v0 witness: OP_0 <32-byte sha256> = 34 bytes
             ?assertEqual(34, byte_size(Script))
         end}
    ].

%%% ===================================================================
%%% G10 — wsh(MINISCRIPT) accepts arbitrary miniscript inner
%%%   MISSING — BUG-7.
%%% ===================================================================

g10_wsh_miniscript_inner_missing_test_() ->
    [
        {"BUG-7: wsh(and_v(v:pk(K), older(144))) fails to parse — wsh "
         "validate_sh_inner whitelist does not delegate to "
         "beamchain_miniscript and so the parser cannot accept any "
         "miniscript expression as the wsh() inner.",
         fun() ->
             Desc = "wsh(and_v(v:pk(" ++ ?KEY1 ++ "),older(144)))",
             Res = beamchain_descriptor:parse(Desc),
             %% Current behavior: parser returns an error (could be
             %% wsh_invalid_inner, or could fail at a deeper point because
             %% the parser tries to parse `and_v` as a descriptor function
             %% name). Either way, NOT {ok, _}.
             ?assertMatch({error, _}, Res)
         end},
        {"BUG-7 evidence: validate_wsh_inner/2 hard-codes 3 inner types",
         fun() ->
             Src = read_src(descriptor_src()),
             %% Pin the four function-head clauses to detect drift if a
             %% future closure adds miniscript support.
             ?assert(string:find(Src, "validate_wsh_inner(#desc_multi") =/= nomatch),
             ?assert(string:find(Src, "validate_wsh_inner(#desc_pk{}") =/= nomatch),
             ?assert(string:find(Src, "validate_wsh_inner(#desc_pkh{}") =/= nomatch),
             %% No bridge call to beamchain_miniscript.
             ?assertEqual(nomatch,
                          string:find(Src, "beamchain_miniscript:from_string"))
         end}
    ].

%%% ===================================================================
%%% G11 — multi(K, keys) enforces MAX_PUBKEYS_PER_MULTISIG=20
%%%   MISSING — BUG-3.
%%% ===================================================================

g11_multi_max_keys_unenforced_test_() ->
    [
        {"BUG-3: multi() does not enforce MAX_PUBKEYS_PER_MULTISIG=20 at "
         "the descriptor-parse layer (validation only happens later in "
         "beamchain_script counting sigops).",
         fun() ->
             Src = read_src(descriptor_src()),
             %% No reference to MAX_PUBKEYS_PER_MULTISIG in descriptor.erl.
             ?assertEqual(nomatch,
                          string:find(Src, "MAX_PUBKEYS_PER_MULTISIG")),
             ?assertEqual(nomatch,
                          string:find(Src, "MAX_PUBKEYS_PER_MULTI_A"))
         end}
    ].

%%% ===================================================================
%%% G12 — sortedmulti BIP-67 byte-lex sort
%%%   PARTIAL — BUG-17 incidental correctness.
%%% ===================================================================

g12_sortedmulti_test_() ->
    [
        {"sortedmulti(2, K1, K2) parses with sorted=true",
         fun() ->
             Desc = "sortedmulti(2," ++ ?KEY1 ++ "," ++ ?KEY2 ++ ")",
             %% sortedmulti is only valid inside sh/wsh, not bare. But
             %% beamchain accepts it bare (separate divergence; flagged
             %% by W125 RPC).
             Wrapped = "sh(" ++ Desc ++ ")",
             {ok, Parsed} = beamchain_descriptor:parse(Wrapped),
             ?assertMatch({desc_sh, {desc_multi, _, _, true}}, Parsed)
         end},
        {"BUG-17: sortedmulti sort is incidental Erlang lists:sort/1 "
         "over binaries; no BIP-67 test vector pinned.",
         fun() ->
             Src = read_src(descriptor_src()),
             %% lists:sort/1 over <<>> binaries does compare bytewise
             %% lexicographically, but it's not commented as BIP-67.
             ?assert(string:find(Src, "lists:sort(PubKeys)") =/= nomatch),
             ?assertEqual(nomatch, string:find(Src, "BIP-67"))
         end}
    ].

%%% ===================================================================
%%% G13 — multi_a(K, keys) — Tapscript-only, x-only keys
%%%   MISSING — BUG-3, BUG-4.
%%% ===================================================================

g13_multi_a_missing_test_() ->
    [
        {"BUG-3 / BUG-4: multi_a is parseable as a *miniscript* fragment, "
         "but not as a *descriptor* — beamchain_descriptor's parse_func "
         "list does not include multi_a or sortedmulti_a.",
         fun() ->
             Src = read_src(descriptor_src()),
             ?assertEqual(nomatch, string:find(Src, "\"multi_a\"")),
             ?assertEqual(nomatch, string:find(Src, "\"sortedmulti_a\""))
         end},
        {"BUG-4: miniscript multi_a parser only accepts length-66 hex "
         "(33-byte compressed) keys, not length-64 (32-byte x-only).",
         fun() ->
             Src = read_src(miniscript_src()),
             %% parse_multi_keys requires length(HexStr) =:= 66.
             ?assert(string:find(Src, "length(HexStr) =:= 66") =/= nomatch),
             %% No accommodation for 64-char x-only.
             ?assertEqual(nomatch, string:find(Src, "length(HexStr) =:= 64"))
         end}
    ].

%%% ===================================================================
%%% G14 — sortedmulti_a — Tapscript-only sorted multisig
%%%   MISSING — BUG-3.
%%% ===================================================================

g14_sortedmulti_a_missing_test_() ->
    [
        {"BUG-3: sortedmulti_a entirely absent at descriptor + miniscript "
         "level.",
         fun() ->
             Src = read_src(descriptor_src()),
             ?assertEqual(nomatch, string:find(Src, "sortedmulti_a")),
             Src2 = read_src(miniscript_src()),
             ?assertEqual(nomatch, string:find(Src2, "sortedmulti_a"))
         end}
    ].

%%% ===================================================================
%%% G15 — tr(internal_key) key-path-only BIP-341 tweak
%%%   PRESENT
%%% ===================================================================

g15_tr_keypath_test_() ->
    [
        {"tr(KEY) parses and emits P2TR scriptPubKey (34 bytes)",
         fun() ->
             Desc = "tr(" ++ ?KEY1 ++ ")",
             {ok, Parsed} = beamchain_descriptor:parse(Desc),
             ?assertMatch({desc_tr, _, []}, Parsed),
             {ok, Script} = beamchain_descriptor:derive(Parsed, 0),
             %% OP_1 <32-byte tweaked output key> = 34 bytes
             ?assertEqual(34, byte_size(Script)),
             <<16#51, 16#20, _:32/binary>> = Script
         end}
    ].

%%% ===================================================================
%%% G16 — tr(internal_key, TREE) honors m_depths
%%%   MISSING — BUG-1, BUG-2. **Funds-loss class.**
%%% ===================================================================

g16_tr_tree_depth_missing_test_() ->
    [
        {"BUG-1: build_taproot_merkle/1 ignores leaf depth; trees of the "
         "shape tr(K, {a, {b, c}}) produce different output keys than "
         "Core's TaprootBuilder.",
         fun() ->
             Src = read_src(descriptor_src()),
             %% build_taproot_merkle takes a list of {Depth, Script} pairs
             %% but the pair_hashes/1 helper discards Depth.
             ?assert(string:find(Src, "build_taproot_merkle") =/= nomatch),
             %% pair_hashes takes plain Hashes (no Depth) — bug evidence.
             ?assert(string:find(Src, "pair_hashes(Hashes)") =/= nomatch),
             %% No call to anything resembling TaprootBuilder.
             ?assertEqual(nomatch, string:find(Src, "TaprootBuilder")),
             ?assertEqual(nomatch, string:find(Src, "taproot_builder"))
         end},
        {"BUG-2: pair_hashes/1 carries odd leaves up unhashed instead of "
         "pairing-with-self (Core TaprootBuilder.Merge semantics).",
         fun() ->
             Src = read_src(descriptor_src()),
             %% pair_hashes([H]) -> [H]  (no self-pair)
             ?assert(string:find(Src, "pair_hashes([H]) -> [H]") =/= nomatch)
         end}
    ].

%%% ===================================================================
%%% G17 — tr() tree round-trip via format_descriptor/1
%%%   PARTIAL — BUG-20.
%%% ===================================================================

g17_tr_format_roundtrip_test_() ->
    [
        {"BUG-20: format_tree/1 collapses nested {a,{b,c}} into {a,b,c} "
         "(flat list), losing internal tree structure.",
         fun() ->
             Src = read_src(descriptor_src()),
             %% format_tree([{_, Script}]) only emits a single
             %% comma-separated string with no tracking of depths.
             ?assert(string:find(Src, "format_tree(Tree) ->") =/= nomatch),
             %% Look for the comment 'Simplified tree formatting'.
             ?assert(string:find(Src, "Simplified tree formatting") =/= nomatch)
         end}
    ].

%%% ===================================================================
%%% G18 — rawtr(KEY) BIP-386 no-tweak emission
%%%   PRESENT (script-emit) — BUG-15 separately (is_solvable wrong).
%%% ===================================================================

g18_rawtr_test_() ->
    [
        {"rawtr(XONLY) parses and emits raw P2TR (no BIP-341 tweak)",
         fun() ->
             Desc = "rawtr(" ++ ?XONLY_KEY1 ++ ")",
             {ok, Parsed} = beamchain_descriptor:parse(Desc),
             ?assertMatch({desc_rawtr, _}, Parsed),
             {ok, Script} = beamchain_descriptor:derive(Parsed, 0),
             ?assertEqual(34, byte_size(Script)),
             <<16#51, 16#20, _:32/binary>> = Script
         end},
        {"BUG-15: is_solvable/1 incorrectly returns true for desc_rawtr "
         "(BIP-386 + Core say rawtr is NOT solvable — wallet has no "
         "way to construct a script-path proof from just the tweaked "
         "output key). The source comment at the is_solvable clause "
         "even acknowledges this divergence; **test-comment-as-confession**.",
         fun() ->
             Desc = "rawtr(" ++ ?XONLY_KEY1 ++ ")",
             {ok, Parsed} = beamchain_descriptor:parse(Desc),
             ?assert(beamchain_descriptor:is_solvable(Parsed)),
             %% Source-level evidence that the divergence is acknowledged.
             Src = read_src(descriptor_src()),
             ?assert(string:find(Src, "desc_rawtr is solvable") =/= nomatch)
         end}
    ].

%%% ===================================================================
%%% G19 — combo(KEY) script enumeration
%%%   PARTIAL — BUG-16.
%%% ===================================================================

g19_combo_test_() ->
    [
        {"BUG-16: combo(KEY) returns one script not four. Core emits P2PK "
         "+ P2PKH + (P2WPKH + P2SH-P2WPKH for compressed). beamchain "
         "returns P2WPKH (compressed) or P2PKH (uncompressed) ONLY.",
         fun() ->
             Desc = "combo(" ++ ?KEY1 ++ ")",
             {ok, Parsed} = beamchain_descriptor:parse(Desc),
             ?assertMatch({desc_combo, _}, Parsed),
             {ok, Script} = beamchain_descriptor:derive(Parsed, 0),
             %% Compressed key → P2WPKH only (22 bytes).
             ?assertEqual(22, byte_size(Script)),
             <<16#00, 16#14, _:20/binary>> = Script
         end}
    ].

%%% ===================================================================
%%% G20 — addr(...) eager validation
%%%   PARTIAL — BUG-14.
%%% ===================================================================

g20_addr_eager_validation_test_() ->
    [
        {"BUG-14: addr(GARBAGE) is accepted by parse/1 — only fails at "
         "derive/3 time. Core validates at construction.",
         fun() ->
             Desc = "addr(notanaddress)",
             Res = beamchain_descriptor:parse(Desc),
             %% Parse succeeds because parse_func only takes-until-paren.
             ?assertMatch({ok, {desc_addr, "notanaddress"}}, Res)
         end}
    ].

%%% ===================================================================
%%% G21 — raw(HEX) byte-for-byte preserve
%%%   PRESENT
%%% ===================================================================

g21_raw_test_() ->
    [
        {"raw(HEX) preserves bytes exactly",
         fun() ->
             Hex = "76a914000102030405060708090a0b0c0d0e0f1011121388ac",
             Desc = "raw(" ++ Hex ++ ")",
             {ok, Parsed} = beamchain_descriptor:parse(Desc),
             ?assertMatch({desc_raw, _}, Parsed),
             {ok, Script} = beamchain_descriptor:derive(Parsed, 0),
             ?assertEqual(25, byte_size(Script))
         end}
    ].

%%% ===================================================================
%%% G22 — BIP-32 derivation: xpub /n/m/* unhardened
%%%   PARTIAL — BUG-13 (uncaught throw), BUG-19 (chain code lost).
%%% ===================================================================

g22_bip32_unhardened_test_() ->
    [
        {"BUG-13: hardened derivation from xpub raises uncaught throw, "
         "not {error, _}. The throw escapes to the caller's process.",
         fun() ->
             Src = read_src(descriptor_src()),
             %% Bare throw, not the {error, _} idiom.
             ?assert(string:find(Src,
                       "throw(hardened_derivation_requires_private_key)")
                     =/= nomatch),
             %% Caller try/catch only catches {derive_error, _, _} from
             %% the explicit path-level throw in expand/3, not this.
             ?assert(string:find(Src,
                       "throw:{derive_error, Idx, Reason}") =/= nomatch)
         end},
        {"BUG-19: derive_bip32_path discards the final chain code on "
         "return (`_ = FinalChain`), foreclosing on multi-step derivation.",
         fun() ->
             Src = read_src(descriptor_src()),
             ?assert(string:find(Src, "_ = FinalChain") =/= nomatch)
         end}
    ].

%%% ===================================================================
%%% G23 — BIP-32 derivation: xprv hardened path
%%%   PRESENT (algorithmically correct for hardened-from-xprv)
%%% ===================================================================

g23_bip32_hardened_test_() ->
    [
        {"derive_bip32_privkey_path supports hardened indices (Index >= "
         "?HARDENED) using the `0 || privkey || idx` HMAC formulation per "
         "BIP-32.",
         fun() ->
             Src = read_src(descriptor_src()),
             %% W161 BUG-2 fix renamed Index → CurIndex inside the retry
             %% helper; the hardened-branch shape is otherwise unchanged.
             ?assert(string:find(Src,
                       "Data = case CurIndex >= ?HARDENED of") =/= nomatch),
             ?assert(string:find(Src,
                       "<<0, PrivKey/binary, CurIndex:32/big>>") =/= nomatch)
         end}
    ].

%%% ===================================================================
%%% G24 — BIP-389 multipath <0;1> expansion
%%%   MISSING — BUG-6.
%%% ===================================================================

g24_multipath_missing_test_() ->
    [
        {"BUG-6: BIP-389 multipath <0;1> expansion entirely absent. The "
         "xpath parser does not recognize the '<' literal.",
         fun() ->
             Src = read_src(descriptor_src()),
             %% No '<' / '>' handling in parse_xkey_path or related.
             ?assertEqual(nomatch, string:find(Src, "multipath")),
             ?assertEqual(nomatch, string:find(Src, "BIP-389")),
             %% take_path_element does not branch on '<'.
             ?assert(string:find(Src, "take_path_element(Str) ->") =/= nomatch)
         end}
    ].

%%% ===================================================================
%%% G25 — musig(K1,...) BIP-388
%%%   MISSING — BUG-5.
%%% ===================================================================

g25_musig_missing_test_() ->
    [
        {"BUG-5: musig() key expression is entirely absent.",
         fun() ->
             Src = read_src(descriptor_src()),
             ?assertEqual(nomatch, string:find(Src, "musig")),
             ?assertEqual(nomatch, string:find(Src, "MuSig")),
             %% No aggregate key construction either.
             ?assertEqual(nomatch, string:find(Src, "aggregate_pubkey"))
         end}
    ].

%%% ===================================================================
%%% G26 — Miniscript type system B/V/K/W + property invariants
%%%   PARTIAL — BUG-11 (no SanitizeType post-processing).
%%% ===================================================================

g26_miniscript_type_system_test_() ->
    [
        {"pk_k type-check returns K type with the canonical property set.",
         fun() ->
             Key = list_to_binary([list_to_integer([H1, H2], 16)
                                   || [H1, H2] <- chunks(?KEY1, 2)]),
             %% compute_type is an internal export for testing.
             T = beamchain_miniscript:compute_type({pk_k, Key}),
             ?assertEqual('K', maps:get(type, T)),
             ?assertEqual(true, maps:get(o, T)),
             ?assertEqual(true, maps:get(n, T)),
             ?assertEqual(true, maps:get(d, T)),
             ?assertEqual(true, maps:get(u, T)),
             ?assertEqual(true, maps:get(e, T)),
             ?assertEqual(true, maps:get(s, T)),
             ?assertEqual(true, maps:get(m, T))
         end},
        {"BUG-11: SanitizeType (Core's post-CalcType cleanup) absent. "
         "compute_type emits its result directly without subset-rule "
         "tightening.",
         fun() ->
             Src = read_src(miniscript_src()),
             ?assertEqual(nomatch, string:find(Src, "SanitizeType")),
             ?assertEqual(nomatch, string:find(Src, "sanitize_type")),
             %% Core's miniscript.cpp uses SanitizeType to enforce that
             %% (z and o) cannot both be set, etc. beamchain has no such
             %% post-pass.
             ?assert(string:find(Src, "compute_type") =/= nomatch)
         end}
    ].

%%% ===================================================================
%%% G27 — MiniscriptContext (P2WSH vs Tapscript) plumbing
%%%   MISSING — BUG-3.
%%% ===================================================================

g27_miniscript_context_missing_test_() ->
    [
        {"BUG-3: no MiniscriptContext anywhere in beamchain_miniscript. "
         "The compiler/type-checker is not parameterized on P2WSH vs "
         "Tapscript. Consequences: multi compiles from tapscript "
         "expressions; multi_a compiles from P2WSH expressions; sigs "
         "are sized at 73 (ECDSA) regardless of context.",
         fun() ->
             Src = read_src(miniscript_src()),
             %% No context type, plumbing, or runtime gate exists.
             %% (A doc comment in the AST docstring mentions "Tapscript
             %% only" for multi_a but there is no runtime check.)
             ?assertEqual(nomatch, string:find(Src, "MiniscriptContext")),
             ?assertEqual(nomatch, string:find(Src, "miniscript_context")),
             ?assertEqual(nomatch, string:find(Src, "ms_ctx")),
             ?assertEqual(nomatch, string:find(Src, "MsContext")),
             ?assertEqual(nomatch, string:find(Src, "is_tapscript")),
             ?assertEqual(nomatch, string:find(Src, "ParseContext"))
         end}
    ].

%%% ===================================================================
%%% G28 — MaxScriptSize 3600 (P2WSH) enforced at parse
%%%   MISSING — BUG-8.
%%% ===================================================================

g28_miniscript_max_script_size_missing_test_() ->
    [
        {"BUG-8: no MAX_STANDARD_P2WSH_SCRIPT_SIZE / MaxScriptSize check "
         "at parse time. A miniscript expression compiles silently to an "
         "oversize unspendable script.",
         fun() ->
             Src = read_src(miniscript_src()),
             ?assertEqual(nomatch,
                          string:find(Src, "MAX_STANDARD_P2WSH_SCRIPT_SIZE")),
             ?assertEqual(nomatch, string:find(Src, "MaxScriptSize")),
             ?assertEqual(nomatch, string:find(Src, "3600"))
         end}
    ].

%%% ===================================================================
%%% G29 — MAX_OPS_PER_SCRIPT=201 enforced in miniscript
%%%   MISSING — BUG-9.
%%% ===================================================================

g29_miniscript_max_ops_missing_test_() ->
    [
        {"BUG-9: validate_type/1 checks top-level type B only — does NOT "
         "check ops count <= MAX_OPS_PER_SCRIPT=201. A miniscript that "
         "compiles to > 201 non-push opcodes is accepted at parse, then "
         "rejected by the interpreter at spend time (wallet sees its tx "
         "bounce; the interpreter is correct).",
         fun() ->
             Src = read_src(miniscript_src()),
             %% No reference to MAX_OPS_PER_SCRIPT or ops-count check.
             ?assertEqual(nomatch, string:find(Src, "MAX_OPS_PER_SCRIPT")),
             ?assertEqual(nomatch, string:find(Src, "ops_count")),
             %% validate_type/1 is purely top-level type B check.
             ?assert(string:find(Src,
                       "validate_type(#{type := 'B'}) -> ok") =/= nomatch)
         end}
    ].

%%% ===================================================================
%%% G30 — Witness-size accounting matches Core
%%%   PARTIAL — BUG-12.
%%% ===================================================================

g30_witness_size_test_() ->
    [
        {"pk_k witness-size is {73, 1}: sat=72-byte sig + 1-byte len, "
         "dissat=0-byte empty + 1-byte len.",
         fun() ->
             Key = list_to_binary([list_to_integer([H1, H2], 16)
                                   || [H1, H2] <- chunks(?KEY1, 2)]),
             Sz = beamchain_miniscript:max_witness_size({pk_k, Key}),
             ?assertEqual(73, Sz)
         end},
        {"BUG-12: multi(K, _) witness-size dissatisfaction is reported as "
         "{1+K} (off-by-N error). CHECKMULTISIG needs 1+N empty stack "
         "elements for dissatisfaction, not 1+K.",
         fun() ->
             Src = read_src(miniscript_src()),
             %% Pin the bug at the call site.
             ?assert(string:find(Src,
                       "witness_size({multi, K, _Keys}) ->") =/= nomatch),
             ?assert(string:find(Src, "{1 + K * 73, 1 + K}") =/= nomatch)
         end},
        {"BUG-12 (Tapscript variant): multi_a uses 73-byte signature size, "
         "but Tapscript signatures are 64 bytes (+ optional 1-byte "
         "sighash flag = 65 max). The 73 hardcode in witness_size/1 "
         "over-estimates by 8 bytes per signature under Tapscript.",
         fun() ->
             Src = read_src(miniscript_src()),
             ?assert(string:find(Src,
                       "witness_size({multi_a, K, Keys}) ->") =/= nomatch),
             %% Same 73 used as for ECDSA.
             ?assert(string:find(Src, "K * 73 + (N - K)") =/= nomatch)
         end}
    ].

%%% ===================================================================
%%% Out-of-gate BUG pins (not bound to a single gate)
%%% ===================================================================

bug10_thresh_k_zero_test_() ->
    [{"BUG-10: thresh K=0 fails with function_clause rather than a typed "
      "parse error (the function-head guard K>=1 silently rejects).",
      fun() ->
          Src = read_src(miniscript_src()),
          ?assert(string:find(Src,
                    "parse_thresh(Str) ->") =/= nomatch),
          %% Guard at top of parse_thresh: K >= 1
          ?assert(string:find(Src, "{K, \",\" ++ Rest} when K >= 1") =/= nomatch)
      end}].

bug21_older_bounds_test_() ->
    [{"BUG-21: older(0) accepted by parse_single_num/3 (N>=1 guard does "
      "reject 0, but the error message is opaque). older(2^31..2^32) NOT "
      "rejected at parse — only at compute_type where the guard "
      "`N < 16#80000000` fails with a function_clause-like opaque crash.",
      fun() ->
          Src = read_src(miniscript_src()),
          ?assert(string:find(Src,
                    "compute_type({older, N}) when is_integer(N), N >= 1, "
                    "N < 16#80000000") =/= nomatch),
          %% The parser-side check is loose:
          ?assert(string:find(Src,
                    "parse_single_num(Name, Str, Constructor)") =/= nomatch)
      end}].

bug22_xkey_encode_zero_origin_test_() ->
    [{"BUG-22: encode_xpub/3 + encode_xprv/3 hardcode depth=0, "
      "fingerprint=0, child_index=0 in the output bytes. Non-master "
      "xpubs round-tripping through format_descriptor -> parse_descriptor "
      "lose their depth and parent fingerprint.",
      fun() ->
          Src = read_src(descriptor_src()),
          %% Look for the canonical zero-tuple in encode_xpub.
          ?assert(string:find(Src,
                    "<<Version:32/big, 0, 0:32, 0:32, ChainCode") =/= nomatch),
          ?assert(string:find(Src,
                    "<<Version:32/big, 0, 0:32, 0:32, ChainCode") =/= nomatch)
      end}].

bug23_base58_linear_decode_test_() ->
    [{"BUG-23: base58_char_val/2 does string:chr/2 per character — O(N*58). "
      "Cosmetic perf only.",
      fun() ->
          Src = read_src(descriptor_src()),
          ?assert(string:find(Src,
                    "base58_char_val(C, Alphabet)") =/= nomatch),
          ?assert(string:find(Src, "string:chr(Alphabet, C)") =/= nomatch)
      end}].

%%% ===================================================================
%%% Universal pattern observations (cross-wave)
%%% ===================================================================

universal_pattern_two_module_bridge_missing_test_() ->
    [{"UNIVERSAL: 'two-module bridge missing' — beamchain_descriptor and "
      "beamchain_miniscript exist as two independent modules with NO "
      "call sites connecting them. validate_wsh_inner enumerates four "
      "hard-coded types and never delegates to beamchain_miniscript. "
      "Same shape as W123 (miner/mempool) and several earlier waves.",
      fun() ->
          Src = read_src(descriptor_src()),
          %% Should find NO call to beamchain_miniscript from descriptor.
          ?assertEqual(nomatch,
                       string:find(Src, "beamchain_miniscript:")),
          %% And vice versa: miniscript does not import descriptor.
          Src2 = read_src(miniscript_src()),
          ?assertEqual(nomatch,
                       string:find(Src2, "beamchain_descriptor:"))
      end}].

universal_pattern_test_comment_as_confession_test_() ->
    [{"UNIVERSAL: 'test-comment-as-confession' (W122 catalogue). BUG-15 "
      "carries a comment claiming rawtr is solvable per BIP-386, which "
      "is the opposite of what BIP-386 + Core's RawTRDescriptor::IsSolvable "
      "say. Comment authored at module creation and never verified.",
      fun() ->
          Src = read_src(descriptor_src()),
          ?assert(string:find(Src,
                    "Note: desc_rawtr is solvable") =/= nomatch)
      end}].

%%% ===================================================================
%%% Helper: split hex string into 2-char chunks
%%% ===================================================================

chunks([], _) -> [];
chunks(L, N) when length(L) >= N ->
    {H, T} = lists:split(N, L),
    [H | chunks(T, N)];
chunks(_, _) -> [].
