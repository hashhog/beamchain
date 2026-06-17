-module(beamchain_w135_standardness_tests).

%% W135 Standardness rules (IsStandardTx) — discovery-only audit (beamchain).
%%
%% Reference: bitcoin-core/src/policy/policy.cpp:100-165 (IsStandardTx),
%%            bitcoin-core/src/policy/policy.cpp:27-78 (dust),
%%            bitcoin-core/src/policy/policy.cpp:214-263 (ValidateInputsStandardness),
%%            bitcoin-core/src/script/solver.{cpp,h} (Solver / TxoutType),
%%            bitcoin-core/src/policy/truc_policy.cpp (TRUC, audit cross-ref W120),
%%            bitcoin-core/src/consensus/tx_check.cpp (CheckTransaction).
%%
%% Scope (audit/w135_standardness_rules.md): 30 gates, 22 BUGs
%% (0 CDIV / 4 HIGH / 11 MEDIUM / 7 LOW).
%%
%% Audit-flip: every test below asserts the current (divergent) behavior
%% so it PASSES today; a follow-up FIX wave that brings the implementation
%% into parity will flip these PASS -> FAIL.

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%%% ===================================================================
%%% Source-path helpers (mirrors W133 convention)
%%% ===================================================================

beamchain_src_dir() ->
    Beam = code:which(beamchain_mempool),
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

beamchain_mempool_src()   -> filename:join(beamchain_src_dir(), "beamchain_mempool.erl").
beamchain_protocol_hrl()  ->
    %% include dir is sibling of src
    case code:which(beamchain_mempool) of
        non_existing -> "include/beamchain_protocol.hrl";
        _ ->
            Beam = code:which(beamchain_mempool),
            Ebin = filename:dirname(Beam),
            Lib  = filename:dirname(Ebin),
            filename:join([Lib, "include", "beamchain_protocol.hrl"])
    end.

read_src(Path) ->
    case file:read_file(Path) of
        {ok, Bin} -> Bin;
        {error, _} -> <<>>
    end.

%%% ===================================================================
%%% Tx fixture helpers
%%% ===================================================================

%% Build a single-input single-output transaction with the given output SPK.
make_tx_with_output(Version, SPK, Value) ->
    #transaction{
        version  = Version,
        inputs   = [#tx_in{prev_out = #outpoint{hash = <<1:256>>, index = 0},
                           script_sig = <<>>,
                           sequence = 16#ffffffff,
                           witness = []}],
        outputs  = [#tx_out{value = Value, script_pubkey = SPK}],
        locktime = 0,
        txid     = undefined,
        wtxid    = undefined
    }.

%% Build a transaction with a given scriptSig on its (only) input.
make_tx_with_scriptsig(ScriptSig) ->
    %% Use a small P2PKH output so the output side passes.
    OkOutput = <<16#76, 16#a9, 16#14, 0:160, 16#88, 16#ac>>,
    #transaction{
        version  = 2,
        inputs   = [#tx_in{prev_out = #outpoint{hash = <<1:256>>, index = 0},
                           script_sig = ScriptSig,
                           sequence = 16#ffffffff,
                           witness = []}],
        outputs  = [#tx_out{value = 100000, script_pubkey = OkOutput}],
        locktime = 0,
        txid     = undefined,
        wtxid    = undefined
    }.

%%% ===================================================================
%%% G1 — tx version: 1..3 are standard, others are not
%%% ===================================================================

g1_tx_version_standard_range_test_() ->
    {"G1: PRESENT — TX_MIN/MAX_STANDARD_VERSION = 1..3. v0, v4+ rejected.",
     [
      ?_test(begin
         OkOutput = <<16#76, 16#a9, 16#14, 0:160, 16#88, 16#ac>>,
         %% v1, v2, v3 must pass
         lists:foreach(fun(V) ->
             Tx = make_tx_with_output(V, OkOutput, 100000),
             ?assertEqual(ok, beamchain_mempool:check_standard(Tx))
         end, [1, 2, 3]),
         %% v0 and v4 must throw `version`
         lists:foreach(fun(V) ->
             Tx = make_tx_with_output(V, OkOutput, 100000),
             ?assertThrow(version, beamchain_mempool:check_standard(Tx))
         end, [0, 4, 5, 255])
       end)
     ]}.

%%% ===================================================================
%%% G2 — MAX_STANDARD_TX_WEIGHT = 400000
%%% ===================================================================

g2_max_standard_tx_weight_test_() ->
    {"G2: PRESENT — MAX_STANDARD_TX_WEIGHT = 400000 = 100 kvB.",
     [
      ?_test(begin
         %% Constant matches Core policy.h:38
         ?assertEqual(400000, ?MAX_STANDARD_TX_WEIGHT)
       end)
     ]}.

%%% ===================================================================
%%% G3 — BUG-9: MIN_STANDARD_TX_NONWITNESS_SIZE = 65 reason atom collides
%%% ===================================================================

g3_bug9_tx_size_small_reason_atom_collides_test_() ->
    {"G3: BUG-9 (MEDIUM) — Core distinguishes `tx-size` (weight cap) "
     "from `tx-size-small` (65-byte minimum); beamchain throws the same "
     "`tx_size` atom for both gates. testmempoolaccept cannot tell them "
     "apart.",
     [
      ?_test(begin
         Src = read_src(beamchain_mempool_src()),
         %% Both throw sites use the same `tx_size` atom in check_standard.
         %% Count occurrences of throw(tx_size) in check_standard region.
         %% The audit-flip: assert there is no `tx_size_small` atom in
         %% mempool source today.
         ?assertEqual(nomatch, binary:match(Src, <<"tx_size_small">>)),
         ?assertEqual(nomatch, binary:match(Src, <<"'tx-size-small'">>)),
         %% And the bundled-atom is still in use:
         ?assertNotEqual(nomatch, binary:match(Src, <<"throw(tx_size)">>))
       end)
     ]}.

%%% ===================================================================
%%% G4 — MAX_STANDARD_SCRIPTSIG_SIZE per-input cap
%%% ===================================================================

g4_max_standard_scriptsig_size_test_() ->
    {"G4: PRESENT — Per-input scriptSig size cap = 1650 bytes.",
     [
      ?_test(begin
         ?assertEqual(1650, ?MAX_STANDARD_SCRIPTSIG_SIZE),
         %% A 1651-byte all-zero scriptSig fails:
         BigSS = binary:copy(<<0>>, 1651),
         Tx = make_tx_with_scriptsig(BigSS),
         ?assertThrow(scriptsig_size, beamchain_mempool:check_standard(Tx))
       end)
     ]}.

%%% ===================================================================
%%% G5 — BUG-5: is_push_only does not accept OP_RESERVED (0x50)
%%% ===================================================================

g5_bug5_is_push_only_rejects_op_reserved_test_() ->
    {"G5: BUG-5 (MEDIUM) — Core's CScript::IsPushOnly accepts OP_RESERVED "
     "(0x50) as push-only because `if (opcode > OP_16) return false;` and "
     "0x50 < OP_16 (0x60). beamchain's is_push_only/1 has no clause for "
     "0x50 and returns false. A scriptSig containing OP_RESERVED is "
     "incorrectly rejected as scriptsig_not_pushonly in beamchain.",
     [
      ?_test(begin
         %% Today: beamchain says OP_RESERVED is NOT push-only.
         ?assertEqual(false, beamchain_script:is_push_only(<<16#50>>)),
         %% A scriptSig of just OP_RESERVED — beamchain rejects.
         Tx = make_tx_with_scriptsig(<<16#50>>),
         ?assertThrow(scriptsig_not_pushonly,
                      beamchain_mempool:check_standard(Tx)),
         %% Sanity: legitimately push-only data still works.
         ?assertEqual(true, beamchain_script:is_push_only(<<>>)),
         ?assertEqual(true, beamchain_script:is_push_only(<<16#51>>)), %% OP_1
         ?assertEqual(true, beamchain_script:is_push_only(<<16#60>>))  %% OP_16
       end)
     ]}.

%%% ===================================================================
%%% G6 — BUG-1: bare P2PK output is nonstandard in beamchain
%%% ===================================================================

g6_bug1_bare_p2pk_output_nonstandard_test_() ->
    {"G6: BUG-1 (HIGH) — bare P2PK output `<33-byte-pubkey> OP_CHECKSIG` "
     "is classified `nonstandard` by beamchain even though Core's Solver "
     "returns TxoutType::PUBKEY and IsStandard accepts it. The INPUT-side "
     "classifier DOES have a `pubkey` arm — so spending P2PK is allowed "
     "but creating P2PK is rejected.",
     [
      ?_test(begin
         %% Compressed-key P2PK: 0x21 <33 bytes> OP_CHECKSIG (35 bytes)
         P2PK33 = <<16#21, 0:264, 16#ac>>,
         ?assertEqual(35, byte_size(P2PK33)),
         ?assertEqual(nonstandard,
                      beamchain_mempool:classify_output_standard(P2PK33)),

         %% Uncompressed-key P2PK: 0x41 <65 bytes> OP_CHECKSIG (67 bytes)
         P2PK65 = <<16#41, 0:520, 16#ac>>,
         ?assertEqual(67, byte_size(P2PK65)),
         ?assertEqual(nonstandard,
                      beamchain_mempool:classify_output_standard(P2PK65)),

         %% End-to-end: check_standard rejects with `scriptpubkey`.
         Tx = make_tx_with_output(2, P2PK33, 100000),
         ?assertThrow(scriptpubkey, beamchain_mempool:check_standard(Tx)),

         %% Audit-flip: the source must NOT have a pubkey arm in
         %% classify_output_standard until the fix lands.
         Src = read_src(beamchain_mempool_src()),
         %% Confirm classify_output_standard exists
         ?assertNotEqual(nomatch,
                         binary:match(Src,
                             <<"classify_output_standard(<<16#76">>)),
         %% No 0x21 ... 0xac (P2PK33) arm
         ?assertEqual(nomatch,
                      binary:match(Src,
                          <<"classify_output_standard(<<16#21,">>)),
         %% No 0x41 ... 0xac (P2PK65) arm
         ?assertEqual(nomatch,
                      binary:match(Src,
                          <<"classify_output_standard(<<16#41,">>))
       end)
     ]}.

%%% ===================================================================
%%% G7 — P2PKH output classifier
%%% ===================================================================

g7_p2pkh_output_standard_test_() ->
    {"G7: PRESENT — P2PKH `OP_DUP OP_HASH160 <20-byte hash> "
     "OP_EQUALVERIFY OP_CHECKSIG` (25 bytes) is classified p2pkh.",
     [
      ?_test(begin
         P2PKH = <<16#76, 16#a9, 16#14, 0:160, 16#88, 16#ac>>,
         ?assertEqual(25, byte_size(P2PKH)),
         ?assertEqual(p2pkh, beamchain_mempool:classify_output_standard(P2PKH))
       end)
     ]}.

%%% ===================================================================
%%% G8 — P2SH output classifier
%%% ===================================================================

g8_p2sh_output_standard_test_() ->
    {"G8: PRESENT — P2SH `OP_HASH160 <20-byte hash> OP_EQUAL` (23 bytes) "
     "is classified p2sh.",
     [
      ?_test(begin
         P2SH = <<16#a9, 16#14, 0:160, 16#87>>,
         ?assertEqual(23, byte_size(P2SH)),
         ?assertEqual(p2sh, beamchain_mempool:classify_output_standard(P2SH))
       end)
     ]}.

%%% ===================================================================
%%% G9 — BUG-2 / BUG-3: bare multisig output is nonstandard
%%% ===================================================================

g9_bug2_bug3_bare_multisig_nonstandard_test_() ->
    {"G9: BUG-2/BUG-3 (HIGH) — bare multisig `OP_M <pk1>..<pkN> OP_N "
     "OP_CHECKMULTISIG` is unconditionally `nonstandard` in beamchain. "
     "Core's Solver returns TxoutType::MULTISIG and IsStandard accepts "
     "n=1..3, m=1..n. Plus there's no permit_bare_multisig config flag "
     "(Core default true, beamchain has no flag).",
     [
      ?_test(begin
         %% 1-of-2 multisig with two 33-byte pubkeys:
         %% OP_1 <33> <pk1> <33> <pk2> OP_2 OP_CHECKMULTISIG
         Pk1 = binary:copy(<<16#aa>>, 33),
         Pk2 = binary:copy(<<16#bb>>, 33),
         MS = <<16#51,            %% OP_1
                16#21, Pk1/binary, %% push 33-byte pk1
                16#21, Pk2/binary, %% push 33-byte pk2
                16#52,            %% OP_2
                16#ae>>,          %% OP_CHECKMULTISIG
         ?assertEqual(nonstandard,
                      beamchain_mempool:classify_output_standard(MS)),

         %% End-to-end: check_standard rejects with `scriptpubkey`
         %% (NOT with the Core-canonical `bare-multisig` token — BUG-21).
         Tx = make_tx_with_output(2, MS, 100000),
         ?assertThrow(scriptpubkey, beamchain_mempool:check_standard(Tx)),

         %% No permit_bare_multisig config flag exists.
         Src = read_src(beamchain_mempool_src()),
         ?assertEqual(nomatch,
                      binary:match(Src, <<"permit_bare_multisig">>)),
         ?assertEqual(nomatch,
                      binary:match(Src, <<"DEFAULT_PERMIT_BAREMULTISIG">>))
       end)
     ]}.

%%% ===================================================================
%%% G10 — OP_RETURN classifier (W56 push-only gate applied)
%%% ===================================================================

g10_op_return_classifier_test_() ->
    {"G10: PRESENT — OP_RETURN with push-only remainder is op_return; "
     "truncated push remainder is nonstandard (W56 fix already applied).",
     [
      ?_test(begin
         %% Well-formed
         ?assertEqual(op_return,
             beamchain_mempool:classify_output_standard(
                 <<16#6a, 16#04, 16#de, 16#ad, 16#be, 16#ef>>)),
         %% Bare OP_RETURN
         ?assertEqual(op_return,
             beamchain_mempool:classify_output_standard(<<16#6a>>)),
         %% Truncated push: claims 9 bytes, only 4 follow
         ?assertEqual(nonstandard,
             beamchain_mempool:classify_output_standard(
                 <<16#6a, 16#09, 16#de, 16#ad, 16#be, 16#ef>>))
       end)
     ]}.

%%% ===================================================================
%%% G11 — Pay-to-Anchor (P2A) classifier
%%% ===================================================================

g11_p2a_classifier_test_() ->
    {"G11: PRESENT — Pay-to-Anchor `OP_1 OP_PUSHBYTES_2 0x4e73` is "
     "classified p2a. Witness v1 program with 2-byte program {0x4e,0x73}.",
     [
      ?_test(begin
         ?assertEqual(p2a,
             beamchain_mempool:classify_output_standard(
                 <<16#51, 16#02, 16#4e, 16#73>>)),
         %% Different 2-byte program is NOT p2a but is still standard
         %% as a witness-v1 future-use program in beamchain (matches
         %% Core WITNESS_UNKNOWN behavior).
         R = beamchain_mempool:classify_output_standard(
                 <<16#51, 16#02, 16#aa, 16#bb>>),
         ?assertEqual({witness, 1}, R)
       end)
     ]}.

%%% ===================================================================
%%% G12 — P2WPKH classifier
%%% ===================================================================

g12_p2wpkh_classifier_test_() ->
    {"G12: PRESENT — P2WPKH `OP_0 OP_PUSHBYTES_20 <20-byte hash>` "
     "(22 bytes) is classified p2wpkh.",
     [
      ?_test(begin
         P2WPKH = <<16#00, 16#14, 0:160>>,
         ?assertEqual(22, byte_size(P2WPKH)),
         ?assertEqual(p2wpkh, beamchain_mempool:classify_output_standard(P2WPKH))
       end)
     ]}.

%%% ===================================================================
%%% G13 — P2WSH classifier
%%% ===================================================================

g13_p2wsh_classifier_test_() ->
    {"G13: PRESENT — P2WSH `OP_0 OP_PUSHBYTES_32 <32-byte hash>` "
     "(34 bytes) is classified p2wsh.",
     [
      ?_test(begin
         P2WSH = <<16#00, 16#20, 0:256>>,
         ?assertEqual(34, byte_size(P2WSH)),
         ?assertEqual(p2wsh, beamchain_mempool:classify_output_standard(P2WSH))
       end)
     ]}.

%%% ===================================================================
%%% G14 — P2TR (Taproot) classifier
%%% ===================================================================

g14_p2tr_classifier_test_() ->
    {"G14: PRESENT — P2TR `OP_1 OP_PUSHBYTES_32 <32-byte program>` "
     "(34 bytes) is classified p2tr.",
     [
      ?_test(begin
         P2TR = <<16#51, 16#20, 0:256>>,
         ?assertEqual(34, byte_size(P2TR)),
         ?assertEqual(p2tr, beamchain_mempool:classify_output_standard(P2TR))
       end)
     ]}.

%%% ===================================================================
%%% G15 — BUG-11/BUG-12: future-witness classifier returns {witness, N}
%%% ===================================================================

g15_bug11_future_witness_returns_tuple_test_() ->
    {"G15: BUG-11/BUG-12 (MEDIUM) — Future witness versions v2..v16 with "
     "2-40 byte programs return `{witness, N}` (a tuple) rather than the "
     "single atom `witness_unknown` that Core's Solver returns as "
     "`TxoutType::WITNESS_UNKNOWN`. End-behaviour matches (forward-compat "
     "standard) but the term shape is incompatible if any downstream "
     "consumer pattern-matches on the classifier atom set.",
     [
      ?_test(begin
         %% Witness v2 with 4-byte program
         R2 = beamchain_mempool:classify_output_standard(
                 <<16#52, 16#04, 0, 0, 0, 0>>),
         ?assertEqual({witness, 2}, R2),
         %% Witness v15 with 32-byte program
         R15 = beamchain_mempool:classify_output_standard(
                 <<16#5f, 16#20, 0:256>>),
         ?assertEqual({witness, 15}, R15),
         %% Witness v16 with 40-byte program (max)
         R16 = beamchain_mempool:classify_output_standard(
                 <<16#60, 16#28, 0:320>>),
         ?assertEqual({witness, 16}, R16),
         %% Witness v0 with non-{20,32} length is nonstandard (matches Core)
         R0 = beamchain_mempool:classify_output_standard(
                 <<16#00, 16#10, 0:128>>),  %% v0, 16-byte program
         ?assertEqual(nonstandard, R0)
       end)
     ]}.

%%% ===================================================================
%%% G16 — BUG-4: MAX_OP_RETURN_RELAY hardcoded, no config plumbing
%%% ===================================================================

g16_bug4_max_op_return_relay_hardcoded_test_() ->
    {"G16: BUG-4 (HIGH) — MAX_OP_RETURN_RELAY = 100000 is hardcoded; "
     "no -datacarrier or -datacarriersize config plumbing. Core uses "
     "std::optional<unsigned> max_datacarrier_bytes; nullopt = disabled.",
     [
      ?_test(begin
         %% Constant matches Core policy.h:84 default (400000/4 = 100000)
         ?assertEqual(100000, ?MAX_OP_RETURN_RELAY),
         %% No config plumbing in mempool source.
         Src = read_src(beamchain_mempool_src()),
         ?assertEqual(nomatch, binary:match(Src, <<"max_datacarrier_bytes">>)),
         ?assertEqual(nomatch, binary:match(Src, <<"datacarriersize">>)),
         %% check_standard uses the literal MAX_OP_RETURN_RELAY define.
         ?assertNotEqual(nomatch,
             binary:match(Src, <<"?MAX_OP_RETURN_RELAY">>))
       end)
     ]}.

%%% ===================================================================
%%% G17 — BUG-3: permit_bare_multisig config missing
%%% ===================================================================

g17_bug3_permit_bare_multisig_missing_test_() ->
    {"G17: BUG-3 (HIGH) — Core has -permitbaremultisig (default true). "
     "beamchain has no equivalent config. The output classifier rejects "
     "all bare multisig as nonstandard regardless of operator preference.",
     [
      ?_test(begin
         Src = read_src(beamchain_mempool_src()),
         ?assertEqual(nomatch, binary:match(Src, <<"permit_bare_multisig">>)),
         ?assertEqual(nomatch, binary:match(Src, <<"permitbaremultisig">>)),
         ProtoHrl = read_src(beamchain_protocol_hrl()),
         ?assertEqual(nomatch, binary:match(ProtoHrl, <<"DEFAULT_PERMIT_BAREMULTISIG">>)),
         ?assertEqual(nomatch, binary:match(ProtoHrl, <<"PERMIT_BAREMULTISIG">>))
       end)
     ]}.

%%% ===================================================================
%%% G18 — BUG-4: max_datacarrier_bytes config missing
%%% ===================================================================

g18_bug4_max_datacarrier_config_missing_test_() ->
    {"G18: BUG-4 (HIGH) — No max_datacarrier_bytes Optional<unsigned> "
     "plumbing. Cannot disable OP_RETURN relay at the operator level.",
     [
      ?_test(begin
         Src = read_src(beamchain_mempool_src()),
         %% No optional-style datacarrier handling.
         ?assertEqual(nomatch, binary:match(Src, <<"max_datacarrier">>)),
         ?assertEqual(nomatch, binary:match(Src, <<"DEFAULT_ACCEPT_DATACARRIER">>))
       end)
     ]}.

%%% ===================================================================
%%% G19 — BUG-7/BUG-8: dust threshold formula constants drift
%%% ===================================================================

g19_bug7_bug8_dust_formula_drift_test_() ->
    {"G19: BUG-7/BUG-8 FIXED — dust threshold now matches Core "
     "GetDustThreshold (policy.cpp:27-63). Spend-input cost is UNIFORM "
     "67 (32+4+1+(107 div 4)+4) for any witness program and 148 for "
     "non-witness, NOT a per-type 68/68/58 table. Output size includes "
     "GetSerializeSize(txout) with a proper CompactSize varint. Canonical "
     "thresholds: P2PKH 546, P2SH 540, P2WPKH 294, P2WSH 330, P2TR 330.",
     [
      ?_test(begin
         %% Pin the exact Core thresholds for all five canonical shapes.
         P2PKH  = <<16#76, 16#a9, 16#14, 0:160, 16#88, 16#ac>>,  % 25 bytes
         P2SH   = <<16#a9, 16#14, 0:160, 16#87>>,                 % 23 bytes
         P2WPKH = <<16#00, 16#14, 0:160>>,                        % 22 bytes
         P2WSH  = <<16#00, 16#20, 0:256>>,                        % 34 bytes
         P2TR   = <<16#51, 16#20, 0:256>>,                        % 34 bytes

         %% P2PKH: (8+1+25+148) = 182 -> 182*3 = 546 sat
         pin_threshold(P2PKH, 546),
         %% P2SH: (8+1+23+148) = 180 -> 180*3 = 540 sat
         pin_threshold(P2SH, 540),
         %% P2WPKH: (8+1+22+67) = 98 -> 98*3 = 294 sat
         pin_threshold(P2WPKH, 294),
         %% P2WSH: (8+1+34+67) = 110 -> 110*3 = 330 sat
         pin_threshold(P2WSH, 330),
         %% P2TR: (8+1+34+67) = 110 -> 110*3 = 330 sat
         pin_threshold(P2TR, 330),

         %% Regression vs the OLD buggy thresholds (297/333/303):
         %% 296-sat P2WPKH was dust at 297 but is NOT at the Core 294.
         ?assertEqual(false, beamchain_mempool:is_dust_output(
             #tx_out{value = 296, script_pubkey = P2WPKH})),
         %% 310-sat P2TR was NOT dust at the old 303 but IS at the Core 330
         %% (beamchain used to under-reject taproot dust).
         ?assertEqual(true, beamchain_mempool:is_dust_output(
             #tx_out{value = 310, script_pubkey = P2TR})),

         %% Unknown/future witness program (v1, 40-byte program) also takes the
         %% UNIFORM 67 spend cost (Core IsWitnessProgram), NOT the 148 fallback.
         %% (8+1+42+67) = 118 -> 118*3 = 354 sat.
         UnkWit = <<16#51, 40, 0:320>>,  % OP_1 OP_PUSHBYTES_40 <40 bytes>
         pin_threshold(UnkWit, 354)
       end)
     ]}.

%% is_dust_output(value=T-1) must be dust; is_dust_output(value=T) must NOT be.
pin_threshold(SPK, T) ->
    ?assertEqual(true, beamchain_mempool:is_dust_output(
        #tx_out{value = T - 1, script_pubkey = SPK})),
    ?assertEqual(false, beamchain_mempool:is_dust_output(
        #tx_out{value = T, script_pubkey = SPK})).

%%% ===================================================================
%%% G20 — BUG-13/BUG-14: dust threshold uses IsUnspendable carve-out
%%% ===================================================================

g20_bug13_bug14_dust_isunspendable_test_() ->
    {"G20: BUG-13/BUG-14 (MEDIUM) — Core's GetDustThreshold returns 0 "
     "for any IsUnspendable() script. beamchain only short-circuits "
     "OP_RETURN (and only via is_dust_output, not via dust_threshold).",
     [
      ?_test(begin
         %% OP_RETURN with any value is NOT dust per is_dust_output.
         ?assertEqual(false, beamchain_mempool:is_dust_output(
             #tx_out{value = 0, script_pubkey = <<16#6a>>})),
         ?assertEqual(false, beamchain_mempool:is_dust_output(
             #tx_out{value = 0, script_pubkey = <<16#6a, 1, 0>>})),
         %% Source: is_dust_output has the 0x6a clause but dust_threshold
         %% itself does NOT carve out IsUnspendable.
         Src = read_src(beamchain_mempool_src()),
         %% is_dust_output OP_RETURN early-return is line 4254-4257.
         ?assertNotEqual(nomatch,
             binary:match(Src,
                 <<"is_dust_output(#tx_out{value = V, script_pubkey = <<16#6a">>)),
         %% dust_threshold/1 has no IsUnspendable check.
         ?assertEqual(nomatch, binary:match(Src, <<"is_unspendable">>)),
         ?assertEqual(nomatch, binary:match(Src, <<"IsUnspendable">>))
       end)
     ]}.

%%% ===================================================================
%%% G21 — IsDust per-output predicate
%%% ===================================================================

g21_is_dust_output_test_() ->
    {"G21: PRESENT — IsDust per-output predicate works for the standard "
     "scriptPubKey types (constants tested in G19).",
     [
      ?_test(begin
         %% Default DUST_RELAY_TX_FEE = 3000 sat/kvB
         %% P2PKH 25-byte SPK: (8+1+25+148) * 3000 / 1000 = 182*3 = 546 sat
         P2PKH = <<16#76, 16#a9, 16#14, 0:160, 16#88, 16#ac>>,
         ?assertEqual(true, beamchain_mempool:is_dust_output(
             #tx_out{value = 545, script_pubkey = P2PKH})),
         ?assertEqual(false, beamchain_mempool:is_dust_output(
             #tx_out{value = 546, script_pubkey = P2PKH}))
       end)
     ]}.

%%% ===================================================================
%%% G22 — BUG-6: MAX_DUST_OUTPUTS_PER_TX count gate missing
%%% ===================================================================

g22_bug6_max_dust_outputs_per_tx_missing_test_() ->
    {"G22: BUG-6 (MEDIUM) — Core's policy.cpp:159-162 checks "
     "`GetDust(tx).size() > MAX_DUST_OUTPUTS_PER_TX (=1)`. beamchain "
     "has no count-based gate; pre_check_ephemeral_tx is fee-gated and "
     "rejects ANY dust output if fee > 0.",
     [
      ?_test(begin
         Src = read_src(beamchain_mempool_src()),
         ProtoHrl = read_src(beamchain_protocol_hrl()),
         %% No constant
         ?assertEqual(nomatch,
             binary:match(ProtoHrl, <<"MAX_DUST_OUTPUTS_PER_TX">>)),
         ?assertEqual(nomatch,
             binary:match(Src, <<"MAX_DUST_OUTPUTS_PER_TX">>)),
         %% No GetDust list-of-dust-outputs helper FUNCTION
         %% (Comment mentions "GetDustThreshold" but no Erlang function
         %% named get_dust/N exists; assert the symbol-table contains no
         %% such export.)
         ?assertEqual(nomatch, binary:match(Src, <<"get_dust(">>)),
         Exports = beamchain_mempool:module_info(exports),
         ?assertNot(lists:keymember(get_dust, 1, Exports))
       end)
     ]}.

%%% ===================================================================
%%% G23 — ValidateInputsStandardness per-input scriptPubKey classifier
%%% ===================================================================

g23_validate_inputs_standardness_present_test_() ->
    {"G23: PRESENT — ValidateInputsStandardness classifies each input's "
     "prev scriptPubKey. Nonstandard returns the canonical Core token "
     "`bad-txns-nonstandard-inputs`.",
     [
      ?_test(begin
         %% Provide one input whose prevout SPK is gibberish.
         NonStdSPK = <<16#99, 16#99, 16#99>>,
         Tx = #transaction{
             version = 2,
             inputs = [#tx_in{prev_out = #outpoint{hash = <<1:256>>, index = 0},
                              script_sig = <<>>,
                              sequence = 16#ffffffff,
                              witness = []}],
             outputs = [#tx_out{value = 100000,
                                script_pubkey = <<16#76, 16#a9, 16#14, 0:160,
                                                   16#88, 16#ac>>}],
             locktime = 0,
             txid = undefined,
             wtxid = undefined},
         Coin = #utxo{value = 200000, script_pubkey = NonStdSPK,
                      is_coinbase = false, height = 1},
         ?assertEqual({error, 'bad-txns-nonstandard-inputs'},
                      beamchain_mempool:validate_inputs_standardness(Tx, [Coin]))
       end)
     ]}.

%%% ===================================================================
%%% G24 — WITNESS_UNKNOWN input rejection (witness v2-v16 prevout)
%%% ===================================================================

g24_witness_unknown_input_rejected_test_() ->
    {"G24: PRESENT — A future witness program prevout (v2-v16) is "
     "treated as witness_unknown by classify_input_template and "
     "rejected as `bad-txns-nonstandard-inputs`.",
     [
      ?_test(begin
         %% Witness v2 with 32-byte program
         WitV2 = <<16#52, 16#20, 0:256>>,
         Tx = #transaction{
             version = 2,
             inputs = [#tx_in{prev_out = #outpoint{hash = <<1:256>>, index = 0},
                              script_sig = <<>>,
                              sequence = 16#ffffffff,
                              witness = []}],
             outputs = [#tx_out{value = 100000,
                                script_pubkey = <<16#76, 16#a9, 16#14, 0:160,
                                                   16#88, 16#ac>>}],
             locktime = 0,
             txid = undefined,
             wtxid = undefined},
         Coin = #utxo{value = 200000, script_pubkey = WitV2,
                      is_coinbase = false, height = 1},
         ?assertEqual({error, 'bad-txns-nonstandard-inputs'},
                      beamchain_mempool:validate_inputs_standardness(Tx, [Coin]))
       end)
     ]}.

%%% ===================================================================
%%% G25 — MAX_P2SH_SIGOPS = 15 per-redeem cap
%%% ===================================================================

g25_max_p2sh_sigops_per_redeem_test_() ->
    {"G25: PRESENT — Each P2SH redeem script's sigop count is capped at "
     "MAX_P2SH_SIGOPS = 15. Higher cap → bad-txns-nonstandard-inputs.",
     [
      ?_test(begin
         ?assertEqual(15, ?MAX_P2SH_SIGOPS),
         %% Build a P2SH prevout. The cap check requires extracting the
         %% redeem script from scriptSig; this gate is tested indirectly
         %% via the classify_input_template/code path. The constant
         %% matches Core policy.h:42.
         Src = read_src(beamchain_mempool_src()),
         ?assertNotEqual(nomatch,
             binary:match(Src, <<"?MAX_P2SH_SIGOPS">>))
       end)
     ]}.

%%% ===================================================================
%%% G26 — CheckSigopsBIP54 (MAX_TX_LEGACY_SIGOPS) NOT implemented
%%% ===================================================================

g26_check_sigops_bip54_missing_test_() ->
    {"G26: MISSING — Core's CheckSigopsBIP54 caps legacy-sigops-per-tx "
     "at MAX_TX_LEGACY_SIGOPS = 2500 (policy.cpp:170-194, policy.h:46). "
     "beamchain has no equivalent. The global "
     "MAX_STANDARD_TX_SIGOPS_COST (16000) gate is enforced separately.",
     [
      ?_test(begin
         Src = read_src(beamchain_mempool_src()),
         ?assertEqual(nomatch,
             binary:match(Src, <<"CheckSigopsBIP54">>)),
         ?assertEqual(nomatch,
             binary:match(Src, <<"check_sigops_bip54">>)),
         ?assertEqual(nomatch,
             binary:match(Src, <<"MAX_TX_LEGACY_SIGOPS">>)),
         ProtoHrl = read_src(beamchain_protocol_hrl()),
         ?assertEqual(nomatch,
             binary:match(ProtoHrl, <<"MAX_TX_LEGACY_SIGOPS">>))
       end)
     ]}.

%%% ===================================================================
%%% G27 — MAX_STANDARD_TX_SIGOPS_COST = 16000 global cap
%%% ===================================================================

g27_max_standard_tx_sigops_cost_test_() ->
    {"G27: PRESENT — MAX_STANDARD_TX_SIGOPS_COST = 16000 = "
     "MAX_BLOCK_SIGOPS_COST / 5. Gate is in W96 GATE 9 (mempool line 631).",
     [
      ?_test(begin
         ?assertEqual(16000, ?MAX_STANDARD_TX_SIGOPS_COST),
         ?assertEqual(?MAX_BLOCK_SIGOPS_COST div 5, ?MAX_STANDARD_TX_SIGOPS_COST),
         Src = read_src(beamchain_mempool_src()),
         ?assertNotEqual(nomatch,
             binary:match(Src,
                 <<"TxSigopCost =< ?MAX_STANDARD_TX_SIGOPS_COST">>))
       end)
     ]}.

%%% ===================================================================
%%% G28 — SpendsNonAnchorWitnessProg (TRUC interaction) NOT implemented
%%% ===================================================================

g28_spends_non_anchor_witness_prog_missing_test_() ->
    {"G28: MISSING — Core's SpendsNonAnchorWitnessProg "
     "(policy.cpp:354-388) is used by BIP-431/TRUC to detect "
     "witness-spending children. beamchain has no equivalent; TRUC "
     "rules are partial via check_truc_rules (W120 audit covers this).",
     [
      ?_test(begin
         Src = read_src(beamchain_mempool_src()),
         ?assertEqual(nomatch,
             binary:match(Src, <<"SpendsNonAnchorWitnessProg">>)),
         ?assertEqual(nomatch,
             binary:match(Src, <<"spends_non_anchor_witness_prog">>))
       end)
     ]}.

%%% ===================================================================
%%% G29 — BUG-9/BUG-20/BUG-21: reason-string surface uses atoms (collisions)
%%% ===================================================================

g29_bug9_bug20_bug21_reason_atom_surface_test_() ->
    {"G29: BUG-9/BUG-20/BUG-21 (LOW-MEDIUM) — beamchain's check_standard "
     "throws atoms (version, tx_size, scriptsig_size, "
     "scriptsig_not_pushonly, scriptpubkey, datacarrier). Compared to "
     "Core's reason strings: `version`, `tx-size` vs `tx-size-small` "
     "(BUG-9), `scriptpubkey` carries no whichType (BUG-20), and "
     "`bare-multisig` is never surfaced (BUG-21).",
     [
      ?_test(begin
         Src = read_src(beamchain_mempool_src()),
         %% atoms thrown from check_standard
         lists:foreach(fun(Atom) ->
             ?assertNotEqual(nomatch, binary:match(Src, Atom))
         end, [<<"throw(version)">>,
               <<"throw(tx_size)">>,
               <<"throw(scriptsig_size)">>,
               <<"throw(scriptsig_not_pushonly)">>,
               <<"throw(datacarrier)">>,
               <<"throw(scriptpubkey)">>]),
         %% No `bare-multisig` reason atom is *thrown* anywhere.
         %% (A comment mentions the phrase "bare-multisig" at line 4215
         %% but no throw('bare-multisig') or 'bare-multisig' atom exists.)
         ?assertEqual(nomatch, binary:match(Src, <<"throw('bare-multisig')">>)),
         ?assertEqual(nomatch, binary:match(Src, <<"throw(bare_multisig)">>)),
         ?assertEqual(nomatch, binary:match(Src, <<"'bare_multisig'">>))
       end)
     ]}.

%%% ===================================================================
%%% G30 — BUG-16/BUG-17: bare multisig matcher caps + pubkey size validation
%%% ===================================================================

g30_bug16_bug17_multisig_matcher_test_() ->
    {"G30: BUG-16/BUG-17 (LOW) — classify_input_template accepts bare "
     "multisig up to 3 keys (literal 3 instead of "
     "MAX_PUBKEYS_PER_MULTISIG-derived). Pubkey-size validation is "
     "byte-count only (33 or 65), not point-on-curve — matches Core's "
     "CPubKey::ValidSize semantic.",
     [
      ?_test(begin
         %% Build a 1-of-2 bare multisig prevout SPK
         Pk1 = binary:copy(<<16#aa>>, 33),
         Pk2 = binary:copy(<<16#bb>>, 33),
         MS_1_of_2 = <<16#51,
                       16#21, Pk1/binary,
                       16#21, Pk2/binary,
                       16#52,
                       16#ae>>,
         Tx = #transaction{
             version = 2,
             inputs = [#tx_in{prev_out = #outpoint{hash = <<1:256>>, index = 0},
                              script_sig = <<>>,
                              sequence = 16#ffffffff,
                              witness = []}],
             outputs = [#tx_out{value = 100000,
                                script_pubkey = <<16#76, 16#a9, 16#14, 0:160,
                                                   16#88, 16#ac>>}],
             locktime = 0,
             txid = undefined,
             wtxid = undefined},
         Coin = #utxo{value = 200000, script_pubkey = MS_1_of_2,
                      is_coinbase = false, height = 1},
         %% 1-of-2 is accepted on the input side (it's an existing UTXO
         %% we can spend even though we can't create one).
         ?assertEqual(ok,
             beamchain_mempool:validate_inputs_standardness(Tx, [Coin])),

         %% 1-of-4 bare multisig (n=4) should be rejected: the cap is 3.
         Pk3 = binary:copy(<<16#cc>>, 33),
         Pk4 = binary:copy(<<16#dd>>, 33),
         MS_1_of_4 = <<16#51,
                       16#21, Pk1/binary,
                       16#21, Pk2/binary,
                       16#21, Pk3/binary,
                       16#21, Pk4/binary,
                       16#54,
                       16#ae>>,
         Coin4 = #utxo{value = 200000, script_pubkey = MS_1_of_4,
                       is_coinbase = false, height = 1},
         ?assertEqual({error, 'bad-txns-nonstandard-inputs'},
             beamchain_mempool:validate_inputs_standardness(Tx, [Coin4])),

         %% Source: the cap is a literal 3, not MAX_PUBKEYS_PER_MULTISIG.
         Src = read_src(beamchain_mempool_src()),
         ?assertNotEqual(nomatch,
             binary:match(Src, <<"Acc =< 3">>))
       end)
     ]}.
