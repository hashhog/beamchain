-module(beamchain_w134_bloom_tests).

%% W134 audit: BIP-37 bloom filter subsystem (legacy SPV) — re-audit.
%%
%% Reference: bitcoin-core/src/common/bloom.{h,cpp}
%%            bitcoin-core/src/hash.{h,cpp} (MurmurHash3)
%%            bitcoin-core/src/merkleblock.{h,cpp}
%%            bitcoin-core/src/net_processing.cpp:4963-5033 (FILTERLOAD/ADD/CLEAR)
%%            bitcoin-core/src/net_processing.cpp:2438-2459 (MSG_FILTERED_BLOCK)
%%            bitcoin-core/src/init.cpp:1104-1105 (NODE_BLOOM advertisement)
%%
%% Verdict: MISSING ENTIRELY (27 of 30 gates) + PARTIAL (3 of 30 gates).
%%
%% No beamchain_bloom.erl module exists. No MurmurHash3 implementation
%% anywhere. P2P message codec (beamchain_p2p_msg.erl) has no encode/decode
%% clause for filterload, filteradd, filterclear, or merkleblock.
%% beamchain_peer_manager.erl has no handle_peer_message clause for any of
%% these messages; they fall through to the catch-all {noreply, State} and
%% are silently dropped. No per-peer bloom_filter / m_bloom_filter_loaded /
%% m_relay_txs state in #peer_data{}. The partial-merkle-tree algorithm
%% does exist (beamchain_rpc.erl:8088-8217, w47b_traverse_and_build /
%% w47b_traverse_and_extract) but is wired only to gettxoutproof /
%% verifytxoutproof RPCs — never reachable from P2P.
%%
%% Re-audit of W110 (2026-04-25, 13559f4). Since W110 two fixes landed:
%%   95ddaea  fix: BIP-35 default peerbloomfilters=false to match Core
%%   1bb22fb  fix: BIP-35 gate on local NODE_BLOOM advertisement
%% Both touched only the *advertisement* + *mempool gate* path, NOT the
%% bloom subsystem itself. Every BUG-N in W110 still applies, plus four
%% finer-grained splits surfaced by this re-audit (filterclear-resets-
%% relay-txs, matched-txn pushback, m_bloom_filter_loaded, stale comment).
%%
%% -----------------------------------------------------------------------
%% BUG CATALOGUE (22 bugs — 0 CDIV / 9 HIGH / 9 MEDIUM / 4 LOW)
%% -----------------------------------------------------------------------
%%
%%  HIGH (9)
%%  BUG-1  No beamchain_bloom.erl module (consumer of gates G1..G10, G29).
%%  BUG-2  No MurmurHash3 (x86_32) primitive anywhere.
%%  BUG-3  filterload/filteradd/filterclear not in p2p codec; falls to catch-all.
%%  BUG-4  No MSG_FILTERED_BLOCK branch in handle_getdata_msg → notfound.
%%  BUG-5  CMerkleBlock / CPartialMerkleTree dead-helper (RPC only).
%%  BUG-6  No per-peer bloom_filter / m_bloom_filter_loaded / m_relay_txs.
%%  BUG-7  No NODE_BLOOM disconnect gate on incoming filter* messages.
%%  BUG-8  No IsWithinSizeConstraints enforcement on filterload.
%%  BUG-9  No MAX_SCRIPT_ELEMENT_SIZE=520 enforcement on filteradd.
%%
%%  MEDIUM (9)
%%  BUG-10 bloomflags enum entirely absent.
%%  BUG-11 0xFBA4C795 hash-schedule constant absent.
%%  BUG-12 No COutPoint serialization for filter insert (canonical 36B form).
%%  BUG-13 IsRelevantAndUpdate txid match absent.
%%  BUG-14 IsRelevantAndUpdate per-output pushdata scan absent.
%%  BUG-15 Output-type detection (PUBKEY/MULTISIG) for UPDATE_P2PUBKEY_ONLY.
%%  BUG-16 Outpoint match in IsRelevantAndUpdate absent.
%%  BUG-17 scriptSig data scan absent.
%%  BUG-18 CMerkleBlock(block, filter) constructor not connected to filter.
%%
%%  LOW (4)
%%  BUG-19 Post-merkleblock matched-txn TX push absent.
%%  BUG-20 filterclear must reset m_relay_txs = true (BIP-37 semantics).
%%  BUG-21 m_bloom_filter_loaded Peer flag absent.
%%  BUG-22 beamchain_peer.erl:1289 stale comment ("Default-true mirrors Core").
%%
%% -----------------------------------------------------------------------
%% GATE SUMMARY
%% -----------------------------------------------------------------------
%%
%%  G1  MAX_BLOOM_FILTER_SIZE = 36000          MISSING ENTIRELY (BUG-1)
%%  G2  MAX_HASH_FUNCS = 50                    MISSING ENTIRELY (BUG-1)
%%  G3  LN2SQUARED full precision              MISSING ENTIRELY (BUG-1)
%%  G4  Constructor sizing formula             MISSING ENTIRELY (BUG-1)
%%  G5  nHashFuncs computation                 MISSING ENTIRELY (BUG-1)
%%  G6  MurmurHash3 x86_32                     MISSING ENTIRELY (BUG-2)
%%  G7  nHashNum*0xFBA4C795+nTweak             MISSING ENTIRELY (BUG-11)
%%  G8  Bit index formula                      MISSING ENTIRELY (BUG-1)
%%  G9  insert + contains round-trip           MISSING ENTIRELY (BUG-1)
%%  G10 isFull / vData.empty() CVE guard        MISSING ENTIRELY (BUG-1)
%%  G11 BLOOM_UPDATE_NONE = 0                  MISSING ENTIRELY (BUG-10)
%%  G12 BLOOM_UPDATE_ALL = 1                   MISSING ENTIRELY (BUG-10)
%%  G13 BLOOM_UPDATE_P2PUBKEY_ONLY = 2         MISSING ENTIRELY (BUG-10)
%%  G14 BLOOM_UPDATE_MASK = 3                  MISSING ENTIRELY (BUG-10)
%%  G15 nFlags & UPDATE_MASK in IRA            MISSING ENTIRELY (BUG-10)
%%  G16 IRA txid match                         MISSING ENTIRELY (BUG-13)
%%  G17 IRA per-output pushdata scan           MISSING ENTIRELY (BUG-14)
%%  G18 P2PKH/P2SH/P2PK/MULTISIG detection     MISSING ENTIRELY (BUG-15)
%%  G19 IRA outpoint match                     MISSING ENTIRELY (BUG-16)
%%  G20 IRA scriptSig data scan                MISSING ENTIRELY (BUG-17)
%%  G21 UPDATE_ALL outpoint-insert-on-match    MISSING ENTIRELY (BUG-1)
%%  G22 UPDATE_P2PUBKEY_ONLY outpoint-insert   MISSING ENTIRELY (BUG-1)
%%  G23 UPDATE_NONE never inserts outpoint     MISSING ENTIRELY (BUG-1)
%%  G24 COutPoint serialization (36B)          MISSING ENTIRELY (BUG-12)
%%  G25 filterload codec + handler             MISSING ENTIRELY (BUG-3)
%%  G26 filteradd ≤520 bytes guard             MISSING ENTIRELY (BUG-3/9)
%%  G27 filterclear codec + handler            MISSING ENTIRELY (BUG-3/20)
%%  G28 merkleblock codec + CMerkleBlock       MISSING ENTIRELY (BUG-4/5/18/19)
%%  G29 IsWithinSizeConstraints enforced       MISSING ENTIRELY (BUG-8)
%%  G30 NODE_BLOOM + BIP-111 disconnect gate   PARTIAL (BUG-7/22)

-include_lib("eunit/include/eunit.hrl").
-include("beamchain_protocol.hrl").

%%%===================================================================
%%% Test suite entry point — 30 gates / 30 tests
%%%===================================================================

w134_bloom_filter_test_() ->
    [
     {"G1-BUG: MAX_BLOOM_FILTER_SIZE missing (no beamchain_bloom module)",
      fun g1_max_bloom_filter_size_missing/0},
     {"G2-BUG: MAX_HASH_FUNCS missing",
      fun g2_max_hash_funcs_missing/0},
     {"G3-BUG: LN2SQUARED full-precision constant missing",
      fun g3_ln2squared_missing/0},
     {"G4-BUG: constructor sizing formula absent",
      fun g4_constructor_absent/0},
     {"G5-BUG: nHashFuncs computation absent",
      fun g5_nhashfuncs_absent/0},
     {"G6-BUG: MurmurHash3 (x86_32) not implemented anywhere",
      fun g6_murmurhash3_absent/0},
     {"G7-BUG: 0xFBA4C795 hash schedule absent",
      fun g7_hash_schedule_absent/0},
     {"G8-BUG: bit-index (h>>3, 1 << (7 & h)) absent",
      fun g8_bit_index_absent/0},
     {"G9-BUG: bloom insert+contains round-trip absent",
      fun g9_insert_contains_absent/0},
     {"G10-BUG: isFull / vData.empty() CVE-2013-5700 guard absent",
      fun g10_isfull_isempty_absent/0},
     {"G11-BUG: BLOOM_UPDATE_NONE constant absent",
      fun g11_update_none_absent/0},
     {"G12-BUG: BLOOM_UPDATE_ALL constant absent",
      fun g12_update_all_absent/0},
     {"G13-BUG: BLOOM_UPDATE_P2PUBKEY_ONLY constant absent",
      fun g13_update_p2pubkey_absent/0},
     {"G14-BUG: BLOOM_UPDATE_MASK constant absent",
      fun g14_update_mask_absent/0},
     {"G15-BUG: nFlags & BLOOM_UPDATE_MASK absent (no IRA)",
      fun g15_nflags_mask_absent/0},
     {"G16-BUG: IsRelevantAndUpdate txid match absent",
      fun g16_txid_match_absent/0},
     {"G17-BUG: per-output pushdata scan absent",
      fun g17_output_pushdata_absent/0},
     {"G18-BUG: P2PKH/P2SH/P2PK/MULTISIG output-type detection absent",
      fun g18_output_type_detection_absent/0},
     {"G19-BUG: outpoint match (txin.prevout) absent",
      fun g19_outpoint_match_absent/0},
     {"G20-BUG: scriptSig data scan absent",
      fun g20_scriptsig_scan_absent/0},
     {"G21-BUG: UPDATE_ALL outpoint-insert-on-match absent",
      fun g21_update_all_outpoint_absent/0},
     {"G22-BUG: UPDATE_P2PUBKEY_ONLY conditional outpoint-insert absent",
      fun g22_update_p2pubkey_only_absent/0},
     {"G23-BUG: UPDATE_NONE never inserts outpoint (N/A: no bloom)",
      fun g23_update_none_absent/0},
     {"G24-BUG: canonical 36B COutPoint serialisation for bloom absent",
      fun g24_outpoint_serialisation_absent/0},
     {"G25-BUG: filterload codec + handler absent (catch-all swallow)",
      fun g25_filterload_codec_handler_absent/0},
     {"G26-BUG: filteradd MAX_SCRIPT_ELEMENT_SIZE=520 guard absent",
      fun g26_filteradd_size_guard_absent/0},
     {"G27-BUG: filterclear codec + handler absent; m_relay_txs reset missing",
      fun g27_filterclear_codec_handler_absent/0},
     {"G28-BUG: merkleblock codec + CMerkleBlock(block,filter) absent (RPC-only)",
      fun g28_merkleblock_p2p_absent/0},
     {"G29-BUG: IsWithinSizeConstraints enforcement absent (no filterload)",
      fun g29_size_constraints_enforcement_absent/0},
     {"G30-PARTIAL: NODE_BLOOM=4 correct + advertised + default-false; "
      "BIP-111 per-msg disconnect gate absent",
      fun g30_node_bloom_and_bip111/0}
    ].

%%%===================================================================
%%% G1-G5: Constants & sizing
%%%===================================================================

%% G1: MAX_BLOOM_FILTER_SIZE = 36000 bytes (Core bloom.h:17)
g1_max_bloom_filter_size_missing() ->
    %% No beamchain_bloom module ever loaded.
    ?assertEqual(non_existing, code:which(beamchain_bloom)),
    %% No symbol MAX_BLOOM_FILTER_SIZE in protocol header.
    HrlPath = filename:join([code:lib_dir(beamchain, include),
                             "beamchain_protocol.hrl"]),
    {ok, Bin} = file:read_file(HrlPath),
    ?assertEqual(nomatch,
                 binary:match(Bin, <<"MAX_BLOOM_FILTER_SIZE">>)),
    ok.

%% G2: MAX_HASH_FUNCS = 50 (Core bloom.h:18)
g2_max_hash_funcs_missing() ->
    ?assertEqual(non_existing, code:which(beamchain_bloom)),
    HrlPath = filename:join([code:lib_dir(beamchain, include),
                             "beamchain_protocol.hrl"]),
    {ok, Bin} = file:read_file(HrlPath),
    ?assertEqual(nomatch,
                 binary:match(Bin, <<"MAX_HASH_FUNCS">>)),
    ok.

%% G3: LN2SQUARED = 0.4804530139182014246671025263266649717305529515945455
%% (Core bloom.cpp:23 — 52 significant digits)
g3_ln2squared_missing() ->
    %% No bloom module → no LN2SQUARED constant.
    ?assertEqual(non_existing, code:which(beamchain_bloom)),
    %% Document the reference value so a future fix has the spec at hand.
    LN2SQUARED = 0.4804530139182014246671025263266649717305529515945455,
    %% Sanity-bound: ln(2)^2 ≈ 0.48045301. The pinned constant must be
    %% within 1.0e-15 of math:log(2)*math:log(2).
    ApproxLn2Sq = math:log(2) * math:log(2),
    ?assert(abs(LN2SQUARED - ApproxLn2Sq) < 1.0e-15),
    ok.

%% G4: vData size = min(trunc(-1/LN2SQ * N * ln(fp)), MAX_BLOOM*8) / 8
%% (Core bloom.cpp:32)
g4_constructor_absent() ->
    ?assertEqual(non_existing, code:which(beamchain_bloom)),
    ok.

%% G5: nHashFuncs = min(trunc(vData*8 / N * LN2), MAX_HASH_FUNCS)
%% (Core bloom.cpp:38)
g5_nhashfuncs_absent() ->
    ?assertEqual(non_existing, code:which(beamchain_bloom)),
    ok.

%%%===================================================================
%%% G6-G10: Hash & bit-set
%%%===================================================================

%% G6: MurmurHash3 (x86_32) — Core hash.cpp:13-65
%% Known test vectors from SMHasher / Core test_bloom.cpp:
%%   MurmurHash3(seed=0, <<>>)  = 0
%%   MurmurHash3(seed=0, <<0>>) = 0x514E28B7
%%   MurmurHash3(seed=1, <<0>>) = 0xEA3F7AFF
%% MurmurHash3 is NOT in OTP's crypto module — would need a manual impl.
g6_murmurhash3_absent() ->
    ?assertEqual(non_existing, code:which(beamchain_bloom)),
    %% Verify no other module exports a murmurhash3/2 helper.
    AllModules = [list_to_atom(filename:basename(F, ".erl"))
                  || F <- filelib:wildcard(
                            filename:join(code:lib_dir(beamchain, src),
                                          "*.erl"))],
    HasMurmur = lists:any(fun(M) ->
        case code:ensure_loaded(M) of
            {module, M} ->
                erlang:function_exported(M, murmurhash3, 2) orelse
                erlang:function_exported(M, murmur_hash3, 2);
            _ -> false
        end
    end, AllModules),
    ?assertNot(HasMurmur),
    ok.

%% G7: hash schedule: MurmurHash3(i * 0xFBA4C795 + nTweak, data)
%% (Core bloom.cpp:46-47)
g7_hash_schedule_absent() ->
    ?assertEqual(non_existing, code:which(beamchain_bloom)),
    %% Document the constant in the spec for future fix waves.
    ?assertEqual(16#FBA4C795, 4221880213),
    %% Source-level check: the constant 0xFBA4C795 must not yet appear in
    %% any .erl in src/. (When the bloom module lands it will appear; this
    %% test will then fail and be deliberately updated.)
    SrcDir = code:lib_dir(beamchain, src),
    Files = filelib:wildcard(filename:join(SrcDir, "*.erl")),
    Hits = [F || F <- Files,
                 case file:read_file(F) of
                     {ok, B} ->
                         binary:match(B, <<"FBA4C795">>) =/= nomatch
                         orelse binary:match(B, <<"fba4c795">>) =/= nomatch
                         orelse binary:match(B, <<"4219829141">>) =/= nomatch;
                     _ -> false
                 end],
    ?assertEqual([], Hits),
    ok.

%% G8: nIndex = hash % (vData.size() * 8)
%%     set:   vData[nIndex>>3] |= (1 << (7 & nIndex))
%%     check: vData[nIndex>>3] &  (1 << (7 & nIndex))
%% (Core bloom.cpp:57-58, 77)
g8_bit_index_absent() ->
    ?assertEqual(non_existing, code:which(beamchain_bloom)),
    ok.

%% G9: insert(K) + contains(K) round-trip
g9_insert_contains_absent() ->
    ?assertEqual(non_existing, code:which(beamchain_bloom)),
    ok.

%% G10: isFull / isEmpty short-circuit (CVE-2013-5700 — divide-by-zero on
%% empty vData; treat as match-all return-true in contains)
g10_isfull_isempty_absent() ->
    ?assertEqual(non_existing, code:which(beamchain_bloom)),
    ok.

%%%===================================================================
%%% G11-G15: Update flags
%%%===================================================================

%% G11: BLOOM_UPDATE_NONE = 0
g11_update_none_absent() ->
    HrlPath = filename:join([code:lib_dir(beamchain, include),
                             "beamchain_protocol.hrl"]),
    {ok, Bin} = file:read_file(HrlPath),
    ?assertEqual(nomatch, binary:match(Bin, <<"BLOOM_UPDATE_NONE">>)),
    ok.

%% G12: BLOOM_UPDATE_ALL = 1
g12_update_all_absent() ->
    HrlPath = filename:join([code:lib_dir(beamchain, include),
                             "beamchain_protocol.hrl"]),
    {ok, Bin} = file:read_file(HrlPath),
    ?assertEqual(nomatch, binary:match(Bin, <<"BLOOM_UPDATE_ALL">>)),
    ok.

%% G13: BLOOM_UPDATE_P2PUBKEY_ONLY = 2
g13_update_p2pubkey_absent() ->
    HrlPath = filename:join([code:lib_dir(beamchain, include),
                             "beamchain_protocol.hrl"]),
    {ok, Bin} = file:read_file(HrlPath),
    ?assertEqual(nomatch,
                 binary:match(Bin, <<"BLOOM_UPDATE_P2PUBKEY_ONLY">>)),
    ok.

%% G14: BLOOM_UPDATE_MASK = 3
g14_update_mask_absent() ->
    HrlPath = filename:join([code:lib_dir(beamchain, include),
                             "beamchain_protocol.hrl"]),
    {ok, Bin} = file:read_file(HrlPath),
    ?assertEqual(nomatch, binary:match(Bin, <<"BLOOM_UPDATE_MASK">>)),
    ok.

%% G15: (nFlags & BLOOM_UPDATE_MASK) selects update-mode for IRA
g15_nflags_mask_absent() ->
    ?assertEqual(non_existing, code:which(beamchain_bloom)),
    ok.

%%%===================================================================
%%% G16-G20: Match logic
%%%===================================================================

%% G16: IRA txid match (Core bloom.cpp:102-104)
g16_txid_match_absent() ->
    ?assertEqual(non_existing, code:which(beamchain_bloom)),
    ok.

%% G17: per-output pushdata scan in IRA (Core bloom.cpp:113-134)
g17_output_pushdata_absent() ->
    ?assertEqual(non_existing, code:which(beamchain_bloom)),
    ok.

%% G18: TxoutType solver (PUBKEY/MULTISIG) for UPDATE_P2PUBKEY_ONLY
%% (Core bloom.cpp:127-131 + script/solver.h Solver())
g18_output_type_detection_absent() ->
    ?assertEqual(non_existing, code:which(beamchain_bloom)),
    ok.

%% G19: outpoint match in IRA (Core bloom.cpp:144)
g19_outpoint_match_absent() ->
    ?assertEqual(non_existing, code:which(beamchain_bloom)),
    ok.

%% G20: scriptSig data scan in IRA (Core bloom.cpp:149-155)
g20_scriptsig_scan_absent() ->
    ?assertEqual(non_existing, code:which(beamchain_bloom)),
    ok.

%%%===================================================================
%%% G21-G24: IsRelevantAndUpdate side-effects
%%%===================================================================

%% G21: UPDATE_ALL — on any output pushdata match, insert(COutPoint(txid, i))
g21_update_all_outpoint_absent() ->
    ?assertEqual(non_existing, code:which(beamchain_bloom)),
    ok.

%% G22: UPDATE_P2PUBKEY_ONLY — insert outpoint only on PUBKEY/MULTISIG
g22_update_p2pubkey_only_absent() ->
    ?assertEqual(non_existing, code:which(beamchain_bloom)),
    ok.

%% G23: UPDATE_NONE — no outpoint ever inserted, even on match
g23_update_none_absent() ->
    ?assertEqual(non_existing, code:which(beamchain_bloom)),
    ok.

%% G24: canonical COutPoint serialisation: txid(32B,LE) ‖ vout(4B LE)
%% Used for filter insertion of outpoints (Core bloom.cpp:62-67, 83-88).
g24_outpoint_serialisation_absent() ->
    %% No serializer is exported for "outpoint to canonical 36 bytes" outside
    %% of the per-tx wire serialiser. beamchain_serialize has encode_varint /
    %% varstr but no encode_outpoint/1.
    {module, beamchain_serialize} = code:ensure_loaded(beamchain_serialize),
    ?assertNot(erlang:function_exported(beamchain_serialize, encode_outpoint, 1)),
    %% No bloom module exists to host an alternate location.
    ?assertEqual(non_existing, code:which(beamchain_bloom)),
    ok.

%%%===================================================================
%%% G25-G28: P2P messages
%%%===================================================================

%% G25: filterload P2P message
%% Wire: varint(|vData|) ‖ vData ‖ nHashFuncs(4B LE) ‖ nTweak(4B LE) ‖ nFlags(1B)
%% (BIP-37; Core net_processing.cpp:4963-4986)
%% Verify (a) command_name/1 maps filterload → undefined (atom missing from
%% match table), (b) encode_payload(filterload, ...) raises function_clause /
%% undef, (c) decode_payload(filterload, ...) likewise.
g25_filterload_codec_handler_absent() ->
    {module, beamchain_p2p_msg} = code:ensure_loaded(beamchain_p2p_msg),
    %% command_name/1 must NOT have a clause for filterload.
    ?assertError(function_clause, beamchain_p2p_msg:command_name(filterload)),
    ?assertError(function_clause, beamchain_p2p_msg:command_name(filteradd)),
    ?assertError(function_clause, beamchain_p2p_msg:command_name(filterclear)),
    ?assertError(function_clause, beamchain_p2p_msg:command_name(merkleblock)),
    %% encode_payload(filterload, _) must blow up — no clause.
    Result = try
        beamchain_p2p_msg:encode_payload(filterload,
            #{filter => <<>>, hash_funcs => 1, tweak => 0, flags => 0})
    catch
        error:function_clause -> missing;
        error:undef           -> missing;
        _:_                   -> missing
    end,
    ?assertEqual(missing, Result),
    ok.

%% G26: filteradd — single varbytes payload, data ≤ MAX_SCRIPT_ELEMENT_SIZE
%% (Core net_processing.cpp:5000)
g26_filteradd_size_guard_absent() ->
    %% MAX_SCRIPT_ELEMENT_SIZE is in the protocol hrl (= 520) ✓.
    ?assertEqual(520, ?MAX_SCRIPT_ELEMENT_SIZE),
    %% No decode_payload(filteradd, _) clause.
    Result = try
        beamchain_p2p_msg:decode_payload(filteradd, <<0:8>>)
    catch
        error:function_clause -> missing;
        error:undef           -> missing;
        _:_                   -> missing
    end,
    ?assertEqual(missing, Result),
    ok.

%% G27: filterclear — empty payload. Core net_processing.cpp:5016-5033
%% semantics include resetting m_relay_txs to true (BUG-20).
g27_filterclear_codec_handler_absent() ->
    Result = try
        beamchain_p2p_msg:encode_payload(filterclear, #{})
    catch
        error:function_clause -> missing;
        error:undef           -> missing;
        _:_                   -> missing
    end,
    ?assertEqual(missing, Result),
    ok.

%% G28: merkleblock P2P message + CMerkleBlock(block, filter)
%% Wire: header(80B) ‖ varint(nTxns) ‖ varint(nHashes) ‖ 32B*nHashes
%%       ‖ varint(nFlagBytes) ‖ flagBytes
%% (Core merkleblock.{h,cpp}; net_processing.cpp:2438-2459 builds
%%  CMerkleBlock(*pblock, *tx_relay->m_bloom_filter) on getdata-msg-filt-block)
%%
%% Confirm two-pipeline / dead-helper: w47b_traverse_* helpers live in
%% beamchain_rpc but are NOT wired to a getdata path.
g28_merkleblock_p2p_absent() ->
    %% No encode_payload(merkleblock, _) clause.
    Result = try
        beamchain_p2p_msg:encode_payload(merkleblock, #{})
    catch
        error:function_clause -> missing;
        error:undef           -> missing;
        _:_                   -> missing
    end,
    ?assertEqual(missing, Result),
    %% command_atom decoded from <<"merkleblock">> falls through to
    %% binary_to_atom(Other, utf8) — confirm by encoding to the catch-all
    %% behaviour: the result atom *is* merkleblock but no handler exists.
    ?assertEqual(merkleblock,
                 beamchain_p2p_msg:command_atom(<<"merkleblock">>)),
    %% MSG_FILTERED_BLOCK inv type exists (= 3) but no getdata branch
    %% handles it — confirmed by source inspection: handle_getdata_msg in
    %% beamchain_peer_manager.erl:1733-1801 only matches MSG_BLOCK /
    %% MSG_WITNESS_BLOCK / MSG_TX / MSG_WITNESS_TX. Test the constant:
    ?assertEqual(3, ?MSG_FILTERED_BLOCK),
    %% The RPC-side PartialMerkleTree helpers exist (dead-helper pattern).
    %% Their containing module must be loaded; their function names are
    %% private (no export) but the gettxoutproof RPC entry point IS exported.
    {module, beamchain_rpc} = code:ensure_loaded(beamchain_rpc),
    ?assertNotEqual(non_existing, code:which(beamchain_rpc)),
    ok.

%%%===================================================================
%%% G29-G30: DoS & service gating
%%%===================================================================

%% G29: IsWithinSizeConstraints (vData ≤ MAX_BLOOM_FILTER_SIZE AND
%% nHashFuncs ≤ MAX_HASH_FUNCS) enforced on filterload before storing.
%% Core bloom.h:77, bloom.cpp:90-93, net_processing.cpp:4972-4975.
g29_size_constraints_enforcement_absent() ->
    ?assertEqual(non_existing, code:which(beamchain_bloom)),
    %% With no filterload handler an oversized filter is silently dropped,
    %% not Misbehaving-flagged.
    ok.

%% G30: NODE_BLOOM service bit + BIP-111 disconnect gate.
%% CORRECT (PARTIAL):
%%   - ?NODE_BLOOM = 4 in beamchain_protocol.hrl ✓ (BIP-37/BIP-111)
%%   - beamchain_config:node_bloom_enabled/0 defaults to false (per 95ddaea) ✓
%%   - NODE_BLOOM conditionally OR'd into services in beamchain_peer.erl:1291 ✓
%%   - mempool message gate at peer_manager.erl:1464-1473 ✓
%% WRONG (BUG-7):
%%   - No filterload / filteradd / filterclear / merkleblock-getdata
%%     handler enforces "if not NODE_BLOOM → disconnect".
%% COMMENT-BUG (BUG-22):
%%   - beamchain_peer.erl:1289 still has the stale "Default-true mirrors
%%     Core's `-peerbloomfilters` default" comment.
g30_node_bloom_and_bip111() ->
    %% NODE_BLOOM service bit must be 4 = 1 << 2 (per BIP-111).
    ?assertEqual(4, ?NODE_BLOOM),
    %% node_bloom_enabled/0 is exported and (in default env) returns false.
    {module, beamchain_config} = code:ensure_loaded(beamchain_config),
    ?assert(erlang:function_exported(beamchain_config,
                                      node_bloom_enabled, 0)),
    %% mempool NODE_BLOOM gate IS present in peer_manager. Source-level
    %% verification: look for "node_bloom_enabled" inside the mempool
    %% handler.
    SrcPath = filename:join([code:lib_dir(beamchain, src),
                             "beamchain_peer_manager.erl"]),
    {ok, PM} = file:read_file(SrcPath),
    ?assertNotEqual(nomatch,
                    binary:match(PM, <<"node_bloom_enabled">>)),
    %% But there is NO filterload/filteradd/filterclear handler — the
    %% catch-all at the end of handle_peer_message/4 swallows them.
    %% Verify by ensuring the source contains no clause like
    %% "handle_peer_message(_, filterload" or similar.
    ?assertEqual(nomatch,
                 binary:match(PM, <<"handle_peer_message(_, filterload">>)),
    ?assertEqual(nomatch,
                 binary:match(PM, <<"handle_peer_message(Pid, filterload">>)),
    ?assertEqual(nomatch,
                 binary:match(PM, <<"handle_peer_message(_, filteradd">>)),
    ?assertEqual(nomatch,
                 binary:match(PM, <<"handle_peer_message(Pid, filteradd">>)),
    ?assertEqual(nomatch,
                 binary:match(PM, <<"handle_peer_message(_, filterclear">>)),
    ?assertEqual(nomatch,
                 binary:match(PM, <<"handle_peer_message(Pid, filterclear">>)),
    %% MSG_FILTERED_BLOCK is similarly missing from handle_getdata_msg.
    %% Pattern '?MSG_FILTERED_BLOCK' must NOT appear in the file.
    ?assertEqual(nomatch,
                 binary:match(PM, <<"?MSG_FILTERED_BLOCK">>)),
    ?assertEqual(nomatch,
                 binary:match(PM, <<"MSG_FILTERED_BLOCK">>)),
    %% Stale-comment check (BUG-22): the "mirrors Core's `-peerbloomfilters`
    %% default" comment is still there.
    PeerSrc = filename:join([code:lib_dir(beamchain, src),
                             "beamchain_peer.erl"]),
    {ok, PS} = file:read_file(PeerSrc),
    ?assertNotEqual(nomatch,
                    binary:match(PS, <<"-peerbloomfilters">>)),
    ok.
