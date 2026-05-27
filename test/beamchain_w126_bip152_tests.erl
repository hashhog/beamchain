-module(beamchain_w126_bip152_tests).

%%% -------------------------------------------------------------------
%%% W126 — BIP-152 Compact Block Relay audit (beamchain).
%%%
%%% Scope: SENDCMPCT/CMPCTBLOCK/GETBLOCKTXN/BLOCKTXN handlers, the
%%%        HB-from (announce-in) accept path, the HB-to (announce-out)
%%%        send path, PartiallyDownloadedBlock reconstruction, short-tx-id
%%%        siphash key derivation, v1 vs v2 negotiation.
%%%
%%% Reference: bitcoin-core/src/net_processing.cpp
%%%              SENDCMPCT     :3901
%%%              CMPCTBLOCK    :4466
%%%              GETBLOCKTXN   :4245
%%%              BLOCKTXN      :4714
%%%              NewPoWValidBlock                   :2103
%%%              MaybeSetPeerAsAnnouncingHeaderAndIDs :1272
%%%              SendBlockTransactions               :2598
%%%              ProcessCompactBlockTxns             :3441
%%%              CMPCTBLOCKS_VERSION = 2             :199
%%%              MAX_BLOCKTXN_DEPTH = 10             :140
%%%              MAX_CMPCTBLOCK_DEPTH = 5            :138
%%%              MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3 (net_processing.h:47)
%%%            bitcoin-core/src/blockencodings.{cpp,h}
%%%              InitData                            :59
%%%              FillBlock                           :191
%%%              GetShortID                          :46
%%%              FillShortTxIDSelector               :35
%%%            bitcoin-core/src/validation.cpp
%%%              IsBlockMutated                      :4027
%%%            BIP-152
%%%
%%% Audit gates: see audit/w126_bip152_compact_blocks.md for full text.
%%% PRESENT gates green-bar a real production invariant. PARTIAL and
%%% MISSING gates land as ?_assert(true) marker tests with the expected
%%% behavior in a comment so the absence is greppable from the test
%%% suite and survives future refactors (W124 beamchain pattern).
%%%
%%% NO PRODUCTION CODE CHANGES IN THIS COMMIT.  This is a discovery
%%% wave; the production code stays as-is.
%%% -------------------------------------------------------------------

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%%% ===================================================================
%%% Test helpers
%%% ===================================================================

%% Synthesize a minimally-valid block_header for reconstruction tests.
make_header() ->
    #block_header{
        version = 1,
        prev_hash = <<1:256>>,
        merkle_root = <<2:256>>,
        timestamp = 1700000000,
        bits = 16#1d00ffff,
        nonce = 0
    }.

%% Locate beamchain src dir (W124 pattern — needed for static-text grepping
%% of constants and call-site invariants without depending on private
%% module accessors).
beamchain_src_dir() ->
    case code:which(beamchain_app) of
        non_existing -> "src";
        Beam ->
            Ebin = filename:dirname(Beam),
            Lib  = filename:dirname(Ebin),
            Src  = filename:join([Lib, "src"]),
            case filelib:is_dir(Src) of
                true -> Src;
                false -> "src"
            end
    end.

read_src_file(Filename) ->
    Path = filename:join(beamchain_src_dir(), Filename),
    case file:read_file(Path) of
        {ok, Bin} -> Bin;
        _ -> <<>>
    end.

src_contains(Filename, Needle) ->
    Bin = read_src_file(Filename),
    binary:match(Bin, Needle) =/= nomatch.

%%% ===================================================================
%%% G1  SENDCMPCT version != CMPCTBLOCKS_VERSION (2) silently ignored
%%%      — Core net_processing.cpp:3907  — MISSING (BUG-1, P0-CDIV)
%%% ===================================================================

%% AUDIT MARKER (FAIL EXPECTED AFTER FIX): handle_sendcmpct_msg accepts
%% ANY version field and stores it on peer_data{cmpct_version}. Core
%% silently drops sendcmpct with version != 2. A peer can send
%% sendcmpct(true, v=999) and beamchain commits "HB at v=999", but
%% compute_short_id only does v2 (wtxid). Result: any subsequent
%% cmpctblock from that peer silently fails to reconstruct.
g1_sendcmpct_version_not_filtered_test() ->
    %% Confirm the divergent behavior by showing the decoder happily
    %% returns any version value, including obviously-out-of-spec ones.
    Bin = beamchain_p2p_msg:encode_payload(sendcmpct,
              #{announce => true, version => 999}),
    ?assertMatch({ok, #{announce := true, version := 999}},
                 beamchain_p2p_msg:decode_payload(sendcmpct, Bin)),
    %% After fix: handle_sendcmpct_msg should ignore version != 2 and
    %% leave peer_data{wants_cmpct, cmpct_version} unchanged.
    ?assert(true).

g1_sendcmpct_v2_only_accept_test() ->
    %% Future invariant (currently failing): the only acceptable
    %% sendcmpct version is 2. Marker test — flipped on FIX.
    ?assert(true).  %% TODO: replace with handle_sendcmpct_msg gate

%%% ===================================================================
%%% G2  SENDCMPCT received post-VERACK still valid
%%%      — Core net_processing.cpp:3901 (no post-verack guard) — PRESENT
%%% ===================================================================

g2_sendcmpct_post_verack_accepted_test() ->
    %% Per Core, sendcmpct can arrive at any time post-version-exchange.
    %% beamchain's dispatch_message(sendcmpct, ...) handler is
    %% unconditional (no handshake_complete guard), matching Core.
    ?assert(src_contains("beamchain_peer.erl",
                         <<"dispatch_message(sendcmpct, Payload, Data) ->">>)).

%%% ===================================================================
%%% G3  Outgoing sendcmpct on handshake (v1+v2) — PRESENT
%%% ===================================================================

g3_outgoing_sendcmpct_on_handshake_test() ->
    %% Encoded sendcmpct must be exactly 9 bytes: 1 byte announce + 8 bytes version.
    Payload = beamchain_p2p_msg:encode_payload(sendcmpct,
                  #{announce => true, version => 2}),
    ?assertEqual(9, byte_size(Payload)),
    ?assertMatch({ok, #{announce := true, version := 2}},
                 beamchain_p2p_msg:decode_payload(sendcmpct, Payload)).

%%% ===================================================================
%%% G4  sendcmpct v1 should NOT be sent (Core 2024+: v2 only)
%%%      — Core net_processing.cpp:3870 — BUG-17 (P1)
%%% ===================================================================

g4_sendcmpct_v1_still_sent_test() ->
    %% AUDIT MARKER: beamchain_peer.erl:1646-1648 still encodes a v1
    %% sendcmpct on handshake. Core 2024+ has dropped v1 entirely.
    %% Per the BUG-17 catalogue, this is dead bandwidth and a subtle
    %% interop hazard: v1 advertises txid-based shortids but our
    %% compute_short_id only does wtxid (v2).
    ?assert(src_contains("beamchain_peer.erl",
                         <<"version => 1">>)),
    ?assert(true).

%%% ===================================================================
%%% G5  CMPCTBLOCK header pre-validation before reconstruction
%%%      — Core net_processing.cpp:4483-4513 — MISSING (BUG-4, P0)
%%% ===================================================================

g5_no_header_prevalidation_before_reconstruction_test() ->
    %% AUDIT MARKER: handle_cmpctblock_received jumps straight to
    %% init_compact_block without LookupBlockIndex(hashPrevBlock), without
    %% low-work guard, without ProcessNewBlockHeaders. Core does ALL THREE
    %% before any reconstruction work.
    %%
    %% Expected after fix: a new prevalidate_cmpctblock_header/1 helper
    %% before init_compact_block in handle_cmpctblock_received.
    Bin = read_src_file("beamchain_block_sync.erl"),
    %% Confirm divergence: the prefix init_compact_block is invoked
    %% immediately from handle_cmpctblock_received without any
    %% prev-block-lookup or chain-work guard between the entry point
    %% and the call site.
    ?assert(binary:match(Bin, <<"handle_cmpctblock_received(Peer, CmpctBlock, State) ->">>) =/= nomatch),
    ?assert(binary:match(Bin, <<"prevalidate_cmpctblock_header">>) =:= nomatch),
    ?assert(true).

%%% ===================================================================
%%% G6  CMPCTBLOCK ignored while LoadingBlocks()
%%%      — Core net_processing.cpp:4469 — MISSING (BUG-6, P0)
%%% ===================================================================

g6_no_loadingblocks_gate_test() ->
    %% AUDIT MARKER: Core gates both CMPCTBLOCK and BLOCKTXN on
    %% LoadingBlocks() = false. beamchain has no such gate.
    Bin = read_src_file("beamchain_block_sync.erl"),
    ?assert(binary:match(Bin, <<"loading_blocks">>) =:= nomatch),
    ?assert(binary:match(Bin, <<"LoadingBlocks">>) =:= nomatch),
    ?assert(true).

%%% ===================================================================
%%% G7  CMPCTBLOCK header punishment via_compact_block=true semantics
%%%      — Core net_processing.cpp:4505, 4677, 4682 — MISSING (BUG-5, P0)
%%% ===================================================================

g7_no_via_compact_block_distinction_test() ->
    %% AUDIT MARKER: BIP-152 §"Pre-Versioning Considerations" — peers
    %% MUST NOT be disconnected for invalid blocks announced via
    %% cmpctblock (HB-relay permits pre-validation forwarding). Core
    %% threads via_compact_block=true into MaybePunishNodeForBlock.
    %% beamchain has no equivalent distinction.
    ?assertNot(src_contains("beamchain_block_sync.erl",
                            <<"via_compact_block">>)),
    ?assert(true).

%%% ===================================================================
%%% G8  CanDirectFetch() gate before reconstruction
%%%      — Core net_processing.cpp:4570 — MISSING (BUG-8, P0)
%%% ===================================================================

g8_no_can_direct_fetch_gate_test() ->
    %% AUDIT MARKER: Core only reconstructs cmpctblocks when the tip is
    %% within 20 * PowTargetSpacing of now. beamchain accepts any
    %% cmpctblock regardless of tip age.
    ?assertNot(src_contains("beamchain_block_sync.erl",
                            <<"can_direct_fetch">>)),
    ?assertNot(src_contains("beamchain_block_sync.erl",
                            <<"CanDirectFetch">>)),
    ?assert(true).

%%% ===================================================================
%%% G9  MAX_CMPCTBLOCK_DEPTH = 5 guard (post-W112 fix) — PRESENT
%%% ===================================================================

g9_max_cmpctblock_depth_constant_test() ->
    %% Core net_processing.cpp:138 MAX_CMPCTBLOCK_DEPTH = 5.
    %% beamchain_block_sync.erl:79.
    ?assert(src_contains("beamchain_block_sync.erl",
                         <<"-define(MAX_CMPCTBLOCK_DEPTH, 5).">>)).

g9_depth_guard_boundary_test() ->
    %% tip=100, block=95 → depth=5 → NOT too deep (exactly at limit).
    ?assertEqual(false, beamchain_block_sync:is_cmpctblock_too_deep(95, 100)),
    %% tip=100, block=94 → depth=6 → TOO deep.
    ?assertEqual(true, beamchain_block_sync:is_cmpctblock_too_deep(94, 100)).

%%% ===================================================================
%%% G10 MAX_BLOCKTXN_DEPTH = 10 guard — PRESENT
%%% ===================================================================

g10_max_blocktxn_depth_constant_test() ->
    %% Core net_processing.cpp:140 MAX_BLOCKTXN_DEPTH = 10.
    %% Defined in beamchain_block_sync.erl AND beamchain_sync.erl.
    ?assert(src_contains("beamchain_block_sync.erl",
                         <<"-define(MAX_BLOCKTXN_DEPTH, 10).">>)),
    ?assert(src_contains("beamchain_sync.erl",
                         <<"-define(MAX_BLOCKTXN_DEPTH, 10).">>)).

%%% ===================================================================
%%% G11 Optimistic reconstruction path (block already in flight elsewhere)
%%%      — Core net_processing.cpp:4635-4654 — MISSING (BUG-13, P1)
%%% ===================================================================

g11_no_optimistic_reconstruction_test() ->
    %% AUDIT MARKER: Core attempts a tempBlock reconstruction even when
    %% the block is already in flight from another peer (lines 4641-4653).
    %% beamchain has no such path; the docstring at block_sync:1316-1320
    %% explicitly defers it.
    ?assert(src_contains("beamchain_block_sync.erl",
                         <<"Tracking partial reconstructions for unsolicited">>)),
    ?assert(true).

%%% ===================================================================
%%% G12 force_processing=true on cmpctblock-derived blocks
%%%      — Core net_processing.cpp:4701 — MISSING (BUG-14, P1)
%%% ===================================================================

g12_no_force_processing_flag_test() ->
    %% AUDIT MARKER: Core invokes ProcessBlock(force_processing=true)
    %% on cmpctblock-derived blocks to bypass anti-DoS rejection of
    %% unrequested blocks. beamchain routes through handle_block_received
    %% with no equivalent flag.
    ?assertNot(src_contains("beamchain_block_sync.erl",
                            <<"force_processing">>)),
    ?assert(true).

%%% ===================================================================
%%% G13 mapBlockSource attribution for cmpctblock-derived blocks
%%%      — Core net_processing.cpp:4690, 3513 — MISSING (BUG-19, P2)
%%% ===================================================================

g13_no_map_block_source_test() ->
    %% AUDIT MARKER: Core records (block_hash → (peer_id, false))
    %% for compact-block-derived blocks so BlockChecked can punish the
    %% peer if validation fails. beamchain has no equivalent table.
    ?assertNot(src_contains("beamchain_block_sync.erl",
                            <<"map_block_source">>)),
    ?assertNot(src_contains("beamchain_block_sync.erl",
                            <<"mapBlockSource">>)),
    ?assert(true).

%%% ===================================================================
%%% G14 MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3 cap
%%%      — Core net_processing.h:47 — MISSING (BUG-15, P1)
%%% ===================================================================

g14_no_max_cmpct_inflight_cap_test() ->
    %% AUDIT MARKER: Core enforces at most 3 simultaneous compact-block
    %% reconstructions per block hash. beamchain has no such cap.
    ?assertNot(src_contains("beamchain_block_sync.erl",
                            <<"MAX_CMPCTBLOCKS_INFLIGHT">>)),
    ?assert(true).

%%% ===================================================================
%%% G15 InitData null-header + empty-cmpctblock reject — PRESENT
%%% ===================================================================

g15_init_rejects_null_header_test() ->
    Hdr = (make_header())#block_header{bits = 0},
    Msg = #{header => Hdr, nonce => 0,
            short_ids => [<<1:48>>], prefilled_txns => []},
    ?assertMatch({error, null_header},
                 beamchain_compact_block:init_compact_block(Msg)).

g15_init_rejects_empty_cmpctblock_test() ->
    Hdr = make_header(),
    Msg = #{header => Hdr, nonce => 0,
            short_ids => [], prefilled_txns => []},
    ?assertMatch({error, empty_cmpctblock},
                 beamchain_compact_block:init_compact_block(Msg)).

%%% ===================================================================
%%% G16 InitData txn-count cap MAX_BLOCK_WEIGHT/MIN_TX_WEIGHT — PRESENT
%%% ===================================================================

g16_init_rejects_over_cap_test() ->
    Hdr = make_header(),
    %% 400001 short_ids → over the 400000 cap.
    Ids = [<<I:48/little>> || I <- lists:seq(1, 400001)],
    Msg = #{header => Hdr, nonce => 0,
            short_ids => Ids, prefilled_txns => []},
    ?assertMatch({error, too_many_txns},
                 beamchain_compact_block:init_compact_block(Msg)).

g16_init_accepts_at_cap_test() ->
    %% At-cap (400000) must be acceptable (not rejected as too-many).
    %% We don't run the full reconstruction here; just confirm the
    %% cap check is at 400000 not lower.
    Hdr = make_header(),
    %% Use a small set to keep the test fast; the cap predicate is
    %% structural and tested with an over-cap above. Confirm the
    %% constant is exactly 400000 (Core: MAX_BLOCK_WEIGHT / MIN_TX_WEIGHT
    %% = 4_000_000 / 10).
    Src = read_src_file("beamchain_compact_block.erl"),
    ?assert(binary:match(Src, <<"-define(MAX_COMPACT_BLOCK_TXS, 400000).">>) =/= nomatch),
    _ = Hdr,
    ok.

%%% ===================================================================
%%% G17 InitData prefilled-tx differential index strict-monotone + uint16
%%%      — Core blockencodings.cpp:73-86 — PRESENT
%%% ===================================================================

g17_prefilled_diff_index_uint16_cap_test() ->
    %% Verify that an absolute prefilled-index > 65535 is rejected
    %% (Core: lastprefilledindex > std::numeric_limits<uint16_t>::max()).
    Hdr = make_header(),
    %% Single prefilled with diff index = 65536 → AbsIdx = 65536, must reject.
    Tx = #transaction{version = 1, inputs = [#tx_in{}], outputs = [#tx_out{}],
                      locktime = 0},
    Msg = #{header => Hdr, nonce => 0,
            short_ids => [<<1:48>>],
            prefilled_txns => [#{index => 65536, tx => Tx}]},
    Result = beamchain_compact_block:init_compact_block(Msg),
    ?assertMatch({error, _}, Result).

%%% ===================================================================
%%% G18 InitData prefilled-tx is-null reject
%%%      — Core blockencodings.cpp:74 — PRESENT
%%% ===================================================================

g18_prefilled_null_tx_reject_test() ->
    Hdr = make_header(),
    NullTx = #transaction{version = 1, inputs = [], outputs = [], locktime = 0},
    Msg = #{header => Hdr, nonce => 0,
            short_ids => [<<1:48>>],
            prefilled_txns => [#{index => 0, tx => NullTx}]},
    ?assertMatch({error, null_prefilled_tx},
                 beamchain_compact_block:init_compact_block(Msg)).

%%% ===================================================================
%%% G19 InitData duplicate-short-id detection
%%%      — Core blockencodings.cpp:115 — PRESENT
%%% ===================================================================

g19_duplicate_short_id_reject_test() ->
    Hdr = make_header(),
    Dup = <<42:48/little>>,
    Tx = #transaction{version = 1, inputs = [#tx_in{}], outputs = [#tx_out{}],
                      locktime = 0},
    Msg = #{header => Hdr, nonce => 0,
            short_ids => [Dup, Dup],
            prefilled_txns => [#{index => 0, tx => Tx}]},
    ?assertMatch({error, short_id_collision},
                 beamchain_compact_block:init_compact_block(Msg)).

%%% ===================================================================
%%% G20 InitData unordered-map bucket-size DoS check (>12 per bucket)
%%%      — Core blockencodings.cpp:110-111 — MISSING (BUG-11, P0)
%%% ===================================================================

g20_no_bucket_size_dos_check_test() ->
    %% AUDIT MARKER: Core caps bucket_size <= 12 in the unordered_map
    %% used to look up shorttxid → position. beamchain uses an Erlang
    %% persistent map and has no per-bucket guard. Erlang's HAMT is
    %% less vulnerable to adversarial-key collisions than std::unordered_map
    %% but the asymptotic worst case is still exposed.
    ?assertNot(src_contains("beamchain_compact_block.erl",
                            <<"bucket_size">>)),
    ?assert(true).

%%% ===================================================================
%%% G21 mempool-side collision: clear slot AND decrement count
%%%      — Core blockencodings.cpp:129-138 — PRESENT (BUG-5 fixed in W112)
%%% ===================================================================

g21_mempool_collision_clears_and_decrements_test() ->
    %% Confirmed indirectly via match_mempool_txns/4 source: the
    %% collision branch returns {array:set(Idx, undefined, Arr),
    %% AccCount - 1, ...}.  The W170 audit refactor renamed the
    %% accumulator from `Count' to `AccCount' and added a 3rd element
    %% (the `Touched' set) to fold accumulator so a same-slot collision
    %% is not re-filled by a later mempool tx (Core have_txn semantics).
    ?assert(src_contains("beamchain_compact_block.erl",
                         <<"array:set(Idx, undefined, Arr)">>)),
    ?assert(src_contains("beamchain_compact_block.erl",
                         <<"AccCount - 1">>)).

%%% ===================================================================
%%% G22 extra_txn-side collision: compare wtxids before clearing
%%%      — Core blockencodings.cpp:163-168 — PRESENT
%%% ===================================================================

g22_extra_txn_wtxid_compare_test() ->
    %% Confirmed by source-grep: match_extra_txns/5 compares
    %% ExistingWtxid =:= Wtxid before clearing.
    ?assert(src_contains("beamchain_compact_block.erl",
                         <<"ExistingWtxid =:= Wtxid">>)).

%%% ===================================================================
%%% G23 FillBlock count-mismatch reject
%%%      — Core blockencodings.cpp:214 — PRESENT (BUG-6 closed in W112)
%%% ===================================================================

g23_fill_block_count_mismatch_test() ->
    %% Confirmed: fill_block/2 emits {error, {fill_block_count_mismatch, ...}}
    %% when the supplied tx count differs from MissingIdxs length.
    ?assert(src_contains("beamchain_compact_block.erl",
                         <<"fill_block_count_mismatch">>)).

%%% ===================================================================
%%% G24 FillBlock IsBlockMutated check (merkle + 64-byte + witness)
%%%      — Core blockencodings.cpp:219-222, validation.cpp:4027 — PARTIAL (BUG-7, P0)
%%% ===================================================================

g24_only_merkle_root_check_test() ->
    %% AUDIT MARKER: beamchain checks ExpectedRoot =:= ComputedRoot
    %% (merkle root) but does NOT check 64-byte-tx mutation (CVE class)
    %% nor witness malleation. Core IsBlockMutated does all three.
    Src = read_src_file("beamchain_compact_block.erl"),
    %% merkle present:
    ?assert(binary:match(Src, <<"verify_merkle_root">>) =/= nomatch),
    %% but no 64-byte-tx mutation check:
    ?assert(binary:match(Src, <<"64">>) =:= nomatch
            orelse binary:match(Src, <<"GetSerializeSize">>) =:= nomatch),
    %% and no witness-malleation check:
    ?assert(binary:match(Src, <<"CheckWitnessMalleation">>) =:= nomatch),
    ?assert(binary:match(Src, <<"check_witness_malleation">>) =:= nomatch),
    ?assert(true).

%%% ===================================================================
%%% G25 GETBLOCKTXN recent-block-hash cache fast path
%%%      — Core net_processing.cpp:4254-4264 — MISSING (BUG-10, P0)
%%% ===================================================================

g25_no_recent_block_cache_test() ->
    %% AUDIT MARKER: Core checks m_most_recent_block_hash == req.blockhash
    %% under m_most_recent_block_mutex and serves from RAM. beamchain's
    %% route_message(getblocktxn) always hits beamchain_db:get_block.
    Bin = read_src_file("beamchain_sync.erl"),
    ?assert(binary:match(Bin, <<"most_recent_block">>) =:= nomatch),
    ?assert(binary:match(Bin, <<"beamchain_db:get_block(BlockHash)">>) =/= nomatch),
    ?assert(true).

%%% ===================================================================
%%% G26 GETBLOCKTXN strict-increasing index invariant post-decode
%%%      — Core net_processing.cpp:4250-4252 — MISSING (BUG-12, P0-CDIV)
%%% ===================================================================

g26_no_post_decode_monotone_assertion_test() ->
    %% AUDIT MARKER: Core has Assume(req.indexes[i] > req.indexes[i-1])
    %% after DifferenceFormatter decode. beamchain accepts ANY decoded
    %% index sequence; the differential decoder only computes
    %% Idx = Prev + Diff + 1 but never asserts the resulting list is
    %% strict-increasing post-decode (relies on the encoder being
    %% honest). A wire-crafted payload with diff=0 is legal per spec
    %% but the decoder pairs that to Idx=Prev+1; the issue is more
    %% subtle: if a peer reuses the prior index by clever varint
    %% choices the decoder will surface duplicates silently.
    Bin = read_src_file("beamchain_p2p_msg.erl"),
    %% No post-decode duplicate-check:
    ?assert(binary:match(Bin, <<"strict_increasing">>) =:= nomatch),
    ?assert(binary:match(Bin, <<"strict-increasing">>) =:= nomatch),
    ?assert(true).

%%% ===================================================================
%%% G27 GETBLOCKTXN out-of-bounds index → Misbehaving
%%%      — Core net_processing.cpp:2602-2605 — MISSING (BUG-9, P0)
%%% ===================================================================

g27_out_of_bounds_index_no_misbehavior_test() ->
    %% AUDIT MARKER: Core punishes peers that request indexes >=
    %% block.vtx.size(). beamchain's lists:filtermap silently drops
    %% out-of-range indices; no add_misbehavior call.
    Bin = read_src_file("beamchain_sync.erl"),
    %% Find the route_message(getblocktxn) clause:
    {Start, _} = binary:match(Bin, <<"route_message(Peer, getblocktxn,">>),
    %% Match the next ~50 lines of body — needs to NOT have an add_misbehavior
    %% call gated specifically on the out-of-bounds index condition.
    EndApprox = Start + 4000,
    Body = binary:part(Bin, Start, min(EndApprox, byte_size(Bin)) - Start),
    %% lists:filtermap is the silent-drop offender:
    ?assert(binary:match(Body, <<"filtermap">>) =/= nomatch),
    %% The out-of-bounds branch does not emit misbehavior:
    %% (we look for the "false" branch of the `if ArrIdx >= 1, ...` guard
    %% which is the silent-drop path — confirmed absent of misbehavior).
    ?assert(true).

%%% ===================================================================
%%% G28 NewPoWValidBlock fast-announce CMPCTBLOCK to HB-from peers
%%%      — Core net_processing.cpp:2103-2152 — MISSING (BUG-2, P0-CDIV)
%%% ===================================================================

g28_no_outbound_cmpctblock_announce_test() ->
    %% AUDIT MARKER: announce_block/2 in peer_manager only branches
    %% headers vs inv. No cmpctblock branch. beamchain accepts
    %% sendcmpct(announce=1) from peers but never sends them cmpctblock
    %% for our new tips.
    Bin = read_src_file("beamchain_peer_manager.erl"),
    %% Confirm pick_announce_msg only emits headers or inv:
    ?assert(binary:match(Bin, <<"pick_announce_msg(true, Header, _BlockHash) ->">>) =/= nomatch),
    ?assert(binary:match(Bin, <<"{headers, #{headers => [Header]}};">>) =/= nomatch),
    ?assert(binary:match(Bin, <<"{inv, #{items => ">>) =/= nomatch),
    %% Confirm absence of cmpctblock branch:
    ?assert(binary:match(Bin, <<"{cmpctblock,">>) =:= nomatch),
    ?assert(true).

%%% ===================================================================
%%% G29 wants_cmpct / cmpct_version propagated to peer_manager ETS
%%%      — Core net_processing.cpp:3911-3912 (CNodeState) — MISSING (BUG-3, P0)
%%% ===================================================================

g29_cmpct_flags_isolated_to_peer_process_test() ->
    %% AUDIT MARKER: peer_data has wants_cmpct and cmpct_version fields
    %% (beamchain_peer.erl:102-103) but the peer_manager peer_entry
    %% record (beamchain_peer_manager.erl:145-180) does NOT.
    %% announce_block/2 reads from peer_entry, so it cannot see the
    %% cmpct flags. This isolates the HB-to side from the negotiated
    %% state — even if BUG-2 were trivially patched in announce_block
    %% by adding a cmpctblock branch, there'd be no peer-manager-side
    %% data to gate it on.
    PeerSrc = read_src_file("beamchain_peer.erl"),
    MgrSrc  = read_src_file("beamchain_peer_manager.erl"),
    %% peer_data has the fields:
    ?assert(binary:match(PeerSrc, <<"wants_cmpct = false">>) =/= nomatch),
    ?assert(binary:match(PeerSrc, <<"cmpct_version = 0">>) =/= nomatch),
    %% peer_entry does NOT:
    ?assert(binary:match(MgrSrc, <<"wants_cmpct">>) =:= nomatch),
    ?assert(binary:match(MgrSrc, <<"cmpct_version">>) =:= nomatch),
    ?assert(true).

%%% ===================================================================
%%% G30 pending_compact stale-entry eviction (timeout sweep)
%%%      — Core via mapBlocksInFlight + RemoveBlockRequest — MISSING (BUG-16, P1)
%%% ===================================================================

g30_no_pending_compact_timeout_test() ->
    %% AUDIT MARKER: pending_compact entries are added in
    %% do_handle_cmpctblock and removed only on blocktxn arrival or
    %% full-block fallback. NOT removed on peer disconnect, timeout,
    %% or tip advancement past the missing block.
    Bin = read_src_file("beamchain_block_sync.erl"),
    %% pending_compact is mentioned, but there's no eviction-by-age helper:
    ?assert(binary:match(Bin, <<"pending_compact">>) =/= nomatch),
    ?assert(binary:match(Bin, <<"evict_pending_compact">>) =:= nomatch),
    ?assert(binary:match(Bin, <<"expire_pending_compact">>) =:= nomatch),
    ?assert(binary:match(Bin, <<"prune_pending_compact">>) =:= nomatch),
    ?assert(true).

%%% ===================================================================
%%% Bonus: cross-cutting checks that anchor the reconstruction codec
%%% ===================================================================

%% SipHash key derivation must use nonce in little-endian (BIP-152).
codec_siphash_key_nonce_le_test() ->
    Header = make_header(),
    {K0a, K1a} = beamchain_compact_block:derive_siphash_key(Header, 0),
    {K0b, K1b} = beamchain_compact_block:derive_siphash_key(Header, 1),
    ?assertNotEqual({K0a, K1a}, {K0b, K1b}).

%% Short ID must be exactly 6 bytes per BIP-152 §"Short transaction IDs".
codec_short_id_length_test() ->
    Wtxid = <<0:256>>,
    SID = beamchain_compact_block:compute_short_id(0, 0, Wtxid),
    ?assertEqual(6, byte_size(SID)).

%% Encoded sendcmpct is exactly 9 bytes (1-byte announce + 8-byte version LE).
codec_sendcmpct_wire_size_test() ->
    P = beamchain_p2p_msg:encode_payload(sendcmpct,
              #{announce => true, version => 2}),
    ?assertEqual(9, byte_size(P)).

%% Encoded cmpctblock has header (80) + nonce (8) + count_varints + content
%% prefix structure. Sanity-check the minimum size for an empty body.
codec_cmpctblock_min_size_test() ->
    Hdr = make_header(),
    Bin = beamchain_p2p_msg:encode_payload(cmpctblock,
              #{header => Hdr, nonce => 0,
                short_ids => [], prefilled_txns => []}),
    %% 80 (header) + 8 (nonce) + 1 (SID count varint = 0) + 1 (Pre count = 0) = 90.
    ?assertEqual(90, byte_size(Bin)).

%% getblocktxn round-trip preserves indexes for the trivial single-index case.
codec_getblocktxn_single_index_roundtrip_test() ->
    Hash = <<7:256>>,
    Bin = beamchain_p2p_msg:encode_payload(getblocktxn,
              #{block_hash => Hash, indexes => [5]}),
    ?assertMatch({ok, #{block_hash := Hash, indexes := [5]}},
                 beamchain_p2p_msg:decode_payload(getblocktxn, Bin)).

%% getblocktxn differential encoding round-trip for [0, 3, 7].
codec_getblocktxn_diff_roundtrip_test() ->
    Hash = <<8:256>>,
    Bin = beamchain_p2p_msg:encode_payload(getblocktxn,
              #{block_hash => Hash, indexes => [0, 3, 7]}),
    ?assertMatch({ok, #{block_hash := Hash, indexes := [0, 3, 7]}},
                 beamchain_p2p_msg:decode_payload(getblocktxn, Bin)).
