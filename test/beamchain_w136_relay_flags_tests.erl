-module(beamchain_w136_relay_flags_tests).

%% W136 BIP-130 sendheaders + BIP-133 feefilter + BIP-339 wtxidrelay audit
%% (beamchain).
%%
%% Reference: bitcoin-core/src/net_processing.cpp (MaybeSendSendHeaders,
%%            MaybeSendFeefilter, ProcessMessage
%%            SENDHEADERS/WTXIDRELAY/FEEFILTER branches),
%%            bitcoin-core/src/net.h + net.cpp (CNode::GetCommonVersion,
%%            IsBlockOnlyConn, HasPermission),
%%            bitcoin-core/src/policy/fees/block_policy_estimator.{h,cpp}
%%            (FeeFilterRounder),
%%            bitcoin-core/src/node/protocol_version.h
%%            (SENDHEADERS_VERSION=70012, FEEFILTER_VERSION=70013,
%%            WTXID_RELAY_VERSION=70016).
%%
%% Scope (audit/w136_relay_flags.md): 30 gates, 22 BUGs
%% (0 CDIV / 4 HIGH / 11 MEDIUM / 7 LOW).
%%
%% Audit-flip: every test below asserts the current (divergent) behavior
%% so it PASSES today; a follow-up FIX wave that brings the implementation
%% into parity will flip these PASS -> FAIL.

-include_lib("eunit/include/eunit.hrl").

%%% ===================================================================
%%% Source-path helpers (mirrors W133 / FIX-66 / W129 convention)
%%% ===================================================================

beamchain_src_dir() ->
    Beam = code:which(beamchain_peer),
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

beamchain_peer_src()         -> filename:join(beamchain_src_dir(), "beamchain_peer.erl").
beamchain_peer_manager_src() -> filename:join(beamchain_src_dir(), "beamchain_peer_manager.erl").

read_src(Path) ->
    case file:read_file(Path) of
        {ok, Bin} -> Bin;
        {error, _} -> <<>>
    end.

%%% ===================================================================
%%% G1 — BUG-1: sendheaders lacks MinimumChainWork gate
%%% ===================================================================

g1_sendheaders_no_chain_work_gate_test_() ->
    {"G1: BUG-1 (HIGH) — beamchain sends sendheaders on ready-enter "
     "without checking that pindexBestKnownBlock->nChainWork > "
     "MinimumChainWork. Core's MaybeSendSendHeaders gates the emit "
     "(net_processing.cpp:5519-5538).",
     [
      ?_test(begin
         Src = read_src(beamchain_peer_src()),
         %% send_feature_msgs/1 must exist and unconditionally do_send_raw(sendheaders, ...)
         ?assertNotEqual(nomatch, binary:match(Src, <<"send_feature_msgs(Data) ->">>)),
         ?assertNotEqual(nomatch, binary:match(Src, <<"do_send_raw(sendheaders, <<>>, Data)">>)),
         %% No MinimumChainWork / min_chain_work reference in the peer module.
         ?assertEqual(nomatch, binary:match(Src, <<"MinimumChainWork">>)),
         ?assertEqual(nomatch, binary:match(Src, <<"min_chain_work">>))
       end)
     ]}.

%%% ===================================================================
%%% G2 — BUG-4: no m_sent_sendheaders latch / post-IBD re-emit
%%% ===================================================================

g2_no_sent_sendheaders_latch_test_() ->
    {"G2: BUG-4 (HIGH) — beamchain has no per-peer m_sent_sendheaders "
     "latch and no periodic re-check that would re-emit sendheaders "
     "after chain-work crosses MinimumChainWork (Core net_processing.cpp:"
     "406, 5519-5538).",
     [
      ?_test(begin
         Src = read_src(beamchain_peer_src()),
         %% No latch field on the peer_data record
         ?assertEqual(nomatch, binary:match(Src, <<"sent_sendheaders">>)),
         ?assertEqual(nomatch, binary:match(Src, <<"m_sent_sendheaders">>)),
         %% No second emit site
         Matches = binary:matches(Src, <<"do_send_raw(sendheaders">>),
         ?assert(length(Matches) =< 1)
       end)
     ]}.

%%% ===================================================================
%%% G3 — BUG-5: sendheaders not version-gated
%%% ===================================================================

g3_sendheaders_no_version_gate_test_() ->
    {"G3: BUG-5 (MEDIUM) — beamchain doesn't compare peer's common "
     "version against SENDHEADERS_VERSION=70012 before sending "
     "sendheaders (Core net_processing.cpp:5525).",
     [
      ?_test(begin
         Src = read_src(beamchain_peer_src()),
         %% No SENDHEADERS_VERSION macro / literal
         ?assertEqual(nomatch, binary:match(Src, <<"SENDHEADERS_VERSION">>)),
         ?assertEqual(nomatch, binary:match(Src, <<"70012">>))
       end)
     ]}.

%%% ===================================================================
%%% G4 — Gate 4: sendheaders sent to non-NODE NETWORK peers (PARTIAL)
%%% ===================================================================

g4_sendheaders_to_all_peers_test_() ->
    {"G4: Gate-4 PARTIAL — beamchain sends sendheaders to all peers "
     "regardless of NODE_NETWORK; Core does too but with a deliberate "
     "comment about pruned-but-announcing nodes (net_processing.cpp:"
     "5530-5533). Audit-flip target: the send-feature-msgs callsite "
     "should either grow a NODE_NETWORK-aware branch or carry the "
     "explanatory comment.",
     [
      ?_test(begin
         Src = read_src(beamchain_peer_src()),
         %% Slice the send_feature_msgs/1 function body and confirm it
         %% has no NODE_NETWORK gate. (Service-flag emission in
         %% do_send_version sets NODE_NETWORK on OUR services bitfield;
         %% that's unrelated to the sendheaders emit gate.)
         {SfStart, _} = binary:match(Src, <<"send_feature_msgs(Data) ->">>),
         %% Take the next ~600 bytes (covers the whole function body)
         SfBody = binary:part(Src, SfStart, min(700, byte_size(Src) - SfStart)),
         ?assertEqual(nomatch, binary:match(SfBody, <<"NODE_NETWORK">>)),
         ?assertEqual(nomatch, binary:match(SfBody, <<"peer_services band">>))
       end)
     ]}.

%%% ===================================================================
%%% G5 — Gate 5 PRESENT: announce_block branches on wants_headers
%%% ===================================================================

g5_announce_block_branches_on_wants_headers_test_() ->
    {"G5: Gate-5 PRESENT — peer_manager announce_block/2 uses the "
     "wants_headers flag to pick headers vs inv (BIP-130 fork in "
     "beamchain_peer_manager.erl:325-342).",
     [
      ?_test(begin
         Src = read_src(beamchain_peer_manager_src()),
         ?assertNotEqual(nomatch, binary:match(Src, <<"announce_block(Header, BlockHash) ->">>)),
         ?assertNotEqual(nomatch, binary:match(Src, <<"pick_announce_msg">>)),
         ?assertNotEqual(nomatch, binary:match(Src, <<"wants_headers = WantsHeaders">>))
       end)
     ]}.

%%% ===================================================================
%%% G6 — BUG-6: feefilter periodic broadcast interval implementation
%%% ===================================================================

g6_feefilter_periodic_interval_test_() ->
    {"G6: BUG-6 (MEDIUM) — beamchain's feefilter Poisson interval "
     "samples exponentially (correct) but clamps to [1000, 1800000] ms "
     "instead of Core's untruncated chrono::microseconds tail "
     "(net_processing.cpp:5572).",
     [
      ?_test(begin
         Src = read_src(beamchain_peer_src()),
         ?assertNotEqual(nomatch, binary:match(Src, <<"feefilter_poisson_interval">>)),
         %% The 600000 ms (10 min) average is hardcoded as a macro.
         ?assertNotEqual(nomatch, binary:match(Src, <<"FEEFILTER_BROADCAST_INTERVAL_MS, 600000">>)),
         %% Clamp at 30 min, which Core does NOT do.
         ?assertNotEqual(nomatch, binary:match(Src, <<"max(1000, min(Interval, 1800000))">>))
       end)
     ]}.

%%% ===================================================================
%%% G7 — BUG-7: feefilter significant-change threshold structure
%%% ===================================================================

g7_feefilter_significant_change_test_() ->
    {"G7: BUG-7 (MEDIUM) — beamchain's algebraically-rearranged "
     "significant-change test (CurrentFee * 4 < SentFee * 3 orelse "
     "CurrentFee * 3 > SentFee * 4) is equivalent to Core's "
     "(currentFilter < 3 * sent / 4 || currentFilter > 4 * sent / 3) "
     "but is a parallel reimplementation; a forward-regression guard "
     "should pin the exact form (beamchain_peer.erl:1588-1589).",
     [
      ?_test(begin
         Src = read_src(beamchain_peer_src()),
         ?assertNotEqual(nomatch, binary:match(Src,
             <<"CurrentFee * 4 < SentFee * 3">>)),
         ?assertNotEqual(nomatch, binary:match(Src,
             <<"CurrentFee * 3 > SentFee * 4">>))
       end)
     ]}.

%%% ===================================================================
%%% G8 — BUG-2: no FeeFilterRounder privacy quantization
%%% ===================================================================

g8_no_feefilter_rounder_test_() ->
    {"G8: BUG-2 (HIGH) — beamchain has no FeeFilterRounder-style "
     "log-bucket quantization. do_send_feefilter clamps to "
     "DEFAULT_MIN_RELAY_FEE and broadcasts the raw value, leaking "
     "exact mempool min-fee. Core uses lower_bound + 1/3 blur via "
     "FeeFilterRounder (block_policy_estimator.{h,cpp}:323/1109).",
     [
      ?_test(begin
         Src = read_src(beamchain_peer_src()),
         %% No FeeFilterRounder analog
         ?assertEqual(nomatch, binary:match(Src, <<"FeeFilterRounder">>)),
         ?assertEqual(nomatch, binary:match(Src, <<"fee_filter_rounder">>)),
         ?assertEqual(nomatch, binary:match(Src, <<"MAX_FILTER_FEERATE">>)),
         ?assertEqual(nomatch, binary:match(Src, <<"FEE_FILTER_SPACING">>)),
         %% No standalone module either
         ?assertEqual(non_existing, code:which(beamchain_fee_filter_rounder)),
         %% do_send_feefilter just clamps; sanity-check the literal form
         ?assertNotEqual(nomatch, binary:match(Src,
             <<"FilterToSend = max(FeeRate, ?DEFAULT_MIN_RELAY_FEE)">>))
       end)
     ]}.

%%% ===================================================================
%%% G9 — BUG-8: feefilter not skipped for block-relay-only outbound
%%% ===================================================================

g9_feefilter_not_skipped_block_relay_only_test_() ->
    {"G9: BUG-8 (MEDIUM) — feefilter path has no IsBlockOnlyConn() "
     "check; block-relay-only outbound peers receive feefilters "
     "unnecessarily. Core: net_processing.cpp:5548 returns early.",
     [
      ?_test(begin
         Src = read_src(beamchain_peer_src()),
         %% No IsBlockOnlyConn / block_only / block_relay_only check in
         %% feefilter path.
         ?assertEqual(nomatch, binary:match(Src, <<"IsBlockOnlyConn">>)),
         ?assertEqual(nomatch, binary:match(Src, <<"block_relay_only">>)),
         %% maybe_send_initial_feefilter gates only on V >= ?FEEFILTER_VERSION + peer_relay
         ?assertNotEqual(nomatch, binary:match(Src,
             <<"maybe_send_initial_feefilter(#peer_data{peer_version = V, peer_relay = Relay} = Data)">>))
       end)
     ]}.

%%% ===================================================================
%%% G10 — BUG-9: no ForceRelay permission exemption
%%% ===================================================================

g10_no_forcerelay_permission_test_() ->
    {"G10: BUG-9 (MEDIUM) — no NetPermissionFlags::ForceRelay analog. "
     "Core skips feefilter for ForceRelay peers (net_processing.cpp:"
     "5545). beamchain has no permission system.",
     [
      ?_test(begin
         Src = read_src(beamchain_peer_src()),
         ?assertEqual(nomatch, binary:match(Src, <<"ForceRelay">>)),
         ?assertEqual(nomatch, binary:match(Src, <<"forcerelay">>)),
         %% Also missing from peer_manager
         MgrSrc = read_src(beamchain_peer_manager_src()),
         ?assertEqual(nomatch, binary:match(MgrSrc, <<"ForceRelay">>))
       end)
     ]}.

%%% ===================================================================
%%% G11 — BUG-10: no MAX_MONEY-during-IBD signal
%%% ===================================================================

g11_no_max_money_during_ibd_test_() ->
    {"G11: BUG-10 (MEDIUM) — beamchain doesn't override feefilter to "
     "MAX_MONEY while IBD. Core net_processing.cpp:5552-5555 forces "
     "MAX_MONEY so peers stop sending tx invs.",
     [
      ?_test(begin
         Src = read_src(beamchain_peer_src()),
         %% No MAX_MONEY reference in feefilter path
         ?assertEqual(nomatch, binary:match(Src, <<"MAX_MONEY">>)),
         %% No IBD check in feefilter send
         ?assertEqual(nomatch, binary:match(Src, <<"is_in_ibd">>)),
         ?assertEqual(nomatch, binary:match(Src, <<"IsInitialBlockDownload">>))
       end)
     ]}.

%%% ===================================================================
%%% G12 — BUG-11: no post-IBD feefilter recovery branch
%%% ===================================================================

g12_no_post_ibd_recovery_test_() ->
    {"G12: BUG-11 (MEDIUM) — no 'reset next_send_feefilter to 0 if "
     "we previously sent MAX_FILTER' branch. Core "
     "net_processing.cpp:5557-5562. Linked to G11.",
     [
      ?_test(begin
         Src = read_src(beamchain_peer_src()),
         ?assertEqual(nomatch, binary:match(Src, <<"MAX_FILTER">>)),
         ?assertEqual(nomatch, binary:match(Src, <<"post_ibd_recovery">>))
       end)
     ]}.

%%% ===================================================================
%%% G13 — Gate 13 PARTIAL: min-relay floor on every send
%%% ===================================================================

g13_min_relay_floor_test_() ->
    {"G13: Gate-13 PARTIAL — beamchain applies a min-relay floor via "
     "?DEFAULT_MIN_RELAY_FEE (1000), but Core uses the runtime "
     "min_relay_feerate from mempool options. (net_processing.cpp:"
     "5567 `std::max(filterToSend, m_mempool.m_opts.min_relay_feerate"
     ".GetFeePerK())`).",
     [
      ?_test(begin
         Src = read_src(beamchain_peer_src()),
         ?assertNotEqual(nomatch, binary:match(Src,
             <<"DEFAULT_MIN_RELAY_FEE, 1000">>)),
         %% No mempool-option lookup in feefilter send path
         ?assertEqual(nomatch, binary:match(Src, <<"min_relay_feerate">>))
       end)
     ]}.

%%% ===================================================================
%%% G14 — BUG-14 sibling: feefilter not skipped in blocksonly mode
%%% ===================================================================

g14_no_blocksonly_skip_test_() ->
    {"G14: Gate-14 MISSING — no blocksonly / ignore_incoming_txs mode "
     "in beamchain, so the feefilter early-return "
     "(net_processing.cpp:5542) has no analog.",
     [
      ?_test(begin
         Src = read_src(beamchain_peer_src()),
         ?assertEqual(nomatch, binary:match(Src, <<"blocksonly">>)),
         ?assertEqual(nomatch, binary:match(Src, <<"ignore_incoming_txs">>)),
         MgrSrc = read_src(beamchain_peer_manager_src()),
         ?assertEqual(nomatch, binary:match(MgrSrc, <<"blocksonly">>))
       end)
     ]}.

%%% ===================================================================
%%% G15 — BUG-12: feefilter received not MoneyRange-checked
%%% ===================================================================

g15_feefilter_received_no_moneyrange_test_() ->
    {"G15: BUG-12 (MEDIUM) — handle_feefilter_msg accepts any uint64; "
     "Core gates on MoneyRange (net_processing.cpp:5038).",
     [
      ?_test(begin
         Src = read_src(beamchain_peer_src()),
         ?assertNotEqual(nomatch, binary:match(Src,
             <<"handle_feefilter_msg(Payload, Data) ->">>)),
         %% No MoneyRange / MAX_MONEY validation
         ?assertEqual(nomatch, binary:match(Src, <<"MoneyRange">>)),
         %% The accept site stores the value verbatim
         ?assertNotEqual(nomatch, binary:match(Src,
             <<"{ok, Data#peer_data{fee_filter = Fee}}">>))
       end)
     ]}.

%%% ===================================================================
%%% G16 — Gate 16 PRESENT: store received in fee_filter slot
%%% ===================================================================

g16_feefilter_received_stored_test_() ->
    {"G16: Gate-16 PRESENT — handle_feefilter_msg writes the decoded "
     "value into peer_data.fee_filter (matches Core's per-peer "
     "m_fee_filter_received).",
     [
      ?_test(begin
         Src = read_src(beamchain_peer_src()),
         %% fee_filter field exists with init = 0
         ?assertNotEqual(nomatch, binary:match(Src,
             <<"fee_filter = 0          :: non_neg_integer()">>))
       end)
     ]}.

%%% ===================================================================
%%% G17 — BUG-3: wtxidrelay after VERACK silently ignored (NOT disconnect)
%%% ===================================================================

g17_wtxidrelay_after_verack_silent_test_() ->
    {"G17: BUG-3 (HIGH) — wtxidrelay after VERACK is silently ignored, "
     "not a disconnect. Core: net_processing.cpp:3921-3927 sets "
     "fDisconnect=true. The companion sendtxrcncl path DOES disconnect "
     "(line 1431), so the behaviour is inconsistent inside beamchain.",
     [
      ?_test(begin
         Src = read_src(beamchain_peer_src()),
         %% The silent-ignore wtxidrelay arm.
         ?assertNotEqual(nomatch, binary:match(Src,
             <<"dispatch_message(wtxidrelay, _Payload, Data) ->">>)),
         %% Confirm the no-op arm via the {ok, Data} -> {ok, Data}
         %% on handshake_complete=true (the silent-ignore form).
         WtxidArm = <<"dispatch_message(wtxidrelay, _Payload, Data) ->\n"
                      "    %% BIP 339: only valid before handshake complete\n"
                      "    case handshake_complete(Data) of\n"
                      "        false -> {ok, Data#peer_data{wtxidrelay = true}};\n"
                      "        true  -> {ok, Data}\n"
                      "    end;">>,
         ?assertNotEqual(nomatch, binary:match(Src, WtxidArm)),
         %% Same shape for sendaddrv2
         AddrV2Arm = <<"dispatch_message(sendaddrv2, _Payload, Data) ->\n"
                       "    %% BIP 155: only valid before handshake complete\n"
                       "    case handshake_complete(Data) of\n"
                       "        false -> {ok, Data#peer_data{wants_addrv2 = true}};\n"
                       "        true  -> {ok, Data}\n"
                       "    end;">>,
         ?assertNotEqual(nomatch, binary:match(Src, AddrV2Arm)),
         %% But sendtxrcncl DOES stop with protocol_violation — confirms
         %% the inconsistency.
         ?assertNotEqual(nomatch, binary:match(Src,
             <<"%% Protocol violation: sendtxrcncl after verack">>)),
         ?assertNotEqual(nomatch, binary:match(Src,
             <<"{stop, protocol_violation}">>))
       end)
     ]}.

%%% ===================================================================
%%% G18 — BUG-3 corollary / Gate 18: wtxidrelay accept lacks version gate
%%% ===================================================================

g18_wtxidrelay_no_version_gate_test_() ->
    {"G18: Gate-18 / BUG-3 corollary — wtxidrelay receive arm accepts "
     "the message regardless of peer's version. Core: net_processing"
     ".cpp:3928 `if (pfrom.GetCommonVersion() >= WTXID_RELAY_VERSION)`.",
     [
      ?_test(begin
         Src = read_src(beamchain_peer_src()),
         %% The receive arm doesn't compare peer_version against 70016.
         %% Note: the *send* path (maybe_send_sendtxrcncl) does (line
         %% 1410), but the receive arm does not.
         WtxidArm = <<"dispatch_message(wtxidrelay, _Payload, Data) ->\n"
                      "    %% BIP 339: only valid before handshake complete\n"
                      "    case handshake_complete(Data) of\n"
                      "        false -> {ok, Data#peer_data{wtxidrelay = true}};\n"
                      "        true  -> {ok, Data}\n"
                      "    end;">>,
         ?assertNotEqual(nomatch, binary:match(Src, WtxidArm)),
         %% Confirm the WTXID_RELAY_VERSION literal appears only in the
         %% sendtxrcncl version-gate (line 1410), not in the wtxidrelay
         %% receive path.
         Matches = binary:matches(Src, <<"70016">>),
         %% Exactly one occurrence (sendtxrcncl version gate)
         ?assert(length(Matches) =< 2)  % allow PROTOCOL_VERSION + sendtxrcncl
       end)
     ]}.

%%% ===================================================================
%%% G19 — BUG-21: wtxidrelay duplicate-receive not logged
%%% ===================================================================

g19_wtxidrelay_dup_silent_test_() ->
    {"G19: BUG-21 (LOW) — duplicate wtxidrelay receive is silently "
     "idempotent (set true -> true). Core logs "
     "`ignoring duplicate wtxidrelay from peer=%d` "
     "(net_processing.cpp:3933).",
     [
      ?_test(begin
         Src = read_src(beamchain_peer_src()),
         ?assertEqual(nomatch, binary:match(Src, <<"duplicate wtxidrelay">>)),
         ?assertEqual(nomatch, binary:match(Src, <<"ignoring duplicate">>))
       end)
     ]}.

%%% ===================================================================
%%% G20 — BUG-13: no m_wtxid_relay_peers global counter
%%% ===================================================================

g20_no_wtxid_relay_peers_counter_test_() ->
    {"G20: BUG-13 (MEDIUM) — no global m_wtxid_relay_peers counter. "
     "Core: net_processing.cpp:837/1688/3931. peer_manager has no "
     "per-fleet wtxidrelay metric.",
     [
      ?_test(begin
         PeerSrc = read_src(beamchain_peer_src()),
         MgrSrc  = read_src(beamchain_peer_manager_src()),
         ?assertEqual(nomatch, binary:match(PeerSrc, <<"wtxid_relay_peers">>)),
         ?assertEqual(nomatch, binary:match(MgrSrc,  <<"wtxid_relay_peers">>)),
         ?assertEqual(nomatch, binary:match(PeerSrc, <<"m_wtxid_relay_peers">>)),
         ?assertEqual(nomatch, binary:match(MgrSrc,  <<"m_wtxid_relay_peers">>))
       end)
     ]}.

%%% ===================================================================
%%% G21 — Gate 21 PRESENT: wtxidrelay sent before verack
%%% ===================================================================

g21_wtxidrelay_send_before_verack_test_() ->
    {"G21: Gate-21 PRESENT — wtxidrelay is sent before verack in "
     "handle_version_msg (beamchain_peer.erl:1374). Mirrors Core "
     "net_processing.cpp:3710-3712.",
     [
      ?_test(begin
         Src = read_src(beamchain_peer_src()),
         ?assertNotEqual(nomatch, binary:match(Src,
             <<"%% Send wtxidrelay and sendaddrv2 before verack">>)),
         ?assertNotEqual(nomatch, binary:match(Src,
             <<"do_send_raw(wtxidrelay, <<>>, Data3)">>))
       end)
     ]}.

%%% ===================================================================
%%% G22 — Gate 22 PRESENT: wtxidrelay flag drives MSG_WTX in inv pipeline
%%% ===================================================================

g22_wtxidrelay_drives_msg_wtx_test_() ->
    {"G22: Gate-22 PRESENT — wtxidrelay flag selects MSG_WTX in "
     "send_tx_inv/2 and handle_mempool_msg. Matches Core "
     "net_processing.cpp:4059 / 2259.",
     [
      ?_test(begin
         PeerSrc = read_src(beamchain_peer_src()),
         MgrSrc  = read_src(beamchain_peer_manager_src()),
         ?assertNotEqual(nomatch, binary:match(PeerSrc,
             <<"send_tx_inv(Txids, #peer_data{wtxidrelay = UseWtxid} = Data) ->">>)),
         ?assertNotEqual(nomatch, binary:match(MgrSrc,
             <<"peer_uses_wtxid(Pid) ->">>)),
         %% peer_uses_wtxid consults info.wtxidrelay
         ?assertNotEqual(nomatch, binary:match(MgrSrc,
             <<"maps:get(wtxidrelay, Info, false) =:= true">>))
       end)
     ]}.

%%% ===================================================================
%%% G23 — BUG-15: feefilter inv-side filter uses rate compare, not
%%%               vsize * feerate (Core does both, but algebraically
%%%               equivalent — flag for forward-regression guard).
%%% ===================================================================

g23_feefilter_inv_rate_compare_test_() ->
    {"G23: BUG-15 (MEDIUM) — beamchain compares "
     "FeeRateKvB >= PeerFeeFilter directly; Core does "
     "txinfo.fee < filterrate.GetFee(vsize). Equivalent at the algebra "
     "level but rounds differently at the boundary "
     "(beamchain_peer.erl:1828-1836).",
     [
      ?_test(begin
         Src = read_src(beamchain_peer_src()),
         ?assertNotEqual(nomatch, binary:match(Src,
             <<"tx_passes_feefilter(Txid, PeerFeeFilter) ->">>)),
         ?assertNotEqual(nomatch, binary:match(Src,
             <<"FeeRateKvB >= PeerFeeFilter">>))
       end)
     ]}.

%%% ===================================================================
%%% G24 — BUG (Gate 24): feefilter inv filter NOT applied to BIP35
%%%       mempool response
%%% ===================================================================

g24_mempool_response_no_feefilter_test_() ->
    {"G24: Gate-24 MISSING — handle_mempool_msg/1 in peer_manager "
     "doesn't consult the peer's fee_filter before emitting the "
     "enumeration inv. Core does (net_processing.cpp:6013 path).",
     [
      ?_test(begin
         Src = read_src(beamchain_peer_manager_src()),
         %% handle_mempool_msg lookup
         ?assertNotEqual(nomatch, binary:match(Src,
             <<"handle_mempool_msg(Pid) ->">>)),
         %% No fee_filter / filter_by_feefilter in peer_manager
         ?assertEqual(nomatch, binary:match(Src, <<"fee_filter">>)),
         ?assertEqual(nomatch, binary:match(Src, <<"filter_by_feefilter">>))
       end)
     ]}.

%%% ===================================================================
%%% G25 — Gate 25 PARTIAL: feefilter periodic dispatch via self-timer
%%% ===================================================================

g25_feefilter_self_timer_test_() ->
    {"G25: Gate-25 PARTIAL — feefilter periodic broadcast is driven by "
     "per-peer self-scheduled timer (`check_feefilter` info msg, "
     "beamchain_peer.erl:619-623), not a SendMessages-style loop.",
     [
      ?_test(begin
         Src = read_src(beamchain_peer_src()),
         ?assertNotEqual(nomatch, binary:match(Src,
             <<"ready(info, check_feefilter, Data) ->">>)),
         ?assertNotEqual(nomatch, binary:match(Src,
             <<"schedule_feefilter_timer">>)),
         %% No MaybeSendFeefilter or equivalent global tick
         ?assertEqual(nomatch, binary:match(Src, <<"MaybeSendFeefilter">>)),
         ?assertEqual(nomatch, binary:match(Src, <<"maybe_send_feefilter_tick">>))
       end)
     ]}.

%%% ===================================================================
%%% G26 — Gate 26 PARTIAL: send-then-update ordering matches Core
%%% ===================================================================

g26_feefilter_send_then_update_ordering_test_() ->
    {"G26: Gate-26 PARTIAL — do_send_feefilter writes-then-updates "
     "sent_at, ordering-equivalent to Core's 5564-5572 path.",
     [
      ?_test(begin
         Src = read_src(beamchain_peer_src()),
         %% Visual ordering: do_send_raw(feefilter, ...) appears
         %% BEFORE feefilter_sent_at = Now in the function body.
         FnStart = case binary:match(Src, <<"do_send_feefilter(FeeRate, Data) ->">>) of
             {S, _} -> S;
             nomatch -> -1
         end,
         SendCall = case binary:match(Src, <<"do_send_raw(feefilter, Payload, Data)">>) of
             {SS, _} -> SS;
             nomatch -> -1
         end,
         SentAt = case binary:match(Src, <<"feefilter_sent_at = Now">>) of
             {SA, _} -> SA;
             nomatch -> -1
         end,
         ?assert(FnStart >= 0),
         ?assert(SendCall > FnStart),
         ?assert(SentAt > SendCall)
       end)
     ]}.

%%% ===================================================================
%%% G27 — Gate 27 PRESENT: peer_relay defaults true (BIP-37 fRelay default)
%%% ===================================================================

g27_peer_relay_defaults_true_test_() ->
    {"G27: Gate-27 PRESENT — peer_relay defaults to `true` in the "
     "#peer_data{} record (matches BIP-37 fRelay-absent default).",
     [
      ?_test(begin
         Src = read_src(beamchain_peer_src()),
         ?assertNotEqual(nomatch, binary:match(Src,
             <<"peer_relay = true       :: boolean()">>))
       end)
     ]}.

%%% ===================================================================
%%% G28 — BUG-14: fee_filter not surfaced via build_info/1
%%% ===================================================================

g28_build_info_no_fee_filter_test_() ->
    {"G28: BUG-14 (MEDIUM) — build_info/1 doesn't include fee_filter, "
     "so getpeerinfo can't report the peer's minfeefilter. Core "
     "surfaces this via CNodeStats::m_fee_filter_received → "
     "getpeerinfo.minfeefilter.",
     [
      ?_test(begin
         Src = read_src(beamchain_peer_src()),
         %% Locate build_info/1 body and verify fee_filter isn't in the map
         {BiStart, _} = binary:match(Src, <<"build_info(#peer_data{} = D) ->">>),
         BiTail = binary:part(Src, BiStart, byte_size(Src) - BiStart),
         %% Look only at the first ~30 lines after build_info/1.
         BiBody = case binary:match(BiTail, <<"peer_version_timestamp => D#peer_data.peer_version_timestamp}">>) of
             {End, EndLen} -> binary:part(BiTail, 0, End + EndLen);
             nomatch -> BiTail
         end,
         ?assertEqual(nomatch, binary:match(BiBody, <<"fee_filter">>)),
         ?assertEqual(nomatch, binary:match(BiBody, <<"minfeefilter">>))
       end)
     ]}.

%%% ===================================================================
%%% G29 — BUG-17: feefilter receive/send not logged
%%% ===================================================================

g29_feefilter_no_logs_test_() ->
    {"G29: BUG-17 (LOW) — handle_feefilter_msg neither logs the "
     "received value nor surfaces a metric. Core net_processing.cpp:"
     "5042 LogDebugs the received CFeeRate.",
     [
      ?_test(begin
         Src = read_src(beamchain_peer_src()),
         %% Find the handle_feefilter_msg function body.
         {FmStart, _} = binary:match(Src, <<"handle_feefilter_msg(Payload, Data) ->">>),
         FmTail = binary:part(Src, FmStart, min(800, byte_size(Src) - FmStart)),
         %% No logger:debug/info/warning inside the function
         ?assertEqual(nomatch, binary:match(FmTail, <<"logger:debug">>)),
         ?assertEqual(nomatch, binary:match(FmTail, <<"logger:info">>)),
         %% No metric increment either
         ?assertEqual(nomatch, binary:match(FmTail, <<"beamchain_metrics">>))
       end)
     ]}.

%%% ===================================================================
%%% G30 — BUG-9 corollary: no ForceRelay exemption on the outbound
%%%       tx-selection side (the inbound feefilter path that drops
%%%       my tx because of peer's filter).
%%% ===================================================================

g30_no_forcerelay_outbound_exempt_test_() ->
    {"G30: Gate-30 MISSING — filter_by_feefilter applies the peer's "
     "filter unconditionally; Core also skips for ForceRelay outbound "
     "(net_processing.cpp:5544-5545). No permission system, no skip.",
     [
      ?_test(begin
         Src = read_src(beamchain_peer_src()),
         ?assertNotEqual(nomatch, binary:match(Src,
             <<"filter_by_feefilter(Txids, PeerFeeFilter) ->">>)),
         %% No exemption / whitelist branch
         ?assertEqual(nomatch, binary:match(Src, <<"force_relay">>)),
         ?assertEqual(nomatch, binary:match(Src, <<"ForceRelay">>)),
         ?assertEqual(nomatch, binary:match(Src, <<"whitelist">>))
       end)
     ]}.

%%% ===================================================================
%%% Pure decision smoke: pick_announce_msg/3 sanity check (PRESENT
%%% path; provides a behavioural anchor so the audit-flip test in G5
%%% is corroborated end-to-end).
%%% ===================================================================

pick_announce_msg_behavioural_smoke_test_() ->
    {"Behavioural smoke — beamchain_peer_manager:pick_announce_msg/3 "
     "returns {headers, _} when wants_headers=true, otherwise {inv, _}.",
     [
      ?_test(begin
         %% Use a stub block header binary (80 bytes of zeros) and a
         %% stub block hash (32 bytes of zeros). pick_announce_msg/3
         %% is pure, so we don't need a live peer.
         Header = <<0:(80*8)>>,
         Hash   = <<0:(32*8)>>,
         {HCmd, _HPayload} = beamchain_peer_manager:pick_announce_msg(true, Header, Hash),
         {ICmd, _IPayload} = beamchain_peer_manager:pick_announce_msg(false, Header, Hash),
         ?assertEqual(headers, HCmd),
         ?assertEqual(inv,     ICmd)
       end)
     ]}.
