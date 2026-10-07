-module(beamchain_sync_wedge_tests).
-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%%% ===================================================================
%%% Mainnet sync wedges, 2026-10-07 (17f6b48): stuck at 970297
%%% ~05:50-07:14Z and at 970314 ~08:40-09:20Z, until a restart.
%%%
%%% restart.log shows one chain of events, both times:
%%%   1. every getheaders probe times out (20 s each, 13 peers in turn,
%%%      31 minutes; peers that answered in 5-14 s minutes earlier) while
%%%      header_sync's own timers fire on the second -- the delay is
%%%      upstream, in beamchain_sync, which routes every headers/block
%%%      message BEHIND every tx (ATMP is a 30 s mempool call) and runs a
%%%      full mempool scan (ets:match_object, 8-32 ms) per MSG_WTX inv item;
%%%   2. late replies arrive from a peer that is no longer the sync peer and
%%%      are deferred, so no header is accepted at all;
%%%   3. after 30 min the stale-tip check re-arms block_sync to the best
%%%      PEER's height (970301 > header tip 970297): "no block index for
%%%      height 970298..970301" -- request_batch DROPS those heights;
%%%   4. the headers then arrive, but start_sync(970301) is a no-op
%%%      (target unchanged) and nothing is queued/in flight/downloaded, so
%%%      block_sync stays `syncing` forever (no watchdog: stuck needs
%%%      in_flight or downloaded > 0).
%%%
%%% Each test below replays one link deterministically and fails on the
%%% deployed code. The end-to-end replay (wedge_replay) is links 3+4.
%%% ===================================================================

-record(mempool_entry, {
    txid, wtxid, tx, fee, size, vsize, weight, fee_rate,
    time_added, height_added,
    ancestor_count, ancestor_size, ancestor_fee,
    descendant_count, descendant_size, descendant_fee,
    spends_coinbase, rbf_signaling, adj_weight
}).

%%% ===================================================================
%%% Part 1: block_sync -- the permanent latch (links 3 + 4)
%%% ===================================================================

-define(BS_MOCKED, [beamchain_db, beamchain_peer, beamchain_peer_manager,
                    beamchain_chainstate, beamchain_validation,
                    beamchain_serialize, beamchain_sync]).

bs_setup() ->
    Tab = ets:new(wedge_bs, [set, public]),
    ets:insert(Tab, {tip, {height_hash(100), 100}}),
    ets:insert(Tab, {header_tip, 100}),
    lists:foreach(fun(M) -> ok = meck:new(M, [no_link]) end, ?BS_MOCKED),
    %% The height index only holds headers we actually have.
    ok = meck:expect(beamchain_db, get_block_index,
        fun(H) ->
            [{header_tip, HT}] = ets:lookup(Tab, header_tip),
            case H =< HT of
                true -> {ok, #{hash => height_hash(H), header => mk_header(H),
                               chainwork => H, n_tx => 1}};
                false -> not_found
            end
        end),
    ok = meck:expect(beamchain_db, get_header_tip,
        fun() ->
            [{header_tip, HT}] = ets:lookup(Tab, header_tip),
            {ok, #{hash => height_hash(HT), height => HT}}
        end),
    ok = meck:expect(beamchain_db, store_block_index,
        fun(_, _, _, _, _) -> ok end),
    ok = meck:expect(beamchain_db, store_block_index,
        fun(_, _, _, _, _, _) -> ok end),
    ok = meck:expect(beamchain_peer, send_message, fun(_, _) -> ok end),
    ok = meck:expect(beamchain_peer, disconnect, fun(_) -> ok end),
    ok = meck:expect(beamchain_peer, add_misbehavior, fun(_, _) -> ok end),
    %% start_sync gathers its peers from peer_manager.
    ok = meck:expect(beamchain_peer_manager, get_peers,
        fun() ->
            case ets:lookup(Tab, peers) of
                [{peers, L}] -> [#{pid => P, connected => true, info => #{}}
                                 || P <- L];
                [] -> []
            end
        end),
    ok = meck:expect(beamchain_chainstate, get_tip,
        fun() -> [{tip, T}] = ets:lookup(Tab, tip), {ok, T} end),
    ok = meck:expect(beamchain_chainstate, connect_block,
        fun(#block{header = #block_header{merkle_root = <<H:256>>}}) ->
            ets:insert(Tab, {tip, {height_hash(H), H}}),
            ok
        end),
    ok = meck:expect(beamchain_validation, check_block, fun(_, _) -> ok end),
    ok = meck:expect(beamchain_serialize, block_hash,
        fun(#block_header{merkle_root = MR}) -> MR end),
    ok = meck:expect(beamchain_sync, notify_blocks_complete, fun(_) -> ok end),
    Tab.

bs_teardown(Tab) ->
    lists:foreach(fun(M) -> catch meck:unload(M) end, ?BS_MOCKED),
    ets:delete(Tab),
    flush_all().

block_sync_wedge_test_() ->
    {foreach, fun bs_setup/0, fun bs_teardown/1,
     [fun(T) -> {"wedge replay: stale-tip re-arm past the header tip, then "
                 "the headers arrive -> the blocks ARE downloaded",
                 fun() -> wedge_replay(T) end} end,
      fun(T) -> {"a height whose header is not here yet stays queued "
                 "(never silently dropped)",
                 fun() -> unindexed_height_kept(T) end} end,
      fun(T) -> {"watchdog re-queues a lost frontier (syncing, nothing "
                 "queued/in flight/downloaded, next =< target)",
                 fun() -> orphaned_frontier_recovered(T) end} end,
      fun(T) -> {"stale-tip self-heal rebuilds a wedged downloader from "
                 "chain state (in-flight to a dead peer, nothing moving)",
                 fun() -> stale_tip_rearm_rebuilds(T) end} end,
      fun(T) -> {"control: ordinary +1 tip advance downloads and completes",
                 fun() -> ordinary_advance_control(T) end} end]}.

%% Links 3 + 4 exactly as on mainnet (970297 -> 970301).
wedge_replay(Tab) ->
    put(getdata_seen, 0),
    P1 = spawn(fun() -> receive stop -> ok end end),
    ets:insert(Tab, {peers, [P1]}),
    S0 = complete_state(100, P1),
    %% 02:19:12 peer_manager stale tip: "requesting headers from best peer
    %% (height 104, ours 100)" -> block_sync:start_sync(104) while our
    %% header tip is still 100.
    {noreply, S1} = beamchain_block_sync:handle_cast(
                      {start_sync, #{target_height => 104}}, S0),
    %% 02:28:05 header_sync stores 101..104 -> sync "headers advanced to
    %% 104 during block download, extending block_sync target", and the
    %% snapshot-gap check fires the same start_sync on every peer connect.
    ets:insert(Tab, {header_tip, 104}),
    {noreply, S2} = beamchain_block_sync:handle_cast(
                      {start_sync, #{target_height => 104}}, S1),
    {noreply, S3} = beamchain_block_sync:handle_cast(
                      {start_sync, #{target_height => 104}}, S2),
    {Requested, S4} = case collect_getdata() of
        [] ->
            %% Nothing requested: give the watchdog four ticks (a minute
            %% on the live node) to rescue it.
            Sx = tick(4, S3),
            {collect_getdata(), Sx};
        R ->
            {R, S3}
    end,
    ?debugFmt("wedge replay: status=~p next=~p target=~p queue=~p "
              "requested=~w",
              [beamchain_block_sync:test_get(status, S4),
               beamchain_block_sync:test_get(next_to_validate, S4),
               beamchain_block_sync:test_get(target_height, S4),
               beamchain_block_sync:test_get(download_queue, S4),
               [H || <<H:256>> <- Requested]]),
    ?assertEqual([height_hash(H) || H <- lists:seq(101, 104)],
                 lists:usort(Requested)),
    S5 = serve_until_quiescent(P1, Requested, S4, 200),
    ?assertEqual(105, beamchain_block_sync:test_get(next_to_validate, S5)),
    ?assertEqual(complete, beamchain_block_sync:test_get(status, S5)),
    P1 ! stop.

unindexed_height_kept(Tab) ->
    put(getdata_seen, 0),
    P1 = spawn(fun() -> receive stop -> ok end end),
    %% Header tip 102, but the queue reaches 104 (e.g. a header reorg
    %% rewound the header chain under an armed download).
    ets:insert(Tab, {header_tip, 102}),
    S0 = beamchain_block_sync:test_state(#{
        status => syncing, next_to_validate => 101, target_height => 104,
        download_queue => lists:seq(101, 104), in_flight => #{},
        hash_to_height => #{}, downloaded => #{},
        peers => #{P1 => #{}}, peer_stats => #{P1 => 0}}),
    {noreply, S1} = beamchain_block_sync:handle_cast(
                      {peer_connected, P1, #{}}, S0),
    ?assertEqual([height_hash(101), height_hash(102)],
                 lists:usort(collect_getdata())),
    ?assert(in_frontier(103, S1)),
    ?assert(in_frontier(104, S1)),
    %% Headers for 103/104 arrive; the next watchdog pass requests them.
    ets:insert(Tab, {header_tip, 104}),
    S2 = tick(1, S1),
    ?assertEqual([height_hash(103), height_hash(104)],
                 lists:usort(collect_getdata())),
    ?assert(in_frontier(104, S2)),
    P1 ! stop.

orphaned_frontier_recovered(Tab) ->
    put(getdata_seen, 0),
    P1 = spawn(fun() -> receive stop -> ok end end),
    ets:insert(Tab, {header_tip, 104}),
    S0 = beamchain_block_sync:test_state(#{
        status => syncing, next_to_validate => 101, target_height => 104,
        download_queue => [], in_flight => #{}, hash_to_height => #{},
        downloaded => #{}, peers => #{P1 => #{}}, peer_stats => #{P1 => 0}}),
    S1 = tick(1, S0),
    Requested = collect_getdata(),
    ?assertEqual([height_hash(H) || H <- lists:seq(101, 104)],
                 lists:usort(Requested)),
    S2 = serve_until_quiescent(P1, Requested, S1, 200),
    ?assertEqual(complete, beamchain_block_sync:test_get(status, S2)),
    P1 ! stop.

stale_tip_rearm_rebuilds(Tab) ->
    put(getdata_seen, 0),
    Dead = spawn(fun() -> ok end),
    P1 = spawn(fun() -> receive stop -> ok end end),
    ets:insert(Tab, {peers, [P1]}),
    ets:insert(Tab, {header_tip, 104}),
    %% Wedged: 101 assigned to a peer that is gone, the rest lost.
    S0 = beamchain_block_sync:test_state(#{
        status => syncing, next_to_validate => 101, target_height => 104,
        download_queue => [],
        in_flight => #{101 => {Dead, erlang:monotonic_time(millisecond),
                               height_hash(101)}},
        hash_to_height => #{height_hash(101) => 101}, downloaded => #{},
        peers => #{}, peer_stats => #{}}),
    {noreply, S1} = beamchain_block_sync:handle_cast(stale_tip_rearm, S0),
    Requested = collect_getdata(),
    ?assertEqual([height_hash(H) || H <- lists:seq(101, 104)],
                 lists:usort(Requested)),
    S2 = serve_until_quiescent(P1, Requested, S1, 200),
    ?assertEqual(complete, beamchain_block_sync:test_get(status, S2)),
    %% No gap -> no-op (control).
    {noreply, S3} = beamchain_block_sync:handle_cast(stale_tip_rearm, S2),
    ?assertEqual([], collect_getdata()),
    ?assertEqual(complete, beamchain_block_sync:test_get(status, S3)),
    P1 ! stop.

ordinary_advance_control(Tab) ->
    put(getdata_seen, 0),
    P1 = spawn(fun() -> receive stop -> ok end end),
    ets:insert(Tab, {peers, [P1]}),
    S0 = complete_state(100, P1),
    ets:insert(Tab, {header_tip, 101}),
    {noreply, S1} = beamchain_block_sync:handle_cast(
                      {start_sync, #{target_height => 101}}, S0),
    Requested = collect_getdata(),
    ?assertEqual([height_hash(101)], Requested),
    S2 = serve_until_quiescent(P1, Requested, S1, 50),
    ?assertEqual(102, beamchain_block_sync:test_get(next_to_validate, S2)),
    ?assertEqual(complete, beamchain_block_sync:test_get(status, S2)),
    P1 ! stop.

complete_state(Tip, Peer) ->
    beamchain_block_sync:test_state(#{
        status => complete, next_to_validate => Tip + 1, target_height => Tip,
        download_queue => [], in_flight => #{}, hash_to_height => #{},
        downloaded => #{}, peers => #{Peer => #{}},
        peer_stats => #{Peer => 0}}).

%% gather_connected_peers() (start_sync) asks peer_manager; feed it P.
tick(0, S) -> S;
tick(N, S) ->
    {noreply, S2} = beamchain_block_sync:handle_info(stall_check, S),
    tick(N - 1, S2).

%%% ===================================================================
%%% Part 1b: wedge 4 (85ca6e9, 970353, 2026-10-07 15:11-15:41Z) -- new
%%% blocks announced as cmpctblock (we ask every peer for BIP152 high
%%% bandwidth) never reached header_sync: a partial reconstruction was
%%% dropped, and Core never re-announces a block it sent as cmpctblock.
%%% ===================================================================

cmpct_setup() ->
    Tab = bs_setup(),
    ok = meck:new(beamchain_compact_block, [no_link]),
    ok = meck:expect(beamchain_compact_block, init_compact_block,
                     fun(_) -> {ok, cs} end),
    ok = meck:new(beamchain_header_sync, [no_link]),
    ok = meck:expect(beamchain_header_sync, handle_headers,
                     fun(_, _) -> ok end),
    ok = meck:expect(beamchain_header_sync, probe_peer, fun(_) -> ok end),
    ok = meck:expect(beamchain_db, has_block, fun(_) -> false end),
    ok = meck:expect(beamchain_db, get_block_index_by_hash,
        fun(<<H:256>>) -> {ok, #{height => H}} end),
    ok = meck:expect(beamchain_chainstate, get_tip_height,
        fun() -> [{tip, {_, H}}] = ets:lookup(Tab, tip), {ok, H} end),
    Tab.

cmpct_teardown(Tab) ->
    catch meck:unload(beamchain_compact_block),
    catch meck:unload(beamchain_header_sync),
    bs_teardown(Tab).

cmpct_announce_test_() ->
    {foreach, fun cmpct_setup/0, fun cmpct_teardown/1,
     [fun(T) -> {"a partially reconstructable HB cmpctblock is NOT dropped: "
                 "its header goes to header_sync and the block is fetched",
                 fun() -> partial_cmpct_not_dropped(T) end} end,
      fun(T) -> {"control: a fully reconstructable cmpctblock connects",
                 fun() -> full_cmpct_connects(T) end} end]}.

cmpct_msg(H) ->
    #{header => mk_header(H), nonce => 0, short_ids => [<<1:48>>],
      prefilled_txns => []}.

partial_cmpct_not_dropped(_Tab) ->
    put(getdata_seen, 0),
    ok = meck:expect(beamchain_compact_block, try_reconstruct,
                     fun(_, _) -> {partial, ps} end),
    P1 = spawn(fun() -> receive stop -> ok end end),
    S0 = complete_state(100, P1),
    {noreply, _S1} = beamchain_block_sync:handle_cast(
                       {cmpctblock, P1, cmpct_msg(101)}, S0),
    %% Core ProcessNewBlockHeaders: the header reaches header_sync...
    ?assert(meck:called(beamchain_header_sync, handle_headers,
                        [P1, [mk_header(101)]])),
    %% ...and the body is requested, not dropped.
    ?assertEqual([height_hash(101)], collect_getdata()),
    P1 ! stop.

full_cmpct_connects(Tab) ->
    ok = meck:expect(beamchain_compact_block, try_reconstruct,
                     fun(_, _) -> {ok, mk_block(101)} end),
    P1 = spawn(fun() -> receive stop -> ok end end),
    S0 = complete_state(100, P1),
    {noreply, _} = beamchain_block_sync:handle_cast(
                     {cmpctblock, P1, cmpct_msg(101)}, S0),
    ?assertMatch([{tip, {_, 101}}], ets:lookup(Tab, tip)),
    P1 ! stop.

%%% ===================================================================
%%% Part 1c: the periodic probe asks a peer that has the chain
%%% ===================================================================

periodic_probe_prefers_outbound_test_() ->
    {setup,
     fun() ->
         beamchain_peer_manager:test_ensure_peer_table(),
         ets:delete_all_objects(beamchain_peers),
         ok = meck:new(beamchain_header_sync, [no_link]),
         ok = meck:expect(beamchain_header_sync, probe_peer, fun(_) -> ok end)
     end,
     fun(_) ->
         catch meck:unload(beamchain_header_sync),
         ets:delete_all_objects(beamchain_peers)
     end,
     fun() ->
         Spawn = fun() -> spawn(fun() -> receive stop -> ok end end) end,
         Inbound = [Spawn() || _ <- lists:seq(1, 6)],
         Out = Spawn(),
         Feeler = Spawn(),
         [beamchain_peer_manager:test_insert_peer(P, inbound, full_relay,
                                                  normal) || P <- Inbound],
         beamchain_peer_manager:test_insert_peer(Out, outbound, full_relay,
                                                 normal),
         beamchain_peer_manager:test_insert_peer(Feeler, outbound, feeler,
                                                 normal),
         [beamchain_peer_manager:test_send_periodic_getheaders()
          || _ <- lists:seq(1, 40)],
         Probed = lists:usort([P || {_, {beamchain_header_sync, probe_peer,
                                         [P]}, _} <-
                                        meck:history(beamchain_header_sync)]),
         ?assertEqual([Out], Probed),
         [P ! stop || P <- [Out, Feeler | Inbound]]
     end}.

%%% ===================================================================
%%% Part 2: header_sync -- late replies from a rotated-away peer (link 2)
%%% ===================================================================

-define(HS_MOCKED, [beamchain_db, beamchain_chainstate, beamchain_peer,
                    beamchain_peer_manager, beamchain_sync,
                    beamchain_serialize, beamchain_pow, beamchain_config]).

hs_setup() ->
    Tab = ets:new(wedge_hs, [set, public]),
    lists:foreach(fun(M) -> ok = meck:new(M, [no_link]) end, ?HS_MOCKED),
    Known = fun(H) -> H =< 20 orelse ets:member(Tab, {stored, H}) end,
    ok = meck:expect(beamchain_db, get_block_index,
        fun(H) ->
            case Known(H) of
                true -> {ok, #{hash => height_hash(H), header => mk_header(H),
                               chainwork => <<H:256>>, height => H}};
                false -> not_found
            end
        end),
    ok = meck:expect(beamchain_db, get_block_index_by_hash,
        fun(<<H:256>>) ->
            case Known(H) of
                true -> {ok, #{hash => height_hash(H), header => mk_header(H),
                               chainwork => <<H:256>>, height => H}};
                false -> not_found
            end
        end),
    ok = meck:expect(beamchain_db, store_block_index,
        fun(H, _, _, _, _) -> ets:insert(Tab, {{stored, H}}), ok end),
    ok = meck:expect(beamchain_db, set_header_tip, fun(_, _) -> ok end),
    ok = meck:expect(beamchain_chainstate, is_known_invalid,
                     fun(_) -> false end),
    ok = meck:expect(beamchain_chainstate, get_tip,
                     fun() -> {ok, {height_hash(20), 20}} end),
    ok = meck:expect(beamchain_peer, send_message, fun(_, _) -> ok end),
    ok = meck:expect(beamchain_peer, add_misbehavior, fun(_, _) -> ok end),
    ok = meck:expect(beamchain_peer_manager, mark_headers_received,
                     fun(_) -> ok end),
    ok = meck:expect(beamchain_peer_manager, mark_getheaders_sent,
                     fun(_) -> ok end),
    ok = meck:expect(beamchain_peer_manager, update_peer_height,
                     fun(_, _) -> ok end),
    ok = meck:expect(beamchain_sync, notify_headers_complete,
                     fun(_) -> ok end),
    ok = meck:expect(beamchain_serialize, block_hash,
        fun(#block_header{merkle_root = MR}) -> MR end),
    ok = meck:expect(beamchain_config, prune_enabled, fun() -> false end),
    ok = meck:expect(beamchain_config, network, fun() -> regtest end),
    ok = meck:expect(beamchain_pow, check_pow, fun(_, _, _) -> true end),
    ok = meck:expect(beamchain_pow, compute_work, fun(_) -> 1 end),
    ok = meck:expect(beamchain_pow, permitted_difficulty_transition,
                     fun(_, _, _, _) -> true end),
    ok = meck:expect(beamchain_pow, get_next_work_required,
        fun(_, #block_header{bits = Bits}, _) -> Bits end),
    Tab.

hs_teardown(Tab) ->
    lists:foreach(fun(M) -> catch meck:unload(M) end, ?HS_MOCKED),
    ets:delete(Tab),
    flush_all().

header_sync_wedge_test_() ->
    {foreach, fun hs_setup/0, fun hs_teardown/1,
     [fun(T) -> {"a connecting reply that arrives after its probe rotated "
                 "away is processed (tip advances, block download notified)",
                 fun() -> late_connecting_reply_processed(T) end} end,
      fun(T) -> {"a whole rotation of late replies cannot starve header "
                 "sync (every peer late by one probe window)",
                 fun() -> rotation_of_late_replies(T) end} end,
      fun(T) -> {"control: a non-connecting batch from a non-sync peer is "
                 "still deferred (no store, no punishment)",
                 fun() -> nonconnecting_still_deferred(T) end} end]}.

late_connecting_reply_processed(_Tab) ->
    P1 = spawn(fun() -> receive stop -> ok end end),
    P2 = spawn(fun() -> receive stop -> ok end end),
    %% Probe of P1 timed out and rotated to P2 (status syncing, sync_peer
    %% P2); P1's reply -- headers 21..24 extending our tip -- lands now.
    S0 = hs_state(20, syncing, P2, #{P1 => 24, P2 => 24}),
    Hdrs = [mk_header(H) || H <- lists:seq(21, 24)],
    {noreply, S1} = beamchain_header_sync:handle_cast({headers, P1, Hdrs}, S0),
    ?assertEqual(24, beamchain_header_sync:test_get(tip_height, S1)),
    ?assert(meck:called(beamchain_sync, notify_headers_complete, [24])),
    ?assertNot(meck:called(beamchain_peer, add_misbehavior, '_')),
    P1 ! stop, P2 ! stop.

%% The live failure mode: the reply ALWAYS lands one window late, so the
%% sender is never the current sync peer. With the old clause no header is
%% ever accepted; the fix accepts the first connecting one.
rotation_of_late_replies(_Tab) ->
    Peers = [spawn(fun() -> receive stop -> ok end end) || _ <- lists:seq(1, 4)],
    Heights = maps:from_list([{P, 22} || P <- Peers]),
    S0 = hs_state(20, syncing, hd(Peers), Heights),
    SN = lists:foldl(
        fun(_, S) ->
            Late = beamchain_header_sync:test_get(sync_peer, S),
            %% The probe of Late times out and rotates to another peer...
            {noreply, Sa} = beamchain_header_sync:handle_info(
                              getheaders_timeout, S),
            %% ...then Late's reply arrives.
            Tip = beamchain_header_sync:test_get(tip_height, Sa),
            Hdrs = [mk_header(H) || H <- lists:seq(Tip + 1, 22)],
            case is_pid(Late) of
                true ->
                    {noreply, Sb} = beamchain_header_sync:handle_cast(
                                      {headers, Late, Hdrs}, Sa),
                    Sb;
                false ->
                    Sa
            end
        end, S0, lists:seq(1, 8)),
    ?assertEqual(22, beamchain_header_sync:test_get(tip_height, SN)),
    [P ! stop || P <- Peers].

nonconnecting_still_deferred(Tab) ->
    P1 = spawn(fun() -> receive stop -> ok end end),
    P2 = spawn(fun() -> receive stop -> ok end end),
    S0 = hs_state(20, syncing, P2, #{P1 => 30, P2 => 30}),
    %% 26..27: prev (25) unknown -- does not extend our tip.
    Hdrs = [mk_header(H) || H <- [26, 27]],
    {noreply, S1} = beamchain_header_sync:handle_cast({headers, P1, Hdrs}, S0),
    ?assertEqual(20, beamchain_header_sync:test_get(tip_height, S1)),
    ?assertEqual(P2, beamchain_header_sync:test_get(sync_peer, S1)),
    ?assertNot(ets:member(Tab, {stored, 26})),
    ?assertNot(meck:called(beamchain_peer, add_misbehavior, '_')),
    P1 ! stop, P2 ! stop.

hs_state(TipH, Status, SyncPeer, Peers) ->
    beamchain_header_sync:test_state(#{
        status => Status, sync_peer => SyncPeer,
        tip_height => TipH, tip_hash => height_hash(TipH),
        tip_chainwork => <<TipH:256>>,
        mtp_window => [{H, 1296688602 + H} || H <- lists:seq(TipH - 10, TipH)],
        params => #{pow_limit => <<16#7fffff:24, 0:232>>, checkpoints => #{}},
        peer_heights => Peers}).

%%% ===================================================================
%%% Part 3: beamchain_sync -- headers never queue behind tx validation
%%% (link 1, real processes)
%%% ===================================================================

-define(SYNC_MOCKED, [beamchain_mempool, beamchain_header_sync,
                      beamchain_p2p_msg, beamchain_peer_manager]).
-define(ATMP_MS, 300).
-define(N_TX, 10).

sync_setup() ->
    Tab = ets:new(wedge_sync, [set, public]),
    ok = meck:new(beamchain_p2p_msg, [no_link, passthrough]),
    ok = meck:expect(beamchain_p2p_msg, decode_payload,
        fun(tx, _) -> {ok, #transaction{version = 2, inputs = [],
                                        outputs = [], locktime = 0}};
           (headers, _) -> {ok, #{headers => []}}
        end),
    ok = meck:new(beamchain_mempool, [no_link]),
    %% A slow mempool (busy behind a connect, disk-bound coin reads).
    ok = meck:expect(beamchain_mempool, accept_to_memory_pool,
        fun(_Tx, _Peer) -> timer:sleep(?ATMP_MS), {error, rejected} end),
    ok = meck:new(beamchain_header_sync, [no_link]),
    ok = meck:expect(beamchain_header_sync, handle_headers,
        fun(_Peer, _H) ->
            ets:insert(Tab, {headers_at, erlang:monotonic_time(millisecond)}),
            ok
        end),
    ok = meck:new(beamchain_peer_manager, [no_link]),
    ok = meck:expect(beamchain_peer_manager, announce_tx, fun(_) -> ok end),
    {ok, Sync} = beamchain_sync:start_link(),
    unlink(Sync),
    %% The ingest process exists only in the fixed tree.
    Ingest = case code:ensure_loaded(beamchain_tx_ingest) of
        {module, _} ->
            {ok, I} = beamchain_tx_ingest:start_link(),
            unlink(I),
            I;
        _ ->
            undefined
    end,
    {Tab, Sync, Ingest}.

sync_teardown({Tab, Sync, Ingest}) ->
    [catch gen_server:stop(P, normal, 15000) || P <- [Ingest, Sync],
                                                is_pid(P)],
    lists:foreach(fun(M) -> catch meck:unload(M) end, ?SYNC_MOCKED),
    ets:delete(Tab),
    flush_all().

sync_isolation_test_() ->
    {foreach, fun sync_setup/0, fun sync_teardown/1,
     [fun(Ctx) -> {timeout, 60,
                   {"a headers message is delivered while " ++
                    integer_to_list(?N_TX) ++ " slow txs are pending "
                    "(not after them)",
                    fun() -> headers_not_behind_txs(Ctx) end}} end]}.

headers_not_behind_txs({Tab, _Sync, _Ingest}) ->
    Peer = self(),
    T0 = erlang:monotonic_time(millisecond),
    [beamchain_sync:handle_peer_message(Peer, tx, <<I:32>>)
     || I <- lists:seq(1, ?N_TX)],
    beamchain_sync:handle_peer_message(Peer, headers, <<>>),
    ok = wait_for(fun() -> ets:member(Tab, headers_at) end, 30000),
    [{headers_at, T1}] = ets:lookup(Tab, headers_at),
    Latency = T1 - T0,
    ?debugFmt("headers delivered after ~B ms (~B txs x ~B ms ATMP queued)",
              [Latency, ?N_TX, ?ATMP_MS]),
    %% Deployed: ~N_TX * ATMP_MS (3000 ms) -- headers wait for every tx.
    ?assert(Latency < ?ATMP_MS * 2),
    %% Control: the txs are still all validated.
    ok = meck:wait(?N_TX, beamchain_mempool, accept_to_memory_pool, '_',
                   ?N_TX * ?ATMP_MS * 3).

wait_for(F, Left) when Left =< 0 -> case F() of true -> ok; false -> timeout end;
wait_for(F, Left) ->
    case F() of
        true -> ok;
        false -> timer:sleep(10), wait_for(F, Left - 10)
    end.

%%% ===================================================================
%%% Part 4: mempool wtxid lookup is O(1) (link 1's other half)
%%% ===================================================================

-define(N_POOL, 20000).
-define(N_LOOKUPS, 500).

wtxid_setup() ->
    Tabs = [{mempool_txs, set}, {mempool_wtxid, set},
            {mempool_by_fee, ordered_set}, {mempool_outpoints, set},
            {mempool_ephemeral, set}],
    [begin
         case ets:info(T) of undefined -> ok; _ -> ets:delete(T) end,
         ets:new(T, [Type, public, named_table])
     end || {T, Type} <- Tabs],
    Tabs.

wtxid_teardown(Tabs) ->
    [catch ets:delete(T) || {T, _} <- Tabs],
    ok.

mempool_wtxid_test_() ->
    {foreach, fun wtxid_setup/0, fun wtxid_teardown/1,
     [fun(_) -> {timeout, 120,
                 {"wtxid lookups stay O(1) in a 20k-entry mempool",
                  fun wtxid_lookup_is_fast/0}} end,
      fun(_) -> {"wtxid index follows insert/remove; direct inserts still "
                 "found (fallback)", fun wtxid_index_correct/0} end]}.

mk_entry(I) ->
    Txid = <<1:8, I:248>>,
    Wtxid = <<2:8, I:248>>,
    Tx = #transaction{version = 2,
                      inputs = [#tx_in{prev_out = #outpoint{hash = <<3:8, I:248>>,
                                                            index = 0},
                                       script_sig = <<>>, sequence = 0,
                                       witness = []}],
                      outputs = [#tx_out{value = 1000,
                                         script_pubkey = <<0:200>>}],
                      locktime = 0},
    #mempool_entry{txid = Txid, wtxid = Wtxid, tx = Tx, fee = 1000,
                   size = 100, vsize = 100, weight = 400, fee_rate = 10.0,
                   time_added = 0, height_added = 0,
                   ancestor_count = 1, ancestor_size = 100, ancestor_fee = 1000,
                   descendant_count = 1, descendant_size = 100,
                   descendant_fee = 1000, spends_coinbase = false,
                   rbf_signaling = false, adj_weight = 400}.

insert(E) ->
    case erlang:function_exported(beamchain_mempool, test_insert_entry, 1) of
        true -> beamchain_mempool:test_insert_entry(E);
        false -> ets:insert(mempool_txs, {E#mempool_entry.txid, E})
    end.

wtxid_lookup_is_fast() ->
    {module, _} = code:ensure_loaded(beamchain_mempool),
    [insert(mk_entry(I)) || I <- lists:seq(1, ?N_POOL)],
    %% The inv path's common case: an announced tx we do NOT have.
    Absent = [<<9:8, I:248>> || I <- lists:seq(1, ?N_LOOKUPS)],
    {Us, Res} = timer:tc(fun() ->
        [beamchain_mempool:lookup_entry_by_wtxid(W) || W <- Absent]
    end),
    ?assert(lists:all(fun(R) -> R =:= not_found end, Res)),
    PerLookupUs = Us / ?N_LOOKUPS,
    ?debugFmt("~B wtxid lookups in a ~B-entry pool: ~.1f us each",
              [?N_LOOKUPS, ?N_POOL, PerLookupUs]),
    %% Deployed (full ets:match_object scan): ~8000 us each at 20k.
    ?assert(PerLookupUs < 200),
    %% And a present one is found.
    #mempool_entry{wtxid = W7} = mk_entry(7),
    ?assertMatch({ok, #mempool_entry{wtxid = W7}},
                 beamchain_mempool:lookup_entry_by_wtxid(W7)).

wtxid_index_correct() ->
    {module, _} = code:ensure_loaded(beamchain_mempool),
    E1 = mk_entry(1), E2 = mk_entry(2),
    insert(E1), insert(E2),
    W1 = E1#mempool_entry.wtxid, W2 = E2#mempool_entry.wtxid,
    ?assertMatch({ok, #mempool_entry{txid = <<1:8, 1:248>>}},
                 beamchain_mempool:lookup_entry_by_wtxid(W1)),
    ?assertEqual(not_found,
                 beamchain_mempool:lookup_entry_by_wtxid(<<9:256>>)),
    case erlang:function_exported(beamchain_mempool, test_remove_entry, 1) of
        true -> beamchain_mempool:test_remove_entry(E1#mempool_entry.txid);
        false -> ets:delete(mempool_txs, E1#mempool_entry.txid)
    end,
    ?assertEqual(not_found, beamchain_mempool:lookup_entry_by_wtxid(W1)),
    ?assertMatch({ok, _}, beamchain_mempool:lookup_entry_by_wtxid(W2)),
    %% A writer that bypasses insert_entry/1 (tests seed the table this
    %% way) must still be found: index size != table size -> scan.
    E3 = mk_entry(3),
    ets:insert(mempool_txs, {E3#mempool_entry.txid, E3}),
    ?assertMatch({ok, #mempool_entry{txid = <<1:8, 3:248>>}},
                 beamchain_mempool:lookup_entry_by_wtxid(
                   E3#mempool_entry.wtxid)),
    ?assertMatch({ok, _}, beamchain_mempool:lookup_entry_by_wtxid(W2)).

%%% ===================================================================
%%% Helpers
%%% ===================================================================

height_hash(H) -> <<H:256>>.

mk_header(H) ->
    #block_header{
        version     = 1,
        prev_hash   = height_hash(H - 1),
        merkle_root = height_hash(H),
        timestamp   = 1296688602 + H,
        bits        = 16#207fffff,
        nonce       = 0
    }.

mk_block(H) ->
    #block{header = mk_header(H), transactions = []}.

in_frontier(Height, S) ->
    lists:member(Height, beamchain_block_sync:test_get(download_queue, S))
        orelse maps:is_key(Height, beamchain_block_sync:test_get(in_flight, S))
        orelse maps:is_key(Height, beamchain_block_sync:test_get(downloaded, S)).

serve_until_quiescent(_Peer, _Hashes, S, 0) ->
    S;
serve_until_quiescent(Peer, [<<H:256>> | Rest], S, Fuel) ->
    {noreply, S2} = beamchain_block_sync:handle_cast(
                      {block, Peer, mk_block(H)}, S),
    serve_until_quiescent(Peer, Rest ++ collect_getdata(), S2, Fuel - 1);
serve_until_quiescent(Peer, [], S, Fuel) ->
    receive
        continue_validation ->
            {noreply, S2} = beamchain_block_sync:handle_info(
                              continue_validation, S),
            serve_until_quiescent(Peer, collect_getdata(), S2, Fuel - 1)
    after 0 ->
        case collect_getdata() of
            [] -> S;
            More -> serve_until_quiescent(Peer, More, S, Fuel - 1)
        end
    end.

all_requested() ->
    lists:append(
      [[Hash || #{hash := Hash} <- Items]
       || {_Pid, {beamchain_peer, send_message,
                  [_Peer, {getdata, #{items := Items}}]}, _Ret}
              <- meck:history(beamchain_peer)]).

collect_getdata() ->
    All = all_requested(),
    Seen = case get(getdata_seen) of undefined -> 0; N -> N end,
    put(getdata_seen, length(All)),
    lists:nthtail(min(Seen, length(All)), All).

flush_all() ->
    receive _ -> flush_all() after 0 -> ok end.
