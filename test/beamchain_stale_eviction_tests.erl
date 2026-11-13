-module(beamchain_stale_eviction_tests).

%%% Outbound stale-peer eviction: Core v31.1 net_processing.cpp parity.
%%%
%%% Mainnet 2026-11-11 19:01:19.944-.945: seven "evicting stale peer ...
%%% stale tip (2 blocks behind for 1355 s)" in one millisecond, 8 -> 1
%%% full-relay outbound with no restart. peer_entry.best_height was only
%%% refreshed by header_sync, never by the cmpctblock / inv announcements
%%% in-sync peers actually send, so every in-sync peer looked "behind" once
%%% the tip moved, and there was no getheaders challenge before the drop.
%%% The stale-tip handler also disconnected the "worst" (lowest
%%% best_height) outbound peer instead of opening an extra one.
%%%
%%% Core behaviour pinned here:
%%%   UpdateBlockAvailability on headers / inv / cmpctblock / block
%%%   (net_processing.cpp l.2668, 2913, 4069, 4529);
%%%   ConsiderEviction (l.5204): benchmark = our tip when the peer fell
%%%   behind, CHAIN_SYNC_TIMEOUT 20 min, ONE getheaders from
%%%   m_work_header->pprev, HEADERS_RESPONSE_TIME 2 min, m_protect for up to
%%%   MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT = 4 outbound peers;
%%%   stale tip -> SetTryNewOutboundPeer(true) + EvictExtraOutboundPeers,
%%%   never below the 8 full-relay budget.
%%%
%%% Nothing dials: only the peer-manager ETS table and the pure helpers are
%%% driven; every collaborator is mocked.

-include_lib("eunit/include/eunit.hrl").

-define(TIP, 975523).
-define(IDX, beamchain_stale_eviction_idx).
-define(TIP_KEY, beamchain_stale_eviction_tip).
-define(MOCKED, [beamchain_chainstate, beamchain_db, beamchain_sync,
                 beamchain_header_sync, beamchain_block_sync, beamchain_peer]).

%%% ===================================================================
%%% Fixture
%%% ===================================================================

setup() ->
    beamchain_peer_manager:test_ensure_peer_table(),
    ets:delete_all_objects(beamchain_peers),
    case ets:info(?IDX) of
        undefined -> ets:new(?IDX, [named_table, public, set]);
        _ -> ets:delete_all_objects(?IDX)
    end,
    set_tip(?TIP),
    lists:foreach(fun(M) -> ok = meck:new(M, [no_link, non_strict]) end,
                  ?MOCKED),
    ok = meck:expect(beamchain_chainstate, is_chain_paused, fun() -> false end),
    ok = meck:expect(beamchain_chainstate, get_tip_height,
                     fun() -> {ok, persistent_term:get(?TIP_KEY)} end),
    ok = meck:expect(beamchain_db, get_block_index_by_hash,
                     fun(H) ->
                         case ets:lookup(?IDX, H) of
                             [{H, Height}] -> {ok, #{height => Height}};
                             [] -> not_found
                         end
                     end),
    ok = meck:expect(beamchain_sync, handle_peer_message,
                     fun(_, _, _) -> ok end),
    ok = meck:expect(beamchain_header_sync, send_chain_sync_getheaders,
                     fun(_, _) -> ok end),
    ok = meck:expect(beamchain_header_sync, probe_peer, fun(_) -> ok end),
    ok = meck:expect(beamchain_header_sync, handle_peer_connected,
                     fun(_, _) -> ok end),
    ok = meck:expect(beamchain_block_sync, start_sync, fun(_) -> ok end),
    ok = meck:expect(beamchain_peer, disconnect, fun(_) -> ok end),
    flush(),
    ok.

teardown(_) ->
    lists:foreach(fun(M) -> catch meck:unload(M) end, ?MOCKED),
    ets:delete_all_objects(beamchain_peers),
    catch ets:delete(?IDX),
    persistent_term:erase(?TIP_KEY),
    flush().

stale_eviction_test_() ->
    {foreach, fun setup/0, fun teardown/1,
     [fun(_) -> {"1: a peer whose only announcement is a cmpctblock for our "
                 "new tip is not behind and is not evicted",
                 fun cmpctblock_announcer_not_evicted/0} end,
      fun(_) -> {"1b: same for an inv announcement",
                 fun inv_announcer_not_evicted/0} end,
      fun(_) -> {"2: a peer really behind is sent getheaders first and "
                 "evicted only if still behind 2 min later",
                 fun behind_peer_challenged_then_evicted/0} end,
      fun(_) -> {"2b: a challenged peer that answers with our chain's "
                 "headers is kept",
                 fun challenged_peer_that_answers_kept/0} end,
      fun(_) -> {"3: eight in-sync outbound peers + two new blocks by "
                 "cmpctblock -> zero evictions over 25 simulated min",
                 fun eight_in_sync_peers_zero_evictions/0} end,
      fun(_) -> {"4: stale tip with 8 outbound opens an extra slot and "
                 "does not disconnect below 8",
                 fun stale_tip_opens_extra_slot/0} end,
      fun(_) -> {"4b: above the budget, exactly the extra peer with the "
                 "oldest block announcement is evicted",
                 fun extra_outbound_peer_trimmed/0} end,
      fun(_) -> {"negative control: a peer that stays on an old chain IS "
                 "evicted (anti-eclipse rule kept)",
                 fun peer_on_old_chain_evicted/0} end,
      fun(_) -> {"m_protect covers at most 4 outbound full-relay peers",
                 fun protect_cap_is_four/0} end]}.

%%% ===================================================================
%%% Helpers
%%% ===================================================================

set_tip(H) -> persistent_term:put(?TIP_KEY, H).

flush() ->
    receive _ -> flush() after 0 -> ok end.

evictions() ->
    receive {evict_peer, P, Why} -> [{P, lists:flatten(Why)} | evictions()]
    after 0 -> []
    end.

spawn_peer() -> spawn(fun() -> receive stop -> ok end end).

outbound(N) ->
    [begin
         P = spawn_peer(),
         ok = beamchain_peer_manager:test_insert_peer(P, outbound, full_relay,
                                                      normal),
         P
     end || _ <- lists:seq(1, N)].

stop_all(Ps) -> [P ! stop || P <- Ps], ok.

%% A distinct 80-byte header per (Tag, Height); registered in the mocked
%% block index when Known.
header(Tag, Height) ->
    <<Tag:32, Height:32, 0:(72 * 8)>>.

hash(Hdr) -> beamchain_serialize:hash256(Hdr).

index(Hdr, Height) ->
    ets:insert(?IDX, {hash(Hdr), Height}),
    Hdr.

cmpctblock(Hdr) -> <<Hdr/binary, 0:64, 0, 0>>.
inv_block(Hdr) -> <<1, 16#40000002:32/little, (hash(Hdr))/binary>>.
headers([_ | _] = Hdrs) ->
    <<(length(Hdrs)), << <<H/binary, 0>> || H <- Hdrs >>/binary>>.

%% The three hooks below exist only with the fix. On master they are absent
%% and the fallback models master's behaviour (the manager forwards the
%% message to sync without noting it; there is no extra-outbound flag; the
%% budget is fixed), so the tests compile and run there and fail on their
%% assertions, not on undef.
hook(F, A) ->
    {module, _} = code:ensure_loaded(beamchain_peer_manager),
    erlang:function_exported(beamchain_peer_manager, F, A).

peer_message(P, Cmd, Payload) ->
    case hook(test_peer_message, 3) of
        true -> beamchain_peer_manager:test_peer_message(P, Cmd, Payload);
        false -> ok
    end.

stale_tip_detected(TryNew) ->
    case hook(test_stale_tip_detected, 1) of
        true -> beamchain_peer_manager:test_stale_tip_detected(TryNew);
        false -> TryNew
    end.

stale_peer_pass(TryNew, Now) ->
    case hook(test_stale_peer_pass, 2) of
        true -> beamchain_peer_manager:test_stale_peer_pass(TryNew, Now);
        false -> pass(Now), TryNew
    end.

outbound_target(TryNew) ->
    case hook(test_outbound_target, 1) of
        true -> beamchain_peer_manager:test_outbound_target(TryNew);
        false -> 10
    end.

announce(P, cmpctblock, Hdr) ->
    peer_message(P, cmpctblock, cmpctblock(Hdr));
announce(P, inv, Hdr) ->
    peer_message(P, inv, inv_block(Hdr)).

pass(Now) ->
    beamchain_peer_manager:test_check_stale_peers(Now).

challenged() ->
    [P || {_, {beamchain_header_sync, send_chain_sync_getheaders, [P, _]}, _}
              <- meck:history(beamchain_header_sync)].

%% Run a stale-peer pass every 45 s from T0 to T0 + Secs, applying the
%% scheduled events [{OffsetSec, Fun}] first; returns all evictions.
simulate(T0, Secs, Events) ->
    lists:append(
      [begin
           [F() || {At, F} <- Events, At > Off - 45, At =< Off],
           pass(T0 + Off),
           evictions()
       end || Off <- lists:seq(0, Secs, 45)]).

%%% ===================================================================
%%% 1. announcement by cmpctblock / inv
%%% ===================================================================

cmpctblock_announcer_not_evicted() ->
    announcer_not_evicted(cmpctblock).

inv_announcer_not_evicted() ->
    announcer_not_evicted(inv).

announcer_not_evicted(How) ->
    [Cur, P] = outbound(2),
    beamchain_peer_manager:update_peer_height(Cur, ?TIP),
    %% P was last seen (by header_sync) one block below our old tip.
    beamchain_peer_manager:update_peer_height(P, ?TIP - 1),
    %% A new block arrives; P announces it, and only that.
    Hdr = index(header(1, ?TIP + 1), ?TIP + 1),
    set_tip(?TIP + 1),
    ok = announce(P, How, Hdr),
    beamchain_peer_manager:update_peer_height(Cur, ?TIP + 1),
    T0 = erlang:system_time(second),
    Ev = simulate(T0, 25 * 60, []),
    ?assertEqual([], Ev),
    ?assertEqual([], challenged()),
    ?assertEqual(?TIP + 1, beamchain_peer_manager:test_peer_field(P, best_height)),
    stop_all([Cur, P]).

%%% ===================================================================
%%% 2. a peer really behind: getheaders first, eviction 2 min later
%%% ===================================================================

behind_peer_challenged_then_evicted() ->
    [Cur, B] = outbound(2),
    beamchain_peer_manager:update_peer_height(Cur, ?TIP),
    beamchain_peer_manager:update_peer_height(B, ?TIP - 5),
    T0 = erlang:system_time(second),
    pass(T0),
    ?assertEqual([], evictions()),
    %% Still inside CHAIN_SYNC_TIMEOUT: nothing.
    pass(T0 + 20 * 60),
    ?assertEqual([], evictions()),
    ?assertEqual([], challenged()),
    %% Timeout passed: ONE getheaders from m_work_header->pprev, no drop.
    pass(T0 + 20 * 60 + 1),
    ?assertEqual([], evictions()),
    ?assertEqual([B], challenged()),
    ?assert(meck:called(beamchain_header_sync, send_chain_sync_getheaders,
                        [B, ?TIP - 1])),
    %% Within HEADERS_RESPONSE_TIME: still kept, no second getheaders.
    pass(T0 + 22 * 60),
    ?assertEqual([], evictions()),
    ?assertEqual([B], challenged()),
    %% Still behind after the 2 min response window: evicted.
    pass(T0 + 22 * 60 + 2),
    ?assertMatch([{B, "stale tip" ++ _}], evictions()),
    stop_all([Cur, B]).

challenged_peer_that_answers_kept() ->
    [Cur, B] = outbound(2),
    beamchain_peer_manager:update_peer_height(Cur, ?TIP),
    beamchain_peer_manager:update_peer_height(B, ?TIP - 5),
    Work = index(header(1, ?TIP), ?TIP),
    T0 = erlang:system_time(second),
    pass(T0),
    pass(T0 + 20 * 60 + 1),
    ?assertEqual([B], challenged()),
    %% B answers the getheaders with m_work_header (our tip).
    ok = peer_message(B, headers, headers([Work])),
    Ev = simulate(T0 + 21 * 60, 10 * 60, []),
    ?assertEqual([], Ev),
    ?assertEqual(?TIP, beamchain_peer_manager:test_peer_field(B, best_height)),
    stop_all([Cur, B]).

%%% ===================================================================
%%% 3. eight in-sync outbound peers, two new blocks by cmpctblock
%%% ===================================================================

eight_in_sync_peers_zero_evictions() ->
    Peers = outbound(8),
    [beamchain_peer_manager:update_peer_height(P, ?TIP) || P <- Peers],
    B1 = index(header(1, ?TIP + 1), ?TIP + 1),
    B2 = index(header(1, ?TIP + 2), ?TIP + 2),
    NewBlock = fun(Hdr, H) ->
                   fun() ->
                       set_tip(H),
                       [ok = announce(P, cmpctblock, Hdr) || P <- Peers]
                   end
               end,
    T0 = erlang:system_time(second),
    Ev = simulate(T0, 25 * 60, [{60, NewBlock(B1, ?TIP + 1)},
                                {12 * 60, NewBlock(B2, ?TIP + 2)}]),
    ?assertEqual([], Ev),
    ?assertEqual([], challenged()),
    ?assertNot(meck:called(beamchain_peer, disconnect, '_')),
    [?assertEqual(?TIP + 2, beamchain_peer_manager:test_peer_field(P, best_height))
     || P <- Peers],
    stop_all(Peers).

%%% ===================================================================
%%% 4. stale tip: extra outbound slot, never a disconnect below 8
%%% ===================================================================

stale_tip_opens_extra_slot() ->
    Peers = outbound(8),
    %% Every peer looks "behind" (the shape that used to pick a victim).
    [beamchain_peer_manager:update_peer_height(P, ?TIP - 2) || P <- Peers],
    [Low | _] = Peers,
    beamchain_peer_manager:update_peer_height(Low, 0),
    ?assertEqual(true, stale_tip_detected(false)),
    ?assertNot(meck:called(beamchain_peer, disconnect, '_')),
    ?assertEqual(outbound_target(false) + 1,
                 outbound_target(true)),
    %% With exactly 8 full-relay the extra-peer trim does nothing.
    pass(erlang:system_time(second)),
    ?assertEqual([], [E || {_, "extra" ++ _} = E <- evictions()]),
    stop_all(Peers).

extra_outbound_peer_trimmed() ->
    Peers = outbound(8),
    [beamchain_peer_manager:update_peer_height(P, ?TIP) || P <- Peers],
    %% A 9th full-relay peer (the stale-tip extra) with the oldest block
    %% announcement: none since connect.
    Old = spawn_peer(),
    ok = beamchain_peer_manager:test_insert_peer(Old, outbound, full_relay,
                                                 normal),
    %% 9 full-relay, one over budget; 4 of the in-sync ones get m_protect.
    %% Core: after trimming, SetTryNewOutboundPeer(false) -- the stale tip
    %% gets ONE extra peer per check, not one every 45 s pass.
    ?assertEqual(false, stale_peer_pass(true, erlang:system_time(second))),
    Ev = evictions(),
    ?assertEqual([Old], [P || {P, "extra" ++ _} <- Ev]),
    stop_all([Old | Peers]).

%%% ===================================================================
%%% Negative control + m_protect
%%% ===================================================================

peer_on_old_chain_evicted() ->
    [Cur, F] = outbound(2),
    beamchain_peer_manager:update_peer_height(Cur, ?TIP),
    beamchain_peer_manager:update_peer_height(F, ?TIP - 3),
    %% F announces and answers only blocks of its own fork, which are not
    %% in our block index.
    Fork1 = header(7, ?TIP - 2),
    Fork2 = header(7, ?TIP - 1),
    ok = peer_message(F, cmpctblock,
                                                  cmpctblock(Fork1)),
    T0 = erlang:system_time(second),
    pass(T0),
    pass(T0 + 20 * 60 + 1),
    ?assertEqual([F], challenged()),
    ok = peer_message(F, headers,
                                                  headers([Fork1, Fork2])),
    pass(T0 + 21 * 60),
    ?assertEqual([], evictions()),
    pass(T0 + 22 * 60 + 2),
    ?assertMatch([{F, "stale tip" ++ _}], evictions()),
    stop_all([Cur, F]).

protect_cap_is_four() ->
    Peers = outbound(6),
    [beamchain_peer_manager:update_peer_height(P, ?TIP) || P <- Peers],
    T0 = erlang:system_time(second),
    pass(T0),
    %% The tip moves and NOBODY announces it: every peer is behind.
    set_tip(?TIP + 1),
    Ev = simulate(T0 + 45, 25 * 60, []),
    Evicted = lists:usort([P || {P, "stale tip" ++ _} <- Ev]),
    ?assertEqual(2, length(Evicted)),
    ?assertEqual(2, length(lists:usort(challenged()))),
    stop_all(Peers).
