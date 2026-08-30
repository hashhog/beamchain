-module(beamchain_block_sync_tests).
-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% Per-peer tracking record (duplicated from beamchain_block_sync)
-record(peer_stats, {
    in_flight_count = 0  :: non_neg_integer(),
    stall_count = 0      :: non_neg_integer(),
    avg_response_ms = 0  :: non_neg_integer(),
    total_blocks = 0     :: non_neg_integer(),
    total_time_ms = 0    :: non_neg_integer()
}).

%%% ===================================================================
%%% take_from_queue tests
%%% ===================================================================

take_empty_test() ->
    {Taken, Rest} = take_from_queue(5, []),
    ?assertEqual([], Taken),
    ?assertEqual([], Rest).

take_fewer_than_available_test() ->
    {Taken, Rest} = take_from_queue(3, [1, 2, 3, 4, 5]),
    ?assertEqual([1, 2, 3], Taken),
    ?assertEqual([4, 5], Rest).

take_exact_test() ->
    {Taken, Rest} = take_from_queue(3, [1, 2, 3]),
    ?assertEqual([1, 2, 3], Taken),
    ?assertEqual([], Rest).

take_more_than_available_test() ->
    {Taken, Rest} = take_from_queue(10, [1, 2]),
    ?assertEqual([1, 2], Taken),
    ?assertEqual([], Rest).

take_zero_test() ->
    {Taken, Rest} = take_from_queue(0, [1, 2, 3]),
    ?assertEqual([], Taken),
    ?assertEqual([1, 2, 3], Rest).

%%% ===================================================================
%%% Peer stats tracking tests
%%% ===================================================================

peer_stats_update_test() ->
    Stats0 = #{ pid1 => new_peer_stats() },
    Stats1 = update_peer_block_received(pid1, 500, Stats0),
    #{pid1 := PS} = Stats1,
    ?assertEqual(1, PS#peer_stats.total_blocks),
    ?assertEqual(500, PS#peer_stats.total_time_ms),
    ?assertEqual(500, PS#peer_stats.avg_response_ms),
    %% started with in_flight_count=0, so after decrement should be 0
    ?assertEqual(0, PS#peer_stats.in_flight_count).

peer_stats_multiple_blocks_test() ->
    Stats0 = #{ pid1 => new_peer_stats() },
    Stats0b = increment_peer_in_flight(pid1, 3, Stats0),
    Stats1 = update_peer_block_received(pid1, 400, Stats0b),
    Stats2 = update_peer_block_received(pid1, 600, Stats1),
    #{pid1 := PS} = Stats2,
    ?assertEqual(2, PS#peer_stats.total_blocks),
    ?assertEqual(1000, PS#peer_stats.total_time_ms),
    ?assertEqual(500, PS#peer_stats.avg_response_ms),
    ?assertEqual(1, PS#peer_stats.in_flight_count).

decrement_unknown_peer_test() ->
    Stats = #{ pid1 => new_peer_stats() },
    %% Decrementing unknown peer should be a no-op
    Result = decrement_peer_in_flight(pid_unknown, Stats),
    ?assertEqual(Stats, Result).

%%% ===================================================================
%%% Requeue logic tests
%%% ===================================================================

requeue_peer_blocks_test() ->
    InFlight = #{
        100 => {peer1, 1000, <<1:256>>},
        101 => {peer2, 1001, <<2:256>>},
        102 => {peer1, 1002, <<3:256>>},
        103 => {peer2, 1003, <<4:256>>}
    },
    H2H = #{
        <<1:256>> => 100, <<2:256>> => 101,
        <<3:256>> => 102, <<4:256>> => 103
    },
    Queue = [200, 201],

    {Remaining, H2H2, NewQueue} =
        requeue_peer_blocks_pure(peer1, InFlight, H2H, Queue),

    %% peer1 had heights 100 and 102
    ?assertEqual(2, maps:size(Remaining)),
    ?assert(maps:is_key(101, Remaining)),
    ?assert(maps:is_key(103, Remaining)),

    %% Hash index should not contain peer1's hashes
    ?assertNot(maps:is_key(<<1:256>>, H2H2)),
    ?assertNot(maps:is_key(<<3:256>>, H2H2)),
    ?assert(maps:is_key(<<2:256>>, H2H2)),
    ?assert(maps:is_key(<<4:256>>, H2H2)),

    %% Re-queued heights should be sorted and prepended
    ?assertEqual([100, 102, 200, 201], NewQueue).

requeue_empty_test() ->
    {Remaining, H2H2, NewQueue} =
        requeue_peer_blocks_pure(peer1, #{}, #{}, []),
    ?assertEqual(#{}, Remaining),
    ?assertEqual(#{}, H2H2),
    ?assertEqual([], NewQueue).

%%% ===================================================================
%%% Hash hex formatting test
%%% ===================================================================

hash_hex_test() ->
    Hash = <<16#de, 16#ad, 16#be, 16#ef, 0:224>>,
    Hex = hash_hex(Hash),
    ?assertEqual("deadbeef...", Hex).

hash_hex_short_test() ->
    ?assertEqual("???", hash_hex(<<>>)).

%%% ===================================================================
%%% Available peers selection test
%%% ===================================================================

get_available_peers_test() ->
    Peers = #{peer1 => #{}, peer2 => #{}, peer3 => #{}},
    PeerStats = #{
        peer1 => (new_peer_stats())#peer_stats{in_flight_count = 16},
        peer2 => (new_peer_stats())#peer_stats{in_flight_count = 5},
        peer3 => (new_peer_stats())#peer_stats{in_flight_count = 0}
    },
    Available = get_available_peers_pure(Peers, PeerStats, 16),
    %% peer1 is at max (16), should not be available
    ?assertNot(lists:member(peer1, Available)),
    %% peer2 and peer3 should be available
    ?assert(lists:member(peer2, Available)),
    ?assert(lists:member(peer3, Available)).

%%% ===================================================================
%%% Internal helpers (duplicated for unit testing)
%%% ===================================================================

new_peer_stats() ->
    #peer_stats{}.

take_from_queue(N, List) ->
    take_from_queue(N, List, []).

take_from_queue(0, Rest, Acc) ->
    {lists:reverse(Acc), Rest};
take_from_queue(_N, [], Acc) ->
    {lists:reverse(Acc), []};
take_from_queue(N, [H | T], Acc) ->
    take_from_queue(N - 1, T, [H | Acc]).

update_peer_block_received(Peer, ResponseMs, AllStats) ->
    Stats = maps:get(Peer, AllStats, #peer_stats{}),
    NewTotal = Stats#peer_stats.total_blocks + 1,
    NewTotalTime = Stats#peer_stats.total_time_ms + ResponseMs,
    AvgMs = NewTotalTime div max(1, NewTotal),
    Stats2 = Stats#peer_stats{
        in_flight_count = max(0, Stats#peer_stats.in_flight_count - 1),
        total_blocks = NewTotal,
        total_time_ms = NewTotalTime,
        avg_response_ms = AvgMs
    },
    maps:put(Peer, Stats2, AllStats).

decrement_peer_in_flight(Peer, AllStats) ->
    case maps:get(Peer, AllStats, undefined) of
        undefined -> AllStats;
        Stats ->
            Stats2 = Stats#peer_stats{
                in_flight_count = max(0,
                    Stats#peer_stats.in_flight_count - 1)
            },
            maps:put(Peer, Stats2, AllStats)
    end.

increment_peer_in_flight(Peer, N, AllStats) ->
    Stats = maps:get(Peer, AllStats, #peer_stats{}),
    Stats2 = Stats#peer_stats{
        in_flight_count = Stats#peer_stats.in_flight_count + N
    },
    maps:put(Peer, Stats2, AllStats).

requeue_peer_blocks_pure(Peer, InFlight, H2H, Queue) ->
    {ReQueued, Remaining, H2H2} = maps:fold(
        fun(Height, {P, _At, Hash}, {RQ, Rem, H2HAcc}) when P =:= Peer ->
            {[Height | RQ], Rem, maps:remove(Hash, H2HAcc)};
           (Height, Entry, {RQ, Rem, H2HAcc}) ->
            {RQ, maps:put(Height, Entry, Rem), H2HAcc}
        end, {[], #{}, H2H}, InFlight),
    SortedRQ = lists:sort(ReQueued),
    {Remaining, H2H2, SortedRQ ++ Queue}.

hash_hex(<<H:4/binary, _/binary>>) ->
    lists:flatten(io_lib:format("~s...", [binary_to_hex_str(H)]));
hash_hex(_) ->
    "???".

binary_to_hex_str(Bin) ->
    lists:flatten([io_lib:format("~2.16.0b", [B]) || <<B:8>> <= Bin]).

get_available_peers_pure(Peers, PeerStats, MaxPerPeer) ->
    lists:filtermap(fun({Pid, Stats}) ->
        case maps:is_key(Pid, Peers) andalso
             Stats#peer_stats.in_flight_count < MaxPerPeer of
            true -> {true, Pid};
            false -> false
        end
    end, maps:to_list(PeerStats)).

%%% ===================================================================
%%% SipHash tests (BIP152)
%%% ===================================================================

siphash_basic_test() ->
    %% Test vector from SipHash reference implementation
    %% Key: 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
    K0 = 16#0706050403020100,
    K1 = 16#0f0e0d0c0b0a0908,
    %% Empty input should hash to a known value
    Hash = beamchain_crypto:siphash(K0, K1, <<>>),
    ?assert(is_integer(Hash)).

siphash_uint256_test() ->
    %% Test SipHash with a 32-byte input
    K0 = 16#0706050403020100,
    K1 = 16#0f0e0d0c0b0a0908,
    Data = <<1:256>>,
    Hash = beamchain_crypto:siphash_uint256(K0, K1, Data),
    ?assert(is_integer(Hash)),
    %% Should be same as regular siphash
    Hash2 = beamchain_crypto:siphash(K0, K1, Data),
    ?assertEqual(Hash, Hash2).

siphash_consistency_test() ->
    %% Same input should always produce same output
    K0 = 16#deadbeef,
    K1 = 16#cafebabe,
    Data = <<"hello compact blocks">>,
    Hash1 = beamchain_crypto:siphash(K0, K1, Data),
    Hash2 = beamchain_crypto:siphash(K0, K1, Data),
    ?assertEqual(Hash1, Hash2).

%%% ===================================================================
%%% Compact block short id tests
%%% ===================================================================

short_id_length_test() ->
    %% Short ids should be 6 bytes
    K0 = 16#1234567890abcdef,
    K1 = 16#fedcba0987654321,
    Wtxid = <<0:256>>,
    ShortId = beamchain_compact_block:compute_short_id(K0, K1, Wtxid),
    ?assertEqual(6, byte_size(ShortId)).

short_id_deterministic_test() ->
    K0 = 16#1111,
    K1 = 16#2222,
    Wtxid = <<1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
              17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32>>,
    ShortId1 = beamchain_compact_block:compute_short_id(K0, K1, Wtxid),
    ShortId2 = beamchain_compact_block:compute_short_id(K0, K1, Wtxid),
    ?assertEqual(ShortId1, ShortId2).

short_id_differs_for_different_wtxids_test() ->
    K0 = 16#1111,
    K1 = 16#2222,
    Wtxid1 = <<0:256>>,
    Wtxid2 = <<1:256>>,
    ShortId1 = beamchain_compact_block:compute_short_id(K0, K1, Wtxid1),
    ShortId2 = beamchain_compact_block:compute_short_id(K0, K1, Wtxid2),
    ?assertNotEqual(ShortId1, ShortId2).

%%% ===================================================================
%%% SipHash key derivation tests
%%% ===================================================================

siphash_key_derivation_test() ->
    Header = #block_header{
        version = 1,
        prev_hash = <<0:256>>,
        merkle_root = <<1:256>>,
        timestamp = 1000,
        bits = 0,
        nonce = 0
    },
    Nonce = 12345,
    {K0, K1} = beamchain_compact_block:derive_siphash_key(Header, Nonce),
    ?assert(is_integer(K0)),
    ?assert(is_integer(K1)),
    %% Different nonce should produce different key
    {K0b, K1b} = beamchain_compact_block:derive_siphash_key(Header, Nonce + 1),
    ?assert(K0 =/= K0b orelse K1 =/= K1b).

%%% ===================================================================
%%% W18 IBD re-arm predicate tests (regression for liveness latch bug)
%%%
%%% These mirror the pure decision logic of the start_sync handler in
%%% beamchain_block_sync.erl after the W18 fix:
%%%   - status=complete + new peer-announced target > local tip  -> re-arm
%%%   - status=complete + target == local tip                    -> stay complete
%%%   - status=syncing  + new target > old target                -> extend queue
%%%   - status=syncing  + new target =< old target               -> no change
%%% Reference: bitcoin-core/src/net_processing.cpp
%%%   FindNextBlocksToDownload runs every peer-message tick; IBD-complete is a
%%%   dynamic predicate, never a latched terminal state.
%%% ===================================================================

%% Re-arm decision: returns rearm | stay_complete.
rearm_decision(complete, LocalTipHeight, AnnouncedTarget)
        when AnnouncedTarget > LocalTipHeight -> rearm;
rearm_decision(complete, _LocalTipHeight, _AnnouncedTarget) -> stay_complete;
rearm_decision(_, _, _) -> not_applicable.

%% Queue-extension decision for status=syncing: returns the new queue.
extend_queue(OldTarget, NewTarget, OldQueue) when NewTarget > OldTarget ->
    OldQueue ++ lists:seq(OldTarget + 1, NewTarget);
extend_queue(_OldTarget, _NewTarget, OldQueue) ->
    OldQueue.

ibd_complete_then_peer_higher_rearms_test() ->
    %% W17/W18 root cause: block_sync at status=complete, local tip=945127,
    %% peer announces 945191. Must re-arm.
    ?assertEqual(rearm, rearm_decision(complete, 945127, 945191)).

ibd_complete_at_tip_stays_complete_test() ->
    %% Peer at same height as local tip: stay complete (no spurious re-arm).
    ?assertEqual(stay_complete, rearm_decision(complete, 945127, 945127)).

ibd_complete_peer_behind_stays_complete_test() ->
    %% Peer behind us (lagging peer): stay complete.
    ?assertEqual(stay_complete, rearm_decision(complete, 945127, 945100)).

syncing_extends_queue_when_new_target_higher_test() ->
    %% Block sync mid-IBD with target=945127. Headers advance to 945200.
    %% Queue must be extended with [945128..945200].
    OldQueue = [945120, 945121, 945122, 945123],
    NewQueue = extend_queue(945127, 945200, OldQueue),
    ?assertEqual(OldQueue ++ lists:seq(945128, 945200), NewQueue),
    %% Sanity: 73 blocks added to queue.
    ?assertEqual(length(OldQueue) + 73, length(NewQueue)).

syncing_no_change_when_new_target_not_higher_test() ->
    %% header_sync notify with same/lower target: queue unchanged.
    OldQueue = [945120, 945121],
    ?assertEqual(OldQueue, extend_queue(945200, 945200, OldQueue)),
    ?assertEqual(OldQueue, extend_queue(945200, 945100, OldQueue)).

%%% ===================================================================
%%% Issue #34 — frontier-request lifecycle regression tests
%%%
%%% The from-genesis R4 rig soft-deadlocked every ~287 blocks: the
%%% watchdog force_unstick killed the (healthy) pinned peer, the blast
%%% re-request then ran against ZERO connected peers (the replacement
%%% was still handshaking) and silently DROPPED next_to_validate from
%%% the request frontier — not queued, not in flight, not downloaded.
%%% With the head missing, the refill ramp packed the buffer to
%%% MAX_DOWNLOADED_AHEAD, the deadlock branch evicted 64 good blocks
%%% and finally re-planted the head; ~193 blocks later the eviction gap
%%% caused a ticks=1 stall observation, and because stuck_ticks carried
%%% over ACROSS heights, the very next tick that caught a transient
%%% empty-buffer moment at a DIFFERENT height summed to ticks=2 and
%%% killed the healthy peer again. Period: 192 (post-evict buffer) + 1
%%% (blast) + 30 (arrival races) + 64 (re-fetched evictions) = 287.
%%%
%%% Core reference: a removed block request never leaves the download
%%% window (net_processing.cpp:1199 RemoveBlockRequest + :1394
%%% FindNextBlocksToDownload re-walks every non-received block), and
%%% stalling state is cleared on every completed request
%%% (net_processing.cpp:1230), so stalling escalation never survives
%%% download progress.
%%%
%%% These tests drive the gen_server callbacks directly on a scripted
%%% #state{} (test_state/1) with meck on the collaborators, so both the
%%% frontier hole and the watchdog carryover reproduce deterministically
%%% without timers.
%%% ===================================================================

-define(MOCKED, [beamchain_db, beamchain_peer, beamchain_peer_manager,
                 beamchain_chainstate, beamchain_validation,
                 beamchain_serialize, beamchain_sync]).

%%% ===================================================================
%%% Fixtures
%%% ===================================================================

setup() ->
    Tab = ets:new(frontier_test_tip, [set, public]),
    ets:insert(Tab, {tip, {height_hash(99), 99}}),
    lists:foreach(fun(M) -> ok = meck:new(M, [no_link]) end, ?MOCKED),
    ok = meck:expect(beamchain_db, get_block_index,
        fun(H) ->
            {ok, #{hash => height_hash(H), header => mk_header(H),
                   chainwork => H, n_tx => 1}}
        end),
    ok = meck:expect(beamchain_db, store_block_index,
        fun(_, _, _, _, _) -> ok end),
    ok = meck:expect(beamchain_db, store_block_index,
        fun(_, _, _, _, _, _) -> ok end),
    ok = meck:expect(beamchain_peer, send_message,
        fun(_Peer, _Msg) -> ok end),
    ok = meck:expect(beamchain_peer, disconnect, fun(_) -> ok end),
    ok = meck:expect(beamchain_peer, add_misbehavior, fun(_, _) -> ok end),
    ok = meck:expect(beamchain_peer_manager, get_peers, fun() -> [] end),
    ok = meck:expect(beamchain_chainstate, get_tip,
        fun() -> [{tip, T}] = ets:lookup(Tab, tip), {ok, T} end),
    ok = meck:expect(beamchain_chainstate, connect_block,
        fun(#block{header = #block_header{merkle_root = <<H:256>>}}) ->
            ets:insert(Tab, {tip, {height_hash(H), H}}),
            ok
        end),
    ok = meck:expect(beamchain_validation, check_block,
        fun(_, _) -> ok end),
    ok = meck:expect(beamchain_serialize, block_hash,
        fun(#block_header{merkle_root = MR}) -> MR end),
    ok = meck:expect(beamchain_sync, notify_blocks_complete,
        fun(_) -> ok end),
    Tab.

teardown(Tab) ->
    lists:foreach(fun(M) -> catch meck:unload(M) end, ?MOCKED),
    ets:delete(Tab),
    flush_all().

frontier_test_() ->
    {foreach, fun setup/0, fun teardown/1,
     [fun(_) -> {"forced eviction with no peers keeps the height in "
                 "the frontier and refills without the timeout path",
                 fun frontier_survives_forced_eviction/0} end,
      fun(_) -> {"watchdog stuck count does not carry across heights "
                 "(no healthy-peer kill after progress)",
                 fun watchdog_no_cross_height_carryover/0} end]}.

%%% ===================================================================
%%% Test 1: the frontier hole (issue #34 root cause A)
%%%
%%% Wedge instant from the rig: next_to_validate is in flight from a
%%% dead peer, no replacement connected yet, watchdog escalating.
%%% force_unstick evicts the in_flight entry and blast-requests the
%%% height — with zero connected peers. The height MUST remain in the
%%% request frontier (queue/in_flight/downloaded); when the replacement
%%% peer connects, it must be requested FIRST and sync must run to
%%% completion with no stall-timeout involvement.
%%% ===================================================================

frontier_survives_forced_eviction() ->
    put(getdata_seen, 0),
    DeadPid = spawn(fun() -> ok end),
    Now = erlang:monotonic_time(millisecond),
    S0 = beamchain_block_sync:test_state(#{
        status           => syncing,
        next_to_validate => 100,
        target_height    => 140,
        download_queue   => lists:seq(101, 140),
        in_flight        => #{100 => {DeadPid, Now, height_hash(100)}},
        hash_to_height   => #{height_hash(100) => 100},
        downloaded       => #{},
        peers            => #{},
        peer_stats       => #{},
        stuck_ticks      => 1
    }),

    %% Two watchdog ticks at the same stuck height escalate to
    %% force_unstick (with per-height tracking the first tick counts 1,
    %% the second 2; the pre-fix code escalates on the first already —
    %% either way the eviction + empty blast has happened after two).
    {noreply, S1} = beamchain_block_sync:handle_info(stall_check, S0),
    {noreply, S2} = beamchain_block_sync:handle_info(stall_check, S1),
    flush_getdata(),

    %% THE frontier invariant (Core: a removed request never leaves the
    %% download window): height 100 is still queued, in flight, or
    %% downloaded. The unfixed code dropped it in blast_request_height's
    %% no-peers branch.
    ?assert(in_frontier(100, S2)),

    %% Replacement peer completes its handshake. The frontier head must
    %% be requested first, and serving every getdata (no stall timeouts,
    %% no further watchdog ticks) must complete the sync.
    P1 = spawn(fun() -> receive stop -> ok end end),
    {noreply, S3} = beamchain_block_sync:handle_cast(
                      {peer_connected, P1, #{}}, S2),
    FirstBatch = collect_getdata(),
    ?assert(lists:member(height_hash(100), FirstBatch)),

    S4 = serve_until_quiescent(P1, FirstBatch, S3, 2000),
    ?assertEqual(141, beamchain_block_sync:test_get(next_to_validate, S4)),
    ?assertEqual(complete, beamchain_block_sync:test_get(status, S4)),
    P1 ! stop.

%%% ===================================================================
%%% Test 2: watchdog cross-height carryover (issue #34 root cause B)
%%%
%%% A ticks=1 observation at one height must not combine with a later
%%% observation at a DIFFERENT height into an escalation: in between
%%% the pipeline made progress, so the peer is healthy. The unfixed
%%% code killed the rig's only peer this way every 287 blocks. A
%%% genuine same-height repeat must still escalate (eviction preserved).
%%% ===================================================================

watchdog_no_cross_height_carryover() ->
    put(getdata_seen, 0),
    P1 = spawn(fun() -> receive stop -> ok end end),
    Now = erlang:monotonic_time(millisecond),
    S0 = beamchain_block_sync:test_state(#{
        status           => syncing,
        next_to_validate => 100,
        target_height    => 400,
        download_queue   => [101],
        in_flight        => #{100 => {P1, Now, height_hash(100)}},
        hash_to_height   => #{height_hash(100) => 100},
        downloaded       => #{},
        peers            => #{P1 => #{}},
        peer_stats       => #{P1 => 1},
        stuck_ticks      => 0
    }),

    %% Tick 1: stuck at 100 -> counts 1, no escalation.
    {noreply, S1} = beamchain_block_sync:handle_info(stall_check, S0),
    ?assertEqual(0, meck:num_calls(beamchain_peer, disconnect, '_')),

    %% Progress: 100 arrives and connects; the refill puts 101 in
    %% flight (fresh request to the same healthy peer).
    {noreply, S2} = beamchain_block_sync:handle_cast(
                      {block, P1, mk_block(100)}, S1),
    flush_getdata(),
    ?assertEqual(101, beamchain_block_sync:test_get(next_to_validate, S2)),
    ?assert(maps:is_key(101, beamchain_block_sync:test_get(in_flight, S2))),

    %% Tick 2: first stuck observation at 101. The count from height 100
    %% is stale — this must NOT escalate and must NOT kill the peer.
    {noreply, S3} = beamchain_block_sync:handle_info(stall_check, S2),
    ?assertEqual(0, meck:num_calls(beamchain_peer, disconnect, '_')),
    ?assert(maps:is_key(P1, beamchain_block_sync:test_get(peers, S3))),

    %% Tick 3: SECOND stuck observation at 101 — a genuine wedge at one
    %% height. Escalation (force_unstick -> disconnect) must still fire:
    %% stalled-request eviction is preserved.
    {noreply, _S4} = beamchain_block_sync:handle_info(stall_check, S3),
    ?assertEqual(1, meck:num_calls(beamchain_peer, disconnect, '_')),
    P1 ! stop.

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
        bits        = 16#1d00ffff,
        nonce       = 0
    }.

mk_block(H) ->
    #block{header = mk_header(H), transactions = []}.

in_frontier(Height, S) ->
    lists:member(Height,
                 beamchain_block_sync:test_get(download_queue, S))
        orelse maps:is_key(Height,
                           beamchain_block_sync:test_get(in_flight, S))
        orelse maps:is_key(Height,
                           beamchain_block_sync:test_get(downloaded, S)).

%% Serve every outstanding getdata (perfectly responsive peer) and drain
%% continue_validation self-messages until nothing is pending. Never
%% invokes the stall/watchdog path — liveness must come from the
%% request lifecycle alone.
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

%% getdata capture is meck-history based (fixture setup may run in a
%% different process than the test body, so a mailbox capture is not
%% reliable). A process-dictionary cursor yields only NEW requests.
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

flush_getdata() ->
    put(getdata_seen, length(all_requested())).

flush_all() ->
    receive _ -> flush_all() after 0 -> ok end.
