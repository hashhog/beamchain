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
