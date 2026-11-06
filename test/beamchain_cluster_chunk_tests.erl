%%% Chunk values must come from the feerate-diagram-optimal linearization
%%% (Core v31 cluster_linearize.h: the first chunk is the highest-feerate
%%% topologically closed set, not just the best single-tx ancestor set).
-module(beamchain_cluster_chunk_tests).
-include_lib("eunit/include/eunit.hrl").

-define(P, <<10:256>>).
-define(C1, <<11:256>>).
-define(C2, <<12:256>>).
-define(C3, <<13:256>>).

%% Zero-fee parent with three equal children.  Ancestor sets only reach
%% {P,Ci} at 0.30; the closed set {P,C1,C2,C3} is 180/400 = 0.45, so Core
%% puts the whole cluster in ONE chunk.
star_children_merge_into_one_chunk_test() ->
    Nodes = #{?P  => {0,  100, []},
              ?C1 => {60, 100, [?P]},
              ?C2 => {60, 100, [?P]},
              ?C3 => {60, 100, [?P]}},
    [?assertEqual({400, 180}, beamchain_mempool_chunks:chunk_of(T, Nodes))
     || T <- [?P, ?C1, ?C2, ?C3]].

%% Two rich children and one poor one: {P,C1,C2} = 200/300 beats adding the
%% poor child; the poor child is a chunk of its own afterwards.
star_poor_child_stays_separate_test() ->
    Nodes = #{?P  => {0,   100, []},
              ?C1 => {100, 100, [?P]},
              ?C2 => {100, 100, [?P]},
              ?C3 => {1,   100, [?P]}},
    ?assertEqual({300, 200}, beamchain_mempool_chunks:chunk_of(?P, Nodes)),
    ?assertEqual({300, 200}, beamchain_mempool_chunks:chunk_of(?C2, Nodes)),
    ?assertEqual({100, 1},   beamchain_mempool_chunks:chunk_of(?C3, Nodes)).

%% A 64-child star like the harness's warden_e cluster: one chunk of all 65.
star_64_children_one_chunk_test() ->
    Kids = [<<(100 + I):256>> || I <- lists:seq(1, 64)],
    Nodes = maps:from_list(
        [{?P, {0, 100, []}}
         | [{K, {60, 100, [?P]}} || K <- Kids]]),
    TotalFee = 64 * 60,
    ?assertEqual({6500, TotalFee},
                 beamchain_mempool_chunks:chunk_of(lists:last(Kids), Nodes)).
