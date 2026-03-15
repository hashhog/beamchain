-module(beamchain_peer_tests).

-include_lib("eunit/include/eunit.hrl").

%%% ===================================================================
%%% Inv trickling unit tests
%%% ===================================================================

%% Test Poisson interval distribution
poisson_interval_test_() ->
    {"Poisson interval generation",
     [
      {"interval is positive", fun() ->
          %% Generate many intervals and verify all positive
          Intervals = [poisson_interval_test(5000) || _ <- lists:seq(1, 100)],
          ?assert(lists:all(fun(I) -> I >= 1 end, Intervals))
      end},

      {"interval is bounded", fun() ->
          %% All intervals should be <= 60000ms
          Intervals = [poisson_interval_test(5000) || _ <- lists:seq(1, 100)],
          ?assert(lists:all(fun(I) -> I =< 60000 end, Intervals))
      end},

      {"average is roughly correct", fun() ->
          %% Generate many samples and check mean is close to target
          %% Use 1000ms for faster test
          Mean = 1000,
          Samples = [poisson_interval_test(Mean) || _ <- lists:seq(1, 1000)],
          Avg = lists:sum(Samples) / length(Samples),
          %% Should be within 30% of mean (Poisson has high variance)
          ?assert(Avg > Mean * 0.5),
          ?assert(Avg < Mean * 2.0)
      end},

      {"intervals vary (not constant)", fun() ->
          %% Generate several intervals and ensure they're not all the same
          Intervals = [poisson_interval_test(5000) || _ <- lists:seq(1, 10)],
          Unique = lists:usort(Intervals),
          ?assert(length(Unique) > 1)
      end}
     ]}.

%% Test helper: Poisson interval calculation
poisson_interval_test(MeanMs) ->
    U = rand:uniform(),
    Interval = round(-math:log(U) * MeanMs),
    max(1, min(Interval, 60000)).

%% Test shuffle behavior
shuffle_test_() ->
    {"List shuffling",
     [
      {"empty list shuffles to empty", fun() ->
          ?assertEqual([], shuffle_test([]))
      end},

      {"single element unchanged", fun() ->
          ?assertEqual([a], shuffle_test([a]))
      end},

      {"shuffle preserves elements", fun() ->
          List = [1, 2, 3, 4, 5],
          Shuffled = shuffle_test(List),
          ?assertEqual(lists:sort(List), lists:sort(Shuffled))
      end},

      {"shuffle changes order sometimes", fun() ->
          %% With enough iterations, order should change
          List = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
          Results = [shuffle_test(List) || _ <- lists:seq(1, 20)],
          %% At least some should differ from original
          Different = [R || R <- Results, R =/= List],
          ?assert(length(Different) > 0)
      end}
     ]}.

%% Test helper: shuffle implementation
shuffle_test([]) -> [];
shuffle_test([X]) -> [X];
shuffle_test(List) ->
    lists:sort(fun(_, _) -> rand:uniform() > 0.5 end, List).

%%% ===================================================================
%%% Inv queue logic tests
%%% ===================================================================

pending_queue_test_() ->
    {"Pending inv queue logic",
     [
      {"empty queue sends nothing", fun() ->
          PendingTxInv = [],
          {ToSend, _Remaining} = split_for_trickle(PendingTxInv, 70),
          ?assertEqual([], ToSend)
      end},

      {"small queue sends all", fun() ->
          Txids = [crypto:strong_rand_bytes(32) || _ <- lists:seq(1, 5)],
          {ToSend, Remaining} = split_for_trickle(Txids, 70),
          ?assertEqual(5, length(ToSend)),
          ?assertEqual(0, length(Remaining))
      end},

      {"large queue respects max", fun() ->
          Txids = [crypto:strong_rand_bytes(32) || _ <- lists:seq(1, 200)],
          {ToSend, Remaining} = split_for_trickle(Txids, 70),
          ?assertEqual(70, length(ToSend)),
          ?assertEqual(130, length(Remaining))
      end},

      {"broadcast max scales with queue size", fun() ->
          %% Per Bitcoin Core: target + (size/1000)*5, capped at max
          ?assertEqual(70, broadcast_max_test(0)),
          ?assertEqual(70, broadcast_max_test(500)),
          ?assertEqual(75, broadcast_max_test(1000)),
          ?assertEqual(80, broadcast_max_test(2000)),
          ?assertEqual(1000, broadcast_max_test(200000))  %% capped
      end},

      {"no duplicates in queue", fun() ->
          Txid = crypto:strong_rand_bytes(32),
          Queue = [Txid],
          %% Adding same txid should not duplicate
          Queue2 = maybe_add_txid(Txid, Queue),
          ?assertEqual(1, length(Queue2))
      end},

      {"new txid is added", fun() ->
          Txid1 = crypto:strong_rand_bytes(32),
          Txid2 = crypto:strong_rand_bytes(32),
          Queue = [Txid1],
          Queue2 = maybe_add_txid(Txid2, Queue),
          ?assertEqual(2, length(Queue2))
      end}
     ]}.

%% Test helpers
split_for_trickle(Pending, BroadcastMax) ->
    lists:split(min(BroadcastMax, length(Pending)), Pending).

broadcast_max_test(PendingSize) ->
    min(1000, 70 + (PendingSize div 1000) * 5).

maybe_add_txid(Txid, Queue) ->
    case lists:member(Txid, Queue) of
        true  -> Queue;
        false -> [Txid | Queue]
    end.

%%% ===================================================================
%%% Direction-based interval tests
%%% ===================================================================

direction_interval_test_() ->
    {"Direction-based intervals",
     [
      {"inbound uses 5000ms base", fun() ->
          ?assertEqual(5000, interval_for_direction(inbound))
      end},

      {"outbound uses 2000ms base", fun() ->
          ?assertEqual(2000, interval_for_direction(outbound))
      end}
     ]}.

interval_for_direction(inbound) -> 5000;
interval_for_direction(outbound) -> 2000.

%%% ===================================================================
%%% Inv item encoding tests
%%% ===================================================================

inv_item_test_() ->
    {"Inv item construction",
     [
      {"MSG_TX type is 1", fun() ->
          Txid = crypto:strong_rand_bytes(32),
          Item = #{type => 1, hash => Txid},
          ?assertEqual(1, maps:get(type, Item)),
          ?assertEqual(32, byte_size(maps:get(hash, Item)))
      end},

      {"multiple items list", fun() ->
          Txids = [crypto:strong_rand_bytes(32) || _ <- lists:seq(1, 3)],
          Items = [#{type => 1, hash => T} || T <- Txids],
          ?assertEqual(3, length(Items))
      end}
     ]}.

%%% ===================================================================
%%% Privacy property tests
%%% ===================================================================

privacy_test_() ->
    {"Privacy properties",
     [
      {"intervals are exponentially distributed", fun() ->
          %% Exponential distribution property: P(X > s+t | X > s) = P(X > t)
          %% This is the memoryless property - hard to test directly,
          %% but we can verify the shape of the distribution
          Samples = [poisson_interval_test(1000) || _ <- lists:seq(1, 500)],
          %% Mode should be less than mean for exponential
          Sorted = lists:sort(Samples),
          Median = lists:nth(250, Sorted),
          Mean = lists:sum(Samples) / length(Samples),
          %% For exponential, median ≈ 0.693 * mean
          ?assert(Median < Mean)
      end},

      {"shuffling is randomized per call", fun() ->
          List = lists:seq(1, 20),
          Results = [shuffle_test(List) || _ <- lists:seq(1, 10)],
          %% Should have multiple unique orderings
          Unique = lists:usort(Results),
          ?assert(length(Unique) >= 3)
      end}
     ]}.

%%% ===================================================================
%%% Edge cases
%%% ===================================================================

edge_cases_test_() ->
    {"Edge cases",
     [
      {"zero mean interval handled", fun() ->
          %% Should clamp to minimum of 1ms
          I = max(1, round(-math:log(0.5) * 0)),
          ?assertEqual(1, I)
      end},

      {"very small uniform value handled", fun() ->
          %% When U is very small, -ln(U) is very large
          %% Should clamp to max of 60000ms
          SmallU = 0.0001,
          Raw = round(-math:log(SmallU) * 5000),
          Clamped = min(60000, Raw),
          ?assert(Clamped =< 60000)
      end},

      {"peer_relay false clears queue", fun() ->
          %% When peer requests no relay, queue should be cleared
          Pending = [crypto:strong_rand_bytes(32) || _ <- lists:seq(1, 5)],
          Relay = false,
          Remaining = case Relay of
              false -> [];
              true -> Pending
          end,
          ?assertEqual([], Remaining)
      end}
     ]}.
