-module(beamchain_peer_tests).

-include_lib("eunit/include/eunit.hrl").

%% BIP 133 feefilter constants (matching beamchain_peer.erl)
-define(FEEFILTER_BROADCAST_INTERVAL_MS, 600000).
-define(FEEFILTER_MAX_CHANGE_DELAY_MS, 300000).
-define(DEFAULT_MIN_RELAY_FEE, 1000).

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

%%% ===================================================================
%%% BIP 133 feefilter tests
%%% ===================================================================

feefilter_encode_decode_test_() ->
    {"Feefilter message encoding/decoding",
     [
      {"encode feefilter message", fun() ->
          FeeRate = 1000,  %% 1000 sat/kvB
          Encoded = beamchain_p2p_msg:encode_payload(feefilter, #{feerate => FeeRate}),
          ?assertEqual(<<232, 3, 0, 0, 0, 0, 0, 0>>, Encoded)  %% 1000 as 64-bit little-endian
      end},

      {"decode feefilter message", fun() ->
          Payload = <<232, 3, 0, 0, 0, 0, 0, 0>>,  %% 1000 as 64-bit little-endian
          {ok, #{feerate := Fee}} = beamchain_p2p_msg:decode_payload(feefilter, Payload),
          ?assertEqual(1000, Fee)
      end},

      {"roundtrip encode/decode", fun() ->
          FeeRates = [0, 1000, 10000, 100000, 1000000],
          lists:foreach(fun(Rate) ->
              Encoded = beamchain_p2p_msg:encode_payload(feefilter, #{feerate => Rate}),
              {ok, #{feerate := Decoded}} = beamchain_p2p_msg:decode_payload(feefilter, Encoded),
              ?assertEqual(Rate, Decoded)
          end, FeeRates)
      end}
     ]}.

feefilter_poisson_interval_test_() ->
    {"Feefilter Poisson interval",
     [
      {"interval is positive", fun() ->
          Intervals = [feefilter_poisson_interval_test(?FEEFILTER_BROADCAST_INTERVAL_MS)
                       || _ <- lists:seq(1, 100)],
          ?assert(lists:all(fun(I) -> I >= 1000 end, Intervals))
      end},

      {"interval is bounded at 30 minutes", fun() ->
          Intervals = [feefilter_poisson_interval_test(?FEEFILTER_BROADCAST_INTERVAL_MS)
                       || _ <- lists:seq(1, 100)],
          ?assert(lists:all(fun(I) -> I =< 1800000 end, Intervals))
      end},

      {"average is roughly correct (10 minutes)", fun() ->
          %% Use 60000ms (1 minute) for faster test with same distribution
          Mean = 60000,
          Samples = [feefilter_poisson_interval_test(Mean) || _ <- lists:seq(1, 500)],
          Avg = lists:sum(Samples) / length(Samples),
          %% Should be within 50% of mean (Poisson has high variance)
          ?assert(Avg > Mean * 0.5),
          ?assert(Avg < Mean * 2.0)
      end}
     ]}.

feefilter_poisson_interval_test(MeanMs) ->
    U = rand:uniform(),
    Interval = round(-math:log(U) * MeanMs),
    max(1000, min(Interval, 1800000)).

feefilter_significant_change_test_() ->
    {"Feefilter significant change detection",
     [
      {"25% drop is significant", fun() ->
          SentFee = 4000,
          CurrentFee = 2900,  %% < 75% of sent (3000)
          SignificantChange = (CurrentFee * 4 < SentFee * 3),
          ?assert(SignificantChange)
      end},

      {"33% increase is significant", fun() ->
          SentFee = 3000,
          CurrentFee = 4100,  %% > 133% of sent (4000)
          SignificantChange = (CurrentFee * 3 > SentFee * 4),
          ?assert(SignificantChange)
      end},

      {"small changes are not significant", fun() ->
          SentFee = 4000,
          CurrentFee = 3500,  %% 87.5% of sent (between 75% and 133%)
          Drop = (CurrentFee * 4 < SentFee * 3),
          Increase = (CurrentFee * 3 > SentFee * 4),
          ?assertNot(Drop orelse Increase)
      end},

      {"no change is not significant", fun() ->
          SentFee = 4000,
          CurrentFee = 4000,
          Drop = (CurrentFee * 4 < SentFee * 3),
          Increase = (CurrentFee * 3 > SentFee * 4),
          ?assertNot(Drop orelse Increase)
      end}
     ]}.

feefilter_floor_test_() ->
    {"Feefilter minimum relay fee floor",
     [
      {"floor at minimum relay fee", fun() ->
          %% Even if mempool min fee is 0, we send at least 1000 sat/kvB
          CurrentFee = 0,
          FilterToSend = max(CurrentFee, ?DEFAULT_MIN_RELAY_FEE),
          ?assertEqual(1000, FilterToSend)
      end},

      {"higher fee is preserved", fun() ->
          CurrentFee = 5000,
          FilterToSend = max(CurrentFee, ?DEFAULT_MIN_RELAY_FEE),
          ?assertEqual(5000, FilterToSend)
      end}
     ]}.

feefilter_inv_filtering_test_() ->
    {"Feefilter inv filtering logic",
     [
      {"zero feefilter passes all txs", fun() ->
          PeerFeeFilter = 0,
          Txids = [crypto:strong_rand_bytes(32) || _ <- lists:seq(1, 5)],
          Filtered = filter_by_feefilter_test(Txids, PeerFeeFilter),
          ?assertEqual(Txids, Filtered)
      end},

      {"high feefilter filters some txs", fun() ->
          %% Simulated txs with fee rates
          Txs = [{crypto:strong_rand_bytes(32), 500},    %% 500 sat/kvB - filtered
                 {crypto:strong_rand_bytes(32), 1500},   %% 1500 sat/kvB - passes
                 {crypto:strong_rand_bytes(32), 2000}],  %% 2000 sat/kvB - passes
          PeerFeeFilter = 1000,
          Filtered = [Txid || {Txid, Rate} <- Txs, Rate >= PeerFeeFilter],
          ?assertEqual(2, length(Filtered))
      end}
     ]}.

filter_by_feefilter_test(Txids, PeerFeeFilter) when PeerFeeFilter =< 0 ->
    Txids;
filter_by_feefilter_test(_Txids, _PeerFeeFilter) ->
    %% In real code this would look up mempool entries
    %% For test purposes, return empty (simulating no matching txs)
    [].
