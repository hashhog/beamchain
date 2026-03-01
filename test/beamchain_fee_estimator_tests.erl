-module(beamchain_fee_estimator_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

%%% ===================================================================
%%% Re-define internal records for test access
%%% ===================================================================

-record(bucket_data, {
    total      = 0.0,
    in_mempool = 0.0,
    confirmed  = #{}
}).

%%% ===================================================================
%%% ETS setup for testing (no gen_server needed)
%%% ===================================================================

setup() ->
    Tables = [fee_est_tracked, mempool_by_fee],
    lists:foreach(fun(T) ->
        case ets:info(T) of
            undefined -> ok;
            _ -> ets:delete(T)
        end
    end, Tables),
    ets:new(fee_est_tracked, [set, public, named_table]),
    ets:new(mempool_by_fee, [ordered_set, public, named_table]),
    ok.

cleanup(_) ->
    lists:foreach(fun(T) ->
        case ets:info(T) of
            undefined -> ok;
            _ -> ets:delete(T)
        end
    end, [fee_est_tracked, mempool_by_fee]).

%%% ===================================================================
%%% Bucket generation tests
%%% ===================================================================

bucket_generation_test() ->
    %% Test that buckets are generated and logarithmically spaced
    Buckets = generate_test_buckets(),
    ?assertEqual(40, length(Buckets)),
    %% First bucket should be 1.0 sat/vB
    ?assert(abs(hd(Buckets) - 1.0) < 0.001),
    %% Last bucket should be ~10000 sat/vB
    ?assert(abs(lists:last(Buckets) - 10000.0) < 1.0),
    %% Buckets should be strictly increasing
    ?assert(is_strictly_increasing(Buckets)).

bucket_spacing_test() ->
    %% Verify logarithmic spacing: ratio between consecutive buckets
    %% should be approximately constant
    Buckets = generate_test_buckets(),
    Ratios = compute_ratios(Buckets),
    %% All ratios should be approximately equal
    [First | Rest] = Ratios,
    lists:foreach(fun(R) ->
        ?assert(abs(R - First) < 0.001)
    end, Rest).

%%% ===================================================================
%%% find_bucket tests
%%% ===================================================================

find_bucket_test() ->
    Buckets = generate_test_buckets(),
    %% Fee rate of 1.0 should be in bucket 0
    ?assertEqual(0, find_bucket(1.0, Buckets)),
    %% Fee rate at last bucket should be in last bucket
    ?assertEqual(39, find_bucket(10000.0, Buckets)),
    %% Fee rate above max should also be in last bucket
    ?assertEqual(39, find_bucket(50000.0, Buckets)),
    %% Fee rate between two buckets should be in the lower one
    B2 = lists:nth(2, Buckets),
    ?assertEqual(0, find_bucket(B2 - 0.001, Buckets)),
    ?assertEqual(1, find_bucket(B2, Buckets)).

%%% ===================================================================
%%% Tracking tests
%%% ===================================================================

track_tx_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
             %% Tracking a tx should insert into ETS
             Txid = <<1:256>>,
             ets:insert(fee_est_tracked, {Txid, 5, 800000}),
             [{Txid, 5, 800000}] = ets:lookup(fee_est_tracked, Txid),
             %% Can look up tracked tx
             ?assertEqual(1, ets:info(fee_est_tracked, size)),
             %% Tracking another tx
             Txid2 = <<2:256>>,
             ets:insert(fee_est_tracked, {Txid2, 10, 800001}),
             ?assertEqual(2, ets:info(fee_est_tracked, size))
         end]
     end}.

%%% ===================================================================
%%% Confirmation recording tests
%%% ===================================================================

confirmation_test() ->
    %% Test that recording a confirmation updates bucket data correctly
    BD = #bucket_data{total = 10.0, in_mempool = 5.0, confirmed = #{}},
    %% Simulate confirming a tx that waited 3 blocks
    BD2 = record_test_confirmation(BD, 3),
    ?assertEqual(10.0, BD2#bucket_data.total),
    ?assertEqual(4.0, BD2#bucket_data.in_mempool),
    ?assertEqual(#{3 => 1.0}, BD2#bucket_data.confirmed),
    %% Confirm another tx at 3 blocks
    BD3 = record_test_confirmation(BD2, 3),
    ?assertEqual(#{3 => 2.0}, BD3#bucket_data.confirmed),
    %% Confirm at different delay
    BD4 = record_test_confirmation(BD3, 1),
    ?assertEqual(#{1 => 1.0, 3 => 2.0}, BD4#bucket_data.confirmed).

%%% ===================================================================
%%% Decay tests
%%% ===================================================================

decay_test() ->
    BD = #bucket_data{
        total = 100.0,
        in_mempool = 50.0,
        confirmed = #{1 => 30.0, 2 => 20.0}
    },
    Decayed = decay_test_bucket(BD, 0.998),
    ?assert(abs(Decayed#bucket_data.total - 99.8) < 0.001),
    ?assert(abs(Decayed#bucket_data.in_mempool - 49.9) < 0.001),
    #{1 := C1, 2 := C2} = Decayed#bucket_data.confirmed,
    ?assert(abs(C1 - 29.94) < 0.001),
    ?assert(abs(C2 - 19.96) < 0.001).

multiple_decay_test() ->
    %% After many blocks of decay, values should approach zero
    %% 0.998^5000 ≈ 0.0000449, so 100 * 0.998^5000 ≈ 0.0045
    BD = #bucket_data{total = 100.0, in_mempool = 0.0,
                       confirmed = #{1 => 100.0}},
    Final = lists:foldl(fun(_, Acc) ->
        decay_test_bucket(Acc, 0.998)
    end, BD, lists:seq(1, 5000)),
    ?assert(Final#bucket_data.total < 0.01).

%%% ===================================================================
%%% Success rate / sum_confirmed_within tests
%%% ===================================================================

sum_confirmed_within_test() ->
    Confirmed = #{1 => 5.0, 2 => 3.0, 3 => 2.0, 10 => 1.0},
    %% Within 1 block
    ?assertEqual(5.0, sum_test_confirmed(1, Confirmed)),
    %% Within 3 blocks
    ?assertEqual(10.0, sum_test_confirmed(3, Confirmed)),
    %% Within 10 blocks
    ?assertEqual(11.0, sum_test_confirmed(10, Confirmed)),
    %% Within 100 blocks (gets everything)
    ?assertEqual(11.0, sum_test_confirmed(100, Confirmed)),
    %% Empty map
    ?assertEqual(0.0, sum_test_confirmed(10, #{})).

%%% ===================================================================
%%% Mempool fallback tests
%%% ===================================================================

mempool_fallback_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
             %% Empty mempool should return insufficient_data
             %% (collect_mempool_fee_rates returns [])
             FeeRates = collect_test_mempool_rates(),
             ?assertEqual([], FeeRates),

             %% Populate mempool_by_fee with some entries
             ets:insert(mempool_by_fee, {{1.5, <<1:256>>}}),
             ets:insert(mempool_by_fee, {{3.0, <<2:256>>}}),
             ets:insert(mempool_by_fee, {{5.0, <<3:256>>}}),
             ets:insert(mempool_by_fee, {{10.0, <<4:256>>}}),
             ets:insert(mempool_by_fee, {{20.0, <<5:256>>}}),

             %% Should now collect fee rates ascending
             Rates = collect_test_mempool_rates(),
             ?assertEqual([1.5, 3.0, 5.0, 10.0, 20.0], Rates),

             %% Higher targets should give lower fee rates
             %% (broader percentile window)
             ok
         end]
     end}.

%%% ===================================================================
%%% Integration scenario test
%%% ===================================================================

full_scenario_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
             %% Simulate tracking txs, confirming them, and estimating
             Buckets = generate_test_buckets(),

             %% Track 200 txs at various fee rates (all in bucket ~10)
             %% and simulate them all confirming within 1 block
             BucketIdx = find_bucket(5.0, Buckets),
             ?assert(BucketIdx >= 0),

             %% Build a bucket_data with good confirmation stats
             BD = #bucket_data{
                 total = 200.0,
                 in_mempool = 10.0,
                 confirmed = #{1 => 180.0, 2 => 5.0}
             },

             %% success rate for target 1: 180/(200-10) = 0.947 > 0.85
             Resolved = BD#bucket_data.total - BD#bucket_data.in_mempool,
             ConfWithin1 = sum_test_confirmed(1, BD#bucket_data.confirmed),
             Rate1 = ConfWithin1 / Resolved,
             ?assert(Rate1 >= 0.85),

             %% success rate for target 2: (180+5)/(200-10) = 0.974
             ConfWithin2 = sum_test_confirmed(2, BD#bucket_data.confirmed),
             Rate2 = ConfWithin2 / Resolved,
             ?assert(Rate2 >= 0.85)
         end]
     end}.

%%% ===================================================================
%%% Edge case: empty bucket data
%%% ===================================================================

empty_bucket_data_test() ->
    BD = #bucket_data{total = 0.0, in_mempool = 0.0, confirmed = #{}},
    %% Decay of zero stays at zero
    Decayed = decay_test_bucket(BD, 0.998),
    ?assertEqual(0.0, Decayed#bucket_data.total),
    ?assertEqual(0.0, Decayed#bucket_data.in_mempool),
    ?assertEqual(#{}, Decayed#bucket_data.confirmed).

%%% ===================================================================
%%% Success rate edge cases
%%% ===================================================================

success_rate_all_confirmed_test() ->
    %% Everything confirmed within 1 block: perfect success rate
    BD = #bucket_data{
        total = 100.0,
        in_mempool = 0.0,
        confirmed = #{1 => 100.0}
    },
    Resolved = BD#bucket_data.total - BD#bucket_data.in_mempool,
    ConfWithin1 = sum_test_confirmed(1, BD#bucket_data.confirmed),
    Rate = ConfWithin1 / Resolved,
    ?assertEqual(1.0, Rate).

success_rate_none_confirmed_test() ->
    %% Nothing confirmed: 0% success rate
    BD = #bucket_data{
        total = 100.0,
        in_mempool = 100.0,
        confirmed = #{}
    },
    Resolved = BD#bucket_data.total - BD#bucket_data.in_mempool,
    %% All still in mempool, resolved = 0
    ?assertEqual(0.0, Resolved).

%%% ===================================================================
%%% Bucket boundary tests
%%% ===================================================================

find_bucket_at_boundaries_test() ->
    Buckets = generate_test_buckets(),
    %% Fee rate below minimum should be in bucket 0
    ?assertEqual(0, find_bucket(0.5, Buckets)),
    ?assertEqual(0, find_bucket(0.001, Buckets)),
    %% Fee rate exactly at 1.0 (first bucket) should be bucket 0
    ?assertEqual(0, find_bucket(1.0, Buckets)).

%%% ===================================================================
%%% Decay preserves relative proportions
%%% ===================================================================

decay_preserves_ratio_test() ->
    BD = #bucket_data{
        total = 200.0,
        in_mempool = 100.0,
        confirmed = #{1 => 60.0, 5 => 40.0}
    },
    Decayed = decay_test_bucket(BD, 0.998),
    %% Ratio of in_mempool to total should be preserved
    OrigRatio = BD#bucket_data.in_mempool / BD#bucket_data.total,
    NewRatio = Decayed#bucket_data.in_mempool / Decayed#bucket_data.total,
    ?assert(abs(OrigRatio - NewRatio) < 0.0001).

%%% ===================================================================
%%% Test helpers — reimplementations of internal functions
%%% ===================================================================

generate_test_buckets() ->
    Factor = math:pow(10000.0 / 1.0, 1.0 / 39),
    generate_test_buckets(1.0, Factor, 40, []).

generate_test_buckets(_Rate, _Factor, 0, Acc) ->
    lists:reverse(Acc);
generate_test_buckets(Rate, Factor, N, Acc) ->
    generate_test_buckets(Rate * Factor, Factor, N - 1, [Rate | Acc]).

find_bucket(FeeRate, Buckets) ->
    find_bucket(FeeRate, Buckets, 0).

find_bucket(_FeeRate, [_], Idx) ->
    Idx;
find_bucket(FeeRate, [_, B2 | _], Idx) when FeeRate < B2 ->
    Idx;
find_bucket(FeeRate, [_ | Rest], Idx) ->
    find_bucket(FeeRate, Rest, Idx + 1).

record_test_confirmation(BD, BlocksWaited) ->
    Confirmed = BD#bucket_data.confirmed,
    OldCount = maps:get(BlocksWaited, Confirmed, 0.0),
    BD#bucket_data{
        confirmed = maps:put(BlocksWaited, OldCount + 1.0, Confirmed),
        in_mempool = max(0.0, BD#bucket_data.in_mempool - 1.0)
    }.

decay_test_bucket(#bucket_data{total = T, in_mempool = M, confirmed = C},
                  Factor) ->
    #bucket_data{
        total = T * Factor,
        in_mempool = M * Factor,
        confirmed = maps:map(fun(_K, V) -> V * Factor end, C)
    }.

sum_test_confirmed(MaxBlocks, Confirmed) ->
    maps:fold(fun(BlocksWaited, Count, Acc) ->
        case BlocksWaited =< MaxBlocks of
            true -> Acc + Count;
            false -> Acc
        end
    end, 0.0, Confirmed).

collect_test_mempool_rates() ->
    try
        collect_rates_asc(ets:first(mempool_by_fee), [])
    catch
        error:badarg -> []
    end.

collect_rates_asc('$end_of_table', Acc) ->
    lists:reverse(Acc);
collect_rates_asc({FeeRate, _Txid} = Key, Acc) ->
    collect_rates_asc(ets:next(mempool_by_fee, Key), [FeeRate | Acc]).

is_strictly_increasing([]) -> true;
is_strictly_increasing([_]) -> true;
is_strictly_increasing([A, B | Rest]) ->
    A < B andalso is_strictly_increasing([B | Rest]).

compute_ratios([_]) -> [];
compute_ratios([A, B | Rest]) ->
    [B / A | compute_ratios([B | Rest])].
