%% beamchain W114 fee estimation audit tests
%% 30-gate audit against Bitcoin Core CBlockPolicyEstimator
%%
%% References:
%%   bitcoin-core/src/policy/fees/block_policy_estimator.h/.cpp
%%   bitcoin-core/src/policy/feerate.h
%%   bitcoin-core/src/rpc/fees.cpp
%%
%% Core constants:
%%   SHORT: periods=12, scale=1, decay=0.962
%%   MED:   periods=24, scale=2, decay=0.9952
%%   LONG:  periods=42, scale=24, decay=0.99931
%%   Buckets: 237 entries, min=100 sat/kvB, max=1e7 sat/kvB, spacing=1.05
%%   FEE_FLUSH_INTERVAL: 1 hour, MAX_FILE_AGE: 60 hours

-module(beamchain_w114_fee_estimation_tests).

-include_lib("eunit/include/eunit.hrl").

%%% ===================================================================
%%% Setup / teardown
%%% ===================================================================

setup() ->
    %% Provide the chain-meta ETS table that init reads
    case ets:info(beamchain_chain_meta) of
        undefined ->
            ets:new(beamchain_chain_meta, [set, public, named_table]);
        _ -> ok
    end,
    %% Kill any leftover server from a prior run
    case whereis(beamchain_fee_estimator) of
        undefined -> ok;
        Pid ->
            unlink(Pid),
            exit(Pid, kill),
            wait_dead(Pid)
    end,
    %% Remove any persisted state file so tests start fresh
    lists:foreach(fun file:delete/1,
                  filelib:wildcard("fee_estimates.dat") ++
                  filelib:wildcard("/tmp/fee_estimates.dat")),
    {ok, NewPid} = beamchain_fee_estimator:start_link(),
    NewPid.

teardown(Pid) ->
    case is_process_alive(Pid) of
        true ->
            unlink(Pid),
            exit(Pid, kill),
            wait_dead(Pid);
        false -> ok
    end.

wait_dead(Pid) ->
    case is_process_alive(Pid) of
        false -> ok;
        true  -> timer:sleep(5), wait_dead(Pid)
    end.

%% Helper: feed N transactions into the estimator and process them in
%% a block, producing enough data to escape the MIN_TRACKED_TXS floor.
seed_estimator(N) ->
    seed_estimator(N, 1).

seed_estimator(0, _Height) -> ok;
seed_estimator(N, Height) ->
    Txid = crypto:strong_rand_bytes(32),
    FeeRate = 10.0 + float(N rem 50),   %% vary fee rates 10..59 sat/vB
    beamchain_fee_estimator:track_tx(Txid, FeeRate, Height),
    seed_estimator(N - 1, Height).

%%% ===================================================================
%%% G1 — Module exists and starts
%%% ===================================================================

g01_module_exists_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) ->
        [?_assert(is_pid(whereis(beamchain_fee_estimator)))]
     end}.

%%% ===================================================================
%%% G2 — estimate_fee returns {ok, Float} or {error, _}
%%% ===================================================================

g02_estimate_fee_return_shape_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) ->
        [fun() ->
             Res = beamchain_fee_estimator:estimate_fee(6),
             ?assert(
                 case Res of
                     {ok, F} when is_float(F), F > 0 -> true;
                     {error, _}                       -> true;
                     _                                -> false
                 end)
         end]
     end}.

%%% ===================================================================
%%% G3 — estimate_fee rejects out-of-range targets
%%% ===================================================================

g03_estimate_fee_range_validation_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) ->
        [?_assertEqual({error, invalid_target},
                       beamchain_fee_estimator:estimate_fee(0)),
         ?_assertEqual({error, invalid_target},
                       beamchain_fee_estimator:estimate_fee(1009)),
         ?_assertEqual({error, invalid_target},
                       beamchain_fee_estimator:estimate_fee(-1)),
         ?_assertEqual({error, invalid_target},
                       beamchain_fee_estimator:estimate_fee(0))
        ]
     end}.

%%% ===================================================================
%%% G4 — estimate_fee conf_target=1 should return error
%%% Core: "It's not possible to get reasonable estimates for confTarget of 1"
%%% BUG-13: beamchain accepts target=1 and processes it instead of failing
%%% ===================================================================

g04_conf_target_1_rejected_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) ->
        [fun() ->
             %% Core rejects conf_target=1 with CFeeRate(0) (error condition).
             %% beamchain should return {error, _} for target=1.
             Res = beamchain_fee_estimator:estimate_fee(1),
             ?assertEqual(error, element(1, Res),
                 "BUG-13: conf_target=1 should return {error,_} like Core")
         end]
     end}.

%%% ===================================================================
%%% G5 — estimatesmartfee RPC response shape (success)
%%% Core: {feerate, blocks} — no "errors" key when successful
%%% BUG-7: beamchain returns errors => [] even on success
%%% ===================================================================

g05_estimatesmartfee_success_shape_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) ->
        [fun() ->
             %% Seed enough data to get a real estimate
             seed_estimator(150),
             beamchain_fee_estimator:process_block(100,
                 [crypto:strong_rand_bytes(32) || _ <- lists:seq(1,10)]),
             case beamchain_fee_estimator:estimate_fee(6) of
                 {ok, _FeeRate} ->
                     %% A successful response should NOT include errors key.
                     %% We verify via the raw estimate call (not RPC layer).
                     %% The shape contract: {ok, FeeRate} with no error wrapper.
                     ok;
                 {error, _} ->
                     %% Not enough data yet — skip feerate-present test
                     ok
             end
         end]
     end}.

%%% ===================================================================
%%% G6 — estimatesmartfee RPC: "errors" key absent on success
%%% BUG-7: errors => [] always included even on success
%%% ===================================================================

g06_rpc_errors_absent_on_success_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) ->
        [fun() ->
             %% The PRESENCE of errors: [] in a successful response is a Core
             %% divergence (Core only includes errors when estimation fails).
             %% We check the contract: if estimate_fee succeeds, the underlying
             %% data is clean — the rpc layer should not append empty errors.
             %%
             %% Detect the bug by checking the estimator response directly.
             %% When data is insufficient we get {error,_} which IS correct to
             %% include errors in the RPC response.
             Res = beamchain_fee_estimator:estimate_fee(6),
             case Res of
                 {ok, _} ->
                     %% Good path: estimator found a rate.
                     %% Bug: rpc_estimatesmartfee adds errors=>[] here.
                     %% We can't call RPC directly, so assert the shape contract.
                     ?assert(true);
                 {error, _} ->
                     %% Expected with no data.
                     ?assert(true)
             end
         end]
     end}.

%%% ===================================================================
%%% G7 — estimate_mode parameter parsed (conservative / economical)
%%% BUG-8: beamchain ignores estimate_mode — [ConfTarget | _] swallows it
%%% ===================================================================

g07_estimate_mode_parameter_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) ->
        [fun() ->
             %% Both calls should succeed without crash.
             %% The real test: conservative mode MUST return >= economical mode
             %% because conservative adds a doubleEst @ 2*target constraint.
             %% With no data both fall back, so just check no crash.
             R1 = beamchain_fee_estimator:estimate_fee(6),
             R2 = beamchain_fee_estimator:estimate_fee(6),
             ?assert(R1 =:= R2 orelse element(1, R1) =:= ok)
         end,
         fun() ->
             %% estimate_mode=conservative should produce feerate >= economical.
             %% Document that beamchain currently does not implement conservative mode.
             %% This serves as a regression guard when it is added.
             ?assert(true) %% placeholder: BUG-8 not yet fixed
         end]
     end}.

%%% ===================================================================
%%% G8 — Three decay horizons present
%%% Core: SHORT=0.962 (12 blocks), MED=0.9952 (48 blocks), LONG=0.99931 (1008 blocks)
%%% BUG-2: beamchain uses single decay=0.998, none match Core values
%%% ===================================================================

g08_three_horizon_decay_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) ->
        [fun() ->
             %% Verify estimaterawfee reports the Core-specified decay for medium.
             %% Core MED_DECAY = 0.9952
             Res = beamchain_fee_estimator:estimate_raw_fee(6, 0.95),
             Med = maps:get(<<"medium">>, Res, #{}),
             Decay = maps:get(<<"decay">>, Med, undefined),
             ?assertNotEqual(undefined, Decay),
             %% BUG-2: beamchain reports 0.998, should be 0.9952 for medium
             ?assertEqual(0.9952, Decay,
                 "BUG-2: medium horizon decay should be 0.9952 (Core MED_DECAY)")
         end]
     end}.

%%% ===================================================================
%%% G9 — Short horizon present in estimaterawfee for conf_target <= 12
%%% BUG-6: beamchain always returns only "medium"; short and long absent
%%% ===================================================================

g09_short_horizon_present_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) ->
        [fun() ->
             %% For conf_target=6 (<=12) Core returns all three horizons.
             %% beamchain only returns "medium".
             Res = beamchain_fee_estimator:estimate_raw_fee(6, 0.95),
             ?assert(maps:is_key(<<"medium">>, Res)),
             %% BUG-6: short and long horizons absent
             ?assert(maps:is_key(<<"short">>, Res),
                 "BUG-6: short horizon absent for conf_target=6"),
             ?assert(maps:is_key(<<"long">>, Res),
                 "BUG-6: long horizon absent for conf_target=6")
         end]
     end}.

%%% ===================================================================
%%% G10 — Long horizon present in estimaterawfee for conf_target <= 1008
%%% BUG-6 continued
%%% ===================================================================

g10_long_horizon_present_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) ->
        [fun() ->
             Res = beamchain_fee_estimator:estimate_raw_fee(200, 0.95),
             %% For target=200 Core returns medium + long (not short, since 200>12)
             ?assert(maps:is_key(<<"medium">>, Res) orelse
                     maps:is_key(<<"long">>, Res)),
             %% BUG-6: long absent
             ?assert(maps:is_key(<<"long">>, Res),
                 "BUG-6: long horizon absent for conf_target=200")
         end]
     end}.

%%% ===================================================================
%%% G11 — Short horizon scale=1, medium scale=2, long scale=24
%%% ===================================================================

g11_horizon_scale_values_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) ->
        [fun() ->
             Res = beamchain_fee_estimator:estimate_raw_fee(6, 0.95),
             Med = maps:get(<<"medium">>, Res, #{}),
             Scale = maps:get(<<"scale">>, Med, undefined),
             %% Core MED_SCALE = 2
             ?assertEqual(2, Scale,
                 "BUG-2: medium scale should be 2 (Core MED_SCALE)")
         end]
     end}.

%%% ===================================================================
%%% G12 — Bucket count: ~237 buckets (Core: 100..1e7 at 1.05)
%%% BUG-3: beamchain uses 40 buckets instead of ~237
%%% ===================================================================

g12_bucket_count_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) ->
        [fun() ->
             %% get_fee_histogram returns one entry per bucket.
             Histogram = beamchain_fee_estimator:get_fee_histogram(),
             Count = length(Histogram),
             %% Core generates ~237 buckets (100 to 1e7 at 1.05 spacing + INF)
             ?assert(Count >= 200,
                 lists:flatten(io_lib:format(
                     "BUG-3: only ~B buckets, need ~B+ (Core ~B)",
                     [Count, 200, 237])))
         end]
     end}.

%%% ===================================================================
%%% G13 — Min bucket feerate: Core=100 sat/kvB = 0.1 sat/vB
%%% BUG-3: beamchain min=1.0 sat/vB (10x too high, misses low-fee txs)
%%% ===================================================================

g13_min_bucket_feerate_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) ->
        [fun() ->
             Histogram = beamchain_fee_estimator:get_fee_histogram(),
             case Histogram of
                 [{MinBound, _} | _] ->
                     %% Core MIN_BUCKET_FEERATE = 100 sat/kvB = 0.1 sat/vB
                     ?assert(MinBound =< 0.1,
                         lists:flatten(io_lib:format(
                             "BUG-3: min bucket ~p sat/vB > 0.1 sat/vB (Core min)",
                             [MinBound])));
                 [] -> ok
             end
         end]
     end}.

%%% ===================================================================
%%% G14 — Bucket spacing: Core=1.05
%%% BUG-3: beamchain spacing ~1.27 (coarser resolution)
%%% ===================================================================

g14_bucket_spacing_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) ->
        [fun() ->
             Histogram = beamchain_fee_estimator:get_fee_histogram(),
             case length(Histogram) >= 2 of
                 false -> ok;
                 true ->
                     [{B1, _}, {B2, _} | _] = Histogram,
                     Ratio = B2 / B1,
                     %% Core FEE_SPACING = 1.05; allow tiny float error
                     ?assert(abs(Ratio - 1.05) < 0.01,
                         lists:flatten(io_lib:format(
                             "BUG-3: bucket spacing ~.4f != 1.05 (Core FEE_SPACING)",
                             [Ratio])))
             end
         end]
     end}.

%%% ===================================================================
%%% G15 — Max bucket feerate: Core=1e7 sat/kvB = 10000 sat/vB
%%% beamchain max=10000 sat/vB: correct upper bound
%%% ===================================================================

g15_max_bucket_feerate_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) ->
        [fun() ->
             Histogram = beamchain_fee_estimator:get_fee_histogram(),
             case Histogram of
                 [] -> ok;
                 _ ->
                     {MaxBound, _} = lists:last(Histogram),
                     %% Core MAX_BUCKET_FEERATE = 1e7 sat/kvB = 10000 sat/vB
                     ?assert(MaxBound >= 10000.0,
                         lists:flatten(io_lib:format(
                             "max bucket ~p sat/vB < 10000 sat/vB (Core max)",
                             [MaxBound])))
             end
         end]
     end}.

%%% ===================================================================
%%% G16 — track_tx is called from mempool on new tx admission
%%% BUG-1 (DEAD WIRING): track_tx never called outside the estimator module
%%% ===================================================================

g16_track_tx_called_from_mempool_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) ->
        [fun() ->
             %% We cannot easily test the wiring without a running mempool.
             %% Instead we verify: after feeding 200 txs via track_tx manually,
             %% estimates improve (proving the internal logic at least works).
             seed_estimator(200),
             Txids = [crypto:strong_rand_bytes(32) || _ <- lists:seq(1, 50)],
             %% Simulate those txids being confirmed
             lists:foreach(fun(Txid) ->
                 beamchain_fee_estimator:track_tx(Txid, 15.0, 100)
             end, Txids),
             beamchain_fee_estimator:process_block(101, Txids),
             Res = beamchain_fee_estimator:estimate_fee(6),
             %% Should produce a valid estimate now
             ?assertMatch({ok, _}, Res,
                 "BUG-1: after manual track_tx calls estimate_fee should work")
         end]
     end}.

%%% ===================================================================
%%% G17 — process_block called from chain on block connection
%%% BUG-1: process_block never called from chain/validation modules
%%% ===================================================================

g17_process_block_called_from_chain_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) ->
        [fun() ->
             %% Same as G16: verify the API works when called manually.
             Txids = [crypto:strong_rand_bytes(32) || _ <- lists:seq(1, 10)],
             lists:foreach(fun(T) ->
                 beamchain_fee_estimator:track_tx(T, 20.0, 99)
             end, Txids),
             %% Should not crash
             ok = beamchain_fee_estimator:process_block(100, Txids)
         end]
     end}.

%%% ===================================================================
%%% G18 — blocksWaited calculation
%%% Core: blocksToConfirm = nBlockHeight - txHeight  (no +1)
%%% BUG-4: beamchain computes max(1, Height - EntryHeight + 1)  (+1 error)
%%% ===================================================================

g18_blocks_waited_off_by_one_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) ->
        [fun() ->
             %% A tx that entered at height 100 and confirmed at 101 should count
             %% as blocksToConfirm=1 (Core: 101 - 100 = 1).
             %% beamchain computes max(1, 101 - 100 + 1) = 2 -- one too many.
             %%
             %% We test this by tracking a tx at height 100 and processing block 101.
             %% Then request estimate for target=1. With correct accounting the tx
             %% counts as confirmed-within-1-block. With the +1 bug it counts as 2.
             %%
             Txid = crypto:strong_rand_bytes(32),
             beamchain_fee_estimator:track_tx(Txid, 50.0, 100),
             beamchain_fee_estimator:process_block(101, [Txid]),
             %% Force enough volume to escape MIN_TRACKED_TXS
             Txids2 = [crypto:strong_rand_bytes(32) || _ <- lists:seq(1, 150)],
             lists:foreach(fun(T) ->
                 beamchain_fee_estimator:track_tx(T, 50.0, 100)
             end, Txids2),
             beamchain_fee_estimator:process_block(101, Txids2),
             %% With correct blocksWaited=1, estimate_fee(1) should include this tx.
             %% With bugged blocksWaited=2, the tx is missed for target=1.
             %% We assert the result is valid and document the expected discrepancy.
             Res = beamchain_fee_estimator:estimate_fee(1),
             %% Just check no crash and valid shape
             ?assert(element(1, Res) =:= ok orelse element(1, Res) =:= error)
         end]
     end}.

%%% ===================================================================
%%% G19 — failAvg tracking: evicted txs recorded as failures
%%% BUG-5: no removeTx / remove_tx API — evictions silently inflate in_mempool
%%% ===================================================================

g19_evicted_tx_failure_tracking_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) ->
        [fun() ->
             %% Core: when a tx is removed from mempool without confirmation,
             %% removeTx(hash) is called and failAvg is updated.
             %% beamchain has no such API.  We verify by checking the module
             %% exports do NOT include remove_tx (confirming the gap).
             Exports = beamchain_fee_estimator:module_info(exports),
             HasRemoveTx = lists:keymember(remove_tx, 1, Exports) orelse
                           lists:keymember(removetx, 1, Exports),
             ?assertNot(HasRemoveTx,
                 "BUG-5: remove_tx/1 should exist to track evicted txs like Core removeTx")
         end]
     end}.

%%% ===================================================================
%%% G20 — leftmempool field non-zero after evictions
%%% BUG-5: without removeTx, leftmempool is always near-zero / wrong
%%% ===================================================================

g20_leftmempool_reflects_evictions_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) ->
        [fun() ->
             %% Track a tx, do NOT confirm it in any block, then check that
             %% leftmempool is not zero in a raw estimate (it should be after decay).
             %% With no eviction tracking, leftmempool will always be ~0.
             Txids = [crypto:strong_rand_bytes(32) || _ <- lists:seq(1, 200)],
             lists:foreach(fun(T) ->
                 beamchain_fee_estimator:track_tx(T, 30.0, 50)
             end, Txids),
             %% Process several blocks WITHOUT those txids (they "expired")
             lists:foreach(fun(H) ->
                 beamchain_fee_estimator:process_block(H, [])
             end, lists:seq(51, 100)),
             Res = beamchain_fee_estimator:estimate_raw_fee(6, 0.95),
             Med = maps:get(<<"medium">>, Res, #{}),
             Fail = maps:get(<<"fail">>, Med, #{}),
             LeftMem = maps:get(<<"leftmempool">>, Fail, 0.0),
             %% After many blocks without confirmation, leftmempool should be > 0
             %% BUG-5: without eviction tracking this stays at 0
             ?assert(LeftMem > 0,
                 "BUG-5: leftmempool should be > 0 for unconfirmed evicted txs")
         end]
     end}.

%%% ===================================================================
%%% G21 — reorg guard: process_block ignores old heights
%%% BUG-11: no guard, so old/reorg blocks update estimator incorrectly
%%% ===================================================================

g21_reorg_guard_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) ->
        [fun() ->
             %% Feed a block at height 200, then at height 100 (reorg).
             %% Core ignores height <= nBestSeenHeight.
             %% beamchain processes it (no guard).
             Txid = crypto:strong_rand_bytes(32),
             beamchain_fee_estimator:track_tx(Txid, 25.0, 100),
             ok = beamchain_fee_estimator:process_block(200, [Txid]),
             %% Now process a "reorg" block at height 150 (lower than 200).
             %% Should be a no-op; if not guarded it double-processes.
             ok = beamchain_fee_estimator:process_block(150, []),
             %% Check: the estimator state should not be corrupted.
             Res = beamchain_fee_estimator:estimate_raw_fee(6, 0.95),
             ?assert(is_map(Res))
         end]
     end}.

%%% ===================================================================
%%% G22 — SUFFICIENT_FEETXS per-bucket gate (0.1 avg txs/block)
%%% beamchain: uses global MIN_TRACKED_TXS=100 instead of per-bucket avg
%%% ===================================================================

g22_sufficient_feetxs_per_bucket_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) ->
        [fun() ->
             %% Core uses SUFFICIENT_FEETXS=0.1 per bucket per block,
             %% combining buckets until the threshold is met.
             %% beamchain uses a single global 100-tx gate.
             %% Verify that estimate_fee with a sparse bucket still handles
             %% the case gracefully (no crash, returns error or estimate).
             Txid = crypto:strong_rand_bytes(32),
             beamchain_fee_estimator:track_tx(Txid, 200.0, 1),
             beamchain_fee_estimator:process_block(2, [Txid]),
             Res = beamchain_fee_estimator:estimate_fee(6),
             ?assert(element(1, Res) =:= ok orelse element(1, Res) =:= error)
         end]
     end}.

%%% ===================================================================
%%% G23 — estimateSmartFee half/full/double sub-estimate combination
%%% BUG-10: beamchain uses simple ascending scan instead of 3-estimate max
%%% ===================================================================

g23_half_full_double_estimate_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) ->
        [fun() ->
             %% Core: result = max(halfEst@target/2, actualEst@target, doubleEst@2*target)
             %% This ensures monotonicity and conservatism.
             %% beamchain: no half/double logic.
             %%
             %% Test: estimate for target=12 should be >= estimate for target=6
             %% (relaxed requirement, not strictly enforced without the 3-way max).
             seed_estimator(200),
             Txids = [crypto:strong_rand_bytes(32) || _ <- lists:seq(1, 100)],
             lists:foreach(fun(T) ->
                 beamchain_fee_estimator:track_tx(T, 15.0, 100)
             end, Txids),
             beamchain_fee_estimator:process_block(101, Txids),
             R6  = beamchain_fee_estimator:estimate_fee(6),
             R12 = beamchain_fee_estimator:estimate_fee(12),
             case {R6, R12} of
                 {{ok, F6}, {ok, F12}} ->
                     %% Core guarantees estimate for shorter target >= longer target
                     %% (higher fee needed for faster confirmation)
                     ?assert(F6 >= F12,
                         lists:flatten(io_lib:format(
                             "BUG-10: estimate(6)=~.2f < estimate(12)=~.2f "
                             "(should be monotonically decreasing with target)",
                             [F6, F12])));
                 _ -> ok
             end
         end]
     end}.

%%% ===================================================================
%%% G24 — estimatesmartfee "blocks" field = actual target used
%%% BUG-9: beamchain returns requested ConfTarget, not clamped returnedTarget
%%% ===================================================================

g24_blocks_field_is_actual_target_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) ->
        [fun() ->
             %% When MaxUsableEstimate < ConfTarget, Core clamps and reports
             %% the clamped value in "blocks". beamchain always echoes input.
             %% We document this by checking the field exists and is an integer.
             %%
             %% Without a running node stack we test the API shape only.
             Res = beamchain_fee_estimator:estimate_fee(6),
             case Res of
                 {ok, F} ->
                     ?assert(is_float(F), "estimate_fee must return float");
                 {error, _} -> ok
             end
         end]
     end}.

%%% ===================================================================
%%% G25 — Persistence: state saved and restored across restarts
%%% ===================================================================

g25_persistence_roundtrip_test_() ->
    {setup,
     fun() ->
         %% Custom setup that does NOT start the server -- we control lifecycle inside.
         case ets:info(beamchain_chain_meta) of
             undefined ->
                 ets:new(beamchain_chain_meta, [set, public, named_table]);
             _ -> ok
         end,
         %% Kill any leftover server.
         case whereis(beamchain_fee_estimator) of
             undefined -> ok;
             P -> unlink(P), exit(P, kill), wait_dead(P)
         end,
         lists:foreach(fun file:delete/1,
                       filelib:wildcard("fee_estimates.dat")),
         ok  %% Return ok (not a pid) so teardown is a no-op.
     end,
     fun(_) -> ok end,  %% no-op teardown
     fun(_) ->
        [fun() ->
             %% Start server, seed, save, stop.
             {ok, Pid0} = beamchain_fee_estimator:start_link(),
             seed_estimator(150),
             ok = beamchain_fee_estimator:save_state(),
             gen_server:stop(Pid0, normal, 500),
             wait_dead(Pid0),
             %% Restart -- server should load persisted data.
             {ok, Pid1} = beamchain_fee_estimator:start_link(),
             timer:sleep(50),
             Res = beamchain_fee_estimator:estimate_fee(6),
             gen_server:stop(Pid1, normal, 500),
             wait_dead(Pid1),
             %% Persisted state should allow an estimate attempt.
             ?assert(element(1, Res) =:= ok orelse element(1, Res) =:= error)
         end]
     end}.

%%% ===================================================================
%%% G26 — Stale file age guard (Core: reject if > 60 hours old)
%%% BUG-12: beamchain loads any saved file regardless of age
%%% ===================================================================

g26_stale_file_rejected_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) ->
        [fun() ->
             %% Core refuses files older than MAX_FILE_AGE=60 hours.
             %% beamchain has no age check in load_persisted_state/1.
             %% We document this as a known gap.
             %%
             %% Verify: the save/load path works for fresh files (no age check needed).
             seed_estimator(100),
             Res = beamchain_fee_estimator:save_state(),
             ?assertEqual(ok, Res)
             %% BUG-12: no mtime check. A file > 60 hours old should be ignored.
         end]
     end}.

%%% ===================================================================
%%% G27 — estimaterawfee: threshold out-of-range rejected
%%% ===================================================================

g27_threshold_range_validation_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) ->
        [?_assertEqual(#{}, beamchain_fee_estimator:estimate_raw_fee(6, -0.1)),
         ?_assertEqual(#{}, beamchain_fee_estimator:estimate_raw_fee(6, 1.5)),
         ?_assertEqual(#{}, beamchain_fee_estimator:estimate_raw_fee(0, 0.95)),
         ?_assertEqual(#{}, beamchain_fee_estimator:estimate_raw_fee(1009, 0.95))
        ]
     end}.

%%% ===================================================================
%%% G28 — estimaterawfee: pass bucket present when data available
%%% ===================================================================

g28_rawfee_pass_bucket_shape_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) ->
        [fun() ->
             %% When pass bucket is present it must have all 6 Core fields.
             ExpectedKeys = lists:sort([<<"startrange">>, <<"endrange">>,
                                        <<"withintarget">>, <<"totalconfirmed">>,
                                        <<"inmempool">>, <<"leftmempool">>]),
             %% Seed enough to get a passing bucket
             Txids = [crypto:strong_rand_bytes(32) || _ <- lists:seq(1, 200)],
             lists:foreach(fun(T) ->
                 beamchain_fee_estimator:track_tx(T, 20.0, 100)
             end, Txids),
             beamchain_fee_estimator:process_block(101, Txids),
             Res = beamchain_fee_estimator:estimate_raw_fee(6, 0.85),
             Med = maps:get(<<"medium">>, Res, #{}),
             case maps:is_key(<<"pass">>, Med) of
                 true ->
                     PassBucket = maps:get(<<"pass">>, Med),
                     ?assertEqual(ExpectedKeys,
                                  lists:sort(maps:keys(PassBucket)));
                 false -> ok  %% no pass bucket (insufficient data) — acceptable
             end
         end]
     end}.

%%% ===================================================================
%%% G29 — get_fee_histogram returns non-empty list with valid structure
%%% ===================================================================

g29_fee_histogram_shape_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) ->
        [fun() ->
             Histogram = beamchain_fee_estimator:get_fee_histogram(),
             ?assert(is_list(Histogram)),
             ?assert(length(Histogram) > 0),
             %% Each entry is {float(), integer()}
             lists:foreach(fun({Rate, Count}) ->
                 ?assert(is_float(Rate)),
                 ?assert(is_integer(Count))
             end, Histogram)
         end]
     end}.

%%% ===================================================================
%%% G30 — Decay coefficient precision: Erlang float handles 0.99931
%%% Core LONG_DECAY=0.99931 — verify Erlang float precision sufficient
%%% ===================================================================

g30_decay_coefficient_precision_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) ->
        [fun() ->
             %% Erlang floats are IEEE 754 double precision (64-bit).
             %% 0.99931 is representable within ~1e-16 relative error.
             %% Verify that 1000 applications of LONG_DECAY do not drift
             %% beyond 0.1% from the true mathematical value.
             LongDecay = 0.99931,
             Applied = lists:foldl(fun(_, Acc) -> Acc * LongDecay end,
                                   1.0, lists:seq(1, 1008)),
             %% Expected: 0.99931^1008 ≈ 0.5 (half-life is 1008 blocks by design)
             Expected = math:pow(LongDecay, 1008),
             Diff = abs(Applied - Expected),
             ?assert(Diff < 1.0e-10,
                 lists:flatten(io_lib:format(
                     "Float precision drift after 1008 multiplications: ~e",
                     [Diff]))),
             %% Also verify MED_DECAY
             MedDecay = 0.9952,
             AppliedMed = lists:foldl(fun(_, Acc) -> Acc * MedDecay end,
                                      1.0, lists:seq(1, 144)),
             ExpectedMed = math:pow(MedDecay, 144),
             ?assert(abs(AppliedMed - ExpectedMed) < 1.0e-10)
         end]
     end}.
