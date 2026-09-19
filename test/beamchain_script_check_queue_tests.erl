-module(beamchain_script_check_queue_tests).

%% Parallel script verification — the four required controls:
%%   (1) decision identity at 1 worker vs N
%%   (2) failure propagation (one worker fails → whole block rejected,
%%       same reason as serial)
%%   (3) measured scaling 1/2/4/8 on thousands of post-segwit inputs
%%   (4) bounded RSS (worker count capped, ETS objects == jobs not
%%       jobs*workers, workers die after the call)
%%
%% Reference: bitcoin-core/src/checkqueue.h, validation.cpp CScriptCheck,
%%            init.cpp -par, validation.h MAX_SCRIPTCHECK_THREADS.

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-define(N_HEAVY, 2048).

script_check_queue_test_() ->
    {setup,
     fun setup/0,
     fun teardown/1,
     fun(_) ->
         [
          {"-par mapping: 0=auto, >0 clamp, <0 leave cores free",
           fun test_resolve_threads/0},
          {"empty jobs is ok at any worker count",
           fun test_empty_jobs/0},
          {"NEGATIVE: a single failing job is not skipped (off-by-one)",
           fun test_single_job_not_skipped/0},
          {"decision identity: all-pass OP_1 jobs, 1 vs 2 vs 4 vs 8",
           fun test_identity_all_pass/0},
          {"decision identity: single fail at first/middle/last input",
           fun test_identity_single_fail_positions/0},
          {"decision identity: two fails, min {tx,in} order is the reason",
           fun test_identity_multi_fail_min_order/0},
          {"failure propagation: one failing fun among 64, N=8 equals N=1",
           fun test_failure_propagation/0},
          {"per-input expansion: one 4-input tx, fail at input 2",
           fun test_per_input_expansion/0},
          {"ConnectBlock job shape (Tx,Coins) goes through verify/3",
           fun test_connect_block_job_shape/0},
          {"bounded RSS: 2000 jobs / 4 workers → workers=4, ets=2000",
           fun test_bounded_rss/0},
          {"worker count never exceeds MAX, even if -par is huge",
           fun test_max_cap/0},
          {"workers do not leak after verify returns",
           fun test_no_process_leak/0},
          {timeout, 120,
           {"measured scaling 1/2/4/8 on 2048 unique P2WPKH inputs",
            fun test_measured_scaling/0}}
         ]
     end}.

setup() ->
    case whereis(beamchain_sig_cache) of
        undefined ->
            {ok, Pid} = beamchain_sig_cache:start_link(),
            Pid;
        Existing ->
            Existing
    end.

teardown(_) ->
    ok.

%%% ===================================================================
%%% -par
%%% ===================================================================

test_resolve_threads() ->
    Max = beamchain_script_check_queue:max_scriptcheck_threads(),
    ?assertEqual(32, Max),
    Auto = beamchain_script_check_queue:resolve_threads(0),
    ?assert(Auto >= 1),
    ?assert(Auto =< Max),
    ?assertEqual(1, beamchain_script_check_queue:resolve_threads(1)),
    ?assertEqual(8, beamchain_script_check_queue:resolve_threads(8)),
    ?assertEqual(Max, beamchain_script_check_queue:resolve_threads(10_000)),
    Leave2 = beamchain_script_check_queue:resolve_threads(-2),
    ?assert(Leave2 >= 1),
    ?assert(Leave2 =< Auto),
    %% Leaving more cores than exist still floors at 1, never 0.
    ?assertEqual(1, beamchain_script_check_queue:resolve_threads(-10_000)).

test_empty_jobs() ->
    ?assertEqual(ok, beamchain_script_check_queue:verify([], 0, 1)),
    ?assertEqual(ok, beamchain_script_check_queue:verify([], 0, 8)),
    Stats = beamchain_script_check_queue:last_stats(),
    ?assertEqual(0, maps:get(jobs, Stats)).

test_single_job_not_skipped() ->
    %% The off-by-one that skipped ETS key 1 would accept this.
    D1 = catch_verify([false_job()], 0, 1),
    D8 = catch_verify([false_job()], 0, 8),
    ?assertEqual({error, {script_verify_failed, 0}}, D1),
    ?assertEqual(D1, D8),
    ?assertEqual(ok, catch_verify([true_job()], 0, 1)),
    ?assertEqual(ok, catch_verify([true_job()], 0, 8)).

%%% ===================================================================
%%% Decision identity
%%% ===================================================================

test_identity_all_pass() ->
    Jobs = [true_job() || _ <- lists:seq(1, 32)],
    Decisions = [catch_verify(Jobs, 0, N) || N <- [1, 2, 4, 8]],
    lists:foreach(fun(D) -> ?assertEqual(ok, D) end, Decisions).

test_identity_single_fail_positions() ->
    lists:foreach(fun(FailAt) ->
        Jobs = [case I of
                    FailAt -> false_job();
                    _ -> true_job()
                end || I <- lists:seq(0, 15)],
        D1 = catch_verify(Jobs, 0, 1),
        lists:foreach(fun(N) ->
            ?assertEqual(D1, catch_verify(Jobs, 0, N))
        end, [2, 4, 8]),
        ?assertEqual({error, {script_verify_failed, 0}}, D1)
    end, [0, 7, 15]).

test_identity_multi_fail_min_order() ->
    %% Two failing txs. First-in-order (tx 1 input 0) is the reported
    %% reason at every worker count — not whichever worker finished first.
    Jobs = [true_job(), false_job(), true_job(), false_job()],
    D1 = catch_verify(Jobs, 0, 1),
    ?assertEqual({error, {script_verify_failed, 0}}, D1),
    lists:foreach(fun(N) ->
        ?assertEqual(D1, catch_verify(Jobs, 0, N))
    end, [2, 3, 4, 8]).

%%% ===================================================================
%%% Failure propagation
%%% ===================================================================

test_failure_propagation() ->
    %% 63 passing funs, one failing fun in the middle. The failing fun
    %% runs on whichever worker claims it; the whole verify must reject
    %% with the same reason the serial path (N=1) returns.
    FailIdx = 17,
    Funs = [case I of
                FailIdx ->
                    fun() -> {error, {script_verify_failed, FailIdx}} end;
                _ ->
                    fun() -> ok end
            end || I <- lists:seq(0, 63)],
    Serial = catch_funs(Funs, 1),
    Parallel = catch_funs(Funs, 8),
    ?assertEqual({error, {script_verify_failed, FailIdx}}, Serial),
    ?assertEqual(Serial, Parallel).

test_per_input_expansion() ->
    %% One transaction, four inputs; input 2 is OP_0. Serial and N=4
    %% must both report {script_verify_failed, 2}, proving we dispatch
    %% per-input (Core CScriptCheck) not per-tx.
    SPKs = [<<16#51>>, <<16#51>>, <<0>>, <<16#51>>],
    Job = tx_from_spks(SPKs),
    D1 = catch_verify([Job], 0, 1),
    D4 = catch_verify([Job], 0, 4),
    ?assertEqual({error, {script_verify_failed, 2}}, D1),
    ?assertEqual(D1, D4).

test_connect_block_job_shape() ->
    Jobs = [true_job(), true_job(), false_job()],
    ?assertEqual({error, {script_verify_failed, 0}},
                 catch_verify(Jobs, 0, 8)).

%%% ===================================================================
%%% Bounded RSS
%%% ===================================================================

test_bounded_rss() ->
    Jobs = [true_job() || _ <- lists:seq(1, 2000)],
    ok = beamchain_script_check_queue:verify(Jobs, 0, 4),
    Stats = beamchain_script_check_queue:last_stats(),
    ?assertEqual(4, maps:get(workers, Stats)),
    ?assertEqual(2000, maps:get(jobs, Stats)),
    ?assertEqual(2000, maps:get(ets_objects, Stats)),
    ?assertEqual(beamchain_script_check_queue:worker_max_heap_words(),
                 maps:get(max_heap_words, Stats)),
    %% Same job count at 1 worker still has ets_objects == jobs, not
    %% jobs * workers. The queue does not grow with the pool.
    ok = beamchain_script_check_queue:verify(Jobs, 0, 1),
    Stats1 = beamchain_script_check_queue:last_stats(),
    ?assertEqual(1, maps:get(workers, Stats1)),
    ?assertEqual(2000, maps:get(ets_objects, Stats1)).

test_max_cap() ->
    ?assertEqual(beamchain_script_check_queue:max_scriptcheck_threads(),
                 beamchain_script_check_queue:resolve_threads(1_000_000)),
    Jobs = [true_job() || _ <- lists:seq(1, 16)],
    ok = beamchain_script_check_queue:verify(Jobs, 0, 1_000_000),
    Stats = beamchain_script_check_queue:last_stats(),
    %% Spawned workers are min(requested, jobs, MAX). 16 jobs → 16, not 1e6.
    ?assertEqual(16, maps:get(workers, Stats)).

test_no_process_leak() ->
    Before = erlang:system_info(process_count),
    Jobs = [true_job() || _ <- lists:seq(1, 64)],
    ok = beamchain_script_check_queue:verify(Jobs, 0, 8),
    %% Workers exit before verify/3 returns. Allow a few unrelated
    %% processes (timers, the sig-cache gen_server) to jitter.
    After = erlang:system_info(process_count),
    ?assert(After =< Before + 4).

%%% ===================================================================
%%% Measured scaling — 2048 unique P2WPKH inputs (post-segwit shape)
%%% ===================================================================

test_measured_scaling() ->
    Jobs = make_p2wpkh_jobs(?N_HEAVY),
    %% Construction smoke: one real P2WPKH input must pass at N=1
    %% before we time 2048 of them. A bad fixture would otherwise
    %% look like "scaling" of instant rejects.
    ?assertEqual(ok, beamchain_script_check_queue:verify(
                       [hd(Jobs)], p2wpkh_flags(), 1)),
    %% Negative control: corrupt the last witness and prove 1 vs 8
    %% still agree on the reject (decision identity on the heavy set).
    [{BadTx, BadCoins} | RestRev] = lists:reverse(Jobs),
    [BadIn] = BadTx#transaction.inputs,
    BadTx2 = BadTx#transaction{
        inputs = [BadIn#tx_in{witness = [<<0>>, <<>>]}]
    },
    BadJobs = lists:reverse([{BadTx2, BadCoins} | RestRev]),
    Bad1 = catch_verify(BadJobs, p2wpkh_flags(), 1),
    Bad8 = catch_verify(BadJobs, p2wpkh_flags(), 8),
    ?assertMatch({error, {script_verify_failed, _}}, Bad1),
    ?assertEqual(Bad1, Bad8),

    %% Happy-path timings. Median of 3 so a single noisy sample cannot
    %% invent a 4x. Numbers are printed (the control), not just asserted.
    Ns = [1, 2, 4, 8],
    Rows = [{N, median_us(fun() ->
                          ok = beamchain_script_check_queue:verify(
                                 Jobs, p2wpkh_flags(), N)
                      end, 3)} || N <- Ns],
    BlkH = [{N, blk_per_hour(Us)} || {N, Us} <- Rows],
    io:format(user,
              "~nSCRIPT-CHECK SCALING (~B unique P2WPKH inputs):~n"
              "  workers  wall_us   blk/h (this block-shaped job)~n",
              [?N_HEAVY]),
    lists:foreach(fun({N, Us}) ->
        {N, BPH} = lists:keyfind(N, 1, BlkH),
        io:format(user, "  ~7b  ~8b   ~.1f~n", [N, Us, BPH])
    end, Rows),
    {1, Us1} = lists:keyfind(1, 1, Rows),
    {8, Us8} = lists:keyfind(8, 1, Rows),
    {4, Us4} = lists:keyfind(4, 1, Rows),
    %% 8 workers must beat 1 worker. A fake (single-process) pool cannot
    %% pass this on 2048 dirty-CPU ECDSA checks. Allow 15% slack on the
    %% 4-worker row for scheduler noise, but 8 must still be strictly
    %% faster than 1.
    ?assert(Us8 < Us1),
    ?assert(Us4 =< Us1).

%%% ===================================================================
%%% Helpers
%%% ===================================================================

catch_verify(Jobs, Flags, N) ->
    try
        beamchain_script_check_queue:verify(Jobs, Flags, N)
    catch
        throw:Reason -> {error, Reason}
    end.

catch_funs(Funs, N) ->
    try
        beamchain_script_check_queue:verify_funs(Funs, N)
    catch
        throw:Reason -> {error, Reason}
    end.

true_job() ->
    tx_from_spks([<<16#51>>]).

false_job() ->
    tx_from_spks([<<0>>]).

tx_from_spks(SPKs) ->
    Inputs = [#tx_in{
        prev_out = #outpoint{hash = <<0:256>>, index = I},
        script_sig = <<16#51>>,
        sequence = 16#ffffffff,
        witness = []
    } || I <- lists:seq(0, length(SPKs) - 1)],
    Coins = [#utxo{
        value = 2000,
        script_pubkey = SPK,
        is_coinbase = false,
        height = 1
    } || SPK <- SPKs],
    Tx = #transaction{
        version = 1,
        inputs = Inputs,
        outputs = [#tx_out{value = 1000, script_pubkey = <<16#51>>}],
        locktime = 0
    },
    {Tx, Coins}.

p2wpkh_flags() ->
    ?SCRIPT_VERIFY_P2SH bor ?SCRIPT_VERIFY_WITNESS bor
        ?SCRIPT_VERIFY_DERSIG bor ?SCRIPT_VERIFY_NULLDUMMY.

make_p2wpkh_jobs(N) ->
    Priv = <<1:256>>,
    {ok, Pub} = beamchain_crypto:pubkey_from_privkey(Priv),
    Hash160 = beamchain_crypto:hash160(Pub),
    SPK = <<16#00, 20, Hash160/binary>>,
    ScriptCode = <<16#76, 16#a9, 20, Hash160/binary, 16#88, 16#ac>>,
    Amount = 50_000,
    [make_one_p2wpkh(I, Priv, Pub, SPK, ScriptCode, Amount)
     || I <- lists:seq(1, N)].

make_one_p2wpkh(I, Priv, Pub, SPK, ScriptCode, Amount) ->
    %% Unique locktime → unique tx → unique BIP-143 sighash, so the
    %% sig-cache cannot collapse the 2048 verifies into one NIF call.
    Prev = #outpoint{hash = <<I:256>>, index = 0},
    UnsignedIn = #tx_in{
        prev_out = Prev,
        script_sig = <<>>,
        sequence = 16#ffffffff,
        witness = []
    },
    Tx0 = #transaction{
        version = 2,
        inputs = [UnsignedIn],
        outputs = [#tx_out{value = 49_000, script_pubkey = SPK}],
        locktime = I
    },
    SigHash = beamchain_script:sighash_witness_v0(
                Tx0, 0, ScriptCode, Amount, ?SIGHASH_ALL),
    {ok, Der} = beamchain_crypto:ecdsa_sign(SigHash, Priv),
    Sig = <<Der/binary, ?SIGHASH_ALL>>,
    SignedIn = UnsignedIn#tx_in{witness = [Sig, Pub]},
    Tx = Tx0#transaction{inputs = [SignedIn]},
    Coin = #utxo{value = Amount, script_pubkey = SPK,
                 is_coinbase = false, height = 500_000},
    {Tx, [Coin]}.

median_us(Fun, K) ->
    Samples = [element(1, timer:tc(Fun)) || _ <- lists:seq(1, K)],
    lists:nth((K div 2) + 1, lists:sort(Samples)).

blk_per_hour(Us) when Us > 0 ->
    3_600_000_000.0 / Us;
blk_per_hour(_) ->
    0.0.
