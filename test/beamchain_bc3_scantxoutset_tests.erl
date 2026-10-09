-module(beamchain_bc3_scantxoutset_tests).

%%% BC-3: scantxoutset walks the UTXO set inside the chainstate gen_server.
%%% A block connect (and any other gen_server call) waits out the fold.
%%% block_sync then halts after MAX_VALIDATION_RETRIES.
%%%
%%% These tests park the fold on a few-coin regtest chain via
%%% beamchain_fault:scantxoutset_fold. get_tip/0 is an ETS read and does
%%% not enter the actor, so the stall is measured with
%%% gen_server:call(..., {connect_block, _}, Timeout) and
%%% get_chainstate_meta.
%%%
%%% On the in-actor fold the connect times out and the fold process is
%%% the chainstate pid. After the snapshot walk moves out of the actor,
%%% the connect returns while the fold is still parked and the scan
%%% result is the pre-connect tip (same unspents, total_amount, height,
%%% bestblock).
%%%
%%%   rebar3 eunit --module=beamchain_bc3_scantxoutset_tests

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-define(OP_TRUE, <<16#51>>).
-define(CALL_MS, 2000).

bc3_test_() ->
    {foreach, fun setup/0, fun teardown/1,
     [fun(_) -> {timeout, 120, {Name, F}} end || {Name, F} <-
         [          {"BC-3: chainstate connects a block while scantxoutset is folding; "
           "scan is the pre-connect snapshot",
           fun bc3_actor_during_scan/0},
          {"BC-3: status/abort/second start while a scan is parked",
           fun bc3_status_abort/0},
          {"BC-3: killing the fold releases the coins snapshot and the actor answers",
           fun bc3_fold_crash/0},
          {"CONTROL: idle scantxoutset status is null and abort is false",
           fun bc3_idle_status/0}]]}.

%%% ===================================================================
%%% Tests
%%% ===================================================================

bc3_actor_during_scan() ->
    build_chain(3),
    Before = scan_start(<<"raw(51)">>),
    {ok, {TipHash, TipH}} = beamchain_chainstate:get_tip(),
    Next = next_block([]),
    [Cb | _] = Next#block.transactions,
    NewTxid = display_txid(Cb),
    arm_park(),
    Scan = spawn_scan(<<"raw(51)">>),
    FoldPid = wait_parked(),
    io:format(user, "~n  [BC-3] fold pid ~p chainstate ~p~n",
              [FoldPid, whereis(beamchain_chainstate)]),
    {ConnectMs, ConnectRes} = timed_call({connect_block, Next}),
    io:format(user, "  [BC-3] connect_block during fold: ~p in ~B ms~n",
              [ConnectRes, ConnectMs]),
    {MetaMs, MetaRes} = timed_call(get_chainstate_meta),
    io:format(user, "  [BC-3] get_chainstate_meta during fold: ~p in ~B ms~n",
              [case MetaRes of #{role := R} -> {ok, R}; Other -> Other end,
               MetaMs]),
    release_park(),
    After = wait_scan(Scan),
    ?assertEqual(ok, ConnectRes),
    ?assert(ConnectMs < ?CALL_MS),
    ?assertMatch(#{role := _}, MetaRes),
    ?assert(MetaMs < ?CALL_MS),
    ?assertEqual(TipH, maps:get(<<"height">>, After)),
    ?assertEqual(display_hash(TipHash), maps:get(<<"bestblock">>, After)),
    ?assertEqual(maps:get(<<"height">>, Before), maps:get(<<"height">>, After)),
    ?assertEqual(maps:get(<<"bestblock">>, Before), maps:get(<<"bestblock">>, After)),
    ?assertEqual(maps:get(<<"total_amount">>, Before),
                 maps:get(<<"total_amount">>, After)),
    ?assertEqual(maps:get(<<"txouts">>, Before), maps:get(<<"txouts">>, After)),
    ?assertEqual(canon_unspents(Before), canon_unspents(After)),
    ?assertEqual(false, lists:any(fun(U) -> maps:get(<<"txid">>, U) =:= NewTxid end,
                                  maps:get(<<"unspents">>, After))),
    ?assertMatch({ok, {_, _}}, beamchain_chainstate:get_tip()),
    {ok, {LiveHash, LiveH}} = beamchain_chainstate:get_tip(),
    ?assertEqual(TipH + 1, LiveH),
    ?assertEqual(Next#block.hash, LiveHash),
    ?assertNotEqual(display_hash(TipHash), display_hash(LiveHash)).

bc3_status_abort() ->
    build_chain(2),
    arm_park(),
    Scan = spawn_scan(<<"raw(51)">>),
    _FoldPid = wait_parked(),
    Status = beamchain_rpc:handle_method(<<"scantxoutset">>, [<<"status">>], undefined),
    Abort = beamchain_rpc:handle_method(<<"scantxoutset">>, [<<"abort">>], undefined),
    io:format(user, "~n  [BC-3] status during scan ~p abort ~p~n", [Status, Abort]),
    Second = second_start(),
    io:format(user, "  [BC-3] second start ~p~n", [Second]),
    release_park(),
    After = wait_scan(Scan),
    ?assertMatch({ok_raw_json, _}, Status),
    {ok_raw_json, StatusJson} = Status,
    StatusMap = jsx:decode(StatusJson, [return_maps]),
    ?assert(is_map(StatusMap)),
    ?assert(maps:is_key(<<"progress">>, StatusMap)),
    ?assertEqual({ok, true}, Abort),
    ?assertMatch({error, -8, <<"Scan already in progress, use action \"abort\" or \"status\"">>},
                 Second),
    ?assertEqual(false, maps:get(<<"success">>, After)).

bc3_fold_crash() ->
    build_chain(2),
    Test = self(),
    beamchain_fault:set(utxo_snapshot_release, fun([_Snap]) ->
        Test ! bc3_snapshot_released,
        passthrough
    end),
    arm_park(),
    _Scan = spawn_scan(<<"raw(51)">>),
    FoldPid = wait_parked(),
    ChainPid = whereis(beamchain_chainstate),
    io:format(user, "~n  [BC-3] crash fold pid ~p chainstate ~p~n",
              [FoldPid, ChainPid]),
    %% Killing the chainstate process would take the node down. The fold
    %% has to be some other pid before this is safe.
    ?assertNotEqual(ChainPid, FoldPid),
    exit(FoldPid, kill),
    receive bc3_snapshot_released -> ok
    after 5000 -> error(snapshot_not_released)
    end,
    {MetaMs, MetaRes} = timed_call(get_chainstate_meta),
    io:format(user, "  [BC-3] actor after fold kill: ~p in ~B ms~n",
              [case MetaRes of #{role := R} -> {ok, R}; Other -> Other end,
               MetaMs]),
    ?assertMatch(#{role := _}, MetaRes),
    ?assert(MetaMs < ?CALL_MS),
    Again = scan_start(<<"raw(51)">>),
    ?assertEqual(true, maps:get(<<"success">>, Again)),
    ?assert(maps:get(<<"txouts">>, Again) >= 1).

bc3_idle_status() ->
    ?assertEqual({ok_raw_json, <<"null">>},
                 beamchain_rpc:handle_method(<<"scantxoutset">>,
                                             [<<"status">>], undefined)),
    ?assertEqual({ok, false},
                 beamchain_rpc:handle_method(<<"scantxoutset">>,
                                             [<<"abort">>], undefined)).

%%% ===================================================================
%%% Scan / park helpers
%%% ===================================================================

scan_start(Desc) ->
    decode_scan(beamchain_rpc:handle_method(
                  <<"scantxoutset">>, [<<"start">>, [Desc]], undefined)).

spawn_scan(Desc) ->
    Test = self(),
    spawn(fun() ->
        R = beamchain_rpc:handle_method(
              <<"scantxoutset">>, [<<"start">>, [Desc]], undefined),
        Test ! {bc3_scan_done, self(), R}
    end).

wait_scan(Pid) ->
    receive {bc3_scan_done, Pid, R} -> decode_scan(R)
    after 30000 -> error(scan_never_finished)
    end.

decode_scan({ok_raw_json, Bin}) ->
    jsx:decode(Bin, [return_maps]);
decode_scan(Other) ->
    error({scan_failed, Other}).

arm_park() ->
    Test = self(),
    persistent_term:put(bc3_park_armed, true),
    beamchain_fault:set(scantxoutset_fold, fun([_Coin]) ->
        case persistent_term:get(bc3_park_armed, false) of
            true ->
                persistent_term:put(bc3_park_armed, false),
                persistent_term:put(bc3_fold_pid, self()),
                Test ! {bc3_parked, self()},
                receive bc3_go -> ok
                after 60000 -> ok
                end,
                passthrough;
            false ->
                passthrough
        end
    end).

wait_parked() ->
    receive {bc3_parked, Pid} -> Pid
    after 20000 -> error(fold_never_parked)
    end.

release_park() ->
    persistent_term:put(bc3_park_armed, false),
    case persistent_term:get(bc3_fold_pid, undefined) of
        undefined -> ok;
        Pid -> Pid ! bc3_go
    end.

second_start() ->
    Test = self(),
    Pid = spawn(fun() ->
        R = beamchain_rpc:handle_method(
              <<"scantxoutset">>, [<<"start">>, [<<"raw(51)">>]], undefined),
        Test ! {bc3_second, self(), R}
    end),
    receive {bc3_second, Pid, R} -> R
    after ?CALL_MS ->
        exit(Pid, kill),
        {timeout, second_start_blocked}
    end.

timed_call(Request) ->
    T0 = erlang:monotonic_time(millisecond),
    Res = try gen_server:call(beamchain_chainstate, Request, ?CALL_MS)
          catch exit:Reason -> {exit, Reason}
          end,
    {erlang:monotonic_time(millisecond) - T0, Res}.

canon_unspents(Map) ->
    lists:sort([{maps:get(<<"txid">>, U),
                 maps:get(<<"vout">>, U),
                 maps:get(<<"scriptPubKey">>, U),
                 maps:get(<<"amount">>, U),
                 maps:get(<<"coinbase">>, U),
                 maps:get(<<"height">>, U),
                 maps:get(<<"blockhash">>, U),
                 maps:get(<<"desc">>, U)}
                || U <- maps:get(<<"unspents">>, Map)]).

display_hash(Hash) ->
    beamchain_serialize:hex_encode(beamchain_serialize:reverse_bytes(Hash)).

display_txid(Tx) ->
    display_hash(beamchain_serialize:tx_hash(Tx)).

%%% ===================================================================
%%% Chain fixture (regtest, coinbase-only blocks, OP_TRUE outputs)
%%% ===================================================================

setup() ->
    TmpDir = filename:join(["/tmp", "beamchain_bc3_" ++
                            integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),
    application:ensure_all_started(crypto),
    application:ensure_all_started(rocksdb),
    application:set_env(beamchain, datadir, TmpDir),
    application:set_env(beamchain, network, regtest),
    application:set_env(beamchain, fatal_halt, false),
    os:unsetenv("BEAMCHAIN_DATADIR"),
    os:unsetenv("BEAMCHAIN_NETWORK"),
    os:unsetenv("BEAMCHAIN_TEST_HOOK_DIR"),
    catch beamchain_fault:clear_all(),
    catch persistent_term:erase(bc3_park_armed),
    catch persistent_term:erase(bc3_fold_pid),
    catch beamchain_fatal:reset_for_test(),
    catch gen_server:stop(beamchain_chainstate),
    catch beamchain_db:stop(),
    catch gen_server:stop(beamchain_config),
    delete_ets(),
    {ok, _} = beamchain_config:start_link(),
    {ok, _} = beamchain_db:start_link(),
    case whereis(beamchain_sig_cache) of
        undefined -> {ok, SP} = beamchain_sig_cache:start_link(), unlink(SP);
        _ -> ok
    end,
    {ok, Pid} = beamchain_chainstate:start_link(),
    unlink(Pid),
    TmpDir.

teardown(TmpDir) ->
    release_park(),
    catch beamchain_fault:clear_all(),
    catch persistent_term:erase(bc3_park_armed),
    catch persistent_term:erase(bc3_fold_pid),
    catch gen_server:stop(beamchain_chainstate),
    catch beamchain_db:stop(),
    catch gen_server:stop(beamchain_config),
    catch beamchain_fatal:reset_for_test(),
    delete_ets(),
    os:cmd("rm -rf " ++ TmpDir),
    ok.

delete_ets() ->
    lists:foreach(
      fun(T) ->
          case ets:info(T) of
              undefined -> ok;
              _ -> catch ets:delete(T)
          end
      end,
      [beamchain_utxo_cache, beamchain_utxo_dirty, beamchain_utxo_fresh,
       beamchain_utxo_spent, beamchain_chain_meta, beamchain_scantxoutset]).

ts(Height) ->
    erlang:system_time(second) - 200 * 600 + Height * 600.

coinbase(Height) ->
    HeightBin = beamchain_validation:encode_bip34_height(Height),
    ScriptSig = <<HeightBin/binary, 2, "b3", 0:32>>,
    #transaction{
        version = 1,
        inputs = [#tx_in{prev_out = #outpoint{hash = <<0:256>>,
                                              index = 16#ffffffff},
                         script_sig = ScriptSig, sequence = 16#ffffffff,
                         witness = []}],
        outputs = [#tx_out{value = 5000000000, script_pubkey = ?OP_TRUE}],
        locktime = 0}.

mine_block(PrevHash, Height, Txs, Ts) ->
    TxHashes = [beamchain_serialize:tx_hash(T) || T <- Txs],
    Root = beamchain_serialize:compute_merkle_root(TxHashes),
    H0 = #block_header{version = 16#20000000, prev_hash = PrevHash,
                       merkle_root = Root, timestamp = Ts,
                       bits = 16#207fffff, nonce = 0},
    H = grind(H0, 0),
    #block{header = H, transactions = Txs,
           hash = beamchain_serialize:block_hash(H), height = Height}.

grind(H0, N) when N < 1000000 ->
    H = H0#block_header{nonce = N},
    PowLimit = maps:get(pow_limit, beamchain_chain_params:params(regtest)),
    case beamchain_pow:check_pow(beamchain_serialize:block_hash(H),
                                 H#block_header.bits, PowLimit) of
        true -> H;
        false -> grind(H0, N + 1)
    end.

next_block(Txs) ->
    {ok, {TipHash, TipH}} = beamchain_chainstate:get_tip(),
    H = TipH + 1,
    mine_block(TipHash, H, [coinbase(H) | Txs], ts(H)).

build_chain(ToHeight) ->
    {ok, {_, TipH}} = beamchain_chainstate:get_tip(),
    lists:foreach(fun(_) ->
        ok = beamchain_chainstate:connect_block(next_block([]))
    end, lists:seq(TipH + 1, ToHeight)).
