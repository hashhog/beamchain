-module(beamchain_f0_resurrection_tests).

%%% F0 coin-cache RESURRECTION (receipts/arch-f6-f7-design-2026-10-05.md §0,
%%% invariant I5): a reader outside the chainstate process (mempool ATMP,
%%% gettxout, REST, ...) misses ?UTXO_CACHE and reads coin X from RocksDB;
%%% meanwhile a block spends X (and a flush may commit the delete); the
%%% reader then installs its pre-spend copy as a clean, unspent cache entry.
%%% get_utxo/2 consults ?UTXO_CACHE before ?UTXO_SPENT, so X is "unspent"
%%% again and a later block spending X a second time is ACCEPTED.
%%%
%%% Core (coins.cpp:69-82 FetchCoin, :142-171 SpendCoin, cs_main): a spent
%%% entry stays DIRTY-spent until written and is never re-read from the base;
%%% every reader that fills the cache does so under cs_main, serialized with
%%% ConnectBlock and FlushStateToDisk. So none of these interleavings exist
%%% in Core.
%%%
%%% The interleavings are injected deterministically:
%%%   * windows A/B: meck wraps beamchain_db:get_utxo/2 (passthrough); for
%%%     the reader process only, it parks AFTER the real disk read and
%%%     BEFORE get_utxo/2 installs the result, while the test connects
%%%     (and flushes) a block that spends X.
%%%   * window C: the inert beamchain_fault seam `coins_spend_window` runs a
%%%     reader INSIDE spend_utxo/2 between its two coin-table updates.
%%%
%%% Every RACE test FAILS on 0426c66 (deployed) and passes on the fix; the
%%% CONTROL tests pass on both.
%%%
%%%   rebar3 eunit --module=beamchain_f0_resurrection_tests

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-define(OP_TRUE, <<16#51>>).

f0_test_() ->
    {foreach, fun setup/0, fun teardown/1,
     [fun(_) -> {timeout, 180, {Name, F}} end || {Name, F} <-
         [{"RACE A: read X, spend X + flush commit, install -> no resurrection, re-spend rejected",
           fun race_read_spend_flush_install/0},
          {"RACE B: read X, spend X (delete queued, unflushed), install -> no resurrection, re-spend rejected",
           fun race_read_spend_install_unflushed/0},
          {"RACE C: reader inside spend_utxo between its table updates -> sees spent, re-spend rejected",
           fun race_reader_inside_spend_window/0},
          {"CONTROL: plain double spend in the next block (no race) is rejected",
           fun control_plain_double_spend_rejected/0},
          {"CONTROL: a foreign reader with no race sees the coin; the block spending it connects",
           fun control_foreign_read_then_valid_spend/0}]]}.

%%% ===================================================================
%%% Tests
%%% ===================================================================

race_read_spend_flush_install() ->
    race_read_spend_install(true).

race_read_spend_install_unflushed() ->
    race_read_spend_install(false).

race_read_spend_install(DoFlush) ->
    {Txid, _} = X = prepare_disk_only_coin(),
    install_read_gate(),
    Test = self(),
    Reader = spawn(fun() ->
        put(f0_gate, Test),
        R = beamchain_chainstate:get_utxo(Txid, 0),
        Test ! {reader_done, self(), R}
    end),
    %% The reader has the disk copy of X in hand and has not installed it.
    receive {read_issued, Reader, {ok, _}} -> ok
    after 30000 -> error(reader_never_read)
    end,
    %% A block spends X (connect runs in the chainstate process).
    ?assertEqual(ok, beamchain_chainstate:connect_block(
                       next_block([spend_tx(X, 2400000000)]))),
    ?assertMatch({ok, {_, 102}}, beamchain_chainstate:get_tip()),
    case DoFlush of
        true ->
            ok = beamchain_chainstate:flush(),
            %% The delete is committed to RocksDB.
            ?assertEqual(not_found, beamchain_db:get_utxo(Txid, 0));
        false ->
            ok
    end,
    Reader ! f0_go,
    receive {reader_done, Reader, _} -> ok
    after 30000 -> error(reader_never_finished)
    end,
    meck:unload(beamchain_db),
    %% Resurrection check: the spent coin must stay spent.
    Seen = beamchain_chainstate:get_utxo(Txid, 0),
    io:format(user, "~n  [F0 ~s] get_utxo(X) after the race = ~p~n",
              [case DoFlush of true -> "A"; false -> "B" end, summarize(Seen)]),
    %% End to end: a second block spending X again must be rejected.
    assert_double_spend_rejected(X),
    ?assertEqual(not_found, Seen).

race_reader_inside_spend_window() ->
    {Txid, _} = X = prepare_disk_only_coin(),
    %% X is cached CLEAN (read through by the chainstate itself) so the
    %% spend takes the cached branch of spend_utxo/2.
    {ok, _} = gen_server_eval(fun() -> beamchain_chainstate:get_utxo(Txid, 0) end),
    ?assertMatch([_], ets:lookup(beamchain_utxo_cache, X)),
    Test = self(),
    beamchain_fault:set(coins_spend_window, fun([Key]) when Key =:= X ->
        %% A concurrent reader (mempool / RPC) runs in this window.
        Parent = self(),
        P = spawn(fun() -> Parent ! {win_read, self(),
                                     beamchain_chainstate:get_utxo(Txid, 0)} end),
        receive {win_read, P, R} -> Test ! {window_read, R} end,
        ok;
                                               (_) -> ok
    end),
    ?assertEqual(ok, beamchain_chainstate:connect_block(
                       next_block([spend_tx(X, 2400000000)]))),
    beamchain_fault:clear(coins_spend_window),
    WindowRead = receive {window_read, R} -> R after 30000 -> error(no_window_read) end,
    io:format(user, "~n  [F0 C] reader inside the spend window saw ~p~n",
              [summarize(WindowRead)]),
    Seen = beamchain_chainstate:get_utxo(Txid, 0),
    io:format(user, "  [F0 C] get_utxo(X) after the spend = ~p~n", [summarize(Seen)]),
    assert_double_spend_rejected(X),
    ?assertEqual(not_found, Seen),
    %% Core: the spend is atomic w.r.t. readers (cs_main); a reader never
    %% sees the coin as unspent once the spend has begun.
    ?assertEqual(not_found, WindowRead).

control_plain_double_spend_rejected() ->
    X = prepare_disk_only_coin(),
    ?assertEqual(ok, beamchain_chainstate:connect_block(
                       next_block([spend_tx(X, 2400000000)]))),
    assert_double_spend_rejected(X).

control_foreign_read_then_valid_spend() ->
    {Txid, _} = X = prepare_disk_only_coin(),
    Test = self(),
    spawn(fun() -> Test ! {r, beamchain_chainstate:get_utxo(Txid, 0)} end),
    receive {r, R} -> ?assertMatch({ok, #utxo{}}, R) after 30000 -> error(t) end,
    ?assertEqual(ok, beamchain_chainstate:connect_block(
                       next_block([spend_tx(X, 2400000000)]))),
    ?assertEqual(not_found, beamchain_chainstate:get_utxo(Txid, 0)),
    ok = beamchain_chainstate:flush(),
    ?assertEqual(not_found, beamchain_db:get_utxo(Txid, 0)).

%%% ===================================================================
%%% Helpers
%%% ===================================================================

assert_double_spend_rejected(X) ->
    R = beamchain_chainstate:connect_block(next_block([spend_tx(X, 2300000000)])),
    {ok, {_, Tip}} = beamchain_chainstate:get_tip(),
    io:format(user, "  [F0] connect of a block re-spending X -> ~p, tip ~B~n",
              [R, Tip]),
    ?assertNotEqual(ok, R),
    ?assertEqual(102, Tip).

summarize({ok, #utxo{value = V, height = H}}) -> {ok, {value, V, height, H}};
summarize(Other) -> Other.

%% Run Fun inside the chainstate process (the coins-cache owner).
gen_server_eval(Fun) ->
    Ref = make_ref(),
    Test = self(),
    sys:replace_state(beamchain_chainstate,
                      fun(S) -> Test ! {Ref, Fun()}, S end),
    receive {Ref, R} -> R after 30000 -> error(eval_timeout) end.

%% 101 blocks, flushed; coinbase output 0 of block 1 (= X) is on disk and
%% evicted from the cache (as maybe_evict_cache would), so the next read of
%% X is a cache miss that goes to RocksDB.
prepare_disk_only_coin() ->
    build_chain(101),
    ok = beamchain_chainstate:flush(),
    Txid = coinbase_txid_at(1),
    X = {Txid, 0},
    ?assertMatch({ok, _}, beamchain_db:get_utxo(Txid, 0)),
    ets:delete(beamchain_utxo_cache, X),
    ?assertEqual([], ets:lookup(beamchain_utxo_spent, X)),
    X.

%% Park the gated reader (the process with f0_gate in its dictionary) after
%% the real disk read returns and before its caller sees the result.
install_read_gate() ->
    ok = meck:new(beamchain_db, [no_link, passthrough]),
    meck:expect(beamchain_db, get_utxo, fun(T, V) ->
        Res = meck:passthrough([T, V]),
        case get(f0_gate) of
            undefined -> Res;
            Test ->
                Test ! {read_issued, self(), Res},
                receive f0_go -> ok end,
                Res
        end
    end).

setup() ->
    TmpDir = filename:join(["/tmp", "beamchain_f0_" ++
                            integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),
    application:ensure_all_started(crypto),
    application:ensure_all_started(rocksdb),
    application:set_env(beamchain, datadir, TmpDir),
    application:set_env(beamchain, network, regtest),
    application:set_env(beamchain, fatal_halt, false),
    os:unsetenv("BEAMCHAIN_DATADIR"),
    os:unsetenv("BEAMCHAIN_NETWORK"),
    catch beamchain_fault:clear_all(),
    catch beamchain_fatal:reset_for_test(),
    catch gen_server:stop(beamchain_mempool),
    catch gen_server:stop(beamchain_chainstate),
    catch beamchain_db:stop(),
    catch gen_server:stop(beamchain_config),
    delete_chainstate_ets(),
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
    catch meck:unload(beamchain_db),
    catch beamchain_fault:clear_all(),
    catch gen_server:stop(beamchain_chainstate),
    catch beamchain_db:stop(),
    catch gen_server:stop(beamchain_config),
    catch beamchain_fatal:reset_for_test(),
    delete_chainstate_ets(),
    os:cmd("rm -rf " ++ TmpDir),
    ok.

delete_chainstate_ets() ->
    lists:foreach(
      fun(T) ->
          case ets:info(T) of
              undefined -> ok;
              _ -> catch ets:delete(T)
          end
      end,
      [beamchain_utxo_cache, beamchain_utxo_dirty, beamchain_utxo_fresh,
       beamchain_utxo_spent, beamchain_chain_meta]).

ts(Height) ->
    erlang:system_time(second) - 200 * 600 + Height * 600.

coinbase(Height) ->
    HeightBin = beamchain_validation:encode_bip34_height(Height),
    ScriptSig = <<HeightBin/binary, 2, "f0", 0:32>>,
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

coinbase_txid_at(Height) ->
    {ok, #{hash := Hash}} = beamchain_db:get_block_index(Height),
    {ok, #block{transactions = [Cb | _]}} = beamchain_db:get_block(Hash),
    beamchain_serialize:tx_hash(Cb).

%% Spend X (an OP_TRUE output): no witness, no signature needed. Value
%% differs per call so two spends of X are two different txids.
spend_tx({Txid, Vout}, Value) ->
    #transaction{
        version = 1,
        inputs = [#tx_in{prev_out = #outpoint{hash = Txid, index = Vout},
                         script_sig = <<>>, sequence = 16#ffffffff,
                         witness = []}],
        outputs = [#tx_out{value = Value, script_pubkey = ?OP_TRUE}],
        locktime = 0}.
