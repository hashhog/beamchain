-module(beamchain_status_repair_tests).

%%% status_repair_v1: one-shot boot sweep that repairs block-index status
%%% bits clobbered by the pre-fix block_sync "step 5" (status assigned 2
%%% over VALID_SCRIPTS|HAVE_DATA|HAVE_UNDO). See beamchain_chainstate
%%% maybe_schedule_status_repair/2 and beamchain_db:repair_status_chunk/4.
%%%
%%% Rules under test (never lower anything):
%%%   - only the active chain (walk down from the tip by prev_hash)
%%%   - HAVE_DATA only where the body exists, HAVE_UNDO only where undo exists
%%%   - validity raised to VALID_SCRIPTS only when both exist
%%%   - FAILED entries untouched; entries above the tip untouched
%%%   - marker set on completion -> second boot does nothing; a forced second
%%%     pass changes 0 entries (idempotent)
%%%
%%% CONTROL: `rebar3 eunit --module=beamchain_status_repair_tests`

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

-define(N, 8).
-define(KEY, <<"status_repair_v1">>).

boot_repair_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) -> {timeout, 60, fun boot_repair/0} end}.

mismatch_stops_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) -> {timeout, 60, fun mismatch_stops_without_marker/0} end}.

fresh_datadir_marks_done_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) -> {timeout, 60, fun fresh_datadir_marks_done/0} end}.

%%% ===================================================================

setup() ->
    TmpDir = filename:join(["/tmp",
                            "beamchain_status_repair_test_" ++
                            integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),
    application:ensure_all_started(crypto),
    application:ensure_all_started(rocksdb),
    application:set_env(beamchain, datadir, TmpDir),
    application:set_env(beamchain, network, regtest),
    %% Another module may have left BEAMCHAIN_DATADIR set; it outranks the
    %% application env and would point this fixture at a foreign datadir.
    os:unsetenv("BEAMCHAIN_DATADIR"),
    catch gen_server:stop(beamchain_chainstate),
    catch beamchain_db:stop(),
    catch gen_server:stop(beamchain_config),
    delete_chainstate_ets(),
    {ok, _} = beamchain_config:start_link(),
    {ok, _} = beamchain_db:start_link(),
    {module, beamchain_validation} = code:ensure_loaded(beamchain_validation),
    ok = meck:new(beamchain_validation, [no_link, passthrough]),
    ok = meck:expect(beamchain_validation, connect_block,
                     fun(_Block, _Height, _Prev, _Params) -> ok end),
    ok = meck:expect(beamchain_validation, check_block,
                     fun(_Block, _Params) -> ok end),
    TmpDir.

teardown(TmpDir) ->
    catch gen_server:stop(beamchain_chainstate),
    catch meck:unload(beamchain_validation),
    catch beamchain_db:stop(),
    catch gen_server:stop(beamchain_config),
    delete_chainstate_ets(),
    os:cmd("rm -rf " ++ TmpDir),
    ok.

delete_chainstate_ets() ->
    lists:foreach(
      fun(T) ->
          case ets:info(T) of
              undefined -> ok;
              _ -> ets:delete(T)
          end
      end,
      [beamchain_utxo_cache, beamchain_utxo_dirty, beamchain_utxo_fresh,
       beamchain_utxo_spent, beamchain_chain_meta]).

dummy_block(PrevHash, Height, Salt) ->
    Header = #block_header{
        version = 4,
        prev_hash = PrevHash,
        merkle_root = <<Height:128, Salt:128>>,
        timestamp = 1296688602 + Height,
        bits = 16#207fffff,
        nonce = Height + Salt
    },
    Hash = beamchain_serialize:block_hash(Header),
    Coinbase = #transaction{
        version = 1,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = <<0:256>>, index = 16#ffffffff},
            script_sig = <<Height:32/little, Salt:32/little>>,
            sequence = 16#ffffffff,
            witness = []
        }],
        outputs = [#tx_out{value = 5000000000, script_pubkey = <<16#51>>}],
        locktime = 0
    },
    #block{header = Header, transactions = [Coinbase], hash = Hash}.

%% What a datadir written by the OLD code looks like (plus edge cases):
%%   0        genesis, body + undo, status 29 (connected by chainstate init)
%%   1..2     snapshot-like: index only, NO body, status 1
%%   3        body, NO undo, clobbered status 2
%%   4..N-1   body + undo, clobbered status 2       <- the bulk
%%   N        body + undo, status 2|32 (FAILED)     -- but it is the tip
%% Tip = N-1 (N is failed, so roll-forward stops there).
%%   N+1      body + undo, status 2, ABOVE the tip  -> must stay 2
%% Returns #{Height => Hash}.
build_old_datadir() ->
    Genesis = beamchain_chain_params:genesis_block(regtest),
    G = Genesis#block.hash,
    ok = beamchain_db:store_block(Genesis, 0),
    ok = beamchain_db:store_undo(G, <<>>),
    ok = beamchain_db:store_block_index(0, G, Genesis#block.header, <<0:256>>, 29, 1),
    {_, Map} = lists:foldl(
      fun(H, {Prev, Acc}) ->
          B = dummy_block(Prev, H, 0),
          Hash = B#block.hash,
          CW = <<H:256>>,
          if
              H =< 2 ->
                  ok = beamchain_db:store_block_index(H, Hash, B#block.header, CW, 1, 1);
              H =:= 3 ->
                  ok = beamchain_db:store_block(B, H),
                  ok = beamchain_db:store_block_index(H, Hash, B#block.header, CW, 2, 1);
              H =:= ?N ->
                  ok = beamchain_db:store_block(B, H),
                  ok = beamchain_db:store_undo(Hash, <<1>>),
                  ok = beamchain_db:store_block_index(H, Hash, B#block.header, CW, 2 bor 32, 1);
              true ->
                  ok = beamchain_db:store_block(B, H),
                  ok = beamchain_db:store_undo(Hash, <<1>>),
                  ok = beamchain_db:store_block_index(H, Hash, B#block.header, CW, 2, 1)
          end,
          {Hash, Acc#{H => Hash}}
      end, {G, #{0 => G}}, lists:seq(1, ?N + 1)),
    ok = beamchain_db:set_chain_tip(maps:get(?N - 1, Map), ?N - 1),
    Map.

status_at(H) ->
    {ok, #{status := S}} = beamchain_db:get_block_index(H),
    S.

wait_marker(T) when T =< 0 ->
    erlang:error(status_repair_marker_never_set);
wait_marker(T) ->
    case beamchain_db:get_meta(?KEY) of
        {ok, V} -> V;
        not_found -> timer:sleep(20), wait_marker(T - 20)
    end.

start_chainstate() ->
    {ok, Pid} = beamchain_chainstate:start_link(),
    unlink(Pid),
    %% the sweep runs from self-messages after init; a call queued behind
    %% them returns only after every chunk already sent has been handled
    _ = beamchain_chainstate:get_tip(),
    ok.

%%% ===================================================================

boot_repair() ->
    Map = build_old_datadir(),
    ?assertEqual(not_found, beamchain_db:get_meta(?KEY)),
    ok = start_chainstate(),
    {ok, {_, Tip}} = beamchain_chainstate:get_tip(),
    ?assertEqual(?N - 1, Tip),
    Summary = wait_marker(5000),
    %% first boot: heights 3..N-1 change (5 entries), nothing else
    ?assertMatch(<<"done scanned=", _/binary>>, Summary),
    ?assertNotEqual(nomatch, binary:match(Summary, <<"changed=5 ">>)),
    ?assertNotEqual(nomatch, binary:match(Summary, <<"scanned=8 ">>)),
    ?assertEqual(29, status_at(0)),
    ?assertEqual(1, status_at(1)),               %% no body: no HAVE_DATA, level kept
    ?assertEqual(1, status_at(2)),
    ?assertEqual(2 bor 8, status_at(3)),         %% body, no undo: level NOT raised
    [?assertEqual(29, status_at(H)) || H <- lists:seq(4, ?N - 1)],
    ?assertEqual(2 bor 32, status_at(?N)),       %% failed + above tip: untouched
    ?assertEqual(2, status_at(?N + 1)),          %% above tip: untouched
    _ = Map,

    %% second boot: marker present -> no sweep; marker unchanged
    ok = gen_server:stop(beamchain_chainstate),
    delete_chainstate_ets(),
    ok = start_chainstate(),
    ?assertEqual({ok, Summary}, beamchain_db:get_meta(?KEY)),

    %% forced second pass (idempotence control): changes 0
    {ok, {TipHash, TipH}} = beamchain_chainstate:get_tip(),
    ?assertMatch({done, genesis, 8, 0},
                 beamchain_db:repair_status_chunk(TipH, TipHash, 1000, 1 bsl 30)),
    ok = gen_server:stop(beamchain_chainstate).

%% A cursor whose expected hash does not match the entry (the active chain
%% changed under the sweep) stops and leaves the marker unset.
mismatch_stops_without_marker() ->
    _ = build_old_datadir(),
    ?assertEqual({done, {mismatch, 5}, 0, 0},
                 beamchain_db:repair_status_chunk(5, <<9:256>>, 1000, 1 bsl 30)),
    ?assertEqual(2, status_at(5)),
    %% chunking: a 2-entry budget returns a resumable cursor
    {ok, #{hash := H6}} = beamchain_db:get_block_index(6),
    {ok, #{hash := H4}} = beamchain_db:get_block_index(4),
    ?assertEqual({continue, 4, H4, 2, 2},
                 beamchain_db:repair_status_chunk(6, H6, 2, 1 bsl 30)),
    ?assertEqual(not_found, beamchain_db:get_meta(?KEY)).

fresh_datadir_marks_done() ->
    ok = start_chainstate(),
    ?assertEqual({ok, <<"fresh">>}, beamchain_db:get_meta(?KEY)),
    ok = gen_server:stop(beamchain_chainstate).
