-module(beamchain_failed_reorg_restore_tests).

%%% KB-165: a heavier side branch that fails ConnectBlock must leave the
%%% original chain fully usable.
%%%
%%% Sequence (harness group warden_invalidated_submit, cut down):
%%%   active   G - 1 - 2 - 3
%%%   side             \- 3' - 4'   (4' pays 51 BTC: bad-cb-amount)
%%% Submitting 4' makes the side branch heavier, so beamchain disconnects 3,
%%% connects 3' (valid), fails 4' and rolls back to 3. Connecting 3' wrote
%%% the height-keyed index slot 3 (plus its blkidx: reverse key and cumtx:3)
%%% straight to RocksDB, outside the reorg's deferred batch, and the
%%% rollback never put block 3 back. The tip then had no index entry, so the
%%% next valid block on 3 failed with missing_prev_index (and mempool BIP68
%%% checks with missing_tip_index), before and after a restart.
%%%
%%% Core (validation.cpp ActivateBestChainStep / InvalidChainFound) keeps the
%%% hash-keyed block index intact, marks 4' BLOCK_FAILED_VALID and goes back
%%% to the original chain.
%%%
%%% KB-176: when the failed branch's valid prefix has more work than the old
%%% tip, Core stays on the prefix.  InvalidChainFound marks the failing block
%%% and ActivateBestChain/FindMostWorkChain picks the most-work candidate that
%%% is not failed, which is the prefix (validation.cpp:3161-3216, 3433-3442).
%%%   active   G - 1 - 2 - 3a - 4a - 5a
%%%   side             \- 3' - 4' - 5''   (5'' pays 51 BTC: bad-cb-amount)
%%% invalidateblock 4a leaves 3a as the tip with 5'' as the best candidate.
%%% Core v31.1 connects 3', 4', fails 5'' and ends on 4' (getchaintips: 4'
%%% active, 5'' invalid), also after a restart.
%%%
%%% KB-181: a block that loses its height slot (4a after the node moves to
%%% 4') must stay reachable by hash, as in Core's hash-keyed block index.
%%%   active   G - 1 - 2 - 3a - 4a [- 5a]
%%%   side             \- 3' - 4'          (valid, ties 4a)
%%% Core v31.1: invalidateblock 4a -> tip 4'; getblockheader/getblock 4a give
%%% confirmations -1, height 4.  reconsiderblock 4a -> back to 4a (equal work,
%%% 4a has the lower nSequenceId) or 5a (more work).  With a restart between
%%% invalidate and reconsider the tip 4' is loaded with nSequenceId 0 and 4a
%%% with 1, so Core stays on 4'.
%%%
%%%   rebar3 eunit --module=beamchain_failed_reorg_restore_tests

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-define(OP_TRUE, <<16#51>>).

failed_reorg_restore_test_() ->
    {foreach, fun setup/0, fun teardown/1,
     [fun(_) -> {timeout, 120, {Name, F}} end || {Name, F} <-
         [{"next valid block on the restored tip connects",
           fun next_block_after_failed_reorg/0},
          {"restored tip index survives a restart",
           fun restored_tip_survives_restart/0},
          {"the failing side block is marked invalid, its valid parent is not",
           fun failing_block_marked_invalid/0},
          {"a system fault during the reorg marks nothing",
           fun system_fault_marks_nothing/0},
          {"a failed reorg stays on a valid prefix with more work",
           fun failed_reorg_keeps_heavier_prefix/0},
          {"the heavier prefix survives a restart",
           fun heavier_prefix_survives_restart/0},
          {"invalidate/reconsider round trip, equal-work branch",
           fun reconsider_equal_work_returns/0},
          {"invalidate/reconsider round trip, heavier original branch",
           fun reconsider_heavier_returns/0},
          {"invalidate, restart, reconsider: the tip from disk keeps the tie",
           fun reconsider_after_restart_keeps_tip/0}]]}.

%%% ===================================================================
%%% Tests
%%% ===================================================================

next_block_after_failed_reorg() ->
    #{tip := {T3, 3}} = failed_side_reorg(),
    ?assertMatch({ok, #{hash := T3}}, beamchain_db:get_block_index_by_hash(T3)),
    ?assertMatch({ok, #{hash := T3}}, beamchain_db:get_block_index(3)),
    T4 = next_block([]),
    ?assertEqual({ok, active}, beamchain_chainstate:submit_block(T4)),
    ?assertEqual({ok, {T4#block.hash, 4}}, beamchain_chainstate:get_tip()).

restored_tip_survives_restart() ->
    #{tip := {T3, 3}} = failed_side_reorg(),
    restart(),
    ?assertEqual({ok, {T3, 3}}, beamchain_chainstate:get_tip()),
    ?assertMatch({ok, #{hash := T3}}, beamchain_db:get_block_index(3)),
    T4 = next_block([]),
    ?assertEqual({ok, active}, beamchain_chainstate:submit_block(T4)),
    restart(),
    ?assertEqual({ok, {T4#block.hash, 4}}, beamchain_chainstate:get_tip()),
    ?assertEqual({ok, active}, beamchain_chainstate:submit_block(next_block([]))).

failing_block_marked_invalid() ->
    #{side3 := S3, side4 := S4} = failed_side_reorg(),
    ?assert(beamchain_chainstate:is_known_invalid(S4#block.hash)),
    ?assertNot(beamchain_chainstate:is_known_invalid(S3#block.hash)),
    %% Core AcceptBlock: a known-invalid block answers duplicate-invalid.
    ?assertEqual({error, duplicate_invalid},
                 beamchain_chainstate:submit_block(S4)),
    %% 3' is still a side-branch block with its own index entry.
    ?assertMatch({ok, #{hash := _}},
                 beamchain_db:get_side_branch_index(S3#block.hash)).

system_fault_marks_nothing() ->
    build_chain(3),
    {ok, #{hash := T2}} = beamchain_db:get_block_index(2),
    S3 = mine_block(T2, 3, [coinbase(3, <<"s3">>, 5000000000)], ts(3) + 1),
    ?assertEqual({ok, side_branch}, beamchain_chainstate:submit_block(S3)),
    S4 = mine_block(S3#block.hash, 4, [coinbase(4, <<"s4">>, 5000000000)],
                    ts(4) + 1),
    %% The body + index write for 3' fails twice: a disk fault, class 2.
    S3Hash = S3#block.hash,
    beamchain_fault:set(direct_atomic_connect_writes,
        fun([_, _, _, H, _]) when H =:= S3Hash -> {error, injected_io};
           (_) -> passthrough
        end),
    R = beamchain_chainstate:submit_block(S4),
    beamchain_fault:clear(direct_atomic_connect_writes),
    io:format(user, "~n  [KB-165] reorg under an injected write fault -> ~p~n", [R]),
    ?assertMatch({error, _}, R),
    {error, Reason} = R,
    ?assert(beamchain_fatal:is_system_fault(Reason)),
    ?assertNot(beamchain_chainstate:is_known_invalid(S3#block.hash)),
    ?assertNot(beamchain_chainstate:is_known_invalid(S4#block.hash)).

failed_reorg_keeps_heavier_prefix() ->
    #{side3 := S3, side4 := S4, side5 := S5} = failed_prefix_reorg(),
    ?assertEqual({ok, {S4#block.hash, 4}}, beamchain_chainstate:get_tip()),
    ?assertMatch({ok, #{hash := H3}} when H3 =:= S3#block.hash,
                 beamchain_db:get_block_index(3)),
    ?assertMatch({ok, #{hash := H4}} when H4 =:= S4#block.hash,
                 beamchain_db:get_block_index(4)),
    ?assert(beamchain_chainstate:is_known_invalid(S5#block.hash)),
    ?assertNot(beamchain_chainstate:is_known_invalid(S3#block.hash)),
    ?assertNot(beamchain_chainstate:is_known_invalid(S4#block.hash)),
    ?assertEqual({error, duplicate_invalid},
                 beamchain_chainstate:submit_block(S5)),
    T5 = next_block([]),
    ?assertEqual({ok, active}, beamchain_chainstate:submit_block(T5)),
    ?assertEqual({ok, {T5#block.hash, 5}}, beamchain_chainstate:get_tip()).

heavier_prefix_survives_restart() ->
    #{side4 := S4, side5 := S5} = failed_prefix_reorg(),
    restart(),
    ?assertEqual({ok, {S4#block.hash, 4}}, beamchain_chainstate:get_tip()),
    ?assertMatch({ok, #{hash := H4}} when H4 =:= S4#block.hash,
                 beamchain_db:get_block_index(4)),
    ?assert(beamchain_chainstate:is_known_invalid(S5#block.hash)),
    T5 = next_block([]),
    ?assertEqual({ok, active}, beamchain_chainstate:submit_block(T5)),
    restart(),
    ?assertEqual({ok, {T5#block.hash, 5}}, beamchain_chainstate:get_tip()).

reconsider_equal_work_returns() ->
    #{a4 := A4, side4 := S4} = displaced_tip(4),
    assert_off_chain(A4, 4),
    ?assertEqual(ok, beamchain_chainstate:reconsider_block(A4)),
    ?assertEqual({ok, {A4, 4}}, beamchain_chainstate:get_tip()),
    ?assertMatch({ok, #{hash := A4}}, beamchain_db:get_block_index(4)),
    assert_off_chain(S4#block.hash, 4),
    restart(),
    ?assertEqual({ok, {A4, 4}}, beamchain_chainstate:get_tip()),
    assert_off_chain(S4#block.hash, 4).

reconsider_heavier_returns() ->
    #{a4 := A4, side4 := S4} = displaced_tip(5),
    assert_off_chain(A4, 4),
    ?assertEqual(ok, beamchain_chainstate:reconsider_block(A4)),
    {ok, {A5, 5}} = beamchain_chainstate:get_tip(),
    ?assertMatch({ok, #{hash := A4}}, beamchain_db:get_block_index(4)),
    ?assertMatch({ok, #{hash := A5}}, beamchain_db:get_block_index(5)),
    assert_off_chain(S4#block.hash, 4),
    T6 = next_block([]),
    ?assertEqual({ok, active}, beamchain_chainstate:submit_block(T6)).

reconsider_after_restart_keeps_tip() ->
    #{a4 := A4, side4 := S4} = displaced_tip(4),
    restart(),
    ?assertEqual({ok, {S4#block.hash, 4}}, beamchain_chainstate:get_tip()),
    assert_off_chain(A4, 4),
    ?assertEqual(ok, beamchain_chainstate:reconsider_block(A4)),
    ?assertEqual({ok, {S4#block.hash, 4}}, beamchain_chainstate:get_tip()),
    ?assertNot(beamchain_chainstate:is_known_invalid(A4)),
    assert_off_chain(A4, 4),
    restart(),
    ?assertEqual({ok, {S4#block.hash, 4}}, beamchain_chainstate:get_tip()),
    assert_off_chain(A4, 4).

%%% ===================================================================
%%% Helpers
%%% ===================================================================

%% Active chain to height 3, then 3' (valid) and 4' (bad-cb-amount) on 2.
failed_side_reorg() ->
    build_chain(3),
    {ok, {T3, 3}} = beamchain_chainstate:get_tip(),
    {ok, #{hash := T2}} = beamchain_db:get_block_index(2),
    S3 = mine_block(T2, 3, [coinbase(3, <<"s3">>, 5000000000)], ts(3) + 1),
    ?assertEqual({ok, side_branch}, beamchain_chainstate:submit_block(S3)),
    S4 = mine_block(S3#block.hash, 4, [coinbase(4, <<"s4">>, 5100000000)],
                    ts(4) + 1),
    R = beamchain_chainstate:submit_block(S4),
    io:format(user, "~n  [KB-165] submit 4' (bad-cb-amount) -> ~p~n", [R]),
    ?assertMatch({error, _}, R),
    ?assertEqual({ok, {T3, 3}}, beamchain_chainstate:get_tip()),
    #{tip => {T3, 3}, side3 => S3, side4 => S4}.

%% Active chain to 5, side branch 3' 4' 5'' (5'' bad-cb-amount) on 2, all
%% stored without a reorg (5'' only ties 5a).  invalidateblock 4a.
failed_prefix_reorg() ->
    build_chain(5),
    {ok, #{hash := T2}} = beamchain_db:get_block_index(2),
    {ok, #{hash := A4}} = beamchain_db:get_block_index(4),
    S3 = mine_block(T2, 3, [coinbase(3, <<"s3">>, 5000000000)], ts(3) + 1),
    S4 = mine_block(S3#block.hash, 4, [coinbase(4, <<"s4">>, 5000000000)],
                    ts(4) + 1),
    S5 = mine_block(S4#block.hash, 5, [coinbase(5, <<"s5">>, 5100000000)],
                    ts(5) + 1),
    [?assertEqual({ok, side_branch}, beamchain_chainstate:submit_block(B))
     || B <- [S3, S4, S5]],
    R = beamchain_chainstate:invalidate_block(A4),
    io:format(user, "~n  [KB-176] invalidateblock 4a -> ~p, tip ~p~n",
              [R, beamchain_chainstate:get_tip()]),
    ?assertEqual(ok, R),
    #{side3 => S3, side4 => S4, side5 => S5}.

%% Active chain to TipHeight, valid side branch 3' 4' on 2 (ties 4a), then
%% invalidateblock 4a: Core and this node move to 4', displacing 4a.
displaced_tip(TipHeight) ->
    build_chain(TipHeight),
    {ok, #{hash := T2}} = beamchain_db:get_block_index(2),
    {ok, #{hash := A4}} = beamchain_db:get_block_index(4),
    S3 = mine_block(T2, 3, [coinbase(3, <<"s3">>, 5000000000)], ts(3) + 1),
    S4 = mine_block(S3#block.hash, 4, [coinbase(4, <<"s4">>, 5000000000)],
                    ts(4) + 1),
    [?assertEqual({ok, side_branch}, beamchain_chainstate:submit_block(B))
     || B <- [S3, S4]],
    ?assertEqual(ok, beamchain_chainstate:invalidate_block(A4)),
    ?assertEqual({ok, {S4#block.hash, 4}}, beamchain_chainstate:get_tip()),
    #{a4 => A4, side4 => S4}.

%% Core getblockheader / getblock for a block off the active chain:
%% confirmations -1, its own height and chainwork, no nextblockhash.
assert_off_chain(Hash, Height) ->
    Hex = beamchain_serialize:hex_encode(beamchain_serialize:reverse_bytes(Hash)),
    ?assertMatch({ok, #{chainwork := _}}, lookup_any(Hash)),
    {ok, #{chainwork := CW}} = lookup_any(Hash),
    CWHex = beamchain_serialize:hex_encode(CW),
    lists:foreach(fun(Resp) ->
        ?assertMatch({ok_raw_json, _}, Resp),
        {ok_raw_json, Json} = Resp,
        M = jsx:decode(Json, [return_maps]),
        ?assertEqual(-1, maps:get(<<"confirmations">>, M)),
        ?assertEqual(Height, maps:get(<<"height">>, M)),
        ?assertEqual(CWHex, maps:get(<<"chainwork">>, M)),
        ?assertNot(maps:is_key(<<"nextblockhash">>, M))
    end, [beamchain_rpc:rpc_getblockheader([Hex, true]),
          beamchain_rpc:rpc_getblock([Hex, 1])]).

lookup_any(Hash) ->
    case beamchain_db:get_block_index_by_hash(Hash) of
        {ok, _} = Ok -> Ok;
        not_found -> beamchain_db:get_side_branch_index(Hash)
    end.

restart() ->
    ok = gen_server:stop(beamchain_chainstate),
    ok = beamchain_db:stop(),
    delete_chainstate_ets(),
    {ok, _} = beamchain_db:start_link(),
    {ok, Pid} = beamchain_chainstate:start_link(),
    unlink(Pid),
    ok.

setup() ->
    TmpDir = filename:join(["/tmp", "beamchain_kb165_" ++
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

coinbase(Height, Tag, Value) ->
    HeightBin = beamchain_validation:encode_bip34_height(Height),
    ScriptSig = <<HeightBin/binary, (byte_size(Tag)), Tag/binary, 0:32>>,
    #transaction{
        version = 1,
        inputs = [#tx_in{prev_out = #outpoint{hash = <<0:256>>,
                                              index = 16#ffffffff},
                         script_sig = ScriptSig, sequence = 16#ffffffff,
                         witness = []}],
        outputs = [#tx_out{value = Value, script_pubkey = ?OP_TRUE}],
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
    mine_block(TipHash, H, [coinbase(H, <<"kb">>, 5000000000) | Txs], ts(H)).

build_chain(ToHeight) ->
    {ok, {_, TipH}} = beamchain_chainstate:get_tip(),
    lists:foreach(fun(_) ->
        ok = beamchain_chainstate:connect_block(next_block([]))
    end, lists:seq(TipH + 1, ToHeight)).
