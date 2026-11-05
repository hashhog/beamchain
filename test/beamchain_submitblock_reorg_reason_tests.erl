-module(beamchain_submitblock_reorg_reason_tests).

%%% submitblock BIP-22 reason token for blocks that do not simply extend
%%% the tip (Core regtest rows chain/submit/prev-not-found,
%%% failed_reorg/a/bad-4s, seed_invalidated_submit/submit/bad-cb-amount,
%%% warden_invalidated_submit/submit/failed-connect-bad-cb-amount).
%%%
%%% Core v31.1 rpc/mining.cpp submitblock answers BIP22ValidationResult of
%%% the state its submitblock_StateCatcher caught for the SUBMITTED block's
%%% hash, else "inconclusive":
%%%   * parent unknown: AcceptBlockHeader (validation.cpp:4217)
%%%     "prev-blk-not-found", BlockChecked from ProcessNewBlock (:4421-4423);
%%%   * a side block that makes its branch heavier and fails its own
%%%     ConnectBlock: ConnectTip fires BlockChecked for it (:3038-3039), so
%%%     the answer is ConnectBlock's reason (bad-cb-amount);
%%%   * an ANCESTOR of the submitted block fails ConnectBlock: BlockChecked
%%%     never fires for the submitted block -> "inconclusive".
%%% beamchain answered the generic "rejected" in all three cases.
%%%
%%% The reply is mapped through beamchain_rpc:bip22_result/1, the same
%%% function rpc_submitblock applies to beamchain_miner's {error, Reason}
%%% (the miner passes chainstate's error through unchanged).
%%%
%%%   rebar3 eunit --module=beamchain_submitblock_reorg_reason_tests

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-define(OP_TRUE, <<16#51>>).
-define(SUBSIDY, 5000000000).

submitblock_reorg_reason_test_() ->
    {foreach, fun setup/0, fun teardown/1,
     [fun(_) -> {timeout, 120, {Name, F}} end || {Name, F} <-
         [{"orphan block answers prev-blk-not-found",
           fun orphan_answers_prev_blk_not_found/0},
          {"side block failing its own connect in a reorg answers its reason",
           fun side_block_own_connect_failure_answers_reason/0},
          {"side block whose ancestor fails in a reorg answers inconclusive",
           fun side_block_ancestor_failure_answers_inconclusive/0},
          {"control: tip-extending bad block still answers bad-cb-amount",
           fun tip_extension_bad_cb_amount_control/0},
          {"control: valid heavier side block still reorgs (null)",
           fun valid_side_reorg_control/0}]]}.

%%% ===================================================================

answer(Block) ->
    case beamchain_chainstate:submit_block(Block, true) of
        {ok, Outcome} when Outcome =:= active; Outcome =:= reorg -> null;
        {ok, side_branch} -> <<"inconclusive">>;
        {ok, duplicate} -> <<"duplicate">>;
        {error, Reason} -> beamchain_rpc:bip22_result(Reason)
    end.

orphan_answers_prev_blk_not_found() ->
    build_chain(2),
    Orphan = mine_block(<<16#ab:256>>, 3,
                        [coinbase(3, <<"orphan">>, ?SUBSIDY)], ts(3)),
    ?assertEqual(<<"prev-blk-not-found">>, answer(Orphan)).

%% active G-1-2-3, side 3' (valid) then 4' (51 BTC) on 2: 4' makes the
%% side branch heavier, 3' connects, 4' fails its own ConnectBlock.
side_block_own_connect_failure_answers_reason() ->
    build_chain(3),
    {ok, {T3, 3}} = beamchain_chainstate:get_tip(),
    {ok, #{hash := T2}} = beamchain_db:get_block_index(2),
    S3 = mine_block(T2, 3, [coinbase(3, <<"s3">>, ?SUBSIDY)], ts(3) + 1),
    ?assertEqual(<<"inconclusive">>, answer(S3)),
    S4 = mine_block(S3#block.hash, 4,
                    [coinbase(4, <<"s4">>, ?SUBSIDY + 100000000)], ts(4) + 1),
    ?assertEqual(<<"bad-cb-amount">>, answer(S4)),
    ?assertEqual({ok, {T3, 3}}, beamchain_chainstate:get_tip()),
    ?assert(beamchain_chainstate:is_known_invalid(S4#block.hash)),
    ?assertNot(beamchain_chainstate:is_known_invalid(S3#block.hash)).

%% active G-1-2-3, side 3' (51 BTC, stored without connect at equal work)
%% then 4' (valid) on 3': the reorg fails connecting 3', never reaches 4'.
side_block_ancestor_failure_answers_inconclusive() ->
    build_chain(3),
    {ok, {T3, 3}} = beamchain_chainstate:get_tip(),
    {ok, #{hash := T2}} = beamchain_db:get_block_index(2),
    S3 = mine_block(T2, 3, [coinbase(3, <<"s3">>, ?SUBSIDY + 100000000)],
                    ts(3) + 1),
    ?assertEqual(<<"inconclusive">>, answer(S3)),
    S4 = mine_block(S3#block.hash, 4, [coinbase(4, <<"s4">>, ?SUBSIDY)],
                    ts(4) + 1),
    ?assertEqual(<<"inconclusive">>, answer(S4)),
    ?assertEqual({ok, {T3, 3}}, beamchain_chainstate:get_tip()),
    ?assert(beamchain_chainstate:is_known_invalid(S3#block.hash)),
    %% 3' is now known-invalid: resubmitting 3' / building on it is refused
    %% the way Core's AcceptBlockHeader refuses it.
    ?assertEqual(<<"duplicate-invalid">>, answer(S3)).

tip_extension_bad_cb_amount_control() ->
    build_chain(2),
    {ok, {T2, 2}} = beamchain_chainstate:get_tip(),
    Bad = mine_block(T2, 3, [coinbase(3, <<"bad">>, ?SUBSIDY + 1)], ts(3)),
    ?assertEqual(<<"bad-cb-amount">>, answer(Bad)),
    ?assertEqual({ok, {T2, 2}}, beamchain_chainstate:get_tip()).

valid_side_reorg_control() ->
    build_chain(3),
    {ok, #{hash := T2}} = beamchain_db:get_block_index(2),
    S3 = mine_block(T2, 3, [coinbase(3, <<"s3">>, ?SUBSIDY)], ts(3) + 1),
    ?assertEqual(<<"inconclusive">>, answer(S3)),
    S4 = mine_block(S3#block.hash, 4, [coinbase(4, <<"s4">>, ?SUBSIDY)],
                    ts(4) + 1),
    ?assertEqual(null, answer(S4)),
    ?assertEqual({ok, {S4#block.hash, 4}}, beamchain_chainstate:get_tip()).

%%% ===================================================================
%%% Fixture (same shape as beamchain_failed_reorg_restore_tests)
%%% ===================================================================

setup() ->
    TmpDir = filename:join(["/tmp", "beamchain_sbreason_" ++
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
    mine_block(TipHash, H, [coinbase(H, <<"sb">>, ?SUBSIDY) | Txs], ts(H)).

build_chain(ToHeight) ->
    {ok, {_, TipH}} = beamchain_chainstate:get_tip(),
    lists:foreach(fun(_) ->
        ok = beamchain_chainstate:connect_block(next_block([]))
    end, lists:seq(TipH + 1, ToHeight)).
