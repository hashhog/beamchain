%%% Snapshot-boot / missing-history honesty for getblockchaininfo + getblockhash.
%%%
%%% Live mainnet (2026-09-17T22:50Z): getblock on Core's real block hash misses
%%% at 1 / 500000 / 900000 / 940000 and HAVEs from 960000, while
%%% getblockchaininfo reports pruned=false with no pruneheight. getblockhash(1)
%%% still answers because the height→hash index is dense — that is not the
%%% same as holding the body.
%%%
%%% Core (rpc/blockchain.cpp): pruned is true when the node does not hold the
%%% full chain; pruneheight is the first height with complete block data.
%%% getblockhash -8 is only for height < 0 or height > tip; an in-range height
%%% the node simply does not retain is -1 "Block not available (pruned data)"
%%% (same string Core's getblock uses for pruned bodies).
%%%
%%% This commit reports the truth. It does not backfill genesis→floor.
%%%
%%% CONTROL: `rebar3 eunit --module=beamchain_pruned_history_tests`

-module(beamchain_pruned_history_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

-define(RPC_MISC_ERROR, -1).
-define(RPC_INVALID_PARAMETER, -8).
-define(RPC_INVALID_ADDRESS_OR_KEY, -5).
-define(PRUNED_MSG, <<"Block not available (pruned data)">>).
-define(OOR_MSG, <<"Block height out of range">>).

rpc(Method, Params) ->
    beamchain_rpc:handle_method(Method, Params, undefined).

info_map() ->
    case rpc(<<"getblockchaininfo">>, []) of
        {ok_raw_json, Bin} ->
            jsx:decode(Bin, [{return_maps, true}]);
        {ok, Term} ->
            jsx:decode(jsx:encode(Term), [{return_maps, true}]);
        Other ->
            erlang:error({unexpected_getblockchaininfo, Other})
    end.

%%% ===================================================================
%%% Fixtures
%%% ===================================================================

with_fixture(SeedFun, TestFun) ->
    TmpDir = filename:join(["/tmp",
                            "beamchain_pruned_hist_" ++
                            integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),
    application:ensure_all_started(rocksdb),
    application:set_env(beamchain, datadir, TmpDir),
    application:set_env(beamchain, network, regtest),
    os:unsetenv("BEAMCHAIN_PRUNE"),
    {ok, _} = start_or_ok(fun beamchain_config:start_link/0),
    {ok, _} = start_or_ok(fun beamchain_db:start_link/0),
    {module, beamchain_chainstate} = code:ensure_loaded(beamchain_chainstate),
    ok = meck:new(beamchain_chainstate, [no_link]),
    try
        {TipHash, TipH} = SeedFun(),
        ok = meck:expect(beamchain_chainstate, get_tip,
                         fun() -> {ok, {TipHash, TipH}} end),
        ok = meck:expect(beamchain_chainstate, get_mtp,
                         fun() -> 1231006505 end),
        ok = meck:expect(beamchain_chainstate, is_synced,
                         fun() -> true end),
        TestFun(TipHash, TipH)
    after
        catch meck:unload(beamchain_chainstate),
        catch beamchain_db:stop(),
        catch gen_server:stop(beamchain_config),
        os:unsetenv("BEAMCHAIN_PRUNE"),
        os:cmd("rm -rf " ++ TmpDir)
    end.

start_or_ok(StartFun) ->
    case StartFun() of
        {ok, Pid} -> {ok, Pid};
        {error, {already_started, Pid}} -> {ok, Pid}
    end.

make_block(PrevHash, Height) ->
    Header = #block_header{
        version = 1,
        prev_hash = PrevHash,
        merkle_root = <<Height:256>>,
        timestamp = 1231006505 + Height,
        bits = 16#1d00ffff,
        nonce = Height
    },
    CoinbaseTx = #transaction{
        version = 1,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = <<0:256>>, index = 16#ffffffff},
            script_sig = <<Height:32/big>>,
            sequence = 16#ffffffff,
            witness = []
        }],
        outputs = [#tx_out{
            value = 5000000000,
            script_pubkey = <<16#76, 16#a9, 16#14,
                              0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                              16#88, 16#ac>>
        }],
        locktime = 0
    },
    Hash = beamchain_serialize:block_hash(Header),
    #block{header = Header, transactions = [CoinbaseTx], hash = Hash,
           height = Height}.

store_index(Height, Block) ->
    ok = beamchain_db:store_block_index(
           Height, Block#block.hash, Block#block.header,
           <<Height:256>>, 1).

store_body(Height, Block) ->
    ok = beamchain_db:store_block(Block, Height).

%% Genesis body + index, then index+body for Floor..Tip. Hole in 1..Floor-1
%% for both the height index and the body store. Mirrors rustoshi/clearbit
%% snapshot-boot index hole, and is the CONTROL for getblockhash -1 vs -8.
seed_index_and_body_hole(Floor, Tip) ->
    Genesis = make_block(<<0:256>>, 0),
    store_index(0, Genesis),
    store_body(0, Genesis),
    Last = lists:foldl(
             fun(H, Prev) ->
                 B = make_block(Prev#block.hash, H),
                 store_index(H, B),
                 store_body(H, B),
                 B
             end, Genesis, lists:seq(Floor, Tip)),
    ok = beamchain_db:set_chain_tip(Last#block.hash, Tip),
    {Last#block.hash, Tip}.

%% Dense height index 0..Tip (getblockhash(1) answers) but bodies only
%% from Floor..Tip. Live beamchain shape as of 2026-09-17.
seed_dense_index_body_hole(Floor, Tip) ->
    Genesis = make_block(<<0:256>>, 0),
    store_index(0, Genesis),
    store_body(0, Genesis),
    Last = lists:foldl(
             fun(H, Prev) ->
                 B = make_block(Prev#block.hash, H),
                 store_index(H, B),
                 case H >= Floor of
                     true -> store_body(H, B);
                     false -> ok
                 end,
                 B
             end, Genesis, lists:seq(1, Tip)),
    ok = beamchain_db:set_chain_tip(Last#block.hash, Tip),
    {Last#block.hash, Tip}.

seed_complete(Tip) ->
    Genesis = make_block(<<0:256>>, 0),
    store_index(0, Genesis),
    store_body(0, Genesis),
    Last = lists:foldl(
             fun(H, Prev) ->
                 B = make_block(Prev#block.hash, H),
                 store_index(H, B),
                 store_body(H, B),
                 B
             end, Genesis, lists:seq(1, Tip)),
    ok = beamchain_db:set_chain_tip(Last#block.hash, Tip),
    {Last#block.hash, Tip}.

%%% ===================================================================
%%% getblockchaininfo honesty
%%% ===================================================================

complete_chain_reports_pruned_false_test() ->
    with_fixture(
      fun() -> seed_complete(10) end,
      fun(_TipHash, _TipH) ->
          Info = info_map(),
          ?assertEqual(false, maps:get(<<"pruned">>, Info)),
          ?assertEqual(false, maps:is_key(<<"pruneheight">>, Info)),
          ?assertEqual(false, maps:is_key(<<"prune_target_size">>, Info))
      end).

snapshot_hole_reports_pruned_true_and_pruneheight_test() ->
    Floor = 10,
    Tip = 20,
    with_fixture(
      fun() -> seed_index_and_body_hole(Floor, Tip) end,
      fun(_TipHash, _TipH) ->
          Info = info_map(),
          Pruned = maps:get(<<"pruned">>, Info),
          ?assertEqual(true, Pruned),
          ?assertEqual(Floor, maps:get(<<"pruneheight">>, Info)),
          ?assertEqual(false, maps:is_key(<<"prune_target_size">>, Info)),
          ?assertEqual(false, maps:is_key(<<"automatic_pruning">>, Info))
      end).

%% Live beamchain: getblockhash(1) works, bodies start at Floor.
dense_index_missing_bodies_reports_pruned_true_test() ->
    Floor = 10,
    Tip = 20,
    with_fixture(
      fun() -> seed_dense_index_body_hole(Floor, Tip) end,
      fun(_TipHash, _TipH) ->
          Info = info_map(),
          ?assertEqual(true, maps:get(<<"pruned">>, Info)),
          ?assertEqual(Floor, maps:get(<<"pruneheight">>, Info)),
          %% Index is dense: getblockhash of an in-range retained-index
          %% height still returns the hash (Core getblockhash is index-only).
          HashRes = rpc(<<"getblockhash">>, [5]),
          ?assertMatch({ok, Hash} when is_binary(Hash), HashRes)
      end).

%%% ===================================================================
%%% getblockhash: -1 in-range unretained, -8 out of range
%%% ===================================================================

getblockhash_below_floor_is_minus1_not_minus8_test() ->
    with_fixture(
      fun() -> seed_index_and_body_hole(10, 20) end,
      fun(_TipHash, _TipH) ->
          Res = rpc(<<"getblockhash">>, [1]),
          ?assertEqual({error, ?RPC_MISC_ERROR, ?PRUNED_MSG}, Res),
          ?assertNotEqual({error, ?RPC_INVALID_PARAMETER, ?OOR_MSG}, Res)
      end).

getblockhash_mid_hole_is_minus1_not_minus8_test() ->
    with_fixture(
      fun() -> seed_index_and_body_hole(10, 20) end,
      fun(_TipHash, _TipH) ->
          Res = rpc(<<"getblockhash">>, [5]),
          ?assertEqual({error, ?RPC_MISC_ERROR, ?PRUNED_MSG}, Res)
      end).

getblockhash_at_floor_returns_hash_test() ->
    with_fixture(
      fun() -> seed_index_and_body_hole(10, 20) end,
      fun(_TipHash, _TipH) ->
          Res = rpc(<<"getblockhash">>, [10]),
          ?assertMatch({ok, Hash} when is_binary(Hash) andalso byte_size(Hash) =:= 64, Res),
          TipRes = rpc(<<"getblockhash">>, [20]),
          ?assertMatch({ok, Hash} when is_binary(Hash) andalso byte_size(Hash) =:= 64, TipRes),
          GenRes = rpc(<<"getblockhash">>, [0]),
          ?assertMatch({ok, Hash} when is_binary(Hash) andalso byte_size(Hash) =:= 64, GenRes)
      end).

getblockhash_above_tip_is_still_minus8_test() ->
    with_fixture(
      fun() -> seed_index_and_body_hole(10, 20) end,
      fun(_TipHash, _TipH) ->
          Res = rpc(<<"getblockhash">>, [21]),
          ?assertEqual({error, ?RPC_INVALID_PARAMETER, ?OOR_MSG}, Res),
          Far = rpc(<<"getblockhash">>, [999999]),
          ?assertEqual({error, ?RPC_INVALID_PARAMETER, ?OOR_MSG}, Far)
      end).

getblockhash_negative_is_still_minus8_test() ->
    with_fixture(
      fun() -> seed_index_and_body_hole(10, 20) end,
      fun(_TipHash, _TipH) ->
          Res = rpc(<<"getblockhash">>, [-1]),
          ?assertEqual({error, ?RPC_INVALID_PARAMETER, ?OOR_MSG}, Res)
      end).

%%% ===================================================================
%%% getblock of a known-but-unretained body is pruned-data, not -5
%%% ===================================================================

getblock_missing_body_with_index_is_pruned_data_test() ->
    with_fixture(
      fun() -> seed_dense_index_body_hole(10, 20) end,
      fun(_TipHash, _TipH) ->
          {ok, HashHex} = rpc(<<"getblockhash">>, [5]),
          Res = rpc(<<"getblock">>, [HashHex]),
          ?assertEqual({error, ?RPC_MISC_ERROR, ?PRUNED_MSG}, Res),
          ?assertNotEqual({error, ?RPC_INVALID_ADDRESS_OR_KEY,
                           <<"Block not found">>}, Res)
      end).

getblock_at_floor_has_body_test() ->
    with_fixture(
      fun() -> seed_dense_index_body_hole(10, 20) end,
      fun(_TipHash, _TipH) ->
          {ok, HashHex} = rpc(<<"getblockhash">>, [10]),
          Res = rpc(<<"getblock">>, [HashHex, 0]),
          ?assertMatch({ok, Hex} when is_binary(Hex), Res)
      end).

%%% ===================================================================
%%% db-level floor detector
%%% ===================================================================

history_floor_none_when_complete_test() ->
    with_fixture(
      fun() -> seed_complete(10) end,
      fun(_TipHash, TipH) ->
          ?assertEqual(undefined, beamchain_db:history_floor(TipH)),
          ?assertEqual(undefined, beamchain_db:history_floor(0))
      end).

history_floor_finds_first_body_test() ->
    with_fixture(
      fun() -> seed_index_and_body_hole(10, 20) end,
      fun(_TipHash, TipH) ->
          ?assertEqual(10, beamchain_db:history_floor(TipH))
      end).

history_floor_finds_body_hole_behind_dense_index_test() ->
    with_fixture(
      fun() -> seed_dense_index_body_hole(10, 20) end,
      fun(_TipHash, TipH) ->
          ?assertEqual(10, beamchain_db:history_floor(TipH))
      end).
