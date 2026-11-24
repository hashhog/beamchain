%%% -prune must delete what beamchain actually stores.
%%%
%%% Block bodies live in the RocksDB `blocks` column family and undo data in
%%% the `undo` column family, both keyed by block hash. The prune code walked
%%% blk*.dat / rev*.dat flat files that nothing ever writes, so -prune freed
%%% nothing, getblockchaininfo.pruneheight never moved, and a pruned node kept
%%% advertising NODE_NETWORK.
%%%
%%% Core reference:
%%%   node/blockstorage.cpp FindFilesToPrune / FindFilesToPruneManual
%%%   validation.cpp Chainstate::GetPruneRange (keep MIN_BLOCKS_TO_KEEP = 288)
%%%   rpc/blockchain.cpp pruneblockchain, GetPruneHeight, getblockchaininfo
%%%   init.cpp:1947-1953 (NODE_NETWORK only when not pruned and no snapshot
%%%   chainstate still missing history)
%%%
%%% New exports (plan_prune/6, holds_full_history/0) are called through
%%% apply/3 so this file compiles against a tree without them and fails
%%% there by test name.
%%%
%%% CONTROL: rebar3 eunit --module=beamchain_prune_bodies_tests

-module(beamchain_prune_bodies_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

-define(NODE_NETWORK, 16#1).
-define(NODE_WITNESS, 16#8).
-define(NODE_NETWORK_LIMITED, 16#400).
-define(UNDO_BYTES, 4096).
-define(CHAIN, 1500).
-define(MIB, (1024 * 1024)).

%%% ===================================================================
%%% Fixture: a real beamchain_db on a scratch regtest datadir
%%% ===================================================================

start_db(PruneEnv) ->
    TmpDir = filename:join(["/tmp", "beamchain_prune_bodies_" ++
                            integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),
    application:ensure_all_started(rocksdb),
    application:set_env(beamchain, datadir, TmpDir),
    application:set_env(beamchain, network, regtest),
    case PruneEnv of
        undefined -> os:unsetenv("BEAMCHAIN_PRUNE");
        V -> os:putenv("BEAMCHAIN_PRUNE", V)
    end,
    {ok, _} = start_or_ok(fun beamchain_config:start_link/0),
    {ok, _} = start_or_ok(fun beamchain_db:start_link/0),
    TmpDir.

stop_db(TmpDir) ->
    catch beamchain_db:stop(),
    catch gen_server:stop(beamchain_config),
    os:unsetenv("BEAMCHAIN_PRUNE"),
    os:cmd("rm -rf " ++ TmpDir).

start_or_ok(F) ->
    case F() of
        {ok, P} -> {ok, P};
        {error, {already_started, P}} -> {ok, P}
    end.

with_db(PruneEnv, Fun) ->
    Dir = start_db(PruneEnv),
    try Fun(Dir) after stop_db(Dir) end.

%% Seed an active chain 0..Tip: body, height index entry and undo blob for
%% every height (genesis has no undo, as in Core), then mark Flushed as the
%% flushed tip. Returns #{Height => Hash}.
seed_chain(Tip, Flushed) ->
    Hashes = seed(0, Tip, <<0:256>>, #{}),
    ok = beamchain_db:set_chain_tip(maps:get(Flushed, Hashes), Flushed),
    Hashes.

seed(H, Tip, _Prev, Acc) when H > Tip ->
    Acc;
seed(H, Tip, Prev, Acc) ->
    Block = make_block(Prev, H),
    Hash = Block#block.hash,
    ok = beamchain_db:store_block(Block, H),
    ok = beamchain_db:store_block_index(H, Hash, Block#block.header,
                                        <<H:256>>, 29, 1),
    case H of
        0 -> ok;
        %% Random bytes: SSTs are block-compressed, so a repeated
        %% pattern would hide the size change the reclaim test measures.
        _ -> ok = beamchain_db:store_undo(Hash, crypto:strong_rand_bytes(?UNDO_BYTES))
    end,
    seed(H + 1, Tip, Hash, Acc#{H => Hash}).

make_block(Prev, N) ->
    Header = #block_header{version = 1, prev_hash = Prev,
                           merkle_root = crypto:hash(sha256, <<N:64>>),
                           timestamp = 1296688602 + N, bits = 16#207fffff,
                           nonce = N},
    Cb = #transaction{
            version = 1,
            inputs = [#tx_in{prev_out = #outpoint{hash = <<0:256>>,
                                                  index = 16#ffffffff},
                             script_sig = <<4, N:32/little>>,
                             sequence = 16#ffffffff, witness = []}],
            outputs = [#tx_out{value = 5000000000,
                               script_pubkey = <<16#51>>}],
            locktime = 0},
    #block{header = Header, transactions = [Cb],
           hash = beamchain_serialize:block_hash(Header)}.

has_body(Hashes, H) -> beamchain_db:has_block(maps:get(H, Hashes)).

has_undo(Hashes, H) ->
    case beamchain_db:get_undo(maps:get(H, Hashes)) of
        {ok, _} -> true;
        _ -> false
    end.

%% Live SST bytes of the blocks + undo column families, after flushing the
%% memtables so every byte written so far is in an SST file.
store_sst_bytes() ->
    Db = persistent_term:get(beamchain_db_handle),
    CFs = [persistent_term:get(beamchain_cf_blocks),
           persistent_term:get(beamchain_cf_undo)],
    [ok = rocksdb:flush(Db, CF, [{wait, true}]) || CF <- CFs],
    lists:sum([begin
                   {ok, B} = rocksdb:get_property(
                               Db, CF, <<"rocksdb.live-sst-files-size">>),
                   binary_to_integer(B)
               end || CF <- CFs]).

wait_compaction_idle(0) ->
    erlang:error(prune_compaction_still_running);
wait_compaction_idle(N) ->
    case maps:get(compacting, beamchain_db:get_prune_state(), false) of
        false -> ok;
        true -> timer:sleep(100), wait_compaction_idle(N - 1)
    end.

%%% ===================================================================
%%% Manual prune (-prune=1 / pruneblockchain) deletes bodies and undo
%%% ===================================================================

manual_prune_test_() ->
    {timeout, 120,
     [{"manual prune deletes bodies and undo up to the target",
       fun manual_prune_deletes_bodies_and_undo/0},
      {"manual prune keeps 288 blocks below the tip",
       fun manual_prune_keeps_288/0},
      {"keep window is measured from the FLUSHED tip",
       fun keep_window_from_flushed_tip/0},
      {"pruned space comes back after compaction",
       fun pruned_space_is_reclaimed/0},
      {"prune height survives a restart and genesis is kept",
       fun prune_height_persists/0},
      {"side-branch bodies below the prune height are deleted",
       fun side_branch_bodies_pruned/0},
      {"automatic trigger does nothing in -prune=1 mode",
       fun manual_mode_trigger_is_noop/0}]}.

manual_prune_deletes_bodies_and_undo() ->
    with_db("1", fun(_) ->
        Hashes = seed_chain(?CHAIN, ?CHAIN),
        {ok, R} = beamchain_db:prune_block_files_manual(1000),
        [?assertNot(has_body(Hashes, H)) || H <- [1, 2, 500, 999, 1000]],
        [?assertNot(has_undo(Hashes, H)) || H <- [1, 500, 1000]],
        [?assert(has_body(Hashes, H)) || H <- [1001, 1212, 1213, ?CHAIN]],
        [?assert(has_undo(Hashes, H)) || H <- [1001, ?CHAIN]],
        ?assertEqual(1000, maps:get(last_pruned, R, undefined)),
        ?assertEqual(1000, maps:get(pruned_count, R)),
        ?assert(beamchain_db:is_block_pruned(maps:get(500, Hashes))),
        ?assertNot(beamchain_db:is_block_pruned(maps:get(1001, Hashes))),
        %% getblockchaininfo.pruneheight = first height still held.
        ?assertEqual(1001, maps:get(prune_height, beamchain_db:get_prune_state())),
        %% getblock on a pruned body: index entry present, body gone.
        ?assertEqual(not_found, beamchain_db:get_block(maps:get(500, Hashes))),
        ?assertMatch({ok, #{hash := _}},
                     beamchain_db:get_block_index_by_hash(maps:get(500, Hashes)))
    end).

manual_prune_keeps_288() ->
    with_db("1", fun(_) ->
        Hashes = seed_chain(?CHAIN, ?CHAIN),
        {ok, R} = beamchain_db:prune_block_files_manual(?CHAIN),
        %% Core GetPruneRange: last prunable = tip - MIN_BLOCKS_TO_KEEP.
        ?assertNot(has_body(Hashes, ?CHAIN - 288)),
        ?assertEqual(?CHAIN - 288, maps:get(last_pruned, R, undefined)),
        %% The 288 blocks tip-287..tip keep body AND undo: enough to
        %% disconnect all of them in a reorg.
        [?assert(has_body(Hashes, H) andalso has_undo(Hashes, H))
         || H <- lists:seq(?CHAIN - 287, ?CHAIN)]
    end).

keep_window_from_flushed_tip() ->
    %% Bodies exist up to 1500 but only 1300 is flushed: boot roll-forward
    %% replays 1301..1500 from bodies, so nothing above 1300 - 288 may go.
    with_db("1", fun(_) ->
        Hashes = seed_chain(?CHAIN, 1300),
        {ok, R} = beamchain_db:prune_block_files_manual(?CHAIN),
        ?assertNot(has_body(Hashes, 1300 - 288)),
        ?assert(has_body(Hashes, 1300 - 287)),
        ?assertEqual(1300 - 288, maps:get(last_pruned, R, undefined))
    end).

pruned_space_is_reclaimed() ->
    with_db("1", fun(_) ->
        _ = seed_chain(?CHAIN, ?CHAIN),
        Before = store_sst_bytes(),
        {ok, _} = beamchain_db:prune_block_files_manual(?CHAIN),
        ok = wait_compaction_idle(600),
        After = store_sst_bytes(),
        %% 1212 of 1500 heights went (~4 KiB undo + body each). Demand at
        %% least half the store back, not an exact figure: SST sizes are
        %% block-compressed.
        ?assert(Before > 3 * 1024 * 1024),
        ?assert(After < Before div 2)
    end).

prune_height_persists() ->
    Dir = start_db("1"),
    try
        Hashes = seed_chain(?CHAIN, ?CHAIN),
        {ok, _} = beamchain_db:prune_block_files_manual(700),
        ok = beamchain_db:stop(),
        {ok, _} = start_or_ok(fun beamchain_db:start_link/0),
        ?assertNot(has_body(Hashes, 700)),
        ?assertEqual(701, maps:get(prune_height, beamchain_db:get_prune_state())),
        ?assertEqual(700, maps:get(last_pruned, beamchain_db:get_prune_state(),
                                   undefined)),
        %% Genesis is never pruned.
        ?assert(has_body(Hashes, 0)),
        %% A second prune continues from 701, not from 1.
        {ok, R} = beamchain_db:prune_block_files_manual(800),
        ?assertNot(has_body(Hashes, 800)),
        ?assert(has_body(Hashes, 801)),
        ?assertEqual(100, maps:get(pruned_count, R)),
        ?assertEqual(800, maps:get(last_pruned, R, undefined))
    after
        stop_db(Dir)
    end.

side_branch_bodies_pruned() ->
    with_db("1", fun(_) ->
        Hashes = seed_chain(?CHAIN, ?CHAIN),
        %% A competing block at height 600 and one at 1400, stored as
        %% side-branch blocks (body + hash-keyed side index).
        Low = make_block(maps:get(599, Hashes), 900600),
        High = make_block(maps:get(1399, Hashes), 901400),
        [begin
             ok = beamchain_db:store_block(B, H),
             ok = beamchain_db:store_side_branch_index(
                    B#block.hash, #{height => H, header => B#block.header,
                                    chainwork => <<H:256>>, status => 29,
                                    n_tx => 1})
         end || {B, H} <- [{Low, 600}, {High, 1400}]],
        {ok, _} = beamchain_db:prune_block_files_manual(1000),
        ?assertNot(beamchain_db:has_block(Low#block.hash)),
        ?assert(beamchain_db:is_block_pruned(Low#block.hash)),
        ?assert(beamchain_db:has_block(High#block.hash))
    end).

manual_mode_trigger_is_noop() ->
    with_db("1", fun(_) ->
        Hashes = seed_chain(?CHAIN, ?CHAIN),
        ok = beamchain_db:trigger_pruning(?CHAIN),
        _ = beamchain_db:get_prune_state(),            %% cast processed
        ?assert(has_body(Hashes, 1)),
        ?assertEqual({ok, 0}, beamchain_db:prune_block_files()),
        ?assert(has_body(Hashes, 1)),
        ?assertEqual(0, maps:get(prune_height, beamchain_db:get_prune_state()))
    end).

%%% ===================================================================
%%% Automatic prune (-prune=N) against a real store
%%% ===================================================================

%% Live SST + memtable bytes of blocks + undo: what the node measures.
store_bytes() ->
    Db = persistent_term:get(beamchain_db_handle),
    lists:sum([begin
                   {ok, B} = rocksdb:get_property(Db, persistent_term:get(CF), P),
                   binary_to_integer(B)
               end || CF <- [beamchain_cf_blocks, beamchain_cf_undo],
                      P <- [<<"rocksdb.live-sst-files-size">>,
                            <<"rocksdb.cur-size-all-mem-tables">>]]).

set_target(Bytes) ->
    ?assert(erlang:function_exported(beamchain_db, test_set_prune_target, 1)),
    apply(beamchain_db, test_set_prune_target, [Bytes]).

wait_last_pruned(0) ->
    erlang:error(auto_prune_did_not_run);
wait_last_pruned(N) ->
    case maps:get(last_pruned, beamchain_db:get_prune_state(), 0) of
        L when L > 0 -> L;
        _ -> timer:sleep(50), wait_last_pruned(N - 1)
    end.

auto_prune_test_() ->
    {timeout, 120,
     [{"auto prune honours the target: prunes only what it must",
       fun auto_prune_honours_target/0},
      {"auto prune on trigger_pruning (block connect path)",
       fun auto_prune_on_trigger/0},
      {"auto prune waits for PruneAfterHeight", fun auto_prune_after_height/0}]}.

auto_prune_honours_target() ->
    with_db("550", fun(_) ->
        Hashes = seed_chain(?CHAIN, ?CHAIN),
        %% Memtable size is reported per arena block (MBs at a time), so
        %% flush first: the node and this test then read the same bytes.
        _ = store_sst_bytes(),
        Usage = store_bytes(),
        %% Core stops once usage + 17 MiB buffer < target. Ask for about
        %% 2 MiB of the store to go: a partial prune, not "everything
        %% below the window".
        Target = 17 * ?MIB + Usage - 2 * ?MIB,
        ok = set_target(Target),
        {ok, N} = beamchain_db:prune_block_files(),
        Last = maps:get(last_pruned, beamchain_db:get_prune_state()),
        ?assert(N > 0),
        ?assert(Last > 0 andalso Last < ?CHAIN - 288),
        ?assertNot(has_body(Hashes, Last)),
        ?assert(has_body(Hashes, Last + 1)),
        %% Deleted bytes count at once (before any compaction; 2 MiB is
        %% under the 64 MiB compaction threshold, so none starts). They
        %% reach the 2 MiB goal and overshoot it by at most one block.
        Freed = maps:get(reclaim_pending, beamchain_db:get_prune_state()),
        ?assert(Freed > 2 * ?MIB),
        ?assert(Freed =< 2 * ?MIB + ?UNDO_BYTES + 1024),
        %% A second pass has little left: the flushed delete tombstones
        %% are real disk usage until compacted (~100 bytes per pruned
        %% block: about 2.5% of these 4 KiB test blocks, ~0.01% of a
        %% mainnet block), so it takes that share more and no further.
        _ = store_sst_bytes(),
        {ok, N2} = beamchain_db:prune_block_files(),
        ?assert(N2 =< N div 20 + 1)
    end).

auto_prune_on_trigger() ->
    with_db("550", fun(_) ->
        Hashes = seed_chain(?CHAIN, ?CHAIN),
        ok = set_target(1),           %% everything below the window must go
        ok = beamchain_db:trigger_pruning(?CHAIN),
        Last = wait_last_pruned(200),
        %% The cast re-queues itself step by step to the keep window.
        _ = (fun W(0) -> ok;
                 W(K) -> case maps:get(last_pruned,
                                       beamchain_db:get_prune_state()) of
                             L when L >= ?CHAIN - 288 -> ok;
                             _ -> timer:sleep(50), W(K - 1)
                         end
             end)(200),
        ?assert(Last > 0),
        ?assertEqual(?CHAIN - 288,
                     maps:get(last_pruned, beamchain_db:get_prune_state())),
        ?assertNot(has_body(Hashes, ?CHAIN - 288)),
        ?assert(has_body(Hashes, ?CHAIN - 287))
    end).

auto_prune_after_height() ->
    %% Core FindFilesToPrune: nothing while height <= PruneAfterHeight
    %% (1000 on regtest), however far over target.
    with_db("550", fun(_) ->
        Hashes = seed_chain(900, 900),
        ok = set_target(1),
        ?assertEqual({ok, 0}, beamchain_db:prune_block_files()),
        ?assert(has_body(Hashes, 1))
    end).

%%% ===================================================================
%%% Automatic prune planner (Core FindFilesToPrune, per height)
%%% ===================================================================


sizes(Bytes) -> fun(H) -> {ok, <<H:256>>, Bytes} end.

%% Assert the export first, so a tree without the planner fails on an
%% assertion here rather than on undef.
plan(From, Upto, Usage, Target, Steps, F) ->
    {module, _} = code:ensure_loaded(beamchain_db),
    ?assert(erlang:function_exported(beamchain_db, plan_prune, 6)),
    apply(beamchain_db, plan_prune, [From, Upto, Usage, Target, Steps, F]).

planner_test_() ->
    [{"no prune while usage + buffer is under the target",
      fun() ->
          ?assertMatch({0, [], 0, done},
                       plan(1, 5000, 500 * ?MIB, 550 * ?MIB, 2000, sizes(?MIB)))
      end},
     {"prunes oldest first until usage + buffer drops under the target",
      fun() ->
          %% 590 MiB used, 550 MiB target, 1 MiB per block: needs
          %% 590 - x + 17 < 550 -> x = 58 blocks.
          {Last, Items, Freed, done} =
              plan(1, 5000, 590 * ?MIB, 550 * ?MIB, 2000, sizes(?MIB)),
          ?assertEqual(58, Last),
          ?assertEqual(lists:seq(1, 58), [H || {H, _} <- Items]),
          ?assertEqual(58 * ?MIB, Freed)
      end},
     {"never above the last prunable height",
      fun() ->
          {Last, _, _, done} =
              plan(1, 40, 600 * ?MIB, 550 * ?MIB, 2000, sizes(?MIB)),
          ?assertEqual(40, Last)
      end},
     {"a bounded step reports more",
      fun() ->
          ?assertMatch({10, _, _, more},
                       plan(1, 5000, 9000 * ?MIB, 550 * ?MIB, 10, sizes(?MIB)))
      end},
     {"manual target prunes the whole range",
      fun() ->
          {Last, Items, _, done} = plan(1, 300, 0, manual, 2000, sizes(1)),
          ?assertEqual(300, Last),
          ?assertEqual(300, length(Items))
      end},
     {"heights that hold nothing are covered but not deleted",
      fun() ->
          F = fun(H) when H < 100 -> none; (H) -> {ok, <<H:256>>, 10} end,
          {Last, Items, Freed, done} = plan(1, 150, 0, manual, 2000, F),
          ?assertEqual(150, Last),
          ?assertEqual(51, length(Items)),
          ?assertEqual(510, Freed)
      end},
     {"genesis is never planned",
      fun() ->
          {_, Items, _, _} = plan(0, 10, 0, manual, 2000, sizes(1)),
          ?assertEqual(lists:seq(1, 10), [H || {H, _} <- Items])
      end},
     {"a step stops after about 64 MiB of data",
      fun() ->
          ?assertMatch({64, _, _, more},
                       plan(1, 5000, 9000 * ?MIB, 550 * ?MIB, 2000, sizes(?MIB)))
      end},
     {"buffer is part of the stop rule",
      fun() ->
          %% usage 540 MiB < target 550 but 540 + 17 >= 550: Core prunes.
          {Last, _, _, done} =
              plan(1, 5000, 540 * ?MIB, 550 * ?MIB, 2000, sizes(?MIB)),
          ?assertEqual(8, Last),
          ?assert(540 - Last + 17 < 550),
          ?assertNot(540 - (Last - 1) + 17 < 550)
      end}].

%%% ===================================================================
%%% NODE_NETWORK only with the full history (Core init.cpp:1947-1953)
%%% ===================================================================

services() -> beamchain_peer:advertised_services().

has_network(S) -> (S band ?NODE_NETWORK) =:= ?NODE_NETWORK.

services_test_() ->
    {timeout, 60,
     [{"full node holding block 1 keeps NODE_NETWORK",
       fun full_node_keeps_network/0},
      {"-prune mode drops NODE_NETWORK, keeps LIMITED | WITNESS",
       fun prune_mode_drops_network/0},
      {"snapshot-style store without block 1 drops NODE_NETWORK",
       fun missing_history_drops_network/0},
      {"getnetworkinfo localservices follows the same rule",
       fun localservices_follows/0}]}.

full_node_keeps_network() ->
    with_db(undefined, fun(_) ->
        _ = seed_chain(300, 300),
        S = services(),
        ?assert(has_network(S)),
        ?assert((S band ?NODE_NETWORK_LIMITED) =/= 0)
    end).

prune_mode_drops_network() ->
    %% Core: -prune clears NODE_NETWORK at startup, before anything is
    %% deleted.
    with_db("1", fun(_) ->
        _ = seed_chain(300, 300),
        S = services(),
        ?assertNot(has_network(S)),
        ?assertEqual(?NODE_NETWORK_LIMITED bor ?NODE_WITNESS,
                     S band (?NODE_NETWORK bor ?NODE_NETWORK_LIMITED
                             bor ?NODE_WITNESS))
    end).

missing_history_drops_network() ->
    %% -prune off, but the store does not hold block 1 (a snapshot boot
    %% that never fetched old bodies): the 11-23 fleet FLOOR MISMATCH.
    with_db(undefined, fun(_) ->
        Hashes = seed_chain(300, 300),
        Db = persistent_term:get(beamchain_db_handle),
        BlocksCF = persistent_term:get(beamchain_cf_blocks),
        [ok = rocksdb:delete(Db, BlocksCF, maps:get(H, Hashes), [])
         || H <- lists:seq(1, 200)],
        S = services(),
        ?assertNot(has_network(S)),
        ?assert((S band ?NODE_NETWORK_LIMITED) =/= 0),
        ?assert(erlang:function_exported(beamchain_db, holds_full_history, 0)),
        ?assertNot(apply(beamchain_db, holds_full_history, []))
    end).

localservices_follows() ->
    with_db("1", fun(_) ->
        _ = seed_chain(300, 300),
        Info = beamchain_rpc:networkinfo_proplist(0, 0, 0, []),
        Local = binary_to_integer(
                  proplists:get_value(<<"localservices">>, Info), 16),
        ?assertNot(has_network(Local)),
        ?assertEqual(Local, services())
    end).

%%% ===================================================================
%%% pruneblockchain RPC (Core rpc/blockchain.cpp)
%%% ===================================================================

rpc_test_() ->
    {timeout, 120,
     [{"pruneblockchain returns the last pruned height", fun rpc_returns_last_pruned/0},
      {"pruneblockchain rejects a negative height", fun rpc_negative/0},
      {"pruneblockchain: chain below PruneAfterHeight is too short", fun rpc_too_short/0},
      {"pruneblockchain: height above the tip", fun rpc_above_tip/0}]}.

with_rpc_chain(Tip, Fun) ->
    with_db("1", fun(_) ->
        Hashes = seed_chain(Tip, Tip),
        {module, _} = code:ensure_loaded(beamchain_chainstate),
        ok = meck:new(beamchain_chainstate, [no_link, passthrough]),
        try
            ok = meck:expect(beamchain_chainstate, get_tip,
                             fun() -> {ok, {maps:get(Tip, Hashes), Tip}} end),
            ok = meck:expect(beamchain_chainstate, flush, fun() -> ok end),
            Fun(Hashes)
        after
            meck:unload(beamchain_chainstate)
        end
    end).

prune_rpc(P) -> beamchain_rpc:handle_method(<<"pruneblockchain">>, P, undefined).

rpc_returns_last_pruned() ->
    with_rpc_chain(?CHAIN, fun(Hashes) ->
        %% Asked for 1400: clamped to tip - 288 = 1212, which Core returns
        %% (GetPruneHeight), and block 1212 is really gone.
        ?assertEqual({ok, ?CHAIN - 288}, prune_rpc([1400])),
        ?assertNot(has_body(Hashes, ?CHAIN - 288)),
        ?assert(has_body(Hashes, ?CHAIN - 287))
    end).

rpc_negative() ->
    with_rpc_chain(?CHAIN, fun(_) ->
        ?assertEqual({error, -8, <<"Negative block height.">>}, prune_rpc([-1]))
    end).

rpc_too_short() ->
    with_rpc_chain(900, fun(Hashes) ->
        ?assertEqual({error, -1, <<"Blockchain is too short for pruning.">>},
                     prune_rpc([100])),
        ?assert(has_body(Hashes, 1))
    end).

rpc_above_tip() ->
    with_rpc_chain(?CHAIN, fun(_) ->
        ?assertEqual({error, -8,
                      <<"Blockchain is shorter than the attempted prune height.">>},
                     prune_rpc([?CHAIN + 1]))
    end).
