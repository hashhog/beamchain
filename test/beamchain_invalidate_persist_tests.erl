-module(beamchain_invalidate_persist_tests).

%%% invalidateblock must survive a restart; reconsiderblock must undo it,
%%% also across a restart.
%%%
%%% Core (validation.cpp InvalidateBlock / ResetBlockFailureFlags): the
%%% disconnected blocks get BLOCK_FAILED_VALID in the block index, the dirty
%%% index entries are written by the next flush (blockstorage.cpp
%%% WriteBatchSync), and LoadBlockIndex never re-activates a failed block.
%%% reconsiderblock clears the flag on the block, its descendants and its
%%% ancestors and re-runs ActivateBestChain.
%%%
%%% beamchain bug (2026-10-02, intrablock-disconnect-probe invalidate path):
%%% the flag WAS persisted in the height-keyed block index, but the boot
%%% crash-recovery roll_forward_from_disk/1 re-connected every stored body
%%% above the flushed tip by height, without reading that flag — so a clean
%%% restart walked straight back onto the invalidated branch.
%%%
%%% CONTROL: `rebar3 eunit --module=beamchain_invalidate_persist_tests`

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

-define(N, 6).
-define(FAILED_VALID, 32).

invalidate_persist_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) -> {timeout, 60, fun invalidate_restart_reconsider_restart/0} end}.

descendants_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) -> {timeout, 60, fun descendants_and_stale_reverse_key/0} end}.

%%% ===================================================================

setup() ->
    TmpDir = filename:join(["/tmp",
                            "beamchain_invalidate_persist_test_" ++
                            integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),
    application:ensure_all_started(crypto),
    application:ensure_all_started(rocksdb),
    application:set_env(beamchain, datadir, TmpDir),
    application:set_env(beamchain, network, regtest),
    catch gen_server:stop(beamchain_chainstate),
    catch beamchain_db:stop(),
    catch gen_server:stop(beamchain_config),
    delete_chainstate_ets(),
    {ok, _} = beamchain_config:start_link(),
    {ok, _} = beamchain_db:start_link(),
    Genesis = beamchain_chain_params:genesis_block(regtest),
    GenesisHash = Genesis#block.hash,
    ok = beamchain_db:store_block(Genesis, 0),
    ok = beamchain_db:store_block_index(0, GenesisHash,
                                        Genesis#block.header, <<0:256>>, 29),
    ok = beamchain_db:set_chain_tip(GenesisHash, 0),
    Hashes = store_dummy_chain(GenesisHash, 1, ?N, []),
    application:set_env(beamchain, invalidate_persist_test_hashes, Hashes),
    {module, beamchain_validation} = code:ensure_loaded(beamchain_validation),
    ok = meck:new(beamchain_validation, [no_link, passthrough]),
    ok = meck:expect(beamchain_validation, connect_block,
                     fun(_Block, _Height, _Prev, _Params) -> ok end),
    %% Dummy blocks carry no real PoW / merkle root; the test is about the
    %% block-index state machine, not block validity.
    ok = meck:expect(beamchain_validation, check_block,
                     fun(_Block, _Params) -> ok end),
    ok = meck:expect(beamchain_validation, disconnect_block,
                     fun(Block, _Height, _Params) ->
                             {ok, beamchain_serialize:block_hash(Block#block.header)}
                     end),
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

%% Returns [{Height, Hash}] for 1..N; bodies + height index stored, chain_tip
%% left at genesis, so the first boot rolls forward to N exactly like a node
%% whose bodies are ahead of its flushed tip.
store_dummy_chain(_Prev, Height, N, Acc) when Height > N ->
    lists:reverse(Acc);
store_dummy_chain(PrevHash, Height, N, Acc) ->
    Block = dummy_block(PrevHash, Height, 0),
    Hash = Block#block.hash,
    ok = beamchain_db:store_block(Block, Height),
    ok = beamchain_db:store_block_index(Height, Hash, Block#block.header,
                                        <<Height:256>>, 29),
    store_dummy_chain(Hash, Height + 1, N, [{Height, Hash} | Acc]).

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

start_chainstate() ->
    {ok, Pid} = beamchain_chainstate:start_link(),
    unlink(Pid),
    {ok, Pid}.

%% Clean stop (terminate/2 flushes), fresh ETS, start again.
restart_chainstate() ->
    ok = gen_server:stop(beamchain_chainstate),
    delete_chainstate_ets(),
    start_chainstate().

tip_height() ->
    {ok, {_Hash, H}} = beamchain_chainstate:get_tip(),
    H.

hash_at(H) ->
    {ok, Hs} = application:get_env(beamchain, invalidate_persist_test_hashes),
    {H, Hash} = lists:keyfind(H, 1, Hs),
    Hash.

status_of(Hash) ->
    {ok, #{status := S}} = beamchain_db:get_block_index_by_hash(Hash),
    S.

failed(Hash) -> (status_of(Hash) band ?FAILED_VALID) =/= 0.

%%% ===================================================================

invalidate_restart_reconsider_restart() ->
    {ok, _} = start_chainstate(),
    ?assertEqual(?N, tip_height()),
    %% Mirror the probe: invalidate the tip, then its parent.
    ok = beamchain_chainstate:invalidate_block(hash_at(?N)),
    ?assertEqual(?N - 1, tip_height()),
    ok = beamchain_chainstate:invalidate_block(hash_at(?N - 1)),
    ?assertEqual(?N - 2, tip_height()),
    ?assert(failed(hash_at(?N - 1))),
    ?assert(failed(hash_at(?N))),
    ?assertNot(failed(hash_at(?N - 2))),

    %% (a)+(b): a clean restart boots and stays OFF the invalidated blocks.
    {ok, _} = restart_chainstate(),
    ?assertEqual(?N - 2, tip_height()),
    ?assert(failed(hash_at(?N - 1))),
    ?assert(failed(hash_at(?N))),

    %% (c): reconsiderblock(parent) clears it AND its descendant (Core
    %% ResetBlockFailureFlags) and returns to the best chain ...
    ok = beamchain_chainstate:reconsider_block(hash_at(?N - 1)),
    ?assertEqual(?N, tip_height()),
    ?assertNot(failed(hash_at(?N - 1))),
    ?assertNot(failed(hash_at(?N))),
    %% ... and that survives a restart too.
    {ok, _} = restart_chainstate(),
    ?assertEqual(?N, tip_height()),
    ok = gen_server:stop(beamchain_chainstate).

%% A block whose height slot was later overwritten by another block must not
%% be resolved to that other block by the hash lookup (the blkidx:<hash>
%% reverse key is never deleted), and invalidate/reconsider of it must not
%% flip the flag of the block that now owns the height.
descendants_and_stale_reverse_key() ->
    {ok, _} = start_chainstate(),
    ?assertEqual(?N, tip_height()),
    Old = hash_at(?N),
    %% Overwrite height N in the index with a different block B.
    B = dummy_block(hash_at(?N - 1), ?N, 7),
    ok = beamchain_db:store_block(B, ?N),
    ok = beamchain_db:store_block_index(?N, B#block.hash, B#block.header,
                                        <<?N:256>>, 29),
    ?assertEqual(not_found, beamchain_db:get_block_index_by_hash(Old)),
    ?assertMatch({error, _}, beamchain_db:update_block_status(Old, 29 bor 32)),
    {ok, #{status := SB}} = beamchain_db:get_block_index_by_hash(B#block.hash),
    ?assertEqual(0, SB band ?FAILED_VALID),
    ok = gen_server:stop(beamchain_chainstate).
