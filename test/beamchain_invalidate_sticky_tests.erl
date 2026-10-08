-module(beamchain_invalidate_sticky_tests).

%%% invalidateblock must STICK (BC-1, receipts/arch-concurrency-liveness-
%%% audit-2026-10-07.md, fleet brief #6), and must cost O(fork).
%%%
%%% Core (validation.cpp):
%%%   InvalidateBlock -- the block BLOCK_FAILED_VALID, descendants failed,
%%%     only the active branch disconnected, candidates from one pass;
%%%   InvalidChainFound -> RecalculateBestHeader -- the best header leaves
%%%     the failed branch;
%%%   AcceptBlockHeader -- "duplicate-invalid" for a failed block,
%%%     "bad-prevblk" for a child of one; a failed block is never
%%%     re-connected (FindMostWorkChain) nor re-requested (net_processing);
%%%   ResetBlockFailureFlags + ActivateBestChain -- reconsiderblock.
%%%
%%% beamchain bug (deployed 5b0419a): invalidateblock set BLOCK_FAILED_VALID
%%% in the index, but not the hash-keyed verdict header sync and block
%%% download honour; the best header stayed on the failed branch; no connect
%%% path checked failure.  The next announcement / stale-tip re-arm / a
%%% submitblock reconnected the invalidated block.  The best-chain search
%%% after it read EVERY block-index entry (get_all_block_indexes).
%%%
%%% CONTROL: `rebar3 eunit --module=beamchain_invalidate_sticky_tests`

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

-define(N, 6).
-define(FAILED_VALID, 32).

sticky_test_() ->
    {foreach, fun setup/0, fun teardown/1,
     [fun(_) -> {timeout, 60, {"connect / submitblock refuse the "
                               "invalidated block and its children",
                               fun connect_paths_refuse_failed/0}} end,
      fun(_) -> {timeout, 60, {"best header leaves the failed branch; its "
                               "headers are refused",
                               fun header_layer/0}} end,
      fun(_) -> {timeout, 60, {"invalidate/reconsider never walk the whole "
                               "block index",
                               fun no_whole_index_walk/0}} end]}.

%%% ===================================================================

setup() ->
    TmpDir = filename:join(["/tmp",
                            "beamchain_invalidate_sticky_test_" ++
                            integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),
    application:ensure_all_started(crypto),
    application:ensure_all_started(rocksdb),
    application:set_env(beamchain, datadir, TmpDir),
    application:set_env(beamchain, network, regtest),
    catch gen_server:stop(beamchain_header_sync),
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
    Blocks = store_dummy_chain(GenesisHash, 1, ?N, []),
    {?N, LastHash, _} = lists:last(Blocks),
    ok = beamchain_db:set_header_tip(LastHash, ?N),
    application:set_env(beamchain, invalidate_sticky_test_blocks, Blocks),
    {module, beamchain_validation} = code:ensure_loaded(beamchain_validation),
    ok = meck:new(beamchain_validation, [no_link, passthrough]),
    ok = meck:expect(beamchain_validation, connect_block,
                     fun(_Block, _Height, _Prev, _Params) -> ok end),
    ok = meck:expect(beamchain_validation, check_block,
                     fun(_Block, _Params) -> ok end),
    ok = meck:expect(beamchain_validation, contextual_check_block_header,
                     fun(_H, _P, _Params) -> ok end),
    ok = meck:expect(beamchain_validation, check_witness_malleation,
                     fun(_B, _H, _Params) -> ok end),
    ok = meck:expect(beamchain_validation, disconnect_block,
                     fun(Block, _Height, _Params) ->
                             {ok, beamchain_serialize:block_hash(Block#block.header)}
                     end),
    TmpDir.

teardown(TmpDir) ->
    catch gen_server:stop(beamchain_header_sync),
    catch gen_server:stop(beamchain_chainstate),
    catch meck:unload(beamchain_validation),
    catch meck:unload(beamchain_db),
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

%% [{Height, Hash, Block}] for 1..N; bodies + height index stored, chain tip
%% at genesis, so the chainstate boot rolls forward to N.
store_dummy_chain(_Prev, Height, N, Acc) when Height > N ->
    lists:reverse(Acc);
store_dummy_chain(PrevHash, Height, N, Acc) ->
    Block = dummy_block(PrevHash, Height, 0),
    Hash = Block#block.hash,
    ok = beamchain_db:store_block(Block, Height),
    ok = beamchain_db:store_block_index(Height, Hash, Block#block.header,
                                        <<Height:256>>, 29),
    store_dummy_chain(Hash, Height + 1, N, [{Height, Hash, Block} | Acc]).

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

tip_height() ->
    {ok, {_Hash, H}} = beamchain_chainstate:get_tip(),
    H.

blk(H) ->
    {ok, Bs} = application:get_env(beamchain, invalidate_sticky_test_blocks),
    {H, _, B} = lists:keyfind(H, 1, Bs),
    B.

hash_at(H) -> (blk(H))#block.hash.

%% Wait until a cast has been processed by Name (a sync call drains its mailbox).
drain(Name) ->
    _ = sys:get_state(Name),
    ok.

%%% ===================================================================

connect_paths_refuse_failed() ->
    {ok, _} = start_chainstate(),
    ?assertEqual(?N, tip_height()),
    ok = beamchain_chainstate:invalidate_block(hash_at(4)),
    ?assertEqual(3, tip_height()),
    %% The block and every descendant carry the failed verdict.
    [?assert(beamchain_chainstate:is_known_invalid(hash_at(H)))
     || H <- [4, 5, ?N]],
    ?assertNot(beamchain_chainstate:is_known_invalid(hash_at(3))),

    %% Block download / roll-forward path: connect_block(4) on tip 3.
    ?assertEqual({error, duplicate_invalid},
                 beamchain_chainstate:connect_block(blk(4))),
    ?assertEqual(3, tip_height()),
    %% submitblock of the invalidated block: Core "duplicate-invalid".
    ?assertEqual({error, duplicate_invalid},
                 beamchain_chainstate:submit_block(blk(4), true)),
    ?assertEqual(3, tip_height()),
    %% A NEW child on the failed branch (N+1 on top of N): Core
    %% BLOCK_INVALID_PREV "bad-prevblk"; never stored, never activated.
    Child = dummy_block(hash_at(?N), ?N + 1, 0),
    ?assertEqual({error, invalid_prevblk},
                 beamchain_chainstate:submit_block(Child, true)),
    ?assertEqual(3, tip_height()),
    ?assertEqual({error, invalid_prevblk},
                 beamchain_chainstate:submit_header(Child#block.header)),

    %% Negative control: reconsiderblock lifts it (block, descendants) and
    %% re-activates the best chain; the same child then connects.
    ok = beamchain_chainstate:reconsider_block(hash_at(4)),
    ?assertEqual(?N, tip_height()),
    [?assertNot(beamchain_chainstate:is_known_invalid(hash_at(H)))
     || H <- [4, 5, ?N]],
    ?assertEqual({ok, active}, beamchain_chainstate:submit_block(Child, true)),
    ?assertEqual(?N + 1, tip_height()),
    ok = gen_server:stop(beamchain_chainstate).

header_layer() ->
    {ok, _} = start_chainstate(),
    {ok, HS} = beamchain_header_sync:start_link(),
    unlink(HS),
    ?assertMatch({ok, #{height := ?N}}, beamchain_db:get_header_tip()),
    ok = beamchain_chainstate:invalidate_block(hash_at(4)),
    drain(beamchain_header_sync),
    %% Core RecalculateBestHeader: the best header is the active tip again,
    %% so block download has nothing on the failed branch to fetch.
    H3 = hash_at(3),
    ?assertMatch({ok, #{hash := H3, height := 3}}, beamchain_db:get_header_tip()),
    ?assertMatch(#{tip_height := 3}, beamchain_header_sync:get_status()),

    %% The network announces the failed branch again: the invalidated
    %% header itself, and a new header N+1 on top of it.  Both refused.
    Child = dummy_block(hash_at(?N), ?N + 1, 0),
    beamchain_header_sync:handle_headers(self(), [(blk(4))#block.header]),
    beamchain_header_sync:handle_headers(self(), [Child#block.header]),
    drain(beamchain_header_sync),
    ?assertMatch({ok, #{hash := H3, height := 3}}, beamchain_db:get_header_tip()),
    ?assertEqual(not_found,
                 beamchain_db:get_block_index_by_hash(Child#block.hash)),

    %% Negative control: reconsiderblock -> the best header returns to N.
    ok = beamchain_chainstate:reconsider_block(hash_at(4)),
    drain(beamchain_header_sync),
    ?assertEqual(?N, tip_height()),
    HN = hash_at(?N),
    ?assertMatch({ok, #{hash := HN, height := ?N}}, beamchain_db:get_header_tip()),
    ok = gen_server:stop(beamchain_header_sync),
    ok = gen_server:stop(beamchain_chainstate).

no_whole_index_walk() ->
    {ok, _} = start_chainstate(),
    ok = meck:new(beamchain_db, [no_link, passthrough]),
    ok = beamchain_chainstate:invalidate_block(hash_at(4)),
    ?assertEqual(3, tip_height()),
    ok = beamchain_chainstate:reconsider_block(hash_at(4)),
    ?assertEqual(?N, tip_height()),
    %% Core's cost is proportional to the disconnected blocks (+ one
    %% in-memory candidate pass); a scan of every block-index entry in the
    %% DB is a mainnet-sized read (~970k entries) on the only chainstate
    %% process.
    ?assertEqual(0, meck:num_calls(beamchain_db, get_all_block_indexes, '_')),
    meck:unload(beamchain_db),
    ok = gen_server:stop(beamchain_chainstate).
