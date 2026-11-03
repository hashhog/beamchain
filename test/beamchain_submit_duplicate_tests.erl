-module(beamchain_submit_duplicate_tests).

%%% submitblock of a block whose body this node already stores answers
%%% BIP-22 "duplicate", as Core's does (fleet item
%%% refill-20261102-beamchain-consensus).
%%%
%%% Core v31.1:
%%%   rpc/mining.cpp:1096-1099 submitblock -- ProcessNewBlock(...,
%%%     &new_block); `if (!new_block && accepted) return "duplicate";`
%%%   validation.cpp:4318,4335 AcceptBlock -- `fAlreadyHave = pindex->nStatus
%%%     & BLOCK_HAVE_DATA; ... if (fAlreadyHave) return true;` with new_block
%%%     left false.  A side-branch block Core stored earlier has HAVE_DATA too,
%%%     so its resubmit is also "duplicate", not "inconclusive".
%%%   AcceptBlockHeader (validation.cpp:4195-4202) answers duplicate-invalid
%%%     for a known-failed block first; that order is kept.
%%%
%%% beamchain bug (master 03b9ac3): a block already stored took the side-
%%% branch path and came back {ok, side_branch} -> "inconclusive".  Core
%%% regtest rows: chain/submit/duplicate, seed_mempool_reorg/submit/active,
%%% seed_invalidated_submit/submit/duplicate,
%%% warden_invalidated_submit/submit/duplicate and
%%% warden_invalidated_submit/submit/inconclusive-resubmit.
%%%
%%% CONTROL: `rebar3 eunit --module=beamchain_submit_duplicate_tests`

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

-define(N, 6).

submit_duplicate_test_() ->
    {foreach, fun setup/0, fun teardown/1,
     [fun(_) -> {timeout, 60, {"resubmitting the active tip is duplicate",
                               fun active_tip_resubmit_is_duplicate/0}} end,
      fun(_) -> {timeout, 60, {"resubmitting a buried active block is "
                               "duplicate",
                               fun buried_active_resubmit_is_duplicate/0}} end,
      fun(_) -> {timeout, 60, {"resubmitting a stored side-branch block is "
                               "duplicate, not inconclusive",
                               fun side_branch_resubmit_is_duplicate/0}} end,
      fun(_) -> {timeout, 60, {"submitblock RPC answers \"duplicate\"",
                               fun rpc_submitblock_answers_duplicate/0}} end,
      fun(_) -> {timeout, 60, {"a new side branch is still side_branch, "
                               "then reorgs and extends",
                               fun new_blocks_unchanged/0}} end,
      fun(_) -> {timeout, 60, {"a known-invalid block is still "
                               "duplicate-invalid",
                               fun failed_block_still_duplicate_invalid/0}} end]}.

%%% ===================================================================

active_tip_resubmit_is_duplicate() ->
    {ok, _} = start_chainstate(),
    ?assertEqual({ok, duplicate},
                 beamchain_chainstate:submit_block(blk(?N), true)),
    ?assertEqual({ok, {hash_at(?N), ?N}}, beamchain_chainstate:get_tip()),
    ?assertEqual([tip(?N, hash_at(?N), 0, <<"active">>)], getchaintips()).

buried_active_resubmit_is_duplicate() ->
    {ok, _} = start_chainstate(),
    ?assertEqual({ok, duplicate},
                 beamchain_chainstate:submit_block(blk(?N - 2), true)),
    ?assertEqual({ok, {hash_at(?N), ?N}}, beamchain_chainstate:get_tip()),
    ?assertEqual([tip(?N, hash_at(?N), 0, <<"active">>)], getchaintips()).

side_branch_resubmit_is_duplicate() ->
    {ok, _} = start_chainstate(),
    Side = dummy_block(hash_at(?N - 2), ?N - 1, 7),
    ?assertEqual({ok, side_branch},
                 beamchain_chainstate:submit_block(Side, true)),
    ?assertEqual({ok, duplicate},
                 beamchain_chainstate:submit_block(Side, true)),
    ?assertEqual({ok, {hash_at(?N), ?N}}, beamchain_chainstate:get_tip()).

rpc_submitblock_answers_duplicate() ->
    {ok, _} = start_chainstate(),
    {ok, MPid} = beamchain_miner:start_link(),
    unlink(MPid),
    try
        ?assertEqual(<<"duplicate">>, rpc_submitblock(blk(?N))),
        Side = dummy_block(hash_at(?N - 2), ?N - 1, 8),
        ?assertEqual(<<"inconclusive">>, rpc_submitblock(Side)),
        ?assertEqual(<<"duplicate">>, rpc_submitblock(Side))
    after
        catch gen_server:stop(MPid)
    end.

%% Negative controls: only a block already stored is a duplicate.
new_blocks_unchanged() ->
    {ok, _} = start_chainstate(),
    Side = dummy_block(hash_at(?N - 2), ?N - 1, 9),
    ?assertEqual({ok, side_branch},
                 beamchain_chainstate:submit_block(Side, true)),
    Side2 = dummy_block(Side#block.hash, ?N, 9),
    ?assertEqual({ok, side_branch},
                 beamchain_chainstate:submit_block(Side2, true)),
    %% A heavier branch built on the stored side blocks still reorgs.
    Side3 = dummy_block(Side2#block.hash, ?N + 1, 9),
    ?assertEqual({ok, reorg}, beamchain_chainstate:submit_block(Side3, true)),
    ?assertEqual({ok, {Side3#block.hash, ?N + 1}},
                 beamchain_chainstate:get_tip()),
    %% And a new block on the new tip connects.
    Next = dummy_block(Side3#block.hash, ?N + 2, 9),
    ?assertEqual({ok, active}, beamchain_chainstate:submit_block(Next, true)),
    ?assertEqual({ok, {Next#block.hash, ?N + 2}},
                 beamchain_chainstate:get_tip()).

failed_block_still_duplicate_invalid() ->
    {ok, _} = start_chainstate(),
    Side = dummy_block(hash_at(?N - 2), ?N - 1, 10),
    ?assertEqual({ok, side_branch},
                 beamchain_chainstate:submit_block(Side, true)),
    ok = beamchain_chainstate:invalidate_block(Side#block.hash),
    ?assertEqual({error, duplicate_invalid},
                 beamchain_chainstate:submit_block(Side, true)).

%%% ===================================================================

%% The boot roll-forward gives the dummy chain 2 work per block (regtest
%% bits), so a fork at N-2 stays a side branch until its third block.
rpc_submitblock(Block) ->
    Hex = beamchain_serialize:hex_encode(
            beamchain_serialize:encode_block(Block)),
    #{<<"error">> := null, <<"result">> := Result} =
        beamchain_rpc:dispatch(#{<<"jsonrpc">> => <<"1.0">>,
                                 <<"id">> => <<"sb">>,
                                 <<"method">> => <<"submitblock">>,
                                 <<"params">> => [Hex]}, undefined),
    Result.

getchaintips() ->
    #{<<"error">> := null, <<"result">> := Result} =
        beamchain_rpc:dispatch(#{<<"jsonrpc">> => <<"1.0">>,
                                 <<"id">> => <<"gct">>,
                                 <<"method">> => <<"getchaintips">>,
                                 <<"params">> => []}, undefined),
    lists:sort([maps:from_list(T) || T <- Result]).

tip(Height, Hash, BranchLen, Status) ->
    #{<<"height">> => Height,
      <<"hash">> => beamchain_serialize:hex_encode(
                      beamchain_serialize:reverse_bytes(Hash)),
      <<"branchlen">> => BranchLen,
      <<"status">> => Status}.

setup() ->
    TmpDir = filename:join(["/tmp",
                            "beamchain_submit_duplicate_test_" ++
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
    application:set_env(beamchain, submit_duplicate_blocks,
                        [{0, GenesisHash, Genesis} | Blocks]),
    application:set_env(beamchain, submit_duplicate_rejects, #{}),
    {module, beamchain_validation} = code:ensure_loaded(beamchain_validation),
    ok = meck:new(beamchain_validation, [no_link, passthrough]),
    ok = meck:expect(beamchain_validation, connect_block,
                     fun(Block, _Height, _Prev, _Params) ->
                             H = beamchain_serialize:block_hash(
                                   Block#block.header),
                             {ok, M} = application:get_env(
                                         beamchain,
                                         submit_duplicate_rejects),
                             case maps:find(H, M) of
                                 {ok, Reason} -> {error, Reason};
                                 error -> ok
                             end
                     end),
    ok = meck:expect(beamchain_validation, check_block,
                     fun(_Block, _Params) -> ok end),
    ok = meck:expect(beamchain_validation, check_block_header,
                     fun(_H, _Params) -> ok end),
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

blk(H) ->
    {ok, Bs} = application:get_env(beamchain, submit_duplicate_blocks),
    {H, _, B} = lists:keyfind(H, 1, Bs),
    B.

hash_at(H) -> (blk(H))#block.hash.
