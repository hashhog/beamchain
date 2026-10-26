-module(beamchain_getchaintips_fleet_tests).

%%% getchaintips must list every block-index leaf, not only the active tip
%%% (fleet item done-fleet-regtest-getchaintips).
%%%
%%% Core rpc/blockchain.cpp getchaintips: tips = every block-index entry not
%%% on the active chain that is not the parent of another such entry, plus
%%% the active tip; branchlen = height - FindFork(active).height; status
%%% active / invalid (BLOCK_FAILED_VALID, descendants included) /
%%% headers-only (!HaveNumChainTxs) / valid-fork (IsValid(BLOCK_VALID_
%%% SCRIPTS)) / valid-headers (IsValid(BLOCK_VALID_TREE)).
%%%
%%% beamchain bug (master edd0919): rpc_getchaintips returned the active tip
%%% alone -- "We only track the active chain" -- although the index holds
%%% invalidated blocks (height slots above the tip), side branches and
%%% displaced blocks ("sbidx:" entries) and headers above the tip.  The
%%% Core regtest ratchet had 176 getchaintips rows, every one a tip missing.
%%%
%%% CONTROL: `rebar3 eunit --module=beamchain_getchaintips_fleet_tests`

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

-define(N, 6).

getchaintips_fleet_test_() ->
    {foreach, fun setup/0, fun teardown/1,
     [fun(_) -> {timeout, 60, {"invalidated branch is an invalid tip",
                               fun invalidated_branch_is_invalid_tip/0}} end,
      fun(_) -> {timeout, 60, {"submitted side branch is valid-headers",
                               fun side_branch_is_valid_headers/0}} end,
      fun(_) -> {timeout, 60, {"once-connected displaced branch is valid-fork",
                               fun displaced_block_is_valid_fork/0}} end,
      fun(_) -> {timeout, 60, {"header above the tip is headers-only",
                               fun header_above_tip_is_headers_only/0}} end,
      fun(_) -> {timeout, 60, {"lost ancestry is left out, never a guessed "
                               "branchlen",
                               fun lost_ancestry_is_omitted/0}} end,
      fun(_) -> {timeout, 60, {"reconsider leaves the active tip alone",
                               fun reconsider_restores_single_tip/0}} end]}.

%%% ===================================================================

invalidated_branch_is_invalid_tip() ->
    {ok, _} = start_chainstate(),
    ok = beamchain_chainstate:invalidate_block(hash_at(4)),
    ?assertEqual(
       lists:sort([tip(3, hash_at(3), 0, <<"active">>),
                   tip(?N, hash_at(?N), 3, <<"invalid">>)]),
       getchaintips()).

side_branch_is_valid_headers() ->
    {ok, _} = start_chainstate(),
    Side = dummy_block(genesis_hash(), 1, 7),
    ?assertMatch({ok, side_branch}, beamchain_chainstate:submit_block(Side, true)),
    ?assertEqual(
       lists:sort([tip(?N, hash_at(?N), 0, <<"active">>),
                   tip(1, Side#block.hash, 1, <<"valid-headers">>)]),
       getchaintips()).

displaced_block_is_valid_fork() ->
    {ok, _} = start_chainstate(),
    %% Blocks 5 and 6 were connected; invalidateblock(5), then a heavier
    %% branch 5'-6'-7' on 4 takes their height slots, and reconsiderblock(5)
    %% lifts the failure.  5-6 is a once-connected fork with less work.
    ok = beamchain_chainstate:invalidate_block(hash_at(5)),
    S5 = dummy_block(hash_at(4), 5, 9),
    S6 = dummy_block(S5#block.hash, 6, 9),
    S7 = dummy_block(S6#block.hash, 7, 9),
    [?assertEqual({ok, active}, beamchain_chainstate:submit_block(B, true))
     || B <- [S5, S6, S7]],
    ok = beamchain_chainstate:reconsider_block(hash_at(5)),
    ?assertEqual({ok, {S7#block.hash, 7}}, beamchain_chainstate:get_tip()),
    ?assertEqual(
       lists:sort([tip(7, S7#block.hash, 0, <<"active">>),
                   tip(6, hash_at(6), 2, <<"valid-fork">>)]),
       getchaintips()).

header_above_tip_is_headers_only() ->
    {ok, _} = start_chainstate(),
    H7 = dummy_block(hash_at(?N), ?N + 1, 0),
    H8 = dummy_block(H7#block.hash, ?N + 2, 0),
    ?assertEqual({ok, accepted},
                 beamchain_chainstate:submit_header(H7#block.header)),
    ?assertEqual({ok, accepted},
                 beamchain_chainstate:submit_header(H8#block.header)),
    ?assertEqual(
       lists:sort([tip(?N, hash_at(?N), 0, <<"active">>),
                   tip(?N + 2, H8#block.hash, 2, <<"headers-only">>)]),
       getchaintips()).

%% Harness warden_invalidated_submit/p2p-header: headers 7 and 8 above the
%% tip, then a competing header 7' takes height slot 7.  beamchain drops a
%% displaced header-only entry (beamchain_db displaced_entry_ops/5), so 8's
%% parent is gone and its fork point is unknowable; Core (which keeps 7)
%% says branchlen 2.  The leaf is left out rather than reported with a
%% wrong branchlen; 7' is reported as Core does.
lost_ancestry_is_omitted() ->
    {ok, _} = start_chainstate(),
    H7 = dummy_block(hash_at(?N), ?N + 1, 0),
    H8 = dummy_block(H7#block.hash, ?N + 2, 0),
    H7b = dummy_block(hash_at(?N), ?N + 1, 5),
    [?assertEqual({ok, accepted},
                  beamchain_chainstate:submit_header(B#block.header))
     || B <- [H7, H8, H7b]],
    ?assertEqual(
       lists:sort([tip(?N, hash_at(?N), 0, <<"active">>),
                   tip(?N + 1, H7b#block.hash, 1, <<"headers-only">>)]),
       getchaintips()).

%% Negative control: with nothing off the active chain the answer is the
%% active tip alone (what master always returned).
reconsider_restores_single_tip() ->
    {ok, _} = start_chainstate(),
    ?assertEqual([tip(?N, hash_at(?N), 0, <<"active">>)], getchaintips()),
    ok = beamchain_chainstate:invalidate_block(hash_at(4)),
    ok = beamchain_chainstate:reconsider_block(hash_at(4)),
    ?assertEqual([tip(?N, hash_at(?N), 0, <<"active">>)], getchaintips()).

%%% ===================================================================

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
                            "beamchain_getchaintips_fleet_test_" ++
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
    application:set_env(beamchain, getchaintips_fleet_test_blocks,
                        [{0, GenesisHash, Genesis} | Blocks]),
    {module, beamchain_validation} = code:ensure_loaded(beamchain_validation),
    ok = meck:new(beamchain_validation, [no_link, passthrough]),
    ok = meck:expect(beamchain_validation, connect_block,
                     fun(_Block, _Height, _Prev, _Params) -> ok end),
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
    {ok, Bs} = application:get_env(beamchain, getchaintips_fleet_test_blocks),
    {H, _, B} = lists:keyfind(H, 1, Bs),
    B.

hash_at(H) -> (blk(H))#block.hash.

genesis_hash() -> hash_at(0).
