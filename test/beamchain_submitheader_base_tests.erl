-module(beamchain_submitheader_base_tests).

%%% submitheader of the snapshot base's own header must index the tip.
%%%
%%% `beamchain import-utxo` (no base_header ancestry on the regtest
%%% assumeutxo entry) leaves the chain tip at the base with NO block-index
%%% row for it.  Core always has an index entry for the active tip, so
%%% getblockhash(tip) answers.  beamchain 32af01b made submitheader store any
%%% header at a height =< tip hash-keyed only (never in the active chain's
%%% height slot); for the tip itself that left the slot empty and
%%% getblockhash(tip) answered "Block not available (pruned data)".  This
%%% broke the nightly boot-smoke cliload step (tools/boot-smoke.sh) from
%%% 2026-11-18.
%%%
%%% CONTROL: `rebar3 eunit --module=beamchain_submitheader_base_tests`

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

-define(N, 6).

base_header_test_() ->
    {foreach, fun setup/0, fun teardown/1,
     [fun(_) -> {timeout, 60, {"submitheader of the tip header fills the "
                               "missing tip slot",
                               fun tip_header_fills_missing_slot/0}} end,
      fun(_) -> {timeout, 60, {"fork header at the tip height leaves the "
                               "tip slot empty (control)",
                               fun fork_at_tip_height_does_not_fill_slot/0}} end]}.

tip_header_fills_missing_slot() ->
    {ok, _} = start_chainstate(),
    ?assertEqual(not_found, beamchain_db:get_block_index(?N)),
    Base = blk(?N),
    ?assertEqual({ok, accepted},
                 beamchain_chainstate:submit_header(Base#block.header)),
    ?assertMatch({ok, #{hash := _}}, beamchain_db:get_block_index(?N)),
    {ok, #{hash := Slot}} = beamchain_db:get_block_index(?N),
    ?assertEqual(Base#block.hash, Slot).

%% A different header at the tip height is not the tip: it must not take the
%% active slot (32af01b's rule still holds).
fork_at_tip_height_does_not_fill_slot() ->
    {ok, _} = start_chainstate(),
    Fork = dummy_block(hash_at(?N - 1), ?N, 7),
    ?assertEqual({ok, accepted},
                 beamchain_chainstate:submit_header(Fork#block.header)),
    ?assertEqual(not_found, beamchain_db:get_block_index(?N)),
    ?assertMatch({ok, #{height := ?N}},
                 beamchain_db:get_side_branch_index(Fork#block.hash)).

setup() ->
    TmpDir = filename:join(["/tmp",
                            "beamchain_submitheader_base_test_" ++
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
    %% Heights 1..N-1 indexed; the tip (height N) is the snapshot base as
    %% `beamchain import-utxo` leaves it: chain tip set, NO block-index row.
    Blocks0 = store_dummy_chain(GenesisHash, 1, ?N - 1, []),
    {_, PrevHash, _} = lists:last(Blocks0),
    BaseBlock = dummy_block(PrevHash, ?N, 0),
    ok = beamchain_db:set_chain_tip(BaseBlock#block.hash, ?N),
    Blocks = Blocks0 ++ [{?N, BaseBlock#block.hash, BaseBlock}],
    ok = beamchain_db:set_header_tip(PrevHash, ?N - 1),
    application:set_env(beamchain, submitheader_base_test_blocks,
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
    {ok, Bs} = application:get_env(beamchain, submitheader_base_test_blocks),
    {H, _, B} = lists:keyfind(H, 1, Bs),
    B.

hash_at(H) -> (blk(H))#block.hash.

genesis_hash() -> hash_at(0).
