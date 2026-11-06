-module(beamchain_best_header_tests).

%%% getblockchaininfo / getchainstates / REST chaininfo `headers` must be the
%%% best header's height, not the active tip's
%%% (item refill-20261106-beamchain-consensus).
%%%
%%% Core rpc/blockchain.cpp getblockchaininfo:
%%%   obj.pushKV("headers", chainman.m_best_header ? m_best_header->nHeight : -1)
%%% m_best_header is the most-work block-index entry not BLOCK_FAILED_VALID:
%%% AddToBlockIndex raises it on every new header with more work
%%% (node/blockstorage.cpp), LoadBlockIndex rebuilds it the same way on
%%% restart (validation.cpp), InvalidateBlock drops it back to the new tip.
%%%
%%% beamchain bug (master caba24c): getblockchaininfo emitted
%%% {<<"headers">>, TipHeight} and REST chaininfo the same ("In a full node,
%%% headers count equals block count"), so after submitheader (or P2P
%%% headers) two blocks above the tip the Core regtest ratchet saw
%%% headers 208 vs Core's 210 (warden_invalidated_submit/{headers-only,
%%% restart,p2p-header}/info:headers).
%%%
%%% CONTROL: `rebar3 eunit --module=beamchain_best_header_tests`

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

-define(N, 6).

best_header_test_() ->
    {foreach, fun setup/0, fun teardown/1,
     [fun(_) -> {timeout, 60, {"headers equals the tip with nothing above it",
                               fun headers_is_tip_without_headers_above/0}} end,
      fun(_) -> {timeout, 60, {"submitheader above the tip raises headers",
                               fun submitheader_above_tip_raises_headers/0}} end,
      fun(_) -> {timeout, 60, {"headers survives a chainstate restart",
                               fun headers_survive_restart/0}} end,
      fun(_) -> {timeout, 60, {"headers counts a leaf whose ancestry was "
                               "displaced (p2p-header)",
                               fun displaced_ancestry_still_counts/0}} end,
      fun(_) -> {timeout, 60, {"invalidated headers do not count",
                               fun invalid_headers_do_not_count/0}} end,
      fun(_) -> {timeout, 60, {"less-work side header does not count",
                               fun less_work_side_header_does_not_count/0}} end]}.

%%% ===================================================================

%% Negative control: nothing above the tip -> headers == blocks (what the
%% old code always answered, and still right here).
headers_is_tip_without_headers_above() ->
    {ok, _} = start_chainstate(),
    ?assertEqual({?N, ?N}, blocks_headers()),
    ?assertEqual(?N, chainstates_headers()).

%% Harness warden_invalidated_submit/headers-only: two headers submitted on
%% top of the tip; Core reports headers = tip + 2, blocks = tip.
submitheader_above_tip_raises_headers() ->
    {ok, _} = start_chainstate(),
    submit_headers_above_tip(),
    ?assertEqual({?N, ?N + 2}, blocks_headers()),
    ?assertEqual(?N + 2, chainstates_headers()),
    ?assertEqual(?N + 2, rest_headers()).

%% Harness warden_invalidated_submit/restart: Core rebuilds m_best_header
%% from the index on load, so the headers-only entries still count.
headers_survive_restart() ->
    {ok, Pid} = start_chainstate(),
    submit_headers_above_tip(),
    ok = gen_server:stop(Pid),
    {ok, _} = start_chainstate(),
    ?assertEqual({?N, ?N + 2}, blocks_headers()).

%% Harness warden_invalidated_submit/p2p-header: headers 7 and 8 above the
%% tip, then a competing header 7' takes height slot 7.  Core still has 8
%% (more work than 7') as its best header.
displaced_ancestry_still_counts() ->
    {ok, _} = start_chainstate(),
    submit_headers_above_tip(),
    H7b = dummy_block(hash_at(?N), ?N + 1, 5),
    ?assertEqual({ok, accepted},
                 beamchain_chainstate:submit_header(H7b#block.header)),
    ?assertEqual({?N, ?N + 2}, blocks_headers()).

%% Core InvalidateBlock: m_best_header falls back to the new tip when it
%% descended from the invalidated block; BLOCK_FAILED_VALID entries never
%% count.
invalid_headers_do_not_count() ->
    {ok, _} = start_chainstate(),
    ok = beamchain_chainstate:invalidate_block(hash_at(4)),
    ?assertEqual({3, 3}, blocks_headers()),
    ?assertEqual(3, chainstates_headers()).

%% A side-branch block with less work than the tip is not the best header.
%% (Submitted as a block, so it lands in the side-branch index: a fork
%% header below the tip sent through submitheader is stored into the active
%% chain's height slot, a separate bug outside this item.)
less_work_side_header_does_not_count() ->
    {ok, _} = start_chainstate(),
    Side = dummy_block(genesis_hash(), 1, 7),
    ?assertMatch({ok, side_branch},
                 beamchain_chainstate:submit_block(Side, true)),
    ?assertEqual({?N, ?N}, blocks_headers()).

%%% ===================================================================

submit_headers_above_tip() ->
    H7 = dummy_block(hash_at(?N), ?N + 1, 0),
    H8 = dummy_block(H7#block.hash, ?N + 2, 0),
    [?assertEqual({ok, accepted},
                  beamchain_chainstate:submit_header(B#block.header))
     || B <- [H7, H8]],
    ok.

blocks_headers() ->
    Info = rpc(<<"getblockchaininfo">>),
    {maps:get(<<"blocks">>, Info), maps:get(<<"headers">>, Info)}.

%% GET /rest/chaininfo.json (Core rest_chaininfo = getblockchaininfo).
rest_headers() ->
    {ok, json, Body} = beamchain_rest:rest_chaininfo(json),
    maps:get(<<"headers">>, jsx:decode(Body, [return_maps])).

chainstates_headers() ->
    maps:get(<<"headers">>, rpc(<<"getchainstates">>)).

rpc(Method) ->
    Reply = beamchain_rpc:dispatch(#{<<"jsonrpc">> => <<"1.0">>,
                                     <<"id">> => <<"bh">>,
                                     <<"method">> => Method,
                                     <<"params">> => []}, undefined),
    Envelope = case Reply of
        {raw_json, Bin} -> jsx:decode(Bin, [return_maps]);
        M when is_map(M) -> M
    end,
    #{<<"error">> := null, <<"result">> := Result} = Envelope,
    case Result of
        R when is_map(R) -> R;
        L when is_list(L) -> maps:from_list(L)
    end.

setup() ->
    TmpDir = filename:join(["/tmp",
                            "beamchain_best_header_test_" ++
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
    application:set_env(beamchain, best_header_test_blocks,
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
    {ok, Bs} = application:get_env(beamchain, best_header_test_blocks),
    {H, _, B} = lists:keyfind(H, 1, Bs),
    B.

hash_at(H) -> (blk(H))#block.hash.

genesis_hash() -> hash_at(0).
