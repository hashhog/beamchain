-module(beamchain_mempool_txgraph_usage_tests).
%%% getmempoolinfo.usage counts Core's TxGraph memory per cluster, not a flat
%%% singleton cost per transaction.
%%%
%%% Core CTxMemPool::DynamicMemoryUsage() (txmempool.cpp:781) adds
%%% m_txgraph->GetMainMemoryUsage() (txgraph.cpp:3535): every cluster's
%%% TotalMemoryUsage(), an 80-byte Entry per transaction and a 64-byte chunk
%%% index node per chunk. beamchain charged every transaction a singleton
%%% cluster's 216 bytes, so a 2-tx cluster read 72 (one chunk) or 136 (two
%%% chunks) bytes under Core and a 64-tx cluster several KB over it. And an
%%% invalidateblock that re-added a parent under its in-pool children left
%%% txns_randomized at capacity 64 where Core has 128.
%%%
%%% Every expected figure below is Core v31.1's (regtest, getmempoolinfo /
%%% getmempoolcluster): the live pools are built from the same transactions
%%% (same sizes and fees; only txids differ) that were sent to Core, so their
%%% usage must equal Core's to the byte.
-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

-define(CHILDREN, 64).

%%% ===================================================================
%%% Per-cluster bytes: traced to Core's structs, checked against Core
%%% ===================================================================

%% Singleton: SingletonClusterImpl 64 + slot 8 + Entry 80 + chunk node 64.
%% Generic: GenericClusterImpl 128 + slot 8 + 2 * MallocUsage(4N) +
%% MallocUsage(32N) + 80N + 64 per chunk.
cluster_usage_terms_test() ->
    ?assertEqual(216, call(txgraph_cluster_usage, [1, 1])),
    %% 2-tx cluster, one chunk: 72 over 2 * 216 (Core mempool/info/pool).
    ?assertEqual(504, call(txgraph_cluster_usage, [2, 1])),
    %% 2-tx cluster, two chunks: 136 over (warden_invalidated_submit usage-chain).
    ?assertEqual(568, call(txgraph_cluster_usage, [2, 2])),
    %% rbf/clusters: a 21-tx single-chunk cluster.
    ?assertEqual(2792, call(txgraph_cluster_usage, [21, 1])),
    %% seed_warden_e: 64 txs in 19 chunks; warden_e: 64 txs in 30 chunks.
    ?assertEqual(9080, call(txgraph_cluster_usage, [64, 19])),
    ?assertEqual(9784, call(txgraph_cluster_usage, [64, 30])).

%%% ===================================================================
%%% Chunk counts: Core's optimal linearization with minimal chunks
%%% ===================================================================

%% Core getmempoolcluster: an equal-feerate parent/child pair is two chunks
%% (minimal chunks: the parent alone already has the pair's feerate).
equal_feerate_pair_is_two_chunks_test() ->
    ?assertEqual(2, call(txgraph_chunk_count, [chain([{1000, 340}, {1000, 340}])])).

%% Core: a child paying for its parent is one chunk.
cpfp_pair_is_one_chunk_test() ->
    ?assertEqual(1, call(txgraph_chunk_count, [chain([{200, 340}, {5000, 340}])])).

%% Core: a parent paying more than its child is two chunks.
parent_first_pair_is_two_chunks_test() ->
    ?assertEqual(2, call(txgraph_chunk_count, [chain([{5000, 340}, {300, 340}])])).

%% Core: an equal-feerate chain of three is three chunks.
equal_feerate_chain_is_one_chunk_per_tx_test() ->
    ?assertEqual(3, call(txgraph_chunk_count,
                         [chain([{1000, 340}, {1000, 340}, {1000, 340}])])).

%% rbf/clusters: a root paying 1000 sat into 20 outputs, each spent by a
%% child paying 1000 sat. Core: one chunk of 21.
rbf_cluster_is_one_chunk_test() ->
    ?assertEqual(1, call(txgraph_chunk_count,
                         [star(1000, 2772, [{I, 1000, 340} || I <- lists:seq(1, 20)])])).

%% seed_warden_e after invalidate: the parent (fee 10000, weight 8532) and
%% children 1..63 (fee 5000 + 200i, weight 340). Core: [46, 1 x 18].
seed_warden_e_cluster_is_19_chunks_test() ->
    ?assertEqual(19, call(txgraph_chunk_count,
                          [star(10000, 8532,
                                [{I, 5000 + 200 * I, 340} || I <- lists:seq(1, 63)])])).

%% warden_e after invalidate: parent fee 10000 weight 8249, children 1..63
%% paying 1000 * (i + 1), weight 437 (one signature a byte shorter: 436).
%% Core: [35, 1 x 29].
warden_e_cluster_is_30_chunks_test() ->
    Kids = [{I, 1000 * (I + 1), case I of 9 -> 436; _ -> 437 end}
            || I <- lists:seq(1, 63)],
    ?assertEqual(30, call(txgraph_chunk_count, [star(10000, 8249, Kids)])).

%% Two parents of one child, each parent cheap, the child rich: one chunk.
%% A sibling chain hanging off the same parent at a lower feerate is not
%% pulled in. Order of the input list does not matter.
diamond_and_order_test() ->
    Nodes = [{c, 9000, 400, [a, b]}, {a, 100, 400, []}, {b, 100, 400, []},
             {d, 10, 400, [a]}],
    ?assertEqual(2, call(txgraph_chunk_count, [Nodes])),
    ?assertEqual(2, call(txgraph_chunk_count, [lists:reverse(Nodes)])).

%%% ===================================================================
%%% txns_randomized across a reorg
%%% ===================================================================

%% Core: 64 children (capacity 64), the parent's emplace_back (65 -> 128),
%% Trim()'s removal of child 0 (64 of 128 is not under half: stays 128).
reorg_replay_keeps_core_capacity_test() ->
    ?assertEqual({64, 128}, call(txns_randomized_replay, [{64, 64}, 1, 1])),
    %% Under half full after the removals: shrink_to_fit.
    ?assertEqual({3, 3}, call(txns_randomized_replay, [{4, 4}, 1, 2])),
    ?assertEqual({0, 4}, call(txns_randomized_replay, [{1, 4}, 0, 1])).

%%% ===================================================================
%%% Live pool: getmempoolinfo.usage equals Core's (gen_server + chain)
%%% ===================================================================

txgraph_usage_test_() ->
    {foreach, fun setup/0, fun teardown/1,
     [fun(_) -> {timeout, 300,
                 {"pairs and a chain: usage is Core's 2008 / 3936 / 6008 / 9088",
                  fun pairs_match_core/0}} end,
      fun(_) -> {timeout, 600,
                 {"seed_warden_e: invalidate a parent of 64 children, usage is Core's 60296",
                  fun seed_warden_e_matches_core/0}} end,
      fun(_) -> {timeout, 300,
                 {"mined txs leave the pool: usage is Core's 4944 / 4096 / 2056 / 64",
                  fun mined_paths_match_core/0}} end]}.

%% Core v31.1 after the same four steps on the same transactions.
pairs_match_core() ->
    send(acs_spend(cb_txid(1), subsidy(), 1000)),
    send(acs_spend(prev(), subsidy() - 1000, 1000)),
    %% Equal-feerate pair: one 2-tx cluster, two chunks.
    ?assertEqual(2008, usage()),
    send(acs_spend(cb_txid(2), subsidy(), 200)),
    send(acs_spend(prev(), subsidy() - 200, 5000)),
    %% Plus a CPFP pair: one chunk.
    ?assertEqual(3936, usage()),
    send(acs_spend(cb_txid(3), subsidy(), 5000)),
    send(acs_spend(prev(), subsidy() - 5000, 300)),
    %% Plus a parent-first pair: two chunks.
    ?assertEqual(6008, usage()),
    send(acs_spend(cb_txid(4), subsidy(), 1000)),
    send(acs_spend(prev(), subsidy() - 1000, 1000)),
    send(acs_spend(prev(), subsidy() - 2000, 1000)),
    %% Plus an equal-feerate chain of three: three chunks.
    ?assertEqual(9088, usage()),
    ?assertEqual(9, maps:get(<<"size">>, info())).

%% Clusters shrink, split and vanish as their txs are mined. Core v31.1 on
%% the same transactions (generateblock with the listed txids):
%% chain A-B-C (fee 1000 each) and CPFP pair P-Q (200, 5000) -> 4944; mine A
%% (B-C is left, a 2-tx cluster of 2 chunks) -> 4096; mine P, Q -> 2056; mine
%% B, C -> 64 (only txns_randomized's allocation is left). No per-cluster
%% TxGraph term may outlive its cluster.
mined_paths_match_core() ->
    A = acs_spend(cb_txid(1), subsidy(), 1000),
    B = acs_spend(beamchain_serialize:tx_hash(A), subsidy() - 1000, 1000),
    C = acs_spend(beamchain_serialize:tx_hash(B), subsidy() - 2000, 1000),
    P = acs_spend(cb_txid(2), subsidy(), 200),
    Q = acs_spend(beamchain_serialize:tx_hash(P), subsidy() - 200, 5000),
    lists:foreach(fun send/1, [A, B, C, P, Q]),
    ?assertEqual(4944, usage()),
    ok = beamchain_chainstate:connect_block(next_block([A])),
    ?assertEqual(4, maps:get(<<"size">>, info())),
    ?assertEqual(4096, usage()),
    ok = beamchain_chainstate:connect_block(next_block([P, Q])),
    ?assertEqual(2, maps:get(<<"size">>, info())),
    ?assertEqual(2056, usage()),
    ok = beamchain_chainstate:connect_block(next_block([B, C])),
    ?assertEqual(0, maps:get(<<"size">>, info())),
    ?assertEqual(64, usage()),
    ?assertEqual([], ets:match(mempool_usage, {{txgraph_excess, '$1'}, '_'})).

%% The core-regtest seed_warden_e group, transaction for transaction: the
%% parent spends the height-1 coinbase into 64 outputs of 200000 sat plus
%% change (fee 10000) and is mined at 111; child i spends output i paying
%% 5000 + 200i. invalidateblock 111 brings the parent back, the cluster
%% limit drops child 0. Core v31.1: getmempoolinfo.usage 60296.
seed_warden_e_matches_core() ->
    Change = subsidy() - ?CHILDREN * 200000 - 10000,
    Parent = tx([in(cb_txid(1), 0)],
                [out(200000) || _ <- lists:seq(1, ?CHILDREN)] ++ [out(Change)]),
    PTxid = beamchain_serialize:tx_hash(Parent),
    ok = beamchain_chainstate:connect_block(next_block([Parent])),
    Kids = [tx([in(PTxid, I)], [out(200000 - (5000 + 200 * I))])
            || I <- lists:seq(0, ?CHILDREN - 1)],
    lists:foreach(fun send/1, Kids),
    ?assertEqual(?CHILDREN, maps:get(<<"size">>, info())),
    {ok, #{hash := H111}} = beamchain_db:get_block_index(111),
    ok = beamchain_chainstate:invalidate_block(H111),
    Pool = rpc(<<"getrawmempool">>, []),
    %% CONTROL (the harness's): the parent is back, child 0 is not.
    ?assert(lists:member(hex_txid(Parent), Pool)),
    ?assertNot(lists:member(hex_txid(hd(Kids)), Pool)),
    ?assertEqual(?CHILDREN, length(Pool)),
    ?assertEqual(60296, usage()).

%%% ===================================================================
%%% Helpers
%%% ===================================================================

%% The function under test, or `undefined' where it does not exist (so a
%% tree without it fails these tests on the assertion).
call(F, Args) ->
    try apply(beamchain_mempool, F, Args)
    catch error:undef -> undefined
    end.

%% [{Fee, Weight}] -> a chain, each tx the child of the one before.
chain(FeeWeights) ->
    {Nodes, _} = lists:foldl(
                   fun({F, W}, {Acc, Prev}) ->
                           Id = length(Acc) + 1,
                           Ps = case Prev of none -> []; _ -> [Prev] end,
                           {[{Id, F, W, Ps} | Acc], Id}
                   end, {[], none}, FeeWeights),
    lists:reverse(Nodes).

star(ParentFee, ParentWeight, Kids) ->
    [{parent, ParentFee, ParentWeight, []}
     | [{{child, I}, F, W, [parent]} || {I, F, W} <- Kids]].

usage() -> maps:get(<<"usage">>, info()).

info() -> maps:from_list(rpc(<<"getmempoolinfo">>, [])).

send(Tx) ->
    ?assertEqual(hex_txid(Tx), rpc(<<"sendrawtransaction">>, [hex(Tx)])),
    put(last_txid, beamchain_serialize:tx_hash(Tx)),
    ok.

prev() -> get(last_txid).

%% The harness's acs_spend: one P2SH(OP_TRUE) input, one output.
acs_spend(PrevTxid, ValueIn, Fee) ->
    tx([in(PrevTxid, 0)], [out(ValueIn - Fee)]).

in(Txid, Vout) ->
    #tx_in{prev_out = #outpoint{hash = Txid, index = Vout},
           script_sig = <<1, 16#51>>, sequence = 16#ffffffff, witness = []}.

out(Value) -> #tx_out{value = Value, script_pubkey = p2sh_true()}.

tx(Ins, Outs) ->
    #transaction{version = 2, inputs = Ins, outputs = Outs, locktime = 0}.

rpc(Method, Params) ->
    case beamchain_rpc:dispatch(#{<<"jsonrpc">> => <<"1.0">>,
                                  <<"id">> => <<"t">>,
                                  <<"method">> => Method,
                                  <<"params">> => Params}, undefined) of
        #{<<"error">> := null, <<"result">> := Result} -> Result;
        Other -> erlang:error({rpc_failed, Method, Other})
    end.

hex(Tx) ->
    beamchain_serialize:hex_encode(beamchain_serialize:encode_transaction(Tx)).

hex_txid(Tx) ->
    beamchain_serialize:hex_encode(
      beamchain_serialize:reverse_bytes(beamchain_serialize:tx_hash(Tx))).

setup() ->
    TmpDir = chain_setup(),
    build_chain(110),
    catch gen_server:stop(beamchain_mempool),
    %% The usage table outlives the gen_server; start from an empty one.
    catch ets:delete(mempool_usage),
    {ok, MP} = beamchain_mempool:start_link(),
    unlink(MP),
    ok = meck:new(beamchain_peer_manager, [passthrough, no_link]),
    ok = meck:expect(beamchain_peer_manager, announce_tx, fun(_) -> ok end),
    TmpDir.

teardown(TmpDir) ->
    catch meck:unload(beamchain_peer_manager),
    chain_teardown(TmpDir).

%%% ===================================================================
%%% Fixture (same regtest chain as beamchain_mempool_txns_randomized_tests)
%%% ===================================================================

chain_setup() ->
    TmpDir = filename:join(["/tmp", "bc_txgraph_usage_" ++ os:getpid() ++ "_" ++
                            integer_to_list(erlang:system_time(microsecond))]),
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

chain_teardown(TmpDir) ->
    catch beamchain_fault:clear_all(),
    catch gen_server:stop(beamchain_mempool),
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

subsidy() -> 5000000000.

p2sh_true() ->
    <<16#a9, 20, (beamchain_crypto:hash160(<<16#51>>))/binary, 16#87>>.

ts(Height) ->
    erlang:system_time(second) - 200 * 600 + Height * 600.

coinbase(Height, Tag) ->
    HeightBin = beamchain_validation:encode_bip34_height(Height),
    TagBin = iolist_to_binary(Tag),
    ScriptSig = <<HeightBin/binary, (byte_size(TagBin)):8,
                  TagBin/binary, 0:32>>,
    #transaction{
        version = 1,
        inputs = [#tx_in{prev_out = #outpoint{hash = <<0:256>>,
                                              index = 16#ffffffff},
                         script_sig = ScriptSig, sequence = 16#ffffffff,
                         witness = []}],
        outputs = [#tx_out{value = subsidy(), script_pubkey = p2sh_true()}],
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
    mine_block(TipHash, H, [coinbase(H, <<"tg">>) | Txs], ts(H)).

build_chain(ToHeight) ->
    {ok, {_, TipH}} = beamchain_chainstate:get_tip(),
    lists:foreach(fun(_) ->
        ok = beamchain_chainstate:connect_block(next_block([]))
    end, lists:seq(TipH + 1, ToHeight)).

cb_txid(Height) ->
    {ok, #{hash := Hash}} = beamchain_db:get_block_index(Height),
    {ok, #block{transactions = [Cb | _]}} = beamchain_db:get_block(Hash),
    beamchain_serialize:tx_hash(Cb).
