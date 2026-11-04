-module(beamchain_free_mempool_eviction_tests).
%%% A replacement that fails ATMP must not evict anything.
%%%
%%% do_rbf/3 (GATE 10) and do_truc_sibling_eviction/3 (GATE 15) used to
%%% remove the conflicting transactions from the live pool the moment the
%%% RBF fee rules passed.  Every later gate (fee floor, cluster limits,
%%% BIP68, scripts) could still reject the replacement, and nothing put the
%%% evicted transactions back.  So:
%%%
%%%   (a) any P2P peer could delete any mempool tx by relaying a conflicting
%%%       tx with an invalid signature -- the fee is computed from the input
%%%       values, so a high fee costs nothing when the tx is never valid;
%%%   (b) testmempoolaccept of a replacement (dry_run_atmp/2 reaches the same
%%%       do_rbf/3) evicted the original from the live pool and left the
%%%       size/bytes counters stale, so the following real submit
%%%       double-counted (Core regtest row rbf/simple/info:size 1 -> 2).
%%%
%%% Core stages the removals in its ChangeSet (validation.cpp StageRemoval)
%%% and applies them only once the whole acceptance has succeeded
%%% (ChangeSet::Apply in FinalizeSubpackage); test_accept never applies.
%%%
%%% The attack cases drive the P2P `tx` handler (beamchain_sync:process_tx/2,
%%% the same function beamchain_tx_ingest runs for a peer's `tx` message) and
%%% the RPC dispatcher, against a real regtest chainstate and a real mempool
%%% gen_server.  Coinbases pay P2SH(OP_TRUE) so every spend is standard.
-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-define(FEE, 10000).
%% Distinct coinbase heights per scenario keep each case's coins apart.
-define(H_VICTIM, 1).
-define(H_TRUC, 2).
-define(H_CLUSTER, 3).

free_eviction_test_() ->
    {foreach, fun setup/0, fun teardown/1,
     [fun(_) -> t("CONTROL: P2P valid replacement replaces the original",
                  fun p2p_valid_replacement_replaces/0) end,
      fun(_) -> t("P2P replacement with an invalid script does not evict",
                  fun p2p_invalid_script_replacement_keeps_original/0) end,
      fun(_) -> t("P2P replacement failing BIP68 does not evict",
                  fun p2p_bip68_fail_replacement_keeps_original/0) end,
      fun(_) -> t("P2P TRUC child failing scripts does not evict its sibling",
                  fun p2p_truc_sibling_invalid_script_keeps_sibling/0) end,
      fun(_) -> t("testmempoolaccept of a replacement does not evict",
                  fun rpc_testmempoolaccept_replacement_keeps_original/0) end,
      fun(_) -> t("rbf/simple: testmempoolaccept, sendrawtransaction, size 1",
                  fun rpc_rbf_simple_control_counters/0) end,
      fun(_) -> t("replacement freeing cluster room: dry run keeps, submit accepts",
                  fun replacement_freeing_cluster_room_accepted/0) end]}.

t(Name, F) -> {timeout, 180, {Name, F}}.

setup() ->
    TmpDir = chain_setup(),
    build_chain(110),
    catch gen_server:stop(beamchain_mempool),
    {ok, MP} = beamchain_mempool:start_link(),
    unlink(MP),
    %% An accepted P2P/RPC tx is announced to peers; there are none here.
    ok = meck:new(beamchain_peer_manager, [passthrough, no_link]),
    ok = meck:expect(beamchain_peer_manager, announce_tx, fun(_) -> ok end),
    TmpDir.

teardown(TmpDir) ->
    catch meck:unload(beamchain_peer_manager),
    chain_teardown(TmpDir).

%%% ===================================================================
%%% Cases
%%% ===================================================================

p2p_valid_replacement_replaces() ->
    A = victim(),
    B = spend(cb_txid(?H_VICTIM), 0, subsidy(), 16#fffffffd, 100000),
    ok = p2p_tx(B),
    ?assert(in_pool(B)),
    ?assertNot(in_pool(A)),
    ?assertEqual(1, pool_len()),
    ?assertEqual(1, info_size()).

p2p_invalid_script_replacement_keeps_original() ->
    A = victim(),
    B = bad_script(spend(cb_txid(?H_VICTIM), 0, subsidy(), 16#fffffffd, 100000)),
    %% The replacement passes the RBF fee rules and then fails scripts.
    ?assertMatch({error, _}, beamchain_mempool:accept_to_memory_pool_dry_run(B)),
    ok = p2p_tx(B),
    ?assertNot(in_pool(B)),
    ?assert(in_pool(A)),
    ?assertEqual(1, pool_len()),
    ?assertEqual(1, info_size()),
    ?assertEqual(vsize_of(A), info_bytes()).

p2p_bip68_fail_replacement_keeps_original() ->
    A = victim(),
    %% Relative lock of 1000 blocks on a coin with ~110 confirmations.
    B = spend(cb_txid(?H_VICTIM), 0, subsidy(), 1000, 100000),
    ?assertEqual({error, sequence_lock_not_met},
                 beamchain_mempool:add_transaction(B)),
    ?assert(in_pool(A)),
    ok = p2p_tx(B),
    ?assertNot(in_pool(B)),
    ?assert(in_pool(A)),
    ?assertEqual(1, pool_len()),
    ?assertEqual(1, info_size()).

p2p_truc_sibling_invalid_script_keeps_sibling() ->
    %% v3 parent P with two outputs, v3 child C1 on P:0.  C2 on P:1 pays
    %% enough for TRUC sibling eviction of C1, then fails scripts.
    Cb = cb_txid(?H_TRUC),
    Half = (subsidy() - ?FEE) div 2,
    P = (spend(Cb, 0, subsidy(), 16#fffffffd, 0))#transaction{
          version = ?TRUC_VERSION,
          outputs = [#tx_out{value = Half, script_pubkey = p2sh_true()},
                     #tx_out{value = Half, script_pubkey = p2sh_true()}]},
    ?assertMatch({ok, _}, beamchain_mempool:add_transaction(P)),
    PTxid = beamchain_serialize:tx_hash(P),
    C1 = (spend(PTxid, 0, Half, 16#fffffffd, 0))#transaction{version = ?TRUC_VERSION},
    ?assertMatch({ok, _}, beamchain_mempool:add_transaction(C1)),
    C2 = bad_script((spend(PTxid, 1, Half, 16#fffffffd, 50000))#transaction{
                       version = ?TRUC_VERSION}),
    ok = p2p_tx(C2),
    ?assertNot(in_pool(C2)),
    ?assert(in_pool(C1)),
    ?assert(in_pool(P)),
    ?assertEqual(2, pool_len()),
    ?assertEqual(2, info_size()),
    %% CONTROL: the same sibling eviction with a valid script does evict C1.
    C3 = (spend(PTxid, 1, Half, 16#fffffffd, 50000))#transaction{version = ?TRUC_VERSION},
    ok = p2p_tx(C3),
    ?assert(in_pool(C3)),
    ?assertNot(in_pool(C1)),
    ?assertEqual(2, pool_len()),
    ?assertEqual(2, info_size()).

rpc_testmempoolaccept_replacement_keeps_original() ->
    A = victim(),
    B = spend(cb_txid(?H_VICTIM), 0, subsidy(), 16#fffffffd, 4000),
    [Row] = rpc(<<"testmempoolaccept">>, [[hex(B)]]),
    ?assertEqual(true, maps:get(<<"allowed">>, Row)),
    ?assert(in_pool(A)),
    ?assertNot(in_pool(B)),
    ?assertEqual(1, pool_len()),
    ?assertEqual(1, info_size()),
    ?assertEqual(vsize_of(A), info_bytes()).

%% Core regtest harness scenario rbf/simple, the group's control: accept
%% check of the replacement, broadcast, then getmempoolinfo size == 1.
rpc_rbf_simple_control_counters() ->
    _A = victim(),
    B = spend(cb_txid(?H_VICTIM), 0, subsidy(), 16#fffffffd, 4000),
    [Row] = rpc(<<"testmempoolaccept">>, [[hex(B)]]),
    ?assertEqual(true, maps:get(<<"allowed">>, Row)),
    BTxidHex = rpc(<<"sendrawtransaction">>, [hex(B)]),
    ?assertEqual(hex_txid(B), BTxidHex),
    Info = maps:from_list(rpc(<<"getmempoolinfo">>, [])),
    ?assertEqual(1, maps:get(<<"size">>, Info)),
    ?assertEqual(vsize_of(B), maps:get(<<"bytes">>, Info)),
    ?assertEqual([beamchain_serialize:tx_hash(B)], beamchain_mempool:get_all_txids()).

%% P + 63 children is a full 64-tx cluster.  A replacement of one child
%% leaves it at 64, so it must pass the cluster limit even though the
%% child it replaces is only staged for eviction when the limit is checked.
replacement_freeing_cluster_room_accepted() ->
    Cb = cb_txid(?H_CLUSTER),
    N = 63,
    Vo = (subsidy() - ?FEE) div N,
    P = (spend(Cb, 0, subsidy(), 16#fffffffd, 0))#transaction{
          outputs = [#tx_out{value = Vo, script_pubkey = p2sh_true()}
                     || _ <- lists:seq(1, N)]},
    ?assertMatch({ok, _}, beamchain_mempool:add_transaction(P)),
    PTxid = beamchain_serialize:tx_hash(P),
    Children = [child(PTxid, I, Vo, 1000) || I <- lists:seq(0, N - 1)],
    lists:foreach(fun(C) ->
        ?assertMatch({ok, _}, beamchain_mempool:add_transaction(C))
    end, Children),
    ?assertEqual(64, pool_len()),
    Last = lists:last(Children),
    R = child(PTxid, N - 1, Vo, 5000),
    ?assertMatch({ok, _, _, _, _, _}, beamchain_mempool:accept_to_memory_pool_dry_run(R)),
    ?assert(in_pool(Last)),
    ?assertEqual(64, pool_len()),
    ?assertMatch({ok, _}, beamchain_mempool:add_transaction(R)),
    ?assert(in_pool(R)),
    ?assertNot(in_pool(Last)),
    ?assertEqual(64, pool_len()),
    ?assertEqual(64, info_size()).

%%% ===================================================================
%%% Helpers
%%% ===================================================================

victim() ->
    A = spend(cb_txid(?H_VICTIM), 0, subsidy(), 16#fffffffd, 0),
    ?assertMatch({ok, _}, beamchain_mempool:add_transaction(A)),
    ?assert(in_pool(A)),
    ?assertEqual(1, info_size()),
    A.

%% One child of Parent:Vout paying Fee.
child(Parent, Vout, Amount, Fee) ->
    #transaction{
        version = 2,
        inputs = [#tx_in{prev_out = #outpoint{hash = Parent, index = Vout},
                         script_sig = <<1, 16#51>>, sequence = 16#fffffffd,
                         witness = []}],
        outputs = [#tx_out{value = Amount - Fee, script_pubkey = p2sh_true()}],
        locktime = 0}.

%% Redeem script OP_2 instead of OP_1: hash160 no longer matches the
%% P2SH(OP_TRUE) output, so the tx fails only at the script gate.
bad_script(#transaction{inputs = [In]} = Tx) ->
    Tx#transaction{inputs = [In#tx_in{script_sig = <<1, 16#52>>}]}.

%% Deliver Tx as a peer's P2P `tx` message.
p2p_tx(Tx) ->
    Payload = beamchain_serialize:encode_transaction(Tx),
    {ok, _} = beamchain_p2p_msg:decode_payload(tx, Payload),
    beamchain_sync:process_tx(self(), Payload).

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

in_pool(Tx) ->
    lists:member(beamchain_serialize:tx_hash(Tx), beamchain_mempool:get_all_txids()).

pool_len() -> length(beamchain_mempool:get_all_txids()).
info_size() -> maps:get(size, beamchain_mempool:get_info()).
info_bytes() -> maps:get(bytes, beamchain_mempool:get_info()).
vsize_of(Tx) -> beamchain_serialize:tx_vsize(Tx).

%% Spend Txid:Vout (a P2SH(OP_TRUE) coin worth Amount) into one
%% P2SH(OP_TRUE) output, paying ?FEE + Salt.
spend(Txid, Vout, Amount, Seq, Salt) ->
    #transaction{
        version = 2,
        inputs = [#tx_in{prev_out = #outpoint{hash = Txid, index = Vout},
                         script_sig = <<1, 16#51>>, sequence = Seq,
                         witness = []}],
        outputs = [#tx_out{value = Amount - ?FEE - Salt,
                           script_pubkey = p2sh_true()}],
        locktime = 0}.

%%% ===================================================================
%%% Fixture (same regtest chain as beamchain_mempool_reorg_tests)
%%% ===================================================================

chain_setup() ->
    TmpDir = filename:join(["/tmp", "bc_free_evict_" ++
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
    mine_block(TipHash, H, [coinbase(H, <<"fe">>) | Txs], ts(H)).

build_chain(ToHeight) ->
    {ok, {_, TipH}} = beamchain_chainstate:get_tip(),
    lists:foreach(fun(_) ->
        ok = beamchain_chainstate:connect_block(next_block([]))
    end, lists:seq(TipH + 1, ToHeight)).

cb_txid(Height) ->
    {ok, #{hash := Hash}} = beamchain_db:get_block_index(Height),
    {ok, #block{transactions = [Cb | _]}} = beamchain_db:get_block(Hash),
    beamchain_serialize:tx_hash(Cb).
