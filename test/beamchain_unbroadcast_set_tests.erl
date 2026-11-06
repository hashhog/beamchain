-module(beamchain_unbroadcast_set_tests).
%%% Core's unbroadcast set (CTxMemPool::m_unbroadcast_txids).
%%%
%%% A tx submitted through sendrawtransaction is added to the set
%%% (node/transaction.cpp BroadcastTransaction -> AddUnbroadcastTx) and
%%% getmempoolentry reports `unbroadcast: true` / getmempoolinfo
%%% `unbroadcastcount` counts it, until a peer requests it with getdata
%%% (net_processing.cpp ProcessGetData -> RemoveUnbroadcastTx), it is mined,
%%% or it leaves the pool (txmempool.cpp removeUnchecked).  A tx that arrived
%%% from a peer is never in the set.  beamchain always answered false / 0.
-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-define(FEE, 10000).
-define(H_A, 1).
-define(H_B, 2).

unbroadcast_test_() ->
    {foreach, fun setup/0, fun teardown/1,
     [fun(_) -> t("sendrawtransaction: entry unbroadcast true, count 1",
                  fun rpc_submit_marks_unbroadcast/0) end,
      fun(_) -> t("CONTROL: P2P-received tx is not unbroadcast",
                  fun p2p_tx_is_not_unbroadcast/0) end,
      fun(_) -> t("a peer's getdata clears the flag",
                  fun getdata_clears_unbroadcast/0) end,
      fun(_) -> t("a mined tx leaves the set",
                  fun mined_tx_leaves_set/0) end,
      fun(_) -> t("a child pulled and re-added by a reorg stays unbroadcast",
                  fun reorg_keeps_child_unbroadcast/0) end,
      fun(_) -> t("a tx evicted from the pool leaves the set",
                  fun removed_tx_leaves_set/0) end]}.

t(Name, F) -> {timeout, 180, {Name, F}}.

setup() ->
    TmpDir = chain_setup(),
    build_chain(110),
    catch gen_server:stop(beamchain_mempool),
    {ok, MP} = beamchain_mempool:start_link(),
    unlink(MP),
    ok = meck:new(beamchain_peer_manager, [passthrough, no_link]),
    ok = meck:expect(beamchain_peer_manager, announce_tx, fun(_) -> ok end),
    ok = meck:new(beamchain_peer, [passthrough, no_link]),
    ok = meck:expect(beamchain_peer, send_message, fun(_, _) -> ok end),
    TmpDir.

teardown(TmpDir) ->
    catch meck:unload(beamchain_peer),
    catch meck:unload(beamchain_peer_manager),
    chain_teardown(TmpDir).

%%% Cases

rpc_submit_marks_unbroadcast() ->
    A = spend(cb_txid(?H_A), 0, subsidy(), 16#fffffffd, 0),
    ?assertEqual(hex_txid(A), rpc(<<"sendrawtransaction">>, [hex(A)])),
    Entry = rpc(<<"getmempoolentry">>, [hex_txid(A)]),
    ?assertEqual(true, maps:get(<<"unbroadcast">>, Entry)),
    ?assertEqual(1, info_field(<<"unbroadcastcount">>)).

p2p_tx_is_not_unbroadcast() ->
    A = spend(cb_txid(?H_A), 0, subsidy(), 16#fffffffd, 0),
    Payload = beamchain_serialize:encode_transaction(A),
    ok = beamchain_sync:process_tx(self(), Payload),
    ?assert(in_pool(A)),
    Entry = rpc(<<"getmempoolentry">>, [hex_txid(A)]),
    ?assertEqual(false, maps:get(<<"unbroadcast">>, Entry)),
    ?assertEqual(0, info_field(<<"unbroadcastcount">>)).

getdata_clears_unbroadcast() ->
    A = spend(cb_txid(?H_A), 0, subsidy(), 16#fffffffd, 0),
    B = spend(cb_txid(?H_B), 0, subsidy(), 16#fffffffd, 0),
    rpc(<<"sendrawtransaction">>, [hex(A)]),
    rpc(<<"sendrawtransaction">>, [hex(B)]),
    ?assertEqual(2, info_field(<<"unbroadcastcount">>)),
    TxidA = beamchain_serialize:tx_hash(A),
    Payload = beamchain_p2p_msg:encode_payload(getdata,
        #{items => [#{type => ?MSG_WITNESS_TX, hash => TxidA}]}),
    beamchain_peer_manager:handle_getdata_msg(self(), Payload),
    ?assertEqual(false, maps:get(<<"unbroadcast">>,
        rpc(<<"getmempoolentry">>, [hex_txid(A)]))),
    ?assertEqual(true, maps:get(<<"unbroadcast">>,
        rpc(<<"getmempoolentry">>, [hex_txid(B)]))),
    ?assertEqual(1, info_field(<<"unbroadcastcount">>)).

mined_tx_leaves_set() ->
    A = spend(cb_txid(?H_A), 0, subsidy(), 16#fffffffd, 0),
    rpc(<<"sendrawtransaction">>, [hex(A)]),
    ?assertEqual(1, info_field(<<"unbroadcastcount">>)),
    ok = beamchain_chainstate:connect_block(next_block([A])),
    %% mempool notification of a connected block may be async
    ok = wait_until(fun() -> not in_pool(A) end),
    ?assertEqual(0, info_field(<<"unbroadcastcount">>)),
    ?assertNot(beamchain_mempool:is_unbroadcast(beamchain_serialize:tx_hash(A))).

%% seed_warden_e shape: parent P mined, child C submitted after; invalidating
%% P's block puts P back and relinks C (removed and re-added by beamchain).
%% Core never takes C out of its pool, so C is still unbroadcast.
reorg_keeps_child_unbroadcast() ->
    P = spend(cb_txid(?H_A), 0, subsidy(), 16#fffffffd, 0),
    ok = beamchain_chainstate:connect_block(next_block([P])),
    ok = wait_until(fun() -> not in_pool(P) end),
    {ok, {TipHash, _}} = beamchain_chainstate:get_tip(),
    PTxid = beamchain_serialize:tx_hash(P),
    C = spend(PTxid, 0, subsidy() - ?FEE, 16#fffffffd, 0),
    rpc(<<"sendrawtransaction">>, [hex(C)]),
    ?assertEqual(true, maps:get(<<"unbroadcast">>,
        rpc(<<"getmempoolentry">>, [hex_txid(C)]))),
    rpc(<<"invalidateblock">>,
        [beamchain_serialize:hex_encode(beamchain_serialize:reverse_bytes(TipHash))]),
    ?assert(in_pool(P)),
    ?assert(in_pool(C)),
    ?assertEqual(true, maps:get(<<"unbroadcast">>,
        rpc(<<"getmempoolentry">>, [hex_txid(C)]))),
    ?assertEqual(1, info_field(<<"unbroadcastcount">>)).

removed_tx_leaves_set() ->
    A = spend(cb_txid(?H_A), 0, subsidy(), 16#fffffffd, 0),
    rpc(<<"sendrawtransaction">>, [hex(A)]),
    ?assertEqual(1, info_field(<<"unbroadcastcount">>)),
    %% Replacement (BIP125) evicts A from the pool.
    B = spend(cb_txid(?H_A), 0, subsidy(), 16#fffffffd, 100000),
    rpc(<<"sendrawtransaction">>, [hex(B)]),
    ?assertNot(in_pool(A)),
    ?assertNot(beamchain_mempool:is_unbroadcast(beamchain_serialize:tx_hash(A))),
    ?assertEqual(1, info_field(<<"unbroadcastcount">>)).

wait_until(F) -> wait_until(F, 100).
wait_until(F, 0) -> case F() of true -> ok; false -> timeout end;
wait_until(F, N) ->
    case F() of
        true -> ok;
        false -> timer:sleep(50), wait_until(F, N - 1)
    end.

info_field(K) ->
    case rpc(<<"getmempoolinfo">>, []) of
        M when is_map(M) -> maps:get(K, M);
        L -> proplists:get_value(K, L)
    end.

%%% ===================================================================
%%% Helpers
%%% ===================================================================

rpc(Method, Params) ->
    case beamchain_rpc:dispatch(#{<<"jsonrpc">> => <<"1.0">>,
                                  <<"id">> => <<"t">>,
                                  <<"method">> => Method,
                                  <<"params">> => Params}, undefined) of
        #{<<"error">> := null, <<"result">> := Result} -> Result;
        {raw_json, Bin} ->
            #{<<"error">> := null, <<"result">> := R} = jsx:decode(Bin, [return_maps]),
            R;
        Other -> erlang:error({rpc_failed, Method, Other})
    end.

hex(Tx) ->
    beamchain_serialize:hex_encode(beamchain_serialize:encode_transaction(Tx)).

hex_txid(Tx) ->
    beamchain_serialize:hex_encode(
      beamchain_serialize:reverse_bytes(beamchain_serialize:tx_hash(Tx))).

in_pool(Tx) ->
    lists:member(beamchain_serialize:tx_hash(Tx), beamchain_mempool:get_all_txids()).

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
    TmpDir = filename:join(["/tmp", "bc_unbroadcast_" ++
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
