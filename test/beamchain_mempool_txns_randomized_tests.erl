-module(beamchain_mempool_txns_randomized_tests).
%%% getmempoolinfo.usage counts Core's txns_randomized vector.
%%%
%%% Core CTxMemPool::DynamicMemoryUsage() (txmempool.cpp:781) adds
%%% memusage::DynamicUsage(txns_randomized): MallocUsage(40 * capacity) for a
%%% std::vector<std::pair<Wtxid, txiter>> that addNewTransaction grows with
%%% emplace_back (libstdc++ doubles a full vector) and removeUnchecked shrinks
%%% with pop_back + shrink_to_fit once under half full, or clear() for the
%%% last element, which keeps the capacity. beamchain left the term out, so
%%% every non-empty pool reported less than Core, and a pool drained by a
%%% block reported 0 where Core reports 64.
%%%
%%% Core v31.1 regtest rows (warden_invalidated_submit): usage-drained 64 vs
%%% beamchain 0; tip100-info 1176 vs 1112, usage-2in2out 1624 vs 1560,
%%% usage-heavy 1272 vs 1208 (one tx each, capacity 1: 64 bytes short).
-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

-define(FANOUT_OUTPUTS, 16).

txns_randomized_test_() ->
    {foreach, fun setup/0, fun teardown/1,
     [fun(_) -> {timeout, 300,
                 {"one tx: usage is the entry plus MallocUsage(40) = 64",
                  fun one_tx_counts_capacity_one/0}} end,
      fun(_) -> {timeout, 300,
                 {"drained by a block: usage stays 64, as Core's clear() keeps capacity",
                  fun drained_pool_keeps_capacity/0}} end,
      fun(_) -> {timeout, 300,
                 {"capacity doubles on push and shrinks to fit under half full",
                  fun capacity_grows_and_shrinks/0}} end]}.

one_tx_counts_capacity_one() ->
    ?assertEqual(0, usage()),
    T = spend(0),
    ok = send(T),
    %% Core: usage/usage-2in2out etc. are entry + 64 for a one-tx pool.
    ?assertEqual(beamchain_mempool:entry_dynamic_usage(T) + 64, usage()).

drained_pool_keeps_capacity() ->
    T = spend(0),
    ok = send(T),
    ok = beamchain_mempool:remove_for_block([beamchain_serialize:tx_hash(T)]),
    ?assertEqual(0, maps:get(<<"size">>, info())),
    %% Core usage/usage-drained:usage = 64 on an empty pool.
    ?assertEqual(64, usage()).

capacity_grows_and_shrinks() ->
    Txs = [spend(I) || I <- lists:seq(0, 4)],
    lists:foreach(fun(T) -> ok = send(T) end, Txs),
    Entries = fun(L) -> lists:sum([beamchain_mempool:entry_dynamic_usage(T) || T <- L]) end,
    %% Five pushes: capacity 1, 2, 4, 8 -> MallocUsage(320) = 336.
    ?assertEqual(Entries(Txs) + 336, usage()),
    %% Size 4 of capacity 8 is not under half: capacity stays 8.
    [T0, T1, T2 | Rest] = Txs,
    ok = beamchain_mempool:remove_for_block([beamchain_serialize:tx_hash(T0)]),
    ?assertEqual(Entries([T1, T2 | Rest]) + 336, usage()),
    %% Size 3 of capacity 8: shrink_to_fit to 3 -> MallocUsage(120) = 144.
    ok = beamchain_mempool:remove_for_block([beamchain_serialize:tx_hash(T1)]),
    ?assertEqual(Entries([T2 | Rest]) + 144, usage()),
    %% A push into a full vector of 3 doubles it to 6 -> MallocUsage(240) = 256.
    T5 = spend(5),
    ok = send(T5),
    ?assertEqual(Entries([T2, T5 | Rest]) + 256, usage()).

%%% ===================================================================
%%% Helpers
%%% ===================================================================

usage() -> maps:get(<<"usage">>, info()).

send(Tx) ->
    Hex = hex_txid(Tx),
    ?assertEqual(Hex, rpc(<<"sendrawtransaction">>, [hex(Tx)])),
    ok.

%% Tx I spends fanout output I into one P2SH(OP_TRUE) output.
spend(I) ->
    Fanout = cb_txid(1),
    #transaction{version = 2,
                 inputs = [#tx_in{prev_out = #outpoint{hash = Fanout, index = I},
                                  script_sig = <<1, 16#51>>,
                                  sequence = 16#fffffffd, witness = []}],
                 outputs = [#tx_out{value = fanout_value() - 10000 - I * 1000,
                                    script_pubkey = p2sh_true()}],
                 locktime = 0}.

fanout_value() -> subsidy() div ?FANOUT_OUTPUTS.

info() -> maps:from_list(rpc(<<"getmempoolinfo">>, [])).

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
    {ok, {TipHash, 0}} = beamchain_chainstate:get_tip(),
    Cb = (coinbase(1, <<"fanout">>))#transaction{
           outputs = [#tx_out{value = fanout_value(), script_pubkey = p2sh_true()}
                      || _ <- lists:seq(1, ?FANOUT_OUTPUTS)]},
    ok = beamchain_chainstate:connect_block(mine_block(TipHash, 1, [Cb], ts(1))),
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
%%% Fixture (same regtest chain as beamchain_free_mempool_eviction_tests)
%%% ===================================================================

chain_setup() ->
    %% OS pid + time: unique_integer alone repeats across fresh VMs, and a
    %% leftover dir from a killed run would hand setup a chain at height 110.
    TmpDir = filename:join(["/tmp", "bc_txns_randomized_" ++ os:getpid() ++ "_" ++
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
