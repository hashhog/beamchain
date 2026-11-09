-module(beamchain_mempool_trim_usage_tests).
%%% -maxmempool limits the pool's MEMORY USAGE, like Core, not its vsize.
%%%
%%% Core CTxMemPool::TrimToSize (txmempool.cpp:868) evicts while
%%% DynamicMemoryUsage() > sizelimit, and GetMinFee (txmempool.cpp:829) picks
%%% the rolling-fee halflife from the same number and decays on GetTime(),
%%% which setmocktime moves. beamchain compared the sum of vsizes against the
%%% limit, so a pool of many-input transactions (about 6x more memory than
%%% vsize) was never trimmed, the rolling minimum fee was never raised, and
%%% getmempoolinfo.mempoolminfee was a constant.
%%%
%%% Core regtest rows (warden_invalidated_submit, -maxmempool=5): 14 sends of
%%% an 800-input tx; Core keeps 12 of them (usage 4773160, mempoolminfee
%%% 4.77e-06, after 12 h 2.38e-06), beamchain kept all 14.
-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

-define(FANOUT_HEIGHT, 1).
-define(INPUTS_PER_TX, 1500).
-define(TXS, 4).

%%% ===================================================================
%%% Per-entry estimate, anchored on Core v31.1 getmempoolinfo.usage
%%% ===================================================================
%%% Core's figures (Core regtest run, warden_invalidated_submit group) include
%%% the pool-level txns_randomized vector, MallocUsage(40 * capacity): 64 at
%%% capacity 1, 656 at capacity 16.

%% maturity/tip100-info:usage = 1176 for one 1-in 1-out P2WPKH spend.
p2wpkh_spend_matches_core_test() ->
    Tx = tx([#tx_in{prev_out = op(1), script_sig = <<>>, sequence = 16#ffffffff,
                    witness = [bytes(72), bytes(33)]}],
            [out(p2wpkh())]),
    ?assertEqual(1176 - 64, beamchain_mempool:entry_dynamic_usage(Tx)).

%% usage/usage-heavy:usage = 1272 for one P2WSH(OP_DROP OP_DROP OP_TRUE)
%% spend with an 80, 80, 3 byte witness.
p2wsh_drop_spend_matches_core_test() ->
    Tx = tx([drop_in(1)], [out(p2wpkh())]),
    ?assertEqual(1272 - 64, beamchain_mempool:entry_dynamic_usage(Tx)).

%% usage/usage-2in2out:usage = 1624 for one 2-in 2-out P2WPKH spend paying a
%% P2WPKH and a P2WSH output.
two_in_two_out_matches_core_test() ->
    In = fun(I) -> #tx_in{prev_out = op(I), script_sig = <<>>, sequence = 16#ffffffff,
                          witness = [bytes(72), bytes(33)]} end,
    Tx = tx([In(1), In(2)], [out(p2wpkh()), out(<<0, 32, (bytes(32))/binary>>)]),
    ?assertEqual(1624 - 64, beamchain_mempool:entry_dynamic_usage(Tx)).

%% pressure/info:usage = 4773160 for 12 of the 800-input pressure txs plus a
%% parent/child pair of P2WPKH spends. 13 of them exceed -maxmempool=5, 12 do
%% not, which is why Core keeps 12.
pressure_pool_matches_core_test() ->
    Pressure = beamchain_mempool:entry_dynamic_usage(
                 tx([drop_in(I) || I <- lists:seq(1, 800)], [out(p2wpkh())])),
    Pair = 2 * beamchain_mempool:entry_dynamic_usage(
                 tx([#tx_in{prev_out = op(1), script_sig = <<>>,
                            sequence = 16#ffffffff,
                            witness = [bytes(72), bytes(33)]}],
                    [out(p2wpkh())])),
    Pool12 = 12 * Pressure + Pair + 656,
    ?assert(abs(Pool12 - 4773160) < 4773160 div 1000),
    ?assert(12 * Pressure + Pair =< 5000000),
    ?assert(13 * Pressure > 5000000),
    %% vsize alone (about 66 kvB each) would admit 75 of them.
    ?assert(75 * 66244 < 5000000).

%% Scripts up to 36 bytes live inside CScript's prevector; longer ones are a
%% heap allocation (MallocUsage of their length).
long_script_is_counted_test() ->
    Short = tx([#tx_in{prev_out = op(1), script_sig = bytes(36),
                       sequence = 0, witness = []}], [out(p2wpkh())]),
    Long = tx([#tx_in{prev_out = op(1), script_sig = bytes(37),
                      sequence = 0, witness = []}], [out(p2wpkh())]),
    ?assertEqual(64, beamchain_mempool:entry_dynamic_usage(Long)
                     - beamchain_mempool:entry_dynamic_usage(Short)).

%%% ===================================================================
%%% Live pool: trim, rolling minimum fee, decay (gen_server + chain)
%%% ===================================================================

trim_usage_test_() ->
    {foreach, fun setup/0, fun teardown/1,
     [fun(_) -> {timeout, 300,
                 {"-maxmempool=1: usage over the limit evicts the lowest feerate, "
                  "raises and then decays mempoolminfee",
                  fun trims_on_usage_not_vsize/0}} end]}.

trims_on_usage_not_vsize() ->
    Fanout = cb_txid(?FANOUT_HEIGHT),
    Txs = [heavy(Fanout, I) || I <- lists:seq(0, ?TXS - 1)],
    [T0 | _] = Txs,
    %% The vsize of the whole set is far under 1 MB ...
    TotalVSize = lists:sum([vsize_of(T) || T <- Txs]),
    ?assert(TotalVSize < 300000),
    lists:foreach(fun(T) ->
        ?assertEqual(hex_txid(T), rpc(<<"sendrawtransaction">>, [hex(T)]))
    end, lists:sublist(Txs, ?TXS - 1)),
    %% CONTROL: three of them fit, nothing is evicted, no rolling floor.
    I3 = info(),
    ?assertEqual(?TXS - 1, maps:get(<<"size">>, I3)),
    ?assertEqual(1.0e-6, maps:get(<<"mempoolminfee">>, I3)),
    %% ... but the memory usage of four is over it: the lowest-feerate tx goes.
    ?assertEqual(hex_txid(lists:last(Txs)),
                 rpc(<<"sendrawtransaction">>, [hex(lists:last(Txs))])),
    I4 = info(),
    ?assertEqual(?TXS - 1, maps:get(<<"size">>, I4)),
    ?assertNot(in_pool(T0)),
    ?assert(lists:all(fun in_pool/1, tl(Txs))),
    Kept = tl(Txs),
    ?assertEqual(lists:sum([vsize_of(T) || T <- Kept]), maps:get(<<"bytes">>, I4)),
    %% Rolling floor = CFeeRate(fee, vsize).GetFeePerK() (rounded down) +
    %% incremental relay fee 100 sat/kvB.
    Rolling = (fee(0) * 1000) div vsize_of(T0) + 100,
    ?assertEqual(Rolling / 1.0e8, maps:get(<<"mempoolminfee">>, I4)),
    %% A block arrives, then 12 h + 11 s pass on the mocked clock. Usage is
    %% above half the limit, so the halflife is the full 12 h.
    Now = erlang:system_time(second),
    persistent_term:put(beamchain_mocktime, Now),
    ok = beamchain_mempool:remove_for_block([]),
    persistent_term:put(beamchain_mocktime, Now + 43211),
    Decayed = round(Rolling / math:pow(2.0, 43211 / 43200)),
    I5 = info(),
    ?assertEqual(Decayed / 1.0e8, maps:get(<<"mempoolminfee">>, I5)),
    %% getmempoolinfo.usage is the number the limit was enforced on.
    ?assertEqual(lists:sum([beamchain_mempool:entry_dynamic_usage(T) || T <- Kept]),
                 maps:get(<<"usage">>, I5)),
    ?assert(maps:get(<<"usage">>, I5) =< 1000000).

%%% ===================================================================
%%% Helpers
%%% ===================================================================

fee(I) -> 20000 + I * 5000.

%% Tx I spends fanout outputs [I*N, (I+1)*N) into one P2SH(OP_TRUE) output.
heavy(Fanout, I) ->
    N = ?INPUTS_PER_TX,
    Ins = [#tx_in{prev_out = #outpoint{hash = Fanout, index = V},
                  script_sig = <<1, 16#51>>, sequence = 16#fffffffd,
                  witness = []} || V <- lists:seq(I * N, (I + 1) * N - 1)],
    tx(Ins, [#tx_out{value = N * fanout_value() - fee(I),
                     script_pubkey = p2sh_true()}]).

fanout_outputs() -> ?INPUTS_PER_TX * ?TXS.
fanout_value() -> subsidy() div fanout_outputs().

tx(Ins, Outs) ->
    #transaction{version = 2, inputs = Ins, outputs = Outs, locktime = 0}.

op(I) -> #outpoint{hash = <<I:256>>, index = 0}.
out(Spk) -> #tx_out{value = 1000000, script_pubkey = Spk}.
bytes(N) -> binary:copy(<<16#11>>, N).
p2wpkh() -> <<0, 20, (bytes(20))/binary>>.
drop_in(I) ->
    #tx_in{prev_out = op(I), script_sig = <<>>, sequence = 16#fffffffd,
           witness = [bytes(80), bytes(80), <<16#75, 16#51, 16#75>>]}.

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

in_pool(Tx) ->
    lists:member(beamchain_serialize:tx_hash(Tx), beamchain_mempool:get_all_txids()).

vsize_of(Tx) -> beamchain_serialize:tx_vsize(Tx).

setup() ->
    os:putenv("BEAMCHAIN_MAXMEMPOOL", "1"),
    TmpDir = chain_setup(),
    %% Height 1 pays the whole subsidy to fanout_outputs() P2SH(OP_TRUE) coins.
    {ok, {TipHash, 0}} = beamchain_chainstate:get_tip(),
    Cb = (coinbase(1, <<"fanout">>))#transaction{
           outputs = [#tx_out{value = fanout_value(), script_pubkey = p2sh_true()}
                      || _ <- lists:seq(1, fanout_outputs())]},
    ok = beamchain_chainstate:connect_block(mine_block(TipHash, 1, [Cb], ts(1))),
    build_chain(110),
    catch gen_server:stop(beamchain_mempool),
    {ok, MP} = beamchain_mempool:start_link(),
    unlink(MP),
    ok = meck:new(beamchain_peer_manager, [passthrough, no_link]),
    ok = meck:expect(beamchain_peer_manager, announce_tx, fun(_) -> ok end),
    TmpDir.

teardown(TmpDir) ->
    persistent_term:erase(beamchain_mocktime),
    os:unsetenv("BEAMCHAIN_MAXMEMPOOL"),
    catch meck:unload(beamchain_peer_manager),
    chain_teardown(TmpDir).

%%% ===================================================================
%%% Fixture (same regtest chain as beamchain_free_mempool_eviction_tests)
%%% ===================================================================

chain_setup() ->
    %% OS pid + time: unique_integer alone repeats across fresh VMs, and a
    %% leftover dir from a killed run would hand setup a chain at height 110.
    TmpDir = filename:join(["/tmp", "bc_trim_usage_" ++ os:getpid() ++ "_" ++
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
