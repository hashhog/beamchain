-module(beamchain_mempool_bip68_tests).

%%% BIP-68 relative locks on UNCONFIRMED parents in the mempool.
%%%
%%% Core (validation.cpp CalculateLockPointsAtTip / CalculatePrevHeights,
%%% CheckSequenceLocksAtTip): a coin created by a mempool (or package)
%%% transaction is given height tip+1 -- the height of the block that would
%%% include the spender -- and the time lock starts at the tip's MTP. A
%%% child with nSequence relative lock N >= 1 (height or time) on an
%%% unconfirmed parent is therefore NOT final for the next block and is
%%% refused (non-BIP68-final). beamchain gave such coins height 0
%%% (beamchain_mempool get_mempool_utxo / get_package_utxo), counting the
%%% lock from genesis: the child was accepted early and could enter a
%%% block template that the network rejects (bad-txns-nonfinal).
%%%
%%% Driven through the real ATMP over a real regtest chainstate.
%%%   rebar3 eunit --module=beamchain_mempool_bip68_tests

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-define(PRIV, <<7:256>>).
-define(OP_TRUE, <<16#51>>).
-define(TYPE_FLAG, (1 bsl 22)).

bip68_mempool_parent_test_() ->
    {foreach, fun setup/0, fun teardown/1,
     [fun(_) -> {timeout, 120, {"FIX: child with a 1-block height lock on a mempool parent is refused",
                                fun height_lock_on_mempool_parent/0}} end,
      fun(_) -> {timeout, 120, {"FIX: child with a 512 s time lock on a mempool parent is refused",
                                fun time_lock_on_mempool_parent/0}} end,
      fun(_) -> {timeout, 120, {"FIX: testmempoolaccept agrees (dry run)",
                                fun dry_run_agrees/0}} end,
      fun(_) -> {timeout, 120, {"CONTROL: relative lock 0 on a mempool parent is satisfied",
                                fun zero_lock_on_mempool_parent/0}} end,
      fun(_) -> {timeout, 120, {"CONTROL: disable flag on a mempool parent is accepted",
                                fun disabled_lock_on_mempool_parent/0}} end,
      fun(_) -> {timeout, 120, {"CONTROL: satisfied height lock on a confirmed coin is accepted",
                                fun satisfied_lock_confirmed/0}} end,
      fun(_) -> {timeout, 120, {"CONTROL: unsatisfied height lock on a confirmed coin is refused",
                                fun unsatisfied_lock_confirmed/0}} end]}.

setup() ->
    TmpDir = chain_setup(),
    build_chain(101),
    catch gen_server:stop(beamchain_mempool),
    {ok, MP} = beamchain_mempool:start_link(),
    unlink(MP),
    TmpDir.

teardown(TmpDir) ->
    chain_teardown(TmpDir).

%%% ===================================================================

height_lock_on_mempool_parent() ->
    Parent = spend_coinbase_p2wpkh(2, 16#fffffffd, 2),
    ?assertMatch({ok, _}, beamchain_mempool:add_transaction(Parent)),
    Child = spend_prev(Parent, 0, 1),
    ?assertEqual({error, sequence_lock_not_met},
                 beamchain_mempool:add_transaction(Child)),
    ?assertNot(beamchain_mempool:has_tx(beamchain_serialize:tx_hash(Child))).

time_lock_on_mempool_parent() ->
    Parent = spend_coinbase_p2wpkh(2, 16#fffffffd, 2),
    ?assertMatch({ok, _}, beamchain_mempool:add_transaction(Parent)),
    Child = spend_prev(Parent, 0, ?TYPE_FLAG bor 1),
    ?assertEqual({error, sequence_lock_not_met},
                 beamchain_mempool:add_transaction(Child)).

dry_run_agrees() ->
    Parent = spend_coinbase_p2wpkh(2, 16#fffffffd, 2),
    ?assertMatch({ok, _}, beamchain_mempool:add_transaction(Parent)),
    Child = spend_prev(Parent, 0, 1),
    ?assertMatch({error, sequence_lock_not_met},
                 beamchain_mempool:accept_to_memory_pool_dry_run(Child)).

zero_lock_on_mempool_parent() ->
    Parent = spend_coinbase_p2wpkh(2, 16#fffffffd, 2),
    ?assertMatch({ok, _}, beamchain_mempool:add_transaction(Parent)),
    Child = spend_prev(Parent, 0, 0),
    ?assertMatch({ok, _}, beamchain_mempool:add_transaction(Child)),
    Child2 = spend_prev(Parent, 1, ?TYPE_FLAG bor 0),
    ?assertMatch({ok, _}, beamchain_mempool:add_transaction(Child2)).

disabled_lock_on_mempool_parent() ->
    Parent = spend_coinbase_p2wpkh(2, 16#fffffffd, 2),
    ?assertMatch({ok, _}, beamchain_mempool:add_transaction(Parent)),
    Child = spend_prev(Parent, 0, 16#fffffffe),
    ?assertMatch({ok, _}, beamchain_mempool:add_transaction(Child)).

satisfied_lock_confirmed() ->
    %% coinbase at height 2, tip 101: 99 confirmations >= lock 10.
    Tx = spend_coinbase_p2wpkh(2, 10, 1),
    ?assertMatch({ok, _}, beamchain_mempool:add_transaction(Tx)).

unsatisfied_lock_confirmed() ->
    %% coinbase at height 2, next block 102: lock 101 needs height >= 103.
    Tx = spend_coinbase_p2wpkh(2, 101, 1),
    ?assertEqual({error, sequence_lock_not_met},
                 beamchain_mempool:add_transaction(Tx)).

%%% ===================================================================
%%% Fixture + helpers (same regtest chain as beamchain_gate6_tests)
%%% ===================================================================

chain_setup() ->
    TmpDir = filename:join(["/tmp", "beamchain_gate6_" ++
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

pub() ->
    {ok, Pub} = beamchain_crypto:pubkey_from_privkey(?PRIV),
    Pub.

p2wpkh_spk() ->
    <<16#00, 20, (beamchain_crypto:hash160(pub()))/binary>>.

%% Recent timestamps (the last blocks are inside 24 h) so the node can
%% leave IBD; strictly increasing so MTP never blocks a block.
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
        outputs = [#tx_out{value = 2500000000, script_pubkey = ?OP_TRUE},
                   #tx_out{value = 2500000000, script_pubkey = p2wpkh_spk()}],
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
    Cb0 = coinbase(H, <<"g6">>),
    %% Fees go unclaimed (allowed): the coinbase stays at 50 BTC.
    mine_block(TipHash, H, [Cb0 | Txs], ts(H)).

build_chain(ToHeight) ->
    {ok, {_, TipH}} = beamchain_chainstate:get_tip(),
    lists:foreach(fun(_) ->
        ok = beamchain_chainstate:connect_block(next_block([]))
    end, lists:seq(TipH + 1, ToHeight)).

coinbase_txid_at(Height) ->
    {ok, #{hash := Hash}} = beamchain_db:get_block_index(Height),
    {ok, #block{transactions = [Cb | _]}} = beamchain_db:get_block(Hash),
    beamchain_serialize:tx_hash(Cb).


%% Spend coinbase(Height) output 1 (P2WPKH) into NOut P2WPKH outputs.
spend_coinbase_p2wpkh(Height, Seq, NOut) ->
    Txid = coinbase_txid_at(Height),
    sign_p2wpkh(Txid, 1, 2500000000, Seq, NOut).

%% Spend output Vout of an unconfirmed P2WPKH tx.
spend_prev(Prev, Vout, Seq) ->
    #tx_out{value = V} = lists:nth(Vout + 1, Prev#transaction.outputs),
    sign_p2wpkh(beamchain_serialize:tx_hash(Prev), Vout, V, Seq, 1).

sign_p2wpkh(Txid, Vout, Amount, Seq, NOut) ->
    Pub = pub(),
    In = #tx_in{prev_out = #outpoint{hash = Txid, index = Vout},
                script_sig = <<>>, sequence = Seq, witness = []},
    Each = (Amount - 20000) div NOut,
    Tx0 = #transaction{version = 2, inputs = [In],
                       outputs = [#tx_out{value = Each,
                                          script_pubkey = p2wpkh_spk()}
                                  || _ <- lists:seq(1, NOut)],
                       locktime = 0},
    ScriptCode = <<16#76, 16#a9, 20, (beamchain_crypto:hash160(Pub))/binary,
                   16#88, 16#ac>>,
    SigHash = beamchain_script:sighash_witness_v0(Tx0, 0, ScriptCode, Amount,
                                                  ?SIGHASH_ALL),
    {ok, Der} = beamchain_crypto:ecdsa_sign(SigHash, ?PRIV),
    Tx0#transaction{inputs = [In#tx_in{witness = [<<Der/binary, ?SIGHASH_ALL>>,
                                                  Pub]}]}.
