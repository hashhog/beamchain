-module(beamchain_mempool_package_dryrun_tests).

%%% testmempoolaccept on a child-with-parents package: the child must be
%%% evaluated against a view that includes the earlier package members
%%% (Core AcceptMultipleTransactions / PackageMempoolAccept). beamchain
%%% evaluated each member against confirmed UTXOs + mempool only, so the
%%% child of an unconfirmed parent reported missing inputs.
%%%   rebar3 eunit --module=beamchain_mempool_package_dryrun_tests

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-define(PRIV, <<7:256>>).
-define(OP_TRUE, <<16#51>>).

package_dryrun_test_() ->
    {foreach, fun setup/0, fun teardown/1,
     [fun(_) -> {timeout, 120, {"FIX: package child of an unconfirmed parent is allowed (dry run)",
                                fun child_sees_parent/0}} end,
      fun(_) -> {timeout, 120, {"CONTROL: three-deep chain is not child-with-parents (package error)",
                                fun chain_of_three/0}} end,
      fun(_) -> {timeout, 120, {"CONTROL: dry run writes nothing to the mempool",
                                fun dry_run_is_readonly/0}} end,
      fun(_) -> {timeout, 120, {"CONTROL: child alone (parent absent) still lacks inputs",
                                fun child_alone_missing/0}} end,
      fun(_) -> {timeout, 120, {"CONTROL: out-of-order package is a package error",
                                fun out_of_order/0}} end,
      %% Every gate that asks "is this prevout's parent unconfirmed?" must see
      %% the earlier package members, not only lookup_inputs_for_tx/1.
      %% Each case also runs the real accept_package/1 last, so the dry-run
      %% reason is pinned to what submission would say.
      fun(_) -> {timeout, 120, {"FIX: v3 child > 1000 vB of an in-package v3 parent is too large",
                                fun truc_child_too_large/0}} end,
      fun(_) -> {timeout, 120, {"FIX: v3 child of an in-package v2 parent is refused",
                                fun truc_spends_non_truc/0}} end,
      fun(_) -> {timeout, 120, {"FIX: v2 child of an in-package v3 parent is refused",
                                fun non_truc_spends_truc/0}} end,
      fun(_) -> {timeout, 120, {"FIX: child joining a 64-tx cluster via an in-package parent is too large",
                                fun cluster_limit_through_package_parent/0}} end,
      fun(_) -> {timeout, 120, {"CONTROL: small v3 child of an in-package v3 parent is allowed",
                                fun truc_child_small_ok/0}} end,
      fun(_) -> {timeout, 120, {"CONTROL: in-package parent joining a 62-tx cluster leaves room",
                                fun cluster_room_through_package_parent/0}} end,
      fun(_) -> {timeout, 120, {"CONTROL: two members spending one outpoint is conflict_in_package",
                                fun same_outpoint_conflict/0}} end,
      fun(_) -> {timeout, 120, {"CONTROL: a rejected parent exposes no outputs to its child",
                                fun rejected_parent_hides_outputs/0}} end,
      fun(_) -> {timeout, 120, {"CONTROL: allowed parent + failing child leaves nothing behind",
                                fun failing_child_leaves_nothing/0}} end]}.

setup() ->
    TmpDir = chain_setup(),
    build_chain(101),
    catch gen_server:stop(beamchain_mempool),
    {ok, MP} = beamchain_mempool:start_link(),
    unlink(MP),
    TmpDir.

teardown(TmpDir) ->
    chain_teardown(TmpDir).

child_sees_parent() ->
    Parent = spend_coinbase_p2wpkh(2, 16#fffffffd, 2),
    Child = spend_prev(Parent, 0, 16#fffffffd),
    {ok, [R1, R2]} = beamchain_mempool:accept_package_dry_run([Parent, Child]),
    ?assertMatch({ok, _, _, 20000, _}, R1),
    ?assertMatch({ok, _, _, _, _}, R2).

chain_of_three() ->
    Parent = spend_coinbase_p2wpkh(2, 16#fffffffd, 1),
    Mid = spend_prev(Parent, 0, 16#fffffffd),
    Child = spend_prev(Mid, 0, 16#fffffffd),
    ?assertEqual({error, package_not_child_with_parents},
                 beamchain_mempool:accept_package_dry_run([Parent, Mid, Child])).

dry_run_is_readonly() ->
    Parent = spend_coinbase_p2wpkh(2, 16#fffffffd, 2),
    Child = spend_prev(Parent, 0, 16#fffffffd),
    {ok, _} = beamchain_mempool:accept_package_dry_run([Parent, Child]),
    ?assertNot(beamchain_mempool:has_tx(beamchain_serialize:tx_hash(Parent))),
    ?assertNot(beamchain_mempool:has_tx(beamchain_serialize:tx_hash(Child))),
    %% and a second dry run gives the same answer (no leaked overlay)
    {ok, [R1, R2]} = beamchain_mempool:accept_package_dry_run([Parent, Child]),
    ?assertMatch({ok, _, _, _, _}, R1),
    ?assertMatch({ok, _, _, _, _}, R2),
    ?assertMatch({error, _}, beamchain_mempool:accept_to_memory_pool_dry_run(Child)).

child_alone_missing() ->
    Parent = spend_coinbase_p2wpkh(2, 16#fffffffd, 2),
    Child = spend_prev(Parent, 0, 16#fffffffd),
    ?assertMatch({error, _}, beamchain_mempool:accept_to_memory_pool_dry_run(Child)).

out_of_order() ->
    Parent = spend_coinbase_p2wpkh(2, 16#fffffffd, 2),
    Child = spend_prev(Parent, 0, 16#fffffffd),
    ?assertEqual({error, package_not_sorted},
                 beamchain_mempool:accept_package_dry_run([Child, Parent])).

truc_child_too_large() ->
    Parent = spend_coinbase(2, 3, 1),
    Child = spend_prev(Parent, 0, 16#fffffffd, 35, 3),
    {ok, [R1, R2]} = beamchain_mempool:accept_package_dry_run([Parent, Child]),
    ?assertMatch({ok, _, _, _, _}, R1),
    {error, _, _, Reason} = R2,
    ?assertMatch({truc_violation, {child_too_large, _, 1000}}, Reason),
    assert_mempool_empty([Parent, Child]),
    assert_real_accept_agrees(Parent, Child, Reason).

truc_spends_non_truc() ->
    Parent = spend_coinbase(2, 2, 1),
    Child = spend_prev(Parent, 0, 16#fffffffd, 1, 3),
    {ok, [R1, R2]} = beamchain_mempool:accept_package_dry_run([Parent, Child]),
    ?assertMatch({ok, _, _, _, _}, R1),
    ?assertMatch({error, _, _, {truc_violation, truc_spends_non_truc}}, R2),
    assert_mempool_empty([Parent, Child]),
    assert_real_accept_agrees(Parent, Child, {truc_violation, truc_spends_non_truc}).

non_truc_spends_truc() ->
    Parent = spend_coinbase(2, 3, 1),
    Child = spend_prev(Parent, 0, 16#fffffffd, 1, 2),
    {ok, [R1, R2]} = beamchain_mempool:accept_package_dry_run([Parent, Child]),
    ?assertMatch({ok, _, _, _, _}, R1),
    ?assertMatch({error, _, _, {truc_violation, non_truc_spends_truc}}, R2),
    assert_mempool_empty([Parent, Child]),
    assert_real_accept_agrees(Parent, Child, {truc_violation, non_truc_spends_truc}).

%% Mempool fan of 1 + 62 = 63 txs; the package parent joins it (64, the
%% limit) and the child would make 65.
cluster_limit_through_package_parent() ->
    {Parent, Child} = fan_and_package(62),
    {ok, [R1, R2]} = beamchain_mempool:accept_package_dry_run([Parent, Child]),
    ?assertMatch({ok, _, _, _, _}, R1),
    ?assertMatch({error, _, _, too_large_cluster}, R2),
    assert_mempool_empty([Parent, Child]),
    ?assertEqual(63, mempool_size()),
    assert_real_accept_agrees(Parent, Child, too_large_cluster).

cluster_room_through_package_parent() ->
    {Parent, Child} = fan_and_package(61),
    {ok, [R1, R2]} = beamchain_mempool:accept_package_dry_run([Parent, Child]),
    ?assertMatch({ok, _, _, _, _}, R1),
    ?assertMatch({ok, _, _, _, _}, R2),
    assert_mempool_empty([Parent, Child]),
    ?assertEqual(62, mempool_size()).

truc_child_small_ok() ->
    Parent = spend_coinbase(2, 3, 1),
    Child = spend_prev(Parent, 0, 16#fffffffd, 1, 3),
    {ok, [R1, R2]} = beamchain_mempool:accept_package_dry_run([Parent, Child]),
    ?assertMatch({ok, _, _, _, _}, R1),
    ?assertMatch({ok, _, _, _, _}, R2),
    assert_mempool_empty([Parent, Child]).

same_outpoint_conflict() ->
    A = spend_coinbase_p2wpkh(2, 16#fffffffd, 1),
    B = spend_coinbase_p2wpkh(2, 16#fffffffd, 2),
    ?assertEqual({error, conflict_in_package},
                 beamchain_mempool:accept_package_dry_run([A, B])),
    assert_mempool_empty([A, B]),
    ?assertEqual(0, mempool_size()).

rejected_parent_hides_outputs() ->
    Txid = coinbase_txid_at(2),
    %% Signed over the wrong amount: the script check fails.
    Parent = sign_p2wpkh(Txid, 1, 2500000000, 16#fffffffd, 1, 2, 2400000000),
    Child = spend_prev(Parent, 0, 16#fffffffd),
    {ok, [R1, R2]} = beamchain_mempool:accept_package_dry_run([Parent, Child]),
    ?assertMatch({error, _, _, _}, R1),
    ?assertMatch({error, _, _, 'bad-txns-inputs-missingorspent'}, R2),
    assert_mempool_empty([Parent, Child]),
    assert_no_overlay().

failing_child_leaves_nothing() ->
    Parent = spend_coinbase_p2wpkh(2, 16#fffffffd, 1),
    #tx_out{value = V} = hd(Parent#transaction.outputs),
    Child = sign_p2wpkh(beamchain_serialize:tx_hash(Parent), 0, V,
                        16#fffffffd, 1, 2, V - 1),
    {ok, [R1, R2]} = beamchain_mempool:accept_package_dry_run([Parent, Child]),
    ?assertMatch({ok, _, _, _, _}, R1),
    {error, _, _, ChildReason} = R2,
    ?assertNotEqual('bad-txns-inputs-missingorspent', ChildReason),
    assert_mempool_empty([Parent, Child]),
    assert_no_overlay(),
    ?assertEqual({error, 'bad-txns-inputs-missingorspent'},
                 beamchain_mempool:accept_to_memory_pool_dry_run(Child)).

%%% ===================================================================
%%% Fixture + helpers (same regtest chain as beamchain_mempool_bip68_tests)
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

%% Same, with an explicit tx version.
spend_coinbase(Height, Version, NOut) ->
    Txid = coinbase_txid_at(Height),
    sign_p2wpkh(Txid, 1, 2500000000, 16#fffffffd, NOut, Version, 2500000000).

%% Spend output Vout of an unconfirmed P2WPKH tx.
spend_prev(Prev, Vout, Seq) ->
    spend_prev(Prev, Vout, Seq, 1, 2).

spend_prev(Prev, Vout, Seq, NOut, Version) ->
    #tx_out{value = V} = lists:nth(Vout + 1, Prev#transaction.outputs),
    sign_p2wpkh(beamchain_serialize:tx_hash(Prev), Vout, V, Seq, NOut,
                Version, V).

%% A fan in the mempool: one tx with NChildren + 1 outputs and
%% NChildren children spending all but the last. Returns a package whose
%% parent spends that last output, plus its child.
fan_and_package(NChildren) ->
    Fan = spend_coinbase_p2wpkh(2, 16#fffffffd, NChildren + 1),
    {ok, _} = beamchain_mempool:add_transaction(Fan),
    lists:foreach(fun(I) ->
        {ok, _} = beamchain_mempool:add_transaction(spend_prev(Fan, I, 16#fffffffd))
    end, lists:seq(0, NChildren - 1)),
    Parent = spend_prev(Fan, NChildren, 16#fffffffd),
    {Parent, spend_prev(Parent, 0, 16#fffffffd)}.

mempool_size() ->
    ets:info(mempool_txs, size).

assert_mempool_empty(Txs) ->
    [?assertNot(beamchain_mempool:has_tx(beamchain_serialize:tx_hash(T)))
     || T <- Txs],
    ok.

%% The dry-run package view lives in the mempool server's process
%% dictionary only for the duration of one call.
assert_no_overlay() ->
    {dictionary, D} = erlang:process_info(whereis(beamchain_mempool),
                                          dictionary),
    ?assertEqual([], [K || {K, _} <- D,
                           is_atom(K),
                           lists:prefix("beamchain_dry_run",
                                        atom_to_list(K))]).

%% Real submission of the same package rejects the child for the same reason.
assert_real_accept_agrees(Parent, Child, Reason) ->
    ChildTxid = beamchain_serialize:tx_hash(Child),
    ?assertEqual({error, {tx_failed, ChildTxid, Reason}},
                 beamchain_mempool:accept_package([Parent, Child])).

sign_p2wpkh(Txid, Vout, Amount, Seq, NOut) ->
    sign_p2wpkh(Txid, Vout, Amount, Seq, NOut, 2, Amount).

%% SignAmount =/= Amount produces a signature that fails the script check.
sign_p2wpkh(Txid, Vout, Amount, Seq, NOut, Version, SignAmount) ->
    Pub = pub(),
    In = #tx_in{prev_out = #outpoint{hash = Txid, index = Vout},
                script_sig = <<>>, sequence = Seq, witness = []},
    Each = (Amount - 20000) div NOut,
    Tx0 = #transaction{version = Version, inputs = [In],
                       outputs = [#tx_out{value = Each,
                                          script_pubkey = p2wpkh_spk()}
                                  || _ <- lists:seq(1, NOut)],
                       locktime = 0},
    ScriptCode = <<16#76, 16#a9, 20, (beamchain_crypto:hash160(Pub))/binary,
                   16#88, 16#ac>>,
    SigHash = beamchain_script:sighash_witness_v0(Tx0, 0, ScriptCode, SignAmount,
                                                  ?SIGHASH_ALL),
    {ok, Der} = beamchain_crypto:ecdsa_sign(SigHash, ?PRIV),
    Tx0#transaction{inputs = [In#tx_in{witness = [<<Der/binary, ?SIGHASH_ALL>>,
                                                  Pub]}]}.
