-module(beamchain_package_rbf_reconsider_tests).

%%% Package RBF (refill-20261114-beamchain-policy, core-regtest group
%%% package_rbf).  Core's ReplacementChecks marks an RBF fee shortfall
%%% TX_RECONSIDERABLE ("Result may change in a package context",
%%% validation.cpp), so a 1-parent-1-child package whose parent cannot pay
%%% for the replacement alone is retried as a package RBF (PackageRBFChecks).
%%% beamchain treated the parent's "insufficient fee" as final: the package
%%% failed, the conflicts stayed, and package_msg read "transaction failed"
%%% where Core says "success" (or "too-large-cluster" over the cluster
%%% limit).  The old package RBF code also evicted the conflicts BEFORE the
%%% package's last gates ran, so a package that then failed still cost the
%%% mempool its conflicts; the guard tests below pin that nothing is evicted.
%%%   rebar3 eunit --module=beamchain_package_rbf_reconsider_tests

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-define(PRIV, <<7:256>>).
-define(OP_TRUE, <<16#51>>).
-define(CB_VALUE, 2500000000).
-define(RBF_SEQ, 16#fffffffd).

package_rbf_test_() ->
    {foreach, fun setup/0, fun teardown/1,
     [fun(_) -> {timeout, 120, {"FIX: parent failing RBF alone is replaced as a 1p1c package",
                                fun package_rbf_replaces_conflicts/0}} end,
      fun(_) -> {timeout, 120, {"FIX: submitpackage reports success and the replaced txids",
                                fun rpc_reports_success_and_replaced/0}} end,
      fun(_) -> {timeout, 180, {"FIX: cluster at the 404000-weight limit is accepted",
                                fun at_cluster_limit_accepted/0}} end,
      fun(_) -> {timeout, 180, {"FIX: cluster over the limit is too-large-cluster and evicts nothing",
                                fun over_cluster_limit_evicts_nothing/0}} end,
      fun(_) -> {timeout, 120, {"FIX: package fees below the conflicts fail anti-DoS, evict nothing",
                                fun insufficient_package_fees/0}} end,
      fun(_) -> {timeout, 120, {"GUARD: package with a mempool ancestor is refused, evicts nothing",
                                fun mempool_ancestor_refused/0}} end,
      fun(_) -> {timeout, 120, {"GUARD: child with a bad signature evicts nothing",
                                fun bad_child_signature_evicts_nothing/0}} end,
      fun(_) -> {timeout, 120, {"CONTROL: a lone RBF failure keeps its own reason",
                                fun lone_rbf_failure_is_final/0}} end]}.

setup() ->
    TmpDir = chain_setup(),
    build_chain(110),
    catch gen_server:stop(beamchain_mempool),
    {ok, MP} = beamchain_mempool:start_link(),
    unlink(MP),
    TmpDir.

teardown(TmpDir) ->
    chain_teardown(TmpDir).

txid(Tx) -> beamchain_serialize:tx_hash(Tx).

in_pool(Tx) -> beamchain_mempool:has_tx(txid(Tx)).

%% O (fee 20000) and its descendant D (fee 1000) spend coinbase(Height):1;
%% P (fee 6000) double-spends O's input and C (fee ChildFee) spends P:0.
%% P and C also carry NP / NC bare 1-of-1 multisig outputs (20 legacy
%% sigops each), as in the core-regtest package_rbf group.
scenario(Height, NP, NC, ChildFee) ->
    scenario(Height, NP, NC, ChildFee, 0).

%% NO extra 1000-sat outputs make O wide and cheap, so a large package still
%% improves the feerate diagram and the cluster limit is what decides.
scenario(Height, NP, NC, ChildFee, NO) ->
    Cb = coinbase_txid_at(Height),
    VO = ?CB_VALUE - 20000 - NO * 1000,
    O = sign_outs(Cb, 1, ?CB_VALUE,
                  [{VO, p2wpkh_spk()} | lists:duplicate(NO, {1000, p2wpkh_spk()})]),
    D = sign_outs(txid(O), 0, VO, [{VO - 1000, p2wpkh_spk()}]),
    VP = ?CB_VALUE - 6000 - NP * 1000,
    P = sign_outs(Cb, 1, ?CB_VALUE,
                  [{VP, p2wpkh_spk()} | lists:duplicate(NP, {1000, multisig_spk()})]),
    VC = VP - ChildFee - NC * 1000,
    C = sign_outs(txid(P), 0, VP,
                  [{VC, p2wpkh_spk()} | lists:duplicate(NC, {1000, multisig_spk()})]),
    {ok, _} = beamchain_mempool:add_transaction(O),
    {ok, _} = beamchain_mempool:add_transaction(D),
    {O, D, P, C}.

package_rbf_replaces_conflicts() ->
    {O, D, P, C} = scenario(2, 0, 0, 200000),
    PT = txid(P), CT = txid(C),
    %% P alone cannot pay for O + D.
    ?assertEqual({error, rbf_insufficient_fee}, beamchain_mempool:add_transaction(P)),
    {ok, Accepted, Info} = beamchain_mempool:accept_package_info([P, C]),
    ?assertEqual([PT, CT], Accepted),
    ?assertEqual(lists:usort([txid(O), txid(D)]), lists:usort(maps:get(replaced, Info))),
    ?assertNot(in_pool(O)),
    ?assertNot(in_pool(D)),
    ?assert(in_pool(P)),
    ?assert(in_pool(C)),
    ?assertEqual(lists:usort([PT, CT]), lists:usort(beamchain_mempool:get_all_txids())),
    %% Each tx counted once: O and D subtracted, C not inserted twice.
    #{size := Size, bytes := Bytes} = beamchain_mempool:get_info(),
    ?assertEqual(2, Size),
    ?assertEqual(beamchain_serialize:tx_vsize(P) + beamchain_serialize:tx_vsize(C),
                 Bytes).

rpc_reports_success_and_replaced() ->
    {O, D, P, C} = scenario(2, 0, 0, 200000),
    {ok, Res} = beamchain_rpc:rpc_submitpackage([[hex(P), hex(C)]]),
    ?assertEqual(<<"success">>, maps:get(<<"package_msg">>, Res)),
    %% Core: std::set<Txid>, i.e. sorted by internal byte order.
    ?assertEqual([display_hex(T) || T <- lists:usort([txid(O), txid(D)])],
                 maps:get(<<"replaced-transactions">>, Res)),
    TxRes = maps:values(maps:get(<<"tx-results">>, Res)),
    ?assertEqual(2, length(TxRes)),
    [?assertNot(maps:is_key(<<"error">>, R)) || R <- TxRes],
    [?assert(is_integer(maps:get(<<"vsize">>, R))) || R <- TxRes].

at_cluster_limit_accepted() ->
    %% 126 + 126 multisig outputs: 403200 sigop-adjusted weight.
    {O, D, P, C} = scenario(2, 126, 126, 200000, 600),
    ?assertMatch({ok, [_, _], _}, beamchain_mempool:accept_package_info([P, C])),
    ?assertNot(in_pool(O)),
    ?assertNot(in_pool(D)),
    ?assert(in_pool(P)),
    ?assert(in_pool(C)).

over_cluster_limit_evicts_nothing() ->
    %% 127 + 126 multisig outputs: 404800 > 404000.
    {O, D, P, C} = scenario(2, 127, 126, 200000, 600),
    PT = txid(P), CT = txid(C),
    {error, Reason, Info} = beamchain_mempool:accept_package_info([P, C]),
    ?assertEqual({package_policy, <<"too-large-cluster">>, <<>>}, Reason),
    %% Each member keeps its individual result (Core PCKG_POLICY).
    ?assertEqual(rbf_insufficient_fee, maps:get(PT, maps:get(errors, Info))),
    ?assertEqual(orphan, maps:get(CT, maps:get(errors, Info))),
    ?assert(in_pool(O)),
    ?assert(in_pool(D)),
    ?assertNot(in_pool(P)),
    ?assertNot(in_pool(C)),
    %% And the RPC says so the way Core does.
    {ok, Res} = beamchain_rpc:rpc_submitpackage([[hex(P), hex(C)]]),
    ?assertEqual(<<"too-large-cluster">>, maps:get(<<"package_msg">>, Res)),
    ?assertEqual([], maps:get(<<"replaced-transactions">>, Res)),
    ?assert(in_pool(O)),
    ?assert(in_pool(D)).

insufficient_package_fees() ->
    %% P 6000 + C 1000 < O 20000 + D 1000.
    {O, D, P, C} = scenario(2, 0, 0, 1000),
    {error, Reason, _} = beamchain_mempool:accept_package_info([P, C]),
    Want = iolist_to_binary(["rejecting replacement ", display_hex(txid(C)),
                             ", less fees than conflicting txs; 0.00007 < 0.00021"]),
    ?assertEqual({package_policy,
                  <<"package RBF failed: insufficient anti-DoS fees">>, Want},
                 Reason),
    ?assert(in_pool(O)),
    ?assert(in_pool(D)),
    ?assertNot(in_pool(P)).

mempool_ancestor_refused() ->
    %% X in the mempool; O spends X:0; P double-spends X:0, so P has a
    %% mempool parent and a package RBF is not considered.
    Cb = coinbase_txid_at(3),
    VX = ?CB_VALUE - 10000,
    X = sign_outs(Cb, 1, ?CB_VALUE, [{VX, p2wpkh_spk()}]),
    {ok, _} = beamchain_mempool:add_transaction(X),
    O = sign_outs(txid(X), 0, VX, [{VX - 20000, p2wpkh_spk()}]),
    {ok, _} = beamchain_mempool:add_transaction(O),
    VP = VX - 6000,
    P = sign_outs(txid(X), 0, VX, [{VP, p2wpkh_spk()}]),
    C = sign_outs(txid(P), 0, VP, [{VP - 200000, p2wpkh_spk()}]),
    {error, Reason, _} = beamchain_mempool:accept_package_info([P, C]),
    ?assertEqual({package_policy, <<"package RBF failed: new transaction cannot "
                                    "have mempool ancestors">>, <<>>}, Reason),
    ?assert(in_pool(X)),
    ?assert(in_pool(O)),
    ?assertNot(in_pool(P)).

bad_child_signature_evicts_nothing() ->
    {O, D, P, _} = scenario(2, 0, 0, 200000),
    VP = ?CB_VALUE - 6000,
    BadC = sign_outs(txid(P), 0, VP, [{VP - 200000, p2wpkh_spk()}], VP - 1),
    ?assertMatch({error, _, _}, beamchain_mempool:accept_package_info([P, BadC])),
    ?assert(in_pool(O)),
    ?assert(in_pool(D)),
    ?assertNot(in_pool(P)),
    ?assertNot(in_pool(BadC)).

lone_rbf_failure_is_final() ->
    {O, D, P, _} = scenario(2, 0, 0, 200000),
    PT = txid(P),
    ?assertMatch({error, {tx_failed, PT, rbf_insufficient_fee}, _},
                 beamchain_mempool:accept_package_info([P])),
    ?assert(in_pool(O)),
    ?assert(in_pool(D)).

hex(T) ->
    beamchain_serialize:hex_encode(beamchain_serialize:encode_transaction(T)).

display_hex(Hash) ->
    beamchain_serialize:hex_encode(beamchain_serialize:reverse_bytes(Hash)).

multisig_spk() ->
    %% OP_1 <33-byte pubkey> OP_1 OP_CHECKMULTISIG
    <<16#51, 33, (pub())/binary, 16#51, 16#ae>>.

chain_setup() ->
    TmpDir = filename:join(["/tmp", "beamchain_pkgrbf_" ++
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



sign_outs(Txid, Vout, Amount, Outputs) ->
    sign_outs(Txid, Vout, Amount, Outputs, Amount).

%% Spend a P2WPKH output into Outputs ({Value, Spk}); SignAmount =/= Amount
%% gives a signature that fails the script check.
sign_outs(Txid, Vout, _Amount, Outputs, SignAmount) ->
    Pub = pub(),
    In = #tx_in{prev_out = #outpoint{hash = Txid, index = Vout},
                script_sig = <<>>, sequence = ?RBF_SEQ, witness = []},
    Tx0 = #transaction{version = 2, inputs = [In],
                       outputs = [#tx_out{value = V, script_pubkey = S}
                                  || {V, S} <- Outputs],
                       locktime = 0},
    ScriptCode = <<16#76, 16#a9, 20, (beamchain_crypto:hash160(Pub))/binary,
                   16#88, 16#ac>>,
    SigHash = beamchain_script:sighash_witness_v0(Tx0, 0, ScriptCode, SignAmount,
                                                  ?SIGHASH_ALL),
    {ok, Der} = beamchain_crypto:ecdsa_sign(SigHash, ?PRIV),
    Tx0#transaction{inputs = [In#tx_in{witness = [<<Der/binary, ?SIGHASH_ALL>>,
                                                  Pub]}]}.
