-module(beamchain_mempool_reorg_tests).

%%% The mempool must agree with the chain when the chain goes BACK:
%%% invalidateblock, reconsiderblock, a side-branch reorg (submitblock /
%%% block download) and a header-driven rollback (header_sync).
%%%
%%% Core (validation.cpp):
%%%   DisconnectTip   -> the block's txs go to the disconnect pool;
%%%   ConnectTip      -> mempool.removeForBlock(vtx) for EVERY connected
%%%                      block: confirmed txs and their conflicts (with
%%%                      descendants) leave the pool;
%%%   MaybeUpdateMempoolForReorg (InvalidateBlock: after each disconnected
%%%     block; ActivateBestChainStep: once at the end) -> re-accept the
%%%     disconnected txs earliest first, removeRecursive the ones that fail
%%%     (a child of a tx conflicted by the new branch goes too), then
%%%     removeForReorg drops entries non-final / immature at tip+1.
%%%   All under cs_main: RPC never sees the pool disagree with the tip.
%%%
%%% beamchain bug (c7f15d6, receipts/arch-concurrency-liveness-audit-
%%% 2026-10-07.md BC-2): every connect inside a reorg skipped removeForBlock
%%% and only a caller-side refill ran afterwards (most recent block first,
%%% so a child came before its parent); invalidateblock and the header-sync
%%% rollback refilled nothing. The pool kept a child of a conflicted tx and a
%%% double spend of the new branch -- an invalid getblocktemplate.
%%%
%%% Driven through a real regtest chainstate + the real mempool ATMP.
%%%   rebar3 eunit --module=beamchain_mempool_reorg_tests

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-define(FEE, 10000).

reorg_mempool_test_() ->
    {foreach, fun setup/0, fun teardown/1,
     [fun(_) -> {timeout, 180, {"invalidateblock refills the pool, drops what "
                                "is non-final / immature at tip+1; "
                                "reconsiderblock removes it again",
                                fun invalidate_then_reconsider/0}} end,
      fun(_) -> {timeout, 180, {"side-branch reorg (submitblock): new branch's "
                                "conflicts and their children leave the pool "
                                "before the call returns",
                                fun side_branch_reorg/0}} end,
      fun(_) -> {timeout, 180, {"header-driven rollback + linear connect of the "
                                "heavier branch ends where Core ends",
                                fun header_rollback_reorg/0}} end,
      fun(_) -> {timeout, 180, {"CONTROL: a branch that conflicts nothing keeps "
                                "every mempool tx",
                                fun control_no_conflict/0}} end]}.

%%% ===================================================================
%%% Scenario (mirrors tools/mempool-reorg-sweep.py)
%%%   1..110  coinbase only (pays P2SH(OP_TRUE))
%%%   111   [cb, A <- cb1, P <- cb2]
%%%   112   [cb, C <- P:0, LT <- cb3 (nLockTime 111), IMM <- cb12]
%%%   pool at 112: M <- A:0, M3 <- cb4
%%%   branch off 110: 111b [cb, X <- cb1 (conflicts A)], 112b [cb, P],
%%%                   113b [cb, Z <- cb4 (conflicts M3)]
%%% ===================================================================

setup() ->
    TmpDir = chain_setup(),
    build_chain(110),
    catch gen_server:stop(beamchain_mempool),
    {ok, MP} = beamchain_mempool:start_link(),
    unlink(MP),
    Txs = main_branch(),
    application:set_env(beamchain, reorg_test_txs, Txs),
    TmpDir.

teardown(TmpDir) ->
    chain_teardown(TmpDir).

txs() ->
    {ok, T} = application:get_env(beamchain, reorg_test_txs),
    T.

tx(Name) -> maps:get(Name, txs()).

txid(Name) -> beamchain_serialize:tx_hash(tx(Name)).

%% Mempool contents as a sorted list of scenario names (unknown txids are
%% reported as {unknown, Txid} so an extra entry can never be hidden).
pool() ->
    ByTxid = maps:from_list([{beamchain_serialize:tx_hash(T), N}
                             || {N, T} <- maps:to_list(txs())]),
    lists:sort([maps:get(Id, ByTxid, {unknown, Id})
                || Id <- beamchain_mempool:get_all_txids()]).

main_branch() ->
    A = spend(cb_txid(1), 0, subsidy(), 16#fffffffe, 0, 0),
    P = spend(cb_txid(2), 0, subsidy(), 16#fffffffe, 0, 0),
    ok = beamchain_chainstate:connect_block(next_block([A, P])),
    C = spend(beamchain_serialize:tx_hash(P), 0, subsidy() - ?FEE,
              16#fffffffe, 0, 0),
    LT = spend(cb_txid(3), 0, subsidy(), 16#fffffffe, 111, 0),
    IMM = spend(cb_txid(12), 0, subsidy(), 16#fffffffe, 0, 0),
    ok = beamchain_chainstate:connect_block(next_block([C, LT, IMM])),
    ?assertEqual({ok, 112}, beamchain_chainstate:get_tip_height()),
    M = spend(beamchain_serialize:tx_hash(A), 0, subsidy() - ?FEE,
              16#fffffffe, 0, 0),
    M3 = spend(cb_txid(4), 0, subsidy(), 16#fffffffe, 0, 0),
    ?assertMatch({ok, _}, beamchain_mempool:add_transaction(M)),
    ?assertMatch({ok, _}, beamchain_mempool:add_transaction(M3)),
    %% X / Z: different fee than A / M3, so different txids, same inputs.
    X = spend(cb_txid(1), 0, subsidy(), 16#fffffffe, 0, 1),
    Z = spend(cb_txid(4), 0, subsidy(), 16#fffffffe, 0, 1),
    #{'A' => A, 'P' => P, 'C' => C, 'LT' => LT, 'IMM' => IMM,
      'M' => M, 'M3' => M3, 'X' => X, 'Z' => Z}.

%% The competing branch off 110.
side_blocks(Branch) ->
    {ok, #{hash := H110}} = beamchain_db:get_block_index(110),
    B111 = mine_block(H110, 111, [coinbase(111, <<"b">>) | maps:get(111, Branch)],
                      ts(111) + 1),
    B112 = mine_block(B111#block.hash, 112,
                      [coinbase(112, <<"b">>) | maps:get(112, Branch)], ts(112) + 1),
    B113 = mine_block(B112#block.hash, 113,
                      [coinbase(113, <<"b">>) | maps:get(113, Branch)], ts(113) + 1),
    [B111, B112, B113].

conflicting_branch() ->
    side_blocks(#{111 => [tx('X')], 112 => [tx('P')], 113 => [tx('Z')]}).

%%% ===================================================================

invalidate_then_reconsider() ->
    ?assertEqual(['M', 'M3'], pool()),
    {ok, #{hash := H111}} = beamchain_db:get_block_index(111),
    ok = beamchain_chainstate:invalidate_block(H111),
    ?assertEqual({ok, 110}, beamchain_chainstate:get_tip_height()),
    %% Read IMMEDIATELY after the call returned (no settling): A, P, C back,
    %% M kept (its parent A is back); LT non-final at 111, IMM's coinbase
    %% immature at 111.
    ?assertEqual(lists:sort(['A', 'P', 'C', 'M', 'M3']), pool()),
    ok = beamchain_chainstate:reconsider_block(H111),
    ?assertEqual({ok, 112}, beamchain_chainstate:get_tip_height()),
    ?assertEqual(['M', 'M3'], pool()).

side_branch_reorg() ->
    [B111, B112, B113] = conflicting_branch(),
    ?assertEqual({ok, side_branch}, beamchain_chainstate:submit_block(B111, true)),
    ?assertEqual({ok, side_branch}, beamchain_chainstate:submit_block(B112, true)),
    ?assertEqual({ok, reorg}, beamchain_chainstate:submit_block(B113, true)),
    ?assertEqual({ok, 113}, beamchain_chainstate:get_tip_height()),
    %% A conflicts X -> fails re-accept -> its child M goes too; P is
    %% confirmed again; M3 conflicts Z. LT / IMM are fine at 114.
    ?assertEqual(lists:sort(['C', 'LT', 'IMM']), pool()).

header_rollback_reorg() ->
    [B111, B112, B113] = conflicting_branch(),
    ok = beamchain_chainstate:disconnect_block(header_reorg),
    ok = beamchain_chainstate:disconnect_block(header_reorg),
    ?assertEqual({ok, 110}, beamchain_chainstate:get_tip_height()),
    %% In the window the pool matches tip 110 (as after invalidateblock).
    ?assertEqual(lists:sort(['A', 'P', 'C', 'M', 'M3']), pool()),
    ok = beamchain_chainstate:connect_block(B111),
    %% X confirmed: its conflict A and A's child M are gone at once.
    ?assertEqual(lists:sort(['P', 'C', 'M3']), pool()),
    ok = beamchain_chainstate:connect_block(B112),
    ok = beamchain_chainstate:connect_block(B113),
    ?assertEqual({ok, 113}, beamchain_chainstate:get_tip_height()),
    %% Same end state as Core's single activation step.
    ?assertEqual(lists:sort(['C', 'LT', 'IMM']), pool()).

control_no_conflict() ->
    %% A branch with no txs: every disconnected tx comes back (LT, IMM
    %% included: final and mature at 114) and M, M3 stay.
    [B111, B112, B113] = side_blocks(#{111 => [], 112 => [], 113 => []}),
    {ok, side_branch} = beamchain_chainstate:submit_block(B111, true),
    {ok, side_branch} = beamchain_chainstate:submit_block(B112, true),
    {ok, reorg} = beamchain_chainstate:submit_block(B113, true),
    ?assertEqual(lists:sort(['A', 'P', 'C', 'LT', 'IMM', 'M', 'M3']), pool()).

%%% ===================================================================
%%% Fixture + helpers (same regtest chain as beamchain_mempool_bip68_tests,
%%% coinbases pay P2SH(OP_TRUE) so every spend is standard and witness-free)
%%% ===================================================================

chain_setup() ->
    TmpDir = filename:join(["/tmp", "beamchain_mpreorg_" ++
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
    mine_block(TipHash, H, [coinbase(H, <<"mr">>) | Txs], ts(H)).

build_chain(ToHeight) ->
    {ok, {_, TipH}} = beamchain_chainstate:get_tip(),
    lists:foreach(fun(_) ->
        ok = beamchain_chainstate:connect_block(next_block([]))
    end, lists:seq(TipH + 1, ToHeight)).

cb_txid(Height) ->
    {ok, #{hash := Hash}} = beamchain_db:get_block_index(Height),
    {ok, #block{transactions = [Cb | _]}} = beamchain_db:get_block(Hash),
    beamchain_serialize:tx_hash(Cb).

%% Spend Txid:Vout (a P2SH(OP_TRUE) coin worth Amount) into one P2SH(OP_TRUE)
%% output, paying ?FEE (+ Salt sat, to make a distinct conflicting tx).
spend(Txid, Vout, Amount, Seq, LockTime, Salt) ->
    #transaction{
        version = 2,
        inputs = [#tx_in{prev_out = #outpoint{hash = Txid, index = Vout},
                         script_sig = <<1, 16#51>>, sequence = Seq,
                         witness = []}],
        outputs = [#tx_out{value = Amount - ?FEE - Salt,
                           script_pubkey = p2sh_true()}],
        locktime = LockTime}.
