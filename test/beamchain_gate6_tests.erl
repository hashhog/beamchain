-module(beamchain_gate6_tests).

%%% Gate 6 (docs/RELEASE-CHECKLIST.md): a system fault -- OOM, I/O error,
%%% dead worker, timeout -- leads to retry or halt, NEVER to a reject or an
%%% accept. Core: a CScriptCheck reports only ScriptErrors; FatalError /
%%% AbortNode for a failed block/undo/coins write or flush (validation.cpp,
%%% node/abort.cpp); MaybePunishNodeForBlock only on a BlockValidationResult;
%%% submitblock answers RPC_VERIFY_ERROR for a non-validation failure.
%%%
%%% Faults are injected with beamchain_fault hooks (inert in production) at
%%% the real call sites, and the tests drive the REAL code: verify_script,
%%% the CCheckQueue pool, beamchain_chainstate's connect/flush/reorg over a
%%% real beamchain_db on regtest blocks, the mempool's ATMP, block_sync's
%%% unsolicited-penalty classifier and the submitblock RPC.
%%%
%%% Every test is meant to FAIL on the deployed code (19878f4 + the hooks
%%% commit) and PASS on the fix, except the CONTROL tests, which pass on
%%% both: genuinely invalid scripts/blocks keep their verdicts, valid ones
%%% keep being accepted.
%%%
%%%   rebar3 eunit --module=beamchain_gate6_tests

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-define(PRIV, <<7:256>>).
-define(OP_TRUE, <<16#51>>).
-define(BLOCK_FLAGS, (?SCRIPT_VERIFY_P2SH bor ?SCRIPT_VERIFY_WITNESS bor
                      ?SCRIPT_VERIFY_DERSIG bor ?SCRIPT_VERIFY_NULLDUMMY bor
                      ?SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY bor
                      ?SCRIPT_VERIFY_CHECKSEQUENCEVERIFY bor
                      ?SCRIPT_VERIFY_TAPROOT)).

%%% ===================================================================
%%% A. Script layer: three outcomes (OK / SCRIPT_ERROR / INTERNAL)
%%% ===================================================================

script_layer_test_() ->
    {foreach, fun pure_setup/0, fun pure_teardown/1,
     [fun(_) -> T end || T <-
         [{"FAULT: an exception inside verify_script is INTERNAL, not false",
           fun interp_exception_is_internal/0},
          {"FAULT: <sig> <pk> CHECKSIG NOT under an ECDSA NIF fault is not an ACCEPT",
           fun checksig_not_nif_raise_not_accept/0},
          {"FAULT: an unexpected ECDSA NIF error tuple is not an ACCEPT",
           fun checksig_not_nif_error_tuple_not_accept/0},
          {"FAULT: a Schnorr NIF fault raises instead of 'does not verify'",
           fun schnorr_nif_fault_raises/0},
          {"FAULT: P2WPKH under an ECDSA NIF fault is not a reject verdict",
           fun p2wpkh_nif_fault_not_reject/0},
          {"CONTROL: valid P2WPKH verifies",
           fun control_valid_p2wpkh/0},
          {"CONTROL: wrong signature is false (a verdict)",
           fun control_bad_sig_false/0},
          {"CONTROL: CHECKSIG NOT with a valid sig fails (false)",
           fun control_checksig_not_valid_sig_false/0},
          {"CONTROL: CHECKSIG NOT with a wrong sig passes (true)",
           fun control_checksig_not_bad_sig_true/0},
          {"CONTROL: an off-curve pubkey does not verify (false)",
           fun control_invalid_pubkey_false/0},
          {"CONTROL: malformed script bytes are a script error (false)",
           fun control_malformed_script_false/0}]]}.

%%% ===================================================================
%%% B. CCheckQueue: INTERNAL is re-run once, then the node latches
%%% ===================================================================

check_queue_test_() ->
    {foreach, fun pure_setup/0, fun pure_teardown/1,
     [fun(_) -> T end || T <-
         [{"FAULT: persistent INTERNAL check -> latch + error, never a verdict",
           fun queue_persistent_internal_latches/0},
          {"FAULT: transient INTERNAL check -> re-run passes, block accepted",
           fun queue_transient_internal_reruns/0},
          {"CONTROL: a genuinely failing check still rejects (verdict)",
           fun queue_real_failure_still_rejects/0}]]}.

%%% ===================================================================
%%% C. Chainstate over a real db: write-before-forget + AbortNode
%%% ===================================================================

chainstate_test_() ->
    {foreach, fun chain_setup/0, fun chain_teardown/1,
     [fun(_) -> {timeout, 120, {"FAULT: persistent undo-write failure -> no connect, latch",
                                fun undo_write_persistent/0}} end,
      fun(_) -> {timeout, 120, {"FAULT: transient undo-write failure -> retried, undo on disk",
                                fun undo_write_transient/0}} end,
      fun(_) -> {timeout, 120, {"FAULT: persistent block-write failure -> latch, next connect refused",
                                fun block_write_persistent/0}} end,
      fun(_) -> {timeout, 120, {"FAULT: transient block-write failure -> retried, connected",
                                fun block_write_transient/0}} end,
      fun(_) -> {timeout, 120, {"FAULT: persistent flush failure -> latch, tip frozen, dirty kept",
                                fun flush_persistent/0}} end,
      fun(_) -> {timeout, 120, {"FAULT: transient flush failure -> retried, flushed",
                                fun flush_transient/0}} end,
      fun(_) -> {timeout, 120, {"FAULT: shutdown after the latch does not flush",
                                fun shutdown_skips_flush_after_abort/0}} end,
      fun(_) -> {timeout, 120, {"FAULT: failed pre-reorg flush -> reorg not started, coins kept",
                                fun reorg_preflush_failure/0}} end,
      fun(_) -> {timeout, 120, {"FAULT: script INTERNAL during a real connect -> non-verdict + latch",
                                fun connect_script_internal/0}} end,
      fun(_) -> {timeout, 120, {"CONTROL: a block spending a missing coin is still a verdict",
                                fun control_connect_missing_inputs_verdict/0}} end,
      fun(_) -> {timeout, 120, {"CONTROL: a valid spend connects (no fault)",
                                fun control_connect_valid_spend/0}} end]}.

%%% ===================================================================
%%% D. Mempool: refuse a fault, never remember it as a reject, never crash
%%% ===================================================================

mempool_test_() ->
    {foreach, fun mempool_setup/0, fun mempool_teardown/1,
     [fun(_) -> {timeout, 120, {"FAULT: script INTERNAL in ATMP -> system_fault, not a reject",
                                fun mempool_script_internal/0}} end,
      fun(_) -> {timeout, 120, {"FAULT: chainstate busy (suspended) -> mempool survives, answers",
                                fun mempool_survives_busy_chainstate/0}} end,
      fun(_) -> {timeout, 120, {"FAULT: busy chainstate + no current MTP -> time-locked tx refused, mempool alive",
                                fun mempool_busy_chainstate_unknown_mtp/0}} end,
      fun(_) -> {timeout, 120, {"FAULT: latched node -> mempool refuses",
                                fun mempool_refuses_after_abort/0}} end,
      fun(_) -> {timeout, 120, {"CONTROL: valid spend accepted",
                                fun mempool_control_accept/0}} end,
      fun(_) -> {timeout, 120, {"CONTROL: bad signature rejected as a script failure",
                                fun mempool_control_bad_sig/0}} end]}.

%%% ===================================================================
%%% E. Punishment + submitblock classifiers
%%% ===================================================================

unsolicited_penalty_test_() ->
    P = fun beamchain_block_sync:unsolicited_connect_penalty/1,
    Faults = [{exit_during_connect, {timeout, {gen_server, call, [x]}}},
              {internal_error, badarg},
              {internal_error, {script_internal, {error, badarg}}},
              {post_validation_failure, {badmatch, {error, "IO error"}}},
              {node_aborted, {flush_failed, 1, x}},
              {script_check_worker_crash, oops},
              some_future_token],
    Verdicts = [bad_cb_amount, missing_inputs, {script_verify_failed, 3},
                {check_block_failed, bad_blk_length}],
    Mutated = [bad_merkle_root, {block_mutated, x}],
    [{lists:flatten(io_lib:format("FAULT: ~0p scores 0", [F])),
      ?_assertEqual(0, P(F))} || F <- Faults] ++
    [{lists:flatten(io_lib:format("CONTROL: ~0p scores 100", [V])),
      ?_assertEqual(100, P(V))} || V <- Verdicts ++ Mutated] ++
    [{"CONTROL: bad_prevblk scores 0", ?_assertEqual(0, P(bad_prevblk))}].

submitblock_test_() ->
    {setup,
     fun() ->
         persistent_term:erase({beamchain_rpc, block_submission_paused}),
         catch beamchain_fatal:reset_for_test(),
         application:set_env(beamchain, fatal_halt, false),
         {module, beamchain_miner} = code:ensure_loaded(beamchain_miner),
         ok = meck:new(beamchain_miner, [no_link, passthrough])
     end,
     fun(_) -> catch meck:unload(beamchain_miner),
               catch beamchain_fatal:reset_for_test() end,
     fun(_) ->
         [{"FAULT: {internal_error,_} -> -25, not a BIP-22 token",
           fun() -> submit_expect({error, {internal_error, badarg}}, fault) end},
          {"FAULT: {exit_during_connect,_} -> -25",
           fun() -> submit_expect({error, {exit_during_connect, timeout}}, fault) end},
          {"FAULT: {post_validation_failure,_} -> -25",
           fun() -> submit_expect({error, {post_validation_failure, enospc}}, fault) end},
          {"FAULT: miner call exit (timeout) -> -25, RPC does not crash",
           fun() -> submit_expect(raise_exit, fault) end},
          {"FAULT: latched node -> -25 without submitting",
           fun submit_latched/0},
          {"CONTROL: bad_cb_amount -> BIP-22 'bad-cb-amount'",
           fun() -> submit_expect({error, bad_cb_amount},
                                  {ok, <<"bad-cb-amount">>}) end},
          {"CONTROL: script failure -> BIP-22 token",
           fun() -> submit_expect({error, {script_verify_failed, 0}},
                                  {ok, <<"block-script-verify-flag-failed">>}) end},
          {"CONTROL: accepted -> null",
           fun() -> submit_expect(ok, {ok, null}) end}]
     end}.

%%% ===================================================================
%%% Fixtures
%%% ===================================================================

pure_setup() ->
    application:set_env(beamchain, fatal_halt, false),
    catch beamchain_fatal:reset_for_test(),
    catch beamchain_fault:clear_all(),
    case whereis(beamchain_sig_cache) of
        undefined -> {ok, P} = beamchain_sig_cache:start_link(), unlink(P);
        _ -> ok
    end,
    clear_sig_cache(),
    ok.

%% A cached successful verify would skip the NIF the fault hooks sit on.
clear_sig_cache() ->
    %% insert/4 is an async cast: drain the cache server first.
    catch sys:get_state(beamchain_sig_cache),
    lists:foreach(fun(T) -> catch ets:delete_all_objects(T) end,
                  [beamchain_sig_cache_tab, beamchain_sig_cache_order]).

pure_teardown(_) ->
    catch beamchain_fault:clear_all(),
    catch beamchain_fatal:reset_for_test(),
    ok.

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

mempool_setup() ->
    TmpDir = chain_setup(),
    %% 101 blocks so block 1's coinbase is mature for the next block;
    %% recent timestamps so the node leaves IBD.
    build_chain(101),
    catch gen_server:stop(beamchain_mempool),
    {ok, MP} = beamchain_mempool:start_link(),
    unlink(MP),
    TmpDir.

mempool_teardown(TmpDir) ->
    catch sys:resume(beamchain_chainstate),
    chain_teardown(TmpDir).

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

%%% ===================================================================
%%% A. tests
%%% ===================================================================

interp_exception_is_internal() ->
    {SSig, SPK, Wit, Checker} = p2wpkh_spend(),
    ?assertEqual(true, verify(SSig, SPK, Wit, Checker)),
    hook(verify_script, fun(_) -> error(badarg) end),
    ?assertMatch({internal, _}, verify_outcome(SSig, SPK, Wit, Checker)).

checksig_not_nif_raise_not_accept() ->
    {SSig, SPK, Wit, Checker} = p2wsh_checksig_not_spend(valid),
    %% No fault: the valid signature makes CHECKSIG true, NOT false.
    ?assertEqual(false, verify(SSig, SPK, Wit, Checker)),
    hook(ecdsa_verify_nif, fun(_) -> error(nif_not_loaded) end),
    %% Deployed: the fault read as "does not verify" -> NOT -> ACCEPT.
    ?assertMatch({internal, _}, verify_outcome(SSig, SPK, Wit, Checker)).

checksig_not_nif_error_tuple_not_accept() ->
    {SSig, SPK, Wit, Checker} = p2wsh_checksig_not_spend(valid),
    hook(ecdsa_verify_nif, fun(_) -> {error, secp256k1_context_lost} end),
    ?assertMatch({internal, _}, verify_outcome(SSig, SPK, Wit, Checker)).

schnorr_nif_fault_raises() ->
    Msg = crypto:hash(sha256, <<"gate6">>),
    {ok, Sig} = beamchain_crypto:schnorr_sign(Msg, ?PRIV, <<0:256>>),
    {ok, Pub33} = beamchain_crypto:pubkey_from_privkey(?PRIV),
    <<_:8, XOnly:32/binary>> = Pub33,
    ?assertEqual(true, beamchain_crypto:schnorr_verify(Msg, Sig, XOnly)),
    hook(schnorr_verify_nif, fun(_) -> error(nif_not_loaded) end),
    R = try beamchain_crypto:schnorr_verify(Msg, Sig, XOnly)
        catch error:_ -> raised
        end,
    ?assertEqual(raised, R).

p2wpkh_nif_fault_not_reject() ->
    {SSig, SPK, Wit, Checker} = p2wpkh_spend(),
    hook(ecdsa_verify_nif, fun(_) -> error(nif_not_loaded) end),
    ?assertMatch({internal, _}, verify_outcome(SSig, SPK, Wit, Checker)).

control_valid_p2wpkh() ->
    {SSig, SPK, Wit, Checker} = p2wpkh_spend(),
    ?assertEqual(true, verify(SSig, SPK, Wit, Checker)).

control_bad_sig_false() ->
    {SSig, SPK, [Sig, Pub], Checker} = p2wpkh_spend(),
    ?assertEqual(false, verify(SSig, SPK, [flip_sig(Sig), Pub], Checker)).

control_checksig_not_valid_sig_false() ->
    {SSig, SPK, Wit, Checker} = p2wsh_checksig_not_spend(valid),
    ?assertEqual(false, verify(SSig, SPK, Wit, Checker)).

control_checksig_not_bad_sig_true() ->
    {SSig, SPK, Wit, Checker} = p2wsh_checksig_not_spend(bad),
    ?assertEqual(true, verify(SSig, SPK, Wit, Checker)).

control_invalid_pubkey_false() ->
    %% x = 5 has no curve point (Core: CPubKey parse fails -> false).
    BadPub = <<2, 5:256>>,
    WS = <<33, BadPub/binary, 16#ac>>,
    SPK = <<0, 32, (crypto:hash(sha256, WS))/binary>>,
    {Tx, _} = spend_tx(SPK, 100000),
    Sig = <<16#30, 6, 2, 1, 1, 2, 1, 1, ?SIGHASH_ALL>>,
    ?assertEqual(false, verify(<<>>, SPK, [Sig, WS],
                               {Tx, 0, 100000, [{100000, SPK}]})).

control_malformed_script_false() ->
    {Tx, _} = spend_tx(?OP_TRUE, 1000),
    Checker = {Tx, 0, 1000, [{1000, <<16#4c, 200, 1, 2>>}]},
    %% scriptPubKey: OP_PUSHDATA1 200 with 2 bytes of data -- truncated.
    ?assertEqual(false, verify(<<>>, <<16#4c, 200, 1, 2>>, [], Checker)),
    %% scriptSig with a truncated direct push.
    ?assertEqual(false, verify(<<16#05, 1, 2>>, ?OP_TRUE, [], Checker)).

%%% ===================================================================
%%% B. tests
%%% ===================================================================

queue_persistent_internal_latches() ->
    Bad = <<16#51, 16#51, 16#75>>,   %% OP_1 OP_1 OP_DROP: passes normally
    Jobs = [op_true_job(?OP_TRUE), op_true_job(Bad), op_true_job(?OP_TRUE)],
    ?assertEqual(ok, queue_outcome(Jobs, 2)),
    hook(verify_script, fun([_SSig, SPK]) when SPK =:= Bad -> error(badarg);
                           (_) -> passthrough end),
    ?assertMatch({error_raised, {script_internal, _}}, queue_outcome(Jobs, 2)),
    ?assert(aborted()).

queue_transient_internal_reruns() ->
    Bad = <<16#51, 16#51, 16#75>>,
    Jobs = [op_true_job(?OP_TRUE), op_true_job(Bad), op_true_job(?OP_TRUE)],
    Counter = counters:new(1, []),
    hook(verify_script, fun([_SSig, SPK]) when SPK =:= Bad ->
                                counters:add(Counter, 1, 1),
                                case counters:get(Counter, 1) of
                                    1 -> error(badarg);
                                    _ -> passthrough
                                end;
                           (_) -> passthrough end),
    ?assertEqual(ok, queue_outcome(Jobs, 2)),
    ?assertNot(aborted()).

queue_real_failure_still_rejects() ->
    Jobs = [op_true_job(?OP_TRUE), op_true_job(<<0>>), op_true_job(?OP_TRUE)],
    ?assertEqual({verdict, {script_verify_failed, 0}}, queue_outcome(Jobs, 2)),
    ?assertNot(aborted()).

%%% ===================================================================
%%% C. tests
%%% ===================================================================

undo_write_persistent() ->
    build_chain(3),
    {ok, {TipHash, 3}} = beamchain_chainstate:get_tip(),
    hook(direct_store_undo, fun(_) -> {error, "IO error: No space left on device"} end),
    Block = next_block([]),
    R = beamchain_chainstate:connect_block(Block),
    clear_hooks(),
    ?assertMatch({error, _}, R),
    {error, Reason} = R,
    ?assertNot(beamchain_block_sync:is_consensus_verdict(Reason)),
    ?assertEqual({ok, {TipHash, 3}}, beamchain_chainstate:get_tip()),
    ?assert(aborted()).

undo_write_transient() ->
    build_chain(3),
    hook(direct_store_undo, fail_first_n(1, {error, "IO error: transient"})),
    Block = next_block([]),
    ?assertEqual(ok, beamchain_chainstate:connect_block(Block)),
    clear_hooks(),
    Hash = beamchain_serialize:block_hash(Block#block.header),
    %% The undo record exists: BLOCK_HAVE_UNDO is not a lie.
    ?assertMatch({ok, _}, beamchain_db:get_undo(Hash)),
    ?assertNot(aborted()).

block_write_persistent() ->
    build_chain(3),
    {ok, {TipHash, 3}} = beamchain_chainstate:get_tip(),
    hook(direct_atomic_connect_writes, fun(_) -> {error, "IO error: No space left on device"} end),
    Block = next_block([]),
    R = beamchain_chainstate:connect_block(Block),
    clear_hooks(),
    ?assertMatch({error, _}, R),
    {error, Reason} = R,
    ?assertNot(beamchain_block_sync:is_consensus_verdict(Reason)),
    ?assertEqual({ok, {TipHash, 3}}, beamchain_chainstate:get_tip()),
    %% Latched: even with the disk healthy again nothing connects.
    ?assertMatch({error, _}, beamchain_chainstate:connect_block(Block)),
    ?assertEqual({ok, {TipHash, 3}}, beamchain_chainstate:get_tip()).

block_write_transient() ->
    build_chain(3),
    hook(direct_atomic_connect_writes, fail_first_n(1, {error, "IO error: transient"})),
    Block = next_block([]),
    ?assertEqual(ok, beamchain_chainstate:connect_block(Block)),
    clear_hooks(),
    ?assertMatch({ok, {_, 4}}, beamchain_chainstate:get_tip()),
    ?assertNot(aborted()).

flush_persistent() ->
    build_chain(3),
    DirtyBefore = ets:info(beamchain_utxo_dirty, size),
    ?assert(DirtyBefore > 0),
    hook(direct_write_batch, fun(_) -> {error, "IO error: No space left on device"} end),
    _ = beamchain_chainstate:flush(),
    clear_hooks(),
    %% Write before forget: nothing was dropped from the dirty set.
    ?assertEqual(DirtyBefore, ets:info(beamchain_utxo_dirty, size)),
    %% AbortNode: the tip does not move any more.
    Block = next_block([]),
    ?assertMatch({error, _}, beamchain_chainstate:connect_block(Block)),
    ?assertMatch({ok, {_, 3}}, beamchain_chainstate:get_tip()).

flush_transient() ->
    build_chain(3),
    hook(direct_write_batch, fail_first_n(1, {error, "IO error: transient"})),
    _ = beamchain_chainstate:flush(),
    clear_hooks(),
    ?assertEqual(0, ets:info(beamchain_utxo_dirty, size)),
    ?assertNot(aborted()),
    ?assertEqual(ok, beamchain_chainstate:connect_block(next_block([]))).

shutdown_skips_flush_after_abort() ->
    build_chain(3),
    Calls = counters:new(1, []),
    hook(direct_write_batch, fun(_) ->
        counters:add(Calls, 1, 1),
        {error, "IO error: No space left on device"}
    end),
    _ = beamchain_chainstate:flush(),
    AfterFlush = counters:get(Calls, 1),
    ?assert(AfterFlush >= 1),
    %% The disk "recovers"; the node must still not write its view.
    hook(direct_write_batch, fun(_) -> counters:add(Calls, 1, 1), passthrough end),
    ok = gen_server:stop(beamchain_chainstate),
    ?assertEqual(AfterFlush, counters:get(Calls, 1)).

reorg_preflush_failure() ->
    %% Active A1..A3; competitor B2'..B4' on A1 (more work).
    build_chain(3),
    {ok, {A3, 3}} = beamchain_chainstate:get_tip(),
    {ok, #{hash := A1}} = beamchain_db:get_block_index(1),
    B2 = mine_block(A1, 2, [coinbase(2, <<"fork">>)], ts(2) + 1),
    B2H = beamchain_serialize:block_hash(B2#block.header),
    B3 = mine_block(B2H, 3, [coinbase(3, <<"fork">>)], ts(3) + 1),
    B3H = beamchain_serialize:block_hash(B3#block.header),
    B4 = mine_block(B3H, 4, [coinbase(4, <<"fork">>)], ts(4) + 1),
    %% A3's coinbase coin only lives in the unflushed cache.
    A3Cb = coinbase_txid_at(3),
    ?assertMatch({ok, _}, beamchain_chainstate:get_utxo(A3Cb, 0)),
    hook(direct_write_batch, fun(_) -> {error, "IO error: No space left on device"} end),
    R = beamchain_chainstate:reorganize([B2, B3, B4]),
    clear_hooks(),
    ?assertMatch({error, _}, R),
    ?assertEqual({ok, {A3, 3}}, beamchain_chainstate:get_tip()),
    %% The unflushed coin was not wiped by a "rollback" that assumed the
    %% pre-flush had landed.
    ?assertMatch({ok, _}, beamchain_chainstate:get_utxo(A3Cb, 0)).

connect_script_internal() ->
    build_chain(101),
    {ok, {TipHash, 101}} = beamchain_chainstate:get_tip(),
    Spend = spend_coinbase_op_true(1),
    Block = next_block([Spend]),
    hook(verify_script, fun([_, SPK]) when SPK =:= ?OP_TRUE -> error(badarg);
                           (_) -> passthrough end),
    R = beamchain_chainstate:connect_block(Block),
    clear_hooks(),
    ?assertMatch({error, _}, R),
    {error, Reason} = R,
    ?assertNot(beamchain_block_sync:is_consensus_verdict(Reason)),
    ?assertEqual({ok, {TipHash, 101}}, beamchain_chainstate:get_tip()),
    ?assert(aborted()),
    %% Not marked invalid.
    Hash = beamchain_serialize:block_hash(Block#block.header),
    ?assertNot(beamchain_chainstate:is_known_invalid(Hash)).

control_connect_missing_inputs_verdict() ->
    build_chain(3),
    Ghost = #transaction{
        version = 1,
        inputs = [#tx_in{prev_out = #outpoint{hash = <<9:256>>, index = 0},
                         script_sig = <<>>, sequence = 16#ffffffff,
                         witness = []}],
        outputs = [#tx_out{value = 1000, script_pubkey = ?OP_TRUE}],
        locktime = 0},
    R = beamchain_chainstate:connect_block(next_block([Ghost])),
    ?assertEqual({error, missing_inputs}, R),
    ?assert(beamchain_block_sync:is_consensus_verdict(missing_inputs)),
    ?assertNot(aborted()).

control_connect_valid_spend() ->
    build_chain(101),
    Spend = spend_coinbase_op_true(1),
    ?assertEqual(ok, beamchain_chainstate:connect_block(next_block([Spend]))),
    ?assertMatch({ok, {_, 102}}, beamchain_chainstate:get_tip()),
    ?assertNot(aborted()).

%%% ===================================================================
%%% D. tests
%%% ===================================================================

mempool_script_internal() ->
    Tx = mempool_spend(2, valid),
    hook(verify_script, fun(_) -> error(badarg) end),
    R = beamchain_mempool:add_transaction(Tx),
    clear_hooks(),
    ?assertMatch({error, {system_fault, _}}, R),
    ?assert(is_process_alive(whereis(beamchain_mempool))),
    %% Nothing remembered: the same tx is accepted once the fault is gone.
    ?assertMatch({ok, _}, beamchain_mempool:add_transaction(Tx)).

mempool_survives_busy_chainstate() ->
    Tx = mempool_spend(2, valid),
    MP = whereis(beamchain_mempool),
    ok = sys:suspend(beamchain_chainstate),
    R = (catch beamchain_mempool:add_transaction(Tx)),
    ok = sys:resume(beamchain_chainstate),
    ?assertEqual(MP, whereis(beamchain_mempool)),
    ?assert(is_process_alive(MP)),
    ?assertMatch({ok, _}, R).

mempool_busy_chainstate_unknown_mtp() ->
    %% A time-locked tx (nLockTime = a recent timestamp) needs the MTP. The
    %% published MTP is gone (as at boot / mid-publication) and chainstate
    %% is busy: the mempool must neither crash nor admit the tx.
    Tx0 = mempool_spend(2, valid),
    Tx = Tx0#transaction{locktime = erlang:system_time(second) - 100000},
    Txs = resign(Tx),
    MP = whereis(beamchain_mempool),
    catch ets:delete(beamchain_chain_meta, mtp),
    ok = sys:suspend(beamchain_chainstate),
    R = (catch beamchain_mempool:add_transaction(Txs)),
    ok = sys:resume(beamchain_chainstate),
    ?assertEqual(MP, whereis(beamchain_mempool)),
    ?assert(is_process_alive(MP)),
    ?assertMatch({error, {system_fault, _}}, R),
    ?assertNot(beamchain_mempool:has_tx(beamchain_serialize:tx_hash(Txs))),
    %% Chainstate answers again: the same tx is admitted (nothing remembered).
    ?assertMatch({ok, _}, beamchain_mempool:add_transaction(Txs)).

mempool_refuses_after_abort() ->
    Tx = mempool_spend(2, valid),
    ok = beamchain_fatal:abort_node(test_fault),
    ?assertMatch({error, {node_aborted, _}}, beamchain_mempool:add_transaction(Tx)),
    ?assertNot(beamchain_mempool:has_tx(beamchain_serialize:tx_hash(Tx))).

mempool_control_accept() ->
    Tx = mempool_spend(2, valid),
    ?assertMatch({ok, _}, beamchain_mempool:add_transaction(Tx)).

mempool_control_bad_sig() ->
    Tx = mempool_spend(2, bad),
    ?assertEqual({error, {script_verify_failed, 0}},
                 beamchain_mempool:add_transaction(Tx)).

%%% ===================================================================
%%% E. submitblock helpers
%%% ===================================================================

submit_expect(MinerResult, Expect) ->
    catch beamchain_fatal:reset_for_test(),
    case MinerResult of
        raise_exit ->
            meck:expect(beamchain_miner, submit_block,
                        fun(_) -> exit({timeout, {gen_server, call, [x]}}) end);
        _ ->
            meck:expect(beamchain_miner, submit_block, fun(_) -> MinerResult end)
    end,
    R = (catch beamchain_rpc:handle_method(<<"submitblock">>, [<<"00">>], undefined)),
    case Expect of
        fault -> ?assertMatch({error, -25, _}, R);
        _ -> ?assertEqual(Expect, R)
    end.

submit_latched() ->
    catch beamchain_fatal:reset_for_test(),
    Calls = counters:new(1, []),
    meck:expect(beamchain_miner, submit_block,
                fun(_) -> counters:add(Calls, 1, 1), {error, bad_cb_amount} end),
    _ = (catch beamchain_fatal:abort_node(test_fault)),
    R = (catch beamchain_rpc:handle_method(<<"submitblock">>, [<<"00">>], undefined)),
    catch beamchain_fatal:reset_for_test(),
    ?assertMatch({error, -25, _}, R),
    ?assertEqual(0, counters:get(Calls, 1)).

%%% ===================================================================
%%% Helpers: verification outcomes
%%% ===================================================================

verify(SSig, SPK, Wit, Checker) ->
    beamchain_script:verify_script(SSig, SPK, Wit, ?BLOCK_FLAGS, Checker).

%% true | false | {internal, Reason} (raised)
verify_outcome(SSig, SPK, Wit, Checker) ->
    try verify(SSig, SPK, Wit, Checker)
    catch error:R -> {internal, R}
    end.

%% ok | {verdict, Reason} (throw) | {error_raised, Reason}
queue_outcome(Jobs, N) ->
    try beamchain_script_check_queue:verify(Jobs, ?BLOCK_FLAGS, N)
    catch
        throw:R -> {verdict, R};
        error:R -> {error_raised, R}
    end.

aborted() ->
    try beamchain_fatal:is_aborted()
    catch error:undef -> false
    end.

hook(Point, Fun) ->
    clear_sig_cache(),
    beamchain_fault:set(Point, Fun).

clear_hooks() ->
    beamchain_fault:clear_all().

fail_first_n(N, Err) ->
    C = counters:new(1, []),
    fun(_) ->
        counters:add(C, 1, 1),
        case counters:get(C, 1) =< N of
            true -> Err;
            false -> passthrough
        end
    end.

%%% ===================================================================
%%% Helpers: scripts
%%% ===================================================================

pub() ->
    {ok, Pub} = beamchain_crypto:pubkey_from_privkey(?PRIV),
    Pub.

p2wpkh_spk() ->
    <<16#00, 20, (beamchain_crypto:hash160(pub()))/binary>>.

spend_tx(SPK, Amount) ->
    In = #tx_in{prev_out = #outpoint{hash = <<1:256>>, index = 0},
                script_sig = <<>>, sequence = 16#ffffffff, witness = []},
    Tx = #transaction{version = 2, inputs = [In],
                      outputs = [#tx_out{value = Amount - 1000,
                                         script_pubkey = SPK}],
                      locktime = 0},
    {Tx, In}.

p2wpkh_spend() ->
    Pub = pub(),
    SPK = p2wpkh_spk(),
    Amount = 100000,
    {Tx0, In} = spend_tx(SPK, Amount),
    ScriptCode = <<16#76, 16#a9, 20, (beamchain_crypto:hash160(Pub))/binary,
                   16#88, 16#ac>>,
    SigHash = beamchain_script:sighash_witness_v0(Tx0, 0, ScriptCode, Amount,
                                                  ?SIGHASH_ALL),
    {ok, Der} = beamchain_crypto:ecdsa_sign(SigHash, ?PRIV),
    Sig = <<Der/binary, ?SIGHASH_ALL>>,
    Wit = [Sig, Pub],
    Tx = Tx0#transaction{inputs = [In#tx_in{witness = Wit}]},
    {<<>>, SPK, Wit, {Tx, 0, Amount, [{Amount, SPK}]}}.

%% P2WSH witnessScript = <pk> OP_CHECKSIG OP_NOT.
p2wsh_checksig_not_spend(Kind) ->
    Pub = pub(),
    WS = <<33, Pub/binary, 16#ac, 16#91>>,
    SPK = <<0, 32, (crypto:hash(sha256, WS))/binary>>,
    Amount = 100000,
    {Tx0, In} = spend_tx(SPK, Amount),
    SigHash = beamchain_script:sighash_witness_v0(Tx0, 0, WS, Amount,
                                                  ?SIGHASH_ALL),
    {ok, Der} = beamchain_crypto:ecdsa_sign(SigHash, ?PRIV),
    Sig0 = <<Der/binary, ?SIGHASH_ALL>>,
    Sig = case Kind of
              valid -> Sig0;
              bad -> flip_sig(Sig0)
          end,
    Wit = [Sig, WS],
    Tx = Tx0#transaction{inputs = [In#tx_in{witness = Wit}]},
    {<<>>, SPK, Wit, {Tx, 0, Amount, [{Amount, SPK}]}}.

%% Flip the last byte of R (stays strict DER, low-S untouched).
flip_sig(<<16#30, L, 16#02, RL, Rest/binary>>) ->
    <<R:RL/binary, Tail/binary>> = Rest,
    RHead = binary:part(R, 0, RL - 1),
    <<Last>> = binary:part(R, RL - 1, 1),
    <<16#30, L, 16#02, RL, RHead/binary, (Last bxor 1), Tail/binary>>.

op_true_job(SPK) ->
    In = #tx_in{prev_out = #outpoint{hash = <<0:256>>, index = 0},
                script_sig = <<>>, sequence = 16#ffffffff, witness = []},
    Tx = #transaction{version = 1, inputs = [In],
                      outputs = [#tx_out{value = 1000, script_pubkey = ?OP_TRUE}],
                      locktime = 0},
    {Tx, [#utxo{value = 2000, script_pubkey = SPK, is_coinbase = false,
                height = 1}]}.

%%% ===================================================================
%%% Helpers: regtest chain
%%% ===================================================================

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

%% Spend output 0 (OP_TRUE) of the coinbase at Height: no witness, so the
%% block needs no witness commitment.
spend_coinbase_op_true(Height) ->
    Txid = coinbase_txid_at(Height),
    #transaction{
        version = 1,
        inputs = [#tx_in{prev_out = #outpoint{hash = Txid, index = 0},
                         script_sig = <<>>, sequence = 16#ffffffff,
                         witness = []}],
        outputs = [#tx_out{value = 2400000000, script_pubkey = ?OP_TRUE}],
        locktime = 0}.

%% Re-sign a mempool_spend/2 tx after its fields changed.
resign(#transaction{inputs = [In]} = Tx0) ->
    Amount = 2500000000,
    Pub = pub(),
    Tx1 = Tx0#transaction{inputs = [In#tx_in{witness = []}]},
    ScriptCode = <<16#76, 16#a9, 20, (beamchain_crypto:hash160(Pub))/binary,
                   16#88, 16#ac>>,
    SigHash = beamchain_script:sighash_witness_v0(Tx1, 0, ScriptCode, Amount,
                                                  ?SIGHASH_ALL),
    {ok, Der} = beamchain_crypto:ecdsa_sign(SigHash, ?PRIV),
    Tx1#transaction{inputs = [In#tx_in{witness = [<<Der/binary, ?SIGHASH_ALL>>, Pub]}]}.

%% Spend output 1 (P2WPKH) of the coinbase at Height, signed.
mempool_spend(Height, Kind) ->
    Txid = coinbase_txid_at(Height),
    Amount = 2500000000,
    Pub = pub(),
    In = #tx_in{prev_out = #outpoint{hash = Txid, index = 1},
                script_sig = <<>>, sequence = 16#fffffffd, witness = []},
    Tx0 = #transaction{version = 2, inputs = [In],
                       outputs = [#tx_out{value = Amount - 20000,
                                          script_pubkey = p2wpkh_spk()}],
                       locktime = 0},
    ScriptCode = <<16#76, 16#a9, 20, (beamchain_crypto:hash160(Pub))/binary,
                   16#88, 16#ac>>,
    SigHash = beamchain_script:sighash_witness_v0(Tx0, 0, ScriptCode, Amount,
                                                  ?SIGHASH_ALL),
    {ok, Der} = beamchain_crypto:ecdsa_sign(SigHash, ?PRIV),
    Sig0 = <<Der/binary, ?SIGHASH_ALL>>,
    Sig = case Kind of valid -> Sig0; bad -> flip_sig(Sig0) end,
    Tx0#transaction{inputs = [In#tx_in{witness = [Sig, Pub]}]}.
