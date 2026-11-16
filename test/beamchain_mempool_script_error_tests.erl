-module(beamchain_mempool_script_error_tests).

%%% Mempool script failures report Core's reject reason and details
%%% (refill-20261116-beamchain-policy, core-regtest group seed_submitpackage,
%%% rows invalid-sig-child / invalid-sig-parent).
%%%
%%% Core validation.cpp CheckInputScripts runs the scripts under the policy
%%% (STANDARD) flags in ATMP and, on failure, returns
%%%   state.Invalid(TX_NOT_STANDARD,
%%%       strprintf("mempool-script-verify-flag-failed (%s)",
%%%                 ScriptErrorString(error)), debug)
%%% with debug = CScriptCheck's
%%%   "input %i of %s (wtxid %s), spending %s:%i".
%%% testmempoolaccept reports GetRejectReason() as reject-reason and
%%% ToString() ("reason, debug") as reject-details; submitpackage's
%%% tx-results error and sendrawtransaction's message are ToString().
%%% beamchain dropped the script error and said
%%% "mandatory-script-verify-flag-failed (input N)" with no details.
%%%   rebar3 eunit --module=beamchain_mempool_script_error_tests

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-define(PRIV, <<7:256>>).
-define(OP_TRUE, <<16#51>>).
-define(CB_VALUE, 2500000000).
-define(RBF_SEQ, 16#fffffffd).

-define(NULLFAIL_REASON,
        <<"mempool-script-verify-flag-failed (Signature must be zero for "
          "failed CHECK(MULTI)SIG operation)">>).

script_error_test_() ->
    {foreach, fun setup/0, fun teardown/1,
     [fun(_) -> {timeout, 120, {"FIX: testmempoolaccept reason + details for a bad signature",
                                fun testmempoolaccept_single/0}} end,
      fun(_) -> {timeout, 120, {"FIX: sendrawtransaction message is Core's ToString()",
                                fun sendrawtransaction_message/0}} end,
      fun(_) -> {timeout, 120, {"FIX: package with a bad child signature (invalid-sig-child)",
                                fun package_bad_child/0}} end,
      fun(_) -> {timeout, 120, {"FIX: package with a bad parent signature (invalid-sig-parent)",
                                fun package_bad_parent/0}} end,
      fun(_) -> {timeout, 120, {"CONTROL: a well-signed spend is still accepted",
                                fun good_spend_accepted/0}} end]}.

%% No chain needed: the interpreter-level contract.
script_error_string_test_() ->
    [{"FIX: nullfail renders as Core's SCRIPT_ERR_SIG_NULLFAIL text",
      ?_assertEqual(<<"Signature must be zero for failed CHECK(MULTI)SIG operation">>,
                    beamchain_script:script_error_string(nullfail))},
     {"FIX: a false final stack is SCRIPT_ERR_EVAL_FALSE",
      ?_assertEqual(<<"Script evaluated without error but finished with a "
                      "false/empty top stack element">>,
                    beamchain_script:script_error_string(eval_false))},
     {"FIX: an unmapped token gets Core's fallback",
      ?_assertEqual(<<"unknown error">>,
                    beamchain_script:script_error_string(no_such_error))}].

verify_script_error_test_() ->
    %% <sig> <pk> CHECKSIG with a non-empty failing signature: NULLFAIL.
    NonEmptySig = <<16#30, 16#06, 16#02, 16#01, 16#01, 16#02, 16#01, 16#01, 16#01>>,
    FakePK = <<16#02, 0:256>>,
    SigChecker = #{check_ecdsa_sig => fun(_, _, _) -> false end,
                   compute_sighash => fun(_, _) -> <<0:256>> end},
    ScriptSig = <<(byte_size(NonEmptySig)), NonEmptySig/binary>>,
    Spk = <<(byte_size(FakePK)), FakePK/binary, 16#ac>>,
    [{"FIX: verify_script_error keeps the interpreter's error",
      ?_assertEqual({error, nullfail},
                    beamchain_script:verify_script_error(
                      ScriptSig, Spk, [], ?SCRIPT_VERIFY_NULLFAIL, SigChecker))},
     {"FIX: a false top stack is eval_false",
      ?_assertEqual({error, eval_false},
                    beamchain_script:verify_script_error(
                      ScriptSig, Spk, [], 0, SigChecker))},
     {"FIX: OP_1 verifies as ok",
      ?_assertEqual(ok, beamchain_script:verify_script_error(
                          <<>>, <<16#51>>, [], 0, SigChecker))},
     {"GUARD: verify_script/5 verdicts are unchanged",
      fun() ->
          ?assertNot(beamchain_script:verify_script(
                       ScriptSig, Spk, [], ?SCRIPT_VERIFY_NULLFAIL, SigChecker)),
          ?assertNot(beamchain_script:verify_script(
                       ScriptSig, Spk, [], 0, SigChecker)),
          ?assert(beamchain_script:verify_script(<<>>, <<16#51>>, [], 0,
                                                 SigChecker))
      end}].

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
wtxid(Tx) -> beamchain_serialize:wtx_hash(Tx).

in_pool(Tx) -> beamchain_mempool:has_tx(txid(Tx)).

%% Core's ToString() for a failing input 0 of Tx spending Prev:Vout.
details(Tx, Prev, Vout) ->
    iolist_to_binary(
      [?NULLFAIL_REASON, ", input 0 of ", display_hex(txid(Tx)),
       " (wtxid ", display_hex(wtxid(Tx)), "), spending ",
       display_hex(Prev), ":", integer_to_list(Vout)]).

%% Spend coinbase(2):1 with a signature over the wrong amount.
bad_spend() ->
    Cb = coinbase_txid_at(2),
    Bad = sign_outs(Cb, 1, ?CB_VALUE, [{?CB_VALUE - 10000, p2wpkh_spk()}],
                    ?CB_VALUE - 1),
    {Cb, Bad}.

%% Parent P spends coinbase(2):1; child C spends P:0.
pair(BadParent, BadChild) ->
    Cb = coinbase_txid_at(2),
    VP = ?CB_VALUE - 10000,
    P = sign_outs(Cb, 1, ?CB_VALUE, [{VP, p2wpkh_spk()}],
                  case BadParent of true -> ?CB_VALUE - 1; false -> ?CB_VALUE end),
    C = sign_outs(txid(P), 0, VP, [{VP - 10000, p2wpkh_spk()}],
                  case BadChild of true -> VP - 1; false -> VP end),
    {Cb, P, C}.

testmempoolaccept_single() ->
    {Cb, Bad} = bad_spend(),
    {ok, [Row]} = beamchain_rpc:handle_method(<<"testmempoolaccept">>,
                                              [[hex(Bad)]], undefined),
    ?assertEqual(false, maps:get(<<"allowed">>, Row)),
    ?assertEqual(?NULLFAIL_REASON, maps:get(<<"reject-reason">>, Row)),
    ?assertEqual(details(Bad, Cb, 1), maps:get(<<"reject-details">>, Row, missing)),
    ?assertNot(in_pool(Bad)).

sendrawtransaction_message() ->
    {Cb, Bad} = bad_spend(),
    ?assertEqual({error, -26, details(Bad, Cb, 1)},
                 beamchain_rpc:rpc_sendrawtransaction([hex(Bad)])),
    ?assertNot(in_pool(Bad)).

package_bad_child() ->
    {_Cb, P, C} = pair(false, true),
    {ok, Rows} = beamchain_rpc:handle_method(<<"testmempoolaccept">>,
                                             [[hex(P), hex(C)]], undefined),
    [_, CRow] = Rows,
    ?assertEqual(?NULLFAIL_REASON, maps:get(<<"reject-reason">>, CRow)),
    ?assertEqual(details(C, txid(P), 0),
                 maps:get(<<"reject-details">>, CRow, missing)),
    {ok, Res} = beamchain_rpc:rpc_submitpackage([[hex(P), hex(C)]]),
    CRes = maps:get(display_hex(wtxid(C)), maps:get(<<"tx-results">>, Res)),
    ?assertEqual(details(C, txid(P), 0), maps:get(<<"error">>, CRes, missing)),
    ?assertNot(in_pool(C)).

package_bad_parent() ->
    {Cb, P, C} = pair(true, false),
    {ok, Rows} = beamchain_rpc:handle_method(<<"testmempoolaccept">>,
                                             [[hex(P), hex(C)]], undefined),
    [PRow, _] = Rows,
    ?assertEqual(?NULLFAIL_REASON, maps:get(<<"reject-reason">>, PRow)),
    ?assertEqual(details(P, Cb, 1), maps:get(<<"reject-details">>, PRow, missing)),
    {ok, Res} = beamchain_rpc:rpc_submitpackage([[hex(P), hex(C)]]),
    PRes = maps:get(display_hex(wtxid(P)), maps:get(<<"tx-results">>, Res)),
    ?assertEqual(details(P, Cb, 1), maps:get(<<"error">>, PRes, missing)),
    ?assertNot(in_pool(P)),
    ?assertNot(in_pool(C)).

good_spend_accepted() ->
    {_Cb, P, C} = pair(false, false),
    {ok, Res} = beamchain_rpc:rpc_submitpackage([[hex(P), hex(C)]]),
    ?assertEqual(<<"success">>, maps:get(<<"package_msg">>, Res)),
    ?assert(in_pool(P)),
    ?assert(in_pool(C)).

hex(T) ->
    beamchain_serialize:hex_encode(beamchain_serialize:encode_transaction(T)).

display_hex(Hash) ->
    beamchain_serialize:hex_encode(beamchain_serialize:reverse_bytes(Hash)).

chain_setup() ->
    TmpDir = filename:join(["/tmp", "beamchain_scripterr_" ++
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
