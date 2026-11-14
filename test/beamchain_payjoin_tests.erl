-module(beamchain_payjoin_tests).

%% BIP-78 receiver safety (secfix-beamchain-payjoin-receiver-theft).
%%
%% The receiver used to hand the merged PSBT to walletprocesspsbt with
%% SIGHASH_ALL, which signs EVERY input the wallet owns, and it never
%% raised the receiver output by the value it contributed. A sender could
%% therefore list one of the receiver's own coins as an "original" input
%% and get it signed, and an honest payjoin gave the contributed coin away
%% as fee. These tests pin the safe behaviour:
%%
%%   receiver_output_credited_and_inputs_limited
%%       honest Original: receiver output grows by exactly the contributed
%%       value, the sender's input maps come back untouched, and only the
%%       contributed input carries a receiver signature.  An Original
%%       that smuggles a receiver-owned input is refused and that input
%%       is never signed.
%%   payjoin_token_gate_from_conf
%%       payjoin_require_token=1 in beamchain.conf (stored as the string
%%       "1" by the conf parser) turns the token gate on.
%%   payjoin_original_must_be_broadcastable
%%       an Original whose inputs are not finalized is rejected, and the
%%       broadcast check fails closed when no mempool is running.
%%   payjoin_fee_never_docked_from_a_receiver_output
%%       additionalfeeoutputindex pointing at a second receiver output
%%       takes nothing from it.
%%   payjoin_min_fee_rate_honoured
%%       a reachable minfeerate is met; one that would need more than the
%%       receiver's own input fee is refused instead of paid by the
%%       receiver.
%%   payjoin_declared_input_value_not_trusted
%%       the Original is priced from the mempool's measurement; a PSBT
%%       that overstates its input value is refused.
%%   rest_listener_binds_loopback_by_default
%%       the REST listener (which also serves /payjoin) binds 127.0.0.1
%%       unless rpcbind says otherwise, as Core's HTTP server does.

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").
-include("beamchain_psbt.hrl").

-define(CFG, beamchain_config_ets).

%%% ===================================================================
%%% Fixtures
%%% ===================================================================

start_seeded_wallet() ->
    case whereis(beamchain_wallet) of
        undefined -> ok;
        Old -> gen_server:stop(Old)
    end,
    {ok, Pid} = beamchain_wallet:start_link(),
    {ok, _} = gen_server:call(Pid, {create, crypto:strong_rand_bytes(32),
                                    undefined}),
    Pid.

stop_wallet() ->
    case whereis(beamchain_wallet) of
        undefined -> ok;
        Pid -> gen_server:stop(Pid)
    end.

wallet_script() ->
    {ok, Addr} = beamchain_wallet:get_new_address(p2wpkh),
    {ok, Script} = beamchain_address:address_to_script(Addr, mainnet),
    Script.

sender_script(N) ->
    <<16#00, 20, N:160>>.

utxo(Value, Script) ->
    #utxo{value = Value, script_pubkey = Script, is_coinbase = false,
          height = 1}.

fake_sig() -> <<48, 6, 2, 1, 1, 2, 1, 1, 1>>.
fake_pub() -> <<2, 0:256>>.

%% A sender input already finalized the way BIP-78 requires (the Original
%% must be broadcastable): witness_utxo + final_script_witness.
finalized_input(Psbt, Idx, Utxo) ->
    P1 = beamchain_wallet:add_witness_utxo(Psbt, Idx, Utxo),
    Maps = P1#psbt.inputs,
    M = lists:nth(Idx + 1, Maps),
    M1 = M#{final_script_witness => [fake_sig(), fake_pub()]},
    P1#psbt{inputs = replace_nth(Idx + 1, M1, Maps)}.

%% An input that only carries a (fake) partial signature — what an
%% attacker would send for a coin they want the receiver to sign.
partial_input(Psbt, Idx, Utxo) ->
    P1 = beamchain_wallet:add_witness_utxo(Psbt, Idx, Utxo),
    Maps = P1#psbt.inputs,
    M = lists:nth(Idx + 1, Maps),
    M1 = M#{partial_sigs => #{fake_pub() => fake_sig()}},
    P1#psbt{inputs = replace_nth(Idx + 1, M1, Maps)}.

replace_nth(1, X, [_ | T]) -> [X | T];
replace_nth(N, X, [H | T]) -> [H | replace_nth(N - 1, X, T)].

txin(Hash) ->
    #tx_in{prev_out = #outpoint{hash = <<Hash:256>>, index = 0},
           script_sig = <<>>, sequence = 16#fffffffd, witness = []}.

%% 1 sender input (150000) -> receiver 100000 + sender change 49000.
%% Original fee 1000 sat.
honest_original(RecvScript) ->
    Tx = #transaction{version = 2, inputs = [txin(2)],
                      outputs = [#tx_out{value = 100000,
                                         script_pubkey = RecvScript},
                                 #tx_out{value = 49000,
                                         script_pubkey = sender_script(9)}],
                      locktime = 0},
    {ok, P0} = beamchain_psbt:create(Tx),
    finalized_input(P0, 0, utxo(150000, sender_script(1))).

params(FeeIdx, MaxFee, MinRate) ->
    #{version => 1,
      additional_fee_output_index => FeeIdx,
      max_additional_fee_contribution => MaxFee,
      disable_output_substitution => false,
      min_fee_rate => MinRate}.

out_values(#psbt{unsigned_tx = Tx}) ->
    [V || #tx_out{value = V} <- Tx#transaction.outputs].

signed(Map) ->
    maps:is_key(partial_sigs, Map) orelse
        maps:is_key(final_script_witness, Map) orelse
        maps:is_key(final_script_sig, Map) orelse
        maps:is_key(tap_key_sig, Map).

%%% ===================================================================
%%% receiver_output_credited_and_inputs_limited
%%% ===================================================================

receiver_output_credited_and_inputs_limited_test_() ->
    {foreach,
     fun start_seeded_wallet/0,
     fun(_) -> stop_wallet() end,
     [{"honest Original: receiver output += contributed value, only the "
       "contributed input is signed",
       fun() ->
           RecvScript = wallet_script(),
           Contrib = 200000,
           ok = beamchain_wallet:add_wallet_utxo(<<7:256>>, 0, Contrib,
                                                 wallet_script(), 1),
           Orig = honest_original(RecvScript),
           {ok, PJ} = beamchain_payjoin_server:build_payjoin_psbt(
                        Orig, params(1, 1000, 0), whereis(beamchain_wallet)),
           [RecvOut, Change] = out_values(PJ),
           %% Sender pays the contributed input's fee out of output 1, so
           %% the receiver output grows by the full contributed value.
           ?assertEqual(100000 + Contrib, RecvOut),
           ?assert(Change < 49000),
           ?assert(Change >= 49000 - 1000),
           %% Sender's input map is byte-for-byte what the sender sent.
           [SenderMap, RecvMap] = PJ#psbt.inputs,
           ?assertEqual(hd(Orig#psbt.inputs), SenderMap),
           ?assert(signed(RecvMap)),
           %% Value is conserved: fee only grows by what output 1 lost.
           ?assertEqual(150000 + Contrib - (RecvOut + Change),
                        1000 + (49000 - Change))
       end},
      {"Original smuggling a receiver-owned input is refused and that "
       "input is never signed",
       fun() ->
           RecvScript = wallet_script(),
           Victim = wallet_script(),
           ok = beamchain_wallet:add_wallet_utxo(<<7:256>>, 0, 200000,
                                                 wallet_script(), 1),
           Tx = #transaction{version = 2, inputs = [txin(2), txin(3)],
                             outputs = [#tx_out{value = 100000,
                                                script_pubkey = RecvScript},
                                        #tx_out{value = 549000,
                                                script_pubkey =
                                                    sender_script(9)}],
                             locktime = 0},
           {ok, P0} = beamchain_psbt:create(Tx),
           P1 = finalized_input(P0, 0, utxo(150000, sender_script(1))),
           Orig = partial_input(P1, 1, utxo(500000, Victim)),
           R = beamchain_payjoin_server:build_payjoin_psbt(
                 Orig, params(undefined, 0, 0), whereis(beamchain_wallet)),
           case R of
               {ok, PJ} ->
                   %% Whatever happens, the victim input must come back
                   %% exactly as the sender sent it (no receiver sig).
                   ?assertEqual(lists:nth(2, Orig#psbt.inputs),
                                lists:nth(2, PJ#psbt.inputs));
               _ -> ok
           end,
           ?assertMatch({error, {original_rejected, _}}, R)
       end}]}.

%%% ===================================================================
%%% payjoin_fee_never_docked_from_a_receiver_output
%%% ===================================================================

%% additionalfeeoutputindex is the SENDER's output. An Original that pays
%% the receiver twice and points the fee index at the second receiver
%% output must not get its fee share out of the receiver.
payjoin_fee_never_docked_from_a_receiver_output_test_() ->
    {setup,
     fun start_seeded_wallet/0,
     fun(_) -> stop_wallet() end,
     fun(_) ->
       ?_test(begin
           Recv1 = wallet_script(),
           Recv2 = wallet_script(),
           Contrib = 200000,
           ok = beamchain_wallet:add_wallet_utxo(<<10:256>>, 0, Contrib,
                                                 wallet_script(), 1),
           Tx = #transaction{version = 2, inputs = [txin(2)],
                             outputs = [#tx_out{value = 100000,
                                                script_pubkey = Recv1},
                                        #tx_out{value = 49000,
                                                script_pubkey = Recv2}],
                             locktime = 0},
           {ok, P0} = beamchain_psbt:create(Tx),
           Orig = finalized_input(P0, 0, utxo(150000, sender_script(1))),
           {ok, PJ} = beamchain_payjoin_server:build_payjoin_psbt(
                        Orig, params(1, 1000, 0), whereis(beamchain_wallet)),
           [Out0, Out1] = out_values(PJ),
           %% The second receiver output is untouched ...
           ?assertEqual(49000, Out1),
           %% ... and the first is credited with the contribution less
           %% only its own input's fee (the sender paid nothing).
           ?assert(Out0 > 100000),
           ?assert(Out0 =< 100000 + Contrib)
       end)
     end}.

%%% ===================================================================
%%% payjoin_min_fee_rate_honoured
%%% ===================================================================

payjoin_min_fee_rate_honoured_test_() ->
    {foreach,
     fun start_seeded_wallet/0,
     fun(_) -> stop_wallet() end,
     [{"reachable minfeerate: the proposal's fee rate meets it",
       fun() ->
           RecvScript = wallet_script(),
           Contrib = 200000,
           ok = beamchain_wallet:add_wallet_utxo(<<8:256>>, 0, Contrib,
                                                 wallet_script(), 1),
           Orig = honest_original(RecvScript),
           {ok, OrigTx} = beamchain_psbt:extract(Orig),
           OrigVsize = beamchain_serialize:tx_vsize(OrigTx),
           %% The Original's own rate (fee 1000), rounded down: reachable
           %% with the receiver paying only its own input's fee.
           MinRate = 1000 div OrigVsize,
           ?assert(MinRate > 0),
           {ok, PJ} = beamchain_payjoin_server:build_payjoin_psbt(
                        Orig, params(undefined, 0, MinRate),
                        whereis(beamchain_wallet)),
           [RecvOut, Change] = out_values(PJ),
           ?assertEqual(49000, Change),
           Fee = 150000 + Contrib - (RecvOut + Change),
           ?assert(Fee >= MinRate * (OrigVsize + 68)),
           %% The receiver paid its own input's fee and nothing more.
           ?assert(RecvOut > 100000),
           ?assert(100000 + Contrib - RecvOut =< 1000 * 68 div OrigVsize + 1)
       end},
      {"unreachable minfeerate: refused, receiver does not burn its coin",
       fun() ->
           RecvScript = wallet_script(),
           ok = beamchain_wallet:add_wallet_utxo(<<8:256>>, 0, 200000,
                                                 wallet_script(), 1),
           Orig = honest_original(RecvScript),
           R = beamchain_payjoin_server:build_payjoin_psbt(
                 Orig, params(1, 300, 1000), whereis(beamchain_wallet)),
           case R of
               {ok, PJ} ->
                   %% The receiver must not have paid 1000 sat/vB itself.
                   [RecvOut, _] = out_values(PJ),
                   ?assert(RecvOut >= 100000 + 200000 - 1000);
               _ -> ok
           end,
           ?assertMatch({error, {original_rejected, _}}, R)
       end}]}.

%%% ===================================================================
%%% payjoin_declared_input_value_not_trusted
%%% ===================================================================

%% The PSBT's witness_utxo values are only what the sender claims. A
%% sender that overstates its input value inflates the Original's fee
%% rate and, with it, the fee charged to the receiver's input. The
%% handler prices the Original from the mempool dry-run instead
%% (check_original_broadcastable -> #{original_fee, original_vsize}), and
%% the builder refuses an Original whose declared fee disagrees.
payjoin_declared_input_value_not_trusted_test_() ->
    {setup,
     fun start_seeded_wallet/0,
     fun(_) -> stop_wallet() end,
     fun(_) ->
       ?_test(begin
           ?assert(exported(beamchain_payjoin_server,
                            check_original_broadcastable, 2)),
           RecvScript = wallet_script(),
           ok = beamchain_wallet:add_wallet_utxo(<<9:256>>, 0, 200000,
                                                 wallet_script(), 1),
           Tx = #transaction{version = 2, inputs = [txin(2)],
                             outputs = [#tx_out{value = 100000,
                                                script_pubkey = RecvScript},
                                        #tx_out{value = 49000,
                                                script_pubkey =
                                                    sender_script(9)}],
                             locktime = 0},
           {ok, P0} = beamchain_psbt:create(Tx),
           %% Real coin is 150000 (fee 1000); sender declares 250000.
           Lying = finalized_input(P0, 0, utxo(250000, sender_script(1))),
           {ok, LTx} = beamchain_psbt:extract(Lying),
           VSize = beamchain_serialize:tx_vsize(LTx),
           %% What the mempool would report for the real coin.
           DryRun = fun(_) -> {ok, <<1:256>>, <<1:256>>, 1000, VSize,
                               1000 / VSize} end,
           {ok, Verified} =
               beamchain_payjoin_server:check_original_broadcastable(
                 Lying, DryRun),
           ?assertEqual(#{original_fee => 1000, original_vsize => VSize},
                        Verified),
           Params = maps:merge(params(undefined, 0, 0), Verified),
           R = beamchain_payjoin_server:build_payjoin_psbt(
                 Lying, Params, whereis(beamchain_wallet)),
           ?assertMatch({error, {original_rejected, _}}, R),
           %% Control: the honest Original with the same verified numbers
           %% goes through, and the receiver pays only its own input's
           %% fee at the real rate.
           Honest = honest_original(RecvScript),
           {ok, PJ} = beamchain_payjoin_server:build_payjoin_psbt(
                        Honest, Params, whereis(beamchain_wallet)),
           [RecvOut, 49000] = out_values(PJ),
           ?assert(100000 + 200000 - RecvOut =< 1000 * 68 div VSize + 1)
       end)
     end}.

%%% ===================================================================
%%% payjoin_original_must_be_broadcastable
%%% ===================================================================

exported(M, F, A) ->
    {module, M} = code:ensure_loaded(M),
    erlang:function_exported(M, F, A).

payjoin_original_must_be_broadcastable_test() ->
    ?assert(exported(beamchain_payjoin_server, validate_original_psbt, 1)),
    ?assert(exported(beamchain_payjoin_server,
                     check_original_broadcastable, 1)),
    Tx = #transaction{version = 2, inputs = [txin(2)],
                      outputs = [#tx_out{value = 1000,
                                         script_pubkey = sender_script(3)}],
                      locktime = 0},
    {ok, P0} = beamchain_psbt:create(Tx),
    Partial = partial_input(P0, 0, utxo(5000, sender_script(1))),
    %% Not finalized -> not broadcastable -> rejected.
    ?assertMatch({error, _},
                 beamchain_payjoin_server:validate_original_psbt(Partial)),
    Final = finalized_input(P0, 0, utxo(5000, sender_script(1))),
    ?assertEqual(ok,
                 beamchain_payjoin_server:validate_original_psbt(Final)),
    %% Broadcast check fails closed with no mempool to ask.
    case whereis(beamchain_mempool) of
        undefined ->
            ?assertMatch({error, _},
                         beamchain_payjoin_server:check_original_broadcastable(
                           Final));
        _ -> ok
    end.

%%% ===================================================================
%%% payjoin_token_gate_from_conf
%%% ===================================================================

with_config(Pairs, Fun) ->
    Created = case ets:info(?CFG) of
                  undefined ->
                      ets:new(?CFG, [named_table, set, public]),
                      true;
                  _ -> false
              end,
    Saved = [{K, ets:lookup(?CFG, K)} || {K, _} <- Pairs],
    [ets:insert(?CFG, P) || P <- Pairs],
    try Fun()
    after
        lists:foreach(fun({K, []}) -> ets:delete(?CFG, K);
                         ({_K, [Old]}) -> ets:insert(?CFG, Old)
                      end, Saved),
        case Created of
            true -> ets:delete(?CFG);
            false -> ok
        end
    end.

payjoin_token_gate_from_conf_test_() ->
    %% beamchain_config:parse_config_line/2 stores every conf value as a
    %% trimmed string, so `payjoin_require_token=1` arrives as "1".
    [{"payjoin_require_token=" ++ V ++ " -> " ++ atom_to_list(Want),
      fun() ->
          with_config([{payjoin_require_token, V}], fun() ->
              ?assertEqual(Want, beamchain_config:payjoin_require_token())
          end)
      end}
     || {V, Want} <- [{"1", true}, {"true", true},
                      {"0", false}, {"false", false}]].

%%% ===================================================================
%%% rest_listener_binds_loopback_by_default
%%% ===================================================================

rest_listener_binds_loopback_by_default_test() ->
    ?assert(exported(beamchain_rest, rest_socket_opts, 1)),
    %% rpcbind unset (get/1 -> undefined) is the default config.
    Opts = with_config([{rpcbind, undefined}], fun() ->
               beamchain_rest:rest_socket_opts(18555)
           end),
    ?assertEqual({127, 0, 0, 1}, proplists:get_value(ip, Opts)),
    ?assertEqual(18555, proplists:get_value(port, Opts)),
    Wide = with_config([{rpcbind, "0.0.0.0"}], fun() ->
               beamchain_rest:rest_socket_opts(18555)
           end),
    ?assertEqual({0, 0, 0, 0}, proplists:get_value(ip, Wide)).
