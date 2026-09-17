-module(beamchain_t3_rpc_parity_tests).

%%% T3 wallet-basic probe parity vs Bitcoin Core (tools/r5-probes.d/wallet.jsonl
%%% plus stop / getblockfilter on the R5 regtest lane).
%%%
%%% Encodes the rejection probes and help-parity the lane scores. Dispatch
%%% goes through beamchain_rpc:dispatch/2 (the JSON-RPC path) so a missing
%%% arity gate, a usage-string -32602, or a crash (-32603) fails these.
%%%
%%% CONTROL: `rebar3 eunit --module=beamchain_t3_rpc_parity_tests`

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

dispatch_rpc(Method, Params) ->
    case beamchain_rpc:dispatch(
           #{<<"jsonrpc">> => <<"1.0">>,
             <<"id">> => <<"t3">>,
             <<"method">> => Method,
             <<"params">> => Params},
           undefined) of
        #{<<"error">> := null, <<"result">> := Result} ->
            {ok, Result};
        #{<<"error">> := #{<<"code">> := Code, <<"message">> := Msg}} ->
            {error, Code, Msg};
        {raw_json, Bin} ->
            Decoded = jsx:decode(Bin, [return_maps]),
            case Decoded of
                #{<<"error">> := null, <<"result">> := Result} ->
                    {ok, Result};
                #{<<"error">> := #{<<"code">> := Code, <<"message">> := Msg}} ->
                    {error, Code, Msg}
            end
    end.

%%% ===================================================================
%%% help-parity — operators discover T3 methods in `help`
%%% ===================================================================

help_lists_t3_methods_test() ->
    Names = beamchain_rpc:beamchain_method_names(),
    lists:foreach(
      fun(M) ->
          ?assertEqual({M, true}, {M, lists:member(M, Names)})
      end,
      [<<"createwallet">>,
       <<"loadwallet">>,
       <<"unloadwallet">>,
       <<"listwallets">>,
       <<"getwalletinfo">>,
       <<"backupwallet">>,
       <<"restorewallet">>,
       <<"getnewaddress">>,
       <<"getaddressinfo">>,
       <<"getbalances">>,
       <<"listunspent">>,
       <<"listtransactions">>,
       <<"sendtoaddress">>,
       <<"send">>,
       <<"walletcreatefundedpsbt">>,
       <<"walletprocesspsbt">>,
       <<"stop">>,
       <<"getblockfilter">>]).

%%% ===================================================================
%%% Arity / type rejections that must not be silently accepted
%%% (Core HelpResult → -1; MatchesType → -3)
%%% ===================================================================

createwallet_no_name_is_minus1_test() ->
    ?assertMatch({error, -1, _}, dispatch_rpc(<<"createwallet">>, [])).

createwallet_legacy_refused_is_minus4_test() ->
    %% descriptors=false is Core RPC_WALLET_ERROR. Must NOT create a
    %% second, legacy wallet (the "accepts what Core rejects" class).
    ?assertMatch({error, -4, _},
                 dispatch_rpc(<<"createwallet">>,
                              [<<"r5legacy">>, null, null, null, null, false])).

getwalletinfo_wrong_arity_is_minus1_test() ->
    ?assertMatch({error, -1, _},
                 dispatch_rpc(<<"getwalletinfo">>, [<<"unexpected">>])).

listwallets_wrong_arity_is_minus1_test() ->
    ?assertMatch({error, -1, _},
                 dispatch_rpc(<<"listwallets">>, [<<"unexpected">>])).

getbalances_wrong_arity_is_minus1_test() ->
    ?assertMatch({error, -1, _},
                 dispatch_rpc(<<"getbalances">>, [<<"unexpected">>])).

stop_wrong_type_is_minus3_test() ->
    %% Must NOT shut the node down. Core type-checks `wait` first.
    ?assertMatch({error, -3, _},
                 dispatch_rpc(<<"stop">>, [<<"notanumber">>])).

getnewaddress_bad_type_is_minus5_test() ->
    ?assertMatch({error, -5, _},
                 dispatch_rpc(<<"getnewaddress">>, [<<>>, <<"bogustype">>])).

getaddressinfo_invalid_is_minus5_test() ->
    %% Invalid address is -5 even with no wallet loaded? Core needs a
    %% wallet first (-18/-19). The address check still fires when a
    %% wallet is present; without one we at least must not return ok.
    Res = dispatch_rpc(<<"getaddressinfo">>, [<<"notanaddress">>]),
    ?assertMatch({error, _, _}, Res),
    {error, Code, _} = Res,
    ?assert(lists:member(Code, [-5, -4, -18, -19, -1])).

walletcreatefundedpsbt_no_outputs_is_minus8_test() ->
    Res = dispatch_rpc(<<"walletcreatefundedpsbt">>, [[], []]),
    ?assertMatch({error, _, _}, Res),
    {error, Code, _} = Res,
    %% -8 once a wallet is loaded; without one, wallet-missing is honest.
    ?assert(lists:member(Code, [-8, -4, -18, -19, -1])).

walletcreatefundedpsbt_invalid_address_is_minus5_test() ->
    Res = dispatch_rpc(<<"walletcreatefundedpsbt">>,
                       [[], [#{<<"notanaddress">> => 0.001}]]),
    ?assertMatch({error, _, _}, Res),
    {error, Code, _} = Res,
    ?assert(lists:member(Code, [-5, -4, -18, -19, -1])).

walletprocesspsbt_decode_error_is_minus22_test() ->
    Res = dispatch_rpc(<<"walletprocesspsbt">>, [<<"not-a-psbt">>]),
    ?assertMatch({error, _, _}, Res),
    {error, Code, _} = Res,
    ?assert(lists:member(Code, [-22, -4, -18, -19, -1])).

sendtoaddress_invalid_address_is_minus5_test() ->
    Res = dispatch_rpc(<<"sendtoaddress">>, [<<"notanaddress">>, 0.001]),
    ?assertMatch({error, _, _}, Res),
    {error, Code, _} = Res,
    ?assert(lists:member(Code, [-5, -4, -18, -19, -1])).

sendtoaddress_invalid_amount_is_minus3_test() ->
    Res = dispatch_rpc(<<"sendtoaddress">>,
                       [<<"bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080">>, -1]),
    ?assertMatch({error, _, _}, Res),
    {error, Code, _} = Res,
    ?assert(lists:member(Code, [-3, -4, -18, -19, -1])).

send_no_outputs_is_minus8_test() ->
    Res = dispatch_rpc(<<"send">>, [[]]),
    ?assertMatch({error, _, _}, Res),
    {error, Code, _} = Res,
    ?assert(lists:member(Code, [-8, -4, -18, -19, -1])).

send_invalid_address_is_minus5_test() ->
    Res = dispatch_rpc(<<"send">>, [[#{<<"notanaddress">> => 0.001}]]),
    ?assertMatch({error, _, _}, Res),
    {error, Code, _} = Res,
    ?assert(lists:member(Code, [-5, -4, -18, -19, -1])).

restorewallet_backup_missing_is_minus8_test() ->
    ?assertMatch({error, -8, _},
                 dispatch_rpc(<<"restorewallet">>,
                              [<<"r5probe_fresh">>,
                               <<"/nonexistent/r5probe-nope.bak">>])).

loadwallet_not_found_is_minus18_test() ->
    ?assertMatch({error, -18, _},
                 dispatch_rpc(<<"loadwallet">>, [<<"r5probe_missing">>])).

unloadwallet_not_loaded_is_minus18_test() ->
    ?assertMatch({error, -18, _},
                 dispatch_rpc(<<"unloadwallet">>, [<<"r5probe_missing">>])).

listtransactions_negative_count_is_minus8_test() ->
    Res = dispatch_rpc(<<"listtransactions">>, [<<"*">>, -1]),
    ?assertMatch({error, _, _}, Res),
    {error, Code, _} = Res,
    ?assert(lists:member(Code, [-8, -4, -18, -19, -1])).

listtransactions_negative_skip_is_minus8_test() ->
    Res = dispatch_rpc(<<"listtransactions">>, [<<"*">>, 10, -1]),
    ?assertMatch({error, _, _}, Res),
    {error, Code, _} = Res,
    ?assert(lists:member(Code, [-8, -4, -18, -19, -1])).

listunspent_invalid_address_is_minus5_test() ->
    Res = dispatch_rpc(<<"listunspent">>,
                       [1, 9999999, [<<"notanaddress">>]]),
    ?assertMatch({error, _, _}, Res),
    {error, Code, _} = Res,
    ?assert(lists:member(Code, [-5, -4, -18, -19, -1])).

listunspent_duplicate_address_is_minus8_test() ->
    %% Mainnet P2WPKH so the address is valid without a regtest config;
    %% Core then rejects the duplicate with -8 before looking at the wallet.
    Addr = <<"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4">>,
    ?assertMatch({error, -8, _},
                 dispatch_rpc(<<"listunspent">>, [1, 9999999, [Addr, Addr]])).

backupwallet_bad_destination_is_minus4_test() ->
    Res = dispatch_rpc(<<"backupwallet">>,
                       [<<"/nonexistent-r5probe-dir/backup.dat">>]),
    ?assertMatch({error, _, _}, Res),
    {error, Code, _} = Res,
    ?assert(lists:member(Code, [-4, -18, -19, -1])).

%%% ===================================================================
%%% Wallet-backed probes: create / already-exists / address types /
%%% backup+restore already-exists.
%%% ===================================================================

wallet_lifecycle_test_() ->
    {setup,
     fun setup_wallet/0,
     fun cleanup_wallet/1,
     fun(_) ->
         [
          {"createwallet success + already-exists is -4",
           fun() ->
               {ok, Res} = dispatch_rpc(<<"createwallet">>, [<<"r5">>]),
               Name = case Res of
                          #{<<"name">> := N} -> N;
                          L when is_list(L) -> proplists:get_value(<<"name">>, L)
                      end,
               ?assertEqual(<<"r5">>, Name),
               ?assertMatch({error, -4, _},
                            dispatch_rpc(<<"createwallet">>, [<<"r5">>]))
           end},
          {"getnewaddress types (regtest prefixes)",
           fun() ->
               {ok, Bech} = dispatch_rpc(<<"getnewaddress">>, []),
               ?assertMatch({match, _},
                            re:run(Bech, <<"^bcrt1q[0-9a-z]{38}$">>)),
               {ok, Tr} = dispatch_rpc(<<"getnewaddress">>,
                                       [<<>>, <<"bech32m">>]),
               ?assertMatch({match, _},
                            re:run(Tr, <<"^bcrt1p[0-9a-z]{58}$">>)),
               {ok, Nested} = dispatch_rpc(<<"getnewaddress">>,
                                           [<<>>, <<"p2sh-segwit">>]),
               ?assertMatch({match, _},
                            re:run(Nested, <<"^2[1-9A-HJ-NP-Za-km-z]{25,39}$">>)),
               {ok, Leg} = dispatch_rpc(<<"getnewaddress">>,
                                        [<<>>, <<"legacy">>]),
               ?assertMatch({match, _},
                            re:run(Leg, <<"^[mn][1-9A-HJ-NP-Za-km-z]{25,39}$">>))
           end},
          {"getwalletinfo shape + descriptors",
           fun() ->
               {ok, Info} = dispatch_rpc(<<"getwalletinfo">>, []),
               Map = case Info of
                         M when is_map(M) -> M;
                         L when is_list(L) -> maps:from_list(L)
                     end,
               ?assertEqual(<<"r5">>, maps:get(<<"walletname">>, Map)),
               ?assertEqual(true, maps:get(<<"descriptors">>, Map)),
               ?assertEqual(true, maps:get(<<"private_keys_enabled">>, Map)),
               ?assertEqual(false, maps:get(<<"blank">>, Map)),
               ?assert(is_map(maps:get(<<"lastprocessedblock">>, Map))),
               ?assert(is_list(maps:get(<<"flags">>, Map)))
           end},
          {"listwallets contains r5",
           fun() ->
               {ok, Names} = dispatch_rpc(<<"listwallets">>, []),
               ?assert(lists:member(<<"r5">>, Names))
           end},
          {"getaddressinfo invalid is -5 with a wallet loaded",
           fun() ->
               ?assertMatch({error, -5, _},
                            dispatch_rpc(<<"getaddressinfo">>,
                                         [<<"notanaddress">>]))
           end},
          {"getbalances shape",
           fun() ->
               {ok, Bal} = dispatch_rpc(<<"getbalances">>, []),
               Map = case Bal of
                         M when is_map(M) -> M;
                         L when is_list(L) -> maps:from_list(L)
                     end,
               Mine = maps:get(<<"mine">>, Map),
               MineMap = case Mine of
                             M2 when is_map(M2) -> M2;
                             L2 when is_list(L2) -> maps:from_list(L2)
                         end,
               ?assert(is_number(maps:get(<<"trusted">>, MineMap))),
               ?assert(maps:is_key(<<"lastprocessedblock">>, Map))
           end},
          {"backupwallet + restorewallet already-exists is -36",
           fun() ->
               Dest = filename:join("/tmp",
                   "beamchain_t3_bak_" ++
                       integer_to_list(erlang:unique_integer([positive]))),
               {ok, null} = dispatch_rpc(<<"backupwallet">>,
                                         [list_to_binary(Dest)]),
               ?assertMatch({error, -36, _},
                            dispatch_rpc(<<"restorewallet">>,
                                         [<<"r5">>, list_to_binary(Dest)])),
               _ = file:delete(Dest)
           end},
          {"loadwallet already-loaded is -35",
           fun() ->
               ?assertMatch({error, -35, _},
                            dispatch_rpc(<<"loadwallet">>, [<<"r5">>]))
           end},
          {"send no-outputs / invalid-address with wallet loaded",
           fun() ->
               ?assertMatch({error, -8, _}, dispatch_rpc(<<"send">>, [[]])),
               ?assertMatch({error, -5, _},
                            dispatch_rpc(<<"send">>,
                                         [[#{<<"notanaddress">> => 0.001}]]))
           end},
          {"walletcreatefundedpsbt no-outputs / invalid-address with wallet",
           fun() ->
               ?assertMatch({error, -8, _},
                            dispatch_rpc(<<"walletcreatefundedpsbt">>,
                                         [[], []])),
               ?assertMatch({error, -5, _},
                            dispatch_rpc(<<"walletcreatefundedpsbt">>,
                                         [[], [#{<<"notanaddress">> => 0.001}]]))
           end},
          {"walletprocesspsbt decode-error with wallet loaded",
           fun() ->
               ?assertMatch({error, -22, _},
                            dispatch_rpc(<<"walletprocesspsbt">>,
                                         [<<"not-a-psbt">>]))
           end},
          {"listunspent invalid/duplicate with wallet loaded",
           fun() ->
               ?assertMatch({error, -5, _},
                            dispatch_rpc(<<"listunspent">>,
                                         [1, 9999999, [<<"notanaddress">>]])),
               Addr = <<"bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080">>,
               ?assertMatch({error, -8, _},
                            dispatch_rpc(<<"listunspent">>,
                                         [1, 9999999, [Addr, Addr]]))
           end},
          {"listtransactions negative count/skip with wallet loaded",
           fun() ->
               ?assertMatch({error, -8, _},
                            dispatch_rpc(<<"listtransactions">>,
                                         [<<"*">>, -1])),
               ?assertMatch({error, -8, _},
                            dispatch_rpc(<<"listtransactions">>,
                                         [<<"*">>, 10, -1]))
           end},
          {"sendtoaddress invalid address/amount with wallet loaded",
           fun() ->
               ?assertMatch({error, -5, _},
                            dispatch_rpc(<<"sendtoaddress">>,
                                         [<<"notanaddress">>, 0.001])),
               ?assertMatch({error, -3, _},
                            dispatch_rpc(<<"sendtoaddress">>,
                                         [<<"bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080">>,
                                          -1]))
           end}
         ]
     end}.

setup_wallet() ->
    {Dir, Owned} = beamchain_wallet_test_env:setup(),
    ets:insert(beamchain_config_ets, {network, regtest}),
    _ = stop_proc(beamchain_wallet),
    _ = stop_proc(beamchain_wallet_sup),
    catch ets:delete(beamchain_wallet_registry),
    {ok, SupPid} = beamchain_wallet_sup:start_link(),
    true = unlink(SupPid),
    {Dir, Owned, SupPid}.

cleanup_wallet({Dir, Owned, _SupPid}) ->
    _ = stop_proc(beamchain_wallet_sup),
    _ = stop_proc(beamchain_wallet),
    catch ets:delete(beamchain_wallet_registry),
    beamchain_wallet_test_env:teardown({Dir, Owned}).

stop_proc(Name) ->
    case whereis(Name) of
        undefined -> ok;
        Pid ->
            MRef = erlang:monitor(process, Pid),
            exit(Pid, kill),
            receive {'DOWN', MRef, process, Pid, _} -> ok
            after 2000 -> ok
            end
    end.
