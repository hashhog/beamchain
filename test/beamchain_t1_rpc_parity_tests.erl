-module(beamchain_t1_rpc_parity_tests).

%%% T1 probe parity vs live Bitcoin Core (tools/r5-probes.d).
%%%
%%% These four calls are the remaining T1 FAILs on beamchain:
%%%   getblocktemplate [{}]                  -> -8  (missing rules=["segwit"])
%%%   testmempoolaccept [["deadbeef"]]       -> -22 (decode is an RPC error)
%%%   addnode ["192.0.2.1:8333","notacommand"] -> -1 (help-text misc error)
%%%   getnetworkhashps ["foo"]               -> -3  (Arg<int> type error)
%%% plus getnetworkhashps height / float shape so the exact-check probe
%%% at [120, %TIP-10%] is a double computed at that height, not a truncated
%%% integer at the tip.
%%%
%%% CONTROL: `rebar3 eunit --module=beamchain_t1_rpc_parity_tests`
%%% fails if any of the four production handlers is reverted.

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

rpc(Method, Params) ->
    beamchain_rpc:handle_method(Method, Params, undefined).

%%% ===================================================================
%%% getblocktemplate — missing-segwit-rule (r5-probes.d/mining-relay.jsonl)
%%% Core rpc/mining.cpp:854-857 RPC_INVALID_PARAMETER (-8).
%%% ===================================================================

getblocktemplate_missing_segwit_rule_is_minus8_test() ->
    Res = rpc(<<"getblocktemplate">>, [#{}]),
    ?assertMatch({error, -8, _}, Res),
    {error, -8, Msg} = Res,
    ?assertEqual(
       <<"getblocktemplate must be called with the segwit rule set "
         "(call with {\"rules\": [\"segwit\"]})">>,
       Msg).

getblocktemplate_empty_rules_is_minus8_test() ->
    ?assertMatch({error, -8, _},
                 rpc(<<"getblocktemplate">>,
                     [#{<<"rules">> => []}])).

%% With rules=["segwit"] the missing-segwit gate must not fire. The miner
%% gen_server is not running here, so the call may EXIT; that is still a
%% pass. A handler that always returns the -8 segwit error fails.
getblocktemplate_segwit_rules_not_minus8_test() ->
    Res = (catch rpc(<<"getblocktemplate">>,
                     [#{<<"rules">> => [<<"segwit">>]}])),
    case Res of
        {error, -8, Msg} ->
            ?assertEqual(nomatch, binary:match(Msg, <<"segwit rule">>));
        _ ->
            ok
    end.

%%% ===================================================================
%%% testmempoolaccept — decode-error (r5-probes.d/mining-relay.jsonl)
%%% Core rpc/mempool.cpp:332-335 RPC_DESERIALIZATION_ERROR (-22).
%%% Must NOT be a result-row {allowed:false, reject-reason:"TX decode failed"}.
%%% ===================================================================

testmempoolaccept_decode_fail_is_minus22_test() ->
    Res = rpc(<<"testmempoolaccept">>, [[<<"deadbeef">>]]),
    ?assertMatch({error, -22, _}, Res),
    ?assertNotMatch({ok, _}, Res),
    {error, -22, Msg} = Res,
    ?assertEqual(
       <<"TX decode failed: deadbeef Make sure the tx has at "
         "least one input.">>,
       Msg).

%%% ===================================================================
%%% addnode — invalid-command (r5-probes.d/control-network.jsonl)
%%% Core rpc/net.cpp:336-339 throws runtime_error(help) -> RPC_MISC_ERROR (-1).
%%% ===================================================================

addnode_invalid_command_is_minus1_test() ->
    Res = rpc(<<"addnode">>, [<<"192.0.2.1:8333">>, <<"notacommand">>]),
    ?assertMatch({error, -1, _}, Res),
    ?assertNotMatch({error, -8, _}, Res).

%%% ===================================================================
%%% getnetworkhashps — type-error + domain + height + float
%%% (r5-probes.d/mining-relay.jsonl)
%%% ===================================================================

help_lists_getnetworkhashps_test() ->
    Names = beamchain_rpc:beamchain_method_names(),
    ?assertEqual(true, lists:member(<<"getnetworkhashps">>, Names)).

getnetworkhashps_string_nblocks_is_minus3_test() ->
    Res = rpc(<<"getnetworkhashps">>, [<<"foo">>]),
    ?assertMatch({error, -3, _}, Res),
    {error, -3, Msg} = Res,
    ?assertEqual(
       <<"JSON value of type string is not of expected type number">>,
       Msg).

getnetworkhashps_zero_nblocks_is_minus8_test() ->
    ?assertEqual(
       {error, -8, <<"Invalid nblocks. Must be a positive number or -1.">>},
       rpc(<<"getnetworkhashps">>, [0])).

getnetworkhashps_height_and_float_test_() ->
    {setup,
     fun hashps_setup/0,
     fun hashps_cleanup/1,
     fun(_) ->
         [
          {"height above tip -> -8 (height is not ignored)",
           fun() ->
               ?assertEqual(
                  {error, -8,
                   <<"Block does not exist at specified height">>},
                  rpc(<<"getnetworkhashps">>, [3, 999]))
           end},
          {"result is a float using min/max timestamps, not trunc(endpoints)",
           fun() ->
               %% Window at height=3, nblocks=3: heights 3,2,1,0.
               %% timestamps 300, 1000, 200, 100 -> min=100 max=1000.
               %% workDiff = 3000, timeDiff = 900 -> 3000/900.
               %% Endpoint delta would be 300-100=200 -> 15.0.
               %% trunc() would yield the integer 3.
               Res = rpc(<<"getnetworkhashps">>, [3, 3]),
               ?assertMatch({ok, N} when is_float(N), Res),
               {ok, N} = Res,
               Expected = 3000.0 / 900,
               ?assert(abs(N - Expected) < 1.0e-9)
           end}
         ]
     end}.

hashps_setup() ->
    ok = meck:new(beamchain_chainstate, [no_link]),
    ok = meck:expect(beamchain_chainstate, get_tip,
                     fun() -> {ok, {<<0:256>>, 3}} end),
    ok = meck:new(beamchain_db, [no_link]),
    ok = meck:expect(beamchain_db, get_block_index,
                     fun(H) -> {ok, hashps_index(H)} end),
    ok.

hashps_cleanup(_) ->
    catch meck:unload(beamchain_db),
    catch meck:unload(beamchain_chainstate),
    ok.

%% Heights 0..3. Height 2 is time-warped into the future so min/max
%% differs from the endpoint delta.
hashps_index(0) -> idx(0, 100);
hashps_index(1) -> idx(1000, 200);
hashps_index(2) -> idx(2000, 1000);
hashps_index(3) -> idx(3000, 300);
hashps_index(_) -> not_found.

idx(Work, Time) ->
    #{chainwork => <<0:224, Work:32>>,
      header => #block_header{
          version = 1,
          prev_hash = <<0:256>>,
          merkle_root = <<0:256>>,
          timestamp = Time,
          bits = 16#1d00ffff,
          nonce = 0}}.
