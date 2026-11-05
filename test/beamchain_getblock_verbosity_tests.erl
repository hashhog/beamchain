%%% getblock verbosity parsing, mirroring Core's ParseVerbosity(allow_bool=true)
%%% in rpc/blockchain.cpp. Regtest row operator/getblock/{true,false,bad-verbosity}
%%% were node_error: beamchain answered -8 "Invalid verbosity value" for booleans
%%% and for integers above 2, where Core answers with a block.
-module(beamchain_getblock_verbosity_tests).
-include_lib("eunit/include/eunit.hrl").

bool_true_is_1_test() ->
    ?assertEqual(1, beamchain_rpc:getblock_verbosity(true)).
bool_false_is_0_test() ->
    ?assertEqual(0, beamchain_rpc:getblock_verbosity(false)).
null_is_default_1_test() ->
    ?assertEqual(1, beamchain_rpc:getblock_verbosity(null)).
ints_0_1_2_test() ->
    ?assertEqual([0, 1, 2],
                 [beamchain_rpc:getblock_verbosity(V) || V <- [0, 1, 2]]).
large_int_is_prevout_json_test() ->
    ?assertEqual(3, beamchain_rpc:getblock_verbosity(9)).
negative_int_is_raw_hex_test() ->
    ?assertEqual(0, beamchain_rpc:getblock_verbosity(-3)).
three_is_prevout_json_test() ->
    ?assertEqual(3, beamchain_rpc:getblock_verbosity(3)).
