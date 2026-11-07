%%% getblockheader rejects a non-boolean `verbose` with Core's -3 type error
%%% (params[1].get_bool()). Regtest row operator/getblockheader/bad-verbose
%%% was a node_error: beamchain answered with a header.
-module(beamchain_getblockheader_verbose_tests).
-include_lib("eunit/include/eunit.hrl").

-define(H, <<"00000000000000000000000000000000000000000000000000000000000000aa">>).

string_verbose_is_type_error_test() ->
    ?assertEqual({error, -3,
                  <<"Wrong type passed:\n{\n    \"Position 2 (verbose)\": "
                    "\"JSON value of type string is not of expected type bool\"\n}">>},
                 beamchain_rpc:rpc_getblockheader([?H, <<"x">>])).
number_verbose_is_type_error_test() ->
    {error, -3, Msg} = beamchain_rpc:rpc_getblockheader([?H, 1]),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"of type number is not of expected type bool">>)).
bad_hash_is_reported_before_bad_verbose_test() ->
    %% Core ParseHashV(params[0]) runs before params[1].get_bool().
    {error, Code, _} = beamchain_rpc:rpc_getblockheader([<<"zz">>, <<"x">>]),
    ?assertEqual(-8, Code).
