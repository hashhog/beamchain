-module(beamchain_decoderawtransaction_core_tests).
%%% decoderawtransaction vs Core v31.1 (rpc/rawtransaction.cpp, core_io.cpp DecodeHexTx):
%%%  - optional bool `iswitness` (true = extended only, false = legacy only)
%%%  - a serialization must consume the whole hex: trailing bytes -> -22 "TX decode failed"
-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

-define(DESER, -22).

mk_tx(Witness) ->
    In = #tx_in{prev_out = #outpoint{hash = <<1:256>>, index = 0},
                script_sig = <<>>, sequence = 16#fffffffd, witness = Witness},
    Out = #tx_out{value = 1000, script_pubkey = <<16#51>>},
    #transaction{version = 2, inputs = [In], outputs = [Out], locktime = 0}.

hex(Tx, W) ->
    binary:encode_hex(beamchain_serialize:encode_transaction(Tx, W), lowercase).

segwit_hex() -> hex(mk_tx([<<1,2,3>>]), witness).
legacy_hex() -> hex(mk_tx([]), no_witness).

%% Guarded so a tree without the export fails on the assertion, not on undef.
dec(Params) ->
    try beamchain_rpc:rpc_decoderawtransaction(Params)
    catch error:undef -> not_exported end.

cat(Hex, Suffix) -> <<Hex/binary, Suffix/binary>>.

plain_ok_test() ->
    ?assertMatch({ok_raw_json, _}, dec([legacy_hex()])),
    ?assertMatch({ok_raw_json, _}, dec([segwit_hex()])).

segwit_iswitness_false_is_deserialization_error_test() ->
    ?assertMatch({error, ?DESER, <<"TX decode failed">>}, dec([segwit_hex(), false])).

legacy_iswitness_true_ok_test() ->
    ?assertMatch({ok_raw_json, _}, dec([legacy_hex(), true])).

iswitness_matching_ok_test() ->
    ?assertMatch({ok_raw_json, _}, dec([segwit_hex(), true])),
    ?assertMatch({ok_raw_json, _}, dec([legacy_hex(), false])).

trailing_bytes_rejected_test() ->
    ?assertMatch({error, ?DESER, <<"TX decode failed">>}, dec([cat(legacy_hex(), <<"00">>)])),
    ?assertMatch({error, ?DESER, <<"TX decode failed">>}, dec([cat(segwit_hex(), <<"00">>)])).

garbage_rejected_test() ->
    ?assertMatch({error, ?DESER, _}, dec([<<"zz">>])),
    ?assertMatch({error, ?DESER, _}, dec([<<>>])).
