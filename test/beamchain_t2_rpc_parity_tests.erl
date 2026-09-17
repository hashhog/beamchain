-module(beamchain_t2_rpc_parity_tests).

%%% T2 probe parity vs live Bitcoin Core (tools/r5-probes.d).
%%%
%%% Encodes the remaining T2 FAILs from the 2026-09-01 r5_probe sweep
%%% (tools/diff-test-artifacts/r5-probe/20260901T182642Z.json beamchain
%%% T2 19/41). Dispatch goes through handle_method/3 (same tuple the
%%% cowboy path returns) so a missing method (-32601), a usage-string
%%% -32602, or a crash (-32603) fails these.
%%%
%%% CONTROL: `rebar3 eunit --module=beamchain_t2_rpc_parity_tests`

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

-define(PSBT_A,
        <<"cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9"
          "////AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAAA">>).
%% Core descriptorprocesspsbt(?PSBT_A, [wpkh(WIF-key-1)]) — ProcessPSBT
%% attached PSBT_OUT_BIP32_DERIVATION on the matching wpkh output.
-define(PSBT_A_WP1_DERIV,
        <<"cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9"
          "////AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAAiAgJ5vmZ++d"
          "y7rFWgYpXOhwsHApv82y3OKNlZ8oFbFvgXmAR1HnboAA==">>).
-define(RAW_HEX,
        <<"0200000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
          "aaaaaaaa0000000000fdffffff01a086010000000000160014751e76e8199196d4"
          "54941c45d1b3a323f1433bd600000000">>).
-define(WIF_PRIV1, <<"KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn">>).
-define(KEY1, <<"03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd">>).
-define(KEY2, <<"03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626">>).
-define(DESC_NO_CSUM,
        <<"wpkh(03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd)">>).
-define(DESC_CSUM,
        <<"wpkh(03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd)#e72f49hy">>).
-define(CORE_SIG,
        <<"HANWTfmfhMdsuje52nPqOD/Q4QXfl6q188p2LpAG4ICJONIllahpDidMpe8n2TWE+"
          "VV2kR2cHd3gAv6n+jtRWV0=">>).
-define(ZERO_WIF, <<"5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAbuatmU">>).
-define(P2WPKH, <<"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4">>).
-define(ZERO64, <<"0000000000000000000000000000000000000000000000000000000000000000">>).
-define(ABSENT64, <<"0000000000000000000000000000000000000000000000000000000000000001">>).

rpc(Method, Params) ->
    try beamchain_rpc:handle_method(Method, Params, undefined)
    catch
        throw:{rpc_error, Code, Msg} -> {error, Code, Msg}
    end.

%% Production path: arity gate then handle_method. The live r5_probe
%% talks JSON-RPC, so a handler that is correct but hidden behind a
%% wrong {Required,Declared} cannot pass these.
dispatch_rpc(Method, Params) ->
    case beamchain_rpc:dispatch(
           #{<<"jsonrpc">> => <<"1.0">>,
             <<"id">> => <<"t2">>,
             <<"method">> => Method,
             <<"params">> => Params},
           undefined) of
        #{<<"error">> := null, <<"result">> := Result} ->
            {ok, Result};
        #{<<"error">> := #{<<"code">> := Code, <<"message">> := Msg}} ->
            {error, Code, Msg}
    end.

%%% ===================================================================
%%% help-parity — operators discover T2 methods in `help`
%%% ===================================================================

help_lists_remaining_t2_methods_test() ->
    Names = beamchain_rpc:beamchain_method_names(),
    lists:foreach(
      fun(M) ->
          ?assertEqual({M, true}, {M, lists:member(M, Names)})
      end,
      [<<"importmempool">>,
       <<"utxoupdatepsbt">>,
       <<"descriptorprocesspsbt">>,
       <<"scantxoutset">>,
       <<"getindexinfo">>,
       <<"gettxoutproof">>,
       <<"verifytxoutproof">>,
       <<"combinerawtransaction">>]).

%%% ===================================================================
%%% validateaddress — exact-invalid (r5-probes.d/util.jsonl)
%%% Core key_io.cpp DecodeDestination: "notanaddress" is Base58-decodable
%%% without a valid checksum -> checksum/length error, not the generic
%%% "unsupported Segwit or Base58" fallback.
%%% ===================================================================

validateaddress_exact_invalid_matches_core_test() ->
    Res = rpc(<<"validateaddress">>, [<<"notanaddress">>]),
    ?assertMatch({ok, _}, Res),
    {ok, Obj} = Res,
    Map = case Obj of
              L when is_list(L) -> maps:from_list(L);
              M when is_map(M) -> M
          end,
    ?assertEqual(false, maps:get(<<"isvalid">>, Map)),
    ?assertEqual(
       <<"Invalid checksum or length of Base58 address (P2PKH or P2SH)">>,
       maps:get(<<"error">>, Map)).

validateaddress_exact_valid_bech32_test() ->
    {ok, Obj} = rpc(<<"validateaddress">>, [?P2WPKH]),
    Map = case Obj of
              L when is_list(L) -> maps:from_list(L);
              M when is_map(M) -> M
          end,
    ?assertEqual(true, maps:get(<<"isvalid">>, Map)),
    ?assertEqual(?P2WPKH, maps:get(<<"address">>, Map)).

%%% ===================================================================
%%% gettxoutproof / verifytxoutproof
%%% ===================================================================

gettxoutproof_tx_not_in_block_is_minus5_test() ->
    Res = rpc(<<"gettxoutproof">>, [[?ZERO64]]),
    ?assertMatch({error, -5, _}, Res),
    {error, -5, Msg} = Res,
    ?assertEqual(<<"Transaction not yet in block">>, Msg).

verifytxoutproof_nonhex_is_minus8_test() ->
    Res = rpc(<<"verifytxoutproof">>, [<<"zz">>]),
    ?assertMatch({error, -8, _}, Res),
    {error, -8, Msg} = Res,
    ?assertEqual(<<"proof must be hexadecimal string (not 'zz')">>, Msg).

%%% ===================================================================
%%% importmempool / prioritisetransaction / scantxoutset / pruneblockchain
%%% ===================================================================

importmempool_missing_file_is_minus1_test() ->
    Res = rpc(<<"importmempool">>,
              [<<"/nonexistent/r5-probe-no-such-file.dat">>]),
    ?assertEqual(
       {error, -1,
        <<"Unable to import mempool file, see debug log for details.">>},
       Res).

prioritisetransaction_bad_txid_is_minus8_test() ->
    Res = rpc(<<"prioritisetransaction">>, [<<"zz">>, 0, 1000]),
    ?assertMatch({error, -8, _}, Res).

scantxoutset_bogus_action_is_minus8_test() ->
    Res = rpc(<<"scantxoutset">>, [<<"bogus">>]),
    ?assertEqual({error, -8, <<"Invalid action 'bogus'">>}, Res).

pruneblockchain_string_height_is_minus3_before_prune_mode_test() ->
    Res = rpc(<<"pruneblockchain">>, [<<"zz">>]),
    ?assertMatch({error, -3, _}, Res),
    {error, -3, Msg} = Res,
    ?assertEqual(
       <<"JSON value of type string is not of expected type number">>,
       Msg).

%%% ===================================================================
%%% decodescript / combinerawtransaction / createpsbt
%%% ===================================================================

decodescript_nonhex_is_minus8_test() ->
    Res = rpc(<<"decodescript">>, [<<"zz">>]),
    ?assertEqual(
       {error, -8, <<"argument must be hexadecimal string (not 'zz')">>},
       Res).

combinerawtransaction_unknown_input_is_minus25_test() ->
    Res = rpc(<<"combinerawtransaction">>, [[?RAW_HEX, ?RAW_HEX]]),
    ?assertEqual(
       {error, -25, <<"Input not found or already spent">>},
       Res).

createpsbt_canonical_exact_matches_core_test() ->
    Inputs = [#{<<"txid">> => <<"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">>,
                <<"vout">> => 0}],
    Outputs = #{?P2WPKH => 0.001},
    Res = rpc(<<"createpsbt">>, [Inputs, Outputs]),
    ?assertEqual({ok, ?PSBT_A}, Res).

createpsbt_bad_txid_is_minus8_test() ->
    Inputs = [#{<<"txid">> => <<"zz">>, <<"vout">> => 0}],
    Outputs = #{?P2WPKH => 0.001},
    Res = rpc(<<"createpsbt">>, [Inputs, Outputs]),
    ?assertMatch({error, -8, _}, Res).

%%% ===================================================================
%%% analyzepsbt / combinepsbt / finalizepsbt
%%% ===================================================================

analyzepsbt_bad_base64_is_minus22_test() ->
    Res = rpc(<<"analyzepsbt">>, [<<"notbase64!!">>]),
    ?assertMatch({error, -22, _}, Res).

analyzepsbt_analyze_exact_matches_core_test() ->
    Map = case rpc(<<"analyzepsbt">>, [?PSBT_A]) of
              {ok, M} when is_map(M) -> M;
              {ok_raw_json, Bin} -> jsx:decode(Bin, [{return_maps, true}])
          end,
    ?assertEqual(<<"updater">>, maps:get(<<"next">>, Map)),
    [In] = maps:get(<<"inputs">>, Map),
    ?assertEqual(false, maps:get(<<"has_utxo">>, In)),
    ?assertEqual(false, maps:get(<<"is_final">>, In)),
    ?assertEqual(<<"updater">>, maps:get(<<"next">>, In)).

combinepsbt_empty_array_is_minus8_test() ->
    Res = rpc(<<"combinepsbt">>, [[]]),
    ?assertEqual(
       {error, -8, <<"Parameter 'txs' cannot be empty">>},
       Res).

finalizepsbt_incomplete_exact_matches_core_test() ->
    Res = rpc(<<"finalizepsbt">>, [?PSBT_A]),
    ?assertMatch({ok, _}, Res),
    {ok, Map} = Res,
    ?assertEqual(false, maps:get(<<"complete">>, Map)),
    ?assertEqual(?PSBT_A, maps:get(<<"psbt">>, Map)),
    ?assertEqual(false, maps:is_key(<<"error">>, Map)),
    ?assertEqual(false, maps:is_key(<<"hex">>, Map)).

%% r5-probes.d/rawtx-psbt.jsonl bad-base64. Live FAIL was
%% error code -1 != Core's -22 because OTP 27 throws missing_padding
%% and the catch-all mapped that to RPC_MISC_ERROR.
finalizepsbt_bad_base64_is_minus22_test() ->
    Res = rpc(<<"finalizepsbt">>, [<<"notbase64!!">>]),
    ?assertMatch({error, -22, _}, Res),
    {error, -22, Msg} = Res,
    ?assertEqual(<<"TX decode failed invalid base64">>, Msg),
    ?assertEqual(Res, dispatch_rpc(<<"finalizepsbt">>, [<<"notbase64!!">>])).

%%% ===================================================================
%%% utxoupdatepsbt / descriptorprocesspsbt / signrawtransactionwithkey
%%% ===================================================================

utxoupdatepsbt_bad_base64_is_minus22_test() ->
    Res = rpc(<<"utxoupdatepsbt">>, [<<"notbase64!!">>]),
    ?assertMatch({error, -22, _}, Res).

utxoupdatepsbt_unknown_inputs_passthrough_is_psbt_string_test() ->
    Res = rpc(<<"utxoupdatepsbt">>, [?PSBT_A]),
    ?assertMatch({ok, B} when is_binary(B), Res),
    {ok, B64} = Res,
    ?assertEqual(<<"cHNidP8">>, binary:part(B64, 0, 7)).

descriptorprocesspsbt_bad_descriptor_is_minus5_test() ->
    Res = rpc(<<"descriptorprocesspsbt">>,
              [?PSBT_A, [<<"nonsense(desc)">>]]),
    ?assertMatch({error, -5, _}, Res),
    {error, -5, Msg} = Res,
    ?assertEqual(
       <<"'nonsense(desc)' is not a valid descriptor function">>, Msg),
    %% Live FAIL was -1 "Wrong number of arguments": the arity table
    %% required 4 args so dispatch never reached the -5 handler.
    ?assertEqual(Res, dispatch_rpc(<<"descriptorprocesspsbt">>,
                                   [?PSBT_A, [<<"nonsense(desc)">>]])).

%% r5-probes.d/rawtx-psbt.jsonl update-exact. Core ProcessPSBT with
%% bip32derivs=true attaches PSBT_OUT_BIP32_DERIVATION on the wpkh
%% output (WIF key 1 / G compressed, fingerprint HASH160[0..4]).
descriptorprocesspsbt_update_unknown_input_complete_false_test() ->
    Params = [?PSBT_A, [<<"wpkh(", ?WIF_PRIV1/binary, ")">>]],
    Res = rpc(<<"descriptorprocesspsbt">>, Params),
    ?assertEqual({ok, #{<<"psbt">> => ?PSBT_A_WP1_DERIV,
                        <<"complete">> => false}},
                 Res),
    ?assertEqual(Res, dispatch_rpc(<<"descriptorprocesspsbt">>, Params)).

signrawtransactionwithkey_bad_privkey_is_minus5_test() ->
    Res = rpc(<<"signrawtransactionwithkey">>, [?RAW_HEX, [<<"notakey">>]]),
    ?assertMatch({error, -5, _}, Res).

signrawtransactionwithkey_sign_complete_test() ->
    Prev = [#{<<"txid">> => <<"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">>,
              <<"vout">> => 0,
              <<"scriptPubKey">> => <<"0014751e76e8199196d454941c45d1b3a323f1433bd6">>,
              <<"amount">> => 0.002}],
    Res = rpc(<<"signrawtransactionwithkey">>, [?RAW_HEX, [?WIF_PRIV1], Prev]),
    ?assertMatch({ok, _}, Res),
    {ok, Map} = Res,
    ?assertEqual(true, maps:get(<<"complete">>, Map)),
    ?assertEqual(true, maps:is_key(<<"hex">>, Map)).

%%% ===================================================================
%%% createmultisig / deriveaddresses / getdescriptorinfo / getindexinfo
%%% ===================================================================

createmultisig_invalid_pubkey_is_minus5_test() ->
    Res = rpc(<<"createmultisig">>, [1, [<<"deadbeef">>]]),
    ?assertMatch({error, -5, _}, Res),
    {error, -5, Msg} = Res,
    ?assertNotEqual(nomatch, binary:match(Msg, <<"33 or 65 bytes">>)).

createmultisig_not_enough_keys_is_minus8_test() ->
    Res = rpc(<<"createmultisig">>, [3, [?KEY1, ?KEY2]]),
    ?assertMatch({error, -8, _}, Res),
    {error, -8, Msg} = Res,
    ?assertNotEqual(nomatch, binary:match(Msg, <<"not enough keys supplied">>)).

deriveaddresses_missing_checksum_is_minus5_test() ->
    Res = rpc(<<"deriveaddresses">>, [?DESC_NO_CSUM]),
    ?assertEqual({error, -5, <<"Missing checksum">>}, Res).

deriveaddresses_range_on_unranged_is_minus8_test() ->
    Res = rpc(<<"deriveaddresses">>, [?DESC_CSUM, [0, 2]]),
    ?assertEqual(
       {error, -8,
        <<"Range should not be specified for an un-ranged descriptor">>},
       Res).

getdescriptorinfo_invalid_descriptor_is_minus5_test() ->
    Res = rpc(<<"getdescriptorinfo">>, [<<"notadescriptor">>]),
    ?assertMatch({error, -5, _}, Res).

getdescriptorinfo_bad_checksum_is_minus5_test() ->
    Res = rpc(<<"getdescriptorinfo">>,
              [<<?DESC_NO_CSUM/binary, "#00000000">>]),
    ?assertMatch({error, -5, _}, Res).

getdescriptorinfo_success_exact_single_test() ->
    {ok, Obj} = rpc(<<"getdescriptorinfo">>, [?DESC_NO_CSUM]),
    Map = case Obj of
              L when is_list(L) -> maps:from_list(L);
              M when is_map(M) -> M
          end,
    ?assertEqual(?DESC_CSUM, maps:get(<<"descriptor">>, Map)),
    ?assertEqual(<<"e72f49hy">>, maps:get(<<"checksum">>, Map)),
    ?assertEqual(false, maps:get(<<"isrange">>, Map)),
    ?assertEqual(true, maps:get(<<"issolvable">>, Map)),
    ?assertEqual(false, maps:get(<<"hasprivatekeys">>, Map)).

getindexinfo_numeric_arg_is_minus3_test() ->
    Res = rpc(<<"getindexinfo">>, [123]),
    ?assertEqual(
       {error, -3,
        <<"JSON value of type number is not of expected type string">>},
       Res).

%%% ===================================================================
%%% signmessagewithprivkey
%%% ===================================================================

signmessagewithprivkey_zero_privkey_is_minus5_test() ->
    Res = rpc(<<"signmessagewithprivkey">>, [?ZERO_WIF, <<"x">>]),
    ?assertEqual({error, -5, <<"Invalid private key">>}, Res).

signmessagewithprivkey_success_exact_sig_test() ->
    Res = rpc(<<"signmessagewithprivkey">>,
              [<<"5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ">>,
               <<"hashhog r5 probe">>]),
    ?assertEqual({ok, ?CORE_SIG}, Res).
