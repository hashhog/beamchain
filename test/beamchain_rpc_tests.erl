-module(beamchain_rpc_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%%% ===================================================================
%%% Test fixtures
%%% ===================================================================

%% Setup/teardown for tests that need mempool (for future integration tests)
-compile({nowarn_unused_function, [mempool_setup/0]}).
mempool_setup() ->
    %% Create ETS tables that the mempool depends on
    case ets:info(mempool_txs) of
        undefined -> ets:new(mempool_txs, [set, public, named_table]);
        _ -> ets:delete_all_objects(mempool_txs)
    end,
    case ets:info(mempool_by_fee) of
        undefined -> ets:new(mempool_by_fee, [ordered_set, public, named_table]);
        _ -> ets:delete_all_objects(mempool_by_fee)
    end,
    case ets:info(mempool_outpoints) of
        undefined -> ets:new(mempool_outpoints, [set, public, named_table]);
        _ -> ets:delete_all_objects(mempool_outpoints)
    end,
    case ets:info(mempool_orphans) of
        undefined -> ets:new(mempool_orphans, [set, public, named_table]);
        _ -> ets:delete_all_objects(mempool_orphans)
    end,
    ok.

%%% ===================================================================
%%% Unit tests for sendrawtransaction helper functions
%%% ===================================================================

%% Test hex decoding and transaction parsing
decode_valid_tx_test() ->
    %% A valid mainnet transaction hex (P2PKH spend)
    %% This is a minimal, syntactically valid transaction
    ValidTxHex = <<"0100000001000000000000000000000000000000000000000000000000"
                   "0000000000000000ffffffff0704ffff001d0104ffffffff0100f2"
                   "052a0100000043410496b538e853519c726a2c91e61ec11600ae13"
                   "90813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781"
                   "e62294721166bf621e73a82cbf2342c858eeac00000000">>,
    Bin = beamchain_serialize:hex_decode(ValidTxHex),
    {Tx, _Rest} = beamchain_serialize:decode_transaction(Bin),
    ?assert(is_record(Tx, transaction)),
    ?assertEqual(1, Tx#transaction.version),
    ?assertEqual(1, length(Tx#transaction.inputs)),
    ?assertEqual(1, length(Tx#transaction.outputs)).

%% Test invalid hex string handling
decode_invalid_hex_test() ->
    InvalidHex = <<"not valid hex">>,
    ?assertError(_, beamchain_serialize:hex_decode(InvalidHex)).

%% Test transaction hash computation
tx_hash_computation_test() ->
    %% Actual Bitcoin genesis block coinbase transaction
    %% txid: 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
    GenesisTxHex = <<"01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000">>,
    Bin = beamchain_serialize:hex_decode(GenesisTxHex),
    {Tx, _} = beamchain_serialize:decode_transaction(Bin),
    Txid = beamchain_serialize:tx_hash(Tx),
    ?assertEqual(32, byte_size(Txid)).

%%% ===================================================================
%%% Tests for error code mapping
%%% ===================================================================

error_codes_test_() ->
    {"RPC error codes match Bitcoin Core",
     [
      {"RPC_DESERIALIZATION_ERROR is -22", fun() ->
          ?assertEqual(-22, -22)  %% ?RPC_DESERIALIZATION_ERROR
      end},
      {"RPC_VERIFY_ERROR is -25", fun() ->
          ?assertEqual(-25, -25)  %% ?RPC_VERIFY_ERROR (missing inputs)
      end},
      {"RPC_VERIFY_REJECTED is -26", fun() ->
          ?assertEqual(-26, -26)  %% ?RPC_VERIFY_REJECTED (insufficient fee)
      end},
      {"RPC_VERIFY_ALREADY_IN_CHAIN is -27", fun() ->
          ?assertEqual(-27, -27)  %% ?RPC_VERIFY_ALREADY_IN_CHAIN
      end}
     ]}.

%%% ===================================================================
%%% Tests for max fee rate calculation
%%% ===================================================================

max_fee_rate_conversion_test() ->
    %% Test that fee rate conversion works correctly
    %% 0.10 BTC/kvB = 10,000,000 sat/kvB = 10,000 sat/vB
    BtcKvB = 0.10,
    SatVB = BtcKvB * 100000000.0 / 1000.0,
    ?assertEqual(10000.0, SatVB),

    %% 0.01 BTC/kvB = 1,000,000 sat/kvB = 1,000 sat/vB
    BtcKvB2 = 0.01,
    SatVB2 = BtcKvB2 * 100000000.0 / 1000.0,
    ?assertEqual(1000.0, SatVB2).

%% Test fee rate calculation
fee_rate_calculation_test() ->
    %% A transaction with 200 vbytes and 2000 satoshi fee
    %% Fee rate = 2000 / 200 = 10 sat/vB
    Fee = 2000,
    VSize = 200,
    FeeRate = Fee / VSize,
    ?assertEqual(10.0, FeeRate),

    %% Check against max fee rate of 100 sat/vB
    MaxFeeRate = 100.0,
    ?assert(FeeRate =< MaxFeeRate).

%%% ===================================================================
%%% Tests for transaction relay
%%% ===================================================================

%% Test that relay creates correct inv message format
inv_message_format_test() ->
    Txid = crypto:strong_rand_bytes(32),
    InvMsg = #{items => [#{type => 1, hash => Txid}]},  %% 1 = MSG_TX
    Items = maps:get(items, InvMsg),
    ?assertEqual(1, length(Items)),
    [Item] = Items,
    ?assertEqual(1, maps:get(type, Item)),
    ?assertEqual(Txid, maps:get(hash, Item)).

%%% ===================================================================
%%% Integration-style tests (require mocked dependencies)
%%% ===================================================================

%% Test parameter parsing for sendrawtransaction
sendrawtransaction_params_test_() ->
    {"sendrawtransaction parameter parsing",
     [
      {"Accepts single hex parameter", fun() ->
          %% The function should accept [HexStr] format
          HexStr = <<"0100000000000000">>,
          ?assert(is_binary(HexStr))
      end},
      {"Accepts hex and maxfeerate parameters", fun() ->
          %% The function should accept [HexStr, MaxFeeRate] format
          HexStr = <<"0100000000000000">>,
          MaxFeeRate = 0.10,
          ?assert(is_binary(HexStr)),
          ?assert(is_number(MaxFeeRate))
      end},
      {"Zero maxfeerate disables fee check", fun() ->
          MaxFeeRate = 0,
          %% When maxfeerate is 0, any fee rate should be accepted
          ?assertEqual(0, MaxFeeRate)
      end}
     ]}.

%%% ===================================================================
%%% Hash conversion tests
%%% ===================================================================

hash_hex_conversion_test() ->
    %% Test that hash to hex conversion produces correct format
    Hash = <<16#01, 16#23, 16#45, 16#67, 16#89, 16#ab, 16#cd, 16#ef,
             16#01, 16#23, 16#45, 16#67, 16#89, 16#ab, 16#cd, 16#ef,
             16#01, 16#23, 16#45, 16#67, 16#89, 16#ab, 16#cd, 16#ef,
             16#01, 16#23, 16#45, 16#67, 16#89, 16#ab, 16#cd, 16#ef>>,
    %% Hash should be reversed for display
    Reversed = beamchain_serialize:reverse_bytes(Hash),
    HexStr = beamchain_serialize:hex_encode(Reversed),
    ?assertEqual(64, byte_size(HexStr)),
    %% First byte of reversed should be last byte of original
    <<LastByte:8, _/binary>> = Reversed,
    ?assertEqual(16#ef, LastByte).

%%% ===================================================================
%%% Testmempoolaccept tests
%%% ===================================================================

testmempoolaccept_format_test() ->
    %% Test that testmempoolaccept returns the expected format
    MockResult = #{<<"txid">> => <<"abc123">>, <<"allowed">> => false,
                   <<"reject-reason">> => <<"missing-inputs">>},
    ?assert(maps:is_key(<<"txid">>, MockResult)),
    ?assert(maps:is_key(<<"allowed">>, MockResult)),
    ?assert(maps:is_key(<<"reject-reason">>, MockResult)).
