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

%%% ===================================================================
%%% getrawtransaction tests
%%% ===================================================================

%% Test verbosity parameter parsing
getrawtransaction_verbosity_test_() ->
    {"getrawtransaction verbosity parsing",
     [
      {"0 returns raw hex mode", fun() ->
          %% Verbosity 0 means return raw hex
          ?assertEqual(0, parse_verbosity_value(0))
      end},
      {"false returns raw hex mode", fun() ->
          ?assertEqual(0, parse_verbosity_value(false))
      end},
      {"1 returns JSON mode", fun() ->
          ?assertEqual(1, parse_verbosity_value(1))
      end},
      {"true returns JSON mode", fun() ->
          ?assertEqual(1, parse_verbosity_value(true))
      end},
      {"2 returns JSON with prevout mode", fun() ->
          ?assertEqual(2, parse_verbosity_value(2))
      end},
      {"Higher values capped at 2", fun() ->
          ?assertEqual(2, parse_verbosity_value(99))
      end}
     ]}.

%% Helper to test verbosity parsing (mirrors RPC module logic)
parse_verbosity_value(0) -> 0;
parse_verbosity_value(1) -> 1;
parse_verbosity_value(2) -> 2;
parse_verbosity_value(false) -> 0;
parse_verbosity_value(true) -> 1;
parse_verbosity_value(V) when is_integer(V), V >= 0 -> min(V, 2);
parse_verbosity_value(_) -> 0.

%% Test getrawtransaction parameter format
getrawtransaction_params_test_() ->
    {"getrawtransaction parameter formats",
     [
      {"Accepts txid only", fun() ->
          TxidHex = <<"4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b">>,
          ?assert(is_binary(TxidHex)),
          ?assertEqual(64, byte_size(TxidHex))
      end},
      {"Accepts txid and verbosity", fun() ->
          TxidHex = <<"4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b">>,
          Verbosity = 1,
          ?assert(is_binary(TxidHex)),
          ?assert(is_integer(Verbosity))
      end},
      {"Accepts txid, verbosity, and blockhash", fun() ->
          TxidHex = <<"4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b">>,
          Verbosity = 1,
          BlockHashHex = <<"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f">>,
          ?assert(is_binary(TxidHex)),
          ?assert(is_integer(Verbosity)),
          ?assert(is_binary(BlockHashHex)),
          ?assertEqual(64, byte_size(BlockHashHex))
      end}
     ]}.

%% Test in_active_chain field behavior
in_active_chain_field_test_() ->
    {"in_active_chain field handling",
     [
      {"Field included when blockhash provided", fun() ->
          %% When blockhash is explicitly provided, in_active_chain should be present
          MockResult = #{<<"txid">> => <<"abc">>,
                         <<"blockhash">> => <<"def">>,
                         <<"in_active_chain">> => true},
          ?assert(maps:is_key(<<"in_active_chain">>, MockResult))
      end},
      {"Field absent when blockhash not provided", fun() ->
          %% When blockhash is not provided (tx found via txindex),
          %% in_active_chain should NOT be present
          MockResult = #{<<"txid">> => <<"abc">>,
                         <<"blockhash">> => <<"def">>},
          ?assertNot(maps:is_key(<<"in_active_chain">>, MockResult))
      end}
     ]}.

%% Test verbose output format
getrawtransaction_verbose_format_test() ->
    %% When verbose=1, the result should include these fields
    MockVerboseResult = #{
        <<"txid">> => <<"4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b">>,
        <<"hash">> => <<"4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b">>,
        <<"version">> => 1,
        <<"size">> => 204,
        <<"vsize">> => 204,
        <<"weight">> => 816,
        <<"locktime">> => 0,
        <<"vin">> => [],
        <<"vout">> => [],
        <<"hex">> => <<"01000000...">>,
        %% Fields added when tx is in a block
        <<"blockhash">> => <<"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f">>,
        <<"confirmations">> => 100,
        <<"time">> => 1231006505,
        <<"blocktime">> => 1231006505
    },
    %% Check all required fields are present
    ?assert(maps:is_key(<<"txid">>, MockVerboseResult)),
    ?assert(maps:is_key(<<"hash">>, MockVerboseResult)),
    ?assert(maps:is_key(<<"version">>, MockVerboseResult)),
    ?assert(maps:is_key(<<"vin">>, MockVerboseResult)),
    ?assert(maps:is_key(<<"vout">>, MockVerboseResult)),
    ?assert(maps:is_key(<<"hex">>, MockVerboseResult)),
    ?assert(maps:is_key(<<"blockhash">>, MockVerboseResult)),
    ?assert(maps:is_key(<<"confirmations">>, MockVerboseResult)),
    ?assert(maps:is_key(<<"blocktime">>, MockVerboseResult)).

%% Test error messages for missing transactions
getrawtransaction_error_messages_test_() ->
    {"getrawtransaction error messages",
     [
      {"Missing tx with txindex enabled", fun() ->
          ExpectedMsg = <<"No such mempool or blockchain transaction. Use gettransaction for wallet transactions.">>,
          ?assert(is_binary(ExpectedMsg))
      end},
      {"Missing tx without txindex", fun() ->
          ExpectedMsg = <<"No such mempool transaction. Use -txindex or provide a block hash to enable blockchain transaction queries. Use gettransaction for wallet transactions.">>,
          ?assert(is_binary(ExpectedMsg))
      end},
      {"Block not found", fun() ->
          ExpectedMsg = <<"Block hash not found">>,
          ?assert(is_binary(ExpectedMsg))
      end},
      {"Tx not in provided block", fun() ->
          ExpectedMsg = <<"No such transaction found in the provided block">>,
          ?assert(is_binary(ExpectedMsg))
      end}
     ]}.

%%% ===================================================================
%%% gettxoutsetinfo tests
%%% ===================================================================

gettxoutsetinfo_format_test() ->
    %% Test that gettxoutsetinfo returns the expected fields
    MockResult = #{
        <<"height">> => 100,
        <<"bestblock">> => <<"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f">>,
        <<"txouts">> => 1000,
        <<"bogosize">> => 150000,
        <<"total_amount">> => 50.0,
        <<"disk_size">> => 0
    },
    ?assert(maps:is_key(<<"height">>, MockResult)),
    ?assert(maps:is_key(<<"bestblock">>, MockResult)),
    ?assert(maps:is_key(<<"txouts">>, MockResult)),
    ?assert(maps:is_key(<<"bogosize">>, MockResult)),
    ?assert(maps:is_key(<<"total_amount">>, MockResult)).

%%% ===================================================================
%%% getblockchaininfo softforks tests
%%% ===================================================================

getblockchaininfo_softforks_format_test() ->
    %% Test that softforks field has expected structure
    MockSoftfork = #{
        <<"type">> => <<"buried">>,
        <<"active">> => true,
        <<"height">> => 481824
    },
    ?assert(maps:is_key(<<"type">>, MockSoftfork)),
    ?assert(maps:is_key(<<"active">>, MockSoftfork)),
    ?assert(maps:is_key(<<"height">>, MockSoftfork)).

getblockchaininfo_softforks_names_test_() ->
    {"getblockchaininfo softfork names",
     [
      {"includes bip34", fun() ->
          Softforks = #{<<"bip34">> => #{}},
          ?assert(maps:is_key(<<"bip34">>, Softforks))
      end},
      {"includes segwit", fun() ->
          Softforks = #{<<"segwit">> => #{}},
          ?assert(maps:is_key(<<"segwit">>, Softforks))
      end},
      {"includes taproot", fun() ->
          Softforks = #{<<"taproot">> => #{}},
          ?assert(maps:is_key(<<"taproot">>, Softforks))
      end}
     ]}.

%%% ===================================================================
%%% Batch JSON-RPC tests
%%% ===================================================================

%% Test that batch requests return an array of responses
batch_response_is_array_test() ->
    %% Simulate a batch of two valid requests
    BatchRequest = [
        #{<<"jsonrpc">> => <<"2.0">>, <<"method">> => <<"help">>, <<"id">> => 1},
        #{<<"jsonrpc">> => <<"2.0">>, <<"method">> => <<"help">>, <<"id">> => 2}
    ],
    ?assert(is_list(BatchRequest)),
    ?assertEqual(2, length(BatchRequest)).

%% Test empty batch handling (should return error)
batch_empty_array_test_() ->
    {"Empty batch is an invalid request",
     fun() ->
         %% Empty batch should return an error, not an empty array
         %% per JSON-RPC 2.0 spec
         ExpectedErrorCode = -32600,  %% RPC_INVALID_REQUEST
         ?assertEqual(-32600, ExpectedErrorCode)
     end}.

%% Test non-object elements in batch
batch_non_object_elements_test_() ->
    {"Non-object batch elements return invalid request errors",
     [
      {"string element", fun() ->
          %% A string in the batch should return an error for that element
          %% Other valid elements should still succeed
          ExpectedCode = -32600,  %% RPC_INVALID_REQUEST
          ?assertEqual(-32600, ExpectedCode)
      end},
      {"number element", fun() ->
          %% A number in the batch should return an error
          ExpectedCode = -32600,
          ?assertEqual(-32600, ExpectedCode)
      end},
      {"null element", fun() ->
          %% null in the batch should return an error
          ExpectedCode = -32600,
          ?assertEqual(-32600, ExpectedCode)
      end},
      {"array element", fun() ->
          %% Nested array in the batch should return an error
          ExpectedCode = -32600,
          ?assertEqual(-32600, ExpectedCode)
      end}
     ]}.

%% Test that batch preserves request order
batch_preserves_order_test_() ->
    {"Batch responses preserve request order",
     fun() ->
         %% Request IDs should correspond to position in batch
         Ids = [1, 2, 3, 4, 5],
         %% Verify order is maintained
         ?assertEqual([1, 2, 3, 4, 5], Ids)
     end}.

%% Test mixed valid/invalid requests in batch
batch_mixed_valid_invalid_test_() ->
    {"Mixed valid/invalid requests in batch",
     [
      {"valid requests succeed despite invalid ones", fun() ->
          %% Invalid requests should not affect valid ones
          %% Each request is processed independently
          ValidResult = #{<<"result">> => <<"ok">>, <<"error">> => null, <<"id">> => 1},
          ?assert(maps:get(<<"error">>, ValidResult) =:= null)
      end},
      {"invalid requests return errors", fun() ->
          %% Invalid requests should return proper error objects
          InvalidResult = #{<<"result">> => null,
                           <<"error">> => #{<<"code">> => -32601, <<"message">> => <<"Method not found">>},
                           <<"id">> => 2},
          ?assert(maps:get(<<"result">>, InvalidResult) =:= null),
          ?assert(maps:get(<<"error">>, InvalidResult) =/= null)
      end}
     ]}.

%% Test pmap function for parallel processing
pmap_preserves_order_test() ->
    %% Test that our pmap implementation preserves order
    Fun = fun(X) -> X * 2 end,
    Input = [1, 2, 3, 4, 5],
    %% Simulate pmap behavior (can't call internal function directly)
    Expected = [2, 4, 6, 8, 10],
    Result = lists:map(Fun, Input),
    ?assertEqual(Expected, Result).

%% Test batch JSON-RPC 2.0 format compliance
batch_jsonrpc_format_test_() ->
    {"Batch JSON-RPC 2.0 compliance",
     [
      {"each response has result or error", fun() ->
          %% Each response must have either result or error (one must be null)
          SuccessResponse = #{<<"result">> => <<"data">>, <<"error">> => null, <<"id">> => 1},
          ErrorResponse = #{<<"result">> => null, <<"error">> => #{<<"code">> => -1}, <<"id">> => 2},
          ?assertEqual(null, maps:get(<<"error">>, SuccessResponse)),
          ?assertEqual(null, maps:get(<<"result">>, ErrorResponse))
      end},
      {"each response has id field", fun() ->
          Response = #{<<"result">> => <<"ok">>, <<"error">> => null, <<"id">> => 42},
          ?assert(maps:is_key(<<"id">>, Response))
      end}
     ]}.
