-module(beamchain_getrawtransaction_in_block_msg_tests).
%%% getrawtransaction <txid> true <blockhash> for a txid that is not in the block.
%%%
%%% Core rpc/rawtransaction.cpp builds errmsg = "No such transaction found in
%%% the provided block" and throws RPC_INVALID_ADDRESS_OR_KEY (-5) with
%%% errmsg + ". Use gettransaction for wallet transactions.".  beamchain left
%%% the suffix off (Core regtest rows operator/getrawtransaction/wrong-block and
%%% unknown-in-block, field `message`).
-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

-define(BLOCK_HEX, <<"0707070707070707070707070707070707070707070707070707070707070707">>).
-define(MISSING_TXID, <<"2222222222222222222222222222222222222222222222222222222222222222">>).

tx_not_in_block_test_() ->
    {setup,
     fun() ->
         ok = meck:new(beamchain_db, [no_link]),
         ok = meck:expect(beamchain_db, get_block,
                          fun(_) -> {ok, #block{transactions = []}} end),
         ok = meck:expect(beamchain_db, get_block_index_by_hash,
                          fun(_) -> not_found end)
     end,
     fun(_) -> meck:unload(beamchain_db) end,
     [{"verbose, unknown txid in a provided block",
       fun() ->
           ?assertEqual({error, -5,
                         <<"No such transaction found in the provided block. "
                           "Use gettransaction for wallet transactions.">>},
                        beamchain_rpc:rpc_getrawtransaction(
                          [?MISSING_TXID, true, ?BLOCK_HEX]))
       end},
      {"hex mode, unknown txid in a provided block",
       fun() ->
           ?assertEqual({error, -5,
                         <<"No such transaction found in the provided block. "
                           "Use gettransaction for wallet transactions.">>},
                        beamchain_rpc:rpc_getrawtransaction(
                          [?MISSING_TXID, false, ?BLOCK_HEX]))
       end}]}.
