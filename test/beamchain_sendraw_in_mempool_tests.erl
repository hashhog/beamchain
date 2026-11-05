%%% sendrawtransaction of a tx already in the mempool returns its txid.
%%%
%%% Core node/transaction.cpp BroadcastTransaction only runs the UTXO-set check
%%% and AcceptToMemoryPool when the wtxid is NOT already in the mempool;
%%% otherwise it re-relays and returns the txid. beamchain answered
%%% -27 "Transaction already in mempool" (Core regtest ratchet rows
%%% operator/sendrawtransaction/in-mempool and valid-no-cap).
-module(beamchain_sendraw_in_mempool_tests).
-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

tx() ->
    #transaction{version = 2, locktime = 0,
        inputs = [#tx_in{prev_out = #outpoint{hash = <<1:256>>, index = 0},
                         script_sig = <<>>, sequence = 16#fffffffd, witness = []}],
        outputs = [#tx_out{value = 1000, script_pubkey = <<0, 20, 0:160>>}]}.

hex(Tx) ->
    beamchain_serialize:hex_encode(beamchain_serialize:encode_transaction(Tx)).

setup() ->
    meck:new(beamchain_mempool, [passthrough, no_link]),
    meck:new(beamchain_chainstate, [passthrough, no_link]),
    meck:new(beamchain_peer_manager, [passthrough, no_link]),
    meck:expect(beamchain_peer_manager, announce_tx, fun(_) -> ok end),
    meck:expect(beamchain_chainstate, has_utxo, fun(_, _) -> true end).

cleanup(_) ->
    meck:unload(beamchain_mempool),
    meck:unload(beamchain_chainstate),
    meck:unload(beamchain_peer_manager).

in_mempool_test_() ->
    {foreach, fun setup/0, fun cleanup/1, [
      {"same wtxid in mempool: returns txid, no ATMP", fun() ->
          Tx = tx(),
          Txid = beamchain_serialize:tx_hash(Tx),
          W = beamchain_serialize:wtx_hash(Tx),
          meck:expect(beamchain_mempool, get_wtxid, fun(_) -> {ok, W} end),
          meck:expect(beamchain_mempool, has_tx, fun(_) -> true end),
          meck:expect(beamchain_mempool, accept_to_memory_pool,
                      fun(_) -> error(atmp_must_not_run) end),
          Expected = beamchain_serialize:hex_encode(
                       beamchain_serialize:reverse_bytes(Txid)),
          ?assertEqual({ok, Expected},
                       beamchain_rpc:rpc_sendrawtransaction([hex(Tx)]))
      end},
      {"same txid, different wtxid: not short-circuited, goes to ATMP", fun() ->
          Tx = tx(),
          meck:expect(beamchain_mempool, get_wtxid, fun(_) -> {ok, <<9:256>>} end),
          meck:expect(beamchain_mempool, has_tx, fun(_) -> true end),
          meck:expect(beamchain_mempool, accept_to_memory_pool,
                      fun(_) -> {error, 'txn-same-nonwitness-data-in-mempool'} end),
          ?assertMatch({error, _, _},
                       beamchain_rpc:rpc_sendrawtransaction([hex(Tx)]))
      end}]}.
