%%% sendrawtransaction of a tx already in the mempool returns its txid.
%%%
%%% Core node/transaction.cpp BroadcastTransaction only runs AcceptToMemoryPool
%%% when no mempool entry has this txid (witness is not compared); otherwise it
%%% reannounces the mempool entry's wtxid and returns the txid. beamchain answered
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
      {"same txid, different wtxid in mempool: returns txid, no ATMP", fun() ->
          %% Core BroadcastTransaction keys on the txid: a different witness
          %% is still "already in mempool", reannounced with the mempool
          %% entry's wtxid, and the call returns the txid.
          Tx = tx(),
          Txid = beamchain_serialize:tx_hash(Tx),
          ?assertNotEqual(<<9:256>>, beamchain_serialize:wtx_hash(Tx)),
          %% No confirmed outputs, so only the mempool hit can short-circuit.
          meck:expect(beamchain_chainstate, has_utxo, fun(_, _) -> false end),
          meck:expect(beamchain_mempool, get_wtxid, fun(_) -> {ok, <<9:256>>} end),
          meck:expect(beamchain_mempool, has_tx, fun(_) -> true end),
          meck:expect(beamchain_mempool, accept_to_memory_pool,
                      fun(_) -> error(atmp_must_not_run) end),
          Expected = beamchain_serialize:hex_encode(
                       beamchain_serialize:reverse_bytes(Txid)),
          ?assertEqual({ok, Expected},
                       beamchain_rpc:rpc_sendrawtransaction([hex(Tx)])),
          ?assertEqual(0, meck:num_calls(beamchain_mempool,
                                         accept_to_memory_pool, '_')),
          ?assert(meck:called(beamchain_peer_manager, announce_tx, [Txid]))
      end},
      {"txid not in mempool: still goes to ATMP", fun() ->
          Tx = tx(),
          meck:expect(beamchain_mempool, get_wtxid, fun(_) -> not_found end),
          meck:expect(beamchain_mempool, has_tx, fun(_) -> false end),
          meck:expect(beamchain_chainstate, has_utxo, fun(_, _) -> false end),
          meck:expect(beamchain_mempool, accept_to_memory_pool,
                      fun(_) -> {error, missing_inputs} end),
          ?assertMatch({error, _, _},
                       beamchain_rpc:rpc_sendrawtransaction([hex(Tx), 0])),
          ?assert(meck:num_calls(beamchain_mempool,
                                 accept_to_memory_pool, '_') >= 1)
      end}]}.
