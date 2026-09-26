-module(beamchain_getdata_wtx_tests).

%% getdata serving decision per inv type + BIP-339 tx announcement.
%%
%% Core reference (bitcoin-core/src/net_processing.cpp):
%%   ProcessGetData / FindTxForGetData:
%%     MSG_WTX (5)             hash is a WTXID -> mempool lookup by wtxid,
%%                             serialized WITH witness
%%     MSG_WITNESS_TX          txid lookup, WITH witness
%%     MSG_TX (1)              txid lookup, WITHOUT witness
%%                             (`inv.IsMsgTx() ? TX_NO_WITNESS : TX_WITH_WITNESS`)
%%   ProcessGetBlockData:
%%     MSG_BLOCK               TX_NO_WITNESS(*pblock)
%%     MSG_WITNESS_BLOCK       TX_WITH_WITNESS(*pblock)
%%   INV handler: a wtxidrelay peer ignores MSG_TX invs outright
%%     (`if (peer.m_wtxid_relay) { if (inv.IsMsgTx()) continue; }`), so the
%%     announcement to such a peer must be MSG_WTX + wtxid.
%%
%% Pre-fix (beamchain d571fe3): MSG_WTX fell to the catch-all -> notfound;
%% MSG_TX and MSG_BLOCK were served with witness; every tx announcement was a
%% MSG_TX + txid broadcast regardless of the peer's wtxidrelay flag.

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% Duplicate of beamchain_mempool's private record (same trick as
%% beamchain_mempool_w96_atmp_tests) so the mempool ETS table can be seeded.
-record(mempool_entry, {
    txid, wtxid, tx, fee, size, vsize, weight, fee_rate,
    time_added, height_added,
    ancestor_count, ancestor_size, ancestor_fee,
    descendant_count, descendant_size, descendant_fee,
    spends_coinbase, rbf_signaling, adj_weight
}).

%%% ---------------------------------------------------------------------
%%% Fixtures
%%% ---------------------------------------------------------------------

segwit_tx() ->
    #transaction{
        version = 2,
        inputs = [#tx_in{prev_out = #outpoint{hash = <<7:256>>, index = 0},
                         script_sig = <<>>,
                         sequence = 16#fffffffd,
                         witness = [<<1,2,3,4>>, <<5:264>>]}],
        outputs = [#tx_out{value = 4999900000,
                           script_pubkey = <<0, 20, 9:160>>}],
        locktime = 0}.

txid(Tx)  -> beamchain_serialize:tx_hash(Tx).
wtxid(Tx) -> beamchain_serialize:wtx_hash(Tx).

with_witness(Tx) -> beamchain_serialize:encode_transaction(Tx, witness).
no_witness(Tx)   -> beamchain_serialize:encode_transaction(Tx, no_witness).

%% Lookups keyed like the real mempool: txid table and wtxid table.
by_txid(Tx)  -> T = txid(Tx),  fun(H) when H =:= T -> {ok, Tx}; (_) -> not_found end.
by_wtxid(Tx) -> W = wtxid(Tx), fun(H) when H =:= W -> {ok, Tx}; (_) -> not_found end.

%% Wire bytes of the reply the handler would send.
wire({Cmd, Payload}) -> {Cmd, beamchain_p2p_msg:encode_payload(Cmd, Payload)}.

serve(Type, Hash, Tx) ->
    beamchain_peer_manager:getdata_tx_msg(Type, Hash, by_txid(Tx), by_wtxid(Tx)).

%%% ---------------------------------------------------------------------
%%% Fixture sanity (negative control: the two encodings really differ)
%%% ---------------------------------------------------------------------

fixture_is_segwit_test() ->
    Tx = segwit_tx(),
    ?assertNotEqual(txid(Tx), wtxid(Tx)),
    ?assertNotEqual(with_witness(Tx), no_witness(Tx)).

%%% ---------------------------------------------------------------------
%%% getdata tx items
%%% ---------------------------------------------------------------------

msg_wtx_found_by_wtxid_served_with_witness_test() ->
    Tx = segwit_tx(),
    {ok, Msg} = serve(?MSG_WTX, wtxid(Tx), Tx),
    ?assertEqual({tx, with_witness(Tx)}, wire(Msg)).

msg_wtx_with_a_txid_is_notfound_test() ->
    %% MSG_WTX carries a wtxid; a txid must not match (Core looks up the
    %% wtxid index only).
    Tx = segwit_tx(),
    ?assertEqual(notfound, serve(?MSG_WTX, txid(Tx), Tx)).

msg_wtx_unknown_is_notfound_test() ->
    ?assertEqual(notfound, serve(?MSG_WTX, <<0:256>>, segwit_tx())).

msg_witness_tx_by_txid_served_with_witness_test() ->
    Tx = segwit_tx(),
    {ok, Msg} = serve(?MSG_WITNESS_TX, txid(Tx), Tx),
    ?assertEqual({tx, with_witness(Tx)}, wire(Msg)).

msg_witness_tx_with_a_wtxid_is_notfound_test() ->
    Tx = segwit_tx(),
    ?assertEqual(notfound, serve(?MSG_WITNESS_TX, wtxid(Tx), Tx)).

msg_tx_by_txid_served_without_witness_test() ->
    Tx = segwit_tx(),
    {ok, Msg} = serve(?MSG_TX, txid(Tx), Tx),
    ?assertEqual({tx, no_witness(Tx)}, wire(Msg)).

msg_tx_unknown_is_notfound_test() ->
    ?assertEqual(notfound, serve(?MSG_TX, <<0:256>>, segwit_tx())).

other_types_are_notfound_test() ->
    Tx = segwit_tx(),
    ?assertEqual(notfound, serve(?MSG_FILTERED_BLOCK, txid(Tx), Tx)),
    ?assertEqual(notfound, serve(?MSG_CMPCT_BLOCK, txid(Tx), Tx)),
    ?assertEqual(notfound, serve(16#12345, wtxid(Tx), Tx)).

%%% ---------------------------------------------------------------------
%%% getdata block items
%%% ---------------------------------------------------------------------

segwit_block() ->
    Coinbase = #transaction{
        version = 2,
        inputs = [#tx_in{prev_out = #outpoint{hash = <<0:256>>, index = 16#ffffffff},
                         script_sig = <<1, 101>>, sequence = 16#ffffffff,
                         witness = [<<0:256>>]}],
        outputs = [#tx_out{value = 5000000000, script_pubkey = <<16#51>>}],
        locktime = 0},
    #block{header = #block_header{version = 16#20000000, prev_hash = <<1:256>>,
                                  merkle_root = <<2:256>>, timestamp = 1700000000,
                                  bits = 16#207fffff, nonce = 0},
           transactions = [Coinbase, segwit_tx()]}.

msg_block_served_without_witness_test() ->
    B = segwit_block(),
    Msg = beamchain_peer_manager:getdata_block_msg(?MSG_BLOCK, B),
    ?assertEqual({block, beamchain_serialize:encode_block(B, no_witness)}, wire(Msg)),
    ?assertNotEqual(beamchain_serialize:encode_block(B, no_witness),
                    beamchain_serialize:encode_block(B)).

msg_witness_block_served_with_witness_test() ->
    B = segwit_block(),
    Msg = beamchain_peer_manager:getdata_block_msg(?MSG_WITNESS_BLOCK, B),
    ?assertEqual({block, beamchain_serialize:encode_block(B)}, wire(Msg)).

no_witness_block_roundtrips_as_legacy_test() ->
    %% Stripped block decodes back to the same txids and no witnesses.
    B = segwit_block(),
    {B2, <<>>} = beamchain_serialize:decode_block(
                   beamchain_serialize:encode_block(B, no_witness)),
    ?assertEqual([txid(T) || T <- B#block.transactions],
                 [txid(T) || T <- B2#block.transactions]),
    ?assert(lists:all(fun(#transaction{inputs = Ins}) ->
                          lists:all(fun(#tx_in{witness = W}) ->
                                        W =:= undefined orelse W =:= []
                                    end, Ins)
                      end, B2#block.transactions)).

%%% ---------------------------------------------------------------------
%%% Announcement (BIP-339): per-peer inv type
%%% ---------------------------------------------------------------------

announce_test_() ->
    {setup,
     fun() ->
         case ets:info(mempool_txs) of
             undefined -> ok;
             _ -> ets:delete(mempool_txs)
         end,
         ets:new(mempool_txs, [set, public, named_table]),
         beamchain_peer_manager:test_ensure_peer_table(),
         ok
     end,
     fun(_) ->
         ets:delete(mempool_txs),
         ets:delete_all_objects(beamchain_peers)
     end,
     [fun announce_uses_wtx_for_wtxidrelay_peer/0,
      fun announce_uses_tx_for_legacy_peer/0,
      fun announce_skips_tx_not_in_mempool/0]}.

seed_mempool(Tx) ->
    ets:insert(mempool_txs, {txid(Tx), #mempool_entry{txid = txid(Tx),
                                                      wtxid = wtxid(Tx),
                                                      tx = Tx}}).

fake_peer(WtxidRelay) ->
    Parent = self(),
    Pid = spawn(fun() ->
        receive {'$gen_cast', {send, Cmd, Payload}} -> Parent ! {sent, self(), Cmd, Payload}
        after 2000 -> Parent ! {sent, self(), none, none}
        end
    end),
    beamchain_peer_manager:test_insert_peer(Pid, inbound, full_relay, normal),
    beamchain_peer_manager:test_set_peer_info(Pid, #{wtxidrelay => WtxidRelay}),
    Pid.

sent(Pid) -> receive {sent, Pid, Cmd, Payload} -> {Cmd, Payload} after 3000 -> timeout end.

announce_uses_wtx_for_wtxidrelay_peer() ->
    ets:delete_all_objects(beamchain_peers),
    Tx = segwit_tx(), seed_mempool(Tx),
    P = fake_peer(true),
    ok = beamchain_peer_manager:announce_tx(txid(Tx)),
    ?assertEqual({inv, #{items => [#{type => ?MSG_WTX, hash => wtxid(Tx)}]}}, sent(P)).

announce_uses_tx_for_legacy_peer() ->
    ets:delete_all_objects(beamchain_peers),
    Tx = segwit_tx(), seed_mempool(Tx),
    P = fake_peer(false),
    ok = beamchain_peer_manager:announce_tx(txid(Tx)),
    ?assertEqual({inv, #{items => [#{type => ?MSG_TX, hash => txid(Tx)}]}}, sent(P)).

announce_skips_tx_not_in_mempool() ->
    ets:delete_all_objects(beamchain_peers),
    P = fake_peer(true),
    ok = beamchain_peer_manager:announce_tx(<<42:256>>),
    ?assertEqual({none, none}, sent(P)).
