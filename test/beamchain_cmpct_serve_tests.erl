-module(beamchain_cmpct_serve_tests).

%% Serving side of BIP-152: getdata(MSG_CMPCT_BLOCK) -> cmpctblock within
%% MAX_CMPCTBLOCK_DEPTH of the tip, full block beyond it (Core
%% net_processing.cpp ProcessGetBlockData).  Pre-fix the node always sent the
%% full block, so a Core peer never received a cmpctblock / blocktxn.

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

tx(N) ->
    #transaction{version = 1,
                 inputs = [#tx_in{prev_out = #outpoint{hash = <<N:256>>, index = 0},
                                  script_sig = <<>>, sequence = 16#ffffffff,
                                  witness = undefined}],
                 outputs = [#tx_out{value = 1000 + N, script_pubkey = <<16#51>>}],
                 locktime = 0}.

block(NTx) ->
    #block{header = #block_header{version = 1, prev_hash = <<0:256>>,
                                  merkle_root = <<0:256>>, timestamp = 1296688602,
                                  bits = 16#1d00ffff, nonce = 7},
           transactions = [tx(I) || I <- lists:seq(1, NTx)]}.

within_depth_is_cmpctblock_test() ->
    B = block(4),
    {cmpctblock, #{prefilled_txns := [#{index := 0, tx := Cb}],
                   short_ids := Ids}} =
        beamchain_peer_manager:getdata_cmpct_msg(B, 100, 105),
    ?assertEqual(hd(B#block.transactions), Cb),
    ?assertEqual(3, length(Ids)).

beyond_depth_is_full_block_test() ->
    B = block(4),
    ?assertEqual({block, B}, beamchain_peer_manager:getdata_cmpct_msg(B, 99, 105)),
    ?assertEqual({block, B}, beamchain_peer_manager:getdata_cmpct_msg(B, -1, 105)).

short_ids_are_siphash_of_wtxid_test() ->
    B = block(4),
    {cmpctblock, #{nonce := Nonce, header := H, short_ids := Ids}} =
        beamchain_peer_manager:getdata_cmpct_msg(B, 105, 105),
    {K0, K1} = beamchain_compact_block:derive_siphash_key(H, Nonce),
    Expect = [beamchain_compact_block:compute_short_id(
                K0, K1, beamchain_serialize:wtx_hash(T))
              || T <- tl(B#block.transactions)],
    ?assertEqual(Expect, Ids).

wire_roundtrip_reconstructs_test() ->
    B = block(5),
    {cmpctblock, Msg} = beamchain_peer_manager:getdata_cmpct_msg(B, 1, 1),
    Wire = beamchain_p2p_msg:encode_payload(cmpctblock, Msg),
    {ok, Dec} = beamchain_p2p_msg:decode_payload(cmpctblock, Wire),
    {ok, St} = beamchain_compact_block:init_compact_block(Dec),
    %% only the coinbase is present; the other 4 are missing and in order
    ?assertEqual([1, 2, 3, 4], beamchain_compact_block:get_missing_indices(St)).
