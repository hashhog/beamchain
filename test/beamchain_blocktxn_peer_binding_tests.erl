%%% BIP152 blocktxn must come from the peer we sent getblocktxn to.
%%%
%%% do_handle_cmpctblock stores a partial reconstruction in pending_compact as
%%% {PartialState, RequestedAt, RequestPeer} and sends getblocktxn to that
%%% peer. handle_blocktxn_received looked the entry up by block hash only and
%%% never compared RequestPeer, so a blocktxn from ANY peer for that hash
%%% completed (or, with a bad tx list, tore down) a reconstruction that was
%%% asked of someone else: the stranger's txs went to fill_block, a failed
%%% fill scored the stranger, dropped the honest peer's pending state and
%%% re-requested the whole block from the stranger. The honest peer's real
%%% blocktxn then arrived to an empty pending_compact and was discarded.
%%% do_handle_cmpctblock also overwrote the pending entry when a second peer
%%% sent a cmpctblock for the same hash, so a stranger could make itself the
%%% stored requester first and get past a sender check.
%%%
%%% Core keys partial blocks per peer: ProcessMessage(BLOCKTXN) only proceeds
%%% when mapBlocksInFlight holds an entry for this hash whose node id is the
%%% sender's and which has a partialBlock (requested_block_from_this_peer);
%%% otherwise it logs "sent us block transactions for block we weren't
%%% expecting" and returns, with no misbehavior score
%%% (net_processing.cpp, ProcessMessage BLOCKTXN).
%%%
%%% beamchain_compact_block and beamchain_peer are mocked so the test drives
%%% only block_sync's bookkeeping: the cmpctblock is always "partial, missing
%%% index 1", and fill_block always fails, so every blocktxn that reaches
%%% fill_block is visible as a call and as a misbehavior score.
-module(beamchain_blocktxn_peer_binding_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-define(HASH, <<42:256>>).
-define(HEIGHT, 100).

cmpct() ->
    #{header => #block_header{version = 1, prev_hash = <<0:256>>,
                              merkle_root = <<1:256>>,
                              timestamp = 1296688602,
                              bits = 16#1d00ffff, nonce = 0},
      nonce => 0, short_ids => [1, 2], prefilled_txns => []}.

dummy_peer() ->
    spawn(fun() -> receive stop -> ok end end).

blocktxn(Txns) ->
    #{block_hash => ?HASH, transactions => Txns}.

setup() ->
    Self = self(),
    lists:foreach(fun(M) -> {module, M} = code:ensure_loaded(M) end,
                  [beamchain_peer, beamchain_chainstate,
                   beamchain_compact_block]),
    ok = meck:new(beamchain_peer, [no_link, passthrough]),
    ok = meck:new(beamchain_chainstate, [no_link, passthrough]),
    ok = meck:new(beamchain_compact_block, [no_link, passthrough]),
    ok = meck:expect(beamchain_peer, send_message,
                     fun(P, Msg) -> Self ! {sent, P, Msg}, ok end),
    ok = meck:expect(beamchain_peer, add_misbehavior,
                     fun(P, Score) -> Self ! {scored, P, Score}, ok end),
    ok = meck:expect(beamchain_chainstate, get_tip_height,
                     fun() -> {ok, ?HEIGHT} end),
    ok = meck:expect(beamchain_compact_block, init_compact_block,
                     fun(_) -> {ok, compact_state} end),
    ok = meck:expect(beamchain_compact_block, try_reconstruct,
                     fun(_, _) -> {partial, partial_state} end),
    ok = meck:expect(beamchain_compact_block, get_missing_indices,
                     fun(_) -> [1] end),
    ok = meck:expect(beamchain_compact_block, fill_block,
                     fun(_, Txns) -> Self ! {filled, Txns},
                                     {error, merkle_mismatch} end),
    ok.

cleanup() ->
    catch meck:unload(beamchain_compact_block),
    catch meck:unload(beamchain_chainstate),
    catch meck:unload(beamchain_peer).

flush() ->
    receive _ -> flush() after 0 -> ok end.

%% Asked = the peer the cmpctblock came from (and getblocktxn went to).
pending_state(Asked) ->
    S0 = beamchain_block_sync:test_state(#{status => syncing}),
    S1 = beamchain_block_sync:do_handle_cmpctblock(Asked, cmpct(), ?HASH,
                                                   ?HEIGHT, S0),
    receive
        {sent, Asked, {getblocktxn, #{block_hash := ?HASH}}} -> ok
    after 1000 -> ?assert(false)  %% getblocktxn never went to Asked
    end,
    flush(),
    S1.

cast_blocktxn(Peer, Txns, State) ->
    {noreply, S} = beamchain_block_sync:handle_cast(
                     {blocktxn, Peer, blocktxn(Txns)}, State),
    S.

with_mocks(Name, Fun) ->
    {Name, {timeout, 60, fun() ->
        setup(),
        try Fun() after cleanup() end
    end}}.

%% A blocktxn from a peer we did not ask is ignored: not handed to fill_block,
%% nobody scored, no full-block getdata sent to the stranger.
blocktxn_from_other_peer_is_ignored_test_() ->
    with_mocks("blocktxn_from_other_peer_is_ignored", fun() ->
        Asked = dummy_peer(), Stranger = dummy_peer(),
        S1 = pending_state(Asked),
        _S2 = cast_blocktxn(Stranger, [stranger_tx], S1),
        ?assertEqual(0, meck:num_calls(beamchain_compact_block, fill_block,
                                       '_')),
        ?assertEqual(0, meck:num_calls(beamchain_peer, add_misbehavior, '_')),
        ?assertEqual(0, meck:num_calls(beamchain_peer, send_message,
                                       [Stranger, '_']))
    end).

%% ...and it does not corrupt the reconstruction: the asked peer's blocktxn,
%% arriving afterwards, still reaches fill_block with that peer's txs.
blocktxn_from_other_peer_keeps_reconstruction_test_() ->
    with_mocks("blocktxn_from_other_peer_keeps_reconstruction", fun() ->
        Asked = dummy_peer(), Stranger = dummy_peer(),
        S1 = pending_state(Asked),
        S2 = cast_blocktxn(Stranger, [stranger_tx], S1),
        _S3 = cast_blocktxn(Asked, [asked_tx], S2),
        ?assertEqual(0, meck:num_calls(beamchain_compact_block, fill_block,
                                       [partial_state, [stranger_tx]])),
        ?assertEqual(1, meck:num_calls(beamchain_compact_block, fill_block,
                                       [partial_state, [asked_tx]]))
    end).

%% A stranger cannot rebind the reconstruction to itself by sending its own
%% cmpctblock for the same hash first: the pending entry is not overwritten,
%% no getblocktxn goes to the stranger, its blocktxn is then ignored, and the
%% asked peer's blocktxn is still the one filled.
cmpctblock_from_other_peer_does_not_take_over_test_() ->
    with_mocks("cmpctblock_from_other_peer_does_not_take_over", fun() ->
        Asked = dummy_peer(), Stranger = dummy_peer(),
        S1 = pending_state(Asked),
        S2 = beamchain_block_sync:do_handle_cmpctblock(Stranger, cmpct(),
                                                       ?HASH, ?HEIGHT, S1),
        S3 = cast_blocktxn(Stranger, [stranger_tx], S2),
        _S4 = cast_blocktxn(Asked, [asked_tx], S3),
        ?assertEqual(0, meck:num_calls(beamchain_peer, send_message,
                                       [Stranger, '_'])),
        ?assertEqual(0, meck:num_calls(beamchain_compact_block, fill_block,
                                       [partial_state, [stranger_tx]])),
        ?assertEqual(1, meck:num_calls(beamchain_compact_block, fill_block,
                                       [partial_state, [asked_tx]]))
    end).

%% Control: the asked peer's blocktxn is still processed, and a bad one is
%% still scored 10 and falls back to a full-block getdata to that peer
%% (Core READ_STATUS_FAILED). The binding narrows who may answer; it does not
%% switch the handler off.
blocktxn_from_asked_peer_is_processed_test_() ->
    with_mocks("blocktxn_from_asked_peer_is_processed", fun() ->
        Asked = dummy_peer(),
        S1 = pending_state(Asked),
        _S2 = cast_blocktxn(Asked, [asked_tx], S1),
        ?assertEqual(1, meck:num_calls(beamchain_compact_block, fill_block,
                                       '_')),
        receive {scored, Asked, Score} -> ?assertEqual(10, Score)
        after 1000 -> ?assert(false)
        end,
        receive
            {sent, Asked, {getdata, #{items := Items}}} ->
                ?assertMatch([#{type := ?MSG_WITNESS_BLOCK, hash := ?HASH}],
                             Items)
        after 1000 -> ?assert(false)
        end
    end).
