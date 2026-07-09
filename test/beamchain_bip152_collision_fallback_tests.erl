%%% BIP152 short-id collision handling — beamchain must NOT ban.
%%%
%%% Regression for the collision->ban divergence: do_handle_cmpctblock lumped
%%% a short-id collision (Core READ_STATUS_FAILED, blockencodings.cpp:115) in
%%% with genuinely-invalid init errors (READ_STATUS_INVALID) and called
%%% beamchain_peer:add_misbehavior(Peer, 100) + dropped the block with no
%%% fallback. Core only bans on READ_STATUS_INVALID; a collision re-requests
%%% the full block (net_processing.cpp:4592-4596) with NO ban. beamchain is the
%%% one fleet node that advertises sendcmpct(announce=1), so this path is live-
%%% reachable and an adversarially-crafted collision could unfairly ban an
%%% honest announcing peer.
%%%
%%% This drives the internal handler directly (TEST-exported) with meck on
%%% beamchain_peer and beamchain_chainstate, and asserts: a colliding
%%% cmpctblock produces a getdata(MSG_WITNESS_BLOCK) full-block request and
%%% ZERO add_misbehavior calls.
-module(beamchain_bip152_collision_fallback_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

make_header() ->
    #block_header{
        version    = 1,
        prev_hash  = <<0:256>>,
        merkle_root = <<1:256>>,
        timestamp  = 1296688602,
        bits       = 16#1d00ffff,
        nonce      = 0
    }.

%% A cmpctblock whose short_ids list contains a duplicate -> init_compact_block
%% throws short_id_collision (set size < list length).
colliding_cmpctblock() ->
    #{header => make_header(),
      nonce => 0,
      short_ids => [12345, 12345],
      prefilled_txns => []}.

collision_requests_full_block_no_ban_test() ->
    Height = 100,
    ok = meck:new(beamchain_peer, [no_link, passthrough]),
    ok = meck:new(beamchain_chainstate, [no_link, passthrough]),
    try
        Self = self(),
        ok = meck:expect(beamchain_peer, send_message,
                         fun(_Peer, Msg) -> Self ! {sent, Msg}, ok end),
        ok = meck:expect(beamchain_peer, add_misbehavior,
                         fun(_Peer, _Score) -> ok end),
        ok = meck:expect(beamchain_chainstate, get_tip_height,
                         fun() -> {ok, Height} end),

        BlockHash = <<7:256>>,
        State0 = beamchain_block_sync:test_new_state(),
        _State1 = beamchain_block_sync:do_handle_cmpctblock(
                    Self, colliding_cmpctblock(), BlockHash, Height, State0),

        %% (1) A full-block getdata was sent, using the WITNESS type.
        receive
            {sent, {getdata, #{items := Items}}} ->
                ?assertMatch([#{type := ?MSG_WITNESS_BLOCK, hash := BlockHash}],
                             Items)
        after 1000 ->
            ?assert(false)  %% no getdata sent -> fallback missing
        end,

        %% (2) The announcing peer was NOT banned (Core: collision = FAILED).
        ?assertEqual(0, meck:num_calls(beamchain_peer, add_misbehavior, '_'))
    after
        catch meck:unload(beamchain_chainstate),
        catch meck:unload(beamchain_peer)
    end.

%% Control: a genuinely-invalid cmpctblock (null header) IS still banned 100
%% (READ_STATUS_INVALID) — the fix narrows the ban to real invalidity, it does
%% not remove it.
invalid_cmpctblock_still_bans_test() ->
    Height = 100,
    ok = meck:new(beamchain_peer, [no_link, passthrough]),
    ok = meck:new(beamchain_chainstate, [no_link, passthrough]),
    try
        Self = self(),
        ok = meck:expect(beamchain_peer, send_message,
                         fun(_Peer, _Msg) -> ok end),
        ok = meck:expect(beamchain_peer, add_misbehavior,
                         fun(_Peer, Score) -> Self ! {ban, Score}, ok end),
        ok = meck:expect(beamchain_chainstate, get_tip_height,
                         fun() -> {ok, Height} end),

        %% Null header (bits = 0) -> init throws null_header -> INVALID.
        NullHeader = #block_header{version = 0, prev_hash = <<0:256>>,
                                   merkle_root = <<0:256>>, timestamp = 0,
                                   bits = 0, nonce = 0},
        Cmpct = #{header => NullHeader, nonce => 0,
                  short_ids => [1], prefilled_txns => []},
        _ = beamchain_block_sync:do_handle_cmpctblock(
              Self, Cmpct, <<8:256>>, Height, beamchain_block_sync:test_new_state()),

        receive
            {ban, Score} -> ?assertEqual(100, Score)
        after 1000 ->
            ?assert(false)  %% invalid block must still be banned
        end
    after
        catch meck:unload(beamchain_chainstate),
        catch meck:unload(beamchain_peer)
    end.
