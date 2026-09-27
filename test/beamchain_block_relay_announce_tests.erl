%% Block relay: a block connected via P2P must be announced to peers.
%%
%% Regtest relay test 2026-09-26: two Bitcoin Core nodes connected ONLY to
%% beamchain never converged -- beamchain downloaded and connected Core A's
%% blocks but never announced them to Core B, because
%% beamchain_peer_manager:announce_block/2 was only called from the miner.
%% Core relays every new tip from PeerManagerImpl::UpdatedBlockTip
%% (net_processing.cpp:2158) unless in IBD.
-module(beamchain_block_relay_announce_tests).
-include_lib("eunit/include/eunit.hrl").

should_announce_tip_follows_max_tip_age_test() ->
    Now = 1800000000,
    ?assert(beamchain_chainstate:should_announce_tip(Now, Now)),
    %% Boundary: Core is in IBD only when the tip is OLDER than 24h.
    ?assert(beamchain_chainstate:should_announce_tip(Now - 86400, Now)),
    ?assertNot(beamchain_chainstate:should_announce_tip(Now - 86401, Now)),
    %% Header time slightly in the future: still relay.
    ?assert(beamchain_chainstate:should_announce_tip(Now + 600, Now)).

%% Source pin: the canonical connect site (do_connect_block) must announce.
connect_site_announces_block_test() ->
    Src = source("beamchain_chainstate.erl"),
    Notify = string:find(Src, "beamchain_peer_manager:notify_tip_updated(),"),
    ?assertNotEqual(nomatch, Notify),
    ?assertNotEqual(nomatch,
                    string:find(Notify, "beamchain_peer_manager:announce_block(")).

source(Name) ->
    Dir = filename:dirname(code:which(beamchain_chainstate)),
    Candidates = [filename:join([Dir, "..", "src", Name]),
                  filename:join(["src", Name]),
                  filename:join(["..", "src", Name])],
    [Path | _] = [P || P <- Candidates, filelib:is_file(P)],
    {ok, Bin} = file:read_file(Path),
    unicode:characters_to_list(Bin).

%% An unsolicited block that does not extend our tip (bad_prevblk) must not
%% get the peer banned -- in the regtest relay test beamchain banned Core A,
%% its only upstream, for a compact block that arrived ahead of its headers.
unsolicited_non_connecting_block_not_penalised_test() ->
    ?assertEqual(0, beamchain_block_sync:unsolicited_connect_penalty(bad_prevblk)),
    ?assertEqual(100, beamchain_block_sync:unsolicited_connect_penalty(bad_merkle_root)),
    ?assertEqual(100, beamchain_block_sync:unsolicited_connect_penalty({block_mutated, x})).

%% getheaders from a peer already at our tip must get an EMPTY headers reply
%% (Core always answers); silence arms Core's 2-minute getheaders throttle.
getheaders_always_answered_test() ->
    Src = source("beamchain_peer_manager.erl"),
    Fn = string:find(Src, "handle_getheaders_msg(Pid, Payload) ->"),
    ?assertNotEqual(nomatch, Fn),
    Body = string:slice(Fn, 0, 3000),
    ?assertEqual(nomatch, string:find(Body, "[] -> ok;")),
    ?assertNotEqual(nomatch,
                    string:find(Body, "beamchain_peer:send_message(Pid, {headers, #{headers => Headers}})")),
    %% and the wire encoder accepts the empty list
    ?assertMatch(<<0>>, iolist_to_binary(
                           beamchain_p2p_msg:encode_payload(headers, #{headers => []}))).

%% getheaders is served from the CONNECTED chain only (Core: ActiveChain()),
%% never from header-only index entries ahead of the tip -- a peer that got
%% those asked for bodies we lacked, got notfound, and stalled.
getheaders_capped_at_connected_tip_test() ->
    %% peer at genesis, we are connected to 2 (headers known to 5): serve 2
    ?assertEqual(2, beamchain_peer_manager:getheaders_limit(0, 2)),
    %% peer already at our tip: serve nothing (the reply is an empty headers)
    ?assertEqual(0, beamchain_peer_manager:getheaders_limit(2, 2)),
    %% peer ahead of us (locator matched a header-only entry): nothing
    ?assertEqual(0, beamchain_peer_manager:getheaders_limit(5, 2)),
    %% MAX_HEADERS_RESULTS cap
    ?assertEqual(2000, beamchain_peer_manager:getheaders_limit(0, 950000)).

%% getdata(MSG_CMPCT_BLOCK) is served with the full witness block.
getdata_cmpct_block_served_test() ->
    ?assertEqual({block, blk}, beamchain_peer_manager:getdata_block_msg(4, blk)),
    Src = source("beamchain_peer_manager.erl"),
    ?assertNotEqual(nomatch, string:find(Src, "T =:= ?MSG_CMPCT_BLOCK ->")).
