%%% Tests for the mempool tx-relay REQUEST leg (inv -> getdata).
%%%
%%% beamchain already ANNOUNCES and SERVES transactions, but previously
%%% dropped every tx inv item, so it could never ingest a peer-advertised
%%% mempool tx. beamchain_sync:route_message/4 now, on a tx inv for a tx we
%%% don't already have, issues a getdata. Mirrors Bitcoin Core
%%% net_processing.cpp ProcessMessage(INV) IsGenTxMsg branch
%%% (src/net_processing.cpp:4079-4091) + getdata type at :6206.
%%%
%%% Proven-teeth, in-process (no gen_servers, no regtest):
%%%   - meck stubs the four collaborators route_message consults on the tx
%%%     path: beamchain_chainstate:is_synced/0 (IBD gate),
%%%     beamchain_peer_manager:get_peer/1 (block-relay-only gate),
%%%     beamchain_mempool:has_tx/1 + lookup_entry_by_wtxid/1 (dedup);
%%%   - the "peer" pid is THIS process, so the getdata that route_message
%%%     hands to beamchain_peer:send_message/2 (a gen_statem:cast =>
%%%     {'$gen_cast', {send, getdata, Payload}}) lands in our mailbox and we
%%%     assert its exact contents.
%%%
%%% meck new/expect/unload happen INSIDE each test body so self() is the
%%% process that will receive the cast.
-module(beamchain_tx_inv_request_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain_protocol.hrl").

-define(UNKNOWN, <<1:256>>).   %% txid/wtxid NOT in mempool
-define(KNOWN,   <<2:256>>).   %% txid/wtxid already in mempool

%%% ===================================================================
%%% Helpers
%%% ===================================================================

flush() -> receive _ -> flush() after 0 -> ok end.

%% Install the tx-path collaborators.
%%  Synced  :: boolean() - beamchain_chainstate:is_synced/0
%%  ConnType:: full_relay | block_relay | feeler - our conn to the peer
install(Synced, ConnType) ->
    ok = meck:new(beamchain_chainstate, [no_link, passthrough]),
    ok = meck:expect(beamchain_chainstate, is_synced, fun() -> Synced end),
    ok = meck:new(beamchain_peer_manager, [no_link, passthrough]),
    ok = meck:expect(beamchain_peer_manager, get_peer,
                     fun(_Pid) -> {ok, #{conn_type => ConnType}} end),
    ok = meck:new(beamchain_mempool, [no_link, passthrough]),
    %% Only ?KNOWN is in the mempool (by txid and by wtxid).
    ok = meck:expect(beamchain_mempool, has_tx,
                     fun(H) -> H =:= ?KNOWN end),
    ok = meck:expect(beamchain_mempool, lookup_entry_by_wtxid,
                     fun(?KNOWN) -> {ok, mempool_entry};
                        (_)      -> not_found end),
    ok.

unload() ->
    catch meck:unload(beamchain_mempool),
    catch meck:unload(beamchain_peer_manager),
    catch meck:unload(beamchain_chainstate),
    flush(),
    ok.

%% Encode an inv message payload from a list of {Type, Hash} items.
inv_payload(Items) ->
    beamchain_p2p_msg:encode_payload(
      inv, #{items => [#{type => T, hash => H} || {T, H} <- Items]}).

%% Drive route_message(inv) with the given items against THIS pid, returning
%% the getdata items sent (or no_message).
route(Items) ->
    Payload = inv_payload(Items),
    _ = beamchain_sync:route_message(self(), inv, Payload,
                                     beamchain_sync:test_initial_state()),
    recv_getdata(100).

recv_getdata(Timeout) ->
    receive
        {'$gen_cast', {send, getdata, #{items := Items}}} -> Items
    after Timeout ->
        no_message
    end.

%%% ===================================================================
%%% Request leg: unknown tx -> getdata
%%% ===================================================================

%% A wtxidrelay peer announces MSG_TX (txid) we don't have -> getdata
%% MSG_WITNESS_TX (witness serialization) for that txid.
unknown_txid_requests_witness_tx_test() ->
    install(true, full_relay),
    try
        ?assertEqual([#{type => ?MSG_WITNESS_TX, hash => ?UNKNOWN}],
                     route([{?MSG_TX, ?UNKNOWN}]))
    after unload() end.

%% A wtxid announcement (MSG_WTX) we don't have -> getdata MSG_WTX (wtxid).
unknown_wtxid_requests_wtx_test() ->
    install(true, full_relay),
    try
        ?assertEqual([#{type => ?MSG_WTX, hash => ?UNKNOWN}],
                     route([{?MSG_WTX, ?UNKNOWN}]))
    after unload() end.

%%% ===================================================================
%%% Dedup: already-in-mempool tx -> no getdata
%%% ===================================================================

known_txid_not_requested_test() ->
    install(true, full_relay),
    try ?assertEqual(no_message, route([{?MSG_TX, ?KNOWN}]))
    after unload() end.

known_wtxid_not_requested_test() ->
    install(true, full_relay),
    try ?assertEqual(no_message, route([{?MSG_WTX, ?KNOWN}]))
    after unload() end.

%% Mixed inv: only the unknown tx is requested; the known one is deduped.
mixed_only_unknown_requested_test() ->
    install(true, full_relay),
    try
        ?assertEqual([#{type => ?MSG_WITNESS_TX, hash => ?UNKNOWN}],
                     route([{?MSG_TX, ?KNOWN}, {?MSG_TX, ?UNKNOWN}]))
    after unload() end.

%%% ===================================================================
%%% Gates: IBD and block-relay-only / feeler peers
%%% ===================================================================

no_request_during_ibd_test() ->
    install(false, full_relay),   %% is_synced = false => in IBD
    try ?assertEqual(no_message, route([{?MSG_TX, ?UNKNOWN}]))
    after unload() end.

no_request_from_block_relay_peer_test() ->
    install(true, block_relay),
    try ?assertEqual(no_message, route([{?MSG_TX, ?UNKNOWN}]))
    after unload() end.

no_request_from_feeler_peer_test() ->
    install(true, feeler),
    try ?assertEqual(no_message, route([{?MSG_TX, ?UNKNOWN}]))
    after unload() end.
