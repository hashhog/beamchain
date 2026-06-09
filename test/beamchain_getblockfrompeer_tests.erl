%%% Tests for the getblockfrompeer JSON-RPC method (Core RPC-completeness gap).
%%%
%%% Mirrors Bitcoin Core rpc/blockchain.cpp::getblockfrompeer +
%%% net_processing.cpp::PeerManagerImpl::FetchBlock.
%%%
%%% Proven-teeth, in-process (no cowboy listener, no multi-node regtest):
%%%  - meck stubs beamchain_db:get_block_index_by_hash/1 (header lookup) and
%%%    beamchain_db:has_block/1 (body-on-disk check),
%%%  - meck stubs beamchain_peer_manager:get_peers/0 with a fabricated peer
%%%    whose pid is THIS asserting process, so the getdata that the handler
%%%    hands to beamchain_peer:send_message/2 (a gen_statem:cast => a
%%%    '$gen_cast' message) lands in our mailbox and we assert its contents.
%%%
%%% NOTE on process identity: each test does its own meck new/expect/unload
%%% INSIDE the test body so self() is the process that will receive the cast
%%% (an {setup,...} fixture fun runs in a different process than the body, so
%%% pids captured there would not match the asserting mailbox).
%%%
%%% Asserts:
%%%  (a) unknown header               -> RPC_MISC_ERROR (-1) "Block header missing"
%%%  (b) unknown/disconnected peer_id -> RPC_MISC_ERROR (-1) "Peer does not exist"
%%%  (c) success: a witness-block getdata for the right hash is genuinely sent
%%%      to the resolved peer, and the handler returns {} (the [{}] proplist).
%%%  (d) the peer_id convention matches getpeerinfo's: erlang:phash2({IP,Port}).
-module(beamchain_getblockfrompeer_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain_protocol.hrl").

-define(RPC_MISC_ERROR, -1).

%% A concrete block hash, in display (hex) order, as an RPC caller passes it.
-define(BLOCKHASH_HEX,
    <<"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09">>).

%% The peer's wire address. getpeerinfo emits id = erlang:phash2({IP,Port}),
%% so this is the exact id an operator would pass to getblockfrompeer.
-define(PEER_ADDR, {{203, 0, 113, 7}, 8333}).

%%% ===================================================================
%%% Helpers
%%% ===================================================================

%% Install the two mocked collaborators. HeaderKnown toggles the header
%% lookup; HasBlock is has_block/1's result; PeersFun supplies get_peers/0.
install_mocks(HeaderKnown, HasBlock, PeersFun) ->
    ok = meck:new(beamchain_db, [no_link, passthrough]),
    HeaderResult = case HeaderKnown of
        true  -> {ok, #{height => 100}};
        false -> not_found
    end,
    ok = meck:expect(beamchain_db, get_block_index_by_hash,
                     fun(_Hash) -> HeaderResult end),
    ok = meck:expect(beamchain_db, has_block, fun(_Hash) -> HasBlock end),
    ok = meck:new(beamchain_peer_manager, [no_link, passthrough]),
    ok = meck:expect(beamchain_peer_manager, get_peers, PeersFun),
    ok.

unload_mocks() ->
    catch meck:unload(beamchain_peer_manager),
    catch meck:unload(beamchain_db),
    flush(),
    ok.

flush() ->
    receive _ -> flush() after 0 -> ok end.

%% A peer entry (entry_to_map shape) whose pid is the given process.
peer_entry(Pid, Address, Connected) ->
    #{pid => Pid, address => Address, direction => inbound,
      connected => Connected, info => #{}, conn_type => full_relay}.

%% The getpeerinfo peer-id convention.
peer_id(Address) -> erlang:phash2(Address).

%% Internal byte-order hash for the test blockhash (handler reverses the hex).
expected_internal_hash() ->
    beamchain_serialize:reverse_bytes(
        beamchain_serialize:hex_decode(?BLOCKHASH_HEX)).

%% Pick the {getdata, Payload} out of a beamchain_peer:send_message/2 cast.
%% send_message/2 does gen_statem:cast(Pid, {send, Command, Payload}), which is
%% delivered as {'$gen_cast', {send, Command, Payload}}.
recv_getdata(Timeout) ->
    receive
        {'$gen_cast', {send, getdata, Payload}} -> Payload
    after Timeout ->
        no_message
    end.

%%% ===================================================================
%%% (a) Unknown header -> "Block header missing"
%%% ===================================================================

unknown_header_test() ->
    install_mocks(false, false, fun() -> [] end),
    try
        Res = beamchain_rpc:rpc_getblockfrompeer([?BLOCKHASH_HEX, 0]),
        ?assertEqual({error, ?RPC_MISC_ERROR, <<"Block header missing">>}, Res)
    after
        unload_mocks()
    end.

%%% ===================================================================
%%% (b) Unknown peer_id (no peers) -> "Peer does not exist"
%%% ===================================================================

unknown_peer_test() ->
    install_mocks(true, false, fun() -> [] end),
    try
        Res = beamchain_rpc:rpc_getblockfrompeer([?BLOCKHASH_HEX, 12345]),
        ?assertEqual({error, ?RPC_MISC_ERROR, <<"Peer does not exist">>}, Res)
    after
        unload_mocks()
    end.

%% A peer with the matching id EXISTS but is not yet connected (handshake
%% incomplete) -> Core treats it as "does not exist", and nothing is sent.
disconnected_peer_test() ->
    Self = self(),
    Addr = ?PEER_ADDR,
    install_mocks(true, false, fun() -> [peer_entry(Self, Addr, false)] end),
    try
        Res = beamchain_rpc:rpc_getblockfrompeer([?BLOCKHASH_HEX, peer_id(Addr)]),
        ?assertEqual({error, ?RPC_MISC_ERROR, <<"Peer does not exist">>}, Res),
        ?assertEqual(no_message, recv_getdata(50))
    after
        unload_mocks()
    end.

%%% ===================================================================
%%% (c) Success -> getdata sent to the resolved peer + returns {}
%%% ===================================================================

success_sends_getdata_test() ->
    Self = self(),
    Addr = ?PEER_ADDR,
    install_mocks(true, false, fun() -> [peer_entry(Self, Addr, true)] end),
    try
        %% (d) peer-id convention: the id we pass is phash2({IP,Port}), exactly
        %% what getpeerinfo emits.
        PeerId = peer_id(Addr),
        Res = beamchain_rpc:rpc_getblockfrompeer([?BLOCKHASH_HEX, PeerId]),
        %% Returns {} — represented as the [{}] proplist (jsx -> {}).
        ?assertEqual({ok, [{}]}, Res),
        %% A getdata cast really arrived at the resolved peer (us).
        Payload = recv_getdata(1000),
        ?assertNotEqual(no_message, Payload),
        #{items := Items} = Payload,
        ?assertEqual(1, length(Items)),
        [#{type := Type, hash := Hash}] = Items,
        %% MSG_BLOCK | MSG_WITNESS_FLAG (BIP-144 witness-block inv).
        ?assertEqual(?MSG_WITNESS_BLOCK, Type),
        %% The hash is the requested block, in internal byte order.
        ?assertEqual(expected_internal_hash(), Hash)
    after
        unload_mocks()
    end.

%% Two peers; only the one whose phash2(addr) matches gets the getdata, proving
%% the reverse-lookup is selective (not "send to first peer").
selects_correct_peer_test() ->
    Self = self(),
    Other = spawn(fun() -> receive _ -> ok after 2000 -> ok end end),
    AddrTarget = ?PEER_ADDR,
    AddrOther = {{198, 51, 100, 9}, 8333},
    Peers = [peer_entry(Other, AddrOther, true),
             peer_entry(Self, AddrTarget, true)],
    install_mocks(true, false, fun() -> Peers end),
    try
        Res = beamchain_rpc:rpc_getblockfrompeer([?BLOCKHASH_HEX,
                                                  peer_id(AddrTarget)]),
        ?assertEqual({ok, [{}]}, Res),
        %% We (the target) received the getdata.
        ?assertNotEqual(no_message, recv_getdata(1000))
    after
        exit(Other, kill),
        unload_mocks()
    end.

%%% ===================================================================
%%% block-already-downloaded short-circuit (Core blockchain.cpp:558)
%%% ===================================================================

already_downloaded_test() ->
    Self = self(),
    Addr = ?PEER_ADDR,
    install_mocks(true, true, fun() -> [peer_entry(Self, Addr, true)] end),
    try
        Res = beamchain_rpc:rpc_getblockfrompeer([?BLOCKHASH_HEX, peer_id(Addr)]),
        ?assertEqual({error, ?RPC_MISC_ERROR, <<"Block already downloaded">>},
                     Res),
        %% No getdata sent when the body is already on disk.
        ?assertEqual(no_message, recv_getdata(50))
    after
        unload_mocks()
    end.

%%% ===================================================================
%%% argument-validation guard
%%% ===================================================================

bad_args_test() ->
    %% Missing peer_id -> invalid params.
    {error, Code, _} = beamchain_rpc:rpc_getblockfrompeer([?BLOCKHASH_HEX]),
    ?assertEqual(-32602, Code).
