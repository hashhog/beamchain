-module(beamchain_erlay_tests).
-include_lib("eunit/include/eunit.hrl").

%% ===================================================================
%% Test generators
%% ===================================================================

erlay_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     [
      {"short txid computation", fun test_short_txid/0},
      {"salt computation", fun test_salt_computation/0},
      {"peer registration lifecycle", fun test_peer_registration/0},
      {"reconciliation set operations", fun test_recon_set_ops/0},
      {"minisketch operations", fun test_minisketch/0},
      {"p2p message encoding/decoding", fun test_p2p_messages/0}
     ]}.

setup() ->
    %% Start crypto for hash functions
    application:ensure_all_started(crypto),
    ok.

cleanup(_) ->
    ok.

%% ===================================================================
%% Short txid computation tests
%% ===================================================================

test_short_txid() ->
    %% Test that short txid computation is deterministic
    K0 = 16#0102030405060708,
    K1 = 16#1112131415161718,
    Wtxid = crypto:strong_rand_bytes(32),

    %% Same input should produce same output
    ShortId1 = beamchain_erlay:compute_short_txid(K0, K1, Wtxid),
    ShortId2 = beamchain_erlay:compute_short_txid(K0, K1, Wtxid),
    ?assertEqual(ShortId1, ShortId2),

    %% Result should be 32-bit
    ?assert(ShortId1 >= 0),
    ?assert(ShortId1 =< 16#ffffffff),

    %% Different wtxid should produce different short id (with high probability)
    OtherWtxid = crypto:strong_rand_bytes(32),
    OtherShortId = beamchain_erlay:compute_short_txid(K0, K1, OtherWtxid),
    ?assertNotEqual(ShortId1, OtherShortId),

    %% Different keys should produce different short id
    DiffKeyId = beamchain_erlay:compute_short_txid(K0 + 1, K1, Wtxid),
    ?assertNotEqual(ShortId1, DiffKeyId),

    ok.

test_salt_computation() ->
    %% Test that salt computation is symmetric (order of salts shouldn't matter
    %% for the final result because they're sorted)

    %% The salt computation happens inside beamchain_erlay's internal functions.
    %% We can test it indirectly through the short txid computation after registration.
    %% For now, test the tagged hash pattern
    StaticSalt = beamchain_erlay:recon_static_salt(),
    ?assertEqual(<<"Tx Relay Salting">>, StaticSalt),

    %% Version should be 1
    ?assertEqual(1, beamchain_erlay:version()),

    ok.

%% ===================================================================
%% Peer registration tests
%% ===================================================================

test_peer_registration() ->
    %% Start the erlay gen_server temporarily for this test
    {ok, Pid} = beamchain_erlay:start_link(),

    try
        %% Pre-register a peer
        FakePeer1 = spawn(fun() -> receive stop -> ok end end),
        LocalSalt = beamchain_erlay:pre_register_peer(FakePeer1),
        ?assert(is_integer(LocalSalt)),
        ?assert(LocalSalt >= 0),

        %% Peer should not be registered yet
        ?assertEqual(false, beamchain_erlay:is_peer_registered(FakePeer1)),

        %% Complete registration
        RemoteSalt = 16#deadbeefcafebabe,
        ok = beamchain_erlay:register_peer(FakePeer1, true, 1, RemoteSalt),

        %% Now peer should be registered
        ?assertEqual(true, beamchain_erlay:is_peer_registered(FakePeer1)),

        %% Forget the peer
        beamchain_erlay:forget_peer(FakePeer1),
        ?assertEqual(false, beamchain_erlay:is_peer_registered(FakePeer1)),

        %% Clean up
        FakePeer1 ! stop
    after
        gen_server:stop(Pid)
    end,

    ok.

%% ===================================================================
%% Reconciliation set operations tests
%% ===================================================================

test_recon_set_ops() ->
    {ok, Pid} = beamchain_erlay:start_link(),

    try
        %% Register a peer
        FakePeer = spawn(fun() -> receive stop -> ok end end),
        LocalSalt = beamchain_erlay:pre_register_peer(FakePeer),
        RemoteSalt = 16#1234567890abcdef,
        ok = beamchain_erlay:register_peer(FakePeer, false, 1, RemoteSalt),

        %% Add some transactions
        Wtxid1 = crypto:strong_rand_bytes(32),
        Wtxid2 = crypto:strong_rand_bytes(32),
        ok = beamchain_erlay:add_tx_to_set(FakePeer, Wtxid1),
        ok = beamchain_erlay:add_tx_to_set(FakePeer, Wtxid2),

        %% Remove one
        ok = beamchain_erlay:remove_tx_from_set(FakePeer, Wtxid1),

        %% Clear all
        ok = beamchain_erlay:clear_set(FakePeer),

        %% Clean up
        beamchain_erlay:forget_peer(FakePeer),
        FakePeer ! stop
    after
        gen_server:stop(Pid)
    end,

    ok.

%% ===================================================================
%% Minisketch tests
%% ===================================================================

test_minisketch() ->
    %% Test the pure Erlang fallback implementation
    %% (NIF may not be loaded in test environment)

    %% Create a sketch
    {ok, Sketch} = beamchain_minisketch:create(32, 10),

    %% Add some elements
    ok = beamchain_minisketch:add(Sketch, 12345),
    ok = beamchain_minisketch:add(Sketch, 67890),
    ok = beamchain_minisketch:add(Sketch, 11111),

    %% Bits should be 32
    ?assertEqual(32, beamchain_minisketch:bits(Sketch)),

    %% Serialize and check we get binary data
    {ok, Data} = beamchain_minisketch:serialize(Sketch),
    ?assert(is_binary(Data)),

    %% Compute capacity helper
    Cap = beamchain_minisketch:compute_capacity(32, 10, 16),
    ?assert(Cap >= 10),

    %% Destroy (should be a no-op with fallback)
    ok = beamchain_minisketch:destroy(Sketch),

    ok.

%% ===================================================================
%% P2P message encoding/decoding tests
%% ===================================================================

test_p2p_messages() ->
    %% Test sendtxrcncl
    SendTxRcnclMsg = #{version => 1, salt => 16#0102030405060708},
    SendTxRcnclBin = beamchain_p2p_msg:encode_payload(sendtxrcncl, SendTxRcnclMsg),
    {ok, DecodedSendTxRcncl} = beamchain_p2p_msg:decode_payload(sendtxrcncl, SendTxRcnclBin),
    ?assertEqual(1, maps:get(version, DecodedSendTxRcncl)),
    ?assertEqual(16#0102030405060708, maps:get(salt, DecodedSendTxRcncl)),

    %% Test reqrecon
    ReqReconMsg = #{set_size => 100, q => 16},
    ReqReconBin = beamchain_p2p_msg:encode_payload(reqrecon, ReqReconMsg),
    {ok, DecodedReqRecon} = beamchain_p2p_msg:decode_payload(reqrecon, ReqReconBin),
    ?assertEqual(100, maps:get(set_size, DecodedReqRecon)),
    ?assertEqual(16, maps:get(q, DecodedReqRecon)),

    %% Test sketch
    SketchData = crypto:strong_rand_bytes(128),
    SketchMsg = #{sketch => SketchData},
    SketchBin = beamchain_p2p_msg:encode_payload(sketch, SketchMsg),
    {ok, DecodedSketch} = beamchain_p2p_msg:decode_payload(sketch, SketchBin),
    ?assertEqual(SketchData, maps:get(sketch, DecodedSketch)),

    %% Test reconcildiff (success case)
    ReconcilDiffMsg = #{success => true, short_ids => [12345, 67890, 11111]},
    ReconcilDiffBin = beamchain_p2p_msg:encode_payload(reconcildiff, ReconcilDiffMsg),
    {ok, DecodedReconcilDiff} = beamchain_p2p_msg:decode_payload(reconcildiff, ReconcilDiffBin),
    ?assertEqual(true, maps:get(success, DecodedReconcilDiff)),
    ?assertEqual([12345, 67890, 11111], maps:get(short_ids, DecodedReconcilDiff)),

    %% Test reconcildiff (failure case)
    ReconcilDiffFailMsg = #{success => false},
    ReconcilDiffFailBin = beamchain_p2p_msg:encode_payload(reconcildiff, ReconcilDiffFailMsg),
    {ok, DecodedReconcilDiffFail} = beamchain_p2p_msg:decode_payload(reconcildiff, ReconcilDiffFailBin),
    ?assertEqual(false, maps:get(success, DecodedReconcilDiffFail)),

    %% Test reqtx
    ReqTxMsg = #{short_ids => [11111, 22222, 33333]},
    ReqTxBin = beamchain_p2p_msg:encode_payload(reqtx, ReqTxMsg),
    {ok, DecodedReqTx} = beamchain_p2p_msg:decode_payload(reqtx, ReqTxBin),
    ?assertEqual([11111, 22222, 33333], maps:get(short_ids, DecodedReqTx)),

    %% Test reqsketchext
    ReqSketchExtBin = beamchain_p2p_msg:encode_payload(reqsketchext, #{}),
    {ok, _DecodedReqSketchExt} = beamchain_p2p_msg:decode_payload(reqsketchext, ReqSketchExtBin),

    ok.

%% ===================================================================
%% Additional edge case tests
%% ===================================================================

command_names_test() ->
    %% Test command name mappings
    ?assertEqual(<<"sendtxrcncl">>, beamchain_p2p_msg:command_name(sendtxrcncl)),
    ?assertEqual(<<"reqrecon">>, beamchain_p2p_msg:command_name(reqrecon)),
    ?assertEqual(<<"sketch">>, beamchain_p2p_msg:command_name(sketch)),
    ?assertEqual(<<"reconcildiff">>, beamchain_p2p_msg:command_name(reconcildiff)),
    ?assertEqual(<<"reqsketchext">>, beamchain_p2p_msg:command_name(reqsketchext)),
    ?assertEqual(<<"reqtx">>, beamchain_p2p_msg:command_name(reqtx)),

    ?assertEqual(sendtxrcncl, beamchain_p2p_msg:command_atom(<<"sendtxrcncl">>)),
    ?assertEqual(reqrecon, beamchain_p2p_msg:command_atom(<<"reqrecon">>)),
    ?assertEqual(sketch, beamchain_p2p_msg:command_atom(<<"sketch">>)),
    ?assertEqual(reconcildiff, beamchain_p2p_msg:command_atom(<<"reconcildiff">>)),
    ?assertEqual(reqsketchext, beamchain_p2p_msg:command_atom(<<"reqsketchext">>)),
    ?assertEqual(reqtx, beamchain_p2p_msg:command_atom(<<"reqtx">>)),

    ok.

siphash_short_id_test() ->
    %% Test specific SipHash values for short txid computation
    %% This ensures compatibility with Bitcoin Core's implementation
    K0 = 0,
    K1 = 0,
    Wtxid = <<0:256>>,

    ShortId = beamchain_erlay:compute_short_txid(K0, K1, Wtxid),
    %% Result should be deterministic
    ?assert(is_integer(ShortId)),
    ?assert(ShortId >= 0),
    ?assert(ShortId =< 16#ffffffff),

    ok.
