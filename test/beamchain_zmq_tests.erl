-module(beamchain_zmq_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%%% ===================================================================
%%% Config parsing tests (these don't need mocking)
%%% ===================================================================

parse_endpoint_test_() ->
    [
     ?_assertEqual({ok, tcp, "*", 28332},
                   beamchain_zmq:parse_endpoint_test("tcp://*:28332")),
     ?_assertEqual({ok, tcp, "127.0.0.1", 28333},
                   beamchain_zmq:parse_endpoint_test("tcp://127.0.0.1:28333")),
     ?_assertEqual({ok, tcp, "localhost", 8332},
                   beamchain_zmq:parse_endpoint_test("tcp://localhost:8332")),
     ?_assertEqual({error, missing_port},
                   beamchain_zmq:parse_endpoint_test("tcp://localhost")),
     ?_assertEqual({error, missing_protocol},
                   beamchain_zmq:parse_endpoint_test("localhost:8332")),
     ?_assertEqual({error, invalid_port},
                   beamchain_zmq:parse_endpoint_test("tcp://localhost:abc")),
     %% Binary endpoint should work too
     ?_assertEqual({ok, tcp, "*", 28332},
                   beamchain_zmq:parse_endpoint_test(<<"tcp://*:28332">>))
    ].

%%% ===================================================================
%%% gen_server startup tests
%%% ===================================================================

startup_no_config_test() ->
    %% Empty config should fail to start
    %% Use process_flag to avoid crash report affecting other tests
    OldTrapExit = process_flag(trap_exit, true),
    %% Suppress crash report noise during test
    OldLevel = logger:get_primary_config(),
    logger:set_primary_config(level, emergency),
    Result = beamchain_zmq:start_link(#{}),
    logger:set_primary_config(maps:get(level, OldLevel, notice)),
    process_flag(trap_exit, OldTrapExit),
    %% Flush any exit messages
    receive {'EXIT', _, _} -> ok after 0 -> ok end,
    %% gen_server:start_link returns {error, Reason} where Reason is the stop reason
    ?assertMatch({error, no_zmq_topics_configured}, Result).

%%% ===================================================================
%%% is_enabled tests
%%% ===================================================================

is_enabled_not_started_test() ->
    %% Should not be enabled when not started
    ?assertEqual(false, beamchain_zmq:is_enabled()).

%%% ===================================================================
%%% get_endpoints when not started
%%% ===================================================================

get_endpoints_not_started_test() ->
    %% Should return empty map when not started
    ?assertEqual(#{}, beamchain_zmq:get_endpoints()).

%%% ===================================================================
%%% Test helpers
%%% ===================================================================

make_test_block() ->
    Header = #block_header{
        version = 1,
        prev_hash = <<0:256>>,
        merkle_root = <<1:256>>,
        timestamp = 1234567890,
        bits = 16#1d00ffff,
        nonce = 0
    },
    Tx = make_test_tx(),
    #block{header = Header, transactions = [Tx]}.

make_test_tx() ->
    #transaction{
        version = 1,
        inputs = [
            #tx_in{
                prev_out = #outpoint{hash = <<0:256>>, index = 16#ffffffff},
                script_sig = <<4, 1, 2, 3, 4>>,
                sequence = 16#ffffffff,
                witness = []
            }
        ],
        outputs = [
            #tx_out{
                value = 5000000000,
                script_pubkey = <<118, 169, 20, 0:160, 136, 172>>
            }
        ],
        locktime = 0
    }.

%%% ===================================================================
%%% Notification no-op when disabled tests
%%% ===================================================================

notify_block_when_disabled_test() ->
    %% Should be a no-op when ZMQ is not started
    Block = make_test_block(),
    %% This should just return ok without crashing
    ?assertEqual(ok, beamchain_zmq:notify_block(Block, connect)),
    ?assertEqual(ok, beamchain_zmq:notify_block(Block, disconnect)).

notify_tx_when_disabled_test() ->
    %% Should be a no-op when ZMQ is not started
    Tx = make_test_tx(),
    ?assertEqual(ok, beamchain_zmq:notify_transaction(Tx, mempool_add, 0)),
    ?assertEqual(ok, beamchain_zmq:notify_transaction(Tx, mempool_remove, 1)).
