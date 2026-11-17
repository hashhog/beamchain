-module(beamchain_sync_tests).
-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

%% The dummy application below is started inside a peer node by
%% app_exit_halts_vm; this module is its callback for both the application
%% and its top supervisor.
-export([start/2, stop/1, init/1]).

%%% ===================================================================
%%% secfix-beamchain-malformed-frame-crash
%%%
%%% A peer that sends a truncated headers / inv / block / blocktxn /
%%% cmpctblock payload made beamchain_p2p_msg:decode_payload/2 raise
%%% (function_clause in beamchain_serialize:decode_block_header/1, badmatch
%%% on a short binary). The raise happened inside the shared beamchain_sync
%%% gen_server, so one frame crashed it for every peer; six inside ten
%%% seconds exceeded beamchain_node_sup's intensity (5 in 10 s), the app
%%% stopped, and because it ran `temporary` the VM stayed up with no node in
%%% it, so systemd never restarted it.
%%%
%%% Core: net_processing.cpp ProcessMessages catches the deserialize
%%% exception for that one message and carries on.
%%% ===================================================================

-define(PEER_MOCKS, [beamchain_peer, beamchain_header_sync,
                     beamchain_block_sync, beamchain_db]).

%% Every command the sync gen_server decodes, each with a payload a peer
%% can send that is too short for the frame it claims to be.
truncated_frames() ->
    [{headers, <<1>>},            %% count 1, no header bytes
     {headers, <<1, 0:79/unit:8>>}, %% count 1, 79 of 80 header bytes
     {inv, <<1>>},                %% count 1, no inv entry
     {inv, <<1, 1:32/little>>},   %% count 1, type but no hash
     {block, <<1>>},              %% shorter than an 80-byte header
     {block, <<0:80/unit:8>>},    %% header, no tx count
     {blocktxn, <<1>>},           %% shorter than the 32-byte block hash
     {blocktxn, <<0:32/unit:8, 1>>}, %% hash + count 1, no tx
     {cmpctblock, <<1>>}].

sync_setup() ->
    lists:foreach(fun(M) -> ok = meck:new(M, [no_link]) end, ?PEER_MOCKS),
    ok = meck:expect(beamchain_peer, add_misbehavior, fun(_, _) -> ok end),
    ok = meck:expect(beamchain_peer, send_message, fun(_, _) -> ok end),
    ok = meck:expect(beamchain_header_sync, handle_headers,
                     fun(_, _) -> ok end),
    ok = meck:expect(beamchain_block_sync, handle_block, fun(_, _) -> ok end),
    ok = meck:expect(beamchain_db, has_block, fun(_) -> true end),
    {ok, Sync} = beamchain_sync:start_link(),
    %% Not linked to the test process: on the bug the server crashes, and
    %% the test has to observe that, not die with it.
    unlink(Sync),
    Sync.

sync_cleanup(Sync) ->
    case is_process_alive(Sync) of
        true -> gen_server:stop(Sync);
        false -> ok
    end,
    lists:foreach(fun(M) -> catch meck:unload(M) end, ?PEER_MOCKS).

%% Deliver one frame the way beamchain_peer_manager does (a cast), then
%% wait until the server has handled it. sys:get_state/1 is a call, so it
%% returns only after the cast; on a crash it exits and we report that.
deliver(Peer, Command, Payload) ->
    gen_server:cast(beamchain_sync, {peer_message, Peer, Command, Payload}),
    try sys:get_state(beamchain_sync), alive
    catch exit:_ -> crashed
    end.

%% `foreach`: every frame gets a fresh server, so each case shows on its own
%% that its frame crashed (base) or did not (head).
truncated_headers_payload_does_not_crash_sync_test_() ->
    {foreach, fun sync_setup/0, fun sync_cleanup/1,
     [fun(Sync) ->
          {lists:flatten(io_lib:format("~p ~w bytes", [Cmd, byte_size(P)])),
           fun() ->
               Peer = self(),
               ?assertEqual(alive, deliver(Peer, Cmd, P)),
               %% Same process: it did not crash and get restarted.
               ?assertEqual(Sync, whereis(beamchain_sync)),
               %% The sender is scored, as the existing fallback clauses
               %% already do for a non-{ok, _} decode.
               ?assertEqual(1, meck:num_calls(beamchain_peer, add_misbehavior,
                                              [Peer, 20]))
           end}
      end || {Cmd, P} <- truncated_frames()]}.

%% Six malformed frames inside ten seconds: the burst that used to exhaust
%% beamchain_node_sup's restart intensity. The one server sees all of them.
six_truncated_frames_in_a_row_leave_sync_running_test_() ->
    {setup, fun sync_setup/0, fun sync_cleanup/1,
     fun(Sync) ->
         fun() ->
             Results = [deliver(self(), headers, <<1>>)
                        || _ <- lists:seq(1, 6)],
             ?assertEqual(lists:duplicate(6, alive), Results),
             ?assertEqual(Sync, whereis(beamchain_sync))
         end
     end}.

%% Control: a well-formed headers frame still reaches header_sync with the
%% header it carried, so the guard is not swallowing valid traffic.
valid_headers_frame_still_reaches_header_sync_test_() ->
    {setup, fun sync_setup/0, fun sync_cleanup/1,
     fun(_Sync) ->
         fun() ->
             #block{header = H} = beamchain_chain_params:genesis_block(regtest),
             Frame = beamchain_p2p_msg:encode_payload(headers,
                                                      #{headers => [H]}),
             ?assertEqual(alive, deliver(self(), headers, Frame)),
             ?assert(meck:called(beamchain_header_sync, handle_headers,
                                 [self(), [H]])),
             ?assertEqual(0, meck:num_calls(beamchain_peer, add_misbehavior,
                                            '_'))
         end
     end}.

%%% -------------------------------------------------------------------
%%% decode_payload/2 is total
%%% -------------------------------------------------------------------

%% Every command decode_payload/2 knows, on a set of short or nonsense
%% payloads: the answer is {ok, _} or {error, _}, never a raise. This
%% covers the decoders that run in beamchain_peer_manager (addr, addrv2,
%% getdata, getheaders, the BIP157 requests) as well as beamchain_sync's.
all_commands() ->
    [version, verack, ping, pong, addr, getaddr, inv, getdata, notfound,
     getheaders, headers, getblocks, block, tx, sendheaders, mempool,
     feefilter, sendcmpct, wtxidrelay, sendaddrv2, addrv2, cmpctblock,
     getblocktxn, blocktxn, sendtxrcncl, reqrecon, sketch, reconcildiff,
     reqsketchext, reqtx, getcfilters, cfilter, getcfheaders, cfheaders,
     getcfcheckpt, cfcheckpt].

hostile_payloads() ->
    [<<>>, <<0>>, <<1>>, <<2>>, <<16#fd>>, <<16#fd, 1>>, <<16#fe, 1, 0>>,
     <<16#ff>>, <<1, 0, 0, 0>>, <<0:31/unit:8>>, <<1, 0:31/unit:8>>,
     <<0:32/unit:8, 1>>, <<0:79/unit:8>>, <<0:80/unit:8>>,
     <<1, 0:80/unit:8>>].

decode_payload_is_total_on_truncated_input_test() ->
    Raised = [{Cmd, P, {C, R}}
              || Cmd <- all_commands(), P <- hostile_payloads(),
                 {C, R} <- [try beamchain_p2p_msg:decode_payload(Cmd, P) of
                                {ok, _} -> {none, none};
                                {error, _} -> {none, none};
                                Other -> {bad_return, Other}
                            catch Class:Reason -> {Class, Reason}
                            end],
                 C =/= none],
    ?assertEqual([], Raised).

%% A command with no decoder is a programming error, not peer input (every
%% call site passes a literal), and still raises as before. The bloom audit
%% tests (w110/w134 g26) rely on this to detect that filteradd is absent.
command_without_decoder_still_raises_test() ->
    ?assertError(function_clause,
                 beamchain_p2p_msg:decode_payload(no_such_command, <<1>>)).

%% addr is decoded by beamchain_peer_manager, the other shared server named
%% in the finding.
truncated_addr_payload_is_an_error_test() ->
    ?assertMatch({error, _}, beamchain_p2p_msg:decode_payload(addr, <<1>>)),
    ?assertMatch({error, _},
                 beamchain_p2p_msg:decode_payload(addr, <<1, 0:29/unit:8>>)).

%% Control: valid payloads decode exactly as before.
valid_payloads_decode_unchanged_test() ->
    #block{header = H, transactions = [Cb | _]} = Genesis =
        beamchain_chain_params:genesis_block(regtest),
    BlockBin = beamchain_p2p_msg:encode_payload(block, Genesis),
    {ok, Decoded} = beamchain_p2p_msg:decode_payload(block, BlockBin),
    ?assertEqual(BlockBin, beamchain_p2p_msg:encode_payload(block, Decoded)),
    ?assertEqual({ok, #{headers => [H]}},
                 beamchain_p2p_msg:decode_payload(
                   headers,
                   beamchain_p2p_msg:encode_payload(headers,
                                                    #{headers => [H]}))),
    Hash = <<7:256>>,
    {ok, #{block_hash := Hash, transactions := [Tx]}} =
        beamchain_p2p_msg:decode_payload(
          blocktxn,
          beamchain_p2p_msg:encode_payload(blocktxn,
                                           #{block_hash => Hash,
                                             transactions => [Cb]})),
    ?assertEqual(beamchain_serialize:encode_transaction(Cb),
                 beamchain_serialize:encode_transaction(Tx)),
    Item = #{type => 2, hash => <<9:256>>},
    ?assertEqual({ok, #{items => [Item]}},
                 beamchain_p2p_msg:decode_payload(
                   inv, beamchain_p2p_msg:encode_payload(inv,
                                                         #{items => [Item]}))).

%%% -------------------------------------------------------------------
%%% App exit halts the VM
%%% -------------------------------------------------------------------

%% beamchain_cli:start_app/0 starts beamchain with main_app_start_type/0.
%% In a separate peer node, start a stand-in application the same way and
%% kill its top supervisor (what beamchain_sup exceeding its restart
%% intensity amounts to). The node must go down so systemd can restart it.
%% On the base commit start_app/0 used ensure_all_started/1, i.e.
%% `temporary`, and there is no main_app_start_type/0; the test then uses
%% `temporary` and fails on the halt assertion.
app_exit_halts_vm_test_() ->
    {timeout, 60, fun app_exit_halts_vm/0}.

app_exit_halts_vm() ->
    {module, beamchain_cli} = code:ensure_loaded(beamchain_cli),
    Type = case erlang:function_exported(beamchain_cli,
                                         main_app_start_type, 0) of
        true -> beamchain_cli:main_app_start_type();
        false -> temporary
    end,
    {ok, Peer, _Node} = peer:start_link(
        #{connection => standard_io,
          args => lists:append([["-pa", D] || D <- code:get_path()])}),
    unlink(Peer),
    Mon = erlang:monitor(process, Peer),
    try
        ok = peer:call(Peer, application, load,
                       [{application, halt_probe,
                         [{description, "halt probe"}, {vsn, "0"},
                          {modules, [?MODULE]}, {registered, []},
                          {applications, [kernel, stdlib]},
                          {mod, {?MODULE, []}}]}]),
        {ok, _} = peer:call(Peer, application, ensure_all_started,
                            [halt_probe, Type]),
        Sup = peer:call(Peer, erlang, whereis, [halt_probe_sup]),
        ?assert(is_pid(Sup)),
        %% Fire and forget: the call may never return if the node halts.
        peer:cast(Peer, erlang, exit, [Sup, kill]),
        Halted = receive {'DOWN', Mon, process, Peer, _} -> true
                 after 15000 -> false
                 end,
        ?assertEqual({permanent, true}, {Type, Halted})
    after
        case is_process_alive(Peer) of
            true -> catch peer:stop(Peer);
            false -> ok
        end
    end.

%% Callbacks for the halt_probe application and its supervisor.
start(_Type, _Args) ->
    supervisor:start_link({local, halt_probe_sup}, ?MODULE, sup).

stop(_State) ->
    ok.

init(sup) ->
    {ok, {#{strategy => one_for_one, intensity => 0, period => 1}, []}}.

%%% ===================================================================
%%% secfix-beamchain-getblocktxn-in-sync
%%%
%%% getblocktxn used to be a beamchain_sync:route_message/4 clause: every
%%% peer's request read a block through beamchain_db inside the shared sync
%%% gen_server, with no beamchain_serve_limiter slot; a get_block reply the
%%% case did not match ({error, _}) raised case_clause and crashed sync for
%%% every peer; a block more than MAX_BLOCKTXN_DEPTH deep was pushed whole
%%% from there; and an index past the block or past uint16 was accepted.
%%%
%%% Core net_processing.cpp NetMsgType::GETBLOCKTXN: served by the peer's
%%% own message processing, a missing block is logged and ignored, a deep
%%% block becomes a MSG_WITNESS_BLOCK getdata request on that peer, an
%%% out-of-bounds index is Misbehaving (SendBlockTransactions), and indexes
%%% are uint16 (DifferenceFormatter "differential value overflow").
%%% ===================================================================

-define(GBT_TIP, 110).
-define(GBT_HASH, <<7:256>>).
-define(MSG_WITNESS_BLOCK_T, 16#40000002).  %% beamchain_protocol.hrl

gbt_setup() ->
    ok = meck:new(beamchain_peer, [passthrough, no_link]),
    ok = meck:expect(beamchain_peer, add_misbehavior, fun(_, _) -> ok end),
    ok = meck:expect(beamchain_peer, send_message, fun(_, _) -> ok end),
    ok = meck:expect(beamchain_peer, queue_getdata, fun(_, _) -> ok end),
    Others = [beamchain_header_sync, beamchain_block_sync, beamchain_db,
              beamchain_chainstate],
    lists:foreach(fun(M) -> ok = meck:new(M, [no_link]) end, Others),
    ok = meck:expect(beamchain_header_sync, handle_headers, fun(_, _) -> ok end),
    ok = meck:expect(beamchain_block_sync, handle_block, fun(_, _) -> ok end),
    ok = meck:expect(beamchain_chainstate, get_tip_height,
                     fun() -> {ok, ?GBT_TIP} end),
    {ok, Sync} = beamchain_sync:start_link(),
    unlink(Sync),
    {ok, Lim} = beamchain_serve_limiter:start_link(),
    unlink(Lim),
    {Sync, Lim}.

gbt_cleanup({Sync, Lim}) ->
    lists:foreach(fun(P) ->
                          case is_process_alive(P) of
                              true -> gen_server:stop(P);
                              false -> ok
                          end
                  end, [Sync, Lim]),
    lists:foreach(fun(M) -> catch meck:unload(M) end,
                  [beamchain_peer, beamchain_header_sync, beamchain_block_sync,
                   beamchain_db, beamchain_chainstate]).

gbt_block_at(Height, GetBlock) ->
    ok = meck:expect(beamchain_db, get_block_index_by_hash,
                     fun(?GBT_HASH) -> {ok, #{height => Height}};
                        (_) -> not_found
                     end),
    ok = meck:expect(beamchain_db, get_block, GetBlock).

gbt_payload(Indexes) ->
    beamchain_p2p_msg:encode_payload(getblocktxn,
                                     #{block_hash => ?GBT_HASH,
                                       indexes => Indexes}).

%% Deliver a getblocktxn the way a peer's frame arrives (the peer manager's
%% {peer_message, ...}), then play the requesting peer: take the request the
%% manager handed back to it and run it through beamchain_peer's real
%% {serve, ...} handler, which holds a serve-limiter slot. Returns
%% not_served when the manager did not hand it to the peer (base: it went
%% to beamchain_sync instead). Then waits on sync like deliver/3.
gbt_deliver(Payload) ->
    Peer = self(),
    {noreply, st} = beamchain_peer_manager:handle_info(
                      {peer_message, Peer, getblocktxn, Payload}, st),
    Served = receive
                 {'$gen_cast', {serve, getblocktxn, Payload} = Req} ->
                     keep_state_and_data =
                         beamchain_peer:ready(cast, Req, undefined),
                     served
             after 500 ->
                 not_served
             end,
    SyncState = try sys:get_state(beamchain_sync), alive
                catch exit:_ -> crashed
                end,
    {Served, SyncState}.

gbt_sent() ->
    [Msg || {_, {beamchain_peer, send_message, [_, Msg]}, _}
                <- meck:history(beamchain_peer)].

%% The item's named test: get_block answers {error, _}. Base: sync crashes
%% on case_clause and nothing ran under a serve slot. Head: served in the
%% peer under the limiter, sync untouched, nothing sent, nobody scored.
getblocktxn_error_does_not_crash_sync_test_() ->
    {setup, fun gbt_setup/0, fun gbt_cleanup/1,
     fun({Sync, _Lim}) ->
         fun() ->
             Self = self(),
             gbt_block_at(?GBT_TIP, fun(_) ->
                 Self ! {get_block_slot, beamchain_serve_limiter:stats()},
                 {error, x}
             end),
             ?assertEqual({served, alive}, gbt_deliver(gbt_payload([0]))),
             ?assertEqual(Sync, whereis(beamchain_sync)),
             Slot = receive {get_block_slot, S} -> S after 1000 -> none end,
             ?assertMatch(#{holders := 1}, Slot),
             ?assertEqual([], gbt_sent()),
             ?assertEqual(0, meck:num_calls(beamchain_peer, add_misbehavior,
                                            '_'))
         end
     end}.

%% A block exactly MAX_BLOCKTXN_DEPTH (10) below the tip is still answered
%% with a blocktxn carrying the requested transactions, in order.
getblocktxn_shallow_block_serves_requested_txs_test_() ->
    {setup, fun gbt_setup/0, fun gbt_cleanup/1,
     fun(_) ->
         fun() ->
             gbt_block_at(?GBT_TIP - 10, fun(?GBT_HASH) ->
                 {ok, #block{transactions = [t0, t1, t2]}}
             end),
             ?assertEqual({served, alive}, gbt_deliver(gbt_payload([0, 2]))),
             ?assertEqual([{blocktxn, #{block_hash => ?GBT_HASH,
                                        transactions => [t0, t2]}}],
                          gbt_sent()),
             ?assertEqual(0, meck:num_calls(beamchain_peer, add_misbehavior,
                                            '_'))
         end
     end}.

%% One deeper than MAX_BLOCKTXN_DEPTH: Core queues a MSG_WITNESS_BLOCK
%% getdata for the peer and does not read the block here. Base pushed the
%% whole block straight from beamchain_sync.
getblocktxn_deep_block_queues_block_getdata_test_() ->
    {setup, fun gbt_setup/0, fun gbt_cleanup/1,
     fun(_) ->
         fun() ->
             gbt_block_at(?GBT_TIP - 11, fun(?GBT_HASH) ->
                 {ok, #block{transactions = [t0]}}
             end),
             ?assertEqual({served, alive}, gbt_deliver(gbt_payload([0]))),
             ?assert(meck:called(beamchain_peer, queue_getdata,
                                 [self(), [#{type => ?MSG_WITNESS_BLOCK_T,
                                             hash => ?GBT_HASH}]])),
             ?assertEqual(0, meck:num_calls(beamchain_db, get_block, '_')),
             ?assertEqual([], gbt_sent())
         end
     end}.

%% Core SendBlockTransactions: an index >= vtx.size() is Misbehaving and
%% no blocktxn goes out. Base dropped the bad index and answered the rest.
getblocktxn_out_of_bounds_index_misbehaves_test_() ->
    {setup, fun gbt_setup/0, fun gbt_cleanup/1,
     fun(_) ->
         fun() ->
             gbt_block_at(?GBT_TIP, fun(?GBT_HASH) ->
                 {ok, #block{transactions = [t0, t1, t2]}}
             end),
             ?assertEqual({served, alive}, gbt_deliver(gbt_payload([0, 3]))),
             ?assertEqual([], gbt_sent()),
             ?assert(meck:called(beamchain_peer, add_misbehavior,
                                 [self(), 100]))
         end
     end}.

%% A block we have no index entry for: logged and ignored, no read, no
%% score (Core "a getblocktxn for a block we don't have").
getblocktxn_unknown_block_is_ignored_test_() ->
    {setup, fun gbt_setup/0, fun gbt_cleanup/1,
     fun(_) ->
         fun() ->
             ok = meck:expect(beamchain_db, get_block_index_by_hash,
                              fun(_) -> not_found end),
             ok = meck:expect(beamchain_db, get_block,
                              fun(_) -> {ok, #block{transactions = [t0]}} end),
             ?assertEqual({served, alive}, gbt_deliver(gbt_payload([0]))),
             ?assertEqual(0, meck:num_calls(beamchain_db, get_block, '_')),
             ?assertEqual([], gbt_sent()),
             ?assertEqual(0, meck:num_calls(beamchain_peer, add_misbehavior,
                                            '_'))
         end
     end}.

%% Indexes are uint16 on the wire: 65535 decodes, 65536 is malformed
%% (Core DifferenceFormatter "differential value overflow"), including when
%% it is reached through the differential sum.
getblocktxn_index_over_uint16_is_malformed_test() ->
    H = ?GBT_HASH,
    ?assertEqual({ok, #{block_hash => H, indexes => [16#ffff]}},
                 beamchain_p2p_msg:decode_payload(
                   getblocktxn, <<H/binary, 1, 16#fd, 16#ff, 16#ff>>)),
    ?assertMatch({error, _},
                 beamchain_p2p_msg:decode_payload(
                   getblocktxn, <<H/binary, 1, 16#fe, 0, 0, 1, 0>>)),
    %% 0 then +0xffff (diff 0xffff -> 0 + 0xffff + 1 = 0x10000).
    ?assertMatch({error, _},
                 beamchain_p2p_msg:decode_payload(
                   getblocktxn, <<H/binary, 2, 0, 16#fd, 16#ff, 16#ff>>)).
