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
