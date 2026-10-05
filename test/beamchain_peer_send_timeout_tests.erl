-module(beamchain_peer_send_timeout_tests).

%%% BC-S: a peer that stops reading must not park its process forever, grow
%%% its mailbox without bound, or block anyone else; and serving a peer's
%%% data request must not block the peer manager.
%%%
%%% Observed (live, 2026-10-05): 13 'acceptor died' (check_inbound 5 s
%%% gen_server:call timeouts on beamchain_peer_manager) -- the manager was
%%% busy serving getdata/getheaders itself (beamchain_db reads of up to 30 s
%%% under load). Inbound sockets inherited the listener's options, which had
%%% no send_timeout: a non-reading inbound peer blocked in gen_tcp:send
%%% forever while every announcement cast piled up in its mailbox, and any
%%% gen_statem:call to it (getpeerinfo) hung for the full call timeout.
%%%
%%% Core: per-peer send buffers never block the node (fPauseSend, socket
%%% InactivityCheck), getdata is served per peer (ProcessGetData).
%%%
%%%   rebar3 eunit --module=beamchain_peer_send_timeout_tests

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-define(SEND_TIMEOUT_MS, 2000).

%%% ===================================================================
%%% Manager: serving getdata does not run in the manager
%%% ===================================================================

manager_getdata_not_served_inline_test_() ->
    {setup,
     fun() ->
         {module, beamchain_db} = code:ensure_loaded(beamchain_db),
         ok = meck:new(beamchain_db, [no_link, passthrough]),
         %% A block read stuck behind a loaded beamchain_db.
         ok = meck:expect(beamchain_db, get_block,
                          fun(_) -> timer:sleep(6000), not_found end),
         ok = meck:new(beamchain_config, [no_link, passthrough]),
         ok = meck:expect(beamchain_config, prune_enabled, fun() -> false end)
     end,
     fun(_) -> meck:unload(beamchain_config), meck:unload(beamchain_db) end,
     fun(_) ->
         [{timeout, 30, {"FIX: a getdata whose block read takes 6 s returns from the manager at once",
                         fun manager_getdata_returns_immediately/0}},
          {timeout, 30, {"FIX: a getheaders is handed to the peer, not walked in the manager",
                         fun manager_getheaders_handed_to_peer/0}}]
     end}.

manager_getdata_returns_immediately() ->
    Peer = collector(),
    Payload = beamchain_p2p_msg:encode_payload(getdata, #{items =>
                  [#{type => ?MSG_WITNESS_BLOCK, hash => <<1:256>>}]}),
    {Us, R} = timer:tc(fun() ->
        beamchain_peer_manager:handle_info({peer_message, Peer, getdata,
                                            Payload}, fake_state)
    end),
    ?assertEqual({noreply, fake_state}, R),
    ?assert(Us < 1000000),
    %% ...and the request went to the peer's own process to be served.
    ?assertMatch([{serve, getdata, Payload} | _], collected(Peer)).

manager_getheaders_handed_to_peer() ->
    Peer = collector(),
    Payload = <<"opaque">>,
    ?assertEqual({noreply, fake_state},
                 beamchain_peer_manager:handle_info(
                   {peer_message, Peer, getheaders, Payload}, fake_state)),
    ?assertMatch([{serve, getheaders, Payload} | _], collected(Peer)).

collector() ->
    spawn(fun() -> collect_loop([]) end).

collect_loop(Acc) ->
    receive
        {'$gen_cast', M} -> collect_loop([M | Acc]);
        {dump, From} -> From ! {collected, lists:reverse(Acc)}, collect_loop(Acc)
    end.

collected(Pid) ->
    Pid ! {dump, self()},
    receive {collected, L} -> L after 5000 -> timeout end.

%%% ===================================================================
%%% Peer: a non-reading peer is dropped; a slow reader is not
%%% ===================================================================

peer_socket_test_() ->
    {foreach, fun setup/0, fun teardown/1,
     [fun(_) -> {timeout, 60, {"FIX: non-reading inbound peer exits; mailbox bounded; info/1 never hangs",
                               fun non_reading_peer_dropped/0}} end,
      fun(_) -> {timeout, 60, {"CONTROL: a slow but steady reader stays connected and gets everything",
                               fun slow_reader_kept/0}} end,
      fun(_) -> {timeout, 60, {"CONTROL: a normal peer keeps being served while another is stuck",
                               fun other_peer_unaffected/0}} end]}.

setup() ->
    TmpDir = filename:join(["/tmp", "beamchain_sendto_" ++
                            integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),
    application:set_env(beamchain, datadir, TmpDir),
    application:set_env(beamchain, network, regtest),
    application:set_env(beamchain, peer_send_timeout_ms, ?SEND_TIMEOUT_MS),
    os:unsetenv("BEAMCHAIN_DATADIR"),
    os:unsetenv("BEAMCHAIN_NETWORK"),
    catch gen_server:stop(beamchain_config),
    {ok, Cfg} = beamchain_config:start_link(),
    unlink(Cfg),
    {module, beamchain_chainstate} = code:ensure_loaded(beamchain_chainstate),
    ok = meck:new(beamchain_chainstate, [no_link, passthrough]),
    ok = meck:expect(beamchain_chainstate, get_tip_height, fun() -> {ok, 0} end),
    {ok, L} = gen_tcp:listen(0, [binary, {active, false}, {ip, {127, 0, 0, 1}}]),
    {TmpDir, L}.

teardown({TmpDir, L}) ->
    catch gen_tcp:close(L),
    catch meck:unload(beamchain_chainstate),
    catch gen_server:stop(beamchain_config),
    application:unset_env(beamchain, peer_send_timeout_ms),
    os:cmd("rm -rf " ++ TmpDir),
    ok.

non_reading_peer_dropped() ->
    {_, L} = current_listener(),
    {Peer, Client} = ready_inbound_peer(L),
    MRef = erlang:monitor(process, Peer),
    %% Flood ~1.8 MB inv messages; the client never reads.
    Flood = spawn_flooder(Peer, 50000, 100),
    timer:sleep(3000),
    %% By now the peer is either gone or blocked in gen_tcp:send. A call to
    %% it (getpeerinfo) must not hang for the 5 s call timeout.
    ?assert(info_latency_ms(Peer) < 1000),
    MaxQ = watch_until_down(Peer, MRef, 12000, 0, Flood),
    exit(Flood, kill),
    gen_tcp:close(Client),
    ?assertMatch({down, _}, MaxQ),
    {down, Q} = MaxQ,
    %% The mailbox held at most what arrived during one send timeout.
    ?assert(Q < 200).

slow_reader_kept() ->
    {_, L} = current_listener(),
    {Peer, Client} = ready_inbound_peer(L),
    Total = 30,
    Items = 5000,                                %% ~180 KB per message
    Reader = spawn_reader(Client, 128 * 1024, 20),
    [beamchain_peer:send_message(Peer, {inv, #{items => inv_items(Items, N)}})
     || N <- lists:seq(1, Total)],
    timer:sleep(4 * ?SEND_TIMEOUT_MS),
    ?assert(is_process_alive(Peer)),
    Bytes = reader_bytes(Reader),
    ?assert(Bytes >= Total * Items * 36),
    exit(Reader, kill),
    beamchain_peer:disconnect(Peer),
    gen_tcp:close(Client).

other_peer_unaffected() ->
    {_, L} = current_listener(),
    {Stuck, StuckClient} = ready_inbound_peer(L),
    {Good, GoodClient} = ready_inbound_peer(L),
    Flood = spawn_flooder(Stuck, 50000, 100),
    timer:sleep(500),
    %% The good peer still delivers promptly.
    beamchain_peer:send_message(Good, {inv, #{items => inv_items(3, 1)}}),
    ?assertMatch({ok, _}, recv_command(GoodClient, inv, 3000)),
    exit(Flood, kill),
    beamchain_peer:disconnect(Good),
    catch beamchain_peer:disconnect(Stuck),
    gen_tcp:close(StuckClient),
    gen_tcp:close(GoodClient).

%%% ===================================================================
%%% Helpers
%%% ===================================================================

current_listener() ->
    %% foreach passes the fixture to the instantiator only; keep the
    %% listener in the process dictionary of the test process instead.
    case get(listener) of
        undefined ->
            {ok, L} = gen_tcp:listen(0, [binary, {active, false},
                                         {ip, {127, 0, 0, 1}}]),
            put(listener, L),
            {undefined, L};
        L -> {undefined, L}
    end.

ready_inbound_peer(L) ->
    {ok, Port} = inet:port(L),
    {ok, C} = gen_tcp:connect({127, 0, 0, 1}, Port,
                              [binary, {active, false}, {recbuf, 4096}]),
    {ok, A} = gen_tcp:accept(L),
    {ok, P} = beamchain_peer:accept(A, {{127, 0, 0, 3}, Port}, self()),
    ok = gen_tcp:controlling_process(A, P),
    P ! socket_owner_transferred,
    Magic = beamchain_config:magic(),
    Ver = beamchain_p2p_msg:encode_payload(version, #{
        version => 70016, services => 9,
        timestamp => erlang:system_time(second),
        addr_recv => #{services => 0, ip => {127, 0, 0, 1}, port => Port},
        addr_from => #{services => 9, ip => {0, 0, 0, 0, 0, 0, 0, 0}, port => 0},
        nonce => erlang:unique_integer([positive]),
        user_agent => <<"/gate6-test/">>, start_height => 0, relay => true}),
    ok = gen_tcp:send(C, beamchain_p2p_msg:encode_msg(Magic, version, Ver)),
    ok = gen_tcp:send(C, beamchain_p2p_msg:encode_msg(Magic, verack, <<>>)),
    receive {peer_connected, P, _} -> ok
    after 10000 -> error(handshake_timeout)
    end,
    {P, C}.

inv_items(N, Salt) ->
    [#{type => ?MSG_TX, hash => <<Salt:128, I:128>>} || I <- lists:seq(1, N)].

spawn_flooder(Peer, Items, EveryMs) ->
    spawn(fun() -> flood(Peer, Items, EveryMs, 1) end).

flood(Peer, Items, EveryMs, N) ->
    beamchain_peer:send_message(Peer, {inv, #{items => inv_items(Items, N)}}),
    timer:sleep(EveryMs),
    flood(Peer, Items, EveryMs, N + 1).

%% {down, MaxQueueSeen} once the peer exits, or {alive, MaxQ} at the
%% deadline. Also asserts that a call to the peer never hangs.
watch_until_down(Peer, _MRef, Left, MaxQ, Flood) when Left =< 0 ->
    _ = Flood,
    {_, Q} = safe_qlen(Peer),
    {alive, max(MaxQ, Q), info_latency_ms(Peer)};
watch_until_down(Peer, MRef, Left, MaxQ, Flood) ->
    receive
        {'DOWN', MRef, process, Peer, _} -> {down, MaxQ}
    after 250 ->
        {_, Q} = safe_qlen(Peer),
        watch_until_down(Peer, MRef, Left - 250, max(MaxQ, Q), Flood)
    end.

safe_qlen(Peer) ->
    case erlang:process_info(Peer, message_queue_len) of
        {message_queue_len, Q} -> {ok, Q};
        undefined -> {dead, 0}
    end.

%% gen_statem:call/2 defaults to an infinite timeout: on the deployed code a
%% call to a peer blocked in gen_tcp:send never returns. Cap the wait.
info_latency_ms(Peer) ->
    Self = self(),
    T0 = erlang:monotonic_time(millisecond),
    Pid = spawn(fun() -> catch beamchain_peer:info(Peer),
                         Self ! {info_done, self()} end),
    receive
        {info_done, Pid} -> erlang:monotonic_time(millisecond) - T0
    after 6000 ->
        exit(Pid, kill),
        6000
    end.

spawn_reader(C, Chunk, EveryMs) ->
    Self = self(),
    Pid = spawn(fun() -> read_loop(C, Chunk, EveryMs, 0, Self) end),
    ok = gen_tcp:controlling_process(C, Pid),
    Pid.

read_loop(C, Chunk, EveryMs, Got, Parent) ->
    receive
        {bytes, From} -> From ! {bytes, Got}, read_loop(C, Chunk, EveryMs, Got, Parent)
    after 0 ->
        Got2 = case gen_tcp:recv(C, 0, 50) of
                   {ok, B} -> Got + byte_size(B);
                   _ -> Got
               end,
        case Got2 - Got >= Chunk of
            true -> timer:sleep(EveryMs);
            false -> ok
        end,
        read_loop(C, Chunk, EveryMs, Got2, Parent)
    end.

reader_bytes(Reader) ->
    Reader ! {bytes, self()},
    receive {bytes, N} -> N after 5000 -> 0 end.

%% Read v1 frames until one with Command arrives.
recv_command(C, Command, Timeout) ->
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    recv_command(C, atom_to_binary(Command), Deadline, <<>>).

recv_command(C, Cmd, Deadline, Buf) ->
    case Buf of
        <<_Magic:4/binary, CmdBin:12/binary, Len:32/little, _Ck:4/binary,
          Body:Len/binary, Rest/binary>> ->
            case hd(binary:split(CmdBin, <<0>>)) of
                Cmd -> {ok, Body};
                _ -> recv_command(C, Cmd, Deadline, Rest)
            end;
        _ ->
            Left = Deadline - erlang:monotonic_time(millisecond),
            case Left > 0 andalso gen_tcp:recv(C, 0, Left) of
                {ok, More} -> recv_command(C, Cmd, Deadline, <<Buf/binary, More/binary>>);
                _ -> timeout
            end
    end.
