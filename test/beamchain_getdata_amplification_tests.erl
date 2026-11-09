-module(beamchain_getdata_amplification_tests).

%%% C5: one getdata of 50,000 x MSG_WITNESS_BLOCK used to be materialised
%%% in the requesting peer's mailbox (one {send, block, Block} cast per
%%% item, all queued before the first was written) while the whole list was
%%% read under the single node-wide serve slot (beamchain_serve_limiter,
%%% default 1), so every other peer's getdata waited for all 50,000 reads.
%%%
%%% Core (net_processing.cpp ProcessGetData) serves one item per pass,
%%% keeps the rest in Peer::m_getdata_requests and stops while the send
%%% buffer is full (fPauseSend).  beamchain now queues the decoded,
%%% de-duplicated items on the peer, serves one item per event taking the
%%% serve slot per item, and pauses while the socket's send queue is
%%% non-empty.
%%%
%%%   rebar3 eunit --module=beamchain_getdata_amplification_tests

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-define(SEND_TIMEOUT_MS, 4000).
-define(QUEUE_BOUND, 16).

%%% ===================================================================
%%% handle_getdata_msg: 50,000 identical block invs
%%% ===================================================================

handler_test_() ->
    {setup, fun setup_mocks/0, fun teardown_mocks/1,
     fun(_) ->
         [{timeout, 120, {"FIX: 50,000 identical block invs: peer mailbox bounded, second peer served meanwhile",
                          fun getdata_50k_same_block_bounded_memory/0}}]
     end}.

getdata_50k_same_block_bounded_memory() ->
    Hash = <<7:256>>,
    Big = getdata_payload([#{type => ?MSG_WITNESS_BLOCK, hash => Hash}
                           || _ <- lists:seq(1, ?MAX_INV_SIZE)]),
    PeerA = idle_peer(),
    PeerB = idle_peer(),
    Self = self(),
    %% Exactly as beamchain_peer serves a request: inside a serve slot.
    ServerA = spawn(fun() ->
        beamchain_serve_limiter:with_slot(fun() ->
            beamchain_peer_manager:handle_getdata_msg(PeerA, Big)
        end),
        Self ! {served, a}
    end),
    timer:sleep(200),
    ServerB = spawn(fun() ->
        beamchain_serve_limiter:with_slot(fun() ->
            beamchain_peer_manager:handle_getdata_msg(PeerB,
                getdata_payload([#{type => ?MSG_WITNESS_BLOCK,
                                   hash => <<8:256>>}]))
        end),
        Self ! {served, b}
    end),
    %% Sample peer A's mailbox for 3 s.
    MaxQ = sample_max_qlen(PeerA, 3000),
    BServed = receive {served, b} -> true after 0 -> false end,
    QB = qlen(PeerB),
    [exit(P, kill) || P <- [ServerA, ServerB]],
    Msgs = drain(PeerA),
    [exit(P, kill) || P <- [PeerA, PeerB]],
    ?assert(MaxQ =< ?QUEUE_BOUND),
    ?assert(BServed),
    ?assert(QB >= 1),
    %% The 50,000 repeats were collapsed to one item.
    ?assertMatch([{queue_getdata, [#{hash := Hash}]}], Msgs).

%%% ===================================================================
%%% Real peers over loopback
%%% ===================================================================

peer_test_() ->
    {foreach, fun setup_peers/0, fun teardown_peers/1,
     [fun(_) -> {timeout, 120, {"FIX: 50,000 distinct blocks to a non-reading peer: mailbox bounded, other peer served",
                                fun getdata_50k_distinct_blocks_bounded_memory/0}} end,
      fun(_) -> {timeout, 60, {"CONTROL: a reading peer gets every requested block, then one notfound",
                               fun getdata_reader_gets_every_block/0}} end,
      fun(_) -> {timeout, 60, {"FIX: 50,000 identical invs are answered with one block",
                               fun getdata_same_block_answered_once/0}} end]}.

getdata_50k_distinct_blocks_bounded_memory() ->
    L = listener(),
    {A, _ClientA} = ready_inbound_peer(L),     %% never reads
    {B, ClientB} = ready_inbound_peer(L),
    beamchain_peer:serve_request(A, getdata, getdata_payload(
        [#{type => ?MSG_WITNESS_BLOCK, hash => <<I:256>>}
         || I <- lists:seq(1, ?MAX_INV_SIZE)])),
    timer:sleep(300),
    beamchain_peer:serve_request(B, getdata, getdata_payload(
        [#{type => ?MSG_WITNESS_BLOCK, hash => <<1:256>>}])),
    T0 = erlang:monotonic_time(millisecond),
    BGot = recv_command(ClientB, block, 3000),
    BMs = erlang:monotonic_time(millisecond) - T0,
    MRef = erlang:monitor(process, A),
    MaxQ = sample_max_qlen(A, 2000),
    ?assertMatch({ok, _}, BGot),
    ?assert(BMs < 3000),
    ?assert(MaxQ =< ?QUEUE_BOUND),
    %% A peer that never reads is still dropped after the send timeout,
    %% as a blocked gen_tcp:send would have dropped it.
    Down = receive {'DOWN', MRef, process, A, R} -> {down, R}
           after 3 * ?SEND_TIMEOUT_MS -> alive end,
    ?assertMatch({down, _}, Down).

getdata_reader_gets_every_block() ->
    L = listener(),
    {P, C} = ready_inbound_peer(L),
    N = 200,
    Missing = <<"missing", 0:200>>,
    beamchain_peer:serve_request(P, getdata, getdata_payload(
        [#{type => ?MSG_WITNESS_BLOCK, hash => <<I:256>>} || I <- lists:seq(1, N)]
        ++ [#{type => ?MSG_WITNESS_BLOCK, hash => Missing}])),
    Got = [recv_command(C, block, 5000) || _ <- lists:seq(1, N)],
    ?assertEqual(N, length([ok || {ok, _} <- Got])),
    {ok, NF} = recv_command(C, notfound, 5000),
    ?assertMatch({ok, #{items := [#{hash := Missing}]}},
                 beamchain_p2p_msg:decode_payload(notfound, NF)).

getdata_same_block_answered_once() ->
    L = listener(),
    {P, C} = ready_inbound_peer(L),
    beamchain_peer:serve_request(P, getdata, getdata_payload(
        [#{type => ?MSG_WITNESS_BLOCK, hash => <<5:256>>}
         || _ <- lists:seq(1, ?MAX_INV_SIZE)])),
    ?assertMatch({ok, _}, recv_command(C, block, 5000)),
    ?assertEqual(timeout, recv_command(C, block, 1500)).

%%% ===================================================================
%%% Fixtures
%%% ===================================================================

setup_mocks() ->
    application:set_env(beamchain, serve_concurrency, 1),
    catch gen_server:stop(beamchain_serve_limiter),
    {ok, Lim} = beamchain_serve_limiter:start_link(),
    unlink(Lim),
    Genesis = beamchain_chain_params:genesis_block(regtest),
    {module, beamchain_db} = code:ensure_loaded(beamchain_db),
    ok = meck:new(beamchain_db, [no_link, passthrough]),
    %% Every hash but one "missing" one is a stored block; a read costs 1 ms.
    ok = meck:expect(beamchain_db, get_block,
                     fun(<<"missing", _/binary>>) -> not_found;
                        (_) -> timer:sleep(1), {ok, Genesis}
                     end),
    {module, beamchain_config} = code:ensure_loaded(beamchain_config),
    ok = meck:new(beamchain_config, [no_link, passthrough]),
    ok = meck:expect(beamchain_config, prune_enabled, fun() -> false end),
    Lim.

teardown_mocks(Lim) ->
    catch meck:unload(beamchain_config),
    catch meck:unload(beamchain_db),
    catch gen_server:stop(Lim),
    application:unset_env(beamchain, serve_concurrency),
    ok.

setup_peers() ->
    TmpDir = filename:join(["/tmp", "beamchain_getdata_amp_" ++
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
    Lim = setup_mocks(),
    {module, beamchain_chainstate} = code:ensure_loaded(beamchain_chainstate),
    ok = meck:new(beamchain_chainstate, [no_link, passthrough]),
    ok = meck:expect(beamchain_chainstate, get_tip_height, fun() -> {ok, 0} end),
    {TmpDir, Lim}.

teardown_peers({TmpDir, Lim}) ->
    catch meck:unload(beamchain_chainstate),
    teardown_mocks(Lim),
    catch gen_server:stop(beamchain_config),
    application:unset_env(beamchain, peer_send_timeout_ms),
    os:cmd("rm -rf " ++ TmpDir),
    ok.

%%% ===================================================================
%%% Helpers
%%% ===================================================================

%% foreach runs setup in another process: open the listener in the test
%% process itself (closed when that process exits).
listener() ->
    {ok, L} = gen_tcp:listen(0, [binary, {active, false}, {ip, {127, 0, 0, 1}}]),
    L.

getdata_payload(Items) ->
    beamchain_p2p_msg:encode_payload(getdata, #{items => Items}).

%% A peer stand-in that never consumes its mailbox (so its length is what
%% the server put there) until asked to dump it.
idle_peer() ->
    spawn(fun() -> receive {dump, From} -> From ! {msgs, collect([])} end end).

collect(Acc) ->
    receive {'$gen_cast', M} -> collect([M | Acc])
    after 0 -> lists:reverse(Acc)
    end.

drain(Peer) ->
    Peer ! {dump, self()},
    receive {msgs, L} -> L after 10000 -> timeout end.

qlen(Pid) ->
    case erlang:process_info(Pid, message_queue_len) of
        {message_queue_len, Q} -> Q;
        undefined -> 0
    end.

sample_max_qlen(Pid, Ms) ->
    sample_max_qlen(Pid, Ms, 0).
sample_max_qlen(_Pid, Ms, Max) when Ms =< 0 ->
    Max;
sample_max_qlen(Pid, Ms, Max) ->
    timer:sleep(50),
    sample_max_qlen(Pid, Ms - 50, max(Max, qlen(Pid))).

ready_inbound_peer(L) ->
    {ok, Port} = inet:port(L),
    {ok, C} = gen_tcp:connect({127, 0, 0, 1}, Port,
                              [binary, {active, false}, {recbuf, 4096}]),
    {ok, Acc} = gen_tcp:accept(L),
    {ok, P} = beamchain_peer:accept(Acc, {{127, 0, 0, 3}, Port}, self()),
    ok = gen_tcp:controlling_process(Acc, P),
    P ! socket_owner_transferred,
    Magic = beamchain_config:magic(),
    Ver = beamchain_p2p_msg:encode_payload(version, #{
        version => 70016, services => 9,
        timestamp => erlang:system_time(second),
        addr_recv => #{services => 0, ip => {127, 0, 0, 1}, port => Port},
        addr_from => #{services => 9, ip => {0, 0, 0, 0, 0, 0, 0, 0}, port => 0},
        nonce => erlang:unique_integer([positive]),
        user_agent => <<"/getdata-amp-test/">>, start_height => 0, relay => true}),
    ok = gen_tcp:send(C, beamchain_p2p_msg:encode_msg(Magic, version, Ver)),
    ok = gen_tcp:send(C, beamchain_p2p_msg:encode_msg(Magic, verack, <<>>)),
    receive {peer_connected, P, _} -> ok
    after 10000 -> error(handshake_timeout)
    end,
    {P, C}.

%% Read v1 frames until one with Command arrives.
recv_command(C, Command, Timeout) ->
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    recv_loop(C, atom_to_binary(Command), Deadline).

recv_loop(C, Cmd, Deadline) ->
    Buf = case get({buf, C}) of undefined -> <<>>; B -> B end,
    case Buf of
        <<_Magic:4/binary, CmdBin:12/binary, Len:32/little, _Ck:4/binary,
          Body:Len/binary, Rest/binary>> ->
            put({buf, C}, Rest),
            case hd(binary:split(CmdBin, <<0>>)) of
                Cmd -> {ok, Body};
                _ -> recv_loop(C, Cmd, Deadline)
            end;
        _ ->
            Left = Deadline - erlang:monotonic_time(millisecond),
            case Left > 0 andalso gen_tcp:recv(C, 0, Left) of
                {ok, More} ->
                    put({buf, C}, <<Buf/binary, More/binary>>),
                    recv_loop(C, Cmd, Deadline);
                _ ->
                    timeout
            end
    end.
