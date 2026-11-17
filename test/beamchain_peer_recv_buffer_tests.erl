-module(beamchain_peer_recv_buffer_tests).

%%% A frame that arrives in many small TCP segments must cost time linear
%%% in its size.
%%%
%%% beamchain_peer appended each segment to its receive buffer and then ran
%%% the frame decoder over the whole buffer.  The decoder matches the
%%% buffer, and appending to a binary that has been matched copies it, so
%%% every segment recopied everything received so far: O(size^2).  Measured
%%% on OTP 27 with scripts/recv_bench/recv_bench.erl (output beside it): one
%%% 4 MB frame in 1460-byte segments cost ~3 s of copying in the peer
%%% process (536-byte segments: ~7 s), against ~5 ms when the buffer is not
%%% re-parsed.
%%% Any peer can send one such frame per 4 MB of bandwidth, before the
%%% handshake.
%%%
%%% Core reads into a per-message buffer sized from the header
%%% (net.cpp V1Transport::readHeader/readData) and never re-scans it.
%%%
%%%   rebar3 eunit --module=beamchain_peer_recv_buffer_tests

-include_lib("eunit/include/eunit.hrl").

-define(MAGIC, <<16#fa, 16#bf, 16#b5, 16#da>>).
-define(V2_MAGIC, <<16#1c, 16#16, 16#3f, 16#28>>).
%% The minimum IPv4 MSS: what a trickling peer can force.
-define(SEG, 536).
%% Just under MAX_PROTOCOL_MESSAGE_LENGTH (4 000 000).
-define(BIG, 3999000).
%% Linear buffering of 4 MB in 536-byte segments takes ~5-40 ms; master
%% took 4-7 s (1.7-3 s at 1460 bytes).  >10x margin on each side.
-define(LINEAR_BUDGET_US, 500000).
%% MAX_PROTOCOL_MESSAGE_LENGTH + 1.
-define(OVERSIZE, 4000001).

%%% ===================================================================
%%% v1, through a real inbound peer process (the production path)
%%% ===================================================================

v1_inbound_peer_test_() ->
    {foreach,
     fun setup_peer/0,
     fun cleanup_peer/1,
     [fun(Ctx) ->
          {timeout, 60,
           {"a 4 MB v1 frame trickled in 536-byte segments is buffered in linear time",
            fun() -> trickled_v1_frame_is_linear(Ctx) end}}
      end,
      fun(Ctx) ->
          {timeout, 60,
           {"a v1 frame fed one byte at a time dispatches on its last byte, not before",
            fun() -> v1_frame_dispatches_exactly_when_complete(Ctx) end}}
      end,
      fun(Ctx) ->
          {timeout, 60,
           {"a v1 header claiming more than 4 MB stops the peer on its 24th byte",
            fun() -> v1_oversize_header_stops_peer(Ctx) end}}
      end,
      fun(_Ctx) ->
          {timeout, 60,
           {"after a backpressure pause, resume recomputes the size gate",
            fun resume_after_pause_recomputes_need/0}}
      end]}.

setup_peer() ->
    ok = meck:new(beamchain_config, [no_link, passthrough]),
    ok = meck:expect(beamchain_config, magic, fun() -> ?MAGIC end),
    {ok, L} = gen_tcp:listen(0, [binary, {active, false}, {ip, loopback}]),
    {ok, Port} = inet:port(L),
    {ok, C} = gen_tcp:connect({127, 0, 0, 1}, Port, [binary, {active, false}]),
    {ok, S} = gen_tcp:accept(L),
    {ok, Pid} = beamchain_peer:accept(S, {{127, 0, 0, 1}, Port}, self()),
    #{listen => L, client => C, server => S, pid => Pid}.

cleanup_peer(#{listen := L, client := C, pid := Pid}) ->
    exit(Pid, kill),
    gen_tcp:close(C),
    gen_tcp:close(L),
    meck:unload(beamchain_config).

%% The first 16 bytes classify the inbound stream as v1 ("version"
%% header); the checksum is only checked once the frame is complete.
v1_frame(PayloadLen, Payload) ->
    <<Check:4/binary, _/binary>> = beamchain_crypto:hash256(Payload),
    <<?MAGIC/binary, "version", 0:40, PayloadLen:32/little,
      Check/binary, Payload/binary>>.

%% Inject segments exactly as gen_tcp {active, once} delivers them.
inject(Pid, S, Bin) ->
    Pid ! {tcp, S, binary:copy(Bin)}.

%% #peer_data.buffer is the 4th field (element 5 of the record tuple).
peer_buffer(Pid) ->
    {_StateName, Data} = sys:get_state(Pid, 60000),
    Buf = element(5, Data),
    true = is_binary(Buf),
    Buf.

segments(Bin, N) when byte_size(Bin) =< N -> [Bin];
segments(Bin, N) ->
    <<H:N/binary, T/binary>> = Bin,
    [H | segments(T, N)].

trickled_v1_frame_is_linear(#{server := S, pid := Pid}) ->
    Frame = v1_frame(?BIG, crypto:strong_rand_bytes(?BIG)),
    %% Everything but the last byte: the frame stays partial throughout.
    Partial = binary:part(Frame, 0, byte_size(Frame) - 1),
    Segs = [binary:copy(Seg) || Seg <- segments(Partial, ?SEG)],
    {Us, Buf} = timer:tc(fun() ->
        [Pid ! {tcp, S, Seg} || Seg <- Segs],
        peer_buffer(Pid)
    end),
    ?assert(is_process_alive(Pid)),
    ?assertEqual(byte_size(Partial), byte_size(Buf)),
    ?assert(Us < ?LINEAR_BUDGET_US,
            lists:flatten(io_lib:format(
              "buffering ~B bytes in ~B segments took ~B ms (budget ~B ms)",
              [byte_size(Partial), length(Segs), Us div 1000,
               ?LINEAR_BUDGET_US div 1000]))).

v1_frame_dispatches_exactly_when_complete(#{server := S, pid := Pid}) ->
    %% eunit runs foreach setup in another process: monitor from here.
    Mon = erlang:monitor(process, Pid),
    %% A checksum-valid frame whose 10-byte payload is not a valid version
    %% message: dispatching it stops the peer with bad_version.  Fed one
    %% byte at a time, the header itself arrives split, so this covers the
    %% partial-header and partial-payload states.
    Frame = v1_frame(10, <<0:80>>),
    N = byte_size(Frame),
    lists:foreach(
      fun(I) ->
          inject(Pid, S, binary:part(Frame, I, 1)),
          ?assertEqual(I + 1, byte_size(peer_buffer(Pid)))
      end, lists:seq(0, N - 2)),
    inject(Pid, S, binary:part(Frame, N - 1, 1)),
    receive
        {'DOWN', Mon, process, Pid, Reason} ->
            ?assertEqual(bad_version, Reason)
    after 10000 ->
        ?assert(false, "complete frame was never dispatched")
    end.

%% Warden, hashhog/beamchain#65 (2026-11-10): decode_msg rejects a header
%% whose length exceeds MAX_PROTOCOL_MESSAGE_LENGTH as soon as the 24
%% header bytes are present.  The size gate must not defer that: a first
%% segment of 20-23 bytes that already holds such a length must not set
%% recv_need to 24 + Len (up to ~4 GB buffered before the reject).
v1_oversize_header_stops_peer(#{server := S, pid := Pid}) ->
    Mon = erlang:monitor(process, Pid),
    Hdr = <<?MAGIC/binary, "version", 0:40, (?OVERSIZE):32/little, 0:32>>,
    inject(Pid, S, binary:part(Hdr, 0, 20)),
    ?assertEqual(20, byte_size(peer_buffer(Pid))),
    inject(Pid, S, binary:part(Hdr, 20, 4)),
    receive
        {'DOWN', Mon, process, Pid, Reason} ->
            ?assertEqual({shutdown, {frame_error, message_too_large}}, Reason)
    after 10000 ->
        ?assert(false, "oversize header was buffered instead of rejected")
    end.

%% Master's receive backpressure (recv_paused / resume_recv) dispatches
%% the frames left in the buffer from resume_recv, outside buffer_recv/2.
%% If that left recv_need at the size of a frame it has since consumed, a
%% smaller frame behind it would wait for bytes that never come.  Here a
%% 100 kB frame is consumed on resume and a 50-byte frame behind it must
%% still dispatch on its last byte.
resume_after_pause_recomputes_need() ->
    %% Pause as soon as one forwarded frame is in our mailbox.
    application:set_env(beamchain, recv_backlog_limit, 0),
    %% The version reply reads the tip height; no chainstate runs here.
    {module, _} = code:ensure_loaded(beamchain_chainstate),
    ok = meck:new(beamchain_chainstate, [no_link, passthrough]),
    ok = meck:expect(beamchain_chainstate, get_tip_height, fun() -> {ok, 0} end),
    ok = meck:expect(beamchain_config, prune_enabled, fun() -> false end),
    try resume_after_pause_recomputes_need_()
    after
        meck:unload(beamchain_chainstate),
        application:unset_env(beamchain, recv_backlog_limit)
    end.

resume_after_pause_recomputes_need_() ->
    {ok, L} = gen_tcp:listen(0, [binary, {active, false}, {ip, loopback}]),
    {ok, Port} = inet:port(L),
    {ok, C} = gen_tcp:connect({127, 0, 0, 1}, Port, [binary, {active, false}]),
    {ok, S} = gen_tcp:accept(L),
    %% Handler = this process, so its mailbox is the backlog.
    {ok, Pid} = beamchain_peer:accept(S, {{127, 0, 0, 1}, Port}, self()),
    ok = gen_tcp:controlling_process(S, Pid),
    Pid ! socket_owner_transferred,
    Ver = beamchain_p2p_msg:encode_payload(version, #{
        version => 70016, services => 9,
        timestamp => erlang:system_time(second),
        addr_recv => #{services => 0, ip => {127, 0, 0, 1}, port => Port},
        addr_from => #{services => 9, ip => {0, 0, 0, 0, 0, 0, 0, 0}, port => 0},
        nonce => erlang:unique_integer([positive]),
        user_agent => <<"/recv-buffer-test/">>, start_height => 0,
        relay => true}),
    ok = gen_tcp:send(C, beamchain_p2p_msg:encode_msg(?MAGIC, version, Ver)),
    ok = gen_tcp:send(C, beamchain_p2p_msg:encode_msg(?MAGIC, verack, <<>>)),
    receive {peer_connected, Pid, _} -> ok
    after 10000 -> error(handshake_timeout)
    end,
    %% peer_connected sat in our mailbox, so the peer paused after verack.
    %% Wait for that pause to clear, so no resume_recv timer is in flight
    %% (a stray one dispatches the buffer whatever recv_need says, and
    %% would hide the stall this test is for).
    wait_unpaused(Pid, 200),
    Block = fun(Len) ->
                beamchain_p2p_msg:encode_msg(?MAGIC, block,
                                             binary:copy(<<Len:8>>, Len))
            end,
    F1 = Block(10), F2 = Block(100000), F3 = Block(50),
    <<F3a:30/binary, F3b/binary>> = F3,
    %% F1 is forwarded and the peer pauses with F2 + the start of F3
    %% buffered: recv_need is F2's size.
    inject(Pid, S, <<F1/binary, F2/binary, F3a/binary>>),
    %% F1's forward is still in our mailbox, so the peer stays paused.
    ?assertEqual(byte_size(F2) + 30, byte_size(peer_buffer(Pid))),
    ?assertEqual(10, forwarded_block(Pid)),
    %% Our mailbox is empty again: resume_recv dispatches F2, pauses again.
    ?assertEqual(100000, forwarded_block(Pid)),
    %% Resumed (the resume found only F3's first 30 bytes, incomplete) and
    %% re-armed: from here only a new segment can dispatch F3.
    wait_unpaused(Pid, 200),
    ?assertEqual(30, byte_size(peer_buffer(Pid))),
    inject(Pid, S, F3b),
    ?assertEqual(50, forwarded_block(Pid)),
    exit(Pid, kill),
    gen_tcp:close(C),
    gen_tcp:close(L).

%% recv_paused is the last #peer_data field.
wait_unpaused(_Pid, 0) ->
    error(still_paused);
wait_unpaused(Pid, N) ->
    {_State, Data} = sys:get_state(Pid),
    case element(tuple_size(Data), Data) of
        false -> ok;
        true -> timer:sleep(10), wait_unpaused(Pid, N - 1)
    end.

forwarded_block(Pid) ->
    receive {peer_message, Pid, block, Payload} -> byte_size(Payload)
    after 5000 ->
        {_State, Data} = sys:get_state(Pid),
        {not_dispatched, {buffered, byte_size(element(5, Data))}}
    end.

%%% ===================================================================
%%% Unit level: recv_need/1 and buffer_recv/2 (test exports)
%%% ===================================================================

v1_recv_need_test() ->
    Hdr = <<?MAGIC/binary, "block", 0:56, 1000:32/little, 0:32>>,
    P = fun(B) -> beamchain_peer:make_test_peer(v1, undefined, B) end,
    ?assertEqual(24, beamchain_peer:recv_need(P(<<>>))),
    ?assertEqual(24, beamchain_peer:recv_need(P(binary:part(Hdr, 0, 19)))),
    ?assertEqual(24 + 1000, beamchain_peer:recv_need(P(Hdr))),
    ?assertEqual(24 + 1000, beamchain_peer:recv_need(P(<<Hdr/binary, 0:800>>))).

v2_cipher_pair() ->
    {ok, A0} = beamchain_transport_v2:new_cipher(),
    {ok, B0} = beamchain_transport_v2:new_cipher(),
    PA = beamchain_transport_v2:get_pubkey(A0),
    PB = beamchain_transport_v2:get_pubkey(B0),
    {ok, A1} = beamchain_transport_v2:initialize(A0, PB, true, false, ?V2_MAGIC),
    {ok, B1} = beamchain_transport_v2:initialize(B0, PA, false, false, ?V2_MAGIC),
    {A1, B1}.

v2_recv_need_test() ->
    {A1, B1} = v2_cipher_pair(),
    Contents = beamchain_v2_msg:encode_contents(block, <<0:8000>>),
    {ok, CT, _} = beamchain_transport_v2:encrypt(A1, Contents, <<>>, false),
    %% 3-byte length + 1-byte header + contents + 16-byte tag.
    Total = 3 + 1 + byte_size(Contents) + 16,
    ?assertEqual(Total, byte_size(CT)),
    P = fun(B) -> beamchain_peer:make_test_peer(ready, B1, B) end,
    ?assertEqual(3, beamchain_peer:recv_need(P(<<>>))),
    ?assertEqual(3, beamchain_peer:recv_need(P(binary:part(CT, 0, 2)))),
    ?assertEqual(Total, beamchain_peer:recv_need(P(binary:part(CT, 0, 3)))),
    ?assertEqual(Total, beamchain_peer:recv_need(P(binary:part(CT, 0, 500)))).

%% v2 counterpart of the linear-time test, through buffer_recv/2.  The
%% decrypted `block` arrives before the handshake, so dispatch ignores it
%% (Core's pre-verack rule) and the buffer is simply consumed.
v2_trickled_packet_is_linear_and_dispatched_test_() ->
    {timeout, 60, fun v2_trickled_packet/0}.

v2_trickled_packet() ->
    {A1, B1} = v2_cipher_pair(),
    Contents = beamchain_v2_msg:encode_contents(block,
                                                crypto:strong_rand_bytes(?BIG)),
    {ok, CT, _} = beamchain_transport_v2:encrypt(A1, Contents, <<>>, false),
    Partial = binary:part(CT, 0, byte_size(CT) - 1),
    Segs = [binary:copy(Seg) || Seg <- segments(Partial, ?SEG)],
    Peer0 = beamchain_peer:make_test_peer(ready, B1, <<>>),
    {Us, Peer1} = timer:tc(fun() ->
        lists:foldl(fun(Seg, P) ->
                        {ok, P2} = beamchain_peer:buffer_recv(Seg, P),
                        P2
                    end, Peer0, Segs)
    end),
    ?assert(Us < ?LINEAR_BUDGET_US,
            lists:flatten(io_lib:format("v2 buffering took ~B ms", [Us div 1000]))),
    ?assertEqual(byte_size(CT), beamchain_peer:recv_need(Peer1)),
    %% The last byte completes the packet: it is decrypted and consumed.
    {ok, Peer2} = beamchain_peer:buffer_recv(binary:part(CT, byte_size(CT) - 1, 1),
                                             Peer1),
    ?assertEqual(3, beamchain_peer:recv_need(Peer2)).

%% No frame is lost or held back by the size gate: two complete frames and
%% the start of a third arrive in one segment, the rest of the third in a
%% second.  `block` before the handshake is ignored (Core's pre-verack
%% rule), so each dispatched frame simply leaves the buffer.
v1_frames_split_across_segments_all_dispatch_test() ->
    F = fun(Len) ->
            Payload = binary:copy(<<7>>, Len),
            <<Check:4/binary, _/binary>> = beamchain_crypto:hash256(Payload),
            <<?MAGIC/binary, "block", 0:56, Len:32/little, Check/binary,
              Payload/binary>>
        end,
    F1 = F(100), F2 = F(0), F3 = F(5000),
    Cut = 30,
    <<F3a:Cut/binary, F3b/binary>> = F3,
    P0 = beamchain_peer:make_test_peer(v1, undefined, <<>>),
    {ok, P1} = beamchain_peer:buffer_recv(<<F1/binary, F2/binary, F3a/binary>>, P0),
    %% F1 and F2 consumed; the gate now waits for all of F3.
    ?assertEqual(byte_size(F3), beamchain_peer:recv_need(P1)),
    %% Deliver F3 in pieces below the gate, then the last byte.
    Body = binary:part(F3b, 0, byte_size(F3b) - 1),
    P2 = lists:foldl(fun(Seg, P) ->
                         {ok, Q} = beamchain_peer:buffer_recv(Seg, P),
                         ?assertEqual(byte_size(F3), beamchain_peer:recv_need(Q)),
                         Q
                     end, P1, segments(Body, 700)),
    {ok, P3} = beamchain_peer:buffer_recv(binary:part(F3b, byte_size(F3b) - 1, 1), P2),
    %% F3 consumed: buffer empty, the gate is back to a bare header.
    ?assertEqual(24, beamchain_peer:recv_need(P3)),
    %% A frame with a bad checksum is still reported once complete.
    Bad = <<?MAGIC/binary, "block", 0:56, 4:32/little, 0:32, 1:32>>,
    ?assertMatch({stop, {shutdown, {frame_error, bad_checksum}}},
                 beamchain_peer:buffer_recv(Bad, P0)).

%% The BIP-324 decoy phase reads packets with the same decoder as `ready`,
%% and a decoy may be up to 4 MB, so it is gated the same way: a peer that
%% has sent its pubkey and garbage terminator cannot trickle a 4 MB decoy
%% at quadratic cost either.
v2_trickled_decoy_is_linear_and_consumed_test_() ->
    {timeout, 60, fun v2_trickled_decoy/0}.

v2_trickled_decoy() ->
    {A1, B1} = v2_cipher_pair(),
    %% Ignore bit set: a decoy.  AAD <<>> matches make_test_peer's
    %% v2_next_aad (empty garbage).
    {ok, CT, _} = beamchain_transport_v2:encrypt(
                    A1, crypto:strong_rand_bytes(?BIG), <<>>, true),
    Partial = binary:part(CT, 0, byte_size(CT) - 1),
    Segs = [binary:copy(Seg) || Seg <- segments(Partial, ?SEG)],
    Peer0 = beamchain_peer:make_test_peer(drain_decoy, B1, <<>>),
    {Us, Peer1} = timer:tc(fun() ->
        lists:foldl(fun(Seg, P) ->
                        {ok, P2} = beamchain_peer:buffer_recv(Seg, P),
                        P2
                    end, Peer0, Segs)
    end),
    ?assert(Us < ?LINEAR_BUDGET_US,
            lists:flatten(io_lib:format("v2 decoy buffering took ~B ms",
                                        [Us div 1000]))),
    ?assertEqual(byte_size(CT), beamchain_peer:recv_need(Peer1)),
    %% The last byte completes the decoy: decrypted, discarded, consumed;
    %% still waiting for the version packet.
    {ok, Peer2} = beamchain_peer:buffer_recv(
                    binary:part(CT, byte_size(CT) - 1, 1), Peer1),
    ?assertEqual(3, beamchain_peer:recv_need(Peer2)).

%% Unit-level twin of v1_oversize_header_stops_peer: 20 bytes of a v1
%% header with Len = 4000001, then the 4 checksum bytes.  recv_need never
%% exceeds 24, so the checksum bytes reach the decoder and the frame is
%% rejected at the header.  Also fed one byte at a time.
v1_oversize_header_recv_need_capped_test() ->
    Hdr = <<?MAGIC/binary, "block", 0:56, (?OVERSIZE):32/little, 0:32>>,
    P0 = beamchain_peer:make_test_peer(v1, undefined, <<>>),
    {ok, P1} = beamchain_peer:buffer_recv(binary:part(Hdr, 0, 20), P0),
    ?assertEqual(24, beamchain_peer:recv_need(P1)),
    ?assertMatch({stop, {shutdown, {frame_error, message_too_large}}},
                 beamchain_peer:buffer_recv(binary:part(Hdr, 20, 4), P1)),
    %% The whole header in one segment: rejected, never buffered.
    ?assertMatch({stop, {shutdown, {frame_error, message_too_large}}},
                 beamchain_peer:buffer_recv(Hdr, P0)),
    %% Byte at a time: the gate stays at 24 through the length field.
    Last = lists:foldl(
             fun(I, P) ->
                 {ok, Q} = beamchain_peer:buffer_recv(binary:part(Hdr, I, 1), P),
                 ?assert(beamchain_peer:recv_need(Q) =< 24),
                 Q
             end, P0, lists:seq(0, 22)),
    ?assertMatch({stop, {shutdown, {frame_error, message_too_large}}},
                 beamchain_peer:buffer_recv(binary:part(Hdr, 23, 1), Last)),
    %% The exact maximum is still a legal size and waits for its payload.
    Max = <<?MAGIC/binary, "block", 0:56, (?OVERSIZE - 1):32/little, 0:32>>,
    {ok, PM} = beamchain_peer:buffer_recv(Max, P0),
    ?assertEqual(24 + ?OVERSIZE - 1, beamchain_peer:recv_need(PM)).
