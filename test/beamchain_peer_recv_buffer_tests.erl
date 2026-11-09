-module(beamchain_peer_recv_buffer_tests).

%%% A frame that arrives in many small TCP segments must cost time linear
%%% in its size.
%%%
%%% beamchain_peer appended each segment to its receive buffer and then ran
%%% the frame decoder over the whole buffer.  The decoder matches the
%%% buffer, and appending to a binary that has been matched copies it, so
%%% every segment recopied everything received so far: O(size^2).  Measured
%%% on OTP 27 (staged-patches/cffix-beamchain-recv-buffer-quadratic): one
%%% 4 MB frame in 1460-byte segments cost ~3 s of copying in the peer
%%% process (1 MB: ~145 ms), against ~5 ms when the buffer is not re-parsed.
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
-define(SEG, 1460).
%% Just under MAX_PROTOCOL_MESSAGE_LENGTH (4 000 000).
-define(BIG, 3999000).
%% Generous: linear buffering of 4 MB takes a few ms; master takes ~3 s.
-define(LINEAR_BUDGET_US, 1000000).

%%% ===================================================================
%%% v1, through a real inbound peer process (the production path)
%%% ===================================================================

v1_inbound_peer_test_() ->
    {foreach,
     fun setup_peer/0,
     fun cleanup_peer/1,
     [fun(Ctx) ->
          {timeout, 60,
           {"a 4 MB v1 frame trickled in 1460-byte segments is buffered in linear time",
            fun() -> trickled_v1_frame_is_linear(Ctx) end}}
      end,
      fun(Ctx) ->
          {timeout, 60,
           {"a v1 frame fed one byte at a time dispatches on its last byte, not before",
            fun() -> v1_frame_dispatches_exactly_when_complete(Ctx) end}}
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
