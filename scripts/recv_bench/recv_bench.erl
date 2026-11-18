%% Receive-buffer cost harness: how long one peer frame takes to buffer
%% when it arrives in many small TCP segments.
%%
%% It replays beamchain_peer's receive loop in its own process, which holds
%% the buffer in a record as the gen_statem does. One framed `block`
%% message of each size is delivered in fixed-size segments, and the whole
%% delivery is timed (wall clock, in the receiving process).
%%
%% Variants:
%%   master  : the pre-fix loop (beamchain 444142c handle_tcp_data/2 +
%%             process_buffer_v1/1): append the segment, then run
%%             beamchain_p2p_msg:decode_msg/1 over the whole buffer, which
%%             returns `incomplete` until the frame is whole.
%%   head    : the fix's logic (beamchain_peer:buffer_recv/2): append, and
%%             decode only once the buffer reaches the size the header says.
%%   nomatch : negative control. Append only, and decode once at the end:
%%             nothing matches the buffer in between.
%%   copy    : positive control. binary:copy/1 the buffer on every segment,
%%             a forced full recopy: what quadratic looks like.
%%
%% Run from a built beamchain checkout (rebar3 compile), on any OTP:
%%   mkdir -p _build/recv_bench && erlc -o _build/recv_bench scripts/recv_bench/recv_bench.erl
%%   erl -noshell -pa _build/recv_bench -pa _build/default/lib/*/ebin \
%%       -s recv_bench main 1460 -s init stop
%% The argument is the segment size in bytes (1460: a typical Ethernet MSS;
%% 536: the IPv4 minimum). Output from OTP 27 is in output-otp27.txt.
-module(recv_bench).
-export([main/0, main/1]).

-record(pd, {buffer = <<>> :: binary(), bytes_recv = 0, last_recv = 0}).

main() -> main([1460]).
main([Chunk0]) ->
    Chunk = case Chunk0 of A when is_atom(A) -> list_to_integer(atom_to_list(A)); I -> I end,
    io:format("OTP ~s, chunk=~B bytes~n", [erlang:system_info(otp_release), Chunk]),
    Sizes = [250000, 500000, 1000000, 2000000, 3999000],
    lists:foreach(fun(V) ->
        io:format("~n variant=~p~n", [V]),
        io:format("  ~10s ~8s ~10s ~12s ~s~n",
                  ["size", "chunks", "ms", "ns/byte", "frame_consumed"]),
        lists:foreach(fun(S) -> run(V, S, Chunk) end, Sizes)
    end, [master, head, nomatch, copy]).

run(Variant, Size, Chunk) ->
    Payload = crypto:strong_rand_bytes(Size),
    Frame = beamchain_p2p_msg:encode_msg(<<16#0b, 16#11, 16#09, 16#07>>, block, Payload),
    Chunks = split(Frame, Chunk, []),
    Self = self(),
    Pid = spawn_opt(fun() -> worker(Self, Variant) end, [link]),
    %% warm: let worker start
    Pid ! {go, Chunks},
    receive {done, Pid, Us, Ok} ->
        io:format("  ~10B ~8B ~10.1f ~12.2f ~p~n",
                  [Size, length(Chunks), Us / 1000, Us * 1000 / Size, Ok])
    end.

split(<<>>, _, Acc) -> lists:reverse(Acc);
split(Bin, N, Acc) when byte_size(Bin) =< N -> lists:reverse([Bin | Acc]);
split(Bin, N, Acc) ->
    <<H:N/binary, T/binary>> = Bin,
    %% copy so each chunk is a fresh binary, as gen_tcp delivers
    split(T, N, [binary:copy(H) | Acc]).

worker(Parent, Variant) ->
    receive {go, Chunks} -> ok end,
    garbage_collect(),
    T0 = erlang:monotonic_time(microsecond),
    {Res, _} = feed(Variant, Chunks, #pd{}),
    T1 = erlang:monotonic_time(microsecond),
    Parent ! {done, self(), T1 - T0, Res}.

feed(_, [], #pd{buffer = B} = D) ->
    {byte_size(B) =:= 0, D};
feed(master, [New | T], #pd{buffer = Buf} = D) ->
    Buffer = <<Buf/binary, New/binary>>,
    D2 = D#pd{buffer = Buffer, bytes_recv = D#pd.bytes_recv + byte_size(New),
              last_recv = erlang:system_time(millisecond)},
    case beamchain_p2p_msg:decode_msg(Buffer) of
        {ok, _Cmd, _Payload, Rest} -> feed(master, T, D2#pd{buffer = Rest});
        incomplete -> feed(master, T, D2);
        {error, R} -> {{error, R}, D2}
    end;
%% head: the fix's logic (beamchain_peer:buffer_recv/2) - skip decoding
%% while byte_size(Buffer) < Need; Need from the v1 header after dispatch.
feed(head, Chunks, D) -> feed_head(Chunks, D, 0);
feed(nomatch, [New | T], #pd{buffer = Buf} = D) ->
    Buffer = <<Buf/binary, New/binary>>,
    D2 = D#pd{buffer = Buffer},
    case T of
        [] ->
            {ok, _, _, Rest} = beamchain_p2p_msg:decode_msg(Buffer),
            feed(nomatch, T, D2#pd{buffer = Rest});
        _ -> feed(nomatch, T, D2)
    end;
feed(copy, [New | T], #pd{buffer = Buf} = D) ->
    Buffer = binary:copy(<<Buf/binary, New/binary>>),
    D2 = D#pd{buffer = Buffer},
    case beamchain_p2p_msg:decode_msg(Buffer) of
        {ok, _Cmd, _Payload, Rest} -> feed(copy, T, D2#pd{buffer = Rest});
        incomplete -> feed(copy, T, D2);
        {error, R} -> {{error, R}, D2}
    end.

feed_head([], #pd{buffer = B} = D, _) -> {byte_size(B) =:= 0, D};
feed_head([New | T], #pd{buffer = Buf} = D, Need) ->
    Buffer = <<Buf/binary, New/binary>>,
    D2 = D#pd{buffer = Buffer, bytes_recv = D#pd.bytes_recv + byte_size(New),
              last_recv = erlang:system_time(millisecond)},
    case byte_size(Buffer) < Need of
        true -> feed_head(T, D2, Need);
        false ->
            case beamchain_p2p_msg:decode_msg(Buffer) of
                {ok, _Cmd, _Payload, Rest} ->
                    feed_head(T, D2#pd{buffer = Rest}, need(Rest));
                incomplete -> feed_head(T, D2, need(Buffer));
                {error, R} -> {{error, R}, D2}
            end
    end.

need(<<_:16/binary, Len:32/little, _/binary>>) -> 24 + Len;
need(_) -> 24.
