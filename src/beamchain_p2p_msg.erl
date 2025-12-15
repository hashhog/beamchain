-module(beamchain_p2p_msg).

%% Bitcoin P2P protocol message serialization.
%%
%% Each message has a 24-byte header:
%%   magic(4) | command(12, null-padded) | length(4 LE) | checksum(4)
%% Checksum = first 4 bytes of SHA256d(payload).

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% Message framing
-export([encode_msg/3, decode_msg/1]).

%% Payload encode/decode
-export([encode_payload/2, decode_payload/2]).

%% Command name conversion
-export([command_name/1, command_atom/1]).

%% Network address (26 bytes, no timestamp — used in version msg)
-export([encode_net_addr/1, decode_net_addr/1]).

%%% ===================================================================
%%% Message framing
%%% ===================================================================

%% @doc Encode a framed P2P message.
%% Magic is the 4-byte network magic, Command is an atom,
%% Payload is the already-encoded payload binary.
-spec encode_msg(binary(), atom(), binary()) -> binary().
encode_msg(Magic, Command, Payload) ->
    CmdBin = pad_command(command_name(Command)),
    Len = byte_size(Payload),
    <<Check:4/binary, _/binary>> = beamchain_serialize:hash256(Payload),
    <<Magic:4/binary, CmdBin:12/binary, Len:32/little,
      Check:4/binary, Payload/binary>>.

%% @doc Decode a framed P2P message from a binary stream.
%% Returns {ok, Command, Payload, Rest} on success,
%% `incomplete' if more data is needed, or {error, Reason}.
-spec decode_msg(binary()) ->
    {ok, atom(), binary(), binary()} | incomplete | {error, term()}.
decode_msg(Bin) when byte_size(Bin) < 24 ->
    incomplete;
decode_msg(<<_Magic:4/binary, CmdBin:12/binary, Len:32/little,
             Check:4/binary, Rest/binary>>) ->
    case Len > ?MAX_PROTOCOL_MESSAGE_LENGTH of
        true ->
            {error, message_too_large};
        false when byte_size(Rest) < Len ->
            incomplete;
        false ->
            <<Payload:Len/binary, Rest2/binary>> = Rest,
            <<ExpCheck:4/binary, _/binary>> = beamchain_serialize:hash256(Payload),
            case Check =:= ExpCheck of
                true ->
                    Cmd = command_atom(unpad_command(CmdBin)),
                    {ok, Cmd, Payload, Rest2};
                false ->
                    {error, bad_checksum}
            end
    end.

%%% ===================================================================
%%% Command name mapping
%%% ===================================================================

-spec command_name(atom()) -> binary().
command_name(version)     -> <<"version">>;
command_name(verack)      -> <<"verack">>;
command_name(ping)        -> <<"ping">>;
command_name(pong)        -> <<"pong">>;
command_name(addr)        -> <<"addr">>;
command_name(getaddr)     -> <<"getaddr">>;
command_name(inv)         -> <<"inv">>;
command_name(getdata)     -> <<"getdata">>;
command_name(notfound)    -> <<"notfound">>;
command_name(getheaders)  -> <<"getheaders">>;
command_name(headers)     -> <<"headers">>;
command_name(getblocks)   -> <<"getblocks">>;
command_name(block)       -> <<"block">>;
command_name(tx)          -> <<"tx">>;
command_name(mempool)     -> <<"mempool">>;
command_name(sendheaders) -> <<"sendheaders">>;
command_name(feefilter)   -> <<"feefilter">>;
command_name(sendcmpct)   -> <<"sendcmpct">>;
command_name(cmpctblock)  -> <<"cmpctblock">>;
command_name(getblocktxn) -> <<"getblocktxn">>;
command_name(blocktxn)    -> <<"blocktxn">>;
command_name(wtxidrelay)  -> <<"wtxidrelay">>;
command_name(sendaddrv2)  -> <<"sendaddrv2">>.

-spec command_atom(binary()) -> atom().
command_atom(<<"version">>)     -> version;
command_atom(<<"verack">>)      -> verack;
command_atom(<<"ping">>)        -> ping;
command_atom(<<"pong">>)        -> pong;
command_atom(<<"addr">>)        -> addr;
command_atom(<<"getaddr">>)     -> getaddr;
command_atom(<<"inv">>)         -> inv;
command_atom(<<"getdata">>)     -> getdata;
command_atom(<<"notfound">>)    -> notfound;
command_atom(<<"getheaders">>)  -> getheaders;
command_atom(<<"headers">>)     -> headers;
command_atom(<<"getblocks">>)   -> getblocks;
command_atom(<<"block">>)       -> block;
command_atom(<<"tx">>)          -> tx;
command_atom(<<"mempool">>)     -> mempool;
command_atom(<<"sendheaders">>) -> sendheaders;
command_atom(<<"feefilter">>)   -> feefilter;
command_atom(<<"sendcmpct">>)   -> sendcmpct;
command_atom(<<"cmpctblock">>)  -> cmpctblock;
command_atom(<<"getblocktxn">>) -> getblocktxn;
command_atom(<<"blocktxn">>)    -> blocktxn;
command_atom(<<"wtxidrelay">>)  -> wtxidrelay;
command_atom(<<"sendaddrv2">>)  -> sendaddrv2;
command_atom(Other)             -> binary_to_atom(Other, utf8).

%%% ===================================================================
%%% Payload encoding
%%% ===================================================================

-spec encode_payload(atom(), map()) -> binary().

%% -- Handshake --------------------------------------------------------

encode_payload(version, #{version := V, services := Svc, timestamp := T,
                          addr_recv := Recv, addr_from := From,
                          nonce := Nonce, user_agent := UA,
                          start_height := Height, relay := Relay}) ->
    <<V:32/little, Svc:64/little, T:64/little,
      (encode_net_addr(Recv))/binary,
      (encode_net_addr(From))/binary,
      Nonce:64/little,
      (beamchain_serialize:encode_varstr(UA))/binary,
      Height:32/little-signed,
      (encode_bool(Relay)):8>>;

encode_payload(verack, _) -> <<>>;

encode_payload(ping, #{nonce := Nonce}) ->
    <<Nonce:64/little>>;

encode_payload(pong, #{nonce := Nonce}) ->
    <<Nonce:64/little>>.

%%% ===================================================================
%%% Payload decoding
%%% ===================================================================

-spec decode_payload(atom(), binary()) -> {ok, term()} | {error, term()}.

decode_payload(version, Bin) ->
    try decode_version(Bin) of
        Msg -> {ok, Msg}
    catch _:_ -> {error, bad_version}
    end;

decode_payload(verack, <<>>) ->
    {ok, #{}};

decode_payload(ping, <<Nonce:64/little>>) ->
    {ok, #{nonce => Nonce}};

decode_payload(pong, <<Nonce:64/little>>) ->
    {ok, #{nonce => Nonce}}.

%%% ===================================================================
%%% Version message decoding
%%% ===================================================================

decode_version(Bin) ->
    <<V:32/little, Svc:64/little, T:64/little, Rest/binary>> = Bin,
    {Recv, Rest2} = decode_net_addr(Rest),
    {From, Rest3} = decode_net_addr(Rest2),
    <<Nonce:64/little, Rest4/binary>> = Rest3,
    {UA, Rest5} = beamchain_serialize:decode_varstr(Rest4),
    <<Height:32/little-signed, Rest6/binary>> = Rest5,
    Relay = case Rest6 of
        <<R:8, _/binary>> -> R =/= 0;
        <<>> -> true   %% relay defaults to true if absent
    end,
    #{version => V, services => Svc, timestamp => T,
      addr_recv => Recv, addr_from => From,
      nonce => Nonce, user_agent => UA,
      start_height => Height, relay => Relay}.

%%% ===================================================================
%%% Network address (26 bytes, no timestamp)
%%% ===================================================================

-spec encode_net_addr(map()) -> binary().
encode_net_addr(#{services := Svc, ip := IP, port := Port}) ->
    IPBin = encode_ip(IP),
    <<Svc:64/little, IPBin:16/binary, Port:16/big>>.

-spec decode_net_addr(binary()) -> {map(), binary()}.
decode_net_addr(<<Svc:64/little, IPBin:16/binary, Port:16/big, Rest/binary>>) ->
    {#{services => Svc, ip => decode_ip(IPBin), port => Port}, Rest}.

%%% ===================================================================
%%% Internal helpers
%%% ===================================================================

encode_ip({A, B, C, D}) ->
    %% IPv4-mapped IPv6
    <<0:80, 16#FFFF:16, A:8, B:8, C:8, D:8>>;
encode_ip(Bin) when byte_size(Bin) =:= 16 ->
    Bin.

decode_ip(<<0:80, 16#FFFF:16, A:8, B:8, C:8, D:8>>) ->
    {A, B, C, D};
decode_ip(<<IPv6:16/binary>>) ->
    IPv6.

pad_command(Name) when byte_size(Name) =< 12 ->
    PadLen = 12 - byte_size(Name),
    <<Name/binary, 0:(PadLen * 8)>>.

unpad_command(<<Bin:12/binary>>) ->
    strip_trailing_nulls(Bin).

strip_trailing_nulls(<<>>) -> <<>>;
strip_trailing_nulls(Bin) ->
    case binary:last(Bin) of
        0 -> strip_trailing_nulls(binary:part(Bin, 0, byte_size(Bin) - 1));
        _ -> Bin
    end.

encode_bool(true) -> 1;
encode_bool(false) -> 0.
