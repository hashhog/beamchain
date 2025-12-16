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

%% Addr entry (30 bytes, with timestamp — used in addr msg)
-export([encode_addr_entry/1, decode_addr_entry/1]).

%% Inventory items
-export([encode_inv_item/1, decode_inv_item/1]).

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
    <<Nonce:64/little>>;

%% -- Address discovery ------------------------------------------------

encode_payload(addr, #{addrs := Addrs}) ->
    Count = beamchain_serialize:encode_varint(length(Addrs)),
    Data = << <<(encode_addr_entry(A))/binary>> || A <- Addrs >>,
    <<Count/binary, Data/binary>>;

encode_payload(getaddr, _) -> <<>>;

%% -- Inventory --------------------------------------------------------

encode_payload(inv, #{items := Items}) ->
    encode_inv_list(Items);

encode_payload(getdata, #{items := Items}) ->
    encode_inv_list(Items);

encode_payload(notfound, #{items := Items}) ->
    encode_inv_list(Items);

%% -- Headers/blocks ---------------------------------------------------

encode_payload(getheaders, #{version := V, locators := Locators,
                             stop_hash := Stop}) ->
    Count = beamchain_serialize:encode_varint(length(Locators)),
    LocBin = << <<H:32/binary>> || H <- Locators >>,
    <<V:32/little, Count/binary, LocBin/binary, Stop:32/binary>>;

encode_payload(headers, #{headers := Headers}) ->
    Count = beamchain_serialize:encode_varint(length(Headers)),
    Data = << <<(beamchain_serialize:encode_block_header(H))/binary,
               0:8>> || H <- Headers >>,
    <<Count/binary, Data/binary>>;

encode_payload(getblocks, #{version := V, locators := Locators,
                            stop_hash := Stop}) ->
    Count = beamchain_serialize:encode_varint(length(Locators)),
    LocBin = << <<H:32/binary>> || H <- Locators >>,
    <<V:32/little, Count/binary, LocBin/binary, Stop:32/binary>>;

encode_payload(block, Block) ->
    beamchain_serialize:encode_block(Block);

encode_payload(tx, Tx) ->
    beamchain_serialize:encode_transaction(Tx);

encode_payload(sendheaders, _) -> <<>>;

encode_payload(mempool, _) -> <<>>.

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
    {ok, #{nonce => Nonce}};

%% -- Address discovery ------------------------------------------------

decode_payload(addr, Bin) ->
    {Count, Rest} = beamchain_serialize:decode_varint(Bin),
    {Addrs, _} = decode_addr_entries(Count, Rest, []),
    {ok, #{addrs => Addrs}};

decode_payload(getaddr, <<>>) ->
    {ok, #{}};

%% -- Inventory --------------------------------------------------------

decode_payload(inv, Bin) ->
    {ok, #{items => decode_inv_list(Bin)}};

decode_payload(getdata, Bin) ->
    {ok, #{items => decode_inv_list(Bin)}};

decode_payload(notfound, Bin) ->
    {ok, #{items => decode_inv_list(Bin)}};

%% -- Headers/blocks ---------------------------------------------------

decode_payload(getheaders, <<V:32/little, Rest/binary>>) ->
    {Count, Rest2} = beamchain_serialize:decode_varint(Rest),
    {Locators, Rest3} = decode_hashes(Count, Rest2, []),
    <<Stop:32/binary, _/binary>> = Rest3,
    {ok, #{version => V, locators => Locators, stop_hash => Stop}};

decode_payload(headers, Bin) ->
    {Count, Rest} = beamchain_serialize:decode_varint(Bin),
    {Headers, _} = decode_headers_list(Count, Rest, []),
    {ok, #{headers => Headers}};

decode_payload(getblocks, <<V:32/little, Rest/binary>>) ->
    {Count, Rest2} = beamchain_serialize:decode_varint(Rest),
    {Locators, Rest3} = decode_hashes(Count, Rest2, []),
    <<Stop:32/binary, _/binary>> = Rest3,
    {ok, #{version => V, locators => Locators, stop_hash => Stop}};

decode_payload(block, Bin) ->
    {Block, _} = beamchain_serialize:decode_block(Bin),
    {ok, Block};

decode_payload(tx, Bin) ->
    {Tx, _} = beamchain_serialize:decode_transaction(Bin),
    {ok, Tx};

decode_payload(sendheaders, <<>>) ->
    {ok, #{}};

decode_payload(mempool, <<>>) ->
    {ok, #{}}.

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
%%% Addr entry (30 bytes: timestamp + net_addr)
%%% ===================================================================

-spec encode_addr_entry(map()) -> binary().
encode_addr_entry(#{timestamp := T, services := Svc, ip := IP, port := Port}) ->
    IPBin = encode_ip(IP),
    <<T:32/little, Svc:64/little, IPBin:16/binary, Port:16/big>>.

-spec decode_addr_entry(binary()) -> {map(), binary()}.
decode_addr_entry(<<T:32/little, Svc:64/little, IPBin:16/binary,
                    Port:16/big, Rest/binary>>) ->
    {#{timestamp => T, services => Svc,
       ip => decode_ip(IPBin), port => Port}, Rest}.

decode_addr_entries(0, Rest, Acc) -> {lists:reverse(Acc), Rest};
decode_addr_entries(N, Bin, Acc) ->
    {Entry, Rest} = decode_addr_entry(Bin),
    decode_addr_entries(N - 1, Rest, [Entry | Acc]).

%%% ===================================================================
%%% Inventory items (36 bytes: type + hash)
%%% ===================================================================

-spec encode_inv_item(map()) -> binary().
encode_inv_item(#{type := Type, hash := Hash}) ->
    <<Type:32/little, Hash:32/binary>>.

-spec decode_inv_item(binary()) -> {map(), binary()}.
decode_inv_item(<<Type:32/little, Hash:32/binary, Rest/binary>>) ->
    {#{type => Type, hash => Hash}, Rest}.

encode_inv_list(Items) ->
    Count = beamchain_serialize:encode_varint(length(Items)),
    Data = << <<(encode_inv_item(I))/binary>> || I <- Items >>,
    <<Count/binary, Data/binary>>.

decode_inv_list(Bin) ->
    {Count, Rest} = beamchain_serialize:decode_varint(Bin),
    decode_inv_items(Count, Rest, []).

decode_inv_items(0, _Rest, Acc) -> lists:reverse(Acc);
decode_inv_items(N, Bin, Acc) ->
    {Item, Rest} = decode_inv_item(Bin),
    decode_inv_items(N - 1, Rest, [Item | Acc]).

%%% ===================================================================
%%% Hash list / headers list helpers
%%% ===================================================================

decode_hashes(0, Rest, Acc) -> {lists:reverse(Acc), Rest};
decode_hashes(N, <<H:32/binary, Rest/binary>>, Acc) ->
    decode_hashes(N - 1, Rest, [H | Acc]).

%% Each header entry in a "headers" message is 80 bytes + varint(0)
decode_headers_list(0, Rest, Acc) -> {lists:reverse(Acc), Rest};
decode_headers_list(N, Bin, Acc) ->
    {Header, Rest} = beamchain_serialize:decode_block_header(Bin),
    {_TxCount, Rest2} = beamchain_serialize:decode_varint(Rest),
    decode_headers_list(N - 1, Rest2, [Header | Acc]).

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
