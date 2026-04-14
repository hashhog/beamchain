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

%% ADDRv2 (BIP155) support
-export([encode_addrv2_entry/1, decode_addrv2_entry/1]).
-export([network_id/1, network_id_to_atom/1, addr_size_for_network/1]).

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
command_name(sendaddrv2)  -> <<"sendaddrv2">>;
command_name(addrv2)      -> <<"addrv2">>;
%% BIP330 Erlay transaction reconciliation
command_name(sendtxrcncl) -> <<"sendtxrcncl">>;
command_name(reqrecon)    -> <<"reqrecon">>;
command_name(sketch)      -> <<"sketch">>;
command_name(reconcildiff) -> <<"reconcildiff">>;
command_name(reqsketchext) -> <<"reqsketchext">>;
command_name(reqtx)       -> <<"reqtx">>.

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
command_atom(<<"addrv2">>)      -> addrv2;
%% BIP330 Erlay transaction reconciliation
command_atom(<<"sendtxrcncl">>) -> sendtxrcncl;
command_atom(<<"reqrecon">>)    -> reqrecon;
command_atom(<<"sketch">>)      -> sketch;
command_atom(<<"reconcildiff">>) -> reconcildiff;
command_atom(<<"reqsketchext">>) -> reqsketchext;
command_atom(<<"reqtx">>)       -> reqtx;
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

encode_payload(mempool, _) -> <<>>;

%% -- Policy ---------------------------------------------------------------

encode_payload(feefilter, #{feerate := Fee}) ->
    <<Fee:64/little>>;

encode_payload(sendcmpct, #{announce := Ann, version := V}) ->
    <<(encode_bool(Ann)):8, V:64/little>>;

encode_payload(wtxidrelay, _) -> <<>>;

encode_payload(sendaddrv2, _) -> <<>>;

%% -- ADDRv2 (BIP155) -----------------------------------------------------

encode_payload(addrv2, #{addrs := Addrs}) ->
    Count = beamchain_serialize:encode_varint(length(Addrs)),
    Data = << <<(encode_addrv2_entry(A))/binary>> || A <- Addrs >>,
    <<Count/binary, Data/binary>>;

%% -- Compact blocks (BIP 152) --------------------------------------------

encode_payload(cmpctblock, #{header := Header, nonce := Nonce,
                             short_ids := ShortIds,
                             prefilled_txns := Prefilled}) ->
    HdrBin = beamchain_serialize:encode_block_header(Header),
    SIDCount = beamchain_serialize:encode_varint(length(ShortIds)),
    SIDBin = << <<SID:6/binary>> || SID <- ShortIds >>,
    PreCount = beamchain_serialize:encode_varint(length(Prefilled)),
    PreBin = << <<(encode_prefilled_txn(P))/binary>> || P <- Prefilled >>,
    <<HdrBin/binary, Nonce:64/little,
      SIDCount/binary, SIDBin/binary,
      PreCount/binary, PreBin/binary>>;

encode_payload(getblocktxn, #{block_hash := Hash, indexes := Indexes}) ->
    Count = beamchain_serialize:encode_varint(length(Indexes)),
    IdxBin = encode_diff_indexes(Indexes),
    <<Hash:32/binary, Count/binary, IdxBin/binary>>;

encode_payload(blocktxn, #{block_hash := Hash, transactions := Txs}) ->
    Count = beamchain_serialize:encode_varint(length(Txs)),
    TxsBin = << <<(beamchain_serialize:encode_transaction(T))/binary>>
                || T <- Txs >>,
    <<Hash:32/binary, Count/binary, TxsBin/binary>>;

%% -- BIP330 Erlay transaction reconciliation -------------------------------

%% sendtxrcncl: version(4) + salt(8)
encode_payload(sendtxrcncl, #{version := V, salt := Salt}) ->
    <<V:32/little, Salt:64/little>>;

%% reqrecon: peer_set_size(2) + q(2)
%% q = coefficient for estimating expected difference
encode_payload(reqrecon, #{set_size := SetSize, q := Q}) ->
    <<SetSize:16/little, Q:16/little>>;

%% sketch: sketch_data (variable length)
encode_payload(sketch, #{sketch := SketchData}) ->
    SketchData;

%% reconcildiff: success(1) + short_ids (if success)
encode_payload(reconcildiff, #{success := true, short_ids := ShortIds}) ->
    Count = beamchain_serialize:encode_varint(length(ShortIds)),
    IdsBin = << <<Id:32/little>> || Id <- ShortIds >>,
    <<1:8, Count/binary, IdsBin/binary>>;
encode_payload(reconcildiff, #{success := false}) ->
    <<0:8>>;

%% reqsketchext: extension capacity request
encode_payload(reqsketchext, _) ->
    <<>>;

%% reqtx: request missing transactions by short txid
encode_payload(reqtx, #{short_ids := ShortIds}) ->
    Count = beamchain_serialize:encode_varint(length(ShortIds)),
    IdsBin = << <<Id:32/little>> || Id <- ShortIds >>,
    <<Count/binary, IdsBin/binary>>.

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
    {ok, #{}};

%% -- Policy ---------------------------------------------------------------

decode_payload(feefilter, <<Fee:64/little>>) ->
    {ok, #{feerate => Fee}};

decode_payload(sendcmpct, <<Ann:8, V:64/little>>) ->
    {ok, #{announce => Ann =/= 0, version => V}};

decode_payload(wtxidrelay, <<>>) ->
    {ok, #{}};

decode_payload(sendaddrv2, <<>>) ->
    {ok, #{}};

%% -- ADDRv2 (BIP155) -----------------------------------------------------

decode_payload(addrv2, Bin) ->
    {Count, Rest} = beamchain_serialize:decode_varint(Bin),
    {Addrs, _} = decode_addrv2_entries(Count, Rest, []),
    {ok, #{addrs => Addrs}};

%% -- Compact blocks (BIP 152) --------------------------------------------

decode_payload(cmpctblock, Bin) ->
    {Header, Rest} = beamchain_serialize:decode_block_header(Bin),
    <<Nonce:64/little, Rest2/binary>> = Rest,
    {SIDCount, Rest3} = beamchain_serialize:decode_varint(Rest2),
    {ShortIds, Rest4} = decode_short_ids(SIDCount, Rest3, []),
    {PreCount, Rest5} = beamchain_serialize:decode_varint(Rest4),
    {Prefilled, _} = decode_prefilled_txns(PreCount, Rest5, []),
    {ok, #{header => Header, nonce => Nonce,
           short_ids => ShortIds, prefilled_txns => Prefilled}};

decode_payload(getblocktxn, <<Hash:32/binary, Rest/binary>>) ->
    {Count, Rest2} = beamchain_serialize:decode_varint(Rest),
    {Indexes, _} = decode_diff_indexes(Count, Rest2),
    {ok, #{block_hash => Hash, indexes => Indexes}};

decode_payload(blocktxn, <<Hash:32/binary, Rest/binary>>) ->
    {Count, Rest2} = beamchain_serialize:decode_varint(Rest),
    {Txs, _} = decode_txs(Count, Rest2, []),
    {ok, #{block_hash => Hash, transactions => Txs}};

%% -- BIP330 Erlay transaction reconciliation -------------------------------

decode_payload(sendtxrcncl, <<V:32/little, Salt:64/little>>) ->
    {ok, #{version => V, salt => Salt}};

decode_payload(reqrecon, <<SetSize:16/little, Q:16/little>>) ->
    {ok, #{set_size => SetSize, q => Q}};

decode_payload(sketch, SketchData) ->
    {ok, #{sketch => SketchData}};

decode_payload(reconcildiff, <<1:8, Rest/binary>>) ->
    {Count, Rest2} = beamchain_serialize:decode_varint(Rest),
    {ShortIds, _} = decode_erlay_short_ids(Count, Rest2, []),
    {ok, #{success => true, short_ids => ShortIds}};
decode_payload(reconcildiff, <<0:8>>) ->
    {ok, #{success => false, short_ids => []}};

decode_payload(reqsketchext, <<>>) ->
    {ok, #{}};

decode_payload(reqtx, Bin) ->
    {Count, Rest} = beamchain_serialize:decode_varint(Bin),
    {ShortIds, _} = decode_erlay_short_ids(Count, Rest, []),
    {ok, #{short_ids => ShortIds}}.

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
%%% Compact block helpers (BIP 152)
%%% ===================================================================

encode_prefilled_txn(#{index := Idx, tx := Tx}) ->
    IdxBin = beamchain_serialize:encode_varint(Idx),
    TxBin = beamchain_serialize:encode_transaction(Tx),
    <<IdxBin/binary, TxBin/binary>>.

decode_prefilled_txns(0, Rest, Acc) -> {lists:reverse(Acc), Rest};
decode_prefilled_txns(N, Bin, Acc) ->
    {Idx, Rest} = beamchain_serialize:decode_varint(Bin),
    {Tx, Rest2} = beamchain_serialize:decode_transaction(Rest),
    decode_prefilled_txns(N - 1, Rest2, [#{index => Idx, tx => Tx} | Acc]).

decode_short_ids(0, Rest, Acc) -> {lists:reverse(Acc), Rest};
decode_short_ids(N, <<SID:6/binary, Rest/binary>>, Acc) ->
    decode_short_ids(N - 1, Rest, [SID | Acc]).

%% Erlay short txids (32-bit, little-endian)
decode_erlay_short_ids(0, Rest, Acc) -> {lists:reverse(Acc), Rest};
decode_erlay_short_ids(N, <<Id:32/little, Rest/binary>>, Acc) ->
    decode_erlay_short_ids(N - 1, Rest, [Id | Acc]).

%% Differentially-encoded indexes for getblocktxn.
%% Each index is encoded as the difference from the previous index minus one.
encode_diff_indexes([]) -> <<>>;
encode_diff_indexes([First | Rest]) ->
    encode_diff_indexes(Rest, First, beamchain_serialize:encode_varint(First)).

encode_diff_indexes([], _Prev, Acc) -> Acc;
encode_diff_indexes([Idx | Rest], Prev, Acc) ->
    Diff = Idx - Prev - 1,
    DiffBin = beamchain_serialize:encode_varint(Diff),
    encode_diff_indexes(Rest, Idx, <<Acc/binary, DiffBin/binary>>).

decode_diff_indexes(Count, Bin) ->
    decode_diff_indexes(Count, Bin, -1, []).

decode_diff_indexes(0, Rest, _Prev, Acc) -> {lists:reverse(Acc), Rest};
decode_diff_indexes(N, Bin, Prev, Acc) ->
    {Diff, Rest} = beamchain_serialize:decode_varint(Bin),
    Idx = Prev + Diff + 1,
    decode_diff_indexes(N - 1, Rest, Idx, [Idx | Acc]).

decode_txs(0, Rest, Acc) -> {lists:reverse(Acc), Rest};
decode_txs(N, Bin, Acc) ->
    {Tx, Rest} = beamchain_serialize:decode_transaction(Bin),
    decode_txs(N - 1, Rest, [Tx | Acc]).

%%% ===================================================================
%%% Internal helpers
%%% ===================================================================

encode_ip({A, B, C, D}) ->
    %% IPv4-mapped IPv6
    <<0:80, 16#FFFF:16, A:8, B:8, C:8, D:8>>;
encode_ip({A, B, C, D, E, F, G, H}) ->
    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>;
encode_ip(Bin) when byte_size(Bin) =:= 16 ->
    Bin.

decode_ip(<<0:80, 16#FFFF:16, A:8, B:8, C:8, D:8>>) ->
    {A, B, C, D};
decode_ip(<<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>) ->
    {A, B, C, D, E, F, G, H}.

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

%%% ===================================================================
%%% BIP155 ADDRv2 support
%%% ===================================================================

%% BIP155 Network IDs
-define(BIP155_IPV4, 1).
-define(BIP155_IPV6, 2).
-define(BIP155_TORV2, 3).  %% deprecated, 10 bytes
-define(BIP155_TORV3, 4).  %% 32 bytes (ed25519 pubkey)
-define(BIP155_I2P, 5).    %% 32 bytes (SHA256 of destination)
-define(BIP155_CJDNS, 6).  %% 16 bytes (starts with 0xFC)

%% Address sizes per network
-define(ADDR_IPV4_SIZE, 4).
-define(ADDR_IPV6_SIZE, 16).
-define(ADDR_TORV2_SIZE, 10).
-define(ADDR_TORV3_SIZE, 32).
-define(ADDR_I2P_SIZE, 32).
-define(ADDR_CJDNS_SIZE, 16).
-define(MAX_ADDRV2_SIZE, 512).

%% @doc Get BIP155 network ID for an address.
%% Returns network_id for the given address type.
-spec network_id(map() | inet:ip_address() | binary()) -> non_neg_integer().
network_id(#{network_id := NetId}) -> NetId;
network_id(#{network := Network}) -> network_atom_to_id(Network);
network_id(#{ip := IP}) -> network_id(IP);
network_id({_, _, _, _}) -> ?BIP155_IPV4;
network_id({_, _, _, _, _, _, _, _}) -> ?BIP155_IPV6;
network_id(Bin) when byte_size(Bin) =:= 32 ->
    %% Could be TorV3 or I2P - need network_id field to distinguish
    ?BIP155_TORV3;  %% default assumption
network_id(Bin) when byte_size(Bin) =:= 16 ->
    case Bin of
        <<16#FC, _:120>> -> ?BIP155_CJDNS;
        _ -> ?BIP155_IPV6
    end;
network_id(Bin) when byte_size(Bin) =:= 10 -> ?BIP155_TORV2;
network_id(_) -> ?BIP155_IPV4.

%% @doc Convert network atom to BIP155 network ID.
-spec network_atom_to_id(atom()) -> non_neg_integer().
network_atom_to_id(ipv4)  -> ?BIP155_IPV4;
network_atom_to_id(ipv6)  -> ?BIP155_IPV6;
network_atom_to_id(torv2) -> ?BIP155_TORV2;
network_atom_to_id(torv3) -> ?BIP155_TORV3;
network_atom_to_id(i2p)   -> ?BIP155_I2P;
network_atom_to_id(cjdns) -> ?BIP155_CJDNS;
network_atom_to_id(_)     -> ?BIP155_IPV4.

%% @doc Convert BIP155 network ID to atom.
-spec network_id_to_atom(non_neg_integer()) -> atom().
network_id_to_atom(?BIP155_IPV4)  -> ipv4;
network_id_to_atom(?BIP155_IPV6)  -> ipv6;
network_id_to_atom(?BIP155_TORV2) -> torv2;
network_id_to_atom(?BIP155_TORV3) -> torv3;
network_id_to_atom(?BIP155_I2P)   -> i2p;
network_id_to_atom(?BIP155_CJDNS) -> cjdns;
network_id_to_atom(_)             -> unknown.

%% @doc Get expected address size for a BIP155 network ID.
-spec addr_size_for_network(non_neg_integer()) -> non_neg_integer() | variable.
addr_size_for_network(?BIP155_IPV4)  -> ?ADDR_IPV4_SIZE;
addr_size_for_network(?BIP155_IPV6)  -> ?ADDR_IPV6_SIZE;
addr_size_for_network(?BIP155_TORV2) -> ?ADDR_TORV2_SIZE;
addr_size_for_network(?BIP155_TORV3) -> ?ADDR_TORV3_SIZE;
addr_size_for_network(?BIP155_I2P)   -> ?ADDR_I2P_SIZE;
addr_size_for_network(?BIP155_CJDNS) -> ?ADDR_CJDNS_SIZE;
addr_size_for_network(_)             -> variable.

%% @doc Encode an ADDRv2 address entry.
%% Entry format: time(4) + services(compactsize) + network_id(1) + addr_len(compactsize) + addr + port(2)
-spec encode_addrv2_entry(map()) -> binary().
encode_addrv2_entry(#{timestamp := T, services := Svc} = Entry) ->
    %% Determine network ID and address bytes
    {NetId, AddrBytes} = encode_addrv2_address(Entry),
    AddrLen = byte_size(AddrBytes),
    Port = maps:get(port, Entry, 0),
    SvcBin = beamchain_serialize:encode_varint(Svc),
    LenBin = beamchain_serialize:encode_varint(AddrLen),
    <<T:32/little, SvcBin/binary, NetId:8, LenBin/binary, AddrBytes/binary, Port:16/big>>.

%% @doc Encode the address portion based on network type.
-spec encode_addrv2_address(map()) -> {non_neg_integer(), binary()}.
encode_addrv2_address(#{network_id := NetId, address := Addr}) when is_binary(Addr) ->
    {NetId, Addr};
encode_addrv2_address(#{network := torv3, address := Addr}) when byte_size(Addr) =:= 32 ->
    {?BIP155_TORV3, Addr};
encode_addrv2_address(#{network := i2p, address := Addr}) when byte_size(Addr) =:= 32 ->
    {?BIP155_I2P, Addr};
encode_addrv2_address(#{network := cjdns, address := Addr}) when byte_size(Addr) =:= 16 ->
    {?BIP155_CJDNS, Addr};
encode_addrv2_address(#{ip := {A, B, C, D}}) ->
    {?BIP155_IPV4, <<A:8, B:8, C:8, D:8>>};
encode_addrv2_address(#{ip := {A, B, C, D, E, F, G, H}}) ->
    {?BIP155_IPV6, <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>};
encode_addrv2_address(#{ip := Bin}) when byte_size(Bin) =:= 16 ->
    {?BIP155_IPV6, Bin};
encode_addrv2_address(#{address := Addr}) when byte_size(Addr) =:= 4 ->
    {?BIP155_IPV4, Addr};
encode_addrv2_address(#{address := Addr}) when byte_size(Addr) =:= 16 ->
    %% Check if CJDNS (starts with 0xFC)
    case Addr of
        <<16#FC, _:120>> -> {?BIP155_CJDNS, Addr};
        _ -> {?BIP155_IPV6, Addr}
    end;
encode_addrv2_address(#{address := Addr}) when byte_size(Addr) =:= 32 ->
    %% Assume TorV3 for 32-byte addresses without explicit network
    {?BIP155_TORV3, Addr}.

%% @doc Decode an ADDRv2 address entry.
-spec decode_addrv2_entry(binary()) -> {map(), binary()}.
decode_addrv2_entry(<<T:32/little, Rest/binary>>) ->
    {Svc, Rest2} = beamchain_serialize:decode_varint(Rest),
    <<NetId:8, Rest3/binary>> = Rest2,
    {AddrLen, Rest4} = beamchain_serialize:decode_varint(Rest3),
    <<AddrBytes:AddrLen/binary, Port:16/big, Rest5/binary>> = Rest4,
    Entry = decode_addrv2_address(NetId, AddrBytes, T, Svc, Port),
    {Entry, Rest5}.

%% @doc Decode address bytes based on network ID.
-spec decode_addrv2_address(non_neg_integer(), binary(), non_neg_integer(),
                             non_neg_integer(), non_neg_integer()) -> map().
decode_addrv2_address(?BIP155_IPV4, <<A:8, B:8, C:8, D:8>>, T, Svc, Port) ->
    #{timestamp => T, services => Svc, network => ipv4,
      network_id => ?BIP155_IPV4, ip => {A, B, C, D}, port => Port};
decode_addrv2_address(?BIP155_IPV6, AddrBytes, T, Svc, Port) when byte_size(AddrBytes) =:= 16 ->
    %% Parse as IPv6 tuple or IPv4-mapped
    IP = decode_ipv6_address(AddrBytes),
    #{timestamp => T, services => Svc, network => ipv6,
      network_id => ?BIP155_IPV6, ip => IP, port => Port};
decode_addrv2_address(?BIP155_TORV2, AddrBytes, T, Svc, Port) when byte_size(AddrBytes) =:= 10 ->
    %% TorV2 is deprecated but we still decode it
    #{timestamp => T, services => Svc, network => torv2,
      network_id => ?BIP155_TORV2, address => AddrBytes, port => Port};
decode_addrv2_address(?BIP155_TORV3, AddrBytes, T, Svc, Port) when byte_size(AddrBytes) =:= 32 ->
    %% TorV3: 32-byte ed25519 public key
    #{timestamp => T, services => Svc, network => torv3,
      network_id => ?BIP155_TORV3, address => AddrBytes, port => Port};
decode_addrv2_address(?BIP155_I2P, AddrBytes, T, Svc, Port) when byte_size(AddrBytes) =:= 32 ->
    %% I2P: 32-byte destination hash
    #{timestamp => T, services => Svc, network => i2p,
      network_id => ?BIP155_I2P, address => AddrBytes, port => Port};
decode_addrv2_address(?BIP155_CJDNS, AddrBytes, T, Svc, Port) when byte_size(AddrBytes) =:= 16 ->
    %% CJDNS: 16-byte address (starts with 0xFC)
    #{timestamp => T, services => Svc, network => cjdns,
      network_id => ?BIP155_CJDNS, address => AddrBytes, port => Port};
decode_addrv2_address(NetId, AddrBytes, T, Svc, Port) ->
    %% Unknown network type - store raw
    #{timestamp => T, services => Svc, network => unknown,
      network_id => NetId, address => AddrBytes, port => Port}.

%% @doc Decode an IPv6 address, handling IPv4-mapped addresses.
-spec decode_ipv6_address(binary()) -> inet:ip_address().
decode_ipv6_address(<<0:80, 16#FFFF:16, A:8, B:8, C:8, D:8>>) ->
    %% IPv4-mapped IPv6 address
    {A, B, C, D};
decode_ipv6_address(<<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>) ->
    {A, B, C, D, E, F, G, H}.

%% @doc Decode multiple addrv2 entries.
decode_addrv2_entries(0, Rest, Acc) -> {lists:reverse(Acc), Rest};
decode_addrv2_entries(N, Bin, Acc) ->
    {Entry, Rest} = decode_addrv2_entry(Bin),
    decode_addrv2_entries(N - 1, Rest, [Entry | Acc]).
