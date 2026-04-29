-module(beamchain_v2_msg).

%% @doc BIP-324 v2 application-layer message wrap/unwrap.
%%
%% Once the v2 cipher handshake has completed, each application message
%% travels inside one AEAD packet whose plaintext contents are:
%%
%%     short_id (1 byte) || payload                 (when short_id =/= 0)
%%     0x00 (1 byte) || 12-byte ASCII command || payload   (long form)
%%
%% This is NOT the v1 24-byte framed envelope (no magic, no length, no
%% checksum) — those fields are subsumed by the v2 outer AEAD packet's
%% encrypted-length field and Poly1305 tag.
%%
%% The short-id table is fixed by BIP-324 (29 entries, indices 1..28).
%% Index 0 is reserved as the "long-form" sentinel.

-export([encode_contents/2, decode_contents/1]).

%% Internal helpers (exported for unit tests).
-export([short_id_for/1, command_for_short_id/1, short_id_table/0]).

%%% ===================================================================
%%% Short-id table (BIP-324)
%%% ===================================================================

%% Index 0 is the "long-form" sentinel.  Indices 1..28 are the standard
%% BIP-324 short-message-ids.  29..255 are reserved.
short_id_table() ->
    [<<>>,                  %% 0 — reserved sentinel
     <<"addr">>,            %% 1
     <<"block">>,           %% 2
     <<"blocktxn">>,        %% 3
     <<"cmpctblock">>,      %% 4
     <<"feefilter">>,       %% 5
     <<"filteradd">>,       %% 6
     <<"filterclear">>,     %% 7
     <<"filterload">>,      %% 8
     <<"getblocks">>,       %% 9
     <<"getblocktxn">>,     %% 10
     <<"getdata">>,         %% 11
     <<"getheaders">>,      %% 12
     <<"headers">>,         %% 13
     <<"inv">>,             %% 14
     <<"mempool">>,         %% 15
     <<"merkleblock">>,     %% 16
     <<"notfound">>,        %% 17
     <<"ping">>,            %% 18
     <<"pong">>,            %% 19
     <<"sendcmpct">>,       %% 20
     <<"tx">>,              %% 21
     <<"getcfilters">>,     %% 22
     <<"cfilter">>,         %% 23
     <<"getcfheaders">>,    %% 24
     <<"cfheaders">>,       %% 25
     <<"getcfcheckpt">>,    %% 26
     <<"cfcheckpt">>,       %% 27
     <<"addrv2">>           %% 28
    ].

%% @doc Look up a command's short-id.  Returns ``undefined`` for
%% commands that must use the long-form (e.g. ``version``, ``verack``,
%% ``sendaddrv2``, ``wtxidrelay``, ``sendtxrcncl``).
-spec short_id_for(binary()) -> non_neg_integer() | undefined.
short_id_for(Cmd) when is_binary(Cmd) ->
    short_id_for(Cmd, 1, tl(short_id_table())).

short_id_for(_Cmd, _Idx, []) -> undefined;
short_id_for(Cmd, Idx, [Cmd | _]) -> Idx;
short_id_for(Cmd, Idx, [_ | Rest]) -> short_id_for(Cmd, Idx + 1, Rest).

%% @doc Look up the command name for a given short-id.  Returns
%% ``undefined`` for id 0 (the long-form sentinel) or any reserved /
%% unknown id.
-spec command_for_short_id(non_neg_integer()) -> binary() | undefined.
command_for_short_id(0) -> undefined;
command_for_short_id(Id) when is_integer(Id), Id > 0 ->
    Table = short_id_table(),
    case Id < length(Table) of
        true ->
            case lists:nth(Id + 1, Table) of
                <<>> -> undefined;
                Cmd  -> Cmd
            end;
        false ->
            undefined
    end.

%%% ===================================================================
%%% Wrap/unwrap
%%% ===================================================================

%% @doc Encode one v2 packet body for a (Command, Payload) pair.  Caller
%% feeds the result to ``beamchain_transport_v2:encrypt/4``.
-spec encode_contents(atom() | binary(), binary()) -> binary().
encode_contents(Command, Payload) when is_atom(Command) ->
    encode_contents(beamchain_p2p_msg:command_name(Command), Payload);
encode_contents(CmdBin, Payload) when is_binary(CmdBin), is_binary(Payload) ->
    case short_id_for(CmdBin) of
        undefined ->
            %% Long form: 0x00 || 12-byte ASCII command (null-padded) || payload
            CmdLen = byte_size(CmdBin),
            true = CmdLen =< 12,
            Padding = binary:copy(<<0>>, 12 - CmdLen),
            <<0, CmdBin/binary, Padding/binary, Payload/binary>>;
        Id when is_integer(Id) ->
            <<Id, Payload/binary>>
    end.

%% @doc Decode the plaintext contents of one v2 AEAD packet into a
%% (Command, Payload) pair.  Returns ``{error, _}`` on malformed input.
-spec decode_contents(binary()) ->
    {ok, binary(), binary()} | {error, term()}.
decode_contents(<<>>) ->
    %% Empty contents are valid only for the BIP-324 version packet
    %% (sent during cipher handshake) — they have no command/payload to
    %% dispatch.  Caller must filter version packets before calling
    %% decode_contents/1, so reaching here is a protocol violation.
    {error, empty_contents};
decode_contents(<<0, Rest/binary>>) when byte_size(Rest) >= 12 ->
    %% Long-form: 12-byte ASCII command (null-padded) || payload
    <<CmdRaw:12/binary, Payload/binary>> = Rest,
    Cmd = unpad_command(CmdRaw),
    {ok, Cmd, Payload};
decode_contents(<<0, _/binary>>) ->
    {error, short_long_command};
decode_contents(<<Id, Payload/binary>>) ->
    case command_for_short_id(Id) of
        undefined -> {error, {unknown_short_id, Id}};
        Cmd when is_binary(Cmd) -> {ok, Cmd, Payload}
    end.

%%% ===================================================================
%%% Helpers
%%% ===================================================================

unpad_command(Bin) when is_binary(Bin) ->
    case binary:match(Bin, <<0>>) of
        nomatch ->
            Bin;
        {Pos, _} ->
            binary:part(Bin, 0, Pos)
    end.
