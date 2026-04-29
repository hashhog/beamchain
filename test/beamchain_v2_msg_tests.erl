-module(beamchain_v2_msg_tests).
-include_lib("eunit/include/eunit.hrl").

%%% ===================================================================
%%% Tests for the BIP-324 v2 application-layer wrap/unwrap.
%%% ===================================================================

%% Short-id round-trip for every entry in the table (other than 0).
short_id_table_roundtrip_test() ->
    Table = beamchain_v2_msg:short_id_table(),
    %% Index 0 is the long-form sentinel (empty binary).
    ?assertEqual(<<>>, hd(Table)),
    %% Indices 1..N round-trip.
    lists:foreach(
        fun({Cmd, Idx}) when is_binary(Cmd), Cmd =/= <<>> ->
                ?assertEqual(Idx, beamchain_v2_msg:short_id_for(Cmd)),
                ?assertEqual(Cmd, beamchain_v2_msg:command_for_short_id(Idx))
        end,
        lists:zip(tl(Table), lists:seq(1, length(Table) - 1))).

%% A command not in the short-id table must fall through to long-form.
short_id_unknown_returns_undefined_test() ->
    ?assertEqual(undefined, beamchain_v2_msg:short_id_for(<<"version">>)),
    ?assertEqual(undefined, beamchain_v2_msg:short_id_for(<<"verack">>)),
    ?assertEqual(undefined, beamchain_v2_msg:short_id_for(<<"wtxidrelay">>)),
    ?assertEqual(undefined, beamchain_v2_msg:short_id_for(<<"sendaddrv2">>)).

%% Encode then decode a short-form message round-trips.
short_form_roundtrip_test() ->
    Payload = <<"some-inv-payload-bytes">>,
    Wire = beamchain_v2_msg:encode_contents(<<"inv">>, Payload),
    %% First byte is the short-id for "inv" (= 14).
    ?assertEqual(14, binary:first(Wire)),
    ?assertEqual(byte_size(Payload) + 1, byte_size(Wire)),
    {ok, Cmd, P} = beamchain_v2_msg:decode_contents(Wire),
    ?assertEqual(<<"inv">>, Cmd),
    ?assertEqual(Payload, P).

%% Encode then decode a long-form message round-trips.
long_form_roundtrip_test() ->
    Payload = <<0, 1, 2, 3, 4, 5>>,
    Wire = beamchain_v2_msg:encode_contents(<<"verack">>, Payload),
    %% Long form: 0x00 + 12-byte command + payload.
    ?assertEqual(0, binary:first(Wire)),
    ?assertEqual(1 + 12 + byte_size(Payload), byte_size(Wire)),
    {ok, Cmd, P} = beamchain_v2_msg:decode_contents(Wire),
    ?assertEqual(<<"verack">>, Cmd),
    ?assertEqual(Payload, P).

%% encode_contents accepts the atom form too (matches command_name/1).
atom_form_encode_test() ->
    P = <<"x">>,
    A = beamchain_v2_msg:encode_contents(ping, P),
    B = beamchain_v2_msg:encode_contents(<<"ping">>, P),
    ?assertEqual(A, B),
    %% "ping" is short-id 18.
    ?assertEqual(18, binary:first(A)).

%% Empty contents are not a valid application packet — only the version
%% packet (sent during cipher handshake) carries empty contents, and
%% decode_contents/1 is never called on it.
empty_contents_is_error_test() ->
    ?assertEqual({error, empty_contents}, beamchain_v2_msg:decode_contents(<<>>)).

%% A long-form marker without the trailing 12-byte command is malformed.
short_long_form_is_error_test() ->
    ?assertEqual({error, short_long_command},
                 beamchain_v2_msg:decode_contents(<<0, 1, 2, 3>>)).

%% Unknown short-ids surface a structured error.
unknown_short_id_is_error_test() ->
    %% 200 is in the reserved range; never assigned.
    ?assertEqual({error, {unknown_short_id, 200}},
                 beamchain_v2_msg:decode_contents(<<200, "payload">>)).
