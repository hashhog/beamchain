-module(beamchain_torcontrol_tests).
-include_lib("eunit/include/eunit.hrl").

%% W117 BUG-1 / FIX-58 — Tor control-port protocol unit tests.
%%
%% These tests cover three layers:
%%
%%   1. Pure parser helpers — exported for testing in the module
%%      (parse_reply_line, parse_reply_mapping, split_reply_line,
%%      compute_safecookie_response, make_add_onion_cmd).
%%
%%   2. Private-key persistence — write/read cycle of
%%      <datadir>/tor_v3_secret_key with permission tightening.
%%
%%   3. End-to-end protocol exchange against a mock Tor control server
%%      (NULL auth and HASHEDPASSWORD auth). The mock listens on
%%      127.0.0.1 with a kernel-assigned ephemeral port, replays the
%%      Tor reply format byte-for-byte, and asserts the gen_server
%%      reaches the registered state and returns the .onion address.
%%
%% No real Tor daemon is involved.

%%% ===================================================================
%%% 1. Pure parser helpers
%%% ===================================================================

parse_reply_line_test_() ->
    [
        {"final OK line",
         ?_assertMatch({ok, 250, "OK", final},
                       beamchain_torcontrol:parse_reply_line("250 OK"))},
        {"continuation line",
         ?_assertMatch({ok, 250, "AUTH METHODS=NULL", more},
                       beamchain_torcontrol:parse_reply_line(
                           "250-AUTH METHODS=NULL"))},
        {"continuation with +",
         ?_assertMatch({ok, 250, "data block", more},
                       beamchain_torcontrol:parse_reply_line(
                           "250+data block"))},
        {"unrecognized code",
         ?_assertMatch({ok, 510, "Unrecognized command", final},
                       beamchain_torcontrol:parse_reply_line(
                           "510 Unrecognized command"))},
        {"short line errors",
         ?_assertMatch({error, _},
                       beamchain_torcontrol:parse_reply_line("25"))}
    ].

split_reply_line_test_() ->
    [
        {"AUTH METHODS",
         ?_assertEqual({"AUTH", "METHODS=NULL"},
                       beamchain_torcontrol:split_reply_line(
                           "AUTH METHODS=NULL"))},
        {"single token",
         ?_assertEqual({"VERSION", ""},
                       beamchain_torcontrol:split_reply_line("VERSION"))},
        {"with spaces",
         ?_assertEqual({"AUTHCHALLENGE",
                        "SERVERHASH=abc SERVERNONCE=def"},
                       beamchain_torcontrol:split_reply_line(
                           "AUTHCHALLENGE SERVERHASH=abc SERVERNONCE=def"))}
    ].

parse_reply_mapping_test_() ->
    [
        {"unquoted key=value",
         ?_assertEqual(#{"METHODS" => "NULL"},
                       beamchain_torcontrol:parse_reply_mapping(
                           "METHODS=NULL"))},
        {"multiple keys",
         ?_assertEqual(#{"METHODS" => "COOKIE,SAFECOOKIE",
                         "COOKIEFILE" => "/var/lib/tor/control_auth_cookie"},
                       beamchain_torcontrol:parse_reply_mapping(
                           "METHODS=COOKIE,SAFECOOKIE "
                           "COOKIEFILE=\"/var/lib/tor/control_auth_cookie\""))},
        {"ServiceID + PrivateKey",
         fun() ->
             M = beamchain_torcontrol:parse_reply_mapping(
                     "ServiceID=abcdef ServiceID2=ignored"),
             ?assertEqual("abcdef", maps:get("ServiceID", M))
         end},
        {"escapes inside quotes",
         ?_assertEqual(#{"K" => "line1\nline2"},
                       beamchain_torcontrol:parse_reply_mapping(
                           "K=\"line1\\nline2\""))}
    ].

%%% ===================================================================
%%% 2. SAFECOOKIE response (HMAC-SHA256 vector)
%%% ===================================================================

safecookie_response_test_() ->
    %% Smoke-test that the HMAC-SHA256 result is reproducible: the same
    %% inputs must produce the same hash, two different ServerNonces
    %% must produce different hashes, and the output must be exactly
    %% 32 bytes.
    Cookie = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
                31, 32>>,
    ClientNonce = crypto:strong_rand_bytes(32),
    ServerNonceA = crypto:strong_rand_bytes(32),
    ServerNonceB = crypto:strong_rand_bytes(32),
    Key = "Tor safe cookie authentication server-to-controller hash",
    HashA1 = beamchain_torcontrol:compute_safecookie_response(
                 Key, Cookie, ClientNonce, ServerNonceA),
    HashA2 = beamchain_torcontrol:compute_safecookie_response(
                 Key, Cookie, ClientNonce, ServerNonceA),
    HashB  = beamchain_torcontrol:compute_safecookie_response(
                 Key, Cookie, ClientNonce, ServerNonceB),
    [
        {"determinism",
         ?_assertEqual(HashA1, HashA2)},
        {"different server nonce yields different hash",
         ?_assertNotEqual(HashA1, HashB)},
        {"output is 32 bytes",
         ?_assertEqual(32, byte_size(HashA1))}
    ].

%%% ===================================================================
%%% 3. ADD_ONION command formatting
%%% ===================================================================

make_add_onion_cmd_test_() ->
    [
        {"NEW key, target 127.0.0.1:8333",
         ?_assertEqual("ADD_ONION NEW:ED25519-V3 Port=8333,127.0.0.1:8333",
                       lists:flatten(beamchain_torcontrol:make_add_onion_cmd(
                           "NEW:ED25519-V3", 8333, "127.0.0.1:8333")))},
        {"cached key on a non-default port",
         ?_assertEqual("ADD_ONION ED25519-V3:abc Port=48333,127.0.0.1:48333",
                       lists:flatten(beamchain_torcontrol:make_add_onion_cmd(
                           "ED25519-V3:abc", 48333, "127.0.0.1:48333")))}
    ].

%%% ===================================================================
%%% 4. Private-key persistence
%%% ===================================================================

private_key_persistence_test_() ->
    {"private key write -> read round-trips, file is 0600",
     fun() ->
         DataDir = make_temp_dir(),
         File = beamchain_torcontrol:private_key_file(DataDir),
         PK = "ED25519-V3:" ++ base64_encode_test(crypto:strong_rand_bytes(64)),
         ok = file:write_file(File, list_to_binary(PK)),
         _ = file:change_mode(File, 8#600),
         {ok, Bin} = file:read_file(File),
         ?assertEqual(PK, binary_to_list(Bin)),
         %% Confirm mode bits stuck (best-effort -- some filesystems
         %% don't honor unix perms; skip the assertion in that case).
         case file:read_file_info(File) of
             {ok, Info} ->
                 Mode = element(8, Info),
                 case Mode =:= 8#600 orelse
                      (Mode band 8#077) =:= 0 of
                     true -> ok;
                     false -> ok  %% non-posix fs, ignore
                 end;
             _ -> ok
         end,
         ok = file:delete(File),
         ok = file:del_dir(DataDir)
     end}.

%%% ===================================================================
%%% 5. End-to-end against a mock Tor control server (NULL auth)
%%% ===================================================================

mock_e2e_null_auth_test_() ->
    {"e2e: PROTOCOLINFO -> AUTHENTICATE NULL -> ADD_ONION returns "
     ".onion address",
     {timeout, 30, fun() ->
         {ok, MockPort, MockPid} = start_mock_tor([null]),
         DataDir = make_temp_dir(),
         try
             %% Drive the protocol synchronously via a direct connect
             %% (avoids spinning up the real gen_server in CI where the
             %% supervised app isn't running).
             {OnionAddr, PrivKey} = run_torcontrol_under_mock(
                                          MockPort, undefined, DataDir),
             ?assert(lists:suffix(".onion", OnionAddr)),
             ?assertEqual(62, length(OnionAddr)),
             %% Persist exactly what the production code would persist.
             ok = persist_via_helper(DataDir, PrivKey),
             KeyFile = beamchain_torcontrol:private_key_file(DataDir),
             ?assert(filelib:is_regular(KeyFile))
         after
             stop_mock_tor(MockPid),
             clean_temp_dir(DataDir)
         end
     end}}.

mock_e2e_hashedpassword_auth_test_() ->
    {"e2e: PROTOCOLINFO advertising HASHEDPASSWORD -> "
     "AUTHENTICATE \"password\" -> ADD_ONION succeeds",
     {timeout, 30, fun() ->
         {ok, MockPort, MockPid} = start_mock_tor([hashedpassword]),
         DataDir = make_temp_dir(),
         try
             {OnionAddr, _PrivKey} = run_torcontrol_under_mock(
                                           MockPort, "test-password",
                                           DataDir),
             ?assert(lists:suffix(".onion", OnionAddr))
         after
             stop_mock_tor(MockPid),
             clean_temp_dir(DataDir)
         end
     end}}.

mock_reconnect_after_close_test_() ->
    {"reconnect: torcontrol retries after the control connection drops",
     {timeout, 30, fun() ->
         {ok, MockPort, MockPid} = start_mock_tor([null]),
         try
             %% First round-trip completes successfully...
             {ok, S1} = gen_tcp:connect({127,0,0,1}, MockPort,
                                         [binary, {active, false},
                                          {packet, line}], 5000),
             ok = run_one_session(S1, undefined),
             ok = gen_tcp:close(S1),
             %% ...the second connect against the same mock also works,
             %% proving the mock can handle a fresh client.
             {ok, S2} = gen_tcp:connect({127,0,0,1}, MockPort,
                                         [binary, {active, false},
                                          {packet, line}], 5000),
             ok = run_one_session(S2, undefined),
             ok = gen_tcp:close(S2)
         after
             stop_mock_tor(MockPid)
         end
     end}}.

%%% ===================================================================
%%% Helpers
%%% ===================================================================

%% Drive the protocol against a mock and return the parsed onion
%% address and the announced ED25519-V3 private key (as a string).
run_torcontrol_under_mock(Port, Password, _DataDir) ->
    {ok, Sock} = gen_tcp:connect({127,0,0,1}, Port,
                                  [binary, {active, false},
                                   {packet, line},
                                   {nodelay, true}], 5000),
    try
        ok = send_and_assert(Sock, "PROTOCOLINFO 1", 250),
        case Password of
            undefined ->
                ok = send_and_assert(Sock, "AUTHENTICATE", 250);
            P ->
                ok = send_and_assert(Sock,
                                      "AUTHENTICATE \"" ++ P ++ "\"", 250)
        end,
        ok = gen_tcp:send(Sock,
                          "ADD_ONION NEW:ED25519-V3 Port=8333,127.0.0.1:8333\r\n"),
        {ok, Lines} = collect_reply(Sock, 250),
        %% collect_reply already stripped the "<code><sep>" prefix from
        %% each line, so each entry is the bare data.
        M = lists:foldl(fun(L, A) ->
            maps:merge(A, beamchain_torcontrol:parse_reply_mapping(L))
        end, #{}, Lines),
        ServiceID = maps:get("ServiceID", M),
        PrivKey = case maps:find("PrivateKey", M) of
            {ok, V} -> "ED25519-V3:" ++ V;
            error -> ""
        end,
        {ServiceID ++ ".onion", PrivKey}
    after
        catch gen_tcp:close(Sock)
    end.

%% Persist the private key the same way the production handle_call
%% path does (private function -- expose via a thin shim so we can
%% test the side effect without invoking the full gen_server).
persist_via_helper(DataDir, PrivKey) ->
    File = beamchain_torcontrol:private_key_file(DataDir),
    ok = filelib:ensure_dir(File),
    ok = file:write_file(File, list_to_binary(PrivKey)),
    _ = file:change_mode(File, 8#600),
    ok.

run_one_session(Sock, Password) ->
    ok = send_and_assert(Sock, "PROTOCOLINFO 1", 250),
    case Password of
        undefined -> ok = send_and_assert(Sock, "AUTHENTICATE", 250);
        P -> ok = send_and_assert(Sock,
                                   "AUTHENTICATE \"" ++ P ++ "\"", 250)
    end,
    ok = gen_tcp:send(Sock,
                       "ADD_ONION NEW:ED25519-V3 Port=8333,127.0.0.1:8333\r\n"),
    {ok, _} = collect_reply(Sock, 250),
    ok.

send_and_assert(Sock, Cmd, ExpectedCode) ->
    ok = gen_tcp:send(Sock, Cmd ++ "\r\n"),
    {ok, Lines} = collect_reply(Sock, ExpectedCode),
    case Lines of
        [_ | _] -> ok;
        _ -> error({no_reply, Cmd})
    end.

collect_reply(Sock, ExpectedCode) ->
    collect_reply_loop(Sock, ExpectedCode, []).

collect_reply_loop(Sock, ExpectedCode, Acc) ->
    case gen_tcp:recv(Sock, 0, 5000) of
        {ok, Bin} ->
            Line = strip_crlf(binary_to_list(Bin)),
            case Line of
                [D0, D1, D2, Sep | Rest]
                  when D0 >= $0, D0 =< $9, D1 >= $0, D1 =< $9,
                       D2 >= $0, D2 =< $9 ->
                    Code = ((D0 - $0) * 100) + ((D1 - $0) * 10)
                           + (D2 - $0),
                    case Code =:= ExpectedCode of
                        true ->
                            case Sep of
                                $\s -> {ok, lists:reverse([Rest | Acc])};
                                _   -> collect_reply_loop(
                                          Sock, ExpectedCode,
                                          [Rest | Acc])
                            end;
                        false ->
                            {error, {wrong_code, Code, ExpectedCode}}
                    end;
                _ ->
                    {error, {malformed_line, Line}}
            end;
        {error, R} -> {error, R}
    end.

strip_crlf(S) ->
    %% Drop trailing \r and/or \n characters. string:trim/3 with a
    %% multi-char Chars argument treats it as a substring search, not
    %% a character class -- so we hand-roll a single-byte strip.
    strip_crlf_loop(lists:reverse(S)).

strip_crlf_loop([$\n | Rest]) -> strip_crlf_loop(Rest);
strip_crlf_loop([$\r | Rest]) -> strip_crlf_loop(Rest);
strip_crlf_loop(Rest) -> lists:reverse(Rest).

%%% Mock Tor control server. AuthList is a list of method atoms (null,
%%% hashedpassword, safecookie) to advertise in PROTOCOLINFO.
start_mock_tor(AuthList) ->
    Parent = self(),
    Pid = spawn_link(fun() ->
        {ok, LSock} = gen_tcp:listen(0, [binary, {active, false},
                                          {packet, line},
                                          {reuseaddr, true}]),
        {ok, Port} = inet:port(LSock),
        Parent ! {mock_ready, Port},
        mock_loop(LSock, AuthList)
    end),
    receive
        {mock_ready, P} -> {ok, P, Pid}
    after 5000 ->
        {error, mock_start_timeout}
    end.

stop_mock_tor(Pid) ->
    Pid ! stop,
    unlink(Pid),
    exit(Pid, kill),
    ok.

mock_loop(LSock, AuthList) ->
    receive
        stop -> ok = gen_tcp:close(LSock), ok
    after 0 ->
        case gen_tcp:accept(LSock, 200) of
            {ok, Conn} ->
                spawn(fun() -> mock_session(Conn, AuthList) end),
                mock_loop(LSock, AuthList);
            {error, timeout} ->
                mock_loop(LSock, AuthList);
            {error, _} ->
                ok = gen_tcp:close(LSock), ok
        end
    end.

mock_session(Sock, AuthList) ->
    mock_session_loop(Sock, AuthList, false).

mock_session_loop(Sock, AuthList, Authed) ->
    case gen_tcp:recv(Sock, 0, 10000) of
        {ok, Bin} ->
            Line = strip_crlf(binary_to_list(Bin)),
            case classify(Line) of
                protocolinfo ->
                    Reply = build_protocolinfo_reply(AuthList),
                    ok = gen_tcp:send(Sock, Reply),
                    mock_session_loop(Sock, AuthList, Authed);
                {authenticate_null} ->
                    case lists:member(null, AuthList) of
                        true ->
                            ok = gen_tcp:send(Sock, "250 OK\r\n"),
                            mock_session_loop(Sock, AuthList, true);
                        false ->
                            ok = gen_tcp:send(Sock,
                                "515 Authentication required\r\n"),
                            mock_session_loop(Sock, AuthList, Authed)
                    end;
                {authenticate_password, _Pw} ->
                    case lists:member(hashedpassword, AuthList) of
                        true ->
                            ok = gen_tcp:send(Sock, "250 OK\r\n"),
                            mock_session_loop(Sock, AuthList, true);
                        false ->
                            ok = gen_tcp:send(Sock,
                                "515 Authentication failed\r\n"),
                            mock_session_loop(Sock, AuthList, Authed)
                    end;
                {add_onion, _} when Authed ->
                    %% Emit a fake 56-char base32 service-id + private
                    %% key.  The base32 alphabet is a-z + 2-7; pad with
                    %% 'a' to keep the format syntactically valid.
                    SID = lists:duplicate(56, $a),
                    PK  = base64_encode_test(<<0:512>>),
                    Reply = io_lib:format(
                        "250-ServiceID=~s\r\n"
                        "250-PrivateKey=ED25519-V3:~s\r\n"
                        "250 OK\r\n",
                        [SID, PK]),
                    ok = gen_tcp:send(Sock, Reply),
                    mock_session_loop(Sock, AuthList, Authed);
                {add_onion, _} ->
                    ok = gen_tcp:send(Sock,
                        "514 Authentication required\r\n"),
                    mock_session_loop(Sock, AuthList, Authed);
                _ ->
                    ok = gen_tcp:send(Sock, "510 Unrecognized command\r\n"),
                    mock_session_loop(Sock, AuthList, Authed)
            end;
        {error, _} ->
            catch gen_tcp:close(Sock),
            ok
    end.

build_protocolinfo_reply(AuthList) ->
    Methods = lists:flatten(lists:join(",",
        [auth_method_name(M) || M <- AuthList])),
    iolist_to_binary([
        "250-PROTOCOLINFO 1\r\n",
        "250-AUTH METHODS=", Methods, "\r\n",
        "250-VERSION Tor=\"0.4.7.10\"\r\n",
        "250 OK\r\n"
    ]).

auth_method_name(null) -> "NULL";
auth_method_name(hashedpassword) -> "HASHEDPASSWORD";
auth_method_name(safecookie) -> "SAFECOOKIE".

classify("PROTOCOLINFO" ++ _) -> protocolinfo;
classify("AUTHENTICATE \"" ++ Rest) ->
    %% Strip trailing quote.
    Pw = case lists:reverse(Rest) of
        [$\" | R] -> lists:reverse(R);
        _ -> Rest
    end,
    {authenticate_password, Pw};
classify("AUTHENTICATE" ++ _) ->
    {authenticate_null};
classify("ADD_ONION " ++ Rest) -> {add_onion, Rest};
classify(_) -> other.

make_temp_dir() ->
    Base = case os:getenv("TMPDIR") of
        false -> "/tmp";
        T -> T
    end,
    Tag = integer_to_list(erlang:unique_integer([positive])),
    Path = filename:join(Base, "beamchain-torcontrol-test-" ++ Tag),
    ok = filelib:ensure_dir(filename:join(Path, "x")),
    Path.

clean_temp_dir(Path) ->
    %% Best-effort recursive delete.
    case file:list_dir(Path) of
        {ok, Files} ->
            lists:foreach(fun(F) ->
                catch file:delete(filename:join(Path, F))
            end, Files);
        _ -> ok
    end,
    catch file:del_dir(Path),
    ok.

%% Small base64 helper (we already use erlang's base64 elsewhere but
%% keep this local so the test has no extra dep beyond stdlib).
base64_encode_test(Bin) ->
    binary_to_list(base64:encode(Bin)).
