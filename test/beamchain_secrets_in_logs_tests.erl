-module(beamchain_secrets_in_logs_tests).

%% Wallet secrets must never reach log output (Core never logs passphrases,
%% seeds or keys). Each test runs a call with a known canary secret, captures
%% every log event emitted meanwhile, and asserts the canary is absent. Each
%% test also asserts the event it expects WAS captured, so a capture handler
%% that saw nothing cannot pass.

-include_lib("eunit/include/eunit.hrl").

%% logger handler callback
-export([log/2]).

-define(CANARY, <<"CANARY-PASS-7f3e19c2">>).
-define(HANDLER, beamchain_secrets_in_logs_capture).

%%% -------------------------------------------------------------------
%%% Log capture
%%% -------------------------------------------------------------------

log(Event, #{config := #{to := To}}) ->
    Text = try iolist_to_binary(
                 logger_formatter:format(Event, #{single_line => true,
                                                  depth => unlimited,
                                                  chars_limit => unlimited}))
           catch _:_ -> <<>>
           end,
    Msg = maps:get(msg, Event),
    Raw = iolist_to_binary(io_lib:format("~0p", [Msg])),
    To ! {captured_log, <<Text/binary, "\n", Raw/binary>>, Msg},
    ok.

with_capture(Fun) ->
    Primary = logger:get_primary_config(),
    ok = logger:set_primary_config(level, all),
    _ = logger:remove_handler(?HANDLER),
    ok = logger:add_handler(?HANDLER, ?MODULE,
                            #{level => all, config => #{to => self()}}),
    try
        Result = Fun(),
        timer:sleep(300),
        {Result, drain([], [])}
    after
        _ = logger:remove_handler(?HANDLER),
        ok = logger:set_primary_config(level, maps:get(level, Primary))
    end.

drain(Texts, Terms) ->
    receive {captured_log, L, T} -> drain([L | Texts], [T | Terms])
    after 0 -> {lists:reverse(Texts), lists:reverse(Terms)}
    end.

any_contains(Logs, Needle) ->
    lists:any(fun(L) -> binary:match(L, Needle) =/= nomatch end, Logs).

%% Does any binary inside Term contain Needle?
term_contains(B, Needle) when is_binary(B) ->
    binary:match(B, Needle) =/= nomatch;
term_contains(T, Needle) when is_tuple(T) ->
    term_contains(tuple_to_list(T), Needle);
term_contains([H | T], Needle) ->
    term_contains(H, Needle) orelse term_contains(T, Needle);
term_contains(M, Needle) when is_map(M) ->
    term_contains(maps:to_list(M), Needle);
term_contains(_, _) ->
    false.

%%% -------------------------------------------------------------------
%%% RPC dispatch catch-all
%%% -------------------------------------------------------------------

%% A stand-in for the default wallet, registered under the name the RPC
%% layer resolves when no wallet registry exists. It answers one call with
%% Behaviour and then stops.
with_fake_default_wallet(Behaviour, Fun) ->
    ?assertEqual(undefined, whereis(beamchain_wallet)),
    ?assertEqual([], beamchain_wallet_sup:list_wallets()),
    Pid = spawn(fun() ->
                    receive
                        {'$gen_call', From, Req} ->
                            case Behaviour of
                                crash -> exit(wallet_crashed_mid_call);
                                echo  -> gen_server:reply(From, {unexpected, Req})
                            end
                    after 10000 -> ok
                    end
                end),
    true = register(beamchain_wallet, Pid),
    try Fun()
    after
        catch unregister(beamchain_wallet),
        exit(Pid, kill)
    end.

rpc(Method, Params) ->
    beamchain_rpc:dispatch(#{<<"jsonrpc">> => <<"1.0">>, <<"id">> => 1,
                             <<"method">> => Method,
                             <<"params">> => Params}, <<>>).

assert_dispatch_error_redacted(Method, Params, Behaviour) ->
    {Resp, {Logs, _}} = with_capture(
                     fun() ->
                         with_fake_default_wallet(
                           Behaviour, fun() -> rpc(Method, Params) end)
                     end),
    %% Instrument check: the catch-all really logged this failure.
    ?assert(any_contains(Logs, <<"rpc dispatch error">>)),
    ?assertNot(any_contains(Logs, ?CANARY)),
    %% The -32603 reply is built from the same term.
    ?assertNot(term_contains(Resp, ?CANARY)),
    Logs.

%% The wallet process dies while handling walletpassphrase: the caller exits
%% with {Why, {gen_server, call, [Pid, {walletpassphrase, Passphrase, T}]}}.
walletpassphrase_call_failure_not_logged_test() ->
    Logs = assert_dispatch_error_redacted(
             <<"walletpassphrase">>, [?CANARY, 60], crash),
    %% Still says which call failed.
    ?assert(any_contains(Logs, <<"walletpassphrase">>)).

encryptwallet_call_failure_not_logged_test() ->
    assert_dispatch_error_redacted(<<"encryptwallet">>, [?CANARY], crash).

%% An unexpected reply that embeds the secret becomes a case_clause whose
%% value is the reply: the scrub, not the call-request redaction, has to
%% catch this one.
walletpassphrase_unexpected_reply_not_logged_test() ->
    assert_dispatch_error_redacted(
      <<"walletpassphrase">>, [?CANARY, 60], echo).

%%% -------------------------------------------------------------------
%%% beamchain_wallet crash reports and sys:get_status
%%% -------------------------------------------------------------------

start_encrypted_wallet(Name) ->
    {ok, Pid} = gen_server:start(beamchain_wallet, [Name], []),
    Seed = crypto:strong_rand_bytes(32),
    {ok, _} = gen_server:call(Pid, {create, Seed, undefined}),
    ok = gen_server:call(Pid, {encryptwallet, ?CANARY}),
    {Pid, Seed}.

%% sys:get_status/1 and the crash report both print the state through
%% format_status. An unlocked wallet holds the seed, master key and the
%% cached passphrase.
wallet_status_hides_seed_and_passphrase_test() ->
    {Pid, Seed} = start_encrypted_wallet(<<"secrets_in_logs_status">>),
    try
        ok = gen_server:call(Pid, {walletpassphrase, ?CANARY, 60}),
        Status = sys:get_status(Pid),
        %% Instrument check: the status does carry the wallet state.
        ?assert(term_contains(Status, <<"secrets_in_logs_status">>)),
        ?assertNot(term_contains(Status, Seed)),
        ?assertNot(term_contains(Status, ?CANARY))
    after
        gen_server:stop(Pid)
    end.

%% A wallet that crashes while handling a call logs a {gen_server,
%% terminate} crash report holding the last message, the server state and
%% the exit reason with its stack. Here an unencrypted wallet (seed and
%% master key in state) gets an encryptwallet whose passphrase is not a
%% binary, so crypto:pbkdf2_hmac/5 raises badarg outside any catch and the
%% passphrase is also in the top stack frame's arguments.
wallet_crash_report_hides_seed_and_passphrase_test() ->
    Name = <<"secrets_in_logs_crash">>,
    {ok, Pid} = gen_server:start(beamchain_wallet, [Name], []),
    Seed = crypto:strong_rand_bytes(32),
    {ok, _} = gen_server:call(Pid, {create, Seed, undefined}),
    {Exit, {Logs, Terms}} =
        with_capture(fun() ->
                         catch gen_server:call(Pid, {encryptwallet, {?CANARY}})
                     end),
    ?assertMatch({'EXIT', {{{badarg, _, _}, [_ | _]}, {gen_server, call, _}}}, Exit),
    ?assertNot(is_process_alive(Pid)),
    %% Instrument check: the crash report (which names the wallet in its
    %% state) was captured.
    ?assert(any_contains(Logs, Name)),
    ?assertNot(any_contains(Logs, ?CANARY)),
    ?assertNot(term_contains(Terms, Seed)).

%%% -------------------------------------------------------------------
%%% Negative control for the capture instrument
%%% -------------------------------------------------------------------

%% A log line that does contain the canary must be seen, or every
%% "not logged" assertion above proves nothing.
capture_sees_a_logged_canary_test() ->
    {ok, {Logs, _}} = with_capture(
                   fun() -> logger:warning("control: ~p", [?CANARY]) end),
    ?assert(any_contains(Logs, ?CANARY)).
