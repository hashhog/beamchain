-module(beamchain_empty_rpcpassword_tests).
-include_lib("eunit/include/eunit.hrl").

%%% An empty -rpcpassword is unset, not a credential.
%%%
%%% Core (httprpc.cpp InitRPCAuthentication):
%%%   if (gArgs.GetArg("-rpcpassword", "") == "") { ...GenerateAuthCookie... }
%%% so `rpcuser=u` with a blank `rpcpassword=` gives cookie-only auth, and a
%%% request carrying `Authorization: Basic base64("u:")` is refused.
%%%
%%% beamchain's config parser keeps the blank value as "" (string:trim of the
%%% text after `=`), and setup_auth/0 used to skip only `undefined`, so it
%%% installed {rpc_credentials, <<"u">>, <<>>} and "u:" authenticated.
%%%
%%% Each test installs config the way beamchain_config does (named ETS table
%%% beamchain_config_ets) and runs the RPC server's real startup path,
%%% beamchain_rpc:init([]). That creates the auth table and runs setup_auth/0;
%%% with no network_params configured it then stops with
%%% error(network_params_not_configured), before any listener is started.
%%% The tests then check the credentials startup installed and, through the
%%% real check_auth/1 (cowboy_req:parse_header, so the cowlib parse of "u:"
%%% is exercised too), that a request with the empty password is refused.
%%% check_auth/1 is a TEST-only export added with the fix; the credential
%%% assertions use only master's exports, so on master they compile and fail
%%% on the assertion.

-define(CONFIG_TABLE, beamchain_config_ets).
-define(AUTH_TABLE, rpc_auth).
-define(RATE_TABLE, rpc_rate_limit).

with_config(Kvs, Fun) ->
    Dir = scratch_dir(),
    [drop_table(T) || T <- [?CONFIG_TABLE, ?AUTH_TABLE, ?RATE_TABLE]],
    ets:new(?CONFIG_TABLE, [named_table, set, public]),
    try
        ets:insert(?CONFIG_TABLE, {datadir, Dir}),
        [ets:insert(?CONFIG_TABLE, Kv) || Kv <- Kvs],
        ?assertError(network_params_not_configured, beamchain_rpc:init([])),
        {ok, <<"__cookie__:", Cookie/binary>>} =
            file:read_file(filename:join(Dir, ".cookie")),
        Fun(Cookie)
    after
        [drop_table(T) || T <- [?CONFIG_TABLE, ?AUTH_TABLE, ?RATE_TABLE]],
        file:del_dir_r(Dir)
    end.

drop_table(T) ->
    case ets:whereis(T) of
        undefined -> ok;
        _ -> ets:delete(T)
    end.

scratch_dir() ->
    {ok, Cwd} = file:get_cwd(),
    Dir = filename:join([Cwd, "_build", "test", "empty_rpcpassword_scratch",
                         integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_path(Dir),
    Dir.

credentials() ->
    ets:lookup(?AUTH_TABLE, rpc_credentials).

%% Request-level check through check_auth/1 where it is exported (the fix
%% exports it under TEST). Returns skipped otherwise; callers only use it
%% after a credential assertion that already holds on master's exports.
auth(User, Pass) ->
    {module, beamchain_rpc} = code:ensure_loaded(beamchain_rpc),
    case erlang:function_exported(beamchain_rpc, check_auth, 1) of
        true ->
            Token = base64:encode(<<User/binary, ":", Pass/binary>>),
            beamchain_rpc:check_auth(
                #{headers => #{<<"authorization">> => <<"Basic ", Token/binary>>}});
        false ->
            skipped
    end.

refused(R) -> R =:= skipped orelse (is_tuple(R) andalso element(1, R) =:= error).
accepted(R) -> R =:= skipped orelse R =:= ok.

%% `rpcuser=u` + blank `rpcpassword=` line (the config parser stores "").
empty_rpcpassword_string_refused_test() ->
    with_config([{rpcuser, "u"}, {rpcpassword, ""}],
        fun(Cookie) ->
            ?assertEqual([], credentials()),
            ?assert(refused(auth(<<"u">>, <<>>))),
            %% Core falls back to the cookie, which must still work.
            ?assert(accepted(auth(<<"__cookie__">>, Cookie)))
        end).

%% Same with the value held as a binary (e.g. a CLI/app-env source).
empty_rpcpassword_binary_refused_test() ->
    with_config([{rpcuser, <<"u">>}, {rpcpassword, <<>>}],
        fun(Cookie) ->
            ?assertEqual([], credentials()),
            ?assert(refused(auth(<<"u">>, <<>>))),
            ?assert(accepted(auth(<<"__cookie__">>, Cookie)))
        end).

%% Positive control: a non-empty rpcpassword is still installed and still
%% authenticates, and the instrument tells accept from refuse (wrong and
%% empty passwords refused).
nonempty_rpcpassword_still_works_test() ->
    with_config([{rpcuser, "u"}, {rpcpassword, "p"}],
        fun(Cookie) ->
            ?assertEqual([{rpc_credentials, <<"u">>, <<"p">>}], credentials()),
            ?assert(accepted(auth(<<"u">>, <<"p">>))),
            ?assert(refused(auth(<<"u">>, <<>>))),
            ?assert(refused(auth(<<"u">>, <<"q">>))),
            ?assert(accepted(auth(<<"__cookie__">>, Cookie)))
        end).

%% Guards the guard: on the fixed tree check_auth/1 is exported, so the
%% request-level assertions above really ran (not `skipped`).
check_auth_reachable_with_fix_test() ->
    with_config([{rpcuser, "u"}, {rpcpassword, ""}],
        fun(_Cookie) ->
            case credentials() of
                [] -> ?assertMatch({error, _}, auth(<<"u">>, <<>>));
                _ -> ok   %% unfixed tree: covered by the tests above
            end
        end).
