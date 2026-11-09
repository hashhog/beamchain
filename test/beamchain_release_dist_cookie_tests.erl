-module(beamchain_release_dist_cookie_tests).

%%% The relx release (`rebar3 as prod release`, used by the Dockerfile and
%%% the cold-boot smoke gate) ships config/vm.args as its VM arguments.
%%% Erlang distribution authenticates peers with nothing but the cookie,
%%% and a node that accepts a distribution connection runs any code the
%%% peer sends (rpc:call(Node, os, cmd, [...])). So the shipped vm.args
%%% must not carry a cookie that is the same on every install, and the
%%% distribution listener must not be reachable off-host by default.
%%%
%%% These tests read the exact file relx copies into the release
%%% (the `vm_args` entry of rebar.config's relx section), so they pin
%%% what is shipped, not a copy of it.

-include_lib("eunit/include/eunit.hrl").

root_dir() ->
    {ok, Cwd} = file:get_cwd(),
    case filelib:is_regular(filename:join(Cwd, "rebar.config")) of
        true -> Cwd;
        false -> walk_up(filename:dirname(code:which(?MODULE)), 8)
    end.

walk_up(_Dir, 0) -> error(rebar_config_not_found);
walk_up(Dir, N) ->
    case filelib:is_regular(filename:join(Dir, "rebar.config")) of
        true -> Dir;
        false -> walk_up(filename:dirname(Dir), N - 1)
    end.

%% The vm.args path relx is configured to ship.
shipped_vm_args_path() ->
    Root = root_dir(),
    {ok, Terms} = file:consult(filename:join(Root, "rebar.config")),
    {relx, Relx} = lists:keyfind(relx, 1, Terms),
    {vm_args, Rel} = lists:keyfind(vm_args, 1, Relx),
    filename:join(Root, Rel).

%% Non-comment, non-blank lines of the shipped vm.args, trimmed.
%% Fails (does not skip) if the file is missing.
vm_args_lines() ->
    {ok, Bin} = file:read_file(shipped_vm_args_path()),
    Lines = [string:trim(L) || L <- string:split(binary_to_list(Bin), "\n", all)],
    [L || L <- Lines, L =/= "", hd(L) =/= $#].

flag_lines(Flag) ->
    [L || L <- vm_args_lines(), lists:prefix(Flag, L)].

relx_ships_config_vm_args_test() ->
    ?assertEqual("vm.args", filename:basename(shipped_vm_args_path())),
    ?assert(filelib:is_regular(shipped_vm_args_path())),
    %% Sanity: the parser sees the real file (a -name line is present).
    ?assertMatch([_ | _], flag_lines("-name ")).

%% No static cookie in the release. With no -setcookie, the runtime uses
%% $HOME/.erlang.cookie and, if that is absent, generates a random one on
%% first boot with mode 0400, so each install gets its own. RELX_COOKIE
%% overrides it explicitly.
release_vm_args_has_no_static_cookie_test() ->
    ?assertEqual([], flag_lines("-setcookie")),
    %% A cookie can also be passed as a kernel app env; forbid that too.
    ?assertEqual([], [L || L <- vm_args_lines(),
                           string:str(L, "-kernel") > 0,
                           string:str(L, "cookie") > 0]).

%% The distribution listener binds loopback only, not every interface.
release_dist_listener_binds_loopback_test() ->
    ?assertEqual(["-kernel inet_dist_use_interface {127,0,0,1}"],
                 flag_lines("-kernel inet_dist_use_interface")).

%% The node name resolves to loopback, matching the listener address.
release_node_name_is_loopback_test() ->
    ?assertEqual(["-name beamchain@127.0.0.1"], flag_lines("-name ")).

%% An EPMD started by the release binds loopback only.
release_epmd_binds_loopback_test() ->
    ?assertEqual(["-env ERL_EPMD_ADDRESS 127.0.0.1"],
                 flag_lines("-env ERL_EPMD_ADDRESS")).

%%% -------------------------------------------------------------------
%%% Per-install cookie: the relx pre_start hook.
%%%
%%% The relx start script reads $HOME/.erlang.cookie BEFORE it boots the
%%% node. With no cookie in vm.args and no file yet (a fresh install),
%%% `bin/beamchain daemon` would wait forever, pinging with an empty
%%% cookie. The release therefore ships a sourced pre_start hook that
%%% creates the file (random, owner read-only) and sets COOKIE.
%%% -------------------------------------------------------------------

hook_path() ->
    filename:join([root_dir(), "config", "release-hooks", "ensure_cookie.sh"]).

relx_installs_cookie_hook_test() ->
    {ok, Terms} = file:consult(filename:join(root_dir(), "rebar.config")),
    {relx, Relx} = lists:keyfind(relx, 1, Terms),
    {extended_start_script_hooks, Hooks} =
        lists:keyfind(extended_start_script_hooks, 1, Relx),
    {pre_start, Pre} = lists:keyfind(pre_start, 1, Hooks),
    ?assert(lists:member({custom, "hooks/ensure_cookie.sh"}, Pre)),
    {overlay, Overlay} = lists:keyfind(overlay, 1, Relx),
    ?assert(lists:member({copy, "config/release-hooks/ensure_cookie.sh",
                          "bin/hooks/ensure_cookie.sh"}, Overlay)),
    ?assert(filelib:is_regular(hook_path())).

%% Fresh scratch HOME under _build/test, removed by the caller.
scratch_home(Tag) ->
    Dir = filename:join([root_dir(), "_build", "test",
                         "cookie_hook_" ++ Tag ++ "_" ++
                             integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    Dir.

%% Source the hook the way relx does (the start script runs under
%% `set -e`), with COOKIE as the start script left it, and return what
%% COOKIE is afterwards.
source_hook(Home, CookieIn) ->
    Cmd = "HOME='" ++ Home ++ "' COOKIE='" ++ CookieIn ++ "' sh -ec '. \"$0\"; "
          "printf \"%s\" \"$COOKIE\"' '" ++ hook_path() ++ "'",
    os:cmd(Cmd).

cookie_hook_generates_owner_only_random_cookie_test() ->
    ?assert(filelib:is_regular(hook_path())),
    H1 = scratch_home("a"),
    H2 = scratch_home("b"),
    try
        C1 = source_hook(H1, ""),
        C2 = source_hook(H2, ""),
        F1 = filename:join(H1, ".erlang.cookie"),
        {ok, Bin1} = file:read_file(F1),
        %% The start script's COOKIE now matches the file the VM will read.
        ?assertEqual(binary_to_list(Bin1), C1),
        ?assertEqual(20, length(C1)),
        ?assert(lists:all(fun(Ch) -> Ch >= $A andalso Ch =< $Z end, C1)),
        %% Owner read-only, as erts requires (no group/other bits).
        {ok, Info} = file:read_file_info(F1),
        ?assertEqual(8#400, element(8, Info) band 8#777),
        %% Each install gets its own cookie, never the old fixed one.
        ?assertNotEqual(C1, C2),
        ?assertNotEqual("beamchain", C1),
        %% No temp files left behind.
        ?assertEqual([".erlang.cookie"], lists:sort(element(2, file:list_dir(H1))))
    after
        os:cmd("rm -rf '" ++ H1 ++ "' '" ++ H2 ++ "'")
    end.

cookie_hook_keeps_existing_cookie_test() ->
    ?assert(filelib:is_regular(hook_path())),
    H = scratch_home("c"),
    try
        F = filename:join(H, ".erlang.cookie"),
        ok = file:write_file(F, <<"EXISTINGCOOKIEVALUEX">>),
        ok = file:change_mode(F, 8#400),
        %% File present but COOKIE empty: adopt the file, do not rewrite it.
        ?assertEqual("EXISTINGCOOKIEVALUEX", source_hook(H, "")),
        %% COOKIE already set (RELX_COOKIE or an existing file): no-op.
        ?assertEqual("FROMRELX", source_hook(H, "FROMRELX")),
        ?assertEqual({ok, <<"EXISTINGCOOKIEVALUEX">>}, file:read_file(F))
    after
        os:cmd("rm -rf '" ++ H ++ "'")
    end.
