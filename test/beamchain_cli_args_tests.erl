-module(beamchain_cli_args_tests).
-include_lib("eunit/include/eunit.hrl").

%%% -------------------------------------------------------------------
%%% beamchain_cli argument-parser tests
%%%
%%% Covers the operational-parity CLI flags added alongside this test
%%% module: --daemon, --pid, --debug=<cat>, --conf, --printtoconsole.
%%% These tests exercise parse_args/1 and apply_debug_categories/1
%%% directly and do not start the OTP application.
%%% -------------------------------------------------------------------

%%% ===================================================================
%%% Basic parse_args coverage
%%% ===================================================================

start_default_test() ->
    {start, Opts} = beamchain_cli:parse_args(["start"]),
    ?assertEqual(#{}, Opts).

network_eq_form_test() ->
    {start, Opts} = beamchain_cli:parse_args(["start", "--network=regtest"]),
    ?assertEqual(regtest, maps:get(network, Opts)).

network_space_form_test() ->
    {start, Opts} = beamchain_cli:parse_args(
                      ["start", "--network", "testnet4"]),
    ?assertEqual(testnet4, maps:get(network, Opts)).

%%% ===================================================================
%%% --pid=<path>
%%% ===================================================================

pidfile_eq_form_test() ->
    {start, Opts} = beamchain_cli:parse_args(
                      ["start", "--pid=/var/run/beamchain.pid"]),
    ?assertEqual("/var/run/beamchain.pid", maps:get(pidfile, Opts)).

pidfile_space_form_test() ->
    {start, Opts} = beamchain_cli:parse_args(
                      ["start", "--pid", "/tmp/x.pid"]),
    ?assertEqual("/tmp/x.pid", maps:get(pidfile, Opts)).

pidfile_default_absent_test() ->
    {start, Opts} = beamchain_cli:parse_args(["start"]),
    ?assertEqual(undefined, maps:get(pidfile, Opts, undefined)).

%%% ===================================================================
%%% --conf=<file>  (override of legacy fixed path)
%%% ===================================================================

conf_eq_form_test() ->
    {start, Opts} = beamchain_cli:parse_args(
                      ["start", "--conf=/etc/beamchain/conf.toml"]),
    ?assertEqual("/etc/beamchain/conf.toml", maps:get(conf, Opts)).

conf_space_form_test() ->
    {start, Opts} = beamchain_cli:parse_args(
                      ["start", "--conf", "/tmp/bc.conf"]),
    ?assertEqual("/tmp/bc.conf", maps:get(conf, Opts)).

%%% ===================================================================
%%% --daemon  (background fork)
%%% ===================================================================

daemon_flag_test() ->
    {start, Opts} = beamchain_cli:parse_args(["start", "--daemon"]),
    ?assertEqual(true, maps:get(daemon, Opts)).

daemon_child_marker_internal_test() ->
    %% Internal marker emitted by the parent re-exec; child path runs
    %% the foreground start without forking again.
    {start, Opts} = beamchain_cli:parse_args(
                      ["start", "--daemon", "--_daemon-child"]),
    ?assertEqual(true, maps:get(daemon, Opts)),
    ?assertEqual(true, maps:get('_daemon_child', Opts)).

%%% ===================================================================
%%% --printtoconsole
%%% ===================================================================

printtoconsole_default_off_test() ->
    {start, Opts} = beamchain_cli:parse_args(["start"]),
    ?assertEqual(false, maps:get(printtoconsole, Opts, false)).

printtoconsole_flag_test() ->
    {start, Opts} = beamchain_cli:parse_args(
                      ["start", "--printtoconsole"]),
    ?assertEqual(true, maps:get(printtoconsole, Opts)).

printtoconsole_explicit_zero_test() ->
    {start, Opts} = beamchain_cli:parse_args(
                      ["start", "--printtoconsole=0"]),
    ?assertEqual(false, maps:get(printtoconsole, Opts)).

%%% ===================================================================
%%% --debug and --debug=<cats>
%%% ===================================================================

debug_bare_test() ->
    {start, Opts} = beamchain_cli:parse_args(["start", "--debug"]),
    ?assertEqual(true, maps:get(debug, Opts)),
    ?assertEqual(undefined, maps:get(debug_categories, Opts, undefined)).

debug_one_category_test() ->
    {start, Opts} = beamchain_cli:parse_args(["start", "--debug=net"]),
    ?assertEqual(true, maps:get(debug, Opts)),
    ?assertEqual([net], maps:get(debug_categories, Opts)).

debug_multi_category_test() ->
    {start, Opts} = beamchain_cli:parse_args(
                      ["start", "--debug=net,rpc,validation"]),
    ?assertEqual([net, rpc, validation], maps:get(debug_categories, Opts)).

debug_ignores_blanks_test() ->
    {start, Opts} = beamchain_cli:parse_args(
                      ["start", "--debug=net,,rpc, "]),
    ?assertEqual([net, rpc], maps:get(debug_categories, Opts)).

%%% ===================================================================
%%% apply_debug_categories/1 -- side-effecting, but module-level only
%%% ===================================================================

apply_known_category_changes_module_level_test() ->
    %% Snapshot pre-state, apply, observe, restore.
    %% logger:get_module_level/1 returns [{Module, Level}] (level set)
    %% or [] (inherits primary).
    Pre = logger:get_module_level(beamchain_rpc),
    ok = beamchain_cli:apply_debug_categories([rpc]),
    Post = logger:get_module_level(beamchain_rpc),
    %% Restore: remove the override entirely so other tests aren't affected.
    _ = logger:unset_module_level(beamchain_rpc),
    ?assertMatch([{beamchain_rpc, debug}], Post),
    ?assert(Post =/= Pre orelse Pre =:= [{beamchain_rpc, debug}]).

apply_unknown_category_is_noop_test() ->
    %% Unknown category logs notice but must not crash. We just call
    %% it and assert the function returned ok-equivalent.
    ?assertEqual(ok, beamchain_cli:apply_debug_categories([nosuch_cat])).

apply_all_pseudo_category_sets_primary_test() ->
    %% 'all' is documented to flip the primary level to debug.
    Pre = maps:get(level, logger:get_primary_config()),
    ok = beamchain_cli:apply_debug_categories([all]),
    Mid = maps:get(level, logger:get_primary_config()),
    %% Restore.
    logger:set_primary_config(level, Pre),
    ?assertEqual(debug, Mid).
