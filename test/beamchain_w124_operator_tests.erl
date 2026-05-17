-module(beamchain_w124_operator_tests).

%%% -------------------------------------------------------------------
%%% W124 — Operator experience audit (beamchain).
%%%
%%% Scope: signal handling / shutdown ordering / supervision-tree hygiene
%%%        / PID-file lifecycle / log rotation / daemon mode / VM args
%%%        / release config / heart watchdog / dist-port hardening /
%%%        crash-dump location / Core operator parity.
%%%
%%% Context: Per /home/work/hashhog/CLAUDE.md, beamchain suffered an
%%% 87-minute DOWN window during Wave 10 (W10) because a hand-rolled
%%% `kill -TERM $(ss …)` + relaunch idiom flushed and SIGTERMed the
%%% node but the relaunch step was silently missed.  The repo-wide fix
%%% was `tools/stop_mainnet.sh` (synchronous restart with RPC verify)
%%% and an in-process SIGTERM handler in beamchain_app.erl that runs
%%% beamchain_chainstate:flush BEFORE init:stop.  This audit verifies
%%% those handler paths AND surfaces remaining operator-surface gaps
%%% that could produce the next outage class.
%%%
%%% Reference:
%%%   bitcoin-core/src/init.cpp                — CreatePidFile / RemovePidFile /
%%%                                              HandleSIGTERM / HandleSIGHUP /
%%%                                              registerSignalHandler / Shutdown
%%%   bitcoin-core/src/logging.{cpp,h}         — log rotation, m_reopen_file
%%%   bitcoin-core/src/util/signalinterrupt.h  — SignalInterrupt
%%%   bitcoin-core/src/init.cpp:521,1432,414   — -pid handling
%%%   bitcoin-core/src/init.cpp:902-909        — SIGTERM/INT/HUP/PIPE
%%%   bitcoin-core/src/init.cpp:530            — -shutdownnotify
%%%   bitcoin-core/src/init.cpp:529            — -startupnotify
%%%   bitcoin-core/src/init.cpp:485            — -alertnotify
%%%   docs/wave12-2026-04-14/BEAMCHAIN-SIGTERM-CULPRIT.md (W10 forensics)
%%%   audit/w124_operator_experience.md        — full classification table
%%%
%%% Gate classification: each gate is PASS / PARTIAL / MISSING.
%%% PASS gates green-bar a real production invariant.
%%% PARTIAL/MISSING gates land as ?_assert(true) marker tests with the
%%% expected operator behavior in a comment, so the absence is
%%% greppable from the test suite and survives future refactors.
%%% -------------------------------------------------------------------

-include_lib("eunit/include/eunit.hrl").

%% Locate the source file directly so we can grep static config /
%% supervision-strategy invariants from disk without depending on
%% module-private accessors.  Same pattern as W118 / W119 / FIX-67.
beamchain_src_dir() ->
    Beam = code:which(beamchain_app),
    case Beam of
        non_existing -> "src";
        _ ->
            Ebin = filename:dirname(Beam),
            Lib  = filename:dirname(Ebin),
            Src  = filename:join([Lib, "src"]),
            case filelib:is_dir(Src) of
                true -> Src;
                false -> "src"
            end
    end.

%% Resolve the project root (where config/, scripts/, rebar.config live).
%% From the eunit run, cwd IS the project root; from rebar3 escript and
%% other harness shapes we walk up from the beam location until we find
%% a rebar.config sibling.  Falls back to ".".
beamchain_root_dir() ->
    {ok, Cwd} = file:get_cwd(),
    case filelib:is_regular(filename:join(Cwd, "rebar.config")) of
        true -> Cwd;
        false -> find_root_from_beam()
    end.

find_root_from_beam() ->
    case code:which(beamchain_app) of
        non_existing -> ".";
        Beam ->
            walk_up_to_rebar_config(filename:dirname(Beam), 8)
    end.

walk_up_to_rebar_config(_Dir, 0) -> ".";
walk_up_to_rebar_config(Dir, N) ->
    case filelib:is_regular(filename:join(Dir, "rebar.config")) of
        true -> Dir;
        false ->
            Parent = filename:dirname(Dir),
            case Parent of
                Dir -> ".";
                _   -> walk_up_to_rebar_config(Parent, N - 1)
            end
    end.

read_src(Module) ->
    Path = filename:join(beamchain_src_dir(), atom_to_list(Module) ++ ".erl"),
    case file:read_file(Path) of
        {ok, Bin} -> binary_to_list(Bin);
        {error, _} -> ""
    end.

read_config(Name) ->
    Path = filename:join([beamchain_root_dir(), "config", Name]),
    case file:read_file(Path) of
        {ok, Bin} -> binary_to_list(Bin);
        {error, _} -> ""
    end.

contains(Hay, Needle) ->
    string:str(Hay, Needle) > 0.

%%% ===================================================================
%%% Section A — Signal handling (Gates G01–G06)
%%% ===================================================================

%% G01 — SIGTERM installed (PASS).  os:set_signal(sigterm, handle) is
%% the OTP API equivalent of Core's registerSignalHandler(SIGTERM, ...)
%% in init.cpp:902.  Without it, the default OTP handler calls
%% init:stop/0 directly and races the supervisor shutdown — exactly
%% the W10 failure shape.
g01_sigterm_handler_installed_test() ->
    Src = read_src(beamchain_app),
    ?assert(contains(Src, "os:set_signal(sigterm, handle)")),
    ?assert(contains(Src, "graceful_shutdown_on_signal")).

%% G02 — SIGHUP rotates log handlers (PASS).  Core's HandleSIGHUP sets
%% LogInstance().m_reopen_file = true (init.cpp:432).  beamchain
%% re-installs the logger_std_h file handler so logrotate can move/
%% truncate the active log and the new fd opens transparently.
g02_sighup_log_reopen_test() ->
    Src = read_src(beamchain_app),
    ?assert(contains(Src, "os:set_signal(sighup, handle)")),
    ?assert(contains(Src, "reopen_log_handlers")),
    ?assert(contains(Src, "beamchain_file_logger")).

%% G03 — SIGTERM handler runs chainstate flush before init:stop (PASS).
%% This is the key W10 regression-guard: chainstate:flush MUST run
%% before init:stop or the UTXO cache replay window jumps back ~42
%% blocks on restart.
g03_sigterm_flushes_before_init_stop_test() ->
    Src = read_src(beamchain_app),
    %% In the production handler the flush call MUST appear before the
    %% init:stop call.  We verify ordering by string position.
    FlushPos = string:str(Src, "beamchain_chainstate:flush"),
    InitStopPos = string:str(Src, "init:stop()"),
    ?assert(FlushPos > 0),
    ?assert(InitStopPos > 0),
    ?assert(FlushPos < InitStopPos).

%% G04 — SIGTERM handler removes PID file (PASS).  Mirrors Core's
%% RemovePidFile call inside Shutdown() (init.cpp:414).  Without this,
%% a graceful SIGTERM leaves a stale PID file and external tools
%% (start_mainnet.sh) treat the node as still up.
g04_sigterm_removes_pidfile_test() ->
    Src = read_src(beamchain_app),
    ?assert(contains(Src, "beamchain_cli:remove_pidfile")).

%% G05 — SIGPIPE ignored (MISSING).  Core: signal(SIGPIPE, SIG_IGN) at
%% init.cpp:909.  On Linux, a peer closing its read side mid-write
%% raises SIGPIPE on the writing process; Erlang's port driver
%% normally handles this via {error, epipe}, but raw os:cmd / shell
%% indirection paths (e.g. daemonize/1's os:cmd) can leak the signal.
%% beamchain has NO explicit SIGPIPE disposition, so it relies on
%% OTP/glibc defaults.  Track as MISSING for explicit-handler parity.
g05_sigpipe_handled_test() ->
    Src = read_src(beamchain_app),
    %% MISSING — expected to be ABSENT for now.  Marker stays as an
    %% ?_assert(true) skip so a future fix can flip the polarity.
    ?assertNot(contains(Src, "sigpipe")),
    ?assert(true).

%% G06 — Signal handler runs in a spawned process so the gen_event
%% callback returns fast (PASS).  Critical for not blocking
%% erl_signal_server.
g06_signal_handler_spawn_test() ->
    Src = read_src(beamchain_app),
    ?assert(contains(Src, "spawn(fun() -> graceful_shutdown_on_signal")),
    ?assert(contains(Src, "spawn(fun() -> reopen_log_handlers")).

%%% ===================================================================
%%% Section B — Supervision tree hygiene (Gates G07–G12)
%%% ===================================================================

%% G07 — Top supervisor uses one_for_one for {config, node_sup} (PASS,
%% but classified PARTIAL in audit md).  If beamchain_config crashes,
%% the node_sup subtree is NOT restarted — config holds critical ETS
%% state and stale config persists.  A rest_for_one strategy would be
%% safer here because node_sup depends on config.  Marker test
%% documents the current strategy.
g07_top_sup_strategy_test() ->
    Src = read_src(beamchain_sup),
    ?assert(contains(Src, "strategy => one_for_one")),
    ?assert(contains(Src, "intensity => 5")),
    ?assert(contains(Src, "period => 10")),
    %% MISSING-flip-target: should be rest_for_one because node_sup
    %% depends on config's ETS state.  ?_assert(true) marker.
    ?assert(true).

%% G08 — node_sup uses rest_for_one (PASS).  Correct for downstream
%% dependencies: if beamchain_db crashes, every child after it
%% (chainstate, mempool, peer_manager, ...) must restart in order.
g08_node_sup_rest_for_one_test() ->
    Src = read_src(beamchain_node_sup),
    ?assert(contains(Src, "strategy => rest_for_one")).

%% G09 — chainstate has 30s shutdown timeout (PASS).  Direct W10
%% lesson: the OTP default of 5000ms truncated the UTXO flush and
%% replayed ~42 blocks on restart.
g09_chainstate_shutdown_timeout_test() ->
    Src = read_src(beamchain_chainstate_sup),
    %% Two child specs (main + snapshot) both need 30000ms.
    ?assertEqual(3, length([X || X <- string:tokens(Src, "\n"),
                                  string:str(X, "shutdown => 30000") > 0])).

%% G10 — wallet_sup uses temporary restart (PASS).  Wallets crashing
%% should NOT auto-restart — preserves the unloaded state operator
%% saw via unloadwallet RPC.
g10_wallet_restart_temporary_test() ->
    Src = read_src(beamchain_wallet_sup),
    ?assert(contains(Src, "restart => temporary")).

%% G11 — node_sup children OTHER than chainstate keep the default
%% 5000ms shutdown (PARTIAL).  Long-flush processes (mempool,
%% peer_manager, sync) could lose state if they cannot complete a
%% terminate/2 in 5s.  No explicit shutdown timeout in
%% beamchain_node_sup's generic child_spec/2 helper.
g11_node_sup_default_shutdown_test() ->
    Src = read_src(beamchain_node_sup),
    %% child_spec/2 does NOT set a shutdown key, so OTP applies the
    %% default 5000ms.  Marker — future fix should bump mempool /
    %% peer_manager / sync / addrman to e.g. 15000ms each.
    ?assertNot(contains(Src, "shutdown =>")),
    ?assert(true).

%% G12 — Intensity / period not tuned for child count (PARTIAL).  Both
%% top-sup and node_sup use intensity=5, period=10.  node_sup hosts ~15
%% permanent children; a transient db / network blip could exhaust the
%% budget and trigger a supervisor SHUTDOWN, killing the whole VM.
g12_restart_intensity_test() ->
    NodeSrc = read_src(beamchain_node_sup),
    TopSrc  = read_src(beamchain_sup),
    ?assert(contains(NodeSrc, "intensity => 5")),
    ?assert(contains(TopSrc,  "intensity => 5")),
    %% Marker — track count of permanent children for context.
    PermCount = length([X || X <- string:tokens(NodeSrc, "\n"),
                              string:str(X, "child_spec(") > 0]),
    ?assert(PermCount >= 15),
    ?assert(true).

%%% ===================================================================
%%% Section C — PID-file lifecycle (Gates G13–G15)
%%% ===================================================================

%% G13 — write_pidfile honors --pid override (PASS).  Mirrors Core's
%% args.GetPathArg("-pid", BITCOIN_PID_FILENAME) at init.cpp:180.
g13_pidfile_path_override_test() ->
    Src = read_src(beamchain_cli),
    ?assert(contains(Src, "pidfile_path")),
    ?assert(contains(Src, "beamchain.pid")).

%% G14 — pidfile_path_safe resolves WITHOUT depending on
%% beamchain_config gen_server (PASS).  Critical at shutdown when the
%% config process may already be down.
g14_pidfile_path_safe_test() ->
    Src = read_src(beamchain_cli),
    ?assert(contains(Src, "pidfile_path_safe")),
    ?assert(contains(Src, "application:get_env(beamchain, pidfile)")).

%% G15 — RemovePidFile is unconditional (MISSING).  Core guards
%% removal with g_generated_pid (init.cpp:203): only the process that
%% CREATED the pid file removes it.  beamchain unconditionally calls
%% file:delete on the path resolved at shutdown — if the operator
%% switched datadir mid-life or another tool is managing the file,
%% beamchain could nuke an externally-managed pid file.
g15_pidfile_remove_creator_guard_test() ->
    Src = read_src(beamchain_cli),
    %% MISSING: there is no g_generated_pid equivalent.  Future fix:
    %% set application:set_env(beamchain, pidfile_owned, true) only
    %% after successful write_file, and gate remove_pidfile on it.
    ?assertNot(contains(Src, "pidfile_owned")),
    ?assert(true).

%%% ===================================================================
%%% Section D — Log rotation & handlers (Gates G16–G19)
%%% ===================================================================

%% G16 — File handler has size-based rotation (PASS).  10 MB / 3 files
%% via logger_std_h's max_no_bytes / max_no_files.  Reasonable default
%% for a node generating ~1-10 MB/day at info level.
g16_file_log_rotation_test() ->
    Src = read_src(beamchain_cli),
    ?assert(contains(Src, "max_no_bytes => 10485760")),
    ?assert(contains(Src, "max_no_files => 3")).

%% G17 — Console handler is opt-in via --printtoconsole (PASS).
%% Mirrors Core's -printtoconsole arg.  Default-off matches Core when
%% running under -daemon.
g17_console_handler_optin_test() ->
    Src = read_src(beamchain_cli),
    ?assert(contains(Src, "maybe_setup_console_logger")),
    ?assert(contains(Src, "beamchain_console_logger")).

%% G18 — Logger handler installed via beamchain_cli, NOT via sys.config
%% (PARTIAL → MISSING in release mode).  Anyone launching via
%% _build/prod/rel/beamchain/bin/beamchain foreground (which skips the
%% escript main/1 path) gets NO file logger because setup_file_logger/0
%% is only called from start_node/import_blocks/import_utxo command
%% handlers.  Cold-boot via rebar3 release start would silently lose
%% logs.  Fix: move the file-logger config into config/sys.config
%% under {kernel, [{logger, [...]}]}.
g18_logger_in_sys_config_test() ->
    Cfg = read_config("sys.config"),
    %% MISSING: sys.config sets logger_level but no handler spec.
    ?assert(contains(Cfg, "logger_level")),
    ?assertNot(contains(Cfg, "logger_std_h")),
    ?assertNot(contains(Cfg, "{file,")),
    ?assert(true).

%% G19 — SASL error logger disabled (PASS, but PARTIAL semantics).
%% sys.config sets sasl_error_logger=false to silence SASL chatter,
%% but the modern logger backend should be used instead.  Without an
%% explicit handler config, supervisor crash reports go to default_h
%% which writes to standard_io (lost under daemon mode).
g19_sasl_disabled_test() ->
    Cfg = read_config("sys.config"),
    ?assert(contains(Cfg, "sasl_error_logger, false")),
    %% Marker — future fix: add a {logger, [...]} spec under kernel
    %% so supervisor crash reports go to beamchain.log too.
    ?assert(true).

%%% ===================================================================
%%% Section E — VM args / release config (Gates G20–G25)
%%% ===================================================================

%% G20 — vm.args sets -name and -setcookie (PASS, security PARTIAL).
%% -name beamchain@127.0.0.1 binds the dist port to loopback — good.
%% BUT -setcookie beamchain is a hardcoded, publicly-known value.
%% Anyone on the same host (or with credentials that let them write a
%% .erlang.cookie) can rpc:call/4 into the running node and execute
%% arbitrary code (rpc:call(beamchain@127.0.0.1, os, cmd, ...)).
g20_setcookie_default_test() ->
    Args = read_config("vm.args"),
    ?assert(contains(Args, "-setcookie beamchain")),
    ?assert(contains(Args, "-name beamchain@127.0.0.1")),
    %% MISSING: the cookie should be a random per-deployment value.
    %% Stop-gap: rebar3 release respects RELEASE_COOKIE env var, but
    %% smoke-beamchain.sh doesn't set it and the production launcher
    %% doesn't generate a random cookie either.  Future fix: emit a
    %% cookie file alongside .cookie (RPC auth cookie) and source it.
    ?assert(true).

%% G21 — vm.args has +P 1048576 process limit (PASS).
g21_process_limit_test() ->
    Args = read_config("vm.args"),
    ?assert(contains(Args, "+P 1048576")).

%% G22 — vm.args has +A async thread pool (PASS).
g22_async_thread_pool_test() ->
    Args = read_config("vm.args"),
    ?assert(contains(Args, "+A 64")).

%% G23 — vm.args missing +Q max ports (MISSING).  At high peer count
%% (mainnet, 125 peers + RPC + dist + listener + RocksDB sockets),
%% the default 65536 port limit is fine, but explicit is better.
%% Track as MISSING for parity with Core's hardcoded MAX_OUTBOUND
%% and connect counters.
g23_max_ports_set_test() ->
    Args = read_config("vm.args"),
    ?assertNot(contains(Args, "+Q ")),
    ?assert(true).

%% G24 — vm.args missing crash-dump path (MISSING).  ERL_CRASH_DUMP
%% defaults to ./erl_crash.dump in CWD.  Under -daemon mode CWD is
%% the directory the operator launched from — frequently $HOME,
%% which is wrong for forensics.  Bitcoin Core writes debug.log
%% next to the datadir.  Future fix: set
%%   -env ERL_CRASH_DUMP /var/log/beamchain/erl_crash.dump
%% (or under <datadir>/erl_crash.dump).
g24_crash_dump_path_test() ->
    Args = read_config("vm.args"),
    ?assertNot(contains(Args, "ERL_CRASH_DUMP")),
    ?assert(true).

%% G25 — No heart watchdog (MISSING).  Core has no equivalent (relies
%% on systemd Restart=on-failure).  But Erlang ships a built-in heart
%% mechanism — `-heart` + HEART_COMMAND env — that respawns the VM if
%% it crashes.  W10 specifically would have been mitigated by heart:
%% if the kill -TERM had crashed the VM unexpectedly, heart would have
%% relaunched it.  Currently the only safety net is start_mainnet.sh
%% being called explicitly, which is what failed in W10.
g25_heart_watchdog_test() ->
    Args = read_config("vm.args"),
    ?assertNot(contains(Args, "-heart")),
    ?assert(true).

%%% ===================================================================
%%% Section F — Daemon mode & lifecycle (Gates G26–G28)
%%% ===================================================================

%% G26 — --daemon detaches via re-exec (PASS).  Mirrors Core's
%% daemon(3) call in src/util/system.cpp.  Erlang has no native
%% daemon(3) so beamchain shells out to nohup with --_daemon-child
%% marker to prevent infinite fork loops.
g26_daemon_reexec_test() ->
    Src = read_src(beamchain_cli),
    ?assert(contains(Src, "daemonize(Opts)")),
    ?assert(contains(Src, "--_daemon-child")),
    ?assert(contains(Src, "nohup")).

%% G27 — Stop RPC bypasses SIGTERM path (PARTIAL).  rpc_stop() in
%% beamchain_rpc.erl spawns a process that calls init:stop() after a
%% 200ms sleep.  This does NOT invoke graceful_shutdown_on_signal/1
%% directly, so beamchain_chainstate:flush is ONLY run via the
%% supervisor terminate chain.  Should the chainstate terminate/2
%% callback ever stop being called (e.g. a refactor removes the
%% trap_exit), the stop RPC would silently lose UTXO cache state.
g27_rpc_stop_relies_on_terminate_test() ->
    Src = read_src(beamchain_rpc),
    ?assert(contains(Src, "init:stop()")),
    %% Extract the rpc_stop/0 body (between "rpc_stop() ->" and the
    %% next blank-line + "rpc_" function) and assert it contains NO
    %% explicit flush call.  Other RPC handlers (flushchainstate)
    %% DO call flush; this test is scoped to rpc_stop/0 only.
    StopPos = string:str(Src, "rpc_stop() ->"),
    ?assert(StopPos > 0),
    Tail = string:substr(Src, StopPos),
    %% End of rpc_stop body is the next "rpc_uptime" function.
    EndPos = string:str(Tail, "rpc_uptime"),
    ?assert(EndPos > 0),
    StopBody = string:substr(Tail, 1, EndPos),
    %% Marker — production-side regression-guard belongs in the rpc
    %% module: an explicit flush before init:stop would harden the
    %% RPC stop path on par with the SIGTERM handler.
    ?assertNot(contains(StopBody, "beamchain_chainstate:flush")),
    ?assert(true).

%% G28 — No -shutdownnotify / -startupnotify / -alertnotify hooks
%% (MISSING).  Core supports operator hook scripts via these three
%% args (init.cpp:485, 529, 530).  beamchain has no equivalent — an
%% operator who wants "page on shutdown" or "rotate slack channel on
%% startup" has to wrap the launcher externally.
g28_lifecycle_hook_scripts_test() ->
    Cli = read_src(beamchain_cli),
    Cfg = read_src(beamchain_config),
    ?assertNot(contains(Cli, "shutdownnotify")),
    ?assertNot(contains(Cli, "startupnotify")),
    ?assertNot(contains(Cfg, "alertnotify")),
    ?assert(true).

%%% ===================================================================
%%% Section G — Datadir & ops safety (Gates G29–G30)
%%% ===================================================================

%% G29 — No explicit datadir lock (MISSING).  Core's init.cpp calls
%% util/fs_helpers.cpp::LockDirectory(datadir, ".lock") to prevent
%% two instances from using the same data directory.  beamchain only
%% gets implicit protection from RocksDB's own LOCK file, which fails
%% with "IO error: ... LOCK: Resource temporarily unavailable" — a
%% confusing operator surface compared to "datadir already in use by
%% pid N".  Lock should be acquired BEFORE rocksdb open so the
%% diagnostic points at the right culprit.
g29_datadir_lock_test() ->
    %% No explicit lock-file management anywhere outside _build/ or
    %% test/.  beamchain_db.erl opens RocksDB and relies on its LOCK.
    Db = read_src(beamchain_db),
    Cli = read_src(beamchain_cli),
    %% No explicit file:open with [write, exclusive] on a .lock file.
    ?assertNot(contains(Db, "datadir.lock")),
    ?assertNot(contains(Cli, "datadir.lock")),
    ?assert(true).

%% G30 — Smoke harness validates cold-boot (PASS, with caveats).
%% scripts/smoke-beamchain.sh runs `rebar3 xref` + `rebar3 as prod
%% release` + ping liveness for SMOKE_LIFETIME seconds.  Crucially,
%% it does NOT verify that the file logger handler was installed —
%% a regression that broke logging entirely would still PASS smoke.
%% Future fix: assert beamchain.log exists and has > 0 bytes after
%% the lifetime window.
g30_smoke_harness_exists_test() ->
    Path = filename:join([beamchain_root_dir(), "scripts",
                          "smoke-beamchain.sh"]),
    ?assert(filelib:is_regular(Path)),
    {ok, Bin} = file:read_file(Path),
    Hay = binary_to_list(Bin),
    ?assert(string:str(Hay, "rebar3 as prod release") > 0),
    ?assert(string:str(Hay, "ping") > 0),
    %% MISSING-flip-target: smoke should grep the resulting
    %% beamchain.log for at least one log line.
    ?assertNot(string:str(Hay, "beamchain.log") > 0),
    ?assert(true).
