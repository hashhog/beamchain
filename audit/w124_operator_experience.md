# W124 — Operator Experience Audit (beamchain)

**Status**: DISCOVERY — 30 gates classified / 13 P0–P1 bugs found / 0 prod
changes (audit-only wave).

**Tests**: `test/beamchain_w124_operator_tests.erl` — 30 tests, all green
on master @ HEAD.  Each MISSING/PARTIAL gate lands as an `?_assert(true)`
marker test with the expected behavior in the comment, so the absence is
greppable from the suite and survives future refactors.

**Reference**:
- `bitcoin-core/src/init.cpp` — CreatePidFile / RemovePidFile /
  HandleSIGTERM / HandleSIGHUP / registerSignalHandler / Shutdown / Interrupt
- `bitcoin-core/src/logging.{cpp,h}` — m_reopen_file, file rotation
- `bitcoin-core/src/util/signalinterrupt.h` — SignalInterrupt
- `/home/work/hashhog/CLAUDE.md` "Ops (mainnet fleet)" — W10 SIGTERM forensics

## Context

Per the root `CLAUDE.md`, beamchain suffered an **87-minute DOWN window in
W10** because a hand-rolled `kill -TERM $(ss …)` + relaunch idiom on the
mainnet host flushed and SIGTERMed the node correctly, but the relaunch
step was silently missed.  The fleet-wide fix was two-pronged:

1. `tools/stop_mainnet.sh` (synchronous restart + RPC verify) — meta-repo
2. An in-process SIGTERM handler in `beamchain_app.erl` that runs
   `beamchain_chainstate:flush` BEFORE `init:stop` — submodule

This audit verifies (1) those handler paths in beamchain are in good
shape AND (2) surfaces the **remaining operator-surface gaps** that
could produce the next outage class.  No production code changes — the
findings are tracked as marker tests that will be flipped to assertions
by future fix waves.

## Top-line counts

| Status   | Count | Gates |
|----------|------:|-------|
| PASS     | 13    | G01 G02 G03 G04 G06 G08 G09 G10 G13 G14 G16 G17 G21 G22 G26 |
| PARTIAL  |  4    | G07 G11 G12 G19 G27 |
| MISSING  | 13    | G05 G15 G18 G20 G23 G24 G25 G28 G29 G30 |

(G07/G11/G12/G19/G27 are PARTIAL because the current behavior is correct
but the operator surface is weaker than Core / OTP best practice.)

## Bug summary (13 bugs ≈ P0/P1)

| ID    | Pri | Gate | Summary                                                                 |
|-------|-----|------|-------------------------------------------------------------------------|
| BUG-1 | P0  | G20  | `-setcookie beamchain` is a hardcoded public cookie in `config/vm.args` |
| BUG-2 | P1  | G25  | No `-heart` watchdog — VM crash silently leaves a dead node             |
| BUG-3 | P1  | G27  | RPC `stop` does NOT explicitly flush chainstate before `init:stop`      |
| BUG-4 | P1  | G18  | File logger handler installed in CLI, NOT in `sys.config`               |
| BUG-5 | P1  | G29  | No explicit datadir lock (relies on RocksDB LOCK; confusing diag)       |
| BUG-6 | P1  | G15  | `RemovePidFile` is unconditional — could nuke externally-managed pid    |
| BUG-7 | P1  | G24  | No `ERL_CRASH_DUMP` path — defaults to CWD, lost on `--daemon`          |
| BUG-8 | P1  | G07  | Top supervisor uses `one_for_one` — config crash strands `node_sup`     |
| BUG-9 | P1  | G28  | No `-shutdownnotify` / `-startupnotify` / `-alertnotify` hook scripts   |
| BUG-10| P1  | G11  | Default 5000ms shutdown timeout on mempool / peer_manager / sync        |
| BUG-11| P2  | G05  | SIGPIPE has no explicit `SIG_IGN` (relies on OTP defaults)              |
| BUG-12| P2  | G19  | SASL crash reports not routed through file logger                       |
| BUG-13| P2  | G30  | Smoke harness doesn't verify the file logger actually emitted lines     |

## Gate-by-gate classification

### Section A — Signal handling (G01–G06)

| Gate | Status | Notes |
|------|--------|-------|
| G01 SIGTERM handler installed                       | PASS    | `os:set_signal(sigterm, handle)` + `graceful_shutdown_on_signal` |
| G02 SIGHUP rotates log handlers                     | PASS    | `reopen_log_handlers/0` swaps `logger_std_h` for logrotate compat |
| G03 SIGTERM flushes chainstate BEFORE init:stop     | PASS    | String-position check — W10 regression-guard |
| G04 SIGTERM removes PID file                        | PASS    | `beamchain_cli:remove_pidfile/0` is called |
| G05 SIGPIPE explicitly ignored                      | MISSING | Core: `signal(SIGPIPE, SIG_IGN)`; beamchain relies on OTP defaults |
| G06 Handler runs in spawned process                 | PASS    | Doesn't block `erl_signal_server` |

### Section B — Supervision tree hygiene (G07–G12)

| Gate | Status | Notes |
|------|--------|-------|
| G07 Top supervisor strategy                         | PARTIAL | `one_for_one` — if config crashes, node_sup is NOT restarted; should be `rest_for_one` |
| G08 node_sup uses rest_for_one                      | PASS    | Correct — downstream children depend on db / chainstate |
| G09 chainstate has 30s shutdown timeout             | PASS    | Direct W10 lesson — default 5000ms replays ~42 blocks |
| G10 wallet uses temporary restart                   | PASS    | Doesn't auto-restart — operator state preserved |
| G11 Default 5000ms shutdown on other children       | PARTIAL | mempool / peer_manager / sync / addrman could lose state |
| G12 intensity=5, period=10 with ~15 children        | PARTIAL | A db blip could exhaust restart budget and SHUTDOWN the VM |

### Section C — PID-file lifecycle (G13–G15)

| Gate | Status | Notes |
|------|--------|-------|
| G13 `pidfile_path` honors `--pid`                   | PASS    | Mirrors Core's `-pid` arg |
| G14 `pidfile_path_safe` config-independent          | PASS    | Resolves at shutdown when config gen_server is dead |
| G15 `RemovePidFile` is creator-guarded              | MISSING | Core: `if (!g_generated_pid) return`; beamchain removes unconditionally |

### Section D — Log rotation & handlers (G16–G19)

| Gate | Status | Notes |
|------|--------|-------|
| G16 File handler has size-based rotation            | PASS    | 10 MB / 3 files via `logger_std_h` |
| G17 Console handler opt-in via `--printtoconsole`   | PASS    | Mirrors Core's `-printtoconsole` |
| G18 Logger handler installed via `sys.config`       | MISSING | Currently in `beamchain_cli` only — release start that skips main/1 loses ALL logs |
| G19 SASL error logger                               | PARTIAL | Disabled correctly but crash reports go to default_h (lost under `--daemon`) |

### Section E — VM args / release config (G20–G25)

| Gate | Status | Notes |
|------|--------|-------|
| G20 `-setcookie` not the literal `beamchain`         | MISSING | **P0 security**: hardcoded public cookie = anyone-on-host can `rpc:call/4` arbitrary code |
| G21 `+P 1048576` process limit                       | PASS    | Sufficient for 125 peers + workers |
| G22 `+A 64` async thread pool                        | PASS    | Good for RocksDB NIF + secp256k1 NIF |
| G23 `+Q` max ports                                   | MISSING | Default 65536 OK at current scale but explicit is better |
| G24 `ERL_CRASH_DUMP` path                            | MISSING | Defaults to CWD — lost when CWD is ephemeral |
| G25 `-heart` watchdog                                | MISSING | VM crash leaves dead node; W10 mitigatable |

### Section F — Daemon mode & lifecycle (G26–G28)

| Gate | Status | Notes |
|------|--------|-------|
| G26 `--daemon` detaches via re-exec                  | PASS    | nohup + `--_daemon-child` marker prevents fork loop |
| G27 RPC `stop` path                                  | PARTIAL | Relies on supervisor `terminate/2` chain; no explicit flush |
| G28 lifecycle hook scripts                           | MISSING | No `-shutdownnotify` / `-startupnotify` / `-alertnotify` |

### Section G — Datadir & ops safety (G29–G30)

| Gate | Status | Notes |
|------|--------|-------|
| G29 Explicit datadir lock                            | MISSING | Relies on RocksDB LOCK — confusing diagnostic vs `LockDirectory` |
| G30 Smoke harness validates cold-boot                | PASS*   | Ping liveness OK; does NOT verify file logger actually wrote anything |

## Universal findings

### F1 — "Stop-path divergence between SIGTERM and RPC stop" (P1)
The SIGTERM path was hardened post-W10 to flush chainstate before
`init:stop`.  The RPC `stop` path was NOT hardened the same way.  It
sleeps 200ms then calls `init:stop()`, relying entirely on the
supervisor's `terminate/2` chain to invoke `beamchain_chainstate:terminate/2`
(which calls `do_flush`).  Both paths reach the same end state under
normal conditions, but any refactor that breaks the supervisor's
trap_exit propagation breaks the RPC stop path silently.  **Fix
shape**: add explicit `beamchain_chainstate:flush()` before
`init:stop()` in `rpc_stop/0`, mirroring `graceful_shutdown_on_signal/1`.

### F2 — "Cookie is the OTP-equivalent of root password" (P0)
`-setcookie beamchain` in vm.args is published in this repo.  Any
process on the same host (or with the ability to read `~/.erlang.cookie`
on the maxbox) can `rpc:call(beamchain@127.0.0.1, os, cmd, ["…"])` and
execute arbitrary shell.  **Mitigation today**: dist port is bound to
loopback via `-name beamchain@127.0.0.1` — so the attack surface is
limited to local users.  **But** the `work` user IS the operator
account on maxbox, so any non-root compromise of `work` becomes a
full RCE inside the BEAM.  **Fix shape**: generate `~/.beamchain/.erlcookie`
at first start (file mode 0400), and source it via `RELEASE_COOKIE` env
or `-setcookie $(cat $HOME/.beamchain/.erlcookie)` in vm.args.

### F3 — "Logger handler depends on CLI entry path" (P1)
The file logger is installed by `beamchain_cli:setup_file_logger/0`,
which is called from `start_node/1`, `import_blocks/1`, and
`do_import_utxo/1`.  An operator who launches via
`_build/prod/rel/beamchain/bin/beamchain foreground` or `console`
bypasses `main/1` and gets the rebar3 release default — NO file
handler, all output to stdout.  Combined with `--daemon` (which
redirects stdout to `<datadir>/beamchain.out`), this is just an
unrotated `beamchain.out` that grows forever.  **Fix shape**: move
the logger handler spec into `config/sys.config` under
`{kernel, [{logger, [...]}]}`, so the handler exists at app-boot
time regardless of launch path.

### F4 — "Supervisor strategy doesn't model config dependency" (P1)
`beamchain_sup` uses `one_for_one` with children `[beamchain_config,
beamchain_node_sup]`.  If `beamchain_config` crashes, `node_sup` keeps
running with the OLD config's ETS state (which the new config will
disagree with).  Should be `rest_for_one` — same shape as `node_sup`
itself.

### F5 — "Restart-budget exhaustion = whole-VM crash" (P1)
Both `beamchain_sup` and `beamchain_node_sup` use `intensity=5,
period=10`.  With ~15 permanent children in `node_sup`, a transient
RocksDB IO error that cascades to mempool / chainstate / peer_manager
could blow through 5 restarts in 10 seconds.  When that happens the
supervisor shuts down its entire subtree, and because
`beamchain_node_sup` is a child of `beamchain_sup`, this exits the
application — which under default release config means `init:stop` and
node DOWN.  **Fix shape**: bump intensity to e.g. 10, OR group fragile
children (mempool, peer_manager) under a child supervisor with its own
budget so failures are contained.

### F6 — "Datadir lock is implicit and operator-unfriendly" (P1)
Bitcoin Core's `LockDirectory(datadir, ".lock")` produces a clean
diagnostic: "Cannot obtain a lock on data directory %s. %s is probably
already running."  beamchain relies on RocksDB's internal LOCK file
which fails with "IO error: While lock file: …LOCK: Resource
temporarily unavailable" — operators have to recognize that pattern.
Worse, two RocksDB column families open in serial, so one CF can
already be opened by THIS process before another instance fails the
LOCK check — partial-init state on disk.

### F7 — "Operator-hook parity gap" (P1)
Core exposes three hook-script args:
- `-startupnotify` — run command after init complete
- `-shutdownnotify` — run command before shutdown begins
- `-alertnotify` — run command when an alert fires

beamchain has none.  Fleet monitor at the meta-repo level can poll RPC
for status, but there's no in-process hook point.

## Recommended fix-wave ordering

Order minimizes risk of breaking operator workflows in flight.

1. **FIX-W124-1 (P0)**: Random per-deployment cookie (G20, BUG-1).
   File mode 0400, generated at first launch, referenced via
   `RELEASE_COOKIE` env or vm.args `-setcookie $(cat …)`.
2. **FIX-W124-2 (P1)**: Move logger handler into `config/sys.config`
   (G18, BUG-4).  Single source of truth across all launch paths.
3. **FIX-W124-3 (P1)**: Hard-code `-heart` + `HEART_COMMAND` in vm.args
   (G25, BUG-2).  Makes W10-class outages self-healing.
4. **FIX-W124-4 (P1)**: Explicit flush in `rpc_stop/0` (G27, BUG-3).
   Decoupled from supervisor `terminate/2` chain.
5. **FIX-W124-5 (P1)**: Top supervisor → `rest_for_one` (G07, BUG-8).
   Models the config dependency correctly.
6. **FIX-W124-6 (P1)**: Datadir `.lock` file (G29, BUG-5).  Clean
   "another beamchain is using this datadir" diagnostic.
7. **FIX-W124-7 (P1)**: `g_generated_pid` equivalent (G15, BUG-6).
   Don't nuke externally-managed pid files.
8. **FIX-W124-8 (P1)**: `ERL_CRASH_DUMP=<datadir>/erl_crash.dump`
   (G24, BUG-7).  Forensics survive container restarts.
9. **FIX-W124-9 (P1)**: Per-child shutdown timeouts for mempool / sync
   / peer_manager (G11, BUG-10).  Bump to 15000ms.
10. **FIX-W124-10 (P1)**: `-shutdownnotify` / `-startupnotify` /
    `-alertnotify` hook args (G28, BUG-9).  Core parity for ops scripts.
11. **FIX-W124-11 (P2)**: SIGPIPE explicit `SIG_IGN` (G05, BUG-11).
12. **FIX-W124-12 (P2)**: SASL crash report routing through file
    logger (G19, BUG-12).
13. **FIX-W124-13 (P2)**: Smoke harness asserts beamchain.log was
    written (G30, BUG-13).
