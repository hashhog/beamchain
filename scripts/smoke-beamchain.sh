#!/usr/bin/env bash
# smoke-beamchain.sh
#
# Cold-boot smoke test. Assembles a prod release, launches it in daemon
# mode against a throwaway datadir, and verifies the node stays up for
# a fixed window by polling `bin/beamchain ping` (rebar3's built-in
# Erlang distribution health check). Tears everything down on exit.
#
# Exits non-zero on ANY failure — safe to chain from build-all.sh or a
# pre-push hook.
#
# The goal is to catch the "release compiled but can't cold-boot" class
# of regression in under a minute, without touching the production
# datadir. Specifically:
#   - Missing parse_transform includes (ets:fun2ms, etc.) — caught by xref
#   - Undefined function calls — caught by xref
#   - Supervision-tree startup crashes — caught by ping timing out
#   - Missing runtime deps / .beam file issues — caught by ping timing out
#   - Config defaults that break boot — caught by ping timing out
#
# Does NOT catch: consensus correctness, peer protocol bugs, long-running
# memory leaks, RPC field completeness. Those need longer integration
# runs (consensus-diff, etc.).
#
# Why ping and not RPC?
#   - The RPC port binds late (after header sync warm-up) and sometimes
#     drops eaddrinuse silently, so it's unreliable as a liveness signal.
#   - `bin/beamchain ping` talks to the node over Erlang distribution,
#     which comes up immediately and is what rebar3 itself uses for the
#     start/stop/attach lifecycle. If ping returns "pong", the VM is
#     alive and the beamchain application has booted past the point where
#     supervision tree init would have crashed.
#
# Environment overrides (for CI / parallel runs):
#   SMOKE_P2P_PORT   — default 18336
#   SMOKE_LIFETIME   — default 25 (seconds the node must stay up)
#   SMOKE_PING_WAIT  — default 30 (seconds to wait for first pong)

set -euo pipefail

BEAMCHAIN_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$BEAMCHAIN_DIR"

SMOKE_DATADIR="$(mktemp -d -t beamchain-smoke-XXXXXXXX)"
SMOKE_P2P_PORT="${SMOKE_P2P_PORT:-18336}"
SMOKE_LIFETIME="${SMOKE_LIFETIME:-25}"
SMOKE_PING_WAIT="${SMOKE_PING_WAIT:-30}"
# Unique node name so we don't collide with a running production node.
SMOKE_NODE_SHORT="beamchain_smoke_$$"
SMOKE_NODE="${SMOKE_NODE_SHORT}@127.0.0.1"
RELEASE="$BEAMCHAIN_DIR/_build/prod/rel/beamchain/bin/beamchain"

BEAM_STARTED=""

run_release() {
    BEAMCHAIN_NETWORK=mainnet \
    BEAMCHAIN_DATADIR="$SMOKE_DATADIR" \
    RELEASE_NODE="$SMOKE_NODE" \
    ERL_FLAGS="-beamchain p2pport $SMOKE_P2P_PORT" \
    "$RELEASE" "$@"
}

cleanup() {
    local rc=$?
    if [ -n "$BEAM_STARTED" ]; then
        run_release stop >/dev/null 2>&1 || true
        sleep 1
        pkill -9 -f "$SMOKE_NODE_SHORT" 2>/dev/null || true
    fi
    rm -rf "$SMOKE_DATADIR"
    if [ "$rc" -eq 0 ]; then
        echo "[smoke] PASS"
    else
        echo "[smoke] FAIL (exit $rc)"
    fi
    exit $rc
}
trap cleanup EXIT INT TERM

fail() {
    echo "[smoke] FAIL: $*" >&2
    local latest
    latest=$(ls -t "$BEAMCHAIN_DIR/_build/prod/rel/beamchain/log/erlang.log."* 2>/dev/null | head -1 || true)
    if [ -n "$latest" ]; then
        echo "--- last 80 lines of $latest ---" >&2
        tail -80 "$latest" >&2 || true
    fi
    exit 1
}

echo "[smoke] 1/5 rebar3 xref (catches undefined function calls)"
# rebar3 xref exits non-zero on undefined_function_calls, which is the
# check that would have caught commit 45dc51f4: ets:fun2ms/1 is not a
# real exported function of the ets module — it only exists through the
# ms_transform parse transform, so without the include it's reported as
# an undefined function call.
rebar3 xref

echo "[smoke] 2/5 rebar3 as prod release (fresh assembly)"
rebar3 as prod release >/dev/null

[ -x "$RELEASE" ] || fail "release binary not found at $RELEASE"

echo "[smoke] 3/5 launching daemon on port $SMOKE_P2P_PORT, node $SMOKE_NODE, datadir $SMOKE_DATADIR"
BEAM_STARTED=1
run_release daemon

# Wait up to SMOKE_PING_WAIT seconds for the first successful ping.
# rebar3's ping command exits 0 and prints "pong" if the node responds
# to net_adm:ping/1, or non-zero / "pang" otherwise.
echo "[smoke] 4/5 waiting up to ${SMOKE_PING_WAIT}s for first pong"
PING_OK=0
for _ in $(seq 1 "$SMOKE_PING_WAIT"); do
    if run_release ping 2>/dev/null | grep -q pong; then
        PING_OK=1
        break
    fi
    sleep 1
done
[ "$PING_OK" -eq 1 ] || fail "node did not respond to ping within ${SMOKE_PING_WAIT}s"

# Now keep the node alive for SMOKE_LIFETIME seconds and confirm it's
# still responding at the end. This catches bugs where boot succeeds
# but the supervision tree dies under the first real workload (e.g.
# the peer_manager ets:fun2ms crash that fired on the first connect_tick).
echo "[smoke] 5/5 confirming liveness over ${SMOKE_LIFETIME}s window"
sleep "$SMOKE_LIFETIME"
run_release ping 2>/dev/null | grep -q pong \
    || fail "node stopped responding to ping after ${SMOKE_LIFETIME}s — supervision tree may have crashed post-boot"

echo "[smoke] cold-boot validation complete"
# trap cleanup will stop the node and remove the throwaway datadir.
