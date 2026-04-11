#!/usr/bin/env bash
# smoke-beamchain.sh
#
# Cold-boot smoke test. Assembles a prod release, launches it against a
# throwaway datadir on non-conflicting ports, waits for the RPC port to
# come up, calls getblockchaininfo once, and tears everything down.
#
# Exits non-zero on ANY failure — safe to chain from build-all.sh or a
# pre-push hook.
#
# The goal is to catch the "release compiled but can't boot" class of
# regression in under a minute, without touching the production datadir.
# Examples of bugs this catches:
#   - Missing parse_transform includes (ets:fun2ms, etc.)
#   - Undefined function calls flagged by xref
#   - Supervision-tree startup crashes
#   - Port binding / datadir permission errors
#   - Config defaults that drift away from "main" chain
#
# Does NOT catch: consensus correctness, peer protocol bugs, long-running
# memory leaks. Those need longer integration runs.

set -euo pipefail

BEAMCHAIN_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$BEAMCHAIN_DIR"

SMOKE_DATADIR="$(mktemp -d -t beamchain-smoke-XXXXXXXX)"
SMOKE_P2P_PORT="${SMOKE_P2P_PORT:-18336}"
SMOKE_RPC_PORT="${SMOKE_RPC_PORT:-18348}"
SMOKE_NODE_NAME="beamchain_smoke_$$@127.0.0.1"
RELEASE="$BEAMCHAIN_DIR/_build/prod/rel/beamchain/bin/beamchain"

BEAM_STARTED=""

cleanup() {
    local rc=$?
    if [ -n "$BEAM_STARTED" ]; then
        # Best-effort graceful stop, then force-kill anything left behind.
        BEAMCHAIN_NETWORK=mainnet \
        BEAMCHAIN_DATADIR="$SMOKE_DATADIR" \
        RELEASE_NODE="$SMOKE_NODE_NAME" \
        "$RELEASE" stop >/dev/null 2>&1 || true
        sleep 1
        pkill -9 -f "$SMOKE_NODE_NAME" 2>/dev/null || true
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
    # Dump the freshest erlang log so CI has something to triage from.
    local latest
    latest=$(ls -t "$BEAMCHAIN_DIR/_build/prod/rel/beamchain/log/erlang.log."* 2>/dev/null | head -1 || true)
    if [ -n "$latest" ]; then
        echo "--- last 80 lines of $latest ---" >&2
        tail -80 "$latest" >&2 || true
    fi
    exit 1
}

echo "[smoke] 1/5 rebar3 xref (catches undefined function calls)"
# rebar3 xref exits non-zero on undefined_function_calls, which is exactly
# what commit 45dc51f4 would have tripped: ets:fun2ms/1 is not a real
# exported function without the ms_transform parse transform.
rebar3 xref

echo "[smoke] 2/5 rebar3 as prod release (fresh assembly)"
rebar3 as prod release >/dev/null

[ -x "$RELEASE" ] || fail "release binary not found at $RELEASE"

echo "[smoke] 3/5 launching against $SMOKE_DATADIR on ports $SMOKE_P2P_PORT/$SMOKE_RPC_PORT"
BEAM_STARTED=1
BEAMCHAIN_NETWORK=mainnet \
BEAMCHAIN_DATADIR="$SMOKE_DATADIR" \
RELEASE_NODE="$SMOKE_NODE_NAME" \
ERL_FLAGS="-beamchain p2pport $SMOKE_P2P_PORT -beamchain rpcport $SMOKE_RPC_PORT" \
"$RELEASE" daemon

# Wait up to 30s for the RPC port to start listening.
for _ in $(seq 1 30); do
    if ss -tln 2>/dev/null | grep -q ":$SMOKE_RPC_PORT "; then
        break
    fi
    sleep 1
done

ss -tln 2>/dev/null | grep -q ":$SMOKE_RPC_PORT " \
    || fail "RPC port $SMOKE_RPC_PORT never started listening within 30s"

echo "[smoke] 4/5 RPC up, calling getblockchaininfo"
COOKIE_FILE="$SMOKE_DATADIR/.cookie"
COOKIE_ARG=()
if [ -s "$COOKIE_FILE" ]; then
    COOKIE_ARG=(--user "$(tr -d '\n' < "$COOKIE_FILE")")
fi

RESPONSE=$(curl -sS --max-time 5 "${COOKIE_ARG[@]}" \
    -H 'content-type: application/json' \
    -d '{"method":"getblockchaininfo","params":[],"id":1}' \
    "http://127.0.0.1:$SMOKE_RPC_PORT/" || true)

[ -n "$RESPONSE" ] || fail "getblockchaininfo returned empty body"

echo "$RESPONSE" | python3 - <<'PY' || fail "getblockchaininfo response did not validate"
import json, sys
raw = sys.stdin.read()
try:
    d = json.loads(raw)
except Exception as e:
    print("[smoke] invalid JSON: %r  raw=%r" % (e, raw[:200]), file=sys.stderr)
    sys.exit(1)
if d.get("error"):
    print("[smoke] RPC error: %r" % d["error"], file=sys.stderr)
    sys.exit(1)
result = d.get("result") or {}
chain = result.get("chain")
if chain != "main":
    print("[smoke] expected chain=main, got %r (config drift?)" % chain, file=sys.stderr)
    sys.exit(1)
print("[smoke] chain=%s blocks=%s headers=%s" % (
    chain, result.get("blocks"), result.get("headers")))
PY

echo "[smoke] 5/5 cold-boot validation complete"
# trap cleanup will stop the node and remove the throwaway datadir.
