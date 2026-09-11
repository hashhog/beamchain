#!/usr/bin/env bash
# Control: three compile + escriptize must produce one sha256.
#
# Fails (exit 1) when the escript zip still carries per-build atime extras,
# which is what provenance-by-reproduction cannot tolerate.
#
# Rebuilds every Erlang ebin under _build/default/lib (so the archive
# contents are freshly compiled) but leaves compiled NIFs in place — the
# escript does not embed .so files.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

usage() {
    echo "usage: $0" >&2
    exit 2
}

[[ $# -eq 0 ]] || usage

echo "=== three compile+escriptize ==="
declare -a SHAS=()
for i in 1 2 3; do
    echo "--- build $i ---"
    find _build/default/lib -type d -name ebin -exec rm -rf {} + 2>/dev/null || true
    rm -f _build/default/bin/beamchain
    rebar3 compile
    rebar3 escriptize
    sha="$(sha256sum _build/default/bin/beamchain | awk '{print $1}')"
    echo "sha $i = $sha"
    SHAS+=("$sha")
done

echo "=== summary ==="
printf '%s\n' "${SHAS[@]}"
uniq="$(printf '%s\n' "${SHAS[@]}" | sort -u | wc -l)"
echo "unique shas: $uniq"
if [[ "$uniq" -ne 1 ]]; then
    echo "FAIL: three builds, $uniq shas (want 1)" >&2
    exit 1
fi
echo "PASS: three builds, one sha ${SHAS[0]}"
