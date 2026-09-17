#!/usr/bin/env bash
# proof/assemble.sh — refresh provenance + MANIFEST for this committed bundle.
# Frozen evidence (lineage log, capture, R1/R2/R5 artifacts) is already in
# proof/ and is not regenerated from outside this repository.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PROOF="$ROOT/proof"

BIN="_build/default/bin/beamchain"
if [ -x "$BIN" ]; then
  BIN_LINE="binary: $BIN"
  BIN_SHA="binary_sha256: $(sha256sum "$BIN" | awk '{print $1}')"
else
  BIN_LINE="binary: $BIN (not present; gitignored)"
  BIN_SHA="binary_sha256: (rebuild with rebar3 escriptize)"
fi

{
  echo "# Provenance — beamchain proof bundle"
  echo "assembled_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "repo: https://github.com/hashhog/beamchain"
  echo "branch: $(git rev-parse --abbrev-ref HEAD)"
  echo "commit: $(git rev-parse HEAD)"
  echo "commit_short: $(git rev-parse --short=12 HEAD)"
  echo "subject: $(git log -1 --format=%s | cut -c1-120)"
  echo "tree_clean: $([ -z "$(git status --porcelain)" ] && echo yes || echo NO)"
  echo "$BIN_LINE"
  echo "$BIN_SHA"
  echo "toolchain: $(erl -noshell -eval 'io:format("~s~n",[string:trim(erlang:system_info(system_version))]), halt().' 2>/dev/null | head -1 || echo 'erl not on PATH')"
  echo "rebar3: $(rebar3 version 2>/dev/null | head -1 || echo 'rebar3 not on PATH')"
  echo "target: Linux amd64"
  echo "build: rebar3 compile && rebar3 escriptize"
  echo "deploy_pin: none (RocksDB NIF is not relocatable from deploy/)"
  echo "live_argv0: /home/work/hashhog/beamchain/_build/default/bin/beamchain"
  echo
  echo "# Honest caveats"
  echo "The attested artifact is the in-tree escript. beamchain has no relocatable"
  echo "deploy pin — the NIF is loaded from _build/default/lib/rocksdb/priv/."
  echo "/proc/<pid>/exe is the BEAM VM (beam.smp), not the escript. Path identity"
  echo "(argv[0]) is the closure; byte-identity of a live process vs this file is"
  echo "UNPROVEN if the on-disk escript was rebuilt after launch."
  echo "A different OTP, zlib, or build path is expected to produce different"
  echo "bytes. Behavioural re-runs (R1 vectors, in-repo T1 eunit) are the"
  echo "stronger check. See scripts/reproducible-escript.sh."
  echo "This script refreshes provenance + MANIFEST only. Frozen evidence in"
  echo "r1/ r2/ r4/ r5/ is not regenerated from outside this repository."
} > "$PROOF/provenance.txt"

# Hash every file except MANIFEST itself, stable order.
( cd "$PROOF" && find . -type f ! -name MANIFEST.sha256 | sed 's|^\./||' | LC_ALL=C sort \
    | xargs -d '\n' sha256sum > MANIFEST.sha256 )

echo "assemble: $PROOF"
echo "  files: $(find "$PROOF" -type f | wc -l)"
echo "  manifest: $(wc -l < "$PROOF/MANIFEST.sha256") hashes"
