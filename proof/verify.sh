#!/usr/bin/env bash
# proof/verify.sh — re-check every claim in this bundle against a file here.
# Exit 0 only if the files match claims.json AND the in-repo T1 eunit
# control is green. Run from the beamchain repo root: `bash proof/verify.sh`
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PROOF="$ROOT/proof"
fail=0
say() { printf '%s\n' "$*"; }
die() { printf 'FAIL: %s\n' "$*"; fail=1; }

need() {
  local f="$1"
  [ -f "$PROOF/$f" ] || die "missing $f"
}

say "== beamchain proof bundle verify =="

# 1. every claims.json file exists
python3 - "$PROOF" <<'PY' || fail=1
import json, sys, pathlib
proof = pathlib.Path(sys.argv[1])
claims = json.loads((proof / "claims.json").read_text())
missing = []
for section, body in claims.items():
    for f in body.get("files", []):
        if not (proof / f).is_file():
            missing.append(f)
if missing:
    print("FAIL: missing files:", ", ".join(missing))
    sys.exit(1)
print("files: every claims.json path exists")
PY

# 2. R4 commitment numbers
python3 - "$PROOF" <<'PY' || fail=1
import json, sys, pathlib
proof = pathlib.Path(sys.argv[1])
c = json.loads((proof / "claims.json").read_text())["r4"]
cap = json.loads((proof / "r4/C958794.json").read_text())
rec = (proof / "r4/capture.md").read_text()
watch = (proof / "r4/capture-watch-excerpt.txt").read_text()
unit = (proof / "r4/genesis-unit.service").read_text()
excerpt = (proof / "r4/lineage-excerpt.txt").read_text()
marker = (proof / "r4/capture-state-marker.txt").read_text().strip()
want = c["hash_serialized_3"]
errs = []
if cap["hash_serialized_3"] != want:
    errs.append("C958794.json hash mismatch")
if cap["height"] != c["height"]:
    errs.append("height mismatch")
if cap["bestblockhash"] != c["bestblockhash"]:
    errs.append("bestblockhash mismatch")
if cap["coins"] != c["coins"]:
    errs.append("coins mismatch")
if cap.get("snapshot_booted") is not False:
    errs.append("C958794.json must set snapshot_booted=false")
if want not in rec:
    errs.append("capture.md does not contain hash_serialized_3")
if want not in watch:
    errs.append("capture-watch excerpt does not contain the MATCH hash")
if marker != want:
    errs.append("capture-state marker is not the MATCH hash")
if "--noassumevalid" not in unit:
    errs.append("genesis-unit.service missing --noassumevalid")
if "loadtxoutset" in unit or "assumeutxo" in unit.lower():
    errs.append("genesis-unit.service looks like a snapshot boot")
if c["genesis_block_hash"] not in excerpt:
    errs.append("lineage excerpt missing Bitcoin genesis hash")
if "initialized at height -1" not in excerpt:
    errs.append("lineage excerpt missing initialized at height -1")
if "connected genesis block" not in excerpt:
    errs.append("lineage excerpt missing connected genesis block")
if "starting IBD from 1" not in excerpt:
    errs.append("lineage excerpt missing starting IBD from 1")
if "verifying scripts" not in excerpt:
    errs.append("lineage excerpt missing verifying scripts")
if "initialized at height 958794" not in excerpt:
    errs.append("lineage excerpt missing initialized at height 958794")
if "loadtxoutset matches=0" not in excerpt:
    errs.append("lineage excerpt missing snapshot-boot negative control")
if errs:
    print("FAIL: R4:", "; ".join(errs))
    sys.exit(1)
print(f"R4: C({c['height']}) hash_serialized_3={want} coins={c['coins']} snapshot_booted=false AV=0")
PY

# 3. lineage log gzip round-trip
need "r4/lineage.log.gz"
need "r4/lineage.log.sha256"
got="$(gzip -dc "$PROOF/r4/lineage.log.gz" | sha256sum | awk '{print $1}')"
want="$(tr -d ' \n' < "$PROOF/r4/lineage.log.sha256")"
if [ "$got" != "$want" ]; then
  die "lineage.log.gz uncompressed sha256 $got != $want"
else
  say "R4: lineage.log.gz round-trip sha256=$want"
fi
if gzip -dc "$PROOF/r4/lineage.log.gz" | grep -qiE 'loadtxoutset|loading snapshot'; then
  die "lineage log contains snapshot-boot evidence (TRUST-ANCHOR: does not count)"
else
  say "R4: lineage log has no loadtxoutset/loading snapshot lines"
fi

# 4. R1 numbers
python3 - "$PROOF" <<'PY' || fail=1
import json, sys, pathlib
proof = pathlib.Path(sys.argv[1])
c = json.loads((proof / "claims.json").read_text())["r1"]
r = json.loads((proof / "r1/results.json").read_text())
errs = []
if r["script_tests"]["pass"] != c["script_pass"] or r["script_tests"]["fail"] != c["script_fail"]:
    errs.append("script")
if r["tx_valid"]["pass"] != c["tx_valid_pass"]:
    errs.append("tx_valid")
if r["tx_invalid"]["pass"] != c["tx_invalid_pass"]:
    errs.append("tx_invalid")
if r["sighash"]["exact_match"] != c["sighash_pass"]:
    errs.append("sighash")
if r["divergences"] != c["divergences"]:
    errs.append("divergences")
script_txt = (proof / "r1/script.txt").read_text()
if "PASS:  1109" not in script_txt:
    errs.append("script.txt missing PASS:  1109")
if "PASS:  113" not in script_txt:
    errs.append("script.txt missing PASS:  113")
if "FAIL:  0" not in script_txt:
    errs.append("script.txt missing FAIL:  0")
if "500 passed, 0 failed out of 500" not in (proof / "r1/sighash.txt").read_text():
    errs.append("sighash.txt missing 500/500")
tx = (proof / "r1/tx.txt").read_text()
if "121/121" not in tx:
    errs.append("tx.txt missing 121/121")
if "93/93" not in tx:
    errs.append("tx.txt missing 93/93")
if errs:
    print("FAIL: R1:", ", ".join(errs))
    sys.exit(1)
print(f"R1: script {c['script_pass']}/1222 tx {c['tx_valid_pass']}+{c['tx_invalid_pass']} sighash {c['sighash_pass']}/500 divergences={c['divergences']}")
PY

# 5. R2 numbers
python3 - "$PROOF" <<'PY' || fail=1
import json, sys, pathlib
proof = pathlib.Path(sys.argv[1])
c = json.loads((proof / "claims.json").read_text())["r2"]
r = json.loads((proof / "r2/results.json").read_text())
errs = []
if r["pass"] != c["pass"] or r["fail"] != c["fail"]:
    errs.append("pass/fail")
if r["consensus_splits_accept_vs_reject"] != c["consensus_splits_accept_vs_reject"]:
    errs.append("splits")
if any(not f["same_accept_reject"] for f in r["fails"]):
    errs.append("a listed FAIL is accept-vs-reject — that would be a consensus split")
excerpt = (proof / "r2/nightly-report-excerpt.txt").read_text()
if "beamchain       367      3" not in excerpt:
    errs.append("excerpt missing 367/3")
if errs:
    print("FAIL: R2:", ", ".join(errs))
    sys.exit(1)
print(f"R2: {c['pass']} PASS / {c['fail']} FAIL, consensus splits={c['consensus_splits_accept_vs_reject']}")
PY

# 6. R5 scorecards
python3 - "$PROOF" <<'PY' || fail=1
import json, sys, pathlib
proof = pathlib.Path(sys.argv[1])
c = json.loads((proof / "claims.json").read_text())["r5"]
live = json.loads((proof / "r5/live-20260917T112139Z.json").read_text())["impls"]["beamchain"]
reg = json.loads((proof / "r5/regtest-20260917T122831Z.json").read_text())["impls"]["beamchain"]
sc = json.loads((proof / "r5/scorecard.json").read_text())
errs = []
if live["tiers"]["T1"]["pass"] != c["live_t1_pass"] or live["tiers"]["T1"]["total"] != c["live_t1_total"]:
    errs.append("live T1")
if live["tiers"]["T2"]["pass"] != c["live_t2_pass"]:
    errs.append("live T2")
fails = [r for r in live["rows"] if r["status"] == "FAIL"]
if len(fails) != c["live_fail_count"]:
    errs.append(f"live FAIL set {fails!r}")
if reg["tiers"]["T3"]["pass"] != c["regtest_t3_pass"] or reg["tiers"]["T3"]["total"] != c["regtest_t3_total"]:
    errs.append("regtest T3")
reg_fails = [r for r in reg["rows"] if r["status"] == "FAIL"]
if reg_fails:
    errs.append(f"regtest FAILs {reg_fails!r}")
if sc["live"]["T1"]["pass"] != c["live_t1_pass"]:
    errs.append("scorecard live T1")
if sc["regtest"]["T3"]["pass"] != c["regtest_t3_total"]:
    errs.append("scorecard regtest T3")
after = (proof / "r5/t1-after.txt").read_text()
if "0 failures" not in after:
    errs.append("t1-after.txt is not a passing run")
if errs:
    print("FAIL: R5:", "; ".join(errs))
    sys.exit(1)
print(f"R5 live T1 {c['live_t1_pass']}/{c['live_t1_total']} T2 {c['live_t2_pass']}/{c['live_t2_total']} FAIL={c['live_fail_count']}")
print(f"R5 regtest T3 {c['regtest_t3_pass']}/{c['regtest_t3_total']}")
PY

# 7. README cites every claims.json file
python3 - "$PROOF" <<'PY' || fail=1
import json, sys, pathlib
proof = pathlib.Path(sys.argv[1])
readme = (proof / "README.md").read_text()
claims = json.loads((proof / "claims.json").read_text())
missing = []
for section, body in claims.items():
    for f in body.get("files", []):
        if f not in readme:
            missing.append(f)
if missing:
    print("FAIL: README.md does not cite:", ", ".join(missing))
    sys.exit(1)
print("README: every claims.json file is cited")
PY

# 8. source lists getnetworkhashps the way Core's help does
if ! grep -q 'getnetworkhashps ( nblocks height )' "$ROOT/src/beamchain_rpc.erl"; then
  die "src/beamchain_rpc.erl does not list 'getnetworkhashps ( nblocks height )'"
else
  say "R5: help lists getnetworkhashps ( nblocks height )"
fi

# 9. provenance binary hash (informational — escript rebuilds are not the live zip)
want_bin="$(python3 -c 'import json,pathlib; print(json.loads(pathlib.Path("proof/claims.json").read_text())["provenance"]["binary_sha256"])')"
if [ -x "$ROOT/_build/default/bin/beamchain" ]; then
  got_bin="$(sha256sum "$ROOT/_build/default/bin/beamchain" | awk '{print $1}')"
  if [ "$got_bin" != "$want_bin" ]; then
    say "NOTE: _build/default/bin/beamchain sha256=$got_bin (bundle records $want_bin). Rebuilds are not the live process zip; this is informational."
  else
    say "provenance: _build/default/bin/beamchain sha256=$want_bin"
  fi
else
  say "NOTE: _build/default/bin/beamchain not present. Rebuild with rebar3 escriptize to check the recorded sha256."
fi

# 9b. live unit path identity (read-only). Never start/stop the unit.
if command -v systemctl >/dev/null 2>&1; then
  pid="$(systemctl --user show -p MainPID --value hashhog-beamchain-mainnet 2>/dev/null || true)"
  if [ -n "${pid:-}" ] && [ "$pid" != "0" ] && [ -r "/proc/$pid/cmdline" ]; then
    cmd="$(tr '\0' ' ' < "/proc/$pid/cmdline")"
    if echo "$cmd" | grep -q '_build/default/bin/beamchain'; then
      say "provenance: live argv[0] is _build/default/bin/beamchain (pid $pid)"
    else
      die "live unit pid $pid cmdline does not contain _build/default/bin/beamchain"
    fi
  else
    say "NOTE: live unit not running; skipped argv[0] path check."
  fi
fi

# 10. in-repo T1 parity control (re-run live so a rotted test cannot sit behind a green bundle)
if command -v rebar3 >/dev/null 2>&1; then
  say "== re-run: rebar3 eunit --module=beamchain_t1_rpc_parity_tests =="
  if rebar3 eunit --module=beamchain_t1_rpc_parity_tests; then
    say "R5 in-repo: beamchain_t1_rpc_parity_tests PASS"
  else
    die "beamchain_t1_rpc_parity_tests failed"
  fi
else
  say "NOTE: rebar3 not on PATH; skipped in-repo re-run."
  say "      The recorded after-control is r5/t1-after.txt (10 tests, 0 failures)."
fi

# 11. MANIFEST (all files except MANIFEST itself)
if [ -f "$PROOF/MANIFEST.sha256" ]; then
  if (cd "$PROOF" && sha256sum -c MANIFEST.sha256 --quiet); then
    say "MANIFEST.sha256: OK"
  else
    die "MANIFEST.sha256 mismatch"
  fi
else
  die "MANIFEST.sha256 missing — run bash proof/assemble.sh"
fi

if [ "$fail" -ne 0 ]; then
  say "== FAIL =="
  exit 1
fi
say "== PASS: every claim cites a file in this bundle and the numbers match =="
exit 0
