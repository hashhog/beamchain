#!/usr/bin/env bash
# Run the COMPLETE beamchain eunit suite.
#
# WHY THIS EXISTS
# ---------------
# `rebar3 eunit` does NOT run every test in test/. Its default is
# `{eunit_tests, [{application, beamchain}]}`, and EUnit's {application, App}
# expands to the modules listed in the .app file PLUS, for each module M, a
# sibling module named M_tests. So a test module is discovered only if its name
# is a src module's name with "_tests" appended.
#
# Measured 2026-08-30: of the 139 test/*_tests.erl files, `rebar3 eunit` ran
# 38 — every one of which had a matching src/<M>.erl — and skipped 101, of
# which 97 had no such src module. Those 101 contribute 239 tests, 4 of them
# FAILING, and none of it appeared in the suite's "0 failures" summary.
# A test that is never discovered is worse than no test: it reports green.
#
# {dir, "test"} and {dir, "_build/test/lib/beamchain/test"} in eunit_tests were
# both tried and did NOT change discovery, so this names the modules
# explicitly instead — derived from the directory, so it cannot go stale.
#
# Usage: ./run-all-eunit.sh   (exit 0 only if BOTH passes are clean)
set -uo pipefail
cd "$(dirname "$0")"

# rebar3 exits non-zero when tests are CANCELLED even with zero failures, so the
# verdict is parsed from the counts instead of the exit code. Cancellations are
# still reported loudly -- they mean a suite aborted, which is its own problem --
# but they are not the same thing as a failing assertion.
summarize() {  # $1=label $2=logfile
  local line fails cancels
  line=$(grep -oE "[0-9]+ tests?, [0-9]+ failures?(, [0-9]+ cancelled)?" "$2" | tail -1)
  [ -z "$line" ] && line=$(grep -oE "All [0-9]+ tests passed" "$2" | tail -1)
  fails=$(printf '%s' "$line"   | grep -oE "[0-9]+ failures?"  | grep -oE "[0-9]+" || echo 0)
  cancels=$(printf '%s' "$line" | grep -oE "[0-9]+ cancelled"  | grep -oE "[0-9]+" || echo 0)
  echo "$1: ${line:-<no summary parsed>}"
  echo "${fails:-0} ${cancels:-0}" > "$2.counts"
}

LOG1=$(mktemp); LOG2=$(mktemp)
echo "== pass 1: application-level (src -ifdef(TEST) tests + the 38 name-matched modules)"
rebar3 eunit 2>&1 | tee "$LOG1"

MODS=$(ls test/*_tests.erl 2>/dev/null | xargs -n1 basename | sed 's/\.erl$//' | paste -sd,)
COUNT=$(echo "$MODS" | tr ',' '\n' | grep -c .)
echo
echo "== pass 2: every test/*_tests.erl module explicitly ($COUNT modules)"
rebar3 eunit --module="$MODS" 2>&1 | tee "$LOG2"

echo
summarize "application pass" "$LOG1"
summarize "module pass     " "$LOG2"
read -r F1 C1 < "$LOG1.counts"
read -r F2 C2 < "$LOG2.counts"
rm -f "$LOG1" "$LOG2" "$LOG1.counts" "$LOG2.counts"

TOTF=$((F1 + F2)); TOTC=$((C1 + C2))
[ "$TOTC" -gt 0 ] && echo "NOTE: $TOTC cancelled — a suite aborted; not a failing assertion, but not nothing."
if [ "$TOTF" -eq 0 ]; then
  echo "GREEN: 0 failures across both passes"; exit 0
fi
echo "RED: $TOTF failures across both passes"
exit 1
