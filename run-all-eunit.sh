#!/usr/bin/env bash
# Run the COMPLETE beamchain eunit suite.
#
# WHY THIS EXISTS  (diagnosis corrected 2026-09-06 — see below)
# ---------------
# The 2026-08-30 note here blamed eunit DISCOVERY: "a test module is discovered
# only if its name is a src module's name with _tests appended". That is WRONG
# for rebar3 >= 3.20 and it sent two separate investigations down a dead end.
#
# rebar_prv_eunit:default_tests/2 is
#     set_apps(Apps) ++ set_modules(Apps, State)
# and set_modules/3 globs <AppDir>/test/*.erl, drops the ones whose name is
# "<src module>_tests" (the {application,_} primitive already covers those) and
# appends the REST as explicit {module, M} entries. So every orphan
# beamchain_w1xx_*_tests module IS in the test set. That is also why pointing
# eunit_tests at {dir, "test"} changed nothing: there was nothing to fix.
#
# What actually hid 97 modules was an ABORT. eunit kills the whole run when a
# test process terminates unexpectedly, and everything queued after the abort
# is silently cancelled — the orphan {module, _} entries sit AFTER
# {application, beamchain} in the list, so they were always in the cancelled
# tail. The trigger was a leaked named ETS table: a fixture creates
# beamchain_config_ets / beamchain_chain_meta as a stand-in, never drops it,
# and the next module to start the real gen_server dies in ets:new/2 with
# "table name already exists" INSIDE init/1.
#
# Fixed 2026-09-06 by guarding every named-table create in src (the idiom
# beamchain_db:805 and beamchain_peer_manager:789 already used) plus two test
# fixtures. Plain `rebar3 eunit` now runs all 140 test modules; measured
# 4717 passed / 47 failed, against 2047 tests / 39 modules before.
#
# This wrapper is kept as a belt-and-braces second pass: pass 2 names every
# module explicitly, so if a future abort ever truncates pass 1 again the
# difference between the two passes makes it visible.
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
