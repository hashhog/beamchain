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

echo "== pass 1: application-level (src -ifdef(TEST) tests + the 38 name-matched modules)"
rebar3 eunit; APP_RC=$?

MODS=$(ls test/*_tests.erl 2>/dev/null | xargs -n1 basename | sed 's/\.erl$//' | paste -sd,)
COUNT=$(echo "$MODS" | tr ',' '\n' | grep -c .)
echo
echo "== pass 2: every test/*_tests.erl module explicitly ($COUNT modules)"
rebar3 eunit --module="$MODS"; MOD_RC=$?

echo
if [ "$APP_RC" -eq 0 ] && [ "$MOD_RC" -eq 0 ]; then
  echo "ALL GREEN (both passes)"; exit 0
fi
echo "FAILURES PRESENT — application pass rc=$APP_RC, module pass rc=$MOD_RC"
exit 1
