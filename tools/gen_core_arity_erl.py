#!/usr/bin/env python3
"""Regenerate src/beamchain_core_arity.erl from the meta-repo's arity table.

Usage (from the beamchain submodule root):

    python3 tools/gen_core_arity_erl.py > src/beamchain_core_arity.erl

The input, ../tools/core-arity.json, is itself derived from Bitcoin Core's own
`help` output by the meta-repo's tools/core-arity.py. Committing the generated
module keeps the table compiled in, so nothing is read from disk at startup.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "..", "tools", "core-arity.json")


def main() -> int:
    with open(SRC) as fh:
        table = json.load(fh)

    rows = ",\n".join(
        '      <<"%s">> => {%d, %d}' % (n, int(table[n]["required"]), int(table[n]["declared"]))
        for n in sorted(table)
    )
    sys.stdout.write(HEADER % (len(table), rows, len(table)))
    return 0


HEADER = '''%%%% @doc Core's central RPC argument-count table (#103).
%%%%
%%%% GENERATED FILE -- do not edit by hand. Regenerate with:
%%%%
%%%%   python3 tools/gen_core_arity_erl.py > src/beamchain_core_arity.erl
%%%%
%%%% Maps a method name to {Required, Declared}, derived from Bitcoin Core's own
%%%% `help' signature line by tools/core-arity.py (%d methods). Core enforces
%%%% Required =< N =< Declared centrally, before any handler runs
%%%% (rpc/util.cpp:644 -> IsValidNumArgs, :733), and answers -1 otherwise.
%%%%
%%%% The table is COMPILED IN rather than read from priv/ at startup. beamchain
%%%% ships as an escript whose resources live inside the archive, and this
%%%% repo's deploy step moves binaries around: camlcoin shipped exactly this
%%%% check on 2026-08-31 reading its table from a relative path, and it silently
%%%% did nothing in production while every test passed.
-module(beamchain_core_arity).
-export([table/0, lookup/1]).

-spec table() -> #{binary() => {non_neg_integer(), non_neg_integer()}}.
table() ->
    #{
%s
    }.

%%%% Returns `error' when the method is absent -- callers MUST fail OPEN.
%%%% Coverage is %d of 103 Core methods; treating an unlisted method as
%%%% zero-arg would reject calls Core accepts.
-spec lookup(binary()) -> {ok, {non_neg_integer(), non_neg_integer()}} | error.
lookup(Method) when is_binary(Method) ->
    maps:find(Method, table());
lookup(_) ->
    error.
'''

if __name__ == "__main__":
    raise SystemExit(main())
