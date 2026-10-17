# Contributing to beamchain

## Build and test

See [docs/building.md](docs/building.md) for the toolchain. Then:

```bash
rebar3 escriptize   # builds _build/default/bin/beamchain
rebar3 eunit        # the whole test suite
rebar3 xref         # static cross-reference check
```

[docs/status.md](docs/status.md#test-suite) lists the tests that currently fail on
`master`. A pull request must not add to that list.

Optional: `git config --local core.hooksPath scripts/hooks` installs a pre-push hook
that runs `rebar3 xref` and the release cold-boot test before every push.

## Pull requests

- Branch from `master` and open the pull request against `master`.
- Every change in behaviour comes with a test that fails before the change and passes
  after it. If an existing test asserts the old behaviour, change that test in the same
  pull request and say why.
- Keep a pull request to one change. Do not disable or delete tests without giving the
  reason in the description.
- Commit messages follow Conventional Commits (`fix:`, `feat:`, `test:`, `perf:`,
  `refactor:`, `docs:`, `chore:`, optionally with a scope such as `fix(rpc):`). The
  subject says what changed; the body says why.

## Consensus changes

Bitcoin Core is the specification. A change to block or transaction validation,
script, the UTXO set, reorgs or chain selection must show that beamchain now behaves
the way Core does: cite the Core code (`src/validation.cpp`, `src/script/interpreter.cpp`
and so on) and add a test that reproduces Core's result, ideally a Core test vector or a
case run against Core on regtest (see `test/bc3_core_regtest.sh`). Say in the
description what could make a valid block invalid, or an invalid block valid, with the
change.
