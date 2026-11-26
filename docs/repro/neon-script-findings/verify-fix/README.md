# verify-fix corpus for Neon finding 1 (cut-off PUSHDATA length in an unexecuted branch)

Three diff-test corpus entries on hashhog's `tools/diff-test-corpus/regression/_base`
(110 regtest blocks). In each, block 111 holds T1, which pays the
`disabled-opcode` mutation's output to a bare scriptPubKey, and T2, which
spends it.

| entry | T1 scriptPubKey | Core v31.1 |
|---|---|---|
| `bare-pushdata2-cutlen-unexec` | `5100634d68` (1 0 IF PUSHDATA2 + one length byte) | reject (BAD_OPCODE) |
| `bare-pushdata4-cutlen-unexec` | `5100634e68` (1 0 IF PUSHDATA4 + one length byte) | reject (BAD_OPCODE) |
| `bare-pushdata2-complete-unexec-control` | `5100634d0100aa68` (complete PUSHDATA2) | accept |

## How the blocks were made
They come from hashhog's `tools/diff-test-corpus/_lib/make_block.py`, with the
one-line change in `make_block.diff`: the `disabled-opcode` mutation takes T1's
scriptPubKey from `$BARE_SPK_HEX` instead of the fixed `7e`. For each entry:

    BARE_SPK_HEX=<spk> python3 make_block.py --base-dir=<regression/_base> \
        --base-blocks=110 --mutation=disabled-opcode --funded-coinbase-block=1 \
        --output=<entry>/block.hex

## How verify-fix ran
`tools/verify-fix.sh --corpus-entry=<entry> --impl=beamchain --pre-sha=7bfdb89
--post-sha=f0ed3a6 --corpus=<this directory>` (2026-11-26). It ran from a
hashhog worktree whose `beamchain/` is its own detached worktree, so no shared
checkout was touched and nothing was stashed. verify-fix builds
`_build/default/rel`, but diff-test launches `_build/prod/rel`, so that worktree
had `_build/prod` as a symlink to `default`. The `regression/_base` directory
must be linked here as `_base`.

| entry | pre 7bfdb89 (master) | post f0ed3a6 (fix) | verdict |
|---|---|---|---|
| `bare-pushdata2-cutlen-unexec` | accept | reject:block-script-verify-flag-failed | EFFECTIVE |
| `bare-pushdata4-cutlen-unexec` | accept | reject:block-script-verify-flag-failed | EFFECTIVE |
| `bare-pushdata2-complete-unexec-control` | accept | accept | NO-OP (control) |

Each entry's `verify-fix-report.md` is the report verify-fix wrote. Core v31.1's
verdicts come from `../repro.py` (outputs `../output-*.txt`), which submits the
same scripts to a pinned bitcoind 31.1.
