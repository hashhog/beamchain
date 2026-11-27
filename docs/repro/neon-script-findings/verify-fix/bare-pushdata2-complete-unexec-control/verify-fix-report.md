# verify-fix report

- Run: `20261126T120458Z`
- Impl: `beamchain`
- Corpus entry: `bare-pushdata2-complete-unexec-control` (corpus: `f1`)
- Phase: `accept-only`
- Delivery: `submitblock`
- Base port: `24740`
- Pre-sha:  `7bfdb89` (resolved `7bfdb893b70b0a9a0417d1af7717572778dc6d39`)
- Post-sha: `f0ed3a67aa77be870694cfcdc55746e24d3aaf4a` (resolved `f0ed3a67aa77be870694cfcdc55746e24d3aaf4a`)

## Verdict

**NO-OP**

Both pre-fix and post-fix reject the candidate block. The fix may be
redundant (some other check is already rejecting) OR the fix landed in
dead code AND the corpus entry isn't sensitive to the patched logic.
Recommend: pick a corpus entry that exercises the specific code path
the fix is supposed to gate, OR verify by inspection that the fix is
reached during ConnectBlock (or equivalent) on a live block.

## Decisions

| pass | sha | decision | diagnostic |
|------|-----|----------|------------|
| pre  | `7bfdb89`  | `accept`  | — |
| post | `f0ed3a67aa77be870694cfcdc55746e24d3aaf4a` | `accept` | — |

## Suggested commit footer

```
Verified: pre=accept, post=accept (NO-OP, verify-fix.sh, 2026-11-26T12:05Z)
```
