# verify-fix report

- Run: `20261126T120132Z`
- Impl: `beamchain`
- Corpus entry: `bare-pushdata2-cutlen-unexec` (corpus: `f1`)
- Phase: `accept-only`
- Delivery: `submitblock`
- Base port: `24740`
- Pre-sha:  `7bfdb89` (resolved `7bfdb893b70b0a9a0417d1af7717572778dc6d39`)
- Post-sha: `f0ed3a67aa77be870694cfcdc55746e24d3aaf4a` (resolved `f0ed3a67aa77be870694cfcdc55746e24d3aaf4a`)

## Verdict

**EFFECTIVE**

Pre-fix and post-fix decisions differ on the corpus entry, confirming
that the patch actually executes on the live block-acceptance path.

## Decisions

| pass | sha | decision | diagnostic |
|------|-----|----------|------------|
| pre  | `7bfdb89`  | `accept`  | — |
| post | `f0ed3a67aa77be870694cfcdc55746e24d3aaf4a` | `reject:block-script-verify-flag-failed` | — |

## Suggested commit footer

```
Verified: pre=accept, post=reject:block-script-verify-flag-failed (EFFECTIVE, verify-fix.sh, 2026-11-26T12:02Z)
```
