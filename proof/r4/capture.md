# T2 capture — beamchain — MATCH

**beamchain reproduces C(958794).**

| field | value |
|---|---|
| captured (UTC) | 2026-08-25T04:29:27Z (watcher MATCH; ledger row 2026-08-25T03:49:53Z) |
| height | 958794 |
| bestblockhash | `000000000000000000015eaadd989e4f09ff75b643a128dc7bdf6070431d7d0e` |
| hash_serialized_3 | `29692050559b8f064a03af9cd605040e71d1d978fa22947c079cc7e5546e7af0` |
| coins | 166,180,925 |

Lineage: from-genesis, `--noassumevalid`, fed by the capped
blk-replay-server (`--max-serve-height 958794`) so the node
FROZE on the anchor. No rollback was performed at any point.

Captured automatically by `tools/lineage-capture-watch.sh`:

```
2026-08-25T00:29:27-04:00 beamchain: *** MATCH *** 29692050559b8f064a03af9cd605040e71d1d978fa22947c079cc7e5546e7af0
2026-08-25T00:29:27-04:00 ALERT: hashhog: beamchain REPRODUCES C(958794)
```

The tip was pinned at 958794 / `…15eaadd989e4f09ff75b643a128dc7bdf6070431d7d0e`
before the scan and re-checked after. The scan itself took 35m36s after
Cowboy's `inactivity_timeout` (third HTTP timer) was raised; two earlier
300s ceilings had been hiding the cost, not a wrong hash.

## What this does not claim

This records a reproduction of C(958794), nothing more. It does not
certify wallet or fund-custody readiness. Blocks after 958794 have no
from-genesis UTXO-hash capture in this bundle.
