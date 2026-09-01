# Security Policy — beamchain

beamchain is a from-scratch Bitcoin full-node implementation in Erlang/OTP, part of
the [hashhog](https://github.com/hashhog) fleet of ten independent nodes that
cross-validate each other and Bitcoin Core. Security is the entire purpose.

## Project maturity — read this first

beamchain is a **pre-release validator**: a node you can build, run *beside*
Bitcoin Core in watchtower mode, and compare against it. It tracks the Core tip on
mainnet under the fleet's differential guard, but a trustless `--assumevalid=0`
genesis-to-tip validation has **not** yet completed for this node (the genesis rig is
mid-flight). Treat every consensus claim in the README as evidenced only to the
extent the fleet receipts (`../receipts/`, `../CORE-PARITY-AUDIT/`) say so.

**It is NOT fund-capable.** Do not custody funds on it. The intended trust model for
this release is: run it alongside Core with `consensus-diff` as a live divergence
alarm.

There are no fund-grade guarantees. Run from a pinned commit.

Release-signing key fingerprint: to be published with v1.0.0.

## Supported versions

| Version | Supported |
|---------|-----------|
| `v0.1.0-rc1` (pinned `893c9ce`) | Validator RC — best-effort; no security SLA until the final `v0.1.0` |
| pre-release (`master`) | Best-effort |

## Reporting a vulnerability

**Please do NOT open a public GitHub issue** for anything in the consensus, P2P, or
wallet paths — a public report could put real Bitcoin nodes or funds at risk.

Report privately to the maintainer:

- **Email:** `max@dockyard.navy`  <!-- TODO(max): confirm or replace with a dedicated security alias -->

Include the affected path, a deterministic reproduction (a diff-test corpus entry,
regtest script, or malformed message), impact, and any suggested fix. We coordinate
a fix + disclosure timeline and credit you if you wish.

## In scope (highest priority)

- **Consensus divergence** — beamchain accepting a block/tx Core rejects, or vice-versa.
  This is the core concern (see `../CORE-PARITY-AUDIT/`).
- **Remotely-triggerable crashes / OOM / resource exhaustion** in the P2P or block/tx
  decode paths, including NIF crashes (the crypto and RocksDB NIFs run inside the VM;
  a NIF fault takes the whole node down).
- **Wallet funds-safety** — silent wrong-key signing, a spend the node reports valid
  that the network rejects, un-recoverable backups, fee miscalculation stranding funds.
- **Chainstate corruption on crash** (roll-forward recovery is in place; regressions
  are in scope).

## Custody caveats (not consensus, but real)

- The wallet is pre-release and has not been through a funds-safety audit. Do not
  fund it beyond an eyes-open canary.

These gate fund-capability, not the watchtower-validator tag.

## Out of scope

- IBD/sync performance characteristics.
- Issues requiring an already-compromised host.

## Disclosure

Coordinated disclosure. Consensus fixes are verified with `../tools/verify-fix.sh` and
gated through the differential corpus before they are considered landed; a live
watchtower (`../tools/watchtower.sh`) alarms on any beamchain-vs-Core divergence.
