# Security policy

beamchain is an experimental, independent implementation of a Bitcoin full node, for
research and testing. It has not been audited. Do not use it to hold or move real
funds, and do not rely on it alone to decide whether a block or transaction is valid.

## Supported versions

Only the latest commit on `master` is supported. Fixes are not backported.

## Reporting a vulnerability

Do not open a public issue for a problem in consensus, P2P or wallet code: a public
report could be used against people running the node before a fix exists.

Email the maintainer at `max@dockyard.navy`. Include the affected code, a way to
reproduce it (a regtest script, a raw block or transaction, or a malformed P2P
message), and what you think the impact is. You will get a reply, a plan for a fix and
a disclosure date, and credit if you want it.

## In scope

- Consensus divergence: beamchain accepting a block or transaction that Bitcoin Core
  rejects, or rejecting one that Core accepts.
- Crashes, hangs or unbounded memory or disk use that a remote peer or an RPC caller
  can trigger, including faults in the C NIFs (a NIF fault stops the whole node).
- Chain state left corrupt after a crash or power loss.
- Wallet faults: signing with the wrong key, building a transaction the network
  rejects, losing keys, or a wrong fee.

## Out of scope

- Sync speed and resource use that are not caused by a peer or caller.
- Attacks that need control of the host or of the RPC credentials.
