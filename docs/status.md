# Status: how to check it yourself

Each row of the README status table, and how to reproduce it from this repository.

## Test suite

```bash
rebar3 eunit
```

This builds the `test` profile and runs every EUnit module: the tests inside `src/`
modules and every `test/*_tests.erl`. It takes about five minutes on a 16-core
machine. Core's script and sighash vectors are checked in under `test/data/`, so no
Bitcoin Core checkout is needed.

Result on `master` at the date in the README:

```
  Failed: 10.  Skipped: 0.  Passed: 5257.
```

rebar3's reporter stops while printing the third failure and never prints the totals
(it ends with `===> Error running tests`). The line above comes from running the same
test set through EUnit's plain reporter:

```bash
rebar3 eunit   # once, to build the test profile
erl -noshell -pa _build/test/lib/*/ebin -pa _build/test/lib/beamchain/test -eval '
  {ok, Fs} = file:list_dir("_build/test/lib/beamchain/test"),
  Src = [filename:basename(F, ".erl") || F <- filelib:wildcard("src/*.erl")],
  Mods = [list_to_atom(filename:basename(F, ".beam")) || F <- Fs,
          filename:extension(F) =:= ".beam",
          not lists:member(filename:basename(F, "_tests.beam"), Src)],
  eunit:test([{application, beamchain} | [{module, M} || M <- lists:sort(Mods)]], []),
  halt().'
```
 The failures are listed under [Known limitations](#known-limitations).

To run one module:

```bash
rebar3 eunit --module=script_vectors_tests
rebar3 eunit --module=sighash_vectors_tests
```

Expected output includes:

```
Non-witness tests: 1109
  PASS:  1109
...
Witness tests: 113
  PASS:  113
...
Sighash vectors: 500 passed, 0 failed out of 500
```

## Regtest comparison with Core v31.1

`test/bc3_core_regtest.sh` starts Bitcoin Core v31.1 and beamchain on regtest with no
peers, mines and spends on Core, submits every block to beamchain, and then compares
`getblockcount`, `getbestblockhash`, `gettxoutsetinfo` and `scantxoutset` results field
by field. It also checks that a `scantxoutset` running while a new block connects
returns a consistent snapshot. It needs the official v31.1 binaries
(<https://bitcoincore.org/bin/bitcoin-core-31.1/>) and a built escript:

```bash
BITCOIN_DIR=/path/to/bitcoin-31.1 BC3_WORK="$(mktemp -d)" bash test/bc3_core_regtest.sh
```

It uses ports 18443 (Core RPC), 18445 and 18446 (beamchain). Expected last lines:

```
=== SUMMARY ===
  matched_fields=141
  justified=0
  unsupported=0
  unjustified=0
OK
```

## UTXO-set hash at height 958,794

The UTXO set at a given height has exactly one correct `hash_serialized_3`. At mainnet
height 958,794 (block
`000000000000000000015eaadd989e4f09ff75b643a128dc7bdf6070431d7d0e`) Bitcoin Core
reports:

```
hash_serialized_3  29692050559b8f064a03af9cd605040e71d1d978fa22947c079cc7e5546e7af0
txouts             166180925
```

beamchain produced the same value after connecting every block from genesis with
script checks on for every block. To reproduce it you need about 1 TB of SSD, 16 GB of
RAM and several days. beamchain has no option to stop at a height, so hold it there by
giving it a single peer that is itself stopped at 958,794: a Bitcoin Core node synced
with `-stopatheight=958794`, then restarted with `-connect=0` so it stays at that
height and only serves blocks. `-stopatheight` may connect a block or two past the
target while shutting down; if Core's `getblockcount` is above 958,794, run
`invalidateblock` on block 958,795 there first.

```bash
./_build/default/bin/beamchain start --network=mainnet --datadir=/path/to/datadir \
  --noassumevalid --connect=<core-ip>:8333
# when getblockcount returns 958794:
curl -s --user "$(cat /path/to/datadir/.cookie)" \
  -d '{"method":"gettxoutsetinfo","params":["hash_serialized_3"]}' http://127.0.0.1:8332/
```

On mainnet the `gettxoutsetinfo` call reads the whole UTXO set and takes about 35
minutes. The same call works on regtest in a second:

```bash
curl -s --user "$(cat "$DATADIR/regtest/.cookie")" \
  -d '{"method":"gettxoutsetinfo","params":["hash_serialized_3"]}' http://127.0.0.1:18443/
```

`proof/` holds the records of the run the maintainers did: the captured result
(`proof/r4/C958794.json`), the node's log of that sync from genesis
(`proof/r4/lineage.log.gz`) and the launch command. `bash proof/verify.sh` checks that
those files are consistent with each other and with `proof/claims.json`, that the log
starts at genesis with assumevalid off and never loads a snapshot, and re-runs one
EUnit module. It does not re-sync the chain. Expected last lines:

```
R5 in-repo: beamchain_t1_rpc_parity_tests PASS
MANIFEST.sha256: OK
== PASS: every claim cites a file in this bundle and the numbers match ==
```

## Known limitations

- There is no Docker setup that builds from source. The `Dockerfile` copies a release
  that has already been built into `_build/prod/rel/beamchain`, and
  `config/sys.config` (which that release reads) names a data directory and ports for
  a particular machine.
- `beamchain status`, `stop` and `getbalance` read the cookie from `--datadir` without
  adding the network subdirectory. Pass `--datadir=<datadir>/<network>` for anything
  other than mainnet.
- `config.example.toml` is not in the format the node reads. The real format is
  `key=value` lines in `beamchain.conf` (see [running.md](running.md#config-file)), and
  the network and data directory cannot be set from that file.
- On regtest the wallet directory is nested one level deeper than on other networks
  (`<datadir>/regtest/regtest/wallet`).
- The Prometheus port (9332) can only be changed through `ERL_FLAGS`
  (see [running.md](running.md#networks-and-ports)).
- The RPC, REST and metrics listeners bind every interface.
- 30 methods in Core v31.1's `help` are not implemented, mostly label, rescan and
  send-many wallet calls; see [rpc.md](rpc.md#in-core-v311-but-not-in-beamchain).
- PayJoin (BIP-78) lacks output substitution and the anti-fingerprinting rules.
- Ten unit tests fail on `master`:
  - `beamchain_gate6_tests`: `mempool_survives_busy_chainstate`,
    `mempool_busy_chainstate_unknown_mtp`, `mempool_refuses_after_abort`,
    `mempool_control_accept`, `mempool_control_bad_sig`
  - `beamchain_invalidate_sticky_tests`: `header_layer`, `no_whole_index_walk`
  - `beamchain_mempool_bip68_tests`: `disabled_lock_on_mempool_parent`
  - `beamchain_w118_wallet_tests`: `g27_listunspent_exists_test_`
  - `beamchain_w126_bip152_tests`: `g13_no_map_block_source_test`
