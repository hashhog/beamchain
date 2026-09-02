# Changelog

## v1.0.0 (unreleased)

Changes since `v0.1.0-rc1`:

- 5c8a745 docs: LICENSE copyright holder
- be6aad9 docs: LICENSE, SECURITY.md, toolchain versions (release hygiene)
- 44af71d fix(rpc): validate argument COUNT centrally, as Core does (#103)
- 06851d5 test: wallet tests get a private datadir — one leak caused all 5 #89 failures
- 7d72bd9 test: run-all-eunit.sh — `rebar3 eunit` silently skips 101 of 139 test modules
- 1283fba fix(sync): frontier-request lifecycle — stop the 287-block IBD soft-deadlock cycle (#34)
- 1d91053 fix(rpc): the integer conversion runs before the lookup, and disconnectnode honours nodeid
- 5780b82 fix(rpc): read integer arguments at Core's width, and honour the ones we read
- 42a5498 feat(rpc): implement createrawtransaction's `version` argument
- 958de9a fix(rpc): submitblock separates DECODE failure from validation failure (R2 token parity)
- af3b9c7 fix(rpc): createrawtransaction rejects replaceable=true contradicted by its sequences
- 773c054 fix(rpc): createrawtransaction range-checks vout/sequence/locktime instead of truncating them
- 8622118 fix(rpc): getblockheader nTx computed from the LOCAL block store — Core proxy removed (#44, R3 self-sufficiency)
- 790eaa9 fix+test: eunit triage — 14 stale fixtures updated, get_fee_delta missing-table guard; suite 2034/0
- 8cfc3d3 fix(chainstate): add_utxo_fresh refuses FRESH for DB-resident keys (audit unconditional-FRESH row)
- a6002ff fix(p2p): pre-ready send casts are postponed, not eaten; request-send failures log at warning (#74)
- a982f50 fix(p2p): chain_start locator gets the real LocatorEntries walk; holey-index walk keeps its genesis anchor
- 72a4b18 fix(consensus): select chains by WORK alone, never by length (#45)

