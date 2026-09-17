# Changelog

## v1.0.2 — 2026-09-17

- 41c97aa fix: reject wrong walletpassphrase instead of unlocking
- d07827e test: load passthrough meck targets before meck:new
- 0dc210c test: align eunit suite with Core CompactSize MAX_SIZE and current APIs
- 67758f4 fix: snapshot graft uses trusted assumeutxo chainwork
- 782cc46 fix: pin escript zip extras so three builds share one sha
- 65d5f41 fix: stream assumeutxo snapshot load and HASH_SERIALIZED
- 061fd04 fix: T1 RPC parity for GBT, testmempoolaccept, addnode, getnetworkhashps


## v1.0.2 — 2026-09-17

Changes since `v1.0.0`:

- fix: snapshot graft uses trusted assumeutxo chainwork (G9 no longer treats 0 as a bypass)
- fix: pin escript zip extras so three `rebar3 escriptize` builds share one sha
- fix: stream assumeutxo snapshot load and HASH_SERIALIZED (8G HIT_CAP)
- fix: T1 RPC parity — GBT requires rules=["segwit"], testmempoolaccept decode is -22, addnode invalid-command is -1, getnetworkhashps is a float honoring height
- 2695352 docs: say the cited paths are private before the claims that rest on them
- 0252cda fix: an ETS leak was cancelling 101 of 140 test modules, not test discovery
- 0441ac3 fix: graft the snapshot base into the block index, and thread min_pow_checked
- 93129e8 fix: import-utxo must not start the node's listeners
- 4c418b5 feat: HASHHOG_UNSAFE_SNAPSHOT_HEIGHT — accept an un-anchored UTXO snapshot

