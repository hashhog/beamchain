# Changelog

## v1.0.1 (unreleased)

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

