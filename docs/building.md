# Building beamchain

## Toolchain

| Tool | Version | Notes |
|---|---|---|
| Erlang/OTP | 27 | Tested with 27.3. Nothing pins the version; older releases are untested. |
| rebar3 | 3.24 | |
| C and C++ compiler, make, CMake, git | any recent | For the crypto NIF, libsecp256k1 and RocksDB. |
| Snappy, LZ4, Zstandard headers | | RocksDB compression. |

On Debian 13 (trixie) the distribution packages have these versions:

```bash
sudo apt-get install -y erlang rebar3 build-essential cmake git libsnappy-dev liblz4-dev libzstd-dev
erl -noshell -eval 'io:format("~s~n", [erlang:system_info(otp_release)]), halt().'
rebar3 version
```

On other systems install OTP 27 and rebar3 with your package manager or a version
manager such as `asdf` or `kerl`.

## Build

```bash
rebar3 escriptize
./_build/default/bin/beamchain --version
```

The first build needs network access and takes a few minutes:

- `rebar.config` fetches the Erlang dependencies (`jsx`, `cowboy`, `chumak`) from Hex
  and `erlang-rocksdb` (tag `9.10.0-emqx-2`) from GitHub, which builds RocksDB from
  source.
- A pre-compile hook runs `make -C c_src`, which clones libsecp256k1 `v0.5.1` into
  `c_src/secp256k1/`, builds it, and links the NIF into `priv/beamchain_crypto_nif.so`.
  The NIF is built with `-msha -msse4.1`, so it needs an x86-64 CPU with those
  extensions.

`_build/default/bin/beamchain` is an escript: a zip of the compiled modules with a
`#!` line. RocksDB's NIF cannot be loaded from inside the zip, so the escript loads it
from `_build/default/lib/rocksdb`. Run the escript from the tree it was built in; do
not copy it elsewhere on its own.

`./beamchain` at the repository root is a small wrapper that runs the same CLI from the
compiled `.beam` files in `_build/default/lib/` (after `rebar3 compile`), without
Erlang's progress reports.

## Other build targets

| Command | Result |
|---|---|
| `rebar3 compile` | Compile only (also builds the NIF). |
| `rebar3 eunit` | Build with the `test` profile (adds `meck`) and run the tests. |
| `rebar3 as prod release` | An OTP release with ERTS included, in `_build/prod/rel/beamchain/`. It reads `config/sys.config` and `config/vm.args`; edit `sys.config` before using it, because the committed file names a network, data directory and ports for a particular machine. |
| `rebar3 xref` | Cross-reference check configured in `rebar.config` (undefined calls, unused locals). |

## Reproducible escript

A post-escriptize hook (`scripts/normalize_escript.escript`) strips the per-build
timestamps from the zip, so rebuilding the same tree with the same toolchain gives the
same bytes. `scripts/reproducible-escript.sh` checks that: it recompiles and rebuilds
the escript three times and fails unless all three SHA-256 sums match.

```bash
bash scripts/reproducible-escript.sh
```

It does not show that different OTP or rebar3 versions produce the same file.
