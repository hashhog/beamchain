# W140 — HTTP server + rpcauth + cookie auth + JSON-RPC dispatch (beamchain)

**Status**: DISCOVERY — 30 gates classified / 22 P0/P1/P2 bugs found / 0 prod
changes (audit-only wave).

**Tests**: `test/beamchain_w140_http_rpcauth_tests.erl` — 30 EUnit tests.
Each MISSING / PARTIAL gate lands as a marker test asserting the *current*
divergent behavior, so a future FIX wave that closes the gap flips the test
PASS → FAIL and forces the audit doc to update.  Audit-flip convention.

**Reference**:
- `bitcoin-core/src/httpserver.{cpp,h}` — libevent-backed HTTP server,
  `InitHTTPServer` / `InitHTTPAllowList` / `HTTPBindAddresses` /
  `ClientAllowed` / `http_request_cb` / `HTTPRequest::WriteReply` /
  thread-pool work-queue / max headers + body limits.
- `bitcoin-core/src/httprpc.cpp` — `StartHTTPRPC` / `HTTPReq_JSONRPC` /
  `RPCAuthorized` / `CheckUserAuthorized` / `InitRPCAuthentication` /
  rpcauth whitelist + 250ms anti-brute-force sleep.
- `bitcoin-core/src/rpc/server.cpp` — `tableRPC` / `JSONRPCExec` /
  `transformNamedArguments` / `RPCIsInWarmup` / `getrpcinfo` /
  `DeleteAuthCookie`.
- `bitcoin-core/src/rpc/server_util.cpp` — `EnsureAnyNodeContext`,
  `EnsureMemPool`, `EnsureChainman` etc — error mapping to RPC codes.
- `bitcoin-core/src/rpc/request.cpp` — `GenerateAuthCookie` /
  `GetAuthCookieFile` / `DeleteAuthCookie` / `COOKIEAUTH_USER` /
  `g_generated_cookie` / `-rpccookieperms`.
- `bitcoin-core/share/rpcauth/rpcauth.py` — salted HMAC-SHA-256 generator
  (`{user}:{salt}${hmac_hex}`).
- `bitcoin-core/src/init.cpp` lines 710-711 — `-rpccookiefile`,
  `-rpccookieperms` argument plumbing.

**Beamchain refs**:
- `src/beamchain_rpc.erl` (≈9500 LOC) — Cowboy listener + cookie/rpcuser
  auth + JSON-RPC dispatch + rate limiter.  Lines 163–306, 358–605.
- `src/beamchain_app.erl` — signal handling + supervision-tree start.
- `src/beamchain_listener.erl` — shared cowboy start_clear/start_tls
  with exponential-backoff retry.
- `src/beamchain_metrics.erl` — Prometheus `/metrics` endpoint
  (separate cowboy listener on 9332, no auth, same bind issue).
- `src/beamchain_rest.erl` — REST endpoint (separate listener,
  unauthenticated, bound on all interfaces).
- `config/vm.args` — escripted release VM args (W124 BUG-1 source).

## Context

W124 found BUG-1 P0 `-setcookie beamchain` in vm.args, exposing local
RCE inside the BEAM to anyone on the host who can read the published
literal.  W140 broadens the lens to the entire HTTP RPC surface and
turns up the larger story: **the JSON-RPC RPC port is bound on
`0.0.0.0` with NO IP allow-list**, so the cookie/password is the *only*
gate between an attacker on the network and `dumpprivkey` /
`sendtoaddress` / `signrawtransactionwithwallet`.  Bitcoin Core's
defense-in-depth model uses **two** gates: (a) `-rpcallowip` subnet
ACL applied at HTTP-accept time *before* parsing the request, and
(b) Basic-auth credential check on every request.  beamchain has only
(b).  This is the W140 top-line finding (BUG-1, P0-SEC).

## Top-line counts

| Status   | Count | Gates |
|----------|------:|-------|
| PASS     |  6    | G01 G02 G09 G11 G15 G19 |
| PARTIAL  |  8    | G03 G05 G07 G10 G12 G17 G23 G27 |
| MISSING  | 16    | G04 G06 G08 G13 G14 G16 G18 G20 G21 G22 G24 G25 G26 G28 G29 G30 |

(Eight PARTIAL because the current behavior is *functionally* correct
but the Core parity surface — flags, headers, error semantics — is
incomplete.)

## Bug summary (22 bugs)

| ID    | Pri    | Gate | Summary                                                                          |
|-------|--------|------|----------------------------------------------------------------------------------|
| BUG-1 | P0-SEC | G04  | RPC listener binds `0.0.0.0` with NO `-rpcallowip` ACL — wire-side bypass        |
| BUG-2 | P0-SEC | G16  | rpcuser/rpcpassword stored & compared **plaintext**; no rpcauth salt/HMAC        |
| BUG-3 | P0-SEC | G18  | Credential check uses pattern-match: **timing-leaky** (no constant-time)         |
| BUG-4 | P0-SEC | G06  | Prometheus `/metrics` listener also bound `0.0.0.0`, no auth, no ACL             |
| BUG-5 | P1     | G14  | `-rpcbind` / `-rpcallowip` flags absent — operator cannot constrain bind         |
| BUG-6 | P1     | G20  | No 250ms anti-brute-force sleep on bad auth (Core httprpc.cpp:128)               |
| BUG-7 | P1     | G22  | No `-rpcauth` (salted HMAC) wire format — operators forced into plaintext path   |
| BUG-8 | P1     | G24  | No `-rpcwhitelist` / `-rpcwhitelistdefault` per-method ACL                       |
| BUG-9 | P1     | G13  | Cookie file content omits trailing newline; Core writes `__cookie__:<hex>` + LF  |
| BUG-10| P1     | G08  | No `-rpccookieperms` (group/all-readable cookie option) — locked at 0600         |
| BUG-11| P1     | G10  | Cookie deleted on shutdown **unconditionally** — nukes externally-managed file   |
| BUG-12| P1     | G25  | No `-rpcservertimeout` / `-rpcworkqueue` / `-rpcthreads` parity                  |
| BUG-13| P1     | G26  | `-norpccookiefile` (disable cookie) flag absent                                  |
| BUG-14| P1     | G21  | HTTP status mapping wrong: parse-error → 200 (Core: 400) etc                     |
| BUG-15| P1     | G28  | 401-Unauthorized body is JSON error object (Core: empty body)                    |
| BUG-16| P1     | G17  | Cowboy `cowboy_req:parse_header` accepts non-`Basic` schemes silently            |
| BUG-17| P2     | G27  | `getrpcinfo` is a stub: returns `active_commands=[]`, `logpath=""`               |
| BUG-18| P2     | G29  | No request-method `HEAD` / `PUT` rejection at the cowboy ACL layer               |
| BUG-19| P2     | G30  | `/health` exposes height/tip hash/IBD unauthenticated — info-leak vs Core        |
| BUG-20| P2     | G12  | No HTTP request work-queue depth limit (cowboy's default per-connection only)    |
| BUG-21| P2     | G23  | Rate limit set to 100,000 req/min ≈ no limit; not Core-spec, false security      |
| BUG-22| P2     | G03  | Warmup gate (`-32 RPC_IN_WARMUP`) plumbed only at `/health`, NOT at JSON-RPC     |

## Gate-by-gate classification

### Section A — Listener / socket / bind (G01–G06)

| Gate | Status | Notes |
|------|--------|-------|
| G01 HTTP listener starts on configured port                | PASS    | `cowboy:start_clear` via `beamchain_listener:start_clear_with_retry`; bounded retry on EADDRINUSE |
| G02 Per-network default RPC port honored                   | PASS    | `rpc_port(Params)` falls back to `Params#network_params.rpc_port` |
| G03 Warmup state surfaced                                  | PARTIAL | `/health` returns 503 `{"status":"warmup"}` but JSON-RPC dispatcher does NOT check warmup (no `?RPC_IN_WARMUP` on `/` POST during chainstate replay) — BUG-22 |
| G04 RPC IP allow-list applied at HTTP accept               | MISSING | **P0-SEC**: cowboy passed only `[{port, Port}, {reuseaddr, true}]` → ranch binds `INADDR_ANY` (all interfaces); no `ClientAllowed` analog; log message even claims `"0.0.0.0:~B"` — BUG-1 |
| G05 `-rpcbind` honored                                     | PARTIAL | No CLI flag — bind is hardcoded to whatever ranch_tcp defaults to (= all interfaces); operator cannot constrain |
| G06 Auxiliary HTTP listeners auth-gated or loopback-only   | MISSING | **P0-SEC**: `beamchain_metrics` and `beamchain_rest` ALSO use `[{port, P}, {reuseaddr, true}]` with zero auth; `/metrics` leaks tip height / peer count / mempool size to the public internet — BUG-4 |

### Section B — Cookie authentication (G07–G14)

| Gate | Status | Notes |
|------|--------|-------|
| G07 Random cookie generated at startup                     | PARTIAL | 32 bytes `crypto:strong_rand_bytes` ✓, but only at `init/1`; no fallback if datadir not writable |
| G08 `-rpccookieperms` (owner/group/all)                    | MISSING | `file:change_mode(CookiePath, 8#0600)` hardcoded; Core: `-rpccookieperms=owner|group|all` |
| G09 Cookie file location is per-network datadir            | PASS    | `filename:join(beamchain_config:datadir(), ".cookie")` — Core mirrors with `AbsPathForConfigVal` |
| G10 Cookie deleted on shutdown only if generated by us     | PARTIAL | `file:delete(CookiePath)` runs in `terminate/2` unconditionally; Core gates on `g_generated_cookie` — would nuke an operator-managed cookie shared with a sibling tool — BUG-11 |
| G11 `__cookie__` username constant                         | PASS    | `verify_credentials(<<"__cookie__">>, Pass)` literal matches Core's `COOKIEAUTH_USER` |
| G12 Cookie HMAC-SHA-256 not just plaintext                 | PARTIAL | Cookie path is a 64-hex-char random string used in **plaintext basic-auth**; for **cookie** auth this is Core-compatible (Core also bears the random string in plaintext in `.cookie`), but the docstring is misleading — there is no HMAC anywhere — see also G16 / BUG-2 |
| G13 Cookie file content `__cookie__:<hex>` plus newline    | MISSING | Beamchain writes `<<"__cookie__:", Cookie/binary>>` with NO trailing `\n`; bitcoin-cli's `std::getline` works either way but the format diverges from Core — BUG-9 |
| G14 `-rpccookiefile` (custom path) honored                 | MISSING | No CLI flag; Core: `gArgs.GetPathArg("-rpccookiefile", ".cookie")` — BUG-5 covers this jointly with `-rpcbind` |

### Section C — rpcuser/rpcpassword + rpcauth (G15–G20)

| Gate | Status | Notes |
|------|--------|-------|
| G15 `rpcuser` / `rpcpassword` plumbed from config          | PASS    | `setup_auth/0` reads `beamchain_config:get(rpcuser|rpcpassword)` |
| G16 Plaintext password stored hashed (`-rpcauth`)          | MISSING | **P0-SEC**: stored in ETS as `{rpc_credentials, U, P}` then compared via pattern match; Core hashes plaintext at startup with random 16-byte salt + HMAC-SHA-256, stores `{user, salt, hash}` — BUG-2 |
| G17 Authorization header parsed strictly                   | PARTIAL | `cowboy_req:parse_header(<<"authorization">>, Req)` returns `{basic,U,P}` only for `Basic ...` headers, else falls through to `{error, missing_auth}` — but no audit log on bad scheme; bearer/digest get the same 401 silently — BUG-16 |
| G18 Credential check uses constant-time compare            | MISSING | **P0-SEC**: `verify_credentials(User, Pass)` uses Erlang pattern match on ETS tuple — early-exits on first byte mismatch, leaking timing; Core: `TimingResistantEqual` on both username and HMAC — BUG-3 |
| G19 Cookie verified independently of rpcuser path          | PASS    | Distinct clause `verify_credentials(<<"__cookie__">>, Pass)` checks the cookie ETS slot; cookie auth still works when rpcuser/rpcpassword unset |
| G20 250ms anti-brute-force sleep on bad creds              | MISSING | Core `httprpc.cpp:128`: `UninterruptibleSleep(std::chrono::milliseconds{250})`; beamchain returns 401 immediately — adversary can grind ~10k attempts/s/connection — BUG-6 |

### Section D — JSON-RPC dispatch (G21–G27)

| Gate | Status | Notes |
|------|--------|-------|
| G21 HTTP status mirrors RPC code                           | MISSING | Core `JSONErrorReply`: PARSE_ERROR → 400, METHOD_NOT_FOUND → 404, else 500; beamchain always returns 200 on JSON-RPC errors (single-object) → API-gateway tooling can't tell parse from success — BUG-14 |
| G22 `-rpcauth` `user:salt$hmac` syntax                     | MISSING | Not parsed anywhere; only the legacy `rpcuser`/`rpcpassword` path exists — BUG-7 |
| G23 Rate limit at HTTP layer                               | PARTIAL | Per-IP counter ETS table, 100,000 req/min — at that ceiling it's effectively no limit; one peer-IP-spoofing client can still grind brute-force; Core delegates to OS / firewall — beamchain claims rate-limit security it doesn't provide — BUG-21 |
| G24 `-rpcwhitelist` per-user method ACL                    | MISSING | No equivalent of `g_rpc_whitelist`; one credential = all 200+ methods — BUG-8 |
| G25 `-rpcservertimeout` / `-rpcworkqueue` / `-rpcthreads`  | MISSING | Cowboy's defaults (`{idle_timeout, 60_000}`, no explicit work queue cap) are not surfaced to operators; Core: 30s timeout, 16-thread pool, 64-deep queue — BUG-12 |
| G26 `-norpccookiefile` (disable cookie auth)               | MISSING | Cookie generation is unconditional; no opt-out — BUG-13 |
| G27 `getrpcinfo` returns active commands + logpath         | PARTIAL | Method routed at line 774 but `rpc_getrpcinfo/0` (line 9376) returns a **stub** with `active_commands=[]` and `logpath=<<>>`; bitcoin-cli `getrpcinfo` produces an empty payload — BUG-17 |

### Section E — Headers / status codes / batch protocol (G28–G30)

| Gate | Status | Notes |
|------|--------|-------|
| G28 401 response body matches Core                         | MISSING | Core sends empty body on 401 with `WWW-Authenticate` header; beamchain sends JSON error object (`{"result":null,"error":{"code":-1,"message":"Authorization required"}}`) — sufficient info for an attacker to confirm the endpoint speaks JSON-RPC — BUG-15 |
| G29 Method rejection at the cowboy layer                   | MISSING | Cowboy's `init/2` returns 405 for non-POST on `/` and `/wallet/:wallet_name` — correct ✓, but `/health` accepts GET *and* HEAD only and gives 405 for everything else; PUT/DELETE land in a generic cowboy 404 path that returns plaintext — BUG-18 |
| G30 Unauthenticated `/health` endpoint info-leak           | MISSING | `/health` exposes `height`, `bestblock`, `ibd` — useful adversary fingerprint (IBD-or-tip telemetry); Core has no public unauthenticated equivalent; alternative would be returning only `200 OK` / `503` with NO body — BUG-19 |

## Universal findings

### F1 — "RPC port is openly bound; credential is the *only* gate" (P0-SEC)
beamchain ships listening on all interfaces by default.  `cowboy:start_clear`
is invoked with socket_opts `[{port, Port}, {reuseaddr, true}]` — no `{ip, ...}`
binding, no application-level allow-list.  Core's `InitHTTPAllowList` +
`HTTPBindAddresses` enforces **two** safeguards:
(a) bind defaults to `127.0.0.1` + `::1` when `-rpcallowip` is empty, and
(b) every accepted connection is filtered through `ClientAllowed(netaddr)` *before*
any HTTP parsing.  beamchain has neither.  The 32-byte random cookie is the
sole defense; if the cookie file is readable (e.g. shared NFS, container
mount, leaky log entry), a network adversary at the maxbox's IP has full
RPC.  Fix shape: `{ip, {127,0,0,1}}` default in `socket_opts`; add
`-rpcbind` / `-rpcallowip` flags with Core-equivalent semantics; reject
connections at `cowboy_req:peer/1` before reading headers.

### F2 — "Plaintext password compared with pattern match" (P0-SEC)
`setup_auth/0` (line 525-531) stores `{rpc_credentials, U, P}` literally
in ETS.  `verify_credentials/2` (line 547-554) compares with pattern
matching, which short-circuits on first byte mismatch.  An adversary who
can issue many auth attempts (no 250ms sleep, no rate limit at sane
values, no method whitelist) can mount a *timing* attack on the password.
Core stores `{user, salt, hash}` after computing HMAC-SHA-256 at startup
and compares both username and hash with `TimingResistantEqual` (see
httprpc.cpp:66-77).  Fix shape: (a) `crypto:hash_equals/2` (OTP 27+) or
hand-rolled constant-time XOR-and-OR loop on equal-length binaries; (b)
support `-rpcauth=user:salt$hmac` syntax and hash-at-startup of any
legacy plaintext; (c) `compare_digest` semantics on the username too.

### F3 — "Prometheus + REST listeners replicate the bind bug, unauthenticated" (P0-SEC)
`beamchain_metrics.erl` and `beamchain_rest.erl` use the same
`[{port, P}, {reuseaddr, true}]` socket-opts shape.  Both are
unauthenticated by design.  `/metrics` leaks tip height, peer count,
mempool size; `/rest` exposes block/transaction data (public anyway,
but at 1 RPC per query an attacker can grind transaction lookups for
analysis purposes).  Core's `httpserver.cpp` is the single bind point,
so `InitHTTPAllowList` covers all paths.  Beamchain has three
independent listeners with three independent (missing) ACLs.  Fix
shape: shared `beamchain_listener_acl` module called at every cowboy
`init/2`; default `ip => loopback`; if `-rpcbind` is set, allow
configured bind + IPs.

### F4 — "rpcauth (salted HMAC) wire format absent" (P1)
Operators today have *two* options: (a) cookie auth (random per-run,
not shareable in config files), or (b) plaintext `rpcuser` +
`rpcpassword` in `beamchain.conf`.  Core deprecated (b) in favor of
**rpcauth** — a config-file-safe salted HMAC line:
`rpcauth=alice:c0ffee...$abc123...`.  The plain password is supplied
out-of-band (env var, CI secret, password manager).  Beamchain has no
equivalent.  This forces deployments either to live-write
`rpcpassword=` into the config file (and risk it leaking through
backup / log / config-dump tools) or to rely solely on the random
cookie (and accept that the cookie is unguessable but ALSO
non-shareable across automation hosts).  Fix shape: parse
`rpcauth=user:salt$hmac` lines from config; compute HMAC-SHA-256 on
inbound creds; compare with `crypto:hash_equals/2`.

### F5 — "JSON-RPC HTTP-status mapping diverges from Core" (P1)
Core `JSONErrorReply` maps RPC error codes onto HTTP status:
parse-error → 400, method-not-found → 404, all other errors → 500.
Beamchain returns **200 OK** for every JSON-RPC response body
including parse errors, then puts the error code in
`error.code`/`error.message`.  bitcoin-cli tolerates either form (it
parses the body), but API gateways, Cloudflare Workers, and L7 load
balancers can't tell parse-error from success in their hit-rate
dashboards.  Fix shape: thread the code → status map through
`reply_json`; bump 401 (no auth) and 403 (whitelist violation) to
match.

### F6 — "Brute-force defense is missing on every layer" (P1)
Three Core defense-in-depth measures, all absent in beamchain:
- `UninterruptibleSleep(250ms)` on every bad-auth path (BUG-6).
- Rate limit at OS/firewall layer (Core's stance) OR application
  layer with a Core-sized cap (≤100 req/min/IP).  Beamchain's
  100,000 cap is theatrical — BUG-21.
- `-rpcwhitelist` per-user method ACL (BUG-8): with the cookie
  exposed, *every* method is reachable.  A wallet-tools deployment
  that only needs `getnewaddress` + `listunspent` still ships
  `dumpprivkey` reachable.

### F7 — "`getrpcinfo` is a documented method but returns nothing useful" (P2)
Line 9376: `rpc_getrpcinfo/0` returns `#{<<"active_commands">> => [], <<"logpath">> => <<>>}`.
Core uses this for liveness debugging — "is this RPC stuck?",
"where's the log?".  Stub leaks the existence of the endpoint
without delivering its value.  Fix shape: track active commands via
process dictionary or ETS keyed by request-id, return real values.

## Recommended fix-wave ordering

Order minimizes risk of breaking operator workflows in flight.
P0-SEC items first; P1 ops parity after; P2 surface polish last.

1. **FIX-W140-1 (P0-SEC)**: Bind cowboy listeners to `{ip, {127,0,0,1}}`
   by default (G04, G06; BUG-1, BUG-4).  Add `-rpcbind` and
   `-rpcallowip` flags with Core-equivalent semantics.
2. **FIX-W140-2 (P0-SEC)**: Constant-time credential compare
   (G18, BUG-3).  `crypto:hash_equals/2` on padded binaries OR
   hand-rolled `lists:foldl` with XOR-OR accumulator.
3. **FIX-W140-3 (P0-SEC)**: Hash `rpcpassword` at startup; refuse to
   start if plaintext detected after grace period (G16, BUG-2).
4. **FIX-W140-4 (P1)**: `-rpcauth=user:salt$hmac` line parser
   (G22, BUG-7).  Ship `scripts/rpcauth.py` clone.
5. **FIX-W140-5 (P1)**: 250ms `timer:sleep/1` on bad auth path
   (G20, BUG-6).  Keep the spawn so the cowboy worker isn't tied up.
6. **FIX-W140-6 (P1)**: `-rpcwhitelist` / `-rpcwhitelistdefault`
   per-user method ACL (G24, BUG-8).  ETS-backed set; check inside
   `dispatch/2` after auth.
7. **FIX-W140-7 (P1)**: HTTP status mapping for JSON-RPC errors
   (G21, BUG-14).  Wire the code → status table into `reply_json`.
8. **FIX-W140-8 (P1)**: Stop emitting JSON body on 401; empty body
   with `WWW-Authenticate` header only (G28, BUG-15).
9. **FIX-W140-9 (P1)**: Cookie permissions flag plumbing — owner /
   group / all (G08, BUG-10).
10. **FIX-W140-10 (P1)**: `g_generated_cookie` equivalent — delete the
    cookie file ONLY if we wrote it (G10, BUG-11).
11. **FIX-W140-11 (P1)**: Cookie content trailing newline + content
    parity with Core (G13, BUG-9).
12. **FIX-W140-12 (P1)**: `-rpccookiefile` / `-norpccookiefile` flags
    (G14, G26; BUG-5, BUG-13).
13. **FIX-W140-13 (P1)**: `-rpcservertimeout` / `-rpcworkqueue` /
    `-rpcthreads` parity (G25, BUG-12).
14. **FIX-W140-14 (P1)**: Plumb `RPC_IN_WARMUP` into JSON-RPC dispatch
    so RPC clients don't see successful `getblockcount` during cold
    chainstate replay (G03, BUG-22).
15. **FIX-W140-15 (P2)**: Real `getrpcinfo` (G27, BUG-17).
16. **FIX-W140-16 (P2)**: Lower rate-limit cap to ≤100 req/min/IP OR
    remove the false-security implementation entirely (G23, BUG-21).
17. **FIX-W140-17 (P2)**: Tighten `/health` body — `200 OK` or
    `503` with no payload (G30, BUG-19).
18. **FIX-W140-18 (P2)**: Auth-scheme logging for non-Basic
    (G17, BUG-16); reject all non-GET/HEAD on `/health` (G29, BUG-18).
