-module(beamchain_w140_http_rpcauth_tests).

%%% -------------------------------------------------------------------
%%% W140 — HTTP server + rpcauth + cookie auth + JSON-RPC dispatch
%%% audit (DISCOVERY-ONLY).
%%%
%%% Cross-references beamchain's HTTP RPC surface against Bitcoin Core
%%% (httpserver.cpp / httprpc.cpp / rpc/server.cpp / rpc/request.cpp /
%%% share/rpcauth/rpcauth.py).  These tests are NOT meant to pass as
%%% they are written — they assert the *current divergent behavior* so
%%% that a later FIX wave that brings the surface into parity will flip
%%% them from PASS → FAIL and force a doc update.  Audit-flip convention.
%%%
%%% NO PRODUCTION CODE CHANGES IN THIS COMMIT.  This is a discovery
%%% wave; the production code that ought to be updated stays as-is.
%%%
%%% Source-of-truth for the 30 gates: audit/w140_http_rpcauth.md.
%%% -------------------------------------------------------------------

-include_lib("eunit/include/eunit.hrl").
-include_lib("kernel/include/file.hrl").

%%% ===================================================================
%%% Helpers
%%% ===================================================================

rpc_module_src() ->
    %% Read beamchain_rpc.erl from the source tree so we can grep for
    %% specific call patterns without depending on the BEAM-loaded
    %% module exporting them.  This is the same shape used by W124 +
    %% W125 marker tests.
    {ok, Bin} = file:read_file(
                  filename:join([code:lib_dir(beamchain, src),
                                 "beamchain_rpc.erl"])),
    Bin.

metrics_module_src() ->
    {ok, Bin} = file:read_file(
                  filename:join([code:lib_dir(beamchain, src),
                                 "beamchain_metrics.erl"])),
    Bin.

rest_module_src() ->
    case file:read_file(
           filename:join([code:lib_dir(beamchain, src),
                          "beamchain_rest.erl"])) of
        {ok, Bin} -> Bin;
        _ -> <<>>
    end.

contains(Hay, Needle) ->
    binary:match(Hay, Needle) =/= nomatch.

%%% ===================================================================
%%% Section A — Listener / socket / bind (G01–G06)
%%% ===================================================================

%% G01 PASS — cowboy listener boots via shared start_clear_with_retry.
g01_listener_starts_test() ->
    Src = rpc_module_src(),
    ?assert(contains(Src,
                     <<"beamchain_listener:start_clear_with_retry">>)),
    ?assert(contains(Src, <<"beamchain_rpc_listener">>)).

%% G02 PASS — per-network default port via network_params.rpc_port.
g02_per_network_default_port_test() ->
    Src = rpc_module_src(),
    ?assert(contains(Src, <<"Params#network_params.rpc_port">>)),
    ?assert(contains(Src, <<"rpc_port(Params)">>)).

%% G03 PARTIAL — warmup gate present at /health but not at JSON-RPC.
%% Marker for BUG-22.  Audit-flip: a future FIX wave adding RPC_IN_WARMUP
%% to dispatch/2 will trip this on a "warmup string also appears outside
%% handle_health" check.
g03_warmup_only_at_health_test() ->
    Src = rpc_module_src(),
    ?assert(contains(Src, <<"\"warmup\"">>)),
    %% Today: dispatcher does NOT check ?RPC_IN_WARMUP (-28).  We pin
    %% absence so a future fix flips the assertion.
    ?assertEqual(nomatch,
                 binary:match(Src, <<"?RPC_IN_WARMUP">>)),
    ?assertEqual(nomatch,
                 binary:match(Src, <<"-28, <<\"Loading">>)).

%% G04 MISSING — **P0-SEC** bind on 0.0.0.0 with no ACL.  BUG-1.
g04_listener_binds_all_interfaces_test() ->
    Src = rpc_module_src(),
    %% Confirm the bug shape: socket_opts has port + reuseaddr but NO
    %% {ip, ...} option.  ranch_tcp defaults to INADDR_ANY.
    ?assert(contains(Src,
                     <<"[{port, Port}, {reuseaddr, true}]">>)),
    %% No application-level allow-list / ClientAllowed equivalent.
    ?assertEqual(nomatch, binary:match(Src, <<"rpcallowip">>)),
    ?assertEqual(nomatch, binary:match(Src, <<"client_allowed">>)),
    %% The log message literally claims "0.0.0.0".
    ?assert(contains(Src, <<"0.0.0.0">>)).

%% G05 PARTIAL — no -rpcbind flag.  BUG-5 (shared with G14).
g05_rpcbind_missing_test() ->
    Src = rpc_module_src(),
    ?assertEqual(nomatch, binary:match(Src, <<"-rpcbind">>)),
    ?assertEqual(nomatch, binary:match(Src, <<"rpcbind">>)).

%% G06 MISSING — auxiliary listeners replicate the bind bug.  BUG-4.
g06_aux_listeners_also_unbound_test() ->
    Mh = metrics_module_src(),
    ?assert(contains(Mh,
                     <<"[{port, Port},\n                                              {reuseaddr, true}]">>)
            orelse contains(Mh,
                     <<"[{port, Port}, {reuseaddr, true}]">>)),
    %% No auth on /metrics.
    ?assertEqual(nomatch, binary:match(Mh, <<"check_auth">>)),
    %% REST listener: also no auth path, same bind shape.
    Rh = rest_module_src(),
    ?assertEqual(nomatch, binary:match(Rh, <<"check_auth">>)).

%%% ===================================================================
%%% Section B — Cookie authentication (G07–G14)
%%% ===================================================================

%% G07 PARTIAL — random cookie via crypto:strong_rand_bytes/1.
g07_random_cookie_generated_test() ->
    Src = rpc_module_src(),
    ?assert(contains(Src,
                     <<"crypto:strong_rand_bytes(32)">>)),
    ?assert(contains(Src, <<"hex_encode">>)).

%% G08 MISSING — no -rpccookieperms flag.  BUG-10.
g08_rpccookieperms_missing_test() ->
    Src = rpc_module_src(),
    ?assertEqual(nomatch, binary:match(Src, <<"rpccookieperms">>)),
    %% Permissions are hardcoded to 0600.
    ?assert(contains(Src, <<"8#0600">>)).

%% G09 PASS — cookie file is per-network datadir.
g09_cookie_in_datadir_test() ->
    Src = rpc_module_src(),
    ?assert(contains(Src,
                     <<"filename:join(DataDir, \".cookie\")">>)).

%% G10 PARTIAL — cookie deleted unconditionally; Core gates on
%% g_generated_cookie.  BUG-11.
g10_cookie_delete_unconditional_test() ->
    Src = rpc_module_src(),
    %% file:delete fires in terminate/2 without a "did we generate it"
    %% guard.
    ?assert(contains(Src, <<"file:delete(CookiePath)">>)),
    ?assertEqual(nomatch, binary:match(Src,
                                       <<"g_generated_cookie">>)),
    ?assertEqual(nomatch, binary:match(Src,
                                       <<"cookie_generated_by_us">>)).

%% G11 PASS — __cookie__ literal username matches Core.
g11_cookie_user_literal_test() ->
    Src = rpc_module_src(),
    ?assert(contains(Src,
                     <<"verify_credentials(<<\"__cookie__\">>, Pass)">>)).

%% G12 PARTIAL — cookie value is a 64-hex random string, not HMAC.
%% This is Core-compatible *for cookie auth* (Core also stores plaintext
%% in .cookie); the gate is here so the W140 audit document captures
%% the full HMAC story including BUG-2 / G16.
g12_cookie_value_format_test() ->
    Src = rpc_module_src(),
    ?assert(contains(Src,
                     <<"hex_encode(\n        crypto:strong_rand_bytes">>)
            orelse contains(Src,
                     <<"hex_encode(crypto:strong_rand_bytes">>)
            orelse contains(Src,
                     <<"hex_encode(\n            crypto:strong_rand_bytes">>)).

%% G13 MISSING — cookie content has no trailing newline.  BUG-9.
g13_cookie_content_no_newline_test() ->
    Src = rpc_module_src(),
    %% The literal we write to disk: ":Cookie/binary>>", no "\n" tail.
    ?assert(contains(Src,
                     <<"<<\"__cookie__:\", Cookie/binary>>">>)),
    %% Confirm we don't append a newline anywhere near the write.
    ?assertEqual(nomatch,
                 binary:match(Src,
                              <<"<<\"__cookie__:\", Cookie/binary, \"\\n\">>">>)).

%% G14 MISSING — no -rpccookiefile flag for custom path.  BUG-5/13.
g14_rpccookiefile_missing_test() ->
    Src = rpc_module_src(),
    ?assertEqual(nomatch, binary:match(Src, <<"rpccookiefile">>)).

%%% ===================================================================
%%% Section C — rpcuser/rpcpassword + rpcauth (G15–G20)
%%% ===================================================================

%% G15 PASS — rpcuser / rpcpassword plumbed from config.
g15_rpcuser_rpcpassword_plumbed_test() ->
    Src = rpc_module_src(),
    ?assert(contains(Src,
                     <<"beamchain_config:get(rpcuser)">>)),
    ?assert(contains(Src,
                     <<"beamchain_config:get(rpcpassword)">>)).

%% G16 MISSING — **P0-SEC** plaintext password stored & compared
%% literally.  BUG-2.
g16_plaintext_password_stored_test() ->
    Src = rpc_module_src(),
    %% ETS slot literally stores {rpc_credentials, U, P}.
    ?assert(contains(Src,
                     <<"{rpc_credentials, to_bin(U), to_bin(P)}">>)),
    %% No HMAC, no salt, no hashing anywhere in setup_auth.
    ?assertEqual(nomatch, binary:match(Src, <<"hmac_sha256">>)),
    ?assertEqual(nomatch, binary:match(Src, <<"GenerateAuthCookie">>)),
    ?assertEqual(nomatch, binary:match(Src, <<"password_hmac">>)).

%% G17 PARTIAL — authorization header parsed via cowboy_req:parse_header
%% but non-Basic schemes get silently dropped.  BUG-16.
g17_auth_header_parsed_test() ->
    Src = rpc_module_src(),
    ?assert(contains(Src,
                     <<"cowboy_req:parse_header(<<\"authorization\">>, Req)">>)),
    %% Non-Basic schemes (Bearer / Digest / NTLM) fall into the
    %% catch-all `_ -> {error, missing_auth}` clause with no log.
    ?assert(contains(Src, <<"{error, missing_auth}">>)),
    ?assertEqual(nomatch, binary:match(Src,
                                       <<"non_basic_scheme">>)).

%% G18 MISSING — **P0-SEC** non-constant-time credential compare.
%% BUG-3.
g18_credential_compare_timing_leaky_test() ->
    Src = rpc_module_src(),
    %% Pattern-match comparison short-circuits on first mismatch.
    ?assert(contains(Src,
                     <<"[{rpc_credentials, User, Pass}] -> ok">>)),
    %% No timing-safe equality helper.
    ?assertEqual(nomatch, binary:match(Src, <<"hash_equals">>)),
    ?assertEqual(nomatch, binary:match(Src,
                                       <<"constant_time_compare">>)),
    ?assertEqual(nomatch, binary:match(Src,
                                       <<"TimingResistantEqual">>)).

%% G19 PASS — cookie clause separate from rpcuser clause; cookie auth
%% still works without rpcuser configured.
g19_cookie_path_independent_test() ->
    Src = rpc_module_src(),
    ?assert(contains(Src,
                     <<"verify_credentials(<<\"__cookie__\">>, Pass)">>)),
    %% Empty ETS for rpc_credentials falls back to cookie verification.
    ?assert(contains(Src,
                     <<"verify_credentials(<<\"__cookie__\">>, Pass)">>)).

%% G20 MISSING — no 250ms anti-brute-force sleep on bad auth.  BUG-6.
g20_no_antibrute_force_sleep_test() ->
    Src = rpc_module_src(),
    %% Core: UninterruptibleSleep(std::chrono::milliseconds{250}).
    %% In Erlang the equivalent is timer:sleep(250) before the 401
    %% reply.  Confirm we don't currently have any sleep in the auth
    %% error branch.
    AuthErrBranch =
        case binary:match(Src,
                          <<"{error, _} ->\n                    Req = cowboy_req:reply(401">>) of
            {Pos, _} -> binary:part(Src, Pos, 250);
            _ -> <<>>
        end,
    ?assertEqual(nomatch, binary:match(AuthErrBranch,
                                       <<"timer:sleep">>)).

%%% ===================================================================
%%% Section D — JSON-RPC dispatch (G21–G27)
%%% ===================================================================

%% G21 MISSING — HTTP status code does NOT mirror JSON-RPC error.
%% BUG-14.  Every dispatcher reply uses 200 even on parse error /
%% method-not-found / etc.
g21_http_status_constant_200_test() ->
    Src = rpc_module_src(),
    %% reply_json always uses cowboy_req:reply(200, ...).
    ?assert(contains(Src, <<"cowboy_req:reply(200, #{">>)),
    %% No code → status lookup table.
    ?assertEqual(nomatch, binary:match(Src,
                                       <<"http_status_for_code">>)),
    ?assertEqual(nomatch, binary:match(Src, <<"code_to_status">>)),
    %% Core's JSONErrorReply mapping: -32700 → 400, -32601 → 404 —
    %% neither present.
    ?assertEqual(nomatch, binary:match(Src, <<"reply(400">>)),
    ?assertEqual(nomatch, binary:match(Src, <<"reply(404">>)).

%% G22 MISSING — -rpcauth=user:salt$hmac syntax absent.  BUG-7.
g22_rpcauth_syntax_missing_test() ->
    Src = rpc_module_src(),
    ?assertEqual(nomatch, binary:match(Src, <<"-rpcauth">>)),
    ?assertEqual(nomatch, binary:match(Src, <<"rpcauth=">>)),
    ?assertEqual(nomatch, binary:match(Src,
                                       <<"parse_rpcauth_line">>)).

%% G23 PARTIAL — rate limit set so high it's effectively absent.
%% BUG-21.
g23_rate_limit_theatrical_test() ->
    Src = rpc_module_src(),
    %% Cap of 100,000 / minute.  Core delegates to OS; this is
    %% application-layer security theater.
    ?assert(contains(Src,
                     <<"MAX_REQUESTS_PER_MINUTE, 100000">>)).

%% G24 MISSING — no -rpcwhitelist per-user method ACL.  BUG-8.
g24_no_rpcwhitelist_test() ->
    Src = rpc_module_src(),
    ?assertEqual(nomatch, binary:match(Src, <<"rpcwhitelist">>)),
    ?assertEqual(nomatch, binary:match(Src,
                                       <<"g_rpc_whitelist">>)),
    %% Dispatch routes every method to every authenticated caller.
    ?assert(contains(Src,
                     <<"handle_method(<<\"dumpprivkey\">>">>)).

%% G25 MISSING — no -rpcservertimeout / -rpcworkqueue / -rpcthreads.
%% BUG-12.
g25_rpc_perf_flags_missing_test() ->
    Src = rpc_module_src(),
    ?assertEqual(nomatch, binary:match(Src, <<"rpcservertimeout">>)),
    ?assertEqual(nomatch, binary:match(Src, <<"rpcworkqueue">>)),
    ?assertEqual(nomatch, binary:match(Src, <<"rpcthreads">>)),
    %% No explicit idle_timeout / max_keepalive override.
    ?assertEqual(nomatch, binary:match(Src, <<"idle_timeout =>">>)).

%% G26 MISSING — no -norpccookiefile opt-out.  BUG-13.
g26_no_norpccookiefile_test() ->
    Src = rpc_module_src(),
    ?assertEqual(nomatch, binary:match(Src, <<"norpccookiefile">>)),
    ?assertEqual(nomatch, binary:match(Src,
                                       <<"cookie_disabled">>)).

%% G27 PARTIAL — getrpcinfo is a stub returning empty payload.  BUG-17.
g27_getrpcinfo_is_stub_test() ->
    Src = rpc_module_src(),
    %% Route is wired.
    ?assert(contains(Src,
                     <<"handle_method(<<\"getrpcinfo\">>">>)),
    %% Body is a stub: empty active_commands, empty logpath.
    ?assert(contains(Src, <<"\"active_commands\">> => []">>)),
    ?assert(contains(Src, <<"\"logpath\">> => <<>>">>)).

%%% ===================================================================
%%% Section E — Headers / status codes / batch (G28–G30)
%%% ===================================================================

%% G28 MISSING — 401 body is JSON error object.  BUG-15.
g28_unauthorized_body_format_test() ->
    Src = rpc_module_src(),
    %% Confirm current shape: 401 + Content-Type + WWW-Authenticate +
    %% jsx-encoded error body.
    ?assert(contains(Src, <<"reply(401, #{">>)),
    ?assert(contains(Src,
                     <<"<<\"www-authenticate\">> => <<\"Basic realm=\\\"jsonrpc\\\"\">>">>)),
    ?assert(contains(Src, <<"Authorization required">>)),
    %% Core sends an empty body with just the WWW-Authenticate header.
    %% A future fix removes the jsx:encode payload from the 401 path.
    ?assertEqual(nomatch,
                 binary:match(Src, <<"reply(401, Headers, <<>>">>)).

%% G29 MISSING — method rejection at cowboy layer is per-handler,
%% not centralized.  BUG-18.
g29_method_rejection_centralization_test() ->
    Src = rpc_module_src(),
    %% Two distinct 405-reply sites: handle_health (GET/HEAD allowed)
    %% and the / + /wallet/:wallet handler (POST only).  No shared
    %% method-allowlist.
    ?assertEqual(2,
                 length(binary:matches(Src,
                                       <<"<<\"Method Not Allowed\">>">>))).

%% G30 MISSING — /health unauthenticated info-leak.  BUG-19.
g30_health_leaks_tip_data_test() ->
    Src = rpc_module_src(),
    %% Confirm /health exposes height, bestblock hash, IBD state with
    %% NO auth check.
    ?assert(contains(Src,
                     <<"<<\"height\">>     => Height">>)),
    ?assert(contains(Src,
                     <<"<<\"bestblock\">>  => bin_to_hex(Hash)">>)),
    ?assert(contains(Src,
                     <<"<<\"ibd\">>        => IBD">>)),
    %% /health handler does NOT call check_auth.
    %% Find the handle_health body and prove check_auth is absent.
    {Start, _} = binary:match(Src,
                              <<"handle_health(Req0, CowboyState) ->">>),
    %% handle_health ends before the bin_to_hex helper definition.
    {End, _} = binary:match(Src,
                            <<"bin_to_hex(Bin) when is_binary(Bin) ->">>),
    HealthBody = binary:part(Src, Start, End - Start),
    ?assertEqual(nomatch, binary:match(HealthBody, <<"check_auth">>)).

%%% ===================================================================
%%% Bug-summary recap (anchor for grep / future fix waves)
%%% ===================================================================
%%%
%%% BUG-1  P0-SEC G04 — RPC listener binds 0.0.0.0 with no ACL
%%% BUG-2  P0-SEC G16 — Plaintext rpcpassword stored & compared
%%% BUG-3  P0-SEC G18 — Credential compare is timing-leaky
%%% BUG-4  P0-SEC G06 — Prometheus /metrics also unbound + no auth
%%% BUG-5  P1     G14 — No -rpcbind / -rpcallowip / -rpccookiefile
%%% BUG-6  P1     G20 — No 250ms anti-brute-force sleep
%%% BUG-7  P1     G22 — No -rpcauth salt+HMAC line format
%%% BUG-8  P1     G24 — No -rpcwhitelist per-user ACL
%%% BUG-9  P1     G13 — Cookie content omits trailing newline
%%% BUG-10 P1     G08 — No -rpccookieperms (owner|group|all) flag
%%% BUG-11 P1     G10 — Cookie deleted unconditionally on shutdown
%%% BUG-12 P1     G25 — No -rpcservertimeout/-rpcworkqueue/-rpcthreads
%%% BUG-13 P1     G26 — No -norpccookiefile opt-out
%%% BUG-14 P1     G21 — HTTP status doesn't mirror JSON-RPC error
%%% BUG-15 P1     G28 — 401 body is JSON object (Core: empty)
%%% BUG-16 P1     G17 — Non-Basic auth schemes silently dropped
%%% BUG-17 P2     G27 — getrpcinfo is a stub returning {[],""}
%%% BUG-18 P2     G29 — No central method-allowlist
%%% BUG-19 P2     G30 — /health unauthenticated info-leak
%%% BUG-20 P2     G12 — Cookie value documented as HMAC but plaintext
%%% BUG-21 P2     G23 — Rate limit cap 100k/min — theatrical
%%% BUG-22 P2     G03 — Warmup gate not wired into JSON-RPC dispatch
