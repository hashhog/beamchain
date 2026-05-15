-module(beamchain_fix64_tls_tests).

%% FIX-64 / W119 — beamchain RPC HTTPS/TLS termination.
%%
%% Pre-FIX-64 beamchain_rpc:init/1 called cowboy:start_clear/3
%% unconditionally; there was no path to terminate TLS inside the
%% node, so operators wanting HTTPS had to front the JSON-RPC port
%% with nginx / haproxy / stunnel. FIX-64 wires
%%   --rpc-tls-cert=<pem> + --rpc-tls-key=<pem>
%%   (or rpctlscert= / rpctlskey= in beamchain.conf,
%%    or BEAMCHAIN_RPC_TLS_CERT / BEAMCHAIN_RPC_TLS_KEY env vars)
%% into a cowboy:start_tls/3 call via beamchain_listener:
%% start_tls_with_retry/4. When neither flag is set, the existing
%% start_clear path is preserved (backward-compatible).
%%
%% Mirrors bitcoin-core/src/httpserver.cpp's HTTPServerInit() ->
%% libevent + OpenSSL wiring for -rpcsslcertificatechainfile /
%% -rpcsslprivatekeyfile, and BIP-78 §"Protocol" which mandates
%% TLS for production PayJoin endpoints.
%%
%% Test matrix:
%%   1. resolve_tls_config: no env, no app env  ->  {ok, none}
%%      (backward-compat path)
%%   2. resolve_tls_config: cert set + key set  ->  {ok, {tls, ...}}
%%   3. resolve_tls_config: cert without key    ->  {error, half-config}
%%   4. resolve_tls_config: key without cert    ->  {error, half-config}
%%   5. resolve_tls_config: cert file missing   ->  {error, not-found}
%%   6. start_clear_with_retry: HTTP roundtrip on plaintext listener
%%   7. start_tls_with_retry: HTTPS roundtrip on TLS listener with a
%%      generated self-signed cert + key from public_key:pkix_test_data/1
%%      (handshake-level proof the certfile + keyfile pair landed).

-include_lib("eunit/include/eunit.hrl").

%% Cowboy handler entry point. Test modules don't auto-export init/2;
%% without this, cowboy's request-process spawn sees `undef` and replies
%% with 500 Internal Server Error before our handler body runs.
-export([init/2]).

%%% ===================================================================
%%% half-config / missing-file detection (resolve_tls_config/0)
%%% ===================================================================

resolve_no_config_test() ->
    with_clean_env(fun() ->
        ?assertEqual({ok, none}, beamchain_rpc:resolve_tls_config())
    end).

resolve_half_config_cert_without_key_test() ->
    with_clean_env(fun() ->
        {CertPath, KeyPath, _Dir} = make_cert_files(),
        application:set_env(beamchain, rpc_tls_cert, CertPath),
        ets_insert_config(rpc_tls_cert, CertPath),
        try
            Result = beamchain_rpc:resolve_tls_config(),
            ?assertMatch({error, {rpc_tls_key_missing, _}}, Result)
        after
            cleanup_cert_files(KeyPath, CertPath)
        end
    end).

resolve_half_config_key_without_cert_test() ->
    with_clean_env(fun() ->
        {CertPath, KeyPath, _Dir} = make_cert_files(),
        application:set_env(beamchain, rpc_tls_key, KeyPath),
        ets_insert_config(rpc_tls_key, KeyPath),
        try
            Result = beamchain_rpc:resolve_tls_config(),
            ?assertMatch({error, {rpc_tls_cert_missing, _}}, Result)
        after
            cleanup_cert_files(KeyPath, CertPath)
        end
    end).

resolve_cert_file_missing_test() ->
    with_clean_env(fun() ->
        BadCert = "/tmp/beamchain-fix64-nonexistent-cert.pem",
        BadKey  = "/tmp/beamchain-fix64-nonexistent-key.pem",
        application:set_env(beamchain, rpc_tls_cert, BadCert),
        application:set_env(beamchain, rpc_tls_key, BadKey),
        ets_insert_config(rpc_tls_cert, BadCert),
        ets_insert_config(rpc_tls_key, BadKey),
        Result = beamchain_rpc:resolve_tls_config(),
        ?assertMatch({error, {cert_file_not_found, _}}, Result)
    end).

resolve_both_present_test() ->
    with_clean_env(fun() ->
        {CertPath, KeyPath, _Dir} = make_cert_files(),
        application:set_env(beamchain, rpc_tls_cert, CertPath),
        application:set_env(beamchain, rpc_tls_key, KeyPath),
        ets_insert_config(rpc_tls_cert, CertPath),
        ets_insert_config(rpc_tls_key, KeyPath),
        try
            Result = beamchain_rpc:resolve_tls_config(),
            ?assertMatch({ok, {tls, CertPath, KeyPath}}, Result)
        after
            cleanup_cert_files(KeyPath, CertPath)
        end
    end).

%%% ===================================================================
%%% Listener: HTTP + HTTPS roundtrips
%%% ===================================================================

start_clear_http_roundtrip_test_() ->
    {timeout, 30, fun() ->
        ok = ensure_apps([crypto, asn1, public_key, cowlib, ranch, cowboy, ssl,
                          inets]),
        Port = ephemeral_port(),
        Ref = beamchain_fix64_clear_listener,
        Dispatch = cowboy_router:compile([{'_', [{"/", ?MODULE, [pong]}]}]),
        %% Ranch already enables SO_REUSEADDR by default on ranch_tcp; we
        %% don't add a user-level {reuseaddr,true} here purely to keep the
        %% test output clean (ranch logs a "Transport option unknown or
        %% invalid" warning when reuseaddr is supplied by the caller,
        %% because it's on ranch_tcp:disallowed_listen_options/0).
        TransportOpts = #{socket_opts => [{port, Port}]},
        ProtoOpts = #{env => #{dispatch => Dispatch}},
        try
            {ok, _Pid} = beamchain_listener:start_clear_with_retry(
                Ref, TransportOpts, ProtoOpts, "test-clear"),
            Url = "http://127.0.0.1:" ++ integer_to_list(Port) ++ "/",
            {ok, {{_, 200, _}, _Hdrs, Body}} =
                httpc:request(get, {Url, []}, [{timeout, 5000}], []),
            ?assertEqual("pong", Body)
        after
            catch cowboy:stop_listener(Ref)
        end
    end}.

start_tls_https_roundtrip_test_() ->
    {timeout, 60, fun() ->
        ok = ensure_apps([crypto, asn1, public_key, cowlib, ranch, cowboy, ssl,
                          inets]),
        {CertPath, KeyPath, Dir} = make_cert_files(),
        Port = ephemeral_port(),
        Ref = beamchain_fix64_tls_listener,
        Dispatch = cowboy_router:compile([{'_', [{"/", ?MODULE, [pong]}]}]),
        %% Note: reuseaddr is rejected by ranch_ssl as an unknown option
        %% (only valid on plain TCP). Production beamchain_rpc keeps
        %% reuseaddr because the *plaintext* and *TLS* branches build
        %% separate option lists; the eunit fixture does the same here.
        TransportOpts = #{socket_opts =>
                            [{port, Port},
                             {certfile, CertPath},
                             {keyfile, KeyPath}]},
        ProtoOpts = #{env => #{dispatch => Dispatch}},
        try
            {ok, _Pid} = beamchain_listener:start_tls_with_retry(
                Ref, TransportOpts, ProtoOpts, "test-tls"),
            %% Use ssl:connect directly so we can disable cert
            %% verification (self-signed cert from pkix_test_data is
            %% not in any trust store). This is the same shape Core's
            %% rpc-ssl integration tests use.
            {ok, Sock} = ssl:connect("127.0.0.1", Port,
                                     [{verify, verify_none},
                                      {active, false},
                                      binary],
                                     5000),
            Req = <<"GET / HTTP/1.1\r\n"
                    "Host: 127.0.0.1\r\n"
                    "Connection: close\r\n"
                    "\r\n">>,
            ok = ssl:send(Sock, Req),
            Resp = recv_all(Sock, <<>>),
            ssl:close(Sock),
            ?assertNotEqual(nomatch,
                            binary:match(Resp, <<"HTTP/1.1 200">>)),
            ?assertNotEqual(nomatch, binary:match(Resp, <<"pong">>))
        after
            catch cowboy:stop_listener(Ref),
            cleanup_cert_files(KeyPath, CertPath),
            cleanup_dir(Dir)
        end
    end}.

%%% ===================================================================
%%% Cowboy handler (returns "pong" for any request) -- shared test fixture
%%% ===================================================================

init(Req0, [pong] = State) ->
    Req = cowboy_req:reply(200,
                           #{<<"content-type">> => <<"text/plain">>},
                           <<"pong">>,
                           Req0),
    {ok, Req, State}.

%%% ===================================================================
%%% Helpers
%%% ===================================================================

with_clean_env(Fun) ->
    %% Ensure the config ETS table exists -- beamchain_rpc:resolve_tls_config/0
    %% calls beamchain_config:get/2 which raises {badarg, ets, lookup, ...}
    %% if the table is absent (production code path is gen_server-managed).
    %% Track whether WE created it so teardown can remove it WITHOUT
    %% stomping on a sibling test that has already started a real
    %% beamchain_config gen_server (which would crash on a duplicate
    %% ets:new at init/1 line 464).
    WeCreated = case ets:info(beamchain_config_ets) of
        undefined ->
            ets:new(beamchain_config_ets,
                    [named_table, set, public, {read_concurrency, true}]),
            true;
        _ -> false
    end,
    %% Snapshot + clear so test isolation is not polluted by prior runs.
    Cert0 = application:get_env(beamchain, rpc_tls_cert),
    Key0  = application:get_env(beamchain, rpc_tls_key),
    EtsCert0 = ets_lookup_config(rpc_tls_cert),
    EtsKey0  = ets_lookup_config(rpc_tls_key),
    EnvCert0 = os:getenv("BEAMCHAIN_RPC_TLS_CERT"),
    EnvKey0  = os:getenv("BEAMCHAIN_RPC_TLS_KEY"),
    application:unset_env(beamchain, rpc_tls_cert),
    application:unset_env(beamchain, rpc_tls_key),
    ets_delete_config(rpc_tls_cert),
    ets_delete_config(rpc_tls_key),
    os:unsetenv("BEAMCHAIN_RPC_TLS_CERT"),
    os:unsetenv("BEAMCHAIN_RPC_TLS_KEY"),
    try
        Fun()
    after
        restore_app_env(rpc_tls_cert, Cert0),
        restore_app_env(rpc_tls_key, Key0),
        restore_ets_config(rpc_tls_cert, EtsCert0),
        restore_ets_config(rpc_tls_key,  EtsKey0),
        restore_os_env("BEAMCHAIN_RPC_TLS_CERT", EnvCert0),
        restore_os_env("BEAMCHAIN_RPC_TLS_KEY",  EnvKey0),
        case WeCreated of
            true ->
                %% Only delete if nobody has whereis'd onto it as a
                %% gen_server -- a downstream test may have spun up
                %% beamchain_config in the meantime (whereupon the
                %% table is gen_server-owned and not ours to drop).
                case whereis(beamchain_config) of
                    undefined ->
                        catch ets:delete(beamchain_config_ets);
                    _ -> ok
                end;
            false -> ok
        end
    end.

restore_app_env(_K, undefined) -> ok;
restore_app_env(K, {ok, V}) -> application:set_env(beamchain, K, V).

restore_ets_config(_K, undefined) -> ok;
restore_ets_config(K, V) -> ets_insert_config(K, V).

restore_os_env(_K, false) -> ok;
restore_os_env(K, V) -> os:putenv(K, V).

ets_lookup_config(K) ->
    case ets:info(beamchain_config_ets) of
        undefined -> undefined;
        _ ->
            case ets:lookup(beamchain_config_ets, K) of
                [{K, V}] -> V;
                _ -> undefined
            end
    end.

ets_insert_config(K, V) ->
    ensure_config_ets(),
    ets:insert(beamchain_config_ets, {K, V}).

ets_delete_config(K) ->
    case ets:info(beamchain_config_ets) of
        undefined -> ok;
        _ -> ets:delete(beamchain_config_ets, K), ok
    end.

ensure_config_ets() ->
    case ets:info(beamchain_config_ets) of
        undefined ->
            ets:new(beamchain_config_ets,
                    [named_table, set, public, {read_concurrency, true}]);
        _ -> ok
    end.

ensure_apps([]) -> ok;
ensure_apps([App | Rest]) ->
    case application:ensure_all_started(App) of
        {ok, _} -> ensure_apps(Rest);
        {error, {already_started, _}} -> ensure_apps(Rest);
        Other -> Other
    end.

ephemeral_port() ->
    %% Open a temporary listening socket, capture its port number, close,
    %% and return -- not race-free, but adequate for an eunit fixture and
    %% keeps the test independent of any hard-coded RPC port. Cowboy will
    %% reopen the same port via {reuseaddr, true}.
    {ok, S} = gen_tcp:listen(0, [{reuseaddr, true}]),
    {ok, Port} = inet:port(S),
    gen_tcp:close(S),
    Port.

recv_all(Sock, Acc) ->
    case ssl:recv(Sock, 0, 3000) of
        {ok, Bin}        -> recv_all(Sock, <<Acc/binary, Bin/binary>>);
        {error, closed}  -> Acc;
        {error, timeout} -> Acc
    end.

%% Generate a self-signed cert + key pair via public_key:pkix_test_data/1
%% (OTP 20.2+), PEM-encode, and write to /tmp/beamchain-fix64-<pid>/.
make_cert_files() ->
    ok = ensure_apps([crypto, asn1, public_key]),
    TestData = public_key:pkix_test_data(
        #{root => [{key, {rsa, 2048, 65537}}, {digest, sha256}],
          peer => [{key, {rsa, 2048, 65537}}, {digest, sha256},
                   {extensions, []}]}),
    CertDER = proplists:get_value(cert, TestData),
    %% public_key:pkix_test_data returns the key as a 2-tuple
    %% {KeyType, DER} (e.g. {'RSAPrivateKey', DER}) ready to drop into
    %% the pem_encode list directly.
    {KeyType, KeyDER} = proplists:get_value(key, TestData),
    Dir = filename:join("/tmp",
                        "beamchain-fix64-" ++ os:getpid() ++ "-" ++
                        integer_to_list(erlang:unique_integer([positive]))),
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    CertPath = filename:join(Dir, "server.crt"),
    KeyPath  = filename:join(Dir, "server.key"),
    CertPem = public_key:pem_encode([{'Certificate', CertDER, not_encrypted}]),
    KeyPem  = public_key:pem_encode([{KeyType, KeyDER, not_encrypted}]),
    ok = file:write_file(CertPath, CertPem),
    ok = file:write_file(KeyPath,  KeyPem),
    ok = file:change_mode(KeyPath, 8#0600),
    {CertPath, KeyPath, Dir}.

cleanup_cert_files(KeyPath, CertPath) ->
    _ = file:delete(KeyPath),
    _ = file:delete(CertPath),
    ok.

cleanup_dir(Dir) ->
    _ = file:del_dir(Dir),
    ok.
