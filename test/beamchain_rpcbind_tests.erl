-module(beamchain_rpcbind_tests).

%% RPC listen address (--rpcbind / rpcbind=).
%%
%% The RPC listener used to start with socket_opts [{port, Port},
%% {reuseaddr, true}] and no {ip, _}, so ranch_tcp bound INADDR_ANY and
%% mainnet RPC was reachable on 0.0.0.0. Core binds loopback unless told
%% otherwise (httpserver.cpp HTTPBindAddresses). These tests pin:
%%   - no flag      -> the listener's socket is bound to 127.0.0.1
%%   - --rpcbind X  -> parsed, carried through config, and the socket binds X
%%   - garbage      -> an error, never a silent fall back to another interface
%%
%% The listener tests bind a real cowboy/ranch socket with the exact
%% socket_opts beamchain_rpc:init/1 uses and read the bound address back with
%% ranch:get_addr/1, so they measure the socket, not the source text.

-include_lib("eunit/include/eunit.hrl").

-define(CFG, beamchain_config_ets).

%%% ===================================================================
%%% Resolver
%%% ===================================================================

default_rpcbind_is_loopback_test() ->
    with_rpcbind(undefined, fun() ->
        ?assertEqual({ok, {127, 0, 0, 1}}, beamchain_rpc:rpc_bind_ip())
    end).

rpcbind_from_config_test() ->
    with_rpcbind("0.0.0.0", fun() ->
        ?assertEqual({ok, {0, 0, 0, 0}}, beamchain_rpc:rpc_bind_ip())
    end),
    with_rpcbind("192.168.1.5", fun() ->
        ?assertEqual({ok, {192, 168, 1, 5}}, beamchain_rpc:rpc_bind_ip())
    end).

rpcbind_value_forms_test() ->
    ?assertEqual({ok, {127, 0, 0, 1}}, beamchain_rpc:rpc_bind_ip(undefined)),
    ?assertEqual({ok, {0, 0, 0, 0}}, beamchain_rpc:rpc_bind_ip(<<"0.0.0.0">>)),
    ?assertEqual({ok, {10, 0, 0, 1}}, beamchain_rpc:rpc_bind_ip(" 10.0.0.1 ")),
    ?assertEqual({ok, {0, 0, 0, 0, 0, 0, 0, 1}},
                 beamchain_rpc:rpc_bind_ip("::1")),
    ?assertEqual({ok, {0, 0, 0, 0, 0, 0, 0, 1}},
                 beamchain_rpc:rpc_bind_ip("[::1]")).

rpcbind_invalid_is_error_test() ->
    ?assertMatch({error, {invalid_rpcbind, _}},
                 beamchain_rpc:rpc_bind_ip("")),
    ?assertMatch({error, {invalid_rpcbind, _}},
                 beamchain_rpc:rpc_bind_ip("999.1.1.1")),
    ?assertMatch({error, {invalid_rpcbind, _}},
                 beamchain_rpc:rpc_bind_ip(8332)).

%%% ===================================================================
%%% CLI
%%% ===================================================================

cli_parses_rpcbind_test() ->
    {start, O1} = beamchain_cli:parse_args(["start", "--rpcbind=0.0.0.0"]),
    ?assertEqual("0.0.0.0", maps:get(rpc_bind, O1)),
    {start, O2} = beamchain_cli:parse_args(["start", "--rpcbind", "10.1.2.3"]),
    ?assertEqual("10.1.2.3", maps:get(rpc_bind, O2)),
    {start, O3} = beamchain_cli:parse_args(["start", "--rpc-port=48348"]),
    ?assertNot(maps:is_key(rpc_bind, O3)).

%%% ===================================================================
%%% Real listener
%%% ===================================================================

listener_default_binds_loopback_test() ->
    with_rpcbind(undefined, fun() ->
        ?assertEqual({127, 0, 0, 1}, bound_addr())
    end).

listener_explicit_all_interfaces_test() ->
    with_rpcbind("0.0.0.0", fun() ->
        ?assertEqual({0, 0, 0, 0}, bound_addr())
    end).

%%% ===================================================================
%%% Helpers
%%% ===================================================================

%% Start a throwaway cowboy listener on an ephemeral port with the socket
%% options beamchain_rpc:init/1 builds for the plaintext listener, and return
%% the address the socket actually bound.
bound_addr() ->
    {ok, _} = application:ensure_all_started(cowboy),
    {ok, Ip} = beamchain_rpc:rpc_bind_ip(),
    Ref = beamchain_rpcbind_test_listener,
    Dispatch = cowboy_router:compile([{'_', []}]),
    {ok, _} = cowboy:start_clear(
                Ref,
                #{socket_opts => beamchain_rpc:rpc_socket_opts(Ip, 0) ++
                                 [{reuseaddr, true}]},
                #{env => #{dispatch => Dispatch}}),
    try
        {Addr, Port} = ranch:get_addr(Ref),
        ?assert(Port > 0),
        Addr
    after
        cowboy:stop_listener(Ref)
    end.

%% Run Fun with the `rpcbind` config key set to Value (undefined = absent),
%% restoring whatever was there before. Creates the config table only if no
%% one else has, and drops it afterwards only in that case.
with_rpcbind(Value, Fun) ->
    WeCreated = case ets:info(?CFG) of
        undefined ->
            ets:new(?CFG, [named_table, set, public, {read_concurrency, true}]),
            true;
        _ -> false
    end,
    Prev = ets:lookup(?CFG, rpcbind),
    case Value of
        undefined -> ets:delete(?CFG, rpcbind);
        _ -> ets:insert(?CFG, {rpcbind, Value})
    end,
    try
        Fun()
    after
        case WeCreated of
            true -> catch ets:delete(?CFG);
            false ->
                ets:delete(?CFG, rpcbind),
                [ets:insert(?CFG, P) || P <- Prev]
        end
    end.
