-module(beamchain_metrics_tests).

%% Prometheus /metrics listener: bind address and scrape cost.
%%
%% The listener used to start with socket_opts [{port, Port},
%% {reuseaddr, true}] and no {ip, _}, so ranch_tcp bound INADDR_ANY. On
%% mainnet that put an unauthenticated HTTP endpoint on 0.0.0.0:9348, and
%% every request made a gen_server:call into beamchain_mempool (get_info),
%% so anyone who could reach the port could queue work on the mempool
%% process. Core has no such listener at all.
%%
%% These tests pin:
%%   - no option         -> the real listener's socket is bound to
%%                          127.0.0.1 and a connect to a non-loopback
%%                          address of this host is refused
%%   - --metricsbind X   -> parsed, carried through config, socket binds X
%%   - garbage           -> no listener at all, never another interface
%%   - repeated scrapes  -> beamchain_mempool:get_info is called once per
%%                          cache window, not once per request
%%
%% The listener tests start the real beamchain_metrics gen_server (so they
%% measure init/1's socket, not the source text) and read the bound address
%% back from ranch.

-include_lib("eunit/include/eunit.hrl").

-define(CFG, beamchain_config_ets).
-define(LISTENER, beamchain_metrics_listener).
-define(CHAIN_META, beamchain_chain_meta).
-define(PEER_TABLE, beamchain_peers).

%%% ===================================================================
%%% Real listener
%%% ===================================================================

%% The finding: no {ip, _} in the socket options, so every interface.
metrics_binds_loopback_by_default_test() ->
    with_metrics(undefined, fun(Port) ->
        SockOpts = listener_socket_opts(),
        ?assertEqual({127, 0, 0, 1}, proplists:get_value(ip, SockOpts)),
        {Addr, _} = ranch:get_addr(?LISTENER),
        ?assertEqual({127, 0, 0, 1}, Addr),
        %% Loopback still answers ...
        {ok, S} = gen_tcp:connect({127, 0, 0, 1}, Port, [binary], 2000),
        gen_tcp:close(S),
        %% ... and this host's own non-loopback address does not.
        case non_loopback_ipv4() of
            none ->
                ?debugMsg("no non-loopback IPv4 address; "
                          "refusal half not exercised");
            Other ->
                ?assertEqual({error, econnrefused},
                             gen_tcp:connect(Other, Port, [binary], 2000))
        end
    end).

metrics_explicit_all_interfaces_test() ->
    with_metrics("0.0.0.0", fun(Port) ->
        {Addr, _} = ranch:get_addr(?LISTENER),
        ?assertEqual({0, 0, 0, 0}, Addr),
        case non_loopback_ipv4() of
            none -> ok;
            Other ->
                {ok, S} = gen_tcp:connect(Other, Port, [binary], 2000),
                gen_tcp:close(S)
        end
    end).

%% An unparsable --metricsbind never falls back to some other interface:
%% the metrics listener is simply not started (the node keeps running, as
%% for a port collision).
metrics_invalid_bind_starts_no_listener_test() ->
    with_metrics("not an address !!", fun(Port) ->
        ?assertEqual(undefined, ranch_ref_or_undefined()),
        ?assertEqual({error, econnrefused},
                     gen_tcp:connect({127, 0, 0, 1}, Port, [binary], 2000))
    end).

%%% ===================================================================
%%% Resolver
%%% ===================================================================

metrics_bind_ip_value_forms_test() ->
    ?assertEqual({ok, {127, 0, 0, 1}}, beamchain_metrics:metrics_bind_ip(undefined)),
    ?assertEqual({ok, {0, 0, 0, 0}}, beamchain_metrics:metrics_bind_ip("0.0.0.0")),
    ?assertEqual({ok, {0, 0, 0, 0}}, beamchain_metrics:metrics_bind_ip(<<"0.0.0.0">>)),
    ?assertEqual({ok, {10, 0, 0, 1}}, beamchain_metrics:metrics_bind_ip(" 10.0.0.1 ")),
    ?assertEqual({ok, {0, 0, 0, 0, 0, 0, 0, 1}},
                 beamchain_metrics:metrics_bind_ip("[::1]")),
    ?assertMatch({error, {invalid_metricsbind, _}},
                 beamchain_metrics:metrics_bind_ip("")),
    ?assertMatch({error, {invalid_metricsbind, _}},
                 beamchain_metrics:metrics_bind_ip("999.1.1.1")),
    ?assertMatch({error, {invalid_metricsbind, _}},
                 beamchain_metrics:metrics_bind_ip(9348)).

%%% ===================================================================
%%% CLI
%%% ===================================================================

cli_parses_metricsbind_test() ->
    {start, O1} = beamchain_cli:parse_args(["start", "--metricsbind=0.0.0.0"]),
    ?assertEqual("0.0.0.0", maps:get(metrics_bind, O1)),
    {start, O2} = beamchain_cli:parse_args(["start", "--metricsbind", "10.1.2.3"]),
    ?assertEqual("10.1.2.3", maps:get(metrics_bind, O2)),
    {start, O3} = beamchain_cli:parse_args(["start", "--rpc-port=48348"]),
    ?assertNot(maps:is_key(metrics_bind, O3)).

%%% ===================================================================
%%% Scrape cost
%%% ===================================================================

%% Five scrapes inside one cache window cost one mempool call, and the
%% body still carries the values the sources reported.
metrics_scrape_is_cached_test() ->
    with_scrape_sources(7, fun(Counter) ->
        with_metrics(undefined, fun(Port) ->
            Bodies = [http_get_metrics(Port) || _ <- lists:seq(1, 5)],
            [?assertMatch({200, _}, B) || B <- Bodies],
            {200, Body} = hd(Bodies),
            ?assertNotEqual(nomatch,
                            binary:match(Body, <<"bitcoin_mempool_size 7\n">>)),
            ?assertNotEqual(nomatch,
                            binary:match(Body, <<"bitcoin_blocks_total 123\n">>)),
            ?assertEqual(1, counters:get(Counter, 1))
        end)
    end).

%%% ===================================================================
%%% Helpers
%%% ===================================================================

%% Start the real beamchain_metrics gen_server on a free port with the
%% `metricsbind` config key set to Bind (undefined = absent), run Fun(Port),
%% then stop it and restore the config.
with_metrics(Bind, Fun) ->
    {ok, _} = application:ensure_all_started(cowboy),
    Port = free_port(),
    PrevPort = application:get_env(beamchain, metrics_port),
    application:set_env(beamchain, metrics_port, Port),
    with_cfg(metricsbind, Bind, fun() ->
        PrevTrap = process_flag(trap_exit, true),
        {ok, Pid} = beamchain_metrics:start_link(),
        try
            Fun(Port)
        after
            process_flag(trap_exit, PrevTrap),
            unlink(Pid),
            exit(Pid, shutdown),
            wait_dead(Pid),
            catch cowboy:stop_listener(?LISTENER),
            case PrevPort of
                {ok, P} -> application:set_env(beamchain, metrics_port, P);
                undefined -> application:unset_env(beamchain, metrics_port)
            end
        end
    end).

wait_dead(Pid) ->
    Ref = monitor(process, Pid),
    receive {'DOWN', Ref, process, Pid, _} -> ok
    after 5000 -> exit(Pid, kill)
    end.

listener_socket_opts() ->
    TOpts = ranch:get_transport_options(?LISTENER),
    case TOpts of
        #{socket_opts := S} -> S;
        L when is_list(L) -> L
    end.

ranch_ref_or_undefined() ->
    try ranch:get_addr(?LISTENER) of
        _ -> defined
    catch _:_ -> undefined
    end.

%% Probe on every interface: the explicit 0.0.0.0 test binds the same port
%% there, so a port free only on loopback would not do.
free_port() ->
    {ok, L} = gen_tcp:listen(0, [{ip, {0, 0, 0, 0}}]),
    {ok, P} = inet:port(L),
    gen_tcp:close(L),
    P.

non_loopback_ipv4() ->
    {ok, Ifs} = inet:getifaddrs(),
    Addrs = [A || {_, Props} <- Ifs,
                  {addr, A} <- Props,
                  tuple_size(A) =:= 4,
                  element(1, A) =/= 127],
    case Addrs of
        [A | _] -> A;
        [] -> none
    end.

http_get_metrics(Port) ->
    {ok, S} = gen_tcp:connect({127, 0, 0, 1}, Port,
                              [binary, {active, false}], 2000),
    ok = gen_tcp:send(S, <<"GET /metrics HTTP/1.0\r\nHost: localhost\r\n\r\n">>),
    Resp = recv_all(S, <<>>),
    gen_tcp:close(S),
    [Head, Body] = binary:split(Resp, <<"\r\n\r\n">>),
    [StatusLine | _] = binary:split(Head, <<"\r\n">>),
    [_, Code | _] = binary:split(StatusLine, <<" ">>, [global]),
    {binary_to_integer(Code), Body}.

recv_all(S, Acc) ->
    case gen_tcp:recv(S, 0, 5000) of
        {ok, D} -> recv_all(S, <<Acc/binary, D/binary>>);
        {error, closed} -> Acc
    end.

%% Stand in for the three sources a scrape reads: the chain-meta tip row,
%% the peer table, and a process registered as beamchain_mempool that
%% answers get_info and counts how often it is asked.
with_scrape_sources(MempoolSize, Fun) ->
    Counter = counters:new(1, []),
    Tables = [T || T <- [?CHAIN_META, ?PEER_TABLE], ets:info(T) =:= undefined],
    [ets:new(T, [named_table, set, public]) || T <- Tables],
    PrevTip = ets:lookup(?CHAIN_META, tip),
    ets:insert(?CHAIN_META, {tip, <<0:256>>, 123}),
    Self = self(),
    Mp = spawn(fun() ->
        register(beamchain_mempool, self()),
        Self ! {fake_mempool, ready},
        fake_mempool_loop(Counter, MempoolSize)
    end),
    receive {fake_mempool, ready} -> ok after 2000 -> error(no_fake_mempool) end,
    try
        Fun(Counter)
    after
        exit(Mp, kill),
        [catch ets:delete(T) || T <- Tables],
        case lists:member(?CHAIN_META, Tables) of
            true -> ok;
            false ->
                ets:delete(?CHAIN_META, tip),
                [ets:insert(?CHAIN_META, R) || R <- PrevTip]
        end
    end.

fake_mempool_loop(Counter, Size) ->
    receive
        {'$gen_call', From, get_info} ->
            counters:add(Counter, 1, 1),
            gen_server:reply(From, #{size => Size, bytes => 0,
                                     max_size => 0, min_fee => 0}),
            fake_mempool_loop(Counter, Size);
        {'$gen_call', From, _} ->
            gen_server:reply(From, {error, unknown}),
            fake_mempool_loop(Counter, Size);
        _ ->
            fake_mempool_loop(Counter, Size)
    end.

%% Run Fun with config key Key set to Value (undefined = absent), restoring
%% whatever was there before. Creates the config table only if no one else
%% has, and drops it afterwards only in that case.
with_cfg(Key, Value, Fun) ->
    WeCreated = case ets:info(?CFG) of
        undefined ->
            ets:new(?CFG, [named_table, set, public, {read_concurrency, true}]),
            true;
        _ -> false
    end,
    Prev = ets:lookup(?CFG, Key),
    case Value of
        undefined -> ets:delete(?CFG, Key);
        _ -> ets:insert(?CFG, {Key, Value})
    end,
    try
        Fun()
    after
        case WeCreated of
            true -> catch ets:delete(?CFG);
            false ->
                ets:delete(?CFG, Key),
                [ets:insert(?CFG, P) || P <- Prev]
        end
    end.
