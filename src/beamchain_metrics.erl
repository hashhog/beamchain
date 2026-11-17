-module(beamchain_metrics).
-behaviour(gen_server).

%% Prometheus metrics HTTP endpoint.
%% Serves /metrics in Prometheus text exposition format.
%%
%% The endpoint has no authentication, so it binds 127.0.0.1 unless
%% --metricsbind / metricsbind= says otherwise (Core has no such listener;
%% its RPC default is loopback, httpserver.cpp HTTPBindAddresses). A scrape
%% is answered from a body cached for ?SCRAPE_CACHE_MS, so request volume
%% on the port cannot turn into calls on beamchain_mempool.

-include("beamchain.hrl").

%% API
-export([start_link/0]).

%% Exported for testing: listen address resolution.
-export([metrics_bind_ip/0, metrics_bind_ip/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

%% Cowboy handler
-export([init/2]).

-define(SERVER, ?MODULE).
-define(DEFAULT_METRICS_PORT, 9332).
%% A scrape reuses the body built within this window. Prometheus scrapes
%% every 15 s by default, so this only coalesces bursts.
-define(SCRAPE_CACHE_MS, 5000).
%% How long a handler waits for the body before answering 503.
-define(SCRAPE_CALL_TIMEOUT, 10000).

-record(state, {
    port :: non_neg_integer(),
    body = undefined :: binary() | undefined,
    built_at = 0 :: integer()
}).

%%% ===================================================================
%%% API
%%% ===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%%% ===================================================================
%%% gen_server callbacks
%%% ===================================================================

init([]) ->
    %% Resolve effective metrics port. The Prometheus endpoint is a pure
    %% observability surface — its absence MUST NOT prevent the node
    %% from coming up.
    %%
    %% Two failure modes that historically wedged the node and are now
    %% downgraded to "metrics disabled, node continues":
    %%   1. Port collision (eaddrinuse). Hits anyone running a
    %%      second beamchain instance against the default 9332 — e.g.
    %%      tools/diff-test.sh launching a regtest node on the same host
    %%      as a live mainnet beamchain. Crashing the supervisor here
    %%      cascades to the whole node and breaks RPC.
    %%   2. Explicit disable (port=0). Already handled cleanly.
    %%
    %% In both cases we leave RPC, P2P, chainstate, and validation up.
    %% Operators reading /metrics get a connection-refused; everything
    %% else works.
    Port = case application:get_env(beamchain, metrics_port) of
        {ok, P} when is_integer(P) -> P;
        _ -> ?DEFAULT_METRICS_PORT
    end,
    case Port of
        0 ->
            logger:info("metrics: disabled (port=0)"),
            {ok, #state{port = 0}};
        _ ->
            case metrics_bind_ip() of
                {ok, Ip} ->
                    start_listener(Ip, Port);
                {error, BindErr} ->
                    %% Never fall back to some other interface.
                    logger:warning("metrics: invalid metricsbind (~p); "
                                   "continuing with metrics endpoint "
                                   "DISABLED — RPC/P2P unaffected",
                                   [BindErr]),
                    {ok, #state{port = 0}}
            end
    end.

start_listener(Ip, Port) ->
    Dispatch = cowboy_router:compile([
        {'_', [
            {"/metrics", ?MODULE, []}
        ]}
    ]),
    TransportOpts = #{socket_opts => metrics_socket_opts(Ip, Port) ++
                                     [{reuseaddr, true}]},
    ProtoOpts = #{env => #{dispatch => Dispatch}},
    case beamchain_listener:start_clear_with_retry(
            beamchain_metrics_listener, TransportOpts, ProtoOpts,
            "metrics") of
        {ok, _} ->
            logger:info("metrics: Prometheus endpoint on ~s:~B",
                        [inet:ntoa(Ip), Port]),
            {ok, #state{port = Port}};
        {error, Reason} ->
            logger:warning("metrics: bind ~s:~B failed (~p); "
                           "continuing with metrics endpoint "
                           "DISABLED — RPC/P2P unaffected",
                           [inet:ntoa(Ip), Port, Reason]),
            {ok, #state{port = 0}}
    end.

%% Metrics listen address. Source is the `metricsbind` config key:
%% --metricsbind=<addr> (beamchain_cli -> app env -> beamchain_config ETS)
%% or metricsbind=<addr> in beamchain.conf. Unset means 127.0.0.1. Same
%% value forms as --rpcbind: IPv4, IPv6 with or without brackets, or a
%% resolvable name; the port still comes from metrics_port.
-spec metrics_bind_ip() -> {ok, inet:ip_address()} | {error, term()}.
metrics_bind_ip() ->
    metrics_bind_ip(beamchain_config:get(metricsbind)).

-spec metrics_bind_ip(term()) -> {ok, inet:ip_address()} | {error, term()}.
metrics_bind_ip(undefined) ->
    {ok, {127, 0, 0, 1}};
metrics_bind_ip(V) when is_binary(V); is_list(V) ->
    case beamchain_rpc:rpc_bind_ip(V) of
        {ok, Ip} -> {ok, Ip};
        {error, _} -> {error, {invalid_metricsbind, V}}
    end;
metrics_bind_ip(V) ->
    {error, {invalid_metricsbind, V}}.

metrics_socket_opts(Ip, Port) when tuple_size(Ip) =:= 8 ->
    [inet6, {ip, Ip}, {port, Port}];
metrics_socket_opts(Ip, Port) ->
    [{ip, Ip}, {port, Port}].

%% One body per ?SCRAPE_CACHE_MS. Requests that arrive while a body is
%% being built queue here and are answered with that same body.
handle_call(scrape, _From, State) ->
    Now = erlang:monotonic_time(millisecond),
    case State#state.body of
        Body when is_binary(Body),
                  Now - State#state.built_at < ?SCRAPE_CACHE_MS ->
            {reply, {ok, Body}, State};
        _ ->
            Body = render_body(),
            {reply, {ok, Body},
             State#state{body = Body,
                         built_at = erlang:monotonic_time(millisecond)}}
    end;
handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    catch cowboy:stop_listener(beamchain_metrics_listener),
    ok.

%%% ===================================================================
%%% Cowboy handler
%%% ===================================================================

init(Req0, CowboyState) ->
    Req = case catch gen_server:call(?SERVER, scrape, ?SCRAPE_CALL_TIMEOUT) of
        {ok, Body} ->
            cowboy_req:reply(200,
                #{<<"content-type">> =>
                      <<"text/plain; version=0.0.4; charset=utf-8">>},
                Body, Req0);
        _ ->
            cowboy_req:reply(503, #{}, <<>>, Req0)
    end,
    {ok, Req, CowboyState}.

%% Read the three sources and format the exposition body. A source that is
%% down or slow reads as 0 rather than failing the scrape.
render_body() ->
    Height = case catch beamchain_chainstate:get_tip_height() of
        {ok, H} when is_integer(H) -> H;
        _ -> 0
    end,
    Peers = case catch beamchain_peer_manager:peer_count() of
        N when is_integer(N) -> N;
        _ -> 0
    end,
    MempoolSize = case catch beamchain_mempool:get_info() of
        Info when is_map(Info) -> maps:get(size, Info, 0);
        _ -> 0
    end,

    iolist_to_binary(io_lib:format(
        "# HELP bitcoin_blocks_total Current block height~n"
        "# TYPE bitcoin_blocks_total gauge~n"
        "bitcoin_blocks_total ~B~n"
        "# HELP bitcoin_peers_connected Number of connected peers~n"
        "# TYPE bitcoin_peers_connected gauge~n"
        "bitcoin_peers_connected ~B~n"
        "# HELP bitcoin_mempool_size Mempool transaction count~n"
        "# TYPE bitcoin_mempool_size gauge~n"
        "bitcoin_mempool_size ~B~n",
        [Height, Peers, MempoolSize])).
