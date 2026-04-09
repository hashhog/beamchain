-module(beamchain_metrics).
-behaviour(gen_server).

%% Prometheus metrics HTTP endpoint.
%% Serves /metrics in Prometheus text exposition format.

-include("beamchain.hrl").

%% API
-export([start_link/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

%% Cowboy handler
-export([init/2]).

-define(SERVER, ?MODULE).
-define(DEFAULT_METRICS_PORT, 9332).

-record(state, {
    port :: non_neg_integer()
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
    Port = case application:get_env(beamchain, metrics_port) of
        {ok, P} when is_integer(P) -> P;
        _ -> ?DEFAULT_METRICS_PORT
    end,
    case Port of
        0 ->
            logger:info("metrics: disabled (port=0)"),
            {ok, #state{port = 0}};
        _ ->
            Dispatch = cowboy_router:compile([
                {'_', [
                    {"/metrics", ?MODULE, []}
                ]}
            ]),
            case cowboy:start_clear(beamchain_metrics_listener,
                    [{port, Port}],
                    #{env => #{dispatch => Dispatch}}) of
                {ok, _} ->
                    logger:info("metrics: Prometheus endpoint on port ~B", [Port]);
                {error, {already_started, _}} ->
                    logger:info("metrics: already listening on port ~B", [Port]);
                {error, Reason} ->
                    logger:warning("metrics: failed to start on port ~B: ~p",
                                   [Port, Reason])
            end,
            {ok, #state{port = Port}}
    end.

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
    Height = case beamchain_chainstate:get_tip_height() of
        {ok, H} -> H;
        _ -> 0
    end,
    Peers = beamchain_peer_manager:peer_count(),
    MempoolInfo = beamchain_mempool:get_info(),
    MempoolSize = maps:get(size, MempoolInfo, 0),

    Body = io_lib:format(
        "# HELP bitcoin_blocks_total Current block height~n"
        "# TYPE bitcoin_blocks_total gauge~n"
        "bitcoin_blocks_total ~B~n"
        "# HELP bitcoin_peers_connected Number of connected peers~n"
        "# TYPE bitcoin_peers_connected gauge~n"
        "bitcoin_peers_connected ~B~n"
        "# HELP bitcoin_mempool_size Mempool transaction count~n"
        "# TYPE bitcoin_mempool_size gauge~n"
        "bitcoin_mempool_size ~B~n",
        [Height, Peers, MempoolSize]),

    Req = cowboy_req:reply(200,
        #{<<"content-type">> => <<"text/plain; version=0.0.4; charset=utf-8">>},
        iolist_to_binary(Body), Req0),
    {ok, Req, CowboyState}.
