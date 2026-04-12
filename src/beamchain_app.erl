-module(beamchain_app).
-behaviour(application).
-behaviour(gen_event).

-export([start/2, stop/1]).

%% gen_event callbacks for our erl_signal_server handler.
-export([init/1, handle_event/2, handle_call/2, handle_info/2,
         terminate/2, code_change/3]).

start(_StartType, _StartArgs) ->
    %% Initialize the versionbits ETS cache before any RPC can query
    %% deployment state.  Without this, build_deployment_map/3 (used by
    %% getblockchaininfo and getdeploymentinfo) crashes with badarg on
    %% networks that have live BIP9 deployments (mainnet, testnet,
    %% testnet4) because ets:lookup/2 is called on a missing table.
    beamchain_versionbits:init_cache(),
    install_signal_handlers(),
    beamchain_sup:start_link().

stop(_State) ->
    ok.

%% ----------------------------------------------------------------
%% Signal handling
%% ----------------------------------------------------------------
%%
%% Replace OTP's default erl_signal_handler with our own gen_event
%% handler so SIGTERM/SIGINT run beamchain_chainstate:terminate/2 (and
%% therefore flush the UTXO cache) before the VM halts.  The default
%% handler calls init:stop/0 directly which, in escript-hosted nodes,
%% can race the supervision-tree shutdown and skip terminate/2.
install_signal_handlers() ->
    %% Only SIGTERM is configurable via os:set_signal/2 on most OTP
    %% versions — SIGINT handling is fixed by the runtime.  That is
    %% fine: we only need SIGTERM for `kill` / systemd shutdowns.
    ok = os:set_signal(sigterm, handle),
    %% Swap handlers: remove the default, add ours.  If the default is
    %% already absent (some embedded setups) the swap still installs us.
    _ = gen_event:swap_handler(erl_signal_server,
                               {erl_signal_handler, []},
                               {?MODULE, []}),
    ok.

%% gen_event callbacks — run inside erl_signal_server's process, so
%% they must be fast.  We spawn a short-lived process to do the actual
%% shutdown work (flush chainstate, stop application, halt VM).
init(_Args) ->
    {ok, #{}}.

handle_event(sigterm, State) ->
    spawn(fun() -> graceful_shutdown_on_signal(sigterm) end),
    {ok, State};
handle_event(_Other, State) ->
    {ok, State}.

handle_call(_Req, State) ->
    {ok, ok, State}.

handle_info(_Info, State) ->
    {ok, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_Old, State, _Extra) ->
    {ok, State}.

graceful_shutdown_on_signal(Sig) ->
    logger:notice("beamchain: ~p received, running graceful shutdown", [Sig]),
    try beamchain_chainstate:flush()
    catch _:_ -> ok end,
    _ = application:stop(beamchain),
    init:stop().
