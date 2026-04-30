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
    %% SIGTERM is configurable via os:set_signal/2 on every supported OTP
    %% version — SIGINT handling is fixed by the runtime, which is fine:
    %% we only need SIGTERM for `kill` / systemd shutdowns.
    ok = os:set_signal(sigterm, handle),
    %% SIGHUP: standard daemon convention is "reopen log files" so log
    %% rotation tools (logrotate -postrotate, copytruncate, etc.) can
    %% trigger it without restarting the node.  We rotate the file
    %% handler in handle_event/2 below.  os:set_signal(sighup, handle)
    %% requires OTP 24+ which we already require for everything else.
    ok = os:set_signal(sighup, handle),
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
handle_event(sighup, State) ->
    %% Standard daemon convention: SIGHUP reopens log files so log
    %% rotation tools (logrotate, etc.) can move/truncate the active
    %% file and the node will pick up the new fd. Implemented by
    %% removing and re-adding the file handler the CLI installed.
    %% Spawn so we don't block the signal-server process.
    spawn(fun() -> reopen_log_handlers() end),
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
    %% Best-effort PID cleanup mirrors beamchain_cli:graceful_shutdown/0
    %% so SIGTERM-initiated shutdowns also remove the file. Wrapped in
    %% try/catch because beamchain_cli is loaded only when running as
    %% an escript / release; missing module is harmless here.
    try beamchain_cli:remove_pidfile()
    catch _:_ -> ok end,
    _ = application:stop(beamchain),
    init:stop().

%% @doc SIGHUP: reopen the file handler installed by beamchain_cli's
%% setup_file_logger/0 so log rotation tools can move the active file.
%% logger:remove/add_handler is the documented way to swap; the file
%% path is unchanged so the new handler simply opens a fresh fd.
reopen_log_handlers() ->
    Handlers = [beamchain_file_logger, beamchain_console_logger],
    lists:foreach(fun reopen_one_handler/1, Handlers),
    logger:notice("beamchain: SIGHUP — log handlers reopened"),
    ok.

reopen_one_handler(Id) ->
    case logger:get_handler_config(Id) of
        {ok, Config} ->
            _ = logger:remove_handler(Id),
            Module = maps:get(module, Config, logger_std_h),
            Stripped = maps:without([id, module], Config),
            _ = logger:add_handler(Id, Module, Stripped),
            ok;
        _ ->
            ok
    end.
