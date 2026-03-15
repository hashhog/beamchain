-module(beamchain_wallet_sup).
-behaviour(supervisor).

%% Multi-wallet supervisor using simple_one_for_one strategy.
%% Each wallet is a separate gen_server process managed by this supervisor.
%% Wallet processes are registered in an ETS table for name->pid lookup.

-export([start_link/0]).
-export([init/1]).

%% Wallet management API
-export([create_wallet/1, create_wallet/2,
         load_wallet/1, load_wallet/2,
         unload_wallet/1,
         list_wallets/0,
         get_wallet/1]).

-define(SERVER, ?MODULE).
-define(WALLET_REGISTRY, beamchain_wallet_registry).

%%% ===================================================================
%%% API
%%% ===================================================================

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%% @doc Create a new wallet with the given name.
%% Default wallet name is <<>> (empty binary).
-spec create_wallet(binary()) -> {ok, pid()} | {error, term()}.
create_wallet(Name) ->
    create_wallet(Name, undefined).

%% @doc Create a new wallet with name and optional passphrase.
-spec create_wallet(binary(), binary() | undefined) -> {ok, pid()} | {error, term()}.
create_wallet(Name, Passphrase) when is_binary(Name) ->
    case get_wallet(Name) of
        {ok, _Pid} ->
            {error, wallet_already_loaded};
        {error, wallet_not_found} ->
            %% Start a new wallet process
            case supervisor:start_child(?SERVER, [Name]) of
                {ok, Pid} ->
                    %% Register in the wallet registry
                    true = ets:insert(?WALLET_REGISTRY, {Name, Pid}),
                    %% Initialize with a new seed
                    Seed = crypto:strong_rand_bytes(32),
                    case gen_server:call(Pid, {create, Seed, Passphrase}) of
                        {ok, _} ->
                            {ok, Pid};
                        {error, _} = Err ->
                            %% Cleanup on failure
                            supervisor:terminate_child(?SERVER, Pid),
                            ets:delete(?WALLET_REGISTRY, Name),
                            Err
                    end;
                {error, _} = Err ->
                    Err
            end
    end.

%% @doc Load a wallet from file.
-spec load_wallet(binary()) -> {ok, pid()} | {error, term()}.
load_wallet(Name) ->
    load_wallet(Name, undefined).

%% @doc Load a wallet from file with passphrase.
-spec load_wallet(binary(), binary() | undefined) -> {ok, pid()} | {error, term()}.
load_wallet(Name, Passphrase) when is_binary(Name) ->
    case get_wallet(Name) of
        {ok, _Pid} ->
            {error, wallet_already_loaded};
        {error, wallet_not_found} ->
            %% Start a new wallet process
            case supervisor:start_child(?SERVER, [Name]) of
                {ok, Pid} ->
                    %% Register in the wallet registry
                    true = ets:insert(?WALLET_REGISTRY, {Name, Pid}),
                    %% Load from the wallet file
                    FilePath = wallet_file_path(Name),
                    case gen_server:call(Pid, {load, FilePath, Passphrase}) of
                        ok ->
                            {ok, Pid};
                        {error, _} = Err ->
                            %% Cleanup on failure
                            supervisor:terminate_child(?SERVER, Pid),
                            ets:delete(?WALLET_REGISTRY, Name),
                            Err
                    end;
                {error, _} = Err ->
                    Err
            end
    end.

%% @doc Unload a wallet (persist and stop the process).
-spec unload_wallet(binary()) -> ok | {error, term()}.
unload_wallet(Name) when is_binary(Name) ->
    case get_wallet(Name) of
        {ok, Pid} ->
            %% Remove from registry first
            ets:delete(?WALLET_REGISTRY, Name),
            %% Terminate the process (will trigger save in terminate callback)
            supervisor:terminate_child(?SERVER, Pid),
            ok;
        {error, wallet_not_found} ->
            {error, wallet_not_found}
    end.

%% @doc List all loaded wallets.
-spec list_wallets() -> [binary()].
list_wallets() ->
    case ets:whereis(?WALLET_REGISTRY) of
        undefined -> [];
        _ ->
            [Name || {Name, _Pid} <- ets:tab2list(?WALLET_REGISTRY)]
    end.

%% @doc Get the pid for a wallet by name.
-spec get_wallet(binary()) -> {ok, pid()} | {error, wallet_not_found}.
get_wallet(Name) when is_binary(Name) ->
    case ets:whereis(?WALLET_REGISTRY) of
        undefined ->
            {error, wallet_not_found};
        _ ->
            case ets:lookup(?WALLET_REGISTRY, Name) of
                [{Name, Pid}] ->
                    %% Verify process is still alive
                    case is_process_alive(Pid) of
                        true -> {ok, Pid};
                        false ->
                            ets:delete(?WALLET_REGISTRY, Name),
                            {error, wallet_not_found}
                    end;
                [] ->
                    {error, wallet_not_found}
            end
    end.

%%% ===================================================================
%%% Supervisor callbacks
%%% ===================================================================

init([]) ->
    %% Create wallet registry ETS table
    case ets:whereis(?WALLET_REGISTRY) of
        undefined ->
            ets:new(?WALLET_REGISTRY, [named_table, set, public,
                                        {read_concurrency, true}]);
        _ -> ok
    end,

    SupFlags = #{
        strategy => simple_one_for_one,
        intensity => 5,
        period => 60
    },

    ChildSpecs = [
        #{
            id => beamchain_wallet,
            start => {beamchain_wallet, start_link, []},
            restart => temporary,  %% Don't auto-restart wallets
            shutdown => 5000,
            type => worker,
            modules => [beamchain_wallet]
        }
    ],

    {ok, {SupFlags, ChildSpecs}}.

%%% ===================================================================
%%% Internal functions
%%% ===================================================================

%% @doc Get the wallet file path for a given wallet name.
wallet_file_path(<<>>) ->
    %% Default wallet
    wallet_dir() ++ "/wallet.json";
wallet_file_path(Name) when is_binary(Name) ->
    wallet_dir() ++ "/" ++ binary_to_list(Name) ++ ".json".

%% @doc Get the wallet directory for the current network.
wallet_dir() ->
    Network = try beamchain_config:network()
              catch _:_ -> mainnet
              end,
    DataDir = try beamchain_config:datadir()
              catch _:_ -> default_datadir()
              end,
    NetStr = atom_to_list(Network),
    DataDir ++ "/" ++ NetStr ++ "/wallet".

default_datadir() ->
    Home = os:getenv("HOME", "/tmp"),
    Home ++ "/.beamchain".
