-module(beamchain_chainstate_sup).
-behaviour(supervisor).

%% Supervisor for chainstate processes.
%% Manages two concurrent chainstates for assumeUTXO:
%%   - snapshot_chainstate: validates from snapshot height forward
%%   - background_chainstate: validates from genesis (background validation)
%%
%% The main chainstate is started by default. When a snapshot is loaded,
%% the background chainstate is started to validate the historical chain.

-export([start_link/0]).
-export([init/1]).
-export([start_snapshot_chainstate/1, start_background_chainstate/0]).
-export([stop_background_chainstate/0]).
-export([get_active_chainstate/0, get_background_chainstate/0]).
-export([merge_chainstates/0]).

-define(SERVER, ?MODULE).

%%% ===================================================================
%%% API
%%% ===================================================================

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%% @doc Start the snapshot chainstate with coins from a loaded snapshot.
%% This chainstate will handle new blocks from the snapshot height forward.
-spec start_snapshot_chainstate(#{base_hash := binary(),
                                   num_coins := non_neg_integer(),
                                   coins := list()}) ->
    {ok, pid()} | {error, term()}.
start_snapshot_chainstate(SnapshotData) ->
    ChildSpec = #{
        id => beamchain_chainstate_snapshot,
        start => {beamchain_chainstate, start_link, [snapshot, SnapshotData]},
        restart => transient,
        type => worker,
        modules => [beamchain_chainstate]
    },
    supervisor:start_child(?SERVER, ChildSpec).

%% @doc Start the background chainstate for historical validation.
%% This chainstate validates from genesis to the snapshot height.
-spec start_background_chainstate() -> {ok, pid()} | {error, term()}.
start_background_chainstate() ->
    ChildSpec = #{
        id => beamchain_chainstate_background,
        start => {beamchain_chainstate, start_link, [background]},
        restart => transient,
        type => worker,
        modules => [beamchain_chainstate]
    },
    supervisor:start_child(?SERVER, ChildSpec).

%% @doc Stop the background validation chainstate.
%% Called when background validation completes or is no longer needed.
-spec stop_background_chainstate() -> ok | {error, term()}.
stop_background_chainstate() ->
    case supervisor:terminate_child(?SERVER, beamchain_chainstate_background) of
        ok ->
            supervisor:delete_child(?SERVER, beamchain_chainstate_background);
        {error, not_found} ->
            ok;
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc Get the active (main) chainstate process.
%% During normal operation, this is the standard chainstate.
%% During snapshot sync, this is the snapshot chainstate.
-spec get_active_chainstate() -> pid() | undefined.
get_active_chainstate() ->
    %% Check for snapshot chainstate first (it takes precedence)
    case get_child_pid(beamchain_chainstate_snapshot) of
        undefined ->
            get_child_pid(beamchain_chainstate);
        Pid ->
            Pid
    end.

%% @doc Get the background validation chainstate process, if running.
-spec get_background_chainstate() -> pid() | undefined.
get_background_chainstate() ->
    get_child_pid(beamchain_chainstate_background).

%% @doc Merge snapshot and background chainstates after validation.
%% Called when background chainstate reaches the snapshot height
%% and its UTXO hash matches the expected value.
-spec merge_chainstates() -> ok | {error, term()}.
merge_chainstates() ->
    case get_background_chainstate() of
        undefined ->
            {error, no_background_chainstate};
        _BgPid ->
            %% Verify the background chainstate has caught up
            %% and its UTXO hash matches
            case verify_background_complete() of
                ok ->
                    %% Stop the background chainstate
                    ok = stop_background_chainstate(),
                    logger:info("chainstate_sup: background validation complete, "
                                "merged chainstates"),
                    ok;
                {error, Reason} ->
                    {error, Reason}
            end
    end.

%%% ===================================================================
%%% supervisor callbacks
%%% ===================================================================

init([]) ->
    SupFlags = #{
        strategy => one_for_one,
        intensity => 5,
        period => 10
    },

    %% Start the main chainstate by default
    MainChainstate = #{
        id => beamchain_chainstate,
        start => {beamchain_chainstate, start_link, []},
        restart => permanent,
        type => worker,
        modules => [beamchain_chainstate]
    },

    Children = [MainChainstate],

    {ok, {SupFlags, Children}}.

%%% ===================================================================
%%% Internal functions
%%% ===================================================================

get_child_pid(ChildId) ->
    Children = supervisor:which_children(?SERVER),
    case lists:keyfind(ChildId, 1, Children) of
        {ChildId, Pid, _, _} when is_pid(Pid) ->
            Pid;
        _ ->
            undefined
    end.

verify_background_complete() ->
    %% Get the snapshot parameters
    Network = beamchain_config:network(),

    %% Get background chainstate tip
    BgPid = get_background_chainstate(),
    case gen_server:call(BgPid, get_tip_height) of
        {ok, BgHeight} ->
            %% Check if we have snapshot parameters for this height
            case beamchain_chain_params:get_assumeutxo(BgHeight, Network) of
                {ok, #{utxo_hash := ExpectedHash}} ->
                    %% Compute UTXO hash from background chainstate
                    ComputedHash = gen_server:call(BgPid, compute_utxo_hash, 300000),
                    case ComputedHash =:= ExpectedHash of
                        true ->
                            ok;
                        false ->
                            {error, {utxo_hash_mismatch, BgHeight}}
                    end;
                not_found ->
                    {error, {no_snapshot_at_height, BgHeight}}
            end;
        {error, Reason} ->
            {error, Reason}
    end.
