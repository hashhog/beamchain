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
        shutdown => 30000,
        type => worker,
        modules => [beamchain_chainstate]
    },
    supervisor:start_child(?SERVER, ChildSpec).

%% @doc DEPRECATED. The historical (genesis->base) re-derivation no longer
%% runs as a `beamchain_chainstate` gen_server: that design registered
%% under the same name and reused the active chainstate's UTXO ETS tables
%% (a hash-of-self). The real background validation now lives in
%% beamchain_bg_validation, which owns a SEPARATE private coins store with
%% an aliasing guard (see beamchain_chainstate:start_background_validation/1).
%% Kept exported for API stability; it is a no-op and MUST NOT be used to
%% spin up a coins-aliasing chainstate.
-spec start_background_chainstate() -> {error, term()}.
start_background_chainstate() ->
    {error, deprecated_use_beamchain_bg_validation}.

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

%% @doc Complete background validation for the active snapshot. Mirrors
%% Core MaybeCompleteSnapshotValidation (validation.cpp:5967): at the
%% snapshot base, the SEPARATE background coins store's HASH_SERIALIZED is
%% compared to au_data. On match the background chainstate is retired.
%%
%% This now delegates to the REAL engine (beamchain_bg_validation), which
%% re-derives genesis->base in its own private coins store and compares the
%% recomputed commitment to au_data.hash_serialized. The previous
%% implementation hashed a background "chainstate" that aliased the active
%% UTXO ETS tables (a hash-of-self) and never actually replayed any block;
%% that path is gone.
-spec merge_chainstates() -> ok | {error, term()}.
merge_chainstates() ->
    case verify_background_complete() of
        ok ->
            %% Retire the (now-validated) background chainstate, if any.
            _ = stop_background_chainstate(),
            logger:info("chainstate_sup: background validation complete, "
                        "snapshot VALIDATED"),
            ok;
        {error, Reason} ->
            {error, Reason}
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

    %% Start the main chainstate by default.
    %% shutdown=30000: give terminate/2 enough time to flush the UTXO
    %% cache and any in-progress block to disk on SIGTERM.  The default
    %% 5000 ms is not enough for large caches and caused a regression
    %% where the last ~42 blocks had to be replayed on restart.
    MainChainstate = #{
        id => beamchain_chainstate,
        start => {beamchain_chainstate, start_link, []},
        restart => permanent,
        shutdown => 30000,
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

%% Run the REAL background validation for the active snapshot height and
%% return ok on a HASH_SERIALIZED match, {error, _} otherwise. The
%% re-derivation happens in beamchain_bg_validation's SEPARATE store (with
%% its aliasing guard), so this is never a hash-of-self.
verify_background_complete() ->
    Network = beamchain_config:network(),
    case beamchain_chainstate:get_snapshot_base_height() of
        {ok, BaseHeight} ->
            case beamchain_bg_validation:run(Network, BaseHeight) of
                {validated, _Hash} ->
                    ok;
                {invalid, Computed, Expected} ->
                    {error, {utxo_hash_mismatch, BaseHeight, Computed, Expected}};
                {error, Reason} ->
                    {error, Reason}
            end;
        not_snapshot ->
            {error, no_active_snapshot}
    end.
