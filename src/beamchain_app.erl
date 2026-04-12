-module(beamchain_app).
-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    %% Initialize the versionbits ETS cache before any RPC can query
    %% deployment state.  Without this, build_deployment_map/3 (used by
    %% getblockchaininfo and getdeploymentinfo) crashes with badarg on
    %% networks that have live BIP9 deployments (mainnet, testnet,
    %% testnet4) because ets:lookup/2 is called on a missing table.
    beamchain_versionbits:init_cache(),
    beamchain_sup:start_link().

stop(_State) ->
    ok.
