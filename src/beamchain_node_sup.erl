-module(beamchain_node_sup).
-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

-define(SERVER, ?MODULE).

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

init([]) ->
    SupFlags = #{
        strategy => rest_for_one,
        intensity => 5,
        period => 10
    },
    %% Core children always started
    CoreChildren = [
        child_spec(beamchain_db, worker),
        child_spec(beamchain_sig_cache, worker),
        child_spec(beamchain_chainstate_sup, supervisor),
        child_spec(beamchain_mempool, worker),
        child_spec(beamchain_erlay, worker),
        child_spec(beamchain_fee_estimator, worker),
        child_spec(beamchain_addrman, worker),
        child_spec(beamchain_peer_manager, worker),
        child_spec(beamchain_header_sync, worker),
        child_spec(beamchain_block_sync, worker),
        child_spec(beamchain_sync, worker),
        child_spec(beamchain_miner, worker),
        child_spec(beamchain_wallet, worker),
        child_spec(beamchain_rpc, worker),
        child_spec(beamchain_rest, worker)
    ],
    %% Optional ZMQ notifications (only if configured)
    ZmqChildren = case beamchain_config:zmq_enabled() of
        true -> [child_spec(beamchain_zmq, worker)];
        false -> []
    end,
    Children = CoreChildren ++ ZmqChildren,
    {ok, {SupFlags, Children}}.

child_spec(Module, Type) ->
    #{
        id => Module,
        start => {Module, start_link, []},
        restart => permanent,
        type => Type,
        modules => [Module]
    }.
