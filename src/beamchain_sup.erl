-module(beamchain_sup).
-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

-define(SERVER, ?MODULE).

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

init([]) ->
    SupFlags = #{
        strategy => one_for_one,
        intensity => 5,
        period => 10
    },
    Children = [
        #{
            id => beamchain_config,
            start => {beamchain_config, start_link, []},
            restart => permanent,
            type => worker,
            modules => [beamchain_config]
        },
        #{
            id => beamchain_node_sup,
            start => {beamchain_node_sup, start_link, []},
            restart => permanent,
            type => supervisor,
            modules => [beamchain_node_sup]
        }
    ],
    {ok, {SupFlags, Children}}.
