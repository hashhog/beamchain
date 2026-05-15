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
        child_spec(beamchain_wallet_sup, supervisor),
        child_spec(beamchain_wallet, worker),
        child_spec(beamchain_rpc, worker),
        child_spec(beamchain_metrics, worker)
    ],
    %% Optional REST HTTP server (default off, matches Bitcoin Core's
    %% -rest=0).  Enable with rest=1 in beamchain.conf or
    %% BEAMCHAIN_REST=1.  When disabled, the listener is never bound and
    %% no /rest/* HTTP traffic is accepted.
    RestChildren = case beamchain_config:rest_enabled() of
        true  -> [child_spec(beamchain_rest, worker)];
        false -> []
    end,
    %% Optional ZMQ notifications (only if configured)
    ZmqChildren = case beamchain_config:zmq_enabled() of
        true -> [child_spec(beamchain_zmq, worker)];
        false -> []
    end,
    %% Optional BIP-157/158 compact block filter index (default off).
    %% When disabled, the gen_server is NOT started — keeping the
    %% default fleet behavior identical for users who have not opted
    %% in (no extra RocksDB instance, no NODE_COMPACT_FILTERS bit).
    BlockFilterChildren =
        case beamchain_config:blockfilterindex_enabled() of
            true -> [child_spec(beamchain_blockfilter_index, worker)];
            false -> []
        end,
    %% Optional Tor control-port client for v3 hidden-service inbound.
    %% Only started when listenonion=1 in beamchain.conf or
    %% BEAMCHAIN_LISTENONION=1 in the environment.  The client connects
    %% to the Tor control port (default 127.0.0.1:9051), runs the
    %% PROTOCOLINFO -> AUTHENTICATE -> ADD_ONION sequence, persists the
    %% returned ED25519-V3 private key under <datadir>/tor_v3_secret_key
    %% and advertises the resulting .onion via getnetworkinfo.
    %% Mirrors bitcoin-core/src/torcontrol.cpp StartTorControl.
    TorControlChildren =
        case beamchain_config:listen_onion() of
            true  -> [child_spec(beamchain_torcontrol, worker)];
            false -> []
        end,
    Children = CoreChildren ++ RestChildren ++ ZmqChildren
               ++ BlockFilterChildren ++ TorControlChildren,
    {ok, {SupFlags, Children}}.

child_spec(Module, Type) ->
    #{
        id => Module,
        start => {Module, start_link, []},
        restart => permanent,
        type => Type,
        modules => [Module]
    }.
