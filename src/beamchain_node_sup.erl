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
    Children = case beamchain_config:batch_mode() of
        true  -> batch_children();
        false -> daemon_children()
    end,
    {ok, {SupFlags, Children}}.

%% @private One-shot batch mode (`beamchain import-utxo`): start ONLY the
%% storage + validation core.  A batch job runs offline to completion and
%% then halts, so anything that binds a socket, dials out, or drives sync
%% is at best useless and at worst fatal:
%%
%%   * beamchain_rpc bound the network's DEFAULT RPC port (mainnet 8332)
%%     when no --rpc-port was given, and its bind failure is a hard
%%     start_error -- so on a host already running a node on 8332 the
%%     import died with {listener_bind_failed, rpc, 8332, eaddrinuse}
%%     before reading a single coin.  beamchain_metrics / beamchain_rest
%%     bind listeners the same way.
%%   * beamchain_peer_manager (+ header_sync / block_sync / beamchain_sync
%%     / erlay / addrman) would open a P2P listener and start dialling
%%     mainnet peers for a chain the job is about to halt on.
%%   * beamchain_miner / beamchain_wallet / the optional indexes have no
%%     part in an import.
%%
%% What is kept, and why it is the minimum:
%%   * beamchain_db          -- the RocksDB handle everything below writes to.
%%   * beamchain_sig_cache   -- beamchain_crypto's ECDSA/Schnorr verify path
%%                              looks up this ETS-backed cache directly.
%%   * beamchain_tip_notifier-- must precede beamchain_chainstate_sup (the
%%                              connect/reorg tip-advance chokepoint expects
%%                              it registered); cheap, in-VM, no socket.
%%   * beamchain_chainstate_sup -- the chainstate that actually performs the
%%                              load_snapshot + chunked flush.
%%   * beamchain_mempool     -- load_snapshot's G7 guard calls
%%                              beamchain_mempool:get_info/0 SYNCHRONOUSLY
%%                              (Core validation.cpp:5626, "Can't activate a
%%                              snapshot when mempool not empty"); with no
%%                              mempool that gen_server:call exits noproc.
%%
%% Every other cross-module notification on the connect path
%% (remove_for_block_with_txs_async, fee_estimator:process_block,
%% zmq:notify_block, peer_manager:notify_tip_updated, tip_notifier:notify)
%% is a gen_server:cast, which is silently dropped for an unregistered
%% name, and the wallet / blockfilter / coinstats / txospender hooks are
%% `catch`-wrapped -- so omitting those children is a no-op, not a crash.
batch_children() ->
    [
        child_spec(beamchain_db, worker),
        child_spec(beamchain_sig_cache, worker),
        child_spec(beamchain_tip_notifier, worker),
        child_spec(beamchain_chainstate_sup, supervisor),
        mempool_child_spec()
    ].

%% @private The full node supervision tree -- unchanged daemon behaviour
%% (`beamchain start` / `sync` / `import`).
daemon_children() ->
    %% Core children always started
    CoreChildren = [
        child_spec(beamchain_db, worker),
        child_spec(beamchain_sig_cache, worker),
        %% Tip-change notifier for the wait-family RPCs
        %% (waitfornewblock / waitforblock / waitforblockheight).  Must
        %% precede beamchain_chainstate_sup so the connect/reorg tip-advance
        %% chokepoints always find it registered, and precede beamchain_rpc
        %% so a waiter can subscribe.  No dependencies of its own.
        child_spec(beamchain_tip_notifier, worker),
        child_spec(beamchain_chainstate_sup, supervisor),
        %% Mempool gets an extended shutdown timeout so its terminate/2
        %% has time to dump mempool.dat on graceful shutdown. The default
        %% worker shutdown (5000ms) is normally plenty, but a large
        %% mempool serialize + atomic write can exceed it; a SIGKILL of
        %% the gen_server mid-dump would silently lose the whole mempool.
        %% Pairs with process_flag(trap_exit,true) in beamchain_mempool's
        %% init/1 (without that flag terminate/2 never runs at all).
        mempool_child_spec(),
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
    %% Optional coinstatsindex (default off, matches Core -coinstatsindex).
    %% Must be mounted AFTER beamchain_chainstate_sup (which precedes it in
    %% the rest_for_one child list) so its startup reconcile can read the
    %% chainstate tip. When disabled the gen_server is NOT started, keeping
    %% default fleet behaviour identical (no extra RocksDB instance, no
    %% maintenance overhead on the connect/disconnect path).
    CoinStatsChildren =
        case beamchain_config:coinstatsindex_enabled() of
            true -> [child_spec(beamchain_coinstatsindex, worker)];
            false -> []
        end,
    %% Optional txospenderindex (default off, matches Core -txospenderindex).
    %% Like coinstatsindex, must be mounted AFTER beamchain_chainstate_sup so
    %% its startup reconcile can read the chainstate tip. When disabled the
    %% gen_server is NOT started, keeping default fleet behaviour identical
    %% (no extra RocksDB instance, no maintenance overhead on the
    %% connect/disconnect path). Backs the gettxspendingprevout RPC's
    %% confirmed-spend path.
    TxoSpenderChildren =
        case beamchain_config:txospenderindex_enabled() of
            true -> [child_spec(beamchain_txospenderindex, worker)];
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
    CoreChildren ++ RestChildren ++ ZmqChildren
        ++ BlockFilterChildren ++ CoinStatsChildren
        ++ TxoSpenderChildren
        ++ TorControlChildren.

child_spec(Module, Type) ->
    #{
        id => Module,
        start => {Module, start_link, []},
        restart => permanent,
        type => Type,
        modules => [Module]
    }.

%% Mempool worker with an explicit 30s shutdown timeout (vs the default
%% 5000ms) so terminate/2 can finish dumping mempool.dat on a graceful
%% stop. See the call site above for why.
mempool_child_spec() ->
    (child_spec(beamchain_mempool, worker))#{shutdown => 30000}.
