-module(beamchain_erlay).
-behaviour(gen_server).

%% BIP330 Erlay transaction reconciliation.
%%
%% Erlay is a bandwidth-efficient transaction relay protocol that uses
%% set reconciliation instead of flooding inv messages. This module
%% implements the BIP330 specification.
%%
%% High-level protocol:
%%   1. During handshake, peers exchange sendtxrcncl messages with version + salt
%%   2. Each peer maintains a "reconciliation set" of short txids (32-bit)
%%   3. Periodically, the initiator (outbound peer) requests a sketch (reqrecon)
%%   4. Responder sends sketch, initiator computes symmetric difference
%%   5. Missing txs are requested via reqtx, extra txs announced via reconcildiff
%%   6. Flood relay only to ~8 outbound peers; reconcile with the rest
%%
%% Short txid computation (BIP330):
%%   salt = SHA256(TaggedHash("Tx Relay Salting") || min(salt1,salt2) || max(salt1,salt2))
%%   k0, k1 = first two 64-bit words of salt
%%   short_txid = truncate32(SipHash-2-4(k0, k1, wtxid))

-include("beamchain.hrl").

%% API
-export([start_link/0]).

%% Peer registration
-export([pre_register_peer/1, register_peer/4, forget_peer/1, is_peer_registered/1]).

%% Reconciliation set management
-export([add_tx_to_set/2, remove_tx_from_set/2, clear_set/1]).

%% Short txid computation
-export([compute_short_txid/3]).

%% Protocol message handling
-export([handle_sendtxrcncl/3, handle_reqrecon/2, handle_reconcildiff/2]).

%% Protocol info
-export([version/0, recon_static_salt/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-define(SERVER, ?MODULE).

%% BIP330 constants
-define(TXRECONCILIATION_VERSION, 1).
-define(RECON_STATIC_SALT, <<"Tx Relay Salting">>).

%% Reconciliation intervals (milliseconds)
-define(RECON_INTERVAL_OUTBOUND_MS, 2000).   %% 2 seconds for outbound (we initiate)
-define(RECON_INTERVAL_INBOUND_MS, 8000).    %% 8 seconds for inbound (they initiate)

%% Minisketch parameters
-define(SKETCH_BITS, 32).       %% 32-bit elements
-define(SKETCH_CAPACITY, 32).   %% Initial sketch capacity

%% Maximum flood peers (rest use reconciliation)
-define(MAX_FLOOD_PEERS, 8).

%%% -------------------------------------------------------------------
%%% Peer reconciliation state
%%% -------------------------------------------------------------------

-record(peer_recon_state, {
    peer_id          :: pid(),
    we_initiate      :: boolean(),       %% true if we're outbound (initiator)
    k0               :: non_neg_integer(),%% first 64-bit salt word
    k1               :: non_neg_integer(),%% second 64-bit salt word
    recon_set = []   :: [non_neg_integer()],%% short txids pending reconciliation
    last_recon_time  :: non_neg_integer() | undefined,
    timer_ref        :: reference() | undefined
}).

%%% -------------------------------------------------------------------
%%% gen_server state
%%% -------------------------------------------------------------------

-record(state, {
    %% Pre-registered peers (peer_id -> local_salt)
    pre_registered = #{} :: #{pid() => non_neg_integer()},

    %% Fully registered peers (peer_id -> #peer_recon_state{})
    peers = #{} :: #{pid() => #peer_recon_state{}},

    %% Flood peers (subset that receives inv messages)
    flood_peers = [] :: [pid()]
}).

%%% ===================================================================
%%% API
%%% ===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc Pre-register a peer for reconciliation. Called during VERSION handling.
%% Returns the local salt to include in sendtxrcncl message.
-spec pre_register_peer(pid()) -> non_neg_integer().
pre_register_peer(PeerId) ->
    gen_server:call(?SERVER, {pre_register, PeerId}).

%% @doc Register a peer after receiving their sendtxrcncl message.
%% IsPeerInbound: true if peer connected to us (we respond, they initiate)
%% PeerVersion: reconciliation protocol version from peer
%% RemoteSalt: salt from peer's sendtxrcncl message
-spec register_peer(pid(), boolean(), non_neg_integer(), non_neg_integer()) ->
    ok | {error, term()}.
register_peer(PeerId, IsPeerInbound, PeerVersion, RemoteSalt) ->
    gen_server:call(?SERVER, {register, PeerId, IsPeerInbound, PeerVersion, RemoteSalt}).

%% @doc Forget a peer's reconciliation state (called on disconnect).
-spec forget_peer(pid()) -> ok.
forget_peer(PeerId) ->
    gen_server:cast(?SERVER, {forget, PeerId}).

%% @doc Check if a peer is fully registered for reconciliation.
-spec is_peer_registered(pid()) -> boolean().
is_peer_registered(PeerId) ->
    gen_server:call(?SERVER, {is_registered, PeerId}).

%% @doc Add a transaction to a peer's reconciliation set.
%% The wtxid is converted to a short txid using the peer's salt.
-spec add_tx_to_set(pid(), binary()) -> ok.
add_tx_to_set(PeerId, Wtxid) when byte_size(Wtxid) =:= 32 ->
    gen_server:cast(?SERVER, {add_tx, PeerId, Wtxid}).

%% @doc Remove a transaction from a peer's reconciliation set.
-spec remove_tx_from_set(pid(), binary()) -> ok.
remove_tx_from_set(PeerId, Wtxid) when byte_size(Wtxid) =:= 32 ->
    gen_server:cast(?SERVER, {remove_tx, PeerId, Wtxid}).

%% @doc Clear a peer's reconciliation set (after successful reconciliation).
-spec clear_set(pid()) -> ok.
clear_set(PeerId) ->
    gen_server:cast(?SERVER, {clear_set, PeerId}).

%% @doc Compute a 32-bit short txid from a wtxid using the peer's salt keys.
-spec compute_short_txid(non_neg_integer(), non_neg_integer(), binary()) ->
    non_neg_integer().
compute_short_txid(K0, K1, Wtxid) when byte_size(Wtxid) =:= 32 ->
    %% SipHash-2-4 the wtxid, truncate to 32 bits
    Hash = beamchain_crypto:siphash_uint256(K0, K1, Wtxid),
    Hash band 16#ffffffff.

%% @doc Handle incoming sendtxrcncl message from peer.
%% Called from beamchain_peer during handshake.
-spec handle_sendtxrcncl(pid(), non_neg_integer(), non_neg_integer()) ->
    ok | {error, term()}.
handle_sendtxrcncl(PeerId, Version, Salt) ->
    gen_server:call(?SERVER, {sendtxrcncl, PeerId, Version, Salt}).

%% @doc Handle incoming reqrecon message (request for sketch).
%% Returns the sketch to send back to the peer.
-spec handle_reqrecon(pid(), map()) -> {ok, binary()} | {error, term()}.
handle_reqrecon(PeerId, Msg) ->
    gen_server:call(?SERVER, {reqrecon, PeerId, Msg}).

%% @doc Handle incoming reconcildiff message (sketch difference).
%% Returns list of txids to request and txids to announce.
-spec handle_reconcildiff(pid(), map()) -> {ok, {[binary()], [binary()]}} | {error, term()}.
handle_reconcildiff(PeerId, Msg) ->
    gen_server:call(?SERVER, {reconcildiff, PeerId, Msg}).

%%% ===================================================================
%%% gen_server callbacks
%%% ===================================================================

init([]) ->
    logger:info("erlay: initialized"),
    {ok, #state{}}.

handle_call({pre_register, PeerId}, _From, State) ->
    %% Generate random 64-bit local salt
    LocalSalt = generate_salt(),
    PreReg = maps:put(PeerId, LocalSalt, State#state.pre_registered),
    logger:debug("erlay: pre-registered peer ~p", [PeerId]),
    {reply, LocalSalt, State#state{pre_registered = PreReg}};

handle_call({register, PeerId, IsPeerInbound, PeerVersion, RemoteSalt}, _From, State) ->
    case maps:get(PeerId, State#state.pre_registered, undefined) of
        undefined ->
            {reply, {error, not_found}, State};
        LocalSalt ->
            %% Check protocol version
            ReconVersion = min(PeerVersion, ?TXRECONCILIATION_VERSION),
            case ReconVersion < 1 of
                true ->
                    {reply, {error, protocol_violation}, State};
                false ->
                    %% Compute full salt
                    {K0, K1} = compute_salt(LocalSalt, RemoteSalt),

                    %% Create peer state
                    %% we_initiate = true for outbound connections (not inbound)
                    WeInitiate = not IsPeerInbound,
                    PeerState = #peer_recon_state{
                        peer_id = PeerId,
                        we_initiate = WeInitiate,
                        k0 = K0,
                        k1 = K1
                    },

                    %% Remove from pre-registered, add to peers
                    PreReg = maps:remove(PeerId, State#state.pre_registered),
                    Peers = maps:put(PeerId, PeerState, State#state.peers),

                    %% Maybe add to flood peers
                    FloodPeers = maybe_add_flood_peer(PeerId, WeInitiate, State#state.flood_peers),

                    %% Schedule reconciliation timer if we initiate
                    PeerState2 = maybe_schedule_recon_timer(PeerState),
                    Peers2 = maps:put(PeerId, PeerState2, Peers),

                    logger:debug("erlay: registered peer ~p (we_initiate=~p)",
                                 [PeerId, WeInitiate]),
                    {reply, ok, State#state{
                        pre_registered = PreReg,
                        peers = Peers2,
                        flood_peers = FloodPeers
                    }}
            end
    end;

handle_call({is_registered, PeerId}, _From, State) ->
    {reply, maps:is_key(PeerId, State#state.peers), State};

handle_call({sendtxrcncl, PeerId, Version, RemoteSalt}, From, State) ->
    %% This is an alias for register_peer called from message handler
    %% Determine if peer is inbound based on pre-registration
    %% (pre-registration happens during VERSION message, before sendtxrcncl)
    case maps:is_key(PeerId, State#state.pre_registered) of
        true ->
            %% We pre-registered first, so we sent VERSION first, so peer is inbound
            handle_call({register, PeerId, true, Version, RemoteSalt}, From, State);
        false ->
            %% Not pre-registered means we didn't initiate - but this shouldn't happen
            {reply, {error, not_pre_registered}, State}
    end;

handle_call({reqrecon, PeerId, _Msg}, _From, State) ->
    case maps:get(PeerId, State#state.peers, undefined) of
        undefined ->
            {reply, {error, not_registered}, State};
        PeerState ->
            %% Build sketch from our reconciliation set
            Sketch = build_sketch(PeerState#peer_recon_state.recon_set),
            {reply, {ok, Sketch}, State}
    end;

handle_call({reconcildiff, PeerId, Msg}, _From, State) ->
    case maps:get(PeerId, State#state.peers, undefined) of
        undefined ->
            {reply, {error, not_registered}, State};
        PeerState ->
            %% Decode peer's sketch and compute difference
            case decode_and_reconcile(PeerState, Msg) of
                {ok, ToRequest, ToAnnounce} ->
                    %% Clear our set after successful reconciliation
                    PeerState2 = PeerState#peer_recon_state{
                        recon_set = [],
                        last_recon_time = erlang:system_time(millisecond)
                    },
                    Peers = maps:put(PeerId, PeerState2, State#state.peers),
                    {reply, {ok, {ToRequest, ToAnnounce}}, State#state{peers = Peers}};
                {error, _} = Err ->
                    {reply, Err, State}
            end
    end;

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast({forget, PeerId}, State) ->
    %% Cancel any pending timer
    case maps:get(PeerId, State#state.peers, undefined) of
        undefined -> ok;
        #peer_recon_state{timer_ref = Ref} when Ref =/= undefined ->
            erlang:cancel_timer(Ref);
        _ -> ok
    end,
    PreReg = maps:remove(PeerId, State#state.pre_registered),
    Peers = maps:remove(PeerId, State#state.peers),
    FloodPeers = lists:delete(PeerId, State#state.flood_peers),
    {noreply, State#state{
        pre_registered = PreReg,
        peers = Peers,
        flood_peers = FloodPeers
    }};

handle_cast({add_tx, PeerId, Wtxid}, State) ->
    case maps:get(PeerId, State#state.peers, undefined) of
        undefined ->
            {noreply, State};
        PeerState ->
            ShortTxid = compute_short_txid(
                PeerState#peer_recon_state.k0,
                PeerState#peer_recon_state.k1,
                Wtxid),
            Set = PeerState#peer_recon_state.recon_set,
            %% Add to set if not already present
            Set2 = case lists:member(ShortTxid, Set) of
                true -> Set;
                false -> [ShortTxid | Set]
            end,
            PeerState2 = PeerState#peer_recon_state{recon_set = Set2},
            Peers = maps:put(PeerId, PeerState2, State#state.peers),
            {noreply, State#state{peers = Peers}}
    end;

handle_cast({remove_tx, PeerId, Wtxid}, State) ->
    case maps:get(PeerId, State#state.peers, undefined) of
        undefined ->
            {noreply, State};
        PeerState ->
            ShortTxid = compute_short_txid(
                PeerState#peer_recon_state.k0,
                PeerState#peer_recon_state.k1,
                Wtxid),
            Set = lists:delete(ShortTxid, PeerState#peer_recon_state.recon_set),
            PeerState2 = PeerState#peer_recon_state{recon_set = Set},
            Peers = maps:put(PeerId, PeerState2, State#state.peers),
            {noreply, State#state{peers = Peers}}
    end;

handle_cast({clear_set, PeerId}, State) ->
    case maps:get(PeerId, State#state.peers, undefined) of
        undefined ->
            {noreply, State};
        PeerState ->
            PeerState2 = PeerState#peer_recon_state{recon_set = []},
            Peers = maps:put(PeerId, PeerState2, State#state.peers),
            {noreply, State#state{peers = Peers}}
    end;

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({recon_timer, PeerId}, State) ->
    %% Time to initiate reconciliation with this peer
    case maps:get(PeerId, State#state.peers, undefined) of
        undefined ->
            {noreply, State};
        PeerState ->
            case PeerState#peer_recon_state.we_initiate of
                true ->
                    %% Send reqrecon message to peer
                    initiate_reconciliation(PeerId, PeerState),
                    %% Schedule next reconciliation
                    PeerState2 = schedule_recon_timer(PeerState),
                    Peers = maps:put(PeerId, PeerState2, State#state.peers),
                    {noreply, State#state{peers = Peers}};
                false ->
                    %% We shouldn't be initiating if we're not the initiator
                    {noreply, State}
            end
    end;

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

%%% ===================================================================
%%% Internal: Salt computation (BIP330)
%%% ===================================================================

%% Generate a random 64-bit salt
-spec generate_salt() -> non_neg_integer().
generate_salt() ->
    <<Salt:64>> = crypto:strong_rand_bytes(8),
    Salt.

%% Compute the full salt from local and remote salts (BIP330)
%% Returns {K0, K1} - the two 64-bit SipHash keys
-spec compute_salt(non_neg_integer(), non_neg_integer()) ->
    {non_neg_integer(), non_neg_integer()}.
compute_salt(LocalSalt, RemoteSalt) ->
    %% Sort salts in ascending order per BIP330
    {Salt1, Salt2} = case LocalSalt < RemoteSalt of
        true -> {LocalSalt, RemoteSalt};
        false -> {RemoteSalt, LocalSalt}
    end,

    %% TaggedHash("Tx Relay Salting") || salt1 || salt2
    TagHash = beamchain_crypto:sha256(?RECON_STATIC_SALT),
    Data = <<TagHash/binary, TagHash/binary, Salt1:64/little, Salt2:64/little>>,
    FullSalt = beamchain_crypto:sha256(Data),

    %% Extract K0 and K1 (first 128 bits = first 16 bytes)
    <<K0:64/little, K1:64/little, _/binary>> = FullSalt,
    {K0, K1}.

%%% ===================================================================
%%% Internal: Flood peer management
%%% ===================================================================

%% Add peer to flood set if we have room and it's outbound
maybe_add_flood_peer(PeerId, WeInitiate, FloodPeers) ->
    case WeInitiate andalso length(FloodPeers) < ?MAX_FLOOD_PEERS of
        true ->
            [PeerId | FloodPeers];
        false ->
            FloodPeers
    end.

%%% ===================================================================
%%% Internal: Reconciliation timer
%%% ===================================================================

maybe_schedule_recon_timer(#peer_recon_state{we_initiate = true} = PeerState) ->
    schedule_recon_timer(PeerState);
maybe_schedule_recon_timer(PeerState) ->
    PeerState.

schedule_recon_timer(#peer_recon_state{peer_id = PeerId, timer_ref = OldRef} = PeerState) ->
    %% Cancel any existing timer
    case OldRef of
        undefined -> ok;
        _ -> erlang:cancel_timer(OldRef)
    end,
    %% Schedule with Poisson-distributed interval
    Interval = poisson_interval(?RECON_INTERVAL_OUTBOUND_MS),
    Ref = erlang:send_after(Interval, self(), {recon_timer, PeerId}),
    PeerState#peer_recon_state{timer_ref = Ref}.

%% Poisson-distributed interval: -ln(U) * mean
poisson_interval(MeanMs) ->
    U = rand:uniform(),
    Interval = round(-math:log(U) * MeanMs),
    %% Clamp to reasonable bounds
    max(100, min(Interval, 30000)).

%%% ===================================================================
%%% Internal: Minisketch operations
%%% ===================================================================

%% Build a Minisketch from a set of short txids
%% Returns serialized sketch binary
-spec build_sketch([non_neg_integer()]) -> binary().
build_sketch(ShortTxids) ->
    %% Compute capacity needed
    Capacity = max(?SKETCH_CAPACITY, length(ShortTxids) + 1),

    %% Create sketch and add elements
    case beamchain_minisketch:create(?SKETCH_BITS, Capacity) of
        {ok, Sketch} ->
            lists:foreach(fun(Txid) ->
                beamchain_minisketch:add(Sketch, Txid)
            end, ShortTxids),
            {ok, Data} = beamchain_minisketch:serialize(Sketch),
            beamchain_minisketch:destroy(Sketch),
            Data;
        {error, _} ->
            %% Fallback: return empty sketch
            <<>>
    end.

%% Decode peer's sketch and compute set difference
-spec decode_and_reconcile(#peer_recon_state{}, map()) ->
    {ok, [binary()], [binary()]} | {error, term()}.
decode_and_reconcile(PeerState, #{sketch := PeerSketchData,
                                   set_size := _PeerSetSize}) ->
    OurSet = PeerState#peer_recon_state.recon_set,

    %% Build our sketch
    OurSketchData = build_sketch(OurSet),

    %% Merge sketches (XOR) to get symmetric difference
    case merge_sketches(OurSketchData, PeerSketchData) of
        {ok, DiffElements} ->
            %% DiffElements are the short txids that differ
            %% Elements in DiffElements that are in OurSet = peer is missing
            %% Elements in DiffElements that are NOT in OurSet = we are missing
            OurSetMap = sets:from_list(OurSet),
            {Missing, Extra} = lists:partition(fun(E) ->
                not sets:is_element(E, OurSetMap)
            end, DiffElements),

            %% TODO: Map short txids back to full wtxids
            %% For now, return empty lists (caller needs to resolve)
            {ok, Missing, Extra};
        {error, _} = Err ->
            Err
    end;
decode_and_reconcile(_, _) ->
    {error, invalid_message}.

%% Merge two serialized sketches (XOR operation)
-spec merge_sketches(binary(), binary()) -> {ok, [non_neg_integer()]} | {error, term()}.
merge_sketches(Sketch1Data, Sketch2Data) when byte_size(Sketch1Data) =:= byte_size(Sketch2Data) ->
    %% XOR the sketch data
    MergedData = xor_binary(Sketch1Data, Sketch2Data),

    %% Deserialize and decode
    Capacity = byte_size(MergedData) div 4,  %% 32-bit elements = 4 bytes each
    case beamchain_minisketch:create(?SKETCH_BITS, max(1, Capacity)) of
        {ok, Sketch} ->
            beamchain_minisketch:deserialize(Sketch, MergedData),
            Result = beamchain_minisketch:decode(Sketch, Capacity),
            beamchain_minisketch:destroy(Sketch),
            Result;
        {error, _} = Err ->
            Err
    end;
merge_sketches(_, _) ->
    {error, sketch_size_mismatch}.

%% XOR two binaries of equal length
xor_binary(<<>>, <<>>) -> <<>>;
xor_binary(<<A:8, RestA/binary>>, <<B:8, RestB/binary>>) ->
    C = A bxor B,
    Rest = xor_binary(RestA, RestB),
    <<C:8, Rest/binary>>.

%%% ===================================================================
%%% Internal: Reconciliation initiation
%%% ===================================================================

%% Initiate reconciliation by sending reqrecon to peer
initiate_reconciliation(PeerId, PeerState) ->
    %% Build our sketch
    SketchData = build_sketch(PeerState#peer_recon_state.recon_set),
    SetSize = length(PeerState#peer_recon_state.recon_set),

    %% Send reqrecon message
    %% The message format: set_size (u16) + q (u16) + sketch
    %% q is a coefficient for expected diff estimation
    Q = estimate_q(SetSize),
    Msg = #{set_size => SetSize, q => Q, sketch => SketchData},

    %% Send to peer via beamchain_peer
    case is_process_alive(PeerId) of
        true ->
            beamchain_peer:send_message(PeerId, {reqrecon, Msg});
        false ->
            ok
    end.

%% Estimate the Q parameter (expected set difference / set size)
estimate_q(_SetSize) ->
    %% Default Q value - can be tuned based on network conditions
    %% Higher Q = more capacity for differences
    16.

%% @doc Get the supported reconciliation protocol version.
-spec version() -> non_neg_integer().
version() -> ?TXRECONCILIATION_VERSION.

%% @doc Get the static salt tag used for short txid computation.
-spec recon_static_salt() -> binary().
recon_static_salt() -> ?RECON_STATIC_SALT.
