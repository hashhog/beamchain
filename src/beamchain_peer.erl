-module(beamchain_peer).
-behaviour(gen_statem).

%% gen_statem managing a single peer TCP connection.
%%
%% States: connecting -> handshaking -> ready
%%
%% Each peer runs in its own process. Outbound peers do a TCP
%% connect then send a version message. Both sides exchange
%% version + verack to complete the handshake.

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% API
-export([connect/3, accept/3,
         send_message/2, add_misbehavior/2,
         disconnect/1, info/1,
         queue_tx_inv/2]).

%% BIP-324 v2 outbound: per-address v1-only cache + env-var gate.
-export([bip324_v2_outbound_enabled/0,
         mark_v1_only/1, is_v1_only/1,
         clear_v1_only_cache/0]).

%% gen_statem callbacks
-export([callback_mode/0, init/1, terminate/3]).
-export([connecting/3, handshaking/3, ready/3]).

%% Test-only exports (BIP-324 v2 peek-classify helper + initiator
%% state-machine internals).
-ifdef(TEST).
-export([is_v1_version_header/2,
         build_v2_initiator_handshake/2,
         scan_terminator/5,
         extract_v2_packet/1,
         make_test_v2_peer/2]).
-endif.

%%% -------------------------------------------------------------------
%%% Timeouts
%%% -------------------------------------------------------------------

-define(CONNECT_TIMEOUT, 10000).       %% 10 seconds
-define(HANDSHAKE_TIMEOUT, 10000).     %% 10 seconds
-define(PING_INTERVAL, 120000).        %% 2 minutes
-define(PONG_TIMEOUT, 1200000).        %% 20 minutes
-define(INACTIVITY_TIMEOUT, 1800000).  %% 30 minutes

-define(BAN_SCORE, 100).

%%% -------------------------------------------------------------------
%%% BIP 133 feefilter constants
%%% -------------------------------------------------------------------

%% Average delay between feefilter broadcasts (10 minutes)
-define(FEEFILTER_BROADCAST_INTERVAL_MS, 600000).
%% Maximum delay after significant fee change (5 minutes)
-define(FEEFILTER_MAX_CHANGE_DELAY_MS, 300000).
%% Minimum protocol version for feefilter (BIP 133)
-define(FEEFILTER_VERSION, 70013).
%% Default minimum relay fee (1000 sat/kvB = 1 sat/vB)
-define(DEFAULT_MIN_RELAY_FEE, 1000).

%%% -------------------------------------------------------------------
%%% Inv trickling constants (per Bitcoin Core net_processing.cpp)
%%% -------------------------------------------------------------------

%% Average delay between trickled inventory transmissions for inbound peers
-define(INBOUND_INV_INTERVAL_MS, 5000).   %% 5 seconds
%% Average delay for outbound peers (less privacy concern)
-define(OUTBOUND_INV_INTERVAL_MS, 2000).  %% 2 seconds
%% Target number of tx inv items per tick (14/sec * 5s = 70)
-define(INV_BROADCAST_TARGET, 70).
%% Maximum number of tx inv items per tick
-define(INV_BROADCAST_MAX, 1000).

%%% -------------------------------------------------------------------
%%% State data
%%% -------------------------------------------------------------------

-record(peer_data, {
    socket                  :: gen_tcp:socket() | undefined,
    address                 :: {inet:ip_address(), inet:port_number()},
    direction               :: inbound | outbound,
    buffer = <<>>           :: binary(),
    %% Handshake flags
    version_sent = false    :: boolean(),
    version_recv = false    :: boolean(),
    verack_sent = false     :: boolean(),
    verack_recv = false     :: boolean(),
    %% Peer info (from their version message)
    peer_version            :: non_neg_integer() | undefined,
    peer_services = 0       :: non_neg_integer(),
    peer_user_agent = <<>>  :: binary(),
    peer_height = 0         :: integer(),
    peer_relay = true       :: boolean(),
    peer_nonce              :: non_neg_integer() | undefined,
    peer_version_timestamp  :: integer() | undefined,  %% W49 tranche C: peer's nTime from their version msg, for getpeerinfo timeoffset
    %% Feature negotiation
    wants_headers = false   :: boolean(),
    wants_cmpct = false     :: boolean(),
    cmpct_version = 0       :: non_neg_integer(),
    wants_addrv2 = false    :: boolean(),
    wtxidrelay = false      :: boolean(),
    fee_filter = 0          :: non_neg_integer(),
    %% BIP330 Erlay
    erlay_enabled = false   :: boolean(),          %% peer supports erlay
    erlay_local_salt        :: non_neg_integer() | undefined,  %% our salt for sendtxrcncl
    erlay_version = 0       :: non_neg_integer(),  %% negotiated erlay version
    %% Our state
    our_nonce               :: non_neg_integer(),
    magic                   :: binary(),
    handler                 :: pid(),
    handler_mon             :: reference() | undefined,
    %% Stats
    connected_at            :: non_neg_integer() | undefined,
    last_send               :: non_neg_integer() | undefined,
    last_recv               :: non_neg_integer() | undefined,
    last_ping_nonce         :: non_neg_integer() | undefined,
    ping_sent_at            :: non_neg_integer() | undefined,
    latency_ms              :: non_neg_integer() | undefined,
    bytes_sent = 0          :: non_neg_integer(),
    bytes_recv = 0          :: non_neg_integer(),
    misbehavior = 0         :: non_neg_integer(),
    %% Inv trickling (privacy: randomized tx relay)
    pending_tx_inv = []     :: [binary()],  %% txids waiting to be sent
    trickle_timer_ref       :: reference() | undefined,
    %% BIP 133 feefilter
    our_fee_filter = ?DEFAULT_MIN_RELAY_FEE :: non_neg_integer(),  %% our feefilter sent to peer
    feefilter_sent_at       :: non_neg_integer() | undefined,      %% when we last sent feefilter
    feefilter_timer_ref     :: reference() | undefined,            %% timer for periodic updates
    %% BIP-324 v2 encrypted transport (W90).
    %%
    %% v2_phase tracks the inbound responder state machine after the
    %% peek-classify decision in handle_tcp_data:
    %%
    %%   undefined    — we have not yet classified the inbound stream;
    %%                  next 16 bytes will decide v1 vs v2 (or v2 already
    %%                  active for outbound, when we eventually wire it).
    %%   v1           — v1 magic seen; remainder of the buffer feeds the
    %%                  existing decode_msg/dispatch_message path verbatim.
    %%   recv_pubkey  — accumulating peer's 64-byte ElligatorSwift pubkey.
    %%   recv_garbterm — pubkey complete, scanning for the 16-byte
    %%                  recv_garbage_terminator (peer may emit 0..4095
    %%                  random pre-key bytes before it, per BIP-324).
    %%   drain_decoy  — terminator seen; consuming optional decoy AEAD
    %%                  packets up to the peer's mandatory non-decoy
    %%                  version packet.
    %%   ready        — cipher handshake complete; subsequent inbound and
    %%                  outbound bytes are AEAD-wrapped per BIP-324
    %%                  short-id encoding (beamchain_v2_msg).
    v2_phase = undefined :: undefined | v1 | recv_pubkey | recv_garbterm |
                            drain_decoy | ready,
    v2_cipher            :: beamchain_transport_v2:cipher() | undefined,
    %% Random pre-terminator garbage we sent.  Bound into the AAD of the
    %% first encrypted packet we transmit (the version packet) so the
    %% peer authenticates that we observed the same byte sequence on
    %% both sides of the cipher boundary.
    v2_sent_garbage = <<>>      :: binary(),
    %% AAD for the next decrypt() call.  Set to the peer's pre-terminator
    %% garbage on first decrypt (or the full pre-terminator stream if the
    %% peer sent any), then cleared.
    v2_next_aad = <<>>          :: binary(),
    %% Sliding window used during recv_garbterm to find the terminator.
    %% Bounded at MAX_GARBAGE_LEN + 16 bytes — beyond that we MUST drop
    %% the connection (BIP-324 protocol violation).
    v2_recv_window = <<>>       :: binary(),
    %% After decrypt_length() commits the recv_l cipher, we need to
    %% remember the contents length until the corresponding body
    %% arrives — otherwise the next pass would call decrypt_length()
    %% again and double-advance the cipher.  ``undefined`` means "no
    %% pending body".
    v2_pending_len = undefined  :: undefined | non_neg_integer(),
    %% BIP-324 v2 outbound: true iff this is an outbound peer dialing
    %% v2 (initiator).  Set in init/1 from the address-cache + env-var
    %% gate; consumed in connecting → handshaking to drive the initiator
    %% state machine instead of the v1 send-version path.
    v2_initiator = false        :: boolean()
}).

%%% -------------------------------------------------------------------
%%% BIP-324 v2 outbound — module-level state
%%% -------------------------------------------------------------------

%% Per-address v1-only fallback cache.  Keyed by {IP, Port} (the same
%% tuple used everywhere else in this module for addresses).  Mirrors
%% clearbit's `v2_fallback_set` (peer.zig:1759).  Bounded by
%% ?V2_FALLBACK_CACHE_MAX to keep memory finite under churn — when the
%% cap is reached we drop one arbitrary entry before inserting (the ETS
%% iteration order is undefined, which is acceptable for an LRU-ish
%% bound on a self-correcting cache: a v2-capable peer that gets evicted
%% will simply be re-probed on its next outbound attempt).
-define(V2_FALLBACK_TABLE, beamchain_peer_v1_only).
-define(V2_FALLBACK_CACHE_MAX, 4096).

%%% ===================================================================
%%% API
%%% ===================================================================

%% @doc Start an outbound peer connection.
-spec connect({inet:ip_address(), inet:port_number()}, pid(), map()) ->
    {ok, pid()} | {error, term()}.
connect(Address, Handler, Opts) ->
    %% Use start (not start_link) so connection failures don't crash the caller
    gen_statem:start(?MODULE, {outbound, Address, Handler, Opts}, []).

%% @doc Accept an inbound peer connection on an existing socket.
-spec accept(gen_tcp:socket(), {inet:ip_address(), inet:port_number()}, pid()) ->
    {ok, pid()} | {error, term()}.
accept(Socket, Address, Handler) ->
    gen_statem:start_link(?MODULE, {inbound, Socket, Address, Handler}, []).

%% @doc Send a P2P message to this peer.
%% The payload may be a map (common case) or any structured term (e.g.
%% a #block{} or #transaction{} record for in-process relay).
-spec send_message(pid(), {atom(), term()}) -> ok.
send_message(Pid, {Command, Payload}) ->
    gen_statem:cast(Pid, {send, Command, Payload}).

%% @doc Add misbehavior points. Peer is banned at >= 100.
-spec add_misbehavior(pid(), non_neg_integer()) -> ok.
add_misbehavior(Pid, Score) ->
    gen_statem:cast(Pid, {misbehavior, Score}).

%% @doc Disconnect the peer gracefully.
-spec disconnect(pid()) -> ok.
disconnect(Pid) ->
    gen_statem:cast(Pid, disconnect).

%% @doc Get peer connection info.
-spec info(pid()) -> {ok, map()} | {error, term()}.
info(Pid) ->
    gen_statem:call(Pid, info).

%% @doc Queue a transaction for trickling via inv. Instead of immediate
%% broadcast, txids are batched and sent with randomized Poisson delays
%% to prevent timing-based deanonymization.
-spec queue_tx_inv(pid(), binary()) -> ok.
queue_tx_inv(Pid, Txid) when is_binary(Txid), byte_size(Txid) =:= 32 ->
    gen_statem:cast(Pid, {queue_tx_inv, Txid}).

%%% -------------------------------------------------------------------
%%% BIP-324 v2 outbound: feature gate + per-address v1-only cache
%%% -------------------------------------------------------------------

%% @doc Returns true iff outbound BIP-324 v2 is enabled.  Default OFF
%% (conservative: v2 inbound responder landed in 72732d5; outbound is
%% wired by this commit but still gated until soak time accumulates).
%% Operators flip on with `BEAMCHAIN_BIP324_V2_OUTBOUND=1` (or "true")
%% in the environment, or `{bip324_v2_outbound, true}` in the
%% application config.  Mirrors clearbit's `bip324V2Enabled/0`
%% (peer.zig:653) modulo default polarity.
-spec bip324_v2_outbound_enabled() -> boolean().
bip324_v2_outbound_enabled() ->
    case os:getenv("BEAMCHAIN_BIP324_V2_OUTBOUND") of
        false ->
            case application:get_env(beamchain, bip324_v2_outbound) of
                {ok, true}  -> true;
                _           -> false
            end;
        Val ->
            case string:lowercase(Val) of
                "1"      -> true;
                "true"   -> true;
                "on"     -> true;
                "yes"    -> true;
                _        -> false
            end
    end.

%% @doc Mark an address as v1-only.  Future outbound attempts to this
%% address skip the v2 probe.
-spec mark_v1_only({inet:ip_address(), inet:port_number()}) -> ok.
mark_v1_only(Address) ->
    ensure_fallback_table(),
    case ets:info(?V2_FALLBACK_TABLE, size) of
        Size when is_integer(Size), Size >= ?V2_FALLBACK_CACHE_MAX ->
            %% Drop one arbitrary entry to make room.  ETS iteration
            %% order is undefined, which is fine for a bounded
            %% self-correcting cache.
            case ets:first(?V2_FALLBACK_TABLE) of
                '$end_of_table' -> ok;
                K               -> ets:delete(?V2_FALLBACK_TABLE, K)
            end;
        _ ->
            ok
    end,
    ets:insert(?V2_FALLBACK_TABLE, {Address}),
    ok.

%% @doc True iff `Address` is in the v1-only fallback cache.
-spec is_v1_only({inet:ip_address(), inet:port_number()}) -> boolean().
is_v1_only(Address) ->
    ensure_fallback_table(),
    case ets:lookup(?V2_FALLBACK_TABLE, Address) of
        [_] -> true;
        []  -> false
    end.

%% @doc Empty the v1-only fallback cache.  Test-only utility.
-spec clear_v1_only_cache() -> ok.
clear_v1_only_cache() ->
    case ets:info(?V2_FALLBACK_TABLE) of
        undefined -> ok;
        _         -> ets:delete_all_objects(?V2_FALLBACK_TABLE)
    end,
    ok.

%% Lazily create the v1-only cache table.  ETS tables are owned by the
%% process that creates them; on first call we create it from whichever
%% process happened to dial first.  Subsequent processes find it
%% existing.  We use named_table + public so any peer process can
%% read+write without going through a coordinator.  heir_data is set so
%% the table survives the creator dying.
ensure_fallback_table() ->
    case ets:info(?V2_FALLBACK_TABLE) of
        undefined ->
            try
                ets:new(?V2_FALLBACK_TABLE,
                        [named_table, public, set,
                         {read_concurrency, true},
                         {write_concurrency, true},
                         {heir, none}])
            catch
                error:badarg ->
                    %% Race: another process created it between our
                    %% info/0 check and the new/2 call.  That's fine.
                    ok
            end;
        _ ->
            ok
    end.

%%% ===================================================================
%%% gen_statem callbacks
%%% ===================================================================

callback_mode() -> [state_functions, state_enter].

init({outbound, {Host, Port} = Addr, Handler, _Opts}) when is_list(Host); is_binary(Host) ->
    %% Hostname connection (for .onion, .b32.i2p, or regular hostnames)
    %% Route through appropriate proxy based on address type
    Nonce = generate_nonce(),
    Magic = beamchain_config:magic(),
    MonRef = erlang:monitor(process, Handler),
    V2Init = should_init_v2_outbound(Addr),
    Data = #peer_data{
        address = Addr,
        direction = outbound,
        our_nonce = Nonce,
        magic = Magic,
        handler = Handler,
        handler_mon = MonRef,
        v2_initiator = V2Init
    },
    HostStr = to_string(Host),
    ConnectOpts = #{timeout => ?CONNECT_TIMEOUT},
    case beamchain_proxy:connect(HostStr, Port, ConnectOpts) of
        {ok, Socket} ->
            inet:setopts(Socket, [{active, once},
                                   {recbuf, 262144}, {sndbuf, 262144}]),
            Data2 = Data#peer_data{
                socket = Socket,
                connected_at = erlang:system_time(millisecond)
            },
            {ok, connecting, Data2};
        {error, Reason} ->
            %% Wrap in {shutdown, _} so SASL does not log a crash report
            %% for an expected outcome (dead peer, timeout, refused). The
            %% peer manager receives {error, Reason} from gen_statem:start
            %% and calls beamchain_addrman:mark_failed/1 either way.
            {stop, {shutdown, {connection_failed, Reason}}}
    end;
init({outbound, {IP, Port} = Addr, Handler, _Opts}) ->
    %% Standard IP address connection (tuple IP)
    Nonce = generate_nonce(),
    Magic = beamchain_config:magic(),
    MonRef = erlang:monitor(process, Handler),
    V2Init = should_init_v2_outbound(Addr),
    Data = #peer_data{
        address = Addr,
        direction = outbound,
        our_nonce = Nonce,
        magic = Magic,
        handler = Handler,
        handler_mon = MonRef,
        v2_initiator = V2Init
    },
    case gen_tcp:connect(IP, Port,
                         [binary, {active, false}, {packet, raw},
                          {nodelay, true}, {send_timeout, 5000},
                          {recbuf, 262144}, {sndbuf, 262144}],
                         ?CONNECT_TIMEOUT) of
        {ok, Socket} ->
            inet:setopts(Socket, [{active, once}]),
            Data2 = Data#peer_data{
                socket = Socket,
                connected_at = erlang:system_time(millisecond)
            },
            {ok, connecting, Data2};
        {error, Reason} ->
            %% See comment above: shutdown tuple keeps SASL quiet on expected
            %% connect failures (timeout / econnrefused / enetunreach, etc.).
            {stop, {shutdown, {connection_failed, Reason}}}
    end;

init({inbound, Socket, Addr, Handler}) ->
    Nonce = generate_nonce(),
    Magic = beamchain_config:magic(),
    MonRef = erlang:monitor(process, Handler),
    %% Only set buffer sizes here.  Do NOT enable {active, once} yet —
    %% the socket's controlling process is still the peer manager at this
    %% point.  We wait for a socket_owner_transferred message (sent by
    %% the manager after gen_tcp:controlling_process/2) before activating.
    inet:setopts(Socket, [{recbuf, 262144}, {sndbuf, 262144}]),
    Data = #peer_data{
        socket = Socket,
        address = Addr,
        direction = inbound,
        our_nonce = Nonce,
        magic = Magic,
        handler = Handler,
        handler_mon = MonRef,
        connected_at = erlang:system_time(millisecond)
    },
    %% Inbound: go straight to handshaking, wait for their version
    {ok, handshaking, Data}.

%%% -------------------------------------------------------------------
%%% connecting - TCP socket is open, send version
%%% -------------------------------------------------------------------

connecting(enter, _OldState, _Data) ->
    %% Cannot use next_event from enter callbacks in state_enter mode.
    %% Use state_timeout with 0ms to trigger immediately.
    {keep_state_and_data, [{state_timeout, 0, start_handshake}]};

connecting(state_timeout, start_handshake, Data) ->
    start_handshake(Data);

connecting(internal, start_handshake, Data) ->
    start_handshake(Data);

%% Backwards-compat (the old action name is referenced in some tests):
connecting(state_timeout, send_version, Data) ->
    start_handshake(Data);
connecting(internal, send_version, Data) ->
    start_handshake(Data);

connecting(info, {tcp_closed, _}, _Data) ->
    {stop, connection_closed};

connecting(info, {tcp_error, _, Reason}, _Data) ->
    {stop, {tcp_error, Reason}};

connecting(cast, disconnect, _Data) ->
    {stop, normal};

connecting(_EventType, _Event, _Data) ->
    keep_state_and_data.

%% Begin the handshake.  Outbound v2 initiator: send our 64-byte
%% ellswift pubkey + garbage + garbage_terminator + first AEAD packet
%% (BIP-324 version_packet, AAD=our_garbage), then transition to
%% handshaking with v2_phase=recv_pubkey awaiting peer's pubkey.
%% Outbound v1: send our v1 ``version`` and pin v2_phase=v1 so
%% maybe_classify_inbound doesn't re-route bytes through the v2 path.
%% Inbound never reaches connecting (init goes straight to handshaking).
start_handshake(#peer_data{v2_initiator = true} = Data) ->
    case begin_v2_outbound(Data) of
        {ok, Data2}     -> {next_state, handshaking, Data2};
        {stop, Reason}  -> {stop, Reason}
    end;
start_handshake(#peer_data{v2_initiator = false} = Data) ->
    Data2 = do_send_version(Data),
    {next_state, handshaking, Data2#peer_data{v2_phase = v1}}.

%%% -------------------------------------------------------------------
%%% handshaking - waiting for remote version + verack
%%% -------------------------------------------------------------------

handshaking(enter, _OldState, _Data) ->
    {keep_state_and_data,
     [{state_timeout, ?HANDSHAKE_TIMEOUT, handshake_timeout}]};

handshaking(state_timeout, handshake_timeout, Data) ->
    logger:info("peer ~p handshake timeout", [Data#peer_data.address]),
    {stop, handshake_timeout};

handshaking(info, socket_owner_transferred, #peer_data{socket = Socket} = Data) ->
    %% The peer manager has transferred socket ownership to us.
    %% Now it is safe to enable active-once delivery.
    inet:setopts(Socket, [{active, once}]),
    {keep_state, Data};

handshaking(info, {tcp, Socket, Bin}, #peer_data{socket = Socket} = Data) ->
    case handle_tcp_data(Bin, Data) of
        {ok, Data2} ->
            case handshake_complete(Data2) of
                true  -> {next_state, ready, Data2};
                false -> {keep_state, Data2}
            end;
        {stop, Reason} ->
            {stop, Reason}
    end;

handshaking(info, {tcp_closed, _}, Data) ->
    logger:info("peer ~p closed during handshake", [Data#peer_data.address]),
    {stop, normal};

handshaking(info, {tcp_error, _, Reason}, Data) ->
    logger:warning("peer ~p tcp error: ~p", [Data#peer_data.address, Reason]),
    {stop, {tcp_error, Reason}};

handshaking(info, {'DOWN', Ref, process, _, _}, #peer_data{handler_mon = Ref}) ->
    {stop, {shutdown, handler_down}};

handshaking(cast, disconnect, _Data) ->
    {stop, normal};

handshaking(cast, {misbehavior, Score}, Data) ->
    check_ban(Data#peer_data{
        misbehavior = Data#peer_data.misbehavior + Score});

handshaking({call, From}, info, Data) ->
    {keep_state_and_data, [{reply, From, {ok, build_info(Data)}}]};

handshaking(_EventType, _Event, _Data) ->
    keep_state_and_data.

%%% -------------------------------------------------------------------
%%% ready - handshake complete, normal operation
%%% -------------------------------------------------------------------

ready(enter, handshaking, Data) ->
    logger:info("peer ~p ready (~s, height=~B)",
                [Data#peer_data.address,
                 Data#peer_data.peer_user_agent,
                 Data#peer_data.peer_height]),
    %% Send feature negotiation messages
    Data2 = send_feature_msgs(Data),
    %% Notify handler
    Data2#peer_data.handler ! {peer_connected, self(), build_info(Data2)},
    %% Schedule first inv trickle with Poisson delay
    Data3 = schedule_trickle_timer(Data2),
    %% Start ping timer and inactivity timeout
    {keep_state, Data3,
     [{{timeout, ping}, ?PING_INTERVAL, send_ping},
      {{timeout, inactivity}, ?INACTIVITY_TIMEOUT, inactive}]};

ready({timeout, ping}, send_ping, Data) ->
    Data2 = do_send_ping(Data),
    {keep_state, Data2,
     [{{timeout, ping}, ?PING_INTERVAL, send_ping},
      {{timeout, pong}, ?PONG_TIMEOUT, pong_timeout}]};

ready({timeout, inactivity}, inactive, Data) ->
    logger:info("peer ~p inactivity timeout", [Data#peer_data.address]),
    {stop, inactivity_timeout};

ready({timeout, pong}, pong_timeout, Data) ->
    logger:info("peer ~p pong timeout", [Data#peer_data.address]),
    {stop, pong_timeout};

ready(info, {tcp, Socket, Bin}, #peer_data{socket = Socket} = Data) ->
    case handle_tcp_data(Bin, Data) of
        {ok, Data2} ->
            Actions = [{{timeout, inactivity}, ?INACTIVITY_TIMEOUT, inactive}],
            %% Cancel pong timeout if pong was received (nonce cleared)
            Actions2 = case Data2#peer_data.last_ping_nonce of
                undefined -> [{{timeout, pong}, infinity, pong_timeout} | Actions];
                _         -> Actions
            end,
            {keep_state, Data2, Actions2};
        {stop, Reason} ->
            {stop, Reason}
    end;

ready(info, {tcp_closed, _}, Data) ->
    logger:info("peer ~p disconnected", [Data#peer_data.address]),
    Data#peer_data.handler ! {peer_disconnected, self(), closed},
    {stop, normal};

ready(info, {tcp_error, _, Reason}, Data) ->
    logger:warning("peer ~p tcp error: ~p", [Data#peer_data.address, Reason]),
    Data#peer_data.handler ! {peer_disconnected, self(), {tcp_error, Reason}},
    {stop, {tcp_error, Reason}};

ready(info, {'DOWN', Ref, process, _, _}, #peer_data{handler_mon = Ref}) ->
    {stop, {shutdown, handler_down}};

ready(cast, {send, Command, PayloadData}, Data) ->
    Data2 = do_send_msg(Command, PayloadData, Data),
    {keep_state, Data2};

ready(cast, disconnect, Data) ->
    Data#peer_data.handler ! {peer_disconnected, self(), requested},
    {stop, normal};

ready(cast, {misbehavior, Score}, Data) ->
    check_ban(Data#peer_data{
        misbehavior = Data#peer_data.misbehavior + Score});

ready(cast, {queue_tx_inv, Txid}, Data) ->
    %% Add txid to pending queue if not already there
    Pending = Data#peer_data.pending_tx_inv,
    case lists:member(Txid, Pending) of
        true  -> {keep_state, Data};
        false -> {keep_state, Data#peer_data{pending_tx_inv = [Txid | Pending]}}
    end;

ready(info, trickle_inv, Data) ->
    %% Flush queued inv items with randomized ordering
    Data2 = do_trickle_inv(Data),
    Data3 = schedule_trickle_timer(Data2),
    {keep_state, Data3};

ready(info, check_feefilter, Data) ->
    %% Periodic feefilter check - update if fee changed
    Data2 = maybe_update_feefilter(Data),
    Data3 = schedule_feefilter_timer(Data2),
    {keep_state, Data3};

ready(info, send_feefilter_now, Data) ->
    %% Accelerated feefilter update due to significant fee change
    CurrentFee = get_mempool_min_fee(),
    Data2 = do_send_feefilter(CurrentFee, Data),
    {keep_state, Data2};

ready({call, From}, info, Data) ->
    {keep_state_and_data, [{reply, From, {ok, build_info(Data)}}]};

ready(_EventType, _Event, _Data) ->
    keep_state_and_data.

%%% -------------------------------------------------------------------
%%% terminate
%%% -------------------------------------------------------------------

terminate(_Reason, _State, #peer_data{socket = undefined}) -> ok;
terminate(_Reason, _State, #peer_data{socket = Socket}) ->
    gen_tcp:close(Socket),
    ok.

%%% ===================================================================
%%% Internal: TCP receive and buffering
%%% ===================================================================

handle_tcp_data(NewBytes, #peer_data{socket = Socket, buffer = Buf} = Data) ->
    Buffer = <<Buf/binary, NewBytes/binary>>,
    BytesRecv = Data#peer_data.bytes_recv + byte_size(NewBytes),
    Data2 = Data#peer_data{
        buffer = Buffer,
        bytes_recv = BytesRecv,
        last_recv = erlang:system_time(millisecond)
    },
    %% Inbound peers: peek-classify before we know whether the stream is
    %% v1 (Bitcoin Core <26.0 / unencrypted) or v2 (BIP-324).  Outbound
    %% peers stay on the v1 path for now (see "Outbound v2: NOT WIRED"
    %% audit note in W90).
    Data3 = maybe_classify_inbound(Data2),
    case dispatch_buffered(Data3) of
        {ok, Data4} ->
            inet:setopts(Socket, [{active, once}]),
            {ok, Data4};
        {stop, Reason} ->
            {stop, Reason}
    end.

%% Decide v1 vs v2 once we have at least 16 bytes buffered.
%%
%% Inbound: peek the first 16 bytes — if they match `magic ||
%% "version\0\0\0\0\0"` treat as v1; otherwise treat as a v2
%% ElligatorSwift pubkey (responder mode).
%%
%% Outbound: classification is decided in start_handshake/1 before any
%% bytes hit the wire — the v2_initiator path pins v2_phase=recv_pubkey
%% (and has already queued our pubkey + garbage to the peer); the v1
%% path pins v2_phase=v1 (and has already queued our v1 ``version``).
%% By the time we receive any peer bytes, v2_phase is no longer
%% undefined for outbound peers, so this clause matches only inbound.
maybe_classify_inbound(#peer_data{direction = inbound,
                                   v2_phase = undefined,
                                   buffer = Buffer,
                                   magic = Magic} = Data)
  when byte_size(Buffer) >= 16 ->
    <<Head:16/binary, _/binary>> = Buffer,
    case is_v1_version_header(Head, Magic) of
        true ->
            Data#peer_data{v2_phase = v1};
        false ->
            logger:debug("peer ~p classified as v2 (BIP-324) responder",
                         [Data#peer_data.address]),
            Data#peer_data{v2_phase = recv_pubkey}
    end;
maybe_classify_inbound(#peer_data{direction = outbound,
                                   v2_phase = undefined} = Data) ->
    %% Defensive fallback: should never happen — start_handshake/1 sets
    %% v2_phase before any peer bytes can arrive (the v1 path pins v1,
    %% the v2 path pins recv_pubkey).  If we got here it means the peer
    %% raced their first packet ahead of our state-enter timeout, which
    %% is fine: pin to v1 (safer default; v1 magic check still gates
    %% the path below).
    Data#peer_data{v2_phase = v1};
maybe_classify_inbound(Data) ->
    Data.

%% Detect whether the peer responded to our v2 initiator probe with v1
%% magic.  Called from drive_v2_handshake/1 in the recv_pubkey substate
%% as a sanity check before parsing the 64-byte pubkey.  If the first
%% 16 bytes match a v1 ``version`` header, the peer is v1 and we must
%% disconnect, mark v1-only, and let the manager retry on a fresh
%% socket.  Returns:
%%   v1_response  — peer replied with v1 magic; fall back.
%%   v2_response  — first 16 bytes are not v1; carry on with the v2
%%                  cipher handshake.
classify_v2_response(Buffer, Magic) when byte_size(Buffer) >= 16 ->
    <<Head:16/binary, _/binary>> = Buffer,
    case is_v1_version_header(Head, Magic) of
        true  -> v1_response;
        false -> v2_response
    end;
classify_v2_response(_, _) ->
    %% Fewer than 16 bytes — wait for more.  Caller already gates on
    %% ``byte_size(Buffer) >= 64`` for the pubkey, so this case is
    %% unreachable in practice.  Defensive default: assume v2.
    v2_response.

%% True iff the first 16 bytes match a v1 ``version`` message header.
%% We anchor on the literal command name rather than just the network
%% magic so we don't get false positives from a v2 ellswift pubkey
%% whose first 4 bytes happen to equal the magic.
is_v1_version_header(<<Magic:4/binary, "version", 0, 0, 0, 0, 0>>, Magic) ->
    true;
is_v1_version_header(_, _) ->
    false.

%% Drive whichever decoder the current v2_phase requires.
dispatch_buffered(#peer_data{v2_phase = Phase} = Data)
  when Phase =:= undefined ->
    %% Not enough bytes to classify yet — wait for the next TCP segment.
    {ok, Data};
dispatch_buffered(#peer_data{v2_phase = v1} = Data) ->
    process_buffer_v1(Data);
dispatch_buffered(#peer_data{v2_phase = ready} = Data) ->
    process_buffer_v2(Data);
dispatch_buffered(#peer_data{v2_phase = _} = Data) ->
    %% Cipher-handshake substates: recv_pubkey, recv_garbterm, drain_decoy.
    drive_v2_handshake(Data).

process_buffer_v1(#peer_data{buffer = Buffer} = Data) ->
    case beamchain_p2p_msg:decode_msg(Buffer) of
        {ok, Command, Payload, Rest} ->
            Data2 = Data#peer_data{buffer = Rest},
            case dispatch_message(Command, Payload, Data2) of
                {ok, Data3}    -> process_buffer_v1(Data3);
                {stop, Reason} -> {stop, Reason}
            end;
        incomplete ->
            {ok, Data};
        {error, Reason} ->
            logger:warning("peer ~p frame error: ~p",
                           [Data#peer_data.address, Reason]),
            {stop, Reason}
    end.


%%% ===================================================================
%%% Internal: BIP-324 v2 responder state machine
%%% ===================================================================

%% Drive whichever cipher-handshake substate we're currently in.  Each
%% transition consumes some prefix of ``buffer`` and moves to the next
%% substate; on success we eventually land in ``v2_phase = ready`` and
%% the caller starts driving ``process_buffer_v2``.
%%
%% Two recv_pubkey entrypoints:
%%
%%   * Initiator (outbound, v2_cipher already set):
%%       We already sent our 64-byte ellswift + garbage + version
%%       packet from start_handshake/begin_v2_outbound.  Just consume
%%       the peer's pubkey and advance to recv_garbterm.  Sanity-check
%%       the first 16 bytes for a v1 magic response — if the peer is
%%       v1, mark v1-only and disconnect with a fallback reason.
%%
%%   * Responder (inbound, v2_cipher = undefined):
%%       Build a fresh cipher, initialize with peer's pubkey, send our
%%       pubkey + garbage + version packet, advance to recv_garbterm.
drive_v2_handshake(#peer_data{v2_phase = recv_pubkey,
                              v2_cipher = Cipher,
                              direction = outbound,
                              buffer = Buffer,
                              magic = Magic} = Data)
  when Cipher =/= undefined, byte_size(Buffer) >= 64 ->
    case classify_v2_response(Buffer, Magic) of
        v1_response ->
            %% Peer responded with a v1 ``version`` header instead of a
            %% v2 ellswift pubkey.  Mark v1-only so the manager retries
            %% on a fresh socket (we already corrupted the v1 framing
            %% on this one by sending our pubkey).
            logger:info("peer ~p replied v1 to v2 probe; falling back",
                        [Data#peer_data.address]),
            mark_v1_only(Data#peer_data.address),
            {stop, {shutdown, v2_fallback_to_v1}};
        v2_response ->
            <<TheirPubKey:64/binary, Rest/binary>> = Buffer,
            Data1 = Data#peer_data{
                buffer = Rest,
                v2_recv_window = <<>>
            },
            %% Two-step initiator: now that we have peer's pubkey,
            %% complete cipher init (keys depend on ECDH) and send the
            %% remaining wire bytes (garbage + terminator +
            %% version_packet, AAD = our garbage).
            case finish_v2_initiator_send(TheirPubKey, Data1) of
                {ok, Data2} ->
                    Data3 = Data2#peer_data{v2_phase = recv_garbterm},
                    drive_v2_handshake(Data3);
                {stop, Reason} ->
                    {stop, Reason}
            end
    end;
drive_v2_handshake(#peer_data{v2_phase = recv_pubkey,
                              v2_cipher = undefined,
                              direction = inbound,
                              buffer = Buffer} = Data)
  when byte_size(Buffer) >= 64 ->
    <<TheirPubKey:64/binary, Rest/binary>> = Buffer,
    case beamchain_transport_v2:new_cipher() of
        {ok, Cipher0} ->
            case beamchain_transport_v2:initialize(
                   Cipher0, TheirPubKey, false, false) of
                {ok, Cipher1} ->
                    %% Send our 64-byte ellswift + send_garbage +
                    %% send_garbage_terminator + version-packet (AAD =
                    %% sent_garbage).  We pick a small uniformly random
                    %% garbage payload to keep the wire-overhead low while
                    %% still exercising the AAD-binding path.  Bitcoin
                    %% Core picks uniform-random in [0, 4095]; small is
                    %% strictly less observable on the wire.
                    OurPubKey = beamchain_transport_v2:get_pubkey(Cipher1),
                    SentGarbage = crypto:strong_rand_bytes(rand:uniform(33) - 1),
                    SendTerm = beamchain_transport_v2:get_send_garbage_terminator(Cipher1),
                    {ok, VerPkt, Cipher2} = beamchain_transport_v2:encrypt(
                        Cipher1, <<>>, SentGarbage, false),
                    Wire = <<OurPubKey/binary,
                             SentGarbage/binary,
                             SendTerm/binary,
                             VerPkt/binary>>,
                    case raw_socket_send(Data, Wire) of
                        {ok, Data2} ->
                            Data3 = Data2#peer_data{
                                buffer = Rest,
                                v2_phase = recv_garbterm,
                                v2_cipher = Cipher2,
                                v2_sent_garbage = SentGarbage,
                                v2_recv_window = <<>>
                            },
                            drive_v2_handshake(Data3);
                        {stop, Reason} ->
                            {stop, Reason}
                    end;
                {error, Reason} ->
                    logger:warning("peer ~p v2 cipher init failed: ~p",
                                   [Data#peer_data.address, Reason]),
                    {stop, {v2_init_failed, Reason}}
            end;
        {error, Reason} ->
            logger:warning("peer ~p v2 cipher new failed: ~p",
                           [Data#peer_data.address, Reason]),
            {stop, {v2_new_failed, Reason}}
    end;
drive_v2_handshake(#peer_data{v2_phase = recv_pubkey, buffer = Buffer} = Data)
  when byte_size(Buffer) < 64 ->
    %% Need more bytes; wait for the next TCP segment.
    {ok, Data};
drive_v2_handshake(#peer_data{v2_phase = recv_garbterm} = Data) ->
    drive_v2_garbterm(Data);
drive_v2_handshake(#peer_data{v2_phase = drain_decoy} = Data) ->
    drive_v2_drain(Data).

%% Scan the incoming stream for the 16-byte recv_garbage_terminator.
%% The peer may emit 0..MAX_GARBAGE_LEN random bytes before the
%% terminator.  We sweep one byte at a time (matching Bitcoin Core
%% net.cpp:1297 GetMaxBytesToProcess returning 1 in GARB_GARBTERM
%% state) because the terminator may begin at any offset within the
%% pre-key garbage.
drive_v2_garbterm(#peer_data{v2_cipher = Cipher,
                              v2_recv_window = Window,
                              buffer = Buffer} = Data) ->
    Term = beamchain_transport_v2:get_recv_garbage_terminator(Cipher),
    TermLen = beamchain_transport_v2:garbage_terminator_len(),
    MaxLen = beamchain_transport_v2:max_garbage_len() + TermLen,
    %% Move bytes from Buffer into Window, byte-by-byte, watching for
    %% the terminator at the trailing edge.  Bound the search at
    %% MAX_GARBAGE_LEN + 16 — beyond that the peer is misbehaving.
    case scan_terminator(Window, Buffer, Term, TermLen, MaxLen) of
        {found, RecvGarbage, BufferRest} ->
            %% AAD for our first decrypt() call is the peer's pre-terminator
            %% garbage stream.  After that decrypt clears it.
            Data2 = Data#peer_data{
                buffer = BufferRest,
                v2_phase = drain_decoy,
                v2_recv_window = <<>>,
                v2_next_aad = RecvGarbage
            },
            drive_v2_drain(Data2);
        {incomplete, NewWindow, BufferRest} ->
            {ok, Data#peer_data{
                v2_recv_window = NewWindow,
                buffer = BufferRest
            }};
        too_long ->
            logger:warning("peer ~p v2 garbage terminator not seen within "
                            "~B bytes — protocol violation",
                            [Data#peer_data.address, MaxLen]),
            {stop, v2_garbage_too_long}
    end.

%% Returns {found, GarbageBytes, BufferRest}, {incomplete, NewWindow,
%% BufferRest}, or too_long.  ``Window`` is the bytes consumed from the
%% peer so far, ``Buffer`` is the bytes still queued for inspection.
scan_terminator(Window, <<>>, _Term, _TermLen, _MaxLen)
  when byte_size(Window) > 0 ->
    %% No more bytes to scan; preserve window so the next TCP segment
    %% extends it.
    {incomplete, Window, <<>>};
scan_terminator(Window, <<>>, _Term, _TermLen, _MaxLen) ->
    {incomplete, Window, <<>>};
scan_terminator(Window, _Buffer, _Term, _TermLen, MaxLen)
  when byte_size(Window) > MaxLen ->
    too_long;
scan_terminator(Window, <<Byte, BufRest/binary>>, Term, TermLen, MaxLen) ->
    NewWindow = <<Window/binary, Byte>>,
    case byte_size(NewWindow) >= TermLen of
        true ->
            Tail = binary:part(NewWindow, byte_size(NewWindow) - TermLen, TermLen),
            case Tail =:= Term of
                true ->
                    %% Strip the terminator off the trailing edge; the
                    %% bytes that come before it are the peer's pre-key
                    %% garbage (used as AAD for our first decrypt).
                    Garbage = binary:part(NewWindow, 0,
                                          byte_size(NewWindow) - TermLen),
                    {found, Garbage, BufRest};
                false ->
                    scan_terminator(NewWindow, BufRest, Term, TermLen, MaxLen)
            end;
        false ->
            scan_terminator(NewWindow, BufRest, Term, TermLen, MaxLen)
    end.

%% Drain incoming AEAD packets (decoys + version) until we receive the
%% mandatory non-decoy version packet.  Each decoy packet consumes its
%% wire bytes but is otherwise discarded.  AAD is consumed on the first
%% decrypt regardless of decoy/non-decoy (Bitcoin Core net.cpp:1243
%% ClearShrink(m_recv_aad)) — so we clear v2_next_aad after the first
%% decrypt call below.
drive_v2_drain(Data) ->
    case extract_v2_packet(Data) of
        {ok, Contents, Ignore, Data2} ->
            Data3 = Data2#peer_data{v2_next_aad = <<>>},
            case Ignore of
                true  -> drive_v2_drain(Data3);
                false -> on_v2_version_packet(Contents, Data3)
            end;
        incomplete ->
            {ok, Data};
        {stop, Reason} ->
            {stop, Reason}
    end.

%% First non-decoy packet is the BIP-324 version packet.  Per spec the
%% contents are reserved for future protocol extensions; current Bitcoin
%% Core ignores them, and so do we.  We log the size for diagnostics.
on_v2_version_packet(Contents, #peer_data{address = Addr} = Data) ->
    logger:debug("peer ~p v2 version packet received (~B bytes)",
                 [Addr, byte_size(Contents)]),
    %% Cipher handshake is now complete.  Send our own application-level
    %% version message immediately (BIP-324 wraps it as a v2 packet) so
    %% the peer doesn't time out on us.
    Data1 = Data#peer_data{v2_phase = ready},
    Data2 = do_send_version(Data1),
    %% Process any remaining buffered bytes — peer may have pipelined
    %% their version packet right after the version-packet decoy.
    process_buffer_v2(Data2).

%% Decode and dispatch one or more v2 application packets.  Each packet
%% is: 3-byte enc-length || 1-byte hdr || contents || 16-byte tag.
%% Application packets carry no AAD (per BIP-324 §"Wire format").
process_buffer_v2(Data) ->
    case extract_v2_packet(Data) of
        {ok, _Contents, true, Data2} ->
            %% Decoy — discard contents, keep going.
            process_buffer_v2(Data2);
        {ok, Contents, false, Data2} ->
            case beamchain_v2_msg:decode_contents(Contents) of
                {ok, CmdBin, Payload} ->
                    Cmd = beamchain_p2p_msg:command_atom(CmdBin),
                    case dispatch_message(Cmd, Payload, Data2) of
                        {ok, Data3}    -> process_buffer_v2(Data3);
                        {stop, Reason} -> {stop, Reason}
                    end;
                {error, DecodeErr} ->
                    logger:warning("peer ~p v2 contents decode failed: ~p",
                                   [Data#peer_data.address, DecodeErr]),
                    {stop, {v2_decode_failed, DecodeErr}}
            end;
        incomplete ->
            {ok, Data};
        {stop, Reason} ->
            {stop, Reason}
    end.

%% Pull one complete AEAD packet from ``buffer``.  Returns:
%%
%%   {ok, Contents, IgnoreFlag, NewData}  — packet decrypted & consumed.
%%   incomplete                          — need more bytes.
%%   {stop, Reason}                      — protocol violation; close.
%%
%% Handles the half-buffered case (length-field arrived but body in
%% flight) by stashing the decrypted ContentsLen in ``v2_pending_len``
%% so we don't double-advance the recv_l cipher on retry.  AAD is taken
%% from ``v2_next_aad`` and cleared after a successful decrypt.
extract_v2_packet(#peer_data{buffer = Buffer,
                              v2_cipher = Cipher,
                              v2_pending_len = Pending,
                              v2_next_aad = AAD} = Data) ->
    LenLen = beamchain_transport_v2:length_field_len(),
    HdrLen = beamchain_transport_v2:header_len(),
    TagLen = beamchain_transport_v2:tag_len(),
    case Pending of
        undefined ->
            case Buffer of
                <<EncLen:LenLen/binary, BufferRest/binary>> ->
                    {ok, ContentsLen, Cipher1} =
                        beamchain_transport_v2:decrypt_length(Cipher, EncLen),
                    %% W98 G24: reject oversize messages before allocating the
                    %% receive buffer.  Core: MAX_PROTOCOL_MESSAGE_LENGTH = 4 MB.
                    if ContentsLen > ?MAX_PROTOCOL_MESSAGE_LENGTH ->
                        {stop, oversize_message};
                    true ->
                    Data1 = Data#peer_data{
                        v2_cipher = Cipher1,
                        v2_pending_len = ContentsLen,
                        buffer = BufferRest
                    },
                    extract_v2_body(Data1, ContentsLen, HdrLen, TagLen, AAD)
                    end;
                _ ->
                    incomplete
            end;
        ContentsLen when is_integer(ContentsLen) ->
            extract_v2_body(Data, ContentsLen, HdrLen, TagLen, AAD)
    end.

extract_v2_body(#peer_data{buffer = Buffer, v2_cipher = Cipher} = Data,
                ContentsLen, HdrLen, TagLen, AAD) ->
    BodyLen = HdrLen + ContentsLen + TagLen,
    case Buffer of
        <<EncBody:BodyLen/binary, Rest/binary>> ->
            case beamchain_transport_v2:decrypt(
                   Cipher, EncBody, AAD, ContentsLen) of
                {ok, Contents, Ignore, Cipher1} ->
                    Data1 = Data#peer_data{
                        v2_cipher = Cipher1,
                        v2_pending_len = undefined,
                        buffer = Rest
                    },
                    {ok, Contents, Ignore, Data1};
                {error, auth_failed} ->
                    logger:warning("peer ~p v2 AEAD auth failed",
                                   [Data#peer_data.address]),
                    {stop, v2_auth_failed}
            end;
        _ ->
            incomplete
    end.

%% Send raw bytes on the underlying TCP socket without v2-wrapping.
%% Used exclusively during the cipher handshake (the bytes are the
%% ellswift pubkey, garbage, and the very first AEAD packet — all of
%% which are produced by beamchain_transport_v2 directly).
raw_socket_send(#peer_data{socket = Socket} = Data, Bytes) ->
    case gen_tcp:send(Socket, Bytes) of
        ok ->
            {ok, Data#peer_data{
                bytes_sent = Data#peer_data.bytes_sent + byte_size(Bytes),
                last_send  = erlang:system_time(millisecond)
            }};
        {error, Reason} ->
            logger:debug("peer ~p raw_socket_send failed: ~p",
                         [Data#peer_data.address, Reason]),
            {stop, {tcp_send_failed, Reason}}
    end.

%%% ===================================================================
%%% Internal: BIP-324 v2 outbound initiator
%%% ===================================================================

%% Decide whether this outbound peer should attempt BIP-324 v2.
%% Gated by the env-var/app-config flag AND not in the per-address
%% v1-only fallback cache.  Mirrors clearbit's
%%     v2_enabled and !self.isV1Only(address)  (peer.zig:1868).
should_init_v2_outbound(Address) ->
    bip324_v2_outbound_enabled() andalso not is_v1_only(Address).

%% Build an initialised initiator cipher and return the OUTGOING wire
%% prefix that is computable BEFORE peer's pubkey arrives — namely the
%% 64-byte ellswift pubkey.  Returns {ok, Pubkey, Cipher} or {error, _}.
%%
%% Test-only helper: production code calls begin_v2_outbound/1 which
%% sends the pubkey directly on the socket.  The full wire shape (after
%% peer pubkey arrives) is:
%%     [ ellswift_pubkey (64) | garbage (0..32) | garbage_terminator (16)
%%     | version_packet (AEAD, AAD = garbage) ]
%% but the latter three depend on the ECDH shared secret which needs
%% the peer's pubkey, so they are emitted in finish_v2_initiator_send/2
%% after recv_pubkey lands.  Mirrors clearbit's two-phase initiator
%% (V2Transport sends pubkey + queue marker first, then completes after
%% receiving peer's pubkey).
%%
%% Compiled only under TEST so xref's locals_not_used check stays
%% green in prod builds (production code path is begin_v2_outbound/1).
-ifdef(TEST).
build_v2_initiator_handshake(SecKey, AuxRand)
  when byte_size(SecKey) =:= 32, byte_size(AuxRand) =:= 32 ->
    case beamchain_transport_v2:new_cipher(SecKey, AuxRand) of
        {ok, _Cipher0} = OK ->
            build_v2_initiator_handshake_cont(OK);
        {error, _} = Err ->
            Err
    end;
build_v2_initiator_handshake(random, _) ->
    case beamchain_transport_v2:new_cipher() of
        {ok, _Cipher0} = OK ->
            build_v2_initiator_handshake_cont(OK);
        {error, _} = Err ->
            Err
    end.

build_v2_initiator_handshake_cont({ok, Cipher0}) ->
    Pubkey = beamchain_transport_v2:get_pubkey(Cipher0),
    {ok, Pubkey, Cipher0}.

%% Build a minimal #peer_data{} suitable for passing to extract_v2_packet/1
%% in unit tests.  Only the fields consumed by that function are set.
make_test_v2_peer(Cipher, Buffer) ->
    #peer_data{
        socket          = undefined,
        address         = {{127,0,0,1}, 0},
        direction       = inbound,
        buffer          = Buffer,
        v2_cipher       = Cipher,
        v2_pending_len  = undefined,
        v2_next_aad     = <<>>,
        our_nonce       = 0,
        magic           = <<>>,
        handler         = self()
    }.
-endif.

%% Open the BIP-324 outbound handshake.  Called from start_handshake/1
%% when v2_initiator=true.  Sends our 64-byte ellswift pubkey on the
%% socket, sets v2_phase=recv_pubkey, and stashes the partially-init'd
%% cipher in v2_cipher so drive_v2_handshake/1 can finish initialisation
%% once the peer's pubkey arrives.
%%
%% In Bitcoin Core, the initiator can pipeline pubkey + garbage +
%% terminator + version_packet because the cipher keys are derived from
%% the BIP-324 ECDH which requires the peer's pubkey first.  Bitcoin
%% Core works around this by sending the pubkey first, then computing
%% the keys when the peer's pubkey arrives, then sending the
%% remaining bytes — i.e. the same two-phase pattern we use here.
%% (clearbit handles this in v2_transport.zig::V2Transport.init by
%% queueing the first 64 bytes for sending only.)
begin_v2_outbound(Data) ->
    case beamchain_transport_v2:new_cipher() of
        {ok, Cipher0} ->
            %% Send our 64-byte ellswift pubkey now.  Garbage +
            %% terminator + version_packet are sent in
            %% finish_v2_initiator_send/2 once the peer's pubkey
            %% arrives and we can complete cipher initialisation.
            Pubkey = beamchain_transport_v2:get_pubkey(Cipher0),
            case raw_socket_send(Data, Pubkey) of
                {ok, Data2} ->
                    {ok, Data2#peer_data{
                        v2_phase = recv_pubkey,
                        v2_cipher = Cipher0
                    }};
                {stop, Reason} ->
                    %% TCP send failed before any handshake bytes
                    %% landed — no need to mark v1-only.
                    {stop, Reason}
            end;
        {error, Reason} ->
            logger:warning("peer ~p v2 cipher new failed: ~p",
                           [Data#peer_data.address, Reason]),
            {stop, {shutdown, {v2_new_failed, Reason}}}
    end.

%% Finalise the initiator handshake send: derive ECDH-based cipher
%% keys with the peer's pubkey, then send our garbage + terminator +
%% version_packet (AAD = our garbage).  Called from
%% drive_v2_handshake/1 in the recv_pubkey clause for outbound after
%% we've consumed the peer's 64 bytes.
finish_v2_initiator_send(TheirPubKey, Data) ->
    case beamchain_transport_v2:initialize(
           Data#peer_data.v2_cipher, TheirPubKey, true, false) of
        {ok, Cipher1} ->
            SentGarbage = crypto:strong_rand_bytes(rand:uniform(33) - 1),
            SendTerm = beamchain_transport_v2:get_send_garbage_terminator(Cipher1),
            {ok, VerPkt, Cipher2} = beamchain_transport_v2:encrypt(
                Cipher1, <<>>, SentGarbage, false),
            Wire = <<SentGarbage/binary, SendTerm/binary, VerPkt/binary>>,
            case raw_socket_send(Data, Wire) of
                {ok, Data2} ->
                    {ok, Data2#peer_data{
                        v2_cipher = Cipher2,
                        v2_sent_garbage = SentGarbage
                    }};
                {stop, Reason} ->
                    {stop, Reason}
            end;
        {error, Reason} ->
            logger:warning("peer ~p v2 initiator init failed: ~p",
                           [Data#peer_data.address, Reason]),
            mark_v1_only(Data#peer_data.address),
            {stop, {shutdown, {v2_init_failed, Reason}}}
    end.

%%% ===================================================================
%%% Internal: Message dispatch
%%% ===================================================================

dispatch_message(version, Payload, Data) ->
    handle_version_msg(Payload, Data);
dispatch_message(verack, _Payload, Data) ->
    handle_verack_msg(Data);
dispatch_message(ping, Payload, Data) ->
    handle_ping_msg(Payload, Data);
dispatch_message(pong, Payload, Data) ->
    handle_pong_msg(Payload, Data);
dispatch_message(sendheaders, _Payload, Data) ->
    %% BIP-130: peer prefers `headers` announces over `inv`. Surface the flag
    %% to the handler (peer_manager) so future block announces branch
    %% accordingly. Without this notification, peer_manager keeps spamming
    %% `inv` and the peer must round-trip getheaders for every announcement —
    %% the header-sync DoS amplifier this wave is closing.
    Data#peer_data.handler ! {peer_sendheaders, self()},
    {ok, Data#peer_data{wants_headers = true}};
dispatch_message(sendcmpct, Payload, Data) ->
    handle_sendcmpct_msg(Payload, Data);
dispatch_message(sendaddrv2, _Payload, Data) ->
    %% BIP 155: only valid before handshake complete
    case handshake_complete(Data) of
        false -> {ok, Data#peer_data{wants_addrv2 = true}};
        true  -> {ok, Data}
    end;
dispatch_message(wtxidrelay, _Payload, Data) ->
    %% BIP 339: only valid before handshake complete
    case handshake_complete(Data) of
        false -> {ok, Data#peer_data{wtxidrelay = true}};
        true  -> {ok, Data}
    end;
dispatch_message(sendtxrcncl, Payload, Data) ->
    %% BIP 330: Erlay reconciliation handshake
    handle_sendtxrcncl_msg(Payload, Data);
dispatch_message(feefilter, Payload, Data) ->
    handle_feefilter_msg(Payload, Data);
dispatch_message(Command, Payload, Data) ->
    %% Forward everything else to handler
    Data#peer_data.handler ! {peer_message, self(), Command, Payload},
    {ok, Data}.

%%% ===================================================================
%%% Internal: Handshake
%%% ===================================================================

do_send_version(#peer_data{address = {IP, Port}, our_nonce = Nonce} = Data) ->
    Params = beamchain_config:network_params(),
    %% BIP35: advertise NODE_BLOOM only when configured. Bitcoin Core gates
    %% acceptance of inbound `mempool` messages on whether we advertise this
    %% bit (see net_processing.cpp::ProcessMessage NetMsgType::MEMPOOL); the
    %% local advertisement and the inbound handler must therefore stay in
    %% lockstep — beamchain_peer_manager:handle_peer_message(_, mempool, _)
    %% disconnects peers that send MEMPOOL when this bit is off. Default-true
    %% mirrors Core's `-peerbloomfilters` default.
    BaseServices = ?NODE_NETWORK bor ?NODE_WITNESS,
    Services0 = case beamchain_config:node_bloom_enabled() of
        true  -> BaseServices bor ?NODE_BLOOM;
        false -> BaseServices
    end,
    %% BIP-157: advertise NODE_COMPACT_FILTERS only when the
    %% blockfilterindex is enabled AND its gen_server is alive.  We
    %% gate on both the config flag and the index process being up,
    %% because peers that get NODE_COMPACT_FILTERS in our services
    %% will issue getcfilters / getcfheaders / getcfcheckpt and we
    %% must be able to answer them (BIP-157 §"Service bit").
    Services1 = case beamchain_config:blockfilterindex_enabled() andalso
                     beamchain_blockfilter_index:is_enabled() of
        true  -> Services0 bor ?NODE_COMPACT_FILTERS;
        false -> Services0
    end,
    %% BIP-159: advertise NODE_NETWORK_LIMITED when prune mode is on so
    %% peers know we serve only the recent ~288-block window.  Mirrors
    %% Core's `init.cpp` (`nLocalServices |= NODE_NETWORK_LIMITED` when
    %% `IsPruneMode()` is true).  Core advertises NODE_NETWORK alongside
    %% NODE_NETWORK_LIMITED in the auto-prune case (the node still has
    %% the recent-288 window), so we keep NODE_NETWORK set as well.
    Services = case beamchain_config:prune_enabled() of
        true  -> Services1 bor ?NODE_NETWORK_LIMITED;
        false -> Services1
    end,
    Now = erlang:system_time(second),
    %% start_height MUST report our actual current tip height. Bitcoin
    %% Core peers use this to decide whether the remote is a synced
    %% peer worth pushing tip blocks to (BIP152 HB-mode candidate)
    %% or a downloader still catching up (use inv → getdata → block).
    %% Hardcoded 0 made every peer treat us as catching-up, so peers
    %% never honored our sendcmpct(announce=true) request and we
    %% received zero cmpctblocks across the 10 outbound connections.
    %% Diagnosed 2026-04-25 after a chain of three downstream BIP152
    %% fixes (announce=true, unsolicited-cmpctblock handler, and
    %% peer_manager forwarding) all came up dry.
    StartHeight = case beamchain_chainstate:get_tip_height() of
        {ok, H} -> H;
        _ -> 0
    end,
    Payload = beamchain_p2p_msg:encode_payload(version, #{
        version     => ?PROTOCOL_VERSION,
        services    => Services,
        timestamp   => Now,
        addr_recv   => #{services => 0, ip => IP, port => Port},
        addr_from   => #{services => Services, ip => {0,0,0,0},
                         port => Params#network_params.default_port},
        nonce       => Nonce,
        user_agent  => <<"/beamchain:0.1.0/">>,
        start_height => StartHeight,
        relay       => true
    }),
    Data2 = do_send_raw(version, Payload, Data),
    Data2#peer_data{version_sent = true}.

handle_version_msg(_Payload, #peer_data{version_recv = true} = Data) ->
    logger:warning("peer ~p duplicate version", [Data#peer_data.address]),
    {stop, protocol_violation};
handle_version_msg(Payload, Data) ->
    case beamchain_p2p_msg:decode_payload(version, Payload) of
        {ok, #{version := V, services := Svc, user_agent := UA,
               start_height := Height, relay := Relay, nonce := PeerNonce,
               timestamp := PeerTs}} ->
            %% Self-connection detection
            case PeerNonce =:= Data#peer_data.our_nonce of
                true ->
                    logger:info("peer ~p self-connection detected",
                                [Data#peer_data.address]),
                    {stop, self_connection};
                false ->
                    Data2 = Data#peer_data{
                        version_recv = true,
                        peer_version = V,
                        peer_services = Svc,
                        peer_user_agent = UA,
                        peer_height = Height,
                        peer_relay = Relay,
                        peer_nonce = PeerNonce,
                        peer_version_timestamp = PeerTs
                    },
                    %% Inbound: send our version if we haven't yet
                    Data3 = maybe_send_version(Data2),
                    %% Send wtxidrelay and sendaddrv2 before verack (BIP 339/155)
                    Data4 = do_send_raw(wtxidrelay, <<>>, Data3),
                    Data5 = do_send_raw(sendaddrv2, <<>>, Data4),
                    %% BIP330: Send sendtxrcncl before verack (if peer supports wtxidrelay and tx relay)
                    Data6 = maybe_send_sendtxrcncl(Data5),
                    %% Send verack
                    Data7 = do_send_raw(verack, <<>>, Data6),
                    {ok, Data7#peer_data{verack_sent = true}}
            end;
        {error, _} ->
            logger:warning("peer ~p bad version", [Data#peer_data.address]),
            {stop, bad_version}
    end.

maybe_send_version(#peer_data{direction = inbound, version_sent = false} = Data) ->
    do_send_version(Data);
maybe_send_version(Data) ->
    Data.

handle_verack_msg(Data) ->
    {ok, Data#peer_data{verack_recv = true}}.

handshake_complete(#peer_data{version_sent = true, version_recv = true,
                              verack_sent = true, verack_recv = true}) ->
    true;
handshake_complete(_) ->
    false.

%%% ===================================================================
%%% Internal: BIP330 Erlay
%%% ===================================================================

%% Send sendtxrcncl if conditions are met:
%% - Peer supports wtxidrelay (required for Erlay)
%% - Peer allows tx relay (not block-only)
%% - We're in protocol version >= 70016 (WTXID relay version)
maybe_send_sendtxrcncl(#peer_data{peer_relay = true, wtxidrelay = true,
                                   peer_version = V} = Data) when V >= 70016 ->
    %% Pre-register with Erlay module to get our local salt
    LocalSalt = beamchain_erlay:pre_register_peer(self()),
    ErlayVersion = beamchain_erlay:version(),
    Payload = beamchain_p2p_msg:encode_payload(sendtxrcncl, #{
        version => ErlayVersion,
        salt => LocalSalt
    }),
    Data2 = do_send_raw(sendtxrcncl, Payload, Data),
    Data2#peer_data{erlay_local_salt = LocalSalt};
maybe_send_sendtxrcncl(Data) ->
    %% Conditions not met for Erlay
    Data.

%% Handle received sendtxrcncl message
handle_sendtxrcncl_msg(Payload, Data) ->
    case handshake_complete(Data) of
        true ->
            %% Protocol violation: sendtxrcncl after verack
            logger:warning("peer ~p sent sendtxrcncl after verack",
                           [Data#peer_data.address]),
            {stop, protocol_violation};
        false ->
            case beamchain_p2p_msg:decode_payload(sendtxrcncl, Payload) of
                {ok, #{version := PeerVersion, salt := PeerSalt}} when PeerVersion >= 1 ->
                    %% Check if we can support Erlay with this peer
                    case Data#peer_data.peer_relay andalso Data#peer_data.erlay_local_salt =/= undefined of
                        true ->
                            %% Register with Erlay module
                            IsPeerInbound = (Data#peer_data.direction =:= inbound),
                            case beamchain_erlay:register_peer(self(), IsPeerInbound,
                                                                PeerVersion, PeerSalt) of
                                ok ->
                                    ErlayVersion = min(PeerVersion, beamchain_erlay:version()),
                                    logger:debug("peer ~p erlay enabled (version ~p)",
                                                 [Data#peer_data.address, ErlayVersion]),
                                    {ok, Data#peer_data{erlay_enabled = true,
                                                        erlay_version = ErlayVersion}};
                                {error, Reason} ->
                                    logger:warning("peer ~p erlay registration failed: ~p",
                                                   [Data#peer_data.address, Reason]),
                                    {ok, Data}
                            end;
                        false ->
                            %% We didn't send sendtxrcncl or peer doesn't relay txs
                            {ok, Data}
                    end;
                {ok, #{version := V}} when V < 1 ->
                    %% Protocol violation: version below 1
                    logger:warning("peer ~p sent sendtxrcncl with invalid version ~p",
                                   [Data#peer_data.address, V]),
                    {stop, protocol_violation};
                {error, _} ->
                    logger:warning("peer ~p bad sendtxrcncl", [Data#peer_data.address]),
                    {ok, Data}
            end
    end.

%%% ===================================================================
%%% Internal: Ping / Pong
%%% ===================================================================

handle_ping_msg(Payload, Data) ->
    case beamchain_p2p_msg:decode_payload(ping, Payload) of
        {ok, #{nonce := Nonce}} ->
            Pong = beamchain_p2p_msg:encode_payload(pong, #{nonce => Nonce}),
            {ok, do_send_raw(pong, Pong, Data)};
        _ ->
            {ok, Data}
    end.

handle_pong_msg(Payload, Data) ->
    case beamchain_p2p_msg:decode_payload(pong, Payload) of
        {ok, #{nonce := Nonce}} ->
            case Data#peer_data.last_ping_nonce of
                Nonce when Data#peer_data.ping_sent_at =/= undefined ->
                    Now = erlang:system_time(millisecond),
                    Latency = Now - Data#peer_data.ping_sent_at,
                    {ok, Data#peer_data{
                        latency_ms = Latency,
                        last_ping_nonce = undefined,
                        ping_sent_at = undefined
                    }};
                _ ->
                    %% Stale or unexpected pong, ignore
                    {ok, Data}
            end;
        _ ->
            {ok, Data}
    end.

do_send_ping(Data) ->
    Nonce = generate_nonce(),
    Payload = beamchain_p2p_msg:encode_payload(ping, #{nonce => Nonce}),
    Data2 = do_send_raw(ping, Payload, Data),
    Data2#peer_data{
        last_ping_nonce = Nonce,
        ping_sent_at = erlang:system_time(millisecond)
    }.

%%% ===================================================================
%%% Internal: Feature negotiation
%%% ===================================================================

handle_sendcmpct_msg(Payload, Data) ->
    case beamchain_p2p_msg:decode_payload(sendcmpct, Payload) of
        {ok, #{announce := Ann, version := V}} ->
            {ok, Data#peer_data{wants_cmpct = Ann, cmpct_version = V}};
        _ ->
            {ok, Data}
    end.

handle_feefilter_msg(Payload, Data) ->
    case beamchain_p2p_msg:decode_payload(feefilter, Payload) of
        {ok, #{feerate := Fee}} ->
            {ok, Data#peer_data{fee_filter = Fee}};
        _ ->
            {ok, Data}
    end.

%%% ===================================================================
%%% Internal: BIP 133 feefilter
%%% ===================================================================

%% @doc Send initial feefilter after handshake if peer supports it.
%% Only sent to peers with protocol version >= 70013 that accept tx relay.
maybe_send_initial_feefilter(#peer_data{peer_version = V, peer_relay = Relay} = Data)
        when V >= ?FEEFILTER_VERSION, Relay =:= true ->
    %% Get current mempool minimum fee
    FeeRate = get_mempool_min_fee(),
    Data2 = do_send_feefilter(FeeRate, Data),
    %% Schedule periodic feefilter updates with exponential distribution
    schedule_feefilter_timer(Data2);
maybe_send_initial_feefilter(Data) ->
    %% Peer doesn't support feefilter or doesn't want tx relay
    Data.

%% @doc Send a feefilter message to the peer.
do_send_feefilter(FeeRate, Data) ->
    %% Ensure minimum relay fee floor
    FilterToSend = max(FeeRate, ?DEFAULT_MIN_RELAY_FEE),
    Payload = beamchain_p2p_msg:encode_payload(feefilter, #{feerate => FilterToSend}),
    Data2 = do_send_raw(feefilter, Payload, Data),
    Now = erlang:system_time(millisecond),
    Data2#peer_data{
        our_fee_filter = FilterToSend,
        feefilter_sent_at = Now
    }.

%% @doc Schedule next feefilter update using exponential distribution.
%% Average interval is 10 minutes for privacy.
schedule_feefilter_timer(Data) ->
    %% Cancel any existing timer
    case Data#peer_data.feefilter_timer_ref of
        undefined -> ok;
        OldRef -> erlang:cancel_timer(OldRef)
    end,
    %% Exponential distribution: -ln(U) * mean
    Interval = feefilter_poisson_interval(?FEEFILTER_BROADCAST_INTERVAL_MS),
    Ref = erlang:send_after(Interval, self(), check_feefilter),
    Data#peer_data{feefilter_timer_ref = Ref}.

%% @doc Generate Poisson-distributed interval.
feefilter_poisson_interval(MeanMs) ->
    U = rand:uniform(),
    Interval = round(-math:log(U) * MeanMs),
    %% Clamp to reasonable bounds (1 second to 30 minutes)
    max(1000, min(Interval, 1800000)).

%% @doc Check if feefilter should be updated and send if necessary.
maybe_update_feefilter(Data) ->
    CurrentFee = get_mempool_min_fee(),
    SentFee = Data#peer_data.our_fee_filter,
    Now = erlang:system_time(millisecond),
    SentAt = Data#peer_data.feefilter_sent_at,

    %% Check if fee changed significantly (>25% drop or >33% increase)
    %% Bitcoin Core uses: currentFilter < 3 * sent / 4 || currentFilter > 4 * sent / 3
    SignificantChange = (CurrentFee * 4 < SentFee * 3) orelse
                        (CurrentFee * 3 > SentFee * 4),

    case SignificantChange of
        true when SentAt =/= undefined ->
            %% Significant change - schedule accelerated update with random delay
            %% up to MAX_FEEFILTER_CHANGE_DELAY_MS for privacy
            Delay = rand:uniform(?FEEFILTER_MAX_CHANGE_DELAY_MS),
            NextSendAt = SentAt + ?FEEFILTER_BROADCAST_INTERVAL_MS,
            %% Only accelerate if we weren't going to send soon anyway
            case Now + Delay < NextSendAt of
                true ->
                    %% Update now with small random delay
                    erlang:send_after(Delay, self(), send_feefilter_now),
                    Data;
                false ->
                    Data
            end;
        _ ->
            %% No significant change or first update - send if filter value changed
            case CurrentFee =/= SentFee of
                true ->
                    do_send_feefilter(CurrentFee, Data);
                false ->
                    Data
            end
    end.

%% @doc Get current mempool minimum fee rate in sat/kvB.
get_mempool_min_fee() ->
    try
        case beamchain_mempool:get_info() of
            #{min_fee := MinFee} when is_number(MinFee) ->
                %% Convert sat/vB to sat/kvB (multiply by 1000)
                round(MinFee * 1000);
            _ ->
                ?DEFAULT_MIN_RELAY_FEE
        end
    catch
        _:_ -> ?DEFAULT_MIN_RELAY_FEE
    end.

send_feature_msgs(Data) ->
    %% sendheaders and sendcmpct are sent after handshake complete.
    %% wtxidrelay and sendaddrv2 are sent before verack (see handle_version_msg).
    D1 = do_send_raw(sendheaders, <<>>, Data),
    %% BIP152 §"Pre-Versioning Considerations":
    %%   "An implementation that supports both version 1 and version 2 must
    %%    send both sendcmpct messages."
    %% Bitcoin Core sends v1 first, then v2 — the last sendcmpct received
    %% by the peer is the authoritative one for HB-mode preference.
    %%   v1 with announce=false: we don't want non-witness compact blocks
    %%   v2 with announce=true:  we DO want SegWit-aware compact blocks
    %%                           pushed unsolicited for new tips
    %% Sending only v2 (the prior code path) produced 6+ hours of zero
    %% cmpctblock arrivals on mainnet on 2026-04-25 — peers strictly
    %% check v1 support before honoring any HB request, so without the
    %% v1 sendcmpct we never get into any peer's HB-to set.
    CmpctV1 = beamchain_p2p_msg:encode_payload(sendcmpct,
                  #{announce => false, version => 1}),
    D2 = do_send_raw(sendcmpct, CmpctV1, D1),
    CmpctV2 = beamchain_p2p_msg:encode_payload(sendcmpct,
                  #{announce => true, version => 2}),
    D3 = do_send_raw(sendcmpct, CmpctV2, D2),
    %% BIP 133: Send feefilter if peer supports it
    maybe_send_initial_feefilter(D3).

%%% ===================================================================
%%% Internal: Misbehavior
%%% ===================================================================

check_ban(#peer_data{misbehavior = Score, address = Addr} = Data)
        when Score >= ?BAN_SCORE ->
    logger:info("peer ~p banned (score=~B)", [Addr, Score]),
    Data#peer_data.handler ! {peer_banned, self(), Addr},
    {stop, banned};
check_ban(Data) ->
    {keep_state, Data}.

%%% ===================================================================
%%% Internal: Send helpers
%%% ===================================================================

do_send_msg(Command, PayloadData, Data) ->
    Payload = beamchain_p2p_msg:encode_payload(Command, PayloadData),
    do_send_raw(Command, Payload, Data).

%% v2 application-data path.  AEAD-encrypt with empty AAD
%% (BIP-324 §"Wire format" reserves AAD for the very first post-handshake
%% packet from each direction; we already consumed that during the
%% cipher-handshake).
%%
%% IMPORTANT: the cipher state MUST only advance (via the `Cipher2` we
%% commit into the returned record) AFTER `gen_tcp:send` succeeds.  If we
%% advanced unconditionally and the send failed mid-handshake (peer RST),
%% the next outbound message would re-encrypt under a wrongly-advanced
%% cipher and the peer's recv-cipher would auth-fail on the FIRST byte —
%% a desync that's hard to diagnose in the wild.  On send failure we
%% leave the old cipher in place, log, and let the recv side surface
%% `{tcp_closed, _}` to the gen_statem, which exits via the normal
%% `handshaking(info, {tcp_closed, _})` clause.  Net effect: behaviourally
%% equivalent to the prior silent-failure code, but cipher state stays
%% consistent with what's actually on the wire.
do_send_raw(Command, Payload, #peer_data{v2_phase = ready,
                                          v2_cipher = Cipher,
                                          socket = Socket} = Data)
  when Cipher =/= undefined ->
    Contents = beamchain_v2_msg:encode_contents(Command, Payload),
    {ok, Wire, Cipher2} = beamchain_transport_v2:encrypt(
        Cipher, Contents, <<>>, false),
    case gen_tcp:send(Socket, Wire) of
        ok ->
            Data#peer_data{
                v2_cipher  = Cipher2,
                bytes_sent = Data#peer_data.bytes_sent + byte_size(Wire),
                last_send  = erlang:system_time(millisecond)
            };
        {error, Reason} ->
            logger:debug("peer ~p v2 send ~p failed: ~p — leaving cipher "
                         "untouched; closing on next tcp_closed",
                         [Data#peer_data.address, Command, Reason]),
            Data
    end;
do_send_raw(Command, Payload, #peer_data{socket = Socket, magic = Magic} = Data) ->
    Msg = beamchain_p2p_msg:encode_msg(Magic, Command, Payload),
    case gen_tcp:send(Socket, Msg) of
        ok ->
            Data#peer_data{
                bytes_sent = Data#peer_data.bytes_sent + byte_size(Msg),
                last_send  = erlang:system_time(millisecond)
            };
        {error, Reason} ->
            logger:debug("peer ~p v1 send ~p failed: ~p",
                         [Data#peer_data.address, Command, Reason]),
            Data
    end.

%%% ===================================================================
%%% Internal: Helpers
%%% ===================================================================

generate_nonce() ->
    <<N:64>> = crypto:strong_rand_bytes(8),
    N.

build_info(#peer_data{} = D) ->
    #{address       => D#peer_data.address,
      direction     => D#peer_data.direction,
      version       => D#peer_data.peer_version,
      services      => D#peer_data.peer_services,
      user_agent    => D#peer_data.peer_user_agent,
      start_height  => D#peer_data.peer_height,
      relay         => D#peer_data.peer_relay,
      latency_ms    => D#peer_data.latency_ms,
      bytes_sent    => D#peer_data.bytes_sent,
      bytes_recv    => D#peer_data.bytes_recv,
      last_send     => D#peer_data.last_send,
      last_recv     => D#peer_data.last_recv,
      connected_at  => D#peer_data.connected_at,
      %% BIP339: peer signaled wtxidrelay before verack — when answering an
      %% inv-style enumeration (e.g. BIP35 mempool), we send MSG_WTX entries
      %% in place of MSG_TX. Surfaced via info/1 so peer_manager can decide
      %% the inv type without poking the gen_statem state directly.
      wtxidrelay    => D#peer_data.wtxidrelay,
      peer_version_timestamp => D#peer_data.peer_version_timestamp}.

%%% ===================================================================
%%% Internal: Inv trickling (privacy-preserving tx relay)
%%% ===================================================================

%% Schedule the next trickle timer using Poisson distribution.
%% For exponentially distributed intervals: -ln(U) * mean
%% where U is uniform random in (0,1].
schedule_trickle_timer(#peer_data{direction = Dir} = Data) ->
    %% Cancel any existing timer
    case Data#peer_data.trickle_timer_ref of
        undefined -> ok;
        OldRef -> erlang:cancel_timer(OldRef)
    end,
    %% Calculate Poisson-distributed interval
    BaseInterval = case Dir of
        inbound  -> ?INBOUND_INV_INTERVAL_MS;
        outbound -> ?OUTBOUND_INV_INTERVAL_MS
    end,
    Interval = poisson_interval(BaseInterval),
    Ref = erlang:send_after(Interval, self(), trickle_inv),
    Data#peer_data{trickle_timer_ref = Ref}.

%% Generate Poisson-distributed interval: -ln(U) * mean
%% where U is uniform random in (0,1]. We use rand:uniform() which
%% returns (0.0, 1.0] and apply the transformation.
poisson_interval(MeanMs) ->
    U = rand:uniform(),  %% (0.0, 1.0]
    Interval = round(-math:log(U) * MeanMs),
    %% Clamp to reasonable bounds (1ms to 60s)
    max(1, min(Interval, 60000)).

%% Flush pending tx inv items to the peer.
%% Randomize order to prevent timing analysis, limit per tick.
%% Filter by peer's feefilter (BIP 133) before sending.
do_trickle_inv(#peer_data{pending_tx_inv = []} = Data) ->
    Data;
do_trickle_inv(#peer_data{pending_tx_inv = Pending, peer_relay = Relay,
                          fee_filter = PeerFeeFilter} = Data) ->
    case Relay of
        false ->
            %% Peer requested no tx relay, clear queue
            Data#peer_data{pending_tx_inv = []};
        true ->
            %% Filter by peer's feefilter (BIP 133)
            %% Skip txs with fee rate below peer's minimum
            Filtered = filter_by_feefilter(Pending, PeerFeeFilter),
            %% Calculate broadcast max: target + 5 per 1000 pending
            BroadcastMax = min(?INV_BROADCAST_MAX,
                               ?INV_BROADCAST_TARGET + (length(Filtered) div 1000) * 5),
            %% Shuffle and take up to max
            Shuffled = shuffle_list(Filtered),
            {ToSend, Remaining} = lists:split(min(BroadcastMax, length(Shuffled)), Shuffled),
            %% Send inv message if we have items
            Data2 = case ToSend of
                [] -> Data;
                _  -> send_tx_inv(ToSend, Data)
            end,
            %% Remove filtered txs from queue (they'll never pass the filter)
            FilteredOut = Pending -- Filtered,
            Data2#peer_data{pending_tx_inv = Remaining -- FilteredOut}
    end.

%% @doc Filter txids by peer's feefilter value.
%% Returns only txids whose fee rate >= peer's feefilter.
filter_by_feefilter(Txids, PeerFeeFilter) when PeerFeeFilter =< 0 ->
    %% No feefilter or peer accepts all fees
    Txids;
filter_by_feefilter(Txids, PeerFeeFilter) ->
    lists:filter(fun(Txid) ->
        tx_passes_feefilter(Txid, PeerFeeFilter)
    end, Txids).

%% @doc Check if a transaction's fee rate passes the peer's feefilter.
%% feefilter is in sat/kvB, we need to compare with tx fee rate.
tx_passes_feefilter(Txid, PeerFeeFilter) ->
    case beamchain_mempool:get_tx_fee_rate(Txid) of
        {ok, FeeRateKvB} ->
            %% FeeRateKvB is already in sat/kvB
            FeeRateKvB >= PeerFeeFilter;
        not_found ->
            %% Tx no longer in mempool, filter it out
            false
    end.

%% Send inv message for a list of txids
send_tx_inv(Txids, Data) ->
    Items = [#{type => 1, hash => Txid} || Txid <- Txids],  %% 1 = MSG_TX
    do_send_msg(inv, #{items => Items}, Data).

%% Fisher-Yates shuffle for randomizing inv order
shuffle_list([]) -> [];
shuffle_list([X]) -> [X];
shuffle_list(List) ->
    %% Use a simple random sort for small lists
    lists:sort(fun(_, _) -> rand:uniform() > 0.5 end, List).

%% Convert binary to string for hostname handling
to_string(S) when is_list(S) -> S;
to_string(B) when is_binary(B) -> binary_to_list(B).
