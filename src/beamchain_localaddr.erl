-module(beamchain_localaddr).

%% Self-address advertisement (Bitcoin Core parity).
%%
%% A listening node must tell the network where it can be reached, or nobody
%% ever dials it: peers only learn addresses from addr/addrv2 gossip, and the
%% only gossip source for OUR address is us. Core does this in three parts,
%% all mirrored here as PURE functions (the peer manager owns the state and
%% does the I/O, so every decision below is unit-testable):
%%
%%  1. A table of local addresses (Core net.cpp mapLocalHost / AddLocal /
%%     SeenLocal). Entries come from -externalip (score ?LOCAL_MANUAL) and
%%     from discovery: an OUTBOUND peer's VERSION carries addr_recv, the
%%     address it sees us at. A discovered entry's score is the number of
%%     DISTINCT peer netgroups that confirmed it, so one peer (or one /16)
%%     cannot talk us into advertising an address; it must be confirmed by
%%     ?MIN_DISCOVERED_SCORE groups before it is advertised, and it ages out
%%     after ?DISCOVERED_TTL without a fresh confirmation, so a changed public
%%     IP replaces the old one. Inbound peers only score an existing entry.
%%  2. The per-peer choice of which address to advertise (Core net.cpp
%%     GetLocalAddrForPeer:240-268).
%%  3. The send gate (Core net_processing.cpp MaybeSendAddr:5445-5479): only
%%     when listening and out of IBD, never to block-relay-only or feeler
%%     connections; one addr/addrv2 carrying just our address right after the
%%     handshake, then again on a Poisson timer averaging 24h
%%     (AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL). While in IBD the per-peer
%%     schedule is left untouched, so the first send goes out on the first
%%     tick after IBD ends.
%%
%% Reference design: blockbrew a255986 internal/p2p/localaddr.go.

-export([new/0,
         routable_ip/1,
         parse_externalip/1,
         parse_externalip_list/1,
         add_manual/3,
         confirm/6,
         best/3,
         list/2,
         note_addr_recv/2,
         local_addr_for_peer/2,
         announce_due/2,
         self_addr_message/5,
         next_delay/0,
         next_delay/1,
         discover_enabled/2]).

-export_type([table/0]).

%% Core net.h enum: LOCAL_NONE..LOCAL_MANUAL.
-define(LOCAL_MANUAL, 4).
%% Core net_processing.cpp:158 AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL = 24h.
-define(AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL, 86400).
%% Discovered (non-manual) entries unconfirmed for this long are dropped.
-define(DISCOVERED_TTL, 3 * 3600).
%% Distinct peer netgroups that must confirm a discovered address before it
%% is advertised to OTHER peers.
-define(MIN_DISCOVERED_SCORE, 2).
%% Cap on discovered entries (weakest, then oldest, is evicted).
-define(MAX_DISCOVERED, 8).
%% Cap on per-entry confirmer set (score ceiling).
-define(MAX_CONFIRMERS, 64).

%% Entry: #{ip, port, manual, base, confirmers => #{Group => true}, last_seen}
-type entry() :: #{ip := inet:ip_address(), port := inet:port_number(),
                   manual := boolean(), base := non_neg_integer(),
                   confirmers := #{term() => true},
                   last_seen := integer()}.
-type table() :: #{inet:ip_address() => entry()}.

-spec new() -> table().
new() -> #{}.

%%% -------------------------------------------------------------------
%%% Routability
%%% -------------------------------------------------------------------

%% @doc True iff IP is a publicly routable IPv4/IPv6 address. Reuses the
%% addrman filter (Core CNetAddr::IsRoutable) and additionally rejects the
%% IPv6 unspecified address and multicast, which that filter lets through.
-spec routable_ip(term()) -> boolean().
routable_ip({0, 0, 0, 0}) -> false;
routable_ip({A, _, _, _} = IP) when is_integer(A), A >= 224 ->
    %% 224/4 multicast, 240/4 reserved, 255.255.255.255 broadcast.
    _ = IP, false;
routable_ip({_, _, _, _} = IP) ->
    valid_tuple(IP, 255) andalso beamchain_addrman:is_routable({IP, 0}, 1);
routable_ip({0, 0, 0, 0, 0, 0, 0, 0}) -> false;
routable_ip({A, _, _, _, _, _, _, _}) when is_integer(A),
                                            (A band 16#ff00) =:= 16#ff00 ->
    false;  %% ff00::/8 multicast
routable_ip({_, _, _, _, _, _, _, _} = IP) ->
    valid_tuple(IP, 65535) andalso beamchain_addrman:is_routable({IP, 0}, 2);
routable_ip(_) -> false.

valid_tuple(T, Max) ->
    lists:all(fun(X) -> is_integer(X) andalso X >= 0 andalso X =< Max end,
              tuple_to_list(T)).

%%% -------------------------------------------------------------------
%%% -externalip parsing
%%% -------------------------------------------------------------------

%% @doc Parse one -externalip value: "<ip>", "<ip>:<port>", "<ipv6>" or
%% "[<ipv6>]:<port>". Port 0 means "use the P2P listen port".
-spec parse_externalip(string() | binary()) ->
    {ok, inet:ip_address(), inet:port_number()} | {error, term()}.
parse_externalip(B) when is_binary(B) -> parse_externalip(binary_to_list(B));
parse_externalip(S0) when is_list(S0) ->
    S = string:trim(S0),
    case inet:parse_strict_address(S) of
        {ok, IP} -> {ok, IP, 0};
        {error, _} ->
            case S of
                [$[ | Rest] ->
                    case string:split(Rest, "]:") of
                        [Host, PortStr] -> host_port(Host, PortStr, S);
                        _ -> host_port(string:trim(Rest, trailing, "]"), "0", S)
                    end;
                _ ->
                    case string:split(S, ":", trailing) of
                        [Host, PortStr] -> host_port(Host, PortStr, S);
                        _ -> {error, {invalid_address, S}}
                    end
            end
    end.

host_port(Host, PortStr, Orig) ->
    case inet:parse_strict_address(Host) of
        {ok, IP} ->
            case catch list_to_integer(PortStr) of
                0 when PortStr =:= "0" -> {ok, IP, 0};
                P when is_integer(P), P > 0, P =< 65535 -> {ok, IP, P};
                _ -> {error, {invalid_port, Orig}}
            end;
        {error, _} -> {error, {invalid_address, Orig}}
    end.

%% @doc Flatten repeatable / comma-separated -externalip values.
-spec parse_externalip_list([string() | binary()] | string() | binary() | undefined) ->
    [string()].
parse_externalip_list(undefined) -> [];
parse_externalip_list(B) when is_binary(B) -> parse_externalip_list(binary_to_list(B));
parse_externalip_list([]) -> [];
parse_externalip_list([C | _] = S) when is_integer(C) ->
    [X || X <- [string:trim(P) || P <- string:split(S, ",", all)], X =/= ""];
parse_externalip_list(L) when is_list(L) ->
    lists:append([parse_externalip_list(X) || X <- L]).

%% @doc Core init.cpp:815 — -externalip soft-sets -discover=0 unless
%% -discover was given explicitly. Explicit = true | false | undefined.
-spec discover_enabled(true | false | undefined, [term()]) -> boolean().
discover_enabled(true, _) -> true;
discover_enabled(false, _) -> false;
discover_enabled(undefined, []) -> true;
discover_enabled(undefined, [_ | _]) -> false.

%%% -------------------------------------------------------------------
%%% Table operations
%%% -------------------------------------------------------------------

%% @doc Record an operator-specified address (Core AddLocal LOCAL_MANUAL).
%% Refuses non-routable addresses like Core.
-spec add_manual(table(), inet:ip_address(), inet:port_number()) ->
    {ok, table()} | {error, not_routable}.
add_manual(T, IP, Port) ->
    case routable_ip(IP) of
        false -> {error, not_routable};
        true ->
            E0 = maps:get(IP, T, new_entry(IP, Port, 0)),
            {ok, T#{IP => E0#{manual => true, base => ?LOCAL_MANUAL,
                              port => Port}}}
    end.

new_entry(IP, Port, Now) ->
    #{ip => IP, port => Port, manual => false, base => 0,
      confirmers => #{}, last_seen => Now}.

%% @doc A peer in netgroup Group reports seeing us at IP. Create=false
%% (inbound peer, Core SeenLocal) only scores an existing entry; Create=true
%% (outbound addr_recv discovery) creates a new entry with Port.
-spec confirm(table(), inet:ip_address(), inet:port_number(), term(),
              boolean(), integer()) -> table().
confirm(T0, IP, Port, Group, Create, Now) ->
    case routable_ip(IP) of
        false -> T0;
        true ->
            T = expire(T0, Now),
            case maps:find(IP, T) of
                {ok, E} -> T#{IP => add_confirmer(E, Group, Now)};
                error when Create ->
                    T2 = make_room(T),
                    T2#{IP => add_confirmer(new_entry(IP, Port, Now), Group, Now)};
                error -> T
            end
    end.

add_confirmer(#{confirmers := C} = E, Group, Now) ->
    C2 = case maps:size(C) < ?MAX_CONFIRMERS of
        true -> C#{Group => true};
        false -> C
    end,
    E#{confirmers => C2, last_seen => Now}.

expire(T, Now) ->
    maps:filter(fun(_, #{manual := true}) -> true;
                   (_, #{last_seen := L}) -> Now - L =< ?DISCOVERED_TTL
                end, T).

make_room(T) ->
    Disc = [E || E = #{manual := false} <- maps:values(T)],
    case length(Disc) >= ?MAX_DISCOVERED of
        false -> T;
        true ->
            [#{ip := Worst} | _] =
                lists:sort(fun(A, B) ->
                                   {score(A), maps:get(last_seen, A)} =<
                                       {score(B), maps:get(last_seen, B)}
                           end, Disc),
            maps:remove(Worst, T)
    end.

score(#{base := B, confirmers := C}) -> B + maps:size(C).

usable(#{manual := true}) -> true;
usable(#{confirmers := C}) -> maps:size(C) >= ?MIN_DISCOVERED_SCORE.

%% @doc Best usable local address for a peer at PeerIP (Core GetLocal):
%% same address family first, then highest score, then most recent.
-spec best(table(), inet:ip_address() | undefined, integer()) ->
    {ok, {inet:ip_address(), inet:port_number(), non_neg_integer()}} | none.
best(T0, PeerIP, Now) ->
    T = expire(T0, Now),
    Reach = fun(#{ip := IP}) ->
                    case PeerIP of
                        undefined -> 0;
                        _ when tuple_size(IP) =:= tuple_size(PeerIP) -> 1;
                        _ -> 0
                    end
            end,
    Cands = [E || E <- maps:values(T), usable(E)],
    case lists:sort(fun(A, B) ->
                            {Reach(A), score(A), maps:get(last_seen, A)} >=
                                {Reach(B), score(B), maps:get(last_seen, B)}
                    end, Cands) of
        [] -> none;
        [#{ip := IP, port := Port} = E | _] -> {ok, {IP, Port, score(E)}}
    end.

%% @doc Every entry, highest score first (getnetworkinfo.localaddresses).
-spec list(table(), integer()) ->
    [{inet:ip_address(), inet:port_number(), non_neg_integer()}].
list(T0, Now) ->
    T = expire(T0, Now),
    L = [{IP, P, score(E)} || #{ip := IP, port := P} = E <- maps:values(T)],
    lists:sort(fun({IA, _, SA}, {IB, _, SB}) ->
                       {-SA, inet:ntoa(IA)} =< {-SB, inet:ntoa(IB)}
               end, L).

%%% -------------------------------------------------------------------
%%% Discovery from a peer's VERSION addr_recv
%%% -------------------------------------------------------------------

%% @doc Ctx = #{table, discover, listen_port, peer_ip, peer_group, inbound,
%% addr_recv_ip, now}. Only with -discover and while listening; both the
%% peer and the reported address must be routable (Core
%% IsPeerAddrLocalGood). Discovered entries carry OUR listen port — an
%% outbound peer cannot observe it.
-spec note_addr_recv(table(), map()) -> table().
note_addr_recv(T, #{discover := true, listen_port := LP, peer_ip := PeerIP,
                    peer_group := Group, inbound := Inbound,
                    addr_recv_ip := Seen, now := Now})
  when is_integer(LP), LP > 0 ->
    case routable_ip(PeerIP) andalso routable_ip(Seen) of
        true -> confirm(T, Seen, LP, Group, not Inbound, Now);
        false -> T
    end;
note_addr_recv(T, _) -> T.

%%% -------------------------------------------------------------------
%%% Per-peer address choice (Core GetLocalAddrForPeer, net.cpp:240-268)
%%% -------------------------------------------------------------------

%% @doc Ctx = #{table, discover, listen_port, peer_ip, inbound,
%% addr_local => undefined | {IP, Port}, now, rand => fun((Bits) -> int)}.
-spec local_addr_for_peer(table(), map()) ->
    {ok, inet:ip_address(), inet:port_number()} | none.
local_addr_for_peer(T, #{discover := Discover, listen_port := LP,
                         peer_ip := PeerIP, inbound := Inbound,
                         addr_local := AddrLocal, now := Now} = Ctx) ->
    Rand = maps:get(rand, Ctx, fun(Bits) -> rand:uniform(1 bsl Bits) - 1 end),
    {HaveLocal, IP0, Port0, Score} = case best(T, PeerIP, Now) of
        {ok, {I, P, S}} -> {true, I, P, S};
        none -> {false, undefined, LP, 0}
    end,
    {IP, Port} =
        case AddrLocal of
            {SeenIP, SeenPort} ->
                PeerGood = Discover andalso routable_ip(PeerIP)
                           andalso routable_ip(SeenIP),
                Bits = case Score > ?LOCAL_MANUAL of true -> 3; false -> 1 end,
                case PeerGood andalso ((not HaveLocal) orelse Rand(Bits) =:= 0) of
                    true when Inbound -> {SeenIP, SeenPort};
                    true -> {SeenIP, Port0};
                    false -> {IP0, Port0}
                end;
            _ -> {IP0, Port0}
        end,
    case routable_ip(IP) andalso is_integer(Port) andalso Port > 0 of
        true -> {ok, IP, Port};
        false -> none
    end.

%%% -------------------------------------------------------------------
%%% Send gate + message (Core MaybeSendAddr)
%%% -------------------------------------------------------------------

%% @doc Ctx = #{listening, ibd, conn_type, next_send => undefined | Ts, now}.
%% Returns skip, or {send, NextSendTs}. IBD returns skip WITHOUT touching
%% the schedule, so the first send happens on the first tick after IBD.
-spec announce_due(map(), fun(() -> non_neg_integer())) ->
    skip | {send, integer()}.
announce_due(#{listening := false}, _) -> skip;
announce_due(#{conn_type := block_relay}, _) -> skip;
announce_due(#{conn_type := feeler}, _) -> skip;
announce_due(#{ibd := true}, _) -> skip;
announce_due(#{next_send := Next, now := Now}, DelayFun) ->
    case Next =:= undefined orelse Now >= Next of
        true -> {send, Now + DelayFun()};
        false -> skip
    end.

%% @doc The single-entry self-announcement: our address, the services we
%% sent in VERSION, time now, and the given (listen) port. addrv2 when the
%% peer sent sendaddrv2 (BIP-155), else legacy addr.
-spec self_addr_message(inet:ip_address(), inet:port_number(),
                        non_neg_integer(), integer(), boolean()) ->
    {addr | addrv2, map()}.
self_addr_message(IP, Port, Services, Now, WantsAddrv2) ->
    Entry = #{timestamp => Now, services => Services, ip => IP, port => Port},
    case WantsAddrv2 of
        true -> {addrv2, #{addrs => [Entry]}};
        false -> {addr, #{addrs => [Entry]}}
    end.

%% @doc Poisson inter-announcement delay in seconds (mean 24h).
-spec next_delay() -> non_neg_integer().
next_delay() -> next_delay(rand:uniform()).

-spec next_delay(float()) -> non_neg_integer().
next_delay(U) when U > 0.0, U =< 1.0 ->
    round(-math:log(U) * ?AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL).
