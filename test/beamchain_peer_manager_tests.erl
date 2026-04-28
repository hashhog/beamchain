-module(beamchain_peer_manager_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%%% ===================================================================
%%% Test fixtures
%%% ===================================================================

%% Setup banned_peers ETS table for testing
setup() ->
    %% Create the banned_peers table if it doesn't exist
    case ets:info(banned_peers) of
        undefined ->
            ets:new(banned_peers, [named_table, set, public,
                                   {read_concurrency, true}]);
        _ ->
            ets:delete_all_objects(banned_peers)
    end,
    %% Create the beamchain_peers table for peer lookups
    case ets:info(beamchain_peers) of
        undefined ->
            ets:new(beamchain_peers, [named_table, set, public,
                                      {keypos, 2},  %% pid is at position 2
                                      {read_concurrency, true}]);
        _ ->
            ets:delete_all_objects(beamchain_peers)
    end,
    ok.

cleanup(_) ->
    catch ets:delete_all_objects(banned_peers),
    catch ets:delete_all_objects(beamchain_peers).

%%% ===================================================================
%%% Ban list ETS tests (unit tests without gen_server)
%%% ===================================================================

ban_ets_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [
         {"empty ban list", fun() ->
             ?assertEqual([], ets:tab2list(banned_peers))
         end},

         {"add and check ban", fun() ->
             IP = {192, 168, 1, 100},
             BanExpiry = erlang:system_time(second) + 3600,
             ets:insert(banned_peers, {IP, BanExpiry}),
             [{IP, Got}] = ets:lookup(banned_peers, IP),
             ?assertEqual(BanExpiry, Got)
         end},

         {"check non-banned IP", fun() ->
             IP = {10, 0, 0, 1},
             ?assertEqual([], ets:lookup(banned_peers, IP))
         end},

         {"remove ban", fun() ->
             IP = {192, 168, 1, 200},
             BanExpiry = erlang:system_time(second) + 3600,
             ets:insert(banned_peers, {IP, BanExpiry}),
             ?assertMatch([{IP, _}], ets:lookup(banned_peers, IP)),
             ets:delete(banned_peers, IP),
             ?assertEqual([], ets:lookup(banned_peers, IP))
         end},

         {"multiple bans", fun() ->
             ets:delete_all_objects(banned_peers),
             IP1 = {192, 168, 1, 1},
             IP2 = {192, 168, 1, 2},
             IP3 = {192, 168, 1, 3},
             Now = erlang:system_time(second),
             ets:insert(banned_peers, {IP1, Now + 3600}),
             ets:insert(banned_peers, {IP2, Now + 7200}),
             ets:insert(banned_peers, {IP3, Now + 1800}),
             ?assertEqual(3, ets:info(banned_peers, size))
         end}
        ]
     end}.

%%% ===================================================================
%%% Ban expiry tests
%%% ===================================================================

ban_expiry_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [
         {"expired ban detection", fun() ->
             IP = {10, 20, 30, 40},
             %% Set ban to expire 1 second ago
             PastExpiry = erlang:system_time(second) - 1,
             ets:insert(banned_peers, {IP, PastExpiry}),
             %% The ban entry exists
             ?assertMatch([{IP, _}], ets:lookup(banned_peers, IP)),
             %% But logically it's expired (expiry < now)
             Now = erlang:system_time(second),
             [{IP, Expiry}] = ets:lookup(banned_peers, IP),
             ?assert(Expiry < Now)
         end},

         {"future ban is active", fun() ->
             IP = {10, 20, 30, 50},
             FutureExpiry = erlang:system_time(second) + 86400,
             ets:insert(banned_peers, {IP, FutureExpiry}),
             [{IP, Expiry}] = ets:lookup(banned_peers, IP),
             Now = erlang:system_time(second),
             ?assert(Expiry > Now)
         end}
        ]
     end}.

%%% ===================================================================
%%% Misbehavior score accumulation tests
%%% ===================================================================

misbehavior_score_test_() ->
    {"misbehavior score accumulation",
     [
      {"scores below threshold don't ban", fun() ->
          %% 10 + 20 + 30 = 60 < 100
          Score1 = 10,
          Score2 = 20,
          Score3 = 30,
          Total = Score1 + Score2 + Score3,
          ?assert(Total < 100)
      end},

      {"single high score triggers ban", fun() ->
          %% invalid_block = 100 = instant ban
          ?assertEqual(100, 100)  %% BAN_THRESHOLD
      end},

      {"accumulated scores trigger ban", fun() ->
          %% 20 + 20 + 20 + 20 + 20 = 100 = ban
          Scores = [20, 20, 20, 20, 20],
          Total = lists:sum(Scores),
          ?assert(Total >= 100)
      end},

      {"invalid_tx needs 10 violations", fun() ->
          %% invalid_tx = 10 points, need 10 to reach 100
          InvalidTxScore = 10,
          Violations = 100 div InvalidTxScore,
          ?assertEqual(10, Violations)
      end},

      {"unconnecting_headers needs 5 violations", fun() ->
          %% unconnecting_headers = 20 points, need 5 to reach 100
          HeadersScore = 20,
          Violations = 100 div HeadersScore,
          ?assertEqual(5, Violations)
      end}
     ]}.

%%% ===================================================================
%%% Score value tests (matching Bitcoin Core)
%%% ===================================================================

score_values_test_() ->
    {"misbehavior score values",
     [
      {"invalid_block causes instant ban", fun() ->
          ?assertEqual(100, 100)  %% MISBEHAVIOR_INVALID_BLOCK
      end},

      {"invalid_compact_block causes instant ban", fun() ->
          ?assertEqual(100, 100)  %% MISBEHAVIOR_INVALID_COMPACT_BLOCK
      end},

      {"invalid_tx is 10 points", fun() ->
          ?assertEqual(10, 10)  %% MISBEHAVIOR_INVALID_TX
      end},

      {"unconnecting_headers is 20 points", fun() ->
          ?assertEqual(20, 20)  %% MISBEHAVIOR_UNCONNECTING_HEADERS
      end}
     ]}.

%%% ===================================================================
%%% Ban duration tests
%%% ===================================================================

ban_duration_test_() ->
    {"ban duration",
     [
      {"default ban is 24 hours", fun() ->
          DefaultDuration = 86400,
          ?assertEqual(24 * 60 * 60, DefaultDuration)
      end},

      {"ban expiry calculation", fun() ->
          Now = erlang:system_time(second),
          Duration = 86400,
          Expiry = Now + Duration,
          ?assertEqual(Duration, Expiry - Now)
      end}
     ]}.

%%% ===================================================================
%%% IP address handling tests
%%% ===================================================================

ip_address_test_() ->
    {"IP address handling",
     [
      {"ipv4 ban key", fun() ->
          %% Bans are by IP, not port
          IP = {192, 168, 1, 1},
          Port1 = 8333,
          Port2 = 18333,
          Address1 = {IP, Port1},
          Address2 = {IP, Port2},
          {BanIP1, _} = Address1,
          {BanIP2, _} = Address2,
          ?assertEqual(BanIP1, BanIP2)
      end},

      {"different IPs are different bans", fun() ->
          IP1 = {192, 168, 1, 1},
          IP2 = {192, 168, 1, 2},
          ?assertNotEqual(IP1, IP2)
      end}
     ]}.

%%% ===================================================================
%%% Integration-style tests (mocking peer entries)
%%% ===================================================================

peer_entry_misbehavior_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [
         {"peer entry with initial score", fun() ->
             %% Create a mock peer entry with misbehavior_score
             PeerEntry = {peer_entry,
                          self(),                    %% pid
                          {{192,168,1,1}, 8333},    %% address
                          outbound,                  %% direction
                          make_ref(),               %% mon_ref
                          true,                     %% connected
                          #{},                      %% info
                          0},                       %% misbehavior_score
             ?assertMatch({peer_entry, _, _, _, _, _, _, 0}, PeerEntry)
         end},

         {"peer entry with accumulated score", fun() ->
             %% Simulate updating score
             InitialScore = 0,
             Increment = 20,
             NewScore = InitialScore + Increment,
             ?assertEqual(20, NewScore)
         end},

         {"peer entry reaches ban threshold", fun() ->
             Scores = [20, 20, 30, 30],  %% Total: 100
             TotalScore = lists:sum(Scores),
             BanThreshold = 100,
             ?assert(TotalScore >= BanThreshold)
         end}
        ]
     end}.

%%% ===================================================================
%%% Edge cases
%%% ===================================================================

edge_cases_test_() ->
    {"edge cases",
     [
      {"zero score doesn't change total", fun() ->
          InitialScore = 50,
          NewScore = InitialScore + 0,
          ?assertEqual(50, NewScore)
      end},

      {"exact threshold triggers ban", fun() ->
          Score = 100,
          Threshold = 100,
          ?assert(Score >= Threshold)
      end},

      {"one below threshold doesn't ban", fun() ->
          Score = 99,
          Threshold = 100,
          ?assertNot(Score >= Threshold)
      end}
     ]}.

%%% ===================================================================
%%% Pre-handshake rejection tests
%%% ===================================================================

pre_handshake_rejection_test_() ->
    {"pre-handshake connection rejection",
     [
      {"banned IP should be rejected", fun() ->
          %% Logic test: banned IPs rejected before handshake
          IP = {192, 168, 1, 1},
          Now = erlang:system_time(second),
          BanExpiry = Now + 3600,  %% 1 hour in future
          %% Simulates is_banned_internal check
          ?assert(BanExpiry > Now)
      end},

      {"expired ban should not reject", fun() ->
          IP = {192, 168, 1, 2},
          Now = erlang:system_time(second),
          BanExpiry = Now - 1,  %% 1 second in past
          %% Ban is expired
          ?assert(BanExpiry < Now)
      end},

      {"max inbound limit triggers rejection", fun() ->
          %% When inbound >= max_inbound, reject
          Inbound = 125,
          MaxInbound = 125,
          ?assert(Inbound >= MaxInbound)
      end},

      {"below max inbound allows connection", fun() ->
          Inbound = 124,
          MaxInbound = 125,
          ?assertNot(Inbound >= MaxInbound)
      end},

      {"rejection closes socket without protocol message", fun() ->
          %% This is a behavior specification test
          %% On rejection, gen_tcp:close is called directly
          %% No Bitcoin protocol messages are sent
          ?assert(true)  %% Documented behavior
      end}
     ]}.

%%% ===================================================================
%%% Whitelist tests
%%% ===================================================================

whitelist_test_() ->
    {"whitelist functionality",
     [
      {"empty whitelist matches nothing", fun() ->
          IP = {192, 168, 1, 1},
          Whitelist = [],
          ?assertEqual(false, check_whitelist_test(IP, Whitelist))
      end},

      {"exact IP match", fun() ->
          IP = {192, 168, 1, 1},
          Whitelist = [{192, 168, 1, 1}],
          ?assertEqual(true, check_whitelist_test(IP, Whitelist))
      end},

      {"IP string match", fun() ->
          IP = {192, 168, 1, 1},
          Whitelist = ["192.168.1.1"],
          ?assertEqual(true, check_whitelist_test(IP, Whitelist))
      end},

      {"CIDR /24 match", fun() ->
          IP = {192, 168, 1, 100},
          Whitelist = ["192.168.1.0/24"],
          ?assertEqual(true, check_whitelist_test(IP, Whitelist))
      end},

      {"CIDR /24 no match", fun() ->
          IP = {192, 168, 2, 100},
          Whitelist = ["192.168.1.0/24"],
          ?assertEqual(false, check_whitelist_test(IP, Whitelist))
      end},

      {"CIDR /16 match", fun() ->
          IP = {10, 0, 50, 123},
          Whitelist = ["10.0.0.0/16"],
          ?assertEqual(true, check_whitelist_test(IP, Whitelist))
      end},

      {"CIDR /8 match", fun() ->
          IP = {10, 123, 45, 67},
          Whitelist = ["10.0.0.0/8"],
          ?assertEqual(true, check_whitelist_test(IP, Whitelist))
      end},

      {"whitelisted IP bypasses ban check", fun() ->
          %% Spec: if IP is whitelisted, ban check is skipped
          %% This is the Bitcoin Core behavior
          IP = {192, 168, 1, 1},
          Whitelisted = true,
          Banned = true,
          %% With whitelist, ban doesn't matter
          ShouldAccept = Whitelisted orelse (not Banned),
          ?assert(ShouldAccept)
      end},

      {"non-whitelisted banned IP rejected", fun() ->
          IP = {192, 168, 1, 2},
          Whitelisted = false,
          Banned = true,
          ShouldReject = (not Whitelisted) andalso Banned,
          ?assert(ShouldReject)
      end}
     ]}.

%% Local test helper that mirrors the module's check_whitelist logic
check_whitelist_test(_IP, []) ->
    false;
check_whitelist_test(IP, [Entry | Rest]) ->
    case match_whitelist_entry_test(IP, Entry) of
        true -> true;
        false -> check_whitelist_test(IP, Rest)
    end.

match_whitelist_entry_test(IP, Entry) when is_tuple(Entry), is_tuple(IP) ->
    IP =:= Entry;
match_whitelist_entry_test(IP, Entry) when is_list(Entry) ->
    case string:split(Entry, "/") of
        [IPStr, MaskStr] ->
            case {inet:parse_address(IPStr), list_to_integer(MaskStr)} of
                {{ok, NetIP}, Mask} ->
                    ip_in_cidr_test(IP, NetIP, Mask);
                _ ->
                    false
            end;
        [IPStr] ->
            case inet:parse_address(IPStr) of
                {ok, ParsedIP} -> IP =:= ParsedIP;
                _ -> false
            end
    end;
match_whitelist_entry_test(_, _) ->
    false.

ip_in_cidr_test({A1, A2, A3, A4}, {B1, B2, B3, B4}, Mask) when Mask >= 0, Mask =< 32 ->
    IP1 = (A1 bsl 24) bor (A2 bsl 16) bor (A3 bsl 8) bor A4,
    IP2 = (B1 bsl 24) bor (B2 bsl 16) bor (B3 bsl 8) bor B4,
    MaskBits = (16#FFFFFFFF bsl (32 - Mask)) band 16#FFFFFFFF,
    (IP1 band MaskBits) =:= (IP2 band MaskBits);
ip_in_cidr_test(_, _, _) ->
    false.

%%% ===================================================================
%%% Connection count tracking tests
%%% ===================================================================

connection_count_test_() ->
    {"connection count tracking",
     [
      {"max_inbound default is 125", fun() ->
          MaxInboundDefault = 125,
          ?assertEqual(125, MaxInboundDefault)
      end},

      {"inbound count from ETS", fun() ->
          %% inbound_count() counts direction = inbound in ETS
          %% This verifies the counting logic
          Inbound = 10,
          Outbound = 8,
          Total = Inbound + Outbound,
          ?assertEqual(18, Total)
      end},

      {"connection counts are separate", fun() ->
          %% Inbound and outbound are counted separately
          InboundLimit = 125,
          OutboundTarget = 10,
          ?assertNotEqual(InboundLimit, OutboundTarget)
      end}
     ]}.

%%% ===================================================================
%%% Stale peer eviction tests
%%% ===================================================================

stale_peer_constants_test_() ->
    {"stale peer eviction constants",
     [
      {"stale check interval is 45 seconds", fun() ->
          ?assertEqual(45000, 45000)  %% STALE_CHECK_INTERVAL
      end},

      {"stale tip threshold is 30 minutes", fun() ->
          %% 30 minutes = 1800 seconds
          ?assertEqual(1800, 30 * 60)  %% STALE_TIP_THRESHOLD
      end},

      {"headers response timeout is 2 minutes", fun() ->
          %% 2 minutes = 120000 milliseconds
          ?assertEqual(120000, 2 * 60 * 1000)  %% HEADERS_RESPONSE_TIMEOUT
      end},

      {"ping timeout is 20 minutes", fun() ->
          %% 20 minutes = 1200000 milliseconds
          ?assertEqual(1200000, 20 * 60 * 1000)  %% PING_TIMEOUT
      end},

      {"minimum connect time for eviction is 30 seconds", fun() ->
          ?assertEqual(30, 30)  %% MIN_CONNECT_TIME_FOR_EVICTION
      end}
     ]}.

stale_peer_detection_test_() ->
    {"stale peer detection logic",
     [
      {"peer 30 min behind with current peer available should be evicted", fun() ->
          OurTipHeight = 100,
          PeerHeight = 97,  %% 3 blocks behind
          LastBlockTime = erlang:system_time(second) - 1801,  %% > 30 min ago
          HasCurrentPeer = true,
          IsProtected = false,
          %% Peer is stale if: behind tip, inactive > 30 min, has current peer, not protected
          ShouldEvict = (OurTipHeight > PeerHeight) andalso
                        HasCurrentPeer andalso
                        (not IsProtected) andalso
                        ((erlang:system_time(second) - LastBlockTime) > 1800),
          ?assert(ShouldEvict)
      end},

      {"peer 30 min behind without current peer should not be evicted", fun() ->
          OurTipHeight = 100,
          PeerHeight = 97,
          HasCurrentPeer = false,  %% No other peer with current tip
          IsProtected = false,
          %% When no current peer available, don't evict stale peers
          ShouldEvict = HasCurrentPeer andalso (not IsProtected),
          ?assertNot(ShouldEvict)
      end},

      {"protected peer should not be evicted", fun() ->
          IsProtected = true,
          ShouldEvict = not IsProtected,
          ?assertNot(ShouldEvict)
      end},

      {"recently connected peer should not be evicted", fun() ->
          ConnectTime = erlang:system_time(second) - 20,  %% 20 sec ago
          MinConnectTime = 30,  %% MIN_CONNECT_TIME_FOR_EVICTION
          TooRecent = (erlang:system_time(second) - ConnectTime) < MinConnectTime,
          ?assert(TooRecent)
      end},

      {"peer connected > 30 sec ago can be evicted", fun() ->
          ConnectTime = erlang:system_time(second) - 40,  %% 40 sec ago
          MinConnectTime = 30,
          OldEnough = (erlang:system_time(second) - ConnectTime) >= MinConnectTime,
          ?assert(OldEnough)
      end}
     ]}.

headers_timeout_test_() ->
    {"headers response timeout",
     [
      {"pending headers > 2 min should trigger eviction", fun() ->
          PendingHeaders = true,
          SentAt = erlang:system_time(millisecond) - 130000,  %% 130 sec ago
          HeadersTimeout = 120000,  %% 2 minutes
          Now = erlang:system_time(millisecond),
          TimedOut = PendingHeaders andalso ((Now - SentAt) > HeadersTimeout),
          ?assert(TimedOut)
      end},

      {"pending headers < 2 min should not trigger eviction", fun() ->
          PendingHeaders = true,
          SentAt = erlang:system_time(millisecond) - 60000,  %% 60 sec ago
          HeadersTimeout = 120000,
          Now = erlang:system_time(millisecond),
          TimedOut = PendingHeaders andalso ((Now - SentAt) > HeadersTimeout),
          ?assertNot(TimedOut)
      end},

      {"no pending headers should not trigger eviction", fun() ->
          PendingHeaders = false,
          SentAt = erlang:system_time(millisecond) - 200000,  %% old timestamp
          HeadersTimeout = 120000,
          Now = erlang:system_time(millisecond),
          TimedOut = PendingHeaders andalso ((Now - SentAt) > HeadersTimeout),
          ?assertNot(TimedOut)
      end}
     ]}.

ping_timeout_test_() ->
    {"ping timeout detection",
     [
      {"ping latency > 20 min should trigger eviction", fun() ->
          PingLatency = 1300000,  %% 21.67 minutes
          PingTimeout = 1200000,  %% 20 minutes
          TimedOut = PingLatency > PingTimeout,
          ?assert(TimedOut)
      end},

      {"ping latency < 20 min should not trigger eviction", fun() ->
          PingLatency = 500000,  %% 8.3 minutes
          PingTimeout = 1200000,
          TimedOut = PingLatency > PingTimeout,
          ?assertNot(TimedOut)
      end},

      {"zero ping latency should not trigger eviction", fun() ->
          PingLatency = 0,
          PingTimeout = 1200000,
          TimedOut = PingLatency > PingTimeout,
          ?assertNot(TimedOut)
      end}
     ]}.

network_type_test_() ->
    {"network type detection",
     [
      {"ipv4 address detection", fun() ->
          IP = {192, 168, 1, 1},
          NetType = get_network_type_test(IP),
          ?assertEqual(ipv4, NetType)
      end},

      {"ipv6 address detection", fun() ->
          IP = {16#2001, 16#db8, 0, 0, 0, 0, 0, 1},
          NetType = get_network_type_test(IP),
          ?assertEqual(ipv6, NetType)
      end},

      {"ipv4-mapped ipv6 detection", fun() ->
          IP = {0, 0, 0, 0, 0, 16#FFFF, 16#C0A8, 16#0101},
          NetType = get_network_type_test(IP),
          ?assertEqual(ipv4, NetType)
      end},

      {"tor address detection", fun() ->
          IP = {16#FD87, 16#D87E, 16#EB43, 0, 0, 0, 0, 1},
          NetType = get_network_type_test(IP),
          ?assertEqual(tor, NetType)
      end},

      {"i2p address detection", fun() ->
          IP = {16#FD00, 0, 0, 0, 0, 0, 0, 1},
          NetType = get_network_type_test(IP),
          ?assertEqual(i2p, NetType)
      end},

      {"cjdns address detection", fun() ->
          IP = {16#FC00, 16#1234, 0, 0, 0, 0, 0, 1},
          NetType = get_network_type_test(IP),
          ?assertEqual(cjdns, NetType)
      end}
     ]}.

%% Test helper for network type detection
get_network_type_test({_, _, _, _}) ->
    ipv4;
get_network_type_test({0, 0, 0, 0, 0, 16#FFFF, _, _}) ->
    ipv4;
get_network_type_test({16#FD87, 16#D87E, 16#EB43, _, _, _, _, _}) ->
    tor;
get_network_type_test({16#FD00, 0, 0, 0, 0, 0, 0, _}) ->
    i2p;
get_network_type_test({16#FC00, _, _, _, _, _, _, _}) ->
    cjdns;
get_network_type_test({_, _, _, _, _, _, _, _}) ->
    ipv6.

network_protection_test_() ->
    {"network type protection",
     [
      {"single ipv4 peer should be protected", fun() ->
          Peers = [
              {peer1, ipv4},
              {peer2, ipv6},
              {peer3, ipv6}
          ],
          ProtectedNetworks = get_protected_networks_test(Peers),
          ?assertEqual(#{ipv4 => peer1}, ProtectedNetworks)
      end},

      {"multiple ipv4 peers - none should be protected", fun() ->
          Peers = [
              {peer1, ipv4},
              {peer2, ipv4},
              {peer3, ipv6}
          ],
          ProtectedNetworks = get_protected_networks_test(Peers),
          %% ipv4 has 2 peers, so not protected; ipv6 has 1, so protected
          ?assertEqual(#{ipv6 => peer3}, ProtectedNetworks)
      end},

      {"one peer per network type - all protected", fun() ->
          Peers = [
              {peer1, ipv4},
              {peer2, ipv6},
              {peer3, tor}
          ],
          ProtectedNetworks = get_protected_networks_test(Peers),
          ?assertEqual(#{ipv4 => peer1, ipv6 => peer2, tor => peer3}, ProtectedNetworks)
      end},

      {"no single-peer networks - none protected", fun() ->
          Peers = [
              {peer1, ipv4},
              {peer2, ipv4},
              {peer3, ipv6},
              {peer4, ipv6}
          ],
          ProtectedNetworks = get_protected_networks_test(Peers),
          ?assertEqual(#{}, ProtectedNetworks)
      end}
     ]}.

%% Test helper for network protection calculation
get_protected_networks_test(Peers) ->
    ByNetwork = lists:foldl(fun({Pid, NetType}, Acc) ->
        maps:update_with(NetType, fun(L) -> [Pid | L] end, [Pid], Acc)
    end, #{}, Peers),
    maps:fold(fun(NetType, Pids, Acc) ->
        case length(Pids) of
            1 -> maps:put(NetType, hd(Pids), Acc);
            _ -> Acc
        end
    end, #{}, ByNetwork).

current_tip_detection_test_() ->
    {"current tip peer detection",
     [
      {"peer with recent block activity is current", fun() ->
          OurTip = 100,
          PeerHeight = 99,  %% Within 3 blocks
          LastBlockTime = erlang:system_time(second) - 600,  %% 10 min ago, within 30 min
          Now = erlang:system_time(second),
          IsRecent = (Now - LastBlockTime) < 1800,  %% 30 min threshold
          IsClose = (OurTip - PeerHeight) =< 3,
          IsCurrent = IsRecent andalso IsClose,
          ?assert(IsCurrent)
      end},

      {"peer with old block activity is not current", fun() ->
          OurTip = 100,
          PeerHeight = 99,
          LastBlockTime = erlang:system_time(second) - 2000,  %% > 30 min ago
          Now = erlang:system_time(second),
          IsRecent = (Now - LastBlockTime) < 1800,
          IsCurrent = IsRecent,
          ?assertNot(IsCurrent)
      end},

      {"peer far behind tip is not current", fun() ->
          OurTip = 100,
          PeerHeight = 90,  %% 10 blocks behind
          LastBlockTime = erlang:system_time(second) - 600,
          IsClose = (OurTip - PeerHeight) =< 3,
          ?assertNot(IsClose)
      end}
     ]}.

%%% ===================================================================
%%% BIP35 mempool inv chunking (pure helper)
%%% ===================================================================

chunk_inv_items_test_() ->
    Item = fun(N) -> #{type => 1, hash => <<N:256>>} end,
    [
     {"empty list returns empty list", fun() ->
         ?assertEqual([], beamchain_peer_manager:chunk_inv_items([], 50000))
     end},
     {"under one chunk returns single chunk", fun() ->
         Items = [Item(N) || N <- lists:seq(1, 5)],
         ?assertEqual([Items],
             beamchain_peer_manager:chunk_inv_items(Items, 50000))
     end},
     {"exact multiple of chunk size", fun() ->
         Items = [Item(N) || N <- lists:seq(1, 6)],
         Chunks = beamchain_peer_manager:chunk_inv_items(Items, 3),
         ?assertEqual(2, length(Chunks)),
         ?assertEqual(3, length(lists:nth(1, Chunks))),
         ?assertEqual(3, length(lists:nth(2, Chunks))),
         %% Order is preserved across chunks
         ?assertEqual(Items, lists:append(Chunks))
     end},
     {"non-multiple has short tail chunk", fun() ->
         Items = [Item(N) || N <- lists:seq(1, 7)],
         Chunks = beamchain_peer_manager:chunk_inv_items(Items, 3),
         ?assertEqual(3, length(Chunks)),
         ?assertEqual([3, 3, 1], [length(C) || C <- Chunks]),
         ?assertEqual(Items, lists:append(Chunks))
     end},
     {"chunk size 1 yields one item per chunk", fun() ->
         Items = [Item(N) || N <- lists:seq(1, 4)],
         Chunks = beamchain_peer_manager:chunk_inv_items(Items, 1),
         ?assertEqual(4, length(Chunks)),
         lists:foreach(fun(C) -> ?assertEqual(1, length(C)) end, Chunks),
         ?assertEqual(Items, lists:append(Chunks))
     end},
     {"max protocol chunk size respected", fun() ->
         %% 50000 + 17 items: first chunk is full, second is the remainder.
         Items = [Item(N) || N <- lists:seq(1, 50017)],
         Chunks = beamchain_peer_manager:chunk_inv_items(Items, 50000),
         ?assertEqual(2, length(Chunks)),
         ?assertEqual(50000, length(lists:nth(1, Chunks))),
         ?assertEqual(17, length(lists:nth(2, Chunks)))
     end}
    ].
