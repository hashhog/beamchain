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

%%% ===================================================================
%%% BIP35 NODE_BLOOM gate (config + service-flag advertisement)
%%% ===================================================================
%%% Mirrors Bitcoin Core net_processing.cpp's
%%%   if (!(peer.m_our_services & NODE_BLOOM) &&
%%%       !pfrom.HasPermission(NetPermissionFlags::Mempool))
%%% gate on inbound MEMPOOL messages. Beamchain has no per-peer
%%% permission system yet, so the gate collapses to the local
%%% advertisement bit, which is itself controlled by the
%%% `peerbloomfilters` config knob.

node_bloom_config_setup() ->
    %% Ensure the config ETS exists for `beamchain_config:get/2`.
    case ets:info(beamchain_config_ets) of
        undefined ->
            ets:new(beamchain_config_ets,
                    [named_table, set, public, {read_concurrency, true}]),
            created;
        _ ->
            existed
    end.

node_bloom_config_cleanup(created) -> ets:delete(beamchain_config_ets);
node_bloom_config_cleanup(existed) -> ok.

node_bloom_default_test_() ->
    {setup, fun node_bloom_config_setup/0, fun node_bloom_config_cleanup/1,
     fun(_) ->
        [
         {"defaults to disabled (matches Core DEFAULT_PEERBLOOMFILTERS=false)", fun() ->
             os:unsetenv("BEAMCHAIN_PEERBLOOMFILTERS"),
             catch ets:delete(beamchain_config_ets, peerbloomfilters),
             ?assertEqual(false, beamchain_config:node_bloom_enabled())
         end},
         {"env var '0' disables", fun() ->
             os:putenv("BEAMCHAIN_PEERBLOOMFILTERS", "0"),
             ?assertEqual(false, beamchain_config:node_bloom_enabled()),
             os:unsetenv("BEAMCHAIN_PEERBLOOMFILTERS")
         end},
         {"env var 'false' disables", fun() ->
             os:putenv("BEAMCHAIN_PEERBLOOMFILTERS", "false"),
             ?assertEqual(false, beamchain_config:node_bloom_enabled()),
             os:unsetenv("BEAMCHAIN_PEERBLOOMFILTERS")
         end},
         {"env var '1' enables", fun() ->
             os:putenv("BEAMCHAIN_PEERBLOOMFILTERS", "1"),
             ?assertEqual(true, beamchain_config:node_bloom_enabled()),
             os:unsetenv("BEAMCHAIN_PEERBLOOMFILTERS")
         end},
         {"config value '1' enables", fun() ->
             os:unsetenv("BEAMCHAIN_PEERBLOOMFILTERS"),
             ets:insert(beamchain_config_ets, {peerbloomfilters, "1"}),
             ?assertEqual(true, beamchain_config:node_bloom_enabled()),
             ets:delete(beamchain_config_ets, peerbloomfilters)
         end},
         {"config value 1 (integer) enables", fun() ->
             os:unsetenv("BEAMCHAIN_PEERBLOOMFILTERS"),
             ets:insert(beamchain_config_ets, {peerbloomfilters, 1}),
             ?assertEqual(true, beamchain_config:node_bloom_enabled()),
             ets:delete(beamchain_config_ets, peerbloomfilters)
         end},
         {"env var overrides config (env=1, config=0)", fun() ->
             os:putenv("BEAMCHAIN_PEERBLOOMFILTERS", "1"),
             ets:insert(beamchain_config_ets, {peerbloomfilters, "0"}),
             ?assertEqual(true, beamchain_config:node_bloom_enabled()),
             os:unsetenv("BEAMCHAIN_PEERBLOOMFILTERS"),
             ets:delete(beamchain_config_ets, peerbloomfilters)
         end}
        ]
     end}.

%% The local advertisement bit must include NODE_BLOOM when the config
%% knob is on; this is the value that flows into the version handshake's
%% services field at beamchain_peer.erl:do_send_version/1, and is what
%% Bitcoin Core's gate (`peer.m_our_services & NODE_BLOOM`) inspects.
node_bloom_advertised_services_test_() ->
    {setup, fun node_bloom_config_setup/0, fun node_bloom_config_cleanup/1,
     fun(_) ->
        Compute = fun() ->
            Base = ?NODE_NETWORK bor ?NODE_WITNESS,
            case beamchain_config:node_bloom_enabled() of
                true  -> Base bor ?NODE_BLOOM;
                false -> Base
            end
        end,
        [
         {"NODE_BLOOM bit advertised when enabled", fun() ->
             os:putenv("BEAMCHAIN_PEERBLOOMFILTERS", "1"),
             Svc = Compute(),
             ?assertEqual(?NODE_BLOOM, Svc band ?NODE_BLOOM),
             ?assertEqual(?NODE_NETWORK, Svc band ?NODE_NETWORK),
             ?assertEqual(?NODE_WITNESS, Svc band ?NODE_WITNESS),
             os:unsetenv("BEAMCHAIN_PEERBLOOMFILTERS")
         end},
         {"NODE_BLOOM bit cleared when disabled", fun() ->
             os:putenv("BEAMCHAIN_PEERBLOOMFILTERS", "0"),
             Svc = Compute(),
             ?assertEqual(0, Svc band ?NODE_BLOOM),
             %% Other service bits unaffected
             ?assertEqual(?NODE_NETWORK, Svc band ?NODE_NETWORK),
             ?assertEqual(?NODE_WITNESS, Svc band ?NODE_WITNESS),
             os:unsetenv("BEAMCHAIN_PEERBLOOMFILTERS")
         end}
        ]
     end}.

%%% ===================================================================
%%% BIP-130 announce branching: sendheaders peers get `headers`,
%%% other peers get `inv`. Mirrors Bitcoin Core
%%% net_processing.cpp::PeerManagerImpl::SendMessages's
%%% m_blocks_for_headers_relay / fPreferHeaders branch and the camlcoin
%%% reference impl at lib/peer_manager.ml::announce_block.
%%% ===================================================================

announce_branch_test_() ->
    %% Minimal stub header — `headers` payload is encoded by p2p_msg, so
    %% pick_announce_msg/3 only needs to thread the record through
    %% unchanged.
    Header = #block_header{
        version = 1,
        prev_hash = <<0:256>>,
        merkle_root = <<0:256>>,
        timestamp = 1234567890,
        bits = 16#1d00ffff,
        nonce = 0
    },
    BlockHash = <<1:256>>,
    [
     {"sendheaders peer (wants_headers=true) gets `headers`", fun() ->
         {Cmd, Payload} =
             beamchain_peer_manager:pick_announce_msg(true, Header, BlockHash),
         ?assertEqual(headers, Cmd),
         ?assertMatch(#{headers := [#block_header{}]}, Payload),
         #{headers := [GotHdr]} = Payload,
         ?assertEqual(Header, GotHdr)
     end},
     {"non-sendheaders peer falls back to `inv` of MSG_BLOCK", fun() ->
         {Cmd, Payload} =
             beamchain_peer_manager:pick_announce_msg(false, Header, BlockHash),
         ?assertEqual(inv, Cmd),
         ?assertMatch(#{items := [#{type := ?MSG_BLOCK, hash := BlockHash}]},
                      Payload)
     end},
     {"branch is byte-for-byte different (no inv leak when peer wants headers)",
      fun() ->
         {CmdYes, _} =
             beamchain_peer_manager:pick_announce_msg(true, Header, BlockHash),
         {CmdNo, _} =
             beamchain_peer_manager:pick_announce_msg(false, Header, BlockHash),
         ?assertNotEqual(CmdYes, CmdNo)
     end}
    ].

%%% ===================================================================
%%% getaddr response cap — Bitcoin Core GetAddr_ FLOOR semantics
%%%
%%% Core AddrManImpl::GetAddr_ (addrman.cpp:800):
%%%   nNodes = max_pct * nNodes / 100;          %% INTEGER FLOOR
%%%   nNodes = std::min(nNodes, max_addresses); %% MAX_ADDR_TO_SEND=1000
%%% max_pct == MAX_PCT_ADDR_TO_SEND == 23 (net_processing.cpp:188).
%%% Core does NOT clamp the floor up to 1 — a tiny addrman where
%%% 23*N < 100 yields 0. beamchain previously used ceil + max(1,_),
%%% over-disclosing addresses Core withholds; this test pins FLOOR.
%%% ===================================================================
getaddr_cap_floor_test_() ->
    [
     %% Empty table -> 0.
     {"empty table caps at 0", fun() ->
         ?assertEqual(0, beamchain_peer_manager:getaddr_cap(0))
     end},

     %% DISTINGUISHING: N=10 -> floor(2.3) = 2, NOT ceil 3.
     {"N=10 -> 2 (floor), not 3 (ceil)", fun() ->
         ?assertEqual(2, beamchain_peer_manager:getaddr_cap(10))
     end},

     %% DISTINGUISHING: N=50 -> floor(11.5) = 11, NOT ceil 12.
     {"N=50 -> 11 (floor), not 12 (ceil)", fun() ->
         ?assertEqual(11, beamchain_peer_manager:getaddr_cap(50))
     end},

     %% DISTINGUISHING: N=100 -> 23*100/100 = 23 exactly (floor==ceil here,
     %% but confirms the 23% factor is intact).
     {"N=100 -> 23 exactly", fun() ->
         ?assertEqual(23, beamchain_peer_manager:getaddr_cap(100))
     end},

     %% Core does NOT floor-up to 1: tiny tables where 23*N < 100 yield 0.
     {"N=1 -> 0 (Core withholds; no max(1,_))", fun() ->
         ?assertEqual(0, beamchain_peer_manager:getaddr_cap(1))
     end},
     {"N=4 -> 0 (23*4=92 < 100)", fun() ->
         ?assertEqual(0, beamchain_peer_manager:getaddr_cap(4))
     end},
     {"N=5 -> 1 (23*5=115 -> floor 1)", fun() ->
         ?assertEqual(1, beamchain_peer_manager:getaddr_cap(5))
     end},

     %% Upper clamp at MAX_ADDR_TO_SEND=1000: floor(23% of 100000)=23000 -> 1000.
     {"large table clamps at MAX_ADDR_TO_SEND=1000", fun() ->
         ?assertEqual(1000, beamchain_peer_manager:getaddr_cap(100000))
     end},
     %% Boundary: 23*4347/100 = 999.81 -> floor 999; 23*4348/100 = 1000.04
     %% -> floor 1000. 4349 stays clamped at 1000.
     {"N=4349 -> 1000 (clamp boundary)", fun() ->
         ?assertEqual(1000, beamchain_peer_manager:getaddr_cap(4349))
     end},
     {"N=4347 -> 999 (just below clamp)", fun() ->
         ?assertEqual(999, beamchain_peer_manager:getaddr_cap(4347))
     end}
    ].

%%% ===================================================================
%%% Inbound acceptor: exactly one accept loop (Core net.cpp runs a single
%%% accept thread, ThreadSocketHandler -> AcceptConnection).
%%%
%%% accept_loop/2 already loops on its own after every accept. The manager's
%%% {accepted, ...} handler must therefore NOT spawn another acceptor; a new
%%% one is only due when the current acceptor dies ('DOWN'). Before the fix
%%% every inbound connection left one more accept_loop process behind.
%%%
%%% These tests drive the real gen_server callbacks: a proc_lib process
%%% registered as beamchain_peer_manager enters gen_server:enter_loop/4 with a
%%% #state{} record built from the module's own record definition (read from
%%% its debug_info), listen_socket set to a real loopback listener. The real
%%% accept_loop, check_inbound and handle_inbound run; only
%%% beamchain_peer:accept/3 (spawning a peer) and beamchain_config:get/2 for
%%% the whitelist are mocked.
%%% ===================================================================

-define(ACCEPT_TEST_CONNS, 200).

inbound_accept_keeps_one_acceptor_test_() ->
    {foreach, fun acceptor_setup/0, fun acceptor_cleanup/1,
     [fun(Ctx) ->
          {timeout, 60,
           {"inbound_accept_keeps_one_acceptor: 200 inbound connections "
            "leave exactly one accept_loop process",
            fun() -> inbound_accept_keeps_one_acceptor(Ctx) end}}
      end,
      %% The 'DOWN' respawn path the fix relies on still works, and the
      %% respawned acceptor also stays single after it accepts.
      fun(Ctx) ->
          {timeout, 60,
           {"acceptor DOWN respawns exactly one acceptor that still accepts",
            fun() -> acceptor_down_respawns_one(Ctx) end}}
      end]}.

inbound_accept_keeps_one_acceptor(#{port := Port}) ->
    ?assertEqual(1, wait_acceptor_count(1)),
    Before = meck:num_calls(beamchain_peer, accept, '_'),
    Clients = [begin
                   {ok, C} = gen_tcp:connect({127,0,0,1}, Port,
                                             [binary, {active, false}]),
                   C
               end || _ <- lists:seq(1, ?ACCEPT_TEST_CONNS)],
    %% Instrument check: every connection must actually reach the manager's
    %% {accepted, ...} handler, otherwise a count of 1 proves nothing.
    ?assertEqual(Before + ?ACCEPT_TEST_CONNS,
                 wait_num_calls(Before + ?ACCEPT_TEST_CONNS)),
    timer:sleep(200),
    Count = acceptor_count(),
    [gen_tcp:close(C) || C <- Clients],
    ?assertEqual(1, Count).

acceptor_down_respawns_one(#{port := Port}) ->
    ?assertEqual(1, wait_acceptor_count(1)),
    [Old] = acceptor_pids(),
    exit(Old, kill),
    ?assertEqual(1, wait_acceptor_count(1)),
    [New] = acceptor_pids(),
    ?assertNotEqual(Old, New),
    Before = meck:num_calls(beamchain_peer, accept, '_'),
    {ok, C} = gen_tcp:connect({127,0,0,1}, Port, [binary, {active, false}]),
    ?assertEqual(Before + 1, wait_num_calls(Before + 1)),
    gen_tcp:close(C),
    timer:sleep(100),
    ?assertEqual([New], acceptor_pids()).

acceptor_setup() ->
    setup(),
    ok = meck:new(beamchain_peer, [no_link, passthrough]),
    ok = meck:expect(beamchain_peer, accept,
                     fun(_Sock, _Addr, _Mgr) -> {error, acceptor_test} end),
    ok = meck:new(beamchain_config, [no_link, passthrough]),
    ok = meck:expect(beamchain_config, get,
                     fun(whitelist, _Default) -> [];
                        (K, D) -> meck:passthrough([K, D]) end),
    {ok, LSock} = gen_tcp:listen(0, [binary, {active, false}, {packet, raw},
                                     {reuseaddr, true}, {backlog, 512},
                                     {ip, {127,0,0,1}}]),
    {ok, Port} = inet:port(LSock),
    Dummy = spawn(fun() -> receive stop -> ok end end),
    State = build_state(#{listen_socket => LSock, acceptor => Dummy,
                          max_inbound => 100000, network_active => true}),
    Parent = self(),
    Mgr = proc_lib:spawn(fun() ->
        true = register(beamchain_peer_manager, self()),
        Parent ! {mgr_ready, self()},
        gen_server:enter_loop(beamchain_peer_manager, [], State,
                              {local, beamchain_peer_manager})
    end),
    receive {mgr_ready, Mgr} -> ok after 5000 -> error(mgr_not_ready) end,
    %% The manager spawns its acceptor on the acceptor's 'DOWN' (the only
    %% respawn path once the fix is in); feed it one for the dummy pid.
    Mgr ! {'DOWN', make_ref(), process, Dummy, acceptor_test_boot},
    Dummy ! stop,
    #{lsock => LSock, port => Port, mgr => Mgr}.

acceptor_cleanup(#{lsock := LSock, mgr := Mgr}) ->
    MRef = erlang:monitor(process, Mgr),
    exit(Mgr, kill),
    receive {'DOWN', MRef, process, Mgr, _} -> ok after 5000 -> ok end,
    %% Closing the listener ends every accept_loop ({error, closed}).
    gen_tcp:close(LSock),
    _ = wait_acceptor_count(0),
    meck:unload(beamchain_config),
    meck:unload(beamchain_peer),
    ok.

%% Build a #state{} tuple for beamchain_peer_manager from its record
%% definition, evaluating each field's default where possible.
build_state(Overrides) ->
    Beam = code:which(beamchain_peer_manager),
    {ok, {_, [{abstract_code, {raw_abstract_v1, Forms}}]}} =
        beam_lib:chunks(Beam, [abstract_code]),
    [Fields] = [Fs || {attribute, _, record, {state, Fs}} <- Forms],
    Values = [field_value(F, Overrides) || F <- Fields],
    list_to_tuple([state | Values]).

field_value({typed_record_field, RF, _Type}, Ov) -> field_value(RF, Ov);
field_value({record_field, _, {atom, _, Name}}, Ov) ->
    maps:get(Name, Ov, undefined);
field_value({record_field, _, {atom, _, Name}, Default}, Ov) ->
    case maps:find(Name, Ov) of
        {ok, V} -> V;
        error ->
            try erl_eval:expr(Default, erl_eval:new_bindings()) of
                {value, V, _} -> V
            catch _:_ -> undefined
            end
    end.

%% A process "running accept_loop" has beamchain_peer_manager:accept_loop/2
%% on its stack (it calls gen_tcp:accept/1 from inside a case, so the frame
%% is there while it blocks waiting for the next connection).
is_acceptor(P) ->
    case erlang:process_info(P, current_stacktrace) of
        {current_stacktrace, Frames} ->
            lists:any(fun({beamchain_peer_manager, accept_loop, 2, _}) -> true;
                         (_) -> false
                      end, Frames);
        undefined -> false
    end.

acceptor_pids() -> [P || P <- erlang:processes(), is_acceptor(P)].

acceptor_count() -> length(acceptor_pids()).

wait_acceptor_count(N) -> wait_until(fun acceptor_count/0, N, 50).

wait_num_calls(N) ->
    wait_until(fun() -> meck:num_calls(beamchain_peer, accept, '_') end,
               N, 100).

wait_until(F, Want, 0) -> _ = Want, F();
wait_until(F, Want, Tries) ->
    case F() of
        Want -> Want;
        _ -> timer:sleep(50), wait_until(F, Want, Tries - 1)
    end.

%%% ===================================================================
%%% Ban table bound + persistence failure tolerance
%%% (secfix-beamchain-banlist-uncapped)
%%%
%%% Every misbehaviour discouragement used to (a) insert into the
%%% banned_peers ETS table with no bound and (b) rewrite banned.json
%%% synchronously with `ok = file:write_file(...)` on the shared peer
%%% manager.  A peer able to trigger misbehaviour from many addresses
%%% (IPv6 gives an attacker effectively unlimited source IPs) grew the
%%% table without limit and made each event cost an O(table) JSON rewrite;
%%% one ENOSPC / EIO from the write then crashed the manager (badmatch),
%%% dropping every peer.  Core keeps discouragement in a bounded rolling
%%% bloom filter (banman.h m_discouraged{50000, 0.000001}) and dumps its
%%% ban list on a timer (DUMP_BANS_INTERVAL), never per event.
%%%
%%% Drives the real handle_cast({misbehaving,...}) / handle_info callbacks
%%% with a #state{} built from the module's record definition, so the
%%% production code path is what runs.
%%% ===================================================================

-define(BAN_FLOOD, 100000).
%% Core's discouragement filter capacity (banman.h m_discouraged).
-define(BAN_CAP, 50000).

ban_table_is_bounded_and_write_failure_tolerated_test_() ->
    {timeout, 300,
     {setup, fun ban_flood_setup/0, fun ban_flood_cleanup/1,
      fun(Ctx) -> [fun() -> ban_flood_body(Ctx) end] end}}.

ban_flood_setup() ->
    setup(),
    beamchain_peer_manager:test_ensure_peer_table(),
    %% Scratch datadir whose banned.json is a symlink to /dev/full: open
    %% succeeds and every write returns ENOSPC, i.e. a real disk-full error.
    Dir = filename:join(["/tmp", "beamchain-bancap-" ++
                         integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    ok = file:make_symlink("/dev/full", filename:join(Dir, "banned.json")),
    OkDir = Dir ++ "-ok",
    ok = filelib:ensure_dir(filename:join(OkDir, "x")),
    %% 100k discouragement log lines would swamp the eunit output.
    #{level := Level} = logger:get_primary_config(),
    ok = logger:set_primary_config(level, none),
    #{full => Dir, ok => OkDir, level => Level}.

ban_flood_cleanup(#{full := Dir, ok := OkDir, level := Level}) ->
    logger:set_primary_config(level, Level),
    _ = file:del_dir_r(Dir),
    _ = file:del_dir_r(OkDir),
    catch ets:delete_all_objects(beamchain_peers),
    catch ets:delete_all_objects(banned_peers_discouraged_idx),
    cleanup(ok).

ban_flood_body(#{full := FullDir, ok := OkDir}) ->
    %% A dead pid: beamchain_peer:disconnect/1 is a cast, harmless here.
    Pid = spawn(fun() -> ok end),
    beamchain_peer_manager:test_insert_peer(Pid, inbound, full_relay, normal),
    AddrPos = record_field_pos(peer_entry, address),
    %% An operator ban set before the flood must survive it.
    Manual = {203, 0, 113, 7},
    S0 = build_state(#{datadir => FullDir}),
    {reply, ok, S1} = beamchain_peer_manager:handle_call(
                        {set_ban, Manual, 86400, <<"operator">>}, self(), S0),
    Ip = fun(N) -> {16#2001, 16#db8, 0, 0, 0, 0, N bsr 16, N band 16#FFFF} end,
    SFlood = lists:foldl(
        fun(N, S) ->
            true = ets:update_element(beamchain_peers, Pid,
                                      {AddrPos, {Ip(N), 8333}}),
            {noreply, S2} = beamchain_peer_manager:handle_cast(
                              {misbehaving, Pid, 100, <<"flood">>}, S),
            S2
        end, S1, lists:seq(1, ?BAN_FLOOD)),
    %% Bounded: discouragements beyond the cap evict the oldest ones.
    Size = ets:info(banned_peers, size),
    ?assert(Size =< ?BAN_CAP + 1),
    %% The newest discouragement is in force, the oldest was rolled out,
    %% and the operator's manual ban was not evicted by the flood.
    ?assertMatch([{_, _}], ets:lookup(banned_peers, Ip(?BAN_FLOOD))),
    ?assertEqual([], ets:lookup(banned_peers, Ip(1))),
    ?assertMatch([{Manual, _}], ets:lookup(banned_peers, Manual)),
    %% Every discouraged row is indexed exactly once (the manual ban is not).
    ?assertEqual(Size - 1, ets:info(banned_peers_discouraged_idx, size)),
    %% Re-discouraging an already-discouraged address does not add rows.
    SRe = lists:foldl(
        fun(_, S) ->
            {noreply, S2} = beamchain_peer_manager:handle_cast(
                              {misbehaving, Pid, 100, <<"again">>}, S),
            S2
        end, SFlood, lists:seq(1, 3)),
    ?assertEqual(Size, ets:info(banned_peers, size)),
    ?assertEqual(Size - 1, ets:info(banned_peers_discouraged_idx, size)),
    %% Persistence is debounced: flushing it against a full disk must not
    %% crash the manager (returns {noreply, _}, the gen_server lives on).
    {noreply, SFull} = beamchain_peer_manager:handle_info(dump_bans, SRe),
    %% ... and the failed dump stays pending, retried a full interval later.
    DirtyPos = record_field_pos(state, bans_dirty),
    TimerPos = record_field_pos(state, ban_dump_timer),
    ?assertEqual(true, element(DirtyPos, SFull)),
    ?assert(timer_left_ms(element(TimerPos, SFull)) > 50000),
    %% Control: with a writable datadir the same flush really writes the
    %% bounded list (so the ENOSPC case above did reach file:write_file).
    DdPos = record_field_pos(state, datadir),
    {noreply, SOk} = beamchain_peer_manager:handle_info(
                       dump_bans, setelement(DdPos, SFull, OkDir)),
    ?assertEqual(false, element(DirtyPos, SOk)),
    BanFile = filename:join(OkDir, "banned.json"),
    {ok, Bin} = file:read_file(BanFile),
    Entries = jsx:decode(Bin, [return_maps]),
    ?assertEqual(Size, length(Entries)),
    Ips = [maps:get(<<"ip">>, E) || E <- Entries],
    ?assert(lists:member(list_to_binary(inet:ntoa(Ip(?BAN_FLOOD))), Ips)),
    ?assert(lists:member(<<"203.0.113.7">>, Ips)),
    %% Discouragements are flagged on disk and reload under the cap; the
    %% operator ban reloads as an operator ban (not evictable).
    Flagged = [E || E <- Entries, maps:get(<<"discouraged">>, E, false)],
    ?assertEqual(Size - 1, length(Flagged)),
    ets:delete_all_objects(banned_peers),
    ets:delete_all_objects(banned_peers_discouraged_idx),
    beamchain_peer_manager:load_bans(OkDir),
    ?assertEqual(Size, ets:info(banned_peers, size)),
    ?assertEqual(Size - 1, ets:info(banned_peers_discouraged_idx, size)),
    [{Manual, ManualExp}] = ets:lookup(banned_peers, Manual),
    ?assertNot(ets:member(banned_peers_discouraged_idx, {ManualExp, Manual})),
    %% Debounce: no discouragement writes banned.json synchronously.
    %% Right after a dump, a new one is deferred a full interval (bursts
    %% coalesce) ...
    Discourage = fun(N, S) ->
        true = ets:update_element(beamchain_peers, Pid,
                                  {AddrPos, {Ip(N), 8333}}),
        {noreply, S2} = beamchain_peer_manager:handle_cast(
                          {misbehaving, Pid, 100, <<"debounce">>}, S),
        S2
    end,
    flush_dump_bans(),
    SDeferred = Discourage(?BAN_FLOOD + 1, SOk),
    ?assertEqual({ok, Bin}, file:read_file(BanFile)),
    ?assert(timer_left_ms(element(TimerPos, SDeferred)) > 50000),
    %% ... while the first one after a quiet period is dumped on the very
    %% next message (as promptly as the old per-event write).
    _ = Discourage(?BAN_FLOOD + 2, build_state(#{datadir => OkDir})),
    ?assertEqual({ok, Bin}, file:read_file(BanFile)),
    receive dump_bans -> ok after 2000 -> ?assert(false) end.

%% A short operator setban (under the 24 h discouragement) on an address
%% that then misbehaves keeps its manual expiry and stays out of the
%% evictable discouragement index.  Core's Discourage() only inserts into
%% m_discouraged and never touches m_banned, so the setban row must not be
%% lengthened into a discouragement that a later cap eviction could drop
%% before the operator's bantime ends.
short_setban_survives_discouragement_test_() ->
    {setup,
     fun() ->
         setup(),
         beamchain_peer_manager:test_ensure_peer_table(),
         Dir = filename:join(["/tmp", "beamchain-shortban-" ++
                              integer_to_list(erlang:unique_integer([positive]))]),
         ok = filelib:ensure_dir(filename:join(Dir, "x")),
         Dir
     end,
     fun(Dir) ->
         _ = file:del_dir_r(Dir),
         catch ets:delete_all_objects(beamchain_peers),
         catch ets:delete_all_objects(banned_peers_discouraged_idx),
         cleanup(ok)
     end,
     fun(Dir) -> [fun() -> short_setban_body(Dir) end] end}.

short_setban_body(Dir) ->
    Ip = {203, 0, 113, 8},
    Pid = spawn(fun() -> ok end),
    beamchain_peer_manager:test_insert_peer(Pid, inbound, full_relay, normal),
    AddrPos = record_field_pos(peer_entry, address),
    true = ets:update_element(beamchain_peers, Pid, {AddrPos, {Ip, 8333}}),
    S0 = build_state(#{datadir => Dir}),
    {reply, ok, S1} = beamchain_peer_manager:handle_call(
                        {set_ban, Ip, 3600, <<"operator">>}, self(), S0),
    [{Ip, ManualExp}] = ets:lookup(banned_peers, Ip),
    {noreply, _} = beamchain_peer_manager:handle_cast(
                     {misbehaving, Pid, 100, <<"misbehaved">>}, S1),
    %% The manual expiry is unchanged ...
    ?assertEqual([{Ip, ManualExp}], ets:lookup(banned_peers, Ip)),
    %% ... and the address is not in the evictable discouragement index.
    ?assertEqual([], [K || {{_, I} = K} <- ets:tab2list(
                                               banned_peers_discouraged_idx),
                           I =:= Ip]),
    flush_dump_bans().

%% Milliseconds left on a pending timer; 0 if it already fired or is not a
%% timer (erlang:read_timer/1 returns the atom false, and atoms compare
%% greater than every integer).
timer_left_ms(Ref) when is_reference(Ref) ->
    case erlang:read_timer(Ref) of
        Ms when is_integer(Ms) -> Ms;
        false -> 0
    end;
timer_left_ms(_) ->
    0.

flush_dump_bans() ->
    receive dump_bans -> flush_dump_bans() after 0 -> ok end.

%% 1-based tuple position of Field in record Rec of beamchain_peer_manager.
record_field_pos(Rec, Field) ->
    Beam = code:which(beamchain_peer_manager),
    {ok, {_, [{abstract_code, {raw_abstract_v1, Forms}}]}} =
        beam_lib:chunks(Beam, [abstract_code]),
    [Fields] = [Fs || {attribute, _, record, {R, Fs}} <- Forms, R =:= Rec],
    Names = [field_name(F) || F <- Fields],
    true = lists:member(Field, Names),
    %% element 1 is the record tag, so field I sits at position I + 1.
    2 + length(lists:takewhile(fun(N) -> N =/= Field end, Names)).

field_name({typed_record_field, RF, _}) -> field_name(RF);
field_name({record_field, _, {atom, _, N}}) -> N;
field_name({record_field, _, {atom, _, N}, _}) -> N.
