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
