-module(beamchain_peers_outbound_tests).

%% peers-beamchain-outbound: inbound peers must never reach addrman's tried
%% table.
%%
%% Mainnet 2026-11-08: beamchain sat below 8 full-relay outbound peers for 22
%% of 24 hours (min 1). Its addrman held 51,723 entries, of which 46,724 had
%% no source and 46,713 used a non-8333 port. These were inbound crawlers'
%% ephemeral SOURCE addresses: {peer_connected} called addrman:mark_tried/1
%% for inbound peers too, and do_mark_tried/2 inserted unknown addresses
%% straight into tried. 13,198 of the 13,460 tried entries were such
%% addresses, and select_address/0 draws from tried 70% of the time, so
%% almost every outbound dial went to a port nobody listens on.
%%
%% Bitcoin Core:
%%   * net_processing.cpp (VERSION handling): m_addrman.Good(pfrom.addr) only
%%     `if (!pfrom.IsInboundConn())`.
%%   * addrman.cpp AddrManImpl::Good_: `if (!pinfo) return false;` -- Good()
%%     never creates an entry, it only promotes an existing NEW one.

-include_lib("eunit/include/eunit.hrl").

%% A routable address (is_routable/2 accepts it) on an inbound-style
%% ephemeral port, and a listening-port address for the outbound control.
-define(INBOUND_ADDR,  {{93, 184, 216, 34}, 51234}).
-define(OUTBOUND_ADDR, {{93, 184, 216, 35}, 8333}).

%%% ===================================================================
%%% OS env hygiene: beamchain_config reads BEAMCHAIN_NETWORK /
%%% BEAMCHAIN_DATADIR ahead of the application env, so leaving them set (to a
%%% deleted dir) breaks later modules that configure through application env.
%%% Save on setup, restore on cleanup.
%%% ===================================================================

-define(ENV_KEYS, ["BEAMCHAIN_NETWORK", "BEAMCHAIN_DATADIR"]).

save_env() -> [{K, os:getenv(K)} || K <- ?ENV_KEYS].

restore_env(Saved) ->
    lists:foreach(fun({K, false}) -> os:unsetenv(K);
                     ({K, V})     -> os:putenv(K, V)
                  end, Saved).

%%% ===================================================================
%%% addrman-only fixture
%%% ===================================================================

addrman_setup() ->
    TestDir = "/tmp/beamchain_peers_outbound_" ++
              integer_to_list(erlang:unique_integer([positive])),
    ok = filelib:ensure_dir(filename:join(TestDir, "dummy")),
    Saved = save_env(),
    os:putenv("BEAMCHAIN_NETWORK", "regtest"),
    os:putenv("BEAMCHAIN_DATADIR", TestDir),
    catch gen_server:stop(beamchain_addrman),
    catch gen_server:stop(beamchain_config),
    {ok, ConfigPid} = beamchain_config:start_link(),
    {ConfigPid, TestDir, Saved}.

addrman_cleanup({ConfigPid, TestDir, Saved}) ->
    catch gen_server:stop(beamchain_addrman),
    catch gen_server:stop(ConfigPid),
    catch ets:delete(beamchain_config_ets),
    restore_env(Saved),
    os:cmd("rm -rf " ++ TestDir),
    ok.

%% Sync with addrman after casts: count/0 is a call, so it is served after
%% every cast this process already sent.
counts() -> beamchain_addrman:count().

addrman_test_() ->
    {foreach, fun addrman_setup/0, fun addrman_cleanup/1,
     [fun(_) ->
          {"mark_tried on an address addrman does not know is a no-op "
           "(Core Good_: if (!pinfo) return false)",
           fun() ->
               {ok, _} = beamchain_addrman:start_link(),
               beamchain_addrman:mark_tried(?INBOUND_ADDR),
               ?assertEqual({0, 0}, counts())
           end}
      end,
      fun(_) ->
          {"control: mark_tried on a known NEW address still promotes it",
           fun() ->
               {ok, _} = beamchain_addrman:start_link(),
               beamchain_addrman:add_address(?OUTBOUND_ADDR, 9, dns),
               ?assertEqual({1, 0}, counts()),
               beamchain_addrman:mark_tried(?OUTBOUND_ADDR),
               ?assertEqual({0, 1}, counts())
           end}
      end,
      fun(_) ->
          {"load drops source-less entries written by the old "
           "unknown-address mark_tried path; keeps real ones",
           fun() ->
               write_polluted_dets(beamchain_config:datadir()),
               {ok, _} = beamchain_addrman:start_link(),
               %% 1 legit NEW + 1 legit TRIED survive; the 3 source-less
               %% rows (2 tried, 1 evicted-back-to-new) are gone.
               ?assertEqual({1, 1}, counts()),
               Kept = lists:sort(
                        [{maps:get(address, M), maps:get(port, M)}
                         || M <- beamchain_addrman:get_node_addresses(0, all)]),
               ?assertEqual([{<<"8.8.4.4">>, 8333}, {<<"8.8.8.8">>, 8333}],
                            Kept)
           end}
      end]}.

%% peers.dets rows in the current 12-element #addr_info{} layout:
%% {addr_info, Address, Services, Timestamp, Source, SourceNG, Attempts,
%%  LastTry, LastSuccess, InTried, RefCount, NetworkId}
write_polluted_dets(DataDir) ->
    File = filename:join(DataDir, "peers.dets"),
    ok = filelib:ensure_dir(File),
    {ok, T} = dets:open_file(peers_outbound_fixture,
                             [{file, File}, {type, set}, {keypos, 2}]),
    Now = erlang:system_time(second),
    Rows = [
        %% legit NEW (learned from DNS) and legit TRIED (added, then Good())
        {addr_info, {{8, 8, 8, 8}, 8333}, 9, Now, dns, dns, 0, 0, 0,
         false, 1, 1},
        {addr_info, {{8, 8, 4, 4}, 8333}, 9, Now, dns, dns, 0, 0, Now,
         true, 0, 1},
        %% inbound ephemeral source addresses inserted straight into tried
        {addr_info, {{159, 195, 111, 12}, 40001}, 0, Now, undefined,
         undefined, 0, 0, Now, true, 0, 1},
        {addr_info, {{34, 239, 111, 164}, 51111}, 0, Now, undefined,
         undefined, 0, 0, Now, true, 0, 1},
        %% ... and one later evicted from tried back to new
        {addr_info, {{23, 88, 35, 217}, 60606}, 0, Now, undefined,
         undefined, 0, 0, Now, false, 1, 1}
    ],
    ok = dets:insert(T, Rows),
    ok = dets:close(T).

%%% ===================================================================
%%% Real peer manager fixture: drive {peer_connected} end to end
%%% ===================================================================

pm_setup() ->
    TestDir = "/tmp/beamchain_peers_outbound_pm_" ++
              integer_to_list(erlang:unique_integer([positive])),
    ok = filelib:ensure_dir(filename:join(TestDir, "dummy")),
    Port = 40000 + (erlang:unique_integer([positive]) rem 20000),
    Saved = save_env(),
    os:putenv("BEAMCHAIN_NETWORK", "regtest"),
    os:putenv("BEAMCHAIN_DATADIR", TestDir),
    application:set_env(beamchain, p2pport, Port),
    application:set_env(beamchain, nodnsseed, true),
    application:set_env(beamchain, nofixedseeds, true),
    catch gen_server:stop(beamchain_peer_manager),
    catch gen_server:stop(beamchain_addrman),
    catch gen_server:stop(beamchain_config),
    {ok, _} = beamchain_config:start_link(),
    {ok, _} = beamchain_addrman:start_link(),
    {ok, PM} = beamchain_peer_manager:start_link(),
    unlink(PM),
    %% No real dialing from a unit test: suppress new outbound establishment.
    %% {peer_connected} handling is unaffected by this flag.
    false = beamchain_peer_manager:set_network_active(false),
    Dummy = spawn(fun Loop() -> receive stop -> ok; _ -> Loop() end end),
    {TestDir, PM, Dummy, Saved}.

pm_cleanup({TestDir, _PM, Dummy, Saved}) ->
    %% The peer manager reuses a beamchain_peers table an earlier module may
    %% have left behind (init/1 only creates it when absent), so stopping the
    %% manager does not always drop it. Remove our fake row explicitly or a
    %% later module sees a phantom peer (e.g. disconnectnode by nodeid).
    catch ets:delete(beamchain_peers, Dummy),
    Dummy ! stop,
    catch gen_server:stop(beamchain_peer_manager),
    catch gen_server:stop(beamchain_addrman),
    catch gen_server:stop(beamchain_config),
    catch ets:delete(beamchain_config_ets),
    application:unset_env(beamchain, p2pport),
    application:unset_env(beamchain, nodnsseed),
    application:unset_env(beamchain, nofixedseeds),
    restore_env(Saved),
    os:cmd("rm -rf " ++ TestDir),
    ok.

%% Register Dummy as a peer at Addr in the manager's (public) peer table and
%% deliver the handshake-complete edge, then wait for the manager to finish.
connect_fake_peer(PM, Dummy, Direction, Addr) ->
    ok = beamchain_peer_manager:test_insert_peer(Dummy, Direction,
                                                 full_relay, normal),
    %% #peer_entry.address is element 3 (tag, pid, address, ...).
    true = ets:update_element(beamchain_peers, Dummy, {3, Addr}),
    PM ! {peer_connected, Dummy,
          #{user_agent => <<"/bitcoin-seeder:0.01/">>, start_height => 0}},
    _ = sys:get_state(PM),
    ok.

peer_manager_test_() ->
    {foreach, fun pm_setup/0, fun pm_cleanup/1,
     [fun({_, PM, Dummy, _}) ->
          {"inbound handshake does not put the peer's source address in "
           "addrman (Core: Good() only if !IsInboundConn())",
           fun() ->
               ok = connect_fake_peer(PM, Dummy, inbound, ?INBOUND_ADDR),
               ?assertEqual({0, 0}, counts())
           end}
      end,
      fun({_, PM, Dummy, _}) ->
          {"control: outbound handshake promotes the dialed address to tried",
           fun() ->
               beamchain_addrman:add_address(?OUTBOUND_ADDR, 9, dns),
               ?assertEqual({1, 0}, counts()),
               ok = connect_fake_peer(PM, Dummy, outbound, ?OUTBOUND_ADDR),
               ?assertEqual({0, 1}, counts())
           end}
      end]}.
