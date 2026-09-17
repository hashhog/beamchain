-module(beamchain_peer_manager_boot_timeout_tests).

%%% Boot-path 5 s gen_server:call default: peer_manager's connect_tick
%%% calls beamchain_addrman:select_address/0 with no timeout, so a busy
%%% addrman (dets flush, get_addresses of a large table, another call in
%%% flight) kills the manager. OTP reports that as
%%%   initial call: beamchain_peer_manager:init/1
%%%   exception exit: {timeout,{gen_server,call,[beamchain_addrman,{select_address,#{}}]}}
%%% Live 2026-09-17T02:12:26Z during the 084c058 restart; the supervisor
%%% restarted the manager and the node came up. Same defect class as
%%% f823653 / 084c058 on the db and chainstate paths.
%%%
%%% CONTROL: `rebar3 eunit --module=beamchain_peer_manager_boot_timeout_tests`

-include_lib("eunit/include/eunit.hrl").

-define(DELAY_MS, 6000).

%%% ===================================================================
%%% 6 s addrman stall during connect_tick — manager stays up
%%% ===================================================================

slow_addrman_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) ->
         {timeout, 30, fun slow_addrman_connect_tick_completes/0}
     end}.

%%% ===================================================================
%%% Setup / teardown
%%% ===================================================================

setup() ->
    TmpDir = filename:join(["/tmp",
                            "beamchain_pm_boot_timeout_" ++
                            integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),
    Port = 40000 + (erlang:unique_integer([positive]) rem 20000),
    os:putenv("BEAMCHAIN_NETWORK", "regtest"),
    os:putenv("BEAMCHAIN_DATADIR", TmpDir),
    application:set_env(beamchain, p2pport, Port),
    application:set_env(beamchain, nodnsseed, true),
    application:set_env(beamchain, nofixedseeds, true),
    catch gen_server:stop(beamchain_peer_manager),
    catch gen_server:stop(beamchain_addrman),
    catch gen_server:stop(beamchain_config),
    {ok, _} = beamchain_config:start_link(),
    {ok, _} = beamchain_addrman:start_link(),
    TmpDir.

teardown(TmpDir) ->
    catch gen_server:stop(beamchain_peer_manager),
    catch gen_server:stop(beamchain_addrman),
    catch gen_server:stop(beamchain_config),
    application:unset_env(beamchain, p2pport),
    application:unset_env(beamchain, nodnsseed),
    application:unset_env(beamchain, nofixedseeds),
    os:cmd("rm -rf " ++ TmpDir),
    ok.

%%% ===================================================================
%%% Tests
%%% ===================================================================

%% Stall addrman for 6 s and fire the live crash path: connect_tick ->
%% try_connect_one -> select_address (default 5 s call). sys:suspend holds
%% every call on that process without mecking handle_call. The manager
%% must still be the same pid afterwards — no CRASH REPORT, no supervisor
%% restart.
slow_addrman_connect_tick_completes() ->
    process_flag(trap_exit, true),
    {ok, PM} = start_peer_manager(),
    %% Drain bootstrap / asmap_health_check and the nodnsseed connect_tick
    %% scheduled 500 ms later, so the stall applies to a tick we inject.
    _ = sys:get_state(PM),
    timer:sleep(700),
    _ = sys:get_state(PM),
    ?assert(is_process_alive(PM)),
    Addrman = whereis(beamchain_addrman),
    ?assert(is_pid(Addrman)),
    ok = sys:suspend(Addrman),
    Resumer = spawn(fun() ->
                            timer:sleep(?DELAY_MS),
                            catch sys:resume(Addrman)
                    end),
    try
        T0 = erlang:monotonic_time(millisecond),
        PM ! connect_tick,
        TickOk = try
                     _ = sys:get_state(PM, 20000),
                     ok
                 catch
                     exit:Reason -> {error, Reason};
                     error:Reason -> {error, Reason}
                 end,
        Elapsed = erlang:monotonic_time(millisecond) - T0,
        ?assertEqual(ok, TickOk),
        ?assert(Elapsed >= 5500),
        ?assert(is_process_alive(PM)),
        ?assertEqual(PM, whereis(beamchain_peer_manager)),
        receive
            {'EXIT', PM, ExitReason} ->
                erlang:error({peer_manager_exited, ExitReason})
        after 0 ->
            ok
        end
    after
        catch sys:resume(Addrman),
        catch unlink(Resumer),
        catch exit(Resumer, kill)
    end.

%% init/1 failure unlinks, but the EXIT can still land in the test
%% mailbox; trap_exit + catch keeps eunit from cancelling the suite.
start_peer_manager() ->
    try beamchain_peer_manager:start_link()
    catch
        exit:Reason -> {error, Reason};
        error:Reason -> {error, Reason}
    end.
