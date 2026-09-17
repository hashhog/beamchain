-module(beamchain_roll_forward_timeout_tests).

%%% Boot crash-recovery: roll_forward_from_disk must not die on a 5 s
%%% gen_server:call timeout to beamchain_db, and must checkpoint so a
%%% crash mid-replay resumes from the last durable height — not from
%%% the pre-crash flush.
%%%
%%% Live 2026-09-17: after OOM the node re-opened at flushed height
%%% 966303, rolled 310 blocks, then
%%%   {timeout,{gen_server,call,[beamchain_db,{get_block_by_height,966613}]}}
%%% in init/1, systemd restarted, and roll-forward began at 966303 again.
%%% A single slow rocksdb read (coverage slices on the box) is enough.
%%% Core ReplayBlocks / LoadBlockIndex reads are synchronous and unbounded.
%%%
%%% CONTROL: `rebar3 eunit --module=beamchain_roll_forward_timeout_tests`

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

-define(N, 8).
-define(DELAY_MS, 6000).

%%% ===================================================================
%%% 6 s db stall during roll-forward — init completes (no crash)
%%% ===================================================================

slow_db_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) ->
         {timeout, 30, fun slow_db_roll_forward_completes/0}
     end}.

%%% ===================================================================
%%% Crash at N/2 — next boot resumes from >= N/2
%%% ===================================================================

crash_resume_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) -> fun crash_mid_roll_forward_resumes/0 end}.

%%% ===================================================================
%%% Setup / teardown
%%% ===================================================================

setup() ->
    TmpDir = filename:join(["/tmp",
                            "beamchain_roll_forward_test_" ++
                            integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),
    application:ensure_all_started(crypto),
    application:ensure_all_started(rocksdb),
    application:set_env(beamchain, datadir, TmpDir),
    application:set_env(beamchain, network, regtest),
    catch gen_server:stop(beamchain_chainstate),
    catch beamchain_db:stop(),
    catch gen_server:stop(beamchain_config),
    delete_chainstate_ets(),
    {ok, _} = beamchain_config:start_link(),
    {ok, _} = beamchain_db:start_link(),
    Genesis = beamchain_chain_params:genesis_block(regtest),
    GenesisHash = Genesis#block.hash,
    ok = beamchain_db:store_block(Genesis, 0),
    ok = beamchain_db:store_block_index(0, GenesisHash,
                                        Genesis#block.header, <<0, 0, 0, 1>>, 3),
    ok = beamchain_db:set_chain_tip(GenesisHash, 0),
    _ = store_dummy_chain(GenesisHash, 1, ?N),
    {module, beamchain_validation} = code:ensure_loaded(beamchain_validation),
    ok = meck:new(beamchain_validation, [no_link, passthrough]),
    ok = meck:expect(beamchain_validation, connect_block,
                     fun(_Block, _Height, _Prev, _Params) -> ok end),
    TmpDir.

teardown(TmpDir) ->
    catch gen_server:stop(beamchain_chainstate),
    catch meck:unload(beamchain_db),
    catch meck:unload(beamchain_validation),
    catch beamchain_db:stop(),
    catch gen_server:stop(beamchain_config),
    delete_chainstate_ets(),
    os:cmd("rm -rf " ++ TmpDir),
    ok.

delete_chainstate_ets() ->
    lists:foreach(
      fun(T) ->
          case ets:info(T) of
              undefined -> ok;
              _ -> ets:delete(T)
          end
      end,
      [beamchain_utxo_cache, beamchain_utxo_dirty, beamchain_utxo_fresh,
       beamchain_utxo_spent, beamchain_chain_meta]).

store_dummy_chain(_Prev, Height, N) when Height > N ->
    ok;
store_dummy_chain(PrevHash, Height, N) ->
    Block = dummy_block(PrevHash, Height),
    Hash = Block#block.hash,
    ok = beamchain_db:store_block(Block, Height),
    ok = beamchain_db:store_block_index(Height, Hash, Block#block.header,
                                        <<0, 0, 0, 1>>, 3),
    store_dummy_chain(Hash, Height + 1, N).

dummy_block(PrevHash, Height) ->
    Header = #block_header{
        version = 4,
        prev_hash = PrevHash,
        merkle_root = <<Height:256>>,
        timestamp = 1296688602 + Height,
        bits = 16#207fffff,
        nonce = Height
    },
    Hash = beamchain_serialize:block_hash(Header),
    Coinbase = #transaction{
        version = 1,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = <<0:256>>, index = 16#ffffffff},
            script_sig = <<Height:32/little>>,
            sequence = 16#ffffffff,
            witness = []
        }],
        outputs = [#tx_out{value = 5000000000, script_pubkey = <<16#51>>}],
        locktime = 0
    },
    #block{header = Header, transactions = [Coinbase], hash = Hash}.

%%% ===================================================================
%%% Tests
%%% ===================================================================

%% Stall the db gen_server for 6 s while chainstate init is in
%% roll_forward_from_disk. That is the live failure mode: a slow
%% rocksdb read makes get_block_by_height (default 5 s call) exit, and
%% init dies. sys:suspend holds every call on that process, including
%% get_block_by_height, without mecking handle_call (passthrough of a
%% live gen_server callback unloads the original mid-call).
slow_db_roll_forward_completes() ->
    process_flag(trap_exit, true),
    Db = whereis(beamchain_db),
    ?assert(is_pid(Db)),
    ok = sys:suspend(Db),
    Resumer = spawn(fun() ->
                            timer:sleep(?DELAY_MS),
                            catch sys:resume(Db)
                    end),
    try
        T0 = erlang:monotonic_time(millisecond),
        {ok, _Pid} = start_chainstate(),
        Elapsed = erlang:monotonic_time(millisecond) - T0,
        ?assert(Elapsed >= 5500),
        {ok, {_Hash, Tip}} = beamchain_chainstate:get_tip(),
        ?assertEqual(?N, Tip)
    after
        catch sys:resume(Db),
        catch unlink(Resumer),
        catch exit(Resumer, kill)
    end.

%% Crash the roll-forward *caller* (chainstate init) when fetching
%% height N/2+1, after heights 1..N/2 have been connected. The db
%% process must stay up. Next boot must resume from >= N/2, not 0.
crash_mid_roll_forward_resumes() ->
    process_flag(trap_exit, true),
    CrashAt = (?N div 2) + 1,
    {module, beamchain_db} = code:ensure_loaded(beamchain_db),
    ok = meck:new(beamchain_db, [no_link, passthrough]),
    ok = meck:expect(
           beamchain_db, get_block_by_height,
           fun(H) when H =:= CrashAt -> error(injected_crash);
              (H) -> meck:passthrough([H])
           end),
    Start1 = start_chainstate(),
    ?assertMatch({error, _}, Start1),
    {ok, #{height := Durable}} = beamchain_db:get_chain_tip(),
    ?assert(Durable >= (?N div 2)),
    ok = meck:expect(beamchain_db, get_block_by_height,
                     fun(H) -> meck:passthrough([H]) end),
    {ok, _Pid} = start_chainstate(),
    {ok, {_Hash, Tip}} = beamchain_chainstate:get_tip(),
    ?assertEqual(?N, Tip).

%% init/1 failure unlinks, but the EXIT can still land in the test
%% mailbox; trap_exit + catch keeps eunit from cancelling the suite.
start_chainstate() ->
    try beamchain_chainstate:start_link()
    catch
        exit:Reason -> {error, Reason};
        error:Reason -> {error, Reason}
    end.
