-module(beamchain_wallet_persist_tests).

%%% ===================================================================
%%% Wallet restart-persistence regression tests (sweep wa0fq5wtk).
%%%
%%% These prove the four restart-persistence guarantees added to
%%% beamchain_wallet, mirroring Bitcoin Core's wallet durability and this
%%% node's OWN mempool_persist atomic-write pattern:
%%%
%%%   T1  ATOMIC + DURABLE write: a mutation persists to disk with no
%%%       leftover temp file, and a fresh process reloads it intact.
%%%   T2  SAVE-ON-MUTATION survives an UNCLEAN restart: a SIGKILL (which
%%%       skips terminate/2 entirely) must NOT lose a generated address —
%%%       it was already fsynced at mutation time, not only at shutdown.
%%%   T3  FAULT-TOLERANT LOAD: a corrupt / truncated primary wallet file
%%%       must NOT crash startup, and must transparently recover the last
%%%       known-good state from the .bak the durable writer leaves behind.
%%%   T4  A missing wallet file is a clean no-op (fresh datadir boots an
%%%       empty, usable wallet — never a crash).
%%%
%%% The tests drive the real gen_server (no chainstate / rocksdb needed:
%%% the startup reconcile is a no-op when current_tip_height/0 returns
%%% not_found, which it does with no chainstate running).  HOME is pointed
%%% at a throwaway temp dir so we never touch a real datadir.
%%% ===================================================================

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

%% Default wallet file path under our temp HOME (network defaults to
%% mainnet when beamchain_config isn't configured in this process).
wallet_file(Home) ->
    filename:join([Home, ".beamchain", "mainnet", "wallet", "wallet.json"]).

setup() ->
    Home = "/tmp/bc_wallet_persist_" ++ integer_to_list(erlang:unique_integer([positive])),
    ok = filelib:ensure_dir(Home ++ "/"),
    PrevHome = os:getenv("HOME"),
    true = os:putenv("HOME", Home),
    %% Make sure no stray default wallet process is registered.
    _ = stop_default(),
    {Home, PrevHome}.

cleanup({Home, PrevHome}) ->
    _ = stop_default(),
    case PrevHome of
        false -> os:unsetenv("HOME");
        _     -> os:putenv("HOME", PrevHome)
    end,
    _ = os:cmd("rm -rf " ++ Home),
    ok.

stop_default() ->
    case whereis(beamchain_wallet) of
        undefined -> ok;
        Pid ->
            MRef = erlang:monitor(process, Pid),
            exit(Pid, kill),
            receive {'DOWN', MRef, process, Pid, _} -> ok
            after 2000 -> ok
            end
    end.

%% Start the DEFAULT wallet (registers as `beamchain_wallet`, exercises the
%% boot auto-load path).  Unlink immediately so a deliberate `exit(Pid,kill)`
%% in a test (simulating SIGKILL/OOM) does not propagate to and kill the
%% eunit test process itself.
start_default() ->
    {ok, Pid} = beamchain_wallet:start_link(),
    true = unlink(Pid),
    Pid.

persist_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
      fun t1_atomic_durable_roundtrip/1,
      fun t2_mutation_survives_unclean_restart/1,
      fun t3_corrupt_file_load_recovers_from_bak/1,
      fun t4_missing_file_is_clean_noop/1
     ]}.

%%% -------------------------------------------------------------------
%%% T1 — atomic + durable write, no temp leftover, reload intact
%%% -------------------------------------------------------------------
t1_atomic_durable_roundtrip({Home, _}) ->
    fun() ->
        Pid = start_default(),
        Seed = crypto:strong_rand_bytes(32),
        {ok, _} = gen_server:call(Pid, {create, Seed, undefined}),
        {ok, Addr} = gen_server:call(Pid, {get_new_address, p2wpkh}),
        File = wallet_file(Home),
        %% The mutation must have produced a real file...
        ?assert(filelib:is_regular(File)),
        %% ...with NO temp file left behind (atomic rename completed).
        ?assertNot(filelib:is_regular(File ++ ".tmp")),
        %% Kill (unclean) and reload into a brand-new process; the address
        %% generated above must survive.
        ok = stop_default(),
        Pid2 = start_default(),   %% boot auto-load reads wallet.json
        {ok, Addrs} = gen_server:call(Pid2, list_addresses),
        Found = lists:any(
                  fun(A) -> maps:get(<<"address">>, A) =:= list_to_binary(Addr) end,
                  Addrs),
        ?assert(Found),
        ok = stop_default()
    end.

%%% -------------------------------------------------------------------
%%% T2 — a generated address survives a SIGKILL (terminate/2 never runs)
%%% -------------------------------------------------------------------
t2_mutation_survives_unclean_restart({Home, _}) ->
    fun() ->
        Pid = start_default(),
        {ok, _} = gen_server:call(Pid, {create, crypto:strong_rand_bytes(32),
                                        undefined}),
        {ok, _BaseAddrs} = gen_server:call(Pid, list_addresses),
        %% Mutation AFTER creation: this address is only durable if
        %% save-on-mutation actually fsynced it (terminate/2 will not run).
        {ok, NewAddr} = gen_server:call(Pid, {get_new_address, p2wpkh}),
        %% Hard kill — simulates OOM / power loss / SIGKILL.  terminate/2
        %% is skipped, so ONLY the at-mutation durable write can save us.
        MRef = erlang:monitor(process, Pid),
        exit(Pid, kill),
        receive {'DOWN', MRef, process, Pid, _} -> ok after 2000 -> ok end,
        %% File must still hold the post-create mutation.
        ?assert(filelib:is_regular(wallet_file(Home))),
        Pid2 = start_default(),
        {ok, Addrs} = gen_server:call(Pid2, list_addresses),
        Found = lists:any(
                  fun(A) -> maps:get(<<"address">>, A) =:= list_to_binary(NewAddr) end,
                  Addrs),
        ?assert(Found),
        ok = stop_default()
    end.

%%% -------------------------------------------------------------------
%%% T3 — corrupt primary file: load doesn't crash, recovers from .bak
%%% -------------------------------------------------------------------
t3_corrupt_file_load_recovers_from_bak({Home, _}) ->
    fun() ->
        %% First, produce a known-good wallet + at least one address, and a
        %% second mutation so the durable writer rotates the prior good copy
        %% into wallet.json.bak.
        Pid = start_default(),
        {ok, _} = gen_server:call(Pid, {create, crypto:strong_rand_bytes(32),
                                        undefined}),
        {ok, GoodAddr} = gen_server:call(Pid, {get_new_address, p2wpkh}),
        %% Force a .bak to exist by mutating again (rotate prior good file).
        {ok, _} = gen_server:call(Pid, {get_new_address, p2wpkh}),
        ok = stop_default(),
        File = wallet_file(Home),
        Bak  = File ++ ".bak",
        ?assert(filelib:is_regular(File)),
        ?assert(filelib:is_regular(Bak)),
        %% Corrupt the primary file: truncate to a half-written JSON
        %% prefix (the classic partial-write failure mode).
        {ok, Good} = file:read_file(File),
        Half = binary:part(Good, 0, max(1, byte_size(Good) div 2)),
        ok = file:write_file(File, <<Half/binary, "{{{ TRUNCATED">>),
        %% Boot must NOT crash, and must recover SOMETHING valid from .bak.
        %% (The .bak is the state after the FIRST get_new_address, which
        %% includes GoodAddr.)
        Pid2 = start_default(),
        ?assert(is_process_alive(Pid2)),
        {ok, Addrs} = gen_server:call(Pid2, list_addresses),
        ?assert(length(Addrs) >= 1),
        FoundGood = lists:any(
                      fun(A) -> maps:get(<<"address">>, A) =:= list_to_binary(GoodAddr) end,
                      Addrs),
        ?assert(FoundGood),
        ok = stop_default()
    end.

%%% -------------------------------------------------------------------
%%% T4 — missing wallet file: clean empty boot, no crash
%%% -------------------------------------------------------------------
t4_missing_file_is_clean_noop({Home, _}) ->
    fun() ->
        ?assertNot(filelib:is_regular(wallet_file(Home))),
        Pid = start_default(),
        ?assert(is_process_alive(Pid)),
        %% Empty wallet: no addresses, get_wallet_info reports no seed.
        {ok, Addrs} = gen_server:call(Pid, list_addresses),
        ?assertEqual([], Addrs),
        {ok, Info} = gen_server:call(Pid, get_wallet_info),
        ?assertEqual(false, maps:get(has_seed, Info)),
        ok = stop_default()
    end.
