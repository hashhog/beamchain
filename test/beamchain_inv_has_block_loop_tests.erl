%%% Tests for secfix H9: a block inv must not cost one synchronous
%%% beamchain_db:has_block/1 call per item on the shared sync process.
%%%
%%% Bitcoin Core ProcessMessage(INV) (net_processing.cpp:4051-4097) keeps a
%%% single best_block, the last block inv it does not already have, and sends
%%% one getheaders for it. Its AlreadyHaveBlock is an in-memory lookup.
%%% beamchain's has_block/1 is a gen_server:call into beamchain_db (a RocksDB
%%% read), and route_message(inv) used to ask it for every block item, so a
%%% 50,000-item inv (MAX_INV_SIZE, accepted without penalty) kept the sync
%%% process busy for 50,000 db round trips.
%%%
%%% meck stubs the collaborators route_message consults:
%%%   - beamchain_chainstate:is_synced/0 -> false, so the tx-request leg is
%%%     skipped (block items only here);
%%%   - beamchain_db:has_block/1, counted with meck:num_calls/3. In the
%%%     bounded-time cases each call sleeps 1 ms, standing in for the
%%%     gen_server round trip;
%%%   - beamchain_header_sync:probe_peer/1, counted (the one getheaders).
%%%
%%% The new file sits next to beamchain_sync_tests.erl (added by open PR #77)
%%% instead of in it, so neither PR conflicts with the other.
-module(beamchain_inv_has_block_loop_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain_protocol.hrl").

-define(MOCKED, [beamchain_chainstate, beamchain_db, beamchain_header_sync]).

%% Core's MAX_BLOCKS_TO_ANNOUNCE; the fix checks at most this many items.
-define(MAX_CHECKS, 8).

%% A generous bound: the fixed code does <= 8 sleeps of 1 ms. The unfixed
%% code needs 50,000 of them (> 50 s).
-define(RESPONSIVE_MS, 5000).

%%% ===================================================================
%%% Helpers
%%% ===================================================================

flush() -> receive _ -> flush() after 0 -> ok end.

meck_passthrough(Mod) ->
    {module, Mod} = code:ensure_loaded(Mod),
    ok = meck:new(Mod, [no_link, passthrough]).

%% Known :: fun((Hash) -> boolean()) - which hashes beamchain_db "has".
%% DelayMs :: per-call cost of has_block/1.
install(Known, DelayMs) ->
    lists:foreach(fun meck_passthrough/1, ?MOCKED),
    ok = meck:expect(beamchain_chainstate, is_synced, fun() -> false end),
    ok = meck:expect(beamchain_db, has_block,
                     fun(H) -> timer:sleep(DelayMs), Known(H) end),
    ok = meck:expect(beamchain_header_sync, probe_peer, fun(_) -> ok end),
    ok.

unload() ->
    lists:foreach(fun(M) -> catch meck:unload(M) end, ?MOCKED),
    flush(),
    ok.

%% Title is the test's name in eunit output (a bare fun would print as
%% -with_install/3-fun-0-).
with_install(Title, Known, DelayMs, Fun) ->
    {Title, {timeout, 120, fun() ->
        install(Known, DelayMs),
        try Fun()
        after unload() end
    end}}.

hash(N) -> <<N:256>>.

block_items(From, To) ->
    [{?MSG_WITNESS_BLOCK, hash(N)} || N <- lists:seq(From, To)].

inv_payload(Items) ->
    beamchain_p2p_msg:encode_payload(
      inv, #{items => [#{type => T, hash => H} || {T, H} <- Items]}).

%% Run route_message(inv) in a worker so a slow (unfixed) run is cut off at
%% ?RESPONSIVE_MS instead of hanging the suite. Returns {Result, ElapsedMs}
%% where Result is done or timeout.
route_bounded(Items) ->
    Payload = inv_payload(Items),
    Parent = self(),
    T0 = erlang:monotonic_time(millisecond),
    {Pid, Ref} = spawn_monitor(fun() ->
        _ = beamchain_sync:route_message(Parent, inv, Payload,
                                         beamchain_sync:test_initial_state()),
        exit(done)
    end),
    Result = receive
        {'DOWN', Ref, process, Pid, done} -> done;
        {'DOWN', Ref, process, Pid, Other} -> {crashed, Other}
    after ?RESPONSIVE_MS ->
        exit(Pid, kill),
        receive {'DOWN', Ref, process, Pid, _} -> ok end,
        timeout
    end,
    {Result, erlang:monotonic_time(millisecond) - T0}.

db_calls()    -> meck:num_calls(beamchain_db, has_block, '_').
probe_calls() -> meck:num_calls(beamchain_header_sync, probe_peer, '_').

%%% ===================================================================
%%% H9: 50,000-item block inv
%%% ===================================================================

%% 50,000 block items, none known: at most a handful of db calls, the sync
%% process finishes promptly, and exactly one getheaders goes out.
big_block_inv_bounded_db_calls_test_() ->
    with_install("big_block_inv_bounded_db_calls", fun(_) -> false end, 1, fun() ->
        {Result, Ms} = route_bounded(block_items(1, ?MAX_INV_SIZE)),
        Calls = db_calls(),
        ?debugFmt("50k unknown: result=~p elapsed=~B ms has_block calls=~B",
                  [Result, Ms, Calls]),
        ?assertEqual(done, Result),
        ?assert(Calls =< ?MAX_CHECKS),
        ?assertEqual(1, probe_calls())
    end).

%% 50,000 block items, all known: still bounded, and no getheaders.
big_block_inv_all_known_bounded_db_calls_test_() ->
    with_install("big_block_inv_all_known_bounded_db_calls", fun(_) -> true end, 1, fun() ->
        {Result, Ms} = route_bounded(block_items(1, ?MAX_INV_SIZE)),
        Calls = db_calls(),
        ?debugFmt("50k known: result=~p elapsed=~B ms has_block calls=~B",
                  [Result, Ms, Calls]),
        ?assertEqual(done, Result),
        ?assert(Calls =< ?MAX_CHECKS),
        ?assertEqual(0, probe_calls())
    end).

%%% ===================================================================
%%% Core's best_block choice for honest announcements
%%% ===================================================================

%% A single unknown block inv (the normal tip announcement) -> getheaders.
single_unknown_block_probes_test_() ->
    with_install("single_unknown_block_probes", fun(_) -> false end, 0, fun() ->
        {done, _} = route_bounded([{?MSG_BLOCK, hash(1)}]),
        ?assertEqual(1, db_calls()),
        ?assertEqual(1, probe_calls())
    end).

%% A single known block inv -> no getheaders.
single_known_block_no_probe_test_() ->
    with_install("single_known_block_no_probe", fun(_) -> true end, 0, fun() ->
        {done, _} = route_bounded([{?MSG_BLOCK, hash(1)}]),
        ?assertEqual(1, db_calls()),
        ?assertEqual(0, probe_calls())
    end).

%% Core announces up to 8 blocks oldest-first. When the newest is the one we
%% lack, it is found with one db call (the unfixed code asks about all 8).
eight_block_announce_newest_unknown_test_() ->
    Unknown = hash(8),
    with_install("eight_block_announce_newest_unknown", fun(H) -> H =/= Unknown end, 0, fun() ->
        {done, _} = route_bounded(block_items(1, 8)),
        ?assertEqual(1, db_calls()),
        ?assertEqual(1, probe_calls())
    end).

%% Core's best_block is the LAST block item not had, even when later items
%% are known: [unknown, known x7] still triggers getheaders (8 checks).
unknown_followed_by_known_still_probes_test_() ->
    Unknown = hash(1),
    with_install("unknown_followed_by_known_still_probes", fun(H) -> H =/= Unknown end, 0, fun() ->
        {done, _} = route_bounded(block_items(1, 8)),
        ?assertEqual(8, db_calls()),
        ?assertEqual(1, probe_calls())
    end).

%% Tx items around the block items are not looked up in the block store and
%% do not use up the check budget.
tx_items_do_not_consume_block_checks_test_() ->
    Unknown = hash(1),
    Items = [{?MSG_BLOCK, Unknown}]
            ++ [{?MSG_TX, hash(1000 + N)} || N <- lists:seq(1, 100)]
            ++ [{?MSG_BLOCK, hash(2)}],
    with_install("tx_items_do_not_consume_block_checks", fun(H) -> H =/= Unknown end, 0, fun() ->
        {done, _} = route_bounded(Items),
        ?assertEqual(2, db_calls()),
        ?assertEqual(1, probe_calls())
    end).

%% No block items at all -> no db calls, no getheaders.
tx_only_inv_no_block_lookup_test_() ->
    with_install("tx_only_inv_no_block_lookup", fun(_) -> false end, 0, fun() ->
        {done, _} = route_bounded([{?MSG_TX, hash(N)} || N <- lists:seq(1, 10)]),
        ?assertEqual(0, db_calls()),
        ?assertEqual(0, probe_calls())
    end).
