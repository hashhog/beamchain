%%% #72 rows — beamchain locator entries (2026-08-27).
%%%
%%% (a) beamchain_headerssync:chain_start_locator returned ONLY the
%%%     chain_start hash: the 2-hash anti-pattern (nimrod 4deead0, camlcoin
%%%     PRESYNC, clearbit 7b97bce, blockbrew 7009b2b, hotbuns 0e5e25c).
%%%     Core appends LocatorEntries(&m_chain_start) — an exponential walk
%%%     from chain_start down to and INCLUDING genesis (headerssync.cpp:
%%%     296-317, chain.cpp:26-43).
%%% (b) beamchain_header_sync:build_block_locator truncated WITHOUT genesis
%%%     when the height index had a hole mid-walk — a locator that loses
%%%     its genesis anchor is unrecognizable to peers once the walked
%%%     hashes are stale.
%%%
%%% A/B: at the parent commit chain_start_locator_entries/3 does not exist
%%% (undef — the #45 precedent) and the meck'd holey-index walk returns a
%%% locator that does NOT end at genesis.
-module(beamchain_locator_entries_tests).
-include_lib("eunit/include/eunit.hrl").

h(N) -> <<N:256>>.

lookup_full(H) -> {ok, #{hash => h(H)}}.

%% ---- (a) HSS chain-start entries ----

hss_walks_to_genesis_test() ->
    Locator = beamchain_headerssync:chain_start_locator_entries(
                1000, h(1000), fun lookup_full/1),
    ?assert(length(Locator) > 3),
    ?assertEqual(h(1000), hd(Locator)),
    ?assertEqual(h(0), lists:last(Locator)),
    %% ~1000 heights under a doubling step must compress far below 1000.
    ?assert(length(Locator) < 64).

hss_no_index_degrades_to_bare_hash_test() ->
    NoIndex = fun(_) -> not_found end,
    ?assertEqual([h(1000)],
                 beamchain_headerssync:chain_start_locator_entries(
                   1000, h(1000), NoIndex)).

hss_genesis_chain_start_is_single_test() ->
    ?assertEqual([h(0)],
                 beamchain_headerssync:chain_start_locator_entries(
                   0, h(0), fun lookup_full/1)).

hss_holey_index_still_ends_at_genesis_test() ->
    %% Rows exist for heights >= 500 and for genesis; hole in between.
    Holey = fun(0) -> {ok, #{hash => h(0)}};
               (H) when H >= 500 -> {ok, #{hash => h(H)}};
               (_) -> not_found
            end,
    Locator = beamchain_headerssync:chain_start_locator_entries(
                1000, h(1000), Holey),
    ?assertEqual(h(0), lists:last(Locator)).

%% ---- (b) header_sync holey-index genesis terminator ----

header_sync_holey_index_ends_at_genesis_test() ->
    ok = meck:new(beamchain_db, [no_link, passthrough, non_strict]),
    try
        meck:expect(beamchain_db, get_block_index,
                    fun(0) -> {ok, #{hash => h(0)}};
                       (H) when H >= 900 -> {ok, #{hash => h(H)}};
                       (_) -> not_found
                    end),
        Locator = beamchain_header_sync:build_block_locator(1000, h(1000)),
        ?assert(length(Locator) > 1),
        ?assertEqual(h(1000), hd(Locator)),
        ?assertEqual(h(0), lists:last(Locator))
    after
        meck:unload(beamchain_db)
    end.
