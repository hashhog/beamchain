-module(beamchain_campaign_assumeutxo_tests).

%%% -------------------------------------------------------------------
%%% HASHHOG_CAMPAIGN_ASSUMEUTXO — campaign-only assumeutxo allowlist.
%%%
%%% Design spec: receipts/CAMPAIGN-SNAPSHOT-TABLE-SPEC.md.
%%% Porter wave, Change-2 (paired with Change-1's regtest Core-parity
%%% entries in beamchain_w102_assumeutxo_tests.erl /
%%% beamchain_w138_assumeutxo_tests.erl).
%%%
%%% The load-bearing invariant under test: when
%%% HASHHOG_CAMPAIGN_ASSUMEUTXO is unset (the production case — real
%%% mainnet/testnet4 boots never set it), effective_assumeutxo/1 behaves
%%% EXACTLY as it did before this feature existed. See the
%%% unset_flag_bit_identical_test/0 group below.
%%% -------------------------------------------------------------------

-include_lib("eunit/include/eunit.hrl").

-define(CAMPAIGN_ENV, "HASHHOG_CAMPAIGN_ASSUMEUTXO").

%%% ===================================================================
%%% Test fixtures
%%% ===================================================================

tmp_path(Prefix) ->
    "/tmp/" ++ Prefix ++ "_" ++ integer_to_list(erlang:system_time()) ++
        "_" ++ integer_to_list(rand:uniform(1_000_000)) ++ ".json".

%% A single well-formed campaign entry at a height with no built-in
%% collision on any network (mainnet/testnet4/regtest all leave height
%% 500000 unused).
campaign_entry_json(Height, BlockHashHex, HashSerHex, ChainTxCount) ->
    iolist_to_binary(io_lib:format(
        "[{\"height\": ~B, \"blockhash\": \"~s\", "
        "\"hash_serialized\": \"~s\", \"m_chain_tx_count\": ~B}]",
        [Height, BlockHashHex, HashSerHex, ChainTxCount])).

write_campaign_file(Json) ->
    Path = tmp_path("campaign_au"),
    ok = file:write_file(Path, Json),
    Path.

setup() ->
    %% Belt-and-braces: make sure no stray env var / registry state
    %% leaks in from a previous (possibly crashed) test run.
    os:unsetenv(?CAMPAIGN_ENV),
    beamchain_chain_params:clear_campaign_assumeutxo(),
    ok.

teardown(_) ->
    os:unsetenv(?CAMPAIGN_ENV),
    beamchain_chain_params:clear_campaign_assumeutxo(),
    ok.

%%% ===================================================================
%%% Unset-flag bit-identical proof (REQUIRED gate — see
%%% receipts/PORTER-WAVE-WORKORDER.md).
%%% ===================================================================

%% Snapshot the effective assumeutxo table for a network as an ordered
%% list of {Height, Data} pairs, via the same public chokepoint functions
%% every RPC/validation call site uses (get_assumeutxo/2,
%% list_assumeutxo_heights/1) — not by peeking at internal tables.
snapshot_effective(Network) ->
    Heights = beamchain_chain_params:list_assumeutxo_heights(Network),
    [{H, beamchain_chain_params:get_assumeutxo(H, Network)} || H <- Heights].

unset_flag_bit_identical_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun() ->
        %% HASHHOG_CAMPAIGN_ASSUMEUTXO is unset (setup/0 ensures this).
        os:unsetenv(?CAMPAIGN_ENV),

        %% Snapshot every network's effective table BEFORE calling
        %% load_campaign_assumeutxo/0.
        Networks = [mainnet, testnet4, regtest],
        Before = [{N, snapshot_effective(N)} || N <- Networks],

        %% load_campaign_assumeutxo/0 with the flag unset must be a
        %% single getenv that returns `ok` and creates no ETS table.
        ?assertEqual(ok, beamchain_chain_params:load_campaign_assumeutxo()),
        ?assertEqual(#{}, beamchain_chain_params:campaign_assumeutxo_registry()),

        %% Snapshot again AFTER — must be byte-for-byte identical.
        After = [{N, snapshot_effective(N)} || N <- Networks],
        ?assertEqual(Before, After)
     end}.

%% Empty string must behave identically to unset (same single-getenv
%% short-circuit).
empty_string_flag_bit_identical_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun() ->
        os:putenv(?CAMPAIGN_ENV, ""),
        ?assertEqual(ok, beamchain_chain_params:load_campaign_assumeutxo()),
        ?assertEqual(#{}, beamchain_chain_params:campaign_assumeutxo_registry())
     end}.

%%% ===================================================================
%%% Flag set: a campaign-height lookup resolves.
%%% ===================================================================

campaign_height_resolves_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun() ->
        BlockHashHex = "1111111111111111111111111111111111111111111111111111111111111111",
        HashSerHex   = "2222222222222222222222222222222222222222222222222222222222222222",
        Json = campaign_entry_json(500000, BlockHashHex, HashSerHex, 12345678),
        Path = write_campaign_file(Json),
        os:putenv(?CAMPAIGN_ENV, Path),

        ?assertEqual(ok, beamchain_chain_params:load_campaign_assumeutxo()),

        %% Resolves via get_assumeutxo/2 for whichever network is
        %% configured (default: mainnet, since no BEAMCHAIN_NETWORK / app
        %% env is set in this test process).
        {ok, #{block_hash := BH, utxo_hash := UH, chain_tx_count := C}} =
            beamchain_chain_params:get_assumeutxo(500000, mainnet),
        ?assertEqual(12345678, C),
        ?assertEqual(32, byte_size(BH)),
        ?assertEqual(32, byte_size(UH)),

        %% And via get_assumeutxo_by_hash/2.
        {ok, FoundHeight, #{utxo_hash := UH2}} =
            beamchain_chain_params:get_assumeutxo_by_hash(BH, mainnet),
        ?assertEqual(500000, FoundHeight),
        ?assertEqual(UH, UH2),

        %% list_assumeutxo_heights/1 includes the campaign height.
        ?assert(lists:member(500000,
                              beamchain_chain_params:list_assumeutxo_heights(mainnet))),

        file:delete(Path)
     end}.

%% Campaign entries apply to whichever network effective_assumeutxo/1 is
%% asked about — including regtest, layered on top of (not replacing) the
%% regtest runtime registry.
campaign_height_resolves_on_regtest_too_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun() ->
        BlockHashHex = "3333333333333333333333333333333333333333333333333333333333333333",
        HashSerHex   = "4444444444444444444444444444444444444444444444444444444444444444",
        Json = campaign_entry_json(500001, BlockHashHex, HashSerHex, 42),
        Path = write_campaign_file(Json),
        os:putenv(?CAMPAIGN_ENV, Path),
        ?assertEqual(ok, beamchain_chain_params:load_campaign_assumeutxo()),

        %% Built-in regtest entries (110/200/299) still resolve...
        ?assertMatch({ok, _}, beamchain_chain_params:get_assumeutxo(110, regtest)),
        %% ...and the campaign entry resolves too.
        ?assertMatch({ok, _}, beamchain_chain_params:get_assumeutxo(500001, regtest)),

        file:delete(Path)
     end}.

%%% ===================================================================
%%% Refusal cases (refuse to start — load_campaign_assumeutxo/0 returns
%%% {error, _}).
%%% ===================================================================

collision_with_builtin_height_refuses_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun() ->
        %% Height 840000 collides with the built-in mainnet entry.
        BlockHashHex = "5555555555555555555555555555555555555555555555555555555555555555",
        HashSerHex   = "6666666666666666666666666666666666666666666666666666666666666666",
        Json = campaign_entry_json(840000, BlockHashHex, HashSerHex, 1),
        Path = write_campaign_file(Json),
        os:putenv(?CAMPAIGN_ENV, Path),

        ?assertMatch({error, _}, beamchain_chain_params:load_campaign_assumeutxo()),
        %% Refusal must not leave a partial table behind.
        ?assertEqual(#{}, beamchain_chain_params:campaign_assumeutxo_registry()),

        file:delete(Path)
     end}.

collision_with_builtin_blockhash_refuses_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun() ->
        %% Distinct (non-colliding) height, but the built-in mainnet
        %% 840000 blockhash (display order, from chainparams.cpp).
        BlockHashHex = "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5",
        HashSerHex   = "7777777777777777777777777777777777777777777777777777777777777777",
        Json = campaign_entry_json(500002, BlockHashHex, HashSerHex, 1),
        Path = write_campaign_file(Json),
        os:putenv(?CAMPAIGN_ENV, Path),

        ?assertMatch({error, _}, beamchain_chain_params:load_campaign_assumeutxo()),
        ?assertEqual(#{}, beamchain_chain_params:campaign_assumeutxo_registry()),

        file:delete(Path)
     end}.

duplicate_height_within_file_refuses_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun() ->
        Hex1 = "8888888888888888888888888888888888888888888888888888888888888888",
        Hex2 = "9999999999999999999999999999999999999999999999999999999999999999",
        Hex3 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        Json = iolist_to_binary(io_lib:format(
            "[{\"height\": 500003, \"blockhash\": \"~s\", "
            "\"hash_serialized\": \"~s\", \"m_chain_tx_count\": 1},"
            " {\"height\": 500003, \"blockhash\": \"~s\", "
            "\"hash_serialized\": \"~s\", \"m_chain_tx_count\": 2}]",
            [Hex1, Hex2, Hex3, Hex2])),
        Path = write_campaign_file(Json),
        os:putenv(?CAMPAIGN_ENV, Path),

        ?assertMatch({error, _}, beamchain_chain_params:load_campaign_assumeutxo()),
        ?assertEqual(#{}, beamchain_chain_params:campaign_assumeutxo_registry()),

        file:delete(Path)
     end}.

malformed_hex_refuses_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun() ->
        Json = <<"[{\"height\": 500004, \"blockhash\": \"nothex\", "
                  "\"hash_serialized\": \"nothex\", "
                  "\"m_chain_tx_count\": 1}]">>,
        Path = write_campaign_file(Json),
        os:putenv(?CAMPAIGN_ENV, Path),

        ?assertMatch({error, _}, beamchain_chain_params:load_campaign_assumeutxo()),
        ?assertEqual(#{}, beamchain_chain_params:campaign_assumeutxo_registry()),

        file:delete(Path)
     end}.

missing_file_refuses_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun() ->
        os:putenv(?CAMPAIGN_ENV, "/tmp/beamchain_campaign_au_does_not_exist.json"),
        ?assertMatch({error, _}, beamchain_chain_params:load_campaign_assumeutxo())
     end}.

malformed_json_refuses_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun() ->
        Path = write_campaign_file(<<"not json at all {{{">>),
        os:putenv(?CAMPAIGN_ENV, Path),
        ?assertMatch({error, _}, beamchain_chain_params:load_campaign_assumeutxo()),
        file:delete(Path)
     end}.
