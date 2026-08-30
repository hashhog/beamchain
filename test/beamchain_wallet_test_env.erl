%%% @doc Point the wallet at a PRIVATE datadir for the duration of a test.
%%%
%%% WHY THIS EXISTS
%%% ---------------
%%% beamchain_wallet:wallet_dir/1 calls beamchain_config:datadir(), and falls
%%% back to $HOME/.beamchain when the config table is not up. Under eunit the
%%% config server is usually not running, so every wallet test wrote to the
%%% developer's REAL home directory:
%%%
%%%     $HOME/.beamchain/mainnet/wallet/wallet.json
%%%
%%% All 10 wallet-touching test modules shared that one file, and
%%% beamchain_wallet:init/1 AUTO-LOADS it. So a test that encrypts the wallet
%%% (beamchain_fix63_tests:walletprocesspsbt_locked_wallet_test_) left an
%%% encrypted wallet on disk, and every test ordered after it -- in that run
%%% AND IN EVERY LATER RUN, because the file persists -- came up locked and got
%%% RPC -13 "Please enter the wallet passphrase" where it expected success.
%%%
%%% Measured 2026-08-30: that single leak accounted for all 5 failures #89
%%% surfaced (3 in fix63, 1 in fix65_payjoin_receiver, 1 in
%%% fix67_payjoin_cleanup). fix65 and fix67 pass cleanly on their own; they
%%% failed only because an earlier module had poisoned the shared file. The
%%% node's -13 was CORRECT for a locked wallet -- these were test bugs, not
%%% node bugs.
%%%
%%% Seeding the config table with a per-test datadir makes wallet_dir/1 resolve
%%% into a temp directory instead, so no test can see another's wallet and none
%%% of them touch $HOME.
-module(beamchain_wallet_test_env).

-export([setup/0, teardown/1, ensure_isolated_datadir/0]).

-define(CONFIG_TABLE, beamchain_config_ets).

%% @doc Create a private datadir and point beamchain_config at it.
%% Returns {Dir, OwnedTable} to hand to teardown/1.
-spec setup() -> {string(), boolean()}.
setup() ->
    Dir = filename:join("/tmp",
        "beamchain_wallet_test_" ++ integer_to_list(erlang:unique_integer([positive]))),
    ok = filelib:ensure_dir(filename:join(Dir, "dummy")),
    Owned = case ets:info(?CONFIG_TABLE) of
                undefined ->
                    ets:new(?CONFIG_TABLE, [named_table, set, public]),
                    true;
                _ -> false
            end,
    ets:insert(?CONFIG_TABLE, {datadir, Dir}),
    {Dir, Owned}.

%% @doc Undo setup/0: drop the config entry (and the table if we made it) and
%% remove the temp datadir, so nothing leaks into the next test or the next run.
-spec teardown({string(), boolean()}) -> ok.
teardown({Dir, Owned}) ->
    case Owned of
        true  -> catch ets:delete(?CONFIG_TABLE), ok;
        false -> catch ets:delete(?CONFIG_TABLE, datadir), ok
    end,
    _ = rm_rf(Dir),
    ok.

rm_rf(Path) ->
    case filelib:is_dir(Path) of
        true ->
            {ok, Names} = file:list_dir(Path),
            [rm_rf(filename:join(Path, N)) || N <- Names],
            file:del_dir(Path);
        false ->
            file:delete(Path)
    end.

%% @doc Give the caller a FRESH, EMPTY private datadir.
%%
%% Per-MODULE isolation is not enough: beamchain_fix63_tests' locked-wallet
%% test encrypts the wallet, and any later fixture sharing the directory
%% auto-loads that encrypted wallet.json and comes up locked. This CLEARS the
%% directory on every call -- and stop_default_wallet/0 is called at the top of
%% every fixture setup -- so each fixture starts from a wallet nobody has
%% touched, which is the property the tests actually assume.
%%
%% The path is FIXED rather than unique-per-call on purpose. The config ETS
%% table is owned by whichever process created it, and eunit runs each fixture
%% in its own process, so the table (and any remembered path) dies between
%% fixtures -- a unique-per-call scheme therefore leaks one directory per
%% fixture into /tmp, which on this host is a RAM-backed tmpfs. A fixed path
%% that is emptied on entry gives the same isolation with a bounded footprint.
%% Assumes eunit's default SEQUENTIAL execution; parallel fixtures would need
%% the path keyed per worker.
-spec ensure_isolated_datadir() -> string().
ensure_isolated_datadir() ->
    Dir = "/tmp/beamchain_wallet_test_env",
    _ = rm_rf(Dir),
    ok = filelib:ensure_dir(filename:join(Dir, "dummy")),
    case ets:info(?CONFIG_TABLE) of
        undefined -> ets:new(?CONFIG_TABLE, [named_table, set, public]);
        _ -> ok
    end,
    ets:insert(?CONFIG_TABLE, {datadir, Dir}),
    Dir.
