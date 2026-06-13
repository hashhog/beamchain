-module(beamchain_getchainstates_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

%% Focused tests for the getchainstates RPC (beamchain_rpc:rpc_getchainstates/0).
%%
%% Mirrors Bitcoin Core's getchainstates / RPCHelpForChainstate
%% (bitcoin-core/src/rpc/blockchain.cpp:3448-3519). beamchain runs a single,
%% fully-validated main chainstate (no active AssumeUTXO snapshot in steady
%% state), so the response must be:
%%
%%   { "headers": <int>,
%%     "chainstates": [ { "blocks": <int>, "bestblockhash": <hex>,
%%                        "bits": <hex>, "target": <hex>, "difficulty": <num>,
%%                        "verificationprogress": <num>,
%%                        "coins_db_cache_bytes": <int>,
%%                        "coins_tip_cache_bytes": <int>,
%%                        "validated": true } ] }
%%
%% with validated == true and snapshot_blockhash OMITTED. The test drives the
%% PRODUCTION handler end-to-end against a live config/db/chainstate seeded with
%% the regtest genesis block, then decodes the emitted wire JSON (the handler
%% returns {ok_raw_json, Bin} so difficulty is a genuine %.16g Core number) and
%% asserts every required field, type, and the absence of snapshot_blockhash.

getchainstates_test_() ->
    {setup,
     fun setup/0,
     fun teardown/1,
     fun(_) ->
         [
          {"headers is an integer (>= chain tip height)",
           fun test_headers_is_int/0},
          {"chainstates is a 1-element array",
           fun test_chainstates_single_element/0},
          {"chainstate entry has all required fields with correct types",
           fun test_entry_field_types/0},
          {"validated == true for the single fully-validated chainstate",
           fun test_validated_true/0},
          {"no snapshot_blockhash key when no snapshot is active",
           fun test_no_snapshot_blockhash/0},
          {"blocks/bestblockhash match the active chain tip",
           fun test_tip_values/0},
          {"cache sizes are the node's real configured budgets",
           fun test_cache_sizes_genuine/0}
         ]
     end}.

setup() ->
    TmpDir = filename:join(["/tmp", "beamchain_getchainstates_test_" ++
                            integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),

    application:ensure_all_started(rocksdb),
    application:set_env(beamchain, datadir, TmpDir),
    application:set_env(beamchain, network, regtest),

    {ok, ConfigPid} = beamchain_config:start_link(),
    {ok, DbPid} = beamchain_db:start_link(),

    %% Seed the regtest genesis block + index + chain/header tip in the DB
    %% BEFORE starting chainstate (chainstate loads the tip from the DB on init).
    Genesis = beamchain_chain_params:genesis_block(regtest),
    GenesisHash = Genesis#block.hash,
    ok = beamchain_db:store_block(Genesis, 0),
    ok = beamchain_db:store_block_index(0, GenesisHash,
        Genesis#block.header, <<0,0,0,1>>, 3),
    ok = beamchain_db:set_chain_tip(GenesisHash, 0),
    ok = beamchain_db:set_header_tip(GenesisHash, 0),

    {ok, ChainstatePid} = beamchain_chainstate:start_link(),

    {TmpDir, ConfigPid, DbPid, ChainstatePid, Genesis}.

teardown({TmpDir, _ConfigPid, _DbPid, _ChainstatePid, _Genesis}) ->
    catch gen_server:stop(beamchain_chainstate),
    catch beamchain_db:stop(),
    catch gen_server:stop(beamchain_config),
    os:cmd("rm -rf " ++ TmpDir),
    ok.

%%% ===================================================================
%%% Helpers
%%% ===================================================================

%% Drive the production handler and decode the wire JSON it emits.
%% rpc_getchainstates/0 returns {ok_raw_json, Bin}; decode to a map (jsx
%% return_maps) so field presence/types/values can be asserted.
call_result() ->
    {ok_raw_json, Bin} = beamchain_rpc:rpc_getchainstates(),
    ?assert(is_binary(Bin)),
    jsx:decode(Bin, [return_maps]).

entry() ->
    Result = call_result(),
    [Entry] = maps:get(<<"chainstates">>, Result),
    Entry.

%%% ===================================================================
%%% Tests
%%% ===================================================================

test_headers_is_int() ->
    Result = call_result(),
    Headers = maps:get(<<"headers">>, Result),
    ?assert(is_integer(Headers)),
    %% Genesis seeded at height 0 -> best-header height is 0.
    ?assertEqual(0, Headers).

test_chainstates_single_element() ->
    Result = call_result(),
    Chainstates = maps:get(<<"chainstates">>, Result),
    ?assert(is_list(Chainstates)),
    ?assertEqual(1, length(Chainstates)).

test_entry_field_types() ->
    Entry = entry(),
    %% Every required Core field is present with the right JSON type.
    ?assert(is_integer(maps:get(<<"blocks">>, Entry))),
    ?assert(is_binary(maps:get(<<"bestblockhash">>, Entry))),
    ?assert(is_binary(maps:get(<<"bits">>, Entry))),
    ?assert(is_binary(maps:get(<<"target">>, Entry))),
    %% difficulty is a JSON number (Core %.16g) — integer or float decode.
    Diff = maps:get(<<"difficulty">>, Entry),
    ?assert(is_number(Diff)),
    VP = maps:get(<<"verificationprogress">>, Entry),
    ?assert(is_number(VP)),
    ?assert(VP >= 0.0 andalso VP =< 1.0),
    ?assert(is_integer(maps:get(<<"coins_db_cache_bytes">>, Entry))),
    ?assert(is_integer(maps:get(<<"coins_tip_cache_bytes">>, Entry))),
    ?assert(is_boolean(maps:get(<<"validated">>, Entry))),
    %% bestblockhash is 64 lowercase hex chars; bits is 8 hex chars.
    ?assertEqual(64, byte_size(maps:get(<<"bestblockhash">>, Entry))),
    ?assertEqual(8, byte_size(maps:get(<<"bits">>, Entry))),
    ?assertEqual(64, byte_size(maps:get(<<"target">>, Entry))).

test_validated_true() ->
    Entry = entry(),
    ?assertEqual(true, maps:get(<<"validated">>, Entry)).

test_no_snapshot_blockhash() ->
    Entry = entry(),
    %% Core only pushes snapshot_blockhash for a from-snapshot chainstate.
    %% The main fully-validated chainstate must NOT carry the key.
    ?assertEqual(false, maps:is_key(<<"snapshot_blockhash">>, Entry)),
    ?assertEqual(error, maps:find(<<"snapshot_blockhash">>, Entry)).

test_tip_values() ->
    Entry = entry(),
    {ok, {TipHash, TipHeight}} = beamchain_chainstate:get_tip(),
    ExpectedHash = list_to_binary(
        lists:flatten([io_lib:format("~2.16.0b", [B])
                       || <<B>> <= rev_bytes(TipHash)])),
    ?assertEqual(TipHeight, maps:get(<<"blocks">>, Entry)),
    ?assertEqual(ExpectedHash, maps:get(<<"bestblockhash">>, Entry)).

test_cache_sizes_genuine() ->
    Entry = entry(),
    %% coins_db_cache_bytes must equal the node's real on-disk coins-DB
    %% (RocksDB block) cache budget, and coins_tip_cache_bytes the real
    %% configured coins-tip (UTXO) cache flush threshold. Neither is fabricated.
    ?assertEqual(beamchain_db:coins_db_cache_bytes(),
                 maps:get(<<"coins_db_cache_bytes">>, Entry)),
    Meta = beamchain_chainstate:get_chainstate_meta(),
    ?assertEqual(maps:get(coins_tip_cache_bytes, Meta),
                 maps:get(<<"coins_tip_cache_bytes">>, Entry)),
    %% Sanity: budgets are positive (not a fabricated 0).
    ?assert(maps:get(<<"coins_db_cache_bytes">>, Entry) > 0),
    ?assert(maps:get(<<"coins_tip_cache_bytes">>, Entry) > 0).

%% Reverse a binary's bytes (internal hash -> display byte order).
rev_bytes(Bin) ->
    list_to_binary(lists:reverse(binary_to_list(Bin))).
