-module(beamchain_snapshot_graft_tests).

%%% Trusted chainwork on snapshot graft.
%%%
%%% Bitcoin Core never grafts: ActivateSnapshot refuses a snapshot whose
%%% base header is not already in the headers chain, so nChainWork is the
%%% real cumulative work computed from genesis (validation.cpp:5611-5616,
%%% 5703-5708). beamchain's import-utxo / range ladder deliberately
%%% accepts a snapshot with NO synced headers and must therefore take
%%% chainwork from the assumeutxo/campaign entry — the same trusted
%%% scalar the graft writes into the block index.
%%%
%%% Pre-fix G9 read the (missing or zero) block-index entry and treated
%%% SnapCWInt =:= 0 as "permit anyway", so a snapshot whose trusted
%%% chainwork was BELOW the active tip still loaded. A zero-work stub
%%% already in the index was left untouched, so every later best-chain
%%% comparison accumulated from zero.
%%%
%%% CONTROL: `rebar3 eunit --module=beamchain_snapshot_graft_tests`

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

-define(CAMPAIGN_ENV, "HASHHOG_CAMPAIGN_ASSUMEUTXO").
-define(HEIGHT, 500010).
-define(ACTIVE_CW, 1000).
-define(TRUSTED_LOW, 500).
-define(TRUSTED_HIGH, 2000).

%%% ===================================================================
%%% G9 via the public load_snapshot path (the control)
%%% ===================================================================

g9_load_test_() ->
    {setup, fun setup_full/0, fun teardown_full/1,
     fun(_) ->
         [
          {"G9 refuses a snapshot whose trusted chainwork does not exceed the active tip",
           fun g9_refuses_lesser_trusted_chainwork/0}
         ]
     end}.

%%% ===================================================================
%%% Graft writes / overlays the trusted scalar
%%% ===================================================================

graft_test_() ->
    {setup, fun setup_db/0, fun teardown_db/1,
     fun(_) ->
         [
          {"trusted chainwork is the campaign scalar when the base is unindexed",
           fun trusted_chainwork_from_campaign_when_unindexed/0},
          {"graft writes the trusted chainwork onto a fresh index",
           fun graft_writes_trusted_chainwork/0},
          {"graft overlays trusted chainwork onto a zero-work stub",
           fun graft_overlays_zero_work_stub/0},
          {"graft refuses a band that carries no chainwork",
           fun graft_refuses_band_without_chainwork/0},
          {"graft is a no-op when the index already has real work",
           fun graft_noop_when_index_has_work/0},
          {"G9 comparator: positive trusted work is never a zero-bypass",
           fun g9_comparator_no_zero_bypass/0}
         ]
     end}.

%%% ===================================================================
%%% Setup
%%% ===================================================================

setup_db() ->
    TmpDir = tmpdir("graft"),
    application:ensure_all_started(crypto),
    application:ensure_all_started(rocksdb),
    application:set_env(beamchain, datadir, TmpDir),
    application:set_env(beamchain, network, regtest),
    os:unsetenv(?CAMPAIGN_ENV),
    beamchain_chain_params:clear_campaign_assumeutxo(),
    {ok, ConfigPid} = beamchain_config:start_link(),
    {ok, DbPid} = beamchain_db:start_link(),
    #{tmpdir => TmpDir, config => ConfigPid, db => DbPid}.

teardown_db(#{tmpdir := TmpDir}) ->
    catch beamchain_db:stop(),
    catch gen_server:stop(beamchain_config),
    os:unsetenv(?CAMPAIGN_ENV),
    beamchain_chain_params:clear_campaign_assumeutxo(),
    os:cmd("rm -rf " ++ TmpDir),
    ok.

setup_full() ->
    Env = setup_db(),
    Genesis = beamchain_chain_params:genesis_block(regtest),
    GenesisHash = Genesis#block.hash,
    ok = beamchain_db:store_block(Genesis, 0),
    ok = beamchain_db:store_block_index(
           0, GenesisHash, Genesis#block.header,
           <<(?ACTIVE_CW):256>>, 5, 1),
    ok = beamchain_db:set_chain_tip(GenesisHash, 0),
    {ok, MpPid} = beamchain_mempool:start_link(),
    {ok, CsPid} = beamchain_chainstate:start_link(),
    Env#{mempool => MpPid, chainstate => CsPid, genesis => Genesis}.

teardown_full(Env) ->
    catch gen_server:stop(beamchain_chainstate),
    catch gen_server:stop(beamchain_mempool),
    teardown_db(Env).

tmpdir(Prefix) ->
    Dir = filename:join(["/tmp",
                         "beamchain_" ++ Prefix ++ "_" ++
                         integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(Dir, "dummy")),
    Dir.

%%% ===================================================================
%%% G9 control
%%% ===================================================================

g9_refuses_lesser_trusted_chainwork() ->
    BaseHash = binary:copy(<<16#ab>>, 32),
    UtxoHash = binary:copy(<<16#cd>>, 32),
    Json = campaign_json(BaseHash, UtxoHash, ?TRUSTED_LOW, undefined),
    CampPath = write_tmp("campaign", Json),
    os:putenv(?CAMPAIGN_ENV, CampPath),
    ?assertEqual(ok, beamchain_chain_params:load_campaign_assumeutxo()),

    Magic = maps:get(magic, beamchain_chain_params:params(regtest)),
    SnapBin = beamchain_snapshot:serialize_metadata(Magic, BaseHash, 0),
    SnapPath = write_tmp("snap", SnapBin),
    try
        Result = beamchain_chainstate:load_snapshot(SnapPath),
        ?assertEqual({error, snapshot_chainwork_not_greater}, Result)
    after
        file:delete(CampPath),
        file:delete(SnapPath)
    end.

%%% ===================================================================
%%% Graft unit tests
%%% ===================================================================

trusted_chainwork_from_campaign_when_unindexed() ->
    {Header, BaseHash} = mine_header(),
    UtxoHash = binary:copy(<<16#cd>>, 32),
    Json = campaign_json(BaseHash, UtxoHash, ?TRUSTED_HIGH, Header),
    CampPath = write_tmp("campaign", Json),
    os:putenv(?CAMPAIGN_ENV, CampPath),
    ?assertEqual(ok, beamchain_chain_params:load_campaign_assumeutxo()),
    try
        Got = beamchain_chainstate:snapshot_trusted_chainwork(
                BaseHash, ?HEIGHT, regtest),
        ?assertEqual(?TRUSTED_HIGH, Got)
    after
        file:delete(CampPath),
        beamchain_chain_params:clear_campaign_assumeutxo()
    end.

graft_writes_trusted_chainwork() ->
    {Header, BaseHash} = mine_header(),
    install_campaign(BaseHash, Header, ?TRUSTED_HIGH),
    ?assertEqual(not_found, beamchain_db:get_block_index_by_hash(BaseHash)),
    {ok, _} = beamchain_chainstate:graft_snapshot_base_index(
                BaseHash, ?HEIGHT, regtest),
    {ok, Entry} = beamchain_db:get_block_index_by_hash(BaseHash),
    ?assertEqual(?HEIGHT, maps:get(height, Entry)),
    CWInt = binary:decode_unsigned(maps:get(chainwork, Entry), big),
    ?assertEqual(?TRUSTED_HIGH, CWInt).

graft_overlays_zero_work_stub() ->
    {Header, BaseHash} = mine_header(),
    install_campaign(BaseHash, Header, ?TRUSTED_HIGH),
    ok = beamchain_db:store_block_index(
           ?HEIGHT, BaseHash, Header, <<0:256>>, 5, 0),
    {ok, Before} = beamchain_db:get_block_index_by_hash(BaseHash),
    ?assertEqual(0, binary:decode_unsigned(maps:get(chainwork, Before), big)),
    {ok, _} = beamchain_chainstate:graft_snapshot_base_index(
                BaseHash, ?HEIGHT, regtest),
    {ok, After} = beamchain_db:get_block_index_by_hash(BaseHash),
    CWInt = binary:decode_unsigned(maps:get(chainwork, After), big),
    ?assertEqual(?TRUSTED_HIGH, CWInt).

graft_refuses_band_without_chainwork() ->
    {Header, BaseHash} = mine_header(),
    %% Campaign entry with a band but NO chainwork field.
    Json = campaign_json(BaseHash, binary:copy(<<16#cd>>, 32), undefined, Header),
    CampPath = write_tmp("campaign", Json),
    os:putenv(?CAMPAIGN_ENV, CampPath),
    ?assertEqual(ok, beamchain_chain_params:load_campaign_assumeutxo()),
    try
        Result = beamchain_chainstate:graft_snapshot_base_index(
                   BaseHash, ?HEIGHT, regtest),
        ?assertEqual({error, {snapshot_base_ancestry_without_chainwork, ?HEIGHT}},
                     Result)
    after
        file:delete(CampPath),
        beamchain_chain_params:clear_campaign_assumeutxo()
    end.

graft_noop_when_index_has_work() ->
    {Header, BaseHash} = mine_header(),
    install_campaign(BaseHash, Header, ?TRUSTED_HIGH),
    Existing = 12345,
    ok = beamchain_db:store_block_index(
           ?HEIGHT, BaseHash, Header, <<Existing:256>>, 5, 0),
    {ok, _} = beamchain_chainstate:graft_snapshot_base_index(
                BaseHash, ?HEIGHT, regtest),
    {ok, After} = beamchain_db:get_block_index_by_hash(BaseHash),
    CWInt = binary:decode_unsigned(maps:get(chainwork, After), big),
    ?assertEqual(Existing, CWInt).

g9_comparator_no_zero_bypass() ->
    ?assertEqual({error, snapshot_chainwork_not_greater},
                 beamchain_chainstate:check_snapshot_chainwork(?TRUSTED_LOW, ?ACTIVE_CW)),
    ?assertEqual(ok,
                 beamchain_chainstate:check_snapshot_chainwork(?TRUSTED_HIGH, ?ACTIVE_CW)),
    %% Unknown (unsafe-height, no ancestry) still permits — it does not graft.
    ?assertEqual(ok, beamchain_chainstate:check_snapshot_chainwork(0, ?ACTIVE_CW)).

%%% ===================================================================
%%% Helpers
%%% ===================================================================

install_campaign(BaseHash, Header, ChainworkInt) ->
    Json = campaign_json(BaseHash, binary:copy(<<16#cd>>, 32),
                         ChainworkInt, Header),
    CampPath = write_tmp("campaign", Json),
    os:putenv(?CAMPAIGN_ENV, CampPath),
    ?assertEqual(ok, beamchain_chain_params:load_campaign_assumeutxo()),
    CampPath.

campaign_json(BlockHash, UtxoHash, ChainworkInt, HeaderOrUndef) ->
    HeaderField = case HeaderOrUndef of
        undefined -> <<>>;
        Header ->
            Hex = to_hex(beamchain_serialize:encode_block_header(Header)),
            iolist_to_binary([",\"base_header\":\"", Hex, "\""])
    end,
    CWField = case ChainworkInt of
        undefined -> <<>>;
        N when is_integer(N) ->
            iolist_to_binary([",\"chainwork\":\"", chainwork_hex(N), "\""])
    end,
    iolist_to_binary(io_lib:format(
        "[{\"height\": ~B, \"blockhash\": \"~s\", "
        "\"hash_serialized\": \"~s\", \"m_chain_tx_count\": 1~s~s}]",
        [?HEIGHT, display_hex(BlockHash), display_hex(UtxoHash),
         HeaderField, CWField])).

mine_header() ->
    Bits = 16#207fffff,
    Unique = erlang:unique_integer([positive]),
    mine_header_loop(#block_header{
        version = 1,
        prev_hash = <<0:256>>,
        merkle_root = <<Unique:256>>,
        timestamp = 1296688602,
        bits = Bits,
        nonce = 0
    }, 0).

mine_header_loop(_H, N) when N > 1000000 ->
    error(could_not_mine_regtest_header);
mine_header_loop(H, N) ->
    H1 = H#block_header{nonce = N},
    Params = beamchain_chain_params:params(regtest),
    case beamchain_validation:check_block_header(H1, Params) of
        ok -> {H1, beamchain_serialize:block_hash(H1)};
        {error, high_hash} -> mine_header_loop(H, N + 1);
        {error, Reason} -> error({header_check, Reason})
    end.

display_hex(<<H:32/binary>>) ->
    to_hex(list_to_binary(lists:reverse(binary_to_list(H)))).

to_hex(Bin) ->
    lists:flatten([io_lib:format("~2.16.0b", [B]) || <<B>> <= Bin]).

chainwork_hex(N) ->
    lists:flatten(io_lib:format("~64.16.0b", [N])).

write_tmp(Prefix, Bin) ->
    Path = "/tmp/beamchain_graft_" ++ Prefix ++ "_" ++
           integer_to_list(erlang:unique_integer([positive])),
    ok = file:write_file(Path, Bin),
    Path.
