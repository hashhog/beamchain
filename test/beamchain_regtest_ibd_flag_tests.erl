%%% getblockchaininfo.initialblockdownload must follow the chainstate's
%%% tip-age latch on regtest too (policy-cause-16).
%%%
%%% Core validation.cpp IsInitialBlockDownload(): true until the tip is newer
%%% than now - max_tip_age (24h), then latched false. A regtest chain with
%%% fixed 2023 timestamps therefore reports true. beamchain forced false on
%%% regtest regardless of is_synced().
%%%
%%% CONTROL: `rebar3 eunit --module=beamchain_regtest_ibd_flag_tests`
-module(beamchain_regtest_ibd_flag_tests).
-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

info_map() ->
    case beamchain_rpc:handle_method(<<"getblockchaininfo">>, [], undefined) of
        {ok_raw_json, Bin} -> jsx:decode(Bin, [{return_maps, true}]);
        {ok, Term} -> jsx:decode(jsx:encode(Term), [{return_maps, true}])
    end.

with_fixture(Synced, TestFun) ->
    TmpDir = filename:join(["/tmp", "beamchain_ibdflag_" ++
                            integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),
    application:ensure_all_started(rocksdb),
    application:set_env(beamchain, datadir, TmpDir),
    application:set_env(beamchain, network, regtest),
    os:unsetenv("BEAMCHAIN_PRUNE"),
    {ok, _} = start_or_ok(fun beamchain_config:start_link/0),
    {ok, _} = start_or_ok(fun beamchain_db:start_link/0),
    {module, beamchain_chainstate} = code:ensure_loaded(beamchain_chainstate),
    ok = meck:new(beamchain_chainstate, [no_link]),
    try
        {TipHash, TipH} = seed(3),
        ok = meck:expect(beamchain_chainstate, get_tip,
                         fun() -> {ok, {TipHash, TipH}} end),
        ok = meck:expect(beamchain_chainstate, get_mtp, fun() -> 1700000000 end),
        ok = meck:expect(beamchain_chainstate, is_synced, fun() -> Synced end),
        TestFun()
    after
        catch meck:unload(beamchain_chainstate),
        catch beamchain_db:stop(),
        catch gen_server:stop(beamchain_config),
        os:cmd("rm -rf " ++ TmpDir)
    end.

start_or_ok(F) ->
    case F() of
        {ok, P} -> {ok, P};
        {error, {already_started, P}} -> {ok, P}
    end.

make_block(Prev, H) ->
    Header = #block_header{version = 1, prev_hash = Prev,
                           merkle_root = <<H:256>>, timestamp = 1700000000 + H,
                           bits = 16#207fffff, nonce = H},
    Cb = #transaction{version = 1,
                      inputs = [#tx_in{prev_out = #outpoint{hash = <<0:256>>,
                                                            index = 16#ffffffff},
                                       script_sig = <<H:32/big>>,
                                       sequence = 16#ffffffff, witness = []}],
                      outputs = [#tx_out{value = 5000000000,
                                         script_pubkey = <<16#51>>}],
                      locktime = 0},
    #block{header = Header, transactions = [Cb],
           hash = beamchain_serialize:block_hash(Header), height = H}.

seed(Tip) ->
    G = make_block(<<0:256>>, 0),
    store(0, G),
    Last = lists:foldl(fun(H, P) -> B = make_block(P#block.hash, H),
                                    store(H, B), B end,
                       G, lists:seq(1, Tip)),
    ok = beamchain_db:set_chain_tip(Last#block.hash, Tip),
    {Last#block.hash, Tip}.

store(H, B) ->
    ok = beamchain_db:store_block_index(H, B#block.hash, B#block.header,
                                        <<H:256>>, 1),
    ok = beamchain_db:store_block(B, H).

regtest_old_tip_reports_ibd_true_test() ->
    with_fixture(false, fun() ->
        ?assertEqual(true, maps:get(<<"initialblockdownload">>, info_map()))
    end).

regtest_recent_tip_reports_ibd_false_test() ->
    with_fixture(true, fun() ->
        ?assertEqual(false, maps:get(<<"initialblockdownload">>, info_map()))
    end).
