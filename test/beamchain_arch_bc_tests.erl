-module(beamchain_arch_bc_tests).

%%% ARCH-2 BC-5 + BC-1 regression tests.
%%%
%%% BC-5: the RocksDB options must REACH the DB. The instrument is the DB's
%%% own OPTIONS-* file and LOG, read back after open — what RocksDB says it
%%% is running, not what the Erlang code asked for (the bug was that the
%%% NIF silently dropped the request; every CF ran filter_policy=nullptr).
%%% The bloom-bits-0 case is the negative control: the same parser must see
%%% nullptr, so a pass is not the parser finding nothing.
%%%
%%% BC-1: txindex default off (Core DEFAULT_TXINDEX=false); with it off a
%%% connect writes no tx_index rows; with it on it writes them plus the
%%% txindex_best marker; an off period is recorded (txindex_gap_from) and
%%% reported by txindex_status/0.

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-define(ENV_VARS, ["BEAMCHAIN_TXINDEX", "BEAMCHAIN_DB_BLOOM_BITS",
                   "BEAMCHAIN_DBCACHE"]).

%%% -------------------------------------------------------------------
%%% fixtures
%%% -------------------------------------------------------------------

save_env() -> [{V, os:getenv(V)} || V <- ?ENV_VARS].

restore_env(Saved) ->
    lists:foreach(fun({V, false}) -> os:unsetenv(V);
                     ({V, X}) -> os:putenv(V, X)
                  end, Saved).

new_dir() ->
    D = filename:join(["/tmp", "beamchain_archbc_" ++
                       integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(D, "dummy")),
    D.

start(Dir) ->
    application:ensure_all_started(rocksdb),
    os:unsetenv("BEAMCHAIN_DATADIR"),
    application:set_env(beamchain, datadir, Dir),
    application:set_env(beamchain, network, regtest),
    {ok, _} = beamchain_config:start_link(),
    {ok, _} = beamchain_db:start_link(),
    ok.

stop() ->
    catch beamchain_db:stop(),
    catch gen_server:stop(beamchain_config),
    ok.

%% Run Fun with a fresh datadir and the given env, then clean up.
with_db(Env, Fun) ->
    Saved = save_env(),
    Dir = new_dir(),
    try
        [os:unsetenv(V) || V <- ?ENV_VARS],
        [os:putenv(K, V) || {K, V} <- Env],
        ok = start(Dir),
        Fun(Dir)
    after
        stop(),
        restore_env(Saved),
        os:cmd("rm -rf " ++ Dir)
    end.

%%% -------------------------------------------------------------------
%%% OPTIONS / LOG parsing (the instrument)
%%% -------------------------------------------------------------------

%% The DB lives under beamchain_config:datadir() (which may add a network
%% subdirectory to the configured dir), so ask the config, not the fixture.
chaindata(_Dir) ->
    filename:join(beamchain_config:datadir(), "chaindata").

newest_options(Dir) ->
    Files = filelib:wildcard(filename:join(chaindata(Dir), "OPTIONS-*")),
    ?assertNotEqual([], Files),
    Num = fun(F) -> list_to_integer(lists:last(string:split(F, "-", trailing))) end,
    {ok, Bin} = file:read_file(lists:last(lists:sort(
                    fun(A, B) -> Num(A) =< Num(B) end, Files))),
    Bin.

%% #{CfName => FilterPolicyValue} from every [TableOptions/BlockBasedTable "cf"].
filter_policies(OptionsBin) ->
    Sections = binary:split(OptionsBin, <<"[TableOptions/BlockBasedTable \"">>, [global]),
    maps:from_list(
      [begin
           [Name, Rest] = binary:split(S, <<"\"]">>),
           {match, [FP]} = re:run(Rest, "\\n\\s*filter_policy=([^\\n]*)",
                                  [{capture, all_but_first, binary}]),
           {Name, FP}
       end || S <- tl(Sections)]).

%% Every "block_cache: 0x..." pointer and "capacity : N" from the LOG's
%% per-CF table-factory dump.
log_caches(Dir) ->
    {ok, Log} = file:read_file(filename:join(chaindata(Dir), "LOG")),
    {match, Ptrs} = re:run(Log, "\\n\\s*block_cache: (0x[0-9a-f]+)",
                           [global, {capture, all_but_first, binary}]),
    {match, Caps} = re:run(Log, "\\n\\s*capacity : (\\d+)",
                           [global, {capture, all_but_first, binary}]),
    {[P || [P] <- Ptrs], [binary_to_integer(C) || [C] <- Caps]}.

-define(ALL_CFS, [<<"default">>, <<"blocks">>, <<"block_index">>,
                  <<"chainstate">>, <<"tx_index">>, <<"meta">>, <<"undo">>]).

%%% -------------------------------------------------------------------
%%% BC-5
%%% -------------------------------------------------------------------

bc5_test_() ->
    {timeout, 120,
     [{"every CF runs a bloom filter (read back from the DB's OPTIONS file)",
       fun() ->
           with_db([], fun(Dir) ->
               FP = filter_policies(newest_options(Dir)),
               ?assertEqual(lists:sort(?ALL_CFS), lists:sort(maps:keys(FP))),
               [?assertMatch(<<"bloomfilter:10", _/binary>>, maps:get(Cf, FP))
                || Cf <- ?ALL_CFS]
           end)
       end},
      {"NEGATIVE CONTROL: bloom bits 0 -> filter_policy=nullptr on every CF",
       fun() ->
           with_db([{"BEAMCHAIN_DB_BLOOM_BITS", "0"}], fun(Dir) ->
               FP = filter_policies(newest_options(Dir)),
               ?assertEqual(7, map_size(FP)),
               [?assertEqual(<<"nullptr">>, maps:get(Cf, FP)) || Cf <- ?ALL_CFS]
           end)
       end},
      {"one SHARED cache of the --dbcache-derived size on all 7 CFs (LOG)",
       fun() ->
           %% dbcache 2048 -> 2048/4 = 512 MiB (beamchain_db
           %% effective_coins_db_cache_bytes/0), distinct from both RocksDB's
           %% 32 MiB per-CF default and the 256 MiB unset default.
           with_db([{"BEAMCHAIN_DBCACHE", "2048"}], fun(Dir) ->
               {Ptrs, Caps} = log_caches(Dir),
               ?assertEqual(7, length(Ptrs)),
               ?assertEqual(1, length(lists:usort(Ptrs))),
               ?assertEqual([512 * 1024 * 1024], lists:usort(Caps)),
               ?assertEqual(512 * 1024 * 1024,
                            beamchain_db:coins_db_cache_bytes())
           end)
       end},
      {"write buffers unchanged (64 MiB x 2, the values the DB ran with)",
       fun() ->
           with_db([], fun(Dir) ->
               O = newest_options(Dir),
               {match, W} = re:run(O, "\\n\\s*write_buffer_size=(\\d+)",
                                   [global, {capture, all_but_first, binary}]),
               {match, N} = re:run(O, "\\n\\s*max_write_buffer_number=(\\d+)",
                                   [global, {capture, all_but_first, binary}]),
               ?assertEqual([<<"67108864">>], lists:usort([X || [X] <- W])),
               ?assertEqual([<<"2">>], lists:usort([X || [X] <- N]))
           end)
       end}]}.

%%% -------------------------------------------------------------------
%%% BC-1
%%% -------------------------------------------------------------------

make_block(PrevHash, NTx) ->
    Header = #block_header{version = 1, prev_hash = PrevHash,
                           merkle_root = crypto:strong_rand_bytes(32),
                           timestamp = 1231006505, bits = 16#207fffff,
                           nonce = erlang:unique_integer([positive])},
    Txs = [#transaction{
              version = 1,
              inputs = [#tx_in{prev_out = #outpoint{hash = crypto:strong_rand_bytes(32),
                                                     index = I},
                               script_sig = <<1, I>>, sequence = 16#ffffffff,
                               witness = []}],
              outputs = [#tx_out{value = 1000 + I, script_pubkey = <<16#51>>}],
              locktime = 0} || I <- lists:seq(1, NTx)],
    #block{header = Header, transactions = Txs}.

count_cf(CfTerm) ->
    Db = persistent_term:get(beamchain_db_handle),
    Cf = persistent_term:get(CfTerm),
    {ok, It} = rocksdb:iterator(Db, Cf, []),
    N = count_it(rocksdb:iterator_move(It, first), It, 0),
    rocksdb:iterator_close(It),
    N.

count_it({ok, _, _}, It, N) -> count_it(rocksdb:iterator_move(It, next), It, N + 1);
count_it(_, _, N) -> N.

connect(Height, NTx) ->
    B = make_block(crypto:strong_rand_bytes(32), NTx),
    H = beamchain_serialize:block_hash(B#block.header),
    ok = beamchain_db:direct_atomic_connect_writes(B, Height, <<1:256>>, H, 5),
    {B, H}.

bc1_test_() ->
    {timeout, 120,
     [{"default: txindex off, a connect writes NO tx_index rows; gap recorded",
       fun() ->
           with_db([], fun(_Dir) ->
               ?assertEqual(false, beamchain_config:txindex_enabled()),
               ?assertEqual(off, beamchain_db:txindex_status()),
               _ = connect(1, 5),
               ?assertEqual(0, count_cf(beamchain_cf_tx_index)),
               ?assertEqual(not_found, beamchain_db:get_meta(<<"txindex_best">>)),
               %% fresh datadir, nothing indexed -> first unindexed height 0
               ?assertEqual({ok, <<0:64/big>>},
                            beamchain_db:get_meta(<<"txindex_gap_from">>))
           end)
       end},
      {"NEGATIVE CONTROL: txindex on -> one row per tx + best-block marker",
       fun() ->
           with_db([{"BEAMCHAIN_TXINDEX", "1"}], fun(_Dir) ->
               ?assertEqual(synced, beamchain_db:txindex_status()),
               {B, H} = connect(1, 5),
               ?assertEqual(5, count_cf(beamchain_cf_tx_index)),
               ?assertEqual({ok, <<H/binary, 1:64/big>>},
                            beamchain_db:get_meta(<<"txindex_best">>)),
               [T1 | _] = B#block.transactions,
               ?assertMatch({ok, #{height := 1, position := 0}},
                            beamchain_db:get_tx_location(
                              beamchain_serialize:tx_hash(T1)))
           end)
       end},
      {"on -> off -> on with blocks connected while off: gap kept, unsynced",
       fun() ->
           Saved = save_env(),
           Dir = new_dir(),
           try
               [os:unsetenv(V) || V <- ?ENV_VARS],
               os:putenv("BEAMCHAIN_TXINDEX", "1"),
               ok = start(Dir),
               {_, H5} = connect(5, 2),
               ok = beamchain_db:set_chain_tip(H5, 5),
               stop(),
               os:putenv("BEAMCHAIN_TXINDEX", "0"),
               ok = start(Dir),
               %% best marker at 5 -> first unindexed height 6
               ?assertEqual({ok, <<6:64/big>>},
                            beamchain_db:get_meta(<<"txindex_gap_from">>)),
               {_, H6} = connect(6, 2),
               ok = beamchain_db:set_chain_tip(H6, 6),
               ?assertEqual(2, count_cf(beamchain_cf_tx_index)),
               stop(),
               os:putenv("BEAMCHAIN_TXINDEX", "1"),
               ok = start(Dir),
               ?assertEqual({gap, 6}, beamchain_db:txindex_status())
           after
               stop(), restore_env(Saved), os:cmd("rm -rf " ++ Dir)
           end
       end},
      {"on -> off -> on with NO block connected while off: gap cleared",
       fun() ->
           Saved = save_env(),
           Dir = new_dir(),
           try
               [os:unsetenv(V) || V <- ?ENV_VARS],
               os:putenv("BEAMCHAIN_TXINDEX", "1"),
               ok = start(Dir),
               {_, H5} = connect(5, 2),
               ok = beamchain_db:set_chain_tip(H5, 5),
               stop(),
               os:putenv("BEAMCHAIN_TXINDEX", "0"),
               ok = start(Dir),
               stop(),
               os:putenv("BEAMCHAIN_TXINDEX", "1"),
               ok = start(Dir),
               ?assertEqual(synced, beamchain_db:txindex_status()),
               ?assertEqual(not_found, beamchain_db:get_meta(<<"txindex_gap_from">>))
           after
               stop(), restore_env(Saved), os:cmd("rm -rf " ++ Dir)
           end
       end},
      {"pre-marker datadir booted with the index on adopts it at the tip",
       fun() ->
           Saved = save_env(),
           Dir = new_dir(),
           try
               [os:unsetenv(V) || V <- ?ENV_VARS],
               os:putenv("BEAMCHAIN_TXINDEX", "1"),
               ok = start(Dir),
               {_, H9} = connect(9, 1),
               ok = beamchain_db:set_chain_tip(H9, 9),
               %% simulate a datadir written before the marker existed
               Db = persistent_term:get(beamchain_db_handle),
               ok = rocksdb:delete(Db, persistent_term:get(beamchain_cf_meta),
                                   <<"txindex_best">>, []),
               stop(),
               ok = start(Dir),
               ?assertEqual(synced, beamchain_db:txindex_status()),
               ?assertEqual({ok, <<H9/binary, 9:64/big>>},
                            beamchain_db:get_meta(<<"txindex_best">>))
           after
               stop(), restore_env(Saved), os:cmd("rm -rf " ++ Dir)
           end
       end},
      {"--txindex flag overrides an inherited BEAMCHAIN_TXINDEX=0",
       fun() ->
           Saved = save_env(),
           try
               os:putenv("BEAMCHAIN_TXINDEX", "0"),
               {start, Opts} = beamchain_cli:parse_args(
                                 ["start", "--txindex=1"]),
               ?assertEqual(1, maps:get(txindex, Opts)),
               {start, Opts0} = beamchain_cli:parse_args(
                                  ["start", "--txindex=0"]),
               ?assertEqual(0, maps:get(txindex, Opts0)),
               {start, OptsB} = beamchain_cli:parse_args(
                                  ["start", "--txindex"]),
               ?assertEqual(1, maps:get(txindex, OptsB))
           after
               restore_env(Saved)
           end
       end}]}.
