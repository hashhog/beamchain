-module(beamchain_catchup_oom_tests).

%%% Catch-up OOM: in-flight decoded blocks + a 4096MB UTXO cache blew the
%%% 8G MemoryMax, systemd SIGKILL'd the node, and because IBD flush was
%%% gated on 5000 blocks the durable tip stayed at the last flush
%%% (966303) after 650 connected blocks (966949). Live 2026-09-17.
%%%
%%% Core: FlushStateToDisk PERIODIC + cache-budget (validation.cpp),
%%% MAX_BLOCKS_IN_TRANSIT_PER_PEER=16 (net_processing.cpp). is_synced
%%% must not be a 5 s gen_server:call — chainstate is busy connecting
%%% during catch-up and beamchain_sync crash-looped on that timeout.
%%%
%%% CONTROL: `rebar3 eunit --module=beamchain_catchup_oom_tests`

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

-define(N_SMALL, 16).
-define(N_PERIODIC, 80).
-define(CACHE_BUDGET_BYTES, 65536).
-define(CACHE_BUDGET_ENTRIES, 32).
-define(UTXOS_PER_BLOCK, 64).
-define(BUSY_WAIT_MS, 1000).

%%% ===================================================================
%%% Connect N with a small cache budget: flush before N, cache bounded
%%% ===================================================================

small_budget_test_() ->
    {setup, fun setup_chain/0, fun teardown_chain/1,
     fun(_) ->
         {timeout, 60, fun connect_n_flushes_and_bounds_cache/0}
     end}.

%%% ===================================================================
%%% Default cache: periodic flush must fire before N=80 (was 5000)
%%% ===================================================================

periodic_flush_test_() ->
    {setup, fun setup_chain/0, fun teardown_chain/1,
     fun(_) ->
         {timeout, 60, fun periodic_flush_before_n/0}
     end}.

%%% ===================================================================
%%% is_synced must answer while chainstate is busy (suspended)
%%% ===================================================================

is_synced_busy_test_() ->
    {setup, fun setup_chain/0, fun teardown_chain/1,
     fun(_) -> fun is_synced_does_not_block_on_busy_chainstate/0 end}.

%%% ===================================================================
%%% Downloaded-ahead buffer: byte+count cap (was 256 decoded blocks)
%%% ===================================================================

download_budget_test_() ->
    fun download_buffer_byte_cap/0.

%%% ===================================================================
%%% Setup / teardown
%%% ===================================================================

setup_chain() ->
    TmpDir = filename:join(["/tmp",
                            "beamchain_catchup_oom_" ++
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
    {module, beamchain_validation} = code:ensure_loaded(beamchain_validation),
    ok = meck:new(beamchain_validation, [no_link, passthrough]),
    ok = meck:expect(beamchain_validation, connect_block,
                     fun(_Block, Height, _Prev, _Params) ->
                             add_block_utxos(Height),
                             ok
                     end),
    {ok, _} = beamchain_chainstate:start_link(),
    TmpDir.

teardown_chain(TmpDir) ->
    catch gen_server:stop(beamchain_chainstate),
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

add_block_utxos(Height) ->
    lists:foreach(
      fun(I) ->
          Txid = <<Height:32, I:32, 0:192>>,
          U = #utxo{value = 1000,
                    script_pubkey = <<16#51, I:8, Height:32>>,
                    is_coinbase = false,
                    height = Height},
          beamchain_chainstate:add_utxo(Txid, 0, U)
      end,
      lists:seq(1, ?UTXOS_PER_BLOCK)).

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

connect_up_to(Target) ->
    {ok, {Prev, Height}} = beamchain_chainstate:get_tip(),
    connect_from(Height + 1, Target, Prev).

connect_from(H, Target, _Prev) when H > Target ->
    ok;
connect_from(H, Target, Prev) ->
    Block = dummy_block(Prev, H),
    ?assertEqual(ok, beamchain_chainstate:connect_block(Block)),
    connect_from(H + 1, Target, Block#block.hash).

set_small_cache_budget() ->
    %% #state{}: 7=max_cache_bytes, 8=max_cache_entries (tag at 1).
    sys:replace_state(beamchain_chainstate,
                      fun(S) ->
                          S2 = setelement(7, S, ?CACHE_BUDGET_BYTES),
                          setelement(8, S2, ?CACHE_BUDGET_ENTRIES)
                      end).

durable_height() ->
    case beamchain_db:get_chain_tip() of
        {ok, #{height := H}} -> H;
        _ -> 0
    end.

%%% ===================================================================
%%% Tests
%%% ===================================================================

%% Connect N blocks against a small UTXO-cache budget. A flush must
%% land before N (durable tip advances), and the cache working set
%% must sit under budget+slack afterwards. Before the fix, IBD flush
%% waited for 5000 blocks / 8M entries and never evicted down to the
%% configured budget, so a crash lost the whole catch-up run.
connect_n_flushes_and_bounds_cache() ->
    set_small_cache_budget(),
    Mid = ?N_SMALL div 2,
    connect_up_to(Mid),
    DurableMid = durable_height(),
    ?assert(DurableMid >= 1),
    connect_up_to(?N_SMALL),
    {ok, {_Hash, Tip}} = beamchain_chainstate:get_tip(),
    ?assertEqual(?N_SMALL, Tip),
    Durable = durable_height(),
    ?assert(Durable >= 1),
    ?assert(Durable =< ?N_SMALL),
    CacheEntries = ets:info(beamchain_utxo_cache, size),
    %% ETS write_concurrency tables have ~190KB empty overhead, so
    %% cache_memory_usage/0 is not a usable RSS proxy at this budget.
    %% Entry count is what eviction actually controls; without the
    %% budget-aware evict this is N * UTXOS_PER_BLOCK (1024).
    SlackEntries = ?UTXOS_PER_BLOCK,
    ?assert(CacheEntries =< ?CACHE_BUDGET_ENTRIES + SlackEntries),
    ?assert(CacheEntries < ?N_SMALL * ?UTXOS_PER_BLOCK).

%% Default 4GB / 10M-entry budget: size-based flush does not fire in
%% 80 small blocks. Periodic IBD flush must, so an OOM 650 blocks into
%% catch-up does not rewind to the previous 5000-block checkpoint.
periodic_flush_before_n() ->
    connect_up_to(?N_PERIODIC),
    {ok, {_Hash, Tip}} = beamchain_chainstate:get_tip(),
    ?assertEqual(?N_PERIODIC, Tip),
    Durable = durable_height(),
    ?assert(Durable >= 1),
    ?assert(Durable < ?N_PERIODIC orelse Durable =:= ?N_PERIODIC).

%% Live addendum: beamchain_sync crash-looped on
%% {timeout,{gen_server,call,[beamchain_chainstate,is_synced]}} while
%% chainstate was connecting blocks. is_synced must be an ETS read.
is_synced_does_not_block_on_busy_chainstate() ->
    Pid = whereis(beamchain_chainstate),
    ?assert(is_pid(Pid)),
    ok = sys:suspend(Pid),
    try
        Parent = self(),
        Worker = spawn(fun() ->
                               T0 = erlang:monotonic_time(millisecond),
                               try
                                   R = beamchain_chainstate:is_synced(),
                                   T1 = erlang:monotonic_time(millisecond),
                                   Parent ! {is_synced, R, T1 - T0}
                               catch
                                   C:Reason ->
                                       Parent ! {is_synced_crash, C, Reason}
                               end
                       end),
        receive
            {is_synced, Result, Elapsed} ->
                ?assert(is_boolean(Result)),
                ?assert(Elapsed < ?BUSY_WAIT_MS);
            {is_synced_crash, _C, Reason} ->
                ?assertEqual(ok, Reason)
        after ?BUSY_WAIT_MS ->
            catch unlink(Worker),
            catch exit(Worker, kill),
            ?assert(false)
        end
    after
        catch sys:resume(Pid)
    end.

%% 40 × 2 MiB decoded blocks used to fit the 256-count cap and hold
%% ~80 MiB (plus term overhead, many GB on mainnet). Byte budget must
%% refuse the tail.
download_buffer_byte_cap() ->
    Cap = beamchain_block_sync:max_downloaded_bytes(),
    Ahead = beamchain_block_sync:max_downloaded_ahead(),
    Pad = <<0:(2 * 1024 * 1024)/unit:8>>,
    N = 40,
    {_Kept, Bytes, Count} =
        lists:foldl(
          fun(H, {State, _B, _C}) ->
                  Block = fat_block(H, Pad),
                  S2 = beamchain_block_sync:admit_downloaded(State, H, Block),
                  {S2,
                   beamchain_block_sync:test_get(downloaded_bytes, S2),
                   maps:size(beamchain_block_sync:test_get(downloaded, S2))}
          end,
          {beamchain_block_sync:test_state(#{next_to_validate => 0}), 0, 0},
          lists:seq(1, N)),
    ?assert(Count < N),
    ?assert(Count =< Ahead),
    ?assert(Bytes =< Cap).

fat_block(Height, Pad) ->
    Header = #block_header{
        version = 4,
        prev_hash = <<0:256>>,
        merkle_root = <<Height:256>>,
        timestamp = 1296688602 + Height,
        bits = 16#207fffff,
        nonce = Height
    },
    Tx = #transaction{
        version = 1,
        inputs = [],
        outputs = [#tx_out{value = 0, script_pubkey = Pad}],
        locktime = 0
    },
    #block{header = Header, transactions = [Tx], hash = <<Height:256>>}.
