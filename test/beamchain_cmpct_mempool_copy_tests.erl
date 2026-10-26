%%% Compact-block reconstruction must not copy the whole mempool.
%%%
%%% Mainnet beamchain was oom-killed at its 16G MemoryMax on 2026-10-21 while
%%% idle at tip. Every block reaches us as an unsolicited cmpctblock from
%%% 8-12 high-bandwidth peers, and each one ran match_mempool_txns/4, which
%%% started with beamchain_mempool:get_all_txids() = ets:tab2list of the
%%% full mempool table (every #mempool_entry{} with its decoded tx), then
%%% copied each tx a second time through get_tx/1 and re-serialized it for
%%% its wtxid. That is several full mempool copies on the block_sync heap per
%%% block; the cgroup's memory.peak of the restarted node already shows
%%% 12.5G against a 4G resident floor.
%%%
%%% Core's PartiallyDownloadedBlock::InitData walks the mempool's wtxid
%%% vector (txmempool vTxHashes) and touches a tx only when its short id
%%% matches. These tests pin that: the matching pass runs in a process with
%%% a heap cap far below the mempool's size, and it must finish with the
%%% same reconstruction result as before.
-module(beamchain_cmpct_mempool_copy_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% Same shape as the record in beamchain_mempool.erl (as beamchain_rpc.erl
%% and beamchain_miner.erl also copy it); only txid, wtxid and tx are read.
-record(mempool_entry, {
    txid, wtxid, tx, fee, size, vsize, weight, fee_rate, time_added,
    height_added, ancestor_count, ancestor_size, ancestor_fee,
    descendant_count, descendant_size, descendant_fee, spends_coinbase,
    rbf_signaling, adj_weight
}).

-define(TABLES, [mempool_txs, mempool_by_fee, mempool_outpoints,
                 mempool_orphans, mempool_clusters, mempool_ephemeral]).

%% Heap cap for the matching process, in words (8 MiB). The mempool built
%% by the bound test is sized to be several times this.
-define(HEAP_CAP_WORDS, 1000000).

%%% ===================================================================
%%% Fixtures
%%% ===================================================================

setup() ->
    cleanup(ok),
    ets:new(mempool_txs, [set, public, named_table, {read_concurrency, true}]),
    ets:new(mempool_by_fee, [ordered_set, public, named_table]),
    ets:new(mempool_outpoints, [set, public, named_table]),
    ets:new(mempool_orphans, [set, public, named_table]),
    ets:new(mempool_clusters, [set, public, named_table,
                               {read_concurrency, true}]),
    ets:new(mempool_ephemeral, [set, public, named_table]),
    ok.

cleanup(_) ->
    lists:foreach(fun(T) ->
        case ets:info(T) of
            undefined -> ok;
            _ -> ets:delete(T)
        end
    end, ?TABLES).

cmpct_mempool_copy_test_() ->
    {foreach, fun setup/0, fun cleanup/1,
     [{"matching a cmpctblock against a large mempool stays under a "
       "heap cap far below the mempool's size",
       {timeout, 120, fun match_is_bounded_by_matches_not_mempool/0}},
      {"a block whose txs are all in the mempool reconstructs in order",
       fun full_reconstruct_from_mempool/0},
      {"a segwit tx is matched by its wtxid, not its txid",
       fun segwit_tx_matched_by_wtxid/0},
      {"a block with a tx missing from the mempool comes back partial "
       "with exactly that slot missing",
       fun partial_reports_only_the_missing_slot/0},
      {"an entry removed between the id scan and the tx fetch is "
       "treated as missing, not a crash",
       fun entry_removed_mid_scan_is_missing/0}]}.

%%% ===================================================================
%%% Tests
%%% ===================================================================

match_is_bounded_by_matches_not_mempool() ->
    Probe = make_big_tx(0),
    EntryWords = erts_debug:flat_size(entry_for(Probe)),
    %% Enough entries that one copy of the mempool is 6x the heap cap.
    N = (6 * ?HEAP_CAP_WORDS) div EntryWords + 1,
    Txs = [make_big_tx(I) || I <- lists:seq(1, N)],
    lists:foreach(fun insert/1, Txs),
    ?assert(N * EntryWords > 5 * ?HEAP_CAP_WORDS),

    %% Block = coinbase (prefilled) + two mempool txs + one unknown tx.
    InPool = [lists:nth(7, Txs), lists:nth(N - 3, Txs)],
    Unknown = make_small_tx(999999),
    Block = [make_coinbase() | InPool ++ [Unknown]],
    {ok, CS} = init_for(Block, 42),

    Parent = self(),
    {Pid, Ref} = spawn_opt(
        fun() ->
            Parent ! {result, self(),
                      beamchain_compact_block:try_reconstruct(CS, [])}
        end,
        [monitor,
         {max_heap_size, #{size => ?HEAP_CAP_WORDS, kill => true,
                           error_logger => false}}]),
    receive
        {result, Pid, Result} ->
            receive {'DOWN', Ref, process, Pid, _} -> ok end,
            {partial, PS} = Result,
            ?assertEqual([3],
                         beamchain_compact_block:get_missing_indices(PS));
        {'DOWN', Ref, process, Pid, Reason} ->
            erlang:error({matcher_died, Reason,
                          {mempool_entries, N},
                          {mempool_words, N * EntryWords},
                          {heap_cap_words, ?HEAP_CAP_WORDS}})
    after 100000 ->
        erlang:error(matcher_timeout)
    end.

full_reconstruct_from_mempool() ->
    Txs = [make_small_tx(I) || I <- lists:seq(1, 20)],
    lists:foreach(fun insert/1, Txs),
    InBlock = [lists:nth(3, Txs), lists:nth(11, Txs), lists:nth(17, Txs)],
    Cb = make_coinbase(),
    {ok, CS} = init_for([Cb | InBlock], 7),
    {ok, #block{transactions = Got}} =
        beamchain_compact_block:try_reconstruct(CS, []),
    ?assertEqual([Cb | InBlock], Got).

segwit_tx_matched_by_wtxid() ->
    W = make_segwit_tx(5),
    ?assertNotEqual(beamchain_serialize:tx_hash(W),
                    beamchain_serialize:wtx_hash(W)),
    insert(W),
    lists:foreach(fun insert/1, [make_small_tx(I) || I <- lists:seq(1, 5)]),
    Cb = make_coinbase(),
    {ok, CS} = init_for([Cb, W], 9),
    {ok, #block{transactions = Got}} =
        beamchain_compact_block:try_reconstruct(CS, []),
    ?assertEqual([Cb, W], Got).

partial_reports_only_the_missing_slot() ->
    Txs = [make_small_tx(I) || I <- lists:seq(1, 10)],
    lists:foreach(fun insert/1, Txs),
    Missing = make_small_tx(5000),
    Block = [make_coinbase(), lists:nth(2, Txs), Missing, lists:nth(9, Txs)],
    {ok, CS} = init_for(Block, 11),
    {partial, PS} = beamchain_compact_block:try_reconstruct(CS, []),
    ?assertEqual([2], beamchain_compact_block:get_missing_indices(PS)),
    %% Supplying the missing tx completes the block with the right merkle root.
    {ok, #block{transactions = Got}} =
        beamchain_compact_block:fill_block(PS, [Missing]),
    ?assertEqual(Block, Got).

entry_removed_mid_scan_is_missing() ->
    %% The scan sees the entry's wtxid, but the tx is evicted before the
    %% matcher fetches it (the mempool gen_server writes concurrently).
    T = make_small_tx(77),
    insert(T),
    {ok, CS} = init_for([make_coinbase(), T], 13),
    ok = meck:new(beamchain_mempool, [no_link, passthrough]),
    try
        ok = meck:expect(beamchain_mempool, get_tx, fun(_) -> not_found end),
        {partial, PS} = beamchain_compact_block:try_reconstruct(CS, []),
        ?assertEqual([1], beamchain_compact_block:get_missing_indices(PS))
    after
        meck:unload(beamchain_mempool)
    end.

%%% ===================================================================
%%% Helpers
%%% ===================================================================

init_for([Coinbase | Rest] = Txs, Nonce) ->
    Root = beamchain_serialize:compute_merkle_root(
             [beamchain_serialize:tx_hash(T) || T <- Txs]),
    Header = #block_header{version = 1, prev_hash = <<1:256>>,
                           merkle_root = Root, timestamp = 1296688602,
                           bits = 16#207fffff, nonce = 0},
    {K0, K1} = beamchain_compact_block:derive_siphash_key(Header, Nonce),
    ShortIds = [beamchain_compact_block:compute_short_id(
                  K0, K1, beamchain_serialize:wtx_hash(T)) || T <- Rest],
    beamchain_compact_block:init_compact_block(
      #{header => Header, nonce => Nonce, short_ids => ShortIds,
        prefilled_txns => [#{index => 0, tx => Coinbase}]}).

insert(Tx) ->
    ets:insert(mempool_txs, {beamchain_serialize:tx_hash(Tx), entry_for(Tx)}).

entry_for(Tx) ->
    #mempool_entry{txid = beamchain_serialize:tx_hash(Tx),
                   wtxid = beamchain_serialize:wtx_hash(Tx),
                   tx = Tx}.

make_coinbase() ->
    #transaction{
       version = 1,
       inputs = [#tx_in{prev_out = #outpoint{hash = <<0:256>>,
                                             index = 16#ffffffff},
                        script_sig = <<3, 1, 2, 3>>,
                        sequence = 16#ffffffff, witness = undefined}],
       outputs = [#tx_out{value = 5000000000, script_pubkey = <<16#51>>}],
       locktime = 0}.

make_small_tx(I) ->
    #transaction{
       version = 2,
       inputs = [#tx_in{prev_out = #outpoint{hash = <<I:256>>, index = 0},
                        script_sig = <<16#51>>, sequence = 16#fffffffd,
                        witness = undefined}],
       outputs = [#tx_out{value = 1000 + I, script_pubkey = <<16#51>>}],
       locktime = 0}.

make_segwit_tx(I) ->
    T = make_small_tx(I),
    [In] = T#transaction.inputs,
    T#transaction{inputs = [In#tx_in{script_sig = <<>>,
                                     witness = [<<I:64>>, <<1, 2, 3>>]}]}.

%% A tx with 100 inputs and 100 outputs whose fields are all small heap
%% binaries, so its decoded form costs thousands of heap words when copied
%% out of ETS.
make_big_tx(I) ->
    Ins = [#tx_in{prev_out = #outpoint{hash = <<I:128, J:128>>, index = J},
                  script_sig = <<I:32, J:32, 0:256>>,
                  sequence = 16#fffffffd, witness = undefined}
           || J <- lists:seq(1, 100)],
    Outs = [#tx_out{value = J, script_pubkey = <<16#00, 16#14, I:32, J:128>>}
            || J <- lists:seq(1, 100)],
    #transaction{version = 2, inputs = Ins, outputs = Outs, locktime = I}.
