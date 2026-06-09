-module(beamchain_mempool_prioritise_tests).

%% prioritisetransaction / getprioritisedtransactions — Core parity tests.
%%
%% Reference:
%%   bitcoin-core/src/txmempool.cpp:630-688  (PrioritiseTransaction,
%%                                             GetPrioritisedTransactions,
%%                                             ClearPrioritisation)
%%   bitcoin-core/src/rpc/mining.cpp:502-583 (prioritisetransaction,
%%                                             getprioritisedtransactions)
%%
%% Two axes, per the implementation brief:
%%   (a) ROUNDTRIP/SHAPE — additive stacking, net-zero erase, the
%%       {Txid, Delta, InMempool, ModifiedFee} snapshot shape, the
%%       not-in-mempool case, and the dummy-must-be-zero RPC reject.
%%   (b) MINING EFFECT (NOT display-only) — a low-base-fee tx with a big
%%       positive delta out-ranks a higher-base-fee tx in the block-template
%%       selection (the exact ancestor_fee_rate sort beamchain_miner uses),
%%       AND survives eviction (its singleton cluster's aggregate fee_rate,
%%       which find_worst_cluster reads, reflects the modified fee).
%%
%% These run purely at the ETS level (mirroring the other mempool test
%% modules) so no gen_server / rocksdb / chainstate is brought up — OOM-free.

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% Re-declare the internal records so the test can inspect ETS directly.
-record(mempool_entry, {
    txid, wtxid, tx, fee, size, vsize, weight, fee_rate,
    time_added, height_added,
    ancestor_count, ancestor_size, ancestor_fee,
    descendant_count, descendant_size, descendant_fee,
    spends_coinbase, rbf_signaling
}).

-record(cluster_data, {
    id, txids, total_fee, total_vsize, linearization, fee_rate
}).

%%% -------------------------------------------------------------------
%%% ETS lifecycle
%%% -------------------------------------------------------------------

-define(TABLES, [mempool_txs, mempool_by_fee, mempool_outpoints,
                 mempool_orphans, mempool_orphan_by_txid,
                 mempool_clusters, mempool_ephemeral, mempool_deltas]).

setup() ->
    drop_tables(),
    ets:new(mempool_txs,            [set, public, named_table, {read_concurrency, true}]),
    ets:new(mempool_by_fee,         [ordered_set, public, named_table]),
    ets:new(mempool_outpoints,      [set, public, named_table]),
    ets:new(mempool_orphans,        [set, public, named_table]),
    ets:new(mempool_orphan_by_txid, [set, public, named_table]),
    ets:new(mempool_clusters,       [set, public, named_table, {read_concurrency, true}]),
    ets:new(mempool_ephemeral,      [set, public, named_table]),
    ets:new(mempool_deltas,         [set, public, named_table, {read_concurrency, true}]),
    ok.

cleanup(_) ->
    drop_tables().

drop_tables() ->
    lists:foreach(fun(T) ->
        case ets:info(T) of
            undefined -> ok;
            _ -> ets:delete(T)
        end
    end, ?TABLES).

%%% -------------------------------------------------------------------
%%% Construction helpers
%%% -------------------------------------------------------------------

%% Distinct dummy txid (32 bytes) per integer seed.
txid(N) -> <<N:256>>.

p2wpkh_script() -> <<16#00, 16#14, 0:160>>.

make_tx(PrevOuts, OutVals) ->
    Inputs = [#tx_in{prev_out = #outpoint{hash = H, index = I},
                     script_sig = <<>>, sequence = 16#ffffffff, witness = []}
              || {H, I} <- PrevOuts],
    Outs = [#tx_out{value = V, script_pubkey = p2wpkh_script()} || V <- OutVals],
    #transaction{version = 2, inputs = Inputs, outputs = Outs, locktime = 0}.

%% A standalone singleton tx with the given fee + vsize. Spends a unique
%% synthetic prevout so it forms its own cluster (no in-mempool ancestors).
make_entry(N, Fee, VSize) ->
    Tx = make_tx([{txid(1000 + N), 0}], [100000]),
    #mempool_entry{
        txid            = txid(N),
        wtxid           = txid(N),
        tx              = Tx,
        fee             = Fee,
        size            = VSize,
        vsize           = VSize,
        weight          = VSize * 4,
        fee_rate        = Fee / VSize,
        time_added      = erlang:system_time(second),
        height_added    = 800000,
        ancestor_count  = 1,
        ancestor_size   = VSize,
        ancestor_fee    = Fee,
        descendant_count = 1,
        descendant_size = VSize,
        descendant_fee  = Fee,
        spends_coinbase = false,
        rbf_signaling   = false
    }.

%% Insert an entry + register it as its own singleton cluster so the eviction
%% path (find_worst_cluster over mempool_clusters) has data to read. Returns
%% the txid -> txid union_find seed entry.
insert_singleton(Entry) ->
    Txid = Entry#mempool_entry.txid,
    ets:insert(mempool_txs, {Txid, Entry}),
    ets:insert(mempool_by_fee, {{Entry#mempool_entry.fee_rate, Txid}}),
    Tx = Entry#mempool_entry.tx,
    lists:foreach(fun(#tx_in{prev_out = #outpoint{hash = H, index = I}}) ->
        ets:insert(mempool_outpoints, {{H, I}, Txid})
    end, Tx#transaction.inputs),
    %% Singleton cluster keyed by the txid (matches create_singleton_cluster).
    ets:insert(mempool_clusters, {Txid, #cluster_data{
        id = Txid,
        txids = [Txid],
        total_fee = Entry#mempool_entry.fee,
        total_vsize = Entry#mempool_entry.vsize,
        linearization = [Txid],
        fee_rate = Entry#mempool_entry.fee / Entry#mempool_entry.vsize
    }}),
    {Txid, Txid}.

%% Drive the prioritise mutation with a union_find map (no #state{} needed).
prioritise(Txid, Delta, UF) ->
    beamchain_mempool:do_prioritise_transaction(Txid, Delta, UF).

%% Cluster fee_rate as the eviction path (find_worst_cluster) sees it.
cluster_fee_rate(Txid) ->
    [{Txid, CD}] = ets:lookup(mempool_clusters, Txid),
    CD#cluster_data.fee_rate.

%% Replicate the exact ranking beamchain_miner uses: collect the (delta-folded)
%% entries from get_sorted_by_fee, then sort by ancestor_fee_rate descending.
miner_ranked_order() ->
    Entries = beamchain_mempool:get_sorted_by_fee(),
    Sorted = lists:sort(fun(A, B) ->
        ancestor_fee_rate(A) >= ancestor_fee_rate(B)
    end, Entries),
    [E#mempool_entry.txid || E <- Sorted].

%% Copy of beamchain_miner:ancestor_fee_rate/1 (it is not exported).
ancestor_fee_rate(Entry) ->
    AncFee = Entry#mempool_entry.ancestor_fee,
    AncWeight = Entry#mempool_entry.ancestor_size * 4,  %% WITNESS_SCALE_FACTOR
    case AncWeight of
        0 -> Entry#mempool_entry.fee / max(1, Entry#mempool_entry.weight);
        _ -> AncFee / AncWeight
    end.

%%% ===================================================================
%%% (a) Roundtrip / shape
%%% ===================================================================

%% Stacking is additive: two positive prioritise calls sum.
stacking_is_additive_test_() ->
    {setup, fun setup/0, fun cleanup/1, fun(_) ->
        Tx = txid(1),
        {ok, UF0} = {ok, #{}},
        {D1, _} = prioritise(Tx, 5000, UF0),
        {D2, _} = prioritise(Tx, 3000, UF0),
        [?_assertEqual(5000, D1),
         ?_assertEqual(8000, D2),
         ?_assertEqual(8000, beamchain_mempool:get_fee_delta(Tx))]
    end}.

%% A delta that returns to exactly zero ERASES the mapDeltas entry.
net_zero_erases_test_() ->
    {setup, fun setup/0, fun cleanup/1, fun(_) ->
        Tx = txid(2),
        {_, _} = prioritise(Tx, 7000, #{}),
        {DBack, _} = prioritise(Tx, -7000, #{}),
        Got = beamchain_mempool:get_prioritised_transactions(),
        [?_assertEqual(0, DBack),
         ?_assertEqual(0, beamchain_mempool:get_fee_delta(Tx)),
         %% No lingering entry in the snapshot.
         ?_assertEqual([], [T || {T, _, _, _} <- Got, T =:= Tx])]
    end}.

%% Negative-then-positive that crosses zero behaves additively (no early erase).
mixed_sign_stacking_test_() ->
    {setup, fun setup/0, fun cleanup/1, fun(_) ->
        Tx = txid(3),
        {_, _} = prioritise(Tx, -2000, #{}),
        {D, _}  = prioritise(Tx, 5000, #{}),
        [?_assertEqual(3000, D),
         ?_assertEqual(3000, beamchain_mempool:get_fee_delta(Tx))]
    end}.

%% Out-of-mempool delta: present in the snapshot, in_mempool=false, NO
%% modified_fee (undefined). Mirrors Core delta_info with in_mempool=false.
not_in_mempool_shape_test_() ->
    {setup, fun setup/0, fun cleanup/1, fun(_) ->
        Tx = txid(4),
        {_, _} = prioritise(Tx, 12345, #{}),
        [{GotTxid, Delta, InPool, ModFee}] =
            beamchain_mempool:get_prioritised_transactions(),
        [?_assertEqual(Tx, GotTxid),
         ?_assertEqual(12345, Delta),
         ?_assertEqual(false, InPool),
         ?_assertEqual(undefined, ModFee)]
    end}.

%% In-mempool delta: in_mempool=true and modified_fee = base + delta.
in_mempool_modified_fee_test_() ->
    {setup, fun setup/0, fun cleanup/1, fun(_) ->
        Tx = txid(5),
        Entry = make_entry(5, 1000, 250),  %% base fee 1000
        {_TxidKey, RootKey} = insert_singleton(Entry),
        UF = #{Tx => RootKey},
        {_, _UF2} = prioritise(Tx, 4000, UF),
        [{Tx, Delta, InPool, ModFee}] =
            beamchain_mempool:get_prioritised_transactions(),
        [?_assertEqual(4000, Delta),
         ?_assertEqual(true, InPool),
         ?_assertEqual(5000, ModFee),  %% 1000 base + 4000 delta
         ?_assertEqual({ok, 5000}, beamchain_mempool:get_modified_fee(Tx))]
    end}.

%% A delta driving base+delta BELOW zero: getprioritisedtransactions reports the
%% SIGNED modified fee (Core GetModifiedFee is a signed CAmount, rpc/mining.cpp:574),
%% NOT floored at 0. Selection/eviction still clamp at 0 (rustoshi-parity), but the
%% RPC display must show the negative value.
in_mempool_negative_modified_fee_test_() ->
    {setup, fun setup/0, fun cleanup/1, fun(_) ->
        Tx = txid(15),
        Entry = make_entry(15, 1000, 250),  %% base fee 1000
        {_TxidKey, RootKey} = insert_singleton(Entry),
        UF = #{Tx => RootKey},
        {_, _UF2} = prioritise(Tx, -3000, UF),  %% net modified fee = -2000
        [{Tx, Delta, InPool, ModFee}] =
            beamchain_mempool:get_prioritised_transactions(),
        [?_assertEqual(-3000, Delta),
         ?_assertEqual(true, InPool),
         ?_assertEqual(-2000, ModFee)]  %% SIGNED: 1000 + (-3000), not max(0,..)
    end}.

%% Empty mapDeltas -> empty snapshot list (the RPC turns this into {}).
empty_snapshot_test_() ->
    {setup, fun setup/0, fun cleanup/1, fun(_) ->
        ?_assertEqual([], beamchain_mempool:get_prioritised_transactions())
    end}.

%% RPC dummy-arg reject (no gen_server needed — the reject path returns
%% BEFORE touching the mempool). A non-zero legacy dummy is a Core-faithful
%% RPC_INVALID_PARAMETER (-8) error; a malformed arg list is -32602.
rpc_dummy_reject_test_() ->
    {setup, fun setup/0, fun cleanup/1, fun(_) ->
        TxHex = binary:encode_hex(txid(6), lowercase),
        %% Non-zero dummy -> RPC_INVALID_PARAMETER (-8).
        NonZeroFloat = beamchain_rpc:handle_method(
                    <<"prioritisetransaction">>, [TxHex, 1.0, 10000], undefined),
        NonZeroInt = beamchain_rpc:handle_method(
                    <<"prioritisetransaction">>, [TxHex, 5, 10000], undefined),
        %% No fee_delta at all -> usage error (-32602).
        BadArgs = beamchain_rpc:handle_method(
                    <<"prioritisetransaction">>, [TxHex], undefined),
        [?_assertMatch({error, -8, _}, NonZeroFloat),
         ?_assertMatch({error, -8, _}, NonZeroInt),
         ?_assertMatch({error, -32602, _}, BadArgs)]
    end}.

%% RPC accept path end-to-end against a LIVE mempool gen_server (no rocksdb /
%% chainstate). dummy = 0 / null / omitted all accepted and actually record
%% the delta, which getprioritisedtransactions then reflects.
rpc_accept_path_test_() ->
    {setup, fun start_mempool/0, fun stop_mempool/1, fun(_) ->
        %% Display-order hex; the RPC handler reverses to internal byte order,
        %% so we look the deltas back up under the reversed (internal) key.
        HexA = <<"00000000000000000000000000000000000000000000000000000000000000aa">>,
        HexB = <<"00000000000000000000000000000000000000000000000000000000000000bb">>,
        HexC = <<"00000000000000000000000000000000000000000000000000000000000000cc">>,
        IntA = internal_of(HexA),
        IntB = internal_of(HexB),
        IntC = internal_of(HexC),
        ZeroOk = beamchain_rpc:handle_method(
                   <<"prioritisetransaction">>, [HexA, 0, 10000], undefined),
        NullOk = beamchain_rpc:handle_method(
                   <<"prioritisetransaction">>, [HexB, null, 20000], undefined),
        TwoArg = beamchain_rpc:handle_method(
                   <<"prioritisetransaction">>, [HexC, 30000], undefined),
        %% The deltas are now live in the gen_server's mapDeltas.
        DA = beamchain_mempool:get_fee_delta(IntA),
        DB = beamchain_mempool:get_fee_delta(IntB),
        DC = beamchain_mempool:get_fee_delta(IntC),
        %% getprioritisedtransactions RPC returns a JSON object body.
        GPT = beamchain_rpc:handle_method(
                <<"getprioritisedtransactions">>, [], undefined),
        [?_assertEqual({ok, true}, ZeroOk),
         ?_assertEqual({ok, true}, NullOk),
         ?_assertEqual({ok, true}, TwoArg),
         ?_assertEqual(10000, DA),
         ?_assertEqual(20000, DB),
         ?_assertEqual(30000, DC),
         ?_assertMatch({ok_raw_json, _}, GPT),
         %% All three out-of-mempool deltas surface with in_mempool=false.
         ?_assert(gpt_contains(GPT, HexA, 10000)),
         ?_assert(gpt_contains(GPT, HexB, 20000))]
    end}.

start_mempool() ->
    %% The gen_server creates its own named ETS tables; ensure none linger.
    drop_tables(),
    {ok, Pid} = beamchain_mempool:start_link(),
    Pid.

stop_mempool(Pid) ->
    %% trap_exit is set in the mempool; stop it cleanly then drop tables.
    case is_process_alive(Pid) of
        true  -> gen_server:stop(Pid, normal, 5000);
        false -> ok
    end,
    drop_tables().

%% Crude substring check that the raw-JSON getprioritisedtransactions body
%% contains the txid hex and the fee_delta value (avoids a JSON parser dep).
%% Convert display-order hex to the internal byte order the RPC stores under.
internal_of(Hex) ->
    beamchain_serialize:reverse_bytes(beamchain_serialize:hex_decode(Hex)).

gpt_contains({ok_raw_json, Body}, HexTxid, FeeDelta) ->
    BodyBin = iolist_to_binary(Body),
    DeltaBin = integer_to_binary(FeeDelta),
    (binary:match(BodyBin, HexTxid) =/= nomatch)
        andalso (binary:match(BodyBin, DeltaBin) =/= nomatch).

%%% ===================================================================
%%% (b) Mining effect — the delta DRIVES selection + eviction
%%% ===================================================================

%% A low-base-fee tx with a big positive delta out-ranks a higher-base-fee
%% tx in the block-template selection (the exact sort beamchain_miner uses),
%% AND its singleton cluster's aggregate fee_rate (read by find_worst_cluster
%% for eviction) reflects the modified fee — so it survives trimming.
mining_and_eviction_effect_test_() ->
    {setup, fun setup/0, fun cleanup/1, fun(_) ->
        %% A: low base fee (1000 sat / 250 vB) — would lose to B on base fee.
        %% B: higher base fee (4000 sat / 250 vB).
        A = txid(10),
        B = txid(11),
        EA = make_entry(10, 1000, 250),
        EB = make_entry(11, 4000, 250),
        {_, _} = insert_singleton(EA),
        {_, _} = insert_singleton(EB),
        UF = #{A => A, B => B},

        %% BEFORE prioritisation: B out-ranks A (higher base fee).
        OrderBefore = miner_ranked_order(),
        RankBeforeOk = (hd(OrderBefore) =:= B),
        %% Worst cluster (eviction target) is the lower-fee A.
        EvictBeforeOk = (cluster_fee_rate(A) < cluster_fee_rate(B)),

        %% Prioritise A by +100000 sat -> modified fee 101000 >> B's 4000.
        {_, _UF2} = prioritise(A, 100000, UF),

        %% AFTER: A now out-ranks B in the miner's block-template selection.
        OrderAfter = miner_ranked_order(),
        RankAfterOk = (hd(OrderAfter) =:= A),

        %% AFTER: A's cluster fee_rate now EXCEEDS B's, so find_worst_cluster
        %% targets B (the un-prioritised tx) for eviction — A survives.
        FeeA = cluster_fee_rate(A),
        FeeB = cluster_fee_rate(B),
        EvictAfterOk = (FeeA > FeeB),

        %% Cross-check the explicit modified-fee surface.
        {ok, ModA} = beamchain_mempool:get_modified_fee(A),

        [?_assert(RankBeforeOk),
         ?_assert(EvictBeforeOk),
         ?_assert(RankAfterOk),
         ?_assert(EvictAfterOk),
         ?_assertEqual(101000, ModA),
         %% A's folded singleton cluster fee_rate == modified_fee / vsize.
         ?_assertEqual(101000 / 250, FeeA)]
    end}.

%% A negative delta DEMOTES a tx: a high-base-fee tx pushed below a low-base
%% one loses both its mining rank and its eviction protection.
negative_delta_demotes_test_() ->
    {setup, fun setup/0, fun cleanup/1, fun(_) ->
        A = txid(20),  %% high base fee 9000
        B = txid(21),  %% low base fee 1000
        EA = make_entry(20, 9000, 250),
        EB = make_entry(21, 1000, 250),
        {_, _} = insert_singleton(EA),
        {_, _} = insert_singleton(EB),
        UF = #{A => A, B => B},

        %% A out-ranks B before.
        BeforeOk = (hd(miner_ranked_order()) =:= A),

        %% De-prioritise A by -8500 -> modified fee 500 < B's 1000.
        {_, _} = prioritise(A, -8500, UF),

        AfterOk = (hd(miner_ranked_order()) =:= B),
        %% A is now the worst cluster (eviction target).
        EvictOk = (cluster_fee_rate(A) < cluster_fee_rate(B)),
        {ok, ModA} = beamchain_mempool:get_modified_fee(A),

        [?_assert(BeforeOk),
         ?_assert(AfterOk),
         ?_assert(EvictOk),
         ?_assertEqual(500, ModA)]
    end}.

%%% ===================================================================
%%% Saturating i64 arithmetic (Core util::SaturatingAdd)
%%% ===================================================================

saturating_add_test_() ->
    {setup, fun setup/0, fun cleanup/1, fun(_) ->
        Tx = txid(30),
        Max = 9223372036854775807,
        {D1, _} = prioritise(Tx, Max, #{}),
        {D2, _} = prioritise(Tx, Max, #{}),   %% would overflow -> clamp at MAX
        [?_assertEqual(Max, D1),
         ?_assertEqual(Max, D2)]
    end}.
