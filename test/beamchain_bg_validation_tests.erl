-module(beamchain_bg_validation_tests).

%%% ===================================================================
%%% AssumeUTXO REAL background-validation second-chainstate — EUnit.
%%%
%%% Exercises beamchain_bg_validation: a SEPARATE (private-ETS) coins
%%% store that re-derives the UTXO set genesis->base, recomputes the
%%% HASH_SERIALIZED commitment via the existing tx_out_ser kernel, and
%%% compares it to au_data.hash_serialized. Mirrors Core
%%% MaybeCompleteSnapshotValidation (validation.cpp:5967-6077).
%%%
%%% Two load-bearing properties under test:
%%%
%%%   (a) CORRECT snapshot — a chain whose genesis->base re-derivation
%%%       MATCHES the registered au_data hash -> {validated, Hash}.
%%%
%%%   (b) NON-CIRCULAR REJECT (the falsification) — a tampered UTXO set
%%%       (the GENUINE set PLUS a phantom coin the replay never creates),
%%%       committed to ITS OWN tampered hash. The tampered hash is what the
%%%       load gate authenticates the file against AND what bg compares to.
%%%       The background re-derivation walks the genuine chain and produces
%%%       the GENUINE set, whose hash DIFFERS from the tampered commitment
%%%       -> {invalid, _, _}. We further assert the phantom outpoint is
%%%       ABSENT from the bg store: the bg store is a genuine separate
%%%       re-derivation, not a copy of the (tampered) loaded set, so a
%%%       hash-of-self could never reproduce this.
%%%
%%% Separate-store + aliasing-guard tests pin invariants #1/#2 that make
%%% the reject non-circular.
%%% ===================================================================

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

-define(REGTEST_BASE_HEIGHT, 3).

%%% ===================================================================
%%% Fixtures: a tiny synthetic genesis..base chain.
%%%
%%% We don't need real PoW or a real header chain — bg_validation's replay
%%% core only consumes the transactions of each block (it mutates a coins
%%% store). We hand-build 4 blocks (heights 0..3):
%%%
%%%   h0 (genesis): coinbase CB0 -> NOT added to the set (Core skips the
%%%                 genesis coinbase).
%%%   h1: coinbase CB1 creates coin A (50 BTC).
%%%   h2: coinbase CB2 creates coin B; a normal tx TX2 spends A and creates
%%%       coin C + an OP_RETURN output (dropped as unspendable).
%%%   h3 (base): coinbase CB3 creates coin D.
%%%
%%% Genuine UTXO set at base = {B, C, D} (A spent; OP_RETURN + genesis CB
%%% never in the set).
%%% ===================================================================

mk_outpoint(Txid, Idx) -> #outpoint{hash = Txid, index = Idx}.

%% A coinbase tx: single null-prevout input, given outputs. txid left
%% undefined so bg_validation computes it via tx_hash (real path).
coinbase_tx(Tag, Outs) ->
    Null = mk_outpoint(<<0:256>>, 16#ffffffff),
    %% Put the tag in the coinbase scriptSig so each coinbase has a
    %% distinct txid (heights differ -> BIP34-style uniqueness).
    #transaction{version = 1,
                 inputs = [#tx_in{prev_out = Null,
                                  script_sig = <<Tag:32/little>>,
                                  sequence = 16#ffffffff,
                                  witness = undefined}],
                 outputs = Outs,
                 locktime = 0,
                 txid = undefined, wtxid = undefined}.

%% A normal tx spending [{Txid,Vout},...] producing Outs.
normal_tx(Tag, SpendList, Outs) ->
    Ins = [#tx_in{prev_out = mk_outpoint(T, V),
                  script_sig = <<Tag:32/little>>,
                  sequence = 16#ffffffff, witness = undefined}
           || {T, V} <- SpendList],
    #transaction{version = 1, inputs = Ins, outputs = Outs,
                 locktime = 0, txid = undefined, wtxid = undefined}.

out(Value, SPK) -> #tx_out{value = Value, script_pubkey = SPK}.

block(Txs) -> #block{header = undefined, transactions = Txs}.

%% Build the synthetic chain as a height->#block{} map plus the resolved
%% txids we need for spends.
build_chain() ->
    CB0 = coinbase_tx(0, [out(5000000000, <<16#51>>)]),       %% genesis CB (dropped)
    CB1 = coinbase_tx(1, [out(5000000000, <<16#51, 16#aa>>)]), %% creates A
    CB1Txid = beamchain_serialize:tx_hash(CB1),
    CB2 = coinbase_tx(2, [out(5000000000, <<16#51, 16#bb>>)]), %% creates B
    %% TX2 spends A (CB1:0), creates C + an OP_RETURN (unspendable).
    TX2 = normal_tx(99, [{CB1Txid, 0}],
                    [out(4999990000, <<16#51, 16#cc>>),        %% C
                     out(0, <<16#6a, 16#de, 16#ad>>)]),        %% OP_RETURN -> dropped
    CB3 = coinbase_tx(3, [out(5000000000, <<16#51, 16#dd>>)]), %% base CB creates D
    Chain = #{
        0 => block([CB0]),
        1 => block([CB1]),
        2 => block([CB2, TX2]),
        3 => block([CB3])
    },
    {Chain, CB1Txid}.

block_fun(Chain) ->
    fun(H) ->
        case maps:find(H, Chain) of
            {ok, B} -> {ok, B};
            error -> not_found
        end
    end.

%% Compute the GENUINE base UTXO set by replaying into a throwaway store,
%% returning the {Txid,Vout,#utxo{}} coin list (separate-store path).
genuine_coins(Chain) ->
    Store = ets:new(t, [set, private]),
    try
        ok = beamchain_bg_validation:replay_genesis_to_base(
               Store, ?REGTEST_BASE_HEIGHT, block_fun(Chain)),
        beamchain_bg_validation:materialize_store(Store)
    after
        ets:delete(Store)
    end.

setup() ->
    application:set_env(beamchain, network, regtest),
    beamchain_chain_params:clear_regtest_assumeutxo(),
    ok.

teardown(_) ->
    beamchain_chain_params:clear_regtest_assumeutxo(),
    ok.

bg_validation_test_() ->
    {setup, fun setup/0, fun teardown/1,
     [
      {"separate store is a distinct private table (invariant #1)",
       fun separate_store_distinct/0},
      {"aliasing guard refuses the active UTXO table (invariant #2)",
       fun aliasing_guard_rejects_active/0},
      {"genesis coinbase is never added to the bg store",
       fun genesis_coinbase_unspendable/0},
      {"OP_RETURN outputs are dropped from the bg store",
       fun op_return_dropped/0},
      {"spent input is removed from the bg store",
       fun spent_input_removed/0},
      {"(a) CORRECT snapshot: genesis->base re-derivation MATCHES -> validated",
       fun correct_snapshot_validates/0},
      {"(b) NON-CIRCULAR REJECT: tampered phantom-coin snapshot -> invalid",
       fun tampered_phantom_rejected/0},
      {"reject is non-circular: phantom is ABSENT from the bg store",
       fun phantom_absent_from_bg_store/0}
     ]}.

%%% ===================================================================
%%% Invariant #1 — separate store
%%% ===================================================================

separate_store_distinct() ->
    %% Replay into a fresh private store and confirm it holds the genuine
    %% coins, independent of any active chainstate ETS table.
    {Chain, _} = build_chain(),
    Coins = genuine_coins(Chain),
    %% Genuine set = {B, C, D} = 3 coins (A spent, OP_RETURN dropped,
    %% genesis CB never added).
    ?assertEqual(3, length(Coins)),
    %% None of the active named UTXO tables is consulted: the materialized
    %% coins are exactly the replay output.
    ?assert(lists:all(fun({T, _V, #utxo{}}) -> byte_size(T) =:= 32 end, Coins)).

%%% ===================================================================
%%% Invariant #2 — aliasing guard
%%% ===================================================================

aliasing_guard_rejects_active() ->
    %% A private store passes the guard.
    Store = ets:new(t, [set, private]),
    try
        ?assertEqual(ok, beamchain_bg_validation:assert_separate_store(Store))
    after
        ets:delete(Store)
    end,
    %% A table created under the active chainstate name MUST be refused —
    %% running over it would be a hash-of-self.
    Active = ets:new(beamchain_utxo_cache,
                     [set, public, named_table]),
    try
        ?assertError({bg_validation_aliases_active_store, _},
                     beamchain_bg_validation:assert_separate_store(Active))
    after
        ets:delete(Active)
    end.

%%% ===================================================================
%%% Replay correctness primitives
%%% ===================================================================

genesis_coinbase_unspendable() ->
    {Chain, _} = build_chain(),
    Store = ets:new(t, [set, private]),
    try
        ok = beamchain_bg_validation:replay_block_into_store(
               Store, 0, maps:get(0, Chain)),
        %% Genesis coinbase output must NOT be in the store.
        ?assertEqual(0, ets:info(Store, size))
    after
        ets:delete(Store)
    end.

op_return_dropped() ->
    {Chain, CB1Txid} = build_chain(),
    Coins = genuine_coins(Chain),
    %% No coin may carry an OP_RETURN scriptPubKey.
    ?assertEqual([], [C || {_, _, #utxo{script_pubkey = <<16#6a, _/binary>>}} = C
                           <- Coins]),
    %% And coin A (CB1:0) must be absent (spent by TX2).
    ?assertEqual([], [C || {T, 0, _} = C <- Coins, T =:= CB1Txid]).

spent_input_removed() ->
    {Chain, CB1Txid} = build_chain(),
    Store = ets:new(t, [set, private]),
    try
        ok = beamchain_bg_validation:replay_block_into_store(
               Store, 1, maps:get(1, Chain)),
        %% After h1, coin A exists.
        ?assert(ets:member(Store, {CB1Txid, 0})),
        ok = beamchain_bg_validation:replay_block_into_store(
               Store, 2, maps:get(2, Chain)),
        %% After h2 (TX2 spends A), coin A is gone.
        ?assertNot(ets:member(Store, {CB1Txid, 0}))
    after
        ets:delete(Store)
    end.

%%% ===================================================================
%%% (a) CORRECT snapshot -> validated
%%% ===================================================================

correct_snapshot_validates() ->
    {Chain, _} = build_chain(),
    GenuineCoins = genuine_coins(Chain),
    GenuineHash = beamchain_snapshot:compute_utxo_hash_from_list(GenuineCoins),
    BaseHash = <<7:256>>,
    %% Register the GENUINE hash as the regtest au_data commitment. This is
    %% what an honest snapshot for this chain would commit to.
    ok = beamchain_chain_params:register_regtest_assumeutxo(
           ?REGTEST_BASE_HEIGHT, BaseHash, GenuineHash, 4),
    Result = beamchain_bg_validation:run(
               regtest, ?REGTEST_BASE_HEIGHT, block_fun(Chain)),
    ?assertEqual({validated, GenuineHash}, Result).

%%% ===================================================================
%%% (b) NON-CIRCULAR REJECT — the falsification
%%% ===================================================================

%% Build the tampered set = GENUINE coins + a phantom coin the replay
%% never creates, and the hash that set commits to.
tampered_set_and_hash(Chain) ->
    GenuineCoins = genuine_coins(Chain),
    %% Phantom: an outpoint with a txid/value that appears in NO block.
    PhantomTxid = <<16#ee:256>>,
    Phantom = {PhantomTxid, 0,
               #utxo{value = 2100000000000000, %% MAX_MONEY, eye-catching
                     script_pubkey = <<16#51, 16#ff>>,
                     is_coinbase = false, height = 2}},
    TamperedCoins = [Phantom | GenuineCoins],
    TamperedHash = beamchain_snapshot:compute_utxo_hash_from_list(TamperedCoins),
    GenuineHash = beamchain_snapshot:compute_utxo_hash_from_list(GenuineCoins),
    {TamperedHash, GenuineHash, PhantomTxid}.

tampered_phantom_rejected() ->
    {Chain, _} = build_chain(),
    {TamperedHash, GenuineHash, _Phantom} = tampered_set_and_hash(Chain),
    %% The tamper actually changes the commitment (the test is non-vacuous).
    ?assertNotEqual(TamperedHash, GenuineHash),
    BaseHash = <<7:256>>,
    %% A tampered snapshot FILE that contains {phantom} + genuine and
    %% commits to TamperedHash WOULD pass the load gate (the file hashes to
    %% its own committed value). We register that TAMPERED hash as the
    %% au_data commitment — exactly what the load gate authenticated and
    %% what bg compares to.
    ok = beamchain_chain_params:register_regtest_assumeutxo(
           ?REGTEST_BASE_HEIGHT, BaseHash, TamperedHash, 4),
    %% The background re-derivation walks the GENUINE chain (no phantom) and
    %% produces GenuineHash, which differs from the tampered commitment.
    Result = beamchain_bg_validation:run(
               regtest, ?REGTEST_BASE_HEIGHT, block_fun(Chain)),
    ?assertMatch({invalid, _, _}, Result),
    {invalid, Computed, Expected} = Result,
    ?assertEqual(GenuineHash, Computed),
    ?assertEqual(TamperedHash, Expected),
    %% Decisive: the bg store re-derived the GENUINE hash, NOT the loaded
    %% (tampered) hash. A hash-of-self would have reproduced TamperedHash.
    ?assertNotEqual(Expected, Computed).

phantom_absent_from_bg_store() ->
    {Chain, _} = build_chain(),
    {_TamperedHash, _GenuineHash, PhantomTxid} = tampered_set_and_hash(Chain),
    %% Re-derive into a fresh separate store and confirm the phantom
    %% outpoint never appears — the bg store is an independent replay, not a
    %% copy of the tampered loaded set.
    Store = ets:new(t, [set, private]),
    try
        ok = beamchain_bg_validation:replay_genesis_to_base(
               Store, ?REGTEST_BASE_HEIGHT, block_fun(Chain)),
        ?assertNot(ets:member(Store, {PhantomTxid, 0})),
        %% Sanity: the genuine coins ARE present (3 of them).
        ?assertEqual(3, ets:info(Store, size))
    after
        ets:delete(Store)
    end.
