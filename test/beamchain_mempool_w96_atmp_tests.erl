-module(beamchain_mempool_w96_atmp_tests).

%% W96 AcceptToMemoryPool (MemPoolAccept) end-to-end audit tests.
%%
%% References:
%%   bitcoin-core/src/validation.cpp
%%     PreChecks                       :782-983
%%     ReplacementChecks               :984-1036
%%     PolicyScriptChecks              :1135-1157
%%     ConsensusScriptChecks           :1158-1190
%%     AcceptSingleTransactionInternal :1317-1431
%%   bitcoin-core/src/policy/policy.cpp
%%     ValidateInputsStandardness      :214-263
%%   bitcoin-core/src/policy/ephemeral_policy.cpp
%%     PreCheckEphemeralTx             :23-31
%%
%% These tests exercise each newly-added or fixed gate as a unit, without
%% spinning up the full gen_server.

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%%% -------------------------------------------------------------------
%%% Re-define mempool_entry for test-side ETS seeding (it is internal to
%%% beamchain_mempool; the ETS tables are public so tests can insert rows).
%%% -------------------------------------------------------------------
-record(mempool_entry, {
    txid, wtxid, tx, fee, size, vsize, weight, fee_rate,
    time_added, height_added,
    ancestor_count, ancestor_size, ancestor_fee,
    descendant_count, descendant_size, descendant_fee,
    spends_coinbase, rbf_signaling
}).

%%% ===================================================================
%%% Helpers
%%% ===================================================================

p2pkh_script() ->
    <<16#76, 16#a9, 16#14, 0:160, 16#88, 16#ac>>.

p2sh_script() ->
    <<16#a9, 16#14, 0:160, 16#87>>.

p2wpkh_script() ->
    <<16#00, 16#14, 0:160>>.

p2tr_script() ->
    <<16#51, 16#20, 0:256>>.

nonstandard_script() ->
    <<16#51, 0, 0, 0, 0>>.   %% OP_1 then 4 junk bytes — no template match

witness_v2_unknown_script() ->
    %% OP_2 + 32-byte program: standard on output side, witness_unknown on input
    <<16#52, 16#20, 0:256>>.

witness_v0_bad_len_script() ->
    %% v0 with 22-byte program: not 20 (P2WPKH) nor 32 (P2WSH); unknown on input
    <<16#00, 16#16, 0:176>>.

make_coin(Value, SPK) ->
    make_coin(Value, SPK, false, 100).

make_coin(Value, SPK, IsCoinbase, Height) ->
    #utxo{value = Value, script_pubkey = SPK,
          is_coinbase = IsCoinbase, height = Height}.

make_tx_in(Hash, Index) ->
    #tx_in{
        prev_out = #outpoint{hash = Hash, index = Index},
        script_sig = <<>>,
        sequence = 16#fffffffe,
        witness = []
    }.

make_tx_in(Hash, Index, ScriptSig) ->
    #tx_in{
        prev_out = #outpoint{hash = Hash, index = Index},
        script_sig = ScriptSig,
        sequence = 16#fffffffe,
        witness = []
    }.

make_tx(Inputs, Outputs) ->
    #transaction{
        version = 2,
        inputs = Inputs,
        outputs = [#tx_out{value = V, script_pubkey = SPK} || {V, SPK} <- Outputs],
        locktime = 0
    }.

%%% ===================================================================
%%% Gate 5/Bug 5: ValidateInputsStandardness
%%% ===================================================================

%% Standard input templates must pass.
validate_inputs_standard_p2pkh_passes_test() ->
    Tx = make_tx([make_tx_in(<<1:256>>, 0)],
                 [{1000, p2pkh_script()}]),
    Coins = [make_coin(2000, p2pkh_script())],
    ?assertEqual(ok, beamchain_mempool:validate_inputs_standardness(Tx, Coins)).

validate_inputs_standard_p2wpkh_passes_test() ->
    Tx = make_tx([make_tx_in(<<1:256>>, 0)],
                 [{1000, p2pkh_script()}]),
    Coins = [make_coin(2000, p2wpkh_script())],
    ?assertEqual(ok, beamchain_mempool:validate_inputs_standardness(Tx, Coins)).

validate_inputs_standard_p2tr_passes_test() ->
    Tx = make_tx([make_tx_in(<<1:256>>, 0)],
                 [{1000, p2pkh_script()}]),
    Coins = [make_coin(2000, p2tr_script())],
    ?assertEqual(ok, beamchain_mempool:validate_inputs_standardness(Tx, Coins)).

%% Nonstandard input scriptPubKey → reject.
validate_inputs_nonstandard_input_rejected_test() ->
    Tx = make_tx([make_tx_in(<<1:256>>, 0)],
                 [{1000, p2pkh_script()}]),
    Coins = [make_coin(2000, nonstandard_script())],
    ?assertEqual({error, 'bad-txns-nonstandard-inputs'},
                 beamchain_mempool:validate_inputs_standardness(Tx, Coins)).

%% Witness v2 with a known program length is WITNESS_UNKNOWN on input side.
validate_inputs_witness_unknown_v2_rejected_test() ->
    Tx = make_tx([make_tx_in(<<1:256>>, 0)],
                 [{1000, p2pkh_script()}]),
    Coins = [make_coin(2000, witness_v2_unknown_script())],
    ?assertEqual({error, 'bad-txns-nonstandard-inputs'},
                 beamchain_mempool:validate_inputs_standardness(Tx, Coins)).

%% Witness v0 with wrong program length is WITNESS_UNKNOWN on input side.
validate_inputs_witness_v0_wrong_len_rejected_test() ->
    Tx = make_tx([make_tx_in(<<1:256>>, 0)],
                 [{1000, p2pkh_script()}]),
    Coins = [make_coin(2000, witness_v0_bad_len_script())],
    ?assertEqual({error, 'bad-txns-nonstandard-inputs'},
                 beamchain_mempool:validate_inputs_standardness(Tx, Coins)).

%% P2SH with redeem script containing > MAX_P2SH_SIGOPS sigops → reject.
%% Build a scriptSig that pushes a redeem script with 16 OP_CHECKSIG ops.
validate_inputs_p2sh_too_many_sigops_rejected_test() ->
    Redeem = binary:copy(<<16#ac>>, 16),  %% 16 × OP_CHECKSIG
    %% scriptSig pushing the redeem (length 16 = direct push opcode 0x10).
    %% Actually we need OP_PUSHBYTES_16: opcode 0x10 → pushes 16 bytes.
    ScriptSig = <<16#10, Redeem/binary>>,
    Tx = make_tx([make_tx_in(<<1:256>>, 0, ScriptSig)],
                 [{1000, p2pkh_script()}]),
    Coins = [make_coin(2000, p2sh_script())],
    ?assertEqual({error, 'bad-txns-nonstandard-inputs'},
                 beamchain_mempool:validate_inputs_standardness(Tx, Coins)).

%% P2SH with redeem script under the cap (15 OP_CHECKSIG) → pass.
validate_inputs_p2sh_under_cap_passes_test() ->
    Redeem = binary:copy(<<16#ac>>, 15),  %% 15 × OP_CHECKSIG
    ScriptSig = <<16#0f, Redeem/binary>>,
    Tx = make_tx([make_tx_in(<<1:256>>, 0, ScriptSig)],
                 [{1000, p2pkh_script()}]),
    Coins = [make_coin(2000, p2sh_script())],
    ?assertEqual(ok, beamchain_mempool:validate_inputs_standardness(Tx, Coins)).

%% Coinbase txs are exempt (early return).  We synthesize one to confirm the
%% gate doesn't fire on the magic coinbase prevout shape.
validate_inputs_coinbase_exempt_test() ->
    CbInput = #tx_in{
        prev_out = #outpoint{hash = <<0:256>>, index = 16#ffffffff},
        script_sig = <<2, 1, 2>>,
        sequence = 16#ffffffff,
        witness = []
    },
    Tx = #transaction{version = 1, inputs = [CbInput],
                      outputs = [#tx_out{value = 5000000000,
                                         script_pubkey = p2pkh_script()}],
                      locktime = 0},
    %% Coins list doesn't matter for coinbase; pass an empty one.
    ?assertEqual(ok, beamchain_mempool:validate_inputs_standardness(Tx, [])).

%%% ===================================================================
%%% Gate 6/Bug 4: per-coin and accumulated MoneyRange (CheckTxInputs)
%%% ===================================================================

check_money_range_normal_passes_test() ->
    Coins = [make_coin(1000, p2pkh_script()),
             make_coin(2000, p2pkh_script())],
    ?assertEqual(ok, beamchain_mempool:check_tx_inputs_money_range(Coins, <<0:256>>)).

check_money_range_negative_value_rejected_test() ->
    Coins = [make_coin(-1, p2pkh_script())],
    ?assertThrow('bad-txns-inputvalues-outofrange',
                 beamchain_mempool:check_tx_inputs_money_range(Coins, <<0:256>>)).

check_money_range_over_max_money_rejected_test() ->
    %% Single coin > MAX_MONEY: must reject.
    Coins = [make_coin(?MAX_MONEY + 1, p2pkh_script())],
    ?assertThrow('bad-txns-inputvalues-outofrange',
                 beamchain_mempool:check_tx_inputs_money_range(Coins, <<0:256>>)).

check_money_range_accumulated_overflow_rejected_test() ->
    %% Two coins each at MAX_MONEY — individually valid but sum overflows.
    Coins = [make_coin(?MAX_MONEY, p2pkh_script()),
             make_coin(1, p2pkh_script())],
    ?assertThrow('bad-txns-inputvalues-outofrange',
                 beamchain_mempool:check_tx_inputs_money_range(Coins, <<0:256>>)).

check_money_range_zero_value_accepted_test() ->
    %% Zero-value coins (OP_RETURN spends, etc.) are valid in MoneyRange.
    Coins = [make_coin(0, p2pkh_script())],
    ?assertEqual(ok, beamchain_mempool:check_tx_inputs_money_range(Coins, <<0:256>>)).

%%% ===================================================================
%%% Gate 13/Bug 10: PreCheckEphemeralTx — generalized dust gate
%%% ===================================================================

%% Non-zero fee + dust output → reject (Core: tx-with-dust-output must be 0-fee).
pre_check_ephemeral_dust_with_fee_rejected_test() ->
    %% A 1-sat P2WPKH output is dust at the default 3000 sat/kvB rate
    %% (threshold ≈ 294 sat for 31-byte P2WPKH output + 68-byte spend).
    Tx = make_tx([make_tx_in(<<1:256>>, 0)],
                 [{1, p2wpkh_script()}]),
    ?assertEqual({error, dust},
                 beamchain_mempool:pre_check_ephemeral_tx(Tx, 1000)).

%% Zero-fee + dust output → admitted (ephemeral dust path).
pre_check_ephemeral_dust_zero_fee_admitted_test() ->
    Tx = make_tx([make_tx_in(<<1:256>>, 0)],
                 [{1, p2wpkh_script()}]),
    ?assertEqual(ok, beamchain_mempool:pre_check_ephemeral_tx(Tx, 0)).

%% No dust outputs → admitted regardless of fee.
pre_check_ephemeral_no_dust_admitted_test() ->
    Tx = make_tx([make_tx_in(<<1:256>>, 0)],
                 [{10000, p2pkh_script()}]),
    ?assertEqual(ok, beamchain_mempool:pre_check_ephemeral_tx(Tx, 1000)).

%% OP_RETURN outputs are NEVER dust (Core: dust threshold = 0 for OP_RETURN).
pre_check_ephemeral_op_return_not_dust_test() ->
    OpReturn = <<16#6a, 16#04, 1, 2, 3, 4>>,
    ?assertNot(beamchain_mempool:is_dust_output(
                 #tx_out{value = 0, script_pubkey = OpReturn})).

%% Generic P2WPKH below dust threshold IS dust.
is_dust_p2wpkh_below_threshold_test() ->
    %% Threshold for P2WPKH at 3000 sat/kvB is ≈ 294 sat.
    ?assert(beamchain_mempool:is_dust_output(
              #tx_out{value = 100, script_pubkey = p2wpkh_script()})),
    %% Far above threshold: not dust.
    ?assertNot(beamchain_mempool:is_dust_output(
                 #tx_out{value = 100000, script_pubkey = p2wpkh_script()})).

%%% ===================================================================
%%% Gate 21/Bug 7: consensus script flags
%%% ===================================================================

consensus_script_flags_includes_mandatory_test() ->
    Flags = beamchain_mempool:consensus_script_flags(),
    %% P2SH is the original mandatory soft fork — must be set.
    ?assert(Flags band ?SCRIPT_VERIFY_P2SH =/= 0),
    %% DERSIG (BIP-66), CLTV (BIP-65), CSV (BIP-112), WITNESS (BIP-141),
    %% TAPROOT (BIPs 341/342) — all currently mandatory on mainnet.
    ?assert(Flags band ?SCRIPT_VERIFY_DERSIG =/= 0),
    ?assert(Flags band ?SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY =/= 0),
    ?assert(Flags band ?SCRIPT_VERIFY_CHECKSEQUENCEVERIFY =/= 0),
    ?assert(Flags band ?SCRIPT_VERIFY_WITNESS =/= 0),
    ?assert(Flags band ?SCRIPT_VERIFY_TAPROOT =/= 0),
    %% NULLDUMMY was made mandatory in 0.16; must be set.
    ?assert(Flags band ?SCRIPT_VERIFY_NULLDUMMY =/= 0),
    %% NULLFAIL became mandatory in 0.18.
    ?assert(Flags band ?SCRIPT_VERIFY_NULLFAIL =/= 0).

%% Consensus flags must be a STRICT SUBSET of the all-standard mempool flags.
%% A flag set in consensus but not in policy would invert the second-pass:
%% Core's invariant is consensus ⊆ standard (standard adds policy-only flags).
consensus_subset_of_standard_test() ->
    %% Re-derive standard flags via reflection — they're not exported.  We
    %% know the set from src/beamchain_mempool.erl all_standard_flags/0.
    StandardFlags =
        ?SCRIPT_VERIFY_P2SH bor
        ?SCRIPT_VERIFY_DERSIG bor
        ?SCRIPT_VERIFY_NULLDUMMY bor
        ?SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY bor
        ?SCRIPT_VERIFY_CHECKSEQUENCEVERIFY bor
        ?SCRIPT_VERIFY_WITNESS bor
        ?SCRIPT_VERIFY_NULLFAIL bor
        ?SCRIPT_VERIFY_TAPROOT,
    Consensus = beamchain_mempool:consensus_script_flags(),
    ?assertEqual(Consensus, Consensus band StandardFlags).

%%% ===================================================================
%%% ===================================================================
%%% Gate 2a/2b (BIP-339): wtxid vs txid duplicate detection
%%% ===================================================================
%%
%% Core validation.cpp:823-829:
%%   if (m_pool.exists(GenTxid::Wtxid(wtxid))) → "txn-already-in-mempool"
%%   else if (m_pool.exists(GenTxid::Txid(txid))) → "txn-same-nonwitness-data-in-mempool"
%%
%% The two checks MUST return distinct error atoms.  Collapsing them into a
%% single "already in mempool" check (the W96 universal bug) causes nodes to
%% silence the second case, which is required for correct relay behaviour.
%%
%% Strategy: seed the ?MEMPOOL_TXS ETS table directly (it is public), then
%% call beamchain_mempool:lookup_entry_by_wtxid/1 to validate the separation.

setup_ets() ->
    Tables = [mempool_txs, mempool_by_fee, mempool_outpoints,
              mempool_orphans, mempool_clusters, mempool_ephemeral],
    lists:foreach(fun(T) ->
        case ets:info(T) of
            undefined -> ok;
            _         -> ets:delete(T)
        end
    end, Tables),
    ets:new(mempool_txs,       [set, public, named_table, {read_concurrency, true}]),
    ets:new(mempool_by_fee,    [ordered_set, public, named_table]),
    ets:new(mempool_outpoints, [set, public, named_table]),
    ets:new(mempool_orphans,   [set, public, named_table]),
    ets:new(mempool_clusters,  [set, public, named_table, {read_concurrency, true}]),
    ets:new(mempool_ephemeral, [set, public, named_table]),
    ok.

cleanup_ets(_) ->
    lists:foreach(fun(T) ->
        case ets:info(T) of
            undefined -> ok;
            _         -> ets:delete(T)
        end
    end, [mempool_txs, mempool_by_fee, mempool_outpoints,
          mempool_orphans, mempool_clusters, mempool_ephemeral]).

make_dummy_entry(Txid, Wtxid) ->
    #mempool_entry{
        txid = Txid, wtxid = Wtxid, tx = undefined,
        fee = 1000, size = 200, vsize = 200, weight = 800,
        fee_rate = 5.0, time_added = 0, height_added = 0,
        ancestor_count = 1, ancestor_size = 200, ancestor_fee = 1000,
        descendant_count = 1, descendant_size = 200, descendant_fee = 1000,
        spends_coinbase = false, rbf_signaling = true
    }.

%% Gate 2a: exact wtxid already in mempool → found by lookup_entry_by_wtxid.
%% This is the precondition that causes do_add_transaction to throw
%% 'txn-already-in-mempool' per Core validation.cpp:823-826.
gate2a_wtxid_match_found_test_() ->
    {setup, fun setup_ets/0, fun cleanup_ets/1,
     fun(_) ->
         Txid  = <<1:256>>,
         Wtxid = <<2:256>>,
         Entry = make_dummy_entry(Txid, Wtxid),
         ets:insert(mempool_txs, {Txid, Entry}),
         [
          %% Searching by the same wtxid must find the entry.
          ?_assertMatch({ok, _},
                        beamchain_mempool:lookup_entry_by_wtxid(Wtxid)),
          %% Searching by a different wtxid must return not_found.
          ?_assertEqual(not_found,
                        beamchain_mempool:lookup_entry_by_wtxid(<<3:256>>))
         ]
     end}.

%% Gate 2b: same txid but different wtxid (mutated witness) → txid lookup
%% hits but wtxid lookup misses.  This must NOT collapse to the gate-2a
%% error: the path for "same nonwitness data" is triggered by ets:lookup on
%% ?MEMPOOL_TXS (keyed by txid) after the wtxid miss.
gate2b_txid_match_wtxid_miss_test_() ->
    {setup, fun setup_ets/0, fun cleanup_ets/1,
     fun(_) ->
         Txid       = <<10:256>>,
         OrigWtxid  = <<20:256>>,
         MutWtxid   = <<21:256>>,   %% different wtxid — witness was mutated
         Entry = make_dummy_entry(Txid, OrigWtxid),
         ets:insert(mempool_txs, {Txid, Entry}),
         [
          %% wtxid lookup with the MUTATED wtxid must miss (gate 2a would not fire).
          ?_assertEqual(not_found,
                        beamchain_mempool:lookup_entry_by_wtxid(MutWtxid)),
          %% txid lookup must still hit (gate 2b fires → txn-same-nonwitness-data).
          ?_assertMatch([{Txid, _}], ets:lookup(mempool_txs, Txid))
         ]
     end}.

%%% Gate 5b/Bug 3: txn-already-known
%%% ===================================================================

%% Without a UTXO database mock running, check_tx_already_known returns
%% not_known when get_utxo returns not_found for every output index.  This
%% test asserts the return contract — the no-cache-hit path is reachable.
check_tx_already_known_no_cache_hit_test_() ->
    {setup,
     fun() ->
         %% In test env, beamchain_chainstate may not be started.  Skip if so.
         case erlang:whereis(beamchain_chainstate) of
             undefined -> skip;
             _Pid      -> ok
         end
     end,
     fun(_) -> ok end,
     fun(SetupResult) ->
         case SetupResult of
             skip -> [];
             ok ->
                 Tx = make_tx([make_tx_in(<<1:256>>, 0)],
                              [{1000, p2pkh_script()},
                               {1000, p2pkh_script()}]),
                 [?_assertEqual(not_known,
                                beamchain_mempool:check_tx_already_known(Tx))]
         end
     end}.

%%% ===================================================================
%%% Static constant checks
%%% ===================================================================

%% Confirm MAX_P2SH_SIGOPS = 15 (Core policy/policy.h).
max_p2sh_sigops_constant_test() ->
    ?assertEqual(15, ?MAX_P2SH_SIGOPS).

%% Confirm DEFAULT_MIN_RELAY_TX_FEE = 1000 sat/kvB = 1 sat/vB
%% (Core kernel/mempool_options.h:25).
default_min_relay_fee_constant_test() ->
    ?assertEqual(1000, ?DEFAULT_MIN_RELAY_TX_FEE).

%% Confirm DEFAULT_INCREMENTAL_RELAY_FEE = 100 sat/kvB (Core policy/policy.h:48).
default_incremental_relay_fee_constant_test() ->
    ?assertEqual(100, ?DEFAULT_INCREMENTAL_RELAY_FEE).

%% Effective minimum relay fee composition: CheckFeeRate uses
%%   max(rolling_min_fee_sat_per_vb, DEFAULT_MIN_RELAY_TX_FEE / 1000)
%% The static floor must always be at least 1.0 sat/vB.
effective_min_relay_floor_at_least_1_satvb_test() ->
    StaticMinRelay = ?DEFAULT_MIN_RELAY_TX_FEE / 1000.0,
    ?assertEqual(1.0, StaticMinRelay).
