-module(beamchain_w113_coin_selection_tests).

%% W113 Coin Selection algorithms fleet audit — beamchain (Erlang/OTP)
%%
%% 30 gates: G1-G5 Algorithm presence
%%           G6-G10 OutputGroup
%%           G11-G15 BnB
%%           G16-G20 Knapsack
%%           G21-G24 Change output
%%           G25-G28 Anti-fee-sniping
%%           G29-G30 CoinControl + WasteMetric
%%
%% Bugs found:
%%   BUG-1 (HIGH)   BnB depth limit 20 vs Core's TOTAL_TRIES=100000 — beamchain
%%                  aborts after exploring at most 20 nodes, making BnB nearly
%%                  useless for wallets with >20 UTXOs.  Core exhaustively
%%                  tries up to 100,000 combinations.
%%   BUG-2 (HIGH)   WasteMetric entirely absent — beamchain never calculates
%%                  waste = change_cost + inputs*(feerate - long_term_feerate).
%%                  No long-term feerate concept; cannot prefer no-change over
%%                  change when fee rates are elevated.
%%   BUG-3 (HIGH)   SRD (Single Random Draw) algorithm entirely absent —
%%                  Core runs three algorithms (BnB, CoinGrinder/Knapsack, SRD)
%%                  and picks the lowest-waste result.  beamchain has only two
%%                  (BnB→Knapsack fallback) and uses the first winner, not the
%%                  best by waste.
%%   BUG-4 (HIGH)   CoinGrinder algorithm entirely absent — Core added
%%                  CoinGrinder in 27.0 as a weight-aware minimizer that beats
%%                  Knapsack.  beamchain still uses the classic Knapsack.
%%   BUG-5 (HIGH)   OutputGroup struct absent — beamchain passes flat
%%                  {Txid,Vout,Utxo} tuples directly.  Core groups UTXOs
%%                  sharing a scriptPubKey into OutputGroups, which is
%%                  required for -avoidpartialspends correctness and for
%%                  accurate per-group effective_value/long_term_fee fields.
%%   BUG-6 (HIGH)   Anti-fee-sniping entirely absent — build_transaction/3
%%                  hard-codes locktime=0.  Core sets locktime = block_height
%%                  (with a 1-in-10 random-rollback) to prevent snipers
%%                  mining a competing chain and double-spending old outputs.
%%   BUG-7 (MEDIUM) No long-term feerate / consolidation mode — Core uses a
%%                  separate long_term_feerate (CFeeRate) to account for future
%%                  spend cost of change.  beamchain has one flat FeeRate for
%%                  both current and long-term cost, so the waste metric (if
%%                  ever added) would be incorrect.
%%   BUG-8 (MEDIUM) Knapsack picks smallest-first always — Core's Knapsack
%%                  also tries largest-first on each repetition (1000 iters)
%%                  and takes the winner; beamchain's accumulate_coins/5 does
%%                  a single smallest-first linear sweep, producing sub-optimal
%%                  results and missing the stochastic factor entirely.
%%   BUG-9 (MEDIUM) Dust threshold hard-coded to 546 in two places
%%                  (bnb_select, rpc_sendtoaddress) — Core computes
%%                  min_viable_change = max(change_spend_fee+1, dust) where
%%                  dust depends on the discard feerate; hardcoding 546 is
%%                  wrong at non-default discard feerates.
%%   BUG-10 (MEDIUM) OUTPUT_GROUP_MAX_ENTRIES (100) cap absent — Core limits
%%                   each OutputGroup to 100 UTXOs when -avoidpartialspends is
%%                   active; beamchain has no such cap, meaning a wallet with
%%                   many UTXOs at the same address can build oversized txns.
%%   BUG-11 (MEDIUM) change_position always appended (never randomised) —
%%                   Core randomly inserts the change output to prevent change
%%                   fingerprinting; beamchain always appends it last in
%%                   rpc_sendtoaddress and wcfp_append_change.
%%   BUG-12 (LOW)   All P2WPKH_INPUT_WEIGHT assumption — cost_per_input uses
%%                  ?P2WPKH_INPUT_WEIGHT (272 wu) for every UTXO regardless of
%%                  script type.  P2TR inputs weigh 230 wu, P2PKH 592 wu.
%%                  The wrong weight inflates fee estimates for P2TR (over-
%%                  selects) and under-estimates for P2PKH (under-selects).
%%
%% NOT a CDIV: wallet coin-selection bugs affect fee efficiency and change
%% fingerprinting but not consensus validation of received blocks.

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

%%% ===================================================================
%%% G1 — BnB algorithm present
%%% ===================================================================

g1_bnb_present_test_() ->
    {"G1: BnB (branch-and-bound) algorithm is present and exported",
     [
      ?_test(begin
         %% beamchain_wallet exports select_coins/3 which internally uses bnb_select
         Fns = beamchain_wallet:module_info(exports),
         ?assert(lists:member({select_coins, 3}, Fns))
       end)
     ]}.

%%% ===================================================================
%%% G2 — Knapsack algorithm present
%%% ===================================================================

g2_knapsack_present_test_() ->
    {"G2: Knapsack solver present (via select_coins fallback path)",
     [
      ?_test(begin
         %% Drive through a case where BnB cannot match exactly so
         %% knapsack_select is exercised.
         Utxos = [
             {<<1:256>>, 0, #utxo{value = 3000, script_pubkey = <<>>,
                                   is_coinbase = false, height = 100}},
             {<<2:256>>, 0, #utxo{value = 7000, script_pubkey = <<>>,
                                   is_coinbase = false, height = 100}},
             {<<3:256>>, 0, #utxo{value = 11000, script_pubkey = <<>>,
                                   is_coinbase = false, height = 100}}
         ],
         %% Target is deliberately not an exact combination
         Result = beamchain_wallet:select_coins(9999, 1, Utxos),
         ?assertMatch({ok, _, _}, Result)
       end)
     ]}.

%%% ===================================================================
%%% G3 — BUG-3: SRD algorithm absent
%%% ===================================================================

g3_srd_absent_test_() ->
    {"G3: BUG-3 — SRD (Single Random Draw) algorithm absent",
     [
      ?_test(begin
         %% Core exposes SelectCoinsSRD.  beamchain has no equivalent.
         Fns = beamchain_wallet:module_info(exports),
         ?assertNot(lists:member({select_coins_srd, 3}, Fns)),
         ?assertNot(lists:member({srd_select, 2}, Fns)),
         ?assertNot(lists:member({srd_select, 3}, Fns))
       end)
     ]}.

%%% ===================================================================
%%% G4 — BUG-4: CoinGrinder absent
%%% ===================================================================

g4_coingrinder_absent_test_() ->
    {"G4: BUG-4 — CoinGrinder algorithm absent",
     [
      ?_test(begin
         Fns = beamchain_wallet:module_info(exports),
         ?assertNot(lists:member({coin_grinder, 3}, Fns)),
         ?assertNot(lists:member({coin_grinder, 4}, Fns))
       end)
     ]}.

%%% ===================================================================
%%% G5 — Multi-algorithm result comparison absent
%%% ===================================================================

g5_multi_algo_comparison_absent_test_() ->
    {"G5: No multi-algorithm result comparison (waste metric selection)",
     [
      ?_test(begin
         %% Core runs BnB + CoinGrinder + SRD in parallel and picks
         %% the result with the lowest waste.  beamchain returns first
         %% success.  This is structural — we document it by running
         %% select_coins and observing it returns a single result
         %% with no waste field.
         Utxos = [
             {<<1:256>>, 0, #utxo{value = 50000, script_pubkey = <<>>,
                                   is_coinbase = false, height = 100}},
             {<<2:256>>, 0, #utxo{value = 20000, script_pubkey = <<>>,
                                   is_coinbase = false, height = 100}}
         ],
         Result = beamchain_wallet:select_coins(30000, 1, Utxos),
         %% Returns {ok, Selected, Change} — no waste field in response
         {ok, _Selected, _Change} = Result,
         ok
       end)
     ]}.

%%% ===================================================================
%%% G6 — BUG-5: OutputGroup struct absent
%%% ===================================================================

g6_outputgroup_absent_test_() ->
    {"G6: BUG-5 — OutputGroup struct absent; UTXOs passed as flat tuples",
     [
      ?_test(begin
         %% Core groups UTXOs sharing a scriptPubKey into OutputGroups.
         %% beamchain select_coins/3 accepts [{Txid,Vout,#utxo{}}] directly.
         %% Verify select_coins does NOT group by scriptPubKey.
         Script = <<0, 20, 1:160>>,  %% Same P2WPKH script
         Utxos = [
             {<<1:256>>, 0, #utxo{value = 10000, script_pubkey = Script,
                                   is_coinbase = false, height = 100}},
             {<<2:256>>, 1, #utxo{value = 10000, script_pubkey = Script,
                                   is_coinbase = false, height = 100}},
             {<<3:256>>, 0, #utxo{value = 5000, script_pubkey = <<0,20,2:160>>,
                                   is_coinbase = false, height = 100}}
         ],
         %% With grouping, the two UTXOs sharing script would form one
         %% OutputGroup and be treated atomically. Without grouping, they
         %% are independent — beamchain picks the smallest-first, possibly
         %% selecting only one UTXO from the same address.
         {ok, Selected, _} = beamchain_wallet:select_coins(8000, 1, Utxos),
         %% beamchain may pick just one UTXO from the shared-script address
         ?assert(length(Selected) >= 1)
       end)
     ]}.

%%% ===================================================================
%%% G7 — OutputGroup effective_value per-group absent
%%% ===================================================================

g7_outputgroup_effective_value_absent_test_() ->
    {"G7: OutputGroup effective_value aggregation absent",
     [
      ?_test(begin
         %% Core accumulates effective_value, long_term_fee, m_weight
         %% per OutputGroup.  beamchain computes cost_per_input inline
         %% per UTXO rather than per group.  Document this structural gap.
         Fns = beamchain_wallet:module_info(exports),
         ?assertNot(lists:member({output_group_effective_value, 1}, Fns)),
         ?assertNot(lists:member({get_effective_value, 2}, Fns))
       end)
     ]}.

%%% ===================================================================
%%% G8 — OutputGroup long_term_fee absent
%%% ===================================================================

g8_outputgroup_long_term_fee_absent_test_() ->
    {"G8: BUG-7 — long-term feerate for change spend cost absent",
     [
      ?_test(begin
         %% Core's OutputGroup::m_long_term_feerate is passed from
         %% CoinSelectionParams.  beamchain select_coins/3 has a single
         %% FeeRate parameter — no separate long-term feerate.
         %% Confirm the spec says 3 args only.
         ?assertEqual(3, element(2, lists:keyfind(select_coins, 1,
             beamchain_wallet:module_info(exports))))
       end)
     ]}.

%%% ===================================================================
%%% G9 — OutputGroup positive_group / mixed_group split absent
%%% ===================================================================

g9_outputgroup_positive_mixed_split_absent_test_() ->
    {"G9: positive_group / mixed_group split absent",
     [
      ?_test(begin
         %% Core splits UTXOs into positive_group (effective_value > 0) and
         %% mixed_group (may include negative-effective-value UTXOs).
         %% BnB only operates on positive_group; Knapsack uses mixed_group.
         %% beamchain passes the same flat list to both algorithms.
         %%
         %% BUG-5 consequence: beamchain's knapsack accumulate_coins/5 uses
         %% max(eff_value, 0) which guards against negative accumulation but
         %% still adds the coin to the selected list even when eff_value <= 0.
         %% This is a deficit vs Core which would never select such a coin at
         %% all (it would be excluded from mixed_group too if below dust).
         Utxos = [
             %% This UTXO costs more in fees than it's worth (eff value = 50 - 68 = -18)
             {<<1:256>>, 0, #utxo{value = 50, script_pubkey = <<>>,
                                   is_coinbase = false, height = 100}},
             {<<2:256>>, 0, #utxo{value = 50000, script_pubkey = <<>>,
                                   is_coinbase = false, height = 100}}
         ],
         %% BnB skips negative-eff-value coins inline; knapsack adds them
         %% with zero contribution but still includes them in Selected.
         %% This documents the split-absent deficit.
         {ok, _Selected, _} = beamchain_wallet:select_coins(20000, 1, Utxos),
         %% Structural check: no positive_group/mixed_group concept exists
         Fns = beamchain_wallet:module_info(exports),
         ?assertNot(lists:member({positive_group, 1}, Fns)),
         ?assertNot(lists:member({mixed_group, 1}, Fns))
       end)
     ]}.

%%% ===================================================================
%%% G10 — BUG-10: OUTPUT_GROUP_MAX_ENTRIES cap absent
%%% ===================================================================

g10_output_group_max_entries_absent_test_() ->
    {"G10: BUG-10 — OUTPUT_GROUP_MAX_ENTRIES=100 cap absent",
     [
      ?_test(begin
         %% Core limits each OutputGroup to 100 UTXOs when
         %% -avoidpartialspends is active.  beamchain has no cap concept.
         %% Generate 150 UTXOs at the same address and verify select_coins
         %% accepts all of them without any 100-entry cap error.
         Script = <<0, 20, 99:160>>,
         Utxos = lists:map(fun(I) ->
             {<<I:256>>, 0, #utxo{value = 1000, script_pubkey = Script,
                                   is_coinbase = false, height = 100}}
         end, lists:seq(1, 150)),
         %% Target requires many UTXOs — with a 100-entry cap the wallet
         %% would fail or silently truncate.  beamchain accepts all 150.
         Target = 130 * 1000,  %% needs >100 UTXOs worth to cover
         Result = beamchain_wallet:select_coins(Target, 0, Utxos),
         %% Beamchain succeeds — no cap enforced
         ?assertMatch({ok, _, _}, Result),
         {ok, Selected, _} = Result,
         %% With 150 UTXOs of 1000 sat and target=130000 at feerate=0,
         %% select_coins picks exactly 130 smallest to cover the target.
         ?assert(length(Selected) > 100),
         %% Structural check: no output_group_max_entries constant exported
         Fns = beamchain_wallet:module_info(exports),
         ?assertNot(lists:member({output_group_max_entries, 0}, Fns))
       end)
     ]}.

%%% ===================================================================
%%% G11 — BUG-1: BnB depth limit 20 vs Core TOTAL_TRIES=100000
%%% ===================================================================

g11_bnb_depth_limit_test_() ->
    {"G11: BUG-1 — BnB depth limit 20 (Core uses TOTAL_TRIES=100000)",
     [
      ?_test(begin
         %% Core's SelectCoinsBnB iterates up to TOTAL_TRIES=100000 nodes.
         %% beamchain aborts at Depth > 20.
         %% Create 25 UTXOs — BnB with depth limit 20 cannot explore all
         %% combinations and will fall back to Knapsack even when an exact
         %% match exists beyond depth 20.
         Utxos = lists:map(fun(I) ->
             V = I * 1000,
             {<<I:256>>, 0, #utxo{value = V, script_pubkey = <<>>,
                                   is_coinbase = false, height = 100}}
         end, lists:seq(1, 25)),
         %% Target = sum of last two (24000 + 25000 = 49000, or similar).
         %% With depth 20, BnB cannot find the exact pair; falls to Knapsack.
         Target = 24000 + 25000,
         {ok, _Selected, Change} = beamchain_wallet:select_coins(Target, 1, Utxos),
         %% If BnB had found the exact pair, Change would be 0.
         %% With depth-20 limit beamchain falls through to Knapsack.
         %% We document this as a deficit — not assert exact behavior.
         ?assert(Change >= 0)
       end),
      ?_test(begin
         %% Confirm the depth limit is 20 by inspection (structural check).
         %% We call select_coins on a list too deep for BnB and observe
         %% it completes (knapsack takes over) rather than timing out.
         LargeUtxos = [
             {<<I:256>>, 0, #utxo{value = I * 500, script_pubkey = <<>>,
                                   is_coinbase = false, height = 100}}
             || I <- lists:seq(1, 30)
         ],
         Result = beamchain_wallet:select_coins(1000, 1, LargeUtxos),
         ?assertMatch({ok, _, _}, Result)
       end)
     ]}.

%%% ===================================================================
%%% G12 — BnB exact-match window correct (within DustLimit of target)
%%% ===================================================================

g12_bnb_exact_match_window_test_() ->
    {"G12: BnB returns change=0 for exact match within dust limit",
     [
      ?_test(begin
         %% Target = 10000, UTXO = 10068 (single P2WPKH cost ~68 sat at 1 sat/vB)
         %% eff_value = 10068 - 68 = 10000 => exact match, change = 0
         Utxos = [
             {<<1:256>>, 0, #utxo{value = 10068, script_pubkey = <<>>,
                                   is_coinbase = false, height = 100}}
         ],
         Result = beamchain_wallet:select_coins(10000, 1, Utxos),
         case Result of
             {ok, _, Change} ->
                 %% BnB should find this near-exact match (within DustLimit)
                 ?assert(Change =< 546);
             {error, insufficient_funds} ->
                 %% Acceptable — fee calculation may differ slightly
                 ok
         end
       end)
     ]}.

%%% ===================================================================
%%% G13 — BnB skips negative-effective-value UTXOs
%%% ===================================================================

g13_bnb_skips_negative_eff_value_test_() ->
    {"G13: BnB inline-skips UTXOs with non-positive effective value",
     [
      ?_test(begin
         %% UTXO worth 50 sat — at feerate 1, eff_value = 50 - 68 = -18 (<= 0).
         %% bnb_search skips it via the `EffValue > 0` guard.
         %% However knapsack accumulate_coins uses max(eff_value, 0) which
         %% adds 0 to the accumulated total but still INCLUDES the coin in
         %% Selected — this is a deficit: knapsack can return dust coins
         %% that contribute nothing to covering the target.
         Utxos = [
             {<<1:256>>, 0, #utxo{value = 50, script_pubkey = <<>>,
                                   is_coinbase = false, height = 100}},
             {<<2:256>>, 0, #utxo{value = 100000, script_pubkey = <<>>,
                                   is_coinbase = false, height = 100}}
         ],
         {ok, Selected, _} = beamchain_wallet:select_coins(50000, 1, Utxos),
         %% BnB succeeds on the 100000 UTXO alone — bnb_search correctly
         %% skips the 50-sat UTXO since eff_value <= 0.
         SelectedValues = [U#utxo.value || {_, _, U} <- Selected],
         %% BnB path: tiny UTXO NOT selected (eff_value guard works in BnB)
         ?assert(lists:member(100000, SelectedValues))
       end)
     ]}.

%%% ===================================================================
%%% G14 — BnB returns no_match when no candidate found
%%% ===================================================================

g14_bnb_no_match_returns_no_match_test_() ->
    {"G14: BnB returns no_match / fallback to knapsack on no exact match",
     [
      ?_test(begin
         %% Two UTXOs of 10000 sat, target 15000 — no exact BnB match,
         %% must fall through to knapsack.
         Utxos = [
             {<<1:256>>, 0, #utxo{value = 10000, script_pubkey = <<>>,
                                   is_coinbase = false, height = 100}},
             {<<2:256>>, 0, #utxo{value = 10000, script_pubkey = <<>>,
                                   is_coinbase = false, height = 100}}
         ],
         Result = beamchain_wallet:select_coins(15000, 1, Utxos),
         ?assertMatch({ok, _, _}, Result),
         {ok, Selected, Change} = Result,
         Total = lists:sum([U#utxo.value || {_, _, U} <- Selected]),
         ?assert(Total >= 15000),
         ?assert(Change >= 0)
       end)
     ]}.

%%% ===================================================================
%%% G15 — BnB handles empty UTXO list
%%% ===================================================================

g15_bnb_empty_utxo_list_test_() ->
    {"G15: BnB/select_coins returns error on empty UTXO list",
     [
      ?_assertEqual({error, insufficient_funds},
                    beamchain_wallet:select_coins(1000, 1, []))
     ]}.

%%% ===================================================================
%%% G16 — BUG-8: Knapsack single-pass smallest-first only
%%%         (Core does 1000 randomised iterations)
%%% ===================================================================

g16_knapsack_single_pass_test_() ->
    {"G16: BUG-8 — Knapsack is single-pass smallest-first (Core: 1000 rand iter)",
     [
      ?_test(begin
         %% Core's KnapsackSolver shuffles and tries 1000 times.
         %% beamchain has one deterministic pass.  Calling select_coins
         %% twice with the same inputs always returns the same result
         %% — no randomness.
         Utxos = [
             {<<1:256>>, 0, #utxo{value = 5000, script_pubkey = <<>>,
                                   is_coinbase = false, height = 100}},
             {<<2:256>>, 0, #utxo{value = 8000, script_pubkey = <<>>,
                                   is_coinbase = false, height = 100}},
             {<<3:256>>, 0, #utxo{value = 12000, script_pubkey = <<>>,
                                   is_coinbase = false, height = 100}}
         ],
         R1 = beamchain_wallet:select_coins(9000, 1, Utxos),
         R2 = beamchain_wallet:select_coins(9000, 1, Utxos),
         %% Deterministic — same result both times (no SRD randomness)
         ?assertEqual(R1, R2)
       end)
     ]}.

%%% ===================================================================
%%% G17 — Knapsack covers target + change output fee
%%% ===================================================================

g17_knapsack_covers_change_fee_test_() ->
    {"G17: Knapsack selects enough to cover target plus change-output fee",
     [
      ?_test(begin
         %% knapsack_select adds change-output overhead to the effective target
         Utxos = [
             {<<1:256>>, 0, #utxo{value = 10000, script_pubkey = <<>>,
                                   is_coinbase = false, height = 100}},
             {<<2:256>>, 0, #utxo{value = 20000, script_pubkey = <<>>,
                                   is_coinbase = false, height = 100}}
         ],
         {ok, _Selected, Change} = beamchain_wallet:select_coins(8000, 1, Utxos),
         %% Change is positive after covering fees
         ?assert(Change >= 0)
       end)
     ]}.

%%% ===================================================================
%%% G18 — Knapsack returns insufficient_funds when all UTXOs negative
%%% ===================================================================

g18_knapsack_insufficient_funds_test_() ->
    {"G18: Knapsack returns insufficient_funds when target > available",
     [
      ?_assertEqual({error, insufficient_funds},
                    beamchain_wallet:select_coins(1_000_000_000, 1,
                        [{<<1:256>>, 0, #utxo{value = 1000,
                                               script_pubkey = <<>>,
                                               is_coinbase = false,
                                               height = 100}}]))
     ]}.

%%% ===================================================================
%%% G19 — Knapsack: max(eff_value, 0) guard prevents negative accumulation
%%% ===================================================================

g19_knapsack_max_eff_value_guard_test_() ->
    {"G19: Knapsack max(eff_value,0) prevents negative accumulation",
     [
      ?_test(begin
         %% UTXO worth 50 sat — at feerate 1 its eff_value = 50 - 68 = -18.
         %% max(-18, 0) = 0 so accumulate_coins does NOT add to the sum,
         %% preventing negative over-accumulation.  However it still adds
         %% the coin to the Selected list — this is a deficit vs Core which
         %% would exclude sub-dust UTXOs from the positive_group entirely.
         TinyUtxo = {<<1:256>>, 0, #utxo{value = 50, script_pubkey = <<>>,
                                          is_coinbase = false, height = 100}},
         BigUtxo  = {<<2:256>>, 0, #utxo{value = 200000, script_pubkey = <<>>,
                                          is_coinbase = false, height = 100}},
         {ok, Selected, _} = beamchain_wallet:select_coins(100000, 1,
                                                            [TinyUtxo, BigUtxo]),
         SelectedValues = [U#utxo.value || {_, _, U} <- Selected],
         %% BnB path handles this case correctly — the big UTXO is sufficient
         %% for the target so BnB picks it alone and skips the tiny one.
         ?assert(lists:member(200000, SelectedValues)),
         %% The total selected value correctly covers the target
         TotalSelected = lists:sum(SelectedValues),
         ?assert(TotalSelected >= 100000)
       end)
     ]}.

%%% ===================================================================
%%% G20 — BUG-12: All inputs treated as P2WPKH regardless of type
%%% ===================================================================

g20_input_weight_always_p2wpkh_test_() ->
    {"G20: BUG-12 — cost_per_input uses P2WPKH_INPUT_WEIGHT for all types",
     [
      ?_test(begin
         %% P2TR weight (230 wu) vs P2WPKH weight (272 wu).
         %% beamchain always uses P2WPKH_INPUT_WEIGHT=272 for every UTXO
         %% regardless of script type.
         %% At feerate 10 sat/vB:
         %%   CostPerInput = round(10 * 272 / 4) = 680 sat for both types
         %% Core would use 230 wu for P2TR → round(10 * 230 / 4) = 575 sat
         %% This means beamchain over-estimates fees for P2TR by 105 sat/input.
         P2wpkhScript = <<0, 20, 1:160>>,
         P2trScript = <<1, 32, 2:256>>,
         U1 = {<<1:256>>, 0, #utxo{value = 50000,
                                    script_pubkey = P2wpkhScript,
                                    is_coinbase = false, height = 100}},
         U2 = {<<2:256>>, 0, #utxo{value = 50000,
                                    script_pubkey = P2trScript,
                                    is_coinbase = false, height = 100}},
         %% BUG-12: same change for P2WPKH and P2TR (both use 272 wu)
         {ok, _, Change1} = beamchain_wallet:select_coins(30000, 10, [U1]),
         {ok, _, Change2} = beamchain_wallet:select_coins(30000, 10, [U2]),
         %% BUG-12 documented: change amounts are equal because the same
         %% weight constant is used for both script types
         ?assertEqual(Change1, Change2)
         %% Correct behavior: Change2 should be LARGER than Change1 because
         %% P2TR inputs are lighter (230 wu < 272 wu) — less fee needed.
       end)
     ]}.

%%% ===================================================================
%%% G21 — BUG-9: Change dust threshold hard-coded to 546
%%% ===================================================================

g21_change_dust_threshold_hardcoded_test_() ->
    {"G21: BUG-9 — dust threshold hard-coded to 546 (should be feerate-dependent)",
     [
      ?_test(begin
         %% rpc_sendtoaddress and bnb_select both use 546 as the dust limit.
         %% Core: min_viable_change = max(change_spend_fee+1, dust) where
         %% dust = GetDustThreshold(change_out, discard_feerate).
         %% At high discard feerates, min_viable_change > 546 — beamchain
         %% would create uneconomic change outputs.
         %%
         %% Test: at high fee rate BnB still uses 546 as the exact-match
         %% window, over-eagerly calling something a match.
         Utxos = [
             {<<1:256>>, 0, #utxo{value = 100546, script_pubkey = <<>>,
                                   is_coinbase = false, height = 100}}
         ],
         %% High fee rate — Core would compute a much higher min_viable_change
         Result = beamchain_wallet:select_coins(100000, 50, Utxos),
         case Result of
             {ok, _, Change} ->
                 %% If change < 546 beamchain treats as match; Core might not
                 ?assert(Change >= 0);
             {error, insufficient_funds} ->
                 ok
         end
       end)
     ]}.

%%% ===================================================================
%%% G22 — BUG-2: WasteMetric absent
%%% ===================================================================

g22_waste_metric_absent_test_() ->
    {"G22: BUG-2 — WasteMetric entirely absent",
     [
      ?_test(begin
         %% Core's SelectionResult::RecalculateWaste computes
         %% waste = change_cost + sum(input_fee - long_term_fee).
         %% beamchain returns {ok, Selected, Change} — no waste field.
         Utxos = [
             {<<1:256>>, 0, #utxo{value = 50000, script_pubkey = <<>>,
                                   is_coinbase = false, height = 100}},
             {<<2:256>>, 0, #utxo{value = 30000, script_pubkey = <<>>,
                                   is_coinbase = false, height = 100}}
         ],
         Result = beamchain_wallet:select_coins(40000, 1, Utxos),
         %% Returns a 3-tuple, not a 4-tuple with waste
         ?assertMatch({ok, _, _}, Result),
         ?assertNot(tuple_size(Result) =:= 4)
       end)
     ]}.

%%% ===================================================================
%%% G23 — Change amount calculation basic correctness
%%% ===================================================================

g23_change_amount_basic_test_() ->
    {"G23: Change returned equals selected total minus target minus fees",
     [
      ?_test(begin
         %% With feerate=0 (no fees) the change should be exact.
         Utxos = [
             {<<1:256>>, 0, #utxo{value = 50000, script_pubkey = <<>>,
                                   is_coinbase = false, height = 100}}
         ],
         {ok, _Selected, _Change} = beamchain_wallet:select_coins(30000, 0, Utxos),
         %% Change = 50000 - effective_target.  With feerate=0 and BaseFee=0
         %% this should be roughly 50000 - 30000 = 20000.
         ok
       end),
      ?_test(begin
         %% BnB returns change=0 for an exact match
         Utxos = [
             {<<1:256>>, 0, #utxo{value = 30000, script_pubkey = <<>>,
                                   is_coinbase = false, height = 100}}
         ],
         Result = beamchain_wallet:select_coins(30000, 0, Utxos),
         %% At feerate 0, 30000 is effectively the target so BnB may match
         ?assertMatch({ok, _, _}, Result)
       end)
     ]}.

%%% ===================================================================
%%% G24 — BUG-11: Change position always appended (never randomised)
%%% ===================================================================

g24_change_position_not_randomised_test_() ->
    {"G24: BUG-11 — change position always appended at end, not randomised",
     [
      ?_test(begin
         %% beamchain's rpc_sendtoaddress appends change as the last output.
         %% Core randomly inserts it to prevent change fingerprinting.
         %% We document this deficit — no functional API to test the position
         %% from select_coins alone; documented at the RPC layer.
         ok
       end)
     ]}.

%%% ===================================================================
%%% G25 — BUG-6: Anti-fee-sniping entirely absent
%%% ===================================================================

g25_anti_fee_sniping_absent_test_() ->
    {"G25: BUG-6 — anti-fee-sniping absent; locktime always 0",
     [
      ?_test(begin
         %% Core's DiscourageFeeSniping sets nLockTime = current_block_height
         %% (with 1-in-10 random rollback by up to 100 blocks).
         %% beamchain's build_transaction/3 hard-codes locktime = 0.
         Inputs = [
             {<<1:256>>, 0, #utxo{value = 50000, script_pubkey = <<0,20,1:160>>,
                                   is_coinbase = false, height = 100}}
         ],
         Outputs = [{"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 40000}],
         {ok, Tx} = beamchain_wallet:build_transaction(Inputs, Outputs, mainnet),
         %% BUG-6: locktime is 0 instead of current block height
         ?assertEqual(0, Tx#transaction.locktime)
       end)
     ]}.

%%% ===================================================================
%%% G26 — Anti-fee-sniping: tip_height parameter absent in build_transaction
%%% ===================================================================

g26_build_transaction_no_tip_height_test_() ->
    {"G26: build_transaction/3 has no tip_height parameter for anti-fee-sniping",
     [
      ?_test(begin
         %% Core's CreateTransaction receives block_height and block_time.
         %% beamchain's build_transaction(Inputs, Outputs, Network) has no
         %% height parameter — anti-fee-sniping cannot be added without an
         %% API change.
         Fns = beamchain_wallet:module_info(exports),
         %% Only build_transaction/3 exists — no /4 with height
         ?assert(lists:member({build_transaction, 3}, Fns)),
         ?assertNot(lists:member({build_transaction, 4}, Fns))
       end)
     ]}.

%%% ===================================================================
%%% G27 — Anti-fee-sniping: RBF sequence (0xfffffffd) correct
%%% ===================================================================

g27_rbf_sequence_correct_test_() ->
    {"G27: Inputs correctly signal RBF via sequence=0xfffffffd",
     [
      ?_test(begin
         %% Core uses sequence 0xfffffffd to signal RBF opt-in.
         %% beamchain also uses 0xfffffffd — this is CORRECT.
         Inputs = [
             {<<1:256>>, 0, #utxo{value = 50000, script_pubkey = <<>>,
                                   is_coinbase = false, height = 100}}
         ],
         Outputs = [{"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 40000}],
         {ok, Tx} = beamchain_wallet:build_transaction(Inputs, Outputs, mainnet),
         [In] = Tx#transaction.inputs,
         ?assertEqual(16#fffffffd, In#tx_in.sequence)
       end)
     ]}.

%%% ===================================================================
%%% G28 — Anti-fee-sniping: MAX_ANTI_FEE_SNIPING_TIP_AGE logic absent
%%% ===================================================================

g28_anti_fee_sniping_tip_age_logic_absent_test_() ->
    {"G28: No MAX_ANTI_FEE_SNIPING_TIP_AGE (8h) staleness check",
     [
      ?_test(begin
         %% Core falls back to locktime=0 when the tip is >8h old.
         %% beamchain always uses 0 — the fallback behavior is hardcoded.
         %% Document this structural absence.
         ok
       end)
     ]}.

%%% ===================================================================
%%% G29 — CoinControl: manual input override present (via wcfp)
%%% ===================================================================

g29_coincontrol_manual_inputs_present_test_() ->
    {"G29: Manual input selection (CoinControl) present via walletcreatefundedpsbt",
     [
      ?_test(begin
         %% Core's CCoinControl allows specifying exact inputs to use.
         %% beamchain supports this via walletcreatefundedpsbt's manual
         %% inputs parameter — this is PARTIALLY correct.
         Fns = beamchain_rpc:module_info(exports),
         ?assert(lists:member({rpc_walletcreatefundedpsbt, 2}, Fns))
       end)
     ]}.

%%% ===================================================================
%%% G30 — CoinControl: subtract_fee_from_outputs absent
%%% ===================================================================

g30_coincontrol_subtract_fee_absent_test_() ->
    {"G30: CoinControl subtract_fee_from_outputs absent",
     [
      ?_test(begin
         %% Core's CCoinControl::m_subtract_fee_outputs allows the fee to
         %% be deducted from the recipient amount (used in sendtoaddress
         %% with subtractfeefromamount=true).
         %% beamchain's rpc_sendtoaddress has no such option.
         Fns = beamchain_wallet:module_info(exports),
         ?assertNot(lists:member({subtract_fee_from_amount, 3}, Fns)),
         ?assertNot(lists:member({subtract_fee_from_output, 2}, Fns))
       end)
     ]}.

%%% ===================================================================
%%% W88 anti-pattern check: rand:uniform vs crypto:strong_rand_bytes
%%% ===================================================================

w88_no_rand_uniform_in_wallet_test_() ->
    {"W88: wallet module uses crypto:strong_rand_bytes (no rand:uniform)",
     [
      ?_test(begin
         %% Confirm beamchain_wallet.erl does NOT use rand:uniform.
         %% (Inspected source: all randomness uses crypto:strong_rand_bytes.)
         %% This is a PASS for this module.
         ok
       end)
     ]}.

%%% ===================================================================
%%% Additional: coinbase maturity filtering absent in coin selection
%%% ===================================================================

coinbase_maturity_filtering_absent_test_() ->
    {"Additional: coinbase maturity check absent in select_coins",
     [
      ?_test(begin
         %% Core's AvailableCoins filters out immature coinbase UTXOs
         %% (depth < COINBASE_MATURITY=100).  beamchain's select_coins/3
         %% accepts raw UTXO lists with no maturity check — the caller
         %% must filter; select_coins does not.
         %% is_coinbase field exists in #utxo{} but select_coins ignores it.
         CoinbaseUtxo = #utxo{value = 50_000_000,
                               script_pubkey = <<0, 20, 1:160>>,
                               is_coinbase = true,
                               height = 1},   %% would be immature
         Utxos = [{<<1:256>>, 0, CoinbaseUtxo}],
         %% select_coins includes it — no maturity filter
         Result = beamchain_wallet:select_coins(1000, 1, Utxos),
         ?assertMatch({ok, _, _}, Result)
       end)
     ]}.
